using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Kisib
{
    // "Revocation server unreachable": Windows has to ask each CA in the chain whether the certificate was cancelled
    // (OCSP or a CRL download). If it can't reach them, many apps (Apple's sign-in among them) refuse. This shows
    // which servers each certificate in the refused chain names, and whether kisib can reach them from here.
    internal sealed partial class ExplorerForm
    {
        private bool checkingRevocation;

        internal static bool IsRevocationRefusal(Denial d)
        {
            return d != null && (d.Code.EndsWith("92013", StringComparison.OrdinalIgnoreCase) || d.Code.EndsWith("92012", StringComparison.OrdinalIgnoreCase) ||
                (d.Reason ?? "").IndexOf("revocation", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        internal void CheckRevocation(Denial d)
        {
            if (checkingRevocation) { Say("Already checking revocation servers; one moment."); return; }
            List<string> sha1s = d.ChainSha1.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (sha1s.Count == 0) { Say("Windows didn't log the chain for " + d.Subject + ", so kisib can't see which revocation servers it needed."); return; }
            Dictionary<string, byte[]> ders = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < sha1s.Count; i++)
            {
                CertificateRecord c = snapshot == null ? null : snapshot.BySha1(sha1s[i]);
                if (c != null && c.Der != null) ders[sha1s[i]] = c.Der;
                int at = d.ChainSha1.IndexOf(sha1s[i]);
                names[sha1s[i]] = c != null ? c.SubjectShortName : at >= 0 && at < d.ChainNames.Count ? d.ChainNames[at] : sha1s[i].Substring(0, 12);
            }
            string program = ProgramName(d), site = d.Site ?? d.Subject;
            checkingRevocation = true;
            Say("Checking the revocation servers " + program + " needed for " + site + "...");
            Thread worker = new Thread(delegate()
            {
                List<string> notes = new List<string>();
                List<string> missing = sha1s.Where(s => !ders.ContainsKey(s)).ToList();
                if (missing.Count > 0)
                    foreach (byte[] der in FromCrtSh(missing, notes)) ders[CertificateRecord.FromDer(der).Sha1] = der;
                StringBuilder t = new StringBuilder();
                t.AppendLine(program + " → " + site + "   refused " + d.Time.ToString("yyyy-MM-dd HH:mm:ss") + ": " + ShortReason(d.Reason ?? ""));
                t.AppendLine();
                Dictionary<string, string> tested = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                List<string> down = new List<string>();
                foreach (string sha1 in sha1s)
                {
                    t.AppendLine(names[sha1]);
                    byte[] der;
                    if (!ders.TryGetValue(sha1, out der)) { t.AppendLine("    kisib couldn't get this certificate (not on this PC, in its lists or on crt.sh)"); continue; }
                    List<KeyValuePair<string, string>> urls = RevocationUrls(der);
                    if (urls.Count == 0) t.AppendLine("    names no revocation server (normal for a root)");
                    foreach (KeyValuePair<string, string> u in urls)
                    {
                        string result;
                        if (!tested.TryGetValue(u.Value, out result)) { result = Reach(u.Value); tested[u.Value] = result; }
                        t.AppendLine("    " + u.Key.PadRight(7) + u.Value + "\r\n           → " + result);
                        if (!result.StartsWith("reachable", StringComparison.Ordinal)) { string host = HostOf(u.Value); if (!down.Contains(host)) down.Add(host); }
                    }
                }
                t.AppendLine();
                if (down.Count > 0)
                    t.AppendLine("Not reachable from kisib: " + String.Join(", ", down.ToArray()) + ".\r\n" +
                        "Windows needs these to finish the check. A firewall (simplewall, a VPN's kill switch) or a DNS blocker stopping them makes Windows say\r\n" +
                        "\"revocation server unreachable\", and apps like Apple's sign-in give up. These hosts only answer \"is this certificate cancelled?\".");
                else
                    t.AppendLine("Every server answered kisib. If " + program + " still gets \"revocation server unreachable\", its own network access is being blocked\r\n" +
                        "(a per-app firewall rule for " + program + "), or it was offline at " + d.Time.ToString("HH:mm") + ".");
                if (notes.Count > 0) t.AppendLine("(" + String.Join("; ", notes.Distinct().ToArray()) + ")");
                string summary = down.Count > 0 ? "Revocation servers not reachable: " + String.Join(", ", down.ToArray()) + "." : "All revocation servers for " + site + " answered kisib.";
                Post(delegate { checkingRevocation = false; Say(summary); ShowText("Revocation check — " + site, t.ToString()); });
            });
            worker.IsBackground = true; worker.Name = "kisib revocation check"; worker.Start();
        }

        private static string HostOf(string url) { try { return new Uri(url).Host; } catch (Exception) { return url; } }

        // OCSP and CA-issuer addresses (Authority Information Access) and CRL addresses (CRL Distribution Points).
        internal static List<KeyValuePair<string, string>> RevocationUrls(byte[] der)
        {
            List<KeyValuePair<string, string>> list = new List<KeyValuePair<string, string>>();
            try
            {
                using (X509Certificate2 x = new X509Certificate2(der))
                    foreach (X509Extension e in x.Extensions)
                    {
                        string oid = e.Oid == null ? "" : e.Oid.Value;
                        if (oid == "1.3.6.1.5.5.7.1.1") Uris(e.RawData, true, list);
                        else if (oid == "2.5.29.31") Uris(e.RawData, false, list);
                    }
            }
            catch (Exception) { }
            return list;
        }

        private static readonly byte[] AccessMethodPrefix = { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30 };

        private static void Uris(byte[] d, bool aia, List<KeyValuePair<string, string>> list)
        {
            for (int i = 0; i + 2 < d.Length; i++)
            {
                if (d[i] != 0x86) continue;   // GeneralName uniformResourceIdentifier
                int length = d[i + 1], start = i + 2;
                if (length == 0x81 && i + 2 < d.Length) { length = d[i + 2]; start = i + 3; }
                else if (length >= 0x80) continue;
                if (start + length > d.Length || length < 8) continue;
                string url = Encoding.ASCII.GetString(d, start, length);
                if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue;
                string kind = "CRL";
                if (aia)
                {
                    kind = "issuer";
                    if (i >= 10)
                    {
                        bool method = true;
                        for (int k = 0; k < AccessMethodPrefix.Length; k++) if (d[i - 10 + k] != AccessMethodPrefix[k]) { method = false; break; }
                        if (method && d[i - 1] == 0x01) kind = "OCSP";
                    }
                }
                list.Add(new KeyValuePair<string, string>(kind, url));
                i = start + length - 1;
            }
        }

        // Any HTTP answer at all means the server is reachable (OCSP servers answer a plain GET with an error page).
        private static string Reach(string url)
        {
            try
            {
                HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
                r.Method = "GET"; r.Timeout = 7000; r.ReadWriteTimeout = 7000; r.UserAgent = "kisib.dub-sar"; r.AllowAutoRedirect = true;
                using (HttpWebResponse response = (HttpWebResponse)r.GetResponse()) return "reachable (HTTP " + (int)response.StatusCode + ")";
            }
            catch (WebException ex)
            {
                HttpWebResponse response = ex.Response as HttpWebResponse;
                if (response != null) { int code = (int)response.StatusCode; response.Close(); return "reachable (HTTP " + code + ")"; }
                switch (ex.Status)
                {
                    case WebExceptionStatus.NameResolutionFailure: return "NOT reachable: the name didn't resolve (DNS blocked or offline)";
                    case WebExceptionStatus.ConnectFailure: return "NOT reachable: connection refused or blocked";
                    case WebExceptionStatus.Timeout: return "NOT reachable: no answer in 7 seconds";
                    default: return "NOT reachable: " + ex.Status + " (" + ex.Message + ")";
                }
            }
            catch (Exception ex) { return "NOT reachable: " + ex.Message; }
        }
    }
}
