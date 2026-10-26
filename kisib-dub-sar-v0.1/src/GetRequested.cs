using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "Get what it asked for": one button on a refusal. Finds each certificate the program asked for (this PC,
    // kisib's CCADB / Microsoft lists, or crt.sh online), then fixes what is in the way:
    //   - it, or a certificate with its key or its name, is in Disallowed  -> lifted for good
    //   - a CA certificate is missing from this PC                         -> imported into Intermediate CAs
    //   - the root is missing                                              -> fetched from Microsoft's list
    // If none of that applies, it says so: the issuer revoked it, and no import changes that.
    internal sealed partial class ExplorerForm
    {
        private bool gettingRequested;

        internal void GetRequested(Denial d)
        {
            if (snapshot == null) { Say("Run a scan first."); return; }
            if (gettingRequested) { Say("Already getting certificates; one moment."); return; }
            List<string> sha1s = d.ChainSha1.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (sha1s.Count == 0)
            {
                // No chain logged: the best kisib can do is the site owner's blocked CAs (Allow offers the same).
                List<CertificateRecord> guess = CertificatesBehind(d);
                if (guess.Count > 0) { FixRequested(d, new List<CertificateRecord>(), guess, new List<string>()); return; }
                Say("Windows didn't log which certificate " + ProgramName(d) + " asked for, so there is nothing to fetch. " + (IsBlockedCaRefusal(d) ? "It says a CA is blocked; Repair > What this PC uses shows the blocked CAs behind recent refusals." : ""));
                return;
            }
            List<string> unknown = sha1s.Where(s => { CertificateRecord c = snapshot.BySha1(s); return c == null || c.Der == null; }).ToList();
            if (unknown.Count == 0) { FixRequested(d, sha1s.Select(snapshot.BySha1).ToList(), null, new List<string>()); return; }
            gettingRequested = true;
            Say("Looking up " + unknown.Count + " certificate" + (unknown.Count == 1 ? "" : "s") + " " + ProgramName(d) + " asked for on crt.sh (not on this PC or in kisib's lists)...");
            Thread worker = new Thread(delegate()
            {
                List<string> problems = new List<string>();
                List<byte[]> found = FromCrtSh(unknown, problems);
                Post(delegate
                {
                    gettingRequested = false;
                    List<CertificateRecord> chain = new List<CertificateRecord>();
                    foreach (string s in sha1s)
                    {
                        CertificateRecord c = snapshot.BySha1(s);
                        if (c == null || c.Der == null)
                        {
                            byte[] der = found.FirstOrDefault(x => String.Equals(CertificateRecord.FromDer(x).Sha1, s, StringComparison.OrdinalIgnoreCase));
                            if (der != null) c = CertificateRecord.FromDer(der);
                        }
                        if (c != null && c.Der != null) chain.Add(c);
                    }
                    FixRequested(d, chain, null, problems);
                });
            });
            worker.IsBackground = true; worker.Name = "kisib get requested certificates"; worker.Start();
        }

        private static string ProgramName(Denial d) { return String.IsNullOrEmpty(d.Program) ? "the program" : System.IO.Path.GetFileName(d.Program); }

        private void FixRequested(Denial d, List<CertificateRecord> chain, List<CertificateRecord> guessed, List<string> problems)
        {
            List<string> said = new List<string>();
            // 1. Blocks in the way: the certificate itself, anything with its key, or a blocked CA with its exact name.
            List<CertificateRecord> lift = new List<CertificateRecord>(guessed ?? new List<CertificateRecord>());
            foreach (CertificateRecord c in chain)
            {
                lift.AddRange(WithTwins(new CertificateRecord[] { snapshot.BySha1(c.Sha1) ?? c }).Where(snapshot.IsBlocked));
                lift.AddRange(SameNameBlocked(c));
            }
            lift = lift.GroupBy(c => c.Sha1).Select(g => g.First()).ToList();
            if (lift.Count > 0)
                said.Add("Unblocked " + String.Join(", ", lift.Select(c => c.SubjectShortName).Distinct().ToArray()) + ": " + LiftForGood(WithTwins(lift), "got what " + ProgramName(d) + " asked for", "got what it asked for"));
            // 2. CA certificates missing from this PC go into Intermediate Certification Authorities.
            List<CertificateRecord> import = chain.Where(c => c.Subject != c.Issuer && IsCa(c.Der) && !TrustGraph.OnPcForPath(snapshot.BySha1(c.Sha1) ?? c)).ToList();
            if (import.Count > 0)
            {
                X509Location scope = Elevation.IsElevated ? X509Location.LocalMachine : X509Location.CurrentUser;
                try
                {
                    List<string> report = RouteStore.Install(import, scope, "imported: " + ProgramName(d) + " asked for it");
                    said.Add("Imported into " + (scope == X509Location.LocalMachine ? "the whole PC's" : "this user's") + " Intermediate CAs: " +
                        String.Join(", ", report.Where(r => r.StartsWith("added", StringComparison.Ordinal)).Select(r => r.Split(new string[] { "  " }, StringSplitOptions.RemoveEmptyEntries)[2]).ToArray()) + ".");
                    problems.AddRange(report.Where(r => r.StartsWith("error", StringComparison.Ordinal)));
                }
                catch (Exception ex) { problems.Add("import failed: " + ex.Message); }
            }
            // 3. A missing root comes fresh from Microsoft's list (only if Microsoft lists it).
            CertificateRecord top = chain.LastOrDefault();
            bool rootMissing = top != null && top.Subject == top.Issuer && !TrustGraph.InRootStore(snapshot.BySha1(top.Sha1) ?? top) && !snapshot.IsBlocked(snapshot.BySha1(top.Sha1));
            bool issuerMissing = top != null && top.Subject != top.Issuer && d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase);
            if (rootMissing || issuerMissing)
            {
                string issuerDn = top.Subject != top.Issuer ? top.Issuer : null, issuerKey = top.AuthorityKeyId, sha1 = top.Sha1;
                FetchFromMicrosoft(c => String.Equals(c.Sha1, sha1, StringComparison.OrdinalIgnoreCase) || (issuerDn != null && c.Subject == issuerDn && (issuerKey == null || c.SubjectKeyId == issuerKey)),
                    rootMissing ? top.SubjectShortName : top.IssuerShortName);
                said.Add("Getting the root from Microsoft's list (another line says when it's in).");
            }
            if (said.Count == 0 && IsRevocationRefusal(d))
            {
                CheckRevocation(d);
                said.Add("Nothing is blocked or missing: Windows couldn't reach a revocation server. Checking which ones (a window opens).");
            }
            if (said.Count == 0)
            {
                string why = d.Code.EndsWith("92010", StringComparison.OrdinalIgnoreCase)
                    ? "Nothing on this PC blocks it and nothing is missing, so Windows' revocation check says its issuer revoked it (or Microsoft's own untrusted list has it). Importing can't change a revocation."
                    : chain.Count == 0 ? "Couldn't find the certificate it asked for on this PC, in kisib's lists or on crt.sh."
                    : "Everything it asked for is already on this PC and none of it is blocked: " + ShortReason(d.Reason ?? "");
                said.Add(why);
            }
            if (problems.Count > 0) said.Add("(" + String.Join("; ", problems.Distinct().Take(4).ToArray()) + ")");
            Say(String.Join(" ", said.ToArray()));
            if (lift.Count > 0 || import.Count > 0) { WatchAllow(lift.Concat(import).ToList(), d.Subject); StartScan(); }
        }

        internal static bool IsCa(byte[] der)
        {
            try
            {
                using (X509Certificate2 cert = new X509Certificate2(der))
                    foreach (X509Extension e in cert.Extensions)
                    {
                        X509BasicConstraintsExtension b = e as X509BasicConstraintsExtension;
                        if (b != null) return b.CertificateAuthority;
                    }
            }
            catch (Exception) { }
            return false;
        }

        // crt.sh: the public Certificate Transparency search. The SHA-1 page links the PEM download; the result is
        // checked against the SHA-1 asked for, so only that exact certificate comes back.
        private static List<byte[]> FromCrtSh(List<string> sha1s, List<string> problems)
        {
            List<byte[]> found = new List<byte[]>();
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch (Exception) { }
            foreach (string sha1 in sha1s.Take(6))
            {
                try
                {
                    using (WebClient web = new WebClient())
                    {
                        web.Headers[HttpRequestHeader.UserAgent] = "kisib.dub-sar";
                        string page = web.DownloadString("https://crt.sh/?q=" + sha1.ToUpperInvariant());
                        Match id = Regex.Match(page, @"\?d=(\d+)");
                        if (!id.Success) { problems.Add(sha1.Substring(0, 8) + " not on crt.sh"); continue; }
                        web.Headers[HttpRequestHeader.UserAgent] = "kisib.dub-sar";
                        string pem = web.DownloadString("https://crt.sh/?d=" + id.Groups[1].Value);
                        int start = pem.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal), end = pem.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
                        if (start < 0 || end < start) { problems.Add(sha1.Substring(0, 8) + ": crt.sh sent no certificate"); continue; }
                        byte[] der = Convert.FromBase64String(pem.Substring(start + 27, end - start - 27));
                        CertificateRecord c = CertificateRecord.FromDer(der);
                        if (!String.Equals(c.Sha1, sha1, StringComparison.OrdinalIgnoreCase)) { problems.Add(sha1.Substring(0, 8) + ": crt.sh sent a different certificate, not used"); continue; }
                        found.Add(der);
                    }
                }
                catch (Exception ex) { problems.Add("crt.sh: " + ex.Message); }
            }
            return found;
        }
    }
}
