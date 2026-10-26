using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Text;
using Microsoft.Win32;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "root not trusted (not your block)": Windows needed a root it doesn't have and couldn't download it.
    // kisib asks Windows Update for Microsoft's current root list (certutil -generateSSTFromWU, which checks it
    // against Microsoft's signed authroot.stl) and puts just that root into Trusted Root — what Windows itself
    // would have downloaded. Only roots on Microsoft's list; a root you blocked stays blocked.
    internal sealed partial class ExplorerForm
    {
        private bool fetchingRoots;

        // The name of the root a refusal was missing: the top of the logged chain if it is a root, else its issuer.
        internal string MissingRootName(Denial d)
        {
            CertificateRecord top = d.ChainSha1.Count == 0 || snapshot == null ? null : snapshot.BySha1(d.ChainSha1[d.ChainSha1.Count - 1]);
            if (top != null) return top.Subject == top.Issuer ? top.SubjectShortName : top.IssuerShortName;
            return d.ChainNames.Count > 0 && d.ChainNames[d.ChainNames.Count - 1].Length > 0 ? d.ChainNames[d.ChainNames.Count - 1] : "the missing root";
        }

        internal void FetchRoot(Denial d)
        {
            List<string> sha1s = new List<string>(d.ChainSha1);
            CertificateRecord top = sha1s.Count == 0 || snapshot == null ? null : snapshot.BySha1(sha1s[sha1s.Count - 1]);
            string issuerDn = top != null && top.Subject != top.Issuer ? top.Issuer : null, issuerKey = top == null ? null : top.AuthorityKeyId;
            if (sha1s.Count == 0)
            {
                Say("Windows didn't log the chain for " + d.Subject + ", so kisib can't tell which root is missing. Repair > What this PC uses lists the roots behind recent refusals.");
                return;
            }
            FetchFromMicrosoft(delegate(CertificateRecord c)
            {
                return sha1s.Contains(c.Sha1, StringComparer.OrdinalIgnoreCase) || (issuerDn != null && c.Subject == issuerDn && (issuerKey == null || c.SubjectKeyId == issuerKey));
            }, MissingRootName(d));
        }

        // 1. Which roots: what kisib already knows (this PC, Microsoft list, CCADB) matching the request or its name.
        // 2. Approved only if Windows' own trusted-root list names its SHA-1 (authroot.stl in HKLM, kept by Windows).
        // 3. The certificate itself from the first source that has it, checked by SHA-1: kisib's lists, Windows
        //    Update's root download (the same file Windows fetches), or a fresh certutil list.
        internal void FetchFromMicrosoft(Func<CertificateRecord, bool> wanted, string label)
        {
            if (fetchingRoots) { Say("Already getting roots from Microsoft; one moment."); return; }
            Dictionary<string, byte[]> known = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            if (snapshot != null)
                foreach (CertificateRecord c in snapshot.Certificates.Values)
                    if (c.Subject == c.Issuer && (wanted(c) || SameRootName(c, label)) && !known.ContainsKey(c.Sha1)) known[c.Sha1] = c.Der;
            fetchingRoots = true;
            Say("Getting " + label + " the way Windows would (its own root list decides)...");
            bool elevated = Elevation.IsElevated;
            Thread worker = new Thread(delegate()
            {
                List<byte[]> found = new List<byte[]>();
                List<string> notes = new List<string>();
                string error = null;
                try
                {
                    HashSet<string> listed = AuthRootList.Sha1s();
                    if (listed.Count > 50)
                    {
                        List<string> approved = known.Keys.Where(listed.Contains).ToList();
                        if (approved.Count == 0)
                            notes.Add(known.Count == 0 ? "kisib has never seen a root called " + label + " (Tools > Update Microsoft root list adds all of them)"
                                : "Windows' own root list (" + listed.Count + " roots" + (AuthRootList.Synced.HasValue ? ", synced " + AuthRootList.Synced.Value.ToLocalTime().ToString("yyyy-MM-dd") : "") + ") doesn't name " + label);
                        foreach (string sha1 in approved)
                        {
                            byte[] der = known[sha1];
                            if (der == null || !Sha1Of(der).Equals(sha1, StringComparison.OrdinalIgnoreCase)) der = WindowsUpdateRoot(sha1, notes);
                            if (der != null) found.Add(der);
                        }
                    }
                    else
                    {
                        // Windows has no root list stored (its automatic root download never ran): ask certutil for one.
                        notes.Add("Windows has no root list of its own here" + (RootAutoUpdateOff() ? " (its automatic root download is switched off)" : ""));
                        string folder = PrivateFolder(elevated);
                        try
                        {
                            string sst = Path.Combine(folder, "roots.sst");
                            error = MicrosoftList.Generate(sst);
                            if (error == null)
                            {
                                X509Certificate2Collection roots = new X509Certificate2Collection();
                                roots.Import(sst);
                                foreach (X509Certificate2 x in roots)
                                {
                                    CertificateRecord c = CertificateRecord.FromDer(x.RawData);
                                    if (c != null && c.Subject == c.Issuer && (known.ContainsKey(c.Sha1) || wanted(c) || SameRootName(c, label))) found.Add(x.RawData);
                                }
                                if (found.Count == 0) notes.Add("certutil's list had " + roots.Count + " roots and none is " + label + (roots.Count < 200 ? " (that's short: a firewall may be cutting certutil off)" : ""));
                            }
                        }
                        finally { try { Directory.Delete(folder, true); } catch (Exception) { } }
                    }
                }
                catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; }
                Post(delegate { fetchingRoots = false; FinishFetch(found, error, label, elevated, notes); });
            });
            worker.IsBackground = true; worker.Name = "kisib root from Microsoft"; worker.Start();
        }

        private static bool SameRootName(CertificateRecord c, string label)
        {
            return !String.IsNullOrEmpty(label) && (String.Equals(c.SubjectShortName, label, StringComparison.OrdinalIgnoreCase) || String.Equals(c.SubjectCn, label, StringComparison.OrdinalIgnoreCase));
        }

        private static string Sha1Of(byte[] der)
        {
            using (System.Security.Cryptography.SHA1 sha = System.Security.Cryptography.SHA1.Create())
                return BitConverter.ToString(sha.ComputeHash(der)).Replace("-", "");
        }

        // The file Windows itself downloads for a missing root: ctldl.windowsupdate.com/.../<SHA-1>.crt.
        private static byte[] WindowsUpdateRoot(string sha1, List<string> notes)
        {
            try
            {
                using (System.Net.WebClient web = new System.Net.WebClient())
                {
                    byte[] der = web.DownloadData("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + sha1.ToUpperInvariant() + ".crt");
                    if (Sha1Of(der).Equals(sha1, StringComparison.OrdinalIgnoreCase)) return der;
                    notes.Add("Windows Update sent a different file for " + sha1.Substring(0, 8) + ", not used");
                }
            }
            catch (Exception ex) { notes.Add("Windows Update download failed: " + ex.Message); }
            return null;
        }

        private void FinishFetch(List<byte[]> found, string error, string label, bool elevated, List<string> notes)
        {
            if (error != null)
            {
                string first = error.Split('\r', '\n').FirstOrDefault(l => l.Trim().Length > 0) ?? error;
                Say("Couldn't get Microsoft's root list: " + first + (RootAutoUpdateOff() ? " Windows' automatic root download is switched off on this PC too (policy DisableRootAutoUpdate)." : " A VPN or firewall blocking certutil can cause this."));
                return;
            }
            if (found.Count == 0) { Say("Didn't add " + label + ": " + (notes.Count > 0 ? String.Join("; ", notes.ToArray()) : "no trusted root by that name") + "."); return; }
            List<string> added = new List<string>(), problems = new List<string>();
            foreach (byte[] der in found)
            {
                CertificateRecord c = CertificateRecord.FromDer(der);
                CertificateRecord onPc = snapshot == null ? null : snapshot.BySha1(c.Sha1);
                if (onPc != null && snapshot.IsBlocked(onPc)) { problems.Add(c.SubjectShortName + " is blocked by you, so it stays out (Allow or Unblock it first)"); continue; }
                try
                {
                    if (elevated)
                    {
                        using (OwnStore root = OwnStore.Open("Root", X509Location.LocalMachine, true)) root.Add(der);
                        BlockEngine.Note("trust-from-microsoft", X509Location.LocalMachine, c.Sha256, c.Sha1, c.SubjectShortName, "root from Microsoft's list (certutil -generateSSTFromWU)");
                    }
                    else
                    {
                        // This user only. Windows shows its own "install this root?" question here.
                        using (X509Store store = new X509Store(StoreName.Root, X509Location.CurrentUser)) { store.Open(OpenFlags.ReadWrite); store.Add(new X509Certificate2(der)); }
                        BlockEngine.Note("trust-from-microsoft", X509Location.CurrentUser, c.Sha256, c.Sha1, c.SubjectShortName, "root from Microsoft's list (certutil -generateSSTFromWU)");
                    }
                    added.Add(c.SubjectShortName);
                }
                catch (Exception ex) { problems.Add(c.SubjectShortName + ": " + ex.Message); }
            }
            Say((added.Count > 0 ? "Put into Trusted Root (" + (elevated ? "whole PC" : "this user; run kisib as administrator for services like lsass") + "): " + String.Join(", ", added.ToArray()) + ". Try it again now." : "Nothing was added.") +
                (problems.Count > 0 ? " " + String.Join("; ", problems.ToArray()) + "." : ""));
            if (added.Count > 0) StartScan();
        }

        // A folder only administrators can write, so nothing can swap the list between certutil and kisib.
        private static string PrivateFolder(bool elevated)
        {
            string path = Path.Combine(Path.GetTempPath(), "kisib-roots-" + Guid.NewGuid().ToString("N"));
            if (!elevated) { Directory.CreateDirectory(path); return path; }
            DirectorySecurity rules = new DirectorySecurity();
            rules.SetAccessRuleProtection(true, false);
            InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            rules.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            rules.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(path, rules);
            return path;
        }

        // Windows can be told never to download roots on its own; then every missing root stays missing.
        internal static bool RootAutoUpdateOff()
        {
            foreach (string key in new string[] { @"SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot", @"SOFTWARE\Microsoft\SystemCertificates\AuthRoot" })
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(key))
                    {
                        object v = k == null ? null : k.GetValue("DisableRootAutoUpdate");
                        if (v is int && (int)v != 0) return true;
                    }
                }
                catch (Exception) { }
            }
            return false;
        }
    }

    // Windows' own trusted-root list: authroot.stl as Windows last synced it, in HKLM (only admins and Windows
    // write there). Its entries are the SHA-1s of every root Windows would download on demand.
    internal static class AuthRootList
    {
        internal static DateTime? Synced;
        private static HashSet<string> cache;
        private static int cacheLength = -1;

        internal static HashSet<string> Sha1s()
        {
            byte[] blob = null;
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate"))
                {
                    if (k != null)
                    {
                        blob = k.GetValue("EncodedCtl") as byte[];
                        byte[] t = k.GetValue("LastSyncTime") as byte[];
                        if (t != null && t.Length == 8) Synced = DateTime.FromFileTimeUtc(BitConverter.ToInt64(t, 0));
                    }
                }
            }
            catch (Exception) { }
            if (blob == null) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (cache != null && cacheLength == blob.Length) return cache;
            cache = Parse(blob); cacheLength = blob.Length;
            return cache;
        }

        // A certificate trust list entry is SEQUENCE { OCTET STRING (20-byte SHA-1), attributes }. Walk the signed
        // blob's constructed parts and collect those; nothing inside primitive values is read.
        internal static HashSet<string> Parse(byte[] der)
        {
            HashSet<string> found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Walk(der, 0, der.Length, found, 0);
            return found;
        }

        private static void Walk(byte[] d, int start, int end, HashSet<string> found, int depth)
        {
            int i = start;
            while (i < end)
            {
                int length, header;
                if (!Header(d, i, end, out length, out header)) return;
                int contentStart = i + header, contentEnd = contentStart + length;
                if (contentEnd > end) return;
                if (d[i] == 0x30 && contentStart < contentEnd && d[contentStart] == 0x04)
                {
                    int l2, h2;
                    if (Header(d, contentStart, contentEnd, out l2, out h2) && l2 == 20)
                    {
                        StringBuilder hex = new StringBuilder(40);
                        for (int k = 0; k < 20; k++) hex.Append(d[contentStart + h2 + k].ToString("X2"));
                        found.Add(hex.ToString());
                    }
                }
                if ((d[i] & 0x20) != 0 && depth < 16) Walk(d, contentStart, contentEnd, found, depth + 1);
                i = contentEnd;
            }
        }

        private static bool Header(byte[] d, int i, int end, out int length, out int header)
        {
            length = 0; header = 0;
            if (i + 2 > end || (d[i] & 0x1F) == 0x1F) return false;
            int first = d[i + 1];
            if (first < 0x80) { length = first; header = 2; return true; }
            int n = first & 0x7F;
            if (n == 0 || n > 4 || i + 2 + n > end) return false;
            for (int k = 0; k < n; k++) length = (length << 8) | d[i + 2 + k];
            header = 2 + n;
            return length >= 0;
        }
    }
}
