using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace Kisib
{
    // Never lift: whatever button is pressed (Allow, Unblock, Get what it asked for, Required for app, Import, a
    // repair, Keep Claude reachable), these stay blocked and the result line says why:
    //   - on kisib's compromised list (data/incident-hashes.csv), or sharing a key with one listed as a key compromise
    //   - on Windows' own untrusted list (disallowedcert.stl, which Windows keeps in HKLM next to its trusted list)
    //   - expired or not valid yet (Windows ignores those in a chain anyway), except kisib's seals and roots on
    //     Windows' own trusted list, which Windows keeps for old time stamps
    internal static class LiftGuard
    {
        private static Dictionary<string, string> bySha256, bySpki;
        private static string loadedFrom;
        private static HashSet<string> windowsUntrusted;
        private static int untrustedLength = -1;

        internal static string Why(CertificateRecord c, string sourceDirectory)
        {
            if (c == null) return null;
            LoadIncidents(sourceDirectory);
            string id;
            if (c.Sha256 != null && bySha256.TryGetValue(c.Sha256, out id)) return "compromised (" + id + ")";
            if (c.SpkiSha256 != null && bySpki.TryGetValue(c.SpkiSha256, out id)) return "its key was compromised (" + id + ")";
            if (c.Sha1 != null && WindowsUntrusted().Contains(c.Sha1)) return "Windows itself distrusts it";
            // Windows keeps a few expired roots on purpose (old time stamps on signed files, e.g. Thawte Timestamping CA):
            // kisib's own pinned seals and roots on Windows' own trusted list are never refused for being expired.
            if (c.Sha1 != null && (Seals.BySha1(c.Sha1) != null || AuthRootList.Sha1s().Contains(c.Sha1))) return null;
            DateTime now = DateTime.UtcNow;
            if (c.NotAfter.HasValue && c.NotAfter.Value < now) return "expired " + c.NotAfter.Value.ToString("yyyy-MM-dd");
            if (c.NotBefore.HasValue && c.NotBefore.Value > now.AddDays(1)) return "not valid until " + c.NotBefore.Value.ToString("yyyy-MM-dd");
            return null;
        }

        private static void LoadIncidents(string sourceDirectory)
        {
            if (bySha256 != null && loadedFrom == sourceDirectory) return;
            Dictionary<string, string> sha = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), spki = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (IncidentEntry e in IncidentList.Read(IncidentList.PathIn(sourceDirectory)))
                {
                    string label = e.IncidentId + (e.SubjectO != null && e.SubjectO.Length > 0 ? ", " + e.SubjectO : "");
                    if (e.Match == "certificate_sha256") sha[e.Value] = label;
                    else if (e.Match == "spki_sha256") spki[e.Value] = label;
                }
            }
            catch (Exception) { }
            bySha256 = sha; bySpki = spki; loadedFrom = sourceDirectory;
        }

        internal static HashSet<string> WindowsUntrusted()
        {
            byte[] blob = null;
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate"))
                    if (k != null) blob = k.GetValue("DisallowedCertEncodedCtl") as byte[];
            }
            catch (Exception) { }
            if (blob == null) return windowsUntrusted ?? (windowsUntrusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            if (windowsUntrusted != null && untrustedLength == blob.Length) return windowsUntrusted;
            windowsUntrusted = AuthRootList.Parse(blob); untrustedLength = blob.Length;
            return windowsUntrusted;
        }
    }

    internal sealed partial class ExplorerForm
    {
        // The certificates that may be lifted; the rest go into kept with the reason, once per name.
        internal List<CertificateRecord> Guarded(IEnumerable<CertificateRecord> certs, List<string> kept)
        {
            List<CertificateRecord> ok = new List<CertificateRecord>();
            Dictionary<string, string> refused = new Dictionary<string, string>(StringComparer.Ordinal);
            // A key compromise covers every certificate with that key, so check the key twins too.
            foreach (CertificateRecord c in certs.Where(x => x != null))
            {
                string why = LiftGuard.Why(c, sourceDirectory);
                if (why == null && snapshot != null)
                    foreach (CertificateRecord twin in snapshot.SameKey(c))
                    {
                        string w = LiftGuard.Why(twin, sourceDirectory);
                        if (w != null && (w.StartsWith("compromised", StringComparison.Ordinal) || w.StartsWith("its key", StringComparison.Ordinal))) { why = "its key was compromised (" + w.Substring(w.IndexOf('(') + 1).TrimEnd(')') + ")"; break; }
                    }
                if (why == null) ok.Add(c);
                else if (!refused.ContainsKey(c.SubjectShortName)) refused[c.SubjectShortName] = why;
            }
            if (refused.Count > 0 && kept != null)
                kept.Add("Kept blocked: " + String.Join("; ", refused.Select(r => r.Key + " (" + r.Value + ")").Take(6).ToArray()) + (refused.Count > 6 ? " and " + (refused.Count - 6) + " more" : "") + ".");
            return ok;
        }
    }
}
