using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Windows downloads a missing root the first time a signed file needs it. When that is broken on a PC (root
    // auto-download off, or a VPN/firewall blocking Windows Update's certificate server), installers fail with
    // "rejected by digital signature policy" (iCloud's AppleApplicationSupport.msi). kisib does Windows' job here:
    // a root Microsoft's own list trusts, that a refused signed file needs, goes into Trusted Root. Never one you
    // blocked, never past the fail-safe, never a root Microsoft doesn't list. Needs kisib running as administrator.
    internal sealed partial class ExplorerForm
    {
        private readonly HashSet<string> autoRootTried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> autoLooked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool autoRootHinted;

        private void AutoTrustRoots(Denial d)
        {
            if (d == null || d.Ok || d.IsWeb || d.ChainSha1.Count == 0 || snapshot == null || Storage.Setting("auto roots off")) return;
            if (!Elevation.IsElevated)
            {
                if (!autoRootHinted) { autoRootHinted = true; Say("A signed file was refused because Windows is missing a root. Run kisib as administrator and it puts Microsoft-listed roots in by itself."); }
                return;
            }
            List<string> unknown = d.ChainSha1.Where(s => snapshot.BySha1(s) == null && autoLooked.Add(s)).ToList();
            if (unknown.Count == 0) { FinishAutoRoots(d, new List<byte[]>()); return; }
            Thread worker = new Thread(delegate()
            {
                List<byte[]> found;
                try { found = FromCrtSh(unknown, new List<string>()); } catch (Exception) { found = new List<byte[]>(); }
                Post(delegate { FinishAutoRoots(d, found); });
            }) { IsBackground = true, Name = "kisib auto roots" };
            worker.Start();
        }

        private void FinishAutoRoots(Denial d, List<byte[]> fetched)
        {
            if (snapshot == null) return;
            List<CertificateRecord> chain = new List<CertificateRecord>();
            foreach (string s in d.ChainSha1)
            {
                CertificateRecord c = snapshot.BySha1(s);
                if (c == null) { byte[] der = fetched.FirstOrDefault(x => String.Equals(CertificateRecord.FromDer(x).Sha1, s, StringComparison.OrdinalIgnoreCase)); if (der != null) c = CertificateRecord.FromDer(der); }
                if (c != null) chain.Add(c);
            }
            List<CertificateRecord> roots = new List<CertificateRecord>();
            foreach (CertificateRecord c in chain)
            {
                if (c.Subject == c.Issuer) { if (!TrustGraph.InRootStore(c)) roots.Add(c); continue; }
                RootsAbove(c, roots, 0);
            }
            HashSet<string> microsoft = AuthRootList.Sha1s();
            List<CertificateRecord> want = roots.Where(r => r.Der != null && r.Sha1 != null && !autoRootTried.Contains(r.Sha1) && !TrustGraph.InRootStore(r)
                && (microsoft.Contains(r.Sha1) || r.FoundIn.Contains(MicrosoftList.Label) || Seals.BySha1(r.Sha1) != null) && !snapshot.IsBlocked(snapshot.BySha1(r.Sha1)))
                .GroupBy(r => r.Sha1).Select(g => g.First()).ToList();
            if (want.Count == 0) return;
            foreach (CertificateRecord r in want) autoRootTried.Add(r.Sha1);
            List<string> kept = new List<string>(), added = new List<string>();
            want = Guarded(want, kept);
            foreach (CertificateRecord r in want)
                try
                {
                    using (OwnStore root = OwnStore.Open("Root", X509Location.LocalMachine, true)) root.Add(r.Der);
                    BlockEngine.Note("auto-root", X509Location.LocalMachine, r.Sha256, r.Sha1, r.SubjectShortName, "root a signed file needed; Windows didn't download it");
                    added.Add(r.SubjectShortName);
                }
                catch (Exception ex) { kept.Add(r.SubjectShortName + ": " + ex.Message); }
            if (added.Count == 0) return;
            try { AllowedList.AddRange(want, "root a signed file needed"); } catch (IOException) { }
            Say("✅ Put " + String.Join(", ", added.ToArray()) + " into Trusted Root: " + ProgramName(d) + " needed it to check a signed file and Windows didn't download it. Run it again.");
            StartScan();
        }

        // The untrusted roots above a CA, found by issuer name and key id; stops where a trusted root already sits.
        private bool RootsAbove(CertificateRecord c, List<CertificateRecord> roots, int depth)
        {
            if (depth > 6 || c.Issuer == null) return false;
            // On this PC or in kisib's lists, plus the roots kisib carries itself (Windows' code-signing roots among them).
            List<CertificateRecord> parents = snapshot.Certificates.Values.Concat(Seals.All.Where(s => s.Der != null && snapshot.BySha1(s.Sha1) == null).Select(s => CertificateRecord.FromDer(s.Der)))
                .Where(x => x.Der != null && x.Identity != c.Identity && String.Equals(x.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase) &&
                (c.AuthorityKeyId == null || x.SubjectKeyId == null || x.SubjectKeyId == c.AuthorityKeyId)).ToList();
            List<CertificateRecord> found = new List<CertificateRecord>();
            foreach (CertificateRecord p in parents.Where(x => x.Subject == x.Issuer))
            {
                if (TrustGraph.InRootStore(p) && !snapshot.IsBlocked(p)) return true;
                found.Add(p);
            }
            foreach (CertificateRecord p in parents.Where(x => x.Subject != x.Issuer))
                if (RootsAbove(p, found, depth + 1)) return true;
            roots.AddRange(found);
            return false;
        }
    }
}
