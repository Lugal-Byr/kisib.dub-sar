using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // The live map's switch on a certificate box: ✅ Trusted makes Windows trust it (out of Untrusted Certificates for
    // good, a root into Trusted Root, a CA into Intermediate CAs), 🚫 Untrusted blocks it. The fail-safe still keeps
    // expired, compromised and Microsoft-distrusted certificates out.
    internal sealed partial class ExplorerForm
    {
        internal void TrustFromMap(MapNode n, List<CertificateRecord> certs)
        {
            if (snapshot == null) { Say("Run a scan first."); return; }
            List<string> kept = new List<string>();
            List<CertificateRecord> ok = Guarded(certs, kept);
            if (ok.Count == 0) { Say(n.Label + " stays untrusted: " + String.Join("; ", kept.ToArray()) + "."); return; }
            bool elevated = Elevation.IsElevated;
            X509Location scope = elevated ? X509Location.LocalMachine : X509Location.CurrentUser;
            List<string> done = new List<string>(), problems = new List<string>(kept);

            List<CertificateRecord> blocked = WithTwins(ok).Where(snapshot.IsBlocked).ToList();
            if (blocked.Count > 0) done.Add("Unblocked for good. " + LiftForGood(blocked, "trusted from the live map", "trusted from the live map"));

            // The root itself, or the self-signed copy of a cross-signed CA's key (DigiCert Trusted Root G4 sent cross-signed, say).
            List<CertificateRecord> upRoots = new List<CertificateRecord>(), upCas = new List<CertificateRecord>();
            if (snapshot.Paths != null) foreach (CertificateRecord c in ok.Where(x => x.Subject != x.Issuer)) Up(snapshot.Paths, c, upRoots, upCas, 0); foreach (CertificateRecord c in ok.Where(x => x.Subject != x.Issuer)) RootsAbove(c, upRoots, 0);
            List<CertificateRecord> roots = Guarded(WithTwins(ok).Concat(upRoots).Where(x => x.Subject == x.Issuer && x.Der != null && !TrustGraph.InRootStore(x)), problems);
            foreach (CertificateRecord c in roots.GroupBy(x => x.Sha1).Select(g => g.First()))
            {
                try
                {
                    if (elevated) { using (OwnStore root = OwnStore.Open("Root", X509Location.LocalMachine, true)) root.Add(c.Der); }
                    else using (X509Store store = new X509Store(StoreName.Root, X509Location.CurrentUser)) { store.Open(OpenFlags.ReadWrite); store.Add(new X509Certificate2(c.Der)); }
                    BlockEngine.Note("trust-from-map", scope, c.Sha256, c.Sha1, c.SubjectShortName, "trusted from the live map");
                    done.Add("Put " + c.SubjectShortName + " into Trusted Root.");
                }
                catch (Exception ex) { problems.Add(c.SubjectShortName + ": " + ex.Message); }
            }

            List<CertificateRecord> cas = ok.Concat(Guarded(upCas, problems)).Where(x => x.Subject != x.Issuer && x.Der != null && IsCa(x.Der) && !TrustGraph.OnPcForPath(x)).GroupBy(x => x.Sha1).Select(g => g.First()).ToList();
            if (cas.Count > 0)
                try
                {
                    RouteStore.Install(cas, scope, "trusted from the live map");
                    done.Add("Put " + String.Join(", ", cas.Select(x => x.SubjectShortName).Distinct().ToArray()) + " into Intermediate CAs.");
                }
                catch (Exception ex) { problems.Add("Intermediate CAs: " + ex.Message); }

            // Yours now: bloc rules won't block it again.
            try { AllowedList.AddRange(ok, "trusted from the live map"); } catch (IOException) { }
            if (done.Count == 0) done.Add(n.Label + " is already trusted on this PC.");
            n.Flipped = true; n.Refused = false;
            if (liveMap != null) liveMap.Repaint();
            Say("✅ " + n.Label + " trusted" + (elevated ? " (whole PC)" : " (your account; run kisib as administrator so installers and services trust it too)") + ". " +
                String.Join(" ", done.ToArray()) + (problems.Count > 0 ? " " + String.Join("; ", problems.ToArray()) + "." : ""));
            StartScan();
        }

        // Up the chain to a root: the roots above that aren't trusted here, and the CAs on the way that aren't on this PC.
        // Stops where a root is already in Trusted Root (that path works, nothing to add).
        private static bool Up(TrustGraph g, CertificateRecord c, List<CertificateRecord> roots, List<CertificateRecord> cas, int depth)
        {
            List<string> keys;
            if (depth > 8 || !g.IssuerKeys.TryGetValue(c.Identity, out keys)) return false;
            List<CertificateRecord> foundRoots = new List<CertificateRecord>(), foundCas = new List<CertificateRecord>();
            foreach (string k in keys)
            {
                List<CertificateRecord> parents;
                if (!g.ByKey.TryGetValue(k, out parents)) continue;
                foreach (CertificateRecord p in parents)
                {
                    if (g.SelfSigned.Contains(p.Identity)) { if (TrustGraph.InRootStore(p)) return true; foundRoots.Add(p); continue; }
                    if (p.Identity == c.Identity) continue;
                    List<CertificateRecord> branchRoots = new List<CertificateRecord>(), branchCas = new List<CertificateRecord>();
                    if (!TrustGraph.OnPcForPath(p)) branchCas.Add(p);
                    if (Up(g, p, branchRoots, branchCas, depth + 1)) { cas.AddRange(branchCas); return true; }
                    foundRoots.AddRange(branchRoots); foundCas.AddRange(branchCas);
                }
            }
            roots.AddRange(foundRoots); cas.AddRange(foundCas);
            return false;
        }

        internal void DistrustFromMap(MapNode n, List<CertificateRecord> certs)
        {
            if (n.Blocked) { Say(n.Label + " is already untrusted (blocked)."); return; }
            n.Flipped = false;
            ShowBlockDialog(certs, delegate { return "blocked from the live map"; }, "certificate " + n.Label, null);
        }
    }
}
