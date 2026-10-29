using System;
using System.Collections.Generic;
using System.Linq;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;
using System.Windows.Forms;

namespace Kisib
{
    // Block lighter. A CA whose every issuer is a blocked root (or sits under one) is already dead, so it doesn't need
    // its own Untrusted Certificates entry: thousands of those entries slow every certificate check a program makes.
    // Only root keys count as blocked here, every self-signed root counts as a possible anchor (on Windows' list or
    // not), and a CA whose issuer kisib can't place is always kept, so this never opens a path a block was closing.
    internal static class LightBlock
    {
        internal sealed class Cut { internal HashSet<string> RootKeys, LiveKeys; }

        internal static Cut Compute(TrustGraph g, IEnumerable<CertificateRecord> blockedOrPlanned)
        {
            List<CertificateRecord> list = blockedOrPlanned.Where(c => c != null && c.SpkiSha256 != null).ToList();
            HashSet<string> rootKeys = new HashSet<string>(list.Where(c => g.SelfSigned.Contains(c.Identity)).Select(c => c.SpkiSha256), StringComparer.Ordinal);
            HashSet<string> dead = new HashSet<string>(list.Where(c => rootKeys.Contains(c.SpkiSha256)).Select(c => c.Identity), StringComparer.Ordinal);
            HashSet<string> live = new HashSet<string>(StringComparer.Ordinal);
            Queue<string> queue = new Queue<string>();
            foreach (KeyValuePair<string, List<CertificateRecord>> k in g.ByKey)
                foreach (CertificateRecord c in k.Value)
                    if (!dead.Contains(c.Identity) && (g.SelfSigned.Contains(c.Identity) || !g.IssuerKeys.ContainsKey(c.Identity)) && live.Add(k.Key)) queue.Enqueue(k.Key);
            while (queue.Count > 0)
            {
                List<CertificateRecord> kids;
                if (!g.Children.TryGetValue(queue.Dequeue(), out kids)) continue;
                foreach (CertificateRecord c in kids)
                    if (!dead.Contains(c.Identity) && live.Add(c.SpkiSha256)) queue.Enqueue(c.SpkiSha256);
            }
            return new Cut { RootKeys = rootKeys, LiveKeys = live };
        }

        // Worth its own entry: a root or a copy of a blocked root's key, anything kisib can't place, or a CA that can still reach a root.
        internal static bool Needed(TrustGraph g, Cut cut, CertificateRecord c)
        {
            if (c == null || c.SpkiSha256 == null || !g.ByKey.ContainsKey(c.SpkiSha256)) return true;
            return g.SelfSigned.Contains(c.Identity) || cut.RootKeys.Contains(c.SpkiSha256) || cut.LiveKeys.Contains(c.SpkiSha256);
        }

        internal static IEnumerable<CertificateRecord> Records(Snapshot s, IEnumerable<string> identities)
        {
            foreach (string id in identities)
            {
                CertificateRecord c;
                if (s.Certificates.TryGetValue(id, out c)) yield return c;
            }
        }

        // What applies to a scope: the whole PC's Disallowed covers every account too.
        internal static IEnumerable<string> BlockedFor(Snapshot s, X509Location scope)
        {
            HashSet<string> here = s.BlockedIn(BlockEngine.ScopePrefix(scope));
            return scope == X509Location.CurrentUser ? here.Concat(s.BlockedIn("LOCAL_MACHINE")).Distinct() : here;
        }

        // SHA-256s kisib itself added to this scope's Disallowed and hasn't taken out.
        internal static HashSet<string> AddedIn(X509Location scope)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string name = scope.ToString();
            foreach (BlockLogRow r in BlockEngine.ReadLog().Where(x => x.Scope == name && x.Sha256 != null))
            {
                if (r.Action == "block" && r.Result == "added") set.Add(r.Sha256);
                else if (r.Action == "unblock" && r.Result == "removed") set.Remove(r.Sha256);
            }
            return set;
        }

        // Takes kisib's own spare entries back out: CAs under a blocked root that have no other way up.
        internal static int Lighten(Snapshot s, RuleOutcome o)
        {
            TrustGraph g = s.Paths;
            if (g == null) return 0;
            int removed = 0;
            foreach (X509Location scope in new X509Location[] { X509Location.CurrentUser, X509Location.LocalMachine })
            {
                if (scope == X509Location.LocalMachine && !Elevation.IsElevated) continue;
                HashSet<string> here = s.BlockedIn(BlockEngine.ScopePrefix(scope));
                if (here.Count == 0) continue;
                HashSet<string> mine;
                try { mine = AddedIn(scope); } catch (Exception) { continue; }
                if (mine.Count == 0) continue;
                Cut cut = Compute(g, Records(s, BlockedFor(s, scope)));
                List<string> spare = Records(s, here).Where(c => c.Sha256 != null && mine.Contains(c.Sha256) && !Needed(g, cut, c)).Select(c => c.Sha256).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (spare.Count == 0) continue;
                try { removed += BlockEngine.Unblock(spare, scope, "lighter: under a blocked root, already dead").Count(r => r.Result == "removed"); }
                catch (Exception ex) { o.Log.Add(DateTime.UtcNow.ToString("o") + "\tLighter failed\t" + scope + "\t" + ex.Message); }
            }
            return removed;
        }
    }
}
