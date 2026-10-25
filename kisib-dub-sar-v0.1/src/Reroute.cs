using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Cross-signs: one CA key can sit under more than one root. Windows builds a chain from the site's certificate
    // upward and uses a path whose root is trusted and where nothing is in Disallowed. This rebuilds those paths
    // offline from the stores, the Microsoft list and CCADB, matching issuers by name and key ID the way Windows does.
    // LEAK = a blocked CA that still has a path. Rerouted = a CA under a blocked one that still reaches another root.
    internal sealed class TrustGraph
    {
        internal readonly Dictionary<string, List<CertificateRecord>> ByKey = new Dictionary<string, List<CertificateRecord>>(StringComparer.Ordinal);
        internal readonly Dictionary<string, List<string>> IssuerKeys = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        internal readonly Dictionary<string, List<CertificateRecord>> Children = new Dictionary<string, List<CertificateRecord>>(StringComparer.Ordinal);
        internal readonly HashSet<string> SelfSigned = new HashSet<string>(StringComparer.Ordinal);
        internal readonly HashSet<string> Anchors = new HashSet<string>(StringComparer.Ordinal);

        internal static TrustGraph Build(Snapshot snapshot)
        {
            TrustGraph g = new TrustGraph();
            Dictionary<string, string> ski = new Dictionary<string, string>(StringComparer.Ordinal), aki = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, List<CertificateRecord>> bySubject = new Dictionary<string, List<CertificateRecord>>(StringComparer.OrdinalIgnoreCase);
            List<CertificateRecord> all = snapshot.Certificates.Values.Where(c => c.Der != null && c.SpkiSha256 != null && c.ParseError == null)
                .OrderBy(c => OnPcForPath(c) ? 0 : 1).ToList();
            foreach (CertificateRecord c in all)
            {
                string s, a;
                KeyIds(c.Der, out s, out a);
                if (s != null) ski[c.Identity] = s;
                if (a != null) aki[c.Identity] = a;
                Add(g.ByKey, c.SpkiSha256, c);
                Add(bySubject, c.Subject, c);
            }
            foreach (CertificateRecord c in all)
            {
                string a, s;
                aki.TryGetValue(c.Identity, out a);
                ski.TryGetValue(c.Identity, out s);
                if (String.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase) && (a == null || s == null || a == s))
                {
                    g.SelfSigned.Add(c.Identity);
                    if (InRootStore(c) || c.FoundIn.Contains(MicrosoftList.Label)) g.Anchors.Add(c.Identity);
                    continue;
                }
                List<CertificateRecord> candidates;
                if (!bySubject.TryGetValue(c.Issuer, out candidates)) continue;
                List<string> keys = candidates.Where(p =>
                {
                    string ps;
                    return a == null || (ski.TryGetValue(p.Identity, out ps) && ps == a);
                }).Select(p => p.SpkiSha256).Where(k => k != c.SpkiSha256).Distinct(StringComparer.Ordinal).ToList();
                if (keys.Count == 0) continue;
                g.IssuerKeys[c.Identity] = keys;
                foreach (string k in keys) Add(g.Children, k, c);
            }
            return g;
        }

        private static void Add(Dictionary<string, List<CertificateRecord>> map, string key, CertificateRecord c)
        {
            List<CertificateRecord> list;
            if (!map.TryGetValue(key, out list)) { list = new List<CertificateRecord>(); map.Add(key, list); }
            list.Add(c);
        }

        private static void KeyIds(byte[] der, out string ski, out string aki)
        {
            ski = null; aki = null;
            try
            {
                using (X509Certificate2 cert = new X509Certificate2(der))
                    foreach (X509Extension e in cert.Extensions)
                    {
                        if (e.Oid == null) continue;
                        if (e.Oid.Value == "2.5.29.14") ski = new X509SubjectKeyIdentifierExtension(e, e.Critical).SubjectKeyIdentifier;
                        else if (e.Oid.Value == "2.5.29.35") aki = AuthorityKeyId(e.RawData);
                    }
            }
            catch (Exception) { }
            if (ski != null) ski = ski.ToUpperInvariant();
        }

        // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
        private static string AuthorityKeyId(byte[] d)
        {
            try
            {
                int i = 0;
                if (d == null || d.Length < 2 || d[i++] != 0x30) return null;
                int end = Length(d, ref i);
                end += i;
                while (i < end && i < d.Length)
                {
                    byte tag = d[i++];
                    int len = Length(d, ref i);
                    if (tag == 0x80) return BitConverter.ToString(d, i, len).Replace("-", "");
                    i += len;
                }
            }
            catch (IndexOutOfRangeException) { }
            catch (ArgumentException) { }
            return null;
        }
        private static int Length(byte[] d, ref int i)
        {
            int b = d[i++];
            if (b < 0x80) return b;
            int n = b & 0x7F, v = 0;
            for (int k = 0; k < n; k++) v = (v << 8) | d[i++];
            return v;
        }

        internal static bool InRootStore(CertificateRecord c)
        {
            return c.FoundIn.Concat(c.Collections).Any(p => p.IndexOf("\\Root\\", StringComparison.OrdinalIgnoreCase) >= 0 || p.EndsWith("\\Root", StringComparison.OrdinalIgnoreCase) ||
                p.IndexOf("\\AuthRoot", StringComparison.OrdinalIgnoreCase) >= 0);
        }
        // Where Windows looks for issuers on its own: Root and Intermediate Certification Authorities (CA).
        internal static bool OnPcForPath(CertificateRecord c)
        {
            return InRootStore(c) || c.FoundIn.Concat(c.Collections).Any(p => p.IndexOf("\\CA\\", StringComparison.OrdinalIgnoreCase) >= 0 || p.EndsWith("\\CA", StringComparison.OrdinalIgnoreCase));
        }
        internal static bool Live(CertificateRecord c, DateTime now)
        { return (!c.NotAfter.HasValue || c.NotAfter.Value > now) && (!c.NotBefore.HasValue || c.NotBefore.Value <= now); }

        internal Reach Compute(HashSet<string> blocked)
        {
            DateTime now = DateTime.UtcNow;
            Reach r = new Reach();
            Queue<string> queue = new Queue<string>();
            foreach (KeyValuePair<string, List<CertificateRecord>> k in ByKey)
                foreach (CertificateRecord c in k.Value)
                    if (Anchors.Contains(c.Identity) && !blocked.Contains(c.Identity) && Live(c, now) && !r.Via.ContainsKey(k.Key))
                    { r.Via[k.Key] = c; r.Up[k.Key] = null; queue.Enqueue(k.Key); }
            while (queue.Count > 0)
            {
                string key = queue.Dequeue();
                List<CertificateRecord> kids;
                if (!Children.TryGetValue(key, out kids)) continue;
                foreach (CertificateRecord c in kids)
                    if (!r.Via.ContainsKey(c.SpkiSha256) && !blocked.Contains(c.Identity) && Live(c, now))
                    { r.Via[c.SpkiSha256] = c; r.Up[c.SpkiSha256] = key; queue.Enqueue(c.SpkiSha256); }
            }
            return r;
        }

        // From the CA's own certificate up to the trusted root.
        internal List<CertificateRecord> Path(Reach r, string key)
        {
            List<CertificateRecord> hops = new List<CertificateRecord>();
            for (int i = 0; i < 16 && key != null && r.Via.ContainsKey(key); i++) { hops.Add(r.Via[key]); key = r.Up[key]; }
            return hops;
        }

        // Certificates on a path that Windows cannot find by itself (only in CCADB): Install route adds them.
        internal List<CertificateRecord> Missing(List<CertificateRecord> path)
        {
            return path == null ? new List<CertificateRecord>() : path.Where(h => !Anchors.Contains(h.Identity) && !OnPcForPath(h)).ToList();
        }

        internal HashSet<string> KeysOf(HashSet<string> identities)
        {
            return new HashSet<string>(ByKey.Where(k => k.Value.Any(c => identities.Contains(c.Identity))).Select(k => k.Key), StringComparer.Ordinal);
        }

        internal CertificateRecord Representative(string key, HashSet<string> blocked)
        {
            List<CertificateRecord> same;
            if (!ByKey.TryGetValue(key, out same) || same.Count == 0) return null;
            return same.OrderBy(c => Anchors.Contains(c.Identity) ? 0 : SelfSigned.Contains(c.Identity) ? 1 : 2)
                .ThenBy(c => OnPcForPath(c) || blocked.Contains(c.Identity) ? 0 : 1).First();
        }

        internal List<RerouteRow> Analyze(HashSet<string> blocked, Reach r)
        {
            DateTime now = DateTime.UtcNow;
            HashSet<string> blockedKeys = KeysOf(blocked);
            List<RerouteRow> rows = new List<RerouteRow>();
            List<RerouteRow> cas = blockedKeys.Select(k => new RerouteRow { Key = k, Cert = Representative(k, blocked), Kind = r.Has(k) ? "LEAK" : "holds" })
                .Where(x => x.Cert != null).OrderBy(x => x.Kind == "LEAK" ? 0 : 1).ThenBy(x => x.Cert.SubjectShortName, StringComparer.OrdinalIgnoreCase).ToList();
            foreach (RerouteRow ca in cas)
            {
                if (ca.Kind == "LEAK") { ca.Path = Path(r, ca.Key); ca.Missing = Missing(ca.Path); }
                rows.Add(ca);
                List<CertificateRecord> kids;
                if (!Children.TryGetValue(ca.Key, out kids)) continue;
                List<RerouteRow> under = new List<RerouteRow>();
                foreach (IGrouping<string, CertificateRecord> child in kids.Where(c => !blockedKeys.Contains(c.SpkiSha256) && Live(c, now)).GroupBy(c => c.SpkiSha256))
                {
                    RerouteRow row = new RerouteRow { Key = child.Key, Cert = Representative(child.Key, blocked), Parent = ca };
                    if (!r.Has(child.Key)) row.Kind = "cut off";
                    else
                    {
                        row.Path = Path(r, child.Key);
                        row.Missing = Missing(row.Path);
                        row.Kind = row.Path.Any(h => blockedKeys.Contains(h.SpkiSha256)) ? "via leak" : "rerouted";
                    }
                    under.Add(row);
                }
                rows.AddRange(under.OrderBy(x => x.Kind == "rerouted" ? 0 : x.Kind == "via leak" ? 1 : 2).ThenBy(x => x.Cert.SubjectShortName, StringComparer.OrdinalIgnoreCase));
            }
            return rows;
        }

        internal static string Name(CertificateRecord c)
        { return c == null ? "—" : c.SubjectShortName + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : ""); }

        internal static string PathText(List<CertificateRecord> hops)
        {
            if (hops == null || hops.Count == 0) return "no path to a trusted root";
            StringBuilder t = new StringBuilder();
            for (int i = 0; i < hops.Count; i++) t.Append(i == 0 ? "" : " → signed by ").Append(Name(hops[i]));
            t.Append(InRootStore(hops[hops.Count - 1]) ? "  [trusted root on this PC]" : "  [trusted root on Microsoft's list; Windows downloads it when needed]");
            return t.ToString();
        }
    }

    internal sealed class Reach
    {
        internal readonly Dictionary<string, CertificateRecord> Via = new Dictionary<string, CertificateRecord>(StringComparer.Ordinal);
        internal readonly Dictionary<string, string> Up = new Dictionary<string, string>(StringComparer.Ordinal);
        internal bool Has(string key) { return key != null && Via.ContainsKey(key); }
    }

    internal sealed class RerouteRow
    {
        internal string Kind, Key;          // LEAK | holds | rerouted | via leak | cut off
        internal CertificateRecord Cert;
        internal RerouteRow Parent;         // the blocked CA this one sits under
        internal List<CertificateRecord> Path;
        internal List<CertificateRecord> Missing = new List<CertificateRecord>();
        internal bool ByKisib;
    }

    // Cross-signed certificates kisib added to Intermediate Certification Authorities so Windows can build the other
    // path. Never a root, never an unblock. Kept in a portable .txt and put back after a reformat.
    internal static class RouteStore
    {
        private const string Header = "scope,sha1,sha256,subject,added_utc,certificate_base64";
        internal static string FilePath { get { return Storage.File(Storage.RouteList); } }

        internal static List<string[]> Read()
        {
            return System.IO.File.Exists(FilePath) ? GroupCatalog.ReadCsv(FilePath, 64L * 1024 * 1024).Skip(1).Where(f => f.Length >= 6).ToList() : new List<string[]>();
        }
        private static void Write(List<string[]> rows)
        {
            StringBuilder text = new StringBuilder(Header).Append("\r\n");
            foreach (string[] r in rows) text.Append(String.Join(",", r.Select(Q).ToArray())).Append("\r\n");
            System.IO.File.WriteAllText(FilePath, text.ToString(), new UTF8Encoding(false));
        }
        private static string Q(string v) { v = v ?? ""; return v.IndexOfAny(new char[] { ',', '"' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        internal static List<string> Install(List<CertificateRecord> certs, X509Location scope)
        {
            List<string> report = new List<string>();
            List<string[]> rows = Read();
            using (X509Store store = new X509Store(StoreName.CertificateAuthority, scope))
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (CertificateRecord c in certs)
                {
                    try
                    {
                        using (X509Certificate2 cert = new X509Certificate2(c.Der))
                        {
                            if (store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0) { report.Add("already there  " + scope + "\\CA  " + c.SubjectShortName); continue; }
                            store.Add(cert);
                            rows.RemoveAll(r => r[0] == scope.ToString() && String.Equals(r[1], c.Sha1, StringComparison.OrdinalIgnoreCase));
                            rows.Add(new string[] { scope.ToString(), c.Sha1, c.Sha256, c.SubjectShortName, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), Convert.ToBase64String(c.Der) });
                            BlockEngine.Note("route", scope, c.Sha256, c.Sha1, c.SubjectShortName, "cross-sign added to Intermediate Certification Authorities");
                            report.Add("added  " + scope + "\\CA  " + c.SubjectShortName + "  issued by " + c.IssuerShortName + "  " + c.Sha1);
                        }
                    }
                    catch (Exception ex) { report.Add("error  " + c.SubjectShortName + ": " + ex.GetType().Name + ": " + ex.Message); }
                }
            }
            Write(rows);
            return report;
        }

        // Removes only what kisib added (listed in the routes file).
        internal static List<string> Remove(List<string[]> which)
        {
            List<string> report = new List<string>();
            List<string[]> rows = Read();
            foreach (IGrouping<string, string[]> scopeRows in which.GroupBy(r => r[0]))
            {
                X509Location scope;
                try { scope = (X509Location)Enum.Parse(typeof(X509Location), scopeRows.Key); } catch (ArgumentException) { continue; }
                try
                {
                    using (X509Store store = new X509Store(StoreName.CertificateAuthority, scope))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        foreach (string[] r in scopeRows)
                        {
                            X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, r[1], false);
                            foreach (X509Certificate2 cert in found) store.Remove(cert);
                            rows.RemoveAll(x => x[0] == r[0] && String.Equals(x[1], r[1], StringComparison.OrdinalIgnoreCase));
                            BlockEngine.Note("route removed", scope, r[2], r[1], r[3], "kisib route taken out of Intermediate Certification Authorities");
                            report.Add((found.Count > 0 ? "removed  " : "already gone  ") + scope + "\\CA  " + r[3]);
                        }
                    }
                }
                catch (Exception ex) { report.Add("error  " + scopeRows.Key + ": " + ex.GetType().Name + ": " + ex.Message + (scope == X509Location.LocalMachine ? " (whole-PC routes need kisib run as administrator)" : "")); }
            }
            Write(rows);
            return report;
        }

        internal static int Reapply(out string skipped)
        {
            skipped = null;
            List<string[]> rows;
            try { rows = Read(); } catch (Exception) { return 0; }
            int restored = 0;
            bool elevated = BlockEngine.IsElevated();
            foreach (IGrouping<string, string[]> scopeRows in rows.GroupBy(r => r[0]))
            {
                X509Location scope;
                try { scope = (X509Location)Enum.Parse(typeof(X509Location), scopeRows.Key); } catch (ArgumentException) { continue; }
                if (scope == X509Location.LocalMachine && !elevated) { skipped = "Whole-PC routes need kisib run as administrator to re-apply."; continue; }
                try
                {
                    using (X509Store store = new X509Store(StoreName.CertificateAuthority, scope))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        foreach (string[] r in scopeRows)
                        {
                            if (store.Certificates.Find(X509FindType.FindByThumbprint, r[1], false).Count > 0) continue;
                            try
                            {
                                using (X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(r[5]))) store.Add(cert);
                                restored++;
                                BlockEngine.Note("route re-apply", scope, r[2], r[1], r[3], "re-applied from " + Storage.RouteList);
                            }
                            catch (Exception) { }
                        }
                    }
                }
                catch (Exception) { }
            }
            return restored;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private Snapshot pathsFor;
        private Reach pathsReach;
        private HashSet<string> pathsBlocked = new HashSet<string>(StringComparer.Ordinal), pathsBlockedKeys = new HashSet<string>(StringComparer.Ordinal);

        private void InitializeReroute(MenuItem tools, FlowLayoutPanel toolbar)
        {
            tools.MenuItems.Add("-");
            tools.MenuItems.Add(new MenuItem("&Reroute check (cross-signs: leaks and other ways in)...", delegate { ShowReroute(); }, Shortcut.CtrlR));
            tools.MenuItems.Add(new MenuItem("Routes kisib &installed...", delegate { ShowRoutes(); }));
            Button button = new Button { Text = "Reroute check", AutoSize = true };
            button.Click += delegate { ShowReroute(); };
            toolbar.Controls.Add(button);
            Shown += delegate
            {
                string skipped;
                int restored = RouteStore.Reapply(out skipped);
                if (restored > 0)
                {
                    if (tray != null) tray.ShowBalloonTip(6000, "kisib: routes re-applied", restored + " cross-signed certificates were missing and have been put back.", ToolTipIcon.Info);
                    StartScan();
                }
            };
        }

        // Paths with the blocks as they are now. Rebuilt once per scan.
        private Reach PathsNow()
        {
            if (snapshot == null || snapshot.Paths == null) return null;
            if (pathsFor != snapshot)
            {
                pathsBlocked = GroupCatalog.BlockedIdentities(snapshot);
                pathsBlockedKeys = snapshot.Paths.KeysOf(pathsBlocked);
                pathsReach = snapshot.Paths.Compute(pathsBlocked);
                pathsFor = snapshot;
            }
            return pathsReach;
        }

        private static string OwnerName(CertificateRecord c)
        {
            if (c == null) return "—";
            return WhoIsWho.Owner(c) ?? Ccadb.OwnerOf(c.Identity) ?? c.SubjectOrganization ?? "—";
        }

        // " · LEAK" / " · rerouted" / " · via leak" / " · cut off" for the Status column.
        internal string RouteNote(CertificateRecord c)
        {
            Reach r = PathsNow();
            if (r == null || c.SpkiSha256 == null) return "";
            TrustGraph g = snapshot.Paths;
            if (pathsBlockedKeys.Contains(c.SpkiSha256)) return r.Has(c.SpkiSha256) ? " · LEAK" : "";
            List<string> up;
            if (!g.IssuerKeys.TryGetValue(c.Identity, out up) || !up.Any(pathsBlockedKeys.Contains)) return "";
            if (!r.Has(c.SpkiSha256)) return " · cut off";
            return g.Path(r, c.SpkiSha256).Any(h => pathsBlockedKeys.Contains(h.SpkiSha256)) ? " · via leak" : " · rerouted";
        }

        // One line for the certificate card.
        internal string PathSummary(CertificateRecord c)
        {
            Reach r = PathsNow();
            if (r == null || c.SpkiSha256 == null) return "— (after a scan)";
            List<CertificateRecord> p = snapshot.Paths.Path(r, c.SpkiSha256);
            bool blockedKey = pathsBlockedKeys.Contains(c.SpkiSha256);
            if (p.Count == 0) return blockedKey ? "none (blocked; the block holds)" : "none (cut off, or not under a trusted root)";
            List<CertificateRecord> missing = snapshot.Paths.Missing(p);
            return (blockedKey ? "LEAK, still reachable: " : "") + TrustGraph.PathText(p) + (missing.Count > 0 ? "  (needs Install route: " + missing.Count + " only in CCADB)" : "");
        }

        internal int LeakCount()
        {
            Reach r = PathsNow();
            if (r == null) return 0;
            HashSet<string> mine = BlockEngine.KisibBlockedSha1();
            return pathsBlockedKeys.Count(k => r.Has(k) && snapshot.Paths.ByKey[k].Any(c => pathsBlocked.Contains(c.Identity) && mine.Contains(c.Sha1)));
        }

        // Everything about one CA key: every certificate carrying it, where each one hangs, and the CAs under it.
        internal string PathsReport(CertificateRecord c)
        {
            Reach r = PathsNow();
            if (r == null) return "Paths are built after a scan finishes. Press F5, wait, and try again.";
            TrustGraph g = snapshot.Paths;
            DateTime now = DateTime.UtcNow;
            StringBuilder t = new StringBuilder();
            string key = c.SpkiSha256;
            t.AppendLine(TrustGraph.Name(c) + "  —  owner: " + OwnerName(c));
            t.AppendLine("Key (SPKI SHA-256): " + (key ?? "—"));
            List<CertificateRecord> same;
            if (key == null || !g.ByKey.TryGetValue(key, out same)) same = new List<CertificateRecord> { c };
            int blockedCount = same.Count(x => pathsBlocked.Contains(x.Identity));
            t.AppendLine("Blocked: " + (blockedCount == 0 ? "no" : blockedCount + " of " + same.Count + " certificates with this key are in Disallowed"));
            List<CertificateRecord> path = key == null ? new List<CertificateRecord>() : g.Path(r, key);
            t.AppendLine("Path Windows can use now: " + (path.Count > 0 ? TrustGraph.PathText(path) : "none"));
            if (blockedCount > 0 && path.Count > 0)
                t.AppendLine("  LEAK: this CA is blocked but still has a way in. Fix: Tools > Reroute check, right-click it > Block the leak.");
            List<CertificateRecord> missing = g.Missing(path);
            if (missing.Count > 0) t.AppendLine("  Not on this PC: " + String.Join(", ", missing.Select(TrustGraph.Name).ToArray()) + " (only in CCADB; Install route adds it so Windows can find this path)");
            t.AppendLine();
            t.AppendLine("Every certificate carrying this key (" + same.Count + "):");
            foreach (CertificateRecord x in same)
            {
                List<string> marks = new List<string>();
                if (g.Anchors.Contains(x.Identity)) marks.Add("TRUSTED ROOT");
                else if (g.SelfSigned.Contains(x.Identity)) marks.Add("self-signed, not a trusted root");
                if (pathsBlocked.Contains(x.Identity)) marks.Add("BLOCKED");
                if (!TrustGraph.Live(x, now)) marks.Add("expired or not yet valid");
                marks.Add(TrustGraph.OnPcForPath(x) ? "on this PC" : x.FoundIn.Contains(MicrosoftList.Label) ? "Microsoft list" : x.FoundIn.Contains(Ccadb.Label) ? "only in CCADB" : "found: " + x.FoundInText);
                List<string> up;
                if (!g.SelfSigned.Contains(x.Identity))
                    marks.Add(!g.IssuerKeys.TryGetValue(x.Identity, out up) ? "issuer not on this PC or in the lists" :
                        up.Any(r.Has) ? "issuer has a path" : "issuer has no path");
                t.AppendLine("  " + x.SubjectShortName + "  issued by " + TrustGraph.Name(new CertificateRecord { SubjectCn = x.IssuerCn, SubjectOrganization = x.IssuerOrganization, SubjectCountry = x.IssuerCountry }) +
                    "  until " + (x.NotAfter.HasValue ? x.NotAfter.Value.ToString("yyyy-MM-dd") : "?") + "  [" + String.Join("; ", marks.ToArray()) + "]  SHA-1 " + x.Sha1);
            }
            List<CertificateRecord> kids;
            if (key != null && g.Children.TryGetValue(key, out kids))
            {
                List<IGrouping<string, CertificateRecord>> under = kids.Where(k => TrustGraph.Live(k, now)).GroupBy(k => k.SpkiSha256).ToList();
                t.AppendLine();
                t.AppendLine("CAs signed by this key (" + under.Count + "):");
                foreach (IGrouping<string, CertificateRecord> u in under.Take(400))
                {
                    CertificateRecord rep = g.Representative(u.Key, pathsBlocked);
                    string state;
                    if (pathsBlockedKeys.Contains(u.Key)) state = r.Has(u.Key) ? "blocked too, but LEAK" : "blocked too";
                    else if (!r.Has(u.Key)) state = "cut off";
                    else
                    {
                        List<CertificateRecord> p = g.Path(r, u.Key);
                        state = (p.Any(h => pathsBlockedKeys.Contains(h.SpkiSha256)) ? "via a leak: " : "rerouted: ") + TrustGraph.PathText(p);
                    }
                    t.AppendLine("  " + TrustGraph.Name(rep) + "  —  " + state);
                }
                if (under.Count > 400) t.AppendLine("  +" + (under.Count - 400) + " more");
            }
            t.AppendLine();
            t.AppendLine("Built offline from this PC's stores, the Microsoft list (" + (MicrosoftList.Updated.HasValue ? MicrosoftList.Updated.Value.ToString("yyyy-MM-dd") : "not loaded") +
                ") and CCADB (" + (Ccadb.Updated.HasValue ? Ccadb.Updated.Value.ToString("yyyy-MM-dd") : "not loaded") + "), matching issuers by name and key ID the way Windows does.");
            t.AppendLine("Windows picks the path itself; it can only take one it can find (on this PC, or sent by the site) [to test].");
            return t.ToString();
        }

        internal sealed class WhatIf
        {
            internal List<string> Leaks = new List<string>(), Cut = new List<string>(), Rerouted = new List<string>();
            internal Reach After;
            internal HashSet<string> AfterBlocked;
        }

        // CA keys a block would leave leaking, cut off, or rerouted through another root.
        internal WhatIf RerouteKeys(IEnumerable<CertificateRecord> adding)
        {
            Reach before = PathsNow();
            List<CertificateRecord> add = adding.Where(c => c != null).ToList();
            if (before == null || add.Count == 0) return null;
            TrustGraph g = snapshot.Paths;
            WhatIf w = new WhatIf { AfterBlocked = new HashSet<string>(pathsBlocked, StringComparer.Ordinal) };
            foreach (CertificateRecord c in add) w.AfterBlocked.Add(c.Identity);
            w.After = g.Compute(w.AfterBlocked);
            HashSet<string> addKeys = new HashSet<string>(add.Where(c => c.SpkiSha256 != null).Select(c => c.SpkiSha256), StringComparer.Ordinal);
            w.Leaks = addKeys.Where(w.After.Has).ToList();
            w.Cut = before.Via.Keys.Where(k => !addKeys.Contains(k) && !w.After.Has(k)).ToList();
            w.Rerouted = before.Via.Keys.Where(k => !addKeys.Contains(k) && w.After.Has(k) && g.Path(before, k).Any(h => addKeys.Contains(h.SpkiSha256))).ToList();
            return w;
        }

        // What a block would do to everything that hangs under it.
        internal string RerouteWhatIf(IEnumerable<CertificateRecord> adding, out string line)
        {
            line = "";
            WhatIf w = RerouteKeys(adding);
            if (w == null) return "";
            TrustGraph g = snapshot.Paths;
            HashSet<string> after = w.AfterBlocked;
            Reach afterReach = w.After;
            List<string> leaks = w.Leaks, cut = w.Cut, rerouted = w.Rerouted;
            line = "Cross-signs: " + cut.Count + " CAs under this lose every path (cut off); " + rerouted.Count + " stay reachable through another root" +
                (leaks.Count > 0 ? "; " + leaks.Count + " LEAK (still have a path after the block)" : "") + ".";
            StringBuilder t = new StringBuilder(line).Append("\r\n\r\n");
            Action<string, List<string>, Func<string, string>> section = delegate(string title, List<string> keys, Func<string, string> detail)
            {
                t.AppendLine(title + " (" + keys.Count + ")");
                foreach (string k in keys.Take(500)) t.AppendLine("  " + TrustGraph.Name(g.Representative(k, after)) + (detail == null ? "" : "  —  " + detail(k)));
                if (keys.Count > 500) t.AppendLine("  +" + (keys.Count - 500) + " more");
                t.AppendLine();
            };
            section("LEAK: blocked but still reachable", leaks, k => TrustGraph.PathText(g.Path(afterReach, k)));
            section("REROUTED: stay reachable through another root", rerouted, k => TrustGraph.PathText(g.Path(afterReach, k)));
            section("CUT OFF: lose every path", cut, null);
            return t.ToString();
        }

        // The other path for a refused chain: the lowest CA in the chain that still reaches a trusted root without a blocked CA.
        internal List<CertificateRecord> DenialRoute(Denial d, out List<CertificateRecord> missing)
        {
            missing = new List<CertificateRecord>();
            Reach r = PathsNow();
            if (r == null) return null;
            TrustGraph g = snapshot.Paths;
            List<CertificateRecord> chain = d.ChainSha1.Select(FindBySha1).Where(c => c != null && c.SpkiSha256 != null).ToList();
            if (chain.Count == 0) return null;
            CertificateRecord lowest = chain.FirstOrDefault(c => !chain.Any(x =>
            {
                List<string> up;
                return x != c && g.IssuerKeys.TryGetValue(x.Identity, out up) && up.Contains(c.SpkiSha256);
            })) ?? chain[0];
            List<CertificateRecord> path = g.Path(r, lowest.SpkiSha256);
            if (path.Count == 0 || path.Any(h => pathsBlockedKeys.Contains(h.SpkiSha256))) return null;
            missing = g.Missing(path);
            return path;
        }

        private void InstallRoute(List<CertificateRecord> certs, string label)
        {
            certs = certs.Where(c => c != null && c.Der != null).GroupBy(c => c.Sha1).Select(x => x.First()).ToList();
            if (certs.Count == 0) { ShowText("Install route", "Nothing to install: every certificate on this path is already on this PC."); return; }
            X509Location scope = BlockEngine.IsElevated() ? X509Location.LocalMachine : X509Location.CurrentUser;
            string names = String.Join("\r\n", certs.Select(c => "  " + c.SubjectShortName + "  issued by " + c.IssuerShortName + (c.IssuerCountry != null ? " (" + c.IssuerCountry + ")" : "")).ToArray());
            if (MessageBox.Show(this, "Add these cross-signed certificates to " + scope + "\\Intermediate Certification Authorities, so Windows can build the other path?\r\n\r\n" + names +
                "\r\n\r\nNo root is added and nothing is unblocked." + (scope == X509Location.CurrentUser ? "\r\nThis user only. Run kisib as administrator to do it for the whole PC (services like Windows Update)." : "") +
                "\r\nUndo: Tools > Routes kisib installed.", "Install route — " + label, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            List<string> report;
            try { report = RouteStore.Install(certs, scope); }
            catch (Exception ex) { ShowText("Install route", "Failed: " + ex.GetType().Name + ": " + ex.Message); return; }
            ShowText("Install route", String.Join("\r\n", report.ToArray()) + "\r\n\r\nSaved in " + RouteStore.FilePath + " (put back after a reformat).\r\nWindows should take this path on the next try [to test].");
            StartScan();
        }

        private void ShowRoutes()
        {
            Form dialog = new Form { Text = "Routes kisib installed (cross-signs in Intermediate Certification Authorities)", Size = new Size(1000, 420), Font = Font, StartPosition = FormStartPosition.CenterParent };
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Scope", "Certificate", "Added (UTC)", "SHA-1" }, new int[] { 110, 360, 200, 320 });
                Action fill = delegate
                {
                    grid.Items.Clear();
                    foreach (string[] r in RouteStore.Read()) grid.Items.Add(new ListViewItem(new string[] { r[0], r[3], r[4], r[1] }) { Tag = r });
                };
                fill();
                Label note = new Label { Dock = DockStyle.Bottom, Height = 34, Text = "Removing a route takes the cross-sign out again; Windows goes back to the blocked path for those sites.\r\nFile: " + RouteStore.FilePath };
                Button remove = new Button { Text = "Remove selected route", Dock = DockStyle.Bottom, Height = 30 };
                remove.Click += delegate
                {
                    if (grid.SelectedItems.Count == 0) return;
                    ShowText("Remove route", String.Join("\r\n", RouteStore.Remove(new List<string[]> { (string[])grid.SelectedItems[0].Tag }).ToArray()));
                    fill(); StartScan();
                };
                Button removeAll = new Button { Text = "Remove all routes", Dock = DockStyle.Bottom, Height = 30 };
                removeAll.Click += delegate
                {
                    List<string[]> all = RouteStore.Read();
                    if (all.Count == 0) return;
                    if (MessageBox.Show(dialog, "Take out all " + all.Count + " routes kisib installed?", "Remove all routes", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
                    ShowText("Remove routes", String.Join("\r\n", RouteStore.Remove(all).ToArray()));
                    fill(); StartScan();
                };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(remove); dialog.Controls.Add(removeAll); dialog.Controls.Add(close);
                dialog.CancelButton = close;
                ShowTool(dialog, "routes");
            }
        }

        private void ShowReroute()
        {
            Reach r = PathsNow();
            if (r == null) { ShowText("Reroute check", "The cross-sign map is built after a scan. Press F5, wait for it to finish, then try again."); return; }
            TrustGraph g = snapshot.Paths;
            HashSet<string> mine = BlockEngine.KisibBlockedSha1();
            List<RerouteRow> rows = g.Analyze(pathsBlocked, r);
            foreach (RerouteRow x in rows.Where(x => x.Parent == null))
                x.ByKisib = g.ByKey[x.Key].Any(c => pathsBlocked.Contains(c.Identity) && mine.Contains(c.Sha1));
            Func<RerouteRow, bool> byKisib = x => x.Parent == null ? x.ByKisib : x.Parent.ByKisib;
            int leaks = rows.Count(x => x.Kind == "LEAK"), leaksMine = rows.Count(x => x.Kind == "LEAK" && x.ByKisib), holds = rows.Count(x => x.Kind == "holds");
            int re = rows.Count(x => x.Kind == "rerouted"), ready = rows.Count(x => x.Kind == "rerouted" && x.Missing.Count == 0), viaLeak = rows.Count(x => x.Kind == "via leak");
            int cut = rows.Count(x => x.Kind == "cut off");
            string summary = (leaks + holds) + " blocked CAs: " + leaks + " LEAK (" + leaksMine + " of them blocked by kisib) still have a way in, so that block does not hold; " + holds + " hold.\r\n" +
                "Under them: " + re + " CAs still reachable through another root (rerouted: " + ready + " ready, " + (re - ready) + " need Install route), " +
                viaLeak + " reachable only through a leak, " + cut + " cut off.\r\n" +
                "Built offline from this PC's stores + Microsoft list (" + (MicrosoftList.Updated.HasValue ? MicrosoftList.Updated.Value.ToString("yyyy-MM-dd") : "NOT LOADED: Tools > Update Microsoft root list") +
                ") + CCADB (" + (Ccadb.Updated.HasValue ? Ccadb.Updated.Value.ToString("yyyy-MM-dd") : "NOT LOADED: Tools > Update CCADB list, needed to see cross-signs not on this PC") + ").\r\n" +
                "Windows picks the path itself and can only take one it can find (on this PC, or sent by the site) [to test]. LibreWolf/Firefox use their own list for web pages.";
            Action after = null;
            Form dialog = new Form { Text = "Reroute check — blocked CAs, leaks and the other ways in (cross-signs)", Size = new Size(1300, 680), Font = Font, StartPosition = FormStartPosition.CenterParent };
            {
                Label top = new Label { Dock = DockStyle.Top, Height = 76, Padding = new Padding(6, 4, 6, 0), Text = summary };
                FlowLayoutPanel filters = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 30, Padding = new Padding(4, 2, 4, 0) };
                CheckBox fLeak = new CheckBox { Text = "LEAK", Checked = true, AutoSize = true }, fHold = new CheckBox { Text = "blocked, holds", Checked = true, AutoSize = true };
                CheckBox fRe = new CheckBox { Text = "rerouted", Checked = true, AutoSize = true }, fCut = new CheckBox { Text = "cut off", Checked = true, AutoSize = true };
                CheckBox fMine = new CheckBox { Text = "only blocks kisib made", AutoSize = true };
                TextBox find = new TextBox { Width = 240 };
                filters.Controls.AddRange(new Control[] { new Label { Text = "Show:", AutoSize = true, Padding = new Padding(0, 5, 0, 0) }, fLeak, fHold, fRe, fCut, fMine,
                    new Label { Text = "   Find:", AutoSize = true, Padding = new Padding(0, 5, 0, 0) }, find });
                Dictionary<string, CheckBox> show = new Dictionary<string, CheckBox> { { "LEAK", fLeak }, { "holds", fHold }, { "rerouted", fRe }, { "via leak", fRe }, { "cut off", fCut } };
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Status", "CA", "C=", "Owner", "Under blocked CA", "Reachable through root", "Windows can find it", "Blocked by", "Path" },
                    new int[] { 130, 230, 40, 150, 210, 230, 190, 150, 900 });
                Func<RerouteRow, string[]> cells = delegate(RerouteRow x)
                {
                    CertificateRecord root = x.Path != null && x.Path.Count > 0 ? x.Path[x.Path.Count - 1] : null;
                    string word = x.Kind == "LEAK" ? "LEAK, still trusted" : x.Kind == "holds" ? "blocked, holds" : x.Kind == "rerouted" ? "↳ rerouted" : x.Kind == "via leak" ? "↳ via a leak" : "↳ cut off";
                    string findable = x.Path == null ? "—" : x.Missing.Count == 0 ? (TrustGraph.InRootStore(root) ? "yes, all on this PC" : "yes (root downloads on demand)") :
                        "no: " + x.Missing.Count + " only in CCADB → Install route";
                    return new string[] { word, x.Cert.SubjectShortName, x.Cert.SubjectCountry ?? "—", OwnerName(x.Cert), x.Parent == null ? "—" : TrustGraph.Name(x.Parent.Cert),
                        root == null ? "—" : TrustGraph.Name(root) + " — " + OwnerName(root), findable,
                        x.Parent == null ? (x.ByKisib ? "kisib" : "before kisib (Microsoft or earlier hardening)") : "—", x.Path == null ? "—" : TrustGraph.PathText(x.Path) };
                };
                Action fill = delegate
                {
                    string q = find.Text.Trim();
                    grid.BeginUpdate(); grid.Items.Clear();
                    foreach (RerouteRow x in rows)
                    {
                        if (!show[x.Kind].Checked || (fMine.Checked && !byKisib(x))) continue;
                        string[] c = cells(x);
                        if (q.Length > 0 && !c.Any(s => s.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                        ListViewItem item = new ListViewItem(c) { Tag = x };
                        item.ForeColor = x.Kind == "LEAK" ? Color.Firebrick : x.Kind == "rerouted" ? Color.DarkGreen : x.Kind == "via leak" ? Color.DarkOrange : x.Kind == "cut off" ? SystemColors.GrayText : SystemColors.WindowText;
                        grid.Items.Add(item);
                    }
                    grid.EndUpdate();
                };
                foreach (CheckBox box in new CheckBox[] { fLeak, fHold, fRe, fCut, fMine }) box.CheckedChanged += delegate { fill(); };
                find.TextChanged += delegate { fill(); };
                fill();

                // Right-click
                Func<RerouteRow> sel = delegate { return grid.SelectedItems.Count == 0 ? null : grid.SelectedItems[0].Tag as RerouteRow; };
                List<MenuItem> items = new List<MenuItem>();
                MenuItem paths = new MenuItem("All paths for this CA (every cross-sign, what hangs under it)...", delegate { RerouteRow x = sel(); if (x != null) ShowText("Paths — " + x.Cert.SubjectShortName, PathsReport(x.Cert)); });
                MenuItem install = new MenuItem("Install route (add the cross-sign so Windows can go around the block)...", delegate
                { RerouteRow x = sel(); if (x == null) return; List<CertificateRecord> m = x.Missing; string n = x.Cert.SubjectShortName; after = delegate { InstallRoute(m, n); }; dialog.Close(); });
                MenuItem blockLeak = new MenuItem("Block the leak (every certificate still carrying this key)...", delegate
                { RerouteRow x = sel(); if (x == null) return; after = BlockKeyAction(x.Key, x.Cert); dialog.Close(); });
                MenuItem blockToo = new MenuItem("Block this CA too...", delegate
                { RerouteRow x = sel(); if (x == null) return; after = BlockKeyAction(x.Key, x.Cert); dialog.Close(); });
                items.Add(paths); items.Add(install); items.Add(blockLeak); items.Add(blockToo);
                List<MenuItem> allowItems = new List<MenuItem>();
                foreach (int minutes in new int[] { 3, 10, 60 })
                {
                    int m = minutes;
                    MenuItem allow = new MenuItem("Allow this blocked CA for " + m + " minutes", delegate
                    {
                        RerouteRow x = sel(); if (x == null) return;
                        List<CertificateRecord> certs = g.ByKey[x.Key].Where(c => pathsBlocked.Contains(c.Identity)).ToList(); string n = x.Cert.SubjectShortName;
                        after = delegate { AllowTemporarily(certs, n, TimeSpan.FromMinutes(m), true); }; dialog.Close();
                    });
                    allowItems.Add(allow); items.Add(allow);
                }
                items.Add(new MenuItem("Open certificate card", delegate { RerouteRow x = sel(); if (x != null) ShowText("Certificate", CertificateCard(x.Cert)); }));
                items.Add(new MenuItem("Show in main list", delegate
                {
                    RerouteRow x = sel(); if (x == null) return;
                    string sha = x.Cert.Sha256;
                    after = delegate { leftTabs.SelectedTab = storesTab; if (tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0]; findIssuer.Text = sha; };
                    dialog.Close();
                }));
                items.Add(new MenuItem("-"));
                ContextMenu menu = grid.ContextMenu ?? new ContextMenu();
                for (int i = 0; i < items.Count; i++) menu.MenuItems.Add(i, items[i]);
                menu.Popup += delegate
                {
                    RerouteRow x = sel();
                    foreach (MenuItem it in items) it.Enabled = x != null || it.Text == "-";
                    if (x == null) return;
                    install.Enabled = x.Kind == "rerouted" && x.Missing.Count > 0;
                    blockLeak.Enabled = x.Kind == "LEAK";
                    blockToo.Enabled = x.Kind == "rerouted" || x.Kind == "via leak";
                    foreach (MenuItem a in allowItems) a.Enabled = x.Parent == null;
                };
                grid.ContextMenu = menu;

                Button save = new Button { Text = "Save report as .txt in " + Storage.FolderName, Dock = DockStyle.Bottom, Height = 30 };
                save.Click += delegate
                {
                    StringBuilder text = new StringBuilder("REROUTE CHECK  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + "\r\n").Append(summary).Append("\r\n\r\n");
                    text.Append(String.Join("\t", grid.Columns.Cast<ColumnHeader>().Select(h => h.Text).ToArray())).Append("\r\n");
                    foreach (RerouteRow x in rows) text.Append(String.Join("\t", cells(x))).Append("\r\n");
                    string file = Storage.File("REROUTE CHECK (blocked CAs, leaks, other ways in).txt");
                    try { System.IO.File.WriteAllText(file, text.ToString(), new UTF8Encoding(false)); MessageBox.Show(dialog, "Saved:\r\n" + file, "Reroute check"); }
                    catch (IOException ex) { MessageBox.Show(dialog, ex.Message, "Reroute check"); }
                };
                Button routes = new Button { Text = "Routes kisib installed...", Dock = DockStyle.Bottom, Height = 30 };
                routes.Click += delegate { after = ShowRoutes; dialog.Close(); };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(filters); dialog.Controls.Add(top);
                dialog.Controls.Add(save); dialog.Controls.Add(routes); dialog.Controls.Add(close);
                dialog.CancelButton = close;
                dialog.FormClosed += delegate { if (after != null) after(); };
                ShowTool(dialog, "reroute");
            }
        }

        private Action BlockKeyAction(string key, CertificateRecord rep)
        {
            List<CertificateRecord> certs = snapshot.Paths.ByKey[key].Where(c => !pathsBlocked.Contains(c.Identity)).ToList();
            string name = rep.SubjectShortName;
            return delegate { ShowBlockDialog(certs, delegate { return "cross-sign check: same key as " + name; }, "CA " + name + " (every path)", null); };
        }
    }
}
