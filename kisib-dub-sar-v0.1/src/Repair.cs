using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // One row in a repair list: a root (or CA), who owns it, what it fixes, and what Repair will do with it.
    internal sealed class RepairRow
    {
        internal string Name, Owner, Country, Blocs, Fixes, RuledBy, Note;
        internal CertificateRecord Cert;
        internal byte[] SealDer;          // only kisib's own pinned seals ever go into Trusted Root
        internal bool Trusted, Blocked, Check = true;
        internal string[] PutBack;        // "put back what was blocked before kisib": scope, sha1, sha256, subject, time, der
    }

    // Tools > Repair. Every kind of repair is its own button, and each row says whose seal it is and what it fixes.
    // A manual repair always wins over bloc rules: what it puts back goes on the never-block list.
    internal sealed partial class ExplorerForm
    {
        private MenuItem RepairMenu()
        {
            MenuItem repair = new MenuItem("&Repair");
            repair.MenuItems.Add(new MenuItem("Windows essentials (Microsoft's own roots only)...", delegate { RepairSeals("Windows essentials", s => s.IsMicrosoft,
                "Microsoft's own roots: Windows files and drivers, Windows Update, Defender, Microsoft websites and sign-in. Nothing that isn't Microsoft's is in this list."); }));
            repair.MenuItems.Add(new MenuItem("Get online (microsoft.com and the big certificate companies)...", delegate { RepairSeals("Get online", s => s.Set == "online" || s.Set == "microsoft",
                "The roots most websites hang under, including microsoft.com, Office and Microsoft sign-in (DigiCert), Let's Encrypt, Sectigo, GlobalSign and Google. Owners are shown per row."); }));
            repair.MenuItems.Add(new MenuItem("What Windows ships with (Microsoft's required roots)...", delegate { RepairSeals("What Windows ships with", s => s.Set == "windows",
                "The roots Microsoft lists as required by Windows itself (Microsoft, plus old VeriSign, Thawte and Symantec time-stamp roots that keep old signed files valid)."); }));
            repair.MenuItems.Add(new MenuItem("My trusted categories...", delegate { RepairCategories(); }));
            repair.MenuItems.Add(new MenuItem("Reach Claude (the roots the Claude app needs)...", delegate { OpenRepair("claude"); }));
            repair.MenuItems.Add(new MenuItem("What this PC uses (roots behind recent refusals)...", delegate { RepairUsed(); }));
            repair.MenuItems.Add("-");
            repair.MenuItems.Add(new MenuItem("Reset to the standard seals (only your blocs stay blocked)...", delegate { RepairReset(); }));
            repair.MenuItems.Add(new MenuItem("Put back what was blocked before kisib...", delegate { RepairPutBack(); }));
            return repair;
        }

        // Kept for older menu wiring.
        private void ShowRepair() { RepairSeals("Windows essentials", s => s.IsMicrosoft, "Microsoft's own roots."); }

        // ---- Building rows -------------------------------------------------------------------------

        private Dictionary<string, string> RuledMembers()
        {
            Dictionary<string, string> ruled = new Dictionary<string, string>(StringComparer.Ordinal);
            if (groups == null) return ruled;
            foreach (BlockRule r in BlockRules.Read())
            {
                GroupNode g = groups.All.FirstOrDefault(x => x.Key == r.GroupKey);
                if (g == null) continue;
                foreach (string id in g.Members) { string had; ruled[id] = ruled.TryGetValue(id, out had) && !had.Contains(g.Label) ? had + " + " + g.Label : g.Label; }
            }
            return ruled;
        }

        private RepairRow Row(CertificateRecord c, byte[] sealDer, string fixes, Dictionary<string, string> ruled)
        {
            CertificateRecord onPc = snapshot == null ? null : (snapshot.BySha1(c.Sha1) ?? c);
            CertificateRecord use = onPc ?? c;
            string rule;
            bool inRule = ruled.TryGetValue(use.Identity, out rule);
            RepairRow row = new RepairRow
            {
                Name = use.SubjectShortName, Owner = OwnerName(use), Country = use.SubjectCountry ?? "—", Blocs = snapshot == null ? "" : TagsOf(use), Fixes = fixes,
                Cert = use, SealDer = sealDer, Trusted = TrustGraph.InRootStore(use), Blocked = snapshot != null && snapshot.IsBlocked(use), RuledBy = inRule ? rule : null
            };
            row.Check = (row.Blocked || (!row.Trusted && sealDer != null)) && !inRule;
            if (inRule) row.Note = "stays blocked: in your " + rule + " rule (tick to repair anyway)";
            return row;
        }

        private static string WillDo(RepairRow r)
        {
            if (r.PutBack != null) return "block again (" + r.PutBack[0] + ")";
            List<string> parts = new List<string>();
            if (r.Blocked) parts.Add("take out of Disallowed");
            if (!r.Trusted && r.SealDer != null) parts.Add("put into Trusted Root (from kisib's own copy)");
            if (!r.Trusted && r.SealDer == null && !r.Blocked) parts.Add("not on this PC; Windows downloads it when needed");
            return parts.Count == 0 ? "nothing, already fine" : String.Join("; ", parts.ToArray());
        }

        // A repair, built without a window: the Repair menu shows it, commands and the Claude check run it directly.
        internal sealed class RepairSet { internal string Title, Intro, Reason; internal List<RepairRow> Rows = new List<RepairRow>(); }

        internal static readonly string[] RepairKinds = { "essentials", "online", "windows", "categories", "claude", "used", "reset", "putback" };

        internal RepairSet BuildRepair(string kind)
        {
            Dictionary<string, string> ruled = RuledMembers();
            switch (kind)
            {
                case "essentials": return SealSet("Windows essentials", s => s.IsMicrosoft, "Microsoft's own roots: Windows files and drivers, Windows Update, Defender, Microsoft websites and sign-in. Nothing that isn't Microsoft's is in this list.", ruled);
                case "online": return SealSet("Get online", s => s.Set == "online" || s.Set == "microsoft", "The roots most websites hang under, including microsoft.com, Office and Microsoft sign-in (DigiCert), Let's Encrypt, Sectigo, GlobalSign and Google. Owners are shown per row.", ruled);
                case "windows": return SealSet("What Windows ships with", s => s.Set == "windows", "The roots Microsoft lists as required by Windows itself (Microsoft, plus old VeriSign, Thawte and Symantec time-stamp roots that keep old signed files valid).", ruled);
                case "categories": return CategorySet("My trusted categories", c => c.Enabled, false, ruled);
                case "claude": return CategorySet("Reach Claude", c => c.Enabled && c.KeepReachable, true, ruled);
                case "used": return UsedSet(ruled);
                case "reset": return ResetSet(ruled);
                case "putback": return PutBackSet();
            }
            return new RepairSet { Title = kind, Intro = "unknown repair", Reason = "repair: " + kind };
        }

        private void OpenRepair(string kind)
        {
            if (snapshot == null && kind != "putback") { Say("Run a scan first (F5)."); return; }
            RepairSet set = BuildRepair(kind);
            ShowRepairWindow(set.Title, set.Intro + (Seals.LoadError != null ? "\r\nNote: " + Seals.LoadError : ""), set.Rows, set.Reason);
        }

        // Runs a repair with its default ticks, no window. Returns the plain result line.
        internal string RunRepair(string kind)
        {
            if (snapshot == null) return "Run a scan first.";
            RepairSet set = BuildRepair(kind);
            List<RepairRow> picked = set.Rows.Where(r => r.Check && WillDo(r) != "nothing, already fine").ToList();
            if (picked.Count == 0) return set.Title + ": nothing to repair.";
            return set.Title + ": " + DoRepair(picked, set.Reason);
        }

        private void RepairSeals(string title, Func<Seal, bool> which, string intro)
        {
            RepairSet set = SealSet(title, which, intro, RuledMembers());
            ShowRepairWindow(set.Title, set.Intro + (Seals.LoadError != null ? "\r\nNote: " + Seals.LoadError : ""), set.Rows, set.Reason);
        }
        private void RepairCategories() { OpenRepair("categories"); }
        private void RepairUsed() { OpenRepair("used"); }
        private void RepairReset() { OpenRepair("reset"); }
        private void RepairPutBack() { OpenRepair("putback"); }

        private RepairSet SealSet(string title, Func<Seal, bool> which, string intro, Dictionary<string, string> ruled)
        {
            return new RepairSet { Title = title, Intro = intro, Reason = "repair: " + title, Rows = Seals.All.Where(which).Select(s => Row(s.Record, s.Der, s.Purpose, ruled)).ToList() };
        }

        // overrideRules: the roots are repaired even when a bloc rule covers them (Claude has to be able to connect).
        private RepairSet CategorySet(string title, Func<TrustCategory, bool> which, bool overrideRules, Dictionary<string, string> ruled)
        {
            RepairSet set = new RepairSet { Title = title, Reason = "repair: " + title,
                Intro = overrideRules ? "The roots Claude's sites use (Let's Encrypt and Google Trust Services). kisib keeps these working even when a bloc you block covers them, so the Claude app can always connect." :
                    "The roots your switched-on trusted categories need (Tools > Trusted categories). Each row shows the owner, so nothing hides under a Microsoft name.\r\n" +
                    "Roots that kisib carries go back into Trusted Root; others are only taken out of Disallowed (Windows downloads them when needed)." };
            if (snapshot == null) return set;
            foreach (TrustCategory cat in TrustCategories.Read().Where(which))
                foreach (string name in cat.Roots)
                {
                    Seal seal = Seals.ByName(name);
                    CertificateRecord c = seal != null ? seal.Record : snapshot.Certificates.Values
                        .Where(x => String.Equals(x.SubjectCn, name, StringComparison.OrdinalIgnoreCase) && x.Subject == x.Issuer && (TrustGraph.InRootStore(x) || x.FoundIn.Contains(MicrosoftList.Label)))
                        .OrderByDescending(x => x.NotAfter).FirstOrDefault();
                    if (c == null) { set.Rows.Add(new RepairRow { Name = name, Owner = "—", Country = "—", Blocs = "", Fixes = cat.Name, Check = false, Note = "not on this PC or Microsoft's list; Tools > Update Microsoft root list" }); continue; }
                    RepairRow row = Row(c, seal == null ? null : seal.Der, cat.Name, ruled);
                    if (overrideRules && row.RuledBy != null) { row.Check = row.Blocked || (!row.Trusted && row.SealDer != null); row.Note = "in your " + row.RuledBy + " rule, kept working for " + cat.Name; }
                    RepairRow had = set.Rows.FirstOrDefault(x => x.Cert != null && x.Cert.Sha1 == row.Cert.Sha1);
                    if (had != null) { had.Fixes += ", " + cat.Name; continue; }
                    set.Rows.Add(row);
                }
            // Keep-reachable categories: the whole chain counts, not only the roots. A bloc rule blocks the CAs under a root
            // too (Let's Encrypt YE2 / Root YE, Google WE1...), and one blocked CA in the middle cuts the app off.
            if (overrideRules && snapshot.Paths != null)
                foreach (TrustCategory cat in TrustCategories.Read().Where(which))
                {
                    List<CertificateRecord> roots = CategoryRoots(cat);
                    foreach (CertificateRecord c in ChainUnder(roots)) AddReach(set, c, cat.Name + ": a CA under " + String.Join(" / ", cat.Roots.Take(3).ToArray()) + (cat.Roots.Count > 3 ? "..." : ""), cat.Name, ruled);
                    // A root that isn't in Trusted Root (and kisib can't put there without admin) is reached through its
                    // cross-sign, so the root that signed the cross-sign has to stay open too (GTS R4 <- GlobalSign Root CA).
                    foreach (CertificateRecord r in roots.Where(x => !TrustGraph.InRootStore(x) && !(Elevation.IsElevated && Seals.BySha1(x.Sha1) != null)))
                        foreach (CertificateRecord signer in CrossSigners(r))
                            AddReach(set, signer, cat.Name + ": " + r.SubjectShortName + " isn't in Trusted Root, so Windows goes through " + signer.SubjectShortName, cat.Name, ruled);
                }
            // Keep-reachable categories: anything blocked behind a refusal of their program or sites in the last day goes too.
            if (overrideRules)
                foreach (TrustCategory cat in TrustCategories.Read().Where(which))
                    foreach (Denial d in denials.Where(x => !x.Ok && !x.Noise && x.Time > DateTime.Now.AddDays(-1) && Belongs(cat, x)))
                        foreach (string sha1 in d.ChainSha1)
                        {
                            CertificateRecord c = snapshot.BySha1(sha1);
                            if (c == null || !snapshot.IsBlocked(c) || set.Rows.Any(r => r.Cert != null && r.Cert.Sha1 == c.Sha1)) continue;
                            Seal seal = Seals.BySha1(sha1);
                            RepairRow row = Row(c, seal == null ? null : seal.Der, cat.Name + " refusal: " + (d.Site ?? d.Subject), ruled);
                            row.Check = true; if (row.RuledBy != null) row.Note = "in your " + row.RuledBy + " rule, kept working for " + cat.Name;
                            set.Rows.Add(row);
                        }
            return set;
        }

        private List<CertificateRecord> CategoryRoots(TrustCategory cat)
        {
            List<CertificateRecord> roots = new List<CertificateRecord>();
            foreach (string name in cat.Roots)
            {
                Seal seal = Seals.ByName(name);
                CertificateRecord c = seal != null ? (snapshot.BySha1(seal.Sha1) ?? seal.Record) : snapshot.Certificates.Values
                    .Where(x => String.Equals(x.SubjectCn, name, StringComparison.OrdinalIgnoreCase) && x.Subject == x.Issuer).OrderByDescending(x => x.NotAfter).FirstOrDefault();
                if (c != null && c.SpkiSha256 != null) roots.Add(c);
            }
            return roots;
        }

        // Every live blocked certificate whose key sits under these roots (up to 4 levels), plus blocked key twins on the way.
        private List<CertificateRecord> ChainUnder(List<CertificateRecord> roots)
        {
            TrustGraph g = snapshot.Paths;
            DateTime now = DateTime.UtcNow;
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            Queue<KeyValuePair<string, int>> queue = new Queue<KeyValuePair<string, int>>();
            foreach (CertificateRecord r in roots) if (seen.Add(r.SpkiSha256)) queue.Enqueue(new KeyValuePair<string, int>(r.SpkiSha256, 0));
            while (queue.Count > 0)
            {
                KeyValuePair<string, int> k = queue.Dequeue();
                List<CertificateRecord> kids;
                if (k.Value >= 4 || !g.Children.TryGetValue(k.Key, out kids)) continue;
                foreach (CertificateRecord c in kids)
                    if (TrustGraph.Live(c, now) && c.SpkiSha256 != null && seen.Add(c.SpkiSha256)) queue.Enqueue(new KeyValuePair<string, int>(c.SpkiSha256, k.Value + 1));
            }
            Dictionary<string, CertificateRecord> found = new Dictionary<string, CertificateRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (string key in seen)
            {
                List<CertificateRecord> same;
                if (g.ByKey.TryGetValue(key, out same))
                    foreach (CertificateRecord c in same) if (snapshot.IsBlocked(c) && TrustGraph.Live(c, now)) found[c.Sha1] = c;
            }
            return found.Values.ToList();
        }

        // The roots that cross-signed this root's key and are blocked.
        private List<CertificateRecord> CrossSigners(CertificateRecord root)
        {
            TrustGraph g = snapshot.Paths;
            List<CertificateRecord> twins, result = new List<CertificateRecord>();
            if (!g.ByKey.TryGetValue(root.SpkiSha256, out twins)) return result;
            DateTime now = DateTime.UtcNow;
            foreach (CertificateRecord twin in twins)
            {
                List<string> keys;
                if (!TrustGraph.Live(twin, now) || !g.IssuerKeys.TryGetValue(twin.Identity, out keys)) continue;
                foreach (string key in keys)
                {
                    List<CertificateRecord> issuers;
                    if (g.ByKey.TryGetValue(key, out issuers))
                        result.AddRange(issuers.Where(i => g.SelfSigned.Contains(i.Identity) && snapshot.IsBlocked(i) && TrustGraph.Live(i, now)));
                }
            }
            return result.GroupBy(c => c.Sha1).Select(x => x.First()).ToList();
        }

        private void AddReach(RepairSet set, CertificateRecord c, string fixes, string category, Dictionary<string, string> ruled)
        {
            if (set.Rows.Any(r => r.Cert != null && String.Equals(r.Cert.Sha1, c.Sha1, StringComparison.OrdinalIgnoreCase))) return;
            Seal seal = Seals.BySha1(c.Sha1);
            RepairRow row = Row(c, seal == null ? null : seal.Der, fixes, ruled);
            row.Check = true;
            row.Note = (row.RuledBy != null ? "in your " + row.RuledBy + " rule, " : "") + "kept working for " + category;
            set.Rows.Add(row);
        }

        private static bool Belongs(TrustCategory cat, Denial d)
        {
            string exe = String.IsNullOrEmpty(d.Program) ? "" : Path.GetFileName(d.Program);
            if (exe.Length > 0 && cat.Programs.Any(p => String.Equals(p, exe, StringComparison.OrdinalIgnoreCase))) return true;
            string site = d.Site ?? d.Subject ?? "";
            return site.Length > 0 && cat.SiteMatch.Any(r => r.IsMatch(site));
        }

        private RepairSet UsedSet(Dictionary<string, string> ruled)
        {
            RepairSet set = new RepairSet { Title = "What this PC uses", Reason = "repair: what this PC uses",
                Intro = "Roots and CAs behind refusals in the last 7 days that are blocked, or roots that are missing. Your bloc rules win unless you tick a row." };
            if (snapshot == null) return set;
            Dictionary<string, RepairRow> rows = new Dictionary<string, RepairRow>(StringComparer.OrdinalIgnoreCase);
            DateTime since = DateTime.Now.AddDays(-7);
            foreach (Denial d in denials.Where(x => !x.Ok && !x.Noise && x.Time >= since))
            {
                string use = Path.GetFileName(d.Program) + " → " + d.Subject;
                for (int i = 0; i < d.ChainSha1.Count; i++)
                {
                    string sha1 = d.ChainSha1[i];
                    CertificateRecord c = snapshot.BySha1(sha1);
                    Seal seal = Seals.BySha1(sha1);
                    bool isRoot = i == d.ChainSha1.Count - 1 && i > 0;
                    if (c == null && seal != null) c = seal.Record;
                    if (c == null) continue;
                    bool blocked = snapshot.IsBlocked(c), missing = isRoot && !TrustGraph.InRootStore(c) && d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase);
                    if (!blocked && !missing) continue;
                    RepairRow row;
                    if (rows.TryGetValue(c.Sha1, out row)) { if (row.Fixes.IndexOf(use, StringComparison.OrdinalIgnoreCase) < 0 && row.Fixes.Length < 300) row.Fixes += "; " + use; continue; }
                    rows[c.Sha1] = Row(c, seal == null ? null : seal.Der, use, ruled);
                }
            }
            set.Rows = rows.Values.ToList();
            return set;
        }

        private RepairSet ResetSet(Dictionary<string, string> ruled)
        {
            RepairSet set = new RepairSet { Title = "Reset to the standard seals", Reason = "repair: reset to standard seals",
                Intro = "Every seal kisib carries goes back, and every block kisib made that no rule covers is lifted. What your bloc and continent rules block stays blocked.\r\n" +
                    "Blocks that were there before kisib (Microsoft's untrusted list) are not touched." };
            if (snapshot == null) return set;
            set.Rows = Seals.All.Select(s => Row(s.Record, s.Der, s.Purpose, ruled)).ToList();
            // One-off blocks kisib made that no rule covers go too: only what your blocs block stays.
            HashSet<string> listed = new HashSet<string>(set.Rows.Where(r => r.Cert != null).Select(r => r.Cert.Sha1), StringComparer.OrdinalIgnoreCase);
            foreach (string id in snapshot.Blocked)
            {
                CertificateRecord c = snapshot.Certificates[id];
                if (!snapshot.KisibBlockedSha1.Contains(c.Sha1) || ruled.ContainsKey(id) || !listed.Add(c.Sha1)) continue;
                set.Rows.Add(Row(c, null, "a block kisib made that none of your rules covers", ruled));
            }
            return set;
        }

        private RepairSet PutBackSet()
        {
            RepairSet set = new RepairSet { Title = "Put back what was blocked before kisib", Reason = "repair: put back",
                Intro = "Certificates you unblocked by hand that were in Disallowed before kisib (Microsoft's untrusted list or an earlier hardening). Ticked rows go back into Disallowed and come off the never-block list." };
            foreach (string[] r in UnblockedByHand.Read())
            {
                CertificateRecord c = snapshot == null ? null : snapshot.BySha1(r[1]);
                set.Rows.Add(new RepairRow { Name = r[3], Owner = c == null ? "—" : OwnerName(c), Country = c == null ? "—" : c.SubjectCountry ?? "—", Blocs = c == null || snapshot == null ? "" : TagsOf(c),
                    Fixes = "unblocked by hand " + r[4].Replace("T", " ").Substring(0, Math.Min(16, r[4].Length)), Cert = c, Blocked = c != null && snapshot.IsBlocked(c), Trusted = true, PutBack = r, Check = true });
            }
            return set;
        }

        // ---- Keep Claude reachable -------------------------------------------------------------------
        // The Claude app checks certificates through Windows, so a bloc block can cut it off without any refusal showing.
        // After every scan, the roots of categories marked "keep reachable" are unblocked and put back if needed.
        private DateTime lastReachCheck = DateTime.MinValue;
        private string lastReachPrint;

        // force = asked for (tray, Tools, a command): runs even when switched off, and always says the result.
        internal string KeepReachable(bool force)
        {
            if (snapshot == null) return "Run a scan first.";
            if (!force && Storage.Setting("keep claude reachable off")) return null;
            if (!force && lastReachPrint == snapshot.Fingerprint && (DateTime.Now - lastReachCheck).TotalMinutes < 60) return null;
            lastReachCheck = DateTime.Now; lastReachPrint = snapshot.Fingerprint;
            RepairSet set = BuildRepair("claude");
            List<RepairRow> picked = set.Rows.Where(r => r.Check && WillDo(r) != "nothing, already fine").ToList();
            // Without admin, a root missing from Trusted Root can't be added; don't retry that every scan.
            if (!Elevation.IsElevated) picked = picked.Where(r => r.Blocked).ToList();
            string text;
            if (picked.Count == 0)
            {
                text = "Claude's roots are fine: nothing blocked, nothing missing" + (Elevation.IsElevated ? "." : " that kisib can fix without admin.");
                if (force) Say(text);
                return text;
            }
            text = "Kept Claude reachable: " + String.Join(", ", picked.Select(r => r.Name).ToArray()) + ". " + DoRepair(picked, set.Reason);
            Say(text);
            StartScan();
            return text;
        }

        // One line per root the Claude app needs: blocked or not, in Trusted Root or not.
        internal string ClaudeRootsReport()
        {
            if (snapshot == null) return "no scan yet";
            StringBuilder text = new StringBuilder();
            foreach (RepairRow r in BuildRepair("claude").Rows)
                text.Append("  ").Append(r.Name).Append(" (").Append(r.Owner).Append("): ")
                    .Append(r.Cert == null ? "not found" : (r.Blocked ? "BLOCKED" : "not blocked") + ", " + (r.Trusted ? "in Trusted Root" : "not in Trusted Root"))
                    .Append(r.Note != null ? " · " + r.Note : "").Append("\r\n");
            return text.ToString();
        }

        // ---- The window and the work ---------------------------------------------------------------

        private void ShowRepairWindow(string title, string intro, List<RepairRow> rows, string reason)
        {
            Form dialog = new Form { Text = "Repair — " + title, Size = new Size(1250, 560), Font = Font };
            Label top = new Label { Dock = DockStyle.Top, Height = 52, Padding = new Padding(8, 6, 8, 0), Text = intro };
            ListView grid = new ListView { CheckBoxes = true };
            SetupGrid(grid, new string[] { "Root", "Owner", "C=", "Blocs", "What it fixes", "Now", "Repair will", "Note" }, new int[] { 300, 170, 40, 70, 300, 150, 300, 300 });
            EmojiText.AttachTo(grid, 3);
            foreach (RepairRow r in rows)
            {
                string now = r.PutBack != null ? (r.Blocked ? "blocked" : "not blocked") : (r.Blocked ? "BLOCKED" : "") + (r.Blocked && !r.Trusted ? ", " : "") + (!r.Trusted ? "not in Trusted Root" : r.Blocked ? "" : "fine");
                ListViewItem item = new ListViewItem(new string[] { r.Name, r.Owner, r.Country, r.Blocs, r.Fixes ?? "", now, WillDo(r), r.Note ?? "" }) { Tag = r, Checked = r.Check && WillDo(r) != "nothing, already fine" };
                if (r.RuledBy != null) item.ForeColor = Color.DarkGoldenrod; else if (r.Blocked || !r.Trusted) item.ForeColor = Color.Firebrick;
                grid.Items.Add(item);
            }
            Button go = new Button { Dock = DockStyle.Bottom, Height = 32 };
            Action count = delegate { int n = grid.Items.Cast<ListViewItem>().Count(i => i.Checked); go.Text = n == 0 ? "Nothing ticked" : "Repair " + n + " ticked"; go.Enabled = n > 0; };
            grid.ItemChecked += delegate { count(); };
            count();
            Label foot = new Label { Dock = DockStyle.Bottom, Height = 36, Padding = new Padding(8, 4, 8, 0), ForeColor = SystemColors.GrayText,
                Text = (Elevation.IsElevated ? "Running as administrator: changes apply to the whole PC." : "Not running as administrator: kisib can lift this user's blocks only. Run it as administrator to change Trusted Root and whole-PC blocks.") +
                    "\r\nWhat a repair puts back goes on the never-block list, so your bloc rules don't take it away again." };
            go.Click += delegate
            {
                List<RepairRow> picked = grid.Items.Cast<ListViewItem>().Where(i => i.Checked).Select(i => (RepairRow)i.Tag).ToList();
                dialog.Close();
                Say(DoRepair(picked, reason));
                StartScan();
            };
            dialog.Controls.Add(grid); dialog.Controls.Add(top); dialog.Controls.Add(foot); dialog.Controls.Add(go);
            ShowTool(dialog, "repair");
        }

        private string DoRepair(List<RepairRow> picked, string reason)
        {
            List<string> said = new List<string>();
            List<RepairRow> putBack = picked.Where(r => r.PutBack != null).ToList();
            if (putBack.Count > 0) said.Add(PutBackBlocks(putBack));
            List<RepairRow> fix = picked.Where(r => r.PutBack == null && r.Cert != null).ToList();
            if (fix.Count == 0) return String.Join(" ", said.ToArray());
            // 1. Out of Disallowed and onto the never-block list (with key twins), so rules leave them alone.
            //    A reset's one-off blocks are only lifted: your rules can still block them later.
            bool reset = reason.IndexOf("reset", StringComparison.OrdinalIgnoreCase) >= 0;
            List<CertificateRecord> keep = fix.Where(r => r.Blocked && (!reset || r.SealDer != null)).Select(r => r.Cert).ToList();
            List<CertificateRecord> oneOff = fix.Where(r => r.Blocked && reset && r.SealDer == null).Select(r => r.Cert).ToList();
            if (keep.Count > 0) said.Add("Unblocked: " + LiftForGood(WithTwins(keep), reason, reason));
            if (oneOff.Count > 0) said.Add("One-off blocks lifted: " + Lift(WithTwins(oneOff), reason, new List<string>()));
            try { AllowedList.AddRange(fix.Where(r => r.SealDer != null || !reset).Select(r => r.Cert), reason); } catch (IOException) { }
            // 2. Missing roots from kisib's own pinned copies into Trusted Root (whole PC, needs admin).
            List<RepairRow> add = fix.Where(r => !r.Trusted && r.SealDer != null).ToList();
            if (add.Count > 0)
            {
                if (!Elevation.IsElevated) said.Add(add.Count + " roots need kisib run as administrator to go into Trusted Root.");
                else
                {
                    int added = 0; List<string> failed = new List<string>();
                    try
                    {
                        using (OwnStore root = OwnStore.Open("Root", X509Location.LocalMachine, true))
                            foreach (RepairRow r in add)
                            {
                                try { if (root.Add(r.SealDer)) { added++; BlockEngine.Note("repair-trust", X509Location.LocalMachine, r.Cert.Sha256, r.Cert.Sha1, r.Cert.SubjectShortName, reason + ": put into Trusted Root from kisib's seal"); } }
                                catch (Exception ex) { failed.Add(r.Name + ": " + ex.Message); }
                            }
                    }
                    catch (Exception ex) { failed.Add(ex.Message); }
                    said.Add(added + " root" + (added == 1 ? "" : "s") + " put into Trusted Root." + (failed.Count > 0 ? " Failed: " + String.Join("; ", failed.ToArray()) : ""));
                }
            }
            return String.Join(" ", said.ToArray());
        }

        // Back into Disallowed, off the never-block list and off the unblocked-by-hand list.
        private string PutBackBlocks(List<RepairRow> rows)
        {
            int added = 0; List<string> problems = new List<string>();
            List<string[]> done = new List<string[]>();
            foreach (IGrouping<string, RepairRow> scope in rows.GroupBy(r => r.PutBack[0]))
            {
                X509Location location;
                try { location = (X509Location)Enum.Parse(typeof(X509Location), scope.Key); } catch (ArgumentException) { continue; }
                if (location == X509Location.LocalMachine && !Elevation.IsElevated) { problems.Add("whole-PC ones need kisib run as administrator"); continue; }
                try
                {
                    using (OwnStore store = OwnStore.Open("Disallowed", location, true))
                        foreach (RepairRow r in scope)
                        {
                            try { store.Add(Convert.FromBase64String(r.PutBack[5])); added++; done.Add(r.PutBack); AllowedList.Remove(r.PutBack[1]); BlockEngine.Note("put back", location, r.PutBack[2], r.PutBack[1], r.PutBack[3], "put back into Disallowed (was blocked before kisib)"); }
                            catch (Exception ex) { problems.Add(r.Name + ": " + ex.Message); }
                        }
                }
                catch (Exception ex) { problems.Add(ex.Message); }
            }
            if (done.Count > 0) UnblockedByHand.Write(UnblockedByHand.Read().Where(x => !done.Any(d => d[0] == x[0] && d[1] == x[1])).ToList());
            return "Blocked again: " + added + "." + (problems.Count > 0 ? " " + String.Join("; ", problems.Distinct().ToArray()) : "");
        }
    }
}
