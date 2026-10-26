using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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

        private void RepairSeals(string title, Func<Seal, bool> which, string intro)
        {
            List<Seal> seals = Seals.All.Where(which).ToList();
            Dictionary<string, string> ruled = RuledMembers();
            List<RepairRow> rows = seals.Select(s => Row(s.Record, s.Der, s.Purpose, ruled)).ToList();
            ShowRepairWindow(title, intro + (Seals.LoadError != null ? "\r\nNote: " + Seals.LoadError : ""), rows, "repair: " + title);
        }

        private void RepairCategories()
        {
            if (snapshot == null) { Say("Run a scan first (F5)."); return; }
            Dictionary<string, string> ruled = RuledMembers();
            List<RepairRow> rows = new List<RepairRow>();
            foreach (TrustCategory cat in TrustCategories.Read().Where(c => c.Enabled))
                foreach (string name in cat.Roots)
                {
                    Seal seal = Seals.ByName(name);
                    CertificateRecord c = seal != null ? seal.Record : snapshot.Certificates.Values
                        .Where(x => String.Equals(x.SubjectCn, name, StringComparison.OrdinalIgnoreCase) && x.Subject == x.Issuer && (TrustGraph.InRootStore(x) || x.FoundIn.Contains(MicrosoftList.Label)))
                        .OrderByDescending(x => x.NotAfter).FirstOrDefault();
                    if (c == null) { rows.Add(new RepairRow { Name = name, Owner = "—", Country = "—", Blocs = "", Fixes = cat.Name, Check = false, Note = "not on this PC or Microsoft's list; Tools > Update Microsoft root list" }); continue; }
                    RepairRow row = Row(c, seal == null ? null : seal.Der, cat.Name, ruled);
                    if (rows.Any(x => x.Cert != null && x.Cert.Sha1 == row.Cert.Sha1)) { RepairRow had = rows.First(x => x.Cert != null && x.Cert.Sha1 == row.Cert.Sha1); had.Fixes += ", " + cat.Name; continue; }
                    rows.Add(row);
                }
            ShowRepairWindow("My trusted categories", "The roots your switched-on trusted categories need (Tools > Trusted categories). Each row shows the owner, so nothing hides under a Microsoft name.\r\n" +
                "Roots that kisib carries go back into Trusted Root; others are only taken out of Disallowed (Windows downloads them when needed).", rows, "repair: categories");
        }

        private void RepairUsed()
        {
            if (snapshot == null) { Say("Run a scan first (F5)."); return; }
            Dictionary<string, string> ruled = RuledMembers();
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
            ShowRepairWindow("What this PC uses", "Roots and CAs behind refusals in the last 7 days that are blocked, or roots that are missing. Your bloc rules win unless you tick a row.", rows.Values.ToList(), "repair: what this PC uses");
        }

        private void RepairReset()
        {
            if (snapshot == null) { Say("Run a scan first (F5)."); return; }
            Dictionary<string, string> ruled = RuledMembers();
            List<RepairRow> rows = Seals.All.Select(s => Row(s.Record, s.Der, s.Purpose, ruled)).ToList();
            // One-off blocks kisib made that no rule covers go too: only what your blocs block stays.
            foreach (string id in snapshot.Blocked)
            {
                CertificateRecord c = snapshot.Certificates[id];
                if (!snapshot.KisibBlockedSha1.Contains(c.Sha1) || ruled.ContainsKey(id) || rows.Any(r => r.Cert != null && r.Cert.Sha1 == c.Sha1)) continue;
                rows.Add(Row(c, null, "a block kisib made that none of your rules covers", ruled));
            }
            ShowRepairWindow("Reset to the standard seals", "Every seal kisib carries goes back, and every block kisib made that no rule covers is lifted. What your bloc and continent rules block stays blocked.\r\n" +
                "Blocks that were there before kisib (Microsoft's untrusted list) are not touched.", rows, "repair: reset to standard seals");
        }

        private void RepairPutBack()
        {
            List<RepairRow> rows = new List<RepairRow>();
            foreach (string[] r in UnblockedByHand.Read())
            {
                CertificateRecord c = snapshot == null ? null : snapshot.BySha1(r[1]);
                rows.Add(new RepairRow { Name = r[3], Owner = c == null ? "—" : OwnerName(c), Country = c == null ? "—" : c.SubjectCountry ?? "—", Blocs = c == null || snapshot == null ? "" : TagsOf(c),
                    Fixes = "unblocked by hand " + r[4].Replace("T", " ").Substring(0, Math.Min(16, r[4].Length)), Cert = c, Blocked = c != null && snapshot.IsBlocked(c), Trusted = true, PutBack = r, Check = true });
            }
            ShowRepairWindow("Put back what was blocked before kisib", "Certificates you unblocked by hand that were in Disallowed before kisib (Microsoft's untrusted list or an earlier hardening). Ticked rows go back into Disallowed and come off the never-block list.", rows, "repair: put back");
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
