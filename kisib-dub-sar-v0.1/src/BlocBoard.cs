using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Kisib
{
    // Block by bloc and continent: pick 👑 🏛️ 🧱 🌿 💃 and continents, see every country they catch, then block.
    // A normal window (not modal): the main window stays usable while it is open, and it refreshes after every scan.
    internal sealed partial class ExplorerForm
    {
        private Form blocBoard;
        private Action blocBoardRefresh;

        private void OpenBlocBoard()
        {
            if (blocBoard != null && !blocBoard.IsDisposed)
            {
                if (blocBoard.WindowState == FormWindowState.Minimized) blocBoard.WindowState = FormWindowState.Normal;
                blocBoard.Activate();
                return;
            }
            if (snapshot == null || groups == null) { ShowText("Block by bloc and continent", "Run a scan first (F5)."); return; }
            if (groups.Error != null) { ShowText("Block by bloc and continent", "Groups could not load: " + groups.Error); return; }

            HashSet<string> picked = new HashSet<string>(StringComparer.Ordinal);
            Form f = new Form { Text = "Block by bloc and continent — kisib.dub-sar", Size = new Size(1340, 840), Font = Font, Icon = Icon,
                StartPosition = FormStartPosition.CenterScreen, ShowInTaskbar = false, KeyPreview = true };
            f.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Escape) f.Close(); };

            Label blocTitle = new Label { Dock = DockStyle.Top, Height = 24, Padding = new Padding(8, 6, 8, 0), Font = new Font(Font, FontStyle.Bold),
                Text = "Block by bloc   (tags stack: a country can be in several; each certificate is matched on its subject and issuer C=)" };
            FlowLayoutPanel blocPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 66, Padding = new Padding(6, 4, 6, 0) };
            Label contTitle = new Label { Dock = DockStyle.Top, Height = 24, Padding = new Padding(8, 6, 8, 0), Font = new Font(Font, FontStyle.Bold),
                Text = "Block by continent   (all seven, every country on the UN list; Middle East is a region inside Asia)" };
            FlowLayoutPanel contPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 66, Padding = new Padding(6, 4, 6, 0) };
            Panel summaryPanel = new Panel { Dock = DockStyle.Top, Height = 64, Padding = new Padding(8, 6, 8, 6), BackColor = Color.FromArgb(255, 247, 245) };
            Label summary = new Label { Dock = DockStyle.Fill, ForeColor = Color.FromArgb(155, 28, 18) };
            FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Right, Width = 560, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            Button keepBlocked = new Button { Text = "Block + keep blocked...", AutoSize = true, BackColor = Color.FromArgb(155, 28, 18), ForeColor = Color.White };
            Button preview = new Button { Text = "Preview block...", AutoSize = true };
            Button clear = new Button { Text = "Clear picks", AutoSize = true };
            CheckBox onlyHits = new CheckBox { Text = "Show only what this blocks", AutoSize = true, Padding = new Padding(0, 6, 8, 0) };
            actions.Controls.AddRange(new Control[] { keepBlocked, preview, clear, onlyHits });
            summaryPanel.Controls.Add(summary); summaryPanel.Controls.Add(actions);

            ListView grid = new ListView();
            EmojiText.AttachTo(grid, 3);
            SetupGrid(grid, new string[] { "C=", "Country", "Continent", "Blocs", "CA owners", "Roots", "Interm.", "Blocked now", "After this block", "Cross-signs", "Why" },
                new int[] { 42, 170, 150, 90, 300, 55, 60, 95, 190, 150, 220 });
            Label foot = new Label { Dock = DockStyle.Bottom, Height = 38, Padding = new Padding(8, 4, 8, 0), ForeColor = SystemColors.GrayText,
                Text = "Roots = self-signed certificates; the rest are intermediates and cross-signs, including ones only on the Microsoft list or CCADB (blockable before they arrive).\r\n" +
                    "The preview adds every certificate sharing a key with a picked one and skips protected Windows essentials unless you tick them. Double-click a country to open it in the tree." };


            Func<List<GroupNode>> pickedGroups = delegate { return groups == null ? new List<GroupNode>() : groups.Tags.Concat(groups.Continents).Where(g => picked.Contains(g.Key)).ToList(); };

            Action fillGrid = null;
            Func<GroupNode, string, CheckBox> tile = delegate(GroupNode g, string sub)
            {
                string[] caption = { g.Label, sub };
                CheckBox box = new CheckBox { Appearance = Appearance.Button, Width = 205, Height = 56, Margin = new Padding(3),
                    Text = "", AccessibleName = g.Label + " " + sub, Tag = g, Checked = picked.Contains(g.Key), FlatStyle = FlatStyle.Standard };
                box.Paint += delegate(object s, PaintEventArgs e) { EmojiText.DrawLines(e.Graphics, caption, box.Font, new Rectangle(8, 2, box.Width - 14, box.Height - 4), box.ForeColor); };
                Action paint = delegate { box.BackColor = box.Checked ? Color.MistyRose : SystemColors.Control; box.ForeColor = box.Checked ? Color.Firebrick : SystemColors.ControlText; };
                paint();
                box.CheckedChanged += delegate
                {
                    if (box.Checked) picked.Add(g.Key); else picked.Remove(g.Key);
                    paint();
                    fillGrid();
                };
                return box;
            };

            Action buildTiles = delegate
            {
                blocPanel.SuspendLayout(); contPanel.SuspendLayout();
                blocPanel.Controls.Clear(); contPanel.Controls.Clear();
                foreach (GroupNode g in groups.Tags)
                {
                    int countries = groups.Countries.Count(c => c.Members.Overlaps(g.Members));
                    blocPanel.Controls.Add(tile(g, countries + " countries · " + g.Members.Count + " certificates"));
                }
                foreach (GroupNode g in groups.Continents)
                {
                    string name = g.Kind == "region" ? g.Label.Substring(0, Math.Max(0, g.Label.IndexOf(" (", StringComparison.Ordinal))) : g.Label;
                    int listed = groups.CountryRows.Values.Count(r => g.Kind == "region" ? r.Region == name : r.Continent == name);
                    contPanel.Controls.Add(tile(g, listed + " countries · " + g.Members.Count + " certificates"));
                }
                blocPanel.ResumeLayout(); contPanel.ResumeLayout();
            };

            fillGrid = delegate
            {
                if (snapshot == null || groups == null) return;
                List<GroupNode> chosenGroups = pickedGroups();
                HashSet<string> chosen = new HashSet<string>(chosenGroups.SelectMany(g => g.Members), StringComparer.Ordinal);
                List<CertificateRecord> adding = chosen.Where(id => !groups.Blocked.Contains(id)).Select(id => snapshot.Certificates[id]).ToList();
                WhatIf w = adding.Count == 0 ? null : RerouteKeys(adding);
                HashSet<string> rerouted = new HashSet<string>(w == null ? new List<string>() : w.Rerouted, StringComparer.Ordinal);
                HashSet<string> cut = new HashSet<string>(w == null ? new List<string>() : w.Cut, StringComparer.Ordinal);
                int roots = 0, inters = 0, guarded = 0;
                foreach (CertificateRecord c in adding)
                {
                    if (TrustCategories.ProtectedBy(c) != null) { guarded++; continue; }
                    if (c.Subject == c.Issuer) roots++; else inters++;
                }
                int countriesHit = 0;
                grid.BeginUpdate(); grid.Items.Clear();
                foreach (GroupNode country in groups.Countries)
                {
                    string iso = country.Key.StartsWith("country:", StringComparison.Ordinal) ? country.Key.Substring(8) : country.Label;
                    CountryRow row; groups.CountryRows.TryGetValue(iso, out row);
                    List<CertificateRecord> members = country.Members.Select(id => snapshot.Certificates[id]).ToList();
                    List<CertificateRecord> hits = members.Where(c => chosen.Contains(c.Identity) && !groups.Blocked.Contains(c.Identity)).ToList();
                    int prot = hits.Count(c => TrustCategories.ProtectedBy(c) != null);
                    if (hits.Count > 0) countriesHit++;
                    if (onlyHits.Checked && hits.Count == 0) continue;
                    HashSet<string> keys = new HashSet<string>(members.Where(c => c.SpkiSha256 != null).Select(c => c.SpkiSha256), StringComparer.Ordinal);
                    int re = keys.Count(rerouted.Contains), cu = keys.Count(cut.Contains);
                    List<string> owners = members.Select(c => { string o; return groups.OwnerOf.TryGetValue(c.Identity, out o) ? o : null; })
                        .Where(o => o != null).GroupBy(o => o).OrderByDescending(x => x.Count()).Select(x => x.Key).ToList();
                    int blockedNow = members.Count(c => groups.Blocked.Contains(c.Identity));
                    List<string> why = chosenGroups.Where(g => g.Members.Overlaps(country.Members)).Select(g => g.Kind == "tag" ? g.Label : g.Label).ToList();
                    ListViewItem item = new ListViewItem(new string[] {
                        iso, row != null ? row.Name : country.Label,
                        row == null ? "—" : row.Continent + (row.Region.Length > 0 ? " · " + row.Region : ""),
                        GroupCatalog.BlocsOf(groups, iso),
                        owners.Count == 0 ? "—" : String.Join(", ", owners.Take(3).ToArray()) + (owners.Count > 3 ? " +" + (owners.Count - 3) : ""),
                        members.Count(c => c.Subject == c.Issuer).ToString(), members.Count(c => c.Subject != c.Issuer).ToString(),
                        blockedNow == 0 ? "no" : blockedNow == members.Count ? "all " + blockedNow : blockedNow + " of " + members.Count,
                        hits.Count == 0 ? "—" : "BLOCK " + (hits.Count - prot) + (prot > 0 ? " (skip " + prot + " protected)" : ""),
                        re + cu == 0 ? "—" : (re > 0 ? re + " rerouted" : "") + (re > 0 && cu > 0 ? ", " : "") + (cu > 0 ? cu + " cut off" : ""),
                        why.Count == 0 ? "" : "by " + String.Join(" + ", why.ToArray()) }) { Tag = country };
                    if (hits.Count > 0) { item.BackColor = Color.MistyRose; item.UseItemStyleForSubItems = false; item.SubItems[8].ForeColor = Color.Firebrick; }
                    if (re > 0) { item.UseItemStyleForSubItems = false; item.SubItems[9].ForeColor = Color.DarkGreen; }
                    grid.Items.Add(item);
                }
                grid.EndUpdate();

                summary.Text = chosenGroups.Count == 0 ? "Pick blocs or continents above. Nothing is blocked until you confirm in the preview." :
                    "Will block: " + roots + " roots + " + inters + " intermediates from " + countriesHit + " countries   (" + String.Join(" + ", chosenGroups.Select(g => g.Label).ToArray()) + ")\r\n" +
                    (w == null ? "" : w.Rerouted.Count + " CAs stay reachable through other roots · " + w.Cut.Count + " cut off" + (w.Leaks.Count > 0 ? " · " + w.Leaks.Count + " LEAK" : "") + " · ") +
                    guarded + " protected (Windows essentials) skipped · " + chosen.Count(id => groups.Blocked.Contains(id)) + " already blocked";
                preview.Enabled = keepBlocked.Enabled = adding.Count > 0 || chosenGroups.Count > 0;
            };

            Action<bool> block = delegate(bool keep)
            {
                List<GroupNode> chosenGroups = pickedGroups();
                if (chosenGroups.Count == 0) return;
                List<CertificateRecord> certs = chosenGroups.SelectMany(g => g.Members).Distinct().Select(id => snapshot.Certificates[id]).ToList();
                Dictionary<string, string> reasons = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (GroupNode g in chosenGroups)
                    foreach (string id in g.Members)
                    {
                        string r = g.Label + ": " + String.Join("; ", g.Why[id].ToArray());
                        string had;
                        reasons[id] = reasons.TryGetValue(id, out had) ? had + " | " + r : r;
                    }
                string label = String.Join(" + ", chosenGroups.Select(g => g.Label).ToArray());
                ShowBlockDialog(certs, delegate(CertificateRecord c) { string r; return reasons.TryGetValue(c.Identity, out r) ? r : ""; }, label, chosenGroups, keep);
            };
            preview.Click += delegate { block(false); };
            keepBlocked.Click += delegate { block(true); };
            clear.Click += delegate { picked.Clear(); buildTiles(); fillGrid(); };
            onlyHits.CheckedChanged += delegate { fillGrid(); };
            grid.DoubleClick += delegate
            {
                if (grid.SelectedItems.Count == 0) return;
                GroupNode country = grid.SelectedItems[0].Tag as GroupNode;
                if (country == null) return;
                leftTabs.SelectedTab = groupsTab;
                foreach (TreeNode top in groupTree.Nodes)
                {
                    TreeNode hit = FindGroupNode(top, country.Key);
                    if (hit != null) { groupTree.SelectedNode = hit; hit.EnsureVisible(); break; }
                }
                Activate();
            };

            f.Controls.Add(grid); f.Controls.Add(foot);
            f.Controls.Add(summaryPanel); f.Controls.Add(contPanel); f.Controls.Add(contTitle); f.Controls.Add(blocPanel); f.Controls.Add(blocTitle);
            buildTiles(); fillGrid();
            blocBoardRefresh = delegate
            {
                if (f.IsDisposed || groups == null || groups.Error != null) return;
                picked.IntersectWith(groups.Tags.Concat(groups.Continents).Select(g => g.Key));
                buildTiles(); fillGrid();
            };
            f.FormClosed += delegate { blocBoardRefresh = null; blocBoard = null; };
            blocBoard = f;
            f.Show(this);
        }

        private static TreeNode FindGroupNode(TreeNode node, string key)
        {
            GroupNode g = node.Tag as GroupNode;
            if (g != null && g.Filter == "all" && g.Key == key) return node;
            foreach (TreeNode child in node.Nodes) { TreeNode hit = FindGroupNode(child, key); if (hit != null) return hit; }
            return null;
        }
    }
}
