using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Kisib
{
    // The friendlier layer: left tabs, a card view, plain status words, tidy menus and toolbar.
    // Nothing is removed; the raw views stay one click away.
    internal sealed partial class ExplorerForm
    {
        private readonly TreeView groupTree = new TreeView();
        private TabControl leftTabs;
        private TabPage storesTab, groupsTab, watchTab;
        private HashSet<string> rowBlocked = new HashSet<string>(StringComparer.Ordinal);
        private readonly Label watchState = new Label { Dock = DockStyle.Top, Height = 44, Padding = new Padding(8), Font = new Font("Tahoma", 10F, FontStyle.Bold) };
        private ListView watchList;
        private readonly Label watchDot = new Label { Dock = DockStyle.Right, Width = 120, TextAlign = ContentAlignment.MiddleLeft };
        private readonly LinkLabel refusedLink = new LinkLabel { Dock = DockStyle.Right, Width = 130, TextAlign = ContentAlignment.MiddleLeft };
        private readonly Button denialsButton = new Button { AutoSize = true };
        private readonly System.Windows.Forms.Timer uiTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        private bool showSources, cleaning;
        private string SourcesFlag { get { return Storage.File("SETTING - show sources and test labels.txt"); } }

        private TreeView ActiveTree { get { return leftTabs != null && leftTabs.SelectedTab == groupsTab ? groupTree : tree; } }

        // ---- 1. Left tabs: Stores | Groups | Watching ------------------------------------

        private Control BuildLeftTabs()
        {
            groupTree.Dock = DockStyle.Fill; groupTree.ShowLines = true; groupTree.ShowRootLines = true; groupTree.ShowPlusMinus = true;
            groupTree.HideSelection = false; groupTree.ShowNodeToolTips = true; groupTree.AfterSelect += TreeSelected;
            leftTabs = new TabControl { Dock = DockStyle.Fill };
            storesTab = new TabPage("Stores"); groupsTab = new TabPage("Groups"); watchTab = new TabPage("Watching");
            storesTab.Controls.Add(tree); groupsTab.Controls.Add(groupTree);
            watchList = new ListView();
            SetupGrid(watchList, new string[] { "Time", "Verdict", "Who is this", "Why", "Your block" }, new int[] { 60, 120, 260, 160, 140 });
            AddDenialMenu(watchList, null);
            watchList.DoubleClick += delegate { if (watchList.SelectedItems.Count > 0) OpenRefusalCard(watchList.SelectedItems[0].Tag as Denial); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 66, Padding = new Padding(4) };
            foreach (KeyValuePair<string, Action> b in new Dictionary<string, Action> {
                { "Live map", OpenLiveMap }, { "All denials", ShowDenials }, { "Rules", ShowRules }, { "Incident check", ShowIncidents } })
            {
                Action act = b.Value; Button button = new Button { Text = b.Key, AutoSize = true }; button.Click += delegate { act(); }; buttons.Controls.Add(button);
            }
            Label recent = new Label { Text = "Refused recently (newest first):", Dock = DockStyle.Top, Height = 20, Padding = new Padding(6, 4, 0, 0) };
            watchTab.Controls.Add(watchList); watchTab.Controls.Add(recent); watchTab.Controls.Add(buttons); watchTab.Controls.Add(watchState);
            leftTabs.TabPages.AddRange(new TabPage[] { storesTab, groupsTab, watchTab });
            leftTabs.SelectedIndexChanged += delegate
            {
                if (leftTabs.SelectedTab == watchTab) { RefreshWatchTab(); return; }
                TreeView t = ActiveTree;
                if (t.SelectedNode != null) TreeSelected(t, new TreeViewEventArgs(t.SelectedNode));
                else if (t.Nodes.Count > 0) t.SelectedNode = t.Nodes[0];
            };
            return leftTabs;
        }

        private void RefreshWatchTab()
        {
            bool on = denialWatcher != null;
            watchState.Text = on ? "● Watching Windows certificate checks" : "○ Not watching. Watch > Watch for certificate denials (run as admin once).";
            watchState.ForeColor = on ? Color.SeaGreen : Color.DimGray;
            if (watchList == null) return;
            watchList.BeginUpdate(); watchList.Items.Clear();
            foreach (Denial d in denials.Where(x => !x.Ok && !x.Noise).Reverse().Take(200))
            {
                if (d.Verdict == null) Annotate(d);
                ListViewItem row = new ListViewItem(new string[] { d.Time.ToString("HH:mm:ss"), VerdictWord(d), (d.Who ?? d.Program).Replace("\r\n", "  |  "), ShortReason(d.Reason), d.BlockedBy ?? "" }) { Tag = d };
                row.ForeColor = VerdictColor(d.Verdict);
                watchList.Items.Add(row);
            }
            watchList.EndUpdate();
        }
        private static string ShortReason(string reason) { int dash = reason.IndexOf(" — ", StringComparison.Ordinal); return dash > 0 ? reason.Substring(dash + 3) : reason; }

        // ---- 2. Status column instead of the giant found-in column -------------------------

        internal string StatusOf(CertificateRecord c)
        {
            if (rowBlocked.Contains(c.Identity)) return "BLOCKED" + RouteNote(c);
            Func<string, bool> inStore = delegate(string name)
            { return c.FoundIn.Concat(c.Collections).Any(p => p.IndexOf("\\" + name + "\\", StringComparison.OrdinalIgnoreCase) >= 0 || p.EndsWith("\\" + name, StringComparison.OrdinalIgnoreCase)); };
            string extra = (c.CollisionPeers.Count > 0 ? " · SHA-1 collision!" : c.WeakReasons.Count > 0 ? " · weak" : "") + RouteNote(c);
            if (inStore("Root") || inStore("AuthRoot")) return "Trusted root" + extra;
            if (inStore("CA")) return "Intermediate" + extra;
            if (inStore("TrustedPublisher")) return "Trusted publisher" + extra;
            if (inStore("My")) return "Your certificate" + extra;
            if (c.FoundIn.Contains(MicrosoftList.Label)) return "Not on PC (Microsoft list)" + extra;
            if (c.FoundIn.Contains(Ccadb.Label)) return "Not on PC (CCADB)" + extra;
            string first = c.FoundIn.FirstOrDefault();
            if (first == null) return "Other";
            string[] parts = first.Split('\\');
            return (parts.Length >= 2 ? parts[parts.Length - 2] : first) + extra;
        }

        internal ListViewItem CertificateRow(CertificateRecord r)
        {
            ListViewItem row = new ListViewItem(new string[] { r.SubjectShortName, r.IssuerShortName, r.SubjectCountry ?? "—", StatusOf(r), TagsOf(r),
                CertificateRecord.Time(r.NotBefore), CertificateRecord.Time(r.NotAfter), r.FoundInText });
            row.Tag = r;
            return row;
        }

        // ---- 3. Card tab ------------------------------------------------------------------

        private readonly Label cardName = new Label { Dock = DockStyle.Top, Height = 30, Font = new Font("Tahoma", 13F, FontStyle.Bold), AutoEllipsis = true };
        private readonly Label cardIssuer = new Label { Dock = DockStyle.Top, Height = 20, AutoEllipsis = true };
        private readonly Label cardStatus = new Label { Dock = DockStyle.Top, Height = 24, Font = new Font("Tahoma", 10F, FontStyle.Bold) };
        private readonly Label cardFacts = new Label { Dock = DockStyle.Top, Height = 92, AutoEllipsis = true };
        private readonly FlowLayoutPanel cardButtons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36 };

        private TabPage BuildCardTab()
        {
            TabPage card = new TabPage("Card");
            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 6, 10, 6), BackColor = SystemColors.Window };
            Button block = new Button { Text = "Block...", AutoSize = true };
            Button allow = AllowButton("Allow", SelectedTarget);
            Button unblock = new Button { Text = "Unblock", AutoSize = true };
            Button chain = new Button { Text = "Show chain", AutoSize = true };
            Button copy = new Button { Text = "Copy card", AutoSize = true };
            block.Click += delegate { BlockSelectedCertificate(); };
            unblock.Click += delegate { UnblockSelectedCertificate(); };
            chain.Click += delegate { ShowChain(SelectedCertificate()); };
            copy.Click += delegate { CertificateRecord c = SelectedCertificate(); if (c != null) CopyText(CertificateCard(c)); };
            cardButtons.Controls.AddRange(new Control[] { block, allow, unblock, chain, copy });
            body.Controls.Add(cardButtons); body.Controls.Add(cardFacts); body.Controls.Add(cardStatus); body.Controls.Add(cardIssuer); body.Controls.Add(cardName);
            card.Controls.Add(body);
            return card;
        }

        private void UpdateCard(CertificateRecord c)
        {
            if (c == null)
            {
                cardName.Text = address.Text; cardIssuer.Text = "Select a certificate in the list to see its card.";
                cardStatus.Text = ""; cardFacts.Text = ""; cardButtons.Enabled = false; return;
            }
            cardButtons.Enabled = true;
            cardName.Text = c.SubjectShortName + (c.SubjectCountry != null ? "   (" + c.SubjectCountry + ")" : "");
            cardIssuer.Text = "vouched for by " + c.IssuerShortName + (c.IssuerCountry != null ? " (" + c.IssuerCountry + ")" : "") + (c.Subject == c.Issuer ? "  — a root, it vouches for itself" : "");
            string status = StatusOf(c);
            bool blocked = status.StartsWith("BLOCKED", StringComparison.Ordinal);
            cardStatus.Text = blocked ? "BLOCKED by your Disallowed list" : status.StartsWith("Trusted", StringComparison.Ordinal) ? "Trusted by Windows: " + status : status;
            cardStatus.ForeColor = blocked ? Color.Firebrick : status.StartsWith("Trusted", StringComparison.Ordinal) ? Color.SeaGreen : Color.DimGray;
            string tags = TagsOf(c);
            string expiry = !c.NotAfter.HasValue ? "?" : c.NotAfter.Value < DateTime.UtcNow ? "EXPIRED " + c.NotAfter.Value.ToString("yyyy-MM-dd") : "valid until " + c.NotAfter.Value.ToString("yyyy-MM-dd");
            string owner = WhoIsWho.Owner(c), guard = TrustCategories.ProtectedBy(c);
            cardFacts.Text = (owner != null ? "Owner: " + owner + "\r\n" : "") + (guard != null ? "PROTECTED by trusted category: " + guard + "\r\n" : "") +
                "Tags: " + (tags.Length > 0 ? tags : "none") + "\r\n" + expiry + "   ·   " + c.KeyAlgorithm + (c.KeySize.HasValue ? " " + c.KeySize.Value + "-bit" : "") +
                (c.WeakReasons.Count > 0 ? "   ·   weak: " + String.Join(", ", c.WeakReasons.ToArray()) : "") + "\r\nSHA-1 " + c.Sha1;
        }

        // ---- 4. Hide the [to test] / [documented] homework labels unless asked --------------

        private static readonly Regex Labels = new Regex(@" ?\[(to test|documented|documented; [^\]]*|[^\]]*to test[^\]]*)\]", RegexOptions.IgnoreCase);
        private static readonly Regex SourceLines = new Regex(@"^(Microsoft term:|Learn:|Windows execution:|https://learn\.microsoft\.com).*(\r?\n|$)", RegexOptions.Multiline);
        internal string CleanText(string text)
        {
            if (showSources || text == null) return text;
            return SourceLines.Replace(Labels.Replace(text, ""), "");
        }
        private void CleanOnChange(Control box)
        {
            box.TextChanged += delegate
            {
                if (cleaning || showSources) return;
                string clean = CleanText(box.Text);
                if (clean != box.Text) { cleaning = true; box.Text = clean; cleaning = false; }
            };
        }

        // ---- 5 & 6. Menus, status bar and toolbar ----------------------------------------

        private void InitializeFriendly(MainMenu menu, MenuItem view, FlowLayoutPanel toolbar, Panel statusBar)
        {
            showSources = File.Exists(SourcesFlag);
            foreach (Control c in new Control[] { details, issuerDetails, status }) CleanOnChange(c);
            MenuItem sources = new MenuItem("Show sources and test labels") { Checked = showSources };
            sources.Click += delegate
            {
                showSources = !showSources; sources.Checked = showSources;
                try { Directory.CreateDirectory(Path.GetDirectoryName(SourcesFlag)); if (showSources) File.WriteAllText(SourcesFlag, "on"); else File.Delete(SourcesFlag); } catch (IOException) { }
                StartScan();
            };
            view.MenuItems.Add(new MenuItem("-")); view.MenuItems.Add(sources);

            // Watch and Tools menus, built by moving existing items out of View and Block.
            MenuItem watch = new MenuItem("&Watch"), tools = new MenuItem("&Tools");
            MenuItem block = menu.MenuItems.Cast<MenuItem>().First(m => m.Text == "&Block");
            MoveMenuItems(view, watch, "&Watch for certificate denials", "Certificate &denials", "Live certificate &map", "&Incident check");
            MoveMenuItems(view, tools, "&Standings", "Edit my &tags...");
            tools.MenuItems.Add("-");
            MoveMenuItems(block, tools, "Update &Microsoft root list", "Update &CCADB list (all CA certificates, catches cross-signs)");
            int at = menu.MenuItems.IndexOf(view) + 1;
            menu.MenuItems.Add(at, watch); menu.MenuItems.Add(at + 1, tools);
            InitializeReputation(tools);
            InitializePrograms(watch, toolbar);
            InitializeReroute(tools, toolbar);
            InitializeShell(tools);
            Tidy(view); Tidy(block);

            // Toolbar: the daily actions.
            toolbar.Controls.Add(new Label { Width = 12 });
            Button map = new Button { Text = "Live map", AutoSize = true }; map.Click += delegate { OpenLiveMap(); };
            denialsButton.Click += delegate { ShowDenials(); };
            Button allow = AllowButton("Allow", SelectedTarget);
            Button toolsButton = new Button { Text = "Tools", AutoSize = true }; toolsButton.Click += delegate { ShowToolsPage(); };
            toolbar.Controls.AddRange(new Control[] { map, denialsButton, allow, toolsButton });

            // Status bar: small sections on the right.
            refusedLink.LinkClicked += delegate { ShowDenials(); };
            statusBar.Controls.Add(refusedLink); statusBar.Controls.Add(watchDot);
            uiTimer.Tick += delegate { UpdateIndicators(); };
            uiTimer.Start();
            FormClosed += delegate { uiTimer.Stop(); };
            UpdateIndicators();
        }

        private AllowTarget SelectedTarget()
        {
            CertificateRecord c = SelectedCertificate();
            return c == null ? new AllowTarget { Certs = delegate { return new List<CertificateRecord>(); }, NothingWhy = "Select a blocked certificate in the list first." } : TargetFor(c);
        }

        private static void MoveMenuItems(MenuItem from, MenuItem to, params string[] texts)
        {
            foreach (string text in texts)
            {
                MenuItem item = from.MenuItems.Cast<MenuItem>().FirstOrDefault(m => m.Text == text);
                if (item != null) { from.MenuItems.Remove(item); to.MenuItems.Add(item); }
            }
        }
        private static void Tidy(MenuItem menu)
        {
            // Drop doubled or trailing separators left behind by moves.
            for (int i = menu.MenuItems.Count - 1; i >= 0; i--)
            {
                bool sep = menu.MenuItems[i].Text == "-";
                bool prevSep = i == 0 || menu.MenuItems[i - 1].Text == "-";
                if (sep && (prevSep || i == menu.MenuItems.Count - 1)) menu.MenuItems.RemoveAt(i);
            }
        }

        private void UpdateIndicators()
        {
            bool on = denialWatcher != null;
            watchDot.Text = on ? "● Watching" : "○ Not watching";
            watchDot.ForeColor = on ? Color.SeaGreen : Color.Gray;
            int today = denials.Count(d => !d.Ok && !d.Noise && d.Time.Date == DateTime.Today);
            refusedLink.Text = "Refused today: " + today;
            refusedLink.LinkColor = today > 0 ? Color.Firebrick : Color.DimGray;
            denialsButton.Text = "Denials (" + today + ")";
            denialsButton.ForeColor = today > 0 ? Color.Firebrick : SystemColors.ControlText;
            UpdateTrayHover();
        }
    }
}
