using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    internal sealed partial class ExplorerForm : Form
    {
        private readonly TreeView tree = new TreeView();
        private readonly ListView list = new ListView();
        private readonly TextBox details = new TextBox();
        private readonly TextBox issuerDetails = new TextBox();
        private readonly TextBox address = new TextBox();
        private readonly Label status = new Label();
        private readonly LinkLabel errorsLink = new LinkLabel();
        private readonly Button refresh = new Button();
        private readonly MenuItem refreshMenu;
        private readonly List<string> sessionLog = new List<string>();
        private readonly string sourceDirectory;
        private HistoryArchive history;
        private string historyStartupError;
        private readonly string archiveDirectory;
        private readonly System.Windows.Forms.Timer historyTimer = new System.Windows.Forms.Timer();
        private Snapshot snapshot;
        private volatile bool closed;
        private volatile bool collectorsClosed, scanWorkerFinished = true;
        private bool scanning;
        private int sortColumn;
        private bool ascending = true;
        private string nodeDetails = "Select a system store location, system store, or physical store.";

        internal ExplorerForm(string sourceDirectory) : this(sourceDirectory, HistoryArchive.DefaultDirectory) { }
        internal ExplorerForm(string sourceDirectory, string archiveDirectory)
        {
            this.sourceDirectory = sourceDirectory;
            this.archiveDirectory = archiveDirectory;
            Text = "kisib.dub-sar v0.1 — read-only certificate explorer";
            Icon = SystemIcons.Application;
            Font = new Font("Tahoma", 9F);
            BackColor = SystemColors.Control;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1150, 750);
            MinimumSize = new Size(660, 470);
            AutoScaleMode = AutoScaleMode.Font;

            MainMenu menu = new MainMenu();
            MenuItem file = new MenuItem("&File");
            file.MenuItems.Add(new MenuItem("E&xit", delegate { Close(); }));
            MenuItem view = new MenuItem("&View");
            refreshMenu = new MenuItem("&Refresh", delegate { StartScan(); }, Shortcut.F5);
            view.MenuItems.Add(refreshMenu);
            view.MenuItems.Add(new MenuItem("Activity &log", delegate { ShowLog(); }));
            view.MenuItems.Add(new MenuItem("&History log", delegate { ShowLog(); }));
            view.MenuItems.Add(new MenuItem("Enumeration &summary", delegate { ShowSummary(); }));
            view.MenuItems.Add(new MenuItem("Store &errors", delegate { ShowStoreErrors(); }));
            MenuItem certificate = new MenuItem("&Certificate");
            certificate.MenuItems.Add(new MenuItem("Copy SHA-&1", delegate { CopyHash(false); }));
            certificate.MenuItems.Add(new MenuItem("Copy SHA-&256", delegate { CopyHash(true); }));
            certificate.MenuItems.Add(new MenuItem("Copy &SPKI SHA-256", delegate { CopySpkiHash(); }));
            certificate.MenuItems.Add(new MenuItem("Certificate &history", delegate
            { CertificateRecord cert = SelectedCertificate(); if (cert != null) ShowHistory(cert.Sha256); }));
            MenuItem help = new MenuItem("&Help");
            help.MenuItems.Add(new MenuItem("Feature &sources", delegate { ShowSources(); }));
            help.MenuItems.Add(new MenuItem("&About", delegate { ShowText("About", "kisib.dub-sar v0.1\r\nRead-only Windows system certificate store explorer.\r\n\r\nAPI basis: documented. Windows 11 Home/Pro execution: to test.\r\n\r\nCertificate chains, CTLs, CCADB, and owner grids follow the enumeration gate.\r\n\r\nNo certificate store changes are implemented."); }));
            menu.MenuItems.AddRange(new MenuItem[] { file, certificate, view, help });
            Menu = menu;

            FlowLayoutPanel toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(3), WrapContents = false };
            refresh.Text = "Refresh"; refresh.AutoSize = true; refresh.Click += delegate { StartScan(); };
            Button logButton = new Button { Text = "History log", AutoSize = true };
            logButton.Click += delegate { ShowLog(); };
            toolbar.Controls.AddRange(new Control[] { refresh, logButton });
            Panel addressPanel = new Panel { Dock = DockStyle.Top, Height = 29, Padding = new Padding(7, 3, 3, 3) };
            Label addressLabel = new Label { Text = "Address", Dock = DockStyle.Left, Width = 60, TextAlign = ContentAlignment.MiddleLeft };
            address.Dock = DockStyle.Fill; address.ReadOnly = true;
            address.Text = Environment.MachineName + "\\Certificates";
            addressPanel.Controls.Add(address); addressPanel.Controls.Add(addressLabel);

            SplitContainer outer = new SplitContainer { Dock = DockStyle.Fill, Size = new Size(1150, 680),
                Orientation = Orientation.Vertical, SplitterWidth = 5, BorderStyle = BorderStyle.Fixed3D };
            outer.Panel1MinSize = 180; outer.Panel2MinSize = 260; outer.SplitterDistance = 340;
            tree.Dock = DockStyle.Fill; tree.ShowLines = true; tree.ShowRootLines = true; tree.ShowPlusMinus = true;
            tree.HideSelection = false; tree.HotTracking = false; tree.FullRowSelect = false;
            tree.ShowNodeToolTips = true;
            tree.AfterSelect += TreeSelected;
            tree.AccessibleName = "System store locations, system stores, and physical stores";
            outer.Panel1.Controls.Add(tree);

            SplitContainer right = new SplitContainer { Dock = DockStyle.Fill, Size = new Size(700, 680),
                Orientation = Orientation.Horizontal, SplitterWidth = 5, BorderStyle = BorderStyle.Fixed3D };
            right.Panel1MinSize = 100; right.Panel2MinSize = 110; right.SplitterDistance = 350;
            list.Dock = DockStyle.Fill; list.View = View.Details; list.FullRowSelect = true;
            list.MultiSelect = false; list.HideSelection = false; list.GridLines = false;
            list.AccessibleName = "Certificates in the selected store";
            list.Columns.Add("Subject CN", 215); list.Columns.Add("Issuer CN", 215);
            list.Columns.Add("C=", 48); list.Columns.Add("found in (physical stores)", 330);
            list.Columns.Add("not-before", 165); list.Columns.Add("not-after", 165);
            list.Columns.Add("SHA-1", 305); list.Columns.Add("SHA-256", 460);
            list.OwnerDraw = true;
            list.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e) { e.DrawDefault = true; };
            list.DrawSubItem += DrawCertificateCell;
            list.ColumnClick += delegate(object sender, ColumnClickEventArgs e)
            {
                ascending = e.Column != sortColumn || !ascending;
                sortColumn = e.Column;
                list.ListViewItemSorter = new CertificateComparer(sortColumn, ascending);
                list.Sort();
            };
            list.SelectedIndexChanged += delegate { ShowCertificate(); };
            right.Panel1.Controls.Add(list);

            FlowLayoutPanel hashToolbar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(2), WrapContents = true };
            Button sha1 = new Button { Text = "Copy SHA-1", AutoSize = true };
            Button sha256 = new Button { Text = "Copy SHA-256", AutoSize = true };
            Button spki = new Button { Text = "Copy SPKI SHA-256", AutoSize = true };
            sha1.Click += delegate { CopyHash(false); }; sha256.Click += delegate { CopyHash(true); };
            spki.Click += delegate { CopySpkiHash(); };
            hashToolbar.Controls.AddRange(new Control[] { sha1, sha256, spki });
            details.Dock = DockStyle.Fill; details.Multiline = true; details.ReadOnly = true;
            details.ScrollBars = ScrollBars.Both; details.WordWrap = false;
            details.BackColor = SystemColors.Window; details.Font = new Font("Consolas", 9F);
            details.AccessibleName = "Certificate details and source evidence";
            details.Text = nodeDetails;
            issuerDetails.Dock = DockStyle.Fill; issuerDetails.Multiline = true; issuerDetails.ReadOnly = true;
            issuerDetails.ScrollBars = ScrollBars.Both; issuerDetails.WordWrap = false;
            issuerDetails.BackColor = SystemColors.Window; issuerDetails.Font = details.Font;
            issuerDetails.AccessibleName = "Recorded issuer name; issuer certificate and chain not yet verified";
            issuerDetails.Text = "Select a certificate to inspect its recorded issuer name.";
            TabControl detailTabs = new TabControl { Dock = DockStyle.Fill };
            TabPage detailTab = new TabPage("Details");
            TabPage issuerTab = new TabPage("Issuer 🏛️");
            detailTab.Controls.Add(details); detailTab.Controls.Add(hashToolbar);
            issuerTab.Controls.Add(issuerDetails);
            detailTabs.TabPages.Add(detailTab); detailTabs.TabPages.Add(issuerTab);
            right.Panel2.Controls.Add(detailTabs);
            outer.Panel2.Controls.Add(right);
            InitializeControlLayer(outer, right, detailTabs, menu);

            Panel statusBar = new Panel { Dock = DockStyle.Bottom, Height = 25, BorderStyle = BorderStyle.Fixed3D };
            status.Dock = DockStyle.Fill;
            status.TextAlign = ContentAlignment.MiddleLeft; status.Padding = new Padding(4, 0, 0, 0);
            status.Text = "Read-only | Windows verification: to test";
            errorsLink.Dock = DockStyle.Right; errorsLink.Width = 100; errorsLink.TextAlign = ContentAlignment.MiddleLeft;
            errorsLink.Text = "0 errors"; errorsLink.AccessibleName = "Open the list of store errors";
            errorsLink.LinkClicked += delegate { ShowStoreErrors(); };
            statusBar.Controls.Add(status); statusBar.Controls.Add(errorsLink);
            Controls.Add(outer); Controls.Add(addressPanel); Controls.Add(toolbar); Controls.Add(statusBar);
            TreeNode initial = new TreeNode(Environment.MachineName + " — Certificates");
            initial.Nodes.Add("Enumeration starts when this window opens."); tree.Nodes.Add(initial); initial.Expand();
            Shown += delegate { StartScan(); };
            historyTimer.Interval = 60000;
            historyTimer.Tick += delegate { if (!scanning && !closed) StartScan(); };
            FormClosed += delegate
            {
                closed = true; historyTimer.Stop(); historyTimer.Dispose();
                CloseControlLayer();
                collectorsClosed = true;
                if ((!scanning || scanWorkerFinished) && history != null) history.Dispose();
            };
        }

        private void Post(Action action)
        {
            if (closed || IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(action); } catch (InvalidOperationException) { }
        }
        private void StartScan()
        {
            if (scanning) return;
            scanning = true; scanWorkerFinished = false; refresh.Enabled = false; refreshMenu.Enabled = false;
            status.Text = HistoryStatus() + " | Enumerating Windows stores...";
            Thread worker = new Thread(delegate()
            {
                Scanner scanner = null;
                try
                {
                    scanner = new Scanner(delegate(string message) { Post(delegate { status.Text = HistoryStatus() + " | " + message; }); }, delegate { return closed; }, history);
                    Snapshot result = scanner.Run();
                    if (history != null) history.Commit(result);
                    Post(delegate { Display(result); scanning = false; refresh.Enabled = true; refreshMenu.Enabled = true; });
                }
                catch (Exception ex)
                {
                    if (history != null) history.Note(scanner == null ? null : scanner.ScanId, "scan_failed", Environment.MachineName, ex.ToString());
                    Post(delegate
                    {
                        scanning = false; refresh.Enabled = true; refreshMenu.Enabled = true;
                        sessionLog.Add(DateTime.UtcNow.ToString("o") + "\tEnumeration failed\t" + ex.GetType().Name + "\t" + ex.Message);
                        status.Text = HistoryStatus() + " | Enumeration failed; see View > History log";
                        details.Text = ex.ToString();
                    });
                }
                finally { scanWorkerFinished = true; if (closed && collectorsClosed && history != null) history.Dispose(); }
            });
            worker.IsBackground = true; worker.Name = "Read-only certificate enumeration"; worker.Start();
        }

        private void Display(Snapshot result)
        {
            string selectedSource = NodeKey(tree.SelectedNode);
            CertificateRecord selectedCertificate = SelectedCertificate();
            HashSet<string> expanded = new HashSet<string>(StringComparer.Ordinal);
            foreach (TreeNode oldRoot in tree.Nodes) CollectExpanded(oldRoot, expanded);
            snapshot = result;
            if (history == null || history.FailedWrites > 0) sessionLog.AddRange(result.Log);
            tree.BeginUpdate(); tree.Nodes.Clear();
            TreeNode root = new TreeNode(Environment.MachineName + " — Certificates") { Tag = result };
            tree.Nodes.Add(root);
            foreach (StoreLocation location in result.Locations)
            {
                TreeNode locationNode = new TreeNode(location.Name + "   " + location.RegistryPath + (location.Error == null ? "" : " [error]")) { Tag = location };
                root.Nodes.Add(locationNode);
                foreach (SystemStore system in location.Stores)
                {
                    TreeNode systemNode = new TreeNode(system.Name + " (" + system.Certificates.Count + (system.ReadSucceeded ? "" : " observed") + ")" +
                        (system.Error == null && system.PhysicalEnumerationError == null ? "" : " [error]")) { Tag = system,
                        ToolTipText = Source("CertEnumSystemStore / CertEnumPhysicalStore", Sources.Physical) };
                    locationNode.Nodes.Add(systemNode);
                    foreach (PhysicalStore physical in system.PhysicalStores)
                        systemNode.Nodes.Add(new TreeNode(physical.Name + " (" + physical.Certificates.Count + (physical.ReadSucceeded ? "" : " observed") + ")" +
                            (physical.Error == null ? "" : " [error]")) { Tag = physical,
                            ToolTipText = physical.Path + "\r\n" + Source("CertEnumPhysicalStore", Sources.Physical) });
                    AddDocumentedPhysicalReferences(location, system, systemNode);
                }
                AddDocumentedSystemReferences(location, locationNode);
            }
            root.Expand();
            foreach (TreeNode child in root.Nodes)
            { StoreLocation location = child.Tag as StoreLocation; if (location != null && (location.Flags == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE || location.Flags == Native.CERT_SYSTEM_STORE_CURRENT_USER)) child.Expand(); }
            foreach (string key in expanded) { TreeNode node = FindNode(root, key); if (node != null) node.Expand(); }
            tree.EndUpdate(); tree.SelectedNode = FindNode(root, selectedSource) ?? root;
            if (selectedCertificate != null)
                foreach (ListViewItem row in list.Items)
                    if (((CertificateRecord)row.Tag).Der.SequenceEqual(selectedCertificate.Der)) { row.Selected = true; row.EnsureVisible(); break; }
            status.Text = HistoryStatus() + " | " + result.StoreCount + " system / " + result.PhysicalCount + " physical stores | " + result.Certificates.Count +
                " certificates | PC acceptance: to test";
            errorsLink.Text = result.Errors.Count + " errors";
        }

        private string HistoryStatus()
        {
            string error = historyStartupError ?? (history == null ? null : history.LastError);
            return error != null ? "Read-only stores | HISTORY ERROR: " + error : history == null ? "Read-only stores | Recording off" :
                "Read-only stores | Journal on | Archive " + (archiveToggle.Checked ? "on" : "off");
        }
        private static string NodeKey(TreeNode node)
        {
            if (node == null) return null;
            DocumentedStoreReference reference = node.Tag as DocumentedStoreReference;
            if (reference != null) return "documented:" + reference.Path;
            StoreLocation location = node.Tag as StoreLocation;
            SystemStore store = node.Tag as SystemStore;
            PhysicalStore physical = node.Tag as PhysicalStore;
            return location != null ? "location:" + location.Name : store != null ? "system:" + store.Path : physical != null ? "physical:" + physical.Path : "root";
        }
        private static TreeNode FindNode(TreeNode node, string key)
        {
            if (key != null && NodeKey(node) == key) return node;
            foreach (TreeNode child in node.Nodes) { TreeNode found = FindNode(child, key); if (found != null) return found; }
            return null;
        }
        private static void CollectExpanded(TreeNode node, HashSet<string> keys)
        {
            if (node.IsExpanded) keys.Add(NodeKey(node));
            foreach (TreeNode child in node.Nodes) CollectExpanded(child, keys);
        }

        private void TreeSelected(object sender, TreeViewEventArgs args)
        {
            if (snapshot == null) return;
            object selected = args.Node.Tag;
            HashSet<string> keys = new HashSet<string>(StringComparer.Ordinal);
            StoreLocation location = selected as StoreLocation;
            SystemStore system = selected as SystemStore;
            PhysicalStore physical = selected as PhysicalStore;
            DocumentedStoreReference reference = selected as DocumentedStoreReference;
            if (reference != null)
            {
                address.Text = reference.Path;
                nodeDetails = reference.Description;
            }
            else if (selected is Snapshot)
            {
                keys.UnionWith(snapshot.Certificates.Keys);
                address.Text = Environment.MachineName + "\\Certificates";
                nodeDetails = Summary();
            }
            else if (location != null)
            {
                foreach (SystemStore item in location.Stores)
                {
                    keys.UnionWith(item.Certificates);
                    foreach (PhysicalStore part in item.PhysicalStores) keys.UnionWith(part.Certificates);
                }
                address.Text = location.RegistryPath;
                nodeDetails = "System store location: " + location.Name + "\r\nWindows location name: " + location.WindowsName +
                    "\r\nRegistry path: " + location.RegistryPath + "\r\nSystem stores returned: " + location.Stores.Count +
                    "\r\nEnumeration: " + (location.Error ?? "Completed") + "\r\n\r\n" + Source("System Store Locations", Sources.Locations);
            }
            else if (system != null)
            {
                keys.UnionWith(system.Certificates);
                address.Text = system.Path;
                nodeDetails = "System store (logical collection): " + system.Path + "\r\nLocation registry path: " + system.RegistryPath +
                    "\r\nPhysical siblings: " + String.Join(" ", system.PhysicalStores.Select(item => item.Name).ToArray()) +
                    "\r\nCollection read: " + (system.Error ?? "Completed") + "\r\nPhysical enumeration: " + (system.PhysicalEnumerationError ?? "Completed") +
                    "\r\n\r\nThe list is the native collection result; no synthetic physical-store union is substituted.\r\n\r\n" + Source("CertEnumSystemStore / CertEnumPhysicalStore", Sources.Physical);
            }
            else if (physical != null)
            {
                keys.UnionWith(physical.Certificates);
                address.Text = physical.Path;
                nodeDetails = "Physical store: " + physical.Path + "\r\nProvider: " + physical.Provider +
                    "\r\nPredefined: " + physical.Predefined + "\r\ndwPriority: " + physical.Priority + "\r\ndwFlags: 0x" + physical.Flags.ToString("X8") +
                    "\r\nRead: " + (physical.Error ?? "Completed") + "\r\n\r\n" + Source("CERT_PHYSICAL_STORE_INFO", Sources.PhysicalInfo);
            }
            list.BeginUpdate(); list.Items.Clear();
            foreach (string key in keys)
            {
                CertificateRecord record = snapshot.Certificates[key];
                if (!MatchesFind(record)) continue;
                ListViewItem row = new ListViewItem(new string[] { record.SubjectShortName, record.IssuerShortName, record.SubjectCountry ?? "—", record.FoundInText,
                    CertificateRecord.Time(record.NotBefore), CertificateRecord.Time(record.NotAfter), record.Sha1, record.Sha256 });
                row.Tag = record; list.Items.Add(row);
            }
            list.ListViewItemSorter = new CertificateComparer(sortColumn, ascending); list.Sort(); list.EndUpdate();
            details.Text = nodeDetails;
            issuerDetails.Text = "Select a certificate to inspect its recorded issuer name.";
        }

        private void DrawCertificateCell(object sender, DrawListViewSubItemEventArgs e)
        {
            CertificateRecord cert = e.Item.Tag as CertificateRecord;
            bool collision = cert != null && e.ColumnIndex == 6 && cert.CollisionPeers.Count > 0;
            bool warning = false;
            bool selected = e.Item.Selected;
            Color background = collision ? Color.Firebrick : selected ? SystemColors.Highlight : warning ? SystemColors.Info : SystemColors.Window;
            Color foreground = collision ? Color.White : selected ? SystemColors.HighlightText : warning ? SystemColors.InfoText : SystemColors.WindowText;
            using (Brush brush = new SolidBrush(background)) e.Graphics.FillRectangle(brush, e.Bounds);
            Rectangle bounds = e.Bounds; bounds.X += 4; bounds.Width = Math.Max(0, bounds.Width - 8);
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, list.Font, bounds, foreground,
                TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            if (selected && list.Focused && e.ColumnIndex == 0) ControlPaint.DrawFocusRectangle(e.Graphics, e.Bounds, foreground, background);
        }

        private CertificateRecord SelectedCertificate()
        {
            return list.SelectedItems.Count == 0 ? null : list.SelectedItems[0].Tag as CertificateRecord;
        }
        private void ShowCertificate()
        {
            CertificateRecord cert = SelectedCertificate();
            if (cert == null) { details.Text = nodeDetails; issuerDetails.Text = "Select a certificate to inspect its recorded issuer name."; return; }
            StringBuilder text = new StringBuilder();
            text.AppendLine("Subject: " + cert.Subject); text.AppendLine("Issuer: " + cert.Issuer);
            text.AppendLine("Subject CN: " + (cert.SubjectCn ?? "[absent or ambiguous]"));
            text.AppendLine("Issuer CN: " + (cert.IssuerCn ?? "[absent or ambiguous]"));
            text.AppendLine("Short-name fallback: O when CN is absent; a full DN is never used as a row label [to test].");
            text.AppendLine("Subject C=: " + (cert.SubjectCountry ?? "[unavailable]") + "; issuer C=: " + (cert.IssuerCountry ?? "[unavailable]") + " [documented attribute; extraction to test].");
            text.AppendLine("C= is the certificate's own declaration. Country affiliation verification: to test.");
            if (cert.DisplayNameError != null) text.AppendLine("Name attribute read: " + cert.DisplayNameError);
            text.AppendLine(Source("CERT_RDN_ATTR / commonName / organizationName / countryName", Sources.NameAttributes));
            text.AppendLine("Thumbprint (SHA-1): " + cert.Sha1); text.AppendLine("SHA-256: " + cert.Sha256);
            text.AppendLine("Not before: " + CertificateRecord.Time(cert.NotBefore)); text.AppendLine("Not after: " + CertificateRecord.Time(cert.NotAfter));
            text.AppendLine("Key algorithm [documented]: " + cert.KeyAlgorithm);
            text.AppendLine("Key size (bits) [to test]: " + (cert.KeySize.HasValue ? cert.KeySize.Value.ToString() : "[unavailable]"));
            text.AppendLine("Signature algorithm [documented]: " + cert.SignatureAlgorithm);
            text.AppendLine("Signature digest [to test]: " + (cert.SignatureHash ?? "[unavailable]"));
            text.AppendLine("SPKI SHA-256 [to test]: " + (cert.SpkiSha256 ?? "[unavailable]"));
            text.AppendLine("Weak tier: " + cert.WeakTierText);
            text.AppendLine("SHA-1 collision: " + cert.CollisionText);
            AppendPeers(text, cert.CollisionPeers, "Collision peers (different full-certificate SHA-256)");
            text.AppendLine("Key reuse: " + cert.KeyReuseText);
            AppendPeers(text, cert.KeyReusePeers, "Key-reuse peers (different complete Subject strings)");
            text.AppendLine("Signals cover the observed inventory, including stores outside this selected folder.");
            text.AppendLine("Weak tier is the requested local RSA <2048 / MD5 / SHA-1 signature rule, not a Windows trust verdict.");
            text.AppendLine("The complete original DER SubjectPublicKeyInfo is hashed, including algorithm and parameters.");
            if (cert.CryptoError != null) text.AppendLine("Metadata assessment: " + cert.CryptoError);
            text.AppendLine("Key Usage: " + cert.KeyUsage); text.AppendLine();
            text.AppendLine("Found in (observed physical stores):");
            if (cert.FoundIn.Count == 0) text.AppendLine("  Unresolved in this snapshot [to test]");
            foreach (string path in cert.FoundIn) text.AppendLine("  " + path);
            text.AppendLine(); text.AppendLine("Observed logical collections:");
            foreach (string path in cert.Collections) text.AppendLine("  " + path);
            text.AppendLine(); text.AppendLine("Enhanced Key Usage by occurrence — CertGetEnhancedKeyUsage:");
            foreach (KeyValuePair<string, SortedSet<string>> usage in cert.UsageBySource)
            {
                text.AppendLine("  " + usage.Key);
                foreach (string value in usage.Value) text.AppendLine("    " + value);
            }
            text.AppendLine(); text.AppendLine("Source: native enumerated store identity. Physical-to-registry resolution: to test.");
            text.AppendLine("Per-purpose chain policy: not evaluated [to test].");
            text.AppendLine("Microsoft / Mozilla program status: not loaded [to test].");
            if (cert.ParseError != null) text.AppendLine("Decode error: " + cert.ParseError);
            text.AppendLine(); text.AppendLine(Source("CertEnumCertificatesInStore", Sources.Certificates));
            text.AppendLine(Source("CertGetEnhancedKeyUsage", Sources.Usage));
            text.AppendLine(Source("PublicKey.Oid", Sources.PublicKey));
            text.AppendLine(Source("X509Certificate2.SignatureAlgorithm", Sources.Signature));
            text.AppendLine(Source("CERT_PUBLIC_KEY_INFO / SubjectPublicKeyInfo", Sources.Spki));
            text.AppendLine("SPKI encoding extraction and local inspection rules: to test.");
            details.Text = text.ToString();
            details.Text = text.ToString();
            issuerDetails.Text = "Issuer name recorded in the selected certificate [documented]:\r\n" + cert.Issuer +
                "\r\n\r\nSelected certificate Subject:\r\n" + cert.Subject + "\r\nSelected certificate SHA-256:\r\n" + cert.Sha256 +
                "\r\n\r\nIssuer certificate, issuer store, and chain trust: not resolved [to test].\r\n" +
                "CertGetCertificateChain remains after the machine enumeration gate.\r\n" +
                "A matching issuer name or hash lookup does not establish an issuer link.\r\n\r\n" + Source("X509Certificate2.Issuer", Sources.Issuer);
        }

        private void AppendPeers(StringBuilder text, IEnumerable<string> peers, string label)
        {
            string[] keys = peers.ToArray();
            if (keys.Length == 0) return;
            text.AppendLine(label + ":");
            foreach (string key in keys)
            {
                CertificateRecord peer;
                if (snapshot != null && snapshot.Certificates.TryGetValue(key, out peer))
                {
                    text.AppendLine("  Subject: " + peer.Subject); text.AppendLine("  SHA-256: " + peer.Sha256);
                    text.AppendLine("  Found in: " + peer.FoundInText);
                }
            }
        }

        private static string Source(string term, string url) { return "Microsoft term: " + term + " [documented]\r\nLearn: " + url + "\r\nWindows execution: to test"; }
        private void CopyHash(bool sha256)
        {
            CertificateRecord cert = SelectedCertificate();
            if (cert == null) { status.Text = "Select a certificate to copy its hash."; return; }
            try { Clipboard.SetText(sha256 ? cert.Sha256 : cert.Sha1); }
            catch (System.Runtime.InteropServices.ExternalException ex) { status.Text = "Clipboard: " + ex.Message; }
        }
        private void CopySpkiHash()
        {
            CertificateRecord cert = SelectedCertificate();
            if (cert == null || cert.SpkiSha256 == null) { status.Text = "Select a certificate with available SPKI SHA-256."; return; }
            try { Clipboard.SetText(cert.SpkiSha256); }
            catch (System.Runtime.InteropServices.ExternalException ex) { status.Text = "Clipboard: " + ex.Message; }
        }
        private string Summary()
        {
            if (snapshot == null) return "Enumeration has not finished.";
            StringBuilder text = new StringBuilder();
            text.AppendLine("System store enumeration snapshot [Windows execution: to test]");
            text.AppendLine("Started: " + snapshot.Started.ToString("o")); text.AppendLine("Finished: " + snapshot.Finished.ToString("o"));
            text.AppendLine("Locations: " + snapshot.Locations.Count); text.AppendLine("System stores: " + snapshot.StoreCount);
            text.AppendLine("Physical stores: " + snapshot.PhysicalCount); text.AppendLine("Distinct certificates: " + snapshot.Certificates.Count);
            text.AppendLine("Unresolved physical sources: " + snapshot.UnresolvedCount); text.AppendLine("Errors: " + snapshot.Errors.Count);
            text.AppendLine("Canceled: " + snapshot.Canceled); text.AppendLine();
            text.AppendLine("Journal: " + (journalToggle.Checked ? "on" : "off") + "; public-certificate archive: " + (archiveToggle.Checked ? "on" : "off") + " [to test].");
            text.AppendLine("60-second automatic scan: " + (historyTimer.Enabled ? "on" : "off") + "; scans do not overlap [to test].");
            text.AppendLine("Reads are not atomic. Changes between scans, while closed, and outside accessible stores require additional observations.");
            text.AppendLine("Optional history directory: " + archiveDirectory);
            text.AppendLine(HistoryStatus());
            text.AppendLine("USERS covers Windows-discoverable user stores; unloaded user hives are not loaded.");
            text.AppendLine("CURRENT_SERVICE depends on the calling service context; this desktop process does not invent one.");
            text.AppendLine("An inaccessible or unreturned store is not proof that no certificates exist there.");
            text.AppendLine();
            foreach (StoreLocation location in snapshot.Locations)
            {
                text.AppendLine(location.Name + " | " + location.Stores.Count + " stores | " + (location.Error ?? "Enumeration completed"));
                if (!location.Enumerated) text.AppendLine("  Location was not returned; its documented API flag was queried explicitly.");
            }
            text.AppendLine();
            foreach (string error in snapshot.Errors) text.AppendLine(error);
            text.AppendLine(); text.AppendLine(Source("CertEnumSystemStoreLocation", Sources.EnumLocations));
            return text.ToString();
        }
        private void ShowSummary() { ShowText("Enumeration summary", Summary()); }
        private void ShowLog() { ShowHistory(null); }
        private void ShowHistory(string sha256)
        {
            CertificateRecord selected = SelectedCertificate();
            string sha1 = sha256 != null && selected != null && selected.Sha256 == sha256 ? selected.Sha1 : null;
            if (history == null)
            {
                ShowText("History log", "Journal is off. View > Optional features > Journal enables continuing records [to test].\r\n" +
                    (historyStartupError ?? "") + "\r\n\r\nCurrent-session observations (memory only):\r\n" + String.Join(Environment.NewLine, sessionLog.ToArray()));
                return;
            }
            try
            {
                string[] files = history.JournalFiles();
                using (Form dialog = new Form { Text = sha256 == null ? "History log — retained sessions" : "Certificate history — " + sha256,
                    Size = new Size(1040, 620), StartPosition = FormStartPosition.CenterParent, Font = Font })
                {
                    FlowLayoutPanel controls = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, WrapContents = false };
                    ComboBox dates = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
                    dates.Items.AddRange(files.Select(x => (object)Path.GetFileNameWithoutExtension(x)).ToArray());
                    Button previous = new Button { Text = "Previous page", AutoSize = true };
                    Button next = new Button { Text = "Next page", AutoSize = true };
                    Label pageLabel = new Label { AutoSize = true, Padding = new Padding(3, 8, 0, 0) };
                    controls.Controls.AddRange(new Control[] { new Label { Text = "Date (UTC)", AutoSize = true, Padding = new Padding(3, 8, 0, 0) }, dates, previous, next, pageLabel });
                    TextBox text = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Both,
                        WordWrap = false, Font = new Font("Consolas", 9F), BackColor = SystemColors.Window };
                    Label path = new Label { Dock = DockStyle.Bottom, Height = 34, Text = HistoryStatus() + "\r\n" + history.DirectoryPath };
                    Button closeButton = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                    int page = 0;
                    Action loadPage = delegate
                    {
                        bool more = false;
                        try { text.Text = dates.SelectedIndex < 0 ? "No retained journal dates." : history.ReadPage(files[dates.SelectedIndex], sha256, page, out more, sha1); }
                        catch (Exception ex) { text.Text = "History read failed: " + ex.Message; }
                        previous.Enabled = page > 0; next.Enabled = more;
                        pageLabel.Text = "Page " + (page + 1) + " | 500 events per page; all records retained";
                    };
                    dates.SelectedIndexChanged += delegate { page = 0; loadPage(); };
                    previous.Click += delegate { if (page > 0) { page--; loadPage(); } };
                    next.Click += delegate { page++; loadPage(); };
                    dialog.Controls.Add(text); dialog.Controls.Add(controls); dialog.Controls.Add(path); dialog.Controls.Add(closeButton);
                    dialog.CancelButton = closeButton;
                    if (files.Length > 0) dates.SelectedIndex = files.Length - 1; else loadPage();
                    dialog.ShowDialog(this);
                }
            }
            catch (Exception ex) { ShowText("History read failed", ex.ToString()); }
        }
        private void ShowSources()
        {
            string path = Path.Combine(sourceDirectory, "docs", "feature-sources.csv");
            try { ShowText("Feature sources — documented / to test", File.ReadAllText(path)); }
            catch (IOException ex) { ShowText("Feature sources", "Could not read " + path + "\r\n" + ex.Message); }
        }
        private void ShowText(string title, string content)
        {
            using (Form dialog = new Form { Text = title, Size = new Size(950, 570), StartPosition = FormStartPosition.CenterParent, Font = Font })
            {
                TextBox text = new TextBox { Dock = DockStyle.Fill, Text = content, ReadOnly = true, Multiline = true,
                    ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9F), BackColor = SystemColors.Window };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(text); dialog.Controls.Add(close); dialog.CancelButton = close; dialog.ShowDialog(this);
            }
        }
        private sealed class CertificateComparer : IComparer
        {
            private readonly int column;
            private readonly bool ascending;
            internal CertificateComparer(int column, bool ascending) { this.column = column; this.ascending = ascending; }
            public int Compare(object x, object y)
            {
                ListViewItem left = (ListViewItem)x, right = (ListViewItem)y;
                CertificateRecord a = (CertificateRecord)left.Tag, b = (CertificateRecord)right.Tag;
                int comparison = column == 4 ? Nullable.Compare(a.NotBefore, b.NotBefore) : column == 5 ? Nullable.Compare(a.NotAfter, b.NotAfter) :
                    StringComparer.OrdinalIgnoreCase.Compare(left.SubItems[column].Text, right.SubItems[column].Text);
                return ascending ? comparison : -comparison;
            }
        }
    }
    internal static class Sources
    {
        internal const string Locations = "https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations";
        internal const string EnumLocations = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumsystemstorelocation";
        internal const string Physical = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumphysicalstore";
        internal const string PhysicalInfo = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_physical_store_info";
        internal const string Certificates = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore";
        internal const string Usage = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetenhancedkeyusage";
        internal const string PublicKey = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.publickey?view=netframework-4.8.1";
        internal const string Signature = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.signaturealgorithm?view=netframework-4.8.1";
        internal const string Spki = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info";
        internal const string Issuer = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.issuer?view=netframework-4.8.1";
        internal const string NameAttributes = "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_rdn_attr";
    }
}
