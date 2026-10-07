using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    internal sealed class ExplorerScope
    {
        internal string Key, Description, ApplicationKey, Country;
        internal readonly HashSet<string> CertificateKeys = new HashSet<string>(StringComparer.Ordinal);
    }

    internal sealed partial class ExplorerForm
    {
        private ActivityMonitor activity;
        private SyscallTrace syscalls;
        private IssuerLabels labels;
        private readonly TextBox findIssuer = new TextBox();
        private readonly ComboBox groupBy = new ComboBox();
        private readonly ComboBox sortBy = new ComboBox();
        private readonly ListView applicationList = new ListView();
        private readonly ListView activityList = new ListView();
        private readonly ListView countryList = new ListView();
        private readonly Label liveStatus = new Label();
        private readonly TextBox activityDetails = new TextBox();
        private readonly TreeView relationships = new TreeView();
        private readonly System.Windows.Forms.Timer activityTimer = new System.Windows.Forms.Timer();
        private readonly List<ActivityRecord> recentActivity = new List<ActivityRecord>();
        private readonly Button syscallButton = new Button();
        private TabControl resultTabs;
        private TabControl evidenceTabs;
        private int activityTicks, appRefreshInProgress, activityStartInProgress, activityRequestGeneration;
        private long activityRowsRetired;
        private string labelsError;
        private readonly Dictionary<string, ApplicationSignature> applicationSignatures = new Dictionary<string, ApplicationSignature>(StringComparer.Ordinal);
        private bool refreshingControls;

        private void InitializeControlLayer(SplitContainer outer, SplitContainer right, FlowLayoutPanel toolbar, TabControl detailTabs, MainMenu menu)
        {
            activity = new ActivityMonitor(history); syscalls = new SyscallTrace(history, activity.Publish);
            try { labels = new IssuerLabels(CountryCatalog.Read(sourceDirectory), history == null ? new AnnotationSet() : history.LoadAnnotations()); }
            catch (Exception ex) { labelsError = ex.Message; labels = new IssuerLabels(null, new AnnotationSet()); if (history != null) history.Note(null, "issuer_labels_unavailable", sourceDirectory, ex.ToString()); }
            if (history != null && labels.Catalog != null) history.RecordCountryCatalog(labels.Catalog);

            TableLayoutPanel organize = new TableLayoutPanel { Dock = DockStyle.Top, Height = 111, ColumnCount = 2, RowCount = 4, Padding = new Padding(4) };
            organize.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 65)); organize.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Label title = new Label { Text = "Issuer explorer 🏛️", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            organize.Controls.Add(title, 0, 0); organize.SetColumnSpan(title, 2);
            organize.Controls.Add(new Label { Text = "Find issuer", AutoSize = true }, 0, 1); findIssuer.Dock = DockStyle.Fill; organize.Controls.Add(findIssuer, 1, 1);
            organize.Controls.Add(new Label { Text = "Group by", AutoSize = true }, 0, 2);
            groupBy.DropDownStyle = ComboBoxStyle.DropDownList; groupBy.Dock = DockStyle.Fill;
            groupBy.Items.AddRange(new object[] { "Issuer", "Country", "Corporation", "Monarchy", "Tags", "Applications" }); groupBy.SelectedIndex = 0; organize.Controls.Add(groupBy, 1, 2);
            organize.Controls.Add(new Label { Text = "Sort by", AutoSize = true }, 0, 3);
            sortBy.DropDownStyle = ComboBoxStyle.DropDownList; sortBy.Dock = DockStyle.Fill;
            sortBy.Items.AddRange(new object[] { "Name", "Name descending", "Certificate count" }); sortBy.SelectedIndex = 0; organize.Controls.Add(sortBy, 1, 3);
            outer.Panel1.Controls.Add(organize);
            findIssuer.TextChanged += delegate { RebuildControlBranches(); };
            groupBy.SelectedIndexChanged += delegate { RebuildControlBranches(); };
            sortBy.SelectedIndexChanged += delegate { RebuildControlBranches(); };

            right.Panel1.Controls.Remove(list);
            resultTabs = new TabControl { Dock = DockStyle.Fill };
            TabPage certificates = new TabPage("Certificates"), apps = new TabPage("Applications"), events = new TabPage("Live activity"), countries = new TabPage("Countries");
            certificates.Controls.Add(list); apps.Controls.Add(applicationList); events.Controls.Add(activityList); countries.Controls.Add(countryList);
            resultTabs.TabPages.AddRange(new TabPage[] { certificates, apps, events, countries }); right.Panel1.Controls.Add(resultTabs);
            SetupGrid(applicationList, new string[] { "Process name", "Process ID", "Start time", "Executable path", "Access status" }, new int[] { 180, 90, 180, 410, 310 });
            SetupGrid(activityList, new string[] { "TimeCreated", "Process ID", "Thread ID", "Provider / source", "Event ID / opcode", "Operation", "Result", "Certificate references" }, new int[] { 190, 85, 85, 265, 130, 230, 300, 470 });
            SetupGrid(countryList, new string[] { "Country or area", "ISO-alpha2", "Monarchy", "Classification source", "List date" }, new int[] { 290, 100, 150, 510, 150 });
            applicationList.SelectedIndexChanged += delegate { SelectApplication(); };
            activityList.SelectedIndexChanged += delegate { SelectActivity(); };
            countryList.SelectedIndexChanged += delegate { SelectCountry(); };
            evidenceTabs = detailTabs;
            TabPage activityTab = new TabPage("Activity evidence");
            activityDetails.Dock = DockStyle.Fill; activityDetails.ReadOnly = true; activityDetails.Multiline = true;
            activityDetails.ScrollBars = ScrollBars.Both; activityDetails.WordWrap = false; activityDetails.Font = details.Font;
            activityTab.Controls.Add(activityDetails); detailTabs.TabPages.Add(activityTab);
            TabPage relationshipTab = new TabPage("Relationships");
            relationships.Dock = DockStyle.Fill; relationships.ShowLines = true; relationships.ShowRootLines = true; relationships.ShowPlusMinus = true;
            relationshipTab.Controls.Add(relationships); detailTabs.TabPages.Add(relationshipTab);
            liveStatus.Dock = DockStyle.Top; liveStatus.AutoSize = true; liveStatus.Padding = new Padding(4); right.Panel1.Controls.Add(liveStatus);

            Button live = new Button { Text = "Live CAPI2", AutoSize = true }; live.Click += delegate { StartCertificateActivity(); };
            syscallButton.Text = "Start syscalls"; syscallButton.AutoSize = true; syscallButton.Click += delegate { ToggleSyscalls(); };
            Button label = new Button { Text = "Issuer labels", AutoSize = true }; label.Click += delegate { EditCertificateLabels(); };
            Button country = new Button { Text = "Country labels", AutoSize = true }; country.Click += delegate { EditCountryLabels(); };
            toolbar.Controls.AddRange(new Control[] { live, syscallButton, label, country });
            MenuItem liveMenu = new MenuItem("&Live");
            liveMenu.MenuItems.Add(new MenuItem("Start certificate activity", delegate { StartCertificateActivity(); }));
            liveMenu.MenuItems.Add(new MenuItem("Replay available CAPI2 records", delegate { StartCertificateActivity(true); }));
            liveMenu.MenuItems.Add(new MenuItem("Stop certificate activity", delegate { Interlocked.Increment(ref activityRequestGeneration); activity.Stop(); UpdateLiveStatus(); }));
            liveMenu.MenuItems.Add(new MenuItem("Enable Windows CAPI2 logging", delegate { EnableCapi2(); }));
            liveMenu.MenuItems.Add(new MenuItem("Open Windows Event Viewer", delegate { try { Process.Start("eventvwr.msc"); } catch (Exception ex) { ShowText("Event Viewer", ex.Message); } }));
            liveMenu.MenuItems.Add(new MenuItem("Start / stop syscalls", delegate { ToggleSyscalls(); }));
            liveMenu.MenuItems.Add(new MenuItem("Capture coverage", delegate { ShowText("Capture coverage", Coverage()); }));
            liveMenu.MenuItems.Add(new MenuItem("Retained certificate activity", delegate { ShowActivityArchive(false); }));
            liveMenu.MenuItems.Add(new MenuItem("Retained syscall ETLs", delegate { ShowActivityArchive(true); }));
            liveMenu.MenuItems.Add(new MenuItem("Selected application's embedded signer", delegate { ReadSelectedApplicationSigner(); }));
            menu.MenuItems.Add(liveMenu);

            PopulateCountries(); UpdateLiveStatus();
            Shown += delegate { StartCertificateActivity(); };
            activityTimer.Interval = 1000; activityTimer.Tick += delegate { ActivityTick(); }; activityTimer.Start();
        }

        private static void SetupGrid(ListView grid, string[] names, int[] widths)
        {
            grid.Dock = DockStyle.Fill; grid.View = View.Details; grid.FullRowSelect = true; grid.MultiSelect = false; grid.HideSelection = false;
            for (int i = 0; i < names.Length; i++) grid.Columns.Add(names[i], widths[i]);
            bool ascending = true; int previous = -1;
            grid.ColumnClick += delegate(object sender, ColumnClickEventArgs args)
            { ascending = args.Column != previous || !ascending; previous = args.Column; grid.ListViewItemSorter = new PlainComparer(args.Column, ascending); grid.Sort(); };
        }
        private sealed class PlainComparer : System.Collections.IComparer
        {
            private readonly int column; private readonly bool ascending;
            internal PlainComparer(int column, bool ascending) { this.column = column; this.ascending = ascending; }
            public int Compare(object a, object b)
            {
                string first = ((ListViewItem)a).SubItems[column].Text, second = ((ListViewItem)b).SubItems[column].Text;
                long firstNumber, secondNumber;
                int value = Int64.TryParse(first, out firstNumber) && Int64.TryParse(second, out secondNumber) ? firstNumber.CompareTo(secondNumber) : StringComparer.OrdinalIgnoreCase.Compare(first, second);
                return ascending ? value : -value;
            }
        }
        private void StartCertificateActivity(bool replayAvailable = false)
        {
            if (closed || Interlocked.CompareExchange(ref activityStartInProgress, 1, 0) != 0) return;
            int generation = Interlocked.Increment(ref activityRequestGeneration);
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    if (!closed) activity.RefreshApplications();
                    activity.Restart(replayAvailable, delegate { return !closed && Interlocked.CompareExchange(ref activityRequestGeneration, 0, 0) == generation; });
                }
                catch (Exception ex) { if (history != null) history.Note(null, "application_collection_failed", Environment.MachineName, ex.ToString()); }
                finally { Interlocked.Exchange(ref activityStartInProgress, 0); }
                Post(delegate { UpdateLiveStatus(); PopulateApplications(); RebuildControlBranches(); });
            });
        }
        private void EnableCapi2()
        {
            try
            {
                using (EventLogConfiguration configuration = new EventLogConfiguration(ActivityMonitor.Channel))
                { if (!configuration.IsEnabled) { configuration.IsEnabled = true; configuration.SaveChanges(); } }
                if (history != null) history.Note(null, "capi2_logging_enabled", ActivityMonitor.Channel, "Explicit Live menu action; existing Windows records and log size retained.");
                StartCertificateActivity();
            }
            catch (Exception ex) { ShowText("CAPI2 logging", "Windows did not enable the diagnostic log:\r\n" + ex.Message + "\r\n\r\nEnable Log in Windows Event Viewer or run an elevated instance to change this setting."); }
        }
        private void ToggleSyscalls()
        {
            try { if (syscalls.Running) syscalls.Stop(); else syscalls.Start(); }
            catch (Exception ex) { ShowText("Syscall capture", ex.Message + "\r\n\r\n" + syscalls.Status); if (history != null) history.Note(null, "syscall_capture_error", syscalls.Name, ex.ToString()); }
            syscallButton.Text = syscalls.Running ? "Stop syscalls" : "Start syscalls"; UpdateLiveStatus();
        }
        private void ActivityTick()
        {
            if (closed || activity == null) return;
            ActivityRecord[] incoming = activity.Drain();
            if (incoming.Length > 0)
            {
                recentActivity.AddRange(incoming);
                activity.AssociateObservedLifetimes(recentActivity);
                int overflow = recentActivity.Count - 5000;
                if (overflow > 0) { recentActivity.RemoveRange(0, overflow); activityRowsRetired += overflow; }
                UpdateScopeActivity(tree.SelectedNode == null ? null : tree.SelectedNode.Tag as ExplorerScope);
            }
            activityTicks++;
            if (activityTicks % 10 == 0 && Interlocked.CompareExchange(ref appRefreshInProgress, 1, 0) == 0)
                ThreadPool.QueueUserWorkItem(delegate
                {
                    try { if (!closed) activity.RefreshApplications(); }
                    catch (Exception ex) { if (history != null) history.Note(null, "application_inventory_failed", Environment.MachineName, ex.Message); }
                    finally { Interlocked.Exchange(ref appRefreshInProgress, 0); }
                    Post(delegate { activity.AssociateObservedLifetimes(recentActivity); PopulateApplications(); RebuildControlBranches(); });
                });
            if (activityTicks % 5 == 0 && syscalls.Running) syscalls.Query();
            UpdateLiveStatus();
        }
        private void UpdateLiveStatus()
        {
            if (activity == null) return;
            liveStatus.Text = activity.Status + "\r\n" + syscalls.Status + " | " + syscalls.EventsReceived + " events | UI omitted: " +
                (syscalls.DisplaySamplesSkipped + activity.DisplaySkipped + activityRowsRetired) + " | ETW lost: " + syscalls.EventsLost + "/" + syscalls.BuffersLost;
            if (labelsError != null) liveStatus.Text += "\r\nLabels unavailable: " + labelsError;
            if (history != null && history.LastError != null) liveStatus.Text += "\r\nHISTORY ERROR: " + history.LastError;
            if (syscalls.DecodeErrors > 0) liveStatus.Text += " | syscall decode gaps: " + syscalls.DecodeErrors;
        }
        private string Coverage()
        {
            return activity.Status + "\r\n" + syscalls.Status + "\r\n\r\nEach received CAPI2 XML record is written to retained evidence before the replay bookmark advances. Failed writes hold the bookmark before the gap and report an error. UI lists show recent rows; older evidence has dated pages.\r\n" +
                "Certificate references match explicit Certificate hash/fileRef fields. SHA-1 ambiguity remains visible; names and incidental hex text do not create a match.\r\n" +
                "System.Execution identifies the event emitter. A broker's client is unresolved unless the source supplies evidence. PID identity uses observed process start time.\r\n" +
                "Syscalls are recorded in an original sequential ETL per capture, up to 512 MB. The live list receives at most 500 syscall examples per second; omitted display rows remain in ETL.\r\n" +
                "ETW loss counters are separate from UI omissions. Raw syscall addresses have no resolved symbol names. Enter/exit events are not guessed into certificate operations.\r\n" +
                "Protected/exited processes, unavailable logs, private browser/verifier stacks and time outside capture remain explicit coverage gaps.\r\n" +
                "Collection and ETW layouts require Windows 11 verification [to test].\r\n\r\n" +
                "Microsoft: EventLogWatcher; EventRecord.ToXml; EVENT_RECORD; SysCallEnter / SysCallExit.\r\n" +
                "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher\r\n" +
                "https://learn.microsoft.com/en-us/windows/win32/etw/syscallenter\r\n" + "https://learn.microsoft.com/en-us/windows/win32/etw/syscallexit";
        }

        private ExplorerScope Scope(string key, string description, IEnumerable<CertificateRecord> certificates)
        { ExplorerScope scope = new ExplorerScope { Key = "view|" + key, Description = description }; foreach (CertificateRecord c in certificates) scope.CertificateKeys.Add(c.Identity); return scope; }
        private TreeNode Category(string key, string title, IEnumerable<CertificateRecord> source, string description)
        {
            CertificateRecord[] rows = source.ToArray(); ExplorerScope scope = Scope(key, description, rows);
            TreeNode node = new TreeNode(title + " (" + rows.Length + ")") { Tag = scope };
            foreach (string policy in new string[] { "Enabled", "Blocked", "Unassigned" })
            {
                CertificateRecord[] members = rows.Where(c => labels.Policy(c) == policy).ToArray();
                node.Nodes.Add(new TreeNode(policy + " (" + members.Length + ")") { Tag = Scope(key + "|" + policy,
                    description + "\r\nRequested policy: " + policy + "; enforcement not implemented [to test].", members) });
            }
            return node;
        }
        private void AddControlBranches(TreeNode root)
        {
            if (snapshot == null || labels == null) return;
            string query = findIssuer.Text.Trim();
            CertificateRecord[] all = snapshot.Certificates.Values.Where(c => labels.Matches(c, query)).ToArray();
            string mode = Convert.ToString(groupBy.SelectedItem); List<TreeNode> nodes = new List<TreeNode>();
            TreeNode grouped = new TreeNode("Issuer explorer 🏛️ — " + mode) { Tag = Scope("issuers|" + mode, "Grouping keeps original Windows store paths. Local policy labels are previews.\r\n" + (labelsError ?? "Source mappings: to test."), all) };
            Func<CertificateRecord, string> grouping;
            if (mode == "Corporation") grouping = c => labels.Label(c) == null || String.IsNullOrWhiteSpace(labels.Label(c).Corporation) ? "Unassigned corporation" : labels.Label(c).Corporation;
            else if (mode == "Monarchy") grouping = c => labels.Monarchy(labels.Country(c)) == "monarchy" ? "👑 Monarchy" : labels.Monarchy(labels.Country(c)) == "not monarchy" ? "Other classified" : "Classification unknown";
            else grouping = c => labels.Label(c) != null && !String.IsNullOrWhiteSpace(labels.Label(c).Owner) ? labels.Label(c).Owner : "Issuer DN: " + c.Issuer;
            if (mode == "Country")
            {
                Dictionary<string, CertificateRecord[]> countryMembers = all.GroupBy(c => labels.Country(c) ?? "").ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);
                if (labels.Catalog != null) foreach (CountryRecord country in labels.Catalog.Countries)
                {
                    CertificateRecord[] rows; if (!countryMembers.TryGetValue(country.Code, out rows)) rows = new CertificateRecord[0];
                    TreeNode node = Category("country|" + country.Code, labels.CountryDisplay(country.Code), rows,
                        "Country/area: " + country.Code + " " + country.Name + "\r\nISO/M49 source: " + country.Source + " | " + country.Date +
                        "\r\nMonarchy: " + labels.Monarchy(country.Code) + " | " + country.MonarchySource + " | " + country.MonarchyDate + "\r\nC= and owner country remain distinct evidence fields.");
                    ((ExplorerScope)node.Tag).Country = country.Code; nodes.Add(node);
                }
                nodes.Add(Category("country|unknown", "Unknown / unmapped country", all.Where(c => labels.Catalog == null || labels.Catalog.Find(labels.Country(c)) == null), "Country metadata unavailable or not in the loaded catalog."));
            }
            else if (mode == "Tags")
            {
                string[] palette = new string[] { "🏛️", "🧱", "💃", "👑", "🌿", "🇷🇺", "🏴‍☠️", "🇨🇰", "🇲🇸", "🤡", "🇲🇾", "🇮🇱", "🦂", "👽", "💀" };
                foreach (string tag in palette.Concat(all.SelectMany(c => labels.Tags(c))).Distinct())
                    nodes.Add(Category("tag|" + tag, tag, all.Where(c => labels.Tags(c).Contains(tag)), "Independent user grouping tag: " + tag + "; all original tags retained.\r\n" + "Russia uses 🌿 / 🧱 / 🇷🇺 independently; country basis and source remain visible."));
                nodes.Add(Category("tag|unassigned", "Untagged", all.Where(c => labels.Tags(c).Length == 0), "No local or loaded-country tag assigned."));
            }
            else if (mode != "Applications")
                foreach (IGrouping<string, CertificateRecord> group in all.GroupBy(grouping)) nodes.Add(Category("issuer|" + mode + "|" + group.Key, group.Key, group,
                    "Group: " + group.Key + "\r\nOwner/corporation assignments are sourced local annotations. A recorded DN is a declaration, not a corporate ownership finding."));
            IEnumerable<TreeNode> ordered = Convert.ToString(sortBy.SelectedItem) == "Certificate count" ? nodes.OrderByDescending(n => ((ExplorerScope)n.Tag).CertificateKeys.Count).ThenBy(n => n.Text) :
                Convert.ToString(sortBy.SelectedItem) == "Name descending" ? nodes.OrderByDescending(n => n.Text, StringComparer.OrdinalIgnoreCase) : nodes.OrderBy(n => n.Text, StringComparer.OrdinalIgnoreCase);
            foreach (TreeNode node in ordered) grouped.Nodes.Add(node);
            root.Nodes.Insert(0, grouped); grouped.Expand();
            ApplicationRecord[] apps = activity.Applications;
            TreeNode applications = new TreeNode("Applications — observed processes") { Tag = Scope("applications", Coverage(), all) };
            foreach (ApplicationRecord app in apps)
            {
                if (query.Length > 0 && (app.Name ?? "").IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0) continue;
                CertificateRecord[] certs = recentActivity.Where(a => a.ApplicationKey == app.Key).SelectMany(a => a.Match(snapshot)).Distinct().ToArray();
                ExplorerScope scope = Scope("app|" + app.Key, "Observed process: " + app.Name + "\r\nPID: " + app.ProcessId + "\r\nStarted: " + app.StartedUtc +
                    "\r\nExecutable: " + app.Executable + "\r\nObserved: " + app.ObservedUtc + "\r\nAccess errors: " + app.Error + "\r\nCertificate list uses matching CAPI2 references in recent activity; complete earlier payloads remain in history.", certs);
                scope.ApplicationKey = app.Key;
                applications.Nodes.Add(new TreeNode((app.Name ?? "Unknown process") + " [PID " + app.ProcessId + "]") { Tag = scope });
            }
            root.Nodes.Insert(1, applications); if (mode == "Applications") applications.Expand();
            PopulateApplications();
        }
        private void RebuildControlBranches()
        {
            if (refreshingControls || snapshot == null || tree.Nodes.Count == 0) return;
            refreshingControls = true;
            try
            {
                TreeNode root = tree.Nodes[0]; string selected = NodeKey(tree.SelectedNode); HashSet<string> expanded = new HashSet<string>(); CollectExpanded(root, expanded);
                tree.BeginUpdate();
                for (int i = root.Nodes.Count - 1; i >= 0; i--) if (root.Nodes[i].Tag is ExplorerScope) root.Nodes.RemoveAt(i);
                AddControlBranches(root);
                foreach (string key in expanded) { TreeNode node = FindNode(root, key); if (node != null) node.Expand(); }
                tree.EndUpdate(); tree.SelectedNode = FindNode(root, selected) ?? root;
                if (tree.SelectedNode != null) TreeSelected(tree, new TreeViewEventArgs(tree.SelectedNode));
            }
            finally { refreshingControls = false; }
        }
        private void PopulateApplications()
        {
            string selected = applicationList.SelectedItems.Count == 0 ? null : ((ApplicationRecord)applicationList.SelectedItems[0].Tag).Key;
            applicationList.BeginUpdate(); applicationList.Items.Clear();
            foreach (ApplicationRecord app in activity.Applications)
            {
                ListViewItem row = new ListViewItem(new string[] { app.Name ?? "Unresolved", app.ProcessId.ToString(), app.StartedUtc ?? "Unknown", app.Executable ?? "Unavailable", app.Error ?? "Observed" }) { Tag = app };
                applicationList.Items.Add(row); if (app.Key == selected) row.Selected = true;
            }
            applicationList.EndUpdate();
        }
        private void UpdateScopeActivity(ExplorerScope scope)
        {
            string selected = activityList.SelectedItems.Count == 0 ? null : ((ActivityRecord)activityList.SelectedItems[0].Tag).Id;
            activityList.BeginUpdate(); activityList.Items.Clear();
            foreach (ActivityRecord record in recentActivity)
            {
                if (scope != null && scope.ApplicationKey != null && record.ApplicationKey != scope.ApplicationKey) continue;
                if (scope != null && scope.ApplicationKey == null && !scope.Key.StartsWith("view|applications") && !record.Match(snapshot).Any(c => scope.CertificateKeys.Contains(c.Identity))) continue;
                ListViewItem row = new ListViewItem(new string[] { record.Utc ?? record.ReceivedUtc, Convert.ToString(record.ProcessId), Convert.ToString(record.ThreadId), record.Provider ?? record.Source,
                    record.EventId.ToString(), record.Operation ?? "Unknown", record.Result ?? "Not supplied",
                    String.Join("; ", (record.References ?? new CertificateReference[0]).Select(r => r.Algorithm + " " + r.Value).ToArray()) }) { Tag = record };
                activityList.Items.Add(row);
                if (record.Id == selected) row.Selected = true;
            }
            activityList.EndUpdate();
        }
        private void SelectApplication()
        {
            if (applicationList.SelectedItems.Count == 0) return;
            ApplicationRecord app = (ApplicationRecord)applicationList.SelectedItems[0].Tag;
            TreeNode root = tree.Nodes.Count == 0 ? null : tree.Nodes[0]; TreeNode node = root == null ? null : FindNode(root, "view|app|" + app.Key);
            if (node != null) tree.SelectedNode = node;
            UpdateScopeActivity(new ExplorerScope { ApplicationKey = app.Key });
            ApplicationSignature signature;
            if (applicationSignatures.TryGetValue(app.Key, out signature)) activityDetails.Text = signature.Describe();
        }
        private void ReadSelectedApplicationSigner()
        {
            ApplicationRecord app = applicationList.SelectedItems.Count > 0 ? (ApplicationRecord)applicationList.SelectedItems[0].Tag : null;
            ExplorerScope scope = tree.SelectedNode == null ? null : tree.SelectedNode.Tag as ExplorerScope;
            if (app == null && scope != null && scope.ApplicationKey != null) app = activity.Applications.FirstOrDefault(a => a.Key == scope.ApplicationKey);
            if (app == null) { ShowText("Application signer", "Select an application in the Applications tab or left-hand tree."); return; }
            activityDetails.Text = "Reading the selected executable's embedded signer and file hash..."; evidenceTabs.SelectedIndex = 2;
            ThreadPool.QueueUserWorkItem(delegate
            {
                ApplicationSignature signature = ApplicationSignature.Read(app); if (history != null) history.RecordApplicationSigner(signature);
                Post(delegate
                {
                    applicationSignatures[app.Key] = signature; activityDetails.Text = signature.Describe();
                    if (signature.Certificate != null)
                    {
                        ActivityRecord record = new ActivityRecord { Operation = "Observed executable embedded signer", Utc = signature.ObservedUtc, Source = signature.Executable,
                            ApplicationKey = app.Key, ApplicationName = app.Name, ProcessId = (uint)app.ProcessId,
                            ActorEvidence = "Observed live process lifetime/path and extracted embedded signer; file-signature verification not evaluated",
                            Payload = signature.Describe(), References = new CertificateReference[] { new CertificateReference { Algorithm = "SHA-256", Value = signature.SignerSha256, Field = "Extracted file signer DER" } } };
                        ShowRelationships(record, new CertificateRecord[] { signature.Certificate });
                    }
                });
            });
        }
        private void SelectActivity()
        {
            if (activityList.SelectedItems.Count == 0) return;
            ActivityRecord record = (ActivityRecord)activityList.SelectedItems[0].Tag;
            CertificateRecord[] matches = record.Match(snapshot);
            activityDetails.Text = record.Description() + "\r\n\r\nCurrent inventory matches: " + matches.Length + "\r\n" +
                String.Join("\r\n\r\n", matches.Select(c => "SHA-256: " + c.Sha256 + "\r\n" + labels.Describe(c)).ToArray());
            if (matches.Length > 1) activityDetails.AppendText("\r\nMultiple matches retained; this record alone does not establish which certificate was the target.");
            evidenceTabs.SelectedIndex = 2;
            ShowRelationships(record, matches);
        }
        private void ShowRelationships(ActivityRecord record, CertificateRecord[] matches)
        {
            relationships.BeginUpdate(); relationships.Nodes.Clear();
            TreeNode root = new TreeNode(record.Operation + " | " + record.Utc); relationships.Nodes.Add(root);
            root.Nodes.Add("Source: " + record.Source + " | event/opcode " + record.EventId);
            root.Nodes.Add("Event process: " + record.ProcessId + " | " + (record.ApplicationName ?? "Lifetime unresolved"));
            root.Nodes.Add("Actor evidence: " + record.ActorEvidence);
            foreach (CertificateReference reference in record.References ?? new CertificateReference[0]) root.Nodes.Add("Reported reference: " + reference.Algorithm + " " + reference.Value);
            foreach (CertificateRecord certificate in matches)
            {
                TreeNode item = new TreeNode("Inventory match: " + certificate.Subject + " | " + certificate.Sha256); root.Nodes.Add(item);
                item.Nodes.Add("Found in: " + certificate.FoundInText);
                item.Nodes.Add("Recorded issuer DN: " + certificate.Issuer);
                CertificateLabel label = labels.Label(certificate);
                item.Nodes.Add("Mapped CA owner: " + (label == null ? "Unknown" : label.Owner));
                item.Nodes.Add("Corporation/group: " + (label == null ? "Unassigned" : label.Corporation));
                item.Nodes.Add("Grouping country: " + labels.CountryDisplay(labels.Country(certificate)));
                item.Nodes.Add("Monarchy: " + labels.Monarchy(labels.Country(certificate)) + " | tags: " + String.Join(" ", labels.Tags(certificate)));
                item.Nodes.Add("Current label version: " + labels.Annotations.Id + " | requested policy: " + labels.Policy(certificate) + "; enforcement not implemented");
            }
            if (matches.Length == 0) root.Nodes.Add("Certificate identity unresolved in current inventory; original references retained.");
            root.Nodes.Add("These are evidence/metadata relationships. Certificate parent links require returned Windows chain elements.");
            root.Expand(); relationships.EndUpdate();
        }
        private void PopulateCountries()
        {
            countryList.BeginUpdate(); countryList.Items.Clear();
            if (labels.Catalog != null) foreach (CountryRecord country in labels.Catalog.Countries.OrderBy(c => c.Name))
            {
                CountryLabel local = labels.Annotations.Countries.FirstOrDefault(c => c.Code == country.Code);
                countryList.Items.Add(new ListViewItem(new string[] { country.Name, country.Code, labels.Monarchy(country.Code), local == null ? country.MonarchySource ?? "Unclassified" : local.Source,
                    local == null ? country.MonarchyDate ?? country.Date : local.Date }) { Tag = country });
            }
            countryList.EndUpdate();
        }
        private void SelectCountry()
        {
            if (countryList.SelectedItems.Count == 0) return;
            CountryRecord country = (CountryRecord)countryList.SelectedItems[0].Tag;
            CountryLabel local = labels.Annotations.Countries.FirstOrDefault(c => c.Code == country.Code);
            details.Text = country.Code + " " + country.Name + "\r\nM49: " + country.M49 + " | ISO-alpha3: " + country.Alpha3 + "\r\nSource: " + country.Source + " | " + country.Date +
                "\r\nMonarchy: " + labels.Monarchy(country.Code) + "\r\nClassification source: " + country.MonarchySource + " | " + country.MonarchyDate +
                (local == null ? "" : "\r\nLocal override: " + local.Source + " | " + local.Date + " | tags: " + local.Tags) +
                "\r\nCountry labels and policy groups are annotations; effective Windows trust stays a separate evaluation.";
        }

        private void EditCertificateLabels()
        {
            CertificateRecord cert = SelectedCertificate(); if (cert == null) { ShowText("Issuer labels", "Select a certificate in the Certificates tab."); return; }
            CertificateLabel previous = labels.Label(cert);
            using (Form dialog = LabelDialog("Issuer labels — " + cert.Subject))
            {
                TableLayoutPanel fields = LabelFields(dialog); Dictionary<string, TextBox> boxes = new Dictionary<string, TextBox>();
                AddField(fields, boxes, "CA owner", previous == null ? "" : previous.Owner);
                AddField(fields, boxes, "Corporation/group", previous == null ? "" : previous.Corporation);
                AddField(fields, boxes, "Owner country code", previous == null ? "" : previous.OwnerCountry);
                AddField(fields, boxes, "Tags (space separated)", previous == null ? "" : previous.Tags);
                AddField(fields, boxes, "Source", previous == null ? "User-defined" : previous.Source);
                AddField(fields, boxes, "Date", previous == null ? DateTime.UtcNow.ToString("yyyy-MM-dd") : previous.Date);
                ComboBox policy = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
                policy.Items.AddRange(new object[] { "Unassigned", "Enabled", "Blocked" }); policy.SelectedItem = previous == null ? "Unassigned" : previous.Policy;
                AddControl(fields, "Requested policy", policy);
                Button save = new Button { Text = "Save labels", AutoSize = true }; AddControl(fields, "Local label version", save);
                save.Click += delegate
                {
                    try
                    {
                        if (history == null || labelsError != null) throw new InvalidOperationException("Resolve the history/label loading error before writing a new version.");
                        AnnotationSet next = labels.Annotations.Next(); next.Certificates.RemoveAll(c => c.Identity == cert.Identity);
                        next.Certificates.Add(new CertificateLabel { Identity = cert.Identity, Owner = boxes["CA owner"].Text.Trim(), Corporation = boxes["Corporation/group"].Text.Trim(),
                            OwnerCountry = boxes["Owner country code"].Text.Trim().ToUpperInvariant(), Tags = boxes["Tags (space separated)"].Text.Trim(),
                            Source = boxes["Source"].Text.Trim(), Date = boxes["Date"].Text.Trim(), Policy = Convert.ToString(policy.SelectedItem) });
                        next.Validate(); if (!history.SaveAnnotations(next)) throw new InvalidOperationException(history.LastError);
                        labels.Annotations = next; dialog.DialogResult = DialogResult.OK; dialog.Close();
                    }
                    catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Labels were not saved", MessageBoxButtons.OK, MessageBoxIcon.Information); }
                };
                dialog.ShowDialog(this);
            }
            RebuildControlBranches(); ShowCertificate();
        }
        private void EditCountryLabels()
        {
            CountryRecord country = countryList.SelectedItems.Count > 0 ? (CountryRecord)countryList.SelectedItems[0].Tag : null;
            ExplorerScope scope = tree.SelectedNode == null ? null : tree.SelectedNode.Tag as ExplorerScope;
            if (country == null && scope != null && scope.Country != null && labels.Catalog != null) country = labels.Catalog.Find(scope.Country);
            if (country == null) { ShowText("Country labels", "Select a country in the Countries tab or a country branch."); return; }
            CountryLabel previous = labels.Annotations.Countries.FirstOrDefault(c => c.Code == country.Code);
            using (Form dialog = LabelDialog("Country labels — " + country.Code + " " + country.Name))
            {
                TableLayoutPanel fields = LabelFields(dialog); Dictionary<string, TextBox> boxes = new Dictionary<string, TextBox>();
                ComboBox monarchy = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
                monarchy.Items.AddRange(new object[] { "unknown", "monarchy", "not monarchy" }); monarchy.SelectedItem = labels.Monarchy(country.Code); AddControl(fields, "Monarchy", monarchy);
                AddField(fields, boxes, "Tags (space separated)", previous == null ? "" : previous.Tags);
                AddField(fields, boxes, "Source", previous == null ? "User-defined" : previous.Source);
                AddField(fields, boxes, "Date", previous == null ? DateTime.UtcNow.ToString("yyyy-MM-dd") : previous.Date);
                Button save = new Button { Text = "Save country labels", AutoSize = true }; AddControl(fields, "Local label version", save);
                save.Click += delegate
                {
                    try
                    {
                        if (history == null || labelsError != null) throw new InvalidOperationException("Resolve the history/label loading error before writing a new version.");
                        AnnotationSet next = labels.Annotations.Next(); next.Countries.RemoveAll(c => c.Code == country.Code);
                        next.Countries.Add(new CountryLabel { Code = country.Code, Monarchy = Convert.ToString(monarchy.SelectedItem), Tags = boxes["Tags (space separated)"].Text.Trim(),
                            Source = boxes["Source"].Text.Trim(), Date = boxes["Date"].Text.Trim() });
                        next.Validate(); if (!history.SaveAnnotations(next)) throw new InvalidOperationException(history.LastError);
                        labels.Annotations = next; dialog.DialogResult = DialogResult.OK; dialog.Close();
                    }
                    catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Country labels were not saved", MessageBoxButtons.OK, MessageBoxIcon.Information); }
                };
                dialog.ShowDialog(this);
            }
            PopulateCountries(); RebuildControlBranches();
        }
        private Form LabelDialog(string title)
        { return new Form { Text = title, StartPosition = FormStartPosition.CenterParent, Size = new Size(710, 390), Font = Font, MinimizeBox = false, MaximizeBox = false }; }
        private static TableLayoutPanel LabelFields(Form dialog)
        {
            Label scope = new Label { Text = "User-defined labels; requested Enabled/Blocked policy has no OS enforcement. Every saved version is retained.", Dock = DockStyle.Bottom, Height = 38 };
            TableLayoutPanel fields = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 0, AutoScroll = true, Padding = new Padding(7) };
            fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170)); fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            dialog.Controls.Add(fields); dialog.Controls.Add(scope); return fields;
        }
        private static void AddField(TableLayoutPanel fields, Dictionary<string, TextBox> boxes, string title, string value)
        { TextBox field = new TextBox { Text = value ?? "", Dock = DockStyle.Fill, MaxLength = 2048 }; boxes.Add(title, field); AddControl(fields, title, field); }
        private static void AddControl(TableLayoutPanel fields, string title, Control control)
        {
            int row = fields.RowCount++; fields.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            fields.Controls.Add(new Label { Text = title, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, row); fields.Controls.Add(control, 1, row);
        }
        private void CloseControlLayer()
        {
            activityTimer.Stop(); activityTimer.Dispose();
            try { if (activity != null) activity.Dispose(); }
            finally { if (syscalls != null) try { syscalls.Dispose(); } catch (Exception ex) { if (history != null) history.Note(null, "syscall_shutdown_error", syscalls.Name, ex.ToString()); } }
        }

        private void ShowActivityArchive(bool syscallArchive)
        {
            if (history == null) { ShowText("Activity archive", "Persistent history is unavailable: " + historyStartupError); return; }
            string directory = System.IO.Path.Combine(history.DirectoryPath, "traces");
            string[] files;
            try { files = syscallArchive ? System.IO.Directory.Exists(directory) ? System.IO.Directory.GetFiles(directory, "*.etl").OrderBy(x => x).ToArray() : new string[0] : history.JournalFiles(); }
            catch (Exception ex) { ShowText("Activity archive", ex.Message); return; }
            if (files.Length == 0) { ShowText("Activity archive", syscallArchive ? "No retained syscall ETL captures yet." : "No retained certificate activity dates yet."); return; }
            using (Form dialog = new Form { Text = syscallArchive ? "Retained syscall ETLs" : "Retained certificate activity", StartPosition = FormStartPosition.CenterParent,
                Size = new Size(1050, 710), Font = Font })
            {
                FlowLayoutPanel controls = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 35 };
                ComboBox file = new ComboBox { Width = 400, DropDownStyle = ComboBoxStyle.DropDownList, FormattingEnabled = true };
                file.Format += delegate(object sender, ListControlConvertEventArgs args) { args.Value = System.IO.Path.GetFileName(Convert.ToString(args.ListItem)); };
                file.Items.AddRange(files); file.SelectedIndex = files.Length - 1;
                Button previous = new Button { Text = "Previous page", AutoSize = true }, next = new Button { Text = "Next page", AutoSize = true };
                Label coverage = new Label { Dock = DockStyle.Bottom, Height = 45 };
                ListView rows = new ListView(); SetupGrid(rows, new string[] { "TimeCreated", "Process ID", "Thread ID", "Operation", "Result" }, new int[] { 205, 85, 85, 220, 430 });
                TextBox evidence = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, WordWrap = false, ScrollBars = ScrollBars.Both, Font = details.Font };
                SplitContainer panes = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, Size = new Size(1010, 600), SplitterDistance = 265 };
                panes.Panel1.Controls.Add(rows); panes.Panel2.Controls.Add(evidence);
                controls.Controls.AddRange(new Control[] { file, previous, next }); dialog.Controls.Add(panes); dialog.Controls.Add(controls); dialog.Controls.Add(coverage);
                int page = 0, ended = 0; bool loading = false;
                Action load = delegate
                {
                    if (loading) return; loading = true; file.Enabled = previous.Enabled = next.Enabled = false;
                    coverage.Text = "Reading retained page " + (page + 1) + "..."; string chosen = Convert.ToString(file.SelectedItem); int target = page;
                    ThreadPool.QueueUserWorkItem(delegate
                    {
                        ActivityPage result = null; string error = null;
                        try { result = syscallArchive ? ActivityArchive.Syscalls(history, chosen, target) : ActivityArchive.Certificates(history, chosen, target); }
                        catch (Exception ex) { error = ex.Message; }
                        if (Interlocked.CompareExchange(ref ended, 0, 0) != 0) return;
                        try { dialog.BeginInvoke((Action)delegate
                        {
                            loading = false; file.Enabled = true; previous.Enabled = page > 0; next.Enabled = result != null && result.More;
                            rows.Items.Clear();
                            if (result == null) { coverage.Text = "Retained evidence read failed: " + error; evidence.Text = chosen; return; }
                            foreach (ActivityRecord row in result.Records) rows.Items.Add(new ListViewItem(new string[] { row.Utc ?? row.ReceivedUtc, Convert.ToString(row.ProcessId), Convert.ToString(row.ThreadId), row.Operation ?? "Unknown", row.Result ?? "Not supplied" }) { Tag = row });
                            coverage.Text = "Page " + (page + 1) + " | " + result.Coverage; evidence.Text = chosen;
                        }); } catch (InvalidOperationException) { }
                    });
                };
                file.SelectedIndexChanged += delegate { page = 0; load(); };
                previous.Click += delegate { if (page > 0) { page--; load(); } }; next.Click += delegate { page++; load(); };
                rows.SelectedIndexChanged += delegate { if (rows.SelectedItems.Count > 0) evidence.Text = ((ActivityRecord)rows.SelectedItems[0].Tag).Description(); };
                dialog.FormClosed += delegate { Interlocked.Exchange(ref ended, 1); };
                dialog.Shown += delegate { load(); }; dialog.ShowDialog(this);
            }
        }
    }
}
