using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    internal sealed partial class ExplorerForm
    {
        private GroupsRoot groups;

        private void InitializeBlocking(MainMenu menu, FlowLayoutPanel toolbar)
        {
            MenuItem block = new MenuItem("&Block");
            block.MenuItems.Add(new MenuItem("Block selected &group...", delegate { BlockSelectedGroup(); }));
            block.MenuItems.Add(new MenuItem("Block selected &certificate...", delegate { BlockSelectedCertificate(); }));
            block.MenuItems.Add(new MenuItem("-"));
            block.MenuItems.Add(new MenuItem("&Undo last block", delegate { UndoLastBlock(); }));
            block.MenuItems.Add(new MenuItem("U&nblock selected certificate", delegate { UnblockSelectedCertificate(); }));
            block.MenuItems.Add(new MenuItem("-"));
            block.MenuItems.Add(new MenuItem("Block &history", delegate { ShowBlockHistory(); }));
            InitializeRules(block);
            menu.MenuItems.Add(menu.MenuItems.Count - 1, block);
            Button blockGroup = new Button { Text = "Block group...", AutoSize = true };
            Button blockCert = new Button { Text = "Block certificate...", AutoSize = true };
            Button undo = new Button { Text = "Undo last block", AutoSize = true };
            blockGroup.Click += delegate { BlockSelectedGroup(); };
            blockCert.Click += delegate { BlockSelectedCertificate(); };
            undo.Click += delegate { UndoLastBlock(); };
            toolbar.Controls.AddRange(new Control[] { blockGroup, blockCert, undo });
        }

        // ---- Groups tree -------------------------------------------------------------

        private void AddGroupTree(Snapshot result, HashSet<string> expanded)
        {
            groups = GroupCatalog.Build(result, sourceDirectory);
            TreeNode root = new TreeNode("Groups (from data\\*.csv and my tags)" + (groups.Error == null ? "" : " [error]")) { Tag = "groups" };
            groupTree.BeginUpdate(); groupTree.Nodes.Clear();
            groupTree.Nodes.Add(root);
            try {
            if (groups.Error != null) { root.Nodes.Add(new TreeNode("Could not load: " + groups.Error) { Tag = "groups:error" }); return; }
            AddFolder(root, "Tags", groups.Tags, expanded);
            AddFolder(root, "Countries", groups.Countries, expanded);
            AddFolder(root, "Owners", groups.Owners, expanded);
            root.Expand();
            foreach (TreeNode node in root.Nodes) if (expanded.Contains(NodeKey(node))) node.Expand();
            } finally { groupTree.EndUpdate(); }
        }

        private void AddFolder(TreeNode root, string name, List<GroupNode> items, HashSet<string> expanded)
        {
            TreeNode folder = new TreeNode(name + " (" + items.Count + ")") { Tag = "groups:" + name };
            root.Nodes.Add(folder);
            foreach (GroupNode group in items)
            {
                GroupNode enabled = GroupCatalog.Filtered(group, "enabled", groups.Blocked), blocked = GroupCatalog.Filtered(group, "blocked", groups.Blocked);
                TreeNode node = new TreeNode(group.Label + " (" + group.Members.Count + ")") { Tag = group };
                node.Nodes.Add(new TreeNode("Enabled (" + enabled.Members.Count + ")") { Tag = enabled });
                node.Nodes.Add(new TreeNode("Blocked (" + blocked.Members.Count + ")") { Tag = blocked, ForeColor = blocked.Members.Count > 0 ? Color.DarkRed : SystemColors.WindowText });
                folder.Nodes.Add(node);
                if (expanded.Contains(NodeKey(node))) node.Expand();
            }
        }

        private bool SelectGroup(object selected, HashSet<string> keys)
        {
            GroupNode group = selected as GroupNode;
            if (group != null)
            {
                keys.UnionWith(group.Members);
                address.Text = "Groups\\" + group.Kind + "\\" + group.Label + (group.Filter == "all" ? "" : "\\" + group.Filter);
                StringBuilder text = new StringBuilder();
                text.AppendLine(group.Kind + ": " + group.Label + " — " + group.Filter + " — " + group.Members.Count + " certificates");
                text.AppendLine("Membership comes from data\\countries_monarchy_bric.csv and data\\owners.csv. Tags stack; each certificate lists why it is here.");
                text.AppendLine("Blocked = present in a Disallowed store (Windows' untrusted list). Enabled = not in any Disallowed store.");
                text.AppendLine();
                foreach (string id in group.Members.OrderBy(id => snapshot.Certificates[id].SubjectShortName, StringComparer.OrdinalIgnoreCase))
                    text.AppendLine(snapshot.Certificates[id].SubjectShortName + "  <=  " + String.Join("; ", group.Why[id].ToArray()));
                nodeDetails = text.ToString();
                return true;
            }
            string folder = selected as string;
            if (folder != null && folder.StartsWith("groups", StringComparison.Ordinal))
            {
                address.Text = "Groups";
                nodeDetails = "Groups are built from your CSV files in the data folder:\r\n" +
                    "  countries_monarchy_bric.csv — tags, your_group, brics_plus_verify, crown_territory_of (joined on subject C= and issuer C=)\r\n" +
                    "  owners.csv — CA owner by subject/issuer O=, with its country and tags\r\n" +
                    "Edit those files and press F5 to regroup. Select a group, then Block group... to block it.\r\n" +
                    (groups != null && groups.Error != null ? "\r\nLoad error: " + groups.Error : "");
                return true;
            }
            return false;
        }

        // ---- Blocking ----------------------------------------------------------------

        private void BlockSelectedGroup()
        {
            GroupNode group = groupTree.SelectedNode == null ? null : groupTree.SelectedNode.Tag as GroupNode;
            if (snapshot == null || group == null) { ShowText("Block group", "Select a group (or its Enabled branch) under Groups in the left tree first."); return; }
            GroupNode source = group.Filter == "all" ? group : group.Parent ?? group;
            List<CertificateRecord> chosen = source.Members.Select(id => snapshot.Certificates[id]).ToList();
            ShowBlockDialog(chosen, delegate(CertificateRecord c) { SortedSet<string> why; return source.Why.TryGetValue(c.Identity, out why) ? String.Join("; ", why.ToArray()) : ""; }, source.Kind + " " + source.Label, source);
        }

        private void BlockSelectedCertificate()
        {
            CertificateRecord cert = SelectedCertificate();
            if (snapshot == null || cert == null) { ShowText("Block certificate", "Select a certificate in the list first."); return; }
            ShowBlockDialog(new List<CertificateRecord> { cert }, delegate { return "selected certificate"; }, "certificate " + cert.SubjectShortName, null);
        }

        private void ShowBlockDialog(List<CertificateRecord> chosen, Func<CertificateRecord, string> reason, string label, GroupNode ruleGroup)
        {
            bool elevated = BlockEngine.IsElevated();
            using (Form dialog = new Form { Text = "Block — preview: " + label, Size = new Size(1150, 600), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                FlowLayoutPanel scopePanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 30, Padding = new Padding(4) };
                RadioButton user = new RadioButton { Text = "This user (CURRENT_USER\\Disallowed)", AutoSize = true, Checked = true };
                RadioButton machine = new RadioButton { Text = "Whole PC (LOCAL_MACHINE\\Disallowed)" + (elevated ? "" : " — run kisib as administrator to use"), AutoSize = true, Enabled = elevated };
                scopePanel.Controls.AddRange(new Control[] { user, machine });
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Action", "Subject CN", "Issuer CN", "C=", "Why", "Found in (physical stores)", "SHA-256" }, new int[] { 130, 210, 210, 45, 330, 330, 460 });
                Label info = new Label { Dock = DockStyle.Bottom, Height = 96 };
                string whatIf = "";
                Button rerouteDetails = new Button { Text = "Cross-sign details: what this block cuts off and what gets rerouted...", Dock = DockStyle.Bottom, Height = 28 };
                rerouteDetails.Click += delegate { ShowText("If you block this — cross-signs", whatIf.Length > 0 ? whatIf : "Nothing new to block, or the scan is not ready."); };
                CheckBox includeProtected = new CheckBox { Dock = DockStyle.Bottom, Height = 24, Text = "Also block PROTECTED certificates (trusted categories like Windows essentials need them)", ForeColor = Color.Firebrick };
                CheckBox keep = new CheckBox { Dock = DockStyle.Bottom, Height = 26, Checked = ruleGroup != null, Enabled = ruleGroup != null,
                    Text = "Keep this group blocked: block new matches after every scan (rescans every 60 seconds)" };
                Button go = new Button { Dock = DockStyle.Bottom, Height = 32 };
                Button cancel = new Button { Text = "Cancel", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                List<BlockItem> plan = null;
                Action refreshPlan = delegate
                {
                    X509Location scope = machine.Checked ? X509Location.LocalMachine : X509Location.CurrentUser;
                    plan = BlockEngine.Plan(snapshot, chosen, reason, scope);
                    grid.BeginUpdate(); grid.Items.Clear();
                    foreach (BlockItem item in plan.OrderBy(i => i.AlreadyBlocked).ThenBy(i => i.Certificate.SubjectShortName, StringComparer.OrdinalIgnoreCase))
                    {
                        CertificateRecord c = item.Certificate;
                        string guard = TrustCategories.ProtectedBy(c);
                        string action = item.AlreadyBlocked ? "already blocked" : guard != null && !includeProtected.Checked ? "SKIP: protected (" + guard + ")" : guard != null ? "add — PROTECTED (" + guard + ")" : "add to Disallowed";
                        ListViewItem row = new ListViewItem(new string[] { action, c.SubjectShortName, c.IssuerShortName,
                            c.SubjectCountry ?? "—", item.Reason, c.FoundInText, c.Sha256 });
                        if (item.AlreadyBlocked) row.ForeColor = SystemColors.GrayText; else if (guard != null) row.ForeColor = Color.DarkGoldenrod;
                        grid.Items.Add(row);
                    }
                    grid.EndUpdate();
                    plan = plan.Where(i => i.AlreadyBlocked || includeProtected.Checked || TrustCategories.ProtectedBy(i.Certificate) == null).ToList();
                    int add = plan.Count(i => !i.AlreadyBlocked), roots = plan.Count(i => !i.AlreadyBlocked && i.Certificate.FoundIn.Any(p => p.IndexOf("\\Root\\", StringComparison.OrdinalIgnoreCase) >= 0));
                    go.Text = add == 0 ? "Nothing to block" : "Block " + add + " certificate" + (add == 1 ? "" : "s");
                    go.Enabled = add > 0 || keep.Checked;
                    if (add == 0 && keep.Checked) go.Text = "Save rule";
                    info.Text = add + " will be added to " + (machine.Checked ? "LOCAL_MACHINE" : "CURRENT_USER") + "\\Disallowed (" + roots + " of them are trusted roots); " +
                        (plan.Count - add) + " already blocked. Certificates sharing a key with a chosen one are included.\r\n" +
                        "Nothing is deleted from Root or CA, so a Windows root update cannot bring them back: Disallowed wins.\r\n" +
                        "Windows, Edge and apps using Windows certificate checks stop trusting them. Chrome and Firefox keep their own root stores [to test].\r\n" +
                        "Undo: Block > Undo last block. Every change is written to " + BlockEngine.LogPath;
                    string whatIfLine;
                    whatIf = RerouteWhatIf(plan.Where(i => !i.AlreadyBlocked).Select(i => i.Certificate), out whatIfLine);
                    if (whatIfLine.Length > 0) info.Text += "\r\n" + whatIfLine;
                };
                user.CheckedChanged += delegate { refreshPlan(); };
                keep.CheckedChanged += delegate { refreshPlan(); };
                includeProtected.CheckedChanged += delegate { refreshPlan(); };
                refreshPlan();
                go.Click += delegate
                {
                    X509Location scope = machine.Checked ? X509Location.LocalMachine : X509Location.CurrentUser;
                    List<BlockLogRow> rows;
                    try
                    {
                        rows = BlockEngine.Block(plan.Where(i => !i.AlreadyBlocked), scope, label);
                        if (keep.Checked && ruleGroup != null)
                        {
                            BlockRules.Add(ruleGroup.Key, ruleGroup.Label, scope);
                            if (!autoScanToggle.Checked) { autoScanToggle.Checked = true; historyTimer.Start(); }
                        }
                    }
                    catch (Exception ex) { ShowText("Block failed", ex.GetType().Name + ": " + ex.Message + "\r\n\r\nNo log row means no change was made."); return; }
                    dialog.DialogResult = DialogResult.OK; dialog.Close();
                    ShowText("Block result", Report(rows));
                    StartScan();
                };
                dialog.Controls.Add(grid); dialog.Controls.Add(scopePanel); dialog.Controls.Add(info); dialog.Controls.Add(rerouteDetails); dialog.Controls.Add(includeProtected); dialog.Controls.Add(keep); dialog.Controls.Add(go); dialog.Controls.Add(cancel);
                dialog.CancelButton = cancel;
                dialog.ShowDialog(this);
            }
        }

        private void UndoLastBlock()
        {
            string batch = BlockEngine.LastBatch();
            if (batch == null) { ShowText("Undo last block", "No block made by kisib is on record."); return; }
            List<BlockLogRow> rows = BlockEngine.ReadLog().Where(r => r.Batch == batch && r.Action == "block" && r.Result == "added").ToList();
            X509Location scope = (X509Location)Enum.Parse(typeof(X509Location), rows[0].Scope);
            if (scope == X509Location.LocalMachine && !BlockEngine.IsElevated()) { ShowText("Undo last block", "That block was made for the whole PC. Run kisib as administrator to undo it."); return; }
            if (MessageBox.Show(this, "Remove " + rows.Count + " certificates that kisib added to " + rows[0].Scope + "\\Disallowed in batch " + batch + " (" + rows[0].Group + ")?",
                "Undo last block", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            List<BlockLogRow> result;
            try { result = BlockEngine.Unblock(rows.Select(r => r.Sha256), scope, "undo " + batch); }
            catch (Exception ex) { ShowText("Undo failed", ex.GetType().Name + ": " + ex.Message); return; }
            ShowText("Undo result", Report(result)); StartScan();
        }

        private void UnblockSelectedCertificate()
        {
            CertificateRecord cert = SelectedCertificate();
            if (cert == null) { ShowText("Unblock certificate", "Select a certificate in the list first."); return; }
            List<BlockLogRow> result = new List<BlockLogRow>();
            try
            {
                result.AddRange(BlockEngine.Unblock(new string[] { cert.Sha256 }, X509Location.CurrentUser, "unblock selected"));
                if (BlockEngine.IsElevated()) result.AddRange(BlockEngine.Unblock(new string[] { cert.Sha256 }, X509Location.LocalMachine, "unblock selected"));
            }
            catch (Exception ex) { ShowText("Unblock failed", ex.GetType().Name + ": " + ex.Message); return; }
            ShowText("Unblock result", Report(result) + "\r\nkisib only removes Disallowed entries it added itself; Microsoft's own entries stay."); StartScan();
        }

        private void ShowBlockHistory()
        {
            string path = BlockEngine.LogPath;
            string text;
            try { text = File.Exists(path) ? File.ReadAllText(path) : "No blocks yet."; }
            catch (IOException ex) { text = ex.Message; }
            ShowText("Block history — " + path, text);
        }

        private static string Report(List<BlockLogRow> rows)
        {
            StringBuilder text = new StringBuilder();
            foreach (IGrouping<string, BlockLogRow> outcome in rows.GroupBy(r => r.Result.StartsWith("error") ? "error" : r.Result))
                text.AppendLine(outcome.Count() + "  " + outcome.Key);
            text.AppendLine();
            foreach (BlockLogRow r in rows) text.AppendLine(r.Action + "  " + r.Scope + "  " + r.Result + "  " + r.Subject + "  " + r.Sha256);
            text.AppendLine(); text.AppendLine("Logged to " + BlockEngine.LogPath + ". The tree refreshes after this window.");
            return text.ToString();
        }
    }
}
