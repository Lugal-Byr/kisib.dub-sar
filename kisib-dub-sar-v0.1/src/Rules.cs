using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Microsoft's full trusted-root list. Windows downloads these roots on demand, so many are not on disk yet.
    // certutil -generateSSTFromWU is Microsoft's documented way to get the whole list.
    internal static class MicrosoftList
    {
        internal const string Label = "MICROSOFT_LIST (trusted by Windows; downloads on demand)";
        internal static string SstPath
        { get { return Storage.File("microsoft-root-list.sst"); } }

        internal static string Update()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SstPath));
            string temp = SstPath + ".new";
            if (File.Exists(temp)) File.Delete(temp);
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "certutil.exe"), "-generateSSTFromWU \"" + temp + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (Process process = Process.Start(info))
            {
                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                if (!process.WaitForExit(180000)) { try { process.Kill(); } catch (InvalidOperationException) { } return "certutil timed out.\r\n" + output; }
                if (process.ExitCode != 0 || !File.Exists(temp)) return "certutil failed (exit " + process.ExitCode + ").\r\n" + output;
            }
            if (File.Exists(SstPath)) File.Delete(SstPath);
            File.Move(temp, SstPath);
            return null;
        }

        // Adds the list's roots to the snapshot so groups and blocking see roots Windows has not downloaded yet.
        internal static int Merge(Snapshot snapshot)
        {
            if (!File.Exists(SstPath)) return -1;
            X509Certificate2Collection roots = new X509Certificate2Collection();
            roots.Import(SstPath);
            int count = 0;
            foreach (X509Certificate2 root in roots)
            {
                CertificateRecord record = snapshot.Add(root.RawData);
                record.FoundIn.Add(Label);
                count++;
                root.Reset();
            }
            CertificateSignals.Evaluate(snapshot.Certificates.Values.ToArray());
            return count;
        }

        internal static DateTime? Updated
        { get { return File.Exists(SstPath) ? (DateTime?)File.GetLastWriteTime(SstPath) : null; } }
    }

    // A saved rule keeps a group blocked: after every scan, new matches are blocked and logged.
    internal sealed class BlockRule
    {
        internal string GroupKey, Label, Scope, Created;
    }

    internal static class BlockRules
    {
        internal static string RulesPath
        { get { return Storage.File(Storage.Rules); } }

        internal static List<BlockRule> Read()
        {
            List<BlockRule> rules = new List<BlockRule>();
            if (!File.Exists(RulesPath)) return rules;
            foreach (string[] f in GroupCatalog.ReadCsv(RulesPath).Skip(1))
                if (f.Length >= 4) rules.Add(new BlockRule { GroupKey = Renamed(f[0]), Label = f[1], Scope = f[2], Created = f[3] });
            return rules;
        }

        // Groups renamed in v0.2.18: old saved rules keep working.
        private static string Renamed(string key)
        {
            switch (key)
            {
                case "tag:🌿🧱": return "tag:🧱";
                case "tag:BRICS+ (verify)": return "tag:🧱";
                case "tag:🧱 BRICS+": return "tag:🧱";
                case "tag:Google": return "owner:Google Trust Services";
                case "tag:eMudhra": return "owner:eMudhra";
                default: return key;
            }
        }

        internal static void Save(List<BlockRule> rules)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(RulesPath));
            StringBuilder text = new StringBuilder("group_key,label,scope,created_utc\r\n");
            foreach (BlockRule r in rules)
                text.Append(String.Join(",", new string[] { r.GroupKey, r.Label, r.Scope, r.Created }.Select(Csv).ToArray())).Append("\r\n");
            File.WriteAllText(RulesPath, text.ToString(), new UTF8Encoding(false));
        }

        internal static void Add(string key, string label, X509Location scope)
        {
            List<BlockRule> rules = Read();
            if (rules.Any(r => r.GroupKey == key && r.Scope == scope.ToString())) return;
            rules.Add(new BlockRule { GroupKey = key, Label = label, Scope = scope.ToString(), Created = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) });
            Save(rules);
        }

        private static string Csv(string value)
        {
            value = value ?? "";
            return value.IndexOfAny(new char[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private string ruleStatus = "";
        private bool ruleRescan;

        private void InitializeRules(MenuItem block)
        {
            block.MenuItems.Add(new MenuItem("-"));
            block.MenuItems.Add(new MenuItem("&Rules (keep groups blocked)...", delegate { ShowRules(); }));
            block.MenuItems.Add(new MenuItem("Update &Microsoft root list", delegate { UpdateMicrosoftList(); }));
            block.MenuItems.Add(new MenuItem("Update &CCADB list (all CA certificates, catches cross-signs)", delegate { UpdateCcadb(); }));
            // With rules saved, keep watching: rescan every 60 seconds so a new match is caught and blocked.
            Shown += delegate
            {
                if (BlockRules.Read().Count > 0 && !autoScanToggle.Checked) { autoScanToggle.Checked = true; historyTimer.Start(); }
            };
        }

        private static IEnumerable<GroupNode> AllGroups(GroupsRoot root)
        { return root.All; }

        // Runs after each scan is displayed.
        private void ApplyRules(Snapshot result)
        {
            ruleStatus = "";
            List<BlockRule> rules;
            try { rules = BlockRules.Read(); }
            catch (Exception ex) { ruleStatus = "Rules unreadable: " + ex.Message; return; }
            if (rules.Count == 0 || groups == null || groups.Error != null) { ruleRescan = false; return; }
            bool elevated = BlockEngine.IsElevated();
            AllowedSet allowed = AllowedList.Load();
            int added = 0, skipped = 0, failed = 0, protectedSkipped = 0;
            foreach (BlockRule rule in rules)
            {
                X509Location scope;
                try { scope = (X509Location)Enum.Parse(typeof(X509Location), rule.Scope); } catch (ArgumentException) { continue; }
                if (scope == X509Location.LocalMachine && !elevated) { skipped++; continue; }
                GroupNode group = AllGroups(groups).FirstOrDefault(g => g.Key == rule.GroupKey);
                if (group == null) continue;
                List<BlockItem> plan = BlockEngine.Plan(result, group.Members.Select(id => result.Certificates[id]),
                    delegate { return "rule: " + rule.Label; }, scope).Where(i => !i.AlreadyBlocked).ToList();
                int before = plan.Count;
                plan = plan.Where(i => TrustCategories.ProtectedBy(i.Certificate) == null && !allowed.Covers(i.Certificate)).ToList();
                protectedSkipped += before - plan.Count;
                if (plan.Count == 0) continue;
                try
                {
                    List<BlockLogRow> rows = BlockEngine.Block(plan, scope, "rule: " + rule.Label);
                    added += rows.Count(r => r.Result == "added");
                    failed += rows.Count(r => r.Result.StartsWith("error", StringComparison.Ordinal));
                }
                catch (Exception ex) { failed += plan.Count; sessionLog.Add(DateTime.UtcNow.ToString("o") + "\tRule block failed\t" + rule.Label + "\t" + ex.Message); }
            }
            ruleStatus = "Rules: " + rules.Count + " active" + (added > 0 ? ", blocked " + added + " NEW" : ", nothing new") +
                (skipped > 0 ? ", " + skipped + " whole-PC rules need admin" : "") + (failed > 0 ? ", " + failed + " errors (Block history)" : "") +
                (protectedSkipped > 0 ? ", " + protectedSkipped + " protected or allowed skipped" : "");
            // Rescan once so the new blocks show as Blocked; the second pass finds nothing new and stops.
            if (added > 0 && !ruleRescan) { ruleRescan = true; BeginInvoke((Action)StartScan); }
            else ruleRescan = false;
        }

        private void ShowRules()
        {
            Form dialog = new Form { Text = "Rules — groups kept blocked", Size = new Size(900, 420), Font = Font, StartPosition = FormStartPosition.CenterParent };
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Group", "Scope", "Created (UTC)", "Key" }, new int[] { 280, 120, 200, 260 });
                Action fill = delegate
                {
                    grid.Items.Clear();
                    foreach (BlockRule r in BlockRules.Read()) grid.Items.Add(new ListViewItem(new string[] { r.Label, r.Scope, r.Created, r.GroupKey }) { Tag = r });
                };
                fill();
                Label note = new Label { Dock = DockStyle.Bottom, Height = 46, Text = "After every scan (every 60 seconds while rules exist), anything new in these groups is added to Disallowed and logged.\r\n" +
                    "Removing a rule stops new blocks; it does not unblock. Use Undo last block or Unblock selected certificate for that.\r\nFile: " + BlockRules.RulesPath };
                Button remove = new Button { Text = "Remove selected rule", Dock = DockStyle.Bottom, Height = 30 };
                remove.Click += delegate
                {
                    if (grid.SelectedItems.Count == 0) return;
                    BlockRule chosen = (BlockRule)grid.SelectedItems[0].Tag;
                    BlockRules.Save(BlockRules.Read().Where(r => !(r.GroupKey == chosen.GroupKey && r.Scope == chosen.Scope)).ToList());
                    fill();
                };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(remove); dialog.Controls.Add(close); dialog.CancelButton = close;
                ShowTool(dialog, "rules");
            }
        }

        private void UpdateMicrosoftList()
        {
            status.Text = "Downloading Microsoft's trusted root list (certutil -generateSSTFromWU)...";
            Thread worker = new Thread(delegate()
            {
                string error;
                try { error = MicrosoftList.Update(); }
                catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; }
                Post(delegate
                {
                    if (error != null) { ShowText("Microsoft root list", "Could not download the list.\r\n\r\n" + error + "\r\n\r\nA VPN or firewall blocking certutil can cause this."); status.Text = "Microsoft root list: download failed"; return; }
                    StartScan();
                });
            });
            worker.IsBackground = true; worker.Name = "Microsoft root list download"; worker.Start();
        }
    }
}
