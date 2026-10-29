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
            string error = Generate(temp);
            if (error != null) return error;
            if (File.Exists(SstPath)) File.Delete(SstPath);
            File.Move(temp, SstPath);
            return null;
        }

        // certutil checks the list against Microsoft's signed root list (authroot.stl) as it writes it.
        internal static string Generate(string temp)
        {
            if (File.Exists(temp)) File.Delete(temp);
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "certutil.exe"), "-generateSSTFromWU \"" + temp + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (Process process = Process.Start(info))
            {
                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                if (!process.WaitForExit(180000)) { try { process.Kill(); } catch (InvalidOperationException) { } return "certutil timed out.\r\n" + output; }
                if (process.ExitCode != 0 || !File.Exists(temp)) return "certutil failed (exit " + process.ExitCode + ").\r\n" + output;
            }
            return null;
        }

        private static List<byte[]> cache;
        private static DateTime cacheStamp;
        private static readonly object gate = new object();

        // The list's certificates, read from disk once per download.
        private static List<byte[]> Load()
        {
            DateTime stamp = File.GetLastWriteTimeUtc(SstPath);
            lock (gate)
            {
                if (cache != null && stamp == cacheStamp) return cache;
                X509Certificate2Collection roots = new X509Certificate2Collection();
                roots.Import(SstPath);
                List<byte[]> list = new List<byte[]>();
                foreach (X509Certificate2 root in roots) { list.Add(root.RawData); root.Reset(); }
                cache = list; cacheStamp = stamp;
                return list;
            }
        }

        // Adds the list's roots to the snapshot so groups and blocking see roots Windows has not downloaded yet.
        internal static int Merge(Snapshot snapshot)
        {
            if (!File.Exists(SstPath)) return -1;
            int count = 0;
            foreach (byte[] der in Load())
            {
                CertificateRecord record = snapshot.Add(der);
                record.FoundIn.Add(Label);
                count++;
            }
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
                if (f.Length >= 4) rules.Add(new BlockRule { GroupKey = Renamed(f[0]), Label = f[0] == "tag:🌿" ? "🤡" : f[1], Scope = f[2], Created = f[3] });
            return rules;
        }

        // Groups renamed in v0.2.18: old saved rules keep working.
        private static string Renamed(string key)
        {
            switch (key)
            {
                case "tag:🌿🧱": return "tag:🧱";
                case "tag:🌿": return "tag:🤡";       // v0.2.30: Basel / CBDC is the clown bloc now
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

    internal sealed class RuleOutcome
    {
        internal string Status = "";
        internal int Added, Lightened, Removed;
        internal readonly List<string> Log = new List<string>();
    }

    internal static class RuleRunner
    {
        // After a scan, in the scan worker: anything new in a kept-blocked group goes into Disallowed.
        // Never-block certificates (allowed, unblocked by hand, repaired) and protected ones are skipped.
        internal static RuleOutcome Apply(Snapshot result)
        {
            RuleOutcome o = new RuleOutcome();
            // Lighter: kisib's own entries under a blocked root are dead weight; take them back out.
            try { o.Removed = LightBlock.Lighten(result, o); } catch (Exception ex) { o.Log.Add(DateTime.UtcNow.ToString("o") + "\tLighter failed\t" + ex.Message); }
            List<BlockRule> rules;
            try { rules = BlockRules.Read(); }
            catch (Exception ex) { o.Status = "Rules unreadable: " + ex.Message; return o; }
            GroupsRoot groups = result.Groups;
            if (rules.Count == 0 || groups == null || groups.Error != null) { if (o.Removed > 0) o.Status = "Lighter: took out " + o.Removed + " extra Untrusted Certificates entries (already dead under a blocked root)"; return o; }
            bool elevated = Elevation.IsElevated;
            AllowedSet allowed = AllowedList.Load();
            int skipped = 0, failed = 0, protectedSkipped = 0;
            foreach (IGrouping<string, BlockRule> byScope in rules.GroupBy(r => r.Scope))
            {
                X509Location scope;
                try { scope = (X509Location)Enum.Parse(typeof(X509Location), byScope.Key); } catch (ArgumentException) { continue; }
                if (scope == X509Location.LocalMachine && !elevated) { skipped += byScope.Count(); continue; }
                Dictionary<string, BlockItem> plan = new Dictionary<string, BlockItem>(StringComparer.Ordinal);
                List<string> labels = new List<string>();
                foreach (BlockRule rule in byScope)
                {
                    GroupNode group = groups.All.FirstOrDefault(g => g.Key == rule.GroupKey);
                    if (group == null) continue;
                    string label = rule.Label;
                    foreach (BlockItem i in BlockEngine.Plan(result, group.Members.Select(id => result.Certificates[id]), delegate { return "rule: " + label; }, scope))
                    {
                        if (i.AlreadyBlocked || plan.ContainsKey(i.Certificate.Identity)) continue;
                        if (TrustCategories.ProtectedBy(i.Certificate) != null || allowed.Covers(i.Certificate)) { protectedSkipped++; continue; }
                        plan.Add(i.Certificate.Identity, i);
                        if (!labels.Contains(label)) labels.Add(label);
                    }
                }
                // Lighter: a CA under a root this blocks (or already blocked) is dead without its own entry.
                if (plan.Count > 0 && result.Paths != null)
                {
                    LightBlock.Cut cut = LightBlock.Compute(result.Paths, LightBlock.Records(result, LightBlock.BlockedFor(result, scope)).Concat(plan.Values.Select(i => i.Certificate)));
                    List<string> spare = plan.Values.Where(i => !LightBlock.Needed(result.Paths, cut, i.Certificate)).Select(i => i.Certificate.Identity).ToList();
                    foreach (string id in spare) plan.Remove(id);
                    o.Lightened += spare.Count;
                }
                if (plan.Count == 0) continue;
                try
                {
                    List<BlockLogRow> rows = BlockEngine.Block(plan.Values, scope, "rule: " + String.Join(" + ", labels.ToArray()));
                    o.Added += rows.Count(r => r.Result == "added");
                    failed += rows.Count(r => r.Result.StartsWith("error", StringComparison.Ordinal));
                }
                catch (Exception ex) { failed += plan.Count; o.Log.Add(DateTime.UtcNow.ToString("o") + "\tRule block failed\t" + byScope.Key + "\t" + ex.Message); }
            }
            o.Status = "Rules: " + rules.Count + " active" + (o.Added > 0 ? ", blocked " + o.Added + " NEW" : ", nothing new") +
                (skipped > 0 ? ", " + skipped + " whole-PC rules need admin" : "") + (failed > 0 ? ", " + failed + " errors (Block history)" : "") +
                (protectedSkipped > 0 ? ", " + protectedSkipped + " protected or never-block skipped" : "") +
                (o.Lightened > 0 ? ", " + o.Lightened + " not needed (under a blocked root)" : "") +
                (o.Removed > 0 ? ", took out " + o.Removed + " extra entries (lighter)" : "");
            return o;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private string ruleStatus = "";

        private void InitializeRules(MenuItem block)
        {
            block.MenuItems.Add(new MenuItem("-"));
            block.MenuItems.Add(new MenuItem("&Rules (keep groups blocked)...", delegate { ShowRules(); }));
            block.MenuItems.Add(new MenuItem("Update &Microsoft root list", delegate { UpdateMicrosoftList(); }));
            block.MenuItems.Add(new MenuItem("Update &CCADB list (all CA certificates, catches cross-signs)", delegate { UpdateCcadb(); }));
        }

        private static IEnumerable<GroupNode> AllGroups(GroupsRoot root)
        { return root.All; }

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
                Label note = new Label { Dock = DockStyle.Bottom, Height = 46, Text = "Whenever Windows adds a certificate (and every 10 minutes), anything new in these groups is added to Disallowed and logged.\r\n" +
                    "Never-block certificates (allowed, unblocked by hand, repaired) are skipped.\r\nFile: " + BlockRules.RulesPath };
                Button remove = new Button { Text = "Remove rule (keep what it already blocked)", Dock = DockStyle.Bottom, Height = 30 };
                remove.Click += delegate
                {
                    if (grid.SelectedItems.Count == 0) return;
                    BlockRule chosen = (BlockRule)grid.SelectedItems[0].Tag;
                    BlockRules.Save(BlockRules.Read().Where(r => !(r.GroupKey == chosen.GroupKey && r.Scope == chosen.Scope)).ToList());
                    fill();
                };
                Button removeAndUnblock = new Button { Text = "Remove rule and unblock its certificates", Dock = DockStyle.Bottom, Height = 30 };
                removeAndUnblock.Click += delegate
                {
                    if (grid.SelectedItems.Count == 0) return;
                    BlockRule chosen = (BlockRule)grid.SelectedItems[0].Tag;
                    GroupNode g = groups == null ? null : groups.All.FirstOrDefault(x => x.Key == chosen.GroupKey);
                    if (g == null) { BlockRules.Save(BlockRules.Read().Where(r => r.GroupKey != chosen.GroupKey).ToList()); fill(); Say("Rule removed; its group is not in this scan, so nothing to unblock."); return; }
                    UnblockGroups(new List<GroupNode> { g });
                    fill();
                };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(remove); dialog.Controls.Add(removeAndUnblock); dialog.Controls.Add(close); dialog.CancelButton = close;
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
