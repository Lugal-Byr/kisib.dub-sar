using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Kisib
{
    // Tools page: every tool on one list, what it does, and how things stand right now. Double-click to run one.
    internal sealed partial class ExplorerForm
    {
        private sealed class ToolRow { internal string Name, What; internal Func<string> Now; internal Action Run; }

        private List<ToolRow> ToolRows()
        {
            Func<Func<Seal, bool>, string> sealState = delegate(Func<Seal, bool> which)
            {
                if (snapshot == null) return "after a scan";
                List<Seal> s = Seals.All.Where(which).ToList();
                int blocked = s.Count(x => { CertificateRecord c = snapshot.BySha1(x.Sha1); return c != null && snapshot.IsBlocked(c); });
                int missing = s.Count(x => { CertificateRecord c = snapshot.BySha1(x.Sha1); return c == null || !TrustGraph.InRootStore(c); });
                return blocked == 0 && missing == 0 ? "all " + s.Count + " fine" : (blocked > 0 ? blocked + " blocked" : "") + (blocked > 0 && missing > 0 ? ", " : "") + (missing > 0 ? missing + " not in Trusted Root" : "");
            };
            return new List<ToolRow>
            {
                new ToolRow { Name = "Repair: Windows essentials", What = "Microsoft's own roots back (Windows files, Update, Defender, Microsoft sites)", Now = () => sealState(s => s.IsMicrosoft), Run = () => RepairSeals("Windows essentials", s => s.IsMicrosoft, "Microsoft's own roots only.") },
                new ToolRow { Name = "Repair: Get online", What = "The roots most websites hang under, carried inside kisib", Now = () => sealState(s => s.Set == "online" || s.Set == "microsoft"), Run = () => RepairSeals("Get online", s => s.Set == "online" || s.Set == "microsoft", "The roots most websites hang under. Owners shown per row.") },
                new ToolRow { Name = "Repair: What Windows ships with", What = "Microsoft's list of roots Windows itself requires", Now = () => sealState(s => s.Set == "windows"), Run = () => RepairSeals("What Windows ships with", s => s.Set == "windows", "Microsoft's required roots.") },
                new ToolRow { Name = "Repair: My trusted categories", What = "Roots your switched-on categories need, with each owner shown", Now = () => TrustCategories.Read().Count(c => c.Enabled) + " categories on", Run = RepairCategories },
                new ToolRow { Name = "Repair: What this PC uses", What = "Blocked or missing roots behind refusals in the last 7 days", Now = () => denials.Count(d => !d.Ok && !d.Noise && d.Time > DateTime.Now.AddDays(-7)) + " refusals this week", Run = RepairUsed },
                new ToolRow { Name = "Repair: Reset to the standard seals", What = "All seals back, one-off blocks lifted; only your blocs stay blocked", Now = () => snapshot == null ? "after a scan" : snapshot.Blocked.Count + " blocked now", Run = RepairReset },
                new ToolRow { Name = "Repair: Put back what was blocked before kisib", What = "Re-blocks what you unblocked by hand from Microsoft's untrusted list", Now = () => UnblockedByHand.Read().Count + " on the list", Run = RepairPutBack },
                new ToolRow { Name = "Revocation check", What = "For the latest \"revocation server unreachable\" refusal: which servers it needed, and can they be reached", Now = () => { int n = denials.Count(d => !d.Ok && IsRevocationRefusal(d) && d.Time > DateTime.Now.AddDays(-1)); return n == 0 ? "none today" : n + " in the last day"; }, Run = () => { Denial last = denials.Where(d => !d.Ok && IsRevocationRefusal(d) && d.ChainSha1.Count > 0).OrderByDescending(d => d.Time).FirstOrDefault(); if (last == null) Say("No revocation refusal with a chain on record."); else CheckRevocation(last); } },
                new ToolRow { Name = "Windows certificates, live", What = "Every cert in Windows' stores and everything kisib did: where it sits, what Windows says right now, who put it there; ✅ / 🚫 switch, trim", Now = () => "live", Run = ShowLedger },
                new ToolRow { Name = "Required for app", What = "Each app > the roots it used > the CAs in between; tick what has to keep working", Now = () => { int n = AppChains.All().Select(r => r.Program).Distinct(StringComparer.OrdinalIgnoreCase).Count(); return n + " apps seen"; }, Run = ShowRequiredForApp },
                new ToolRow { Name = "Import a certificate file", What = "Roots go into Trusted Root (Windows' own list decides, or you do), CAs into Intermediate CAs", Now = () => "", Run = ImportFromFile },
                new ToolRow { Name = "Keep Claude reachable", What = "After every scan, the roots the Claude app needs are unblocked and put back, even inside a blocked bloc", Now = () => (Storage.Setting("keep claude reachable off") ? "off" : "on") + " · " + ClaudeState(), Run = () => { Storage.Setting("keep claude reachable off", !Storage.Setting("keep claude reachable off")); Say("Keep Claude reachable is " + (Storage.Setting("keep claude reachable off") ? "off." : "on.")); if (!Storage.Setting("keep claude reachable off")) KeepReachable(true); } },
                new ToolRow { Name = "Fix Claude's connection", What = "Do the Claude check now (also in the tray menu)", Now = () => ClaudeState(), Run = () => KeepReachable(true) },
                new ToolRow { Name = "Let Claude run kisib", What = "Copies the command line Claude uses from the desktop app: status, refusals, repairs, allows, unblocks", Now = () => "--do \"help\"", Run = CopyClaudeLine },
                new ToolRow { Name = "Block by bloc and continent", What = "Pick 👑 🏛️ 🧱 🤡 💃 or continents, see what they catch, block or unblock", Now = () => RuledSummary(), Run = OpenBlocBoard },
                new ToolRow { Name = "Rules (groups kept blocked)", What = "Groups kisib keeps blocked as new certificates show up", Now = () => BlockRules.Read().Count + " rules", Run = ShowRules },
                new ToolRow { Name = "Undo last block", What = "Takes out the last batch kisib blocked", Now = () => { BlockLogRow r = BlockEngine.ReadLog().LastOrDefault(x => x.Action == "block" && x.Result == "added"); return r == null ? "nothing to undo" : r.Group + " · " + r.Time.Replace("T", " ").Substring(0, Math.Min(16, r.Time.Length)) + " UTC"; }, Run = UndoLastBlock },
                new ToolRow { Name = "Never block list", What = "Allowed for good, unblocked by hand, repaired: rules skip these", Now = () => AllowedList.Read().Count + " certificates", Run = ShowAllowed },
                new ToolRow { Name = "Open right now", What = "Blocks lifted for a while (tray > Open right now re-blocks them)", Now = () => { int n = TempAllow.Read().Select(p => p.Subject).Distinct().Count(); return n == 0 ? "nothing open" : n + " open"; }, Run = () => { if (tray != null) Say("Right-click the seal in the tray > Open right now."); } },
                new ToolRow { Name = "Program allows", What = "Blocks that open while a program runs (like an updater)", Now = () => { List<ProgramAllow> p = ProgramAllows.Read(); return p.Count == 0 ? "none" : String.Join(", ", p.Select(x => x.Program).ToArray()); }, Run = () => Say("Tray > Open right now lists program allows; each can be stopped there.") },
                new ToolRow { Name = "🌀 Route around", What = "Blocked CAs that still have a way in (cross-signs), and the other paths around blocks", Now = () => lastLeaks == 0 ? "no leaks" : lastLeaks + " leaks", Run = ShowReroute },
                new ToolRow { Name = "Routes kisib installed", What = "Cross-signs kisib added so Windows can go around a block", Now = () => RouteStore.Read().Count + " routes", Run = ShowRoutes },
                new ToolRow { Name = "Update Microsoft root list", What = "Microsoft's full list of trusted roots (so groups see roots not downloaded yet)", Now = () => MicrosoftList.Updated.HasValue ? "updated " + MicrosoftList.Updated.Value.ToString("yyyy-MM-dd") : "not loaded", Run = UpdateMicrosoftList },
                new ToolRow { Name = "Update CCADB list", What = "Every public CA certificate (catches cross-signs not on this PC)", Now = () => Ccadb.Updated.HasValue ? "updated " + Ccadb.Updated.Value.ToString("yyyy-MM-dd") : "not loaded", Run = UpdateCcadb },
                new ToolRow { Name = "Refresh lists weekly", What = "Microsoft list and CCADB refresh themselves once a week when online", Now = () => Storage.Setting("lists auto-refresh off") ? "off" : "on", Run = () => { Storage.Setting("lists auto-refresh off", !Storage.Setting("lists auto-refresh off")); Say("Weekly list refresh is " + (Storage.Setting("lists auto-refresh off") ? "off." : "on.")); } },
                new ToolRow { Name = "Trusted categories", What = "Services you expect to work; their roots are protected and their refusals stay calm", Now = () => String.Join(", ", TrustCategories.Read().Where(c => c.Enabled).Select(c => c.Name).ToArray()), Run = ShowCategories },
                new ToolRow { Name = "Who-is-who lists", What = "file.exe = name = what it does; site = who = what for (open the folder to edit)", Now = () => Storage.FolderName, Run = () => { WhoIsWho.EnsureFiles(); try { System.Diagnostics.Process.Start("explorer.exe", "\"" + Storage.Folder + "\""); } catch (Exception ex) { Say(ex.Message); } } },
                new ToolRow { Name = "Watching certificate checks", What = "Windows' CAPI2 log feeds the live map, pop-ups and denials", Now = () => denialWatcher != null ? "on" : "off (Watch menu; run as admin once)", Run = () => watchToggle.PerformClick() },
                new ToolRow { Name = "Quiet mode", What = "Refusals are logged, no pop-ups", Now = () => QuietMode ? "on" : "off", Run = ToggleQuiet },
                new ToolRow { Name = "Update kisib now", What = "Checks GitHub for a newer release and installs it here (your lists stay as they are)", Now = () => AboutText.Version + (updateNote != null ? " · " + updateNote : ""), Run = () => CheckForUpdate(true) },
                new ToolRow { Name = "Auto update", What = "Checks GitHub after start and every 12 hours; installs newer releases by itself", Now = () => AutoUpdate ? "on" : "off", Run = () => { Storage.Setting("auto update off", AutoUpdate); Say("Auto update is " + (AutoUpdate ? "on." : "off.")); } },
                new ToolRow { Name = "Install to C:\\certs\\kisib", What = "Copies kisib (and your lists) there, moves Start with Windows to it, and runs it from there", Now = () => String.Equals(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'), InstallFolder, StringComparison.OrdinalIgnoreCase) ? "running from there" : "running from " + AppDomain.CurrentDomain.BaseDirectory, Run = InstallToCerts },
                new ToolRow { Name = "Rescan when stores change", What = "Rescans when Windows adds or removes a certificate, plus every 10 minutes", Now = () => autoScanToggle.Checked ? "on, " + storeWatcher.Status : "off", Run = () => autoScanToggle.PerformClick() },
                new ToolRow { Name = "Running as administrator", What = "Needed for whole-PC blocks, Trusted Root and services like Windows Update", Now = () => Elevation.IsElevated ? "yes" : "no: whole-PC changes need it", Run = () => Say(Elevation.IsElevated ? "kisib is running as administrator." : "Right-click kisib.dub-sar.exe > Run as administrator.") },
                new ToolRow { Name = "Live map", What = "Programs, sites, CAs and roots as boxes and arrows", Now = () => recentChecks.Count + " checks in memory", Run = OpenLiveMap },
                new ToolRow { Name = "Certificate denials", What = "Every refusal Windows logged, with its card", Now = () => denials.Count(d => !d.Ok && !d.Noise && d.Time.Date == DateTime.Today) + " today", Run = ShowDenials },
                new ToolRow { Name = "Programs", What = "Who listens, who talks, who signed it", Now = () => programs.Count == 0 ? "not collected yet" : programs.Count + " programs", Run = ShowPrograms },
                new ToolRow { Name = "Standings", What = "CA owners by country", Now = () => snapshot == null ? "" : snapshot.Certificates.Count + " certificates", Run = ShowStandings },
                new ToolRow { Name = "My tags", What = "Your own tags on countries, organizations or certificates", Now = () => { try { return MyTags.Read().Count + " tags"; } catch (Exception) { return "?"; } }, Run = ShowMyTags },
                new ToolRow { Name = "Incident check", What = "Published compromised certificates and keys, checked against this PC", Now = () => "", Run = ShowIncidents },
            };
        }

        // Tools grouped by what they do; the emoji draws in color in the list.
        private static readonly string[] ToolKinds = { "🔧 Fix and repair", "🚫 Block", "✅ Allow", "👀 Watch", "📋 Lists and info", "⚙️ kisib itself" };

        private static int KindOf(string name)
        {
            if (name.StartsWith("Repair", StringComparison.Ordinal) || name.StartsWith("Required", StringComparison.Ordinal) || name.StartsWith("Import", StringComparison.Ordinal) ||
                name.IndexOf("Claude's connection", StringComparison.Ordinal) >= 0 || name.StartsWith("Keep Claude", StringComparison.Ordinal) || name.StartsWith("Revocation", StringComparison.Ordinal)) return 0;
            if (name.StartsWith("Block", StringComparison.Ordinal) || name.StartsWith("Rules", StringComparison.Ordinal) || name.StartsWith("Undo", StringComparison.Ordinal) || name.IndexOf("Route", StringComparison.Ordinal) >= 0) return 1;
            if (name.StartsWith("Never", StringComparison.Ordinal) || name.StartsWith("Open right now", StringComparison.Ordinal) || name.StartsWith("Program allows", StringComparison.Ordinal) || name.StartsWith("Trusted categories", StringComparison.Ordinal)) return 2;
            if (name.StartsWith("Live map", StringComparison.Ordinal) || name.StartsWith("Certificate denials", StringComparison.Ordinal) || name.StartsWith("Watching", StringComparison.Ordinal) || name.StartsWith("Quiet", StringComparison.Ordinal) || name == "Programs") return 3;
            if (name.StartsWith("Rescan", StringComparison.Ordinal) || name.StartsWith("Running as", StringComparison.Ordinal) || name.StartsWith("Let Claude", StringComparison.Ordinal) ||
                name.StartsWith("Update kisib", StringComparison.Ordinal) || name.StartsWith("Auto update", StringComparison.Ordinal) || name.StartsWith("Install to", StringComparison.Ordinal)) return 5;
            return 4;
        }

        private string ClaudeState()
        {
            if (snapshot == null) return "after a scan";
            List<RepairRow> rows = BuildRepair("claude").Rows;
            int blocked = rows.Count(r => r.Blocked), missing = rows.Count(r => r.Cert != null && !r.Trusted);
            return blocked == 0 && missing == 0 ? "Claude's roots fine" : (blocked > 0 ? blocked + " of Claude's roots blocked" : "") + (blocked > 0 && missing > 0 ? ", " : "") + (missing > 0 ? missing + " not in Trusted Root" : "");
        }

        private void CopyClaudeLine()
        {
            string line = CommandLine("status");
            try { Clipboard.SetText(line); Say("Copied. Paste it to Claude: " + line); }
            catch (Exception ex) { Say(line + "  (could not copy: " + ex.Message + ")"); }
        }

        private string RuledSummary()
        {
            List<BlockRule> rules = BlockRules.Read();
            if (rules.Count == 0) return "nothing kept blocked";
            return "kept blocked: " + String.Join(" ", rules.Select(r => r.Label).Distinct().ToArray());
        }

        internal void ShowToolsPage()
        {
            Form dialog = new Form { Text = "kisib tools — everything, and how it stands right now", Size = new Size(1150, 720), Font = Font };
            ListView grid = new ListView();
            SetupGrid(grid, new string[] { "Tool", "What it does", "Right now" }, new int[] { 300, 520, 300 });
            EmojiText.AttachTo(grid, 0, 1, 2);
            List<ToolRow> rows = ToolRows();
            bool byName = Storage.Setting("tools a to z");
            ComboBox arrange = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 220, Margin = new Padding(3, 5, 3, 3) };
            arrange.Items.AddRange(new object[] { "by what they do", "A to Z" });
            arrange.SelectedIndex = byName ? 1 : 0;
            FlowLayoutPanel top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(6, 2, 6, 0) };
            top.Controls.Add(new Label { Text = "Arrange:", AutoSize = true, Padding = new Padding(0, 9, 0, 0) });
            top.Controls.Add(arrange);
            Action fill = delegate
            {
                if (dialog.IsDisposed) return;
                string keep = grid.SelectedItems.Count > 0 ? grid.SelectedItems[0].Text : null;
                grid.BeginUpdate(); grid.Items.Clear();
                List<ToolRow> ordered = byName ? rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList()
                    : rows.OrderBy(r => KindOf(r.Name)).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
                int lastKind = -1;
                foreach (ToolRow r in ordered)
                {
                    if (!byName && KindOf(r.Name) != lastKind)
                    {
                        lastKind = KindOf(r.Name);
                        grid.Items.Add(new ListViewItem(new string[] { ToolKinds[lastKind], "", "" }) { BackColor = Color.FromArgb(236, 236, 248), ForeColor = Color.FromArgb(60, 60, 110), Font = new Font(grid.Font, FontStyle.Bold) });
                    }
                    string now;
                    try { now = r.Now(); } catch (Exception ex) { now = "? " + ex.Message; }
                    ListViewItem item = new ListViewItem(new string[] { r.Name, r.What, now }) { Tag = r };
                    if (now.IndexOf("blocked", StringComparison.Ordinal) >= 0 && r.Name.StartsWith("Repair", StringComparison.Ordinal) && !now.StartsWith("all", StringComparison.Ordinal)) item.ForeColor = Color.Firebrick;
                    grid.Items.Add(item);
                    if (r.Name == keep) item.Selected = true;
                }
                grid.EndUpdate();
            };
            fill();
            arrange.SelectedIndexChanged += delegate { byName = arrange.SelectedIndex == 1; Storage.Setting("tools a to z", byName); fill(); };
            Action run = delegate { if (grid.SelectedItems.Count == 0 || grid.SelectedItems[0].Tag == null) return; ToolRow r = (ToolRow)grid.SelectedItems[0].Tag; try { r.Run(); } catch (Exception ex) { Say(r.Name + ": " + ex.Message); } fill(); };
            grid.DoubleClick += delegate { run(); };
            grid.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) run(); };
            Button go = new Button { Text = "Run selected tool", Dock = DockStyle.Bottom, Height = 32 };
            go.Click += delegate { run(); };
            Label foot = new Label { Dock = DockStyle.Bottom, Height = 24, Padding = new Padding(8, 4, 0, 0), ForeColor = SystemColors.GrayText, Text = "Double-click a tool to run it. This list updates after every scan." };
            dialog.Controls.Add(grid); dialog.Controls.Add(top); dialog.Controls.Add(foot); dialog.Controls.Add(go);
            toolsRefresh = fill;
            dialog.FormClosed += delegate { if (toolsRefresh == fill) toolsRefresh = null; };
            ShowTool(dialog, "tools");
        }
    }
}
