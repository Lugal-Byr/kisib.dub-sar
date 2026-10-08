using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
namespace Kisib
{
    public static class GuiVerification
    {
        private static T Field<T>(ExplorerForm form, string name)
        { return (T)typeof(ExplorerForm).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(form); }
        private static void Check(bool condition, string name)
        { if (!condition) throw new InvalidOperationException("FAIL GUI: " + name); Console.WriteLine("PASS GUI: " + name); }
        private static void PumpUntil(Func<bool> condition, int seconds)
        {
            Stopwatch clock = Stopwatch.StartNew();
            while (!condition()) { Application.DoEvents(); if (clock.Elapsed.TotalSeconds > seconds) throw new TimeoutException("GUI operation exceeded deadline."); Thread.Sleep(20); }
            Application.DoEvents();
        }
        private static IEnumerable<TreeNode> Nodes(TreeNode root)
        { yield return root; foreach (TreeNode child in root.Nodes) foreach (TreeNode item in Nodes(child)) yield return item; }
        private static IEnumerable<Control> Controls(Control root)
        { yield return root; foreach (Control child in root.Controls) foreach (Control item in Controls(child)) yield return item; }
        private static IEnumerable<MenuItem> Menus(Menu menu)
        { foreach (MenuItem child in menu.MenuItems) { yield return child; foreach (MenuItem item in Menus(child)) yield return item; } }
        private static TreeNode MachineRoot(TreeView tree)
        { return Nodes(tree.Nodes[0]).First(n => n.Tag is SystemStore && ((SystemStore)n.Tag).Path.Equals("LOCAL_MACHINE\\Root", StringComparison.OrdinalIgnoreCase)); }
        private static void Refresh(ExplorerForm form)
        {
            string previous = Field<Snapshot>(form, "snapshot").ScanId; Field<Button>(form, "refresh").PerformClick();
            PumpUntil(delegate { return !Field<bool>(form, "scanning") && Field<Snapshot>(form, "snapshot").ScanId != previous; }, 180);
        }
        public static int Run(string project, string results)
        {
            Exception failure = null; int checks = 0;
            Thread thread = new Thread(delegate()
            {
                string archive = Path.Combine(Path.GetTempPath(), "kisib-screen1-test-" + Guid.NewGuid().ToString("N"));
                ThreadExceptionEventHandler handler = delegate(object sender, ThreadExceptionEventArgs args) { failure = args.Exception; };
                Application.ThreadException += handler;
                try
                {
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (ExplorerForm form = new ExplorerForm(project, archive))
                    {
                        Stopwatch clock = Stopwatch.StartNew(); form.Show();
                        PumpUntil(delegate { return failure != null || Field<Snapshot>(form, "snapshot") != null; }, 180);
                        Console.WriteLine("GUI first inventory seconds=" + clock.Elapsed.TotalSeconds.ToString("F3")); if (failure != null) throw failure;
                        Snapshot snapshot = Field<Snapshot>(form, "snapshot"); TreeView tree = Field<TreeView>(form, "tree"); ListView list = Field<ListView>(form, "list");
                        Check(form.Visible && tree.Visible && tree.ShowLines && tree.ShowPlusMinus && snapshot.Certificates.Count > 0, "actual native Screen 1 opens and loads Windows certificates"); checks++;
                        Check(!Controls(form).Any(c => c is ComboBox) && Nodes(tree.Nodes[0]).All(n => n.Tag is Snapshot || n.Tag is StoreLocation || n.Tag is SystemStore || n.Tag is PhysicalStore || n.Tag is DocumentedStoreReference), "Screen 1 offers only real store paths and no roadmap grouping switch"); checks++;
                        Check(Nodes(tree.Nodes[0]).Count(n => n.Tag is StoreLocation) == snapshot.Locations.Count && Nodes(tree.Nodes[0]).Count(n => n.Tag is SystemStore) == snapshot.StoreCount && Nodes(tree.Nodes[0]).Count(n => n.Tag is PhysicalStore) == snapshot.PhysicalCount, "every reported location/system/physical store gets a distinct node"); checks++;
                        Check(list.Columns.Cast<ColumnHeader>().Select(c => c.Text).SequenceEqual(new string[] { "Subject CN", "Issuer CN", "C=", "found in (physical stores)", "not-before", "not-after", "SHA-1", "SHA-256" }), "exactly eight requested columns in order"); checks++;
                        Check(Field<HistoryArchive>(form, "history") == null && !Directory.Exists(archive), "opening and scanning creates no history or archive directory by default"); checks++;
                        Check(!Field<System.Windows.Forms.Timer>(form, "historyTimer").Enabled && !Field<System.Windows.Forms.Timer>(form, "activityTimer").Enabled && Field<ActivityMonitor>(form, "activity").Status == "CAPI2 not started" && !Field<SyscallTrace>(form, "syscalls").Running, "automatic scanning and collectors are off by default"); checks++;
                        string[] optional = new string[] { "journalToggle", "archiveToggle", "autoScanToggle", "syscallToggle" };
                        MenuItem optionalMenu = Menus(form.Menu).Single(m => m.Text == "Optional &features");
                        Check(optionalMenu.MenuItems.Count == 4 && optional.All(name => optionalMenu.MenuItems.Cast<MenuItem>().Contains(Field<MenuItem>(form, name)) && !Field<MenuItem>(form, name).Checked), "exactly the four requested optional switches start unchecked"); checks++;
                        Check(!Menus(form.Menu).Any(m => m.Text.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0 || m.Text.IndexOf("incident", StringComparison.OrdinalIgnoreCase) >= 0 || m.Text.IndexOf("CAPI2", StringComparison.OrdinalIgnoreCase) >= 0 || m.Text.IndexOf("country", StringComparison.OrdinalIgnoreCase) >= 0 || m.Text.IndexOf("labels", StringComparison.OrdinalIgnoreCase) >= 0), "roadmap dialogs and CAPI2-setting actions are absent from every menu"); checks++;
                        Check(Field<TabControl>(form, "resultTabs").TabPages.Count == 1 && Field<TabControl>(form, "evidenceTabs").TabPages.Count == 2, "default panes show certificates and Details/Issuer only"); checks++;
                        Check(Nodes(tree.Nodes[0]).Where(n => n.Tag is PhysicalStore).All(n => n.Parent.Tag is SystemStore && n.Parent.Parent.Tag is StoreLocation && n.Text.StartsWith(((PhysicalStore)n.Tag).Name + " (" + ((PhysicalStore)n.Tag).Certificates.Count)), "physical parentage and observed certificate counts match native records"); checks++;
                        Check(Nodes(tree.Nodes[0]).Any(n => n.Tag is PhysicalStore && ((PhysicalStore)n.Tag).ReadSucceeded && ((PhysicalStore)n.Tag).Certificates.Count == 0 && n.Text.EndsWith("(0)")), "reported empty physical stores remain visible with zero counts"); checks++;
                        Check(Nodes(tree.Nodes[0]).Where(n => n.Tag is DocumentedStoreReference).All(n => n.ForeColor == SystemColors.GrayText), "documentation references are grey and never physical store objects"); checks++;
                        CertificateRecord first = snapshot.Certificates.Values.First(); TextBox search = Field<TextBox>(form, "findIssuer"); search.Text = first.Sha256; tree.SelectedNode = tree.Nodes[0]; Application.DoEvents();
                        Check(list.Items.Count == 1 && ((CertificateRecord)list.Items[0].Tag).Identity == first.Identity, "Find filters certificate rows while preserving all store paths"); checks++;
                        Check(list.Items[0].SubItems[0].Text == first.SubjectShortName && list.Items[0].SubItems[1].Text == first.IssuerShortName && list.Items[0].SubItems[2].Text == (first.SubjectCountry ?? "—") && list.Items[0].SubItems[6].Text == first.Sha1 && list.Items[0].SubItems[7].Text == first.Sha256, "rows use CN or O, separate country, and exact certificate hashes"); checks++;
                        list.Items[0].Selected = true; list.Items[0].Focused = true; Application.DoEvents(); string text = Field<TextBox>(form, "details").Text;
                        Check(text.Contains(first.Subject) && text.Contains(first.Issuer) && text.Contains(first.Sha256) && text.Contains("SPKI SHA-256"), "Details retain full DNs and existing security metadata"); checks++;
                        using (Form errors = form.CreateStoreErrorsDialog())
                        {
                            ListView grid = errors.Controls.OfType<ListView>().Single();
                            Check(grid.Columns.Count == 2 && grid.Columns[0].Text == "Store" && grid.Columns[1].Text == "Error" && grid.Items.Count == snapshot.Errors.Count && Field<LinkLabel>(form, "errorsLink").Text == snapshot.Errors.Count + " errors", "clickable count opens the complete Store/Error list"); checks++;
                        }
                        search.Text = "FNMT"; TreeNode root = MachineRoot(tree); tree.SelectedNode = root; root.Expand(); root.Parent.Expand(); Application.DoEvents();
                        Check(root.Nodes.Cast<TreeNode>().Count(n => n.Tag is PhysicalStore) == ((SystemStore)root.Tag).PhysicalStores.Count && list.Items.Cast<ListViewItem>().All(row => ((CertificateRecord)row.Tag).Subject.IndexOf("FNMT", StringComparison.OrdinalIgnoreCase) >= 0 || ((CertificateRecord)row.Tag).Issuer.IndexOf("FNMT", StringComparison.OrdinalIgnoreCase) >= 0), "FNMT Find preserves every reported LOCAL_MACHINE Root sibling"); checks++;
                        Console.WriteLine("GUI native FNMT rows=" + list.Items.Count + "; hosted screenshot is NOT user-PC acceptance.");
                        string[] pathsBeforeFind = Nodes(tree.Nodes[0]).Where(n => n.Tag is PhysicalStore).Select(n => ((PhysicalStore)n.Tag).Path + "|" + n.Text).ToArray();
                        search.Text = "not-a-real-certificate-name-" + Guid.NewGuid().ToString("N"); Application.DoEvents();
                        Check(list.Items.Count == 0 && pathsBeforeFind.SequenceEqual(Nodes(tree.Nodes[0]).Where(n => n.Tag is PhysicalStore).Select(n => ((PhysicalStore)n.Tag).Path + "|" + n.Text)), "a Find miss leaves every native branch and count unchanged"); checks++;
                        search.Text = "FNMT"; Application.DoEvents();
                        using (Bitmap picture = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(picture, new Rectangle(Point.Empty, form.Size)); picture.Save(Path.Combine(results, "screen1-ci-only.png"), ImageFormat.Png); }
                        Snapshot probe = new Snapshot(); StoreLocation loc = new StoreLocation { Name = "LOCAL_MACHINE", Flags = Native.CERT_SYSTEM_STORE_LOCAL_MACHINE, Enumerated = true };
                        SystemStore store = new SystemStore { Name = "Root", Path = "LOCAL_MACHINE\\Root", ReadSucceeded = true }; PhysicalStore part = new PhysicalStore { Name = ".Default", Path = store.Path + "\\.Default", ReadSucceeded = true }; store.PhysicalStores.Add(part); loc.Stores.Add(store); probe.Locations.Add(loc); probe.Fail("Owned test observation", part.Path, "0x00000005 — fixture access denied");
                        MethodInfo display = typeof(ExplorerForm).GetMethod("Display", BindingFlags.Instance | BindingFlags.NonPublic); display.Invoke(form, new object[] { probe }); root = MachineRoot(tree);
                        Check(root.Nodes.Cast<TreeNode>().Count(n => n.Tag is PhysicalStore) == 1 && root.Nodes.Cast<TreeNode>().Count(n => n.Tag is DocumentedStoreReference) == 4 && root.Nodes.Cast<TreeNode>().Where(n => n.Tag is DocumentedStoreReference).All(n => n.Text.EndsWith("not present")), "missing documented siblings are four grey references, not invented stores"); checks++;
                        store.PhysicalEnumerationError = "fixture incomplete enumeration"; display.Invoke(form, new object[] { probe }); root = MachineRoot(tree);
                        Check(root.Nodes.Cast<TreeNode>().Where(n => n.Tag is DocumentedStoreReference).All(n => n.Text.Contains("enumeration incomplete") && !n.Text.EndsWith("not present")), "incomplete enumeration never asserts absent stores"); checks++;
                        using (Form errors = form.CreateStoreErrorsDialog()) { ListView grid = errors.Controls.OfType<ListView>().Single(); Check(grid.Items.Count == 1 && grid.Items[0].SubItems[0].Text == part.Path && grid.Items[0].SubItems[1].Text.Contains("0x00000005"), "error dialog preserves exact source path and Windows code"); checks++; }
                        display.Invoke(form, new object[] { snapshot }); search.Text = ""; tree.SelectedNode = tree.Nodes[0]; form.ClientSize = new Size(660, 470); Application.DoEvents();
                        Check(tree.Width >= 150 && tree.Height >= 100, "minimum size keeps the branch tree usable"); checks++; form.ClientSize = new Size(1150, 750);
                        Field<MenuItem>(form, "journalToggle").PerformClick(); Refresh(form);
                        Check(Field<HistoryArchive>(form, "history") != null && Directory.GetFiles(Path.Combine(archive, "logs"), "*.jsonl").Length > 0 && !Directory.Exists(Path.Combine(archive, "certificates")) && !Directory.Exists(Path.Combine(archive, "inventories")), "Journal opt-in appends observations without a public-certificate archive"); checks++;
                        Field<MenuItem>(form, "archiveToggle").PerformClick(); Refresh(form);
                        Check(Directory.GetFiles(Path.Combine(archive, "certificates"), "*.cer").Length > 0 && Directory.GetFiles(Path.Combine(archive, "inventories"), "*.json").Length > 0, "Archive opt-in retains public certificates and inventories securely"); checks++;
                        Check(Field<TabControl>(form, "resultTabs").TabPages.Count == 1 && Field<TabControl>(form, "evidenceTabs").TabPages.Count == 2 && optionalMenu.MenuItems.Count == 4 && !Controls(form).Any(c => c is ComboBox), "Journal and Archive opt-ins never unlock later-stage views"); checks++;
                        Field<MenuItem>(form, "autoScanToggle").PerformClick(); Check(Field<System.Windows.Forms.Timer>(form, "historyTimer").Enabled, "automatic scanning starts only by explicit toggle"); checks++;
                        Field<MenuItem>(form, "autoScanToggle").PerformClick(); Field<MenuItem>(form, "journalToggle").PerformClick();
                        Check(Field<HistoryArchive>(form, "history") == null && !Field<MenuItem>(form, "archiveToggle").Checked && Directory.Exists(archive), "recording off releases the writer and keeps prior records"); checks++;
                        form.Close(); Application.DoEvents(); Check(Field<bool>(form, "collectorsClosed") && !Field<SyscallTrace>(form, "syscalls").Running, "closing Screen 1 releases collectors"); checks++;
                    }
                    using (HistoryArchive reopened = new HistoryArchive(archive)) { Check(reopened.LastError == null, "opt-in history reopens without writer/recovery errors"); checks++; }
                }
                catch (Exception ex) { failure = ex; }
                finally { Application.ThreadException -= handler; try { if (Directory.Exists(archive)) Directory.Delete(archive, true); } catch (IOException) { } }
            });
            thread.SetApartmentState(ApartmentState.STA); thread.IsBackground = true; thread.Start();
            if (!thread.Join(420000)) { Console.WriteLine("FAIL GUI: Screen 1 timeout."); return 1; }
            if (failure != null) { Console.WriteLine(failure); return 1; }
            Console.WriteLine("GUI assertions passed: " + checks + ". User-PC acceptance remains to test."); return 0;
        }
    }
}
