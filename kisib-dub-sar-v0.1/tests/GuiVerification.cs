using System;
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
            while (!condition()) { Application.DoEvents(); if (clock.Elapsed.TotalSeconds > seconds) throw new TimeoutException("GUI operation exceeded its test deadline."); Thread.Sleep(20); }
            Application.DoEvents();
        }
        public static int Run(string project, string results)
        {
            Exception failure = null; int checks = 0;
            Thread thread = new Thread(delegate()
            {
                string archive = Path.Combine(Path.GetTempPath(), "kisib-gui-test-" + Guid.NewGuid().ToString("N"));
                ThreadExceptionEventHandler handler = delegate(object sender, ThreadExceptionEventArgs args) { failure = args.Exception; };
                Application.ThreadException += handler;
                try
                {
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (ExplorerForm form = new ExplorerForm(project, archive))
                    {
                        Stopwatch firstInventory = Stopwatch.StartNew(); form.Show();
                        try { PumpUntil(delegate { return failure != null || Field<Snapshot>(form, "snapshot") != null; }, 180); }
                        catch { Console.WriteLine("GUI deadline state: " + Field<Label>(form, "status").Text + "; scanning=" + Field<bool>(form, "scanning") + "; CAPI2=" + Field<ActivityMonitor>(form, "activity").Status); throw; }
                        Console.WriteLine("GUI first complete inventory seconds=" + firstInventory.Elapsed.TotalSeconds.ToString("F3"));
                        if (failure != null) throw failure;
                        Check(Field<string>(form, "historyStartupError") == null && Field<string>(form, "labelsError") == null, "history and country data open without errors"); checks++;
                        Snapshot snapshot = Field<Snapshot>(form, "snapshot"); TreeView tree = Field<TreeView>(form, "tree"); ListView list = Field<ListView>(form, "list");
                        Check(form.Visible && tree.Visible && tree.ShowLines && tree.ShowPlusMinus && snapshot.Certificates.Count > 0, "native Explorer window opens, tree branches show, and Windows certificates load"); checks++;
                        Check(list.Columns.Count == 12 && list.Columns.Cast<ColumnHeader>().Any(c => c.Text.StartsWith("SPKI SHA-256")), "all twelve requested certificate columns are present"); checks++;
                        Check(Field<ListView>(form, "countryList").Items.Count == 248, "all 248 loaded country/area rows are reachable"); checks++;
                        ComboBox group = Field<ComboBox>(form, "groupBy"), sort = Field<ComboBox>(form, "sortBy");
                        foreach (string mode in group.Items.Cast<string>().ToArray())
                        {
                            group.SelectedItem = mode; Application.DoEvents();
                            TreeNode root = tree.Nodes[0];
                            Check(root.Nodes.Cast<TreeNode>().Count(n => n.Tag is StoreLocation) == snapshot.Locations.Count, mode + " grouping preserves every Windows store-location branch"); checks++;
                            if (mode != "Applications")
                            {
                                TreeNode category = root.Nodes[0].Nodes.Cast<TreeNode>().FirstOrDefault(n => n.Tag is ExplorerScope);
                                Check(category != null && category.Nodes.Count == 3 && category.Nodes[0].Text.StartsWith("Enabled") && category.Nodes[1].Text.StartsWith("Blocked"), mode + " category keeps Enabled, Blocked and Unassigned children"); checks++;
                                tree.SelectedNode = category; Application.DoEvents();
                                Check(list.Items.Count == ((ExplorerScope)category.Tag).CertificateKeys.Count, mode + " selection lists exactly its certificate scope"); checks++;
                            }
                            foreach (string ordering in sort.Items.Cast<string>().ToArray()) { sort.SelectedItem = ordering; Application.DoEvents(); }
                        }
                        group.SelectedItem = "Issuer"; sort.SelectedItem = "Name";
                        CertificateRecord first = snapshot.Certificates.Values.First(); TextBox search = Field<TextBox>(form, "findIssuer"); search.Text = first.Sha256; Application.DoEvents();
                        ExplorerScope found = (ExplorerScope)tree.Nodes[0].Nodes[0].Tag;
                        Check(found.CertificateKeys.Count == 1 && found.CertificateKeys.Contains(first.Identity), "left search finds the selected complete SHA-256 without losing native paths"); checks++;
                        tree.SelectedNode = tree.Nodes[0].Nodes[0]; Application.DoEvents();
                        if (list.Items.Count > 0) { list.Items[0].Selected = true; list.Items[0].Focused = true; Application.DoEvents(); }
                        Check(Field<TextBox>(form, "details").Text.Contains(first.Sha256), "selecting a certificate populates its exact hash in the details pane"); checks++;
                        search.Text = ""; tree.SelectedNode = tree.Nodes[0]; Application.DoEvents();
                        form.ClientSize = new Size(660, 470); Application.DoEvents();
                        Check(tree.Width >= 150 && tree.Height >= 100 && tree.Visible, "minimum window size keeps the left tree usable"); checks++;
                        form.ClientSize = new Size(1150, 750); Application.DoEvents();
                        using (Bitmap picture = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(picture, new Rectangle(Point.Empty, form.Size)); picture.Save(Path.Combine(results, "gui-smoke.png"), ImageFormat.Png); }
                        if (failure != null) throw failure;
                        form.Close(); Application.DoEvents();
                        Check(Field<bool>(form, "collectorsClosed") && !Field<SyscallTrace>(form, "syscalls").Running, "closing the GUI shuts down its collectors"); checks++;
                    }
                    using (HistoryArchive reopened = new HistoryArchive(archive)) Check(reopened.LastError == null, "GUI history releases its writer lock and reopens after close"); checks++;
                }
                catch (Exception ex) { failure = ex; }
                finally { Application.ThreadException -= handler; try { Directory.Delete(archive, true); } catch (IOException) { } }
            });
            thread.SetApartmentState(ApartmentState.STA); thread.IsBackground = true; thread.Start();
            if (!thread.Join(240000)) { Console.WriteLine("FAIL GUI: STA smoke test timeout."); return 1; }
            if (failure != null) { Console.WriteLine(failure); return 1; }
            Console.WriteLine("GUI assertions passed: " + checks + ". Native Windows Forms were instantiated and operated on an STA thread."); return 0;
        }
    }
}
