using System;
using System.Drawing;
using System.Windows.Forms;

namespace Kisib
{
    internal sealed partial class ExplorerForm
    {
        private ActivityMonitor activity;
        private SyscallTrace syscalls;
        private readonly TextBox findIssuer = new TextBox();
        private readonly Label liveStatus = new Label();
        private readonly System.Windows.Forms.Timer activityTimer = new System.Windows.Forms.Timer();
        private TabControl resultTabs;
        private TabControl evidenceTabs;
        private int activityTicks;

        private void InitializeControlLayer(SplitContainer outer, SplitContainer right, TabControl detailTabs, MainMenu menu)
        {
            // The existing syscall sink is dormant until the explicit optional switch is enabled.
            activity = new ActivityMonitor(history); syscalls = new SyscallTrace(history, activity.Publish);
            TableLayoutPanel find = new TableLayoutPanel { Dock = DockStyle.Top, Height = 61, ColumnCount = 2, RowCount = 2, Padding = new Padding(4) };
            find.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 45)); find.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Label title = new Label { Text = "Certificate explorer", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
            find.Controls.Add(title, 0, 0); find.SetColumnSpan(title, 2);
            find.Controls.Add(new Label { Text = "Find", AutoSize = true }, 0, 1);
            findIssuer.Dock = DockStyle.Fill; find.Controls.Add(findIssuer, 1, 1);
            findIssuer.AccessibleName = "Find certificates without changing store paths";
            outer.Panel1.Controls.Add(find);
            findIssuer.TextChanged += delegate { RefreshFindResults(); };

            right.Panel1.Controls.Remove(list);
            resultTabs = new TabControl { Dock = DockStyle.Fill };
            TabPage certificates = new TabPage("Certificates"); certificates.Controls.Add(list);
            resultTabs.TabPages.Add(certificates); right.Panel1.Controls.Add(resultTabs);
            evidenceTabs = detailTabs;
            liveStatus.Dock = DockStyle.Top; liveStatus.AutoSize = true; liveStatus.Padding = new Padding(4); liveStatus.Visible = false;
            right.Panel1.Controls.Add(liveStatus);
            activityTimer.Interval = 1000; activityTimer.Tick += delegate { ActivityTick(); };
            InitializeScreenOneOptions(viewMenu(menu));
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
        private void ToggleSyscalls()
        {
            if (!syscalls.Running && (!archiveToggle.Checked || history == null))
            { ShowText("Syscall capture", "Enable Journal and Archive in View > Optional features before starting an original ETL capture [to test]."); return; }
            try { if (syscalls.Running) syscalls.Stop(); else syscalls.Start(); }
            catch (Exception ex) { ShowText("Syscall capture", ex.Message + "\r\n\r\n" + syscalls.Status); if (history != null) history.Note(null, "syscall_capture_error", syscalls.Name, ex.ToString()); }
            syscallToggle.Checked = syscalls.Running;
            if (syscalls.Running) activityTimer.Start(); else activityTimer.Stop();
            liveStatus.Visible = syscalls.Running; UpdateLiveStatus();
        }
        private void ActivityTick()
        {
            if (closed || activity == null) return;
            // Original events remain in ETL. Drain the bounded display queue without building an application-use view.
            activity.Drain(); activityTicks++;
            if (activityTicks % 5 == 0 && syscalls.Running) syscalls.Query();
            UpdateLiveStatus();
        }
        private void UpdateLiveStatus()
        {
            if (syscalls == null) return;
            liveStatus.Text = syscalls.Status + " | " + syscalls.EventsReceived + " events | UI omitted: " + syscalls.DisplaySamplesSkipped +
                " | ETW lost: " + syscalls.EventsLost + "/" + syscalls.BuffersLost + " [to test]";
            if (history != null && history.LastError != null) liveStatus.Text += "\r\nHISTORY ERROR: " + history.LastError;
            if (syscalls.DecodeErrors > 0) liveStatus.Text += " | syscall decode gaps: " + syscalls.DecodeErrors;
        }
        private void RefreshFindResults()
        {
            if (snapshot != null && tree.SelectedNode != null)
                TreeSelected(tree, new TreeViewEventArgs(tree.SelectedNode));
        }
        private void CloseControlLayer()
        {
            activityTimer.Stop(); activityTimer.Dispose();
            if (activity != null) activity.Dispose();
            if (syscalls != null) syscalls.Dispose();
        }
    }
}
