using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Kisib
{
    // A documentation reference is never a PhysicalStore or an observed store.
    internal sealed class DocumentedStoreReference
    {
        internal string Path, Description;
    }

    internal sealed partial class ExplorerForm
    {
        private readonly MenuItem journalToggle = new MenuItem("Journal [to test]");
        private readonly MenuItem archiveToggle = new MenuItem("Archive public certificates [to test]");
        private readonly MenuItem autoScanToggle = new MenuItem("60-second automatic scan [to test]");
        private readonly MenuItem syscallToggle = new MenuItem("Syscall capture [to test]");

        private static MenuItem viewMenu(MainMenu menu)
        { return menu.MenuItems.Cast<MenuItem>().First(item => item.Text == "&View"); }

        private void InitializeScreenOneOptions(MenuItem view)
        {
            MenuItem options = new MenuItem("Optional &features");
            options.MenuItems.AddRange(new MenuItem[] { journalToggle, archiveToggle, autoScanToggle, syscallToggle });
            view.MenuItems.Add(options);
            archiveToggle.Enabled = false; syscallToggle.Enabled = false;
            journalToggle.Click += delegate { ChangeRecording(false); };
            archiveToggle.Click += delegate { ChangeRecording(true); };
            autoScanToggle.Click += delegate
            { autoScanToggle.Checked = !autoScanToggle.Checked; if (autoScanToggle.Checked) historyTimer.Start(); else historyTimer.Stop(); };
            syscallToggle.Click += delegate { ToggleSyscalls(); };
        }

        private void ChangeRecording(bool archiveOption)
        {
            // Store readers/collectors retain their configured writer for the whole operation.
            if (scanning || activityTimer.Enabled || syscalls.Running)
            { ShowText("Recording options", "Finish the scan and stop syscall capture before changing recording options [to test]."); return; }
            bool enableJournal = archiveOption ? journalToggle.Checked : !journalToggle.Checked;
            bool enableArchive = enableJournal && (archiveOption ? !archiveToggle.Checked : archiveToggle.Checked);
            activity.Dispose(); syscalls.Dispose();
            if (history != null) { history.Dispose(); history = null; }
            historyStartupError = null;
            if (enableJournal)
            {
                try { history = new HistoryArchive(archiveDirectory, enableArchive); }
                catch (Exception ex) { historyStartupError = ex.GetType().Name + ": " + ex.Message; enableJournal = false; enableArchive = false; }
            }
            journalToggle.Checked = enableJournal; archiveToggle.Checked = enableArchive;
            archiveToggle.Enabled = enableJournal; syscallToggle.Enabled = enableArchive;
            activity = new ActivityMonitor(history); syscalls = new SyscallTrace(history, activity.Publish);
            status.Text = HistoryStatus(); UpdateLiveStatus();
            if (historyStartupError != null) ShowText("Journal could not open", historyStartupError);
        }

        private bool MatchesFind(CertificateRecord certificate)
        {
            string query = findIssuer.Text.Trim();
            return query.Length == 0 || new string[] { certificate.Subject, certificate.Issuer, certificate.SubjectShortName,
                certificate.IssuerShortName, certificate.SubjectCountry, certificate.IssuerCountry,
                certificate.FoundInText, certificate.Sha1, certificate.Sha256 }.Any(value =>
                    value != null && value.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        // Microsoft's table is a reference checklist. Windows enumeration remains authoritative.
        internal static string[] DocumentedSiblings(uint location, string name)
        {
            string system = name.Substring(name.LastIndexOf('\\') + 1).ToUpperInvariant();
            if (location == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE)
            {
                if (system == "MY") return new string[] { ".Default" };
                if (system == "ROOT") return new string[] { ".Default", ".AuthRoot", ".GroupPolicy", ".Enterprise", ".SmartCard" };
                if (system == "CA" || system == "TRUST") return new string[] { ".Default", ".GroupPolicy", ".Enterprise" };
            }
            if (location == Native.CERT_SYSTEM_STORE_CURRENT_USER)
            {
                if (system == "MY") return new string[] { ".Default" };
                if (system == "ROOT") return new string[] { ".Default", ".LocalMachine", ".SmartCard" };
                if (system == "CA" || system == "TRUST") return new string[] { ".Default", ".GroupPolicy", ".LocalMachine" };
                if (system == "USERDS") return new string[] { ".UserCertificate" };
            }
            if (location == Native.CERT_SYSTEM_STORE_CURRENT_SERVICE || location == Native.CERT_SYSTEM_STORE_SERVICES || location == Native.CERT_SYSTEM_STORE_USERS)
            {
                if (system == "MY" && location != Native.CERT_SYSTEM_STORE_USERS) return new string[] { ".Default" };
                if (system == "MY" || system == "ROOT" || system == "CA" || system == "TRUST") return new string[] { ".Default", ".LocalMachine" };
            }
            if (location == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE && (system == "MY" || system == "ROOT" || system == "CA" || system == "TRUST"))
                return new string[] { ".Default" };
            return new string[0];
        }

        private TreeNode ReferenceNode(string name, string path, bool complete)
        {
            string state = complete ? "not present" : "not checked; enumeration incomplete";
            return new TreeNode(name + " — " + state) { ForeColor = SystemColors.GrayText,
                Tag = new DocumentedStoreReference { Path = path, Description = "Documentation reference only [documented].\r\n" + path +
                    "\r\nMachine observation: " + state + " [to test].\r\nThis reference is not an observed store and contributes no certificate count.\r\n" +
                    Source("System Store Locations / predefined physical stores", Sources.Locations) },
                ToolTipText = "Documentation reference only; " + state + " [to test].\r\n" + Sources.Locations };
        }

        private void AddDocumentedPhysicalReferences(StoreLocation location, SystemStore store, TreeNode node)
        {
            foreach (string name in DocumentedSiblings(location.Flags, store.Name))
                if (!store.PhysicalStores.Any(p => String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
                    node.Nodes.Add(ReferenceNode(name, store.Path + "\\" + name, store.PhysicalEnumerationError == null && !snapshot.Canceled));
        }

        private void AddDocumentedSystemReferences(StoreLocation location, TreeNode node)
        {
            string[] names = location.Flags == Native.CERT_SYSTEM_STORE_CURRENT_USER ? new string[] { "MY", "Root", "CA", "Trust", "UserDS" } :
                location.Flags == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE || location.Flags == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE ?
                new string[] { "MY", "Root", "CA", "Trust" } : new string[0];
            foreach (string name in names)
                if (!location.Stores.Any(p => String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
                    node.Nodes.Add(ReferenceNode(name, location.Name + "\\" + name, location.Error == null && !snapshot.Canceled));
        }

        internal Form CreateStoreErrorsDialog()
        {
            Form dialog = new Form { Text = "Store errors [to test]", Size = new Size(1000, 480), Font = Font, StartPosition = FormStartPosition.CenterParent };
            ListView grid = new ListView(); SetupGrid(grid, new string[] { "Store", "Error" }, new int[] { 420, 540 });
            if (snapshot != null) foreach (StoreError error in snapshot.StoreErrors) grid.Items.Add(new ListViewItem(new string[] { error.Store, error.Error }));
            Label source = new Label { Dock = DockStyle.Bottom, Height = 40,
                Text = "Microsoft term: GetLastError / Win32Exception [documented]; observed errors [to test].\r\nhttps://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror" };
            Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, DialogResult = DialogResult.Cancel, Height = 30 };
            dialog.Controls.Add(grid); dialog.Controls.Add(source); dialog.Controls.Add(close); dialog.CancelButton = close;
            return dialog;
        }

        private void ShowStoreErrors()
        { using (Form dialog = CreateStoreErrorsDialog()) dialog.ShowDialog(this); }

    }
}
