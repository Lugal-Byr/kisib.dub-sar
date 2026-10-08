using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    internal sealed class IncidentForm : Form
    {
        internal readonly TextBox HostInput = new TextBox { Width = 230, MaxLength = 253 };
        internal readonly TextBox HashInput = new TextBox { Width = 410, MaxLength = 192 };
        internal readonly TextBox Evidence = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill };
        internal readonly TreeView Incidents = new TreeView { Dock = DockStyle.Fill, ShowLines = true, ShowRootLines = true, ShowPlusMinus = true, HideSelection = false };
        internal readonly ListView Chain = new ListView { Dock = DockStyle.Fill, View = System.Windows.Forms.View.Details, FullRowSelect = true, GridLines = true };
        internal readonly Button InspectButton = new Button { Text = "Inspect TLS", AutoSize = true };
        internal readonly Button CancelCheck = new Button { Text = "Cancel check", AutoSize = true, Enabled = false };
        internal readonly Label State = new Label { Dock = DockStyle.Bottom, Height = 42, Padding = new Padding(5) };
        internal IncidentCatalog Catalog;
        internal TlsObservation LastObservation;
        private readonly IEnumerable<CertificateRecord> inventory;
        private readonly Func<TlsObservation, string> retain;
        private CancellationTokenSource cancellation;
        private bool closeWhenFinished;

        internal IncidentForm(string project, IEnumerable<CertificateRecord> inventory, CertificateRecord selected, Func<TlsObservation, string> retain)
        {
            this.inventory = (inventory ?? new CertificateRecord[0]).ToArray(); this.retain = retain;
            Text = "TLS and incident evidence [to test]"; Font = new Font("Tahoma", 9F); BackColor = SystemColors.Control;
            ClientSize = new Size(1080, 650); MinimumSize = new Size(720, 440); StartPosition = FormStartPosition.CenterParent;
            FlowLayoutPanel checks = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4), WrapContents = false };
            checks.Controls.AddRange(new Control[] { new Label { Text = "Host :443", AutoSize = true, Padding = new Padding(0, 5, 0, 0) }, HostInput, InspectButton, CancelCheck });
            FlowLayoutPanel lookup = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4), WrapContents = false };
            Button find = new Button { Text = "Find hash", AutoSize = true };
            lookup.Controls.AddRange(new Control[] { new Label { Text = "Certificate SHA-256", AutoSize = true, Padding = new Padding(0, 5, 0, 0) }, HashInput, find });
            SplitContainer split = new SplitContainer { Dock = DockStyle.Fill, Size = new Size(1080, 540), SplitterDistance = 260, Panel1MinSize = 180, Panel2MinSize = 360, BorderStyle = BorderStyle.Fixed3D };
            split.Panel1.Controls.Add(Incidents);
            TabControl tabs = new TabControl { Dock = DockStyle.Fill }; TabPage details = new TabPage("Details"), chain = new TabPage("Chain");
            details.Controls.Add(Evidence); chain.Controls.Add(Chain); tabs.TabPages.AddRange(new TabPage[] { details, chain }); split.Panel2.Controls.Add(tabs);
            foreach (string header in new string[] { "Subject CN", "Issuer CN", "SHA-256", "ChainElementStatus" }) Chain.Columns.Add(header, header == "SHA-256" ? 440 : header == "ChainElementStatus" ? 440 : 210);
            FlowLayoutPanel bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 36, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
            Button close = new Button { Text = "Close", AutoSize = true }, copy = new Button { Text = "Copy details", AutoSize = true };
            bottom.Controls.AddRange(new Control[] { close, copy }); close.Click += delegate { Close(); }; copy.Click += delegate { if (Evidence.Text.Length > 0) Clipboard.SetText(Evidence.Text); };
            Controls.Add(split); Controls.Add(lookup); Controls.Add(checks); Controls.Add(State); Controls.Add(bottom);
            State.Text = "Session evidence only unless Journal is on. Inspect TLS contacts the host and may contact Windows chain/revocation services. [to test]";
            InspectButton.Click += delegate { StartInspection(); }; CancelCheck.Click += delegate { if (cancellation != null) cancellation.Cancel(); };
            find.Click += delegate { ShowHash(); };
            Incidents.AfterSelect += delegate(object sender, TreeViewEventArgs args)
            { CertificateIncident incident = args.Node.Tag as CertificateIncident; if (incident != null && Catalog != null) Evidence.Text = Catalog.Describe(incident); };
            FormClosing += delegate(object sender, FormClosingEventArgs args)
            { if (cancellation != null) { args.Cancel = true; closeWhenFinished = true; cancellation.Cancel(); State.Text = "Canceling the TLS check before closing..."; } };
            try
            {
                Catalog = IncidentCatalog.Read(project); TreeNode root = Incidents.Nodes.Add("Incident records (" + Catalog.Incidents.Length + ")");
                foreach (CertificateIncident incident in Catalog.Incidents)
                {
                    TreeNode item = root.Nodes.Add(incident.Title); item.Tag = incident;
                    foreach (IncidentNamespace space in incident.Namespaces) { TreeNode child = item.Nodes.Add("." + space.Suffix + " — " + space.RegistryName); child.Tag = incident; }
                }
                root.Expand(); if (root.Nodes.Count > 0) Incidents.SelectedNode = root.Nodes[0];
                if (selected != null) { HashInput.Text = selected.Sha256; ShowHash(); }
            }
            catch (Exception ex) { find.Enabled = false; Evidence.Text = "Incident catalog unavailable; matches unknown [to test].\r\n" + ex.GetType().Name + ": " + ex.Message; }
        }
        internal void ShowHash()
        {
            try { Evidence.Text = Catalog == null ? "Incident catalog unavailable; matches unknown [to test]." : Catalog.HashReport(HashInput.Text, inventory); }
            catch (ArgumentException ex) { Evidence.Text = ex.Message; }
        }
        internal void ShowObservation(TlsObservation observation)
        {
            LastObservation = observation; observation.CatalogSha256 = Catalog == null ? null : Catalog.Sha256;
            Evidence.Text = observation.Report(Catalog, inventory); Chain.Items.Clear();
            foreach (TlsChainEvidence element in observation.Chain ?? new TlsChainEvidence[0])
            {
                CertificateRecord certificate = CertificateRecord.FromDer(element.CertificateDer);
                Chain.Items.Add(new ListViewItem(new string[] { certificate.SubjectShortName, certificate.IssuerShortName, certificate.Sha256, element.Status }) { Tag = certificate });
            }
        }
        private void StartInspection()
        {
            if (cancellation != null) return; string host;
            try { host = TlsInspection.NormalizeHost(HostInput.Text); } catch (ArgumentException ex) { Evidence.Text = ex.Message; return; }
            cancellation = new CancellationTokenSource(); CancellationToken token = cancellation.Token;
            InspectButton.Enabled = false; HostInput.Enabled = false; CancelCheck.Enabled = true;
            State.Text = "Checking " + host + ":443. Windows validates the certificate; certificate errors are rejected. [to test]";
            ThreadPool.QueueUserWorkItem(delegate
            {
                TlsObservation observation = null; Exception failure = null;
                try { observation = TlsInspection.Run(host, token); } catch (Exception ex) { failure = ex; }
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        try
                        {
                            if (failure != null) Evidence.Text = "Check failed; certificate and enforcement unknown [to test].\r\n" + failure.Message;
                            else { ShowObservation(observation); State.Text = retain == null ? "Session evidence only; Journal is off. [to test]" : retain(observation); }
                        }
                        finally
                        {
                            cancellation.Dispose(); cancellation = null; InspectButton.Enabled = true; HostInput.Enabled = true; CancelCheck.Enabled = false;
                            if (closeWhenFinished) Close();
                        }
                    }));
                }
                catch (InvalidOperationException) { }
            });
        }
    }
}
