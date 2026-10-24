using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // Right-click menus everywhere, so anything on screen can be copied as text and acted on.
    internal sealed partial class ExplorerForm
    {
        internal static void CopyText(string text)
        {
            if (String.IsNullOrEmpty(text)) return;
            try { Clipboard.SetText(text); } catch (System.Runtime.InteropServices.ExternalException) { }
        }

        // Any grid: copy one row, the selected rows, or everything (tab-separated, pastes cleanly into chat or a sheet).
        internal static void AddGridMenu(ListView grid)
        {
            ContextMenu menu = grid.ContextMenu ?? new ContextMenu();
            if (menu.MenuItems.Count > 0) menu.MenuItems.Add("-");
            menu.MenuItems.Add("Copy row", delegate { CopyText(String.Join("\r\n", grid.SelectedItems.Cast<ListViewItem>().Select(r => RowText(grid, r, true)).ToArray())); });
            menu.MenuItems.Add("Copy cell", delegate
            {
                System.Drawing.Point p = grid.PointToClient(Cursor.Position);
                ListViewHitTestInfo hit = grid.HitTest(p);
                if (hit.SubItem != null) CopyText(hit.SubItem.Text);
            });
            menu.MenuItems.Add("Copy all rows", delegate
            {
                StringBuilder text = new StringBuilder(String.Join("\t", grid.Columns.Cast<ColumnHeader>().Select(c => c.Text).ToArray())).Append("\r\n");
                foreach (ListViewItem r in grid.Items) text.Append(RowText(grid, r, false)).Append("\r\n");
                CopyText(text.ToString());
            });
            grid.ContextMenu = menu;
        }
        private static string RowText(ListView grid, ListViewItem row, bool labelled)
        {
            List<string> parts = new List<string>();
            for (int i = 0; i < row.SubItems.Count && i < grid.Columns.Count; i++)
                parts.Add(labelled ? grid.Columns[i].Text + ": " + row.SubItems[i].Text : row.SubItems[i].Text);
            return String.Join(labelled ? "\r\n" : "\t", parts.ToArray()) + (labelled ? "\r\n" : "");
        }

        // A plain-text card for one certificate: everything needed to talk about it without a screenshot.
        internal string CertificateCard(CertificateRecord c)
        {
            HashSet<string> blocked = snapshot == null ? new HashSet<string>() : GroupCatalog.BlockedIdentities(snapshot);
            StringBuilder t = new StringBuilder();
            t.AppendLine("Subject: " + c.Subject);
            t.AppendLine("Issuer: " + c.Issuer);
            t.AppendLine("Subject C=: " + (c.SubjectCountry ?? "—") + "   Issuer C=: " + (c.IssuerCountry ?? "—"));
            t.AppendLine("Valid: " + CertificateRecord.Time(c.NotBefore) + " → " + CertificateRecord.Time(c.NotAfter));
            t.AppendLine("Key: " + c.KeyAlgorithm + (c.KeySize.HasValue ? " " + c.KeySize.Value + " bits" : "") + "   Signature: " + c.SignatureAlgorithm);
            if (c.WeakReasons.Count > 0) t.AppendLine("Weak: " + String.Join("; ", c.WeakReasons.ToArray()));
            t.AppendLine("SHA-1: " + c.Sha1);
            t.AppendLine("SHA-256: " + c.Sha256);
            t.AppendLine("SPKI SHA-256: " + (c.SpkiSha256 ?? "—"));
            t.AppendLine("Found in: " + c.FoundInText);
            t.AppendLine("Blocked (in a Disallowed store): " + (blocked.Contains(c.Identity) ? "YES" : "no"));
            string tags = TagsOf(c);
            t.AppendLine("Tags: " + (tags.Length > 0 ? tags : "—"));
            if (groups != null)
            {
                string owners = String.Join(", ", groups.Owners.Where(g => g.Members.Contains(c.Identity)).Select(g => g.Label).ToArray());
                if (owners.Length > 0) t.AppendLine("Owner: " + owners);
            }
            return t.ToString();
        }

        private void InitializeContextMenus()
        {
            // Certificate list
            ContextMenu certMenu = new ContextMenu();
            Func<CertificateRecord> sel = SelectedCertificate;
            Action<string, Func<CertificateRecord, string>> copy = delegate(string label, Func<CertificateRecord, string> value)
            { certMenu.MenuItems.Add(label, delegate { CertificateRecord c = sel(); if (c != null) CopyText(value(c)); }); };
            copy("Copy certificate card (everything, for sharing)", CertificateCard);
            copy("Copy subject", c => c.Subject);
            copy("Copy issuer", c => c.Issuer);
            copy("Copy SHA-1", c => c.Sha1);
            copy("Copy SHA-256", c => c.Sha256);
            copy("Copy SPKI SHA-256", c => c.SpkiSha256);
            copy("Copy found in", c => c.FoundInText);
            copy("Copy as PEM", c => "-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(c.Der, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----\r\n");
            certMenu.MenuItems.Add("Copy all rows in this list", delegate
            {
                StringBuilder text = new StringBuilder(String.Join("\t", list.Columns.Cast<ColumnHeader>().Select(h => h.Text).ToArray())).Append("\r\n");
                foreach (ListViewItem r in list.Items) text.Append(String.Join("\t", r.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToArray())).Append("\r\n");
                CopyText(text.ToString());
            });
            certMenu.MenuItems.Add("-");
            certMenu.MenuItems.Add("Show chain", delegate { ShowChain(sel()); });
            certMenu.MenuItems.Add("Block this certificate...", delegate { BlockSelectedCertificate(); });
            foreach (int minutes in new int[] { 3, 10, 60 })
            {
                int m = minutes;
                certMenu.MenuItems.Add("Allow for " + m + " minutes", delegate
                { CertificateRecord c = sel(); if (c != null) AllowTemporarily(new List<CertificateRecord> { c }, c.SubjectShortName, TimeSpan.FromMinutes(m), true); });
            }
            certMenu.MenuItems.Add("Unblock (kisib's own blocks)", delegate { UnblockSelectedCertificate(); });
            certMenu.MenuItems.Add("-");
            certMenu.MenuItems.Add("Tag this certificate...", delegate
            {
                CertificateRecord c = sel(); if (c == null) return;
                string tag = Prompt("Tag this certificate", "Tag for " + c.SubjectShortName + ":", "");
                if (tag != null) { MyTags.Add("certificate", c.Sha256, tag); StartScan(); }
            });
            certMenu.MenuItems.Add("Find others from this organization", delegate
            {
                CertificateRecord c = sel(); if (c == null) return;
                string org = c.SubjectOrganization ?? c.SubjectShortName; int slash = org.IndexOf('/'); if (slash > 0) org = org.Substring(0, slash);
                findIssuer.Text = org.Trim();
            });
            certMenu.Popup += delegate { bool any = sel() != null; foreach (MenuItem item in certMenu.MenuItems) if (item.Text != "-" && !item.Text.StartsWith("Copy all", StringComparison.Ordinal)) item.Enabled = any; };
            list.ContextMenu = certMenu;

            // Tree: right-click selects the node first, then offers copy and block.
            tree.NodeMouseClick += delegate(object sender, TreeNodeMouseClickEventArgs e) { if (e.Button == MouseButtons.Right) tree.SelectedNode = e.Node; };
            ContextMenu treeMenu = new ContextMenu();
            treeMenu.MenuItems.Add("Copy name", delegate { if (tree.SelectedNode != null) CopyText(tree.SelectedNode.Text); });
            treeMenu.MenuItems.Add("Copy path", delegate { CopyText(address.Text); });
            treeMenu.MenuItems.Add("Copy details (summary and member list)", delegate { CopyText(nodeDetails); });
            treeMenu.MenuItems.Add("Copy certificate list", delegate
            {
                StringBuilder text = new StringBuilder(address.Text).Append("\r\n");
                foreach (ListViewItem r in list.Items) text.Append(String.Join("\t", r.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToArray())).Append("\r\n");
                CopyText(text.ToString());
            });
            MenuItem blockGroupItem = new MenuItem("Block this group...", delegate { BlockSelectedGroup(); });
            treeMenu.MenuItems.Add("-");
            treeMenu.MenuItems.Add(blockGroupItem);
            treeMenu.MenuItems.Add("Expand all below", delegate { if (tree.SelectedNode != null) tree.SelectedNode.ExpandAll(); });
            treeMenu.MenuItems.Add("Collapse", delegate { if (tree.SelectedNode != null) tree.SelectedNode.Collapse(); });
            treeMenu.Popup += delegate { blockGroupItem.Enabled = tree.SelectedNode != null && tree.SelectedNode.Tag is GroupNode; };
            tree.ContextMenu = treeMenu;

            // Details panes and status bar
            foreach (TextBox box in new TextBox[] { details, issuerDetails })
            {
                TextBox b = box;
                ContextMenu m = new ContextMenu();
                m.MenuItems.Add("Copy selection", delegate { CopyText(b.SelectedText); });
                m.MenuItems.Add("Copy all", delegate { CopyText(b.Text); });
                m.MenuItems.Add("Select all", delegate { b.SelectAll(); });
                b.ContextMenu = m;
            }
            ContextMenu statusMenu = new ContextMenu();
            statusMenu.MenuItems.Add("Copy status", delegate { CopyText(status.Text); });
            statusMenu.MenuItems.Add("Open certificate denials", delegate { ShowDenials(); });
            status.ContextMenu = statusMenu;
        }
    }
}
