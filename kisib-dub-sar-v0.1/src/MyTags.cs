using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // Your own tags, kept next to the block history so app updates never overwrite them.
    // kind: country (ISO code on subject or issuer C=), organization (text inside subject or issuer O=), certificate (SHA-256).
    internal sealed class MyTag
    {
        internal string Kind, Value, Tag;
    }

    internal sealed class MyTagHit
    {
        internal string Identity, Tag, Why;
    }

    internal static class MyTags
    {
        internal static string PathName { get { return Path.Combine(Path.GetDirectoryName(BlockEngine.LogPath), "my-tags.csv"); } }
        internal static readonly string[] Kinds = { "country", "organization", "certificate" };
        // EU member states (27) plus C=EU, which some certificates use.
        internal static readonly string[] EuMembers = { "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
            "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "EU" };

        internal static List<MyTag> Read()
        {
            List<MyTag> tags = new List<MyTag>();
            if (!File.Exists(PathName)) return tags;
            foreach (string[] f in GroupCatalog.ReadCsv(PathName).Skip(1))
                if (f.Length >= 3 && Kinds.Contains(f[0]) && f[1].Trim().Length > 0 && f[2].Trim().Length > 0)
                    tags.Add(new MyTag { Kind = f[0], Value = f[1].Trim(), Tag = f[2].Trim() });
            return tags;
        }

        internal static void Save(IEnumerable<MyTag> tags)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PathName));
            StringBuilder text = new StringBuilder("kind,value,tag\r\n");
            foreach (MyTag t in tags) text.Append(t.Kind).Append(',').Append(Q(t.Value)).Append(',').Append(Q(t.Tag)).Append("\r\n");
            File.WriteAllText(PathName, text.ToString(), new UTF8Encoding(false));
        }
        private static string Q(string v) { return v.IndexOfAny(new char[] { ',', '"' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        internal static void Add(string kind, string value, string tag)
        {
            List<MyTag> tags = Read();
            if (!tags.Any(t => t.Kind == kind && String.Equals(t.Value, value, StringComparison.OrdinalIgnoreCase) && t.Tag == tag))
                tags.Add(new MyTag { Kind = kind, Value = value, Tag = tag });
            Save(tags);
        }

        internal static List<MyTagHit> Matches(Snapshot snapshot)
        {
            List<MyTagHit> hits = new List<MyTagHit>();
            List<MyTag> tags;
            try { tags = Read(); } catch (Exception) { return hits; }
            if (tags.Count == 0) return hits;
            foreach (CertificateRecord c in snapshot.Certificates.Values)
                foreach (MyTag t in tags)
                {
                    string why = null;
                    if (t.Kind == "country")
                    {
                        if (String.Equals(c.SubjectCountry, t.Value, StringComparison.OrdinalIgnoreCase)) why = "my tag: subject C=" + t.Value;
                        else if (String.Equals(c.IssuerCountry, t.Value, StringComparison.OrdinalIgnoreCase)) why = "my tag: issuer C=" + t.Value;
                    }
                    else if (t.Kind == "organization")
                    {
                        if (c.SubjectOrganization != null && c.SubjectOrganization.IndexOf(t.Value, StringComparison.OrdinalIgnoreCase) >= 0) why = "my tag: subject O= contains " + t.Value;
                        else if (c.IssuerOrganization != null && c.IssuerOrganization.IndexOf(t.Value, StringComparison.OrdinalIgnoreCase) >= 0) why = "my tag: issuer O= contains " + t.Value;
                    }
                    else if (t.Kind == "certificate" && String.Equals(c.Sha256, t.Value, StringComparison.OrdinalIgnoreCase)) why = "my tag: this certificate";
                    if (why != null) hits.Add(new MyTagHit { Identity = c.Identity, Tag = t.Tag, Why = why });
                }
            return hits;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private void InitializeMyTags(MenuItem certificate, MenuItem view)
        {
            view.MenuItems.Add(new MenuItem("Edit my &tags...", delegate { ShowMyTags(); }));
            certificate.MenuItems.Add(new MenuItem("-"));
            certificate.MenuItems.Add(new MenuItem("&Tag this certificate...", delegate
            {
                CertificateRecord c = SelectedCertificate();
                if (c == null) { ShowText("Tag", "Select a certificate in the list first."); return; }
                string tag = Prompt("Tag this certificate", "Tag for " + c.SubjectShortName + ":", "");
                if (tag != null) { MyTags.Add("certificate", c.Sha256, tag); StartScan(); }
            }));
            certificate.MenuItems.Add(new MenuItem("Tag this &organization...", delegate
            {
                CertificateRecord c = SelectedCertificate();
                if (c == null) { ShowText("Tag", "Select a certificate in the list first."); return; }
                string org = c.SubjectOrganization ?? c.IssuerOrganization ?? "";
                int slash = org.IndexOf('/'); if (slash > 0) org = org.Substring(0, slash);
                org = Prompt("Tag an organization", "Organization name (matches anywhere in subject or issuer O=):", org.Trim());
                if (String.IsNullOrEmpty(org)) return;
                string tag = Prompt("Tag an organization", "Tag for every certificate from \"" + org + "\":", "");
                if (tag != null) { MyTags.Add("organization", org, tag); StartScan(); }
            }));
        }

        private string Prompt(string title, string question, string value)
        {
            using (Form dialog = new Form { Text = title, Size = new Size(520, 150), Font = Font, StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MinimizeBox = false, MaximizeBox = false })
            {
                Label label = new Label { Text = question, Dock = DockStyle.Top, Height = 28, Padding = new Padding(6, 8, 6, 0) };
                TextBox box = new TextBox { Text = value, Dock = DockStyle.Top };
                Button ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom, Height = 30 };
                dialog.Controls.Add(ok); dialog.Controls.Add(box); dialog.Controls.Add(label);
                dialog.AcceptButton = ok;
                return dialog.ShowDialog(this) == DialogResult.OK && box.Text.Trim().Length > 0 ? box.Text.Trim() : null;
            }
        }

        private void ShowMyTags()
        {
            List<MyTag> tags;
            try { tags = MyTags.Read(); } catch (Exception ex) { ShowText("My tags", ex.Message); return; }
            using (Form dialog = new Form { Text = "My tags — " + MyTags.PathName, Size = new Size(820, 520), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Kind", "Value", "Tag" }, new int[] { 120, 360, 280 });
                Action fill = delegate
                {
                    grid.Items.Clear();
                    foreach (MyTag t in tags) grid.Items.Add(new ListViewItem(new string[] { t.Kind, t.Value, t.Tag }) { Tag = t });
                };
                fill();
                FlowLayoutPanel add = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(2) };
                ComboBox kind = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
                kind.Items.AddRange(MyTags.Kinds); kind.SelectedIndex = 0;
                TextBox value = new TextBox { Width = 260 }, tag = new TextBox { Width = 160 };
                Button addButton = new Button { Text = "Add", AutoSize = true };
                addButton.Click += delegate
                {
                    if (value.Text.Trim().Length == 0 || tag.Text.Trim().Length == 0) return;
                    tags.Add(new MyTag { Kind = (string)kind.SelectedItem, Value = value.Text.Trim(), Tag = tag.Text.Trim() }); fill();
                    value.Text = "";
                };
                add.Controls.AddRange(new Control[] { new Label { Text = "Kind", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, kind,
                    new Label { Text = "Value", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, value,
                    new Label { Text = "Tag", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, tag, addButton });
                FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(2) };
                Button remove = new Button { Text = "Remove selected", AutoSize = true };
                remove.Click += delegate { foreach (ListViewItem item in grid.SelectedItems) tags.Remove((MyTag)item.Tag); fill(); };
                Button eu = new Button { Text = "Add EU (27 member states + C=EU)", AutoSize = true };
                eu.Click += delegate
                {
                    foreach (string code in MyTags.EuMembers)
                        if (!tags.Any(t => t.Kind == "country" && t.Value == code && t.Tag == "EU")) tags.Add(new MyTag { Kind = "country", Value = code, Tag = "EU" });
                    fill();
                };
                Button save = new Button { Text = "Save and regroup", AutoSize = true };
                save.Click += delegate
                {
                    try { MyTags.Save(tags); } catch (Exception ex) { ShowText("My tags", ex.Message); return; }
                    dialog.Close(); StartScan();
                };
                actions.Controls.AddRange(new Control[] { remove, eu, save });
                Label note = new Label { Dock = DockStyle.Bottom, Height = 44, Text = "country = 2-letter code on the certificate's subject or issuer C=.  organization = text found in subject or issuer O=.\r\n" +
                    "certificate = SHA-256.  Tags show under Groups > Tags and can be blocked and kept blocked like any group." };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(add); dialog.Controls.Add(actions);
                dialog.ShowDialog(this);
            }
        }
    }
}
