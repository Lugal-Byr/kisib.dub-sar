using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace Kisib
{
    internal static class AboutText
    {
        internal const string Tagline = "GETTIN’ ROLLED SINCE -2199";
        internal const string Hover = "kisib.dub-sar — " + Tagline;   // tray tooltip, max 63 characters
        internal const string Owner = "S-CORP-i0N";
        internal const string Legal = "Copyright © 2026 S-CORP-ION";
        internal const string Repo = "https://github.com/Lugal-Byr/kisib.dub-sar";

        internal static string Version
        {
            get
            {
                try { string f = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "version.txt"); if (File.Exists(f)) return File.ReadAllText(f).Trim(); } catch (IOException) { }
                return "dev build";
            }
        }
    }

    internal sealed partial class ExplorerForm
    {
        private void ShowAbout()
        {
            using (Form dialog = new Form { Text = "About kisib.dub-sar", Size = new Size(620, 470), Font = Font, StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false })
            {
                PictureBox picture = new PictureBox { Dock = DockStyle.Left, Width = 170, SizeMode = PictureBoxSizeMode.CenterImage, Padding = new Padding(10) };
                try { if (AppIcon.Full != null) picture.Image = new Icon(AppIcon.Full, 128, 128).ToBitmap(); } catch (Exception) { }
                Label title = new Label { Dock = DockStyle.Top, Height = 34, Font = new Font("Tahoma", 15F, FontStyle.Bold), Text = "kisib.dub-sar  " + AboutText.Version };
                Label tagline = new Label { Dock = DockStyle.Top, Height = 28, Font = new Font("Tahoma", 11F), ForeColor = Color.SaddleBrown, Text = AboutText.Tagline };
                TextBox body = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = SystemColors.Control, ScrollBars = ScrollBars.Vertical,
                    Text = "by " + AboutText.Owner + "\r\n" + AboutText.Legal + "\r\n\r\n" +
                        "Free for personal, noncommercial use with credit (PolyForm Noncommercial License 1.0.0, see LICENSE). " +
                        "Commercial use needs a license from S-CORP-ION.\r\n\r\n" +
                        "kisib = seal, dub-sar = scribe (Sumerian).\r\nThe icon is an Akkadian cylinder seal (black serpentine, 2350–2200 BCE) rolling out its presentation scene: " +
                        "two worshippers before a seated king holding a globe.\r\n\r\n" +
                        "Windows certificate manager: explore every store, group by country, owner and your own tags, block through Disallowed, " +
                        "keep groups blocked, watch refusals live, allow for a few minutes, map cross-sign paths. " +
                        "Nothing is deleted from Root or CA; every change is logged and can be undone. Everything it remembers is plain .txt in " + Storage.FolderName + ".\r\n\r\n" +
                        AboutText.Repo };
                Panel right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4, 12, 12, 8) };
                right.Controls.Add(body); right.Controls.Add(tagline); right.Controls.Add(title);
                FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6) };
                Button close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
                Button site = new Button { Text = "Open GitHub page", AutoSize = true };
                site.Click += delegate { try { System.Diagnostics.Process.Start(AboutText.Repo); } catch (Exception) { CopyText(AboutText.Repo); } };
                Button license = new Button { Text = "License", AutoSize = true };
                license.Click += delegate
                {
                    string f = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LICENSE");
                    try { ShowText("License", File.Exists(f) ? File.ReadAllText(f) : AboutText.Legal + "\r\nPolyForm Noncommercial License 1.0.0\r\n" + AboutText.Repo + "/blob/main/LICENSE"); }
                    catch (IOException ex) { ShowText("License", ex.Message); }
                };
                buttons.Controls.AddRange(new Control[] { close, site, license });
                dialog.Controls.Add(right); dialog.Controls.Add(picture); dialog.Controls.Add(buttons);
                dialog.CancelButton = close;
                dialog.ShowDialog(this);
            }
        }
    }
}
