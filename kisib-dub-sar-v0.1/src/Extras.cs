using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // A small card for a refusal: an emoji, who -> what in one line, why in a short grey line, and little chips.
    // Click the card for the refusal card; × closes it. Shows without stealing focus.
    internal sealed class DenialToast : Form
    {
        [System.Runtime.InteropServices.DllImport("gdi32.dll")] private static extern IntPtr CreateRoundRectRgn(int left, int top, int right, int bottom, int width, int height);
        [System.Runtime.InteropServices.DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr handle);
        // Comic Sans MS, bold, a couple of points up (user, 2026-10-26). Windows ships Comic Sans; if it is missing, GDI falls back.
        private static readonly Font TitleFont = new Font("Comic Sans MS", 11.5F, FontStyle.Bold), SmallFont = new Font("Comic Sans MS", 10F, FontStyle.Bold), IconFont = new Font("Segoe UI Emoji", 17F);
        private readonly string icon, line1, line2;
        private readonly Color stripe;

        protected override bool ShowWithoutActivation { get { return true; } }
        protected override CreateParams CreateParams
        {
            get { CreateParams p = base.CreateParams; p.ExStyle |= 0x80; p.ClassStyle |= 0x20000; return p; }   // tool window (no taskbar), soft shadow
        }

        internal DenialToast(string icon, string line1, string line2, Color tint, Color stripe, Button allow, Action details, Action fix, Action quiet)
        {
            this.icon = icon; this.line1 = line1; this.line2 = line2; this.stripe = stripe;
            FormBorderStyle = FormBorderStyle.None; TopMost = true; ShowInTaskbar = false; StartPosition = FormStartPosition.Manual;
            Size = new Size(400, 108); BackColor = tint; Font = SmallFont; DoubleBuffered = true; Cursor = Cursors.Hand;
            IntPtr round = CreateRoundRectRgn(0, 0, Width + 1, Height + 1, 14, 14);
            Region = Region.FromHrgn(round); DeleteObject(round);
            Color chip = Blend(tint, stripe, 0.16), ink = Blend(stripe, Color.Black, 0.35);
            FlowLayoutPanel chips = new FlowLayoutPanel { Location = new Point(52, Height - 36), Size = new Size(Width - 60, 30), BackColor = tint, WrapContents = false, Padding = new Padding(0), Margin = new Padding(0) };
            if (allow != null) chips.Controls.Add(Chip(allow, chip, ink));
            chips.Controls.Add(Chip(new Button { Text = "Fix it" }, chip, ink, delegate { fix(); Close(); }));
            chips.Controls.Add(Chip(new Button { Text = "Details" }, chip, ink, delegate { details(); }));
            chips.Controls.Add(Chip(new Button { Text = "Shh 1 h" }, chip, ink, delegate { quiet(); Close(); }));
            Label close = new Label { Text = "×", Location = new Point(Width - 26, 3), Size = new Size(22, 22), TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.Gray, BackColor = tint, Font = new Font("Comic Sans MS", 11F, FontStyle.Bold), Cursor = Cursors.Hand };
            close.Click += delegate { Close(); };
            Controls.Add(chips); Controls.Add(close);
            Click += delegate { details(); };
        }

        private static Button Chip(Button b, Color back, Color ink) { return Chip(b, back, ink, null); }
        private static Button Chip(Button b, Color back, Color ink, Action click)
        {
            b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0; b.FlatAppearance.MouseOverBackColor = Blend(back, ink, 0.12);
            b.BackColor = back; b.ForeColor = ink; b.Font = SmallFont; b.AutoSize = true; b.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            b.Padding = new Padding(6, 0, 6, 0); b.Margin = new Padding(0, 0, 6, 0); b.Height = 28; b.Cursor = Cursors.Hand;
            if (click != null) b.Click += delegate { click(); };
            return b;
        }

        internal static Color Blend(Color a, Color b, double amount)
        {
            return Color.FromArgb((int)(a.R + (b.R - a.R) * amount), (int)(a.G + (b.G - a.G) * amount), (int)(a.B + (b.B - a.B) * amount));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Graphics g = e.Graphics;
            using (Brush b = new SolidBrush(stripe)) g.FillRectangle(b, 0, 0, 5, Height);
            try { EmojiText.Draw(g, icon, IconFont, new Rectangle(12, 10, 36, 34), Color.Black); } catch (Exception) { }
            TextRenderer.DrawText(g, line1, TitleFont, new Rectangle(52, 8, Width - 82, 26), Color.FromArgb(35, 35, 40),
                TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
            TextRenderer.DrawText(g, line2, SmallFont, new Rectangle(52, 36, Width - 62, 22), Color.FromArgb(105, 105, 115),
                TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }

    internal sealed partial class ExplorerForm
    {
        internal bool StartInTray;
        private readonly List<DenialToast> toasts = new List<DenialToast>();
        private string AppFolder { get { return Storage.Folder; } }
        private string DenialLogPath { get { return Storage.File(Storage.Denials); } }
        private string TrayFlag { get { return Storage.File("SETTING - minimize to tray.txt"); } }
        private const string TaskName = "kisib.dub-sar";

        private void InitializeExtras(MenuItem file, MenuItem view)
        {
            MenuItem startup = new MenuItem("Start with &Windows (in tray)");
            MenuItem quiet = new MenuItem("&Quiet mode (log refusals, no pop-ups)");
            file.MenuItems.Add(2, startup);
            file.MenuItems.Add(3, quiet);
            file.MenuItems.Add(4, new MenuItem("-"));
            file.Popup += delegate { startup.Checked = StartupTaskExists(); quiet.Checked = QuietMode; };
            startup.Click += delegate { ToggleStartup(!StartupTaskExists()); };
            quiet.Click += delegate { ToggleQuiet(); };
            // No taskbar button ever: minimizing or closing the window puts kisib back in the tray.
            Resize += delegate { if (WindowState == FormWindowState.Minimized) { WindowState = FormWindowState.Normal; HideToTray(); } };
            Shown += delegate { if (StartInTray) Hide(); };
            LoadDenials();
        }

        internal void InitializeTrayMenu()
        {
            ContextMenu menu = new ContextMenu();
            menu.MenuItems.Add("Open kisib", delegate { RestoreFromTray(); });
            menu.MenuItems.Add("Certificate denials", delegate { ShowDenials(); });
            menu.MenuItems.Add("Block by bloc and continent...", delegate { RestoreFromTray(); OpenBlocBoard(); });
            menu.MenuItems.Add("Live certificate map", delegate { RestoreFromTray(); OpenLiveMap(); });
            MenuItem openNow = new MenuItem("Open right now (allowed for a while)");
            openNow.MenuItems.Add("(building)");
            openNow.Popup += delegate { FillOpenNow(openNow); };
            menu.MenuItems.Add(openNow);
            menu.MenuItems.Add("Tools...", delegate { RestoreFromTray(); ShowToolsPage(); });
            menu.MenuItems.Add("-");
            menu.MenuItems.Add("Fix Claude's connection", delegate { KeepReachable(true); });
            menu.MenuItems.Add("Copy the line that lets Claude run kisib", delegate { CopyClaudeLine(); });
            menu.MenuItems.Add("-");
            MenuItem quiet = new MenuItem("Quiet mode (no pop-ups)", delegate { ToggleQuiet(); });
            menu.MenuItems.Add(quiet);
            menu.Popup += delegate { quiet.Checked = QuietMode; };
            menu.MenuItems.Add("-");
            menu.MenuItems.Add("Exit kisib", delegate { ExitApp(); });
            tray.ContextMenu = menu;
        }

        private void RestoreFromTray() { Show(); WindowState = FormWindowState.Normal; Activate(); BringToFront(); }

        // Pop-ups stack in the corner (newest at the bottom, four at most) and stay until answered.
        private void ShowDenialToast(Denial d)
        {
            string who = FriendlyProgram(d), what = Shorten(d.Site ?? d.Subject ?? "?", 44);
            string icon, why;
            Color tint, stripe;
            if (d.BlockedBy != null) { icon = "🚫"; why = "blocked by you · " + d.BlockedBy.Split(',')[0].Trim(); tint = Color.FromArgb(255, 240, 242); stripe = Color.FromArgb(222, 84, 104); }
            else if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase)) { icon = "🔑"; why = "root missing, not your block · Fix it gets it"; tint = Color.FromArgb(242, 246, 255); stripe = Color.FromArgb(96, 124, 204); }
            else if (d.Code.EndsWith("92010", StringComparison.OrdinalIgnoreCase)) { icon = "⛔"; why = "revoked, or in Disallowed · Fix it checks"; tint = Color.FromArgb(255, 244, 236); stripe = Color.FromArgb(222, 128, 64); }
            else if (d.Verdict == "yellow") { icon = "🌀"; why = (d.Category != null ? d.Category + " can't connect" : "known company, refused") + " · " + ShortReason(d.Reason ?? ""); tint = Color.FromArgb(255, 250, 230); stripe = Color.FromArgb(214, 164, 40); }
            else { icon = "❔"; why = ShortReason(d.Reason ?? "refused"); tint = Color.FromArgb(246, 246, 250); stripe = Color.FromArgb(140, 140, 160); }
            why += " · " + d.Time.ToString("HH:mm");
            DenialToast t = null;
            Button allow = d.BlockedBy != null ? AllowButton("Allow", delegate { return TargetFor(d); }, delegate { if (t != null && !t.IsDisposed) t.Close(); }) : null;
            t = new DenialToast(icon, who + "  →  " + what, why, tint, stripe, allow,
                delegate { OpenRefusalCard(d); },
                delegate { GetRequested(d); },
                delegate { QuietSites.Quiet(d.Subject, TimeSpan.FromHours(1)); });
            t.FormClosed += delegate { toasts.Remove(t); StackToasts(); };
            while (toasts.Count >= 4) { DenialToast old = toasts[0]; toasts.RemoveAt(0); old.Close(); }
            toasts.Add(t);
            StackToasts();
            t.Show();
        }

        // "Apple Push Service" instead of APSDaemon.exe; the service inside svchost instead of svchost.
        private static string FriendlyProgram(Denial d)
        {
            string exe = String.IsNullOrEmpty(d.Program) ? "?" : Path.GetFileName(d.Program);
            if (d.Service != null && exe.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) return Shorten(d.Service, 30);
            string said = WhoIsWho.Program(d.Program);
            string[] parts = said == null ? null : said.Split(new string[] { " = " }, StringSplitOptions.None);
            return parts != null && parts.Length >= 2 && parts[1].Trim().Length > 0 ? Shorten(parts[1].Trim(), 30) : exe;
        }

        private static string Shorten(string text, int max)
        {
            text = (text ?? "").Trim();
            if (text.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) { int comma = text.IndexOf(','); text = text.Substring(3, comma > 3 ? comma - 3 : text.Length - 3); }
            return text.Length <= max ? text : text.Substring(0, max - 1) + "…";
        }

        private void StackToasts()
        {
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            int y = area.Bottom - 12;
            for (int i = toasts.Count - 1; i >= 0; i--)
            {
                y -= toasts[i].Height;
                toasts[i].Location = new Point(area.Right - toasts[i].Width - 12, y);
                y -= 6;
            }
        }

        // ---- Saved denials -----------------------------------------------------------

        private void SaveDenial(Denial d)
        {
            try
            {
                Directory.CreateDirectory(AppFolder);
                // Keep the log small enough to open fast: past 8 MB the older half moves to DENIALS (older).txt.
                FileInfo info = new FileInfo(DenialLogPath);
                if (info.Exists && info.Length > 8L * 1024 * 1024)
                {
                    string older = Path.Combine(AppFolder, "DENIALS (older).txt");
                    if (File.Exists(older)) File.Delete(older);
                    File.Move(DenialLogPath, older);
                }
                bool header = !File.Exists(DenialLogPath);
                string line = String.Join(",", new string[] { d.Time.ToString("o", CultureInfo.InvariantCulture), Q(d.Program), Q(d.Subject), d.Code, Q(d.Reason), Q(d.Flags),
                    Q(d.BlockedBy ?? ""), d.Noise ? "1" : "0", String.Join(" ", d.ChainSha1.ToArray()) });
                File.AppendAllText(DenialLogPath, (header ? "time,program,subject,code,reason,flags,blocked_by,noise,chain_sha1\r\n" : "") + line + "\r\n", new UTF8Encoding(false));
            }
            catch (IOException) { }
        }
        private static string Q(string v) { v = v ?? ""; return v.IndexOfAny(new char[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        private void LoadDenials()
        {
            try
            {
                if (!File.Exists(DenialLogPath)) return;
                // Only the newest part of the file is read at start.
                string text;
                using (FileStream fs = new FileStream(DenialLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    long from = Math.Max(0, fs.Length - 1024 * 1024);
                    fs.Seek(from, SeekOrigin.Begin);
                    using (StreamReader r = new StreamReader(fs, new UTF8Encoding(false))) text = r.ReadToEnd();
                    // Drop the header line, or the cut-off first line when reading from the middle.
                    int nl = text.IndexOf('\n'); text = nl >= 0 ? text.Substring(nl + 1) : "";
                }
                foreach (string[] f in GroupCatalog.ParseCsv(text).Reverse<string[]>().Take(2000).Reverse())
                {
                    if (f.Length < 9) continue;
                    Denial d = new Denial { Time = DateTime.Parse(f[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToLocalTime(), Program = f[1], Subject = f[2],
                        Code = f[3], Reason = f[4], Flags = f[5], BlockedBy = f[6].Length > 0 ? f[6] : null, Noise = f[7] == "1" };
                    d.ChainSha1.AddRange(f[8].Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
                    denials.Add(d);
                }
            }
            catch (Exception) { }
        }

        // ---- Start with Windows: a logon task with highest privileges, so no admin prompt each time ----

        private static int Schtasks(string arguments, out string output)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (Process p = Process.Start(info))
            {
                output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit(30000);
                return p.ExitCode;
            }
        }

        // Admin-only to change kisib's folder (exe, data, docs); PORTABLE BACKUP LISTS stays changeable by you.
        // Turning Start with Windows off gives the folder back its normal permissions.
        private static void LockFolder(string folder, bool locked)
        {
            System.Security.AccessControl.DirectorySecurity sec = System.IO.Directory.GetAccessControl(folder);
            System.Security.Principal.SecurityIdentifier me = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            System.Security.Principal.SecurityIdentifier admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
            System.Security.Principal.SecurityIdentifier system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            System.Security.Principal.SecurityIdentifier users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
            System.Security.AccessControl.InheritanceFlags both = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
            if (locked)
            {
                sec = new System.Security.AccessControl.DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                sec.SetOwner(admins);
                foreach (System.Security.Principal.SecurityIdentifier who in new System.Security.Principal.SecurityIdentifier[] { admins, system })
                    sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, System.Security.AccessControl.FileSystemRights.FullControl, both, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                foreach (System.Security.Principal.SecurityIdentifier who in new System.Security.Principal.SecurityIdentifier[] { users, me })
                    sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, System.Security.AccessControl.FileSystemRights.ReadAndExecute, both, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                System.IO.Directory.SetAccessControl(folder, sec);
                string lists = Path.Combine(folder, Storage.FolderName);
                if (Directory.Exists(lists))
                {
                    System.Security.AccessControl.DirectorySecurity l = Directory.GetAccessControl(lists);
                    l.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me, System.Security.AccessControl.FileSystemRights.Modify, both, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                    Directory.SetAccessControl(lists, l);
                }
            }
            else
            {
                System.Security.AccessControl.DirectorySecurity open = new System.Security.AccessControl.DirectorySecurity();
                open.SetAccessRuleProtection(false, false);
                open.SetOwner(me);
                open.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me, System.Security.AccessControl.FileSystemRights.FullControl, both, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                Directory.SetAccessControl(folder, open);
            }
        }

        private static bool StartupTaskExists()
        {
            try { string o; return Schtasks("/query /tn \"" + TaskName + "\"", out o) == 0; } catch (Exception) { return false; }
        }

        private void ToggleStartup(bool on)
        {
            if (!BlockEngine.IsElevated()) { ShowText("Start with Windows", "Run kisib as administrator once to set this up. After that it starts at logon with admin rights, without asking."); return; }
            string output; int code;
            string folder = Path.GetDirectoryName(Application.ExecutablePath);
            try
            {
                // The task starts kisib with admin rights at every logon. If anything without admin could replace the exe,
                // that would be a way in, so kisib's own folder becomes admin-only to change (its lists stay yours).
                if (on) LockFolder(folder, true);
                code = on ? Schtasks("/create /f /tn \"" + TaskName + "\" /sc onlogon /rl highest /tr \"\\\"" + Application.ExecutablePath + "\\\" --tray\"", out output)
                          : Schtasks("/delete /f /tn \"" + TaskName + "\"", out output);
                if (!on) LockFolder(folder, false);
            }
            catch (Exception ex) { code = -1; output = ex.Message; }
            Say(code == 0 ? (on ? "kisib now starts in the tray when you log in, with admin rights. Its folder is now admin-only to change (the lists inside stay yours). If you move the folder, turn this off and on again." :
                "kisib no longer starts with Windows; its folder has normal permissions again.") : "Start with Windows failed: " + output.Trim());
        }
    }
}
