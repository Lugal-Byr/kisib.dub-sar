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
    // Pop-up for a denial with the Allow buttons right on it. Shows without stealing focus.
    internal sealed class DenialToast : Form
    {
        protected override bool ShowWithoutActivation { get { return true; } }
        // Stays until you answer it: Details opens the refusal card next to it instead of closing it.
        internal DenialToast(string title, string text, bool canAllow, Action<int> allow, Action details, Action quiet)
        {
            FormBorderStyle = FormBorderStyle.FixedToolWindow; TopMost = true; ShowInTaskbar = false; StartPosition = FormStartPosition.Manual;
            Text = title; Size = new Size(520, 210); Font = new Font("Tahoma", 9F); BackColor = SystemColors.Info;
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(area.Right - Width - 12, area.Bottom - Height - 12);
            Label body = new Label { Text = text, Dock = DockStyle.Fill, Padding = new Padding(8), ForeColor = SystemColors.InfoText };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 36, Padding = new Padding(4), BackColor = SystemColors.Control };
            if (canAllow)
                foreach (int minutes in new int[] { 3, 10, 60 })
                {
                    int m = minutes;
                    Button b = new Button { Text = "Allow " + m + " min", AutoSize = true };
                    b.Click += delegate { Close(); allow(m); };
                    buttons.Controls.Add(b);
                }
            Button more = new Button { Text = "Details...", AutoSize = true }; more.Click += delegate { details(); };
            Button hush = new Button { Text = "Quiet 1 h", AutoSize = true }; hush.Click += delegate { quiet(); Close(); };
            Button dismiss = new Button { Text = "Dismiss", AutoSize = true }; dismiss.Click += delegate { Close(); };
            buttons.Controls.Add(more); buttons.Controls.Add(hush); buttons.Controls.Add(dismiss);
            Controls.Add(body); Controls.Add(buttons);
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
        private void ShowDenialToast(Denial d, string text)
        {
            List<CertificateRecord> behind = d.BlockedBy != null ? CertificatesBehind(d) : new List<CertificateRecord>();
            DenialToast t = new DenialToast("kisib: certificate refused · " + d.Time.ToString("HH:mm"), text, behind.Count > 0,
                delegate(int m) { AllowTemporarily(behind, d.Subject, TimeSpan.FromMinutes(m), false); },
                delegate { OpenRefusalCard(d); },
                delegate { QuietSites.Quiet(d.Subject, TimeSpan.FromHours(1)); });
            t.BackColor = d.Verdict == "yellow" ? Color.LightYellow : d.Verdict == "red" ? Color.MistyRose : SystemColors.Info;
            t.FormClosed += delegate { toasts.Remove(t); StackToasts(); };
            while (toasts.Count >= 4) { DenialToast old = toasts[0]; toasts.RemoveAt(0); old.Close(); }
            toasts.Add(t);
            StackToasts();
            t.Show();
        }

        private void StackToasts()
        {
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            int y = area.Bottom - 12;
            for (int i = toasts.Count - 1; i >= 0; i--)
            {
                y -= toasts[i].Height;
                toasts[i].Location = new Point(area.Right - toasts[i].Width - 12, y);
                y -= 8;
            }
        }

        // ---- Saved denials -----------------------------------------------------------

        private void SaveDenial(Denial d)
        {
            try
            {
                Directory.CreateDirectory(AppFolder);
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
                foreach (string[] f in GroupCatalog.ReadCsv(DenialLogPath, 64L * 1024 * 1024).Skip(1).Reverse().Take(2000).Reverse())
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

        private static bool StartupTaskExists()
        {
            try { string o; return Schtasks("/query /tn \"" + TaskName + "\"", out o) == 0; } catch (Exception) { return false; }
        }

        private void ToggleStartup(bool on)
        {
            if (!BlockEngine.IsElevated()) { ShowText("Start with Windows", "Run kisib as administrator once to set this up. After that it starts at logon with admin rights, without asking."); return; }
            string output; int code;
            try
            {
                code = on ? Schtasks("/create /f /tn \"" + TaskName + "\" /sc onlogon /rl highest /tr \"\\\"" + Application.ExecutablePath + "\\\" --tray\"", out output)
                          : Schtasks("/delete /f /tn \"" + TaskName + "\"", out output);
            }
            catch (Exception ex) { code = -1; output = ex.Message; }
            ShowText("Start with Windows", code == 0 ? (on ? "kisib now starts in the tray when you log in, watching for denials.\r\nIt runs from:\r\n" + Application.ExecutablePath +
                "\r\nIf you move the folder, turn this off and on again." : "kisib no longer starts with Windows.") : "schtasks failed:\r\n" + output);
        }
    }
}
