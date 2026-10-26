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
        // Stays until you answer it: the refusal card opens next to it instead of closing it.
        internal DenialToast(string title, string text, Button allow, Action details, Action quiet)
        {
            FormBorderStyle = FormBorderStyle.FixedToolWindow; TopMost = true; ShowInTaskbar = false; StartPosition = FormStartPosition.Manual;
            Text = title; Size = new Size(520, 210); Font = new Font("Tahoma", 9F); BackColor = SystemColors.Info;
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(area.Right - Width - 12, area.Bottom - Height - 12);
            Label body = new Label { Text = text, Dock = DockStyle.Fill, Padding = new Padding(8), ForeColor = SystemColors.InfoText };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 36, Padding = new Padding(4), BackColor = SystemColors.Control };
            if (allow != null) buttons.Controls.Add(allow);
            Button more = new Button { Text = "Refusal card", AutoSize = true }; more.Click += delegate { details(); };
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
            MenuItem openNow = new MenuItem("Open right now (allowed for a while)");
            openNow.MenuItems.Add("(building)");
            openNow.Popup += delegate { FillOpenNow(openNow); };
            menu.MenuItems.Add(openNow);
            menu.MenuItems.Add("Tools...", delegate { RestoreFromTray(); ShowToolsPage(); });
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
            DenialToast t = null;
            Button allow = d.BlockedBy != null ? AllowButton("Allow", delegate { return TargetFor(d); }, delegate { if (t != null && !t.IsDisposed) t.Close(); }) : null;
            t = new DenialToast("kisib: certificate refused · " + d.Time.ToString("HH:mm"), text, allow,
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
