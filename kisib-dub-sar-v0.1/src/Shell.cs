using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // Window sizes and positions, so each tool window opens where it was last left.
    internal static class WindowPlaces
    {
        private static string PathName { get { return Storage.File("SETTING - window places.txt"); } }

        internal static Rectangle? Get(string key)
        {
            try
            {
                if (!File.Exists(PathName)) return null;
                foreach (string line in File.ReadAllLines(PathName))
                {
                    int bar = line.LastIndexOf('|');
                    if (bar <= 0 || line.Substring(0, bar) != key) continue;
                    int[] n = line.Substring(bar + 1).Split(',').Select(s => Int32.Parse(s.Trim(), CultureInfo.InvariantCulture)).ToArray();
                    if (n.Length == 4 && n[2] > 100 && n[3] > 80) return new Rectangle(n[0], n[1], n[2], n[3]);
                }
            }
            catch (Exception) { }
            return null;
        }

        internal static void Set(string key, Rectangle r)
        {
            try
            {
                List<string> lines = File.Exists(PathName) ? File.ReadAllLines(PathName).ToList() : new List<string> { "# kisib window places: name|x,y,width,height" };
                lines.RemoveAll(l => l.StartsWith(key + "|", StringComparison.Ordinal));
                lines.Add(key + "|" + r.X + "," + r.Y + "," + r.Width + "," + r.Height);
                File.WriteAllLines(PathName, lines.ToArray(), new UTF8Encoding(false));
            }
            catch (Exception) { }
        }
    }

    // "Quiet this site for 1 hour": refusals still get logged, no pop-up.
    internal static class QuietSites
    {
        private static readonly Dictionary<string, DateTime> until = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        internal static void Quiet(string site, TimeSpan span) { if (!String.IsNullOrEmpty(site)) until[site] = DateTime.UtcNow.Add(span); }
        internal static bool IsQuiet(string site)
        {
            DateTime t;
            return !String.IsNullOrEmpty(site) && until.TryGetValue(site, out t) && t > DateTime.UtcNow;
        }
    }

    // Tray-only shell: no taskbar button ever, the X hides to the tray, one copy running, lists refresh weekly.
    internal sealed partial class ExplorerForm
    {
        [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr handle);

        private readonly Dictionary<string, Form> toolWindows = new Dictionary<string, Form>();
        private bool exiting, toldTray, quietMode, listsRefreshing;
        private int badgeState, lastLeaks;
        private Icon[] badgeIcons;
        private Action denialsRefresh;
        private Action toolsRefresh;
        private EventWaitHandle showSignal;
        private readonly System.Windows.Forms.Timer listTimer = new System.Windows.Forms.Timer { Interval = 6 * 60 * 60 * 1000 };

        private bool QuietMode { get { return quietMode; } }

        private void InitializeShell(MenuItem tools)
        {
            quietMode = Storage.Setting("quiet mode");
            MenuItem weekly = new MenuItem("Refresh Microsoft list and CCADB &weekly (when online)");
            tools.MenuItems.Add(weekly);
            tools.MenuItems.Add("-");
            tools.MenuItems.Add(new MenuItem("&Never block list (allowed, unblocked by hand, repaired)...", delegate { ShowAllowed(); }));
            tools.MenuItems.Add(new MenuItem("R&ules (groups kept blocked)...", delegate { ShowRules(); }));
            tools.MenuItems.Add(new MenuItem("Un&do last block", delegate { UndoLastBlock(); }));
            MenuItem quietItem = new MenuItem("&Quiet mode (log refusals, no pop-ups)", delegate { ToggleQuiet(); });
            tools.MenuItems.Add(quietItem);
            tools.MenuItems.Add("-");
            tools.MenuItems.Add(new MenuItem("&Tools page (every tool and how it stands)...", delegate { ShowToolsPage(); }, Shortcut.CtrlT));
            tools.MenuItems.Add(new MenuItem("Re&quired for app (app > root > intermediates)...", delegate { ShowRequiredForApp(); }));
            tools.Popup += delegate { weekly.Checked = !Storage.Setting("lists auto-refresh off"); quietItem.Checked = quietMode; };
            weekly.Click += delegate { Storage.Setting("lists auto-refresh off", !Storage.Setting("lists auto-refresh off")); };

            StartCommandServer();
            // A second copy of kisib only wakes this one up.
            try { showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\kisib.dub-sar.show"); } catch (Exception) { showSignal = null; }
            if (showSignal != null)
            {
                Thread listener = new Thread(delegate()
                {
                    while (!closed)
                    {
                        try { if (showSignal.WaitOne(1000)) Post(RestoreFromTray); }
                        catch (Exception) { return; }
                    }
                });
                listener.IsBackground = true; listener.Name = "Single instance"; listener.Start();
            }

            listTimer.Tick += delegate { MaybeRefreshLists(); };
            Shown += delegate
            {
                System.Windows.Forms.Timer first = new System.Windows.Forms.Timer { Interval = 2 * 60 * 1000 };
                first.Tick += delegate { first.Stop(); first.Dispose(); MaybeRefreshLists(); listTimer.Start(); };
                first.Start();
            };
            FormClosed += delegate { listTimer.Stop(); };
        }

        internal void ExitApp() { exiting = true; try { AppChains.Flush(); } catch (Exception) { } Close(); }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!exiting && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; HideToTray(); return; }
            base.OnFormClosing(e);
        }

        private void HideToTray()
        {
            Hide();
            if (!toldTray && tray != null)
            {
                toldTray = true;
                tray.ShowBalloonTip(4000, "kisib is still watching", "It lives in the tray. Click the seal to open it; Exit is in its right-click menu.", ToolTipIcon.Info);
            }
        }

        // Every tool window: a normal window (the main one stays usable), one of each kind,
        // reopening where it was, Esc closes. If a confirm dialog is open, it waits its turn like before.
        internal void ShowTool(Form f, string key)
        {
            Form modal = Application.OpenForms.Cast<Form>().FirstOrDefault(x => x.Modal && x.Visible && x != f);
            if (modal != null) { using (f) { f.StartPosition = FormStartPosition.CenterParent; f.ShowDialog(modal); } return; }
            string place = key.StartsWith("text:", StringComparison.Ordinal) ? "text" : key.StartsWith("refusal:", StringComparison.Ordinal) ? "refusal" : key;
            Rectangle? bounds = null;
            Form old;
            if (toolWindows.TryGetValue(key, out old) && !old.IsDisposed)
            {
                bounds = old.WindowState == FormWindowState.Normal ? old.Bounds : old.RestoreBounds;
                old.Close();
            }
            if (!bounds.HasValue) bounds = WindowPlaces.Get(place);
            f.ShowInTaskbar = false;
            f.Icon = Icon;
            f.KeyPreview = true;
            f.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Escape) f.Close(); };
            WireClose(f, f);
            f.StartPosition = FormStartPosition.Manual;
            if (bounds.HasValue && Screen.AllScreens.Any(sc => sc.WorkingArea.IntersectsWith(bounds.Value))) f.Bounds = bounds.Value;
            else
            {
                Rectangle area = Visible && WindowState == FormWindowState.Normal ? Bounds : Screen.PrimaryScreen.WorkingArea;
                f.Location = new Point(Math.Max(0, area.X + (area.Width - f.Width) / 2), Math.Max(0, area.Y + (area.Height - f.Height) / 2));
            }
            f.FormClosing += delegate { WindowPlaces.Set(place, f.WindowState == FormWindowState.Normal ? f.Bounds : f.RestoreBounds); };
            f.FormClosed += delegate { Form cur; if (toolWindows.TryGetValue(key, out cur) && cur == f) toolWindows.Remove(key); };
            toolWindows[key] = f;
            if (Visible) f.Show(this); else f.Show();
            f.Activate();
        }

        private static void WireClose(Form f, Control parent)
        {
            foreach (Control c in parent.Controls)
            {
                Button b = c as Button;
                if (b != null && b.DialogResult != DialogResult.None) b.Click += delegate { f.Close(); };
                WireClose(f, c);
            }
        }

        // ---- Tray: badge for refusals, hover with counts ---------------------------------

        private void MarkTrayBadge(bool red)
        {
            int s = red ? 2 : 1;
            if (s > badgeState) { badgeState = s; ApplyBadge(); }
        }

        private void ClearTrayBadge()
        {
            if (badgeState != 0) { badgeState = 0; ApplyBadge(); }
        }

        private void ApplyBadge()
        {
            if (tray == null) return;
            try { tray.Icon = BadgeIcon(badgeState); } catch (Exception) { }
        }

        private Icon BadgeIcon(int state)
        {
            if (badgeIcons == null) badgeIcons = new Icon[3];
            if (badgeIcons[state] != null) return badgeIcons[state];
            Icon baseIcon = AppIcon.Small ?? SystemIcons.Shield;
            if (state == 0) return badgeIcons[0] = baseIcon;
            Size size = SystemInformation.SmallIconSize;
            using (Bitmap b = new Bitmap(size.Width, size.Height))
            {
                using (Graphics g = Graphics.FromImage(b))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.DrawIcon(baseIcon, new Rectangle(0, 0, size.Width, size.Height));
                    int d = Math.Max(7, size.Width * 9 / 16);
                    Rectangle dot = new Rectangle(size.Width - d, size.Height - d, d - 1, d - 1);
                    using (Brush brush = new SolidBrush(state == 2 ? Color.Red : Color.Gold)) g.FillEllipse(brush, dot);
                    using (Pen pen = new Pen(Color.White, 1)) g.DrawEllipse(pen, dot);
                }
                IntPtr h = b.GetHicon();
                badgeIcons[state] = (Icon)Icon.FromHandle(h).Clone();
                DestroyIcon(h);
            }
            return badgeIcons[state];
        }

        private void UpdateTrayHover()
        {
            if (tray == null) return;
            List<string> parts = new List<string>();
            int today = denials.Count(d => !d.Ok && !d.Noise && d.Time.Date == DateTime.Today);
            if (today > 0) parts.Add(today + " refused today");
            if (lastLeaks > 0) parts.Add(lastLeaks + (lastLeaks == 1 ? " leak" : " leaks"));
            try
            {
                List<TempAllowEntry> pending = TempAllow.Read();
                List<TempAllowEntry> timed = pending.Where(p => p.Mode == "timed").ToList();
                if (timed.Count > 0)
                {
                    TimeSpan left = timed.Min(p => p.UntilUtc) - DateTime.UtcNow;
                    if (left > TimeSpan.Zero) parts.Add("open " + (int)left.TotalMinutes + ":" + left.Seconds.ToString("00"));
                }
                else if (pending.Count > 0) parts.Add(pending.Select(p => p.Subject).Distinct().Count() + " open");
            }
            catch (Exception) { }
            if (quietMode) parts.Add("quiet");
            string text = parts.Count == 0 ? AboutText.Hover : "kisib: " + String.Join(" · ", parts.ToArray());
            if (text.Length > 63) text = text.Substring(0, 63);
            if (tray.Text != text) tray.Text = text;
        }

        private void ToggleQuiet()
        {
            quietMode = !quietMode;
            Storage.Setting("quiet mode", quietMode);
            UpdateTrayHover();
        }

        // ---- Weekly list refresh: offline keeps the old copy ---------------------------------

        private void MaybeRefreshLists()
        {
            if (listsRefreshing || closed || Storage.Setting("lists auto-refresh off")) return;
            DateTime week = DateTime.Now.AddDays(-7);
            bool ms = !MicrosoftList.Updated.HasValue || MicrosoftList.Updated.Value < week;
            bool cc = !Ccadb.Updated.HasValue || Ccadb.Updated.Value < week;
            if (!ms && !cc) return;
            listsRefreshing = true;
            Thread worker = new Thread(delegate()
            {
                bool changed = false;
                StringBuilder note = new StringBuilder();
                if (ms)
                {
                    try { string error = MicrosoftList.Update(); if (error == null) { changed = true; note.Append("Microsoft list updated. "); } else note.Append("Microsoft list: not reachable, kept the old copy. "); }
                    catch (Exception) { note.Append("Microsoft list: not reachable, kept the old copy. "); }
                }
                if (cc)
                {
                    try { string report = Ccadb.Update(); if (report.Contains(": ok")) { changed = true; note.Append("CCADB updated. "); } else note.Append("CCADB: not reachable, kept the old copy. "); }
                    catch (Exception) { note.Append("CCADB: not reachable, kept the old copy. "); }
                }
                Post(delegate
                {
                    listsRefreshing = false;
                    sessionLog.Add(DateTime.UtcNow.ToString("o") + "\tWeekly list refresh\t" + note.ToString().Trim());
                    if (changed) StartScan();
                });
            });
            worker.IsBackground = true; worker.Name = "Weekly list refresh"; worker.Start();
        }
    }
}
