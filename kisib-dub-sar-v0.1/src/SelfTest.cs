using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // kisib.dub-sar.exe --probe <hosts file> <out file>: one TLS handshake per host through Windows' own certificate
    // checks, from a separate process, so the kisib being tested sees them the way it sees any other program.
    internal static class Probe
    {
        internal static int Run(string hostsFile, string outFile)
        {
            List<string> lines = new List<string>();
            foreach (string raw in File.ReadAllLines(hostsFile))
            {
                string host = raw.Trim();
                if (host.Length == 0 || host.StartsWith("#", StringComparison.Ordinal)) continue;
                lines.Add(One(host));
            }
            File.WriteAllLines(outFile, lines.ToArray(), new UTF8Encoding(false));
            return 0;
        }

        private static string One(string host)
        {
            string result = "?", chainText = "", flags = "";
            Stopwatch clock = Stopwatch.StartNew();
            try
            {
                using (TcpClient tcp = new TcpClient())
                {
                    IAsyncResult r = tcp.BeginConnect(host, 443, null, null);
                    if (!r.AsyncWaitHandle.WaitOne(8000)) return host + "\tCONNECT-TIMEOUT";
                    tcp.EndConnect(r);
                    using (SslStream ssl = new SslStream(tcp.GetStream(), false, delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
                    {
                        result = errors == SslPolicyErrors.None ? "OK" : "REFUSED " + errors;
                        if (chain != null)
                        {
                            flags = String.Join("+", chain.ChainStatus.Select(x => x.Status.ToString()).Distinct().ToArray());
                            chainText = String.Join(" > ", chain.ChainElements.Cast<X509ChainElement>().Select(e => e.Certificate.GetNameInfo(X509NameType.SimpleName, false) + " [" + e.Certificate.Thumbprint.Substring(0, 8) + "]").ToArray());
                        }
                        return true;
                    }))
                    {
                        ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
                    }
                }
            }
            catch (Exception ex) { result = "ERROR " + ex.GetType().Name + ": " + ex.Message.Replace("\r", " ").Replace("\n", " "); }
            return host + "\t" + result + "\t" + flags + "\t" + chainText + "\t" + clock.ElapsedMilliseconds + "ms";
        }
    }

    // kisib.dub-sar.exe --selftest <folder>: runs the real program on a throwaway Windows machine (GitHub's build
    // service), does what a person would do (scan, block every bloc, watch refusals, flip certificates, unblock), checks
    // that other programs still work, and saves a log and a picture of every window. Refuses to run anywhere else,
    // because it changes certificate stores on purpose.
    internal sealed partial class ExplorerForm
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr h, StringBuilder text, int max);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr h, StringBuilder text, int max);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc proc, IntPtr l);
        [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumProc proc, IntPtr l);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr h);
        private delegate bool EnumProc(IntPtr h, IntPtr l);

        internal string SelfTestFolder;
        private StreamWriter stLog;
        private int stFailed, stShots;
        private readonly Stopwatch stClock = new Stopwatch();
        private readonly List<string> stSummary = new List<string>();

        internal static bool SelfTestAllowed
        { get { return String.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase) && Environment.GetEnvironmentVariable("KISIB_SELFTEST") == "yes"; } }

        internal void StartSelfTest()
        {
            Directory.CreateDirectory(SelfTestFolder);
            stLog = new StreamWriter(Path.Combine(SelfTestFolder, "selftest.log"), false, new UTF8Encoding(false)) { AutoFlush = true };
            stClock.Start();
            Thread dialogs = new Thread(StCloseStrayDialogs) { IsBackground = true, Name = "selftest dialogs" };
            dialogs.Start();
            Thread watchdog = new Thread(delegate() { Thread.Sleep(25 * 60 * 1000); StLine("WATCHDOG: 25 minutes, giving up"); Environment.Exit(3); }) { IsBackground = true };
            watchdog.Start();
            Thread t = new Thread(delegate()
            {
                int code = 1;
                try { StRun(); code = stFailed == 0 ? 0 : 1; }
                catch (Exception ex) { StLine("FATAL " + ex); code = 2; }
                StLine("");
                StLine("==== SUMMARY ====");
                foreach (string s in stSummary) StLine(s);
                StLine("failed steps: " + stFailed + "   exit code " + code);
                try { stLog.Flush(); } catch (Exception) { }
                Environment.Exit(code);
            }) { IsBackground = true, Name = "selftest" };
            t.Start();
        }

        // ---- plumbing ----------------------------------------------------------------------------------------

        private void StLine(string text)
        {
            string line = stClock.Elapsed.TotalSeconds.ToString("0000.0") + "  " + text;
            lock (stSummary) { try { stLog.WriteLine(line); } catch (Exception) { } }
        }
        private void StNote(string text) { StLine("      " + text); }
        private void StSum(string text) { stSummary.Add(text); StLine("  >>  " + text); }

        private void StUi(Action a) { Invoke(a); }
        private T StUi<T>(Func<T> f) { return (T)Invoke(f); }

        private bool StStep(string name, Action body)
        {
            Stopwatch w = Stopwatch.StartNew();
            StLine("STEP  " + name);
            try { body(); StLine("PASS  " + name + "  (" + w.Elapsed.TotalSeconds.ToString("0.0") + "s)"); return true; }
            catch (Exception ex)
            {
                stFailed++;
                Exception inner = ex is System.Reflection.TargetInvocationException && ex.InnerException != null ? ex.InnerException : ex;
                StLine("FAIL  " + name + "  (" + w.Elapsed.TotalSeconds.ToString("0.0") + "s)  " + inner);
                stSummary.Add("FAIL " + name + ": " + inner.GetType().Name + ": " + inner.Message);
                return false;
            }
        }

        private void StWait(string what, int seconds, Func<bool> done)
        {
            Stopwatch w = Stopwatch.StartNew();
            while (w.Elapsed.TotalSeconds < seconds)
            {
                if (StUi(done)) return;
                Thread.Sleep(200);
            }
            throw new TimeoutException(what + " took longer than " + seconds + "s");
        }

        // A full scan cycle: asks for a scan, waits until nothing is scanning and no follow-up scan is queued.
        private double StScan(string why)
        {
            Stopwatch w = Stopwatch.StartNew();
            Snapshot before = StUi(() => snapshot);
            StUi(delegate { StartScan(true); });
            StWait("scan (" + why + ")", 300, () => !scanning && !rescanPending && snapshot != null && snapshot != before);
            // Rules that blocked something start another scan; settle until two looks in a row are quiet.
            for (int quiet = 0; quiet < 3; )
            {
                Thread.Sleep(400);
                if (StUi(() => !scanning && !rescanPending)) quiet++; else quiet = 0;
                if (w.Elapsed.TotalSeconds > 400) throw new TimeoutException("scans never settled (" + why + ")");
            }
            double s = w.Elapsed.TotalSeconds;
            StNote("scan settled in " + s.ToString("0.0") + "s (" + why + "): " + StUi(() => snapshot.Certificates.Count + " certificates, " + snapshot.Blocked.Count + " blocked, status: " + status.Text));
            return s;
        }

        private static int StStoreCount(string name, X509Location scope)
        {
            try { using (OwnStore s = OwnStore.Open(name, scope, false)) return s.Count; } catch (Exception) { return -1; }
        }

        private string StCounts()
        {
            return "Disallowed: whole PC " + StStoreCount("Disallowed", X509Location.LocalMachine) + ", you " + StStoreCount("Disallowed", X509Location.CurrentUser) +
                "   Root: whole PC " + StStoreCount("Root", X509Location.LocalMachine) + ", you " + StStoreCount("Root", X509Location.CurrentUser) +
                "   AuthRoot: " + StStoreCount("AuthRoot", X509Location.LocalMachine) + "   CA: whole PC " + StStoreCount("CA", X509Location.LocalMachine) + ", you " + StStoreCount("CA", X509Location.CurrentUser);
        }

        // Message boxes and file pickers would hang the run: say what they were and close them.
        private void StCloseStrayDialogs()
        {
            uint mine = (uint)Process.GetCurrentProcess().Id;
            Dictionary<IntPtr, DateTime> seen = new Dictionary<IntPtr, DateTime>();
            while (true)
            {
                Thread.Sleep(700);
                try
                {
                    EnumWindows(delegate(IntPtr h, IntPtr l)
                    {
                        uint pid; GetWindowThreadProcessId(h, out pid);
                        if (pid != mine || !IsWindowVisible(h)) return true;
                        StringBuilder cls = new StringBuilder(64); GetClassName(h, cls, 64);
                        if (cls.ToString() != "#32770") return true;
                        DateTime first;
                        if (!seen.TryGetValue(h, out first)) { seen[h] = DateTime.Now; return true; }
                        if ((DateTime.Now - first).TotalSeconds < 2.5) return true;
                        StringBuilder title = new StringBuilder(256); GetWindowText(h, title, 256);
                        List<string> texts = new List<string>();
                        EnumChildWindows(h, delegate(IntPtr c, IntPtr l2) { StringBuilder t = new StringBuilder(600); GetWindowText(c, t, 600); if (t.Length > 0) texts.Add(t.ToString()); return true; }, IntPtr.Zero);
                        StLine("DIALOG closed by the test: [" + title + "] " + String.Join(" | ", texts.ToArray()));
                        PostMessage(h, 0x0010, IntPtr.Zero, IntPtr.Zero);   // WM_CLOSE
                        seen.Remove(h);
                        return true;
                    }, IntPtr.Zero);
                }
                catch (Exception) { }
            }
        }

        // ---- pictures and text of windows ---------------------------------------------------------------------

        private void StShot(string name, Form f)
        {
            try
            {
                StUi(delegate
                {
                    if (f == null || f.IsDisposed) return;
                    f.Activate(); f.BringToFront(); try { SetForegroundWindow(f.Handle); } catch (Exception) { }
                    Application.DoEvents(); f.Refresh(); Application.DoEvents();
                });
                Thread.Sleep(350);
                StUi(delegate
                {
                    if (f == null || f.IsDisposed) return;
                    Application.DoEvents();
                    string file = Path.Combine(SelfTestFolder, (++stShots).ToString("00") + "-" + name + ".png");
                    Rectangle b = f.Bounds;
                    Rectangle screen = Screen.FromControl(f).Bounds;
                    bool whole = screen.Contains(b);
                    string how = "screen";
                    Bitmap bmp = new Bitmap(Math.Max(1, b.Width), Math.Max(1, b.Height));
                    bool ok = false;
                    if (whole)
                        try
                        {
                            using (Graphics g = Graphics.FromImage(bmp)) g.CopyFromScreen(b.Location, Point.Empty, b.Size);
                            ok = !StBlank(bmp);
                        }
                        catch (Exception) { ok = false; }
                    if (!ok) { how = whole ? "drawn (screen copy was blank)" : "drawn (window bigger than the screen)"; using (Graphics g = Graphics.FromImage(bmp)) g.Clear(Color.White); f.DrawToBitmap(bmp, new Rectangle(0, 0, b.Width, b.Height)); }
                    bmp.Save(file, ImageFormat.Png); bmp.Dispose();
                    StNote("picture " + Path.GetFileName(file) + "  " + b.Width + "x" + b.Height + "  " + how + "  title: " + f.Text);
                });
            }
            catch (Exception ex) { StNote("picture " + name + " failed: " + ex.Message); }
        }

        private static bool StBlank(Bitmap b)
        {
            Color first = b.GetPixel(b.Width / 2, b.Height / 2);
            int same = 0, total = 0;
            for (int x = 5; x < b.Width; x += Math.Max(1, b.Width / 23))
                for (int y = 5; y < b.Height; y += Math.Max(1, b.Height / 17)) { total++; if (b.GetPixel(x, y).ToArgb() == first.ToArgb()) same++; }
            return total > 0 && same == total;
        }

        // What a window says, as text: every label, button, list and tree in it.
        private void StDump(string name, Form f)
        {
            try
            {
                string text = StUi(delegate
                {
                    StringBuilder t = new StringBuilder();
                    t.AppendLine("WINDOW " + name + ": [" + f.Text + "] " + f.Width + "x" + f.Height + " font " + f.Font.Name + " " + f.Font.Size);
                    StDumpControl(f, t, 1);
                    return t.ToString();
                });
                File.AppendAllText(Path.Combine(SelfTestFolder, "windows.txt"), text + "\r\n", new UTF8Encoding(false));
            }
            catch (Exception ex) { StNote("dump " + name + " failed: " + ex.Message); }
        }

        private static void StDumpControl(Control c, StringBuilder t, int depth)
        {
            string pad = new string(' ', depth * 2);
            foreach (Control child in c.Controls)
            {
                if (!child.Visible && !(child is TabPage)) continue;
                ListView lv = child as ListView; TreeView tv = child as TreeView;
                string text = (child.Text ?? "").Replace("\r\n", " ⏎ ").Replace("\n", " ⏎ ");
                if (text.Length > 600) text = text.Substring(0, 600) + "…(" + child.Text.Length + " chars)";
                t.AppendLine(pad + child.GetType().Name + (child.Enabled ? "" : " (disabled)") + " " + child.Width + "x" + child.Height + (text.Length > 0 && lv == null && tv == null ? "  \"" + text + "\"" : ""));
                if (lv != null)
                {
                    t.AppendLine(pad + "  columns: " + String.Join(" | ", lv.Columns.Cast<ColumnHeader>().Select(h => h.Text + "(" + h.Width + ")").ToArray()));
                    int n = lv.VirtualMode ? lv.VirtualListSize : lv.Items.Count;
                    t.AppendLine(pad + "  rows: " + n);
                    for (int i = 0; i < Math.Min(n, 14); i++)
                    {
                        try { ListViewItem it = lv.Items[i]; t.AppendLine(pad + "    " + String.Join(" | ", it.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToArray())); }
                        catch (Exception ex) { t.AppendLine(pad + "    (row " + i + ": " + ex.Message + ")"); }
                    }
                }
                else if (tv != null)
                {
                    int shown = 0;
                    foreach (TreeNode node in tv.Nodes) StDumpNode(node, t, pad + "  ", ref shown);
                }
                else StDumpControl(child, t, depth + 1);
            }
        }

        private static void StDumpNode(TreeNode n, StringBuilder t, string pad, ref int shown)
        {
            if (shown++ > 45) return;
            t.AppendLine(pad + (n.Nodes.Count > 0 ? (n.IsExpanded ? "[-] " : "[+] ") : "    ") + n.Text);
            if (n.IsExpanded || pad.Length < 8) foreach (TreeNode child in n.Nodes) StDumpNode(child, t, pad + "  ", ref shown);
        }

        private static void StDumpMenu(Menu.MenuItemCollection items, StringBuilder t, int depth)
        {
            foreach (MenuItem m in items)
            {
                t.AppendLine(new string(' ', depth * 4) + (m.Text == "-" ? "────────" : m.Text.Replace("&", "")) + (m.Shortcut != Shortcut.None ? "    [" + m.Shortcut + "]" : "") + (m.Checked ? "  ✓" : "") + (m.Enabled ? "" : "  (grey)"));
                if (m.MenuItems.Count > 0) StDumpMenu(m.MenuItems, t, depth + 1);
            }
        }

        // Opens a window the way a click would, takes its picture and its text, closes it.
        private void StWindow(string name, Action open)
        {
            StStep("window: " + name, delegate
            {
                List<Form> before = StUi(() => Application.OpenForms.Cast<Form>().ToList());
                // BeginInvoke: a modal window must not hang the test.
                Exception thrown = null;
                BeginInvoke((Action)delegate { try { open(); } catch (Exception ex) { thrown = ex; } });
                Form f = null;
                Stopwatch w = Stopwatch.StartNew();
                while (w.Elapsed.TotalSeconds < 12 && f == null)
                {
                    Thread.Sleep(250);
                    if (thrown != null) throw thrown;
                    f = StUi(() => Application.OpenForms.Cast<Form>().LastOrDefault(x => !before.Contains(x) && x.Visible && !(x is DenialToast)));
                }
                if (f == null) throw new InvalidOperationException("no window opened (status bar: " + StUi(() => status.Text) + ")");
                Thread.Sleep(1200);
                StShot(name, f);
                StDump(name, f);
                StUi(delegate { if (!f.IsDisposed) f.Close(); });
                Thread.Sleep(150);
                if (thrown != null) throw thrown;
            });
        }

        // ---- other programs: do they still work? ----------------------------------------------------------------

        private static readonly string[] StHosts =
        {
            "www.microsoft.com", "login.microsoftonline.com", "login.live.com", "update.microsoft.com", "settings-win.data.microsoft.com", "www.bing.com",
            "github.com", "api.github.com", "objects.githubusercontent.com", "claude.ai", "www.anthropic.com", "api.anthropic.com",
            "www.apple.com", "www.icloud.com", "gsa.apple.com", "api.push.apple.com", "itunes.apple.com",
            "www.google.com", "accounts.google.com", "www.youtube.com", "www.cloudflare.com", "letsencrypt.org", "www.amazon.com",
            "www.digicert.com", "www.sectigo.com", "www.globalsign.com", "store.steampowered.com", "discord.com", "www.mozilla.org", "duckduckgo.com",
            "www.ivpn.net", "codeberg.org", "www.wikipedia.org", "www.reddit.com", "crt.sh", "ccadb.my.salesforce-sites.com", "www.paypal.com", "www.bbc.co.uk", "www.europa.eu", "www.gov.br"
        };

        private Dictionary<string, string> StProbe(string label)
        {
            Dictionary<string, string> results = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string hosts = Path.Combine(SelfTestFolder, "hosts.txt"), outFile = Path.Combine(SelfTestFolder, "probe-" + label + ".txt");
            File.WriteAllLines(hosts, StHosts);
            ProcessStartInfo info = new ProcessStartInfo(Application.ExecutablePath, "--probe \"" + hosts + "\" \"" + outFile + "\"") { UseShellExecute = false, CreateNoWindow = true };
            using (Process p = Process.Start(info)) { if (!p.WaitForExit(240000)) { try { p.Kill(); } catch (Exception) { } StNote("probe " + label + " timed out"); } }
            if (!File.Exists(outFile)) { StNote("probe " + label + " wrote nothing"); return results; }
            foreach (string line in File.ReadAllLines(outFile))
            {
                string[] f = line.Split('\t');
                if (f.Length >= 2) results[f[0]] = f[1] + (f.Length >= 4 ? "\t" + f[2] + "\t" + f[3] : "");
            }
            int ok = results.Values.Count(v => v.StartsWith("OK", StringComparison.Ordinal));
            StNote("probe " + label + ": " + ok + " of " + results.Count + " sites fine");
            foreach (KeyValuePair<string, string> r in results.Where(x => !x.Value.StartsWith("OK", StringComparison.Ordinal))) StNote("    ✗ " + r.Key + "  " + r.Value.Replace("\t", "  |  "));
            return results;
        }

        private const string StSignedFilesScript = @"
$ErrorActionPreference='SilentlyContinue'
$files = @(
 ""$env:WINDIR\System32\ntdll.dll"", ""$env:WINDIR\explorer.exe"", ""$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"", ""$env:WINDIR\System32\drivers\ntfs.sys"",
 ""$env:WINDIR\System32\msiexec.exe"", ""$env:WINDIR\System32\wuaueng.dll"", ""$env:WINDIR\System32\crypt32.dll"",
 ""${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"", ""$env:ProgramFiles\Google\Chrome\Application\chrome.exe"", ""$env:ProgramFiles\Mozilla Firefox\firefox.exe"",
 ""$env:ProgramFiles\Git\cmd\git.exe"", ""$env:ProgramFiles\nodejs\node.exe"", ""$env:ProgramFiles\7-Zip\7z.exe"", ""$env:ProgramFiles\PowerShell\7\pwsh.exe"",
 ""$env:ProgramFiles\Docker\dockerd.exe"", ""$env:ProgramFiles\dotnet\dotnet.exe"", ""$env:ProgramFiles\GitHub CLI\gh.exe"", ""$env:ProgramFiles\Amazon\AWSCLIV2\aws.exe"",
 ""${env:ProgramFiles(x86)}\Google\Cloud SDK\google-cloud-sdk\platform\bundledpython\python.exe"", ""$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe""
)
$def = Get-ChildItem ""$env:ProgramData\Microsoft\Windows Defender\Platform"" -Directory | Sort-Object Name -Descending | Select-Object -First 1
if ($def) { $files += (Join-Path $def.FullName 'MsMpEng.exe') } else { $files += ""$env:ProgramFiles\Windows Defender\MsMpEng.exe"" }
foreach ($f in $files) {
  if (-not (Test-Path -LiteralPath $f)) { continue }
  $s = Get-AuthenticodeSignature -LiteralPath $f
  $signer = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo('SimpleName',$false) + ' <- ' + $s.SignerCertificate.GetNameInfo('SimpleName',$true) } else { '' }
  $stamp = if ($s.TimeStamperCertificate) { $s.TimeStamperCertificate.GetNameInfo('SimpleName',$false) + ' <- ' + $s.TimeStamperCertificate.GetNameInfo('SimpleName',$true) } else { '' }
  $msg = ([string]$s.StatusMessage).Replace(""`r"","" "").Replace(""`n"","" "")
  '{0}|{1}|{2}|{3}|{4}' -f (Split-Path $f -Leaf), $s.Status, $msg, $signer, $stamp
}
";

        private Dictionary<string, string> StSignedFiles(string label)
        {
            Dictionary<string, string> results = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                    "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(StSignedFilesScript)))
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                string output;
                using (Process p = Process.Start(info))
                {
                    output = p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(180000)) { try { p.Kill(); } catch (Exception) { } }
                }
                foreach (string line in output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] f = line.Split('|');
                    if (f.Length >= 5) results[f[0]] = f[1] + "|" + f[3] + "|" + f[4] + "|" + f[2];
                }
            }
            catch (Exception ex) { StNote("signed files " + label + ": " + ex.Message); }
            int ok = results.Values.Count(v => v.StartsWith("Valid|", StringComparison.Ordinal));
            StNote("signed files " + label + ": " + ok + " of " + results.Count + " valid");
            File.WriteAllLines(Path.Combine(SelfTestFolder, "signed-" + label + ".txt"), results.Select(r => r.Key + "|" + r.Value).ToArray());
            foreach (KeyValuePair<string, string> r in results.Where(x => !x.Value.StartsWith("Valid|", StringComparison.Ordinal))) StNote("    ✗ " + r.Key + "  " + r.Value);
            return results;
        }

        private static List<string> StBroken(Dictionary<string, string> baseline, Dictionary<string, string> now, string good)
        {
            return baseline.Where(b => b.Value.StartsWith(good, StringComparison.Ordinal)).Select(b => b.Key)
                .Where(k => !now.ContainsKey(k) || !now[k].StartsWith(good, StringComparison.Ordinal)).OrderBy(k => k).ToList();
        }

        // What Windows wrote to its certificate log lately: event, level, passed or failed.
        private void StCapi2Levels()
        {
            try
            {
                Dictionary<string, int> tally = new Dictionary<string, int>();
                EventLogQuery q = new EventLogQuery(Capi2, PathType.LogName, "*[System[(EventID=11 or EventID=30)]]") { ReverseDirection = true };
                using (EventLogReader reader = new EventLogReader(q))
                {
                    int n = 0;
                    for (EventRecord r = reader.ReadEvent(); r != null && n < 1500; r = reader.ReadEvent(), n++)
                        using (r)
                        {
                            string xml = r.ToXml();
                            Denial d = null;
                            try { d = DenialParser.Parse(xml, true); } catch (Exception) { }
                            string key = "event " + r.Id + " level " + r.Level + " " + (d == null ? "unparsed" : d.Ok ? "passed" : "FAILED");
                            int have; tally.TryGetValue(key, out have); tally[key] = have + 1;
                        }
                }
                foreach (KeyValuePair<string, int> k in tally.OrderBy(x => x.Key)) StNote("CAPI2 last 1500: " + k.Key + "  x" + k.Value);
            }
            catch (Exception ex) { StNote("CAPI2 levels: " + ex.Message); }
        }

        // ---- the run ---------------------------------------------------------------------------------------------

        private void StRun()
        {
            StLine("kisib self-test, " + AboutText.Version);
            string product = "?";
            try { using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")) product = k.GetValue("ProductName") + " " + k.GetValue("DisplayVersion") + " build " + k.GetValue("CurrentBuild") + "." + k.GetValue("UBR"); } catch (Exception) { }
            StLine("Windows: " + product + "   .NET " + Environment.Version + "   64-bit process: " + Environment.Is64BitProcess);
            StLine("administrator: " + Elevation.IsElevated + "   interactive: " + SystemInformation.UserInteractive + "   screen: " + Screen.PrimaryScreen.Bounds.Width + "x" + Screen.PrimaryScreen.Bounds.Height +
                "   user: " + Environment.UserName + "   root auto-download off: " + RootAutoUpdateOff());
            StLine("stores at start   " + StCounts());
            try { using (EventLogConfiguration c = new EventLogConfiguration(Capi2)) StLine("CAPI2 log at start: enabled=" + c.IsEnabled + " max=" + c.MaximumSizeInBytes); } catch (Exception ex) { StLine("CAPI2 config: " + ex.Message); }

            double firstScan = 0;
            StStep("first scan", delegate
            {
                Stopwatch w = Stopwatch.StartNew();
                StWait("first scan", 240, () => snapshot != null && !scanning && !rescanPending);
                firstScan = w.Elapsed.TotalSeconds;
                StNote(StUi(() => snapshot.Certificates.Count + " certificates, " + snapshot.PhysicalCount + " physical stores, " + snapshot.Errors.Count + " errors, " + snapshot.Blocked.Count + " blocked"));
                StNote("status bar: " + StUi(() => status.Text));
                StNote("window title: " + StUi(() => Text));
            });
            StSum("first scan (no lists yet): about " + firstScan.ToString("0.0") + "s after the window opened");
            StShot("main-first-open", this);
            StDump("main-first-open", this);

            StStep("menus as text", delegate
            {
                StringBuilder t = new StringBuilder("MAIN MENU\r\n");
                StUi(delegate { StDumpMenu(Menu.MenuItems, t, 1); t.AppendLine("\r\nTRAY MENU"); StDumpMenu(tray.ContextMenu.MenuItems, t, 1); t.AppendLine("\r\nCERTIFICATE LIST RIGHT-CLICK"); StDumpMenu(list.ContextMenu.MenuItems, t, 1); });
                File.WriteAllText(Path.Combine(SelfTestFolder, "menus.txt"), t.ToString(), new UTF8Encoding(false));
            });

            // The lists a fresh kisib downloads.
            double msSeconds = 0, ccSeconds = 0;
            StStep("download Microsoft's root list (certutil)", delegate
            {
                Stopwatch w = Stopwatch.StartNew();
                string error = MicrosoftList.Update();
                msSeconds = w.Elapsed.TotalSeconds;
                if (error != null) throw new InvalidOperationException(error);
                StNote("microsoft-root-list.sst " + new FileInfo(MicrosoftList.SstPath).Length / 1024 + " KB in " + msSeconds.ToString("0.0") + "s");
            });
            StStep("download CCADB (every public CA certificate)", delegate
            {
                Stopwatch w = Stopwatch.StartNew();
                string report = Ccadb.Update();
                ccSeconds = w.Elapsed.TotalSeconds;
                StNote(report.Trim().Replace("\r\n", " / ") + " in " + ccSeconds.ToString("0.0") + "s");
                if (!report.Contains(": ok")) throw new InvalidOperationException("CCADB download failed: " + report);
            });
            double listScan = 0, warmScan = 0;
            StStep("scan with the lists", delegate { listScan = StScan("lists just downloaded"); });
            StStep("scan again (warm)", delegate { warmScan = StScan("warm"); });
            using (Process me = Process.GetCurrentProcess())
                StSum("scan with lists: first " + listScan.ToString("0.0") + "s, again " + warmScan.ToString("0.0") + "s; " + StUi(() => snapshot.Certificates.Count) + " certificates in memory; kisib uses " + me.WorkingSet64 / 1024 / 1024 + " MB RAM, " + me.TotalProcessorTime.TotalSeconds.ToString("0") + "s CPU so far");
            StShot("main-with-lists", this);

            // Everything other programs need, before kisib blocks anything.
            Dictionary<string, string> baseSites = null, baseFiles = null;
            StStep("other programs before any block", delegate { baseSites = StProbe("0-baseline"); baseFiles = StSignedFiles("0-baseline"); });
            StSum("before any block: " + baseSites.Values.Count(v => v.StartsWith("OK", StringComparison.Ordinal)) + "/" + baseSites.Count + " sites fine, " + baseFiles.Values.Count(v => v.StartsWith("Valid|", StringComparison.Ordinal)) + "/" + baseFiles.Count + " signed files valid");

            // Every window, as it opens on a fresh install.
            StUi(delegate { leftTabs.SelectedTab = groupsTab; });
            Thread.Sleep(500);
            StShot("main-groups-tab", this); StDump("main-groups-tab", this);
            StUi(delegate { leftTabs.SelectedTab = watchTab; });
            Thread.Sleep(300);
            StShot("main-watching-tab", this);
            StUi(delegate { leftTabs.SelectedTab = storesTab; });
            StWindow("tools-page", ShowToolsPage);
            StWindow("bloc-board", OpenBlocBoard);
            StWindow("live-map-empty", OpenLiveMap);
            StWindow("denials-empty", ShowDenials);
            StWindow("rules", ShowRules);
            StWindow("never-block-list", ShowAllowed);
            StWindow("standings", ShowStandings);
            StWindow("programs", ShowPrograms);
            StWindow("reroute-check", ShowReroute);
            StWindow("routes", ShowRoutes);
            StWindow("incident-check", ShowIncidents);
            StWindow("my-tags", ShowMyTags);
            StWindow("trusted-categories", ShowCategories);
            StWindow("required-for-app", ShowRequiredForApp);
            StWindow("windows-certificates-live", ShowLedger);
            foreach (string kind in RepairKinds) { string k = kind; StWindow("repair-" + k, delegate { OpenRepair(k); }); }
            StWindow("about", ShowAbout);
            StWindow("block-history", ShowBlockHistory);
            StWindow("summary", ShowSummary);
            StWindow("store-errors", ShowStoreErrors);

            // Blocs, one at a time, for the whole PC: what each one adds, what it breaks, and whether unblock puts everything back.
            string before = StCounts();
            StLine("stores before blocs   " + before);
            int baseLm = StStoreCount("Disallowed", X509Location.LocalMachine), baseCu = StStoreCount("Disallowed", X509Location.CurrentUser);
            List<string> blocs = StUi(() => groups.Tags.Select(g => g.Label).ToList());
            StNote("blocs in this build: " + String.Join(" ", blocs.ToArray()));
            X509Location scope = Elevation.IsElevated ? X509Location.LocalMachine : X509Location.CurrentUser;
            foreach (string blocLabel in blocs)
            {
                string label = blocLabel;
                StStep("bloc " + label + ": block, check other programs, unblock", delegate
                {
                    GroupNode g = StUi(() => groups.Tags.First(x => x.Label == label));
                    int members = g.Members.Count;
                    BlockRules.Add(g.Key, g.Label, scope);
                    double s = StScan("rule " + label);
                    int lm = StStoreCount("Disallowed", X509Location.LocalMachine), cu = StStoreCount("Disallowed", X509Location.CurrentUser);
                    StNote(label + ": " + members + " certificates in the bloc; Disallowed now whole PC " + lm + " (+" + (lm - baseLm) + "), you " + cu + " (+" + (cu - baseCu) + "); rules: " + StUi(() => ruleStatus));
                    Dictionary<string, string> sites = StProbe("bloc-" + StSafe(label)), files = StSignedFiles("bloc-" + StSafe(label));
                    List<string> brokenSites = StBroken(baseSites, sites, "OK"), brokenFiles = StBroken(baseFiles, files, "Valid|");
                    StSum("bloc " + label + " blocked (" + (lm - baseLm + cu - baseCu) + " entries, " + s.ToString("0") + "s): breaks " + brokenSites.Count + " sites [" + String.Join(", ", brokenSites.ToArray()) + "] and " + brokenFiles.Count + " signed files [" + String.Join(", ", brokenFiles.ToArray()) + "]");
                    Thread.Sleep(2500);   // let the refusals arrive
                    StUi(delegate { UnblockGroups(new List<GroupNode> { groups.Tags.First(x => x.Label == label) }); });
                    StScan("unblock " + label);
                    int lm2 = StStoreCount("Disallowed", X509Location.LocalMachine), cu2 = StStoreCount("Disallowed", X509Location.CurrentUser);
                    StNote("after unblock: whole PC " + lm2 + ", you " + cu2 + "; said: " + StUi(() => lastSay));
                    if (lm2 != baseLm || cu2 != baseCu) { StSum("bloc " + label + ": UNBLOCK LEFT " + (lm2 - baseLm) + " whole-PC and " + (cu2 - baseCu) + " user entries behind"); baseLm = lm2; baseCu = cu2; }
                });
            }

            // All blocs at once, the way a real setup looks; then the watching side.
            Dictionary<string, string> allSites = null, allFiles = null;
            StStep("all blocs blocked together", delegate
            {
                foreach (GroupNode g in StUi(() => groups.Tags.ToList())) BlockRules.Add(g.Key, g.Label, scope);
                double s = StScan("all blocs");
                StNote("all blocs: " + StCounts());
                StNote("rules: " + StUi(() => ruleStatus));
                using (Process me = Process.GetCurrentProcess()) StNote("kisib: " + me.WorkingSet64 / 1024 / 1024 + " MB RAM, " + me.TotalProcessorTime.TotalSeconds.ToString("0") + "s CPU so far");
                allSites = StProbe("all-blocs"); allFiles = StSignedFiles("all-blocs");
                List<string> brokenSites = StBroken(baseSites, allSites, "OK"), brokenFiles = StBroken(baseFiles, allFiles, "Valid|");
                StSum("ALL blocs blocked (" + s.ToString("0") + "s scan): breaks " + brokenSites.Count + "/" + baseSites.Count + " sites [" + String.Join(", ", brokenSites.ToArray()) + "] and " + brokenFiles.Count + "/" + baseFiles.Count + " signed files [" + String.Join(", ", brokenFiles.ToArray()) + "]");
                Thread.Sleep(4000);
            });
            StShot("main-all-blocs", this);
            StCapi2Levels();
            StStep("refusals reached kisib", delegate
            {
                int n = StUi(() => denials.Count(d => !d.Ok && !d.Noise));
                StNote("refusals kisib recorded: " + n + "; checks in memory: " + StUi(() => recentChecks.Count) + "; pop-ups on screen: " + StUi(() => toasts.Count));
                foreach (string line in StUi(() => denials.Where(d => !d.Ok).Reverse().Take(25).Select(d => d.Time.ToString("HH:mm:ss") + " " + Path.GetFileName(d.Program) + " -> " + d.Subject + "  " + d.Code + "  blockedBy=" + (d.BlockedBy ?? "-") + "  verdict=" + d.Verdict + (d.Noise ? " (noise)" : "") + "  chain=" + String.Join(">", d.ChainNames.ToArray())).ToList()))
                    StNote("  " + line);
                if (n == 0) throw new InvalidOperationException("no refusal reached kisib although sites were refused");
            });
            foreach (DenialToast toast in StUi(() => toasts.ToList())) { StShot("pop-up", toast); break; }
            StWindow("live-map-with-refusals", OpenLiveMap);
            StWindow("denials-with-refusals", ShowDenials);
            StWindow("refusal-card", delegate { OpenRefusalCard(denials.LastOrDefault(d => !d.Ok && !d.Noise && d.BlockedBy != null) ?? denials.Last(d => !d.Ok)); });
            StWindow("bloc-board-all-blocked", OpenBlocBoard);
            StWindow("windows-certificates-live-all-blocked", ShowLedger);
            StWindow("required-for-app-after-checks", ShowRequiredForApp);
            StWindow("tools-page-all-blocked", ShowToolsPage);
            StStep("live map right-click menus as text", delegate
            {
                StringBuilder t = new StringBuilder();
                StUi(delegate
                {
                    OpenLiveMap();
                    foreach (MapNode n in liveMap.AllNodes().OrderBy(x => x.Column).ThenByDescending(x => x.Refused).GroupBy(x => x.Column + "|" + x.Refused + "|" + x.Blocked + "|" + (x.Placeholder != null)).Select(x => x.First()).Take(12))
                    {
                        t.AppendLine("\r\nRIGHT-CLICK on column " + n.Column + " box [" + n.Label + "] refused=" + n.Refused + " blocked=" + n.Blocked + (n.Placeholder != null ? " placeholder" : ""));
                        ContextMenu m = MapMenuPlus(n, null);
                        if (m != null) StDumpMenu(m.MenuItems, t, 1);
                    }
                    liveMap.Close();
                });
                File.AppendAllText(Path.Combine(SelfTestFolder, "menus.txt"), "\r\n\r\nLIVE MAP\r\n" + t, new UTF8Encoding(false));
            });

            // The switch: flip one refused site's blocked certificates to Trusted and see the site come back.
            StStep("flip a refused chain to Trusted", delegate
            {
                Denial d = StUi(() => denials.LastOrDefault(x => !x.Ok && !x.Noise && x.IsWeb && x.BlockedBy != null && StHosts.Contains(x.Site ?? x.Subject, StringComparer.OrdinalIgnoreCase)));
                if (d == null) { StNote("no refused test site with a block behind it; skipped"); return; }
                string host = d.Site ?? d.Subject;
                List<CertificateRecord> behind = StUi(() => BlockedBehind(d));
                StNote("flipping for " + host + ": " + String.Join(", ", behind.Select(c => c.SubjectShortName).ToArray()));
                StUi(delegate { TrustCerts(host, behind); });
                StScan("after Trusted");
                StNote("said: " + StUi(() => lastSay));
                File.WriteAllLines(Path.Combine(SelfTestFolder, "hosts.txt"), new string[] { host });
                string outFile = Path.Combine(SelfTestFolder, "probe-after-trusted.txt");
                using (Process p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--probe \"" + Path.Combine(SelfTestFolder, "hosts.txt") + "\" \"" + outFile + "\"") { UseShellExecute = false, CreateNoWindow = true })) p.WaitForExit(60000);
                string line = File.Exists(outFile) ? File.ReadAllText(outFile).Trim() : "(no answer)";
                StNote("after Trusted: " + line.Replace("\t", "  |  "));
                StSum("Trusted switch on " + host + ": " + (line.Contains("\tOK") ? "site works again" : "STILL REFUSED: " + line.Replace("\t", " | ")));
                if (!line.Contains("\tOK")) throw new InvalidOperationException("the site is still refused after Trusted");
            });

            // Unblock everything: is the PC back where it started?
            StStep("unblock every bloc", delegate
            {
                StUi(delegate { UnblockGroups(groups.Tags.ToList()); });
                StScan("unblock all");
                StNote("said: " + StUi(() => lastSay));
                StNote("after unblocking all: " + StCounts() + "   (before blocs: " + before + ")");
                Dictionary<string, string> sites = StProbe("after-unblock"), files = StSignedFiles("after-unblock");
                List<string> brokenSites = StBroken(baseSites, sites, "OK"), brokenFiles = StBroken(baseFiles, files, "Valid|");
                StSum("after unblocking everything: still broken " + brokenSites.Count + " sites [" + String.Join(", ", brokenSites.ToArray()) + "], " + brokenFiles.Count + " signed files [" + String.Join(", ", brokenFiles.ToArray()) + "]; " + StCounts());
            });

            // A PC where Windows can't download roots by itself (a firewall in the way): take a root out, switch Windows' own
            // download off, and see whether kisib puts the root back when a program needs it.
            StStep("missing root with Windows' own download off", delegate
            {
                if (!Elevation.IsElevated) { StNote("not administrator; skipped"); return; }
                string host = "letsencrypt.org", rootSha1 = "CABD2A79A1076A31F21D253635CB039D4329A5E8";   // ISRG Root X1
                using (RegistryKey k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot")) k.SetValue("DisableRootAutoUpdate", 1, RegistryValueKind.DWord);
                int removed = 0;
                foreach (string store in new string[] { "Root", "AuthRoot" })
                    foreach (X509Location where in new X509Location[] { X509Location.LocalMachine, X509Location.CurrentUser })
                        try { using (OwnStore s = OwnStore.Open(store, where, true)) if (s.Remove(rootSha1)) removed++; } catch (Exception ex) { StNote(store + "/" + where + ": " + ex.Message); }
                StNote("took ISRG Root X1 out of " + removed + " stores; Windows' own root download switched off");
                StScan("root removed");
                File.WriteAllLines(Path.Combine(SelfTestFolder, "hosts.txt"), new string[] { host });
                string a = Path.Combine(SelfTestFolder, "probe-missing-root-1.txt"), b = Path.Combine(SelfTestFolder, "probe-missing-root-2.txt");
                using (Process p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--probe \"" + Path.Combine(SelfTestFolder, "hosts.txt") + "\" \"" + a + "\"") { UseShellExecute = false, CreateNoWindow = true })) p.WaitForExit(60000);
                string first = File.Exists(a) ? File.ReadAllText(a).Trim() : "(no answer)";
                StNote("first try:  " + first.Replace("\t", "  |  "));
                Thread.Sleep(9000);   // refusal arrives, kisib reacts, rescans
                StWait("scan after kisib's reaction", 120, () => !scanning && !rescanPending);
                StNote("kisib said: " + StUi(() => lastSay));
                using (Process p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--probe \"" + Path.Combine(SelfTestFolder, "hosts.txt") + "\" \"" + b + "\"") { UseShellExecute = false, CreateNoWindow = true })) p.WaitForExit(60000);
                string second = File.Exists(b) ? File.ReadAllText(b).Trim() : "(no answer)";
                StNote("second try: " + second.Replace("\t", "  |  "));
                StSum("missing root, Windows' download off: first try " + (first.Contains("\tOK") ? "worked (Windows still had it somewhere)" : "refused") + ", second try " + (second.Contains("\tOK") ? "WORKS (kisib put the root back)" : "STILL REFUSED"));
                try { using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot", true)) if (k != null) k.DeleteValue("DisableRootAutoUpdate", false); } catch (Exception) { }
                if (!first.Contains("\tOK") && !second.Contains("\tOK")) throw new InvalidOperationException("kisib did not put the missing root back");
            });
            StWindow("live-map-end", OpenLiveMap);
            StShot("main-end", this);

            using (Process me = Process.GetCurrentProcess())
                StSum("end: kisib uses " + me.WorkingSet64 / 1024 / 1024 + " MB RAM, " + me.TotalProcessorTime.TotalSeconds.ToString("0") + "s CPU over " + stClock.Elapsed.TotalSeconds.ToString("0") + "s; " + StUi(() => recentChecks.Count) + " checks seen");
            try { using (EventLogConfiguration c = new EventLogConfiguration(Capi2)) StSum("CAPI2 log at end: enabled=" + c.IsEnabled); } catch (Exception) { }
            string crash = Storage.File(Storage.CrashLog);
            if (File.Exists(crash)) { StSum("CRASH LOG has entries (copied next to this log)"); File.Copy(crash, Path.Combine(SelfTestFolder, "CRASH LOG.txt"), true); stFailed++; }
            try { foreach (string f in new string[] { Storage.BlockHistory, Storage.Rules, Storage.AllowedList, Storage.Denials, Storage.Settings }) if (File.Exists(Storage.File(f))) File.Copy(Storage.File(f), Path.Combine(SelfTestFolder, "lists - " + f), true); } catch (Exception) { }
        }

        private static string StSafe(string label)
        {
            StringBuilder t = new StringBuilder();
            foreach (char c in label) t.Append(((int)c).ToString("X"));
            return t.ToString();
        }
    }
}
