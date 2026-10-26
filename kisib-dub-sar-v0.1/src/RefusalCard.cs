using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // The card behind a refusal: who asked (and, for lsass/svchost, which app is really behind it), why it was refused,
    // and every way out: allow for a while, allow always, reroute, keep blocked, quiet the site.
    internal sealed partial class ExplorerForm
    {
        internal void OpenRefusalCard(Denial d)
        {
            if (d == null) return;
            if (d.Verdict == null) Annotate(d);
            ClearTrayBadge();
            // Big, friendly and nothing pre-selected (user, 2026-10-26: the text opened selected and hard to read).
            Form f = new Form { Text = "Refused: " + d.Subject + " — " + d.Time.ToString("HH:mm:ss"), Size = new Size(860, 620), Font = new Font("Comic Sans MS", 10F, FontStyle.Bold) };
            string program = (WhoIsWho.Program(d.Program) ?? d.Program) + (d.Service != null ? "   (service: " + d.Service + ")" : "");
            bool service = IsBroker(d.Program);
            Label head = new Label { Dock = DockStyle.Top, Height = 84, Padding = new Padding(12, 10, 12, 0), Font = new Font("Comic Sans MS", 11.5F, FontStyle.Bold),
                Text = program + "\r\nwas refused  " + d.Subject + "   at " + d.Time.ToString("HH:mm:ss") + "\r\n" + VerdictWord(d) + "   " + ShortReason(d.Reason) };
            head.ForeColor = VerdictColor(d.Verdict);
            Label behind = new Label { Dock = DockStyle.Top, Height = 50, Padding = new Padding(12, 6, 12, 0), BackColor = Color.FromArgb(245, 245, 238), Font = new Font("Comic Sans MS", 10F),
                Text = service ? "App behind " + d.Program + ": looking for the open connection..." : "Program: " + program };
            string explained = CleanText(ExplainDenial(d));
            if (d.Who != null && explained.StartsWith(CleanText(d.Who), StringComparison.Ordinal)) explained = explained.Substring(CleanText(d.Who).Length).TrimStart('\r', '\n');
            TextBox why = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true, BorderStyle = BorderStyle.None, TabStop = false,
                Font = new Font("Comic Sans MS", 11F), BackColor = Color.White, ForeColor = Color.FromArgb(40, 40, 48), Text = explained };
            Panel whyPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 10, 6), BackColor = Color.White };
            whyPanel.Controls.Add(why);

            List<CertificateRecord> blocked = CertificatesBehind(d);
            List<CertificateRecord> missing;
            List<CertificateRecord> route = DenialRoute(d, out missing);
            FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 76, Padding = new Padding(6), WrapContents = true };
            Func<string, bool, Button> button = delegate(string text, bool enabled)
            { Button b = new Button { Text = text, AutoSize = true, Height = 30, Enabled = enabled, Margin = new Padding(3) }; actions.Controls.Add(b); return b; };
            Button allow = AllowButton("Allow", delegate { return TargetFor(d); });
            allow.Margin = new Padding(3); allow.Height = 30; allow.Enabled = blocked.Count > 0;
            actions.Controls.Add(allow);
            Button around = button(route == null ? "Route around: no other path" : missing.Count == 0 ? "Route around: already on PC" : "Route around...", route != null && missing.Count > 0);
            Image spiral = EmojiImages.For(0x1F300);
            if (spiral != null) { around.Image = new Bitmap(spiral, new Size(20, 20)); around.TextImageRelation = TextImageRelation.ImageBeforeText; around.ImageAlign = ContentAlignment.MiddleLeft; }
            around
                .Click += delegate { InstallRoute(missing, d.Subject); };
            button("Get what it asked for", true).Click += delegate { GetRequested(d); };
            CertificateRecord shown = blocked.FirstOrDefault() ?? d.ChainSha1.Select(FindBySha1).FirstOrDefault(x => x != null);
            if (shown != null) button("Where Windows keeps it", true).Click += delegate { ShowWhereInWindows(shown); };
            if (IsRevocationRefusal(d)) button("Check revocation servers", true).Click += delegate { CheckRevocation(d); };
            button("Fix it on Windows' side", true).Click += delegate { ShowWindowsSideFix(d.Site ?? d.Subject, d.ChainSha1.Take(1), d); };
            if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase))
                button("Get " + MissingRootName(d) + " from Microsoft", true).Click += delegate { FetchRoot(d); };
            if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase))
                button("Repair: Get online...", true).Click += delegate { RepairSeals("Get online", s => s.Set == "online" || s.Set == "microsoft", "The roots most websites hang under, carried inside kisib."); };
            button("Keep blocked", true).Click += delegate { f.Close(); };
            button("Quiet this site 1 hour", true).Click += delegate { QuietSites.Quiet(d.Subject, TimeSpan.FromHours(1)); f.Close(); };
            button("Show certificate in list", blocked.Count > 0 || d.ChainSha1.Count > 0).Click += delegate
            {
                CertificateRecord c = blocked.FirstOrDefault() ?? d.ChainSha1.Select(FindBySha1).FirstOrDefault(x => x != null);
                if (c == null) return;
                RestoreFromTray(); leftTabs.SelectedTab = storesTab;
                if (tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0];
                findIssuer.Text = c.Sha256;
            };
            button("Copy all", true).Click += delegate { CopyText(head.Text + "\r\n" + behind.Text + "\r\n\r\n" + why.Text); };
            if (blocked.Count == 0)
                actions.Controls.Add(new Label { AutoSize = true, Padding = new Padding(6, 9, 0, 0), ForeColor = SystemColors.GrayText,
                    Text = "Not caused by one of your blocks, so there is nothing to allow; see why above." });

            f.Controls.Add(whyPanel); f.Controls.Add(behind); f.Controls.Add(head); f.Controls.Add(actions);
            f.Shown += delegate { why.SelectionStart = 0; why.SelectionLength = 0; if (actions.Controls.Count > 0) f.ActiveControl = actions.Controls[0]; };
            ShowTool(f, "refusal:" + d.Time.Ticks + ":" + d.Subject);

            if (!service) return;
            Thread worker = new Thread(delegate()
            {
                string found;
                try { found = AppBehind(d); } catch (Exception ex) { found = "Could not look: " + ex.Message; }
                Post(delegate { if (!behind.IsDisposed) behind.Text = found; });
            });
            worker.IsBackground = true; worker.Name = "App behind refusal"; worker.Start();
        }

        private static bool IsBroker(string program)
        {
            string name = Path.GetFileName(program ?? "").ToLowerInvariant();
            return name == "lsass.exe" || name == "svchost.exe" || name.Length == 0;
        }

        private const string ConnectionScript = @"
$ErrorActionPreference='SilentlyContinue'
$ips = $env:KISIB_IPS -split ','
$procs=@{}; Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId]=$_ }
$svcs=@{}; Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { $k=[int]$_.ProcessId; $v=$_.Name + ' (' + $_.DisplayName + ')'; if($svcs.ContainsKey($k)){ $svcs[$k]+='; '+$v } else { $svcs[$k]=$v } }
Get-NetTCPConnection | Where-Object { $ips -contains [string]$_.RemoteAddress } | ForEach-Object {
  $p=$procs[[int]$_.OwningProcess]
  '{0}|{1}|{2}|{3}|{4}' -f $_.OwningProcess, $(if($p){$p.Name}else{'PID '+$_.OwningProcess}), $(if($p){$p.ExecutablePath}else{''}), $svcs[[int]$_.OwningProcess], [string]$_.State
} | Sort-Object -Unique
";

        // lsass.exe and svchost.exe check certificates for other programs. The site in the refusal is matched
        // against open connections right now to name the program actually talking to it [to test].
        private static string AppBehind(Denial d)
        {
            string host = (d.Subject ?? "").Trim();
            if (host.StartsWith("*.", StringComparison.Ordinal)) host = host.Substring(2);
            if (host.Length == 0 || host.Contains(" ") || !host.Contains(".")) return "This refusal names no site, so there is no connection to match. Windows only logs " + d.Program + ".";
            List<string> ips = new List<string>();
            foreach (string h in new string[] { host, "www." + host })
                try { ips.AddRange(Dns.GetHostAddresses(h).Select(a => a.ToString())); } catch (Exception) { }
            ips = ips.Distinct().ToList();
            if (ips.Count == 0) return "Could not look up " + host + " right now, so no connection could be matched.";
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(ConnectionScript)))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.EnvironmentVariables["KISIB_IPS"] = String.Join(",", ips.ToArray());
            string output;
            using (Process p = Process.Start(info))
            {
                output = p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                if (!p.WaitForExit(30000)) { try { p.Kill(); } catch (InvalidOperationException) { } }
            }
            List<string> lines = new List<string>();
            foreach (string line in output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] f = line.Split('|');
                if (f.Length < 5) continue;
                string exe = f[2].Length > 0 ? f[2] : f[1];
                string name = WhoIsWho.Program(exe) ?? Path.GetFileName(exe);
                lines.Add(name + (f[3].Length > 0 ? "  → " + f[3] : "") + "   (PID " + f[0] + ", " + f[4] + ")");
            }
            if (lines.Count == 0) return "No open connection to " + host + " right now (it may have closed). Open this card within a few seconds of the refusal for a match [to test].";
            return "App behind " + d.Program + " (open connection to " + host + "):\r\n" + String.Join("\r\n", lines.Take(3).ToArray());
        }
    }
}
