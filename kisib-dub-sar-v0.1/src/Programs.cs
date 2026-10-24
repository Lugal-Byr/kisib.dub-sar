using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // Programs view: which program listens or talks on the network, who signed it, and which firewall rule lets it in.
    // Collected with Windows' own PowerShell cmdlets (Get-NetTCPConnection, Get-AuthenticodeSignature, Get-NetFirewallRule).
    // Local only: nothing is sent anywhere.
    internal sealed class ProgramInfo
    {
        internal int Pid;
        internal string Program, Service, Exe, SigStatus, Signer, SignerIssuer, SignerThumb, IsOS;
        internal readonly SortedSet<string> Listening = new SortedSet<string>(StringComparer.Ordinal);
        internal readonly SortedSet<string> Remotes = new SortedSet<string>(StringComparer.Ordinal);
        internal readonly SortedSet<string> Firewall = new SortedSet<string>(StringComparer.Ordinal);
        internal string Flags = "", Verdict = "grey";
    }

    internal static class ProgramCollector
    {
        private const string Script = @"
$ErrorActionPreference='SilentlyContinue'
$procs=@{}; Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId]=$_ }
$svcs=@{}; Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { $k=[int]$_.ProcessId; if($svcs.ContainsKey($k)){ $svcs[$k]+=','+$_.Name } else { $svcs[$k]=$_.Name } }
$apps=@{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $apps[$_.InstanceID]=$_.Program }
$pf=@{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pf[$_.InstanceID]=($_.LocalPort -join ',') }
$rules=New-Object System.Collections.ArrayList
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -PolicyStore ActiveStore | ForEach-Object { [void]$rules.Add([pscustomobject]@{Name=$_.DisplayName;App=$apps[$_.InstanceID];Port=$pf[$_.InstanceID]}) }
$sig=@{}
$rows = foreach($c in (Get-NetTCPConnection -State Listen,Established)) {
  $p=$procs[[int]$c.OwningProcess]; $exe=$p.ExecutablePath
  if($exe -and -not $sig.ContainsKey($exe)){ $sig[$exe]=Get-AuthenticodeSignature -LiteralPath $exe }
  $s=$null; if($exe){ $s=$sig[$exe] }
  $fw=''
  if([string]$c.State -eq 'Listen'){
    $fw=(@($rules | Where-Object { ($_.App -and $exe -and $_.App -ieq $exe) -or (($_.Port -split ',') -contains [string]$c.LocalPort) }) | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; '
  }
  $name = if($p){ $p.Name } elseif([int]$c.OwningProcess -eq 4){ 'System' } else { 'PID ' + $c.OwningProcess }
  [pscustomobject]@{ PID=$c.OwningProcess; Program=$name; Service=$svcs[[int]$c.OwningProcess]; EXE=$exe; State=[string]$c.State;
    LocalAddress=$c.LocalAddress; LocalPort=$c.LocalPort; RemoteAddress=$c.RemoteAddress; RemotePort=$c.RemotePort;
    SigStatus=$(if($s){[string]$s.Status}else{'Unavailable'});
    Signer=$(if($s -and $s.SignerCertificate){$s.SignerCertificate.GetNameInfo('SimpleName',$false)}else{''});
    SignerIssuer=$(if($s -and $s.SignerCertificate){$s.SignerCertificate.Issuer}else{''});
    SignerThumb=$(if($s -and $s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{''});
    IsOS=$(if($s){[string]$s.IsOSBinary}else{''}); Firewall=$fw }
}
$rows | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding UTF8 -FilePath $env:KISIB_OUT
";

        internal static List<ProgramInfo> Collect(out string error)
        {
            error = null;
            string output = Path.Combine(Path.GetTempPath(), "kisib-programs-" + Guid.NewGuid().ToString("N") + ".csv");
            try
            {
                ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                    "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Script)))
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
                info.EnvironmentVariables["KISIB_OUT"] = output;
                using (Process p = Process.Start(info))
                {
                    string err = p.StandardError.ReadToEnd(); p.StandardOutput.ReadToEnd();
                    if (!p.WaitForExit(180000)) { try { p.Kill(); } catch (InvalidOperationException) { } error = "Timed out after 3 minutes."; return new List<ProgramInfo>(); }
                    if (!File.Exists(output)) { error = "PowerShell produced no output. " + err; return new List<ProgramInfo>(); }
                }
                List<string[]> rows = GroupCatalog.ReadCsv(output, 64L * 1024 * 1024);
                if (rows.Count < 1) return new List<ProgramInfo>();
                Dictionary<string, int> h = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < rows[0].Length; i++) h[rows[0][i].Trim().TrimStart('﻿')] = i;
                Func<string[], string, string> cell = delegate(string[] r, string name) { int i; return h.TryGetValue(name, out i) && i < r.Length ? r[i].Trim() : ""; };
                Dictionary<int, ProgramInfo> byPid = new Dictionary<int, ProgramInfo>();
                foreach (string[] r in rows.Skip(1))
                {
                    int pid; if (!Int32.TryParse(cell(r, "PID"), out pid)) continue;
                    ProgramInfo pi;
                    if (!byPid.TryGetValue(pid, out pi))
                    {
                        pi = new ProgramInfo { Pid = pid, Program = cell(r, "Program"), Service = cell(r, "Service"), Exe = cell(r, "EXE"), SigStatus = cell(r, "SigStatus"),
                            Signer = cell(r, "Signer"), SignerIssuer = cell(r, "SignerIssuer"), SignerThumb = cell(r, "SignerThumb"), IsOS = cell(r, "IsOS") };
                        byPid.Add(pid, pi);
                    }
                    string local = cell(r, "LocalAddress"), port = cell(r, "LocalPort");
                    if (cell(r, "State") == "Listen") pi.Listening.Add(port + (local == "0.0.0.0" || local == "::" ? " (all addresses)" : local == "127.0.0.1" || local == "::1" ? " (this PC only)" : " on " + local));
                    else pi.Remotes.Add(cell(r, "RemoteAddress") + ":" + cell(r, "RemotePort"));
                    foreach (string f in cell(r, "Firewall").Split(new string[] { "; " }, StringSplitOptions.RemoveEmptyEntries)) pi.Firewall.Add(f);
                }
                return byPid.Values.ToList();
            }
            catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; return new List<ProgramInfo>(); }
            finally { try { File.Delete(output); } catch (IOException) { } }
        }
    }

    internal sealed partial class ExplorerForm
    {
        private List<ProgramInfo> programs = new List<ProgramInfo>();

        private void InitializePrograms(MenuItem watch, FlowLayoutPanel toolbar)
        {
            watch.MenuItems.Add(new MenuItem("&Programs (who listens, who signed it)", delegate { ShowPrograms(); }, Shortcut.CtrlP));
            Button b = new Button { Text = "Programs", AutoSize = true }; b.Click += delegate { ShowPrograms(); };
            toolbar.Controls.Add(b);
        }

        private void Assess(ProgramInfo p)
        {
            List<string> flags = new List<string>();
            bool listening = p.Listening.Any(l => !l.Contains("this PC only"));
            bool valid = String.Equals(p.SigStatus, "Valid", StringComparison.OrdinalIgnoreCase);
            if (!valid && p.Exe.Length > 0) flags.Add(listening ? "NOT VALIDLY SIGNED & LISTENING" : "signature: " + p.SigStatus);
            if (snapshot != null && p.SignerThumb.Length > 0)
            {
                HashSet<string> blocked = GroupCatalog.BlockedIdentities(snapshot);
                CertificateRecord signer = FindBySha1(p.SignerThumb);
                if (signer != null && blocked.Contains(signer.Identity)) flags.Add("SIGNED BY A CERTIFICATE YOU BLOCKED");
                CertificateRecord issuer = snapshot.Certificates.Values.FirstOrDefault(c => String.Equals(c.Subject, p.SignerIssuer, StringComparison.OrdinalIgnoreCase));
                if (issuer != null)
                {
                    if (blocked.Contains(issuer.Identity)) flags.Add("signer's CA is blocked: " + issuer.SubjectShortName);
                    string tags = TagsOf(issuer); if (tags.Length > 0) flags.Add("signer's CA tags: " + tags);
                }
            }
            string owner = WhoIsWho.Owner(p.Signer) ?? WhoIsWho.Owner(p.SignerIssuer);
            if (listening && valid && owner == null) flags.Add("signer not in your who-is-who list");
            p.Flags = String.Join("; ", flags.ToArray());
            p.Verdict = flags.Any(f => f.Contains("BLOCKED") || f.Contains("NOT VALIDLY") || f.Contains("is blocked")) ? "red" :
                flags.Count > 0 ? "yellow" : WhoIsWho.Program(p.Exe.Length > 0 ? p.Exe : p.Program + ".exe") != null ? "green" : "grey";
        }

        private string ProgramText(ProgramInfo p)
        {
            StringBuilder t = new StringBuilder();
            string exeName = p.Exe.Length > 0 ? Path.GetFileName(p.Exe) : p.Program;
            t.AppendLine(WhoIsWho.Program(exeName) ?? WhoIsWho.Program(p.Program + ".exe") ?? exeName + " = (not in your who-is-who list)");
            t.AppendLine("   PID " + p.Pid + (p.Service.Length > 0 ? "   service: " + p.Service : "") + (p.Exe.Length > 0 ? "   " + p.Exe : ""));
            string owner = WhoIsWho.Owner(p.Signer) ?? WhoIsWho.Owner(p.SignerIssuer);
            t.AppendLine("   signed by   " + (p.Signer.Length > 0 ? p.Signer + " (" + p.SigStatus + ")" + (owner != null ? "  = " + owner : "") : p.SigStatus) +
                (p.SignerIssuer.Length > 0 ? "\r\n               issued by " + p.SignerIssuer : ""));
            if (p.Listening.Count > 0) t.AppendLine("   listening   port " + String.Join(", ", p.Listening.ToArray()));
            if (p.Firewall.Count > 0) t.AppendLine("   firewall    inbound allowed by: " + String.Join("; ", p.Firewall.ToArray()));
            if (p.Remotes.Count > 0) t.AppendLine("   talking to  " + String.Join(", ", p.Remotes.Take(12).ToArray()) + (p.Remotes.Count > 12 ? " +" + (p.Remotes.Count - 12) + " more" : ""));
            if (p.Flags.Length > 0) t.AppendLine("   FLAGS       " + p.Flags);
            return t.ToString();
        }

        private void ShowPrograms()
        {
            Form dialog = new Form { Text = "Programs — who listens, who talks, who signed it", Size = new Size(1250, 720), Font = Font, StartPosition = FormStartPosition.CenterParent };
            ListView grid = new ListView();
            SetupGrid(grid, new string[] { "Verdict", "Program = name = what it does", "PID", "Listening", "Talking to", "Signed by", "Signature", "Firewall in", "Flags" },
                new int[] { 70, 330, 55, 160, 90, 190, 70, 170, 300 });
            TextBox detail = new TextBox { Dock = DockStyle.Bottom, Height = 170, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9F), BackColor = SystemColors.Window };
            Label state = new Label { AutoSize = true, Padding = new Padding(6, 7, 0, 0) };
            FlowLayoutPanel bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(3) };
            Button refreshButton = new Button { Text = "Refresh", AutoSize = true };
            Button copyAll = new Button { Text = "Copy all as text", AutoSize = true };
            bar.Controls.AddRange(new Control[] { refreshButton, copyAll, state });
            Action fill = delegate
            {
                grid.BeginUpdate(); grid.Items.Clear();
                foreach (ProgramInfo p in programs.OrderBy(x => x.Verdict == "red" ? 0 : x.Verdict == "yellow" ? 1 : 2).ThenByDescending(x => x.Listening.Count).ThenBy(x => x.Program))
                {
                    string exeName = p.Exe.Length > 0 ? Path.GetFileName(p.Exe) : p.Program;
                    string who = WhoIsWho.Program(exeName) ?? WhoIsWho.Program(p.Program + ".exe") ?? exeName;
                    ListViewItem row = new ListViewItem(new string[] { "● " + p.Verdict, who + (p.Service.Length > 0 ? "  [" + p.Service + "]" : ""), p.Pid.ToString(),
                        String.Join(", ", p.Listening.ToArray()), p.Remotes.Count > 0 ? p.Remotes.Count + " connection" + (p.Remotes.Count == 1 ? "" : "s") : "",
                        p.Signer, p.SigStatus, String.Join("; ", p.Firewall.ToArray()), p.Flags }) { Tag = p, ForeColor = VerdictColor(p.Verdict) };
                    grid.Items.Add(row);
                }
                grid.EndUpdate();
            };
            Action collect = delegate
            {
                refreshButton.Enabled = false; state.Text = "Collecting with PowerShell (listening ports, connections, signatures, firewall rules)... can take up to a minute.";
                Thread worker = new Thread(delegate()
                {
                    string error; List<ProgramInfo> result = ProgramCollector.Collect(out error);
                    Post(delegate
                    {
                        if (dialog.IsDisposed) return;
                        programs = result; foreach (ProgramInfo p in programs) Assess(p);
                        fill(); refreshButton.Enabled = true;
                        state.Text = error ?? (programs.Count + " programs, " + programs.Count(p => p.Listening.Count > 0) + " listening, " + programs.Count(p => p.Verdict == "red") + " red. " +
                            (BlockEngine.IsElevated() ? "" : "Run as administrator to see system programs' paths and signatures."));
                    });
                });
                worker.IsBackground = true; worker.Start();
            };
            grid.SelectedIndexChanged += delegate { if (grid.SelectedItems.Count > 0) detail.Text = ProgramText((ProgramInfo)grid.SelectedItems[0].Tag); };
            refreshButton.Click += delegate { collect(); };
            copyAll.Click += delegate { CopyText(String.Join("\r\n", programs.Select(ProgramText).ToArray())); };
            dialog.Controls.Add(grid); dialog.Controls.Add(detail); dialog.Controls.Add(bar);
            dialog.Shown += delegate { if (programs.Count == 0) collect(); else { fill(); state.Text = programs.Count + " programs (press Refresh for now)."; } };
            dialog.Show(this);
        }
    }
}
