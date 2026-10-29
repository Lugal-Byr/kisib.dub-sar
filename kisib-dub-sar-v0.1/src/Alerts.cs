using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Xml;

namespace Kisib
{
    // A certificate check that failed anywhere on the PC, as Windows logged it in CAPI2.
    internal sealed class Denial
    {
        internal DateTime Time;
        internal string Program, Subject, Code, Reason, Flags, BlockedBy, Who, Category, Verdict;
        internal string Site, Policy, Service;   // server name the program asked for, which check Windows ran, the service inside svchost
        internal int ProcessId;
        internal int EventId;
        internal readonly List<string> ChainSha1 = new List<string>();    // leaf first, root last
        internal readonly List<string> ChainNames = new List<string>();
        internal bool Noise, Ok, Known, SideCheck;
        internal string Key { get { return (Site ?? Subject ?? "").Trim().TrimStart('*', '.').ToLowerInvariant(); } }
        internal IEnumerable<string> Keys
        {
            get
            {
                foreach (string n in new string[] { Site, Subject })
                    if (!String.IsNullOrEmpty(n)) yield return n.Trim().TrimStart('*', '.').ToLowerInvariant();
            }
        }
        // A website name (no spaces, has a dot) versus a signed file ("Microsoft Windows", "Microsoft Time-Stamp Service").
        internal bool IsWeb
        {
            get
            {
                if (Policy != null && Policy.IndexOf("SSL", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                if (Policy != null && Policy.IndexOf("AUTHENTICODE", StringComparison.OrdinalIgnoreCase) >= 0) return false;
                string n = (Site ?? Subject ?? "").Trim();
                return n.Length > 0 && n.IndexOf(' ') < 0 && n.IndexOf('.') > 0;
            }
        }
    }

    internal static class DenialParser
    {
        private static readonly Dictionary<string, string> Codes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "80092010", "CRYPT_E_REVOKED — revoked, or in a Disallowed store" },
            { "800B0111", "TRUST_E_EXPLICIT_DISTRUST — explicitly distrusted (Disallowed)" },
            { "800B0109", "CERT_E_UNTRUSTEDROOT — root not trusted" },
            { "800B010A", "CERT_E_CHAINING — chain could not be built" },
            { "800B0101", "CERT_E_EXPIRED — expired or not yet valid" },
            { "800B010F", "CERT_E_CN_NO_MATCH — name does not match the site" },
            { "800B0110", "CERT_E_WRONG_USAGE — not allowed for this purpose" },
            { "80092012", "CRYPT_E_NO_REVOCATION_CHECK — revocation could not be checked" },
            { "80092013", "CRYPT_E_REVOCATION_OFFLINE — revocation server unreachable" },
        };

        internal static Denial Parse(string xml) { return Parse(xml, false); }
        internal static Denial Parse(string xml, bool includeTrusted)
        {
            if (xml == null || xml.Length > 4 * 1024 * 1024) return null;
            XmlDocument doc = new XmlDocument { XmlResolver = null };
            using (XmlReader reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
                doc.Load(reader);
            string result = null;
            foreach (XmlElement e in doc.GetElementsByTagName("Result"))
            {
                string v = e.GetAttribute("value");
                if (v.Length > 0 && v.Trim('0').Length > 0) { result = v.ToUpperInvariant(); break; }
            }
            if (result == null && !includeTrusted) return null;
            Denial d = new Denial { Time = DateTime.Now, Code = "0x" + (result ?? "0"), Ok = result == null };
            foreach (XmlElement e in doc.GetElementsByTagName("EventAuxInfo")) { d.Program = e.GetAttribute("ProcessName"); break; }
            foreach (XmlElement e in doc.GetElementsByTagName("Execution")) { int pid; if (Int32.TryParse(e.GetAttribute("ProcessID"), out pid)) d.ProcessId = pid; break; }
            foreach (XmlElement e in doc.GetElementsByTagName("EventID")) { int id; if (Int32.TryParse(e.InnerText, out id)) d.EventId = id; break; }
            foreach (XmlElement e in doc.GetElementsByTagName("Policy")) { string t = e.GetAttribute("type"); if (t.Length > 0) { d.Policy = t; break; } }
            foreach (XmlElement e in doc.GetElementsByTagName("SSLAdditionalPolicyInfo")) { string n = e.GetAttribute("serverName"); if (n.Length > 0) { d.Site = n; break; } }
            // The certificate being checked is the first one; the chain is the ChainElement list in order (site, CAs, root).
            // Certificates under AdditionalStore are only what the program offered, not the chain, so they are left out.
            foreach (XmlElement e in doc.GetElementsByTagName("Certificate")) { d.Subject = e.GetAttribute("subjectName"); AddCert(d, e); break; }
            List<XmlElement> chain = doc.GetElementsByTagName("ChainElement").Cast<XmlElement>()
                .Select(el => el.GetElementsByTagName("Certificate").Cast<XmlElement>().FirstOrDefault()).Where(x => x != null).ToList();
            if (chain.Count > 0) { d.ChainSha1.Clear(); d.ChainNames.Clear(); foreach (XmlElement e in chain) AddCert(d, e); }
            List<string> flags = new List<string>();
            foreach (XmlElement e in doc.GetElementsByTagName("*"))
                if (e.LocalName.StartsWith("CERT_TRUST_", StringComparison.Ordinal) && !flags.Contains(e.LocalName)) flags.Add(e.LocalName);
            d.Flags = String.Join(" ", flags.ToArray());
            string reason;
            if (result == null) d.Reason = "trusted";
            else d.Reason = Codes.TryGetValue(result.TrimStart('0'), out reason) || Codes.TryGetValue(result, out reason) ? reason : "error " + d.Code;
            d.Noise = result != null && (result.EndsWith("92012", StringComparison.Ordinal) || result.EndsWith("92013", StringComparison.Ordinal));
            // An expired time-stamping certificate is normal: the timestamp is what keeps old signatures valid.
            if (result != null && result.EndsWith("B0101", StringComparison.Ordinal) && d.ChainNames.Concat(new[] { d.Subject ?? "" })
                .Any(n => n.IndexOf("Time-Stamp", StringComparison.OrdinalIgnoreCase) >= 0 || n.IndexOf("Timestamp", StringComparison.OrdinalIgnoreCase) >= 0 || n.IndexOf("TSA", StringComparison.Ordinal) >= 0))
            { d.Noise = true; d.Reason = "expired time-stamp certificate (normal for older signed files)"; }
            if (String.IsNullOrEmpty(d.Program)) d.Program = "[program not logged]";
            if (String.IsNullOrEmpty(d.Subject)) d.Subject = d.Site ?? "[subject not logged]";
            return d;
        }

        private static void AddCert(Denial d, XmlElement e)
        {
            string file = e.GetAttribute("fileRef");
            if (!file.EndsWith(".cer", StringComparison.OrdinalIgnoreCase)) return;
            string sha1 = file.Substring(0, file.Length - 4).ToUpperInvariant();
            if (sha1.Length != 40 || d.ChainSha1.Contains(sha1)) return;
            d.ChainSha1.Add(sha1); d.ChainNames.Add(e.GetAttribute("subjectName"));
        }

        // Plain words for the check Windows ran.
        internal static string PolicyWords(string policy)
        {
            if (String.IsNullOrEmpty(policy)) return "building the chain";
            string p = policy.ToUpperInvariant();
            if (p.Contains("MICROSOFT_ROOT")) return "Microsoft-root check (is the top a Microsoft root?)";
            if (p.Contains("SSL")) return "website check (TLS)";
            if (p.Contains("AUTHENTICODE")) return "signed-file check";
            if (p.Contains("BASE")) return "basic chain check";
            return policy;
        }
    }

    internal sealed partial class ExplorerForm
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct FLASHWINFO { public uint cbSize; public IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }
        [DllImport("user32.dll")] private static extern bool FlashWindowEx(ref FLASHWINFO info);

        private const string Capi2 = "Microsoft-Windows-CAPI2/Operational";
        private EventLogWatcher denialWatcher;
        private NotifyIcon tray;
        private readonly List<Denial> denials = new List<Denial>();
        private readonly MenuItem watchToggle = new MenuItem("&Watch for certificate denials");
        private string WatchOffFlag { get { return Storage.File("SETTING - watching is turned off.txt"); } }

        private void InitializeAlerts(MenuItem view)
        {
            view.MenuItems.Add(new MenuItem("-"));
            view.MenuItems.Add(watchToggle);
            view.MenuItems.Add(new MenuItem("Certificate &denials", delegate { ShowDenials(); }));
            watchToggle.Click += delegate
            {
                if (denialWatcher != null) { StopWatching(); try { Directory.CreateDirectory(Path.GetDirectoryName(WatchOffFlag)); File.WriteAllText(WatchOffFlag, "off"); } catch (IOException) { } }
                else { try { if (File.Exists(WatchOffFlag)) File.Delete(WatchOffFlag); } catch (IOException) { } StartWatching(true); }
            };
            tray = new NotifyIcon { Icon = AppIcon.Small ?? SystemIcons.Shield, Text = AboutText.Hover, Visible = true };
            tray.BalloonTipClicked += delegate { ShowDenials(); };
            tray.DoubleClick += delegate { RestoreFromTray(); };
            tray.MouseClick += delegate(object sender, MouseEventArgs e) { if (e.Button == MouseButtons.Left) RestoreFromTray(); };
            InitializeTrayMenu();
            Shown += delegate { if (!File.Exists(WatchOffFlag)) StartWatching(false); };
            FormClosed += delegate { StopWatching(); tray.Visible = false; tray.Dispose(); };
        }

        private void StartWatching(bool askedByUser)
        {
            try
            {
                using (EventLogConfiguration config = new EventLogConfiguration(Capi2))
                {
                    if (!config.IsEnabled)
                    {
                        if (!BlockEngine.IsElevated())
                        {
                            if (askedByUser) ShowText("Watch for certificate denials", "Windows' certificate log (CAPI2) is off. Run kisib as administrator once and turn this on; after that it works without admin.");
                            watchToggle.Checked = false; return;
                        }
                        config.IsEnabled = true; config.MaximumSizeInBytes = Math.Max(config.MaximumSizeInBytes, 16L * 1024 * 1024);
                        config.SaveChanges();
                    }
                }
                EventLogQuery query = new EventLogQuery(Capi2, PathType.LogName, "*[System[(EventID=11 or EventID=30)]]");
                denialWatcher = new EventLogWatcher(query);
                denialWatcher.EventRecordWritten += delegate(object sender, EventRecordWrittenEventArgs args)
                {
                    if (args.EventRecord == null) return;
                    Denial d = null;
                    try { using (EventRecord record = args.EventRecord) d = DenialParser.Parse(record.ToXml(), true); }
                    catch (Exception) { return; }
                    if (d != null) Post(delegate { HandleCheck(d); });
                };
                denialWatcher.Enabled = true;
                watchToggle.Checked = true;
            }
            catch (Exception ex)
            {
                StopWatching();
                if (askedByUser) ShowText("Watch for certificate denials", "Could not start: " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private void StopWatching()
        {
            if (denialWatcher != null) { try { denialWatcher.Enabled = false; denialWatcher.Dispose(); } catch (Exception) { } denialWatcher = null; }
            watchToggle.Checked = false;
        }

        // ---- Every check Windows logs comes through here -------------------------------------------

        private readonly List<Denial> held = new List<Denial>();
        private readonly Dictionary<string, DateTime> recentPass = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        private readonly System.Windows.Forms.Timer holdTimer = new System.Windows.Forms.Timer { Interval = 500 };

        private void HandleCheck(Denial d)
        {
            d.Service = ServiceNames.For(d.Program, d.ProcessId);
            if (d.Ok)
            {
                foreach (string k in d.Keys) recentPass[k] = d.Time;
                if (recentPass.Count > 2000) foreach (string k in recentPass.Where(x => (DateTime.Now - x.Value).TotalSeconds > 30).Select(x => x.Key).ToList()) recentPass.Remove(k);
                MapAdd(d); CheckAllowWatch(d);
                return;
            }
            // A refusal waits 2 seconds: Windows often runs a stricter side check that fails while the real check of the
            // same site passes in the same second. Those are folded into a grey "side check" instead of a red refusal.
            held.Add(d);
            if (!holdTimer.Enabled) { holdTimer.Tick -= ReleaseHeld; holdTimer.Tick += ReleaseHeld; holdTimer.Start(); }
        }

        private void ReleaseHeld(object sender, EventArgs e)
        {
            DateTime now = DateTime.Now;
            foreach (Denial d in held.Where(x => (now - x.Time).TotalSeconds >= 2).ToList())
            {
                held.Remove(d);
                DateTime passed = DateTime.MinValue;
                // Only a policy-only check (no chain of its own) saying "root not trusted", or a Microsoft-root check, is folded.
                // A failed chain, a wrong site name or a revoked certificate always stays a real refusal.
                bool sideKind = d.ChainSha1.Count <= 1 && (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase) ||
                    (d.Policy != null && d.Policy.IndexOf("MICROSOFT_ROOT", StringComparison.OrdinalIgnoreCase) >= 0));
                if (!d.Noise && sideKind && d.Keys.Any(k => recentPass.TryGetValue(k, out passed) && Math.Abs((passed - d.Time).TotalSeconds) <= 3))
                {
                    d.Noise = true; d.SideCheck = true;
                    d.Reason = "side check, went through: the same site passed at the same moment (" + PolicyWordsOrReason(d) + ")";
                }
                MapAdd(d); CheckAllowWatch(d);
                if (!d.SideCheck) { OnDenial(d); ProgramAllowOnRefusal(d); try { AutoTrustRoots(d); } catch (Exception ex) { CrashLog.Write("auto roots", ex); } }
            }
            if (held.Count == 0) holdTimer.Stop();
        }
        private static string PolicyWordsOrReason(Denial d) { return d.Policy != null ? DenialParser.PolicyWords(d.Policy) + ": " + d.Reason : d.Reason; }

        private void OnDenial(Denial d)
        {
            // Windows logs a failure from both chain building and policy; keep one per program/subject/code within 5 seconds.
            for (int i = denials.Count - 1; i >= 0 && (d.Time - denials[i].Time).TotalSeconds < 5; i--)
                if (denials[i].Program == d.Program && denials[i].Subject == d.Subject && denials[i].Code == d.Code) return;
            if (snapshot != null)
            {
                List<string> hits;
                try { hits = BlockedBehind(d).Select(c => c.SubjectShortName).Distinct().ToList(); }
                catch (Exception ex) { CrashLog.Write("refusal: blocked behind", ex); hits = new List<string>(); }
                if (hits.Count > 0) d.BlockedBy = String.Join(", ", hits.ToArray());
            }
            Annotate(d);
            denials.Add(d);
            SaveDenial(d);
            RefreshWatchTab(); UpdateIndicators();
            if (denialsRefresh != null) denialsRefresh();
            if (denials.Count > 2000) denials.RemoveAt(0);
            if (d.Noise) return;
            MarkTrayBadge(d.Verdict == "red");
            if (QuietMode || QuietSites.IsQuiet(d.Subject) || (d.Site != null && QuietSites.IsQuiet(d.Site)) || QuietSites.IsQuiet("program:" + Path.GetFileName(d.Program ?? ""))) return;
            if (d.Verdict == "yellow")
            {
                // A trusted category is failing: one calm notice per hour, not a pop-up per refusal.
                string key = d.Category ?? ("known: " + (d.Who ?? d.Subject).Split('\n').Last().Split('=')[0].Trim());
                if (!CategoryNoticeDue(key)) return;
                ShowDenialToast(d);
                return;
            }
            ShowDenialToast(d);
            status.Text = "DENIED: " + d.Program + " → " + d.Subject + " (" + d.Code + ")" + (d.BlockedBy != null ? " — your block" : "");
        }

        private void ShowDenials()
        {
            Form dialog = new Form { Text = "Certificate denials (Windows CAPI2 log) — double-click one for its card", Size = new Size(1150, 520), Font = Font };
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Time", "Verdict", "Who is this", "Reason", "Blocked by your list", "Program", "Certificate / site", "Trust flags" }, new int[] { 70, 160, 420, 260, 200, 120, 220, 300 });
                AddDenialMenu(grid, null);
                Action fill = delegate
                {
                    Denial keep = grid.SelectedItems.Count > 0 ? grid.SelectedItems[0].Tag as Denial : null;
                    grid.BeginUpdate(); grid.Items.Clear();
                    foreach (Denial d in denials.AsEnumerable().Reverse())
                    {
                        if (d.Verdict == null) Annotate(d);
                        ListViewItem row = new ListViewItem(new string[] { d.Time.ToString("HH:mm:ss"), VerdictWord(d), (d.Who ?? "").Replace("\r\n", "  |  "), ShortReason(d.Reason), d.BlockedBy ?? "", d.Program, d.Subject, d.Flags });
                        row.ForeColor = VerdictColor(d.Verdict);
                        row.Tag = d; grid.Items.Add(row);
                        if (d == keep) row.Selected = true;
                    }
                    grid.EndUpdate();
                };
                fill();
                denialsRefresh = fill;
                dialog.FormClosed += delegate { denialsRefresh = null; };
                grid.DoubleClick += delegate { if (grid.SelectedItems.Count > 0) OpenRefusalCard((Denial)grid.SelectedItems[0].Tag); };
                ClearTrayBadge();
                Label note = new Label { Dock = DockStyle.Bottom, Height = 40, Text = "Red = refused because of your Disallowed list. Grey = harmless (revocation server unreachable, expired time-stamp certificate); listed, no alert.\r\n" +
                    "Source: Microsoft-Windows-CAPI2/Operational events 11 and 30. Chrome and Firefox check certificates themselves and do not appear here." };
                FlowLayoutPanel allow = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(2) };
                allow.Controls.Add(AllowButton("Allow selected", delegate
                {
                    Denial d = grid.SelectedItems.Count == 0 ? null : grid.SelectedItems[0].Tag as Denial;
                    return d == null ? new AllowTarget { Certs = delegate { return new List<CertificateRecord>(); }, NothingWhy = "Select a refusal in the list first." } : TargetFor(d);
                }));
                Button card = new Button { Text = "Refusal card", AutoSize = true };
                card.Click += delegate { if (grid.SelectedItems.Count > 0) OpenRefusalCard((Denial)grid.SelectedItems[0].Tag); };
                allow.Controls.Add(card);
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(allow); dialog.Controls.Add(close); dialog.CancelButton = close;
                ShowTool(dialog, "denials");
            }
        }
    }
}
