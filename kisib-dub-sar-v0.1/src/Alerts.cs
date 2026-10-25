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
        internal readonly List<string> ChainSha1 = new List<string>();
        internal readonly List<string> ChainNames = new List<string>();
        internal bool Noise, Ok, Known;
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
            foreach (XmlElement e in doc.GetElementsByTagName("Certificate"))
            {
                if (d.Subject == null) d.Subject = e.GetAttribute("subjectName");
                string file = e.GetAttribute("fileRef");
                if (file.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
                {
                    string sha1 = file.Substring(0, file.Length - 4).ToUpperInvariant();
                    if (!d.ChainSha1.Contains(sha1)) { d.ChainSha1.Add(sha1); d.ChainNames.Add(e.GetAttribute("subjectName")); }
                }
            }
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
            if (String.IsNullOrEmpty(d.Subject)) d.Subject = "[subject not logged]";
            return d;
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
            tray = new NotifyIcon { Icon = AppIcon.Small ?? SystemIcons.Shield, Text = "kisib.dub-sar", Visible = true };
            tray.BalloonTipClicked += delegate { ShowDenials(); };
            tray.DoubleClick += delegate { RestoreFromTray(); };
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
                    if (d != null) Post(delegate { MapAdd(d); if (!d.Ok) OnDenial(d); });
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

        private void OnDenial(Denial d)
        {
            // Windows logs a failure from both chain building and policy; keep one per program/subject/code within 5 seconds.
            if (denials.Any(x => x.Program == d.Program && x.Subject == d.Subject && x.Code == d.Code && (d.Time - x.Time).TotalSeconds < 5)) return;
            if (snapshot != null)
            {
                HashSet<string> blocked = GroupCatalog.BlockedIdentities(snapshot);
                List<string> hits = snapshot.Certificates.Values.Where(c => blocked.Contains(c.Identity) && d.ChainSha1.Contains(c.Sha1)).Select(c => c.SubjectShortName).ToList();
                if (hits.Count > 0) d.BlockedBy = String.Join(", ", hits.ToArray());
            }
            Annotate(d);
            denials.Add(d);
            SaveDenial(d);
            RefreshWatchTab(); UpdateIndicators();
            if (denials.Count > 2000) denials.RemoveAt(0);
            if (d.Noise) return;
            if (d.Verdict == "yellow")
            {
                // A trusted category is failing: one calm notice per hour, not a pop-up per refusal.
                string key = d.Category ?? ("known: " + (d.Who ?? d.Subject).Split('\n').Last().Split('=')[0].Trim());
                if (!CategoryNoticeDue(key)) return;
                ShowDenialToast(d, (d.Category != null ? "Expected service broken: " + d.Category : "Known company, refused") + "\r\n" + d.Who + "\r\n" + ShortReason(d.Reason) +
                    (d.Category != null ? "\r\nTools > Repair Windows essentials can fix missing Microsoft roots." : "\r\nTurn its category on in Tools > Trusted categories to protect it."));
                return;
            }
            string text = d.Who + "\r\n" + ShortReason(d.Reason) + (d.BlockedBy != null ? "\r\nBlocked by your Disallowed list: " + d.BlockedBy : "");
            ShowDenialToast(d, text);
            FLASHWINFO flash = new FLASHWINFO { cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)), hwnd = Handle, dwFlags = 3 | 12, uCount = 0, dwTimeout = 0 }; // all + until foreground
            FlashWindowEx(ref flash);
            status.Text = "DENIED: " + d.Program + " → " + d.Subject + " (" + d.Code + ")" + (d.BlockedBy != null ? " — your block" : "");
        }

        private void ShowDenials()
        {
            using (Form dialog = new Form { Text = "Certificate denials (Windows CAPI2 log, since kisib opened)", Size = new Size(1150, 520), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Time", "Verdict", "Who is this", "Reason", "Blocked by your list", "Program", "Certificate / site", "Trust flags" }, new int[] { 70, 160, 420, 260, 200, 120, 220, 300 });
                AddDenialMenu(grid, delegate { dialog.Close(); });
                foreach (Denial d in denials.AsEnumerable().Reverse())
                {
                    if (d.Verdict == null) Annotate(d);
                    ListViewItem row = new ListViewItem(new string[] { d.Time.ToString("HH:mm:ss"), VerdictWord(d), (d.Who ?? "").Replace("\r\n", "  |  "), ShortReason(d.Reason), d.BlockedBy ?? "", d.Program, d.Subject, d.Flags });
                    row.ForeColor = VerdictColor(d.Verdict);
                    row.Tag = d; grid.Items.Add(row);
                }
                Label note = new Label { Dock = DockStyle.Bottom, Height = 40, Text = "Red = refused because of your Disallowed list. Grey = harmless (revocation server unreachable, expired time-stamp certificate); listed, no alert.\r\n" +
                    "Source: Microsoft-Windows-CAPI2/Operational events 11 and 30. Chrome and Firefox check certificates themselves and do not appear here." };
                FlowLayoutPanel allow = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(2) };
                allow.Controls.Add(new Label { Text = "Allow selected for:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
                foreach (int minutes in new int[] { 3, 10, 60 })
                {
                    int m = minutes;
                    Button b = new Button { Text = m + " min", AutoSize = true };
                    b.Click += delegate
                    {
                        if (grid.SelectedItems.Count == 0) return;
                        Denial d = (Denial)grid.SelectedItems[0].Tag;
                        dialog.Close();
                        AllowTemporarily(CertificatesBehind(d), d.Subject, TimeSpan.FromMinutes(m), true);
                    };
                    allow.Controls.Add(b);
                }
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(allow); dialog.Controls.Add(close); dialog.CancelButton = close;
                dialog.ShowDialog(this);
            }
        }
    }
}
