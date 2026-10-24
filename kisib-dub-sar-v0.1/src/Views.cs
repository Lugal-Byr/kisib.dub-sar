using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // S4 standings and chain view, S5 clock sanity, S6 read-only certificate file view.
    internal sealed partial class ExplorerForm
    {
        internal string PendingFile;

        private void InitializeViews(MenuItem file, MenuItem view, MenuItem certificate)
        {
            file.MenuItems.Add(0, new MenuItem("&Open certificate file...", delegate { OpenCertificateFile(null); }, Shortcut.CtrlO));
            file.MenuItems.Add(1, new MenuItem("-"));
            view.MenuItems.Add(new MenuItem("&Standings", delegate { ShowStandings(); }));
            certificate.MenuItems.Add(new MenuItem("Show &chain", delegate { ShowChain(SelectedCertificate()); }));
        }

        // Called after each scan: a file passed on the command line opens once the inventory exists.
        private void OpenPendingFile()
        {
            if (PendingFile == null) return;
            string file = PendingFile; PendingFile = null;
            BeginInvoke((Action)delegate { OpenCertificateFile(file); });
        }

        // ---- Standings (S4) -----------------------------------------------------------

        private string OwnerOf(CertificateRecord cert, bool subject)
        {
            if (groups != null)
                foreach (GroupNode owner in groups.Owners)
                    if (owner.Members.Contains(cert.Identity)) return owner.Label;
            string o = subject ? cert.SubjectOrganization : cert.IssuerOrganization;
            return !String.IsNullOrWhiteSpace(o) ? o.Trim() : subject ? cert.SubjectShortName : cert.IssuerShortName;
        }

        private string TagsOf(CertificateRecord cert)
        {
            if (groups == null) return "";
            return String.Join(" ", groups.Tags.Where(t => t.Members.Contains(cert.Identity)).Select(t => t.Label).ToArray());
        }

        private static bool InStore(CertificateRecord cert, string system)
        {
            return cert.FoundIn.Concat(cert.Collections).Any(p => p.IndexOf("\\" + system, StringComparison.OrdinalIgnoreCase) >= 0 &&
                (p.EndsWith("\\" + system, StringComparison.OrdinalIgnoreCase) || p.IndexOf("\\" + system + "\\", StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private void ShowStandings()
        {
            if (snapshot == null) { ShowText("Standings", "Run a scan first (F5)."); return; }
            DateTime soon = DateTime.UtcNow.AddMonths(12);
            HashSet<string> blocked = GroupCatalog.BlockedIdentities(snapshot);
            var rows = snapshot.Certificates.Values
                .GroupBy(c => (c.SubjectCountry ?? "—") + "\u0001" + OwnerOf(c, true))
                .Select(g => new
                {
                    Country = g.Key.Split('\u0001')[0], Owner = g.Key.Split('\u0001')[1],
                    Roots = g.Count(c => InStore(c, "Root") || InStore(c, "AuthRoot")),
                    Intermediates = g.Count(c => InStore(c, "CA")),
                    Expiring = g.Count(c => c.NotAfter.HasValue && c.NotAfter.Value > DateTime.UtcNow && c.NotAfter.Value <= soon),
                    Expired = g.Count(c => c.NotAfter.HasValue && c.NotAfter.Value <= DateTime.UtcNow),
                    Blocked = g.Count(c => blocked.Contains(c.Identity)),
                    Weak = g.Count(c => c.WeakReasons.Count > 0),
                    Total = g.Count(),
                    Tags = String.Join(" ", g.SelectMany(c => TagsOf(c).Split(' ')).Where(t => t.Length > 0).Distinct().ToArray())
                })
                .OrderBy(r => r.Country, StringComparer.OrdinalIgnoreCase).ThenByDescending(r => r.Total).ToList();
            using (Form dialog = new Form { Text = "Standings — CA owners by country", Size = new Size(1150, 650), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "C=", "Owner", "Roots", "Intermediates", "Expiring 12 mo", "Expired", "Blocked", "Weak", "Total", "Tags" },
                    new int[] { 50, 330, 70, 100, 110, 75, 75, 65, 65, 200 });
                grid.ShowGroups = true;
                foreach (var r in rows)
                {
                    ListViewGroup country = grid.Groups[r.Country] ?? grid.Groups.Add(r.Country, r.Country);
                    ListViewItem item = new ListViewItem(new string[] { r.Country, r.Owner, r.Roots.ToString(), r.Intermediates.ToString(), r.Expiring.ToString(),
                        r.Expired.ToString(), r.Blocked.ToString(), r.Weak.ToString(), r.Total.ToString(), r.Tags }, country);
                    if (r.Blocked > 0 && r.Blocked == r.Total) item.ForeColor = SystemColors.GrayText;
                    else if (r.Blocked > 0) item.ForeColor = Color.DarkRed;
                    else if (r.Weak > 0) item.BackColor = SystemColors.Info;
                    grid.Items.Add(item);
                }
                Label note = new Label { Dock = DockStyle.Bottom, Height = 40, Text = "Grouped by the certificate's own C=; owner from data\\owners.csv, else subject O=. " +
                    "Roots = in Root/AuthRoot, Intermediates = in CA. Grey = fully blocked, red = partly blocked, yellow = weak key or signature. Click a heading to sort." };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(close); dialog.CancelButton = close;
                dialog.ShowDialog(this);
            }
        }

        // ---- Chain view (S4) ----------------------------------------------------------

        private void ShowChain(CertificateRecord record)
        {
            if (record == null) { ShowText("Show chain", "Select a certificate in the list first."); return; }
            ShowChainFor(record.Der, record.SubjectShortName);
        }

        private void ShowChainFor(byte[] der, string label)
        {
            List<X509ChainElement> elements = new List<X509ChainElement>(); string status = "";
            X509Chain chain = new X509Chain();
            try
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                using (X509Certificate2 cert = new X509Certificate2(der))
                {
                    bool ok = chain.Build(cert);
                    status = ok ? "Windows builds a trusted chain." : "Windows reports: " + String.Join("; ", chain.ChainStatus.Select(s => s.Status + " " + s.StatusInformation.Trim()).ToArray());
                    foreach (X509ChainElement e in chain.ChainElements) elements.Add(e);
                }
            }
            catch (Exception ex) { status = "Chain build failed: " + ex.GetType().Name + ": " + ex.Message; }
            using (Form dialog = new Form { Text = "Chain — " + label, Size = new Size(1150, 470), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                FlowLayoutPanel bracket = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, WrapContents = false, FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(8) };
                HashSet<string> blocked = snapshot == null ? new HashSet<string>() : GroupCatalog.BlockedIdentities(snapshot);
                // Left to right: root first, the selected certificate last.
                for (int i = elements.Count - 1; i >= 0; i--)
                {
                    X509Certificate2 c = elements[i].Certificate;
                    CertificateRecord local = CertificateRecord.FromDer(c.RawData);
                    CertificateRecord seen = null;
                    if (snapshot != null) snapshot.Certificates.TryGetValue(local.Sha256, out seen);
                    StringBuilder text = new StringBuilder();
                    text.AppendLine(local.SubjectShortName);
                    text.AppendLine("C= " + (local.SubjectCountry ?? "—") + "   " + (i == elements.Count - 1 ? "root" : i == 0 ? "end certificate" : "intermediate"));
                    text.AppendLine("SHA-256 " + local.Sha256.Substring(0, 32));
                    text.AppendLine("        " + local.Sha256.Substring(32));
                    text.AppendLine("SHA-1   " + local.Sha1);
                    text.AppendLine("Found in: " + (seen == null ? "not in a scanned store" : seen.FoundInText));
                    text.AppendLine("Status: " + (elements[i].ChainElementStatus.Length == 0 ? "OK" : String.Join(", ", elements[i].ChainElementStatus.Select(s => s.Status.ToString()).ToArray())));
                    text.AppendLine("Blocked: " + (seen != null && blocked.Contains(seen.Identity) ? "YES (Disallowed)" : "no"));
                    text.AppendLine("Tags: " + (seen == null ? "" : TagsOf(seen)));
                    TextBox card = new TextBox { Multiline = true, ReadOnly = true, Width = 330, Height = 330, Font = new Font("Consolas", 8.5F), Text = text.ToString(),
                        BackColor = seen != null && blocked.Contains(seen.Identity) ? Color.MistyRose : SystemColors.Window, BorderStyle = BorderStyle.FixedSingle };
                    bracket.Controls.Add(card);
                    if (i > 0) bracket.Controls.Add(new Label { Text = "→", AutoSize = false, Width = 30, Height = 330, TextAlign = ContentAlignment.MiddleCenter, Font = new Font(Font.FontFamily, 18F) });
                }
                chain.Reset();
                Label info = new Label { Dock = DockStyle.Bottom, Height = 40, Text = status + "\r\nBuilt by Windows (CertGetCertificateChain via X509Chain); revocation not checked here." };
                Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
                dialog.Controls.Add(bracket); dialog.Controls.Add(info); dialog.Controls.Add(close); dialog.CancelButton = close;
                dialog.ShowDialog(this);
            }
        }

        // ---- Certificate files (S6): read-only, never installs, never opens private keys --

        private void OpenCertificateFile(string path)
        {
            if (path == null)
                using (OpenFileDialog pick = new OpenFileDialog { Filter = "Certificates (*.cer;*.crt;*.der;*.pem;*.p7b;*.sst)|*.cer;*.crt;*.der;*.pem;*.p7b;*.sst|All files (*.*)|*.*", Title = "Open certificate file (read-only)" })
                { if (pick.ShowDialog(this) != DialogResult.OK) return; path = pick.FileName; }
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext == ".pfx" || ext == ".p12") { ShowText("Open certificate file", "PFX/P12 files hold private keys. kisib never opens or shows private keys."); return; }
            X509Certificate2Collection certs = new X509Certificate2Collection();
            try
            {
                if (new FileInfo(path).Length > 16 * 1024 * 1024) throw new InvalidDataException("File is larger than 16 MB.");
                byte[] bytes = File.ReadAllBytes(path);
                string text = Encoding.ASCII.GetString(bytes);
                if (text.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    foreach (string block in text.Split(new string[] { "-----BEGIN CERTIFICATE-----" }, StringSplitOptions.RemoveEmptyEntries).Skip(text.StartsWith("-----BEGIN CERTIFICATE-----") ? 0 : 1))
                    {
                        int end = block.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
                        if (end > 0) certs.Add(new X509Certificate2(Convert.FromBase64String(block.Substring(0, end))));
                    }
                }
                else certs.Import(bytes);
            }
            catch (Exception ex) { ShowText("Open certificate file", path + "\r\n\r\nCould not read: " + ex.GetType().Name + ": " + ex.Message); return; }
            StringBuilder report = new StringBuilder();
            report.AppendLine(path); report.AppendLine(certs.Count + " certificate(s). Read-only: nothing was installed."); report.AppendLine();
            HashSet<string> blocked = snapshot == null ? new HashSet<string>() : GroupCatalog.BlockedIdentities(snapshot);
            foreach (X509Certificate2 c in certs)
            {
                CertificateRecord r = CertificateRecord.FromDer(c.RawData);
                CertificateRecord seen = null;
                if (snapshot != null) snapshot.Certificates.TryGetValue(r.Sha256, out seen);
                report.AppendLine("Subject: " + r.Subject); report.AppendLine("Issuer:  " + r.Issuer);
                report.AppendLine("C=: " + (r.SubjectCountry ?? "—") + "   issuer C=: " + (r.IssuerCountry ?? "—"));
                report.AppendLine("Valid: " + CertificateRecord.Time(r.NotBefore) + " → " + CertificateRecord.Time(r.NotAfter));
                report.AppendLine("SHA-1:   " + r.Sha1); report.AppendLine("SHA-256: " + r.Sha256); report.AppendLine("SPKI SHA-256: " + (r.SpkiSha256 ?? "[unavailable]"));
                report.AppendLine("On this PC: " + (seen == null ? "not in any scanned store" : seen.FoundInText) + (seen != null && blocked.Contains(seen.Identity) ? "   BLOCKED" : ""));
                report.AppendLine("Tags: " + (seen == null ? "(scan groups apply only to certificates on this PC)" : TagsOf(seen)));
                report.AppendLine();
                c.Reset();
            }
            ShowText("Certificate file — " + Path.GetFileName(path), report.ToString());
        }

        // ---- Clock sanity (S5) -------------------------------------------------------

        private string ClockStatus(Snapshot result)
        {
            DateTime now = DateTime.UtcNow;
            List<CertificateRecord> dated = result.Certificates.Values.Where(c => c.NotBefore.HasValue && c.NotAfter.HasValue).ToList();
            if (dated.Count == 0) return "Clock: unknown";
            DateTime newest = dated.Max(c => c.NotBefore.Value);
            double expired = dated.Count(c => c.NotAfter.Value < now) / (double)dated.Count;
            if (now < newest) return "Clock: SUSPECT (earlier than the newest certificate, " + newest.ToString("yyyy-MM-dd") + ")";
            if (expired > 0.9) return "Clock: SUSPECT (" + (int)(expired * 100) + "% of certificates read as expired)";
            return "Clock: ok";
        }
    }
}
