using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "Allow always": certificates you decided to trust for good. Rules and group blocks skip them,
    // including every certificate sharing their key. Plain .txt in PORTABLE BACKUP LISTS.
    internal sealed class AllowedSet
    {
        internal readonly HashSet<string> Sha1 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        internal readonly HashSet<string> Spki = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        internal bool Covers(CertificateRecord c)
        { return c != null && (Sha1.Contains(c.Sha1) || (c.SpkiSha256 != null && Spki.Contains(c.SpkiSha256))); }
    }

    internal static class AllowedList
    {
        private const string Header = "sha1,sha256,spki_sha256,subject,added_utc";
        internal static string FilePath { get { return Storage.File(Storage.AllowedList); } }

        internal static List<string[]> Read()
        {
            try { return File.Exists(FilePath) ? GroupCatalog.ReadCsv(FilePath).Skip(1).Where(f => f.Length >= 5).ToList() : new List<string[]>(); }
            catch (Exception) { return new List<string[]>(); }
        }

        internal static AllowedSet Load()
        {
            AllowedSet set = new AllowedSet();
            foreach (string[] r in Read()) { if (r[0].Length > 0) set.Sha1.Add(r[0]); if (r[2].Length > 0) set.Spki.Add(r[2]); }
            return set;
        }

        private static void Write(List<string[]> rows)
        {
            StringBuilder text = new StringBuilder(Header).Append("\r\n");
            foreach (string[] r in rows) text.Append(String.Join(",", r.Select(Q).ToArray())).Append("\r\n");
            File.WriteAllText(FilePath, text.ToString(), new UTF8Encoding(false));
        }
        private static string Q(string v) { v = v ?? ""; return v.IndexOfAny(new char[] { ',', '"' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        internal static void Add(CertificateRecord c)
        {
            List<string[]> rows = Read();
            if (rows.Any(r => String.Equals(r[0], c.Sha1, StringComparison.OrdinalIgnoreCase))) return;
            rows.Add(new string[] { c.Sha1, c.Sha256, c.SpkiSha256 ?? "", c.SubjectShortName, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) });
            Write(rows);
        }

        internal static void Remove(string sha1)
        {
            List<string[]> rows = Read();
            if (rows.RemoveAll(r => String.Equals(r[0], sha1, StringComparison.OrdinalIgnoreCase)) > 0) Write(rows);
        }
    }

    internal sealed partial class ExplorerForm
    {
        // Takes the certificates out of Disallowed for good (not just for minutes) and lists them as allowed.
        internal void AllowAlways(List<CertificateRecord> certs, string label)
        {
            certs = certs.Where(c => c != null).GroupBy(c => c.Sha1).Select(g => g.First()).ToList();
            if (certs.Count == 0) { ShowText("Allow always", "No blocked certificate found for this."); return; }
            string names = String.Join("\r\n", certs.Select(c => "  " + c.SubjectShortName + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : "")).ToArray());
            if (MessageBox.Show(this, "Allow these for good?\r\n\r\n" + names + "\r\n\r\nThey come out of Disallowed and go on " + Storage.AllowedList +
                ", so your rules stop blocking them (and anything sharing their key).\r\nUndo: Tools > Allowed (never block).",
                "Allow always — " + label, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            List<string> report = new List<string>();
            bool elevated = BlockEngine.IsElevated();
            HashSet<string> sha1s = new HashSet<string>(certs.Select(c => c.Sha1), StringComparer.OrdinalIgnoreCase);
            try { TempAllow.Save(TempAllow.Read().Where(t => !sha1s.Contains(t.Sha1)).ToList()); } catch (Exception) { }
            foreach (X509Location scope in elevated ? new X509Location[] { X509Location.CurrentUser, X509Location.LocalMachine } : new X509Location[] { X509Location.CurrentUser })
            {
                try
                {
                    using (X509Store store = new X509Store(StoreName.Disallowed, scope))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        foreach (CertificateRecord c in certs)
                        {
                            X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, c.Sha1, false);
                            foreach (X509Certificate2 x in found) store.Remove(x);
                            BlockedCertificates.Remove(scope, c.Sha1);
                            if (found.Count > 0)
                            {
                                BlockEngine.Note("allow-always", scope, c.Sha256, c.Sha1, c.SubjectShortName, "allowed for good: " + label);
                                report.Add("unblocked  " + scope + "  " + c.SubjectShortName);
                            }
                        }
                    }
                }
                catch (Exception ex) { report.Add("error  " + scope + ": " + ex.Message); }
            }
            foreach (CertificateRecord c in certs) { try { AllowedList.Add(c); } catch (IOException ex) { report.Add("could not save the allowed list: " + ex.Message); } }
            if (!elevated && snapshot != null && certs.Any(c => c.FoundIn.Any(p => p.StartsWith("LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) && p.IndexOf("Disallowed", StringComparison.OrdinalIgnoreCase) >= 0)))
                report.Add("Some of these are blocked for the whole PC: run kisib as administrator and Allow always again to lift those.");
            report.Add("Listed in " + AllowedList.FilePath + "; rules skip them from now on.");
            ShowText("Allow always — " + label, String.Join("\r\n", report.ToArray()));
            StartScan();
        }

        private void ShowAllowed()
        {
            Form dialog = new Form { Text = "Allowed (never block)", Size = new Size(980, 420), Font = Font };
            ListView grid = new ListView();
            SetupGrid(grid, new string[] { "Certificate", "Allowed (UTC)", "SHA-1", "Key (SPKI SHA-256)" }, new int[] { 300, 190, 300, 420 });
            Action fill = delegate
            {
                grid.Items.Clear();
                foreach (string[] r in AllowedList.Read()) grid.Items.Add(new ListViewItem(new string[] { r[3], r[4], r[0], r[2] }) { Tag = r });
            };
            fill();
            Label note = new Label { Dock = DockStyle.Bottom, Height = 34, Text = "Rules and group blocks skip these and every certificate sharing their key. Removing one here does not block it again by itself;\r\nyour rules will catch it on the next scan. File: " + AllowedList.FilePath };
            Button remove = new Button { Text = "Remove from allowed", Dock = DockStyle.Bottom, Height = 30 };
            remove.Click += delegate
            {
                if (grid.SelectedItems.Count == 0) return;
                AllowedList.Remove(((string[])grid.SelectedItems[0].Tag)[0]);
                fill(); StartScan();
            };
            Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
            dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(remove); dialog.Controls.Add(close); dialog.CancelButton = close;
            ShowTool(dialog, "allowed");
        }
    }
}
