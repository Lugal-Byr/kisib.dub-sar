using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "Never block": certificates allowed for good, unblocked by hand, or put back by a repair. Rules and group blocks
    // skip them, including every certificate sharing their key. Plain .txt in PORTABLE BACKUP LISTS.
    internal sealed class AllowedSet
    {
        internal readonly HashSet<string> Sha1 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        internal readonly HashSet<string> Spki = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        internal bool Covers(CertificateRecord c)
        { return c != null && (Sha1.Contains(c.Sha1) || (c.SpkiSha256 != null && Spki.Contains(c.SpkiSha256))); }
    }

    internal static class AllowedList
    {
        private const string Header = "sha1,sha256,spki_sha256,subject,added_utc,source";
        internal static string FilePath { get { return Storage.File(Storage.AllowedList); } }

        internal static List<string[]> Read()
        {
            try
            {
                if (!File.Exists(FilePath)) return new List<string[]>();
                return GroupCatalog.ReadCsv(FilePath).Skip(1).Where(f => f.Length >= 5)
                    .Select(f => f.Length >= 6 ? f : new string[] { f[0], f[1], f[2], f[3], f[4], "allow always" }).ToList();
            }
            catch (Exception) { return new List<string[]>(); }
        }

        private static AllowedSet cache;
        private static DateTime cacheStamp;
        internal static AllowedSet Load()
        {
            DateTime stamp = File.Exists(FilePath) ? File.GetLastWriteTimeUtc(FilePath) : DateTime.MinValue;
            if (cache != null && stamp == cacheStamp) return cache;
            AllowedSet set = new AllowedSet();
            foreach (string[] r in Read()) { if (r[0].Length > 0) set.Sha1.Add(r[0]); if (r[2].Length > 0) set.Spki.Add(r[2]); }
            cache = set; cacheStamp = stamp;
            return set;
        }

        private static void Write(List<string[]> rows)
        {
            StringBuilder text = new StringBuilder(Header).Append("\r\n");
            foreach (string[] r in rows) text.Append(String.Join(",", r.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
            File.WriteAllText(FilePath, text.ToString(), new UTF8Encoding(false));
            cache = null;
        }

        internal static void AddRange(IEnumerable<CertificateRecord> certs, string source)
        {
            List<string[]> rows = Read();
            HashSet<string> have = new HashSet<string>(rows.Select(r => r[0]), StringComparer.OrdinalIgnoreCase);
            int before = rows.Count;
            foreach (CertificateRecord c in certs)
                if (c != null && have.Add(c.Sha1))
                    rows.Add(new string[] { c.Sha1, c.Sha256, c.SpkiSha256 ?? "", c.SubjectShortName, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), source });
            if (rows.Count != before) Write(rows);
        }

        internal static void Remove(string sha1)
        {
            List<string[]> rows = Read();
            if (rows.RemoveAll(r => String.Equals(r[0], sha1, StringComparison.OrdinalIgnoreCase)) > 0) Write(rows);
        }
    }

    internal sealed partial class ExplorerForm
    {
        // Takes the certificates out of Disallowed for good and puts them on the never-block list.
        internal void AllowAlways(List<CertificateRecord> certs, string label)
        {
            List<CertificateRecord> all = WithTwins(certs);
            if (all.Count == 0) { Say("Allow always: nothing blocked was found for " + label + "."); return; }
            string result = LiftForGood(all, "allow always: " + label, "allow always");
            Say("Allowed for good: " + label + ". " + result);
            WatchAllow(all, label);
            StartScan();
        }

        // A certificate plus every certificate on this PC sharing its key, so a cross-signed twin can't keep the block alive.
        internal List<CertificateRecord> WithTwins(IEnumerable<CertificateRecord> certs)
        {
            Dictionary<string, CertificateRecord> all = new Dictionary<string, CertificateRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (CertificateRecord c in certs.Where(x => x != null))
            {
                all[c.Sha1] = c;
                if (snapshot != null) foreach (CertificateRecord twin in snapshot.SameKey(c)) all[twin.Sha1] = twin;
            }
            return all.Values.ToList();
        }

        // Out of Disallowed (this user, and the whole PC when kisib runs as admin) and onto the never-block list,
        // so a bloc rule doesn't put it back. Returns one plain line about what happened.
        internal string LiftForGood(List<CertificateRecord> certs, string reason, string source)
        {
            List<string> problems = new List<string>();
            List<CertificateRecord> ok = Guarded(certs, problems);
            string said = LiftCore(ok, reason, problems);
            try { AllowedList.AddRange(ok, source); } catch (IOException ex) { return said + " Could not save the never-block list: " + ex.Message; }
            return said;
        }

        // Out of Disallowed only; nothing goes on the never-block list (a reset keeps your rules able to block them later).
        internal string Lift(List<CertificateRecord> certs, string reason, List<string> problems)
        { return LiftCore(Guarded(certs, problems), reason, problems); }

        // Compromised, Windows-distrusted and expired certificates were taken out by Guarded() before this.
        private string LiftCore(List<CertificateRecord> certs, string reason, List<string> problems)
        {
            int removed = 0, errors = 0;
            HashSet<string> sha1s = new HashSet<string>(certs.Select(c => c.Sha1), StringComparer.OrdinalIgnoreCase);
            try { TempAllow.Save(TempAllow.Read().Where(t => !sha1s.Contains(t.Sha1)).ToList()); } catch (Exception) { }
            foreach (X509Location scope in Elevation.IsElevated ? new X509Location[] { X509Location.CurrentUser, X509Location.LocalMachine } : new X509Location[] { X509Location.CurrentUser })
            {
                try
                {
                    List<BlockLogRow> rows = BlockEngine.UnblockAny(certs, scope, reason);
                    removed += rows.Count(r => r.Result == "removed");
                    errors += rows.Count(r => r.Result.StartsWith("error", StringComparison.Ordinal));
                }
                catch (Exception ex) { problems.Add(ex.Message); }
            }
            return LiftSummary(certs, removed, errors, problems);
        }

        // Where a block still is after kisib lifted what it could.
        private string LiftSummary(List<CertificateRecord> certs, int removed, int errors, List<string> problems)
        {
            List<string> parts = new List<string>();
            bool machine = certs.Any(c => c.FoundIn.Concat(c.Collections).Any(p => p.StartsWith("LOCAL_MACHINE\\Disallowed", StringComparison.OrdinalIgnoreCase)));
            bool policy = certs.Any(c => c.FoundIn.Concat(c.Collections).Any(p => p.IndexOf("GROUP_POLICY\\Disallowed", StringComparison.OrdinalIgnoreCase) >= 0));
            if (removed > 0) parts.Add("Lifted for " + (Elevation.IsElevated ? "the whole PC" : "this user") + " (" + removed + (removed == 1 ? " certificate)." : " certificates)."));
            else parts.Add("Nothing was in a Disallowed store kisib can change.");
            if (machine && !Elevation.IsElevated) parts.Add("Still blocked for the whole PC: lsass, updaters and services stay blocked. Run kisib as administrator for those.");
            if (policy) parts.Add("Part of it is set by Group Policy, which only a policy change lifts.");
            if (errors > 0) parts.Add(errors + " could not be changed (Block history has the reason).");
            parts.AddRange(problems);
            return String.Join(" ", parts.ToArray());
        }

        private void ShowAllowed()
        {
            Form dialog = new Form { Text = "Never block (allowed for good, unblocked by hand, repaired)", Size = new Size(1100, 440), Font = Font };
            ListView grid = new ListView();
            SetupGrid(grid, new string[] { "Certificate", "Why it's here", "Added (UTC)", "SHA-1", "Key (SPKI SHA-256)" }, new int[] { 300, 220, 170, 300, 420 });
            Action fill = delegate
            {
                grid.Items.Clear();
                foreach (string[] r in AllowedList.Read()) grid.Items.Add(new ListViewItem(new string[] { r[3], r[5], r[4], r[0], r[2] }) { Tag = r });
            };
            fill();
            Label note = new Label { Dock = DockStyle.Bottom, Height = 34, Text = "Rules and group blocks skip these and every certificate sharing their key. Taking one off this list lets your rules block it again on the next scan.\r\nFile: " + AllowedList.FilePath };
            Button remove = new Button { Text = "Take off the list", Dock = DockStyle.Bottom, Height = 30 };
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
