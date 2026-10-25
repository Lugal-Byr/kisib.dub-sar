using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Kisib
{
    // A dated local list of published incident hashes. Read-only lookup; no network, no store writes.
    internal sealed class IncidentEntry
    {
        internal string IncidentId, Class, Match, Value, SubjectCn, SubjectO, SubjectC, IssuerCn, Source, Date;
    }

    internal sealed class IncidentHit
    {
        internal IncidentEntry Entry;
        internal CertificateRecord Certificate;
        internal bool InDisallowed;
    }

    internal static class IncidentList
    {
        internal const string FileName = "incident-hashes.csv";
        internal const string Header = "incident_id,class,match,value,subject_cn,subject_o,subject_c,issuer_cn,source,date";
        internal const int MaxBytes = 1024 * 1024;
        private static readonly Regex Hash = new Regex("^[0-9A-F]{64}$", RegexOptions.CultureInvariant);
        private static readonly Regex Date = new Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", RegexOptions.CultureInvariant);
        private static readonly string[] Classes = { "key_compromise", "dns_hijack", "misissuance", "other" };
        private static readonly string[] Matches = { "certificate_sha256", "spki_sha256" };

        internal static string PathIn(string sourceDirectory) { return System.IO.Path.Combine(sourceDirectory, "data", FileName); }

        internal static List<IncidentEntry> Read(string path)
        {
            FileInfo info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("Incident list not found.", path);
            if (info.Length > MaxBytes) throw new InvalidDataException("Incident list exceeds " + MaxBytes + " bytes.");
            return Parse(File.ReadAllText(path, new UTF8Encoding(false, true)));
        }

        internal static List<IncidentEntry> Parse(string text)
        {
            string[] lines = text.Replace("\r\n", "\n").Split('\n');
            if (lines.Length == 0 || lines[0] != Header) throw new InvalidDataException("Incident list header must be: " + Header);
            List<IncidentEntry> entries = new List<IncidentEntry>();
            HashSet<string> keys = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 1; i < lines.Length; i++)
            {
                if (lines[i].Length == 0) continue;
                string[] f = lines[i].Split(',');
                string row = "Incident list line " + (i + 1) + ": ";
                if (f.Length != 10) throw new InvalidDataException(row + "expected 10 fields, found " + f.Length + ".");
                if (f.Any(value => value.Length == 0 || value.Length > 512 || value.Any(Char.IsControl) || value.Contains("\"")))
                    throw new InvalidDataException(row + "empty, quoted, control-character or oversized field.");
                IncidentEntry entry = new IncidentEntry { IncidentId = f[0], Class = f[1], Match = f[2], Value = f[3], SubjectCn = f[4],
                    SubjectO = f[5], SubjectC = f[6], IssuerCn = f[7], Source = f[8], Date = f[9] };
                if (!Classes.Contains(entry.Class)) throw new InvalidDataException(row + "unknown class " + entry.Class + ".");
                if (!Matches.Contains(entry.Match)) throw new InvalidDataException(row + "unknown match " + entry.Match + ".");
                if (!Hash.IsMatch(entry.Value)) throw new InvalidDataException(row + "value must be 64 uppercase hex characters.");
                if (!Date.IsMatch(entry.Date)) throw new InvalidDataException(row + "date must be YYYY-MM-DD.");
                if (!entry.Source.StartsWith("https://", StringComparison.Ordinal)) throw new InvalidDataException(row + "source must be an https URL.");
                if (!keys.Add(entry.Match + ":" + entry.Value)) throw new InvalidDataException(row + "duplicate " + entry.Match + " value.");
                entries.Add(entry);
            }
            return entries;
        }

        // System store named Disallowed: Windows' untrusted-certificate store. Presence is an observation, not a browser decision.
        internal static HashSet<string> DisallowedPaths(Snapshot snapshot)
        {
            HashSet<string> paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (SystemStore store in snapshot.Locations.SelectMany(location => location.Stores))
                if (String.Equals(store.Name, "Disallowed", StringComparison.OrdinalIgnoreCase))
                {
                    paths.Add(store.Path);
                    foreach (PhysicalStore physical in store.PhysicalStores) paths.Add(physical.Path);
                }
            return paths;
        }

        internal static List<IncidentHit> Match(Snapshot snapshot, IList<IncidentEntry> entries)
        {
            HashSet<string> disallowed = DisallowedPaths(snapshot);
            List<IncidentHit> hits = new List<IncidentHit>();
            foreach (CertificateRecord cert in snapshot.Certificates.Values)
                foreach (IncidentEntry entry in entries)
                {
                    string value = entry.Match == "certificate_sha256" ? cert.Sha256 : cert.SpkiSha256;
                    if (value != null && String.Equals(value, entry.Value, StringComparison.Ordinal))
                        hits.Add(new IncidentHit { Entry = entry, Certificate = cert,
                            InDisallowed = cert.FoundIn.Any(disallowed.Contains) || cert.Collections.Any(disallowed.Contains) });
                }
            return hits;
        }
    }

    internal sealed partial class ExplorerForm
    {
        internal Form CreateIncidentDialog()
        {
            Form dialog = new Form { Text = "Incident check — published hashes [to test]", Size = new Size(1150, 560), Font = Font, StartPosition = FormStartPosition.CenterParent };
            ListView grid = new ListView();
            SetupGrid(grid, new string[] { "Incident", "Listed certificate", "Listed issuer", "Match", "On this PC", "In Disallowed store", "Found in (physical stores)", "Value" },
                new int[] { 110, 170, 170, 130, 90, 120, 330, 470 });
            Label summary = new Label { Dock = DockStyle.Bottom, Height = 92 };
            Button close = new Button { Text = "Close", Dock = DockStyle.Bottom, Height = 30, DialogResult = DialogResult.Cancel };
            List<IncidentEntry> entries = null; string error = null;
            try { entries = IncidentList.Read(IncidentList.PathIn(sourceDirectory)); }
            catch (Exception ex) { if (!(ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException)) throw; error = ex.Message; }
            if (snapshot == null || error != null)
                summary.Text = error != null ? "Incident list unavailable: " + error : "Run a scan first (F5).";
            else
            {
                List<IncidentHit> hits = IncidentList.Match(snapshot, entries);
                foreach (IncidentEntry entry in entries.Where(e => e.Match == "certificate_sha256"))
                {
                    IncidentHit hit = hits.FirstOrDefault(h => h.Entry == entry);
                    grid.Items.Add(new ListViewItem(new string[] { entry.IncidentId, entry.SubjectCn, entry.IssuerCn, "certificate SHA-256",
                        hit == null ? "MISS" : "HIT", hit == null ? "—" : hit.InDisallowed ? "yes" : "NO",
                        hit == null ? "not in any scanned store" : hit.Certificate.FoundInText, entry.Value }));
                }
                // Same public key under a certificate not on the list (another cross-sign or reissue).
                foreach (IncidentHit hit in hits.Where(h => h.Entry.Match == "spki_sha256" &&
                    !hits.Any(other => other.Certificate == h.Certificate && other.Entry.Match == "certificate_sha256")))
                    grid.Items.Add(new ListViewItem(new string[] { hit.Entry.IncidentId, hit.Certificate.SubjectShortName, hit.Certificate.IssuerShortName,
                        "SPKI SHA-256 only", "HIT", hit.InDisallowed ? "yes" : "NO", hit.Certificate.FoundInText, hit.Entry.Value }));
                int listed = entries.Count(e => e.Match == "certificate_sha256");
                int present = hits.Where(h => h.Entry.Match == "certificate_sha256").Select(h => h.Certificate).Distinct().Count();
                int spkiOnly = grid.Items.Count - listed;
                int notDisallowed = hits.Where(h => !h.InDisallowed).Select(h => h.Certificate).Distinct().Count();
                foreach (ListViewItem item in grid.Items) if (item.SubItems[4].Text == "HIT" && item.SubItems[5].Text == "NO") item.ForeColor = Color.DarkRed;
                summary.Text = listed + " listed certificates: " + present + " on this PC; " + spkiOnly + " other certificates share a listed key; " +
                    notDisallowed + " matched certificates found outside the Disallowed store.\r\n" +
                    "Read-only. MISS means not found in this scan, never safe. Disallowed-store presence is Windows' own untrusted list, not a browser decision [to test].\r\n" +
                    "Microsoft term: untrusted certificates / Disallowed certificate trust list [documented]. Check Windows' list sync: certutil -verifyctl Disallowed\r\n" +
                    Sources.Disallowed + "\r\nList: data\\" + IncidentList.FileName + " — sources and dates per row; details in docs\\incident-records-2026-10.txt";
            }
            dialog.Controls.Add(grid); dialog.Controls.Add(summary); dialog.Controls.Add(close); dialog.CancelButton = close;
            return dialog;
        }

        private void ShowIncidents()
        { ShowTool(CreateIncidentDialog(), "incidents"); }
    }
}
