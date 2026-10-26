using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "Who is this?" dictionaries: file.exe = common name = what it does; site = who = what for; owner = who (country) = what.
    // Shipped defaults are copied into PORTABLE BACKUP LISTS on first run; the copies there are yours to edit.
    internal static class WhoIsWho
    {
        internal const string ProgramsFile = "WHO IS WHO - programs.txt";
        internal const string SitesFile = "WHO IS WHO - sites.txt";
        internal const string OwnersFile = "WHO IS WHO - certificate owners.txt";
        internal const string CategoriesFile = "TRUSTED CATEGORIES.txt";
        private static readonly Dictionary<string, string> Shipped = new Dictionary<string, string>
        { { ProgramsFile, "who-programs.txt" }, { SitesFile, "who-sites.txt" }, { OwnersFile, "who-owners.txt" }, { CategoriesFile, "trusted-categories.txt" } };

        internal sealed class Entry { internal string Pattern, Name, What; internal Regex Match; }
        private static List<Entry> programs, sites, owners;
        private static DateTime stamp, lastLook;
        private static readonly object gate = new object();
        internal static string SourceDirectory;

        private static bool ensured;
        internal static void EnsureFiles()
        {
            if (ensured) return;
            foreach (KeyValuePair<string, string> f in Shipped)
            {
                string target = Storage.File(f.Key), source = SourceDirectory == null ? null : Path.Combine(SourceDirectory, "data", f.Value);
                try { if (!File.Exists(target) && source != null && File.Exists(source)) File.Copy(source, target); } catch (IOException) { }
            }
            MergeNewSites();
            ensured = SourceDirectory != null;
        }

        // New shipped site names get added to your copy (yours stays first, so your edits win).
        private static void MergeNewSites()
        {
            try
            {
                string target = Storage.File(SitesFile), source = SourceDirectory == null ? null : Path.Combine(SourceDirectory, "data", "who-sites.txt");
                if (source == null || !File.Exists(source) || !File.Exists(target)) return;
                List<string> mine = File.ReadAllLines(target).ToList();
                HashSet<string> have = new HashSet<string>(mine.Select(l => l.Split(new string[] { " = " }, 2, StringSplitOptions.None)[0].Trim()), StringComparer.OrdinalIgnoreCase);
                List<string> add = File.ReadAllLines(source).Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith("#", StringComparison.Ordinal) &&
                    !have.Contains(l.Split(new string[] { " = " }, 2, StringSplitOptions.None)[0].Trim())).ToList();
                if (add.Count == 0) return;
                // Specific names go before the broad "*.microsoft.com" style lines so they match first.
                int broad = mine.FindIndex(l => l.StartsWith("*.microsoft.com", StringComparison.OrdinalIgnoreCase));
                if (broad < 0) mine.AddRange(add); else mine.InsertRange(broad, add);
                File.WriteAllLines(target, mine.ToArray(), new UTF8Encoding(false));
            }
            catch (Exception) { }
        }

        // Looks at the files at most every 3 seconds (it used to check the disk on every single lookup).
        private static void Load()
        {
            lock (gate)
            {
                if (programs != null && (DateTime.UtcNow - lastLook).TotalSeconds < 3) return;
                lastLook = DateTime.UtcNow;
                EnsureFiles();
                DateTime newest = Shipped.Keys.Select(k => Storage.File(k)).Where(File.Exists).Select(File.GetLastWriteTimeUtc).DefaultIfEmpty(DateTime.MinValue).Max();
                if (programs != null && newest == stamp) return;
                List<Entry> p = Read(ProgramsFile, false), s = Read(SitesFile, true), o = Read(OwnersFile, false);
                programs = p; sites = s; owners = o;
                stamp = newest;
            }
        }

        private static List<Entry> Read(string file, bool wildcard)
        {
            List<Entry> list = new List<Entry>();
            string path = Storage.File(file);
            if (!File.Exists(path)) return list;
            foreach (string raw in File.ReadAllLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] parts = line.Split(new string[] { " = " }, 3, StringSplitOptions.None);
                if (parts.Length < 2) continue;
                Entry e = new Entry { Pattern = parts[0].Trim(), Name = parts[1].Trim(), What = parts.Length > 2 ? parts[2].Trim() : "" };
                if (wildcard) e.Match = Wildcard(e.Pattern);
                list.Add(e);
            }
            return list;
        }

        // *.example.com matches example.com and anything under it; * elsewhere matches anything.
        internal static Regex Wildcard(string pattern)
        {
            string p = pattern.Trim().ToLowerInvariant();
            if (p.StartsWith("*.", StringComparison.Ordinal))
                return new Regex("^(.*\\.)?" + Regex.Escape(p.Substring(2)).Replace("\\*", ".*") + "$", RegexOptions.IgnoreCase);
            return new Regex("^" + Regex.Escape(p).Replace("\\*", ".*") + "$", RegexOptions.IgnoreCase);
        }

        internal static string Program(string exe)
        {
            if (String.IsNullOrEmpty(exe)) return null;
            try { Load(); } catch (Exception) { return null; }
            string name = Path.GetFileName(exe);
            Entry e = programs.FirstOrDefault(p => String.Equals(p.Pattern, name, StringComparison.OrdinalIgnoreCase)) ??
                      programs.FirstOrDefault(p => String.Equals(Path.GetFileNameWithoutExtension(p.Pattern), Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase));
            return e == null ? null : name + " = " + e.Name + " = " + e.What;
        }

        internal static string Site(string host)
        {
            if (String.IsNullOrEmpty(host) || host.StartsWith("[", StringComparison.Ordinal)) return null;
            try { Load(); } catch (Exception) { return null; }
            string h = host.Trim().TrimStart('*', '.');
            // Most specific first: the shipped file lists specific names before broad ones.
            Entry e = sites.FirstOrDefault(s => s.Match.IsMatch(h) || s.Match.IsMatch(host.Trim()));
            return e == null ? null : host + " = " + e.Name + " = " + e.What;
        }

        internal static string Owner(string organizationOrName)
        {
            if (String.IsNullOrEmpty(organizationOrName)) return null;
            try { Load(); } catch (Exception) { return null; }
            Entry e = owners.FirstOrDefault(o => organizationOrName.IndexOf(o.Pattern, StringComparison.OrdinalIgnoreCase) >= 0);
            return e == null ? null : e.Name + " = " + e.What;
        }

        internal static string Owner(CertificateRecord c)
        {
            return Owner(c.SubjectOrganization) ?? Owner(c.SubjectShortName) ?? Owner(c.Subject);
        }
    }

    internal sealed class TrustCategory
    {
        internal string Name;
        internal bool Enabled;
        internal List<string> Programs = new List<string>(), Sites = new List<string>(), Roots = new List<string>();
        private List<Regex> siteMatch;
        internal List<Regex> SiteMatch { get { if (siteMatch == null) siteMatch = Sites.Select(WhoIsWho.Wildcard).ToList(); return siteMatch; } }
    }

    internal static class TrustCategories
    {
        private static List<TrustCategory> cache;
        private static DateTime stamp, lastLook;
        private static readonly object gate = new object();

        internal static List<TrustCategory> Read()
        {
            lock (gate)
            {
                // Checked against the disk at most every 3 seconds; rules ask once per certificate.
                if (cache != null && (DateTime.UtcNow - lastLook).TotalSeconds < 3) return cache;
                lastLook = DateTime.UtcNow;
                return ReadNow();
            }
        }

        private static List<TrustCategory> ReadNow()
        {
            WhoIsWho.EnsureFiles();
            string path = Storage.File(WhoIsWho.CategoriesFile);
            if (!File.Exists(path)) return cache = new List<TrustCategory>();
            DateTime t = File.GetLastWriteTimeUtc(path);
            if (cache != null && t == stamp) return cache;
            List<TrustCategory> list = new List<TrustCategory>();
            TrustCategory current = null;
            foreach (string raw in File.ReadAllLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                if (line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal))
                { current = new TrustCategory { Name = line.Substring(1, line.Length - 2).Trim() }; list.Add(current); continue; }
                if (current == null) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                List<string> values = line.Substring(eq + 1).Split(',').Select(v => v.Trim()).Where(v => v.Length > 0).ToList();
                if (key == "enabled") current.Enabled = values.Count > 0 && values[0].Equals("on", StringComparison.OrdinalIgnoreCase);
                else if (key == "programs") current.Programs = values;
                else if (key == "sites") current.Sites = values;
                else if (key == "roots") current.Roots = values;
            }
            cache = list; stamp = t;
            return list;
        }

        internal static void SetEnabled(string name, bool on)
        {
            string path = Storage.File(WhoIsWho.CategoriesFile);
            if (!File.Exists(path)) return;
            List<string> lines = File.ReadAllLines(path).ToList();
            bool inside = false;
            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i].Trim();
                if (line.StartsWith("[", StringComparison.Ordinal)) inside = line.Equals("[" + name + "]", StringComparison.OrdinalIgnoreCase);
                else if (inside && line.StartsWith("enabled", StringComparison.OrdinalIgnoreCase)) lines[i] = "enabled = " + (on ? "on" : "off");
            }
            File.WriteAllLines(path, lines.ToArray(), new UTF8Encoding(false));
            lock (gate) cache = null;
        }

        // A protected certificate is a root named in an enabled category, or a CA issued directly by one.
        internal static string ProtectedBy(CertificateRecord c)
        {
            if (c == null) return null;
            foreach (TrustCategory cat in Read().Where(x => x.Enabled))
                if (cat.Roots.Any(r => String.Equals(r, c.SubjectCn, StringComparison.OrdinalIgnoreCase) ||
                    (c.Subject != c.Issuer && String.Equals(r, c.IssuerCn, StringComparison.OrdinalIgnoreCase))))
                    return cat.Name;
            return null;
        }

        internal static string CategoryOf(Denial d)
        {
            string program = Path.GetFileName(d.Program ?? "");
            foreach (TrustCategory cat in Read().Where(x => x.Enabled))
            {
                if (cat.SiteMatch.Any(s => s.IsMatch((d.Subject ?? "").TrimStart('*', '.'))) ||
                    cat.Programs.Any(p => String.Equals(p, program, StringComparison.OrdinalIgnoreCase)) ||
                    d.ChainNames.Any(n => cat.Roots.Any(r => String.Equals(r, n, StringComparison.OrdinalIgnoreCase))))
                    return cat.Name;
            }
            return null;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private readonly Dictionary<string, DateTime> categoryNoticeShown = new Dictionary<string, DateTime>(StringComparer.Ordinal);

        // Fills in Who / Category / Verdict for a check Windows logged.
        internal void Annotate(Denial d)
        {
            List<string> who = new List<string>();
            string program = WhoIsWho.Program(d.Program);
            who.Add(program ?? d.Program + " = (not in your who-is-who list)");
            string site = WhoIsWho.Site(d.Subject);
            if (site != null) who.Add(site);
            string root = d.ChainNames.Count > 0 ? d.ChainNames[d.ChainNames.Count - 1] : null;
            string owner = root == null ? null : WhoIsWho.Owner(root);
            if (owner != null) who.Add(root + " = " + owner);
            d.Who = String.Join("\r\n", who.ToArray());
            d.Category = d.Ok ? null : TrustCategories.CategoryOf(d);
            // Known = the site or the root owner is in the who-is-who lists (a known company, just refused).
            d.Known = site != null || owner != null;
            d.Verdict = d.Ok ? (program != null || site != null ? "green" : "grey") :
                d.Noise ? "grey" : d.BlockedBy != null ? "red" : d.Category != null || d.Known ? "yellow" : "red";
        }

        internal static Color VerdictColor(string verdict)
        {
            return verdict == "green" ? Color.SeaGreen : verdict == "yellow" ? Color.DarkGoldenrod : verdict == "red" ? Color.Firebrick : Color.Gray;
        }

        internal static string VerdictWord(Denial d)
        {
            return d.Verdict == "green" ? "● known, trusted" : d.Verdict == "yellow" ? (d.Category != null ? "● expected service broken" : "● known company, refused") : d.Verdict == "red" ? (d.BlockedBy != null ? "● blocked by you" : "● refused, unknown") : "● harmless";
        }

        // One notice per broken category per hour instead of a pop-up for every refusal.
        private bool CategoryNoticeDue(string category)
        {
            DateTime last;
            if (categoryNoticeShown.TryGetValue(category, out last) && (DateTime.Now - last).TotalMinutes < 60) return false;
            categoryNoticeShown[category] = DateTime.Now;
            return true;
        }

        private void InitializeReputation(MenuItem tools)
        {
            WhoIsWho.SourceDirectory = sourceDirectory;
            tools.MenuItems.Add("-");
            tools.MenuItems.Add(new MenuItem("Trusted &categories...", delegate { ShowCategories(); }));
            tools.MenuItems.Add(RepairMenu());
            tools.MenuItems.Add(new MenuItem("Edit &who-is-who lists (opens the folder)", delegate
            {
                WhoIsWho.EnsureFiles();
                try { System.Diagnostics.Process.Start("explorer.exe", "\"" + Storage.Folder + "\""); } catch (Exception ex) { ShowText("Who is who", ex.Message); }
            }));
        }

        private void ShowCategories()
        {
            List<TrustCategory> cats = TrustCategories.Read();
            Form dialog = new Form { Text = "Trusted categories", Size = new Size(820, 460), Font = Font, StartPosition = FormStartPosition.CenterParent };
            {
                CheckedListBox box = new CheckedListBox { Dock = DockStyle.Fill, CheckOnClick = true };
                foreach (TrustCategory c in cats) box.Items.Add(c.Name, c.Enabled);
                TextBox detail = new TextBox { Dock = DockStyle.Bottom, Height = 150, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
                box.SelectedIndexChanged += delegate
                {
                    TrustCategory c = cats.FirstOrDefault(x => x.Name == (string)box.SelectedItem);
                    if (c != null) detail.Text = "Programs: " + String.Join(", ", c.Programs.ToArray()) + "\r\nSites: " + String.Join(", ", c.Sites.ToArray()) +
                        "\r\nProtected roots: " + String.Join(", ", c.Roots.ToArray());
                };
                Label note = new Label { Dock = DockStyle.Top, Height = 46, Padding = new Padding(6), Text = "A category that is on protects its roots: rules skip them and the block preview warns first. " +
                    "Its refusals show as one \"expected service broken\" notice instead of pop-ups. Edit the lists in " + WhoIsWho.CategoriesFile + "." };
                Button save = new Button { Text = "Save", Dock = DockStyle.Bottom, Height = 30 };
                save.Click += delegate
                {
                    for (int i = 0; i < box.Items.Count; i++) TrustCategories.SetEnabled((string)box.Items[i], box.GetItemChecked(i));
                    dialog.Close(); StartScan();
                };
                dialog.Controls.Add(box); dialog.Controls.Add(note); dialog.Controls.Add(detail); dialog.Controls.Add(save);
                ShowTool(dialog, "categories");
            }
        }
    }
}
