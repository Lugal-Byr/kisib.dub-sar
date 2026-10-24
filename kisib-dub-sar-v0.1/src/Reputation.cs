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
        private static DateTime stamp;
        internal static string SourceDirectory;

        internal static void EnsureFiles()
        {
            foreach (KeyValuePair<string, string> f in Shipped)
            {
                string target = Storage.File(f.Key), source = SourceDirectory == null ? null : Path.Combine(SourceDirectory, "data", f.Value);
                try { if (!File.Exists(target) && source != null && File.Exists(source)) File.Copy(source, target); } catch (IOException) { }
            }
        }

        private static void Load()
        {
            EnsureFiles();
            DateTime newest = Shipped.Keys.Select(k => Storage.File(k)).Where(File.Exists).Select(File.GetLastWriteTimeUtc).DefaultIfEmpty(DateTime.MinValue).Max();
            if (programs != null && newest == stamp) return;
            programs = Read(ProgramsFile, false); sites = Read(SitesFile, true); owners = Read(OwnersFile, false);
            stamp = newest;
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
    }

    internal static class TrustCategories
    {
        private static List<TrustCategory> cache;
        private static DateTime stamp;

        internal static List<TrustCategory> Read()
        {
            WhoIsWho.EnsureFiles();
            string path = Storage.File(WhoIsWho.CategoriesFile);
            if (!File.Exists(path)) return new List<TrustCategory>();
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
            cache = null;
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
                if (cat.Sites.Any(s => WhoIsWho.Wildcard(s).IsMatch((d.Subject ?? "").TrimStart('*', '.'))) ||
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
            d.Verdict = d.Ok ? (program != null || site != null ? "green" : "grey") :
                d.Noise ? "grey" : d.BlockedBy != null ? "red" : d.Category != null ? "yellow" : "red";
        }

        internal static Color VerdictColor(string verdict)
        {
            return verdict == "green" ? Color.SeaGreen : verdict == "yellow" ? Color.DarkGoldenrod : verdict == "red" ? Color.Firebrick : Color.Gray;
        }

        internal static string VerdictWord(Denial d)
        {
            return d.Verdict == "green" ? "● known, trusted" : d.Verdict == "yellow" ? "● expected service broken" : d.Verdict == "red" ? (d.BlockedBy != null ? "● blocked by you" : "● refused, unknown") : "● harmless";
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
            tools.MenuItems.Add(new MenuItem("&Repair Windows essentials...", delegate { ShowRepair(); }));
            tools.MenuItems.Add(new MenuItem("Edit &who-is-who lists (opens the folder)", delegate
            {
                WhoIsWho.EnsureFiles();
                try { System.Diagnostics.Process.Start("explorer.exe", "\"" + Storage.Folder + "\""); } catch (Exception ex) { ShowText("Who is who", ex.Message); }
            }));
        }

        private void ShowCategories()
        {
            List<TrustCategory> cats = TrustCategories.Read();
            using (Form dialog = new Form { Text = "Trusted categories", Size = new Size(820, 460), Font = Font, StartPosition = FormStartPosition.CenterParent })
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
                dialog.ShowDialog(this);
            }
        }

        // Repair: put the roots an enabled category needs back into Trusted Root, and out of Disallowed.
        private void ShowRepair()
        {
            if (snapshot == null) { ShowText("Repair Windows essentials", "Run a scan first (F5)."); return; }
            List<string> needed = TrustCategories.Read().Where(c => c.Enabled).SelectMany(c => c.Roots).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            HashSet<string> blocked = GroupCatalog.BlockedIdentities(snapshot);
            List<KeyValuePair<string, CertificateRecord>> found = new List<KeyValuePair<string, CertificateRecord>>();
            using (Form dialog = new Form { Text = "Repair Windows essentials — preview", Size = new Size(1000, 520), Font = Font, StartPosition = FormStartPosition.CenterParent })
            {
                ListView grid = new ListView();
                SetupGrid(grid, new string[] { "Root", "Trusted now", "In Disallowed", "Will do" }, new int[] { 380, 110, 110, 340 });
                int fixes = 0;
                foreach (string name in needed)
                {
                    CertificateRecord c = snapshot.Certificates.Values.Where(x => String.Equals(x.SubjectCn, name, StringComparison.OrdinalIgnoreCase) && x.Subject == x.Issuer)
                        .OrderByDescending(x => x.NotAfter).FirstOrDefault();
                    if (c == null) { grid.Items.Add(new ListViewItem(new string[] { name, "?", "?", "not available: load Tools > Update Microsoft root list" }) { ForeColor = SystemColors.GrayText }); continue; }
                    bool trusted = c.FoundIn.Any(p => p.IndexOf("\\Root\\", StringComparison.OrdinalIgnoreCase) >= 0 || p.IndexOf("\\AuthRoot\\", StringComparison.OrdinalIgnoreCase) >= 0);
                    bool isBlocked = blocked.Contains(c.Identity);
                    string todo = (isBlocked ? "remove from Disallowed; " : "") + (!trusted ? "add to Trusted Root (whole PC)" : "");
                    if (todo.Length == 0) todo = "nothing, already fine";
                    else { fixes++; found.Add(new KeyValuePair<string, CertificateRecord>(todo, c)); }
                    ListViewItem row = new ListViewItem(new string[] { name, trusted ? "yes" : "NO", isBlocked ? "YES" : "no", todo });
                    if (todo != "nothing, already fine") row.ForeColor = Color.Firebrick;
                    grid.Items.Add(row);
                }
                Label note = new Label { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(6), Text = "Only the roots listed in enabled trusted categories. Needs kisib running as administrator. " +
                    "Each change is written to BLOCK HISTORY. Roots come from your stores, the Microsoft root list, or CCADB." };
                Button go = new Button { Text = fixes == 0 ? "Nothing to repair" : "Repair " + fixes + " root" + (fixes == 1 ? "" : "s"), Dock = DockStyle.Bottom, Height = 32, Enabled = fixes > 0 };
                go.Click += delegate
                {
                    if (!BlockEngine.IsElevated()) { ShowText("Repair", "Run kisib as administrator to change Trusted Root."); return; }
                    StringBuilder report = new StringBuilder();
                    foreach (KeyValuePair<string, CertificateRecord> f in found)
                    {
                        CertificateRecord c = f.Value;
                        try
                        {
                            using (X509Certificate2 cert = new X509Certificate2(c.Der))
                            {
                                if (f.Key.Contains("remove from Disallowed"))
                                    foreach (X509Location scope in new X509Location[] { X509Location.LocalMachine, X509Location.CurrentUser })
                                        using (X509Store store = new X509Store(StoreName.Disallowed, scope))
                                        {
                                            store.Open(OpenFlags.ReadWrite);
                                            foreach (X509Certificate2 hit in store.Certificates.Find(X509FindType.FindByThumbprint, c.Sha1, false)) store.Remove(hit);
                                            BlockedCertificates.Remove(scope, c.Sha1);
                                        }
                                if (f.Key.Contains("add to Trusted Root"))
                                    using (X509Store root = new X509Store(StoreName.Root, X509Location.LocalMachine))
                                    { root.Open(OpenFlags.ReadWrite); root.Add(cert); }
                            }
                            BlockEngine.Note("repair-trust", X509Location.LocalMachine, c.Sha256, c.Sha1, c.SubjectShortName, f.Key);
                            report.AppendLine("fixed   " + c.SubjectShortName + "   (" + f.Key + ")");
                        }
                        catch (Exception ex) { report.AppendLine("FAILED  " + c.SubjectShortName + "   " + ex.Message); }
                    }
                    dialog.Close();
                    ShowText("Repair Windows essentials", report.ToString());
                    StartScan();
                };
                dialog.Controls.Add(grid); dialog.Controls.Add(note); dialog.Controls.Add(go);
                dialog.ShowDialog(this);
            }
        }
    }
}
