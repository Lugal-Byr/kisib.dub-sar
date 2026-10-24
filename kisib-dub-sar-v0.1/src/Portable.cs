using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Everything kisib remembers lives in plain .txt files in "PORTABLE BACKUP LISTS" next to the exe.
    // Copy the kisib folder anywhere (USB stick, D: drive); after a reformat, run it and your blocks come back.
    internal static class Storage
    {
        internal const string FolderName = "PORTABLE BACKUP LISTS";
        private static string folder;

        internal static string Folder
        {
            get
            {
                if (folder != null) return folder;
                string portable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FolderName);
                try
                {
                    Directory.CreateDirectory(portable);
                    string probe = Path.Combine(portable, ".write-test");
                    System.IO.File.WriteAllText(probe, "ok"); System.IO.File.Delete(probe);
                    folder = portable;
                }
                catch (Exception)
                {
                    // Folder not writable (for example under Program Files): fall back to AppData.
                    folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "kisib.dub-sar", FolderName);
                    Directory.CreateDirectory(folder);
                }
                Migrate(folder);
                WriteReadme(folder);
                return folder;
            }
        }

        internal static string File(string name) { return Path.Combine(Folder, name); }

        internal const string BlockHistory = "BLOCK HISTORY.txt";
        internal const string BlockedList = "BLOCKED CERTIFICATES (re-applied after reformat).txt";
        internal const string Rules = "RULES (groups kept blocked).txt";
        internal const string MyTags = "MY TAGS.txt";
        internal const string TempAllows = "TEMP ALLOWS (re-blocked automatically).txt";
        internal const string Denials = "DENIALS (refused certificates log).txt";
        internal const string Settings = "SETTINGS.txt";
        internal const string RouteList = "ROUTES (cross-signs kisib added so Windows can go around blocks).txt";

        // New version unzipped next to an older one: carry the newest older PORTABLE BACKUP LISTS over.
        private static void CarryFromOlderVersion(string target)
        {
            try
            {
                if (Directory.GetFiles(target, "*.txt").Any(f => !Path.GetFileName(f).StartsWith("README", StringComparison.Ordinal))) return;
                DirectoryInfo here = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/'));
                List<DirectoryInfo> roots = new List<DirectoryInfo>();
                if (here.Parent != null) roots.Add(here.Parent);
                if (here.Parent != null && here.Parent.Parent != null) roots.Add(here.Parent.Parent);
                DirectoryInfo best = null;
                foreach (DirectoryInfo root in roots)
                    foreach (DirectoryInfo d in root.GetDirectories("kisib*"))
                        foreach (DirectoryInfo candidate in new[] { d }.Concat(d.GetDirectories("kisib*")))
                        {
                            DirectoryInfo lists = new DirectoryInfo(Path.Combine(candidate.FullName, FolderName));
                            if (!lists.Exists || String.Equals(lists.FullName.TrimEnd('\\'), target.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) continue;
                            if (best == null || lists.LastWriteTimeUtc > best.LastWriteTimeUtc) best = lists;
                        }
                if (best == null) return;
                foreach (FileInfo f in best.GetFiles())
                {
                    string to = Path.Combine(target, f.Name);
                    if (!System.IO.File.Exists(to)) f.CopyTo(to);
                }
            }
            catch (Exception) { }
        }

        // One-time copy of lists from the old AppData location, so nothing is lost on upgrade.
        private static void Migrate(string target)
        {
            CarryFromOlderVersion(target);
            string old = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "kisib.dub-sar");
            Dictionary<string, string> map = new Dictionary<string, string>
            {
                { "block-history.csv", BlockHistory }, { "rules.csv", Rules }, { "my-tags.csv", MyTags },
                { "temp-allow.csv", TempAllows }, { "denials.csv", Denials }, { "WURoots.sst", "microsoft-root-list.sst" },
                { "ccadb-pems-2010s.csv", "ccadb-list-2010s.csv" }, { "ccadb-pems-2020s.csv", "ccadb-list-2020s.csv" }
            };
            foreach (KeyValuePair<string, string> m in map)
            {
                string from = Path.Combine(old, m.Key), to = Path.Combine(target, m.Value);
                try { if (System.IO.File.Exists(from) && !System.IO.File.Exists(to)) System.IO.File.Copy(from, to); } catch (IOException) { }
            }
        }

        private static void WriteReadme(string target)
        {
            string readme = Path.Combine(target, "README - what these files are.txt");
            if (System.IO.File.Exists(readme)) return;
            try
            {
                System.IO.File.WriteAllText(readme,
                    "kisib.dub-sar keeps everything it remembers in this folder, as plain text.\r\n" +
                    "Copy the whole kisib folder (with this folder inside) to a USB stick or another drive to keep it.\r\n" +
                    "After a reformat: run kisib.dub-sar.exe as administrator once. It puts every block back.\r\n\r\n" +
                    BlockedList + "  - every certificate kisib blocked, with the certificate itself, so it can be put back\r\n" +
                    Rules + "  - groups kisib keeps blocked; new matches get blocked automatically\r\n" +
                    MyTags + "  - your own tags (country, organization, certificate)\r\n" +
                    BlockHistory + "  - every block, unblock, allow and re-block, with time\r\n" +
                    TempAllows + "  - blocks lifted for a few minutes; kisib puts them back\r\n" +
                    RouteList + "  - cross-signed certificates added so Windows can reach a site through another root\r\n" +
                    Denials + "  - certificates Windows refused, and which program asked\r\n" +
                    "SETTING - *.txt  - on/off switches: the file existing means the switch is on\r\n" +
                    "microsoft-root-list.sst, ccadb-list-*.csv  - downloaded lists (Tools menu refreshes them)\r\n\r\n" +
                    "All of these are comma-separated text with a header line. Notepad opens them. Editing by hand works;\r\n" +
                    "keep the header line and the commas.\r\n", new UTF8Encoding(false));
            }
            catch (IOException) { }
        }

        // Simple on/off switches in SETTINGS.txt, one "name = on" per line.
        internal static bool Setting(string name)
        {
            try
            {
                string path = File(Settings);
                if (!System.IO.File.Exists(path)) return false;
                return System.IO.File.ReadAllLines(path).Any(l => l.Trim().Equals(name + " = on", StringComparison.OrdinalIgnoreCase));
            }
            catch (IOException) { return false; }
        }

        internal static void Setting(string name, bool on)
        {
            try
            {
                string path = File(Settings);
                List<string> lines = System.IO.File.Exists(path) ? System.IO.File.ReadAllLines(path).ToList() : new List<string> { "# kisib switches: name = on / off" };
                lines.RemoveAll(l => l.Trim().StartsWith(name + " =", StringComparison.OrdinalIgnoreCase));
                lines.Add(name + " = " + (on ? "on" : "off"));
                System.IO.File.WriteAllLines(path, lines.ToArray(), new UTF8Encoding(false));
            }
            catch (IOException) { }
        }
    }

    // The list of certificates kisib blocked, with the certificate bytes, so blocks survive a reformat.
    internal static class BlockedCertificates
    {
        private const string Header = "scope,sha1,sha256,subject,certificate_base64";

        private static List<string[]> Read()
        {
            string path = Storage.File(Storage.BlockedList);
            return System.IO.File.Exists(path) ? GroupCatalog.ReadCsv(path, 64L * 1024 * 1024).Skip(1).Where(f => f.Length >= 5).ToList() : new List<string[]>();
        }

        private static void Write(List<string[]> rows)
        {
            StringBuilder text = new StringBuilder(Header).Append("\r\n");
            foreach (string[] r in rows) text.Append(String.Join(",", r.Select(Q).ToArray())).Append("\r\n");
            System.IO.File.WriteAllText(Storage.File(Storage.BlockedList), text.ToString(), new UTF8Encoding(false));
        }
        private static string Q(string v) { v = v ?? ""; return v.IndexOfAny(new char[] { ',', '"' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        internal static void Add(X509Location scope, CertificateRecord c)
        {
            try
            {
                List<string[]> rows = Read();
                if (rows.Any(r => r[0] == scope.ToString() && r[1] == c.Sha1)) return;
                rows.Add(new string[] { scope.ToString(), c.Sha1, c.Sha256, c.SubjectShortName, Convert.ToBase64String(c.Der) });
                Write(rows);
            }
            catch (IOException) { }
        }

        internal static void Remove(X509Location scope, string sha1)
        {
            try
            {
                List<string[]> rows = Read();
                if (rows.RemoveAll(r => r[0] == scope.ToString() && String.Equals(r[1], sha1, StringComparison.OrdinalIgnoreCase)) > 0) Write(rows);
            }
            catch (IOException) { }
        }

        // Puts back any listed block that is missing (fresh Windows, or someone removed it). Returns how many.
        internal static int Reapply(out string skipped)
        {
            skipped = null;
            List<string[]> rows;
            try { rows = Read(); } catch (Exception) { return 0; }
            int restored = 0;
            bool elevated = BlockEngine.IsElevated();
            foreach (IGrouping<string, string[]> scopeRows in rows.GroupBy(r => r[0]))
            {
                X509Location scope;
                try { scope = (X509Location)Enum.Parse(typeof(X509Location), scopeRows.Key); } catch (ArgumentException) { continue; }
                if (scope == X509Location.LocalMachine && !elevated) { skipped = "Whole-PC blocks need kisib run as administrator to re-apply."; continue; }
                // A block lifted on purpose by "Allow for N minutes" is not re-applied early.
                HashSet<string> lifted = new HashSet<string>(TempAllow.Read().Where(t => t.Scope == scopeRows.Key).Select(t => t.Sha1), StringComparer.OrdinalIgnoreCase);
                using (X509Store store = new X509Store(StoreName.Disallowed, scope))
                {
                    store.Open(OpenFlags.ReadWrite);
                    foreach (string[] r in scopeRows)
                    {
                        if (lifted.Contains(r[1])) continue;
                        if (store.Certificates.Find(X509FindType.FindByThumbprint, r[1], false).Count > 0) continue;
                        try
                        {
                            using (X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(r[4]))) store.Add(cert);
                            restored++;
                            BlockEngine.Note("re-apply", scope, r[2], r[1], r[3], "re-applied from " + Storage.BlockedList);
                        }
                        catch (Exception) { }
                    }
                }
            }
            return restored;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private void InitializePortable(MenuItem file)
        {
            file.MenuItems.Add(5, new MenuItem("Open " + Storage.FolderName + " folder", delegate
            {
                try { System.Diagnostics.Process.Start("explorer.exe", "\"" + Storage.Folder + "\""); } catch (Exception ex) { ShowText(Storage.FolderName, Storage.Folder + "\r\n" + ex.Message); }
            }));
            Shown += delegate
            {
                string skipped;
                int restored = BlockedCertificates.Reapply(out skipped);
                if (restored > 0)
                {
                    if (tray != null) tray.ShowBalloonTip(6000, "kisib: blocks re-applied", restored + " blocked certificates were missing and have been put back.", ToolTipIcon.Info);
                    StartScan();
                }
                else if (skipped != null && System.IO.File.Exists(Storage.File(Storage.BlockedList)) && tray != null)
                    tray.ShowBalloonTip(6000, "kisib", skipped, ToolTipIcon.Info);
            };
        }
    }
}
