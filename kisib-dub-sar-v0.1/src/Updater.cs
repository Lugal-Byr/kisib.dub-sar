using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // Install to C:\certs\kisib and keep it up to date from the GitHub releases: checks after start and every
    // 12 hours, downloads the newest zip over HTTPS, checks it against GitHub's own SHA-256 for that file, swaps the
    // program files in place (PORTABLE BACKUP LISTS is never touched) and restarts in the tray.
    internal sealed partial class ExplorerForm
    {
        internal const string InstallFolder = @"C:\certs\kisib";
        private const string LatestRelease = "https://api.github.com/repos/Lugal-Byr/kisib.dub-sar/releases/latest";
        private readonly System.Windows.Forms.Timer updateTimer = new System.Windows.Forms.Timer { Interval = 60 * 1000 };
        private bool updating;
        private string updateNote;

        internal bool RepointStartup;
        internal string UpdatedTo;

        private void InitializeUpdates()
        {
            // Installed to C:\certs\kisib with Start with Windows on: point the logon task at this copy.
            Shown += delegate
            {
                if (UpdatedTo == "moved") Say("kisib now runs from " + AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\') + " and keeps itself up to date.");
                else if (UpdatedTo != null) Say("kisib updated to " + UpdatedTo + ".");
            };
            Shown += delegate { if (RepointStartup) try { ToggleStartup(true); } catch (Exception ex) { Say("Couldn't move Start with Windows to this copy: " + ex.Message); } };
            // Leftovers from the last swap.
            try { foreach (string old in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.old")) File.Delete(old); } catch (Exception) { }
            updateTimer.Tick += delegate { updateTimer.Interval = 12 * 60 * 60 * 1000; CheckForUpdate(false); };
            updateTimer.Start();
        }

        internal static bool AutoUpdate { get { return !Storage.Setting("auto update off"); } }

        private static int VersionNumber(string tag)
        {
            Match m = Regex.Match(tag ?? "", @"v?\d+\.\d+\.(\d+)");
            int n; return m.Success && Int32.TryParse(m.Groups[1].Value, out n) ? n : -1;
        }

        // manual = the user asked: always say what happened, and update even when auto update is off.
        internal void CheckForUpdate(bool manual)
        {
            if (updating) { if (manual) Say("Already updating."); return; }
            if (!manual && !AutoUpdate) return;
            updating = true;
            if (manual) Say("Checking GitHub for a newer kisib...");
            string current = AboutText.Version;
            Thread worker = new Thread(delegate()
            {
                string result;
                bool restart = false;
                string newTag = null;
                try { result = UpdateNow(current, manual, out restart, out newTag); }
                catch (Exception ex) { result = "Update failed: " + ex.Message; CrashLog.Write("update", ex); }
                Post(delegate
                {
                    updating = false;
                    updateNote = result;
                    if (result != null && (manual || restart || result.StartsWith("Update failed", StringComparison.Ordinal))) Say(result);
                    if (restart)
                    {
                        // The new copy waits for this process to be gone, then opens the way this one was (window or tray).
                        string next = "--restarted --after " + Process.GetCurrentProcess().Id + (Visible ? "" : " --tray") + " --updated " + (newTag ?? "new");
                        try { Process.Start(Application.ExecutablePath, next); } catch (Exception ex) { Say("Updated, but couldn't restart: " + ex.Message); return; }
                        ExitForRestart();
                    }
                });
            });
            worker.IsBackground = true; worker.Name = "kisib update"; worker.Start();
        }

        // Closes kisib for a restart; if anything holds it open, it is ended after 20 seconds so the new copy can start.
        private void ExitForRestart()
        {
            Thread guard = new Thread(delegate() { Thread.Sleep(20000); Environment.Exit(0); });
            guard.IsBackground = true; guard.Start();
            ExitApp();
        }

        private string UpdateNow(string current, bool manual, out bool restart, out string newTag)
        {
            restart = false; newTag = null;
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            string json;
            using (WebClient web = new WebClient())
            {
                web.Headers[HttpRequestHeader.UserAgent] = "kisib.dub-sar";
                json = web.DownloadString(LatestRelease);
            }
            string tag = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"([^\"]+)\"").Groups[1].Value;
            newTag = tag;
            Match asset = Regex.Match(json, "\"browser_download_url\"\\s*:\\s*\"(https://github\\.com/Lugal-Byr/kisib\\.dub-sar/releases/download/[^\"]+-windows\\.zip)\"");
            if (tag.Length == 0 || !asset.Success) return manual ? "Couldn't read the latest release from GitHub." : null;
            int have = VersionNumber(current), latest = VersionNumber(tag);
            if (latest <= have) return manual ? "kisib is up to date (" + current + ")." : null;
            if (have < 0 && !manual) return null;   // a dev build never updates itself
            // GitHub's own SHA-256 of the zip, from the same answer.
            string zipName = asset.Groups[1].Value.Substring(asset.Groups[1].Value.LastIndexOf('/') + 1);
            Match digest = Regex.Match(json, "\"name\"\\s*:\\s*\"" + Regex.Escape(zipName) + "\"[\\s\\S]{0,1500}?\"digest\"\\s*:\\s*\"sha256:([0-9a-fA-F]{64})\"");
            string folder = AppDomain.CurrentDomain.BaseDirectory;
            if (!CanWrite(folder)) return "kisib " + tag + " is out, but this folder needs admin to change (" + folder + "). Run kisib as administrator once to update.";
            // Admin-only when kisib runs as admin, so nothing can swap files between unpacking and copying.
            string temp = PrivateFolder(Elevation.IsElevated);
            try
            {
                string zip = Path.Combine(temp, zipName);
                using (WebClient web = new WebClient()) { web.Headers[HttpRequestHeader.UserAgent] = "kisib.dub-sar"; web.DownloadFile(asset.Groups[1].Value, zip); }
                if (digest.Success)
                {
                    string got;
                    using (SHA256 sha = SHA256.Create()) using (FileStream f = File.OpenRead(zip)) got = BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "");
                    if (!got.Equals(digest.Groups[1].Value, StringComparison.OrdinalIgnoreCase)) return "Update " + tag + " stopped: the download doesn't match GitHub's SHA-256 for it.";
                }
                string unpacked = Path.Combine(temp, "x");
                ProcessStartInfo expand = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"Expand-Archive -LiteralPath '" + zip.Replace("'", "''") + "' -DestinationPath '" + unpacked.Replace("'", "''") + "' -Force\"")
                { UseShellExecute = false, CreateNoWindow = true };
                using (Process p = Process.Start(expand)) { if (!p.WaitForExit(120000) || p.ExitCode != 0) return "Update " + tag + " stopped: couldn't unpack the zip."; }
                string source = Directory.GetFiles(unpacked, "kisib.dub-sar.exe", SearchOption.AllDirectories).Select(Path.GetDirectoryName).FirstOrDefault();
                if (source == null) return "Update " + tag + " stopped: the zip has no kisib.dub-sar.exe.";
                CopyRelease(source, folder);
                restart = true;
                return "Updated to " + tag + " (from " + current + "). Restarting in the tray.";
            }
            finally { try { Directory.Delete(temp, true); } catch (Exception) { } }
        }

        // Program files only: the running exe is renamed out of the way (Windows allows that), everything else is
        // overwritten. PORTABLE BACKUP LISTS is skipped, so blocks, rules and settings stay as they are.
        private static void CopyRelease(string source, string target)
        {
            string exe = Application.ExecutablePath;
            foreach (string file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                string relative = file.Substring(source.Length).TrimStart('\\', '/');
                if (relative.StartsWith(Storage.FolderName, StringComparison.OrdinalIgnoreCase)) continue;
                string to = Path.Combine(target, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(to));
                if (File.Exists(to) && String.Equals(Path.GetFullPath(to), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
                {
                    string old = to + "." + DateTime.Now.Ticks + ".old";
                    File.Move(to, old);
                }
                File.Copy(file, to, true);
            }
        }

        private static bool CanWrite(string folder)
        {
            try { string probe = Path.Combine(folder, "kisib-write-test-" + Guid.NewGuid().ToString("N")); File.WriteAllText(probe, ""); File.Delete(probe); return true; }
            catch (Exception) { return false; }
        }

        // ---- Install to C:\certs\kisib --------------------------------------------------------------------------

        internal void InstallToCerts()
        {
            string here = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            if (String.Equals(here, InstallFolder, StringComparison.OrdinalIgnoreCase)) { Say("kisib already runs from " + InstallFolder + "."); return; }
            try
            {
                Directory.CreateDirectory(InstallFolder);
                foreach (string file in Directory.GetFiles(here, "*", SearchOption.AllDirectories))
                {
                    string relative = file.Substring(here.Length).TrimStart('\\');
                    if (relative.EndsWith(".old", StringComparison.OrdinalIgnoreCase)) continue;
                    string to = Path.Combine(InstallFolder, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(to));
                    // Lists come along only if the new folder has none yet; an existing install keeps its own.
                    if (relative.StartsWith(Storage.FolderName, StringComparison.OrdinalIgnoreCase) && File.Exists(to)) continue;
                    File.Copy(file, to, true);
                }
                bool startup = StartupTaskExists();
                AppChains.Flush();
                Process.Start(Path.Combine(InstallFolder, "kisib.dub-sar.exe"), "--restarted --after " + Process.GetCurrentProcess().Id + (Visible ? "" : " --tray") + " --updated moved" + (startup ? " --installed-startup" : ""));
                Say("Installed to " + InstallFolder + "; that copy is starting and keeps itself up to date.");
                ExitForRestart();
            }
            catch (Exception ex) { Say("Couldn't install to " + InstallFolder + ": " + ex.Message + (Elevation.IsElevated ? "" : " (run kisib as administrator once)")); }
        }
    }
}
