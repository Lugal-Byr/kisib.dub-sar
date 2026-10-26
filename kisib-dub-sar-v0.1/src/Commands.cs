using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // kisib.dub-sar.exe --do "<command>" talks to the kisib already running, so Claude (through the desktop app's
    // shell on this PC) or a script can read what's going on and fix it: status, refusals, repairs, allows, unblocks.
    // The pipe only takes this Windows user, administrators and SYSTEM; nothing from the network.
    internal static class CommandClient
    {
        internal const string PipeName = "kisib.dub-sar.do";

        [DllImport("kernel32.dll")] private static extern IntPtr GetStdHandle(int which);
        [DllImport("kernel32.dll")] private static extern bool AttachConsole(int processId);

        // Returns the exit code: 0 answered, 2 kisib could not be reached, 1 error.
        internal static int Run(string command)
        {
            IntPtr output = GetStdHandle(-11);
            if (output == IntPtr.Zero || output == new IntPtr(-1)) AttachConsole(-1);
            if (command.Trim().Length == 0) command = "help";
            string reply; int code;
            try
            {
                reply = Ask(command, 2000);
                if (reply == null)
                {
                    bool running = true;
                    try { using (Mutex.OpenExisting(@"Local\kisib.dub-sar")) { } } catch (WaitHandleCannotBeOpenedException) { running = false; } catch (Exception) { }
                    if (!running)
                    {
                        // Not running: start it in the tray and wait for it to answer.
                        System.Diagnostics.Process.Start(Application.ExecutablePath, "--tray");
                        reply = Ask(command, 90000);
                    }
                }
                code = reply == null ? 2 : 0;
                if (reply == null) reply = "kisib didn't answer. If an older kisib is running, close it from the tray (Exit kisib) and start this one.";
            }
            catch (Exception ex) { reply = "Error: " + ex.Message; code = 1; }
            try { Console.Out.Write(reply.EndsWith("\n", StringComparison.Ordinal) ? reply : reply + "\r\n"); Console.Out.Flush(); } catch (Exception) { }
            return code;
        }

        private static string Ask(string command, int timeoutMs)
        {
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut))
            {
                try { pipe.Connect(timeoutMs); } catch (TimeoutException) { return null; } catch (IOException) { return null; }
                StreamWriter writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true);
                writer.Write(command.Replace("\r", " ").Replace("\n", " ") + "\n");
                writer.Flush();
                using (StreamReader reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, true)) return reader.ReadToEnd();
            }
        }
    }

    internal sealed partial class ExplorerForm
    {
        private int saidCount;

        private void StartCommandServer()
        {
            Thread server = new Thread(delegate()
            {
                int failures = 0;
                while (!closed && failures < 20)
                {
                    try
                    {
                        using (NamedPipeServerStream pipe = new NamedPipeServerStream(CommandClient.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 1 << 20, PipeRules()))
                        {
                            pipe.WaitForConnection();
                            string command;
                            using (StreamReader reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, true)) command = reader.ReadLine() ?? "";
                            string reply = Command(command.Trim());
                            try { File.WriteAllText(Storage.File(Storage.LastCommand), "> " + command + "\r\n" + reply, new UTF8Encoding(false)); } catch (Exception) { }
                            using (StreamWriter writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true)) { writer.Write(reply); writer.Flush(); }
                            try { pipe.WaitForPipeDrain(); } catch (IOException) { }
                        }
                        failures = 0;
                    }
                    catch (Exception ex) { failures++; CrashLog.Write("command pipe", ex); Thread.Sleep(1000); }
                }
            });
            server.IsBackground = true; server.Name = "kisib --do commands"; server.Start();
        }

        private static PipeSecurity PipeRules()
        {
            PipeSecurity rules = new PipeSecurity();
            rules.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            rules.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
            rules.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            rules.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            return rules;
        }

        // Runs on the window's thread; the pipe thread waits for it.
        private string OnWindow(Func<string> work, int timeoutMs)
        {
            string result = null; Exception error = null;
            using (ManualResetEvent done = new ManualResetEvent(false))
            {
                Post(delegate { try { result = work(); } catch (Exception ex) { error = ex; } finally { try { done.Set(); } catch (ObjectDisposedException) { } } });
                if (!done.WaitOne(timeoutMs)) return "kisib is busy (a window of its own may be open). Try again in a moment.";
            }
            if (error != null) { CrashLog.Write("command", error); return "Error: " + error.GetType().Name + ": " + error.Message; }
            return result ?? "done.";
        }

        // What Say() printed while the work ran, so a command gets the same line the status bar shows.
        private string Said(Action work)
        {
            int before = saidCount;
            work();
            return saidCount != before ? lastSay : "done.";
        }

        private bool WaitFor(Func<bool> ready, int seconds)
        {
            DateTime until = DateTime.Now.AddSeconds(seconds);
            while (!ready() && DateTime.Now < until && !closed) Thread.Sleep(250);
            return ready();
        }

        private const string CommandHelp =
            "kisib.dub-sar.exe --do \"<command>\"\r\n" +
            "  status                       what kisib sees now: blocks, rules, Claude's roots, recent refusals\r\n" +
            "  claude                       the roots the Claude app needs, blocked or not\r\n" +
            "  fix claude                   unblock / put back the roots Claude needs (overrides bloc rules)\r\n" +
            "  keep-claude on|off           the automatic Claude check after every scan\r\n" +
            "  denials [n]                  the last n refusals (default 20) with program, site and chain\r\n" +
            "  find <text>                  certificates whose name, issuer or SHA-1 has the text\r\n" +
            "  cert <sha1>                  one certificate: owner, where it is, blocked or not, which rules catch it\r\n" +
            "  rescan                       scan the stores again and wait for it\r\n" +
            "  repair <kind> [list]         essentials | online | windows | categories | claude | used | reset | putback\r\n" +
            "                               (add 'list' to see the rows without changing anything)\r\n" +
            "  allow <sha1|site> <3|10|60|restart|always>\r\n" +
            "  unblock <sha1|site>          unblock for good (never-block list)\r\n" +
            "  reblock                      close everything open right now (temporary allows)\r\n" +
            "  get-root <sha1|name>         put a missing root into Trusted Root, fresh from Microsoft's list\r\n" +
            "  get <site|program|name>      for the latest refusal that matches: unblock, import, or fetch what it asked for\r\n" +
            "  rules                        groups kept blocked\r\n" +
            "  unblock-bloc <name>          drop a bloc/continent/country rule and lift what kisib blocked for it\r\n" +
            "  quiet on|off                 refusal pop-ups\r\n" +
            "  log [n]                      the last n lines of block history (default 30)\r\n" +
            "  crashlog [n]                 the last n errors kisib caught (default 3)\r\n" +
            "Replies are also saved in " + Storage.FolderName + "\\" + Storage.LastCommand + "\r\n";

        // One command in, plain text out. Called on the pipe thread.
        private string Command(string line)
        {
            string[] words = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0) return CommandHelp;
            string verb = words[0].ToLowerInvariant();
            string rest = words.Length > 1 ? line.Substring(line.IndexOf(words[1], words[0].Length, StringComparison.Ordinal)).Trim() : "";
            string arg2 = words.Length > 2 ? words[words.Length - 1].ToLowerInvariant() : "";
            if (verb == "help" || verb == "?" || verb == "/?") return CommandHelp;
            if (verb == "crashlog") return CrashTail(Number(rest, 3));
            if (verb != "quiet" && verb != "keep-claude" && verb != "log" && verb != "rules" && !WaitFor(() => snapshot != null, 120))
                return "kisib is still on its first scan. Try again in a minute.";
            switch (verb)
            {
                case "status": return OnWindow(StatusReport, 20000);
                case "claude": return OnWindow(() => "Roots the Claude app needs (Let's Encrypt and Google Trust Services):\r\n" + ClaudeRootsReport() +
                    "Automatic check after every scan: " + (Storage.Setting("keep claude reachable off") ? "off" : "on") + "\r\n", 20000);
                case "fix":
                    if (rest.ToLowerInvariant() != "claude") return "fix what? Try: fix claude";
                {
                    string done = OnWindow(() => KeepReachable(true), 60000);
                    AfterRescan();
                    return done + "\r\n\r\nAfter the rescan:\r\n" + OnWindow(ClaudeRootsReport, 20000);
                }
                case "keep-claude":
                    if (rest != "on" && rest != "off") return "keep-claude on | off";
                    Storage.Setting("keep claude reachable off", rest == "off");
                    return "Keeping Claude reachable after every scan: " + rest + ".";
                case "denials": return OnWindow(() => DenialsReport(Number(rest, 20)), 20000);
                case "find": return OnWindow(() => FindReport(rest), 20000);
                case "cert": return OnWindow(() => CertReport(rest), 20000);
                case "rescan":
                    OnWindow(() => { StartScan(true); return ""; }, 10000);
                    return AfterRescan() + "\r\n" + OnWindow(() => lastSay ?? status.Text, 10000);
                case "repair":
                {
                    string kind = words.Length > 1 ? words[1].ToLowerInvariant() : "";
                    if (!RepairKinds.Contains(kind)) return "repair what? " + String.Join(" | ", RepairKinds);
                    if (arg2 == "list") return OnWindow(() => RepairListing(kind), 20000);
                    string done = OnWindow(() => { string r = RunRepair(kind); StartScan(true); return r; }, 60000);
                    return done + "\r\n" + AfterRescan();
                }
                case "allow":
                {
                    if (words.Length < 3) return "allow <sha1|site> <3|10|60|restart|always>";
                    string how = words[words.Length - 1].ToLowerInvariant(), what = String.Join(" ", words.Skip(1).Take(words.Length - 2).ToArray());
                    return OnWindow(() => CommandAllow(what, how), 30000) + "\r\n" + AfterRescan();
                }
                case "unblock":
                    if (rest.Length == 0) return "unblock <sha1|site>";
                    return OnWindow(() =>
                    {
                        string label; List<CertificateRecord> certs = Resolve(rest, out label);
                        if (certs == null) return label;
                        return Said(() => UnblockCertificates(certs, "unblocked by command: " + label));
                    }, 30000) + "\r\n" + AfterRescan();
                case "get":
                {
                    if (rest.Length < 3) return "get <site|program|name>";
                    string result = OnWindow(() =>
                    {
                        Denial d = denials.Where(x => !x.Ok && !x.Noise && ((x.Site ?? "").IndexOf(rest, StringComparison.OrdinalIgnoreCase) >= 0 || (x.Subject ?? "").IndexOf(rest, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            (x.Program ?? "").IndexOf(rest, StringComparison.OrdinalIgnoreCase) >= 0)).OrderByDescending(x => x.Time).FirstOrDefault();
                        if (d == null) return "No refusal matching " + rest + ".";
                        GetRequested(d); return lastSay;
                    }, 20000);
                    WaitFor(() => !gettingRequested && !fetchingRoots, 200);
                    return result + "\r\n" + OnWindow(() => lastSay, 10000);
                }
                case "get-root":
                {
                    if (rest.Length < 3) return "get-root <sha1|name>";
                    string want = rest.Replace(" ", "").Replace(":", "");
                    string started = OnWindow(() => { FetchFromMicrosoft(c => c.Sha1.StartsWith(want, StringComparison.OrdinalIgnoreCase) || String.Equals(c.SubjectShortName, rest, StringComparison.OrdinalIgnoreCase) || String.Equals(c.SubjectCn, rest, StringComparison.OrdinalIgnoreCase), rest); return lastSay; }, 10000);
                    WaitFor(() => !fetchingRoots, 200);
                    return started + "\r\n" + OnWindow(() => lastSay, 10000);
                }
                case "reblock":
                    return OnWindow(() => { List<TempAllowEntry> done = TempAllow.RestoreNow(e => true); StartScan(true); return done.Count == 0 ? "Nothing was open." : "Re-blocked " + done.Count + " (" + String.Join(", ", done.Select(e => e.Subject).Distinct().ToArray()) + ")."; }, 30000);
                case "rules":
                {
                    List<BlockRule> rules = BlockRules.Read();
                    return rules.Count == 0 ? "No rules: kisib keeps no group blocked." : String.Join("\r\n", rules.Select(r => "  " + r.Label + "  [" + r.Scope + ", since " + r.Created + "]").ToArray()) + "\r\n";
                }
                case "unblock-bloc":
                    if (rest.Length == 0) return "unblock-bloc <name>  (see: rules)";
                    return OnWindow(() =>
                    {
                        if (groups == null) return "Groups aren't built yet; try again after the scan.";
                        List<GroupNode> hits = groups.All.Where(g => String.Equals(g.Label, rest, StringComparison.OrdinalIgnoreCase) || String.Equals(g.Key, rest, StringComparison.OrdinalIgnoreCase)).ToList();
                        if (hits.Count == 0) hits = groups.All.Where(g => g.Label.IndexOf(rest, StringComparison.OrdinalIgnoreCase) >= 0 && BlockRules.Read().Any(r => r.GroupKey == g.Key)).ToList();
                        if (hits.Count == 0) return "No group called " + rest + ". Rules now:\r\n" + String.Join("\r\n", BlockRules.Read().Select(r => "  " + r.Label).ToArray());
                        if (hits.Count > 1) return "More than one matches; say which:\r\n" + String.Join("\r\n", hits.Take(30).Select(g => "  " + g.Label).ToArray());
                        return Said(() => UnblockGroups(hits));
                    }, 60000) + "\r\n" + AfterRescan();
                case "quiet":
                    if (rest != "on" && rest != "off") return "quiet on | off";
                    return OnWindow(() => { if (QuietMode != (rest == "on")) ToggleQuiet(); return "Quiet mode " + rest + "."; }, 10000);
                case "log":
                {
                    List<BlockLogRow> rows = BlockEngine.ReadLog();
                    return String.Join("\r\n", rows.Skip(Math.Max(0, rows.Count - Number(rest, 30))).Select(r => r.Time.Replace("T", " ").Substring(0, Math.Min(19, r.Time.Length)) + "  " + r.Action + "  " + r.Scope + "  " + r.Result + "  " + r.Subject + "  (" + r.Group + ")").ToArray()) + "\r\n";
                }
            }
            return "Unknown command: " + verb + "\r\n\r\n" + CommandHelp;
        }

        private static string CrashTail(int count)
        {
            string path = Storage.File(Storage.CrashLog);
            if (!File.Exists(path)) return "No errors caught: " + Storage.CrashLog + " doesn't exist.";
            string text;
            using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (f.Length > 512 * 1024) f.Seek(-512 * 1024, SeekOrigin.End);
                using (StreamReader r = new StreamReader(f, Encoding.UTF8)) text = r.ReadToEnd();
            }
            string[] entries = text.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            return String.Join("\r\n\r\n", entries.Skip(Math.Max(0, entries.Length - count)).ToArray()) + "\r\n";
        }

        private static int Number(string text, int fallback)
        {
            int n; return Int32.TryParse(text, out n) && n > 0 ? Math.Min(n, 2000) : fallback;
        }

        // Waits for the scan a change started, then says what kisib sees for Claude.
        private string AfterRescan()
        {
            Thread.Sleep(300);
            WaitFor(() => !scanning, 180);
            return "";
        }

        // A SHA-1 (or its start), or a site / name from a recent refusal.
        private List<CertificateRecord> Resolve(string what, out string label)
        {
            string hex = what.Replace(" ", "").Replace(":", "").ToUpperInvariant();
            if (hex.Length >= 8 && hex.All(Uri.IsHexDigit))
            {
                List<CertificateRecord> hits = snapshot.Certificates.Values.Where(c => c.Sha1.StartsWith(hex, StringComparison.OrdinalIgnoreCase) || (c.Sha256 != null && c.Sha256.StartsWith(hex, StringComparison.OrdinalIgnoreCase)))
                    .GroupBy(c => c.Sha1).Select(g => g.First()).ToList();
                if (hits.Count == 1) { label = hits[0].SubjectShortName; return hits; }
                if (hits.Count > 1) { label = "More than one certificate starts with " + hex + "; give more of the SHA-1."; return null; }
                Seal seal = Seals.All.FirstOrDefault(s => s.Sha1.StartsWith(hex, StringComparison.OrdinalIgnoreCase));
                if (seal != null) { label = seal.Name; return new List<CertificateRecord> { seal.Record }; }
                label = "No certificate on this PC has SHA-1 " + hex + "."; return null;
            }
            string key = what.Trim().TrimStart('*', '.').ToLowerInvariant();
            Denial d = denials.Where(x => !x.Ok && !x.Noise && (x.Keys.Contains(key) || x.Key.EndsWith(key, StringComparison.Ordinal) || (x.Subject ?? "").IndexOf(what, StringComparison.OrdinalIgnoreCase) >= 0))
                .OrderByDescending(x => x.Time).FirstOrDefault();
            if (d == null) { label = "No refusal for " + what + " on record. Use a SHA-1 (find <name> lists them)."; return null; }
            label = d.Subject;
            List<CertificateRecord> certs = CertificatesBehind(d);
            if (certs.Count == 0) { label = "Nothing kisib blocks is behind " + what + " (" + ShortReason(d.Reason) + ")."; return null; }
            return certs;
        }

        private string CommandAllow(string what, string how)
        {
            string label; List<CertificateRecord> certs = Resolve(what, out label);
            if (certs == null) return label;
            if (snapshot != null) certs = WithTwins(certs).Where(snapshot.IsBlocked).ToList();
            if (certs.Count == 0) return "Nothing to allow: " + label + " is not blocked.";
            if (how == "always") return Said(() => AllowAlways(certs, label));
            if (how == "restart") return Said(() => AllowFor(certs, label, TimeSpan.FromDays(3650), "restart"));
            int minutes;
            if (!Int32.TryParse(how.TrimEnd('m'), out minutes) || minutes < 1 || minutes > 24 * 60) return "How long? 3, 10, 60 (minutes), restart, or always.";
            return Said(() => AllowFor(certs, label, TimeSpan.FromMinutes(minutes), "timed"));
        }

        private string StatusReport()
        {
            StringBuilder t = new StringBuilder();
            t.Append("kisib.dub-sar ").Append(AboutText.Version).Append(" · ").Append(Application.ExecutablePath).Append("\r\n");
            t.Append("Running as administrator: ").Append(Elevation.IsElevated ? "yes" : "no (whole-PC changes and Trusted Root need it)").Append("\r\n");
            t.Append("Lists folder: ").Append(Storage.Folder).Append("\r\n");
            int listed = AuthRootList.Sha1s().Count;
            t.Append("Windows' own root list: ").Append(listed == 0 ? "none stored" : listed + " roots" + (AuthRootList.Synced.HasValue ? ", synced " + AuthRootList.Synced.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : ""))
             .Append(" · automatic root download: ").Append(RootAutoUpdateOff() ? "OFF (policy)" : "on").Append("\r\n");
            if (snapshot != null)
                t.Append("Certificates: ").Append(snapshot.Certificates.Count).Append(" · blocked ").Append(snapshot.Blocked.Count)
                 .Append(" (kisib made ").Append(snapshot.KisibBlockedSha1.Count).Append(") · leaks ").Append(snapshot.LeakCount).Append("\r\n");
            List<BlockRule> rules = BlockRules.Read();
            t.Append("Rules (kept blocked): ").Append(rules.Count == 0 ? "none" : String.Join(", ", rules.Select(r => r.Label).ToArray())).Append("\r\n");
            t.Append("Never block list: ").Append(AllowedList.Read().Count).Append(" · open right now: ").Append(TempAllow.Read().Select(e => e.Subject).Distinct().Count())
             .Append(" · program allows: ").Append(ProgramAllows.Read().Count).Append("\r\n");
            t.Append("Watching certificate checks: ").Append(denialWatcher != null ? "on" : "off").Append(" · quiet: ").Append(QuietMode ? "on" : "off")
             .Append(" · keep Claude reachable: ").Append(Storage.Setting("keep claude reachable off") ? "off" : "on").Append("\r\n");
            t.Append("\r\nRoots the Claude app needs:\r\n").Append(ClaudeRootsReport());
            int today = denials.Count(d => !d.Ok && !d.Noise && d.Time.Date == DateTime.Today);
            t.Append("\r\nRefusals today: ").Append(today).Append("\r\n").Append(DenialsReport(8));
            if (lastSay != null) t.Append("\r\nLast thing kisib said (").Append(lastSayAt.ToString("HH:mm:ss")).Append("): ").Append(lastSay).Append("\r\n");
            return t.ToString();
        }

        private string DenialsReport(int count)
        {
            List<Denial> list = denials.Where(d => !d.Ok && !d.Noise).Reverse().Take(count).ToList();
            if (list.Count == 0) return "  no refusals on record\r\n";
            StringBuilder t = new StringBuilder();
            foreach (Denial d in list)
            {
                t.Append("  ").Append(d.Time.ToString("MM-dd HH:mm:ss")).Append("  ").Append(String.IsNullOrEmpty(d.Program) ? "?" : Path.GetFileName(d.Program))
                 .Append(d.Service != null ? " (" + d.Service + ")" : "").Append(" → ").Append(d.Site ?? d.Subject).Append("  ").Append(d.Code).Append("  ").Append(ShortReason(d.Reason ?? ""));
                if (d.ChainSha1.Count > 0)
                {
                    t.Append("\r\n      chain: ");
                    for (int i = 0; i < d.ChainSha1.Count; i++)
                    {
                        CertificateRecord c = snapshot == null ? null : snapshot.BySha1(d.ChainSha1[i]);
                        t.Append(i > 0 ? " → " : "").Append(i < d.ChainNames.Count ? d.ChainNames[i] : "?").Append(" [").Append(d.ChainSha1[i].Substring(0, 10))
                         .Append(c != null && snapshot.IsBlocked(c) ? " BLOCKED" : "").Append("]");
                    }
                }
                t.Append("\r\n");
            }
            return t.ToString();
        }

        private string FindReport(string text)
        {
            if (text.Length < 2) return "find <text>: at least 2 letters.";
            List<CertificateRecord> hits = snapshot.Certificates.Values.Where(c => (c.SubjectShortName ?? "").IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0 ||
                (c.IssuerShortName ?? "").IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0 || c.Sha1.StartsWith(text, StringComparison.OrdinalIgnoreCase))
                .GroupBy(c => c.Sha1).Select(g => g.First()).OrderBy(c => c.SubjectShortName).Take(60).ToList();
            if (hits.Count == 0) return "Nothing on this PC matches " + text + ".";
            return String.Join("\r\n", hits.Select(c => "  " + c.Sha1 + "  " + c.SubjectShortName + "  ← " + c.IssuerShortName + "  " + (snapshot.IsBlocked(c) ? "BLOCKED" : "not blocked") +
                (TrustGraph.InRootStore(c) ? " · in Trusted Root" : "")).ToArray()) + "\r\n";
        }

        private string CertReport(string what)
        {
            string label; List<CertificateRecord> certs = Resolve(what, out label);
            if (certs == null) return label;
            CertificateRecord c = certs[0];
            StringBuilder t = new StringBuilder();
            t.Append(c.SubjectShortName).Append("\r\n  vouched for by ").Append(c.IssuerShortName).Append("\r\n  owner ").Append(OwnerName(c)).Append(" · country ").Append(c.SubjectCountry ?? "—")
             .Append("\r\n  blocs ").Append(TagsOf(c)).Append("\r\n  SHA-1 ").Append(c.Sha1).Append("\r\n  expires ").Append(c.NotAfter.HasValue ? c.NotAfter.Value.ToString("yyyy-MM-dd") : "?")
             .Append("\r\n  ").Append(snapshot.IsBlocked(c) ? "BLOCKED" : "not blocked").Append(TrustGraph.InRootStore(c) ? " · in Trusted Root" : "")
             .Append(snapshot.KisibBlockedSha1.Contains(c.Sha1) ? " · kisib blocked it" : "").Append(AllowedList.Load().Covers(c) ? " · on the never-block list" : "")
             .Append("\r\n  found in ").Append(String.Join(", ", c.FoundIn.Distinct().ToArray()));
            Dictionary<string, string> ruled = RuledMembers();
            string rule;
            if (ruled.TryGetValue(c.Identity, out rule)) t.Append("\r\n  caught by your rule: ").Append(rule);
            Seal seal = Seals.BySha1(c.Sha1);
            if (seal != null) t.Append("\r\n  kisib carries it as a standard seal: ").Append(seal.Purpose);
            return t.Append("\r\n").ToString();
        }

        private string RepairListing(string kind)
        {
            RepairSet set = BuildRepair(kind);
            StringBuilder t = new StringBuilder(set.Title).Append("\r\n").Append(set.Intro).Append("\r\n");
            foreach (RepairRow r in set.Rows)
                t.Append(r.Check ? "  [x] " : "  [ ] ").Append(r.Name).Append(" (").Append(r.Owner).Append(", ").Append(r.Country).Append(")  → ").Append(WillDo(r))
                 .Append(r.Note != null ? "  · " + r.Note : "").Append("\r\n");
            return t.Append("Ticked rows are what 'repair ").Append(kind).Append("' does.\r\n").ToString();
        }

        // Tray and Tools: the exact line to give Claude so it can drive kisib from the desktop app.
        internal static string CommandLine(string command)
        {
            return "\"" + Application.ExecutablePath + "\" --do \"" + command + "\"";
        }
    }
}
