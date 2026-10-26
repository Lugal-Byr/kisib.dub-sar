using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Temporary allow, like a firewall's timed exception: lift blocks now, put every one back when time is up.
    // Pending re-blocks are written to disk first, so a crash or closed window still re-blocks on next start.
    // Mode: "timed" (until a time), "restart" (until kisib closes or the PC restarts), "program:<file.exe>" (while it runs).
    internal sealed class TempAllowEntry
    {
        internal string Scope, Sha1, Sha256, Subject, Der, Until, Mode = "timed";
        internal DateTime UntilUtc
        {
            get { DateTime t; return DateTime.TryParse(Until, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out t) ? t.ToUniversalTime() : DateTime.MinValue; }
        }
        internal string Program { get { return Mode != null && Mode.StartsWith("program:", StringComparison.Ordinal) ? Mode.Substring(8) : null; } }
    }

    internal sealed class LiftResult
    {
        internal int Removed, Errors;
        internal readonly List<string> Problems = new List<string>();
    }

    internal static class TempAllow
    {
        internal static string PendingPath { get { return Storage.File(Storage.TempAllows); } }
        private static List<TempAllowEntry> cache;
        private static DateTime cacheStamp;
        private static long cacheLength;

        internal static List<TempAllowEntry> Read()
        {
            if (!File.Exists(PendingPath)) { cache = null; return new List<TempAllowEntry>(); }
            FileInfo info = new FileInfo(PendingPath);
            if (cache == null || info.LastWriteTimeUtc != cacheStamp || info.Length != cacheLength)
            {
                List<TempAllowEntry> list = new List<TempAllowEntry>();
                foreach (string[] f in GroupCatalog.ReadCsv(PendingPath, 64L * 1024 * 1024).Skip(1))
                    if (f.Length >= 6) list.Add(new TempAllowEntry { Scope = f[0], Sha1 = f[1], Sha256 = f[2], Subject = f[3], Der = f[4], Until = f[5], Mode = f.Length >= 7 && f[6].Length > 0 ? f[6] : "timed" });
                cache = list; cacheStamp = info.LastWriteTimeUtc; cacheLength = info.Length;
            }
            return new List<TempAllowEntry>(cache);
        }

        internal static void Save(List<TempAllowEntry> list)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PendingPath));
            StringBuilder text = new StringBuilder("scope,sha1,sha256,subject,der_base64,until_utc,mode\r\n");
            foreach (TempAllowEntry e in list)
                text.Append(String.Join(",", new string[] { e.Scope, e.Sha1, e.Sha256, e.Subject, e.Der, e.Until, e.Mode }.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
            File.WriteAllText(PendingPath, text.ToString(), new UTF8Encoding(false));
            cache = null;
        }

        // Removes each certificate from Disallowed in every scope kisib can change; writes the re-block promise first.
        internal static LiftResult Lift(IEnumerable<CertificateRecord> certs, TimeSpan duration, string mode)
        {
            LiftResult result = new LiftResult();
            List<CertificateRecord> list = certs.Where(c => c != null && c.Der != null).GroupBy(c => c.Sha1).Select(g => g.First()).ToList();
            string until = DateTime.UtcNow.Add(duration).ToString("o", CultureInfo.InvariantCulture);
            List<TempAllowEntry> removed = new List<TempAllowEntry>();
            List<X509Location> scopes = new List<X509Location> { X509Location.CurrentUser };
            if (Elevation.IsElevated) scopes.Add(X509Location.LocalMachine);
            foreach (X509Location scope in scopes)
            {
                string error;
                using (OwnStore store = OwnStore.TryOpen("Disallowed", scope, true, out error))
                {
                    if (store == null) { result.Problems.Add(error); continue; }
                    List<TempAllowEntry> entries = list.Where(c => store.Has(c.Sha1)).Select(c => new TempAllowEntry { Scope = scope.ToString(), Sha1 = c.Sha1, Sha256 = c.Sha256,
                        Subject = c.SubjectShortName, Der = Convert.ToBase64String(c.Der), Until = until, Mode = mode }).ToList();
                    if (entries.Count == 0) continue;
                    // The re-block promise goes to disk before anything is removed.
                    List<TempAllowEntry> pending = Read();
                    foreach (TempAllowEntry e in entries) pending.RemoveAll(p => p.Scope == e.Scope && String.Equals(p.Sha1, e.Sha1, StringComparison.OrdinalIgnoreCase));
                    pending.AddRange(entries);
                    Save(pending);
                    foreach (TempAllowEntry e in entries)
                    {
                        try { if (store.Remove(e.Sha1)) { removed.Add(e); result.Removed++; } }
                        catch (Exception) { result.Errors++; }
                    }
                }
            }
            Log(removed, "temp-allow", "lifted " + (mode == "restart" ? "until kisib closes" : mode.StartsWith("program:", StringComparison.Ordinal) ? "while " + mode.Substring(8) + " runs" : "until " + until));
            return result;
        }

        // A program allow stays open while its program runs (checked every few seconds), and closes 2 minutes after it stops.
        internal static void KeepProgramsOpen()
        {
            List<TempAllowEntry> pending = Read();
            bool changed = false;
            foreach (IGrouping<string, TempAllowEntry> byProgram in pending.Where(p => p.Program != null).GroupBy(p => p.Program, StringComparer.OrdinalIgnoreCase))
            {
                if (!ProgramRunning(byProgram.Key)) continue;
                // Pushed forward about once a minute, not every second.
                string until = DateTime.UtcNow.AddMinutes(2).ToString("o", CultureInfo.InvariantCulture);
                foreach (TempAllowEntry e in byProgram) if (e.UntilUtc < DateTime.UtcNow.AddMinutes(1)) { e.Until = until; changed = true; }
            }
            if (changed) Save(pending);
        }

        internal static bool ProgramRunning(string exe)
        {
            try
            {
                Process[] found = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exe));
                bool any = found.Length > 0;
                foreach (Process p in found) p.Dispose();
                return any;
            }
            catch (Exception) { return false; }
        }

        // Puts back every lifted block whose time is up. force = all of them (kisib closing); startup = also the "until restart" ones.
        internal static List<TempAllowEntry> Restore(bool force, bool startup)
        {
            List<TempAllowEntry> pending = Read();
            if (pending.Count == 0) return pending;
            DateTime now = DateTime.UtcNow;
            List<TempAllowEntry> due = pending.Where(p => force || (p.Mode == "restart" ? startup : p.UntilUtc <= now)).ToList();
            List<TempAllowEntry> done = new List<TempAllowEntry>();
            foreach (IGrouping<string, TempAllowEntry> scope in due.GroupBy(p => p.Scope))
            {
                X509Location location;
                try { location = (X509Location)Enum.Parse(typeof(X509Location), scope.Key); } catch (ArgumentException) { done.AddRange(scope); continue; }
                if (location == X509Location.LocalMachine && !Elevation.IsElevated) continue;
                string error;
                using (OwnStore store = OwnStore.TryOpen("Disallowed", location, true, out error))
                {
                    if (store == null) continue;
                    foreach (TempAllowEntry e in scope)
                    {
                        try { store.Add(Convert.FromBase64String(e.Der)); done.Add(e); }
                        catch (Exception) { }
                    }
                }
            }
            if (done.Count > 0)
            {
                Save(pending.Where(p => !done.Any(d => d.Scope == p.Scope && String.Equals(d.Sha1, p.Sha1, StringComparison.OrdinalIgnoreCase))).ToList());
                Log(done, "re-block", "temporary allow ended");
            }
            return done;
        }

        // Re-block now, before the time is up.
        internal static List<TempAllowEntry> RestoreNow(Func<TempAllowEntry, bool> which)
        {
            List<TempAllowEntry> pending = Read();
            List<TempAllowEntry> pick = pending.Where(which).ToList();
            foreach (TempAllowEntry e in pick) e.Until = DateTime.UtcNow.AddSeconds(-1).ToString("o", CultureInfo.InvariantCulture);
            foreach (TempAllowEntry e in pick) if (e.Mode == "restart") e.Mode = "timed";
            Save(pending);
            return Restore(false, false);
        }

        private static void Log(List<TempAllowEntry> entries, string action, string note)
        {
            if (entries.Count == 0) return;
            string now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            BlockEngine.Append(entries.Select(e => new BlockLogRow { Time = now, Batch = "temp-" + now.Substring(0, 19), Action = action, Scope = e.Scope, Sha256 = e.Sha256,
                Sha1 = e.Sha1, Subject = e.Subject, Prior = "", Result = action == "temp-allow" ? "removed" : "added", Group = note }).ToList());
        }
    }

    // Standing rule: when this program starts (or gets refused), these blocks open while it runs.
    internal sealed class ProgramAllow
    {
        internal string Program, Label;
        internal List<string> Sha1 = new List<string>();
    }

    internal static class ProgramAllows
    {
        internal static string FilePath { get { return Storage.File(Storage.ProgramAllows); } }

        internal static List<ProgramAllow> Read()
        {
            List<ProgramAllow> list = new List<ProgramAllow>();
            try
            {
                if (!File.Exists(FilePath)) return list;
                foreach (string[] f in GroupCatalog.ReadCsv(FilePath).Skip(1))
                    if (f.Length >= 3 && f[0].Trim().Length > 0)
                        list.Add(new ProgramAllow { Program = f[0].Trim(), Label = f[1], Sha1 = f[2].Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList() });
            }
            catch (Exception) { }
            return list;
        }

        internal static void Save(List<ProgramAllow> list)
        {
            StringBuilder text = new StringBuilder("program,label,sha1_list\r\n");
            foreach (ProgramAllow a in list)
                text.Append(String.Join(",", new string[] { a.Program, a.Label, String.Join(" ", a.Sha1.ToArray()) }.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
            File.WriteAllText(FilePath, text.ToString(), new UTF8Encoding(false));
        }

        internal static void Add(string program, string label, IEnumerable<CertificateRecord> certs)
        {
            List<ProgramAllow> list = Read();
            ProgramAllow a = list.FirstOrDefault(x => String.Equals(x.Program, program, StringComparison.OrdinalIgnoreCase));
            if (a == null) { a = new ProgramAllow { Program = program, Label = label }; list.Add(a); }
            foreach (CertificateRecord c in certs) if (!a.Sha1.Contains(c.Sha1, StringComparer.OrdinalIgnoreCase)) a.Sha1.Add(c.Sha1);
            Save(list);
        }

        internal static void Remove(string program)
        {
            List<ProgramAllow> list = Read();
            if (list.RemoveAll(x => String.Equals(x.Program, program, StringComparison.OrdinalIgnoreCase)) > 0) Save(list);
        }
    }
}
