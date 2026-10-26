using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Blocking = adding the certificate to Windows' Disallowed (untrusted) store. Nothing is ever deleted from Root or CA.
    internal sealed class BlockItem
    {
        internal CertificateRecord Certificate;
        internal string Reason;
        internal bool AlreadyBlocked;
    }

    internal sealed class BlockLogRow
    {
        internal string Time, Batch, Action, Scope, Sha256, Sha1, Subject, Prior, Result, Group;
    }

    internal static class BlockEngine
    {
        internal static string LogPath
        {
            get { return Storage.File(Storage.BlockHistory); }
        }
        private const string LogHeader = "time_utc,batch,action,scope,sha256,sha1,subject,prior,result,group";

        internal static void Note(string action, X509Location scope, string sha256, string sha1, string subject, string note)
        {
            try
            {
                Append(new List<BlockLogRow> { new BlockLogRow { Time = Now(), Batch = action + "-" + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture),
                    Action = action, Scope = scope.ToString(), Sha256 = sha256, Sha1 = sha1, Subject = subject, Prior = "absent", Result = "added", Group = note } });
            }
            catch (IOException) { }
        }

        internal static bool IsElevated() { return Elevation.IsElevated; }

        internal static string ScopePrefix(X509Location scope) { return scope == X509Location.LocalMachine ? "LOCAL_MACHINE" : "CURRENT_USER"; }

        // Chosen certificates plus every certificate on this PC sharing their public key (cross-signs, reissues).
        internal static List<BlockItem> Plan(Snapshot snapshot, IEnumerable<CertificateRecord> chosen, Func<CertificateRecord, string> reason, X509Location scope)
        {
            HashSet<string> blocked = snapshot.BlockedIn(ScopePrefix(scope));
            Dictionary<string, BlockItem> plan = new Dictionary<string, BlockItem>(StringComparer.Ordinal);
            List<CertificateRecord> first = chosen.Where(c => c != null && c.Der != null).ToList();
            foreach (CertificateRecord cert in first)
                if (!plan.ContainsKey(cert.Identity)) plan.Add(cert.Identity, new BlockItem { Certificate = cert, Reason = reason(cert), AlreadyBlocked = blocked.Contains(cert.Identity) });
            foreach (CertificateRecord cert in first)
                foreach (CertificateRecord twin in snapshot.SameKey(cert))
                    if (!plan.ContainsKey(twin.Identity) && twin.Der != null)
                        plan.Add(twin.Identity, new BlockItem { Certificate = twin, Reason = "same public key (SPKI SHA-256) as a chosen certificate", AlreadyBlocked = blocked.Contains(twin.Identity) });
            return plan.Values.ToList();
        }

        internal static HashSet<string> BlockedIn(Snapshot snapshot, X509Location scope) { return snapshot.BlockedIn(ScopePrefix(scope)); }

        internal static List<BlockLogRow> Block(IEnumerable<BlockItem> items, X509Location scope, string group)
        {
            string batch = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            List<BlockLogRow> rows = new List<BlockLogRow>();
            List<CertificateRecord> listed = new List<CertificateRecord>();
            using (OwnStore store = OwnStore.Open("Disallowed", scope, true))
            {
                foreach (BlockItem item in items)
                {
                    BlockLogRow row = NewRow(batch, "block", scope, item.Certificate, group);
                    try
                    {
                        bool present = store.Has(item.Certificate.Sha1);
                        row.Prior = present ? "present" : "absent";
                        if (!present) store.Add(item.Certificate.Der);
                        row.Result = present ? "already in Disallowed" : "added";
                        listed.Add(item.Certificate);
                    }
                    catch (Exception ex) { row.Result = "error: " + ex.GetType().Name + ": " + ex.Message; if (row.Prior == null) row.Prior = "unknown"; }
                    rows.Add(row);
                }
            }
            BlockedCertificates.AddRange(scope, listed);
            Append(rows);
            return rows;
        }

        // Undo: removes from Disallowed only what kisib added and has not already removed.
        internal static List<BlockLogRow> Unblock(IEnumerable<string> sha256, X509Location scope, string reason)
        {
            HashSet<string> wanted = new HashSet<string>(sha256, StringComparer.OrdinalIgnoreCase);
            string scopeName = scope.ToString();
            Dictionary<string, BlockLogRow> added = new Dictionary<string, BlockLogRow>(StringComparer.OrdinalIgnoreCase);
            foreach (BlockLogRow row in ReadLog().Where(r => r.Scope == scopeName))
            {
                if (row.Action == "block" && row.Result == "added") added[row.Sha256] = row;
                else if (row.Action == "unblock" && row.Result == "removed") added.Remove(row.Sha256);
            }
            string batch = "undo-" + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
            List<BlockLogRow> rows = new List<BlockLogRow>();
            List<string> gone = new List<string>();
            using (OwnStore store = OwnStore.Open("Disallowed", scope, true))
            {
                foreach (string hash in wanted)
                {
                    BlockLogRow source;
                    BlockLogRow row = new BlockLogRow { Time = Now(), Batch = batch, Action = "unblock", Scope = scopeName, Sha256 = hash.ToUpperInvariant(), Group = reason };
                    if (!added.TryGetValue(hash, out source)) { row.Prior = "unknown"; row.Result = "skipped: not added by kisib in this scope"; rows.Add(row); continue; }
                    row.Sha1 = source.Sha1; row.Subject = source.Subject;
                    try
                    {
                        bool removed = store.Remove(source.Sha1);
                        row.Prior = removed ? "present" : "absent";
                        row.Result = removed ? "removed" : "already absent";
                        gone.Add(source.Sha1);
                    }
                    catch (Exception ex) { row.Result = "error: " + ex.GetType().Name + ": " + ex.Message; }
                    rows.Add(row);
                }
            }
            BlockedCertificates.RemoveRange(scope, gone);
            Append(rows);
            return rows;
        }

        // A manual unblock: takes the certificates out of this scope's own Disallowed store, whoever put them there.
        // Ones that were there before kisib are written down so Tools > Repair can put them back.
        internal static List<BlockLogRow> UnblockAny(IEnumerable<CertificateRecord> certs, X509Location scope, string reason)
        {
            HashSet<string> mine = KisibBlockedSha1();
            string batch = "unblock-" + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
            List<BlockLogRow> rows = new List<BlockLogRow>();
            List<string> gone = new List<string>();
            List<string[]> before = new List<string[]>();
            using (OwnStore store = OwnStore.Open("Disallowed", scope, true))
            {
                foreach (CertificateRecord c in certs.Where(x => x != null).GroupBy(x => x.Sha1).Select(g => g.First()))
                {
                    if (!store.Has(c.Sha1)) continue;
                    BlockLogRow row = NewRow(batch, "unblock", scope, c, reason);
                    row.Prior = mine.Contains(c.Sha1) ? "present (kisib)" : "present (before kisib)";
                    try
                    {
                        byte[] der = store.RawData(c.Sha1) ?? c.Der;
                        store.Remove(c.Sha1);
                        row.Result = "removed";
                        gone.Add(c.Sha1);
                        if (!mine.Contains(c.Sha1))
                            before.Add(new string[] { scope.ToString(), c.Sha1, c.Sha256, c.SubjectShortName, Now(), Convert.ToBase64String(der) });
                    }
                    catch (Exception ex) { row.Result = "error: " + ex.GetType().Name + ": " + ex.Message; }
                    rows.Add(row);
                }
            }
            BlockedCertificates.RemoveRange(scope, gone);
            UnblockedByHand.AddRange(before);
            Append(rows);
            return rows;
        }

        // SHA-1s that are in Disallowed because kisib put them there.
        internal static HashSet<string> KisibBlockedSha1()
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (BlockLogRow r in ReadLog())
                {
                    if (r.Sha1 == null) continue;
                    if ((r.Action == "block" && (r.Result == "added" || r.Result == "already in Disallowed")) || r.Action == "re-apply" || r.Action == "re-block") set.Add(r.Sha1);
                    else if (r.Action == "unblock" && r.Result == "removed") set.Remove(r.Sha1);
                }
            }
            catch (Exception) { }
            return set;
        }

        internal static string LastBatch()
        {
            BlockLogRow last = ReadLog().LastOrDefault(r => r.Action == "block" && r.Result == "added");
            return last == null ? null : last.Batch;
        }

        // The history is read often; it is parsed again only when the file changed.
        private static List<BlockLogRow> logCache;
        private static long logLength = -1;
        private static DateTime logStamp;
        private static readonly object logGate = new object();

        internal static List<BlockLogRow> ReadLog()
        {
            lock (logGate)
            {
                FileInfo info = new FileInfo(LogPath);
                if (!info.Exists) { logCache = null; return new List<BlockLogRow>(); }
                if (logCache != null && info.Length == logLength && info.LastWriteTimeUtc == logStamp) return new List<BlockLogRow>(logCache);
                List<BlockLogRow> rows = new List<BlockLogRow>();
                foreach (string[] f in GroupCatalog.ReadCsv(LogPath, 256L * 1024 * 1024).Skip(1))
                    if (f.Length >= 10)
                        rows.Add(new BlockLogRow { Time = f[0], Batch = f[1], Action = f[2], Scope = f[3], Sha256 = f[4], Sha1 = f[5], Subject = f[6], Prior = f[7], Result = f[8], Group = f[9] });
                logCache = rows; logLength = info.Length; logStamp = info.LastWriteTimeUtc;
                return new List<BlockLogRow>(rows);
            }
        }

        private static BlockLogRow NewRow(string batch, string action, X509Location scope, CertificateRecord cert, string group)
        {
            return new BlockLogRow { Time = Now(), Batch = batch, Action = action, Scope = scope.ToString(), Sha256 = cert.Sha256, Sha1 = cert.Sha1, Subject = cert.SubjectShortName, Group = group };
        }
        private static string Now() { return DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture); }
        internal static string Csv(string value)
        {
            value = value ?? "";
            return value.IndexOfAny(new char[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
        }
        internal static void Append(List<BlockLogRow> rows)
        {
            if (rows.Count == 0) return;
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath));
            StringBuilder text = new StringBuilder();
            if (!File.Exists(LogPath)) text.Append(LogHeader).Append("\r\n");
            foreach (BlockLogRow r in rows)
                text.Append(String.Join(",", new string[] { r.Time, r.Batch, r.Action, r.Scope, r.Sha256, r.Sha1, r.Subject, r.Prior, r.Result, r.Group }.Select(Csv).ToArray())).Append("\r\n");
            lock (logGate) { File.AppendAllText(LogPath, text.ToString(), new UTF8Encoding(false)); logCache = null; }
        }
    }

    // Certificates taken out of Disallowed by hand that were there before kisib (Microsoft's untrusted list or an
    // earlier hardening). Tools > Repair > "Put back what was blocked before kisib" uses this list.
    internal static class UnblockedByHand
    {
        private const string Header = "scope,sha1,sha256,subject,removed_utc,certificate_base64";
        internal static string FilePath { get { return Storage.File(Storage.UnblockedByHand); } }

        internal static List<string[]> Read()
        {
            try { return File.Exists(FilePath) ? GroupCatalog.ReadCsv(FilePath, 64L * 1024 * 1024).Skip(1).Where(f => f.Length >= 6).ToList() : new List<string[]>(); }
            catch (Exception) { return new List<string[]>(); }
        }

        internal static void Write(List<string[]> rows)
        {
            StringBuilder text = new StringBuilder(Header).Append("\r\n");
            foreach (string[] r in rows) text.Append(String.Join(",", r.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
            File.WriteAllText(FilePath, text.ToString(), new UTF8Encoding(false));
        }

        internal static void AddRange(List<string[]> add)
        {
            if (add.Count == 0) return;
            try
            {
                List<string[]> rows = Read();
                foreach (string[] a in add) { rows.RemoveAll(r => r[0] == a[0] && String.Equals(r[1], a[1], StringComparison.OrdinalIgnoreCase)); rows.Add(a); }
                Write(rows);
            }
            catch (IOException) { }
        }
    }
}
