using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Blocking = adding the certificate to Windows' Disallowed (untrusted) store. Nothing is ever deleted from Root or CA.
    // Unblocking removes only Disallowed entries that kisib itself added, as recorded in the block history.
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

        internal static bool IsElevated()
        {
            try { using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
            catch (Exception) { return false; }
        }

        // Chosen certificates plus every certificate on this PC sharing their public key (cross-signs, reissues).
        internal static List<BlockItem> Plan(Snapshot snapshot, IEnumerable<CertificateRecord> chosen, Func<CertificateRecord, string> reason, X509Location scope)
        {
            HashSet<string> blocked = BlockedIn(snapshot, scope);
            Dictionary<string, BlockItem> plan = new Dictionary<string, BlockItem>(StringComparer.Ordinal);
            List<CertificateRecord> first = chosen.Where(c => c != null && c.Der != null).ToList();
            foreach (CertificateRecord cert in first)
                if (!plan.ContainsKey(cert.Identity)) plan.Add(cert.Identity, new BlockItem { Certificate = cert, Reason = reason(cert), AlreadyBlocked = blocked.Contains(cert.Identity) });
            HashSet<string> keys = new HashSet<string>(first.Where(c => !String.IsNullOrEmpty(c.SpkiSha256)).Select(c => c.SpkiSha256), StringComparer.Ordinal);
            foreach (CertificateRecord cert in snapshot.Certificates.Values)
                if (!plan.ContainsKey(cert.Identity) && cert.SpkiSha256 != null && keys.Contains(cert.SpkiSha256))
                    plan.Add(cert.Identity, new BlockItem { Certificate = cert, Reason = "same public key (SPKI SHA-256) as a chosen certificate", AlreadyBlocked = blocked.Contains(cert.Identity) });
            return plan.Values.ToList();
        }

        // Observed Disallowed membership for the chosen scope, from the scan.
        internal static HashSet<string> BlockedIn(Snapshot snapshot, X509Location scope)
        {
            string prefix = (scope == X509Location.LocalMachine ? "LOCAL_MACHINE" : "CURRENT_USER") + "\\Disallowed";
            return new HashSet<string>(snapshot.Certificates.Values.Where(c => c.FoundIn.Concat(c.Collections)
                .Any(p => p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))).Select(c => c.Identity), StringComparer.Ordinal);
        }

        internal static List<BlockLogRow> Block(IEnumerable<BlockItem> items, X509Location scope, string group)
        {
            string batch = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            List<BlockLogRow> rows = new List<BlockLogRow>();
            using (X509Store store = new X509Store(StoreName.Disallowed, scope))
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (BlockItem item in items)
                {
                    BlockLogRow row = NewRow(batch, "block", scope, item.Certificate, group);
                    try
                    {
                        using (X509Certificate2 cert = new X509Certificate2(item.Certificate.Der))
                        {
                            bool present = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0;
                            row.Prior = present ? "present" : "absent";
                            if (!present) store.Add(cert);
                            row.Result = present ? "already in Disallowed" : "added";
                            BlockedCertificates.Add(scope, item.Certificate);
                        }
                    }
                    catch (Exception ex) { row.Result = "error: " + ex.GetType().Name + ": " + ex.Message; if (row.Prior == null) row.Prior = "unknown"; }
                    rows.Add(row);
                }
            }
            Append(rows);
            return rows;
        }

        // Removes from Disallowed only what kisib added and has not already removed.
        internal static List<BlockLogRow> Unblock(IEnumerable<string> sha256, X509Location scope, string reason)
        {
            HashSet<string> wanted = new HashSet<string>(sha256, StringComparer.OrdinalIgnoreCase);
            List<BlockLogRow> history = ReadLog();
            string scopeName = scope.ToString();
            Dictionary<string, BlockLogRow> added = new Dictionary<string, BlockLogRow>(StringComparer.OrdinalIgnoreCase);
            foreach (BlockLogRow row in history.Where(r => r.Scope == scopeName))
            {
                if (row.Action == "block" && row.Result == "added") added[row.Sha256] = row;
                else if (row.Action == "unblock" && row.Result == "removed") added.Remove(row.Sha256);
            }
            string batch = "undo-" + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
            List<BlockLogRow> rows = new List<BlockLogRow>();
            using (X509Store store = new X509Store(StoreName.Disallowed, scope))
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (string hash in wanted)
                {
                    BlockLogRow source;
                    BlockLogRow row = new BlockLogRow { Time = Now(), Batch = batch, Action = "unblock", Scope = scopeName, Sha256 = hash.ToUpperInvariant(), Group = reason };
                    if (!added.TryGetValue(hash, out source)) { row.Prior = "unknown"; row.Result = "skipped: not added by kisib in this scope"; rows.Add(row); continue; }
                    row.Sha1 = source.Sha1; row.Subject = source.Subject;
                    try
                    {
                        X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, source.Sha1, false);
                        row.Prior = found.Count > 0 ? "present" : "absent";
                        foreach (X509Certificate2 cert in found) store.Remove(cert);
                        row.Result = found.Count > 0 ? "removed" : "already absent";
                        BlockedCertificates.Remove(scope, source.Sha1);
                    }
                    catch (Exception ex) { row.Result = "error: " + ex.GetType().Name + ": " + ex.Message; }
                    rows.Add(row);
                }
            }
            Append(rows);
            return rows;
        }

        internal static string LastBatch()
        {
            BlockLogRow last = ReadLog().LastOrDefault(r => r.Action == "block" && r.Result == "added");
            return last == null ? null : last.Batch;
        }

        internal static List<BlockLogRow> ReadLog()
        {
            List<BlockLogRow> rows = new List<BlockLogRow>();
            if (!File.Exists(LogPath)) return rows;
            foreach (string[] f in GroupCatalog.ReadCsv(LogPath).Skip(1))
                if (f.Length >= 10)
                    rows.Add(new BlockLogRow { Time = f[0], Batch = f[1], Action = f[2], Scope = f[3], Sha256 = f[4], Sha1 = f[5], Subject = f[6], Prior = f[7], Result = f[8], Group = f[9] });
            return rows;
        }

        private static BlockLogRow NewRow(string batch, string action, X509Location scope, CertificateRecord cert, string group)
        {
            return new BlockLogRow { Time = Now(), Batch = batch, Action = action, Scope = scope.ToString(), Sha256 = cert.Sha256, Sha1 = cert.Sha1, Subject = cert.SubjectShortName, Group = group };
        }
        private static string Now() { return DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture); }
        private static string Csv(string value)
        {
            value = value ?? "";
            return value.IndexOfAny(new char[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
        }
        private static void Append(List<BlockLogRow> rows)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath));
            StringBuilder text = new StringBuilder();
            if (!File.Exists(LogPath)) text.Append(LogHeader).Append("\r\n");
            foreach (BlockLogRow r in rows)
                text.Append(String.Join(",", new string[] { r.Time, r.Batch, r.Action, r.Scope, r.Sha256, r.Sha1, r.Subject, r.Prior, r.Result, r.Group }.Select(Csv).ToArray())).Append("\r\n");
            File.AppendAllText(LogPath, text.ToString(), new UTF8Encoding(false));
        }
    }
}
