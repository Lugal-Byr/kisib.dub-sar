using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace Kisib
{
    // This archive writes application data only. It never opens a private key,
    // imports a certificate, changes a Windows store, or builds a chain.
    internal sealed class HistoryArchive : IDisposable
    {
        private readonly object gate = new object();
        private readonly FileStream writerLock;
        private readonly ArchiveFileSystem files;
        internal const int ObjectByteLimit = 256 * 1024 * 1024;
        internal const int EvidenceByteLimit = 32 * 1024 * 1024;
        internal const int JournalCharacterLimit = 8 * 1024 * 1024;
        private readonly string sessionId = Guid.NewGuid().ToString("N");
        private HistoryIndex index;
        private string activeAnnotationObject, activeCountryCatalogObject;
        private bool disposed;
        internal readonly string DirectoryPath;
        internal string LastError { get; private set; }
        internal int FailedWrites { get; private set; }
        internal readonly List<string> RecoveryWarnings = new List<string>();

        internal static string DefaultDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "kisib.dub-sar", "History"); }
        }

        internal HistoryArchive(string directory)
        {
            DirectoryPath = Path.GetFullPath(directory);
            files = new ArchiveFileSystem(DirectoryPath);
            try
            {
                files.PinDirectory(Path.Combine(DirectoryPath, "logs"));
                writerLock = files.Open(Path.Combine(DirectoryPath, "writer.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                index = ReadCommittedIndex();
                Append(NewEvent(null, "session_opened", DirectoryPath, "Durable public-certificate history; Windows stores remain read-only."));
                foreach (string warning in RecoveryWarnings)
                    Append(NewEvent(null, "history_recovery_warning", DirectoryPath, warning));
            }
            catch { if (writerLock != null) writerLock.Dispose(); files.Dispose(); throw; }
        }

        internal void Note(string scanId, string action, string source, string outcome)
        {
            Attempt(delegate { Append(NewEvent(scanId, action, source, outcome)); });
        }

        internal bool RecordActivity(ActivityRecord activity)
        {
            bool saved = false;
            Attempt(delegate
            {
                activity.AnnotationObjectAtRetention = activeAnnotationObject;
                activity.CountryCatalogObjectAtRetention = activeCountryCatalogObject;
                activity.EvidenceObject = SaveObject("evidence", ".json", Encode(activity));
                HistoryEvent entry = NewEvent(null, "application_certificate_activity", activity.Source, activity.Operation + "; " + activity.Result);
                entry.EvidenceObject = activity.EvidenceObject; entry.ProcessId = activity.ProcessId; entry.ThreadId = activity.ThreadId;
                entry.ActivityId = activity.ActivityId; entry.ApplicationKey = activity.ApplicationKey; entry.EventUtc = activity.Utc;
                entry.References = activity.References;
                Append(entry); saved = true;
            });
            return saved;
        }

        internal void RecordApplicationInventory(ApplicationRecord[] applications)
        {
            Attempt(delegate
            {
                HistoryEvent entry = NewEvent(null, "application_inventory_observed", Environment.MachineName, applications.Length + " observed processes; start-time/path errors retained.");
                entry.EvidenceObject = SaveObject("evidence", ".json", Encode(applications)); Append(entry);
            });
        }
        internal void RecordCountryCatalog(CountryCatalog catalog)
        {
            Attempt(delegate
            {
                HistoryEvent entry = NewEvent(null, "country_catalog_observed", catalog.Source, catalog.Countries.Length + " country/area rows; original classification sources and dates retained.");
                entry.EvidenceObject = SaveObject("evidence", ".json", Encode(catalog)); Append(entry); activeCountryCatalogObject = entry.EvidenceObject;
            });
        }
        internal void RecordApplicationSigner(ApplicationSignature signature)
        {
            if (signature.Certificate != null) CaptureBytes(null, signature.Certificate.Der, "Embedded file signer: " + signature.Executable);
            Attempt(delegate
            {
                HistoryEvent entry = NewEvent(null, "application_signer_observed", signature.Executable, signature.Verification + "; " + signature.Error);
                entry.ApplicationKey = signature.ApplicationKey; entry.Sha256 = signature.SignerSha256;
                entry.EvidenceObject = SaveObject("evidence", ".json", Encode(signature)); Append(entry);
            });
        }

        internal bool SaveAnnotations(AnnotationSet annotations)
        {
            annotations.Validate();
            bool saved = false;
            Attempt(delegate
            {
                HistoryEvent entry = NewEvent(null, "issuer_annotation_version", "User-defined issuer labels", "Label version retained; requested policy is not OS enforcement.");
                entry.EvidenceObject = SaveObject("labels", ".json", Encode(annotations)); Append(entry); activeAnnotationObject = entry.EvidenceObject; saved = true;
            });
            return saved;
        }

        internal AnnotationSet LoadAnnotations()
        {
            foreach (string path in JournalFiles().Reverse())
            {
                HistoryEvent latest = null;
                foreach (string line in Lines(path))
                    try { HistoryEvent row = ReadEvent(line); if (row.Action == "issuer_annotation_version") latest = row; }
                    catch (SerializationException) { }
                if (latest == null) continue;
                if (!ValidObjectName(latest.EvidenceObject)) throw new InvalidOperationException("Invalid issuer annotation object reference.");
                byte[] bytes = files.ReadBytes(Path.Combine(DirectoryPath, "labels", latest.EvidenceObject + ".json"), EvidenceByteLimit);
                if (Digest(bytes) != latest.EvidenceObject.Substring(0, 64)) throw new InvalidOperationException("Issuer annotation integrity check failed.");
                AnnotationSet result = Decode<AnnotationSet>(bytes); result.Validate(); lock (gate) activeAnnotationObject = latest.EvidenceObject; return result;
            }
            return new AnnotationSet();
        }

        internal string LoadCheckpoint(string name)
        {
            if (name != "capi2-bookmark") throw new InvalidOperationException("Unknown application checkpoint.");
            string path = Path.Combine(DirectoryPath, name + ".xml");
            return File.Exists(path) ? Encoding.UTF8.GetString(files.ReadBytes(path, 65536)) : null;
        }

        internal void SaveCheckpoint(string name, string contents)
        {
            Attempt(delegate
            {
                if (name != "capi2-bookmark") throw new InvalidOperationException("Unknown application checkpoint.");
                string path = Path.Combine(DirectoryPath, name + ".xml"), temporary = path + ".pending-" + Guid.NewGuid().ToString("N");
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(contents);
                    if (bytes.Length > 65536) throw new InvalidOperationException("CAPI2 bookmark exceeds the byte size limit.");
                    using (FileStream file = files.Open(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                    if (File.Exists(path)) { using (FileStream existing = files.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read)) { } File.Replace(temporary, path, null); } else File.Move(temporary, path);
                }
                finally { if (File.Exists(temporary)) File.Delete(temporary); }
            });
        }

        internal void Observe(Snapshot scan, CertificateRecord cert, string source, string usage)
        {
            Attempt(delegate
            {
                string objectName = SaveObject("certificates", ".cer", cert.Der);
                HistoryEvent entry = NewEvent(scan.ScanId, "certificate_observed", source, usage);
                entry.CertificateObject = objectName;
                entry.Sha256 = cert.Sha256; entry.Sha1 = cert.Sha1;
                entry.Subject = cert.Subject; entry.Issuer = cert.Issuer;
                Append(entry);
            });
        }

        internal void CaptureBytes(string scanId, byte[] der, string source)
        {
            Attempt(delegate
            {
                string objectName = SaveObject("certificates", ".cer", der);
                HistoryEvent entry = NewEvent(scanId, "certificate_bytes_observed", source, der.Length + " public bytes retained before metadata decoding.");
                entry.CertificateObject = objectName; entry.Sha256 = objectName.Substring(0, 64); Append(entry);
            });
        }

        // Membership comparisons advance only after a successful, uncanceled
        // read of that particular source. Denied/partial sources keep their
        // last successful baseline and are never reported as emptied.
        internal void Commit(Snapshot scan)
        {
            Attempt(delegate
            {
                Dictionary<string, string> objects = new Dictionary<string, string>(StringComparer.Ordinal);
                HistoryInventory inventory = new HistoryInventory();
                foreach (CertificateRecord cert in scan.Certificates.Values.OrderBy(c => c.Identity, StringComparer.Ordinal))
                {
                    string objectName = SaveObject("certificates", ".cer", cert.Der);
                    objects.Add(cert.Identity, objectName);
                    inventory.Certificates.Add(HistoryCertificate.From(cert, objectName));
                }
                foreach (StoreLocation location in scan.Locations)
                {
                    inventory.Locations.Add(new HistoryLocation { Name = location.Name, RegistryPath = location.RegistryPath,
                        Returned = location.Enumerated, Error = location.Error, WindowsName = location.WindowsName, Flags = location.Flags });
                    foreach (SystemStore store in location.Stores)
                    {
                        HistoryStore logical = BuildStore("collection", store.Path, store.RegistryPath,
                            store.ReadSucceeded && !scan.Canceled, store.Error, store.PhysicalEnumerationError, store.Certificates, scan, objects);
                        logical.NativeName = store.Name; inventory.Stores.Add(logical);
                        foreach (PhysicalStore physical in store.PhysicalStores)
                        {
                            HistoryStore observed = BuildStore("physical", physical.Path, null,
                                physical.ReadSucceeded && !scan.Canceled, physical.Error, null, physical.Certificates, scan, objects);
                            observed.NativeName = physical.Name; observed.Provider = physical.Provider; observed.Predefined = physical.Predefined;
                            observed.Flags = physical.Flags; observed.Priority = physical.Priority; inventory.Stores.Add(observed);
                        }
                    }
                }
                inventory.Locations = inventory.Locations.OrderBy(x => x.Name, StringComparer.Ordinal).ToList();
                inventory.Stores = inventory.Stores.OrderBy(x => x.Kind + "|" + x.Source, StringComparer.Ordinal).ToList();
                inventory.Canceled = scan.Canceled; inventory.Errors = scan.Errors.ToArray();
                string inventoryObject = SaveObject("inventories", ".json", Encode(inventory));

                Dictionary<string, HistoryStore> next = index.Stores.ToDictionary(x => x.Kind + "|" + x.Source, StringComparer.OrdinalIgnoreCase);
                HashSet<string> returned = new HashSet<string>(inventory.Stores.Select(x => x.Kind + "|" + x.Source), StringComparer.OrdinalIgnoreCase);
                foreach (HistoryStore missing in index.Stores.Where(x => !returned.Contains(x.Kind + "|" + x.Source)))
                    Append(NewEvent(scan.ScanId, "source_not_returned", missing.Source, "Source not returned in this scan; membership unknown; last successful baseline retained."));
                foreach (HistoryStore store in inventory.Stores.Where(x => x.ReadSucceeded))
                {
                    HistoryStore old;
                    string key = store.Kind + "|" + store.Source;
                    if (!next.TryGetValue(key, out old))
                        Append(NewEvent(scan.ScanId, "store_baseline_established", store.Source, store.Members.Length + " archived occurrences; earlier membership unknown."));
                    else
                    {
                        if (old.Provider != store.Provider || old.Flags != store.Flags || old.Priority != store.Priority || old.Predefined != store.Predefined)
                            Append(NewEvent(scan.ScanId, "store_metadata_changed", store.Source, "Provider/flags/priority/predefined metadata changed; both inventories retained."));
                        Dictionary<string, HistoryMember> before = old.Members.ToDictionary(x => x.ObjectName, StringComparer.Ordinal);
                        Dictionary<string, HistoryMember> after = store.Members.ToDictionary(x => x.ObjectName, StringComparer.Ordinal);
                        foreach (HistoryMember member in store.Members)
                        {
                            HistoryMember previous;
                            if (!before.TryGetValue(member.ObjectName, out previous)) Delta(scan, "occurrence_added", store.Source, member.ObjectName, "Present in successful read; exact arrival time not observed.");
                            else if (!previous.Usages.SequenceEqual(member.Usages)) Delta(scan, "occurrence_usage_changed", store.Source, member.ObjectName, "Effective EKU observation changed; both inventories retained.");
                        }
                        foreach (HistoryMember member in old.Members)
                            if (!after.ContainsKey(member.ObjectName)) Delta(scan, "occurrence_removed", store.Source, member.ObjectName, "Absent from successful read; exact removal time not observed.");
                    }
                    next[key] = store;
                }
                HistoryIndex nextIndex = new HistoryIndex { Computer = Environment.MachineName, UserScope = Environment.UserDomainName + "\\" + Environment.UserName,
                    Stores = next.Values.OrderBy(x => x.Kind + "|" + x.Source, StringComparer.Ordinal).ToList() };
                string indexObject = SaveObject("indexes", ".json", Encode(nextIndex));
                HistoryEvent committed = NewEvent(scan.ScanId, "scan_archive_committed", Environment.MachineName,
                    "Started " + scan.Started.ToString("o", CultureInfo.InvariantCulture) + "; finished " + scan.Finished.ToString("o", CultureInfo.InvariantCulture) +
                    "; " + scan.Certificates.Count + " certificates; " + scan.Errors.Count + " errors; canceled=" + scan.Canceled + "; failed archive writes=" + FailedWrites);
                committed.InventoryObject = inventoryObject; committed.IndexObject = indexObject;
                Append(committed);
                index = nextIndex;
            });
        }

        private static HistoryStore BuildStore(string kind, string source, string registry, bool succeeded, string error,
            string enumerationError, IEnumerable<string> identities, Snapshot scan, Dictionary<string, string> objects)
        {
            return new HistoryStore { Kind = kind, Source = source, RegistryPath = registry, ReadSucceeded = succeeded,
                Error = error, EnumerationError = enumerationError,
                Members = identities.Select(id => new HistoryMember { ObjectName = objects[id],
                    Usages = scan.Certificates[id].UsageBySource.ContainsKey(source) ? scan.Certificates[id].UsageBySource[source].ToArray() : new string[] { "[not observed]" } })
                    .OrderBy(x => x.ObjectName, StringComparer.Ordinal).ToArray() };
        }

        private void Delta(Snapshot scan, string action, string source, string objectName, string outcome)
        {
            HistoryEvent entry = NewEvent(scan.ScanId, action, source, outcome);
            entry.CertificateObject = objectName; entry.Sha256 = objectName.Substring(0, 64); Append(entry);
        }

        private HistoryEvent NewEvent(string scanId, string action, string source, string outcome)
        {
            return new HistoryEvent { Version = 1, EventId = Guid.NewGuid().ToString("N"), SessionId = sessionId, ScanId = scanId,
                Utc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), Action = action, Source = source, Outcome = outcome,
                Computer = Environment.MachineName, UserScope = Environment.UserDomainName + "\\" + Environment.UserName, ArchiveFailures = FailedWrites };
        }

        private void Attempt(Action action)
        {
            lock (gate)
            {
                if (disposed) return;
                try { action(); }
                catch (Exception ex)
                {
                    if (!(ex is IOException || ex is UnauthorizedAccessException || ex is SerializationException || ex is CryptographicException || ex is InvalidOperationException)) throw;
                    FailedWrites++; LastError = ex.GetType().Name + ": " + ex.Message;
                }
            }
        }

        private void Append(HistoryEvent entry)
        {
            string path = Path.Combine(DirectoryPath, "logs", DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".jsonl");
            byte[] bytes = Encode(entry);
            if (bytes.Length > JournalCharacterLimit) throw new InvalidOperationException("History record exceeds the byte size limit; write refused explicitly.");
            using (FileStream file = files.Open(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                // Preserve a torn final line as evidence, then start a fresh record.
                if (file.Length > 0)
                {
                    file.Seek(-1, SeekOrigin.End);
                    if (file.ReadByte() != 10) { file.Seek(0, SeekOrigin.End); file.WriteByte(10); }
                }
                file.Seek(0, SeekOrigin.End); file.Write(bytes, 0, bytes.Length); file.WriteByte(10); file.Flush(true);
            }
        }

        private string SaveObject(string folder, string extension, byte[] bytes)
        {
            if (bytes == null) throw new InvalidOperationException("Archive object bytes are unavailable.");
            string name = Digest(bytes);
            if (bytes.Length > ObjectByteLimit) throw new InvalidOperationException("Archive object exceeds the byte size limit; write refused explicitly.");
            string directory = Path.Combine(DirectoryPath, folder); files.PinDirectory(directory);
            string path = Path.Combine(directory, name + extension);
            if (File.Exists(path))
            {
                if (files.ReadBytes(path, ObjectByteLimit).SequenceEqual(bytes)) return name;
                // Preserve hash collisions or altered objects without overwriting evidence.
                using (SHA512 hash = SHA512.Create()) name += "-" + CertificateRecord.Hex(hash.ComputeHash(bytes));
                path = Path.Combine(directory, name + extension);
                if (File.Exists(path))
                {
                    if (files.ReadBytes(path, ObjectByteLimit).SequenceEqual(bytes)) return name;
                    throw new InvalidOperationException("An existing archive object has conflicting bytes; no object was overwritten.");
                }
                Append(NewEvent(null, "archive_object_conflict", folder, "Different bytes at a SHA-256 object name were preserved separately."));
            }
            string temporary = Path.Combine(directory, ".pending-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (FileStream file = files.Open(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            return name;
        }

        private static string Digest(byte[] bytes)
        { using (SHA256 hash = SHA256.Create()) return CertificateRecord.Hex(hash.ComputeHash(bytes)); }

        internal static byte[] Encode<T>(T value)
        {
            using (MemoryStream stream = new MemoryStream())
            { Serializer(typeof(T)).WriteObject(stream, value); return stream.ToArray(); }
        }

        internal static T Decode<T>(byte[] bytes)
        {
            using (MemoryStream stream = new MemoryStream(bytes))
            { return (T)Serializer(typeof(T)).ReadObject(stream); }
        }

        private static DataContractJsonSerializer Serializer(Type type)
        { return new DataContractJsonSerializer(type, new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = Int32.MaxValue }); }

        private static HistoryEvent ReadEvent(string line)
        {
            HistoryEvent entry = Decode<HistoryEvent>(Encoding.UTF8.GetBytes(line));
            if (entry == null || entry.Version != 1 || String.IsNullOrEmpty(entry.EventId) || String.IsNullOrEmpty(entry.Action) || String.IsNullOrEmpty(entry.Utc))
                throw new SerializationException("Unsupported or incomplete history event; original record retained.");
            return entry;
        }

        private HistoryIndex ReadCommittedIndex()
        {
            foreach (string path in JournalFiles().Reverse())
            {
                HistoryEvent latest = null;
                int unreadable = 0;
                foreach (string line in Lines(path))
                {
                    try
                    {
                        HistoryEvent entry = ReadEvent(line);
                        if (entry.Action == "scan_archive_committed" && entry.IndexObject != null) latest = entry;
                    }
                    catch (SerializationException) { unreadable++; }
                }
                if (unreadable > 0) RecoveryWarnings.Add(Path.GetFileName(path) + ": " + unreadable + " unreadable journal records retained; history coverage incomplete.");
                if (latest == null) continue;
                string objectName = latest.IndexObject;
                if (!ValidObjectName(objectName)) throw new InvalidOperationException("Invalid committed archive index reference.");
                byte[] bytes = files.ReadBytes(Path.Combine(DirectoryPath, "indexes", objectName + ".json"), ObjectByteLimit);
                if (Digest(bytes) != objectName.Substring(0, 64)) throw new InvalidOperationException("Committed archive index integrity check failed; membership comparisons disabled.");
                HistoryIndex restored = Decode<HistoryIndex>(bytes);
                if (restored == null || restored.Version != 1 || restored.Stores == null || restored.Stores.Any(x => x == null || x.Kind == null || x.Source == null || x.Members == null ||
                    x.Members.Any(m => m == null || !ValidObjectName(m.ObjectName) || m.Usages == null)) ||
                    restored.Stores.GroupBy(x => x.Kind + "|" + x.Source, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1) ||
                    restored.Stores.Any(x => x.Members.GroupBy(m => m.ObjectName, StringComparer.Ordinal).Any(g => g.Count() > 1)))
                    throw new InvalidOperationException("Committed archive index schema is unavailable.");
                if (restored.Computer != Environment.MachineName || restored.UserScope != Environment.UserDomainName + "\\" + Environment.UserName)
                {
                    RecoveryWarnings.Add("Archived computer/user scope differs from the current caller; new membership baselines will be established.");
                    return new HistoryIndex();
                }
                return restored;
            }
            return new HistoryIndex();
        }

        private static bool ValidObjectName(string name)
        {
            return name != null && (name.Length == 64 || name.Length == 193) &&
                name.Select((c, i) => i == 64 && name.Length == 193 ? c == '-' : c >= '0' && c <= '9' || c >= 'A' && c <= 'F').All(x => x);
        }

        internal string[] JournalFiles()
        { return Directory.GetFiles(Path.Combine(DirectoryPath, "logs"), "*.jsonl").OrderBy(x => x, StringComparer.Ordinal).ToArray(); }

        internal byte[] ReadObjectBytes(string path, int limit)
        { return files.ReadBytes(path, limit); }
        internal void PinArchiveDirectory(string path)
        { files.PinDirectory(path); }
        internal FileStream OpenArchiveRead(string path)
        { return files.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        internal IEnumerable<string> Lines(string path)
        {
            using (FileStream file = files.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (StreamReader reader = new StreamReader(file, Encoding.UTF8))
            {
                StringBuilder line = new StringBuilder(); bool oversized = false; int value;
                while ((value = reader.Read()) >= 0)
                {
                    if (value == 10)
                    {
                        if (oversized) yield return "[retained record exceeds the explicit character size limit; original bytes remain in the journal]";
                        else if (line.Length > 0) yield return line.ToString().TrimEnd('\r');
                        line.Clear(); oversized = false;
                    }
                    else if (!oversized) { if (line.Length == JournalCharacterLimit) { oversized = true; line.Clear(); } else line.Append((char)value); }
                }
                if (oversized) yield return "[retained record exceeds the explicit character size limit; original bytes remain in the journal]";
                else if (line.Length > 0) yield return line.ToString();
            }
        }

        internal string ReadPage(string journal, string sha256, int page, out bool more, string sha1 = null)
        {
            if (!JournalFiles().Contains(journal, StringComparer.Ordinal)) throw new InvalidOperationException("Select an archived journal date.");
            if (page < 0 || page > Int32.MaxValue / 500) throw new ArgumentOutOfRangeException("page");
            const int pageSize = 500;
            int skip = checked(page * pageSize), matched = 0, shown = 0; more = false;
            StringBuilder text = new StringBuilder();
            foreach (string line in Lines(journal))
            {
                HistoryEvent entry;
                try { entry = ReadEvent(line); }
                catch (SerializationException)
                { if (sha256 != null) continue; entry = new HistoryEvent { Action = "[unreadable retained record]", Outcome = line }; }
                if (sha256 != null && !String.Equals(entry.Sha256, sha256, StringComparison.Ordinal) &&
                    !(entry.References ?? new CertificateReference[0]).Any(r => r != null && (r.Algorithm == "SHA-256" && r.Value == sha256 || sha1 != null && r.Algorithm == "SHA-1" && r.Value == sha1))) continue;
                if (matched++ < skip) continue;
                if (shown++ == pageSize) { more = true; break; }
                text.AppendLine(entry.Utc + "\t" + entry.Action + "\t" + entry.Source);
                text.AppendLine("  " + entry.Outcome);
                if (entry.Sha256 != null) text.AppendLine("  SHA-256: " + entry.Sha256 + " | archive object: " + entry.CertificateObject);
                if (entry.Subject != null) text.AppendLine("  Subject: " + entry.Subject + " | Issuer: " + entry.Issuer);
                if (entry.InventoryObject != null) text.AppendLine("  Retained inventory: " + entry.InventoryObject);
                if (entry.EvidenceObject != null) text.AppendLine("  Retained evidence: " + entry.EvidenceObject + " | event UTC: " + entry.EventUtc);
                if (entry.ProcessId.HasValue) text.AppendLine("  Event process: " + entry.ProcessId + " | thread: " + entry.ThreadId + " | observed lifetime: " + entry.ApplicationKey);
                text.AppendLine("  Event: " + entry.EventId + " | scan: " + entry.ScanId + " | session: " + entry.SessionId);
                text.AppendLine("  Computer: " + entry.Computer + " | user: " + entry.UserScope + " | earlier failed archive writes in session: " + entry.ArchiveFailures);
            }
            return text.Length == 0 ? "No matching events on this page." : text.ToString();
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (disposed) return;
                try { Append(NewEvent(null, "session_closed", DirectoryPath, "Explorer closed; collection resumes on the next launch. Failed archive writes=" + FailedWrites + "; " + LastError)); }
                catch (Exception ex)
                {
                    if (!(ex is IOException || ex is UnauthorizedAccessException || ex is SerializationException)) throw;
                    LastError = ex.Message; FailedWrites++;
                }
                finally { disposed = true; writerLock.Dispose(); files.Dispose(); }
            }
        }
    }

    [DataContract] internal sealed class HistoryEvent
    {
        [DataMember(Order = 0)] internal int Version;
        [DataMember(Order = 1)] internal string EventId;
        [DataMember(Order = 2)] internal string SessionId;
        [DataMember(Order = 3)] internal string ScanId;
        [DataMember(Order = 4)] internal string Utc;
        [DataMember(Order = 5)] internal string Action;
        [DataMember(Order = 6)] internal string Source;
        [DataMember(Order = 7)] internal string Outcome;
        [DataMember(Order = 8)] internal string CertificateObject;
        [DataMember(Order = 9)] internal string Sha256;
        [DataMember(Order = 10)] internal string Sha1;
        [DataMember(Order = 11)] internal string Subject;
        [DataMember(Order = 12)] internal string Issuer;
        [DataMember(Order = 13)] internal string InventoryObject;
        [DataMember(Order = 14)] internal string IndexObject;
        [DataMember(Order = 15)] internal string Computer;
        [DataMember(Order = 16)] internal string UserScope;
        [DataMember(Order = 17)] internal int ArchiveFailures;
        [DataMember(Order = 18)] internal string EvidenceObject;
        [DataMember(Order = 19)] internal uint? ProcessId;
        [DataMember(Order = 20)] internal uint? ThreadId;
        [DataMember(Order = 21)] internal string ActivityId;
        [DataMember(Order = 22)] internal string ApplicationKey;
        [DataMember(Order = 23)] internal string EventUtc;
        [DataMember(Order = 24)] internal CertificateReference[] References;
    }
    [DataContract] internal sealed class HistoryInventory
    {
        [DataMember(Order = 0)] internal int Version = 1;
        [DataMember(Order = 1)] internal List<HistoryLocation> Locations = new List<HistoryLocation>();
        [DataMember(Order = 2)] internal List<HistoryStore> Stores = new List<HistoryStore>();
        [DataMember(Order = 3)] internal List<HistoryCertificate> Certificates = new List<HistoryCertificate>();
        [DataMember(Order = 4)] internal string[] Errors;
        [DataMember(Order = 5)] internal bool Canceled;
        [DataMember(Order = 6)] internal string Computer = Environment.MachineName;
        [DataMember(Order = 7)] internal string UserScope = Environment.UserDomainName + "\\" + Environment.UserName;
    }
    [DataContract] internal sealed class HistoryIndex
    {
        [DataMember(Order = 0)] internal int Version = 1;
        [DataMember(Order = 1)] internal List<HistoryStore> Stores = new List<HistoryStore>();
        [DataMember(Order = 2)] internal string Computer;
        [DataMember(Order = 3)] internal string UserScope;
    }
    [DataContract] internal sealed class HistoryLocation
    {
        [DataMember(Order = 0)] internal string Name;
        [DataMember(Order = 1)] internal string RegistryPath;
        [DataMember(Order = 2)] internal bool Returned;
        [DataMember(Order = 3)] internal string Error;
        [DataMember(Order = 4)] internal string WindowsName;
        [DataMember(Order = 5)] internal uint Flags;
    }
    [DataContract] internal sealed class HistoryStore
    {
        [DataMember(Order = 0)] internal string Kind;
        [DataMember(Order = 1)] internal string Source;
        [DataMember(Order = 2)] internal string RegistryPath;
        [DataMember(Order = 3)] internal bool ReadSucceeded;
        [DataMember(Order = 4)] internal string Error;
        [DataMember(Order = 5)] internal string EnumerationError;
        [DataMember(Order = 6)] internal HistoryMember[] Members;
        [DataMember(Order = 7)] internal string NativeName;
        [DataMember(Order = 8)] internal string Provider;
        [DataMember(Order = 9)] internal bool Predefined;
        [DataMember(Order = 10)] internal uint Flags;
        [DataMember(Order = 11)] internal uint Priority;
    }
    [DataContract] internal sealed class HistoryMember
    {
        [DataMember(Order = 0)] internal string ObjectName;
        [DataMember(Order = 1)] internal string[] Usages;
    }
    [DataContract] internal sealed class HistoryCertificate
    {
        [DataMember(Order = 0)] internal string ObjectName;
        [DataMember(Order = 1)] internal string Identity;
        [DataMember(Order = 2)] internal string Subject;
        [DataMember(Order = 3)] internal string Issuer;
        [DataMember(Order = 4)] internal string Sha1;
        [DataMember(Order = 5)] internal string Sha256;
        [DataMember(Order = 6)] internal string NotBefore;
        [DataMember(Order = 7)] internal string NotAfter;
        [DataMember(Order = 8)] internal string KeyUsage;
        [DataMember(Order = 9)] internal string KeyOid;
        [DataMember(Order = 10)] internal string KeyAlgorithm;
        [DataMember(Order = 11)] internal int? KeySize;
        [DataMember(Order = 12)] internal string SignatureOid;
        [DataMember(Order = 13)] internal string SignatureAlgorithm;
        [DataMember(Order = 14)] internal string SignatureHash;
        [DataMember(Order = 15)] internal string SpkiSha256;
        [DataMember(Order = 16)] internal string[] FoundIn;
        [DataMember(Order = 17)] internal string[] Collections;
        [DataMember(Order = 18)] internal string[] WeakReasons;
        [DataMember(Order = 19)] internal string[] CollisionPeers;
        [DataMember(Order = 20)] internal string[] KeyReusePeers;
        [DataMember(Order = 21)] internal string ParseError;
        [DataMember(Order = 22)] internal string CryptoError;
        internal static HistoryCertificate From(CertificateRecord c, string objectName)
        {
            return new HistoryCertificate { ObjectName = objectName, Identity = c.Identity, Subject = c.Subject, Issuer = c.Issuer,
                Sha1 = c.Sha1, Sha256 = c.Sha256, NotBefore = CertificateRecord.Time(c.NotBefore), NotAfter = CertificateRecord.Time(c.NotAfter),
                KeyUsage = c.KeyUsage, KeyOid = c.KeyOid, KeyAlgorithm = c.KeyAlgorithm, KeySize = c.KeySize,
                SignatureOid = c.SignatureOid, SignatureAlgorithm = c.SignatureAlgorithm, SignatureHash = c.SignatureHash,
                SpkiSha256 = c.SpkiSha256, FoundIn = c.FoundIn.ToArray(), Collections = c.Collections.ToArray(), WeakReasons = c.WeakReasons.ToArray(),
                CollisionPeers = c.CollisionPeers.ToArray(), KeyReusePeers = c.KeyReusePeers.ToArray(), ParseError = c.ParseError, CryptoError = c.CryptoError };
        }
    }
}
