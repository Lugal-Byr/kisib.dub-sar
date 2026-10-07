using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;

namespace Kisib
{
    [DataContract] internal sealed class ApplicationRecord
    {
        [DataMember] internal int ProcessId;
        [DataMember] internal string Name;
        [DataMember] internal string Executable;
        [DataMember] internal string StartedUtc;
        [DataMember] internal string ObservedUtc;
        [DataMember] internal string Error;
        internal string Key { get { return ProcessId + "|" + (StartedUtc ?? "unknown-start"); } }
        internal bool Covers(DateTime time)
        {
            DateTime start, observed;
            return DateTime.TryParse(StartedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out start) &&
                DateTime.TryParse(ObservedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out observed) &&
                time >= start && time <= observed;
        }
        internal static ApplicationRecord[] Read()
        {
            List<ApplicationRecord> rows = new List<ApplicationRecord>();
            foreach (Process process in Process.GetProcesses())
            using (process)
            {
                ApplicationRecord row = new ApplicationRecord { ProcessId = process.Id };
                List<string> errors = new List<string>();
                try { row.Name = process.ProcessName; } catch (Exception ex) { errors.Add(ex.Message); }
                try { row.StartedUtc = process.StartTime.ToUniversalTime().ToString("o"); } catch (Exception ex) { errors.Add("StartTime: " + ex.Message); }
                try { row.Executable = process.MainModule.FileName; } catch (Exception ex) { errors.Add("Executable: " + ex.Message); }
                row.ObservedUtc = DateTime.UtcNow.ToString("o");
                row.Error = errors.Count == 0 ? null : String.Join("; ", errors.ToArray()); rows.Add(row);
            }
            return rows.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.ProcessId).ToArray();
        }
        internal static ApplicationRecord Find(uint processId)
        {
            if (processId > Int32.MaxValue) return null;
            try
            {
                using (Process process = Process.GetProcessById((int)processId))
                {
                    ApplicationRecord row = new ApplicationRecord { ProcessId = process.Id, Name = process.ProcessName,
                        StartedUtc = process.StartTime.ToUniversalTime().ToString("o") };
                    try { row.Executable = process.MainModule.FileName; } catch (Exception ex) { row.Error = ex.Message; }
                    row.ObservedUtc = DateTime.UtcNow.ToString("o"); return row;
                }
            }
            catch { return null; }
        }
    }

    [DataContract] internal sealed class CertificateReference
    {
        [DataMember] internal string Algorithm;
        [DataMember] internal string Value;
        [DataMember] internal string Field;
    }

    [DataContract] internal sealed class ActivityRecord
    {
        [DataMember] internal string Id = Guid.NewGuid().ToString("N");
        [DataMember] internal string Utc;
        [DataMember] internal string ReceivedUtc = DateTime.UtcNow.ToString("o");
        [DataMember] internal string Source;
        [DataMember] internal string Provider;
        [DataMember] internal int EventId;
        [DataMember] internal string RecordId;
        [DataMember] internal uint? ProcessId;
        [DataMember] internal uint? ThreadId;
        [DataMember] internal string ActivityId;
        [DataMember] internal string ApplicationKey;
        [DataMember] internal string ApplicationName;
        [DataMember] internal string ActorEvidence;
        [DataMember] internal string Operation;
        [DataMember] internal string Result;
        [DataMember] internal string Payload;
        [DataMember] internal string EvidenceObject;
        [DataMember] internal string AnnotationObjectAtRetention;
        [DataMember] internal string CountryCatalogObjectAtRetention;
        [DataMember] internal string TracePath;
        [DataMember] internal CertificateReference[] References = new CertificateReference[0];

        internal CertificateRecord[] Match(Snapshot snapshot)
        {
            if (snapshot == null || References == null) return new CertificateRecord[0];
            return snapshot.Certificates.Values.Where(c => References.Any(r =>
                r.Algorithm == "SHA-256" && r.Value == c.Sha256 || r.Algorithm == "SHA-1" && r.Value == c.Sha1)).ToArray();
        }
        internal string Description()
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine("Observed operation: " + Operation); text.AppendLine("Source: " + Source);
            text.AppendLine("Provider: " + Provider + " | Event ID/opcode: " + EventId + " | record: " + RecordId);
            text.AppendLine("Event UTC: " + Utc + " | received UTC: " + ReceivedUtc);
            text.AppendLine("Process ID: " + ProcessId + " | thread ID: " + ThreadId);
            text.AppendLine("Application: " + (ApplicationName ?? "Unresolved") + " | lifetime: " + (ApplicationKey ?? "Unresolved"));
            text.AppendLine("Actor evidence: " + ActorEvidence); text.AppendLine("Activity ID: " + ActivityId);
            text.AppendLine("Reported result: " + (Result ?? "Not supplied"));
            text.AppendLine("Retained evidence object: " + EvidenceObject);
            text.AppendLine("Annotation object when retained: " + (AnnotationObjectAtRetention ?? "Not recorded"));
            text.AppendLine("Country catalog object when retained: " + (CountryCatalogObjectAtRetention ?? "Not recorded"));
            text.AppendLine("Retention context is separate from the event's source time; replay does not reconstruct past labels.");
            if (TracePath != null) text.AppendLine("Original ETL: " + TracePath);
            text.AppendLine("Certificate references (lookup evidence, not parent links):");
            foreach (CertificateReference reference in References ?? new CertificateReference[0])
                text.AppendLine("  " + reference.Algorithm + " " + reference.Value + " | " + reference.Field);
            text.AppendLine("CAPI2 records cover Windows certificate diagnostics. Other application verifiers have separate coverage.");
            text.AppendLine("Syscall rows describe kernel calls; their certificate purpose is not supplied by this provider.");
            text.AppendLine("Implementation/correlation: to test. Original payload follows."); text.AppendLine(); text.Append(Payload);
            return text.ToString();
        }
    }

    internal static class CertificateActivityXml
    {
        internal static ActivityRecord Parse(string xml)
        {
            XmlDocument document = new XmlDocument { XmlResolver = null };
            XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 4 * 1024 * 1024 };
            using (StringReader text = new StringReader(xml)) using (XmlReader reader = XmlReader.Create(text, settings)) document.Load(reader);
            XmlElement root = document.DocumentElement;
            if (root == null || root.LocalName != "Event") throw new XmlException("Windows Event XML root is unavailable.");
            XmlNode system = root.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == "System");
            if (system == null) throw new XmlException("Windows Event System fields are unavailable.");
            Func<string, XmlNode> field = name => system.ChildNodes.Cast<XmlNode>().FirstOrDefault(n => n.LocalName == name);
            int eventId; Int32.TryParse(Value(field("EventID")), out eventId);
            ActivityRecord result = new ActivityRecord { Source = Value(field("Channel")), Provider = Attribute(field("Provider"), "Name"),
                EventId = eventId, RecordId = Value(field("EventRecordID")), Utc = Attribute(field("TimeCreated"), "SystemTime"),
                ProcessId = Number(Attribute(field("Execution"), "ProcessID")), ThreadId = Number(Attribute(field("Execution"), "ThreadID")),
                ActivityId = Attribute(field("Correlation"), "ActivityID"), Payload = xml,
                ActorEvidence = "System.Execution process/thread identifies the log emitter; requesting client identity is not inferred.",
                Operation = "Windows certificate diagnostic event " + eventId };
            if (result.Provider != "Microsoft-Windows-CAPI2") throw new XmlException("Unexpected certificate diagnostic provider.");
            List<CertificateReference> references = new List<CertificateReference>();
            foreach (XmlNode node in root.SelectNodes(".//*"))
            {
                if (node.ParentNode == system || node == system) continue;
                if (node.LocalName == "Result") result.Result = Attribute(node, "value") ?? node.InnerText;
                if (node.ParentNode != null && node.ParentNode.LocalName == "UserData" && result.Operation.StartsWith("Windows certificate"))
                    result.Operation = node.LocalName + " [CAPI2 observed]";
                if (!node.LocalName.Equals("Certificate", StringComparison.OrdinalIgnoreCase) && !node.LocalName.Equals("Cert", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (string name in new string[] { "fileRef", "sha1", "sha256", "thumbprint" })
                {
                    string raw = Attribute(node, name); if (raw == null) continue;
                    string digest = raw.Trim();
                    if (name == "fileRef")
                    {
                        Match match = Regex.Match(digest, @"\A([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\.cer\z", RegexOptions.CultureInvariant);
                        if (!match.Success) continue; digest = match.Groups[1].Value;
                    }
                    else digest = digest.Replace(" ", "").Replace(":", "");
                    if (!Regex.IsMatch(digest, @"\A(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\z", RegexOptions.CultureInvariant)) continue;
                    string algorithm = digest.Length == 40 ? "SHA-1" : "SHA-256";
                    if (name == "sha1" && algorithm != "SHA-1" || name == "sha256" && algorithm != "SHA-256") continue;
                    if (!references.Any(r => r.Algorithm == algorithm && r.Value == digest.ToUpperInvariant()))
                        references.Add(new CertificateReference { Algorithm = algorithm, Value = digest.ToUpperInvariant(), Field = node.LocalName + "@" + name + " [mapping to test]" });
                }
            }
            result.References = references.ToArray(); return result;
        }
        private static string Value(XmlNode node) { return node == null ? null : node.InnerText; }
        private static string Attribute(XmlNode node, string name) { return node == null || node.Attributes == null || node.Attributes[name] == null ? null : node.Attributes[name].Value; }
        private static uint? Number(string text) { uint value; return UInt32.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value) ? (uint?)value : null; }
    }

    internal sealed class ActivityMonitor : IDisposable
    {
        internal const string Channel = "Microsoft-Windows-CAPI2/Operational";
        private readonly object gate = new object();
        private readonly object deliveryGate = new object();
        private readonly object lifecycleGate = new object();
        private readonly HistoryArchive history;
        private EventLogWatcher watcher;
        private readonly Queue<ActivityRecord> pending = new Queue<ActivityRecord>();
        private readonly Dictionary<string, ApplicationRecord> applications = new Dictionary<string, ApplicationRecord>(StringComparer.Ordinal);
        private readonly HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
        private readonly Queue<string> seenOrder = new Queue<string>();
        internal string Status { get; private set; }
        internal long DisplaySkipped { get; private set; }
        internal long ArchivedEvents { get; private set; }
        private bool disposed;
        private bool checkpointBlocked;
        internal ActivityMonitor(HistoryArchive history) { this.history = history; Status = "CAPI2 not started"; }
        internal ApplicationRecord[] Applications { get { lock (gate) return applications.Values.OrderBy(x => x.Name).ThenBy(x => x.ProcessId).ToArray(); } }
        internal void RefreshApplications()
        {
            lock (gate) if (disposed) return;
            ApplicationRecord[] observed = ApplicationRecord.Read();
            lock (gate) { if (disposed) return; foreach (ApplicationRecord app in observed) applications[app.Key] = app; }
            if (history != null) history.RecordApplicationInventory(observed);
        }
        internal void Start()
        { lock (lifecycleGate) StartSerial(false); }
        internal void Restart(bool replayAvailable, Func<bool> allowed)
        { lock (lifecycleGate) { if (!allowed()) return; StopSerial(); StartSerial(replayAvailable); } }
        private void StartSerial(bool replayAvailable)
        {
            lock (gate) if (disposed || watcher != null) return;
            lock (deliveryGate) checkpointBlocked = false;
            try
            {
                using (EventLogConfiguration configuration = new EventLogConfiguration(Channel))
                    if (!configuration.IsEnabled) { SetStatus("CAPI2 disabled — Live > Enable Windows CAPI2 logging"); return; }
                string bookmark = null;
                try { bookmark = history == null || replayAvailable ? null : history.LoadCheckpoint("capi2-bookmark"); }
                catch (Exception ex) { SetStatus("CAPI2 checkpoint read failed; replaying available Windows records: " + ex.Message); }
                if (replayAvailable) SetStatus("CAPI2 explicit replay of all available Windows records; previous evidence retained");
                EventLogQuery query = new EventLogQuery(Channel, PathType.LogName, "*");
                EventLogWatcher candidate;
                try { candidate = new EventLogWatcher(query, bookmark == null ? null : new EventBookmark(bookmark), true); }
                catch (EventLogException ex)
                { SetStatus("CAPI2 bookmark unavailable; replaying available Windows records: " + ex.Message); candidate = new EventLogWatcher(query, null, true); }
                catch (ArgumentException ex)
                { SetStatus("CAPI2 bookmark invalid; replaying available Windows records: " + ex.Message); candidate = new EventLogWatcher(query, null, true); }
                candidate.EventRecordWritten += RecordWritten;
                lock (gate) { if (disposed) { candidate.Dispose(); return; } watcher = candidate; }
                SetStatus("CAPI2 listening; retained Windows records replay, then live events"); candidate.Enabled = true;
            }
            catch (Exception ex) { StopSerial(); SetStatus("CAPI2 unavailable: " + ex.GetType().Name + ": " + ex.Message); }
        }
        private void RecordWritten(object sender, EventRecordWrittenEventArgs args)
        { lock (deliveryGate) RecordWrittenSerial(args); }
        private void RecordWrittenSerial(EventRecordWrittenEventArgs args)
        {
            try
            {
                if (args.EventException != null) { checkpointBlocked = true; SetStatus("CAPI2 delivery gap: " + args.EventException.Message + "; Live > Replay available CAPI2 records can recover records Windows still retains"); return; }
                using (EventRecord record = args.EventRecord)
                {
                    if (record == null) return;
                    string xml = record.ToXml(); ActivityRecord activity;
                    try { activity = CertificateActivityXml.Parse(xml); }
                    catch (Exception ex) { activity = new ActivityRecord { Source = Channel, Provider = "Microsoft-Windows-CAPI2", EventId = record.Id,
                        RecordId = Convert.ToString(record.RecordId, CultureInfo.InvariantCulture), Payload = xml, Operation = "Unparsed CAPI2 record", Result = ex.Message,
                        ActorEvidence = "Payload retained; interpretation unavailable" }; }
                    string key;
                    using (System.Security.Cryptography.SHA256 hash = System.Security.Cryptography.SHA256.Create()) key = CertificateRecord.Hex(hash.ComputeHash(Encoding.UTF8.GetBytes(xml)));
                    activity.Id = key; // stable source-event identity across replay; journal attempts retain their own IDs
                    ApplicationRecord live = activity.ProcessId.HasValue ? ApplicationRecord.Find(activity.ProcessId.Value) : null;
                    lock (gate)
                    {
                        if (disposed || seen.Contains(key)) return;
                        if (live != null) applications[live.Key] = live;
                        DateTime time;
                        if (activity.ProcessId.HasValue && DateTime.TryParse(activity.Utc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out time))
                        {
                            ApplicationRecord app = applications.Values.FirstOrDefault(a => a.ProcessId == activity.ProcessId.Value && a.Covers(time.ToUniversalTime()));
                            if (app != null) { activity.ApplicationKey = app.Key; activity.ApplicationName = app.Name; }
                        }
                    }
                    bool saved = history != null && history.RecordActivity(activity);
                    if (saved)
                    {
                        lock (gate)
                        {
                            ArchivedEvents++; seen.Add(key); seenOrder.Enqueue(key);
                            if (seenOrder.Count > 20000) seen.Remove(seenOrder.Dequeue()); // replay cache only; persisted records have no cap
                        }
                        if (!checkpointBlocked && record.Bookmark != null) history.SaveCheckpoint("capi2-bookmark", record.Bookmark.BookmarkXml);
                    }
                    Publish(activity);
                    if (!saved) { checkpointBlocked = true; SetStatus("CAPI2 received; history write unavailable — bookmark held before the gap for replay"); }
                }
            }
            catch (Exception ex) { checkpointBlocked = true; SetStatus("CAPI2 handler gap: " + ex.GetType().Name + ": " + ex.Message); }
        }
        internal void Publish(ActivityRecord activity)
        {
            lock (gate)
            {
                if (disposed) return;
                if (pending.Count == 2000) { pending.Dequeue(); DisplaySkipped++; }
                pending.Enqueue(activity);
            }
        }
        internal ActivityRecord[] Drain()
        { lock (gate) { ActivityRecord[] result = pending.ToArray(); pending.Clear(); return result; } }
        internal void AssociateObservedLifetimes(IEnumerable<ActivityRecord> records)
        {
            Dictionary<uint, ApplicationRecord[]> byPid;
            lock (gate) byPid = applications.Values.GroupBy(a => (uint)a.ProcessId).ToDictionary(g => g.Key, g => g.ToArray());
            foreach (ActivityRecord activity in records.Where(a => a.ApplicationKey == null && a.ProcessId.HasValue))
            {
                DateTime time; ApplicationRecord[] candidates;
                if (!DateTime.TryParse(activity.Utc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out time) || !byPid.TryGetValue(activity.ProcessId.Value, out candidates)) continue;
                ApplicationRecord[] matches = candidates.Where(a => a.Covers(time.ToUniversalTime())).ToArray();
                if (matches.Length == 1)
                {
                    activity.ApplicationKey = matches[0].Key; activity.ApplicationName = matches[0].Name;
                    activity.ActorEvidence += " UI lifetime association from a later observed process inventory; original retained event fields stay unchanged.";
                }
            }
        }
        private void SetStatus(string value)
        { lock (gate) Status = value; if (history != null) history.Note(null, "capi2_coverage", Channel, value); }
        internal void Stop()
        { lock (lifecycleGate) StopSerial(); }
        private void StopSerial()
        {
            EventLogWatcher old; lock (gate) { old = watcher; watcher = null; }
            if (old == null) return;
            old.EventRecordWritten -= RecordWritten;
            string error = null;
            try { old.Enabled = false; } catch (Exception ex) { error = ex.Message; }
            finally { try { old.Dispose(); } catch (Exception ex) { error = (error == null ? "" : error + "; ") + ex.Message; } }
            SetStatus("CAPI2 stopped; collection gap until restarted" + (error == null ? "" : "; watcher cleanup: " + error));
        }
        public void Dispose() { lock (lifecycleGate) { lock (gate) disposed = true; StopSerial(); } }
    }
}
