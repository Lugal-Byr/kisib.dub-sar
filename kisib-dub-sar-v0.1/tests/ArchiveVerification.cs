using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Kisib
{
    internal static class ArchiveVerification
    {
        private static HistoryEvent[] Events(string directory)
        {
            return Directory.GetFiles(Path.Combine(directory, "logs"), "*.jsonl").OrderBy(x => x)
                .SelectMany(File.ReadAllLines).Where(x => x.Length > 0).Select(line =>
                {
                    using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(line)))
                        return (HistoryEvent)new DataContractJsonSerializer(typeof(HistoryEvent)).ReadObject(stream);
                }).ToArray();
        }

        private static Snapshot Inventory(byte[] der, bool present, bool readable, bool canceled)
        {
            Snapshot scan = new Snapshot();
            StoreLocation location = new StoreLocation { Name = "CURRENT_USER", Enumerated = true, RegistryPath = "Synthetic test source; never installed" };
            SystemStore store = new SystemStore { Name = "ArchiveFixture", Path = @"CURRENT_USER\ArchiveFixture", Error = "Synthetic collection not read" };
            PhysicalStore physical = new PhysicalStore { Name = ".Default", Path = store.Path + @"\.Default", ReadSucceeded = readable,
                Error = readable ? null : "Synthetic access failure" };
            location.Stores.Add(store); store.PhysicalStores.Add(physical); scan.Locations.Add(location);
            if (present)
            {
                CertificateRecord cert = scan.Add(der);
                cert.FoundIn.Add(physical.Path); physical.Certificates.Add(cert.Identity);
                cert.UsageBySource.Add(physical.Path, new System.Collections.Generic.SortedSet<string>(new string[] { "Synthetic EKU observation" }));
            }
            scan.Canceled = canceled; scan.Finished = DateTime.UtcNow;
            return scan;
        }

        internal static void Run(string sourceDirectory, Action<bool, string> check)
        {
            // Synthetic reference records test serializer graph scale, not CA trust.
            HistoryIndex large = new HistoryIndex();
            large.Stores.Add(new HistoryStore { Kind = "synthetic", Source = "Archive codec scale fixture",
                Members = Enumerable.Range(0, 10025).Select(i => new HistoryMember { ObjectName = i.ToString("X64"),
                    Usages = new string[] { "a", "b", "c", "d", "e", "f" } }).ToArray() });
            HistoryIndex roundTrip = HistoryArchive.Decode<HistoryIndex>(HistoryArchive.Encode(large));
            check(roundTrip.Stores.Single().Members.Length == 10025 && roundTrip.Stores.Single().Members.Last().ObjectName == (10024).ToString("X64"),
                "Archive codec retains more than 10000 records and a large object graph without a consumer subset");
            byte[] der = File.ReadAllBytes(Path.Combine(sourceDirectory, "tests", "fixture.cer"));
            string directory = Path.Combine(Path.GetTempPath(), "kisib-history-test-" + Guid.NewGuid().ToString("N"));
            string broken = directory + "-failure";
            string torn = directory + "-torn";
            string altered = directory + "-integrity";
            try
            {
                using (HistoryArchive history = new HistoryArchive(directory))
                {
                    bool refused = false;
                    try { using (HistoryArchive duplicate = new HistoryArchive(directory)) { } }
                    catch (IOException) { refused = true; }
                    check(refused, "Archive refuses concurrent writers");
                    Snapshot first = Inventory(der, true, true, false);
                    first.EventSink = history.Note;
                    first.Note("Test event", "Synthetic source\twith separator", "Outcome\nwith newline");
                    history.CaptureBytes(first.ScanId, der, "Synthetic raw-byte source");
                    history.Observe(first, first.Certificates.Values.Single(), first.Certificates.Values.Single().FoundIn.Single(), "Synthetic usage");
                    history.Commit(first);
                    int inventories = Directory.GetFiles(Path.Combine(directory, "inventories"), "*.json").Length;
                    history.Commit(Inventory(der, true, true, false));
                    check(Directory.GetFiles(Path.Combine(directory, "certificates"), "*.cer").Length == 1, "Repeated DER and scans retain one public certificate object");
                    check(Directory.GetFiles(Path.Combine(directory, "inventories"), "*.json").Length == inventories, "Identical inventory content is stored once; each scan keeps its own journal event");
                    history.Commit(Inventory(der, false, false, false));
                    history.Commit(Inventory(der, false, true, true));
                    check(!Events(directory).Any(x => x.Action == "occurrence_removed"), "Denied and canceled reads never remove prior observed occurrences");
                    check(history.LastError == null && history.FailedWrites == 0, "Successful archive writes report no storage failure");
                }
                using (HistoryArchive history = new HistoryArchive(directory))
                {
                    history.Commit(Inventory(der, false, true, false));
                    HistoryEvent[] events = Events(directory);
                    check(events.Count(x => x.Action == "occurrence_removed") == 1, "A successful empty read after restart compares against the retained successful baseline");
                    check(events.Any(x => x.Action == "Test event" && x.Source.Contains("\t") && x.Outcome.Contains("\n")), "JSON records retain field separators and multiline outcomes without splitting events");
                    check(events.Select(x => x.EventId).Distinct().Count() == events.Length, "Every persisted event retains a distinct ID across launches");
                    check(events.Where(x => x.Action == "scan_archive_committed").Select(x => x.SessionId).Distinct().Count() == 2, "Earlier scan sessions survive restart");
                    bool more;
                    string page = history.ReadPage(history.JournalFiles().Last(), CertificateRecord.FromDer(der).Sha256, 0, out more);
                    check(page.Contains("certificate_observed") && page.Contains("occurrence_removed"), "Certificate history includes old observations and subsequent removal");
                    for (int i = 0; i < 505; i++) history.Note("page-test", "pagination-test", "Synthetic source", i.ToString());
                    history.ReadPage(history.JournalFiles().Last(), null, 0, out more);
                    check(more, "History UI pagination announces retained later records");
                    string next = history.ReadPage(history.JournalFiles().Last(), null, 1, out more);
                    check(next.Contains("pagination-test"), "Later history pages read records beyond the display page size");
                }
                check(File.ReadAllBytes(Directory.GetFiles(Path.Combine(directory, "certificates"), "*.cer").Single()).SequenceEqual(der), "Archived bytes equal the original public DER; no private-key export");

                Directory.CreateDirectory(broken);
                File.WriteAllText(Path.Combine(broken, "certificates"), "Synthetic filesystem obstruction");
                using (HistoryArchive history = new HistoryArchive(broken))
                {
                    Snapshot scan = Inventory(der, true, true, false);
                    history.Observe(scan, scan.Certificates.Values.Single(), "Synthetic source", "Synthetic usage");
                    check(history.LastError != null && history.FailedWrites == 1, "Public-object write failures remain explicit instead of claiming archival success");
                }
                using (HistoryArchive history = new HistoryArchive(torn)) { history.Note("incomplete-scan", "Start", "Synthetic source", "No committed inventory"); }
                string journal = Directory.GetFiles(Path.Combine(torn, "logs"), "*.jsonl").Single();
                File.AppendAllText(journal, "{\"Version\":");
                using (HistoryArchive history = new HistoryArchive(torn))
                {
                    check(history.RecoveryWarnings.Count > 0, "An interrupted journal tail is reported and retained on reopen");
                    bool more;
                    check(history.ReadPage(journal, null, 0, out more).Contains("unreadable retained record"), "History displays preserved interrupted records alongside later events");
                }
                using (HistoryArchive history = new HistoryArchive(altered))
                { history.Commit(Inventory(der, true, true, false)); }
                string index = Path.Combine(altered, "indexes", Events(altered).Single(x => x.Action == "scan_archive_committed").IndexObject + ".json");
                byte[] changed = File.ReadAllBytes(index);
                changed[0] ^= 1;
                File.WriteAllBytes(index, changed);
                bool integrityRefused = false;
                try { using (HistoryArchive history = new HistoryArchive(altered)) { } }
                catch (InvalidOperationException ex) { integrityRefused = ex.Message.Contains("integrity"); }
                check(integrityRefused && File.ReadAllBytes(index).SequenceEqual(changed), "Altered committed index disables recovery without overwriting retained evidence");
            }
            finally
            {
                foreach (string path in new string[] { directory, broken, torn, altered })
                    if (Directory.Exists(path)) Directory.Delete(path, true);
            }
        }
    }
}
