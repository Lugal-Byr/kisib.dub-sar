using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace Kisib
{
    internal static class ControlVerification
    {
        private static string Xml(string digest)
        {
            return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-CAPI2'/><EventID>11</EventID>" +
                "<TimeCreated SystemTime='2026-10-06T12:00:00Z'/><EventRecordID>37</EventRecordID><Correlation ActivityID='{11111111-1111-1111-1111-111111111111}'/>" +
                "<Execution ProcessID='123' ThreadID='456'/><Channel>Microsoft-Windows-CAPI2/Operational</Channel></System><UserData><BuildChain>" +
                "<Certificate fileRef='" + digest + ".cer'/><Certificate fileRef='" + digest + ".cer'/><UnrelatedHex value='" + new string('A',64) + "'/>" +
                "<Result value='0'/></BuildChain></UserData></Event>";
        }
        internal static void Run(string directory, Action<bool, string> check)
        {
            byte[] der = File.ReadAllBytes(Path.Combine(directory, "tests", "fixture.cer"));
            CertificateRecord certificate = CertificateRecord.FromDer(der); Snapshot snapshot = new Snapshot(); snapshot.Add(der);
            ActivityRecord activity = CertificateActivityXml.Parse(Xml(certificate.Sha1));
            check(activity.ProcessId == 123 && activity.ThreadId == 456 && activity.EventId == 11 && activity.RecordId == "37", "Windows event process/thread/time/record fields retain source values");
            check(activity.Operation == "BuildChain [CAPI2 observed]" && activity.Result == "0" && activity.References.Length == 1, "Source operation/result and repeated explicit hash references decode without invented matches");
            check(activity.Match(snapshot).Single().Der.SequenceEqual(der), "Explicit CAPI2 SHA-1 reference matches the observed certificate bytes");
            snapshot.Certificates.Add("synthetic", new CertificateRecord { Identity = "synthetic", Sha1 = certificate.Sha1, Sha256 = "Different synthetic SHA-256", Subject = "Synthetic collision peer" });
            check(activity.Match(snapshot).Length == 2, "Ambiguous SHA-1 references retain all distinct inventory candidates");
            ActivityRecord noHash = CertificateActivityXml.Parse(Xml("unresolved-file"));
            check(noHash.References.Length == 0 && noHash.Match(snapshot).Length == 0, "Unrelated hex and unsupported fileRef values do not create certificate relationships");
            bool dtd = false;
            try { CertificateActivityXml.Parse("<!DOCTYPE Event [<!ENTITY x SYSTEM 'file:///never-read'>]><Event>&x;</Event>"); } catch (XmlException) { dtd = true; }
            check(dtd, "Event XML rejects DTD and external-entity resolution");
            bool wrongProvider = false;
            try { CertificateActivityXml.Parse(Xml(certificate.Sha1).Replace("Name='Microsoft-Windows-CAPI2'", "Name='Other-provider'")); } catch (XmlException) { wrongProvider = true; }
            check(wrongProvider, "Unexpected providers cannot become CAPI2 certificate-use observations");

            ApplicationRecord old = new ApplicationRecord { ProcessId = 123, StartedUtc = "2026-10-06T12:01:00Z", ObservedUtc = "2026-10-06T12:02:00Z" };
            check(!old.Covers(DateTime.Parse("2026-10-06T12:00:00Z").ToUniversalTime()) && old.Covers(DateTime.Parse("2026-10-06T12:01:30Z").ToUniversalTime()), "Historical events before a reused PID's start are not attributed to the later process");
            old.StartedUtc = null; check(!old.Covers(DateTime.UtcNow), "Missing process start times keep temporal attribution unresolved");
            byte[] country = new byte[] { 48,13,49,11,48,9,6,3,85,4,6,19,2,85,83 };
            check(NameAttributes.Single(country, 6) == "US" && NameAttributes.Single(country, 10) == null, "DER name country extraction preserves exact OID meaning");
            byte[] organization = new byte[] { 48,14,49,12,48,10,6,3,85,4,10,12,3,65,44,66 };
            check(NameAttributes.Single(organization, 10) == "A,B", "Quoted/comma-containing organization values are not split as formatted DN text");
            bool truncated = false; try { NameAttributes.Single(country.Take(country.Length - 1).ToArray(), 6); } catch (InvalidOperationException) { truncated = true; }
            check(truncated, "Truncated name attributes remain decoding errors");
            CountryCatalog catalog = CountryCatalog.Read(directory);
            check(catalog.Countries.Length == 248 && catalog.Find("RU") != null && catalog.Find("CK") != null && catalog.Find("MS") != null, "Complete retrieved UN M49 country/area rows and requested country symbols remain present");
            check(catalog.Countries.Count(c => c.Monarchy == "monarchy") == 43 && catalog.Find("GB").MonarchySource != null && catalog.Find("RU").Monarchy == "unknown", "Positive monarchy classifications carry sources; remaining statuses are not guessed");
            IssuerLabels labels = new IssuerLabels(catalog, new AnnotationSet());
            labels.Annotations.Certificates.Add(new CertificateLabel { Identity = certificate.Identity, OwnerCountry = "RU", Source = "Synthetic test", Date = "2026-10-06" });
            check(labels.Tags(certificate).OrderBy(x => x).SequenceEqual(new string[] { "🌿", "🧱", "🇷🇺" }.OrderBy(x => x)), "Russia retains three independent requested tags");
            labels.Annotations.Certificates[0].OwnerCountry = "GB";
            check(labels.Tags(certificate).Contains("👑"), "Monarchy-country grouping supplies the requested crown tag");
            labels.Annotations.Countries.Add(new CountryLabel { Code = "GB", Monarchy = "not monarchy", Source = "Synthetic user override", Date = "2026-10-06" });
            check(!labels.Tags(certificate).Contains("👑") && !labels.CountryDisplay("GB").Contains("👑"), "Sourced local classification overrides update both tag and tree display");

            string temporary = Path.Combine(Path.GetTempPath(), "kisib-controls-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (HistoryArchive history = new HistoryArchive(temporary))
                {
                    history.RecordCountryCatalog(catalog);
                    check(history.RecordActivity(activity), "Original certificate diagnostic payload commits durably");
                    bool more;
                    check(history.ReadPage(history.JournalFiles().Last(), certificate.Sha256, 0, out more, certificate.Sha1).Contains("application_certificate_activity"), "Certificate history includes a reported SHA-1 reference without rewriting it as SHA-256");
                    ActivityPage page = ActivityArchive.Certificates(history, history.JournalFiles().Last(), 0);
                    check(page.Records.Single().Payload == activity.Payload && page.Records.Single().ProcessId == 123, "Retained evidence paging restores original XML and attribution");
                    AnnotationSet first = new AnnotationSet(); first.Certificates.Add(new CertificateLabel { Identity = certificate.Identity, Owner = "Example owner", Source = "Synthetic test", Date = "2026-10-06" });
                    check(history.SaveAnnotations(first), "Issuer label version is stored in the continuing archive");
                    ActivityRecord labeled = CertificateActivityXml.Parse(Xml(certificate.Sha1)); history.RecordActivity(labeled);
                    AnnotationSet second = first.Next(); second.Certificates[0].Owner = "Changed example owner"; history.SaveAnnotations(second);
                    check(Directory.GetFiles(Path.Combine(temporary, "labels"), "*.json").Length == 2, "A changed label version retains the earlier contents");
                    ActivityRecord retained = ActivityArchive.Certificates(history, history.JournalFiles().Last(), 0).Records.Last();
                    AnnotationSet original = HistoryArchive.Decode<AnnotationSet>(File.ReadAllBytes(Path.Combine(temporary, "labels", retained.AnnotationObjectAtRetention + ".json")));
                    check(original.Id == first.Id && original.Certificates.Single().Owner == "Example owner" && retained.CountryCatalogObjectAtRetention != null,
                        "Later label edits do not replace the immutable annotation/catalog context pinned to retained activity");
                    history.SaveCheckpoint("capi2-bookmark", "<BookmarkList>synthetic checkpoint</BookmarkList>");
                }
                using (HistoryArchive history = new HistoryArchive(temporary))
                {
                    check(history.LoadAnnotations().Certificates.Single().Owner == "Changed example owner", "Restart restores the last committed label version");
                    check(history.LoadCheckpoint("capi2-bookmark").Contains("synthetic checkpoint"), "Replay checkpoint survives a new archive session");
                }
            }
            finally { if (Directory.Exists(temporary)) Directory.Delete(temporary, true); }
            check(SyscallTrace.Decode(51, new byte[] { 1,2,3,4,5,6,7,8 }, 8).Contains("0807060504030201"), "System-call enter decoder retains the pointer value");
            check(SyscallTrace.Decode(52, new byte[] { 5,0,0,192 }, 8).Contains("C0000005"), "System-call exit decoder retains reported NTSTATUS");
            check(SyscallTrace.Decode(51, new byte[0], 8).Contains("unsupported"), "Unavailable syscall payload stays unresolved");
            if (IntPtr.Size == 8)
            {
                check(Marshal.SizeOf(typeof(EtwNative.Header)) == 80 && Marshal.SizeOf(typeof(EtwNative.Record)) == 112 && Marshal.SizeOf(typeof(EtwNative.Properties)) == 120, "64-bit ETW header/record/controller ABI sizes");
                check(Marshal.SizeOf(typeof(EtwNative.Logfile)) == 448 && Marshal.OffsetOf(typeof(EtwNative.Logfile), "EventRecordCallback").ToInt32() == 424, "64-bit ETW consumer ABI size and callback offset");
            }
        }
    }
}
