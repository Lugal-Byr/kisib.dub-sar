using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Kisib
{
    public static class NativeActivityVerification
    {
        private static int checks;
        private static void Check(bool condition, string name)
        { if (!condition) throw new InvalidOperationException("FAIL native activity: " + name); checks++; Console.WriteLine("PASS native activity: " + name); }
        public static int Run(string project, string results)
        {
            string directory = Path.Combine(Path.GetTempPath(), "kisib-native-activity-" + Guid.NewGuid().ToString("N"));
            bool originalEnabled = false, configurationRead = false;
            try
            {
                using (EventLogConfiguration configuration = new EventLogConfiguration(ActivityMonitor.Channel))
                {
                    originalEnabled = configuration.IsEnabled; configurationRead = true;
                    if (!originalEnabled) { configuration.IsEnabled = true; configuration.SaveChanges(); }
                }
                using (HistoryArchive history = new HistoryArchive(directory))
                {
                    Snapshot inventory = new Snapshot(); CertificateRecord cert = inventory.Add(File.ReadAllBytes(Path.Combine(project, "tests", "fixture.cer")));
                    List<ActivityRecord> received = new List<ActivityRecord>(); uint processId = (uint)Process.GetCurrentProcess().Id;
                    using (ActivityMonitor monitor = new ActivityMonitor(history))
                    {
                        monitor.RefreshApplications(); monitor.Start();
                        Check(monitor.Status.Contains("listening"), "CAPI2 watcher starts against the real enabled Windows channel");
                        DateTime start = DateTime.UtcNow;
                        for (int i = 0; i < 4; i++)
                        {
                            using (X509Certificate2 certificate = new X509Certificate2(cert.Der))
                            using (X509Chain chain = new X509Chain())
                            { chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(1); chain.Build(certificate); }
                        }
                        Stopwatch wait = Stopwatch.StartNew();
                        while (wait.Elapsed.TotalSeconds < 20)
                        {
                            received.AddRange(monitor.Drain());
                            if (received.Any(a => a.ProcessId == processId && a.Match(inventory).Length > 0) && history.LoadCheckpoint("capi2-bookmark") != null) break;
                            Thread.Sleep(100);
                        }
                        ActivityRecord observed = received.FirstOrDefault(a => a.ProcessId == processId && a.Match(inventory).Length > 0);
                        if (observed == null) Console.WriteLine("Own-process CAPI2 events: " + String.Join("; ", received.Where(a => a.ProcessId == processId).Select(a => a.Operation + ": refs=" + a.References.Length)));
                        Check(observed != null && observed.Provider == "Microsoft-Windows-CAPI2", "real CAPI2 XML contains an explicit reference to the public fixture, associated with its emitting PID");
                        observed.ValidateRetained();
                        Check(monitor.ArchivedEvents > 0 && history.LastError == null, "real CAPI2 evidence is durable before its checkpoint advances");
                        string bookmark = history.LoadCheckpoint("capi2-bookmark");
                        Check(bookmark != null && BookmarkCodec.Encode(BookmarkCodec.Decode(bookmark)) == bookmark, ".NET Framework bookmark transport round-trips without BinaryFormatter");
                        File.WriteAllText(Path.Combine(results, "capi2-owned-fixture.xml"), observed.Payload);
                        monitor.Stop(); monitor.Start();
                        Check(monitor.Status.Contains("listening"), "watcher resumes from the persisted real EventBookmark");
                        monitor.Stop();
                        history.SaveCheckpoint("capi2-bookmark", "<unsupported-bookmark />"); monitor.Start();
                        Check(monitor.Status.Contains("listening"), "invalid checkpoint falls back to available Windows records"); monitor.Stop();
                        int retained = 0; foreach (string journal in history.JournalFiles())
                        {
                            ActivityPage page = ActivityArchive.Certificates(history, journal, 0); retained += page.Records.Length;
                            Check(!page.Records.Any(a => a.Operation == "Retained evidence unavailable"), "real archived CAPI2 records pass schema and integrity checks");
                        }
                        Check(retained > 0, "real CAPI2 records reopen in retained date pages");
                    }
                    List<ActivityRecord> samples = new List<ActivityRecord>(); object gate = new object();
                    using (SyscallTrace trace = new SyscallTrace(history, delegate(ActivityRecord activity) { lock (gate) samples.Add(activity); }))
                    {
                        trace.Start(); Check(trace.Running, "explicit owned syscall session starts on Windows");
                        Stopwatch wait = Stopwatch.StartNew();
                        while (wait.Elapsed.TotalSeconds < 5)
                        { File.Exists(Path.Combine(project, "tests", "fixture.cer")); if (Interlocked.Read(ref trace.EventsReceived) > 100) break; Thread.Sleep(10); }
                        trace.Query(); trace.Stop(); Check(!trace.Running, "owned session stops and its native consumer exits");
                        Check(trace.EventsReceived > 0 && trace.DecodeErrors == 0, "live PerfInfo system-call records arrive and decode using the tested ABI");
                        Check(File.Exists(trace.Path) && new FileInfo(trace.Path).Length > 0, "a nonempty original syscall ETL is retained");
                        ActivityPage page = ActivityArchive.Syscalls(history, trace.Path, 0);
                        Check(page.Records.Length > 0 && !page.Records.Any(a => a.Operation == "ETL decode unavailable"), "original ETL reopens through native OpenTrace/ProcessTrace and yields unsampled records");
                        Console.WriteLine("Syscall observation: received=" + trace.EventsReceived + "; decoded=" + samples.Count + "; display omissions=" + trace.DisplaySamplesSkipped + "; lost events=" + trace.EventsLost + "; lost buffers=" + trace.BuffersLost + "; ETL bytes=" + new FileInfo(trace.Path).Length);
                        File.WriteAllText(Path.Combine(results, "native-activity.txt"), "CAPI2 own-fixture reference observed. Original evidence reopened. Bookmark round-trip/resume and malformed fallback exercised.\r\n" +
                            "Syscall received=" + trace.EventsReceived + "; live examples=" + samples.Count + "; UI omissions=" + trace.DisplaySamplesSkipped + "; decode errors=" + trace.DecodeErrors + "; lost events=" + trace.EventsLost + "; lost buffers=" + trace.BuffersLost + "; ETL bytes=" + new FileInfo(trace.Path).Length + ".\r\n" +
                            "No assertion of universal application verification, syscall purpose, gapless capture, or Home/Pro validation. Temporary full ETL is not distributed.\r\n");
                        trace.Start(); trace.Stop(); Check(!trace.Running, "same controller can start and stop a subsequent distinct capture");
                    }
                    ApplicationRecord app = ApplicationRecord.Find(processId); ApplicationSignature signer = ApplicationSignature.Read(app);
                    string expected; using (FileStream file = File.OpenRead(app.Executable)) using (SHA256 hash = SHA256.Create()) expected = CertificateRecord.Hex(hash.ComputeHash(file));
                    Check(signer.FileSha256 == expected && signer.FileBytes > 0 && signer.Verification.StartsWith("Not evaluated"), "selected running process file hash matches an independent read without claiming Authenticode trust");
                    app.StartedUtc = DateTime.UtcNow.AddYears(-1).ToString("o"); ApplicationSignature stale = ApplicationSignature.Read(app);
                    Check(stale.FileSha256 == null && stale.Error.Contains("lifetime"), "stale PID/start-time evidence refuses signer attribution");
                }
                Console.WriteLine("Native activity assertions passed: " + checks + ". Collector tests ran on this disposable GitHub-hosted Windows VM."); return 0;
            }
            catch (Exception ex) { Console.WriteLine(ex); return 1; }
            finally
            {
                if (configurationRead) using (EventLogConfiguration configuration = new EventLogConfiguration(ActivityMonitor.Channel))
                { if (configuration.IsEnabled != originalEnabled) { configuration.IsEnabled = originalEnabled; configuration.SaveChanges(); } }
                try { Directory.Delete(directory, true); } catch (IOException) { }
            }
        }
    }
}
