using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Kisib
{
    public static class RedTeamVerification
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateHardLinkW(string link, string existing, IntPtr reserved);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern byte CreateSymbolicLinkW(string link, string target, uint flags);
        private static int failed, passed;
        private static void Check(bool condition, string description)
        { if (condition) { passed++; Console.WriteLine("PASS red team: " + description); } else { failed++; Console.WriteLine("FAIL red team: " + description); } }
        private static void Scenario(Action action, string name)
        { try { action(); } catch (Exception ex) { failed++; Console.WriteLine("FAIL red team: " + name + ": " + ex); } }
        private static bool Refused(Action action)
        { try { action(); return false; } catch (IOException) { return true; } catch (InvalidOperationException) { return true; } catch (ArgumentOutOfRangeException) { return true; } catch (OverflowException) { return true; } }
        public static int Run(string project)
        {
            failed = passed = 0;
            string fixture = Path.Combine(Path.GetTempPath(), "kisib-owned-redteam-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(fixture);
            try
            {
                Scenario(delegate
                {
                    string root = Path.Combine(fixture, "hardlink"), victim = Path.Combine(fixture, "owned-sentinel.txt");
                    Directory.CreateDirectory(Path.Combine(root, "logs")); File.WriteAllText(victim, "sentinel", Encoding.UTF8);
                    string log = Path.Combine(root, "logs", DateTime.UtcNow.ToString("yyyy-MM-dd") + ".jsonl");
                    if (!CreateHardLinkW(log, victim, IntPtr.Zero)) throw new IOException("Fixture hardlink failed: " + Marshal.GetLastWin32Error());
                    bool rejected = Refused(delegate { using (HistoryArchive history = new HistoryArchive(root)) history.Note(null, "probe", "owned fixture", "must not reach linked target"); });
                    Check(rejected && File.ReadAllText(victim, Encoding.UTF8) == "sentinel", "preplaced journal hardlink cannot modify an outside sentinel");
                    File.Delete(log);
                }, "hardlink confinement");
                Scenario(delegate
                {
                    string target = Path.Combine(fixture, "owned-target"), link = Path.Combine(fixture, "linked-history");
                    Directory.CreateDirectory(target);
                    if (CreateSymbolicLinkW(link, target, 1) == 0) throw new IOException("Fixture directory symlink failed: " + Marshal.GetLastWin32Error());
                    try
                    {
                        bool rejected = Refused(delegate { using (HistoryArchive history = new HistoryArchive(link)) history.Note(null, "probe", "owned fixture", "must not follow directory link"); });
                        Check(rejected && !Directory.GetFileSystemEntries(target).Any(), "archive directory link is refused before creating target files");
                    }
                    finally { Directory.Delete(link); }
                }, "directory link confinement");
                Scenario(delegate
                {
                    using (HistoryArchive history = new HistoryArchive(Path.Combine(fixture, "pages")))
                    {
                        string journal = history.JournalFiles().Single(); bool more = false;
                        Check(Refused(delegate { history.ReadPage(journal, null, -1, out more); }), "negative history page is rejected");
                        Check(Refused(delegate { history.ReadPage(journal, null, Int32.MaxValue, out more); }), "overflowing history page is rejected");
                    }
                }, "pagination");
                Scenario(delegate
                {
                    using (HistoryArchive history = new HistoryArchive(Path.Combine(fixture, "schema")))
                    {
                        string journal = history.JournalFiles().Single(); Directory.CreateDirectory(Path.Combine(history.DirectoryPath, "evidence"));
                        ActivityRecord forged = new ActivityRecord { Id = "forged", Utc = DateTime.UtcNow.ToString("o"), Payload = "<Event />", Operation = "forged normal event", References = new CertificateReference[] { null } };
                        byte[] bytes = HistoryArchive.Encode(forged); string name;
                        using (SHA256 hash = SHA256.Create()) name = CertificateRecord.Hex(hash.ComputeHash(bytes));
                        File.WriteAllBytes(Path.Combine(history.DirectoryPath, "evidence", name + ".json"), bytes);
                        HistoryEvent row = new HistoryEvent { Version = 1, EventId = "fixture", Utc = DateTime.UtcNow.ToString("o"), Action = "application_certificate_activity", EvidenceObject = name };
                        File.AppendAllText(journal, Encoding.UTF8.GetString(HistoryArchive.Encode(row)) + "\n", Encoding.UTF8);
                        ActivityPage page = ActivityArchive.Certificates(history, journal, 0);
                        bool safe = page.Records.Length == 1 && page.Records[0].Operation == "Retained evidence unavailable";
                        try { page.Records[0].Description(); page.Records[0].Match(new Snapshot()).ToArray(); } catch (NullReferenceException) { safe = false; }
                        Check(safe, "hash-valid evidence with null references becomes a visible schema error instead of a GUI crash");
                        bool more;
                        Check(history.ReadPage(journal, new string('A', 64), 0, out more).Length > 0, "malformed references cannot crash filtered history");
                    }
                }, "hostile evidence schema");
                Scenario(delegate
                {
                    using (HistoryArchive history = new HistoryArchive(Path.Combine(fixture, "resources")))
                    {
                        string journal = history.JournalFiles().Single();
                        File.AppendAllText(journal, new string('X', 9 * 1024 * 1024) + "\n", Encoding.UTF8);
                        history.Note(null, "after_oversized_line", "fixture", "subsequent record remains readable");
                        bool more; string page = history.ReadPage(journal, null, 0, out more);
                        Check(page.Length < 1024 * 1024 && page.Contains("size limit") && page.Contains("after_oversized_line"), "oversized journal row is bounded, visible, and does not hide the next record");
                    }
                }, "journal allocation budget");
            }
            finally { try { Directory.Delete(fixture, true); } catch (IOException) { } }
            Console.WriteLine("Red-team assertions: " + passed + " passed; " + failed + " failed. Fixtures were confined to a new temporary directory.");
            return failed == 0 ? 0 : 1;
        }
    }
}
