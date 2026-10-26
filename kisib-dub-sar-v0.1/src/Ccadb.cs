using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Kisib
{
    // Every CA certificate the browser root programs know about (CCADB), including intermediates and
    // cross-signs that never land on this PC. Merged into each scan so groups and rules can block them ahead of time.
    internal static class Ccadb
    {
        internal const string Label = "CCADB (CA certificate listed publicly; not necessarily on this PC)";
        private static readonly string[] Decades = { "2010", "2020" };
        private const string Url = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade=";

        private sealed class Entry { internal byte[] Der; internal string Owner; internal DateTime NotAfter; }
        private static List<Entry> cache;
        private static DateTime cacheStamp;
        private static readonly object gate = new object();

        private static string Folder { get { return Storage.Folder; } }
        private static string FileFor(string decade) { return Storage.File("ccadb-list-" + decade + "s.csv"); }

        internal static DateTime? Updated
        {
            get
            {
                string[] files = Decades.Select(FileFor).Where(File.Exists).ToArray();
                return files.Length == 0 ? (DateTime?)null : files.Max(f => File.GetLastWriteTime(f));
            }
        }

        internal static string Update()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            Directory.CreateDirectory(Folder);
            StringBuilder report = new StringBuilder();
            foreach (string decade in Decades)
            {
                string target = FileFor(decade), temp = target + ".new";
                try
                {
                    using (WebClient web = new WebClient())
                    {
                        web.Headers[HttpRequestHeader.UserAgent] = "kisib.dub-sar";
                        web.DownloadFile(Url + decade, temp);
                    }
                    if (new FileInfo(temp).Length < 1024) throw new InvalidDataException("download too small");
                    if (File.Exists(target)) File.Delete(target);
                    File.Move(temp, target);
                    report.AppendLine(decade + "s: ok, " + (new FileInfo(target).Length / 1024 / 1024) + " MB");
                }
                catch (Exception ex) { report.AppendLine(decade + "s: FAILED " + ex.GetType().Name + ": " + ex.Message); try { File.Delete(temp); } catch (IOException) { } }
            }
            lock (gate) cache = null;
            return report.ToString();
        }

        private static List<Entry> Load()
        {
            string[] files = Decades.Select(FileFor).Where(File.Exists).ToArray();
            if (files.Length == 0) return new List<Entry>();
            DateTime stamp = files.Max(f => File.GetLastWriteTimeUtc(f));
            lock (gate)
            {
                if (cache != null && stamp == cacheStamp) return cache;
                List<Entry> list = new List<Entry>();
                foreach (string file in files)
                {
                    List<string[]> rows = GroupCatalog.ReadCsv(file, 400L * 1024 * 1024);
                    if (rows.Count == 0) continue;
                    string[] header = rows[0];
                    int owner = Array.FindIndex(header, h => h.Trim().Equals("CA Owner", StringComparison.OrdinalIgnoreCase));
                    if (owner < 0) owner = Array.FindIndex(header, h => h.IndexOf("Owner", StringComparison.OrdinalIgnoreCase) >= 0);
                    int pem = Array.FindIndex(header, h => h.IndexOf("PEM", StringComparison.OrdinalIgnoreCase) >= 0);
                    foreach (string[] row in rows.Skip(1))
                    {
                        string text = pem >= 0 && pem < row.Length && row[pem].Contains("BEGIN CERTIFICATE") ? row[pem] : row.FirstOrDefault(c => c.Contains("BEGIN CERTIFICATE"));
                        if (text == null) continue;
                        try
                        {
                            int start = text.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) + 27;
                            int end = text.IndexOf("-----END CERTIFICATE-----", start, StringComparison.Ordinal);
                            byte[] der = Convert.FromBase64String(text.Substring(start, end - start).Replace("'", ""));
                            using (X509Certificate2 cert = new X509Certificate2(der))
                                list.Add(new Entry { Der = der, Owner = owner >= 0 && owner < row.Length ? row[owner].Trim() : "", NotAfter = cert.NotAfter.ToUniversalTime() });
                        }
                        catch (Exception) { }
                    }
                }
                cache = list; cacheStamp = stamp;
                return list;
            }
        }

        internal static int Merge(Snapshot snapshot)
        {
            List<Entry> entries = Load();
            if (entries.Count == 0) return -1;
            DateTime now = DateTime.UtcNow;
            int count = 0;
            foreach (Entry e in entries)
            {
                if (e.NotAfter < now) continue;
                CertificateRecord record = snapshot.Add(e.Der);
                record.FoundIn.Add(Label);
                if (e.Owner.Length > 0) snapshot.CaOwners[record.Identity] = e.Owner;
                count++;
            }
            return count;
        }
    }

    internal sealed partial class ExplorerForm
    {
        private void UpdateCcadb()
        {
            status.Text = "Downloading the public list of all CA certificates (CCADB)... this can take a few minutes";
            Thread worker = new Thread(delegate()
            {
                string report;
                try { report = Ccadb.Update(); } catch (Exception ex) { report = ex.GetType().Name + ": " + ex.Message; }
                Post(delegate
                {
                    ShowText("CCADB list", report + "\r\nIf it failed, allow kisib.dub-sar.exe to reach ccadb.my.salesforce-sites.com in your firewall.");
                    StartScan();
                });
            });
            worker.IsBackground = true; worker.Name = "CCADB download"; worker.Start();
        }
    }
}
