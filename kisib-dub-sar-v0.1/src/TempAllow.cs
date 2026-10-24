using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // Temporary allow, like a firewall's timed exception: lift blocks now, put every one back when time is up.
    // Pending re-blocks are written to disk first, so a crash or closed window still re-blocks on next start.
    internal sealed class TempAllowEntry
    {
        internal string Scope, Sha1, Sha256, Subject, Der, Until;
    }

    internal static class TempAllow
    {
        internal static string PendingPath { get { return Path.Combine(Path.GetDirectoryName(BlockEngine.LogPath), "temp-allow.csv"); } }

        internal static List<TempAllowEntry> Read()
        {
            List<TempAllowEntry> list = new List<TempAllowEntry>();
            if (!File.Exists(PendingPath)) return list;
            foreach (string[] f in GroupCatalog.ReadCsv(PendingPath).Skip(1))
                if (f.Length >= 6) list.Add(new TempAllowEntry { Scope = f[0], Sha1 = f[1], Sha256 = f[2], Subject = f[3], Der = f[4], Until = f[5] });
            return list;
        }

        internal static void Save(List<TempAllowEntry> list)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PendingPath));
            StringBuilder text = new StringBuilder("scope,sha1,sha256,subject,der_base64,until_utc\r\n");
            foreach (TempAllowEntry e in list)
                text.Append(String.Join(",", new string[] { e.Scope, e.Sha1, e.Sha256, Quote(e.Subject), e.Der, e.Until })).Append("\r\n");
            File.WriteAllText(PendingPath, text.ToString(), new UTF8Encoding(false));
        }
        private static string Quote(string v) { v = v ?? ""; return v.IndexOfAny(new char[] { ',', '"' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; }

        // Removes each certificate from Disallowed in every scope it can open; records what it removed.
        internal static List<string> Lift(IEnumerable<CertificateRecord> certs, TimeSpan duration)
        {
            List<string> report = new List<string>();
            List<TempAllowEntry> pending = Read();
            string until = DateTime.UtcNow.Add(duration).ToString("o", CultureInfo.InvariantCulture);
            List<X509Location> scopes = new List<X509Location> { X509Location.CurrentUser };
            if (BlockEngine.IsElevated()) scopes.Add(X509Location.LocalMachine);
            List<TempAllowEntry> removed = new List<TempAllowEntry>();
            foreach (X509Location scope in scopes)
            {
                using (X509Store store = new X509Store(StoreName.Disallowed, scope))
                {
                    store.Open(OpenFlags.ReadWrite);
                    foreach (CertificateRecord cert in certs)
                    {
                        X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Sha1, false);
                        if (found.Count == 0) continue;
                        TempAllowEntry entry = new TempAllowEntry { Scope = scope.ToString(), Sha1 = cert.Sha1, Sha256 = cert.Sha256, Subject = cert.SubjectShortName, Der = Convert.ToBase64String(cert.Der), Until = until };
                        // Write the re-block promise before removing anything.
                        pending.RemoveAll(p => p.Scope == entry.Scope && p.Sha1 == entry.Sha1);
                        pending.Add(entry); Save(pending);
                        foreach (X509Certificate2 c in found) store.Remove(c);
                        removed.Add(entry);
                        report.Add("lifted  " + scope + "  " + cert.SubjectShortName);
                    }
                }
            }
            Log(removed, "temp-allow", "lifted until " + until);
            if (!BlockEngine.IsElevated()) report.Add("Not running as administrator: whole-PC (LOCAL_MACHINE) blocks could not be lifted.");
            if (removed.Count == 0) report.Add("Nothing was lifted: these blocks are not in a Disallowed store kisib can change (Group Policy blocks need the policy changed).");
            return report;
        }

        // Puts back every lifted block whose time is up (or all of them with force).
        internal static List<TempAllowEntry> Restore(bool force)
        {
            List<TempAllowEntry> pending = Read();
            if (pending.Count == 0) return pending;
            DateTime now = DateTime.UtcNow;
            List<TempAllowEntry> due = pending.Where(p => force || DateTime.Parse(p.Until, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) <= now).ToList();
            List<TempAllowEntry> done = new List<TempAllowEntry>();
            foreach (IGrouping<string, TempAllowEntry> scope in due.GroupBy(p => p.Scope))
            {
                X509Location location = (X509Location)Enum.Parse(typeof(X509Location), scope.Key);
                if (location == X509Location.LocalMachine && !BlockEngine.IsElevated()) continue;
                using (X509Store store = new X509Store(StoreName.Disallowed, location))
                {
                    store.Open(OpenFlags.ReadWrite);
                    foreach (TempAllowEntry e in scope)
                    {
                        using (X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(e.Der)))
                            if (store.Certificates.Find(X509FindType.FindByThumbprint, e.Sha1, false).Count == 0) store.Add(cert);
                        done.Add(e);
                    }
                }
            }
            if (done.Count > 0)
            {
                Save(pending.Where(p => !done.Contains(p)).ToList());
                Log(done, "re-block", "temporary allow ended");
            }
            return done;
        }

        private static void Log(List<TempAllowEntry> entries, string action, string note)
        {
            if (entries.Count == 0) return;
            string path = BlockEngine.LogPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            StringBuilder text = new StringBuilder();
            if (!File.Exists(path)) text.Append("time_utc,batch,action,scope,sha256,sha1,subject,prior,result,group\r\n");
            string now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            foreach (TempAllowEntry e in entries)
                text.Append(String.Join(",", new string[] { now, "temp-" + now.Substring(0, 19), action, e.Scope, e.Sha256, e.Sha1, Quote(e.Subject), "", action == "temp-allow" ? "removed" : "added", Quote(note) })).Append("\r\n");
            File.AppendAllText(path, text.ToString(), new UTF8Encoding(false));
        }
    }

    internal sealed partial class ExplorerForm
    {
        private readonly System.Windows.Forms.Timer allowTimer = new System.Windows.Forms.Timer { Interval = 1000 };

        private void InitializeTempAllow(MenuItem certificate)
        {
            certificate.MenuItems.Add(new MenuItem("-"));
            foreach (int minutes in new int[] { 3, 10, 60 })
            {
                int m = minutes;
                certificate.MenuItems.Add(new MenuItem("&Allow for " + m + " minutes", delegate
                {
                    CertificateRecord cert = SelectedCertificate();
                    if (cert == null) { ShowText("Allow", "Select a blocked certificate in the list first."); return; }
                    AllowTemporarily(new List<CertificateRecord> { cert }, cert.SubjectShortName, TimeSpan.FromMinutes(m), true);
                }));
            }
            allowTimer.Tick += delegate { TickTempAllow(); };
            Shown += delegate
            {
                // Anything left lifted from a previous run is re-blocked now.
                try { List<TempAllowEntry> back = TempAllow.Restore(false); if (back.Count > 0) StartScan(); } catch (Exception) { }
                if (TempAllow.Read().Count > 0) allowTimer.Start();
            };
            FormClosing += delegate { try { TempAllow.Restore(true); } catch (Exception) { } };
        }

        // From a denial: every blocked certificate in the refused chain, plus blocked certificates from the same
        // organization (Actalis S.p.A. and Actalis S.p.A./03358520967 count as one) and the same public keys.
        private List<CertificateRecord> CertificatesBehind(Denial d)
        {
            if (snapshot == null) return new List<CertificateRecord>();
            HashSet<string> blocked = GroupCatalog.BlockedIdentities(snapshot);
            List<CertificateRecord> hits = snapshot.Certificates.Values.Where(c => blocked.Contains(c.Identity) && d.ChainSha1.Contains(c.Sha1)).ToList();
            HashSet<string> orgs = new HashSet<string>(hits.Select(c => Org(c)).Where(o => o.Length > 0), StringComparer.OrdinalIgnoreCase);
            HashSet<string> keys = new HashSet<string>(hits.Where(c => c.SpkiSha256 != null).Select(c => c.SpkiSha256), StringComparer.Ordinal);
            return snapshot.Certificates.Values.Where(c => blocked.Contains(c.Identity) &&
                (hits.Contains(c) || orgs.Contains(Org(c)) || (c.SpkiSha256 != null && keys.Contains(c.SpkiSha256)))).ToList();
        }
        private static string Org(CertificateRecord c)
        { string o = c.SubjectOrganization ?? ""; int slash = o.IndexOf('/'); return (slash >= 0 ? o.Substring(0, slash) : o).Trim(); }

        internal void AllowTemporarily(List<CertificateRecord> certs, string label, TimeSpan duration, bool confirm)
        {
            string span = (int)duration.TotalMinutes + " minutes";
            if (certs.Count == 0) { ShowText("Allow for " + span, "No blocked certificate found for this."); return; }
            string names = String.Join("\r\n", certs.Select(c => "  " + c.SubjectShortName).Distinct().ToArray());
            if (confirm && MessageBox.Show(this, "Lift these blocks for " + span + "?\r\n\r\n" + names + "\r\n\r\nThey are put back automatically, even if kisib is closed.",
                "Allow for " + span + " — " + label, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            List<string> report;
            try { report = TempAllow.Lift(certs, duration); }
            catch (Exception ex) { ShowText("Allow for " + span, "Failed: " + ex.GetType().Name + ": " + ex.Message); return; }
            allowTimer.Start();
            if (tray != null) tray.ShowBalloonTip(5000, "kisib: allowed for " + span, label + "\r\n" + names.Trim() + "\r\nBlocks come back automatically.", ToolTipIcon.Info);
            if (report.Any(r => r.StartsWith("Nothing", StringComparison.Ordinal) || r.StartsWith("Not running", StringComparison.Ordinal)))
                ShowText("Allow for " + span, String.Join("\r\n", report.ToArray()));
            StartScan();
        }

        private void TickTempAllow()
        {
            List<TempAllowEntry> pending;
            try { pending = TempAllow.Read(); } catch (Exception) { return; }
            if (pending.Count == 0) { allowTimer.Stop(); return; }
            DateTime first = pending.Select(p => DateTime.Parse(p.Until, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)).Min();
            TimeSpan left = first - DateTime.UtcNow;
            if (left > TimeSpan.Zero)
            {
                status.Text = "TEMP ALLOW: " + String.Join(", ", pending.Select(p => p.Subject).Distinct().Take(3).ToArray()) +
                    (pending.Count > 3 ? " +" + (pending.Count - 3) : "") + " — re-blocks in " + ((int)left.TotalMinutes) + ":" + left.Seconds.ToString("00");
                return;
            }
            try
            {
                List<TempAllowEntry> back = TempAllow.Restore(false);
                if (back.Count > 0)
                {
                    if (tray != null) tray.ShowBalloonTip(5000, "kisib: blocked again", String.Join(", ", back.Select(b => b.Subject).Distinct().ToArray()), ToolTipIcon.Info);
                    StartScan();
                }
            }
            catch (Exception ex) { status.Text = "Re-block failed: " + ex.Message + " (Block > Block history)"; }
        }
    }
}
