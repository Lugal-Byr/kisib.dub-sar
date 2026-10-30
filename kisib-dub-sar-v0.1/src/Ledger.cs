using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // "What kisib did": every certificate kisib has blocked, unblocked, imported or trusted (from BLOCK HISTORY), where it
    // really sits in Windows now, and what Windows says about it right now (Windows builds the chain, no guessing).
    // Each row has the ✅ Trusted / 🚫 Untrusted switch, Where Windows keeps it and Fix it on Windows' side.
    internal sealed partial class ExplorerForm
    {
        private sealed class LedgerRow
        {
            internal DateTime Time;
            internal string Did, Scope, Sha1, Sha256, Name, Why, Where, Now;
            internal CertificateRecord Cert;
            internal bool Blocked, Trusted, Checked;
        }

        private static string LedgerKind(BlockLogRow r)
        {
            string result = r.Result ?? "";
            switch (r.Action)
            {
                case "block": case "re-block": case "re-apply":
                    return result == "added" || result.StartsWith("already", StringComparison.Ordinal) ? "🚫 blocked" : null;
                case "put back": return "🚫 put back (blocked)";
                case "unblock": return result == "removed" ? "↩ unblocked" : null;
                case "import-root": return "✅ imported root";
                case "trust-from-microsoft": return "✅ root from Microsoft";
                case "trust-from-map": return "✅ trusted on the map";
                case "auto-root": return "✅ root a signed file needed";
                case "repair-trust": return "✅ root from Repair";
                case "route": case "route re-apply": return "✅ CA added";
                case "route removed": return "↩ CA taken out";
            }
            return null;
        }

        private static string ShortWhere(string line)
        {
            return line.Replace(" → Certificates", "").Replace("certlm.msc (whole PC) → ", "whole PC: ").Replace("certmgr.msc (you) → ", "you: ")
                .Replace("Trusted Root Certification Authorities", "Trusted Root").Replace("Intermediate Certification Authorities", "Intermediate CAs")
                .Replace("Third-Party Root Certification Authorities", "Third-Party Root");
        }

        private List<LedgerRow> LedgerRows()
        {
            Dictionary<string, CertificateRecord> by256 = new Dictionary<string, CertificateRecord>(StringComparer.OrdinalIgnoreCase);
            if (snapshot != null)
                foreach (CertificateRecord c in snapshot.Certificates.Values)
                    if (c.Sha256 != null && !by256.ContainsKey(c.Sha256)) by256[c.Sha256] = c;
            // What kisib did last to each certificate (any scope).
            Dictionary<string, LedgerRow> kisib = new Dictionary<string, LedgerRow>(StringComparer.OrdinalIgnoreCase);
            foreach (BlockLogRow r in BlockEngine.ReadLog())
            {
                string did = LedgerKind(r);
                if (did == null || (r.Sha1 == null && r.Sha256 == null)) continue;
                DateTime t;
                if (!DateTime.TryParse(r.Time, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t)) t = DateTime.MinValue;
                CertificateRecord c = null;
                if (r.Sha256 != null) by256.TryGetValue(r.Sha256, out c);
                if (c == null && r.Sha1 != null && snapshot != null) c = snapshot.BySha1(r.Sha1);
                string key = c != null ? c.Sha256 : (r.Sha256 ?? r.Sha1);
                kisib[key] = new LedgerRow { Time = t == DateTime.MinValue ? t : t.ToLocalTime(), Did = "kisib: " + did + (r.Scope == "LocalMachine" ? " (whole PC)" : r.Scope == "CurrentUser" ? " (you)" : ""),
                    Sha1 = r.Sha1 ?? (c == null ? null : c.Sha1), Sha256 = r.Sha256 ?? (c == null ? null : c.Sha256), Name = String.IsNullOrEmpty(r.Subject) && c != null ? c.SubjectShortName : r.Subject, Why = r.Group, Cert = c };
            }
            HashSet<string> microsoftUntrusted = LiftGuard.WindowsUntrusted();
            List<LedgerRow> rows = new List<LedgerRow>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            // Every certificate that really sits in one of Windows' stores, whoever put it there.
            foreach (CertificateRecord c in by256.Values)
            {
                List<string> places = c.FoundIn.Where(p => p.Split('\\').Length >= 3).Select(WhereLine).Where(l => l != null && !l.StartsWith("Microsoft's", StringComparison.Ordinal) && !l.StartsWith("CCADB", StringComparison.Ordinal))
                    .Select(ShortWhere).Distinct().ToList();
                if (places.Count == 0) continue;
                LedgerRow k;
                kisib.TryGetValue(c.Sha256, out k);
                rows.Add(new LedgerRow { Time = k == null ? DateTime.MinValue : k.Time, Did = k == null ? "Windows / before kisib" : k.Did, Sha1 = c.Sha1, Sha256 = c.Sha256,
                    Name = c.SubjectShortName, Why = k == null ? (c.Subject == c.Issuer ? "root" : "issued by " + c.IssuerShortName) : k.Why, Cert = c, Where = String.Join("; ", places.ToArray()) });
                seen.Add(c.Sha256);
            }
            // What kisib took out or never landed: in its history, not in any store now.
            foreach (LedgerRow k in kisib.Values.Where(x => x.Sha256 == null || !seen.Contains(x.Sha256))) { k.Where = "not on this PC"; rows.Add(k); }
            foreach (LedgerRow row in rows)
            {
                CertificateRecord c = row.Cert;
                row.Blocked = c != null && snapshot.IsBlocked(c);
                if (row.Blocked) { row.Now = "🚫 blocked"; row.Checked = true; }
                else if (row.Sha1 != null && microsoftUntrusted.Contains(row.Sha1)) { row.Now = "🚫 Microsoft distrusts it"; row.Checked = true; }
                else if (c == null || c.Der == null || row.Where == "not on this PC") { row.Now = "— not on this PC"; row.Checked = true; }
                else row.Now = "checking...";
            }
            return rows.OrderByDescending(r => r.Time).ThenBy(r => r.Where.IndexOf("Untrusted", StringComparison.Ordinal) >= 0 ? 1 : 0).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // How many certificates sit in each of Windows' stores (the physical ones).
        private static string StoreCounts(List<LedgerRow> rows)
        {
            Dictionary<string, int> n = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (LedgerRow r in rows)
                foreach (string w in (r.Where ?? "").Split(new string[] { "; " }, StringSplitOptions.RemoveEmptyEntries))
                    if (w != "not on this PC") { int v; n.TryGetValue(w, out v); n[w] = v + 1; }
            return String.Join("   ", n.OrderByDescending(x => x.Value).Take(8).Select(x => x.Key + " " + x.Value).ToArray());
        }

        // Windows' own verdict right now: it builds the chain (no revocation download, short network timeout).
        private static void CheckNow(LedgerRow row)
        {
            try
            {
                using (X509Certificate2 x = new X509Certificate2(row.Cert.Der))
                using (X509Chain chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(3);
                    if (chain.Build(x)) { row.Now = "✅ trusted"; row.Trusted = true; return; }
                    X509ChainStatusFlags all = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (a, s) => a | s.Status);
                    row.Now = (all & (X509ChainStatusFlags.Revoked | X509ChainStatusFlags.ExplicitDistrust)) != 0 ? "🚫 blocked (Windows says revoked)"
                        : (all & X509ChainStatusFlags.UntrustedRoot) != 0 ? "✗ its root isn't trusted here"
                        : (all & X509ChainStatusFlags.PartialChain) != 0 ? "✗ root missing (Windows can't reach one)"
                        : (all & X509ChainStatusFlags.NotTimeValid) != 0 ? "✗ expired"
                        : "✗ " + String.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()).Distinct().ToArray());
                }
            }
            catch (Exception ex) { row.Now = "? " + ex.Message; }
            finally { row.Checked = true; }
        }

        internal void ShowLedger()
        {
            if (snapshot == null) { Say("Run a scan first."); return; }
            Form f = new Form { Text = "Windows certificates, live (and what kisib did)", Size = new Size(1280, 720), Font = new Font("Comic Sans MS", 10F), StartPosition = FormStartPosition.CenterScreen };
            Label summary = new Label { Dock = DockStyle.Top, Height = 50, Padding = new Padding(8, 6, 8, 0), Font = new Font("Comic Sans MS", 10.5F, FontStyle.Bold) };
            FlowLayoutPanel top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(6, 4, 6, 0) };
            ComboBox show = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300 };
            show.Items.AddRange(new object[] { "Everything in Windows' stores", "Not trusted right now", "Untrusted Certificates (blocked)", "Trusted Root", "Intermediate CAs",
                "Done by kisib", "Not done by kisib (Windows / before kisib)", "Taken out (not on this PC)" });
            show.SelectedIndex = 0;
            TextBox find = new TextBox { Width = 240 };
            Button again = new Button { Text = "Check again", AutoSize = true };
            Button trim = new Button { Text = "Trim Untrusted Certificates", AutoSize = true };
            top.Controls.AddRange(new Control[] { new Label { Text = "Show:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, show, new Label { Text = "Find:", AutoSize = true, Padding = new Padding(10, 6, 0, 0) }, find, again, trim });
            ListView grid = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = true, VirtualMode = true };
            grid.Columns.Add("Certificate", 280); grid.Columns.Add("Windows says now", 230); grid.Columns.Add("Where it is now", 300);
            grid.Columns.Add("Who put it there", 250); grid.Columns.Add("When", 120); grid.Columns.Add("Why / issuer", 220);
            EmojiText.AttachTo(grid, 1, 3);
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(6) };
            Func<string, Button> add = delegate(string label) { Button b = new Button { Text = label, AutoSize = true, Height = 32, Margin = new Padding(3) }; buttons.Controls.Add(b); return b; };

            List<LedgerRow> rows = new List<LedgerRow>(), shown = new List<LedgerRow>();
            int generation = 0;
            Action fill = delegate
            {
                string q = find.Text.Trim();
                int k = show.SelectedIndex;
                shown = rows.Where(r =>
                {
                    string w = r.Where ?? "";
                    if (k == 1 && (r.Trusted || !r.Checked || w == "not on this PC")) return false;
                    if (k == 2 && w.IndexOf("Untrusted Certificates", StringComparison.Ordinal) < 0) return false;
                    if (k == 3 && w.IndexOf("Trusted Root", StringComparison.Ordinal) < 0 && w.IndexOf("Third-Party Root", StringComparison.Ordinal) < 0) return false;
                    if (k == 4 && w.IndexOf("Intermediate CAs", StringComparison.Ordinal) < 0) return false;
                    if (k == 5 && !r.Did.StartsWith("kisib", StringComparison.Ordinal)) return false;
                    if (k == 6 && r.Did.StartsWith("kisib", StringComparison.Ordinal)) return false;
                    if (k == 7 && w != "not on this PC") return false;
                    return q.Length == 0 || (r.Name ?? "").IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 || (r.Sha1 ?? "").IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
                }).ToList();
                grid.VirtualListSize = shown.Count;
                grid.Invalidate();
            };
            grid.RetrieveVirtualItem += delegate(object sender, RetrieveVirtualItemEventArgs e)
            {
                LedgerRow r = e.ItemIndex < shown.Count ? shown[e.ItemIndex] : null;
                if (r == null) { e.Item = new ListViewItem(new string[] { "", "", "", "", "", "" }); return; }
                ListViewItem it = new ListViewItem(new string[] { r.Name ?? r.Sha1 ?? "", r.Now ?? "", r.Where ?? "", r.Did ?? "", r.Time == DateTime.MinValue ? "" : r.Time.ToString("yyyy-MM-dd HH:mm"), r.Why ?? "" });
                if ((r.Now ?? "").StartsWith("✗", StringComparison.Ordinal) || (r.Now ?? "").StartsWith("🚫", StringComparison.Ordinal)) it.ForeColor = Color.Firebrick;
                else if (r.Trusted) it.ForeColor = Color.SeaGreen;
                e.Item = it;
            };
            Action load = null;
            load = delegate
            {
                int mine = ++generation;
                try { rows = LedgerRows(); } catch (Exception ex) { rows = new List<LedgerRow>(); Say("Couldn't read Windows' stores or kisib's history: " + ex.Message); }
                string counts = StoreCounts(rows);
                int byKisib = rows.Count(r => r.Did.StartsWith("kisib", StringComparison.Ordinal));
                summary.Text = counts + "\r\n" + byKisib + " of these are kisib's doing.   Checking what Windows says now...";
                fill();
                List<LedgerRow> todo = rows.Where(r => !r.Checked).Take(1500).ToList();
                Thread worker = new Thread(delegate()
                {
                    for (int i = 0; i < todo.Count; i++)
                    {
                        if (f.IsDisposed || mine != generation) return;
                        CheckNow(todo[i]);
                        if (i % 40 == 39) Post(delegate { if (!f.IsDisposed && mine == generation) fill(); });
                    }
                    Post(delegate
                    {
                        if (f.IsDisposed || mine != generation) return;
                        int bad = rows.Count(r => r.Checked && !r.Trusted && !r.Blocked && r.Where != "not on this PC" && (r.Now ?? "").StartsWith("✗", StringComparison.Ordinal));
                        summary.Text = counts + "\r\n" + byKisib + " of these are kisib's doing.   " + (bad > 0 ? bad + " in Trusted Root or Intermediate CAs aren't trusted by Windows right now (Show: Not trusted right now)." : "Everything not blocked is trusted by Windows right now.");
                        fill();
                    });
                }) { IsBackground = true, Name = "kisib ledger check" };
                worker.Start();
            };
            // After a switch: wait for the rescan, then load again.
            Action reloadAfterScan = delegate
            {
                Snapshot before = snapshot;
                System.Windows.Forms.Timer t = new System.Windows.Forms.Timer { Interval = 1000 };
                int ticks = 0;
                t.Tick += delegate { ticks++; if (f.IsDisposed) { t.Stop(); t.Dispose(); return; } if ((snapshot != before && !scanning) || ticks > 60) { t.Stop(); t.Dispose(); load(); } };
                t.Start();
            };
            Func<List<LedgerRow>> picked = delegate { return grid.SelectedIndices.Cast<int>().Where(i => i < shown.Count).Select(i => shown[i]).ToList(); };
            Func<List<CertificateRecord>> pickedCerts = delegate { return picked().Where(r => r.Cert != null).Select(r => r.Cert).GroupBy(c => c.Sha1).Select(g => g.First()).ToList(); };
            add("✅ Trusted").Click += delegate
            {
                List<CertificateRecord> certs = pickedCerts();
                if (certs.Count == 0) { Say("Pick rows kisib knows the certificate for."); return; }
                TrustCerts(certs.Count == 1 ? certs[0].SubjectShortName : certs.Count + " certificates", certs);
                reloadAfterScan();
            };
            add("🚫 Untrusted").Click += delegate
            {
                List<CertificateRecord> certs = pickedCerts();
                if (certs.Count == 0) { Say("Pick rows kisib knows the certificate for."); return; }
                ShowBlockDialog(certs, delegate { return "blocked from Windows certificates, live"; }, certs.Count == 1 ? "certificate " + certs[0].SubjectShortName : certs.Count + " certificates", null);
                reloadAfterScan();
            };
            add("Where Windows keeps it").Click += delegate { List<CertificateRecord> certs = pickedCerts(); if (certs.Count > 0) ShowWhereInWindows(certs[0]); };
            add(WindowsSideLabel.Replace("...", "")).Click += delegate
            {
                List<LedgerRow> p = picked();
                if (p.Count > 0) ShowWindowsSideFix(p[0].Name ?? p[0].Sha1, p.Where(r => r.Sha1 != null).Select(r => r.Sha1), null);
            };
            add("Copy").Click += delegate { CopyText(String.Join("\r\n", picked().Select(r => r.Name + "\t" + r.Now + "\t" + r.Where + "\t" + r.Did + "\t" + r.Sha1).ToArray())); };
            grid.DoubleClick += delegate { List<CertificateRecord> certs = pickedCerts(); if (certs.Count > 0) ShowWhereInWindows(certs[0]); };
            show.SelectedIndexChanged += delegate { fill(); };
            find.TextChanged += delegate { fill(); };
            again.Click += delegate { StartScan(); reloadAfterScan(); };
            trim.Click += delegate
            {
                RuleOutcome o = new RuleOutcome();
                int removed;
                try { removed = LightBlock.Lighten(snapshot, o); } catch (Exception ex) { Say("Couldn't trim: " + ex.Message); return; }
                Say(removed > 0 ? "Trimmed " + removed + " Untrusted Certificates entries that were dead weight (each one sat under a root that stays blocked). Repair > Put back can restore the ones kisib didn't add."
                    : "Nothing to trim: every Untrusted Certificates entry left is doing something (a blocked root, a cross-sign, or a CA with another way up)." + (o.Log.Count > 0 ? " " + o.Log[0] : ""));
                StartScan(); reloadAfterScan();
            };
            f.Controls.Add(grid); f.Controls.Add(top); f.Controls.Add(summary); f.Controls.Add(buttons);
            f.Shown += delegate { load(); };
            ShowTool(f, "ledger");
        }
    }
}
