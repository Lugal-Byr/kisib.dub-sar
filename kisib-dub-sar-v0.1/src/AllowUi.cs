using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Kisib
{
    // What an Allow button or menu acts on. Certs is asked for when clicked, so it always reflects the latest scan.
    internal sealed class AllowTarget
    {
        internal Func<List<CertificateRecord>> Certs;
        internal string Label, Program, Site, NothingWhy;
    }

    // One Allow, the same everywhere: 3 / 10 / 60 minutes, until kisib closes, always, or while a program runs.
    // No confirm box; one plain line says what happened, and kisib watches the next check to say whether it got through.
    internal sealed partial class ExplorerForm
    {
        private readonly System.Windows.Forms.Timer allowTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        private readonly System.Windows.Forms.Timer programTimer = new System.Windows.Forms.Timer { Interval = 3000 };
        private readonly HashSet<string> programsSeenRunning = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private sealed class AllowWatch { internal HashSet<string> Sha1; internal string Label; internal DateTime Until; }
        private readonly List<AllowWatch> allowWatches = new List<AllowWatch>();

        private void InitializeTempAllow(MenuItem certificate)
        {
            certificate.MenuItems.Add(new MenuItem("-"));
            certificate.MenuItems.Add(AllowSubmenu("&Allow", delegate
            {
                CertificateRecord c = SelectedCertificate();
                return c == null ? new AllowTarget { Certs = delegate { return new List<CertificateRecord>(); }, Label = "", NothingWhy = "Select a certificate in the list first." } : TargetFor(c);
            }));
            allowTimer.Tick += delegate { TickTempAllow(); };
            programTimer.Tick += delegate { TickProgramAllows(); };
            Shown += delegate
            {
                // Anything left lifted from a previous run (time up, or "until kisib closes") is re-blocked now.
                try { if (TempAllow.Restore(false, true).Count > 0) StartScan(); } catch (Exception) { }
                if (TempAllow.Read().Count > 0) allowTimer.Start();
                if (ProgramAllows.Read().Count > 0) programTimer.Start();
            };
            FormClosing += delegate(object s, FormClosingEventArgs e) { if (exiting || e.CloseReason != CloseReason.UserClosing) try { TempAllow.Restore(true, false); } catch (Exception) { } };
        }

        // ---- The menu and the button ------------------------------------------------------------

        internal MenuItem AllowSubmenu(string text, Func<AllowTarget> target)
        {
            MenuItem root = new MenuItem(text);
            root.MenuItems.Add("(building)");   // a submenu needs a child before Popup fires
            root.Popup += delegate
            {
                root.MenuItems.Clear();
                foreach (MenuItem item in AllowItems(target())) root.MenuItems.Add(item);
            };
            return root;
        }

        internal Button AllowButton(string text, Func<AllowTarget> target) { return AllowButton(text, target, null); }
        internal Button AllowButton(string text, Func<AllowTarget> target, Action after)
        {
            Button b = new Button { Text = text + " ▾", AutoSize = true };
            b.Click += delegate
            {
                MenuItem[] items = AllowItems(target());
                if (after != null) foreach (MenuItem item in items) if (item.Enabled && item.Text != "-") item.Click += delegate { after(); };
                ContextMenu menu = new ContextMenu(items);
                menu.Show(b, new Point(0, b.Height));
            };
            return b;
        }

        private MenuItem[] AllowItems(AllowTarget t)
        {
            List<MenuItem> items = new List<MenuItem>();
            List<CertificateRecord> certs = t.Certs();
            if (certs.Count == 0)
            {
                items.Add(new MenuItem(t.NothingWhy ?? "Nothing to allow: none of your blocks is behind this") { Enabled = false });
                return items.ToArray();
            }
            string what = certs.Count == 1 ? certs[0].SubjectShortName : certs.Count + " blocked certificates";
            items.Add(new MenuItem("Lifts: " + what) { Enabled = false });
            items.Add(new MenuItem("-"));
            foreach (int minutes in new int[] { 3, 10, 60 })
            {
                int m = minutes;
                items.Add(new MenuItem("For " + m + " minutes", delegate { AllowFor(certs, t.Label, TimeSpan.FromMinutes(m), "timed"); }));
            }
            items.Add(new MenuItem("Until kisib closes or the PC restarts", delegate { AllowFor(certs, t.Label, TimeSpan.FromDays(3650), "restart"); }));
            items.Add(new MenuItem("Always (never block it again)", delegate { AllowAlways(certs, t.Label); }));
            if (!String.IsNullOrEmpty(t.Program) && !t.Program.StartsWith("[", StringComparison.Ordinal))
            {
                string exe = Path.GetFileName(t.Program);
                items.Add(new MenuItem("While " + exe + " runs (opens each time it starts)", delegate { AllowWhileProgram(exe, certs, t.Label); }));
            }
            return items.ToArray();
        }

        // The blocked certificates behind one certificate: itself and its key twins, when blocked.
        internal AllowTarget TargetFor(CertificateRecord c)
        {
            return new AllowTarget
            {
                Label = c.SubjectShortName,
                Certs = delegate { return snapshot == null ? new List<CertificateRecord>() : WithTwins(new CertificateRecord[] { c }).Where(snapshot.IsBlocked).ToList(); },
                NothingWhy = "Nothing to allow: " + c.SubjectShortName + " is not blocked"
            };
        }

        internal AllowTarget TargetFor(Denial d)
        {
            return new AllowTarget
            {
                Label = d.Subject, Program = d.Program, Site = d.Subject,
                Certs = delegate { return CertificatesBehind(d); },
                NothingWhy = "Nothing to allow: not one of your blocks (" + ShortReason(d.Reason) + ")"
            };
        }

        // ---- Doing it ------------------------------------------------------------------------------

        // Kept for older callers: confirm is ignored now, every allow just happens and says what it did.
        internal void AllowTemporarily(List<CertificateRecord> certs, string label, TimeSpan duration, bool confirm)
        { AllowFor(certs, label, duration, "timed"); }

        internal void AllowFor(List<CertificateRecord> certs, string label, TimeSpan duration, string mode)
        {
            List<CertificateRecord> all = WithTwins(certs);
            if (all.Count == 0) { Say("Nothing to allow for " + label + "."); return; }
            LiftResult r;
            try { r = TempAllow.Lift(all, duration, mode); }
            catch (Exception ex) { Say("Allow failed for " + label + ": " + ex.Message); return; }
            allowTimer.Start();
            string span = mode == "restart" ? "until kisib closes or the PC restarts" : mode.StartsWith("program:", StringComparison.Ordinal) ? "while " + mode.Substring(8) + " runs" :
                "for " + (int)duration.TotalMinutes + " minutes";
            Say("Allowed " + span + ": " + label + ". " + LiftSummary(all, r.Removed, r.Errors, r.Problems));
            WatchAllow(all, label);
            StartScan();
        }

        private void AllowWhileProgram(string exe, List<CertificateRecord> certs, string label)
        {
            List<CertificateRecord> all = WithTwins(certs);
            try { ProgramAllows.Add(exe, label, all); } catch (IOException ex) { Say("Could not save the program allow: " + ex.Message); return; }
            programTimer.Start();
            AllowFor(all, label, TimeSpan.FromMinutes(10), "program:" + exe);
            Say("From now on " + label + " opens each time " + exe + " starts, and closes 2 minutes after it stops. It's open now. Undo: Tools > Program allows.");
        }

        // One plain line: the status bar and a tray note.
        private string lastSay;
        private DateTime lastSayAt;
        internal void Say(string text)
        {
            lastSay = text; lastSayAt = DateTime.Now; saidCount++;
            status.Text = text;
            sessionLog.Add(DateTime.UtcNow.ToString("o") + "\t" + text);
            if (tray != null) try { tray.ShowBalloonTip(6000, "kisib", text.Length > 250 ? text.Substring(0, 250) + "..." : text, ToolTipIcon.Info); } catch (Exception) { }
        }

        // Proof it worked: the next check that touches these certificates says whether it got through.
        private void WatchAllow(List<CertificateRecord> certs, string label)
        {
            allowWatches.RemoveAll(w => w.Until < DateTime.Now);
            allowWatches.Add(new AllowWatch { Sha1 = new HashSet<string>(certs.Select(c => c.Sha1), StringComparer.OrdinalIgnoreCase), Label = label, Until = DateTime.Now.AddMinutes(15) });
        }

        private void CheckAllowWatch(Denial d)
        {
            if (allowWatches.Count == 0 || d.ChainSha1.Count == 0) return;
            foreach (AllowWatch w in allowWatches.ToArray())
            {
                if (w.Until < DateTime.Now) { allowWatches.Remove(w); continue; }
                if (!d.ChainSha1.Any(w.Sha1.Contains)) continue;
                if (d.Ok) { Say(w.Label + ": went through at " + d.Time.ToString("HH:mm:ss") + " (" + Path.GetFileName(d.Program) + " → " + d.Subject + ")."); allowWatches.Remove(w); }
                else if (!d.Noise) { Say(w.Label + ": still refused at " + d.Time.ToString("HH:mm:ss") + " — " + ShortReason(d.Reason) + ". Open the refusal card for why."); allowWatches.Remove(w); }
            }
        }

        // ---- Timers --------------------------------------------------------------------------------

        private void TickTempAllow()
        {
            List<TempAllowEntry> pending;
            try { TempAllow.KeepProgramsOpen(); pending = TempAllow.Read(); } catch (Exception) { return; }
            if (pending.Count == 0) { allowTimer.Stop(); return; }
            List<TempAllowEntry> timed = pending.Where(p => p.Mode != "restart").ToList();
            if (timed.Count > 0)
            {
                DateTime first = timed.Min(p => p.UntilUtc);
                TimeSpan left = first - DateTime.UtcNow;
                if (left > TimeSpan.Zero)
                {
                    if (!status.Text.StartsWith("Allowed", StringComparison.Ordinal) || left.TotalSeconds % 10 < 1)
                        status.Text = "OPEN NOW: " + String.Join(", ", pending.Select(p => p.Subject).Distinct().Take(3).ToArray()) +
                            (pending.Select(p => p.Subject).Distinct().Count() > 3 ? " +" + (pending.Select(p => p.Subject).Distinct().Count() - 3) : "") +
                            " — next re-block in " + ((int)left.TotalMinutes) + ":" + left.Seconds.ToString("00") + "  (tray > Open right now)";
                    return;
                }
            }
            try
            {
                List<TempAllowEntry> back = TempAllow.Restore(false, false);
                if (back.Count > 0) { Say("Blocked again: " + String.Join(", ", back.Select(b => b.Subject).Distinct().ToArray())); StartScan(); }
            }
            catch (Exception ex) { status.Text = "Re-block failed: " + ex.Message + " (Block > Block history)"; }
        }

        // Program allows: when the program starts, its blocks open for as long as it runs.
        private void TickProgramAllows()
        {
            List<ProgramAllow> rules = ProgramAllows.Read();
            if (rules.Count == 0) { programTimer.Stop(); return; }
            foreach (ProgramAllow rule in rules)
            {
                bool running = TempAllow.ProgramRunning(rule.Program);
                bool wasRunning = programsSeenRunning.Contains(rule.Program);
                if (running && !wasRunning) { programsSeenRunning.Add(rule.Program); OpenProgramAllow(rule, rule.Program + " started"); }
                else if (!running && wasRunning) programsSeenRunning.Remove(rule.Program);
            }
        }

        // Also opens when a refusal comes from the program (it may have started and failed between two checks).
        private void ProgramAllowOnRefusal(Denial d)
        {
            if (d.Ok || d.Noise || String.IsNullOrEmpty(d.Program)) return;
            string exe = Path.GetFileName(d.Program);
            ProgramAllow rule = ProgramAllows.Read().FirstOrDefault(r => String.Equals(r.Program, exe, StringComparison.OrdinalIgnoreCase));
            if (rule != null && d.ChainSha1.Any(s => rule.Sha1.Contains(s, StringComparer.OrdinalIgnoreCase)))
                OpenProgramAllow(rule, exe + " was refused");
        }

        private void OpenProgramAllow(ProgramAllow rule, string why)
        {
            if (snapshot == null) return;
            if (TempAllow.Read().Any(p => String.Equals(p.Program, rule.Program, StringComparison.OrdinalIgnoreCase))) return;   // already open
            List<CertificateRecord> certs = rule.Sha1.Select(snapshot.BySha1).Where(c => c != null && snapshot.IsBlocked(c)).ToList();
            if (certs.Count == 0) return;
            LiftResult r;
            try { r = TempAllow.Lift(certs, TimeSpan.FromMinutes(10), "program:" + rule.Program); } catch (Exception) { return; }
            allowTimer.Start();
            Say(why + ": opened " + rule.Label + " while it runs. " + LiftSummary(certs, r.Removed, r.Errors, r.Problems));
            WatchAllow(certs, rule.Label);
            StartScan();
        }

        // ---- Tray: what is open right now ---------------------------------------------------------

        private void FillOpenNow(MenuItem openNow)
        {
            openNow.MenuItems.Clear();
            List<TempAllowEntry> pending;
            try { pending = TempAllow.Read(); } catch (Exception) { pending = new List<TempAllowEntry>(); }
            if (pending.Count == 0) { openNow.MenuItems.Add(new MenuItem("Nothing is open") { Enabled = false }); }
            foreach (IGrouping<string, TempAllowEntry> g in pending.GroupBy(p => p.Subject))
            {
                TempAllowEntry first = g.First();
                TimeSpan left = g.Max(p => p.UntilUtc) - DateTime.UtcNow;
                string when = first.Mode == "restart" ? "until kisib closes" : first.Program != null ? "while " + first.Program + " runs" :
                    left > TimeSpan.Zero ? (int)left.TotalMinutes + ":" + left.Seconds.ToString("00") + " left" : "closing";
                string subject = g.Key;
                openNow.MenuItems.Add(new MenuItem(subject + "  —  " + when + "  ·  Re-block now", delegate
                {
                    List<TempAllowEntry> back = TempAllow.RestoreNow(p => p.Subject == subject);
                    Say("Blocked again: " + subject + (back.Count == 0 ? " (nothing could be put back; whole-PC blocks need admin)" : ""));
                    StartScan();
                }));
            }
            if (pending.Count > 1)
            {
                openNow.MenuItems.Add("-");
                openNow.MenuItems.Add(new MenuItem("Re-block everything now", delegate { TempAllow.RestoreNow(p => true); Say("Everything that was open is blocked again."); StartScan(); }));
            }
            List<ProgramAllow> rules = ProgramAllows.Read();
            if (rules.Count > 0)
            {
                openNow.MenuItems.Add("-");
                foreach (ProgramAllow rule in rules)
                {
                    ProgramAllow r = rule;
                    openNow.MenuItems.Add(new MenuItem("Stop opening " + r.Label + " for " + r.Program, delegate
                    { ProgramAllows.Remove(r.Program); TempAllow.RestoreNow(p => String.Equals(p.Program, r.Program, StringComparison.OrdinalIgnoreCase)); Say(r.Program + " no longer opens " + r.Label + "."); StartScan(); }));
                }
            }
        }

        // From a denial: every blocked certificate in the refused chain, plus blocked certificates from the same
        // organization (Actalis S.p.A. and Actalis S.p.A./03358520967 count as one) and the same public keys.
        private List<CertificateRecord> CertificatesBehind(Denial d)
        {
            if (snapshot == null) return new List<CertificateRecord>();
            List<CertificateRecord> hits = d.ChainSha1.Select(snapshot.BySha1).Where(c => c != null && snapshot.IsBlocked(c)).Distinct().ToList();
            if (hits.Count == 0) return hits;
            HashSet<string> orgs = new HashSet<string>(hits.Select(c => Org(c)).Where(o => o.Length > 0), StringComparer.OrdinalIgnoreCase);
            HashSet<string> keys = new HashSet<string>(hits.Where(c => c.SpkiSha256 != null).Select(c => c.SpkiSha256), StringComparer.Ordinal);
            return snapshot.Blocked.Select(id => snapshot.Certificates[id]).Where(c => hits.Contains(c) || orgs.Contains(Org(c)) || (c.SpkiSha256 != null && keys.Contains(c.SpkiSha256))).ToList();
        }
        private static string Org(CertificateRecord c)
        { string o = c.SubjectOrganization ?? ""; int slash = o.IndexOf('/'); return (slash >= 0 ? o.Substring(0, slash) : o).Trim(); }
    }
}
