using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // "Fix it on Windows' side": for a refused chain, what Windows holds against each certificate (Untrusted
    // Certificates in certlm.msc / certmgr.msc, Group Policy, Microsoft's own untrusted list, a missing root),
    // the steps in Windows' certificate manager, the certutil lines that do the same, and Windows' own checker
    // (certutil -url, the URL Retrieval Tool) opened on the certificate. kisib only shows the way; the clicks are yours.
    internal sealed partial class ExplorerForm
    {
        private sealed class ChainLink
        {
            internal string Sha1, Name;
            internal CertificateRecord Cert;
            internal string CerPath;                                  // the .cer kisib wrote for certutil
            internal List<string> Untrusted = new List<string>();    // where it sits in Untrusted Certificates
            internal bool MicrosoftUntrusted, SelfSigned, RootHere, OnMicrosoftList, Box;
        }

        internal const string WindowsSideLabel = "🔧 Fix it on Windows' side (certutil + steps)...";

        internal void ShowWindowsSideFix(string title, IEnumerable<string> boxSha1s, Denial d)
        {
            List<string> box = (boxSha1s ?? new string[0]).Where(s => !String.IsNullOrEmpty(s)).ToList();
            List<string> order = new List<string>();
            if (d != null) order.AddRange(d.ChainSha1);
            order.AddRange(box);
            order = order.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (order.Count == 0) { Say("Windows didn't log a chain for " + title + ", so kisib can't see what Windows holds against it."); return; }

            HashSet<string> microsoftUntrusted = LiftGuard.WindowsUntrusted();
            HashSet<string> microsoftList = AuthRootList.Sha1s();
            string folder = CerFolder();
            List<ChainLink> links = new List<ChainLink>();
            foreach (string sha1 in order)
            {
                ChainLink l = new ChainLink { Sha1 = sha1.ToUpperInvariant(), Cert = FindBySha1(sha1) };
                int at = d == null ? -1 : d.ChainSha1.FindIndex(x => String.Equals(x, sha1, StringComparison.OrdinalIgnoreCase));
                l.Name = l.Cert != null ? l.Cert.SubjectShortName : at >= 0 && at < d.ChainNames.Count ? d.ChainNames[at] : l.Sha1.Substring(0, Math.Min(12, l.Sha1.Length));
                l.Box = box.Contains(sha1, StringComparer.OrdinalIgnoreCase);
                l.MicrosoftUntrusted = microsoftUntrusted.Contains(sha1);
                l.OnMicrosoftList = microsoftList.Contains(sha1);
                if (l.Cert != null)
                {
                    l.SelfSigned = l.Cert.Subject == l.Cert.Issuer;
                    l.RootHere = TrustGraph.InRootStore(l.Cert);
                    List<string> physical = l.Cert.FoundIn.Where(p => p.Split('\\').Length >= 3).ToList();
                    if (physical.Count == 0) physical = l.Cert.FoundIn.ToList();
                    l.Untrusted = physical.Where(p => p.Split('\\').Any(x => x.Equals("Disallowed", StringComparison.OrdinalIgnoreCase)))
                        .Select(WhereLine).Where(x => x != null).Distinct().ToList();
                    l.CerPath = WriteCer(folder, l.Cert);
                }
                links.Add(l);
            }

            string code = d == null ? "" : d.Code ?? "";
            bool revoked = code.EndsWith("92010", StringComparison.OrdinalIgnoreCase) || code.EndsWith("B010C", StringComparison.OrdinalIgnoreCase);
            bool offline = code.EndsWith("92013", StringComparison.OrdinalIgnoreCase) || code.EndsWith("92012", StringComparison.OrdinalIgnoreCase);
            bool rootRefused = code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase);
            List<ChainLink> inStores = links.Where(l => l.Untrusted.Count > 0).ToList();
            List<ChainLink> byMicrosoft = links.Where(l => l.MicrosoftUntrusted).ToList();
            // The top of what Windows logged (twins of the box are listed after it, so they don't count as the top).
            string topSha1 = d != null && d.ChainSha1.Count > 0 ? d.ChainSha1[d.ChainSha1.Count - 1] : order[order.Count - 1];
            ChainLink top = links.First(l => String.Equals(l.Sha1, topSha1, StringComparison.OrdinalIgnoreCase));
            ChainLink check = links.FirstOrDefault(l => l.Box && l.CerPath != null) ?? links.FirstOrDefault(l => l.CerPath != null);
            List<string> commands = new List<string>();

            StringBuilder t = new StringBuilder();
            if (d != null)
            {
                t.AppendLine(ProgramName(d) + " → " + (d.Site ?? d.Subject) + "   refused " + d.Time.ToString("yyyy-MM-dd HH:mm:ss"));
                t.AppendLine("Windows said: " + ShortReason(d.Reason ?? "") + (code.Length > 0 ? "  (" + code + ")" : ""));
                if (!String.IsNullOrEmpty(d.Flags)) t.AppendLine("Windows' flags: " + d.Flags);
                t.AppendLine();
            }
            t.AppendLine("THE CHAIN, BOTTOM TO TOP");
            for (int i = 0; i < links.Count; i++)
            {
                ChainLink l = links[i];
                t.AppendLine((i + 1) + ".  " + l.Name + (l.Cert != null && !l.SelfSigned ? "   issued by " + l.Cert.IssuerShortName : "") + (l.Box ? "   ◀ this box" : ""));
                t.AppendLine("      SHA-1 (Windows' Thumbprint) " + l.Sha1);
                foreach (string where in l.Untrusted) t.AppendLine("      BLOCKED IN WINDOWS: " + where);
                if (l.MicrosoftUntrusted) t.AppendLine("      BLOCKED BY MICROSOFT: on Windows' own untrusted list (disallowedcert.stl from Windows Update)");
                if (l.Cert == null) t.AppendLine("      kisib doesn't have this certificate (not on this PC or in its lists)");
                else
                {
                    if (l.SelfSigned) t.AppendLine("      root: " + (l.RootHere ? "in Trusted Root here" : "NOT in Trusted Root here") + (l.OnMicrosoftList ? "  ·  on Microsoft's root list" : "  ·  not on Microsoft's root list"));
                    else if (!TrustGraph.OnPcForPath(l.Cert) && l.Untrusted.Count == 0) t.AppendLine("      not stored on this PC (the program or site sends it along; normal for a CA)");
                    if (l.Cert.NotAfter.HasValue && l.Cert.NotAfter.Value < DateTime.UtcNow) t.AppendLine("      expired " + l.Cert.NotAfter.Value.ToString("yyyy-MM-dd"));
                    if (l.Untrusted.Count == 0 && !l.MicrosoftUntrusted) t.AppendLine("      not in Untrusted Certificates anywhere kisib can see");
                    if (l.CerPath != null) t.AppendLine("      file for certutil: " + l.CerPath);
                }
            }
            t.AppendLine();
            t.AppendLine("WHAT TO DO ON WINDOWS' SIDE");

            if (inStores.Count > 0)
            {
                t.AppendLine("Windows reports a certificate in Untrusted Certificates the same way as a revoked one (0x80092010), so clear these first.");
                t.AppendLine("In Windows' certificate manager:");
                t.AppendLine("  1. Click Open certlm.msc (whole PC; say Yes to the admin prompt) or Open certmgr.msc (you), whichever the BLOCKED line names.");
                t.AppendLine("  2. Left side: Untrusted Certificates → Certificates.");
                foreach (ChainLink l in inStores)
                    t.AppendLine("  3. Find " + l.Name + (l.Cert != null ? " (issued by " + l.Cert.IssuerShortName + ")" : "") + ". Double-click → Details → Thumbprint must read " + l.Sha1 + ".");
                t.AppendLine("  4. Right-click it → Delete → Yes.");
                t.AppendLine("  5. Close the program that was refused and open it again.");
                bool policy = false;
                foreach (ChainLink l in inStores)
                    foreach (string where in l.Untrusted)
                    {
                        if (where.StartsWith("certlm", StringComparison.Ordinal)) commands.Add("certutil -delstore Disallowed " + l.Sha1 + "        # " + l.Name + ", whole PC (PowerShell as administrator)");
                        else if (where.StartsWith("certmgr", StringComparison.Ordinal)) commands.Add("certutil -user -delstore Disallowed " + l.Sha1 + "  # " + l.Name + ", your account");
                        else if (where.StartsWith("Group Policy", StringComparison.Ordinal)) policy = true;
                    }
                if (policy)
                    t.AppendLine("  Group Policy copies don't delete in certlm.msc: gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Public Key Policies → Untrusted Certificates (on a work PC, only its admin can).");
                if (links.Any(l => l.Cert != null && l.Untrusted.Count > 0 && snapshot != null && snapshot.IsBlocked(l.Cert)))
                    t.AppendLine("  If a kisib bloc rule covers it, the next scan puts it back. Unblock for good (button below) lifts it and keeps the rules off it.");
                t.AppendLine();
            }
            if (byMicrosoft.Count > 0)
            {
                t.AppendLine("Microsoft's own untrusted list (" + String.Join(", ", byMicrosoft.Select(l => l.Name).ToArray()) + "): Windows Update sends it and certificate manager doesn't show it.");
                t.AppendLine("There's no supported way to take one entry off it, and kisib's fail-safe won't lift it. The program has to be sent a different chain.");
                t.AppendLine();
            }
            if (revoked && inStores.Count == 0 && byMicrosoft.Count == 0)
            {
                t.AppendLine("Nothing in this chain is in Untrusted Certificates or on Microsoft's untrusted list, so the \"revoked\" came from a CA's own revocation list (CRL) or OCSP answer.");
                t.AppendLine("  1. Click certutil revocation check: Windows' URL Retrieval Tool opens on " + (check != null ? check.Name : "the certificate") + ".");
                t.AppendLine("  2. Pick \"CRLs (from CDP)\" → Retrieve, then \"OCSP (from AIA)\" → Retrieve. Each row says whether Windows got an answer.");
                t.AppendLine("  3. Click certutil -verify (console): the full check. A line \"Certificate is REVOKED\" names the one its CA cancelled.");
                t.AppendLine("  If a CA's list really cancels it, there's no fix on Windows' side: the CA withdrew that copy, and the program's server has to send a newer chain.");
                t.AppendLine("  If Windows kept an old list, clearing its cache helps: certutil -urlcache crl delete, then open the program again.");
                commands.Add("certutil -urlcache crl delete        # clears the revocation lists Windows cached");
                t.AppendLine();
            }
            if (offline)
            {
                t.AppendLine("Windows couldn't reach a revocation server to finish the check.");
                t.AppendLine("  1. Click certutil revocation check → Retrieve on \"CRLs (from CDP)\" and \"OCSP (from AIA)\": the rows marked Failed name the servers it can't reach.");
                t.AppendLine("  2. Let those hosts through the firewall, VPN kill switch or DNS blocker. They only answer \"is this certificate cancelled?\".");
                t.AppendLine();
            }
            if (top.Cert != null && top.SelfSigned && !top.RootHere)
            {
                t.AppendLine("The root at the top (" + top.Name + ") isn't in Trusted Root here.");
                if (top.CerPath != null)
                {
                    t.AppendLine("  1. Open certlm.msc → Trusted Root Certification Authorities → right-click Certificates → All Tasks → Import.");
                    t.AppendLine("  2. Pick " + top.CerPath);
                    t.AppendLine("  3. Place all certificates in: Trusted Root Certification Authorities → Next → Finish.");
                    commands.Add("certutil -addstore Root \"" + top.CerPath + "\"        # " + top.Name + " (PowerShell as administrator)");
                }
                t.AppendLine(top.OnMicrosoftList ? "  Microsoft's list has it; Windows' own copy: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + top.Sha1 + ".crt"
                    : "  It isn't on Microsoft's root list, so Windows will never download it on its own.");
                t.AppendLine();
            }
            else if (rootRefused || (top.Cert != null && !top.SelfSigned && d != null && d.ChainSha1.Count > 0))
            {
                t.AppendLine("Windows stopped at " + top.Name + ": the root above it" + (d != null ? " (" + MissingRootName(d) + ")" : "") + " isn't on this PC.");
                t.AppendLine("  kisib's Get root from Microsoft (button below) fetches it when Microsoft lists it. With the .cer in hand, import it as above: certlm.msc → Trusted Root Certification Authorities → Import.");
                t.AppendLine();
            }
            if (inStores.Count == 0 && byMicrosoft.Count == 0 && !revoked && !offline && !(top.Cert != null && top.SelfSigned && !top.RootHere) && !rootRefused)
            {
                t.AppendLine("kisib can't see anything Windows holds against this chain on this PC. The flags line at the top is exactly what Windows reported.");
                t.AppendLine();
            }
            if (check != null) commands.Add("certutil -verify -urlfetch \"" + check.CerPath + "\"        # full check of " + check.Name);
            if (commands.Count > 0)
            {
                t.AppendLine("THE SAME IN POWERSHELL (Copy commands copies these)");
                foreach (string c in commands) t.AppendLine("  " + c);
            }

            Form f = new Form { Text = "Fix it on Windows' side — " + title, Size = new Size(940, 640), Font = new Font("Comic Sans MS", 10F), StartPosition = FormStartPosition.CenterScreen };
            TextBox text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, WordWrap = true, ScrollBars = ScrollBars.Vertical, BorderStyle = BorderStyle.None, BackColor = Color.White, TabStop = false, Text = t.ToString() };
            Panel pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 10, 6), BackColor = Color.White };
            pad.Controls.Add(text);
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 86, Padding = new Padding(6), WrapContents = true };
            Func<string, Button> add = delegate(string label) { Button b = new Button { Text = label, AutoSize = true, Height = 32, Margin = new Padding(3) }; buttons.Controls.Add(b); return b; };
            add("Open certlm.msc (whole PC)").Click += delegate { Open("certlm.msc"); };
            add("Open certmgr.msc (you)").Click += delegate { Open("certmgr.msc"); };
            if (check != null)
            {
                string file = check.CerPath;
                add("certutil revocation check").Click += delegate { RunCertutil("-url \"" + file + "\"", false); };
                add("certutil -verify (console)").Click += delegate { RunCertutil("-verify -urlfetch \"" + file + "\"", true); };
                add("Show the .cer files").Click += delegate
                {
                    try { Process.Start("explorer.exe", "/select,\"" + file + "\""); } catch (Exception ex) { Say("Couldn't open the folder: " + ex.Message); }
                };
            }
            if (commands.Count > 0) add("Copy commands").Click += delegate { CopyText(String.Join("\r\n", commands.ToArray())); Say("Copied. Paste into PowerShell (as administrator for the whole-PC lines)."); };
            List<CertificateRecord> kisibBlocked = links.Where(l => l.Cert != null && snapshot != null && snapshot.IsBlocked(l.Cert)).Select(l => l.Cert).ToList();
            if (kisibBlocked.Count > 0) add("Unblock for good (kisib)").Click += delegate { UnblockCertificates(kisibBlocked, "unblocked from Fix it on Windows' side"); f.Close(); };
            if (d != null && (rootRefused || (top.Cert != null && !top.SelfSigned))) add("Get root from Microsoft (kisib)").Click += delegate { FetchRoot(d); };
            add("Copy SHA-1s").Click += delegate { CopyText(String.Join("\r\n", links.Select(l => l.Sha1 + "  " + l.Name).ToArray())); };
            f.Controls.Add(pad); f.Controls.Add(buttons);
            f.Shown += delegate { text.SelectionLength = 0; f.ActiveControl = buttons.Controls[0]; };
            ShowTool(f, "windows-side:" + String.Join(",", order.ToArray()));
        }

        // Windows' own checkers. certutil -url is a window (URL Retrieval Tool); -verify prints, so it gets a console that stays open.
        private void RunCertutil(string args, bool console)
        {
            try
            {
                if (console) Process.Start(new ProcessStartInfo("cmd.exe", "/k certutil " + args) { UseShellExecute = true });
                else Process.Start(new ProcessStartInfo("certutil.exe", args) { UseShellExecute = false, CreateNoWindow = true });
            }
            catch (Exception ex) { Say("Couldn't start certutil: " + ex.Message); }
        }

        private static string CerFolder()
        {
            string path = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "kisib.dub-sar"), "certs");
            try { Directory.CreateDirectory(path); return path; }
            catch (Exception) { return Path.GetTempPath(); }
        }

        private static string WriteCer(string folder, CertificateRecord c)
        {
            if (c == null || c.Der == null || c.Sha1 == null) return null;
            string name = new string((c.SubjectShortName ?? "certificate").Select(ch => Path.GetInvalidFileNameChars().Contains(ch) || ch == '"' ? '_' : ch).ToArray()).Trim();
            if (name.Length > 60) name = name.Substring(0, 60).Trim();
            string path = Path.Combine(folder, name + " " + c.Sha1.Substring(0, 8).ToUpperInvariant() + ".cer");
            try
            {
                if (!File.Exists(path) || !File.ReadAllBytes(path).SequenceEqual(c.Der)) File.WriteAllBytes(path, c.Der);
                return path;
            }
            catch (Exception) { return null; }
        }
    }
}
