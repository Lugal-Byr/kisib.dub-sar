using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // "Where Windows keeps it": every store a certificate sits in, said the way Windows' own certificate manager
    // names it (certlm.msc for the whole PC, certmgr.msc for this user), with buttons to open those and Windows'
    // own certificate window. Removing it from Untrusted Certificates there unblocks it in Windows; kisib's
    // "Unblock for good" also keeps your bloc rules from putting it back.
    internal sealed partial class ExplorerForm
    {
        private static readonly Dictionary<string, string> StoreNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Root", "Trusted Root Certification Authorities" }, { "AuthRoot", "Third-Party Root Certification Authorities" },
            { "CA", "Intermediate Certification Authorities" }, { "Disallowed", "Untrusted Certificates" },
            { "TrustedPeople", "Trusted People" }, { "TrustedPublisher", "Trusted Publishers" }, { "My", "Personal" },
            { "Trust", "Enterprise Trust" }, { "SmartCardRoot", "Smart Card Trusted Roots" }, { "Remote Desktop", "Remote Desktop" },
        };

        private static string WhereLine(string path)
        {
            if (path.IndexOf("MICROSOFT_LIST", StringComparison.OrdinalIgnoreCase) >= 0) return "Microsoft's root list (Windows downloads it when needed; not on this PC yet)";
            if (path.StartsWith("CCADB", StringComparison.OrdinalIgnoreCase)) return "CCADB public list (kisib knows it; that alone doesn't put it on this PC)";
            string[] parts = path.Split('\\');
            if (parts.Length < 2) return path;
            string location = parts[0], physical = parts.Length > 2 ? parts[parts.Length - 1] : "";
            bool users = location.Equals("USERS", StringComparison.OrdinalIgnoreCase);
            if (users && parts.Length < 3) return null;
            if (users && parts[1].EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return null;
            int storeAt = users ? 2 : 1;
            physical = parts.Length > storeAt + 1 ? parts[parts.Length - 1] : "";
            string store = parts[storeAt], name;
            if (!StoreNames.TryGetValue(store, out name)) name = store;
            string where;
            // Every account sees the whole-PC copy through ".LocalMachine": that is one place, certlm.msc.
            if (physical.Equals(".LocalMachine", StringComparison.OrdinalIgnoreCase)) return "certlm.msc (whole PC) → " + name + " → Certificates";
            if (location.IndexOf("GROUP_POLICY", StringComparison.OrdinalIgnoreCase) >= 0 || physical.IndexOf("GroupPolicy", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Group Policy → " + name + "   (only a policy change removes it)";
            if (location.StartsWith("LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)) where = "certlm.msc (whole PC) → " + name + " → Certificates";
            else if (location.StartsWith("CURRENT_USER", StringComparison.OrdinalIgnoreCase))
                where = physical.Equals(".LocalMachine", StringComparison.OrdinalIgnoreCase) ? "certlm.msc (whole PC) → " + name + "   (this user only sees the whole-PC copy)"
                    : "certmgr.msc (you) → " + name + " → Certificates";
            else if (location.StartsWith("USERS", StringComparison.OrdinalIgnoreCase))
                where = "another account (" + AccountName(parts[1]) + ") → " + name;
            else if (location.IndexOf("GROUP_POLICY", StringComparison.OrdinalIgnoreCase) >= 0 || physical.IndexOf("GroupPolicy", StringComparison.OrdinalIgnoreCase) >= 0)
                where = "Group Policy → " + name + "   (only a policy change removes it)";
            else if (location.IndexOf("SERVICE", StringComparison.OrdinalIgnoreCase) >= 0) where = "a service's own store → " + name;
            else if (location.IndexOf("MICROSOFT_LIST", StringComparison.OrdinalIgnoreCase) >= 0) return "Microsoft's root list (Windows downloads it when needed; not on this PC yet)";
            else if (location.IndexOf("CCADB", StringComparison.OrdinalIgnoreCase) >= 0) return "CCADB public list (not on this PC)";
            else where = location + " → " + name;
            if (physical.IndexOf("Enterprise", StringComparison.OrdinalIgnoreCase) >= 0) where += "   (domain-managed)";
            return where;
        }

        private static string AccountName(string sid)
        {
            switch (sid.ToUpperInvariant())
            {
                case "S-1-5-18": return "SYSTEM";
                case "S-1-5-19": return "LOCAL SERVICE";
                case "S-1-5-20": return "NETWORK SERVICE";
                case ".DEFAULT": return "new-user default";
                default: return sid.EndsWith("-1001", StringComparison.Ordinal) || sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) ? "a user account" : sid;
            }
        }

        internal void ShowWhereInWindows(CertificateRecord c)
        {
            if (c == null) return;
            // The physical stores say where it really is; the logical views (every account's copy of the whole-PC
            // store) only repeat that, so they are used only when nothing physical is known.
            List<string> source = c.FoundIn.Where(p => p.Split('\\').Length >= 3 || p.IndexOf("CCADB", StringComparison.OrdinalIgnoreCase) >= 0 || p.IndexOf("MICROSOFT_LIST", StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            if (source.Count == 0) source = c.FoundIn.Concat(c.Collections).ToList();
            List<string> places = source.Distinct(StringComparer.OrdinalIgnoreCase).Select(WhereLine).Where(l => l != null).Distinct().ToList();
            bool blocked = snapshot != null && snapshot.IsBlocked(c);
            Form f = new Form { Text = "Where Windows keeps it — " + c.SubjectShortName, Size = new Size(820, 440), Font = new Font("Comic Sans MS", 10F), StartPosition = FormStartPosition.CenterScreen };
            TextBox text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, WordWrap = true, ScrollBars = ScrollBars.Vertical, BorderStyle = BorderStyle.None, BackColor = Color.White, TabStop = false };
            StringBuilder t = new StringBuilder();
            t.AppendLine(c.SubjectShortName + "   issued by " + c.IssuerShortName + (c.NotAfter.HasValue ? "   expires " + c.NotAfter.Value.ToString("yyyy-MM-dd") : ""));
            t.AppendLine("SHA-1 (Windows calls it Thumbprint) " + c.Sha1 + (blocked ? "   ·   BLOCKED" : ""));
            t.AppendLine();
            foreach (string p in places) t.AppendLine("•  " + p);
            t.AppendLine();
            t.AppendLine("In Windows' certificate manager the list isn't searchable by hash: look for the name and issuer above, double-click it, Details tab, Thumbprint.");
            if (blocked) t.AppendLine("Deleting it from Untrusted Certificates there unblocks it in Windows, but a bloc rule in kisib can put it back on the next scan. kisib's Unblock for good does both.");
            text.Text = t.ToString();
            Panel pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 10, 6), BackColor = Color.White };
            pad.Controls.Add(text);
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, Padding = new Padding(6) };
            Func<string, Button> add = delegate(string label) { Button b = new Button { Text = label, AutoSize = true, Height = 32, Margin = new Padding(3) }; buttons.Controls.Add(b); return b; };
            add("Open certlm.msc (whole PC)").Click += delegate { Open("certlm.msc"); };
            add("Open certmgr.msc (you)").Click += delegate { Open("certmgr.msc"); };
            add("Windows' certificate window").Click += delegate
            {
                try { using (X509Certificate2 x = new X509Certificate2(c.Der)) X509Certificate2UI.DisplayCertificate(x, f.Handle); }
                catch (Exception ex) { Say("Couldn't open Windows' certificate window: " + ex.Message); }
            };
            add("Copy SHA-1").Click += delegate { CopyText(c.Sha1); };
            if (blocked) add("Unblock for good (kisib)").Click += delegate { UnblockCertificates(new List<CertificateRecord> { c }, "unblocked from Where Windows keeps it"); f.Close(); };
            f.Controls.Add(pad); f.Controls.Add(buttons);
            f.Shown += delegate { text.SelectionLength = 0; f.ActiveControl = buttons.Controls[0]; };
            ShowTool(f, "where:" + c.Sha1);
        }

        private void Open(string snapIn)
        {
            try { Process.Start(new ProcessStartInfo(snapIn) { UseShellExecute = true }); }
            catch (Exception ex) { Say("Couldn't open " + snapIn + ": " + ex.Message); }
        }
    }
}
