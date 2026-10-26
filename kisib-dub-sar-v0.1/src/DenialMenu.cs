using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // Right-click on a refusal: allow it for a while, or find out exactly why it is blocked.
    internal sealed partial class ExplorerForm
    {
        internal void AddDenialMenu(ListView grid, Action closeParent)
        {
            ContextMenu menu = grid.ContextMenu ?? new ContextMenu();
            Func<Denial> selected = delegate { return grid.SelectedItems.Count == 0 ? null : grid.SelectedItems[0].Tag as Denial; };
            List<MenuItem> items = new List<MenuItem>();
            items.Add(new MenuItem("Open refusal card (app behind it, allow, reroute, quiet)", delegate { OpenRefusalCard(selected()); }));
            items.Add(AllowSubmenu("Allow", delegate
            {
                Denial d = selected();
                return d == null ? new AllowTarget { Certs = delegate { return new List<CertificateRecord>(); }, NothingWhy = "Select a refusal first." } : TargetFor(d);
            }));
            items.Add(new MenuItem("Get the missing root from Microsoft (what Windows would download)", delegate
            {
                Denial d = selected();
                if (d == null) return;
                if (!d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase)) { Say("This refusal isn't a missing root (" + ShortReason(d.Reason ?? "") + ")."); return; }
                FetchRoot(d);
            }));
            items.Add(new MenuItem("Why was this refused? (groups, rules, who blocked it)", delegate { Denial d = selected(); if (d != null) ShowText("Why — " + d.Subject, ExplainDenial(d)); }));
            items.Add(new MenuItem("Reroute around the block (use a cross-signed path)...", delegate
            {
                Denial d = selected(); if (d == null) return;
                List<CertificateRecord> missing;
                List<CertificateRecord> route = DenialRoute(d, out missing);
                if (route == null) { ShowText("Reroute", "No other path: the CA that signed this has no cross-sign to a root you trust, so only Allow gets it through.\r\n\r\n" + ExplainDenial(d)); return; }
                if (missing.Count == 0) { ShowText("Reroute", "The other path is already on this PC:\r\n  " + TrustGraph.PathText(route) + "\r\n\r\nWindows should take it on the next try [to test]. If it still fails, the site or program only offers the blocked path."); return; }
                if (closeParent != null) closeParent();
                InstallRoute(missing, d.Subject);
            }));
            items.Add(new MenuItem("Open certificate card", delegate
            {
                Denial d = selected(); if (d == null) return;
                CertificateRecord c = CertificatesBehind(d).FirstOrDefault() ?? d.ChainSha1.Select(FindBySha1).FirstOrDefault(x => x != null);
                ShowText("Certificate", c != null ? CertificateCard(c) : "None of the certificates in this chain are on this PC. SHA-1s: " + String.Join(", ", d.ChainSha1.ToArray()));
            }));
            items.Add(new MenuItem("Show in main list", delegate
            {
                Denial d = selected(); if (d == null) return;
                CertificateRecord c = CertificatesBehind(d).FirstOrDefault() ?? d.ChainSha1.Select(FindBySha1).FirstOrDefault(x => x != null);
                if (c == null) return;
                if (closeParent != null) closeParent();
                leftTabs.SelectedTab = storesTab;
                if (tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0];
                findIssuer.Text = c.Sha256;
            }));
            items.Add(new MenuItem("Copy who-is-this and reason", delegate { Denial d = selected(); if (d != null) CopyText(d.Who + "\r\n" + d.Reason + (d.BlockedBy != null ? "\r\nBlocked by: " + d.BlockedBy : "")); }));
            items.Add(new MenuItem("-"));
            for (int i = 0; i < items.Count; i++) menu.MenuItems.Add(i, items[i]);
            menu.Popup += delegate { bool any = selected() != null; foreach (MenuItem it in items) it.Enabled = any || it.Text == "-"; };
            grid.ContextMenu = menu;
        }

        internal string WhyBlockedText(CertificateRecord c)
        {
            StringBuilder t = new StringBuilder();
            bool isBlocked = snapshot != null && snapshot.IsBlocked(c);
            t.AppendLine(c.SubjectShortName + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : "") + (isBlocked ? "  BLOCKED" : "  not blocked"));
            string owner = WhoIsWho.Owner(c);
            if (owner != null) t.AppendLine("  owner     " + owner);
            List<BlockLogRow> mine = BlockEngine.ReadLog().Where(r => String.Equals(r.Sha1, c.Sha1, StringComparison.OrdinalIgnoreCase)).ToList();
            BlockLogRow lastBlock = mine.LastOrDefault(r => r.Action == "block" && r.Result == "added");
            BlockLogRow lastUndo = mine.LastOrDefault(r => r.Action == "unblock" && r.Result == "removed");
            if (isBlocked)
                t.AppendLine(lastBlock != null && (lastUndo == null || String.CompareOrdinal(lastUndo.Time, lastBlock.Time) < 0)
                    ? "  blocked   by kisib on " + lastBlock.Time.Replace("T", " ").Substring(0, Math.Min(19, lastBlock.Time.Length)) + " UTC — " + lastBlock.Group + " (" + lastBlock.Scope + ")"
                    : "  blocked   before kisib: already in Disallowed (Microsoft's own untrusted list, or an earlier hardening).");
            List<BlockRule> rules = BlockRules.Read();
            if (groups != null)
                foreach (GroupNode g in AllGroups(groups).Where(g => g.Members.Contains(c.Identity)))
                    t.AppendLine("  group     " + g.Kind + ": " + g.Label + (rules.Any(r => r.GroupKey == g.Key) ? "   ← a RULE keeps this group blocked" : "") + "   (" + String.Join("; ", g.Why[c.Identity].ToArray()) + ")");
            string tags = TagsOf(c);
            if (tags.Length > 0) t.AppendLine("  tags      " + tags);
            string guard = TrustCategories.ProtectedBy(c);
            if (guard != null) t.AppendLine("  NOTE      protected by trusted category " + guard + " — blocking it breaks that category");
            if (AllowedList.Load().Covers(c)) t.AppendLine("  allowed   on your never-block list (allowed for good, unblocked by hand, or repaired)");
            t.AppendLine();
            t.AppendLine("Path to a trusted root: " + PathSummary(c));
            return t.ToString();
        }

        internal string ExplainDenial(Denial d)
        {
            if (d.Verdict == null) Annotate(d);
            StringBuilder t = new StringBuilder();
            t.AppendLine(d.Who);
            if (d.Service != null) t.AppendLine("Service inside svchost: " + d.Service);
            t.AppendLine("Refused: " + d.Reason + "   (" + d.Time.ToString("yyyy-MM-dd HH:mm:ss") + ")");
            t.AppendLine("Check Windows ran: " + DenialParser.PolicyWords(d.Policy) + (d.Site != null && d.Site != d.Subject ? "   site asked for: " + d.Site : ""));
            if (d.ChainNames.Count > 1) t.AppendLine("Chain: " + String.Join("  →  ", d.ChainNames.ToArray()));
            if (d.Category != null) t.AppendLine("Trusted category: " + d.Category + " (this is a service you marked as expected)");
            t.AppendLine();
            List<CertificateRecord> behind = CertificatesBehind(d);
            if (behind.Count == 0)
            {
                t.AppendLine("Not caused by a block. Windows refused it for its own reason:");
                if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase)) t.AppendLine("  the root at the top of the chain is not in Trusted Root, and Windows could not download it.\r\n  Fix: right-click > Get the missing root from Microsoft (what Windows would download), or Tools > Repair > Get online for the roots kisib carries." + (RootAutoUpdateOff() ? "\r\n  Windows' automatic root download is switched off on this PC (policy DisableRootAutoUpdate), which is why it didn't fetch it itself." : ""));
                else if (d.Code.EndsWith("B0101", StringComparison.OrdinalIgnoreCase)) t.AppendLine("  a certificate in the chain is expired (or your clock is off; see Clock in the status bar).");
                else t.AppendLine("  " + d.Reason);
                return t.ToString();
            }
            List<BlockLogRow> history = BlockEngine.ReadLog();
            List<BlockRule> rules = BlockRules.Read();
            foreach (CertificateRecord c in behind)
            {
                t.AppendLine("BLOCKED: " + c.SubjectShortName + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : ""));
                string owner = WhoIsWho.Owner(c);
                if (owner != null) t.AppendLine("  owner     " + owner);
                List<BlockLogRow> mine = history.Where(r => String.Equals(r.Sha1, c.Sha1, StringComparison.OrdinalIgnoreCase)).ToList();
                BlockLogRow lastBlock = mine.LastOrDefault(r => r.Action == "block" && r.Result == "added");
                BlockLogRow lastUndo = mine.LastOrDefault(r => r.Action == "unblock" && r.Result == "removed");
                if (lastBlock != null && (lastUndo == null || String.CompareOrdinal(lastUndo.Time, lastBlock.Time) < 0))
                    t.AppendLine("  blocked   by kisib on " + lastBlock.Time.Replace("T", " ").Substring(0, Math.Min(19, lastBlock.Time.Length)) + " UTC — " + lastBlock.Group + " (" + lastBlock.Scope + ")");
                else
                    t.AppendLine("  blocked   before kisib: it was already in Disallowed (Microsoft's own untrusted list, or an earlier hardening).");
                if (groups != null)
                {
                    foreach (GroupNode g in AllGroups(groups).Where(g => g.Members.Contains(c.Identity)))
                    {
                        bool ruled = rules.Any(r => r.GroupKey == g.Key);
                        t.AppendLine("  group     " + g.Kind + ": " + g.Label + (ruled ? "   ← you have a RULE keeping this group blocked" : "") + "   (" + String.Join("; ", g.Why[c.Identity].ToArray()) + ")");
                    }
                }
                string tags = TagsOf(c);
                if (tags.Length > 0) t.AppendLine("  tags      " + tags);
                string guard = TrustCategories.ProtectedBy(c);
                if (guard != null) t.AppendLine("  NOTE      protected by trusted category " + guard + " — blocking it breaks that category");
                t.AppendLine("  undo      right-click > Allow (for a while, until kisib closes, always, or while a program runs), or Unblock.");
                t.AppendLine();
            }
            List<CertificateRecord> missing;
            List<CertificateRecord> route = DenialRoute(d, out missing);
            t.AppendLine("OTHER ROUTE (cross-signs):");
            if (route == null) t.AppendLine("  none. The CA that signed this has no path to a root you trust except through the block. Only Allow gets it through.");
            else
            {
                t.AppendLine("  " + TrustGraph.PathText(route));
                t.AppendLine(missing.Count == 0 ? "  Already on this PC; Windows should find it [to test]." : "  Needs " + missing.Count + " certificate(s) Windows can't find: right-click > Reroute around the block installs them.");
            }
            return t.ToString();
        }
    }
}
