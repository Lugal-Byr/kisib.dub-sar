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
    // What each app actually leaned on: app -> root -> the CAs in between, from every certificate check Windows
    // logged (trusted or refused), kept across restarts. "Required for app" is built from it.
    internal sealed class AppRoot
    {
        internal string Program, Root;
        internal int Ok, Refused;
        internal DateTime Last;
        internal readonly SortedSet<string> Middle = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        internal readonly SortedSet<string> Sites = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    internal static class AppChains
    {
        private static readonly object gate = new object();
        private static Dictionary<string, AppRoot> rows;
        private static Dictionary<string, string> names;
        private static bool dirty;
        private static DateTime lastSave = DateTime.MinValue;
        internal static string FilePath { get { return Storage.File(Storage.UsedCertificates); } }

        internal static void Record(Denial d)
        {
            if (d == null || d.ChainSha1.Count < 2 || String.IsNullOrEmpty(d.Program)) return;
            string program = Path.GetFileName(d.Program), site = d.Site ?? d.Subject;
            int top = d.ChainSha1.Count - 1;
            lock (gate)
            {
                Load();
                string key = program.ToLowerInvariant() + "|" + d.ChainSha1[top];
                AppRoot r;
                if (!rows.TryGetValue(key, out r)) { r = new AppRoot { Program = program, Root = d.ChainSha1[top] }; rows[key] = r; }
                if (d.Ok) r.Ok++; else r.Refused++;
                r.Last = d.Time;
                for (int i = 1; i < top; i++) r.Middle.Add(d.ChainSha1[i]);
                if (!String.IsNullOrEmpty(site) && r.Sites.Count < 30) r.Sites.Add(site);
                for (int i = 1; i <= top && i < d.ChainNames.Count; i++) if (d.ChainNames[i].Length > 0) names[d.ChainSha1[i]] = d.ChainNames[i];
                dirty = true;
                if ((DateTime.Now - lastSave).TotalMinutes >= 2) SaveLocked();
            }
        }

        internal static List<AppRoot> All() { lock (gate) { Load(); return rows.Values.ToList(); } }
        internal static string NameOf(string sha1) { lock (gate) { Load(); string n; return names.TryGetValue(sha1, out n) ? n : null; } }
        internal static void Flush() { lock (gate) { if (dirty) SaveLocked(); } }

        private static void Load()
        {
            if (rows != null) return;
            rows = new Dictionary<string, AppRoot>(StringComparer.OrdinalIgnoreCase);
            names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(FilePath)) return;
                foreach (string[] f in GroupCatalog.ReadCsv(FilePath).Skip(1))
                {
                    if (f.Length < 3) continue;
                    if (f[0] == "name") { if (f[1].Length == 40) names[f[1]] = f[2]; continue; }
                    if (f[0] != "app" || f.Length < 9) continue;
                    AppRoot r = new AppRoot { Program = f[1], Root = f[2] };
                    Int32.TryParse(f[3], out r.Ok); Int32.TryParse(f[4], out r.Refused);
                    DateTime.TryParse(f[5], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out r.Last);
                    foreach (string s in f[6].Split(';')) if (s.Trim().Length == 40) r.Middle.Add(s.Trim());
                    foreach (string s in f[7].Split(';')) if (s.Trim().Length > 0) r.Sites.Add(s.Trim());
                    rows[r.Program.ToLowerInvariant() + "|" + r.Root] = r;
                }
            }
            catch (Exception) { }
        }

        private static void SaveLocked()
        {
            try
            {
                StringBuilder t = new StringBuilder("kind,program_or_sha1,root_or_name,trusted_checks,refused_checks,last_seen,intermediates,sites,note\r\n");
                foreach (AppRoot r in rows.Values.OrderBy(x => x.Program, StringComparer.OrdinalIgnoreCase))
                    t.Append(String.Join(",", new string[] { "app", r.Program, r.Root, r.Ok.ToString(CultureInfo.InvariantCulture), r.Refused.ToString(CultureInfo.InvariantCulture),
                        r.Last.ToString("o", CultureInfo.InvariantCulture), String.Join(";", r.Middle.ToArray()), String.Join(";", r.Sites.ToArray()), "" }.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
                foreach (KeyValuePair<string, string> n in names)
                    t.Append(String.Join(",", new string[] { "name", n.Key, n.Value }.Select(BlockEngine.Csv).ToArray())).Append("\r\n");
                File.WriteAllText(FilePath, t.ToString(), new UTF8Encoding(false));
                dirty = false; lastSave = DateTime.Now;
            }
            catch (Exception) { }
        }
    }

    internal sealed partial class ExplorerForm
    {
        internal const string RequiredSource = "required for app";

        // ---- Required for app: app > root > intermediates, tick what has to keep working ----------------------

        internal void ShowRequiredForApp()
        {
            if (snapshot == null) { Say("Run a scan first (F5)."); return; }
            Form f = new Form { Text = "Required for app", Size = new Size(1000, 680), Font = new Font("Comic Sans MS", 10F, FontStyle.Bold), StartPosition = FormStartPosition.CenterScreen };
            Label intro = new Label { Dock = DockStyle.Top, Height = 58, Padding = new Padding(10, 8, 10, 0),
                Text = "Each app, the roots it used, and the CAs in between, from every check Windows logged. Tick what has to keep working:\r\n" +
                       "kisib unblocks it, puts a missing root back (only roots Windows' own list names) and keeps it off every bloc rule. Untick to let your rules decide again." };
            TreeView tree = new TreeView { Dock = DockStyle.Fill, CheckBoxes = true, Font = new Font("Comic Sans MS", 10F), ShowNodeToolTips = true, HideSelection = false, ItemHeight = 24 };
            Label detail = new Label { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(10, 4, 10, 0), Font = new Font("Comic Sans MS", 9.5F), ForeColor = Color.FromArgb(80, 80, 90) };
            HashSet<string> confirmed = Confirmed();
            bool cascading = false;

            Func<string, TreeNode> certNode = delegate(string sha1)
            {
                CertificateRecord c = snapshot.BySha1(sha1);
                bool root = c != null && c.Subject == c.Issuer;
                bool blocked = c != null && (snapshot.IsBlocked(c) || snapshot.SameKey(c).Any(snapshot.IsBlocked));
                bool missing = c != null && root && !TrustGraph.InRootStore(c);
                string name = c != null ? c.SubjectShortName : AppChains.NameOf(sha1) ?? sha1.Substring(0, 12);
                string state = c == null ? "not on this PC" : blocked ? "BLOCKED" : missing ? "not in Trusted Root" : AllowedList.Load().Covers(c) ? "fine, never blocked" : "fine";
                TreeNode n = new TreeNode(name + "   ·   " + (c == null ? "" : OwnerName(c) + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : "") + "   ·   ") + state)
                { Tag = sha1, Checked = confirmed.Contains(sha1), ToolTipText = "SHA-1 " + sha1 };
                if (blocked) n.ForeColor = Color.Firebrick; else if (missing || c == null) n.ForeColor = Color.DarkOrange;
                return n;
            };
            Action fill = delegate
            {
                tree.BeginUpdate();
                try
                {
                    tree.Nodes.Clear();
                    foreach (IGrouping<string, AppRoot> app in AppChains.All().GroupBy(r => r.Program, StringComparer.OrdinalIgnoreCase)
                        .OrderByDescending(g => g.Sum(r => r.Refused) > 0).ThenBy(g => FriendlyExe(g.Key), StringComparer.OrdinalIgnoreCase))
                    {
                        int ok = app.Sum(r => r.Ok), bad = app.Sum(r => r.Refused);
                        string friendly = FriendlyExe(app.Key);
                        TreeNode a = new TreeNode((friendly != app.Key ? friendly + "  (" + app.Key + ")" : app.Key) + "   ·   " + ok + " ok" + (bad > 0 ? ", " + bad + " refused" : ""))
                        { Tag = app.ToList(), ForeColor = bad > 0 ? Color.Firebrick : SystemColors.WindowText };
                        foreach (AppRoot r in app.OrderByDescending(x => x.Refused).ThenByDescending(x => x.Ok))
                        {
                            TreeNode rn = certNode(r.Root);
                            rn.ToolTipText += "\r\nSites: " + String.Join(", ", r.Sites.Take(8).ToArray()) + "\r\n" + r.Ok + " ok, " + r.Refused + " refused, last " + r.Last.ToString("MM-dd HH:mm");
                            foreach (string mid in r.Middle) rn.Nodes.Add(certNode(mid));
                            a.Nodes.Add(rn);
                        }
                        a.Checked = a.Nodes.Count > 0 && Flatten(a).All(x => x.Checked);
                        tree.Nodes.Add(a);
                    }
                    foreach (TreeNode a in tree.Nodes) if (a.ForeColor == Color.Firebrick) a.ExpandAll();
                }
                finally { tree.EndUpdate(); }
                if (tree.Nodes.Count == 0) tree.Nodes.Add(new TreeNode("Nothing recorded yet: kisib learns this from Windows' certificate checks (Watch menu > watching on).") { ForeColor = Color.Gray });
            };
            fill();
            // Ticking an app or a root ticks everything under it.
            tree.AfterCheck += delegate(object s, TreeViewEventArgs e)
            {
                if (cascading || e.Action == TreeViewAction.Unknown) return;
                cascading = true;
                try { foreach (TreeNode child in Flatten(e.Node)) child.Checked = e.Node.Checked; }
                finally { cascading = false; }
            };
            tree.AfterSelect += delegate(object s, TreeViewEventArgs e)
            {
                List<AppRoot> app = e.Node.Tag as List<AppRoot>;
                string sha1 = e.Node.Tag as string;
                if (app != null) detail.Text = "Sites: " + String.Join(", ", app.SelectMany(r => r.Sites).Distinct().Take(12).ToArray());
                else if (sha1 != null) { CertificateRecord c = snapshot.BySha1(sha1); detail.Text = (c != null ? c.Subject + "\r\n" : "") + "SHA-1 " + sha1 + (c != null && snapshot.IsBlocked(c) ? "   ·   " + WhyLine(c) : ""); }
            };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(6) };
            Func<string, Button> add = delegate(string text) { Button b = new Button { Text = text, AutoSize = true, Height = 32, Margin = new Padding(3) }; buttons.Controls.Add(b); return b; };
            add("Keep the ticked ones working").Click += delegate
            {
                List<TreeNode> all = tree.Nodes.Cast<TreeNode>().SelectMany(Flatten).Where(n => n.Tag is string).ToList();
                HashSet<string> ticked = new HashSet<string>(all.Where(n => n.Checked).Select(n => (string)n.Tag), StringComparer.OrdinalIgnoreCase);
                List<string> dropped = confirmed.Where(s => !ticked.Contains(s) && all.Any(n => String.Equals((string)n.Tag, s, StringComparison.OrdinalIgnoreCase))).ToList();
                Say(KeepRequired(ticked.ToList(), dropped));
                confirmed = Confirmed();
            };
            add("Tick every app that works now").Click += delegate
            {
                cascading = true;
                try
                {
                    foreach (TreeNode a in tree.Nodes)
                    {
                        List<AppRoot> app = a.Tag as List<AppRoot>;
                        if (app == null || app.Sum(r => r.Ok) == 0) continue;
                        a.Checked = true;
                        foreach (TreeNode n in Flatten(a)) n.Checked = true;
                    }
                }
                finally { cascading = false; }
            };
            add("Untick all").Click += delegate { cascading = true; try { foreach (TreeNode n in tree.Nodes.Cast<TreeNode>().SelectMany(x => new TreeNode[] { x }.Concat(Flatten(x)))) n.Checked = false; } finally { cascading = false; } };
            add("Refresh").Click += delegate { confirmed = Confirmed(); fill(); };
            add("Close").Click += delegate { f.Close(); };
            f.Controls.Add(tree); f.Controls.Add(intro); f.Controls.Add(detail); f.Controls.Add(buttons);
            ShowTool(f, "required-for-app");
        }

        private static IEnumerable<TreeNode> Flatten(TreeNode node)
        {
            foreach (TreeNode child in node.Nodes)
            {
                yield return child;
                foreach (TreeNode deeper in Flatten(child)) yield return deeper;
            }
        }

        private static HashSet<string> Confirmed()
        {
            return new HashSet<string>(AllowedList.Read().Where(r => r[5] == RequiredSource).Select(r => r[0]), StringComparer.OrdinalIgnoreCase);
        }

        private static string FriendlyExe(string exe)
        {
            string said = WhoIsWho.Program(exe);
            string[] parts = said == null ? null : said.Split(new string[] { " = " }, StringSplitOptions.None);
            return parts != null && parts.Length >= 2 ? parts[1].Trim() : exe;
        }

        private string KeepRequired(List<string> ticked, List<string> dropped)
        {
            List<string> said = new List<string>();
            List<CertificateRecord> certs = ticked.Select(snapshot.BySha1).Where(c => c != null).ToList();
            List<CertificateRecord> blocked = WithTwins(certs).Where(snapshot.IsBlocked).ToList();
            if (blocked.Count > 0) said.Add("Unblocked " + blocked.Count + ": " + LiftForGood(blocked, "required for app", RequiredSource));
            try
            {
                foreach (string sha1 in dropped) AllowedList.Remove(sha1);
                AllowedList.AddRange(WithTwins(certs), RequiredSource);
            }
            catch (IOException ex) { said.Add("Couldn't save the never-block list: " + ex.Message); }
            // Missing roots (or roots kisib has never seen): only ones Windows' own list names go in.
            List<string> roots = ticked.Where(s => { CertificateRecord c = snapshot.BySha1(s); return c == null || (c.Subject == c.Issuer && !TrustGraph.InRootStore(c)); }).ToList();
            if (roots.Count > 0)
            {
                HashSet<string> want = new HashSet<string>(roots, StringComparer.OrdinalIgnoreCase);
                FetchFromMicrosoft(c => want.Contains(c.Sha1), roots.Count + " missing root" + (roots.Count == 1 ? "" : "s"), roots);
                said.Add("Getting " + roots.Count + " missing root" + (roots.Count == 1 ? "" : "s") + " (a line says when they're in).");
            }
            said.Insert(0, "Keeping " + ticked.Count + " working" + (dropped.Count > 0 ? ", " + dropped.Count + " back to your rules" : "") + ".");
            StartScan();
            return String.Join(" ", said.ToArray());
        }

        // ---- Import > File... ---------------------------------------------------------------------------------

        internal void ImportFromFile()
        {
            string path;
            using (OpenFileDialog pick = new OpenFileDialog { Title = "Import a certificate", InitialDirectory = @"C:\", CheckFileExists = true,
                Filter = "Certificates (*.cer;*.crt;*.der;*.pem;*.p7b;*.sst)|*.cer;*.crt;*.der;*.pem;*.p7b;*.sst|All files (*.*)|*.*" })
            {
                if (pick.ShowDialog(this) != DialogResult.OK) return;
                path = pick.FileName;
            }
            List<byte[]> ders = new List<byte[]>();
            try
            {
                if (X509Certificate2.GetCertContentType(path) == X509ContentType.Pkcs12) { Say("That file holds a private key (PFX). kisib only imports certificates, never keys."); return; }
                string text = null;
                try { text = File.ReadAllText(path); } catch (Exception) { }
                if (text != null && text.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    int at = 0;
                    while ((at = text.IndexOf("-----BEGIN CERTIFICATE-----", at, StringComparison.Ordinal)) >= 0)
                    {
                        int end = text.IndexOf("-----END CERTIFICATE-----", at, StringComparison.Ordinal);
                        if (end < 0) break;
                        ders.Add(Convert.FromBase64String(text.Substring(at + 27, end - at - 27).Trim()));
                        at = end + 25;
                    }
                }
                else
                {
                    X509Certificate2Collection all = new X509Certificate2Collection();
                    all.Import(path);
                    foreach (X509Certificate2 x in all) ders.Add(x.RawData);
                }
            }
            catch (Exception ex) { Say("Couldn't read " + Path.GetFileName(path) + ": " + ex.Message); return; }
            if (ders.Count == 0) { Say(Path.GetFileName(path) + " has no certificates in it."); return; }
            HashSet<string> windowsList = AuthRootList.Sha1s();
            List<string> report = new List<string>();
            List<CertificateRecord> cas = new List<CertificateRecord>();
            X509Location scope = Elevation.IsElevated ? X509Location.LocalMachine : X509Location.CurrentUser;
            foreach (byte[] der in ders)
            {
                CertificateRecord c = CertificateRecord.FromDer(der);
                CertificateRecord onPc = snapshot == null ? null : snapshot.BySha1(c.Sha1);
                // Importing it means you want it: a block on it (or on its key) comes off first.
                if (snapshot != null)
                {
                    List<CertificateRecord> blocks = WithTwins(new CertificateRecord[] { onPc ?? c }).Where(snapshot.IsBlocked).ToList();
                    if (blocks.Count > 0) report.Add("unblocked " + c.SubjectShortName + ": " + LiftForGood(blocks, "imported from " + Path.GetFileName(path), "imported"));
                }
                if (c.Subject == c.Issuer)
                {
                    bool listed = windowsList.Contains(c.Sha1);
                    if (!listed && MessageBox.Show(this, c.SubjectShortName + "\r\nSHA-1 " + c.Sha1 + "\r\n\r\nWindows' own trusted-root list doesn't name this root. Put it into Trusted Root anyway? Only say yes if you know where the file came from.",
                        "Import root", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) { report.Add("skipped " + c.SubjectShortName + " (not on Windows' list)"); continue; }
                    try
                    {
                        if (scope == X509Location.LocalMachine) { using (OwnStore root = OwnStore.Open("Root", scope, true)) root.Add(der); }
                        else using (X509Store store = new X509Store(StoreName.Root, scope)) { store.Open(OpenFlags.ReadWrite); store.Add(new X509Certificate2(der)); }
                        BlockEngine.Note("import-root", scope, c.Sha256, c.Sha1, c.SubjectShortName, "imported from " + Path.GetFileName(path) + (listed ? " (on Windows' own root list)" : " (NOT on Windows' list, added by choice)"));
                        report.Add("root " + c.SubjectShortName + " into Trusted Root" + (scope == X509Location.LocalMachine ? " (whole PC)" : " (this user)") + (listed ? ", on Windows' own list" : ""));
                    }
                    catch (Exception ex) { report.Add(c.SubjectShortName + ": " + ex.Message); }
                }
                else if (IsCa(der)) cas.Add(c);
                else report.Add("skipped " + c.SubjectShortName + " (a site's own certificate, not a CA)");
            }
            if (cas.Count > 0)
                try { report.AddRange(RouteStore.Install(cas, scope, "imported from " + Path.GetFileName(path))); }
                catch (Exception ex) { report.Add("Intermediate CAs: " + ex.Message); }
            Say("Imported " + Path.GetFileName(path) + ": " + String.Join("; ", report.ToArray()));
            StartScan();
        }

        // The live map's menu, plus Import and Required for app everywhere (also on empty space).
        private ContextMenu MapMenuPlus(MapNode n, MapEdge edge)
        {
            ContextMenu m = MapMenu(n, edge) ?? new ContextMenu();
            if (m.MenuItems.Count > 0) m.MenuItems.Add("-");
            MenuItem import = new MenuItem("Import");
            import.MenuItems.Add("File...", delegate { ImportFromFile(); });
            m.MenuItems.Add(import);
            m.MenuItems.Add("Required for app...", delegate { ShowRequiredForApp(); });
            return m;
        }
    }
}
