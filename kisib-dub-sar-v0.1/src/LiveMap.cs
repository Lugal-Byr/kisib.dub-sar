using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // Live map: program -> site certificate -> intermediate CA(s) -> root, drawn as boxes and arrows,
    // fed by every certificate check Windows logs in CAPI2. Green = trusted, red = refused, grey = could not check revocation.
    internal sealed class MapNode
    {
        internal string Key, Label, Detail, Sha1;
        internal int Column, Hits;
        internal DateTime Last;
        internal bool Blocked, Refused;
        internal RectangleF Box;
    }

    internal sealed class MapEdge
    {
        internal MapNode From, To;
        internal int Ok, Bad, Grey;
        internal DateTime Last;
        internal bool LastBad, LastGrey;
    }

    internal sealed class MapCanvas : Panel
    {
        internal MapCanvas() { DoubleBuffered = true; ResizeRedraw = true; BackColor = Color.White; }
    }

    internal sealed class LiveMap : Form
    {
        private static readonly string[] ColumnNames = { "Programs", "Sites (certificate presented)", "Intermediate CAs", "Roots" };
        private readonly Dictionary<string, MapNode> nodes = new Dictionary<string, MapNode>(StringComparer.Ordinal);
        private readonly Dictionary<string, MapEdge> edges = new Dictionary<string, MapEdge>(StringComparer.Ordinal);
        private readonly List<string> lines = new List<string>();
        private readonly MapCanvas canvas = new MapCanvas { Dock = DockStyle.Fill };
        private readonly CheckBox onlyRefused = new CheckBox { Text = "Only refused", AutoSize = true };
        private readonly CheckBox paused = new CheckBox { Text = "Pause", AutoSize = true };
        private readonly Label info = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        private readonly Func<string, string> describe;
        private readonly Func<string, bool> isBlocked;
        private readonly Action<string> openCertificate;
        private readonly Action<string, string> act;
        private readonly Timer repaint = new Timer { Interval = 1000 };
        private MapNode hover;

        internal LiveMap(Func<string, string> describe, Func<string, bool> isBlocked, Action<string> openCertificate, Action<string, string> act, string status)
        {
            this.describe = describe; this.isBlocked = isBlocked; this.openCertificate = openCertificate; this.act = act;
            Text = "kisib — live certificate map"; Size = new Size(1300, 760); StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Tahoma", 8.5F);
            FlowLayoutPanel bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, Padding = new Padding(4) };
            Button clear = new Button { Text = "Clear", AutoSize = true };
            Button copy = new Button { Text = "Copy as text", AutoSize = true };
            clear.Click += delegate { nodes.Clear(); edges.Clear(); lines.Clear(); canvas.Invalidate(); };
            copy.Click += delegate { ExplorerForm.CopyText(String.Join("\r\n", lines.ToArray())); };
            onlyRefused.CheckedChanged += delegate { canvas.Invalidate(); };
            info.Text = status;
            bar.Controls.AddRange(new Control[] { paused, onlyRefused, clear, copy, info });
            Label legend = new Label { Dock = DockStyle.Bottom, Height = 22, Padding = new Padding(6, 4, 0, 0),
                Text = "Green = trusted   Red = refused   Grey = revocation could not be checked   Red box = in your Disallowed list   Thicker = more often   Faded = older.   Click a box for details; right-click to block, unblock, allow or copy." };
            Controls.Add(canvas); Controls.Add(bar); Controls.Add(legend);
            canvas.Paint += delegate(object s, PaintEventArgs e) { Draw(e.Graphics); };
            canvas.MouseMove += delegate(object s, MouseEventArgs e) { MapNode h = Hit(e.Location); if (h != hover) { hover = h; canvas.Invalidate(); } };
            canvas.MouseClick += delegate(object s, MouseEventArgs e)
            {
                MapNode n = Hit(e.Location); if (n == null) return;
                if (e.Button == MouseButtons.Right) { NodeMenu(n).Show(canvas, e.Location); return; }
                if (n.Sha1 != null) openCertificate(n.Sha1);
                else MessageBox.Show(this, NodeText(n), n.Label);
            };
            repaint.Tick += delegate { canvas.Invalidate(); };
            repaint.Start();
            FormClosed += delegate { repaint.Stop(); repaint.Dispose(); };
        }

        internal void SetStatus(string text) { info.Text = text; }

        // After a block, unblock or allow: recolor the boxes from the new scan.
        internal void RefreshBlocked()
        {
            foreach (MapNode n in nodes.Values) if (n.Sha1 != null) { n.Blocked = isBlocked(n.Sha1); string d = describe(n.Sha1); if (d != null) n.Detail = d; }
            canvas.Invalidate();
        }

        internal void Add(Denial d)
        {
            if (paused.Checked) return;
            bool bad = !d.Ok && !d.Noise, grey = d.Noise;
            List<MapNode> path = new List<MapNode> { Node("p:" + d.Program, 0, d.Program, null, null) };
            int count = d.ChainSha1.Count;
            for (int i = 0; i < count; i++)
            {
                int column = i == 0 ? 1 : i == count - 1 ? 3 : 2;
                if (count == 1) column = 1;
                string name = i < d.ChainNames.Count && d.ChainNames[i].Length > 0 ? d.ChainNames[i] : d.ChainSha1[i].Substring(0, 12);
                path.Add(Node("c:" + d.ChainSha1[i], column, name, d.ChainSha1[i], describe(d.ChainSha1[i])));
            }
            if (count == 0) path.Add(Node("s:" + d.Subject, 1, d.Subject, null, null));
            foreach (MapNode n in path) { n.Hits++; n.Last = d.Time; if (bad) n.Refused = true; }
            for (int i = 0; i + 1 < path.Count; i++)
            {
                string key = path[i].Key + ">" + path[i + 1].Key;
                MapEdge edge;
                if (!edges.TryGetValue(key, out edge)) { edge = new MapEdge { From = path[i], To = path[i + 1] }; edges.Add(key, edge); }
                if (bad) edge.Bad++; else if (grey) edge.Grey++; else edge.Ok++;
                edge.Last = d.Time; edge.LastBad = bad; edge.LastGrey = grey;
            }
            lines.Add(d.Time.ToString("HH:mm:ss") + "  " + String.Join(" → ", path.Select(p => p.Label).ToArray()) + "  [" + (d.Ok ? "trusted" : d.Reason) + "]");
            if (lines.Count > 2000) lines.RemoveAt(0);
        }

        private MapNode Node(string key, int column, string label, string sha1, string detail)
        {
            MapNode n;
            if (!nodes.TryGetValue(key, out n)) { n = new MapNode { Key = key, Column = column, Label = label, Sha1 = sha1 }; nodes.Add(key, n); }
            if (detail != null) n.Detail = detail;
            if (sha1 != null) n.Blocked = isBlocked(sha1);
            return n;
        }

        private MapNode Hit(Point p) { return nodes.Values.FirstOrDefault(n => n.Box.Contains(p)); }

        private string NodeText(MapNode n)
        {
            StringBuilder t = new StringBuilder(n.Label).Append("\r\n");
            if (n.Detail != null) t.Append(n.Detail).Append("\r\n");
            t.Append("Seen ").Append(n.Hits).Append(" times, last ").Append(n.Last.ToString("HH:mm:ss")).Append("\r\n");
            foreach (MapEdge e in edges.Values.Where(x => x.From == n || x.To == n))
                t.Append(e.From.Label).Append(" → ").Append(e.To.Label).Append("   trusted ").Append(e.Ok).Append(", refused ").Append(e.Bad).Append(", unchecked ").Append(e.Grey).Append("\r\n");
            return t.ToString();
        }

        private ContextMenu NodeMenu(MapNode n)
        {
            ContextMenu m = new ContextMenu();
            bool known = n.Sha1 != null && n.Detail != null;
            if (n.Sha1 != null && n.Column >= 2 || known)
            {
                if (n.Blocked)
                {
                    m.MenuItems.Add("Why is it blocked? (groups, rules, who blocked it)", delegate { act(n.Sha1, "why"); });
                    foreach (int minutes in new int[] { 3, 10, 60 }) { string verb = "allow" + minutes; m.MenuItems.Add("Allow for " + minutes + " minutes", delegate { act(n.Sha1, verb); }); }
                    m.MenuItems.Add("Allow always...", delegate { act(n.Sha1, "always"); });
                    m.MenuItems.Add("Unblock (kisib's own block)", delegate { act(n.Sha1, "unblock"); });
                }
                else m.MenuItems.Add("Block this certificate...", delegate { act(n.Sha1, "block"); });
                m.MenuItems.Add("Who vouches for it (paths, cross-signs)...", delegate { act(n.Sha1, "paths"); });
                m.MenuItems.Add("Show in main list", delegate { act(n.Sha1, "list"); });
                m.MenuItems.Add("-");
            }
            else if (n.Column == 1)
            {
                MapEdge up = edges.Values.Where(e => e.From == n && e.To.Sha1 != null).OrderByDescending(e => e.Last).FirstOrDefault();
                if (up != null)
                {
                    MapNode issuer = up.To;
                    m.MenuItems.Add(issuer.Blocked ? "Allow the CA that signed it for 10 minutes (" + issuer.Label + ")" : "Block the CA that signed it (" + issuer.Label + ")...",
                        delegate { act(issuer.Sha1, issuer.Blocked ? "allow10" : "block"); });
                    m.MenuItems.Add("-");
                }
            }
            m.MenuItems.Add("Copy name", delegate { ExplorerForm.CopyText(n.Label); });
            m.MenuItems.Add("Copy connections", delegate { ExplorerForm.CopyText(NodeText(n)); });
            if (n.Sha1 != null) m.MenuItems.Add("Copy SHA-1", delegate { ExplorerForm.CopyText(n.Sha1); });
            if (n.Sha1 != null) m.MenuItems.Add("Open certificate", delegate { openCertificate(n.Sha1); });
            return m;
        }

        private void Draw(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            int width = canvas.ClientSize.Width, height = canvas.ClientSize.Height;
            float colWidth = width / 4f, boxW = Math.Min(250, colWidth - 50), boxH = 34, gap = 8, top = 30;
            using (Font bold = new Font(Font, FontStyle.Bold))
                for (int c = 0; c < 4; c++) g.DrawString(ColumnNames[c], bold, Brushes.DimGray, c * colWidth + 20, 6);
            HashSet<MapEdge> shown = new HashSet<MapEdge>(edges.Values.Where(e => !onlyRefused.Checked || e.Bad > 0));
            HashSet<MapNode> visible = new HashSet<MapNode>(onlyRefused.Checked ? shown.SelectMany(e => new[] { e.From, e.To }) : nodes.Values);
            int perColumn = Math.Max(1, (int)((height - top) / (boxH + gap)));
            foreach (MapNode n in nodes.Values) n.Box = RectangleF.Empty;
            for (int c = 0; c < 4; c++)
            {
                List<MapNode> column = visible.Where(n => n.Column == c).OrderByDescending(n => n.Refused).ThenByDescending(n => n.Last).Take(perColumn).ToList();
                for (int i = 0; i < column.Count; i++) column[i].Box = new RectangleF(c * colWidth + 20, top + i * (boxH + gap), boxW, boxH);
            }
            DateTime now = DateTime.Now;
            foreach (MapEdge e in shown)
            {
                if (e.From.Box.IsEmpty || e.To.Box.IsEmpty) continue;
                double age = (now - e.Last).TotalSeconds;
                int alpha = age < 10 ? 255 : (int)Math.Max(50, 255 - age / 2);
                Color baseColor = e.LastBad || (onlyRefused.Checked && e.Bad > 0) ? Color.Firebrick : e.LastGrey ? Color.Gray : Color.SeaGreen;
                float w = 1.5f + (float)Math.Log(1 + e.Ok + e.Bad + e.Grey, 2);
                if (age < 3) w += 3;   // just happened: pulse
                using (Pen pen = new Pen(Color.FromArgb(alpha, baseColor), w) { CustomEndCap = new AdjustableArrowCap(4, 5) })
                {
                    PointF a = new PointF(e.From.Box.Right, e.From.Box.Top + boxH / 2), b = new PointF(e.To.Box.Left, e.To.Box.Top + boxH / 2);
                    float mid = (b.X - a.X) / 2;
                    g.DrawBezier(pen, a, new PointF(a.X + mid, a.Y), new PointF(b.X - mid, b.Y), b);
                }
            }
            foreach (MapNode n in visible.Where(x => !x.Box.IsEmpty))
            {
                Color fill = n.Blocked ? Color.MistyRose : n.Column == 0 ? Color.AliceBlue : Color.FromArgb(250, 250, 240);
                using (Brush b = new SolidBrush(fill)) g.FillRectangle(b, n.Box);
                using (Pen border = new Pen(n == hover ? Color.Black : n.Refused ? Color.Firebrick : Color.Silver, n == hover ? 2 : 1)) g.DrawRectangle(border, n.Box.X, n.Box.Y, n.Box.Width, n.Box.Height);
                string second = (n.Detail ?? "") + (n.Blocked ? "  BLOCKED" : "") + "  ·  " + n.Hits + "×";
                RectangleF line1 = new RectangleF(n.Box.X + 4, n.Box.Y + 2, n.Box.Width - 8, 16), line2 = new RectangleF(n.Box.X + 4, n.Box.Y + 17, n.Box.Width - 8, 16);
                using (StringFormat f = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap })
                {
                    g.DrawString(n.Label, Font, Brushes.Black, line1, f);
                    g.DrawString(second.Trim(' ', '·'), Font, n.Blocked ? Brushes.Firebrick : Brushes.DimGray, line2, f);
                }
            }
            if (nodes.Count == 0)
                g.DrawString("Waiting for Windows certificate checks... open a website in Edge, run winget, or curl something.", Font, Brushes.Gray, 20, top + 10);
        }
    }

    internal sealed partial class ExplorerForm
    {
        private LiveMap liveMap;
        private readonly List<Denial> recentChecks = new List<Denial>();
        private Snapshot sha1Source;
        private Dictionary<string, CertificateRecord> bySha1;

        private CertificateRecord FindBySha1(string sha1)
        {
            if (snapshot == null) return null;
            if (sha1Source != snapshot)
            {
                bySha1 = new Dictionary<string, CertificateRecord>(StringComparer.OrdinalIgnoreCase);
                foreach (CertificateRecord c in snapshot.Certificates.Values) bySha1[c.Sha1] = c;
                sha1Source = snapshot;
            }
            CertificateRecord found; return bySha1.TryGetValue(sha1, out found) ? found : null;
        }

        private void InitializeLiveMap(MenuItem view)
        {
            view.MenuItems.Add(new MenuItem("Live certificate &map", delegate { OpenLiveMap(); }, Shortcut.CtrlM));
        }

        private void OpenLiveMap()
        {
            if (liveMap != null && !liveMap.IsDisposed) { liveMap.Activate(); return; }
            string status = denialWatcher == null ? "Watching is OFF: View > Watch for certificate denials (run as admin once)." : "Watching Windows certificate checks live.";
            liveMap = new LiveMap(
                delegate(string sha1)
                {
                    CertificateRecord c = FindBySha1(sha1);
                    if (c == null) return null;
                    string tags = TagsOf(c);
                    return "C=" + (c.SubjectCountry ?? "—") + (tags.Length > 0 ? "  " + tags : "");
                },
                delegate(string sha1) { CertificateRecord c = FindBySha1(sha1); return c != null && snapshot != null && GroupCatalog.BlockedIdentities(snapshot).Contains(c.Identity); },
                delegate(string sha1)
                {
                    CertificateRecord c = FindBySha1(sha1);
                    ShowText("Certificate " + sha1, c != null ? CertificateCard(c) : "SHA-1 " + sha1 + "\r\nNot in any scanned store on this PC (Windows got it from the site or downloaded it).");
                },
                MapAct,
                status);
            foreach (Denial d in recentChecks) liveMap.Add(d);
            liveMap.Show(this);
        }

        // Right-click actions from the live map.
        private void MapAct(string sha1, string verb)
        {
            CertificateRecord c = FindBySha1(sha1);
            if (c == null) { ShowText("Live map", "This certificate is not in any store on this PC (the site sent it), so kisib can't block it directly.\r\nRight-click the CA above it instead."); return; }
            HashSet<string> blocked = snapshot == null ? new HashSet<string>() : GroupCatalog.BlockedIdentities(snapshot);
            List<CertificateRecord> sameKey = snapshot.Certificates.Values.Where(x => blocked.Contains(x.Identity) && (x == c || (c.SpkiSha256 != null && x.SpkiSha256 == c.SpkiSha256))).ToList();
            switch (verb)
            {
                case "block": ShowBlockDialog(new List<CertificateRecord> { c }, delegate { return "blocked from the live map"; }, "certificate " + c.SubjectShortName, null); break;
                case "unblock": UnblockCertificates(sameKey.Count > 0 ? sameKey : new List<CertificateRecord> { c }, "unblock from live map"); break;
                case "allow3": AllowTemporarily(sameKey, c.SubjectShortName, TimeSpan.FromMinutes(3), true); break;
                case "allow10": AllowTemporarily(sameKey, c.SubjectShortName, TimeSpan.FromMinutes(10), true); break;
                case "allow60": AllowTemporarily(sameKey, c.SubjectShortName, TimeSpan.FromMinutes(60), true); break;
                case "always": AllowAlways(sameKey, c.SubjectShortName); break;
                case "why": ShowText("Why — " + c.SubjectShortName, WhyBlockedText(c)); break;
                case "paths": ShowText("Paths — " + c.SubjectShortName, PathsReport(c)); break;
                case "list":
                    RestoreFromTray(); leftTabs.SelectedTab = storesTab;
                    if (tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0];
                    findIssuer.Text = c.Sha256;
                    break;
            }
        }

        private void MapAdd(Denial d)
        {
            recentChecks.Add(d);
            if (recentChecks.Count > 1000) recentChecks.RemoveAt(0);
            if (liveMap != null && !liveMap.IsDisposed) liveMap.Add(d);
        }
    }
}
