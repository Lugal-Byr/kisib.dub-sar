using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Kisib
{
    // Live map: program -> site -> intermediate CA(s) -> root, drawn as boxes and arrows, fed by every certificate check
    // Windows logs in CAPI2. Green = trusted, red = refused, grey = side check or revocation not checked.
    internal sealed class MapNode
    {
        internal string Key, Label, Detail, Sha1, Program, Site, Placeholder, Service;
        internal readonly List<string> Sha1s = new List<string>();   // boxes with the same name are one box
        internal int Column, Hits;
        internal DateTime Last;
        internal bool Blocked, Refused, Web, Files;
        internal Denial LastDenial;   // the latest refusal that went through this box
        internal RectangleF Box;
    }

    internal sealed class MapEdge
    {
        internal MapNode From, To;
        internal int Ok, Bad, Grey;
        internal DateTime Last;
        internal bool LastBad, LastGrey, Web, Files;
        internal Denial LastDenial, LastAny;
        internal PointF A, B, C1, C2;   // drawn curve, for clicking on it
        internal bool Drawn;
    }

    internal sealed class MapCanvas : Panel
    {
        internal MapCanvas() { DoubleBuffered = true; ResizeRedraw = true; BackColor = Color.White; }
    }

    internal sealed class LiveMap : Form
    {
        private static readonly string[] ColumnNames = { "Programs", "Sites / signed files", "Intermediate CAs", "Roots" };
        private readonly Dictionary<string, MapNode> nodes = new Dictionary<string, MapNode>(StringComparer.Ordinal);
        private readonly Dictionary<string, MapEdge> edges = new Dictionary<string, MapEdge>(StringComparer.Ordinal);
        private readonly List<string> lines = new List<string>();
        private readonly MapCanvas canvas = new MapCanvas { Dock = DockStyle.Fill };
        private readonly CheckBox onlyRefused = new CheckBox { Text = "Only refused", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
        private readonly CheckBox paused = new CheckBox { Text = "Pause", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
        private readonly RadioButton showWeb = new RadioButton { Text = "Websites", AutoSize = true, Checked = true, Padding = new Padding(0, 4, 0, 0) };
        private readonly RadioButton showFiles = new RadioButton { Text = "Signed files", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
        private readonly RadioButton showBoth = new RadioButton { Text = "Both", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
        private readonly Button showAll = new Button { Text = "Show all programs", AutoSize = true, Visible = false };
        private readonly Label info = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        private readonly Func<string, string> describe;
        private readonly Func<string, bool> isBlocked;
        private readonly Func<string, string> siteLabel;
        private readonly Timer repaint = new Timer { Interval = 1000 };
        private MapNode hover, selected, focusProgram;
        private MapEdge hoverEdge;
        private bool dirty = true;
        private int adds;
        private DateTime lastFadeDraw;

        internal LiveMap(Func<string, string> describe, Func<string, bool> isBlocked, Func<string, string> siteLabel, Action<MapNode> open,
            Func<MapNode, MapEdge, ContextMenu> buildMenu, string status)
        {
            this.describe = describe; this.isBlocked = isBlocked; this.siteLabel = siteLabel;
            Text = "kisib — live certificate map"; Size = new Size(1300, 760); StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Tahoma", 8.5F);
            FlowLayoutPanel bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, Padding = new Padding(4), WrapContents = false };
            Button clear = new Button { Text = "Clear", AutoSize = true };
            Button copy = new Button { Text = "Copy as text", AutoSize = true };
            clear.Click += delegate { nodes.Clear(); edges.Clear(); lines.Clear(); selected = hover = focusProgram = null; showAll.Visible = false; Dirty(); };
            copy.Click += delegate { ExplorerForm.CopyText(String.Join("\r\n", lines.ToArray())); };
            showAll.Click += delegate { focusProgram = null; showAll.Visible = false; Dirty(); };
            foreach (Control c in new Control[] { onlyRefused, showWeb, showFiles, showBoth })
            {
                CheckBox box = c as CheckBox; RadioButton radio = c as RadioButton;
                if (box != null) box.CheckedChanged += delegate { Dirty(); };
                if (radio != null) radio.CheckedChanged += delegate { Dirty(); };
            }
            info.Text = status;
            bar.Controls.AddRange(new Control[] { paused, onlyRefused, new Label { Text = "  Show:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, showWeb, showFiles, showBoth, clear, copy, showAll, info });
            Label legend = new Label { Dock = DockStyle.Bottom, Height = 22, Padding = new Padding(6, 4, 0, 0),
                Text = "Green = trusted   Red = refused (drawn on top)   Grey = side check / not checked   Red box = blocked   Dashed box = not on this PC.   Hover to follow a path, click to keep it lit, double-click for details, right-click a box or an arrow for actions." };
            Controls.Add(canvas); Controls.Add(bar); Controls.Add(legend);
            canvas.Paint += delegate(object s, PaintEventArgs e) { Draw(e.Graphics); };
            canvas.MouseMove += delegate(object s, MouseEventArgs e)
            {
                MapNode h = Hit(e.Location);
                MapEdge he = h == null ? HitEdge(e.Location) : null;
                if (h != hover || he != hoverEdge) { hover = h; hoverEdge = he; Dirty(); }
            };
            canvas.MouseLeave += delegate { if (hover != null || hoverEdge != null) { hover = null; hoverEdge = null; Dirty(); } };
            canvas.MouseClick += delegate(object s, MouseEventArgs e)
            {
                MapNode n = Hit(e.Location);
                MapEdge edge = n == null ? HitEdge(e.Location) : null;
                if (e.Button == MouseButtons.Right)
                {
                    ContextMenu menu = buildMenu(n, edge);
                    if (menu != null && menu.MenuItems.Count > 0) menu.Show(canvas, e.Location);
                    return;
                }
                selected = n == selected ? null : n;
                Dirty();
            };
            canvas.MouseDoubleClick += delegate(object s, MouseEventArgs e) { MapNode n = Hit(e.Location); if (n != null) open(n); };
            repaint.Tick += delegate
            {
                // Redraw only when something changed, or while a fresh arrow is still pulsing/fading.
                DateTime now = DateTime.Now;
                bool fresh = edges.Values.Any(x => (now - x.Last).TotalSeconds < 15);
                if (dirty || fresh || (now - lastFadeDraw).TotalSeconds >= 20) { dirty = false; lastFadeDraw = now; canvas.Invalidate(); }
            };
            repaint.Start();
            FormClosed += delegate { repaint.Stop(); repaint.Dispose(); };
        }

        private void Dirty() { dirty = true; canvas.Invalidate(); }
        internal void SetStatus(string text) { info.Text = text; }

        internal void FocusProgram(MapNode program)
        {
            focusProgram = program; showAll.Visible = program != null; selected = program; Dirty();
        }

        internal IEnumerable<MapEdge> EdgesOf(MapNode n) { return edges.Values.Where(e => e.From == n || e.To == n); }

        // After a block, unblock or allow: recolor the boxes from the new scan.
        internal void RefreshBlocked()
        {
            foreach (MapNode n in nodes.Values)
                if (n.Sha1s.Count > 0) { n.Blocked = n.Sha1s.Any(isBlocked); string d = describe(n.Sha1s[0]); if (d != null) n.Detail = d; }
            Dirty();
        }

        internal void Add(Denial d)
        {
            if (paused.Checked) return;
            bool bad = !d.Ok && !d.Noise, grey = d.Noise;
            bool web = d.IsWeb;
            string exe = Path.GetFileName(d.Program ?? "");
            MapNode program = Node("p:" + exe + (d.Service != null ? "|" + d.Service : ""), 0, exe, null);
            program.Program = d.Program; program.Service = d.Service;
            if (d.Service != null) program.Detail = d.Service;
            List<MapNode> path = new List<MapNode> { program };
            int count = d.ChainSha1.Count;
            for (int i = 0; i < count; i++)
            {
                int column = i == 0 ? 1 : i == count - 1 ? 3 : 2;
                string name = i < d.ChainNames.Count && d.ChainNames[i].Length > 0 ? d.ChainNames[i] : d.ChainSha1[i].Substring(0, 12);
                // Same name in the same column = one box ("Microsoft Time-Stamp Service" is many certificates, one name).
                MapNode n = Node("c" + column + ":" + name.ToLowerInvariant(), column, name, d.ChainSha1[i]);
                if (column == 1) { n.Site = d.Site ?? d.Subject; string label = siteLabel(n.Site); if (label != null) n.Detail = label; }
                path.Add(n);
            }
            if (count == 0)
            {
                MapNode site = Node("c1:" + (d.Subject ?? "").ToLowerInvariant(), 1, d.Subject, null);
                site.Site = d.Site ?? d.Subject;
                string label = siteLabel(site.Site); if (label != null) site.Detail = label;
                path.Add(site);
            }
            // A refusal with nothing above the site: draw what is missing, so there is something to click.
            if (bad && path.Count <= 2)
            {
                string kind = d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase) ? "root missing (not trusted on this PC)" :
                    d.Code.EndsWith("92010", StringComparison.OrdinalIgnoreCase) || d.Code.EndsWith("B0111", StringComparison.OrdinalIgnoreCase) ? "a blocked CA (in Disallowed)" : "CA not on this PC";
                MapNode ph = Node("x:" + kind, 3, kind, null);
                ph.Placeholder = kind;
                path.Add(ph);
            }
            foreach (MapNode n in path)
            {
                n.Hits++; n.Last = d.Time;
                if (web) n.Web = true; else n.Files = true;
                if (bad) { n.Refused = true; n.LastDenial = d; }
            }
            for (int i = 0; i + 1 < path.Count; i++)
            {
                string key = path[i].Key + ">" + path[i + 1].Key;
                MapEdge edge;
                if (!edges.TryGetValue(key, out edge)) { edge = new MapEdge { From = path[i], To = path[i + 1] }; edges.Add(key, edge); }
                if (bad) { edge.Bad++; edge.LastDenial = d; } else if (grey) edge.Grey++; else edge.Ok++;
                if (web) edge.Web = true; else edge.Files = true;
                edge.Last = d.Time; edge.LastBad = bad; edge.LastGrey = grey; edge.LastAny = d;
            }
            lines.Add(d.Time.ToString("HH:mm:ss") + "  " + String.Join(" → ", path.Select(p => p.Label + (p.Service != null ? " (" + p.Service + ")" : "")).ToArray()) +
                "  [" + (d.Ok ? "trusted" : d.Reason) + "]");
            if (lines.Count > 2000) lines.RemoveAt(0);
            if (++adds % 50 == 0) Prune();
            dirty = true;
        }

        // Keep the last hour: older arrows and boxes go, so the map stays readable and light.
        private void Prune()
        {
            DateTime cut = DateTime.Now.AddHours(-1);
            foreach (string k in edges.Where(e => e.Value.Last < cut).Select(e => e.Key).ToList()) edges.Remove(k);
            HashSet<MapNode> used = new HashSet<MapNode>(edges.Values.SelectMany(e => new[] { e.From, e.To }));
            foreach (string k in nodes.Where(n => !used.Contains(n.Value)).Select(n => n.Key).ToList()) nodes.Remove(k);
            if (selected != null && !used.Contains(selected)) selected = null;
            if (focusProgram != null && !used.Contains(focusProgram)) { focusProgram = null; showAll.Visible = false; }
        }

        private MapNode Node(string key, int column, string label, string sha1)
        {
            MapNode n;
            if (!nodes.TryGetValue(key, out n)) { n = new MapNode { Key = key, Column = column, Label = label, Sha1 = sha1 }; nodes.Add(key, n); }
            if (sha1 != null && !n.Sha1s.Contains(sha1))
            {
                n.Sha1s.Add(sha1);
                if (isBlocked(sha1)) n.Blocked = true;
                if (n.Detail == null || column >= 2) { string d = describe(sha1); if (d != null) n.Detail = d; }
            }
            return n;
        }

        internal MapNode Hit(Point p) { return nodes.Values.FirstOrDefault(n => n.Box.Contains(p)); }

        // An arrow is clickable along its whole curve.
        private MapEdge HitEdge(Point p)
        {
            MapEdge best = null; double bestDistance = 6;
            foreach (MapEdge e in edges.Values.Where(x => x.Drawn))
                for (int i = 0; i <= 24; i++)
                {
                    double t = i / 24.0, u = 1 - t;
                    double x = u * u * u * e.A.X + 3 * u * u * t * e.C1.X + 3 * u * t * t * e.C2.X + t * t * t * e.B.X;
                    double y = u * u * u * e.A.Y + 3 * u * u * t * e.C1.Y + 3 * u * t * t * e.C2.Y + t * t * t * e.B.Y;
                    double dist = Math.Sqrt((x - p.X) * (x - p.X) + (y - p.Y) * (y - p.Y));
                    if (dist < bestDistance) { bestDistance = dist; best = e; }
                }
            return best;
        }

        internal string NodeText(MapNode n)
        {
            StringBuilder t = new StringBuilder(n.Label).Append("\r\n");
            if (n.Service != null) t.Append("Service: ").Append(n.Service).Append("\r\n");
            if (n.Detail != null && n.Detail != n.Service) t.Append(n.Detail).Append("\r\n");
            if (n.Sha1s.Count > 1) t.Append(n.Sha1s.Count).Append(" certificates with this name\r\n");
            t.Append("Seen ").Append(n.Hits).Append(" times, last ").Append(n.Last.ToString("HH:mm:ss")).Append("\r\n");
            foreach (MapEdge e in EdgesOf(n))
                t.Append(e.From.Label).Append(" → ").Append(e.To.Label).Append("   trusted ").Append(e.Ok).Append(", refused ").Append(e.Bad).Append(", side check / not checked ").Append(e.Grey).Append("\r\n");
            return t.ToString();
        }

        // Everything connected to a box (or an arrow), upstream and downstream.
        private HashSet<object> Lit(HashSet<MapEdge> shown)
        {
            HashSet<object> lit = new HashSet<object>();
            MapNode start = hover ?? selected;
            if (hoverEdge != null) { lit.Add(hoverEdge); lit.Add(hoverEdge.From); lit.Add(hoverEdge.To); start = null; }
            if (start == null) return hoverEdge != null ? Grow(lit, shown) : null;
            lit.Add(start);
            return Grow(lit, shown);
        }
        private static HashSet<object> Grow(HashSet<object> lit, HashSet<MapEdge> shown)
        {
            // Downstream from the left, upstream from the right, so a path lights up end to end.
            List<MapNode> seeds = lit.OfType<MapNode>().ToList();
            foreach (MapNode s in seeds)
            {
                Queue<MapNode> down = new Queue<MapNode>(); down.Enqueue(s);
                while (down.Count > 0) { MapNode n = down.Dequeue(); foreach (MapEdge e in shown.Where(x => x.From == n)) if (lit.Add(e) | lit.Add(e.To)) down.Enqueue(e.To); }
                Queue<MapNode> up = new Queue<MapNode>(); up.Enqueue(s);
                while (up.Count > 0) { MapNode n = up.Dequeue(); foreach (MapEdge e in shown.Where(x => x.To == n)) if (lit.Add(e) | lit.Add(e.From)) up.Enqueue(e.From); }
            }
            return lit;
        }

        private void Draw(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            int width = canvas.ClientSize.Width, height = canvas.ClientSize.Height;
            float colWidth = width / 4f, boxW = Math.Min(250, colWidth - 50), boxH = 34, gap = 8, top = 30;
            using (Font bold = new Font(Font, FontStyle.Bold))
                for (int c = 0; c < 4; c++) g.DrawString(ColumnNames[c], bold, Brushes.DimGray, c * colWidth + 20, 6);
            DateTime now = DateTime.Now, cut = now.AddHours(-1);
            bool wantWeb = showWeb.Checked || showBoth.Checked, wantFiles = showFiles.Checked || showBoth.Checked;
            HashSet<MapEdge> shown = new HashSet<MapEdge>(edges.Values.Where(e => e.Last >= cut && (!onlyRefused.Checked || e.Bad > 0) && ((wantWeb && e.Web) || (wantFiles && e.Files))));
            if (focusProgram != null)
            {
                HashSet<MapEdge> keep = new HashSet<MapEdge>();
                Queue<MapNode> q = new Queue<MapNode>(); q.Enqueue(focusProgram);
                while (q.Count > 0) { MapNode n = q.Dequeue(); foreach (MapEdge e in shown.Where(x => x.From == n)) if (keep.Add(e)) q.Enqueue(e.To); }
                shown = keep;
            }
            HashSet<MapNode> visible = new HashSet<MapNode>(shown.SelectMany(e => new[] { e.From, e.To }));
            int perColumn = Math.Max(1, (int)((height - top) / (boxH + gap)));
            foreach (MapNode n in nodes.Values) n.Box = RectangleF.Empty;
            foreach (MapEdge e in edges.Values) e.Drawn = false;
            for (int c = 0; c < 4; c++)
            {
                List<MapNode> column = visible.Where(n => n.Column == c).OrderByDescending(n => n.Refused).ThenByDescending(n => n.Last).Take(perColumn).ToList();
                for (int i = 0; i < column.Count; i++) column[i].Box = new RectangleF(c * colWidth + 20, top + i * (boxH + gap), boxW, boxH);
            }
            HashSet<object> lit = Lit(shown);
            // Green and grey first, red last and thicker, so a refusal is never buried under trusted arrows.
            foreach (MapEdge e in shown.OrderBy(x => x.LastBad || x.Bad > 0 ? 1 : 0))
            {
                if (e.From.Box.IsEmpty || e.To.Box.IsEmpty) continue;
                double age = (now - e.Last).TotalSeconds;
                bool red = e.LastBad || (onlyRefused.Checked && e.Bad > 0) || (e.Bad > 0 && e.Ok == 0);
                int alpha = age < 15 ? 255 : (int)Math.Max(70, 255 - age / 20);
                if (lit != null && !lit.Contains(e)) alpha = 35;
                Color baseColor = red ? Color.Firebrick : e.LastGrey ? Color.Gray : Color.SeaGreen;
                float w = 1.5f + (float)Math.Log(1 + e.Ok + e.Bad + e.Grey, 2) + (red ? 1.5f : 0);
                if (age < 3) w += 3;   // just happened: pulse
                if (e == hoverEdge) w += 2;
                PointF a = new PointF(e.From.Box.Right, e.From.Box.Top + boxH / 2), b = new PointF(e.To.Box.Left, e.To.Box.Top + boxH / 2);
                float mid = (b.X - a.X) / 2;
                e.A = a; e.B = b; e.C1 = new PointF(a.X + mid, a.Y); e.C2 = new PointF(b.X - mid, b.Y); e.Drawn = true;
                using (Pen pen = new Pen(Color.FromArgb(alpha, baseColor), w) { CustomEndCap = new AdjustableArrowCap(4, 5) })
                    g.DrawBezier(pen, e.A, e.C1, e.C2, e.B);
            }
            using (StringFormat f = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap })
            using (Pen dashed = new Pen(Color.Gray, 1) { DashStyle = DashStyle.Dash })
                foreach (MapNode n in visible.Where(x => !x.Box.IsEmpty))
                {
                    bool dim = lit != null && !lit.Contains(n);
                    Color fill = n.Placeholder != null ? Color.White : n.Blocked ? Color.MistyRose : n.Column == 0 ? Color.AliceBlue : Color.FromArgb(250, 250, 240);
                    if (dim) fill = Color.FromArgb(120, fill);
                    using (Brush b = new SolidBrush(fill)) g.FillRectangle(b, n.Box);
                    bool notOnPc = n.Placeholder != null || (n.Column >= 2 && n.Sha1s.Count > 0 && n.Detail == null);
                    if (notOnPc) g.DrawRectangle(dashed, n.Box.X, n.Box.Y, n.Box.Width, n.Box.Height);
                    else using (Pen border = new Pen(n == hover || n == selected ? Color.Black : n.Refused ? Color.Firebrick : Color.Silver, n == hover || n == selected ? 2 : 1))
                        g.DrawRectangle(border, n.Box.X, n.Box.Y, n.Box.Width, n.Box.Height);
                    string second = (n.Detail ?? (notOnPc && n.Placeholder == null ? "not on this PC" : "")) + (n.Blocked ? "  BLOCKED" : "") +
                        (n.Sha1s.Count > 1 ? "  ·  " + n.Sha1s.Count + " certs" : "") + "  ·  " + n.Hits + "×";
                    RectangleF line1 = new RectangleF(n.Box.X + 4, n.Box.Y + 2, n.Box.Width - 8, 16), line2 = new RectangleF(n.Box.X + 4, n.Box.Y + 17, n.Box.Width - 8, 16);
                    using (Brush text = new SolidBrush(dim ? Color.Silver : Color.Black))
                    using (Brush sub = new SolidBrush(dim ? Color.Silver : n.Blocked || n.Placeholder != null ? Color.Firebrick : Color.DimGray))
                    {
                        g.DrawString(n.Label, Font, text, line1, f);
                        string tail = second.Trim(' ', '·');
                        // Bloc tags in color pictures instead of empty boxes.
                        if (EmojiText.Has(tail)) EmojiText.Draw(g, tail, Font, Rectangle.Round(line2), dim ? Color.Silver : n.Blocked || n.Placeholder != null ? Color.Firebrick : Color.DimGray);
                        else g.DrawString(tail, Font, sub, line2, f);
                    }
                }
            if (visible.Count == 0)
                g.DrawString(nodes.Count == 0 ? "Waiting for Windows certificate checks... open a website in Edge, run winget, or let Windows Update check." :
                    "Nothing to show with these switches (try Both, or untick Only refused).", Font, Brushes.Gray, 20, top + 10);
        }
    }

    internal sealed partial class ExplorerForm
    {
        private LiveMap liveMap;
        private readonly List<Denial> recentChecks = new List<Denial>();

        private CertificateRecord FindBySha1(string sha1) { return snapshot == null ? null : snapshot.BySha1(sha1); }

        private void InitializeLiveMap(MenuItem view)
        {
            view.MenuItems.Add(new MenuItem("Live certificate &map", delegate { OpenLiveMap(); }, Shortcut.CtrlM));
        }

        private void OpenLiveMap()
        {
            if (liveMap != null && !liveMap.IsDisposed) { liveMap.Activate(); return; }
            string status = denialWatcher == null ? "Watching is OFF: Watch > Watch for certificate denials (run as admin once)." : "Watching Windows certificate checks live.";
            liveMap = new LiveMap(
                delegate(string sha1)
                {
                    CertificateRecord c = FindBySha1(sha1);
                    if (c == null) return null;
                    string tags = TagsOf(c);
                    return "C=" + (c.SubjectCountry ?? "—") + (tags.Length > 0 ? "  " + tags : "");
                },
                delegate(string sha1) { CertificateRecord c = FindBySha1(sha1); return c != null && snapshot.IsBlocked(c); },
                delegate(string site) { string w = WhoIsWho.Site(site); if (w == null) return null; int eq = w.IndexOf(" = ", StringComparison.Ordinal); return eq < 0 ? w : "= " + w.Substring(eq + 3); },
                MapOpen, MapMenuPlus, status);
            foreach (Denial d in recentChecks) liveMap.Add(d);
            liveMap.Show(this);
        }

        private void MapAdd(Denial d)
        {
            try { AppChains.Record(d); } catch (Exception ex) { CrashLog.Write("required for app", ex); }
            recentChecks.Add(d);
            if (recentChecks.Count > 3000) recentChecks.RemoveRange(0, 500);
            if (liveMap != null && !liveMap.IsDisposed) liveMap.Add(d);
        }

        private void MapOpen(MapNode n)
        {
            CertificateRecord c = n.Sha1s.Select(FindBySha1).FirstOrDefault(x => x != null);
            if (c != null) ShowText("Certificate — " + c.SubjectShortName, CertificateCard(c) + "\r\n" + liveMap.NodeText(n));
            else if (n.LastDenial != null) OpenRefusalCard(n.LastDenial);
            else ShowText(n.Label, liveMap.NodeText(n));
        }

        // The blocked certificates behind a map box: the certificates with its name, plus their key twins.
        private List<CertificateRecord> MapCerts(MapNode n)
        {
            return n.Sha1s.Select(FindBySha1).Where(c => c != null).ToList();
        }

        // Right-click menus for the live map. Every menu has something to do and starts with a plain line saying what's going on.
        private ContextMenu MapMenu(MapNode n, MapEdge edge)
        {
            ContextMenu m = new ContextMenu();
            Action<string> line = delegate(string text) { m.MenuItems.Add(new MenuItem(text) { Enabled = false }); };
            if (n == null && edge == null) return null;
            if (n == null)
            {
                // An arrow: what happened on it, and the actions for its latest refusal.
                Denial d = edge.LastDenial;
                line(edge.From.Label + " → " + edge.To.Label + ":  trusted " + edge.Ok + ", refused " + edge.Bad + ", side check " + edge.Grey);
                if (d != null)
                {
                    line("Last refused " + d.Time.ToString("HH:mm:ss") + ": " + ShortReason(d.Reason) + (d.BlockedBy != null ? " (your block: " + d.BlockedBy + ")" : " (not your block)"));
                    m.MenuItems.Add("-");
                    RefusalItems(m, d);
                }
                else if (edge.LastAny != null && edge.LastAny.SideCheck)
                    line("Only side checks failed here; the connection went through.");
                m.MenuItems.Add("-");
                m.MenuItems.Add("Copy this connection", delegate { CopyText(edge.From.Label + " → " + edge.To.Label + "  trusted " + edge.Ok + ", refused " + edge.Bad + ", side check " + edge.Grey); });
                return m;
            }
            if (n.Column == 0)
            {
                string exe = Path.GetFileName(n.Program ?? n.Label);
                line(WhoIsWho.Program(exe) ?? exe + " = (not in your who-is-who list)");
                if (n.Service != null) line("service: " + n.Service);
                m.MenuItems.Add("-");
                if (IsBroker(n.Program))
                    m.MenuItems.Add("Find the app behind it (open connections right now)...", delegate
                    {
                        MapEdge last = liveMap.EdgesOf(n).Where(e => e.From == n && e.LastAny != null).OrderByDescending(e => e.Last).FirstOrDefault();
                        if (last == null) { Say("No site seen from " + exe + " yet."); return; }
                        Denial probe = last.LastDenial ?? last.LastAny;
                        Say("Looking for the app behind " + exe + " (talking to " + probe.Subject + ")...");
                        System.Threading.Thread worker = new System.Threading.Thread(delegate()
                        {
                            string found; try { found = AppBehind(probe); } catch (Exception ex) { found = "Could not look: " + ex.Message; }
                            Post(delegate { ShowText("App behind " + exe, found); });
                        }) { IsBackground = true };
                        worker.Start();
                    });
                m.MenuItems.Add("Show only this program's paths", delegate { liveMap.FocusProgram(n); });
                m.MenuItems.Add("Open in Programs (who listens, who signed it)", delegate { ShowPrograms(); });
                m.MenuItems.Add("Quiet this program's pop-ups for 1 hour", delegate { QuietSites.Quiet("program:" + exe, TimeSpan.FromHours(1)); Say("No pop-ups from " + exe + " for an hour; refusals are still logged."); });
                m.MenuItems.Add("-");
                m.MenuItems.Add("Copy name", delegate { CopyText(exe + (n.Service != null ? " (" + n.Service + ")" : "")); });
                return m;
            }
            if (n.Placeholder != null)
            {
                line("Not a certificate on this PC: " + n.Placeholder);
                line(n.Placeholder.StartsWith("root missing", StringComparison.Ordinal) ? "Not your block: the root at the top is not trusted here and Windows couldn't fetch it." :
                    n.Placeholder.StartsWith("a blocked", StringComparison.Ordinal) ? "A CA above the site is in Disallowed but isn't in kisib's lists by name." : "Windows didn't log the chain for this one.");
                m.MenuItems.Add("-");
                m.MenuItems.Add("Repair: Get online (roots kisib carries)...", delegate { RepairSeals("Get online", s => s.Set == "online" || s.Set == "microsoft", "The roots most websites hang under."); });
                m.MenuItems.Add("Repair: Windows essentials...", delegate { RepairSeals("Windows essentials", s => s.IsMicrosoft, "Microsoft's own roots only."); });
                m.MenuItems.Add("Repair: What this PC uses...", delegate { RepairUsed(); });
                if (n.LastDenial != null) { m.MenuItems.Add("-"); RefusalItems(m, n.LastDenial); }
                return m;
            }
            List<CertificateRecord> certs = MapCerts(n);
            if (n.Column == 1)
            {
                line(n.Label + (n.Detail != null && n.Detail.StartsWith("=", StringComparison.Ordinal) ? "  " + n.Detail : ""));
                Denial d = n.LastDenial;
                if (d != null)
                {
                    line("Refused " + d.Time.ToString("HH:mm:ss") + ": " + ShortReason(d.Reason) + (d.BlockedBy != null ? " (your block: " + d.BlockedBy + ")" : " (not your block)"));
                    m.MenuItems.Add("-");
                    RefusalItems(m, d);
                }
                else line(n.Refused ? "Refused earlier" : "Trusted");
                // The CA right above the site.
                MapEdge up = liveMap.EdgesOf(n).Where(e => e.From == n && e.To.Sha1s.Count > 0).OrderByDescending(e => e.Last).FirstOrDefault();
                if (up != null)
                {
                    MapNode issuer = up.To;
                    List<CertificateRecord> issuerCerts = MapCerts(issuer);
                    m.MenuItems.Add("-");
                    if (issuer.Blocked && issuerCerts.Count > 0)
                        m.MenuItems.Add(AllowSubmenu("Allow the CA that signed it (" + issuer.Label + ")", delegate { return MapTarget(issuer, issuerCerts); }));
                    else if (issuerCerts.Count > 0)
                        m.MenuItems.Add("Block the CA that signed it (" + issuer.Label + ")...", delegate { ShowBlockDialog(issuerCerts, delegate { return "blocked from the live map"; }, "CA " + issuer.Label, null); });
                }
                m.MenuItems.Add("-");
                m.MenuItems.Add("Quiet this site's pop-ups for 1 hour", delegate { QuietSites.Quiet(n.Site ?? n.Label, TimeSpan.FromHours(1)); Say("No pop-ups for " + (n.Site ?? n.Label) + " for an hour; refusals are still logged."); });
                m.MenuItems.Add("Copy name", delegate { CopyText(n.Label); });
                m.MenuItems.Add("Copy connections", delegate { CopyText(liveMap.NodeText(n)); });
                return m;
            }
            // A CA or a root.
            if (certs.Count == 0)
            {
                line(n.Label + ": not on this PC or in kisib's lists (the site sent it).");
                line("Block or allow the CA above it instead, or load Tools > Update CCADB list so kisib knows it.");
                m.MenuItems.Add("-");
                if (n.Column == 3 && n.Sha1s.Count > 0)
                {
                    List<string> wanted = new List<string>(n.Sha1s);
                    m.MenuItems.Add("Get " + n.Label + " from Microsoft (what Windows would download)", delegate { FetchFromMicrosoft(x => wanted.Contains(x.Sha1, StringComparer.OrdinalIgnoreCase), n.Label); });
                }
                m.MenuItems.Add("Copy SHA-1", delegate { CopyText(String.Join("\r\n", n.Sha1s.ToArray())); });
                return m;
            }
            CertificateRecord c = certs[0];
            string guard = TrustCategories.ProtectedBy(c);
            line(n.Label + (c.SubjectCountry != null ? " (" + c.SubjectCountry + ")" : "") + "  ·  " + OwnerName(c) + (certs.Count > 1 ? "  ·  " + certs.Count + " certificates" : ""));
            bool missingRoot = !n.Blocked && c.Subject == c.Issuer && !TrustGraph.InRootStore(c);
            line(n.Blocked ? "Blocked: " + WhyLine(c) : missingRoot ? "Not your block: this root isn't in Trusted Root here, and Windows didn't download it" + (RootAutoUpdateOff() ? " (its automatic root download is switched off)" : "") :
                guard != null ? "Trusted, protected by trusted category " + guard : "Trusted");
            m.MenuItems.Add("-");
            if (missingRoot)
                m.MenuItems.Add("Get " + c.SubjectShortName + " from Microsoft (what Windows would download)", delegate { FetchFromMicrosoft(x => certs.Any(y => String.Equals(y.Sha1, x.Sha1, StringComparison.OrdinalIgnoreCase)), c.SubjectShortName); });
            if (n.Blocked)
            {
                m.MenuItems.Add(AllowSubmenu("Allow", delegate { return MapTarget(n, certs); }));
                m.MenuItems.Add("Unblock for good (rules won't put it back)", delegate { UnblockCertificates(certs, "unblock from live map"); });
                m.MenuItems.Add("Why is it blocked?", delegate { ShowText("Why — " + c.SubjectShortName, WhyBlockedText(c)); });
            }
            else
            {
                m.MenuItems.Add("Block this certificate...", delegate { ShowBlockDialog(certs, delegate { return "blocked from the live map"; }, "certificate " + c.SubjectShortName, null); });
                foreach (GroupNode g in groups == null ? new List<GroupNode>() : groups.Tags.Where(t => t.Members.Contains(c.Identity)).ToList())
                {
                    GroupNode bloc = g;
                    m.MenuItems.Add("Block its whole bloc (" + bloc.Label + ")...", delegate
                    {
                        ShowBlockDialog(bloc.Members.Select(id => snapshot.Certificates[id]).ToList(), delegate { return "bloc " + bloc.Label; }, bloc.Label, new List<GroupNode> { bloc }, true);
                    });
                }
                m.MenuItems.Add("What breaks if I block it...", delegate { ShowText("If you block " + c.SubjectShortName, WhatBreaks(n, certs)); });
            }
            m.MenuItems.Add("Who vouches for it (paths, cross-signs)...", delegate { ShowText("Paths — " + c.SubjectShortName, PathsReport(c)); });
            m.MenuItems.Add("Show in main list", delegate
            {
                RestoreFromTray(); leftTabs.SelectedTab = storesTab;
                if (tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0];
                findIssuer.Text = c.Sha256;
            });
            m.MenuItems.Add("-");
            m.MenuItems.Add("Copy name", delegate { CopyText(n.Label); });
            m.MenuItems.Add("Copy SHA-1", delegate { CopyText(String.Join("\r\n", n.Sha1s.ToArray())); });
            return m;
        }

        private AllowTarget MapTarget(MapNode n, List<CertificateRecord> certs)
        {
            return new AllowTarget { Label = n.Label, Certs = delegate { return snapshot == null ? new List<CertificateRecord>() : WithTwins(certs).Where(snapshot.IsBlocked).ToList(); },
                NothingWhy = "Nothing to allow: " + n.Label + " is not blocked" };
        }

        // The actions for one refusal, shared by arrows, sites and placeholders.
        private void RefusalItems(ContextMenu m, Denial d)
        {
            m.MenuItems.Add("Open refusal card", delegate { OpenRefusalCard(d); });
            m.MenuItems.Add("Get what it asked for (unblock, import, or fetch the root)", delegate { GetRequested(d); });
            m.MenuItems.Add(AllowSubmenu("Allow", delegate { return TargetFor(d); }));
            m.MenuItems.Add("Why was it refused?", delegate { ShowText("Why — " + d.Subject, ExplainDenial(d)); });
            m.MenuItems.Add("Reroute around the block...", delegate
            {
                List<CertificateRecord> missing;
                List<CertificateRecord> route = DenialRoute(d, out missing);
                if (route == null) { Say("No other path for " + d.Subject + ": the CA that signed it has no cross-sign to a root you trust. Only Allow gets it through."); return; }
                if (missing.Count == 0) { Say("The other path for " + d.Subject + " is already on this PC; Windows should take it on the next try."); return; }
                InstallRoute(missing, d.Subject);
            });
            if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase))
                m.MenuItems.Add("Get " + MissingRootName(d) + " from Microsoft (what Windows would download)", delegate { FetchRoot(d); });
            if (d.Code.EndsWith("B0109", StringComparison.OrdinalIgnoreCase))
                m.MenuItems.Add("Repair: Get online (roots kisib carries)...", delegate { RepairSeals("Get online", s => s.Set == "online" || s.Set == "microsoft", "The roots most websites hang under."); });
        }

        // One line on why a certificate is blocked: kisib's rule, an earlier block, or Microsoft's list.
        private string WhyLine(CertificateRecord c)
        {
            if (snapshot != null && !snapshot.KisibBlockedSha1.Contains(c.Sha1)) return "it was in Disallowed before kisib";
            if (groups != null)
            {
                List<string> rules = BlockRules.Read().Select(r => r.GroupKey).ToList();
                GroupNode g = groups.All.FirstOrDefault(x => rules.Contains(x.Key) && x.Members.Contains(c.Identity));
                if (g != null) return "your " + g.Label + " rule";
            }
            return "kisib blocked it";
        }

        // Sites and programs seen under a CA or root on the live map, plus what loses its path.
        private string WhatBreaks(MapNode n, List<CertificateRecord> certs)
        {
            StringBuilder t = new StringBuilder();
            HashSet<string> sites = new HashSet<string>(StringComparer.OrdinalIgnoreCase), programs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Denial d in recentChecks.Where(x => x.ChainSha1.Any(s => n.Sha1s.Contains(s, StringComparer.OrdinalIgnoreCase))))
            { sites.Add(d.Site ?? d.Subject); programs.Add(Path.GetFileName(d.Program) + (d.Service != null ? " (" + d.Service + ")" : "")); }
            t.AppendLine("Seen under " + n.Label + " since kisib started: " + sites.Count + " sites or signed files, from " + programs.Count + " programs.");
            foreach (string s in sites.OrderBy(x => x).Take(60)) t.AppendLine("  " + s + (WhoIsWho.Site(s) != null ? "   " + WhoIsWho.Site(s) : ""));
            if (sites.Count > 60) t.AppendLine("  +" + (sites.Count - 60) + " more");
            t.AppendLine();
            t.AppendLine("Programs: " + String.Join(", ", programs.OrderBy(x => x).ToArray()));
            string guard = certs.Select(TrustCategories.ProtectedBy).FirstOrDefault(x => x != null);
            if (guard != null) t.AppendLine("\r\nPROTECTED by trusted category " + guard + ": blocking it breaks that category.");
            string whatIfLine;
            string whatIf = RerouteWhatIf(WithTwins(certs), out whatIfLine);
            if (whatIf.Length > 0) { t.AppendLine(); t.AppendLine(whatIf); }
            return t.ToString();
        }
    }
}
