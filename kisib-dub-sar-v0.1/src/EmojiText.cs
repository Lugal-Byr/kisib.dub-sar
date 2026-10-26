using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Kisib
{
    // Tahoma has no emoji, so 👑 🏛️ 🧱 🌿 💃 came out as boxes. Text with emoji is drawn in runs:
    // the emoji in Segoe UI Emoji, everything else in the control's own font.
    internal static class EmojiText
    {
        private static readonly Dictionary<float, Font> fonts = new Dictionary<float, Font>();
        private const TextFormatFlags Flags = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.Left | TextFormatFlags.VerticalCenter;

        private static Font EmojiFont(float size)
        {
            Font f;
            if (!fonts.TryGetValue(size, out f)) { f = new Font("Segoe UI Emoji", size, GraphicsUnit.Point); fonts[size] = f; }
            return f;
        }

        private static bool IsEmoji(int cp)
        {
            return cp >= 0x1F000 || (cp >= 0x2600 && cp <= 0x27BF) || (cp >= 0x2B00 && cp <= 0x2BFF) || cp == 0xFE0F || cp == 0x200D || cp == 0x2122;
        }

        internal static bool Has(string text)
        {
            if (String.IsNullOrEmpty(text)) return false;
            for (int i = 0; i < text.Length; i++)
            {
                if (Char.IsHighSurrogate(text[i]) && i + 1 < text.Length) { if (IsEmoji(Char.ConvertToUtf32(text[i], text[i + 1]))) return true; i++; }
                else if (IsEmoji(text[i])) return true;
            }
            return false;
        }

        private static List<KeyValuePair<bool, string>> Runs(string text)
        {
            List<KeyValuePair<bool, string>> runs = new List<KeyValuePair<bool, string>>();
            int start = 0; bool? current = null;
            for (int i = 0; i < text.Length; )
            {
                int len = Char.IsHighSurrogate(text[i]) && i + 1 < text.Length ? 2 : 1;
                int cp = len == 2 ? Char.ConvertToUtf32(text[i], text[i + 1]) : text[i];
                bool emoji = IsEmoji(cp) || (text[i] == ' ' && current.HasValue && current.Value && i + 1 < text.Length && Has(text.Substring(i + 1, Math.Min(2, text.Length - i - 1))));
                if (current.HasValue && emoji != current.Value) { runs.Add(new KeyValuePair<bool, string>(current.Value, text.Substring(start, i - start))); start = i; }
                current = emoji;
                i += len;
            }
            if (current.HasValue) runs.Add(new KeyValuePair<bool, string>(current.Value, text.Substring(start)));
            return runs;
        }

        internal static void Draw(Graphics g, string text, Font font, Rectangle bounds, Color color)
        {
            if (!Has(text)) { TextRenderer.DrawText(g, text, font, bounds, color, Flags | TextFormatFlags.EndEllipsis); return; }
            GraphicsState saved = g.Save();
            g.SetClip(bounds, CombineMode.Intersect);
            int x = bounds.X;
            foreach (KeyValuePair<bool, string> run in Runs(text))
            {
                Font f = run.Key ? EmojiFont(font.SizeInPoints) : font;
                Rectangle r = new Rectangle(x, bounds.Y, Math.Max(0, bounds.Right - x), bounds.Height);
                TextRenderer.DrawText(g, run.Value, f, r, color, Flags);
                x += TextRenderer.MeasureText(g, run.Value, f, new Size(Int32.MaxValue, bounds.Height), Flags).Width;
                if (x >= bounds.Right) break;
            }
            g.Restore(saved);
        }

        internal static void DrawLines(Graphics g, string[] lines, Font font, Rectangle bounds, Color color)
        {
            int line = font.Height + 2, y = bounds.Y + Math.Max(0, (bounds.Height - line * lines.Length) / 2);
            foreach (string text in lines) { Draw(g, text, font, new Rectangle(bounds.X, y, bounds.Width, line), color); y += line; }
        }

        // Owner-draw for a tree: only nodes with emoji are drawn by hand.
        internal static void AttachTo(TreeView tree)
        {
            tree.DrawMode = TreeViewDrawMode.OwnerDrawText;
            tree.DrawNode += delegate(object sender, DrawTreeNodeEventArgs e)
            {
                if (e.Bounds.IsEmpty || !Has(e.Node.Text)) { e.DrawDefault = true; return; }
                bool selected = (e.State & TreeNodeStates.Selected) != 0;
                Font font = e.Node.NodeFont ?? tree.Font;
                Rectangle area = new Rectangle(e.Bounds.X, e.Bounds.Y, Math.Max(e.Bounds.Width, tree.ClientSize.Width - e.Bounds.X), e.Bounds.Height);
                int width = 6;
                foreach (KeyValuePair<bool, string> run in Runs(e.Node.Text))
                    width += TextRenderer.MeasureText(e.Graphics, run.Value, run.Key ? EmojiFont(font.SizeInPoints) : font, new Size(Int32.MaxValue, area.Height), Flags).Width;
                Rectangle back = new Rectangle(area.X, area.Y, Math.Min(width, area.Width), area.Height);
                Color fore = selected && tree.Focused ? SystemColors.HighlightText : e.Node.ForeColor.IsEmpty ? tree.ForeColor : e.Node.ForeColor;
                if (selected) using (Brush b = new SolidBrush(tree.Focused ? SystemColors.Highlight : SystemColors.Control)) e.Graphics.FillRectangle(b, back);
                Draw(e.Graphics, e.Node.Text, font, new Rectangle(area.X + 2, area.Y, area.Width - 2, area.Height), fore);
            };
        }

        // Owner-draw for one column of a details ListView; the other cells draw normally.
        internal static void AttachTo(ListView grid, params int[] columns)
        {
            grid.OwnerDraw = true;
            grid.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e) { e.DrawDefault = true; };
            grid.DrawSubItem += delegate(object sender, DrawListViewSubItemEventArgs e)
            {
                if (Array.IndexOf(columns, e.ColumnIndex) < 0 || !Has(e.SubItem.Text)) { e.DrawDefault = true; return; }
                bool selected = e.Item.Selected;
                Color back = selected ? SystemColors.Highlight : e.Item.UseItemStyleForSubItems ? e.Item.BackColor : e.SubItem.BackColor;
                Color fore = selected ? SystemColors.HighlightText : e.Item.UseItemStyleForSubItems ? e.Item.ForeColor : e.SubItem.ForeColor;
                using (Brush b = new SolidBrush(back)) e.Graphics.FillRectangle(b, e.Bounds);
                Draw(e.Graphics, e.SubItem.Text, grid.Font, new Rectangle(e.Bounds.X + 4, e.Bounds.Y, Math.Max(0, e.Bounds.Width - 8), e.Bounds.Height), fore);
            };
        }
    }
}
