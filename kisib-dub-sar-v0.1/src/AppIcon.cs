using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace Kisib
{
    // The kisib seal icon, embedded in the exe (assets\kisib.ico). Falls back to Windows' own icons if missing.
    internal static class AppIcon
    {
        private static Icon full;
        private static bool tried;

        internal static Icon Full
        {
            get
            {
                if (tried) return full;
                tried = true;
                try
                {
                    using (Stream s = typeof(AppIcon).Assembly.GetManifestResourceStream("Kisib.kisib.ico"))
                        if (s != null) full = new Icon(s);
                }
                catch (Exception) { full = null; }
                return full;
            }
        }

        internal static Icon Small
        {
            get
            {
                try { return Full == null ? null : new Icon(Full, SystemInformation.SmallIconSize); }
                catch (Exception) { return null; }
            }
        }
    }
}
