using System;
using System.IO;
using System.Windows.Forms;

namespace Kisib
{
    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException("kisib.dub-sar v0.1 requires Windows.");
            string directory = Environment.GetEnvironmentVariable("KISIB_SOURCE_DIR");
            if (String.IsNullOrEmpty(directory))
            {
                directory = AppDomain.CurrentDomain.BaseDirectory;
                if (!Directory.Exists(Path.Combine(directory, "docs"))) directory = Path.GetFullPath(Path.Combine(directory, ".."));
            }
            // Native classic controls: no web view, card shell, or modern theme override.
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ExplorerForm(directory));
        }
    }
}
