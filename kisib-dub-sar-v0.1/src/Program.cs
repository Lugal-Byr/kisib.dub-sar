using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException("kisib.dub-sar v0.1 requires Windows.");
            // kisib.dub-sar.exe --do "status": ask the running kisib (Claude uses this from the desktop app).
            if (args != null && args.Length > 0 && args[0].Equals("--do", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = CommandClient.Run(String.Join(" ", args.Skip(1).ToArray()));
                return;
            }
            string directory = Environment.GetEnvironmentVariable("KISIB_SOURCE_DIR");
            if (String.IsNullOrEmpty(directory))
            {
                directory = AppDomain.CurrentDomain.BaseDirectory;
                if (!Directory.Exists(Path.Combine(directory, "docs"))) directory = Path.GetFullPath(Path.Combine(directory, ".."));
            }
            // Native classic controls: no web view, card shell, or modern theme override.
            Application.SetCompatibleTextRenderingDefault(false);
            CrashLog.Install();
            // One kisib at a time: starting it again just opens the one already in the tray.
            bool first = true;
            Mutex single = null;
            try { single = new Mutex(true, @"Local\kisib.dub-sar", out first); }
            catch (UnauthorizedAccessException) { first = false; }
            if (!first)
            {
                try { using (EventWaitHandle show = EventWaitHandle.OpenExisting(@"Local\kisib.dub-sar.show")) show.Set(); }
                catch (Exception) { MessageBox.Show("kisib is already running (look for the seal in the tray, next to the clock).", "kisib.dub-sar"); }
                return;
            }
            // So a command line (or Claude) can find this copy of kisib wherever it was unzipped.
            try
            {
                string where = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "kisib.dub-sar");
                Directory.CreateDirectory(where);
                File.WriteAllText(Path.Combine(where, "where is kisib.txt"), Application.ExecutablePath + "\r\n");
            }
            catch (Exception) { }
            ExplorerForm form = new ExplorerForm(directory);
            // Opening a .cer/.crt/.p7b/.sst with kisib shows it read-only; nothing is installed.
            foreach (string arg in args ?? new string[0])
            {
                if (arg == "--tray") form.StartInTray = true;
                else if (form.PendingFile == null && File.Exists(arg)) form.PendingFile = Path.GetFullPath(arg);
            }
            Application.Run(form);
            GC.KeepAlive(single);
        }
    }
}
