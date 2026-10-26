using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Kisib
{
    // An error anywhere used to close kisib. Now it is written to CRASH LOG.txt and kisib keeps running.
    internal static class CrashLog
    {
        private static readonly object gate = new object();
        private static int written;

        internal static void Write(string where, Exception ex)
        {
            try
            {
                lock (gate)
                {
                    if (written > 200) return;   // one bad loop can't fill the disk
                    written++;
                    string path = Storage.File(Storage.CrashLog);
                    FileInfo info = new FileInfo(path);
                    if (info.Exists && info.Length > 2 * 1024 * 1024) { File.Delete(path + ".old"); File.Move(path, path + ".old"); }
                    File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + where + "  " + AboutVersion() + "\r\n" + ex + "\r\n\r\n", new UTF8Encoding(false));
                }
            }
            catch (Exception) { }
        }

        private static string AboutVersion()
        {
            try { return "kisib " + Application.ProductVersion; } catch (Exception) { return "kisib"; }
        }

        internal static void Install()
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object sender, ThreadExceptionEventArgs e)
            {
                Write("window", e.Exception);
                ExplorerForm main = Application.OpenForms.Count > 0 ? Application.OpenForms[0] as ExplorerForm : null;
                if (main != null) try { main.Say("kisib hit an error and kept going: " + e.Exception.Message + " (written to " + Storage.CrashLog + ")"); } catch (Exception) { }
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
            {
                Exception ex = e.ExceptionObject as Exception;
                if (ex != null) Write("background", ex);
            };
        }
    }
}
