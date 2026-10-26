using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Kisib
{
    // svchost.exe is one name for dozens of Windows services. This names the service actually running in that svchost,
    // from Windows' service list (which service runs in which process).
    internal static class ServiceNames
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW", ExactSpelling = true)]
        private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "EnumServicesStatusExW", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumServicesStatusEx(IntPtr manager, int infoLevel, uint serviceType, uint serviceState, IntPtr buffer, uint bufferSize,
            out uint bytesNeeded, out uint returned, ref uint resume, string group);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS
        {
            internal uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ENUM_SERVICE_STATUS_PROCESS
        {
            internal IntPtr lpServiceName, lpDisplayName;
            internal SERVICE_STATUS_PROCESS Status;
        }

        private static Dictionary<int, List<string>> byPid = new Dictionary<int, List<string>>();
        private static DateTime read = DateTime.MinValue;

        // "Windows Update (wuauserv)", or null when the program isn't svchost or the service can't be found.
        internal static string For(string program, int pid)
        {
            if (pid <= 0 || !String.Equals(Path.GetFileName(program ?? ""), "svchost.exe", StringComparison.OrdinalIgnoreCase)) return null;
            List<string> names;
            if ((!byPid.TryGetValue(pid, out names) && (DateTime.UtcNow - read).TotalSeconds > 5) || (DateTime.UtcNow - read).TotalMinutes > 2)
            {
                Refresh();
                byPid.TryGetValue(pid, out names);
            }
            if (names == null || names.Count == 0) return null;
            return String.Join(", ", names.Take(2).ToArray()) + (names.Count > 2 ? " +" + (names.Count - 2) : "");
        }

        private static void Refresh()
        {
            read = DateTime.UtcNow;
            Dictionary<int, List<string>> map = new Dictionary<int, List<string>>();
            IntPtr manager = OpenSCManager(null, null, 0x0004);   // SC_MANAGER_ENUMERATE_SERVICE
            if (manager == IntPtr.Zero) return;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint needed, returned, resume = 0;
                EnumServicesStatusEx(manager, 0, 0x30, 1, IntPtr.Zero, 0, out needed, out returned, ref resume, null);   // SERVICE_WIN32, SERVICE_ACTIVE
                if (needed == 0 || needed > 8 * 1024 * 1024) return;
                uint size = needed + 4096;
                buffer = Marshal.AllocHGlobal((int)size);
                resume = 0;
                if (!EnumServicesStatusEx(manager, 0, 0x30, 1, buffer, size, out needed, out returned, ref resume, null)) return;
                int step = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));
                for (int i = 0; i < (int)returned; i++)
                {
                    ENUM_SERVICE_STATUS_PROCESS e = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(IntPtr.Add(buffer, i * step), typeof(ENUM_SERVICE_STATUS_PROCESS));
                    int pid = (int)e.Status.dwProcessId;
                    if (pid <= 0) continue;
                    string name = Marshal.PtrToStringUni(e.lpServiceName) ?? "", display = Marshal.PtrToStringUni(e.lpDisplayName) ?? name;
                    List<string> list;
                    if (!map.TryGetValue(pid, out list)) { list = new List<string>(); map.Add(pid, list); }
                    list.Add(display == name ? name : display + " (" + name + ")");
                }
                byPid = map;
            }
            catch (Exception) { }
            finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); CloseServiceHandle(manager); }
        }
    }
}
