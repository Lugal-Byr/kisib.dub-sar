using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Kisib
{
    // Pin each actual directory without FILE_SHARE_DELETE. Validate the opened
    // file handle before reading/writing; checking only a pathname is racy.
    internal sealed class ArchiveFileSystem : IDisposable
    {
        private readonly object gate = new object();
        private readonly Dictionary<string, SafeFileHandle> directories = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        private readonly string root;
        private bool disposed;
        internal ArchiveFileSystem(string root)
        {
            this.root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            try { PinDirectory(this.root); } catch { Dispose(); throw; }
        }
        private string Confined(string path)
        {
            string full = Path.GetFullPath(path);
            if (!full.Equals(root, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Archive path is outside the selected history directory.");
            return full;
        }
        internal void PinDirectory(string directory)
        {
            lock (gate)
            {
                if (disposed) throw new ObjectDisposedException("ArchiveFileSystem");
                string full = Confined(directory), drive = Path.GetPathRoot(full);
                if (drive.Length != 3 || drive[1] != ':' || drive[2] != '\\') throw new IOException("History requires a local Windows drive; network/device paths are unsupported.");
                List<string> paths = new List<string> { drive };
                string current = drive;
                foreach (string part in full.Substring(drive.Length).Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
                { current = Path.Combine(current, part); paths.Add(current); }
                foreach (string path in paths)
                {
                    if (directories.ContainsKey(path)) continue;
                    // Each parent is already pinned. Create only this next component.
                    if (!Directory.Exists(path)) Directory.CreateDirectory(path);
                    SafeFileHandle handle = CreateFileW(path, 0, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
                    if (handle.IsInvalid) { int code = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException("Cannot pin history directory: " + path, new Win32Exception(code)); }
                    try { Validate(handle, path, true); directories.Add(path, handle); }
                    catch { handle.Dispose(); throw; }
                }
            }
        }
        internal FileStream Open(string path, FileMode mode, FileAccess access, FileShare share)
        {
            if (mode == FileMode.Create || mode == FileMode.Truncate || mode == FileMode.Append) throw new InvalidOperationException("Destructive archive open mode is unsupported.");
            lock (gate)
            {
                string full = Confined(path); PinDirectory(Path.GetDirectoryName(full));
                FileStream file = new FileStream(full, mode, access, share & ~FileShare.Delete);
                try { Validate(file.SafeFileHandle, full, false); return file; }
                catch { file.Dispose(); throw; }
            }
        }
        internal byte[] ReadBytes(string path, int limit)
        {
            using (FileStream file = Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length > limit) throw new IOException("Archive object exceeds the explicit byte size limit; original file retained.");
                byte[] bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int read = file.Read(bytes, offset, bytes.Length - offset); if (read == 0) throw new EndOfStreamException("Archive object changed during read."); offset += read; }
                return bytes;
            }
        }
        private static void Validate(SafeFileHandle handle, string expected, bool directory)
        {
            FileInformation info;
            if (!GetFileInformationByHandle(handle, out info)) throw new IOException("History handle metadata unavailable.", new Win32Exception(Marshal.GetLastWin32Error()));
            if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || !directory && info.NumberOfLinks != 1)
                throw new IOException("History refuses reparse points, unexpected object types, and multiply linked files.");
            StringBuilder name = new StringBuilder(512); uint count = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
            if (count >= name.Capacity && count < 32768) { name = new StringBuilder((int)count + 1); count = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0); }
            if (count == 0 || count >= name.Capacity) throw new IOException("History handle final path unavailable.", new Win32Exception(Marshal.GetLastWin32Error()));
            string actual = name.ToString(); if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            if (!actual.TrimEnd('\\').Equals(Path.GetFullPath(expected).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException("History handle resolves through an unexpected file link or path.");
        }
        public void Dispose()
        { lock (gate) { if (disposed) return; disposed = true; foreach (SafeFileHandle handle in directories.Values) handle.Dispose(); directories.Clear(); } }
        [StructLayout(LayoutKind.Sequential)] private struct FileInformation
        {
            internal uint Attributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            internal uint VolumeSerial, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    }
}
