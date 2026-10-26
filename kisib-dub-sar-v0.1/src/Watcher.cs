using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Kisib
{
    // Rescan when Windows changes a certificate store (a root downloaded on demand, an update, kisib's own blocks),
    // instead of rescanning everything every minute. Windows keeps the stores in these registry keys.
    internal sealed class StoreWatcher : IDisposable
    {
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern int RegNotifyChangeKeyValue(SafeRegistryHandle key, [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, uint filter, SafeWaitHandle evt, [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
        private const uint REG_NOTIFY_CHANGE_NAME = 0x1, REG_NOTIFY_CHANGE_LAST_SET = 0x4;

        private readonly Action changed;
        private readonly ManualResetEvent stop = new ManualResetEvent(false);
        private Thread thread;
        internal string Status = "not started";

        internal StoreWatcher(Action changed) { this.changed = changed; }

        internal void Start()
        {
            if (thread != null) return;
            stop.Reset();
            thread = new Thread(Run) { IsBackground = true, Name = "Certificate store watcher" };
            thread.Start();
        }

        private void Run()
        {
            List<RegistryKey> keys = new List<RegistryKey>();
            List<AutoResetEvent> events = new List<AutoResetEvent>();
            try
            {
                foreach (KeyValuePair<RegistryKey, string> k in new KeyValuePair<RegistryKey, string>[] {
                    new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates"),
                    new KeyValuePair<RegistryKey, string>(Registry.CurrentUser, @"Software\Microsoft\SystemCertificates"),
                    new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\SystemCertificates"),
                    new KeyValuePair<RegistryKey, string>(Registry.CurrentUser, @"Software\Policies\Microsoft\SystemCertificates"),
                    new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Microsoft\EnterpriseCertificates") })
                {
                    try
                    {
                        RegistryKey key = k.Key.OpenSubKey(k.Value, false);
                        if (key == null) continue;
                        AutoResetEvent e = new AutoResetEvent(false);
                        if (RegNotifyChangeKeyValue(key.Handle, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, e.SafeWaitHandle, true) != 0) { key.Close(); e.Close(); continue; }
                        keys.Add(key); events.Add(e);
                    }
                    catch (Exception) { }
                }
                Status = keys.Count == 0 ? "could not watch the stores" : "watching " + keys.Count + " store locations";
                if (keys.Count == 0) return;
                WaitHandle[] handles = new WaitHandle[events.Count + 1];
                for (int i = 0; i < events.Count; i++) handles[i] = events[i];
                handles[events.Count] = stop;
                while (true)
                {
                    int hit = WaitHandle.WaitAny(handles);
                    if (hit == events.Count || hit == WaitHandle.WaitTimeout) break;
                    // A notification fires once; ask again before reporting so nothing in between is missed.
                    try { RegNotifyChangeKeyValue(keys[hit].Handle, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, events[hit].SafeWaitHandle, true); } catch (Exception) { }
                    try { changed(); } catch (Exception) { }
                }
            }
            catch (Exception ex) { Status = "stopped: " + ex.Message; }
            finally
            {
                foreach (RegistryKey k in keys) try { k.Close(); } catch (Exception) { }
                foreach (AutoResetEvent e in events) try { e.Close(); } catch (Exception) { }
            }
        }

        public void Dispose() { stop.Set(); }
    }
}
