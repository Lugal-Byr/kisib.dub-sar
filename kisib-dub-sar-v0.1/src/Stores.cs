using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // One store at one location, without the others Windows mixes in.
    // A normal "this user" store also shows the whole PC's certificates; changing one of those needs admin and used to
    // fail halfway through a list. Opening only the registry part means kisib sees exactly what it can change.
    internal sealed class OwnStore : IDisposable
    {
        internal readonly X509Store Store;
        internal readonly X509Location Scope;
        private readonly Dictionary<string, X509Certificate2> byThumb = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

        private OwnStore(X509Store store, X509Location scope)
        {
            Store = store; Scope = scope;
            // Read the store once. Asking the store again for every certificate made big blocks take minutes.
            foreach (X509Certificate2 c in store.Certificates) { if (!byThumb.ContainsKey(c.Thumbprint)) byThumb.Add(c.Thumbprint, c); else c.Reset(); }
        }

        internal static OwnStore Open(string storeName, X509Location scope, bool write)
        {
            uint flags = (scope == X509Location.LocalMachine ? Native.CERT_SYSTEM_STORE_LOCAL_MACHINE : Native.CERT_SYSTEM_STORE_CURRENT_USER) |
                (write ? 0u : Native.CERT_STORE_READONLY_FLAG);
            using (StoreHandle handle = Native.CertOpenStore(Native.CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, IntPtr.Zero, flags, storeName))
            {
                int error = Marshal.GetLastWin32Error();
                if (handle == null || handle.IsInvalid)
                    throw new Win32Exception(error, (scope == X509Location.LocalMachine ? "Whole PC" : "This user") + " \\" + storeName + ": " + new Win32Exception(error).Message +
                        (scope == X509Location.LocalMachine && write ? " (run kisib as administrator)" : ""));
                // X509Store duplicates the handle; ours closes when this block ends.
                return new OwnStore(new X509Store(handle.DangerousGetHandle()), scope);
            }
        }

        internal static OwnStore TryOpen(string storeName, X509Location scope, bool write, out string error)
        {
            error = null;
            try { return Open(storeName, scope, write); }
            catch (Exception ex) { error = ex.Message; return null; }
        }

        internal bool Has(string sha1) { return sha1 != null && byThumb.ContainsKey(sha1); }
        internal int Count { get { return byThumb.Count; } }
        internal IEnumerable<string> Thumbprints { get { return byThumb.Keys; } }

        internal bool Add(byte[] der)
        {
            using (X509Certificate2 cert = new X509Certificate2(der))
            {
                if (byThumb.ContainsKey(cert.Thumbprint)) return false;
                Store.Add(cert);
                byThumb.Add(cert.Thumbprint, new X509Certificate2(der));
                return true;
            }
        }

        internal bool Remove(string sha1)
        {
            X509Certificate2 found;
            if (sha1 == null || !byThumb.TryGetValue(sha1, out found)) return false;
            Store.Remove(found);
            byThumb.Remove(sha1);
            found.Reset();
            return true;
        }

        internal byte[] RawData(string sha1)
        {
            X509Certificate2 found;
            return sha1 != null && byThumb.TryGetValue(sha1, out found) ? found.RawData : null;
        }

        public void Dispose()
        {
            foreach (X509Certificate2 c in byThumb.Values) c.Reset();
            byThumb.Clear();
            Store.Close();
        }
    }

    internal static class Elevation
    {
        private static bool? elevated;
        internal static bool IsElevated
        {
            get
            {
                if (!elevated.HasValue)
                {
                    try { using (System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                        elevated = new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); }
                    catch (Exception) { elevated = false; }
                }
                return elevated.Value;
            }
        }
    }
}
