using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;

namespace Kisib
{
    internal sealed class Scanner
    {
        private readonly Snapshot snapshot = new Snapshot();
        private readonly Action<string> progress;
        private readonly Func<bool> canceled;
        internal string ScanId { get { return snapshot.ScanId; } }

        internal Scanner(Action<string> progress, Func<bool> canceled)
        {
            this.progress = progress;
            this.canceled = canceled;
        }
        internal Scanner(Action<string> progress, Func<bool> canceled, HistoryArchive history)
            : this(progress, canceled)
        {
            if (history != null)
            {
                snapshot.EventSink = history.Note;
                snapshot.RawCertificateSink = history.CaptureBytes;
                snapshot.CertificateSink = history.Observe;
            }
        }
        internal Snapshot Run()
        {
            snapshot.Note("Start", Environment.MachineName, "Read-only system store enumeration; no application network fetch or chain building. Native provider behavior: to test.");
            EnumerateLocations();
            foreach (StoreLocation location in snapshot.Locations)
            {
                if (canceled()) break;
                EnumerateSystems(location, null);
                foreach (SystemStore store in location.Stores)
                {
                    if (canceled()) break;
                    progress("Reading " + store.Path);
                    EnumeratePhysical(location, store);
                    string collectionError = ReadStore(location, store, null);
                    store.Error = collectionError;
                    store.ReadSucceeded = collectionError == null;
                    foreach (PhysicalStore physical in store.PhysicalStores)
                    {
                        if (canceled()) break;
                        progress("Reading " + physical.Path);
                        physical.Error = ReadStore(location, store, physical);
                        physical.ReadSucceeded = physical.Error == null;
                    }
                }
            }
            CertificateSignals.Evaluate(snapshot.Certificates.Values);
            snapshot.Note("Certificate metadata signals", "All observed certificate records", "RSA <2048 / MD5 or SHA-1 signature; SHA-1 collision; SPKI key reuse [to test]");
            snapshot.Canceled = canceled();
            snapshot.Finished = DateTime.UtcNow;
            snapshot.Note("Finish", Environment.MachineName,
                snapshot.StoreCount + " system stores; " + snapshot.PhysicalCount + " physical stores; " +
                snapshot.Certificates.Count + " distinct certificates; " + snapshot.Errors.Count + " errors; " +
                snapshot.UnresolvedCount + " certificates with unresolved physical sources" + (snapshot.Canceled ? "; canceled" : "."));
            return snapshot;
        }

        private void EnumerateLocations()
        {
            snapshot.Note("CertEnumSystemStoreLocation", "Local computer", "Enumeration requested.");
            Native.LocationCallback callback = delegate(IntPtr name, uint flags, IntPtr reserved, IntPtr arg)
            {
                if (canceled()) return false;
                try
                {
                    uint locationFlag = flags & Native.CERT_SYSTEM_STORE_LOCATION_MASK;
                    if (snapshot.Locations.Any(item => item.Flags == locationFlag)) return true;
                    string windowsName = Marshal.PtrToStringUni(name) ?? "[unnamed location]";
                    snapshot.Locations.Add(new StoreLocation
                    {
                        WindowsName = windowsName, Flags = locationFlag, Name = StorePaths.Name(locationFlag, windowsName),
                        RegistryPath = StorePaths.Location(locationFlag), Enumerated = true
                    });
                    snapshot.Note("CertEnumSystemStoreLocation", windowsName, "Returned location 0x" + locationFlag.ToString("X8", CultureInfo.InvariantCulture));
                    return true;
                }
                catch (Exception ex) { snapshot.Fail("Location callback", "[unknown]", ex.Message); return false; }
            };
            bool success = Native.CertEnumSystemStoreLocation(0, IntPtr.Zero, callback);
            int error = Marshal.GetLastWin32Error();
            GC.KeepAlive(callback);
            if (!success && !canceled()) snapshot.Fail("CertEnumSystemStoreLocation", "Local computer", Snapshot.WindowsError(error));

            // These are API locations, not fabricated store contents. An unreturned location stays labeled.
            uint[] documented = {
                Native.CERT_SYSTEM_STORE_LOCAL_MACHINE, Native.CERT_SYSTEM_STORE_CURRENT_USER,
                Native.CERT_SYSTEM_STORE_CURRENT_SERVICE, Native.CERT_SYSTEM_STORE_SERVICES,
                Native.CERT_SYSTEM_STORE_USERS, Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
                Native.CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY, Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
            };
            foreach (uint flag in documented)
                if (!snapshot.Locations.Any(item => item.Flags == flag))
                    snapshot.Locations.Add(new StoreLocation { Flags = flag, Name = StorePaths.Name(flag, "[unknown]"),
                        WindowsName = "[not returned by CertEnumSystemStoreLocation; to test]", RegistryPath = StorePaths.Location(flag) });
            snapshot.Locations.Sort(delegate(StoreLocation a, StoreLocation b)
            {
                int left = Array.IndexOf(documented, a.Flags), right = Array.IndexOf(documented, b.Flags);
                return (left < 0 ? 100 : left).CompareTo(right < 0 ? 100 : right);
            });
        }

        private void EnumerateSystems(StoreLocation location, string owner)
        {
            snapshot.Note("CertEnumSystemStore", location.Name + (owner == null ? "" : "\\" + owner), "Enumeration requested; flags 0x" + location.Flags.ToString("X8", CultureInfo.InvariantCulture));
            List<string> owners = new List<string>();
            Native.SystemCallback callback = delegate(IntPtr name, uint flags, IntPtr info, IntPtr reserved, IntPtr arg)
            {
                if (canceled()) return false;
                try
                {
                    if ((flags & Native.CERT_SYSTEM_STORE_RELOCATE_FLAG) != 0)
                    {
                        snapshot.Fail("CertEnumSystemStore", location.Name, "Unexpected relocated store pointer; not interpreted as a name.");
                        return true;
                    }
                    string nativeName = Marshal.PtrToStringUni(name);
                    if (String.IsNullOrEmpty(nativeName)) throw new InvalidOperationException("Windows returned an empty system store name.");
                    bool namedLocation = location.Flags == Native.CERT_SYSTEM_STORE_SERVICES || location.Flags == Native.CERT_SYSTEM_STORE_USERS;
                    if (namedLocation && owner == null && nativeName.IndexOf('\\') < 0)
                    {
                        if (!owners.Contains(nativeName)) owners.Add(nativeName);
                        return true;
                    }
                    if (owner != null && nativeName.IndexOf('\\') < 0) nativeName = owner + "\\" + nativeName;
                    if (location.Stores.Any(item => String.Equals(item.Name, nativeName, StringComparison.OrdinalIgnoreCase))) return true;
                    SystemStore store = new SystemStore { Name = nativeName, Path = location.Name + "\\" + nativeName,
                        RegistryPath = StorePaths.System(location.Flags, nativeName) };
                    location.Stores.Add(store);
                    snapshot.Note("CertEnumSystemStore", store.Path, "Returned by Windows.");
                    return true;
                }
                catch (Exception ex) { snapshot.Fail("System callback", location.Name, ex.Message); return false; }
            };
            bool success = Native.CertEnumSystemStore(location.Flags, owner, IntPtr.Zero, callback);
            int error = Marshal.GetLastWin32Error();
            GC.KeepAlive(callback);
            if (!success && !canceled())
            {
                string message = Snapshot.WindowsError(error);
                location.Error = (location.Error == null ? "" : location.Error + Environment.NewLine) + (owner == null ? "" : owner + ": ") + message;
                snapshot.Fail("CertEnumSystemStore", location.Name + (owner == null ? "" : "\\" + owner), message);
            }
            foreach (string serviceOrUser in owners)
            {
                if (canceled()) break;
                EnumerateSystems(location, serviceOrUser);
            }
            location.Stores.Sort(delegate(SystemStore a, SystemStore b) { return StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name); });
        }

        private void EnumeratePhysical(StoreLocation location, SystemStore store)
        {
            snapshot.Note("CertEnumPhysicalStore", store.Path, "Physical sibling enumeration requested.");
            Native.PhysicalCallback callback = delegate(IntPtr system, uint flags, IntPtr name, IntPtr info, IntPtr reserved, IntPtr arg)
            {
                if (canceled()) return false;
                try
                {
                    string nativeName = Marshal.PtrToStringUni(name);
                    if (String.IsNullOrEmpty(nativeName)) throw new InvalidOperationException("Windows returned an empty physical store name.");
                    if (store.PhysicalStores.Any(item => String.Equals(item.Name, nativeName, StringComparison.OrdinalIgnoreCase))) return true;
                    PhysicalStore physical = new PhysicalStore { Name = nativeName, Path = store.Path + "\\" + nativeName,
                        Predefined = (flags & Native.CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG) != 0, Provider = "[not supplied]" };
                    if (info != IntPtr.Zero)
                    {
                        Native.CERT_PHYSICAL_STORE_INFO data = (Native.CERT_PHYSICAL_STORE_INFO)Marshal.PtrToStructure(info, typeof(Native.CERT_PHYSICAL_STORE_INFO));
                        physical.Flags = data.dwFlags;
                        physical.Priority = data.dwPriority;
                        long provider = data.pszOpenStoreProvider.ToInt64();
                        physical.Provider = provider >= 0 && provider <= 65535
                            ? "Provider identifier " + provider.ToString(CultureInfo.InvariantCulture)
                            : Marshal.PtrToStringAnsi(data.pszOpenStoreProvider);
                    }
                    store.PhysicalStores.Add(physical);
                    snapshot.Note("CertEnumPhysicalStore", physical.Path, physical.Predefined ? "Predefined sibling; returned by Windows." : "Registered sibling; returned by Windows.");
                    return true;
                }
                catch (Exception ex) { snapshot.Fail("Physical callback", store.Path, ex.Message); return false; }
            };
            bool success = Native.CertEnumPhysicalStore(store.Name,
                location.Flags | Native.CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG, IntPtr.Zero, callback);
            int error = Marshal.GetLastWin32Error();
            GC.KeepAlive(callback);
            if (!success && !canceled())
            {
                store.PhysicalEnumerationError = Snapshot.WindowsError(error);
                snapshot.Fail("CertEnumPhysicalStore", store.Path, store.PhysicalEnumerationError);
            }
        }

        private string ReadStore(StoreLocation location, SystemStore system, PhysicalStore physical)
        {
            string path = physical == null ? system.Path : physical.Path;
            string parameter = system.Name + (physical == null ? "" : "\\" + physical.Name);
            IntPtr provider = physical == null ? Native.CERT_STORE_PROV_SYSTEM_W : Native.CERT_STORE_PROV_PHYSICAL_W;
            snapshot.Note("CertOpenStore", path, "Read-only existing-store open requested; flags 0x" + (location.Flags | Native.ReadFlags).ToString("X8", CultureInfo.InvariantCulture));
            using (StoreHandle handle = Native.CertOpenStore(provider, 0, IntPtr.Zero, location.Flags | Native.ReadFlags, parameter))
            {
                int openError = Marshal.GetLastWin32Error();
                if (handle == null || handle.IsInvalid)
                {
                    string message = Snapshot.WindowsError(openError);
                    snapshot.Fail("CertOpenStore", path, message);
                    return message;
                }
                snapshot.Note("CertOpenStore", path, "Existing store opened read-only.");
                IntPtr current = IntPtr.Zero;
                int inspectionFailures = 0;
                try
                {
                    while (!canceled())
                    {
                        // The API frees the previous context, including when it fails.
                        IntPtr previous = current;
                        current = IntPtr.Zero;
                        current = Native.CertEnumCertificatesInStore(handle, previous);
                        int enumError = Marshal.GetLastWin32Error();
                        if (current == IntPtr.Zero)
                        {
                            uint code = unchecked((uint)enumError);
                            if (code != Native.CRYPT_E_NOT_FOUND && code != Native.ERROR_NO_MORE_FILES)
                            {
                                string message = Snapshot.WindowsError(enumError);
                                snapshot.Fail("CertEnumCertificatesInStore", path, message);
                                return message;
                            }
                            break;
                        }
                        try
                        {
                            Native.CERT_CONTEXT context = (Native.CERT_CONTEXT)Marshal.PtrToStructure(current, typeof(Native.CERT_CONTEXT));
                            if (context.cbCertEncoded == 0 || context.cbCertEncoded > 16 * 1024 * 1024 || context.pbCertEncoded == IntPtr.Zero)
                                throw new InvalidOperationException("Certificate DER is empty or exceeds the 16 MiB inspection limit; enumeration is incomplete.");
                            byte[] der = new byte[(int)context.cbCertEncoded];
                            Marshal.Copy(context.pbCertEncoded, der, 0, der.Length);
                            if (snapshot.RawCertificateSink != null) snapshot.RawCertificateSink(snapshot.ScanId, der, path);
                            CertificateRecord record = snapshot.Add(der);
                            if (record.ParseError != null)
                            {
                                inspectionFailures++;
                                snapshot.Fail("X509Certificate2 decode", path + " | " + record.Sha256, record.ParseError);
                            }
                            if (physical == null)
                            {
                                system.Certificates.Add(record.Identity);
                                record.Collections.Add(system.Path);
                            }
                            else
                            {
                                physical.Certificates.Add(record.Identity);
                                record.FoundIn.Add(physical.Path);
                            }
                            SortedSet<string> usages;
                            if (!record.UsageBySource.TryGetValue(path, out usages))
                            {
                                usages = new SortedSet<string>(StringComparer.Ordinal);
                                record.UsageBySource.Add(path, usages);
                            }
                            string usage = ReadUsage(current);
                            usages.Add(usage);
                            if (snapshot.CertificateSink != null) snapshot.CertificateSink(snapshot, record, path, usage);
                        }
                        catch (Exception ex) { inspectionFailures++; snapshot.Fail("Certificate inspection", path, ex.Message); }
                    }
                }
                finally
                {
                    if (current != IntPtr.Zero) Native.CertFreeCertificateContext(current);
                }
                int count = physical == null ? system.Certificates.Count : physical.Certificates.Count;
                snapshot.Note("CertEnumCertificatesInStore", path, count + " distinct certificates" + (canceled() ? "; canceled" : "; end of enumeration."));
                return canceled() ? "Canceled; partial enumeration" : inspectionFailures > 0 ?
                    "Enumeration ended with " + inspectionFailures + " certificate inspection errors; see activity log." : null;
            }
        }

        internal static string ReadUsage(IntPtr cert)
        {
            uint size = 0;
            Native.SetLastError(0);
            bool success = Native.CertGetEnhancedKeyUsage(cert, 0, IntPtr.Zero, ref size);
            int error = Marshal.GetLastWin32Error();
            if (!success) return "[EKU unavailable: " + Snapshot.WindowsError(error) + "]";
            if (size < Marshal.SizeOf(typeof(Native.CERT_ENHKEY_USAGE)) || size > 1024 * 1024)
                return "[EKU size outside inspection limits; to test]";
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                Native.SetLastError(0);
                success = Native.CertGetEnhancedKeyUsage(cert, 0, buffer, ref size);
                error = Marshal.GetLastWin32Error();
                if (!success) return "[EKU unavailable: " + Snapshot.WindowsError(error) + "]";
                Native.CERT_ENHKEY_USAGE usage = (Native.CERT_ENHKEY_USAGE)Marshal.PtrToStructure(buffer, typeof(Native.CERT_ENHKEY_USAGE));
                if (usage.cUsageIdentifier == 0)
                    return unchecked((uint)error) == Native.CRYPT_E_NOT_FOUND ? "All uses (no EKU restriction; not a trust verdict)" :
                        error == 0 ? "No valid uses (EKU restriction)" : "[Zero EKU count with unexpected error: " + Snapshot.WindowsError(error) + "]";
                if (usage.cUsageIdentifier > 4096 || usage.rgpszUsageIdentifier == IntPtr.Zero)
                    return "[Invalid EKU identifier array; to test]";
                List<string> oids = new List<string>();
                for (int i = 0; i < (int)usage.cUsageIdentifier; i++)
                {
                    IntPtr oid = Marshal.ReadIntPtr(usage.rgpszUsageIdentifier, i * IntPtr.Size);
                    oids.Add(Marshal.PtrToStringAnsi(oid) ?? "[empty OID]");
                }
                return String.Join(", ", oids.ToArray()) + " (usage OIDs; chain policy not evaluated)";
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
