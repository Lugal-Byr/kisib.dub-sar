using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kisib
{
    internal sealed class CertificateRecord
    {
        internal string Identity;
        internal byte[] Der;
        internal string Subject;
        internal string Issuer;
        internal string Sha1;
        internal string Sha256;
        internal DateTime? NotBefore;
        internal DateTime? NotAfter;
        internal string KeyUsage;
        internal string ParseError;
        internal string KeyOid;
        internal string KeyAlgorithm = "[unavailable; to test]";
        internal int? KeySize;
        internal string SignatureOid;
        internal string SignatureAlgorithm = "[unavailable; to test]";
        internal string SignatureHash;
        internal byte[] SpkiDer;
        internal string SpkiSha256;
        internal string CryptoError;
        internal readonly List<string> WeakReasons = new List<string>();
        internal readonly List<string> CollisionPeers = new List<string>();
        internal readonly List<string> KeyReusePeers = new List<string>();
        internal string WeakTierText { get { return WeakReasons.Count > 0 ? String.Join("; ", WeakReasons.ToArray()) + " [to test]" : CryptoError != null || ParseError != null ? "Incomplete assessment [to test]" : "No listed criterion [to test]"; } }
        internal string CollisionText { get { return CollisionPeers.Count > 0 ? "Same SHA-1; different SHA-256 [to test]" : "No match [to test]"; } }
        internal string KeyReuseText { get { return SpkiSha256 == null || ParseError != null ? "Unavailable [to test]" : KeyReusePeers.Count > 0 ? "Different subjects [to test]" : "No match [to test]"; } }
        internal readonly SortedSet<string> FoundIn = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        internal readonly SortedSet<string> Collections = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        // Enhanced key usage can differ between store occurrences of identical DER.
        internal readonly SortedDictionary<string, SortedSet<string>> UsageBySource = new SortedDictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);

        internal static CertificateRecord FromDer(byte[] der)
        {
            CertificateRecord result = new CertificateRecord();
            result.Der = der;
            using (SHA1 sha = SHA1.Create()) result.Sha1 = Hex(sha.ComputeHash(der));
            using (SHA256 sha = SHA256.Create()) result.Sha256 = Hex(sha.ComputeHash(der));
            result.Identity = result.Sha256;
            result.Subject = "[certificate decode failed]";
            result.Issuer = "[unavailable]";
            result.KeyUsage = "No Key Usage extension";
            try
            {
                using (X509Certificate2 cert = new X509Certificate2(der))
                {
                    result.Subject = cert.Subject;
                    result.Issuer = cert.Issuer;
                    result.NotBefore = cert.NotBefore.ToUniversalTime();
                    result.NotAfter = cert.NotAfter.ToUniversalTime();
                    CertificateSignals.ReadMetadata(result, cert);
                    foreach (X509Extension extension in cert.Extensions)
                    {
                        if (extension.Oid != null && extension.Oid.Value == "2.5.29.15")
                        {
                            try
                            {
                                X509KeyUsageExtension keyUsage = new X509KeyUsageExtension(extension, extension.Critical);
                                result.KeyUsage = keyUsage.KeyUsages.ToString();
                            }
                            catch (CryptographicException ex) { result.KeyUsage = "Decode error: " + ex.Message; }
                        }
                    }
                }
            }
            catch (CryptographicException ex) { result.ParseError = ex.Message; }
            return result;
        }

        internal static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", ""); }
        internal static string Time(DateTime? value) { return value.HasValue ? value.Value.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) : "[unavailable]"; }
        internal string FoundInText { get { return FoundIn.Count == 0 ? "[physical source unresolved; to test]" : String.Join("; ", FoundIn.ToArray()); } }
    }

    internal sealed class PhysicalStore
    {
        internal string Name;
        internal string Path;
        internal string Provider;
        internal bool Predefined;
        internal uint Flags;
        internal uint Priority;
        internal string Error;
        internal bool ReadSucceeded;
        internal readonly HashSet<string> Certificates = new HashSet<string>(StringComparer.Ordinal);
    }
    internal sealed class SystemStore
    {
        internal string Name;
        internal string Path;
        internal string RegistryPath;
        internal string Error;
        internal string PhysicalEnumerationError;
        internal bool ReadSucceeded;
        internal readonly List<PhysicalStore> PhysicalStores = new List<PhysicalStore>();
        internal readonly HashSet<string> Certificates = new HashSet<string>(StringComparer.Ordinal);
    }
    internal sealed class StoreLocation
    {
        internal string Name;
        internal string WindowsName;
        internal uint Flags;
        internal string RegistryPath;
        internal string Error;
        internal bool Enumerated;
        internal readonly List<SystemStore> Stores = new List<SystemStore>();
    }
    internal sealed class Snapshot
    {
        internal readonly string ScanId = Guid.NewGuid().ToString("N");
        internal Action<string, string, string, string> EventSink;
        internal Action<string, byte[], string> RawCertificateSink;
        internal Action<Snapshot, CertificateRecord, string, string> CertificateSink;
        internal readonly List<StoreLocation> Locations = new List<StoreLocation>();
        internal readonly Dictionary<string, CertificateRecord> Certificates = new Dictionary<string, CertificateRecord>(StringComparer.Ordinal);
        internal readonly List<string> Log = new List<string>();
        internal readonly List<string> Errors = new List<string>();
        internal DateTime Started = DateTime.UtcNow;
        internal DateTime Finished;
        internal bool Canceled;
        internal int StoreCount { get { return Locations.Sum(location => location.Stores.Count); } }
        internal int PhysicalCount { get { return Locations.Sum(location => location.Stores.Sum(store => store.PhysicalStores.Count)); } }
        internal int UnresolvedCount { get { return Certificates.Values.Count(cert => cert.FoundIn.Count == 0); } }

        internal void Note(string action, string path, string outcome)
        {
            Log.Add(DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + "\t" + action + "\t" + path + "\t" + outcome);
            if (EventSink != null) EventSink(ScanId, action, path, outcome);
        }
        internal void Fail(string action, string path, string message)
        {
            Errors.Add(action + " | " + path + " | " + message);
            Note(action, path, message);
        }
        internal CertificateRecord Add(byte[] der)
        {
            CertificateRecord incoming = CertificateRecord.FromDer(der);
            CertificateRecord existing;
            string identity = incoming.Identity;
            int suffix = 1;
            while (Certificates.TryGetValue(identity, out existing))
            {
                if (existing.Der.SequenceEqual(der)) return existing;
                identity = incoming.Sha256 + ":" + (++suffix).ToString(CultureInfo.InvariantCulture);
            }
            if (suffix > 1) Fail("SHA-256 identity", incoming.Sha256, "Different DER bytes share a lookup hash; preserved separately.");
            incoming.Identity = identity;
            Certificates.Add(identity, incoming);
            return incoming;
        }
        internal static string WindowsError(int code)
        {
            return "0x" + unchecked((uint)code).ToString("X8", CultureInfo.InvariantCulture) + " — " + new Win32Exception(code).Message;
        }
    }

    internal static class StorePaths
    {
        internal const string MicrosoftBase = @"Software\Microsoft\SystemCertificates";
        internal const string PolicyBase = @"Software\Policies\Microsoft\SystemCertificates";
        internal static string Location(uint flags)
        {
            switch (flags)
            {
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE: return @"HKLM\" + MicrosoftBase;
                case Native.CERT_SYSTEM_STORE_CURRENT_USER: return @"HKCU\" + MicrosoftBase;
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY: return @"HKLM\" + PolicyBase;
                case Native.CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY: return @"HKCU\" + PolicyBase;
                case Native.CERT_SYSTEM_STORE_SERVICES: return @"HKLM\Software\Microsoft\Cryptography\Services\<ServiceName>\SystemCertificates";
                case Native.CERT_SYSTEM_STORE_CURRENT_SERVICE: return @"HKLM\Software\Microsoft\Cryptography\Services\<current service>\SystemCertificates";
                case Native.CERT_SYSTEM_STORE_USERS: return @"HKU\<SID>\" + MicrosoftBase;
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE: return "Enterprise directory / client cache [exact registry path: to test]";
                default: return "[registry path not documented in the source mapping; to test]";
            }
        }
        internal static string System(uint flags, string nativeName)
        {
            int split = nativeName.IndexOf('\\');
            if (split >= 0 && flags == Native.CERT_SYSTEM_STORE_SERVICES)
                return @"HKLM\Software\Microsoft\Cryptography\Services\" + nativeName.Substring(0, split) + @"\SystemCertificates\" + nativeName.Substring(split + 1);
            if (split >= 0 && flags == Native.CERT_SYSTEM_STORE_USERS)
                return @"HKU\" + nativeName.Substring(0, split) + "\\" + MicrosoftBase + "\\" + nativeName.Substring(split + 1);
            return Location(flags) + "\\" + nativeName;
        }
        internal static string Name(uint flags, string nativeName)
        {
            switch (flags)
            {
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE: return "LOCAL_MACHINE";
                case Native.CERT_SYSTEM_STORE_CURRENT_USER: return "CURRENT_USER";
                case Native.CERT_SYSTEM_STORE_CURRENT_SERVICE: return "CURRENT_SERVICE";
                case Native.CERT_SYSTEM_STORE_SERVICES: return "SERVICES";
                case Native.CERT_SYSTEM_STORE_USERS: return "USERS";
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY: return "LOCAL_MACHINE_GROUP_POLICY";
                case Native.CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY: return "CURRENT_USER_GROUP_POLICY";
                case Native.CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE: return "LOCAL_MACHINE_ENTERPRISE";
                default: return nativeName;
            }
        }
    }
}
