using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Kisib
{
    // Microsoft's API names are preserved here. See docs/feature-sources.csv.
    internal static class Native
    {
        internal const uint CERT_SYSTEM_STORE_LOCATION_MASK = 0x00ff0000;
        internal const uint CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
        internal const uint CERT_SYSTEM_STORE_CURRENT_SERVICE = 0x00040000;
        internal const uint CERT_SYSTEM_STORE_SERVICES = 0x00050000;
        internal const uint CERT_SYSTEM_STORE_USERS = 0x00060000;
        internal const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 0x00070000;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 0x00080000;
        internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 0x00090000;
        internal const uint CERT_SYSTEM_STORE_RELOCATE_FLAG = 0x80000000;
        internal const uint CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG = 0x00000001;
        internal const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        internal const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
        internal const uint CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200;
        internal const uint ReadFlags = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG;
        internal const uint CRYPT_E_NOT_FOUND = 0x80092004;
        internal const uint ERROR_NO_MORE_FILES = 18;
        internal static readonly IntPtr CERT_STORE_PROV_SYSTEM_W = new IntPtr(10);
        internal static readonly IntPtr CERT_STORE_PROV_PHYSICAL_W = new IntPtr(14);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool LocationCallback(IntPtr name, uint flags, IntPtr reserved, IntPtr arg);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool SystemCallback(IntPtr name, uint flags, IntPtr info, IntPtr reserved, IntPtr arg);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool PhysicalCallback(IntPtr system, uint flags, IntPtr name, IntPtr info, IntPtr reserved, IntPtr arg);

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_CONTEXT
        {
            internal uint dwCertEncodingType;
            internal IntPtr pbCertEncoded;
            internal uint cbCertEncoded;
            internal IntPtr pCertInfo;
            internal IntPtr hCertStore;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_DATA_BLOB
        {
            internal uint cbData;
            internal IntPtr pbData;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_PHYSICAL_STORE_INFO
        {
            internal uint cbSize;
            internal IntPtr pszOpenStoreProvider;
            internal uint dwOpenEncodingType;
            internal uint dwOpenFlags;
            internal CRYPT_DATA_BLOB OpenParameters;
            internal uint dwFlags;
            internal uint dwPriority;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_ENHKEY_USAGE
        {
            internal uint cUsageIdentifier;
            internal IntPtr rgpszUsageIdentifier;
        }

        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertEnumSystemStoreLocation(uint flags, IntPtr arg, LocationCallback callback);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertEnumSystemStore(uint flags, string locationParameter, IntPtr arg, SystemCallback callback);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertEnumPhysicalStore(string system, uint flags, IntPtr arg, PhysicalCallback callback);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern StoreHandle CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider, uint flags, string parameter);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr CertEnumCertificatesInStore(StoreHandle store, IntPtr previous);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertGetEnhancedKeyUsage(IntPtr cert, uint flags, IntPtr usage, ref uint size);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertFreeCertificateContext(IntPtr cert);
        [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertCloseStore(IntPtr store, uint flags);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern void SetLastError(uint error);
    }

    internal sealed class StoreHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public StoreHandle() : base(true) { }
        protected override bool ReleaseHandle() { return Native.CertCloseStore(handle, 0); }
    }
}
