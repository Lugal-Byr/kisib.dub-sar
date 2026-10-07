using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace Kisib
{
    public static class Verification
    {
        private static int checks;
        private static void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException("FAIL: " + message);
            checks++; Console.WriteLine("PASS: " + message);
        }
        private static void Reject(Action read, string message)
        {
            bool rejected = false;
            try { read(); } catch (CryptographicException) { rejected = true; }
            Check(rejected, message);
        }
        private static void VerifyMetadata(string directory)
        {
            string testDirectory = Path.Combine(directory, "tests");
            Dictionary<string, CertificateRecord> fixtures = new Dictionary<string, CertificateRecord>();
            foreach (string line in File.ReadAllLines(Path.Combine(testDirectory, "metadata-vectors.csv")).Skip(1))
            {
                if (line.Length == 0) continue;
                string[] vector = line.Split(',');
                Check(vector.Length == 8, "Public metadata vector schema");
                CertificateRecord cert = CertificateRecord.FromDer(File.ReadAllBytes(Path.Combine(testDirectory, vector[0].Replace('/', Path.DirectorySeparatorChar))));
                fixtures.Add(vector[0], cert);
                Check(cert.ParseError == null && cert.CryptoError == null, vector[0] + " metadata extraction: " + cert.ParseError + cert.CryptoError);
                Check(cert.KeyOid == vector[1] && cert.KeySize == Int32.Parse(vector[2]), vector[0] + " key algorithm and exact bit size");
                Check(cert.SignatureOid == vector[3] && cert.SignatureHash == vector[4], vector[0] + " signature algorithm and digest");
                Check(cert.SpkiSha256 == vector[5] && cert.Sha256 == vector[6], vector[0] + " independent complete-SPKI and certificate SHA-256 vectors");
                Check(cert.SpkiSha256 != cert.Sha256, vector[0] + " SPKI and certificate hashes remain distinct");
                CertificateSignals.Evaluate(new CertificateRecord[] { cert });
                Check((cert.WeakReasons.Count > 0) == Boolean.Parse(vector[7]), vector[0] + " requested weak-tier result");
            }
            Check(fixtures["metadata/rsa2047.cer"].KeySize == 2047 && fixtures["metadata/rsa2047.cer"].WeakReasons.Count == 1, "2047-bit RSA is not rounded to 2048");
            Check(fixtures["metadata/rsa2048.cer"].WeakReasons.Count == 0 && fixtures["fixture.cer"].WeakReasons.Count == 0, "RSA threshold and EC size are assessed separately");
            CertificateRecord original = fixtures["metadata/rsa2048.cer"], reissue = fixtures["metadata/rsa2048-reissue.cer"], renamed = fixtures["metadata/rsa2048-other-subject.cer"];
            CertificateSignals.Evaluate(new CertificateRecord[] { original, reissue });
            Check(original.SpkiSha256 == reissue.SpkiSha256 && original.Subject == reissue.Subject && original.KeyReusePeers.Count == 0, "Same-subject reissue does not trigger key reuse");
            CertificateSignals.Evaluate(new CertificateRecord[] { original, reissue, renamed });
            Check(original.SpkiSha256 == renamed.SpkiSha256 && original.Subject != renamed.Subject && original.KeyReusePeers.Count == 1 && renamed.KeyReusePeers.Count == 2, "Shared key under distinct subjects flags every affected certificate");
            CertificateSignals.Evaluate(new CertificateRecord[] { original });
            Check(original.KeyReusePeers.Count == 0, "Reevaluation clears stale reuse signals");

            // Artificial lookup labels exercise collision grouping; no real hash collision is generated.
            CertificateRecord a = new CertificateRecord { Identity = "a", Sha1 = "synthetic-sha1", Sha256 = "synthetic-sha256-a", SpkiSha256 = "synthetic-spki", Subject = "CN=Same, O=One" };
            CertificateRecord b = new CertificateRecord { Identity = "b", Sha1 = "synthetic-sha1", Sha256 = "synthetic-sha256-b", SpkiSha256 = "synthetic-spki", Subject = "CN=Same, O=Two" };
            CertificateRecord c = new CertificateRecord { Identity = "c", Sha1 = "different-sha1", Sha256 = "synthetic-sha256-c", SpkiSha256 = "different-spki", Subject = "CN=Other" };
            CertificateSignals.Evaluate(new CertificateRecord[] { a, b, c });
            Check(a.CollisionPeers.SequenceEqual(new string[] { "b" }) && b.CollisionPeers.SequenceEqual(new string[] { "a" }) && c.CollisionPeers.Count == 0, "Same SHA-1 / different SHA-256 marks both records only");
            Check(a.KeyReusePeers.Count == 1 && b.KeyReusePeers.Count == 1, "Full subject differences trigger reuse even when CN is identical");
            CertificateSignals.Evaluate(new CertificateRecord[] { a, c });
            Check(a.CollisionPeers.Count == 0 && a.KeyReusePeers.Count == 0, "Fresh inventory evaluation clears stale collision and reuse signals");
            b.Sha256 = a.Sha256;
            CertificateSignals.Evaluate(new CertificateRecord[] { a, b });
            Check(a.CollisionPeers.Count == 0 && b.CollisionPeers.Count == 0, "Matching SHA-1 and SHA-256 alone do not trigger collision");
            a.KeyOid = "1.2.840.113549.1.1.1"; a.KeySize = 1024; a.SignatureHash = "MD5";
            CertificateSignals.Evaluate(new CertificateRecord[] { a });
            Check(a.WeakReasons.Count == 2, "Weak tier retains all matching reasons");
            c.CryptoError = "Unknown signature digest [to test]";
            Check(c.WeakTierText == "Incomplete assessment [to test]", "Unknown metadata stays incomplete");

            Check(CertificateDer.PssHash(new byte[] { 0x30, 0x00 }) == "SHA-1", "Valid RSA-PSS default parameters specify SHA-1");
            Check(CertificateDer.PssHash(null).Contains("unavailable"), "Absent RSA-PSS parameters are not guessed");
            byte[] ignored = null;
            Reject(delegate { CertificateDer.GetSpki(original.Der.Take(original.Der.Length - 1).ToArray(), out ignored); }, "Truncated certificate DER rejected");
            Reject(delegate { CertificateDer.GetSpki(original.Der.Concat(new byte[] { 0 }).ToArray(), out ignored); }, "Trailing certificate DER rejected");
            Reject(delegate { CertificateDer.GetSpki(new byte[] { 0x30, 0x80, 0, 0 }, out ignored); }, "Indefinite DER length rejected");
            Reject(delegate { CertificateDer.GetSpki(new byte[] { 0x30, 0x81, 0 }, out ignored); }, "Noncanonical DER length rejected");
            Reject(delegate { CertificateDer.RsaModulusBits(original.SpkiDer.Concat(new byte[] { 0 }).ToArray()); }, "Trailing SPKI DER rejected");
            Reject(delegate { CertificateDer.PssHash(new byte[] { 0x30, 0x04, 0xa4, 0x02, 0x05, 0 }); }, "Unknown RSA-PSS parameter tag rejected");
        }
        public static int Run(string directory)
        {
            try
            {
                ArchiveVerification.Run(directory, Check);
                ControlVerification.Run(directory, Check);
                VerifyMetadata(directory);
                Check(Marshal.SizeOf(typeof(Native.CERT_CONTEXT)) == (IntPtr.Size == 8 ? 40 : 20), "CERT_CONTEXT size for this architecture");
                Check(Marshal.OffsetOf(typeof(Native.CERT_CONTEXT), "hCertStore").ToInt32() == (IntPtr.Size == 8 ? 32 : 16), "CERT_CONTEXT hCertStore offset");
                Check(Marshal.SizeOf(typeof(Native.CERT_PHYSICAL_STORE_INFO)) == (IntPtr.Size == 8 ? 48 : 32), "CERT_PHYSICAL_STORE_INFO size");
                Check(Marshal.SizeOf(typeof(Native.CERT_ENHKEY_USAGE)) == (IntPtr.Size == 8 ? 16 : 8), "CERT_ENHKEY_USAGE size");
                byte[] der = File.ReadAllBytes(Path.Combine(directory, "tests", "fixture.cer"));
                Snapshot identity = new Snapshot();
                CertificateRecord first = identity.Add(der), second = identity.Add((byte[])der.Clone());
                Check(Object.ReferenceEquals(first, second) && identity.Certificates.Count == 1, "Exact DER duplicates merge without losing occurrences");
                Check(first.ParseError == null && first.Subject.Contains("kisib enumeration fixture"), "Public certificate metadata decodes");
                using (SHA256 hash = SHA256.Create()) Check(first.Sha256 == CertificateRecord.Hex(hash.ComputeHash(der)), "SHA-256 covers full certificate DER");
                Check(StorePaths.System(Native.CERT_SYSTEM_STORE_SERVICES, @"ExampleService\MY") == @"HKLM\Software\Microsoft\Cryptography\Services\ExampleService\SystemCertificates\MY", "Service system store registry path");
                Check(StorePaths.System(Native.CERT_SYSTEM_STORE_USERS, @"S-1-5-21-example\CA") == @"HKU\S-1-5-21-example\Software\Microsoft\SystemCertificates\CA", "User system store registry path");

                string missing = "kisib-readonly-verification-" + Guid.NewGuid().ToString("N");
                string registry = StorePaths.MicrosoftBase + "\\" + missing;
                using (RegistryKey before = Registry.CurrentUser.OpenSubKey(registry, false)) Check(before == null, "Verification store does not exist before read");
                using (StoreHandle handle = Native.CertOpenStore(Native.CERT_STORE_PROV_SYSTEM_W, 0, IntPtr.Zero, Native.CERT_SYSTEM_STORE_CURRENT_USER | Native.ReadFlags, missing))
                    Check(handle == null || handle.IsInvalid, "Read-only OpenExisting rejects a missing system store");
                using (RegistryKey after = Registry.CurrentUser.OpenSubKey(registry, false)) Check(after == null, "Read did not create a registry store");

                Console.WriteLine("Enumerating native stores on this Windows machine...");
                Snapshot snapshot = new Scanner(delegate(string message) { Console.WriteLine(message); }, delegate { return false; }).Run();
                Check(snapshot.Locations.Any(item => item.Flags == Native.CERT_SYSTEM_STORE_CURRENT_USER && item.Enumerated), "CURRENT_USER returned by Windows");
                Check(snapshot.Locations.Any(item => item.Flags == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE && item.Enumerated), "LOCAL_MACHINE returned by Windows");
                Check(snapshot.Locations.Where(item => item.Flags == Native.CERT_SYSTEM_STORE_CURRENT_USER || item.Flags == Native.CERT_SYSTEM_STORE_LOCAL_MACHINE).All(item => item.Error == null && item.Stores.Count > 0), "User and machine system-store enumerations completed");
                Check(snapshot.Certificates.Count > 0, "Native inventory contains certificates");
                foreach (StoreLocation location in snapshot.Locations)
                    foreach (SystemStore store in location.Stores)
                        foreach (PhysicalStore physical in store.PhysicalStores)
                            foreach (string key in physical.Certificates)
                                Check(snapshot.Certificates[key].FoundIn.Contains(physical.Path), "Observed physical occurrence retained: " + physical.Path);
                foreach (CertificateRecord cert in snapshot.Certificates.Values)
                    foreach (string path in cert.FoundIn)
                        Check(snapshot.Locations.SelectMany(item => item.Stores).SelectMany(item => item.PhysicalStores).Any(item => item.Path == path && item.Certificates.Contains(cert.Identity)), "Found in is backed by an actual physical enumeration");
                Console.WriteLine("Windows inventory errors: " + snapshot.Errors.Count + "; unresolved physical sources: " + snapshot.UnresolvedCount);
                foreach (string error in snapshot.Errors) Console.WriteLine("TO TEST: " + error);
                Console.WriteLine(checks + " checks passed. This does not pass the manual Home/Pro enumeration gate.");
                return 0;
            }
            catch (Exception ex) { Console.WriteLine(ex.ToString()); return 1; }
        }
    }
}
