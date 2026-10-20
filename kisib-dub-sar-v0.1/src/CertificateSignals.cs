using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kisib
{
    // Local inspection rules, not Windows chain-policy or compromise verdicts.
    internal static class CertificateSignals
    {
        internal static bool IsRsa(string oid) { return oid == "1.2.840.113549.1.1.1" || oid == "1.2.840.113549.1.1.10"; }

        internal static void ReadMetadata(CertificateRecord record, X509Certificate2 cert)
        {
            try
            {
                record.SignatureOid = cert.SignatureAlgorithm.Value;
                record.SignatureAlgorithm = (cert.SignatureAlgorithm.FriendlyName ?? record.SignatureOid) + " (" + record.SignatureOid + ")";
                record.KeyOid = cert.PublicKey.Oid.Value;
                record.KeyAlgorithm = (cert.PublicKey.Oid.FriendlyName ?? record.KeyOid) + " (" + record.KeyOid + ")";
                byte[] parameters;
                record.SpkiDer = CertificateDer.GetSpki(record.Der, out parameters);
                using (SHA256 hash = SHA256.Create()) record.SpkiSha256 = CertificateRecord.Hex(hash.ComputeHash(record.SpkiDer));
                try
                {
                    if (IsRsa(record.KeyOid)) record.KeySize = CertificateDer.RsaModulusBits(record.SpkiDer);
                    else if (record.KeyOid == "1.2.840.10045.2.1")
                    {
                        using (ECDsa key = ECDsaCertificateExtensions.GetECDsaPublicKey(cert))
                            if (key != null) record.KeySize = key.KeySize;
                    }
                    else if (record.KeyOid == "1.2.840.10040.4.1")
                    {
                        using (AsymmetricAlgorithm key = cert.PublicKey.Key) record.KeySize = key.KeySize;
                    }
                    if (!record.KeySize.HasValue) record.CryptoError = "Key size unavailable for this algorithm/provider [to test].";
                }
                catch (Exception ex)
                {
                    if (!(ex is CryptographicException || ex is ArgumentException || ex is NotSupportedException)) throw;
                    record.CryptoError = ex.Message + " [to test]";
                }
                // A failed size/provider lookup must not suppress signature digest inspection.
                record.SignatureHash = SignatureHash(record.SignatureOid, parameters);
                if (record.SignatureHash.StartsWith("Other", StringComparison.Ordinal) || record.SignatureHash.Contains("unavailable"))
                    record.CryptoError = (record.CryptoError ?? "") + " Signature digest not classified [to test].";
            }
            catch (Exception ex)
            {
                if (!(ex is CryptographicException || ex is ArgumentException || ex is NotSupportedException)) throw;
                record.CryptoError = (record.CryptoError == null ? "" : record.CryptoError + "; ") + ex.Message + " [to test]";
                // A known signature OID can still be assessed if key extraction failed.
                if (record.SignatureHash == null && record.SignatureOid != "1.2.840.113549.1.1.10")
                    record.SignatureHash = SignatureHash(record.SignatureOid, null);
            }
        }

        internal static string SignatureHash(string oid, byte[] parameters)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.4": case "1.3.14.3.2.3": return "MD5";
                case "1.2.840.113549.1.1.5": case "1.3.14.3.2.29":
                case "1.2.840.10040.4.3": case "1.3.14.3.2.27": case "1.2.840.10045.4.1": return "SHA-1";
                case "1.2.840.113549.1.1.10": return CertificateDer.PssHash(parameters);
                case "1.2.840.113549.1.1.11": case "1.2.840.10045.4.3.2": case "2.16.840.1.101.3.4.3.2": return "SHA-256";
                case "1.2.840.113549.1.1.12": case "1.2.840.10045.4.3.3": return "SHA-384";
                case "1.2.840.113549.1.1.13": case "1.2.840.10045.4.3.4": return "SHA-512";
                case "1.2.840.113549.1.1.14": case "1.2.840.10045.4.3.1": case "2.16.840.1.101.3.4.3.1": return "SHA-224";
                default: return "Other signature OID: " + oid;
            }
        }

        internal static void Evaluate(IEnumerable<CertificateRecord> records)
        {
            CertificateRecord[] all = records.ToArray();
            foreach (CertificateRecord cert in all)
            {
                cert.WeakReasons.Clear(); cert.CollisionPeers.Clear(); cert.KeyReusePeers.Clear();
                if (IsRsa(cert.KeyOid) && cert.KeySize.HasValue && cert.KeySize.Value < 2048) cert.WeakReasons.Add("RSA under 2048 bits");
                if (cert.SignatureHash == "MD5" || cert.SignatureHash == "SHA-1") cert.WeakReasons.Add(cert.SignatureHash + " signature");
            }
            foreach (IGrouping<string, CertificateRecord> group in all.Where(item => !String.IsNullOrEmpty(item.Sha1)).GroupBy(item => item.Sha1, StringComparer.Ordinal))
            {
                if (group.Select(item => item.Sha256).Distinct(StringComparer.Ordinal).Count() < 2) continue;
                foreach (CertificateRecord cert in group) cert.CollisionPeers.AddRange(group.Where(item => item != cert && item.Sha256 != cert.Sha256).Select(item => item.Identity));
            }
            foreach (IGrouping<string, CertificateRecord> group in all.Where(item => !String.IsNullOrEmpty(item.SpkiSha256) && item.ParseError == null).GroupBy(item => item.SpkiSha256, StringComparer.Ordinal))
            {
                if (group.Select(item => item.Subject).Distinct(StringComparer.Ordinal).Count() < 2) continue;
                foreach (CertificateRecord cert in group) cert.KeyReusePeers.AddRange(group.Where(item => item != cert && item.Subject != cert.Subject).Select(item => item.Identity));
            }
        }
    }

    // Bounded DER slicing preserves the original full SubjectPublicKeyInfo encoding.
    // It does not reconstruct SPKI from key bits or encode it using a different provider.
    internal static class CertificateDer
    {
        private struct Node { internal byte Tag; internal int Start; internal int Content; internal int End; }
        private static Node Read(byte[] data, ref int cursor, int limit)
        {
            if (cursor < 0 || limit > data.Length || cursor + 2 > limit) throw new CryptographicException("Truncated DER.");
            Node result = new Node { Start = cursor, Tag = data[cursor++] };
            if ((result.Tag & 31) == 31) throw new CryptographicException("Unsupported DER tag.");
            int first = data[cursor++], length = first;
            if (first >= 128)
            {
                int count = first & 127;
                if (count == 0 || count > 4 || cursor + count > limit || data[cursor] == 0) throw new CryptographicException("Invalid DER length.");
                long value = 0;
                for (int i = 0; i < count; i++) value = (value << 8) | data[cursor++];
                if (value < 128 || value > Int32.MaxValue) throw new CryptographicException("Noncanonical or oversized DER length.");
                length = (int)value;
            }
            if (length > limit - cursor) throw new CryptographicException("DER length exceeds enclosing value.");
            result.Content = cursor; result.End = cursor + length; cursor = result.End;
            return result;
        }
        private static Node Expect(byte[] data, ref int cursor, int limit, byte tag)
        {
            Node result = Read(data, ref cursor, limit);
            if (result.Tag != tag) throw new CryptographicException("Unexpected certificate DER field.");
            return result;
        }
        private static byte[] Copy(byte[] data, int start, int end)
        {
            byte[] result = new byte[end - start]; Array.Copy(data, start, result, 0, result.Length); return result;
        }
        internal static byte[] GetSpki(byte[] der, out byte[] signatureParameters)
        {
            int cursor = 0; Node certificate = Expect(der, ref cursor, der.Length, 0x30);
            if (cursor != der.Length) throw new CryptographicException("Data follows certificate DER.");
            cursor = certificate.Content; Node tbs = Expect(der, ref cursor, certificate.End, 0x30);
            Node signature = Expect(der, ref cursor, certificate.End, 0x30);
            Expect(der, ref cursor, certificate.End, 0x03);
            if (cursor != certificate.End) throw new CryptographicException("Unexpected certificate fields.");
            int signatureCursor = signature.Content;
            Expect(der, ref signatureCursor, signature.End, 0x06);
            signatureParameters = signatureCursor == signature.End ? null : Copy(der, signatureCursor, signature.End);
            cursor = tbs.Content; Node serial = Read(der, ref cursor, tbs.End);
            if (serial.Tag == 0xa0) serial = Read(der, ref cursor, tbs.End);
            if (serial.Tag != 0x02) throw new CryptographicException("Invalid certificate serial field.");
            Node innerSignature = Expect(der, ref cursor, tbs.End, 0x30);
            if (!Copy(der, innerSignature.Start, innerSignature.End).SequenceEqual(Copy(der, signature.Start, signature.End)))
                throw new CryptographicException("Inner and outer signature AlgorithmIdentifier encodings differ.");
            Expect(der, ref cursor, tbs.End, 0x30); // issuer
            Expect(der, ref cursor, tbs.End, 0x30); // validity
            Expect(der, ref cursor, tbs.End, 0x30); // subject
            Node spki = Expect(der, ref cursor, tbs.End, 0x30);
            return Copy(der, spki.Start, spki.End);
        }
        internal static int RsaModulusBits(byte[] spki)
        {
            int cursor = 0; Node sequence = Expect(spki, ref cursor, spki.Length, 0x30);
            if (cursor != spki.Length) throw new CryptographicException("Data follows SubjectPublicKeyInfo.");
            cursor = sequence.Content; Expect(spki, ref cursor, sequence.End, 0x30);
            Node bits = Expect(spki, ref cursor, sequence.End, 0x03);
            if (cursor != sequence.End) throw new CryptographicException("Unexpected SubjectPublicKeyInfo fields.");
            if (bits.Content == bits.End || spki[bits.Content] != 0) throw new CryptographicException("Invalid RSA public-key bit string.");
            cursor = bits.Content + 1; Node key = Expect(spki, ref cursor, bits.End, 0x30);
            if (cursor != bits.End) throw new CryptographicException("Data follows RSA public key.");
            cursor = key.Content; Node modulus = Expect(spki, ref cursor, key.End, 0x02);
            Expect(spki, ref cursor, key.End, 0x02);
            if (cursor != key.End || modulus.Content == modulus.End || (spki[modulus.Content] & 128) != 0) throw new CryptographicException("Invalid RSA modulus.");
            int first = modulus.Content;
            while (first < modulus.End && spki[first] == 0) first++;
            if (first == modulus.End) throw new CryptographicException("Zero RSA modulus.");
            int highBits = 8; byte value = spki[first];
            while ((value & 128) == 0) { value <<= 1; highBits--; }
            return (modulus.End - first - 1) * 8 + highBits;
        }
        internal static string PssHash(byte[] parameters)
        {
            if (parameters == null) return "RSA-PSS parameters unavailable [to test]";
            int cursor = 0; Node sequence = Expect(parameters, ref cursor, parameters.Length, 0x30);
            if (cursor != parameters.Length) throw new CryptographicException("Invalid RSA-PSS parameters.");
            string hash = "SHA-1"; // RFC 4055 default when hashAlgorithm is omitted from valid parameters.
            cursor = sequence.Content; int previousTag = 0x9f;
            while (cursor < sequence.End)
            {
                Node option = Read(parameters, ref cursor, sequence.End);
                if (option.Tag < 0xa0 || option.Tag > 0xa3 || option.Tag <= previousTag) throw new CryptographicException("Invalid RSA-PSS parameter order or tag.");
                previousTag = option.Tag;
                if (option.Tag != 0xa0)
                {
                    int valueCursor = option.Content;
                    Node valueNode = Expect(parameters, ref valueCursor, option.End, option.Tag == 0xa1 ? (byte)0x30 : (byte)0x02);
                    if (valueCursor != option.End || valueNode.Content == valueNode.End || (option.Tag != 0xa1 && (parameters[valueNode.Content] & 128) != 0))
                        throw new CryptographicException("Invalid RSA-PSS parameter value.");
                    continue;
                }
                int nested = option.Content; Node algorithm = Expect(parameters, ref nested, option.End, 0x30);
                if (nested != option.End) throw new CryptographicException("Invalid RSA-PSS hash wrapper.");
                nested = algorithm.Content; Node oid = Expect(parameters, ref nested, algorithm.End, 0x06);
                if (nested < algorithm.End)
                {
                    Node nullValue = Expect(parameters, ref nested, algorithm.End, 0x05);
                    if (nullValue.Content != nullValue.End || nested != algorithm.End) throw new CryptographicException("Invalid RSA-PSS hash parameters.");
                }
                string value = CertificateRecord.Hex(Copy(parameters, oid.Content, oid.End));
                hash = value == "2B0E03021A" ? "SHA-1" : value == "2A864886F70D0205" ? "MD5" :
                    value == "608648016503040201" ? "SHA-256" : value == "608648016503040202" ? "SHA-384" :
                    value == "608648016503040203" ? "SHA-512" : value == "608648016503040204" ? "SHA-224" : "Other RSA-PSS hash OID encoding: " + value;
            }
            return hash;
        }
    }
}
