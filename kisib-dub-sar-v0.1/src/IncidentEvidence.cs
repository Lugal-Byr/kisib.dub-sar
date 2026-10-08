using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Kisib
{
    [DataContract] internal sealed class IncidentNamespace
    {
        [DataMember] internal string Suffix, RegistryName, CountryCode;
    }
    [DataContract] internal sealed class IncidentHash
    {
        [DataMember] internal string Sha256, Source, Date, Tag;
    }
    [DataContract] internal sealed class BrowserIncidentReport
    {
        [DataMember] internal string Browser, Action, Scope, Source, Date, Tag;
    }
    [DataContract] internal sealed class CertificateIncident
    {
        [DataMember] internal string Id, Title, Source, Published, Summary, RevocationReport, Tag;
        [DataMember] internal IncidentNamespace[] Namespaces;
        [DataMember] internal IncidentHash[] Hashes;
        [DataMember] internal BrowserIncidentReport[] Browsers;
    }
    [DataContract] internal sealed class IncidentCatalog
    {
        internal const int ByteLimit = 8 * 1024 * 1024;
        [DataMember] internal int Version;
        [DataMember] internal string ReviewedUtc;
        [DataMember] internal CertificateIncident[] Incidents;
        internal string Sha256;

        internal static IncidentCatalog Read(string project)
        {
            byte[] bytes;
            using (FileStream file = new FileStream(Path.Combine(project, "data", "certificate-incidents.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length > ByteLimit) throw new InvalidOperationException("Incident catalog exceeds its byte limit.");
                bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int count = file.Read(bytes, offset, bytes.Length - offset); if (count == 0) throw new EndOfStreamException("Incident catalog changed during read."); offset += count; }
            }
            return Decode(bytes);
        }
        internal static IncidentCatalog Decode(byte[] bytes)
        {
            if (bytes == null || bytes.Length > ByteLimit) throw new InvalidOperationException("Invalid incident catalog size.");
            IncidentCatalog result;
            using (MemoryStream stream = new MemoryStream(bytes))
                result = (IncidentCatalog)new DataContractJsonSerializer(typeof(IncidentCatalog), new DataContractJsonSerializerSettings { MaxItemsInObjectGraph = 200000 }).ReadObject(stream);
            if (result == null) throw new InvalidOperationException("Incident catalog is missing.");
            result.Validate(); using (SHA256 hash = SHA256.Create()) result.Sha256 = CertificateRecord.Hex(hash.ComputeHash(bytes)); return result;
        }
        private static bool Text(string value, int limit)
        { return !String.IsNullOrWhiteSpace(value) && value.Length <= limit && !value.Any(c => Char.IsControl(c)); }
        private static bool Url(string value)
        {
            Uri uri; return Text(value, 2048) && Uri.TryCreate(value, UriKind.Absolute, out uri) && uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Host.Length > 0;
        }
        private static bool Date(string value)
        { DateTime date; return value != null && DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out date); }
        private static bool Tag(string value) { return value == "documented" || value == "to test"; }
        internal void Validate()
        {
            DateTime reviewed;
            if (Version != 1 || ReviewedUtc == null || ReviewedUtc.Length > 64 || !DateTime.TryParse(ReviewedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out reviewed) ||
                Incidents == null || Incidents.Length > 1000 || Incidents.Any(i => i == null || !Text(i.Id, 128) || !Text(i.Title, 256) || !Url(i.Source) || !Date(i.Published) ||
                    !Text(i.Summary, 4096) || !Text(i.RevocationReport, 2048) || !Tag(i.Tag) || i.Namespaces == null || i.Hashes == null || i.Browsers == null ||
                    i.Namespaces.Any(n => n == null || !Regex.IsMatch(n.Suffix ?? "", "^[a-z]{2,63}$") || !Text(n.RegistryName, 256) || !Regex.IsMatch(n.CountryCode ?? "", "^[A-Z]{2}$")) ||
                    i.Hashes.Any(h => h == null || !Regex.IsMatch(h.Sha256 ?? "", "^[A-F0-9]{64}$") || !Url(h.Source) || !Date(h.Date) || !Tag(h.Tag)) ||
                    i.Hashes.GroupBy(h => h.Sha256).Any(g => g.Count() > 1) || i.Namespaces.GroupBy(n => n.Suffix).Any(g => g.Count() > 1) ||
                    i.Browsers.Any(b => b == null || !Text(b.Browser, 128) || !Text(b.Action, 1024) || !Text(b.Scope, 2048) || !Url(b.Source) || !Date(b.Date) || !Tag(b.Tag))) ||
                Incidents.GroupBy(i => i.Id).Any(g => g.Count() > 1)) throw new InvalidOperationException("Incident catalog schema is invalid; no matches evaluated.");
        }
        internal static string NormalizeHash(string value)
        {
            string result = (value ?? "").Trim().Replace(" ", "").Replace(":", "").Replace("-", "").ToUpperInvariant();
            if (!Regex.IsMatch(result, "^[A-F0-9]{64}$")) throw new ArgumentException("Enter the complete certificate SHA-256 (64 hex characters), not an SPKI or SHA-1 hash.");
            return result;
        }
        internal CertificateIncident[] HashMatches(string sha256)
        {
            string hash = NormalizeHash(sha256);
            return Incidents.Where(i => i.Hashes.Any(h => h.Sha256 == hash)).ToArray();
        }
        internal CertificateIncident[] NamespaceMatches(string host)
        {
            string name = TlsInspection.NormalizeHost(host);
            return Incidents.Where(i => i.Namespaces.Any(n => name.EndsWith("." + n.Suffix, StringComparison.Ordinal) || name == n.Suffix)).ToArray();
        }
        internal string HashReport(string value, IEnumerable<CertificateRecord> certificates)
        {
            string hash = NormalizeHash(value); CertificateIncident[] hits = HashMatches(hash);
            StringBuilder text = new StringBuilder(); text.AppendLine("Certificate SHA-256: " + hash);
            text.AppendLine("Incident hash lookup [to test]: " + (hits.Length == 0 ? "MISS in this catalog; absence is not a safety verdict." : "HIT in the source records listed below; local enforcement remains separate."));
            text.AppendLine("Catalog reviewed UTC: " + ReviewedUtc + " | SHA-256: " + Sha256);
            text.AppendLine("Listed hashes: " + Incidents.Sum(i => i.Hashes.Length) + "; this is not a complete threat list.");
            foreach (CertificateIncident incident in hits) foreach (IncidentHash entry in incident.Hashes.Where(h => h.Sha256 == hash))
                text.AppendLine(incident.Title + " | " + entry.Date + " [" + entry.Tag + "]\r\n" + entry.Source);
            CertificateRecord[] found = (certificates ?? new CertificateRecord[0]).Where(c => c != null && c.Sha256 == hash).ToArray();
            text.AppendLine("Current inventory matches: " + found.Length + " [to test]. Store membership is not application use.");
            foreach (CertificateRecord certificate in found) text.AppendLine(certificate.SubjectShortName + " | " + certificate.FoundInText);
            return text.ToString();
        }
        internal string Describe(CertificateIncident incident)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine(incident.Title + " [" + incident.Tag + "]"); text.AppendLine("Published: " + incident.Published + " | catalog reviewed: " + ReviewedUtc);
            text.AppendLine(incident.Source); text.AppendLine(); text.AppendLine(incident.Summary); text.AppendLine();
            foreach (IncidentNamespace space in incident.Namespaces) text.AppendLine("Namespace ." + space.Suffix + " | " + space.RegistryName + " | registry country/territory code " + space.CountryCode);
            text.AppendLine("Namespace geography is separate from the certificate's subject/issuer C= and CA owner.");
            text.AppendLine("Published certificate hash entries in this catalog: " + incident.Hashes.Length + ". No hash entries means exact certificate identity remains unknown.");
            text.AppendLine("Issuer revocation report: " + incident.RevocationReport + " [" + incident.Tag + "]");
            text.AppendLine(); text.AppendLine("Browser reports (source reports, not this PC's enforcement):");
            foreach (BrowserIncidentReport browser in incident.Browsers)
                text.AppendLine(browser.Browser + ": " + browser.Action + " [" + browser.Tag + "]\r\nScope: " + browser.Scope + "\r\nDate: " + browser.Date + "\r\n" + browser.Source + "\r\nLocal browser result: unknown [to test].");
            text.AppendLine(); text.AppendLine("Microsoft term: X509Certificate2 / SHA256 [documented]; incident joins and display [to test].");
            text.AppendLine(IncidentSources.Certificate); text.AppendLine(IncidentSources.Hash);
            return text.ToString();
        }
    }
    internal static class IncidentSources
    {
        internal const string Certificate = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2";
        internal const string Hash = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256";
        internal const string Tls = "https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasclient?view=netframework-4.8.1";
        internal const string Callback = "https://learn.microsoft.com/en-us/dotnet/api/system.net.security.remotecertificatevalidationcallback?view=netframework-4.8.1";
        internal const string ChainStatus = "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags?view=netframework-4.8.1";
    }
}
