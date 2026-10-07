using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Kisib
{
    [DataContract] internal sealed class CountryRecord
    {
        [DataMember] internal string Code;
        [DataMember] internal string Alpha3;
        [DataMember] internal string M49;
        [DataMember] internal string Name;
        [DataMember] internal string Region;
        [DataMember] internal string Source;
        [DataMember] internal string Date;
        [DataMember] internal string Monarchy;
        [DataMember] internal string MonarchySource;
        [DataMember] internal string MonarchyDate;
        [DataMember] internal string MonarchyTag;
    }
    [DataContract] internal sealed class CountryCatalog
    {
        [DataMember] internal int Version = 1;
        [DataMember] internal string Source;
        [DataMember] internal string RetrievedUtc;
        [DataMember] internal CountryRecord[] Countries;
        private Dictionary<string, CountryRecord> byCode;
        internal static CountryCatalog Read(string directory)
        {
            byte[] bytes;
            using (FileStream file = new FileStream(Path.Combine(directory, "data", "countries.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length > 1024 * 1024) throw new InvalidOperationException("Country catalog exceeds its explicit byte size limit.");
                bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int count = file.Read(bytes, offset, bytes.Length - offset); if (count == 0) throw new EndOfStreamException("Country catalog changed during read."); offset += count; }
            }
            CountryCatalog result = HistoryArchive.Decode<CountryCatalog>(bytes);
            if (result == null || result.Version != 1 || String.IsNullOrEmpty(result.Source) || String.IsNullOrEmpty(result.RetrievedUtc) || result.Countries == null || result.Countries.Any(c => c == null ||
                !Regex.IsMatch(c.Code ?? "", "^[A-Z]{2}$") || !Regex.IsMatch(c.Alpha3 ?? "", "^[A-Z]{3}$") || !Regex.IsMatch(c.M49 ?? "", "^[0-9]{3}$") ||
                String.IsNullOrEmpty(c.Name) || String.IsNullOrEmpty(c.Source) || String.IsNullOrEmpty(c.Date) ||
                c.Monarchy != "unknown" && c.Monarchy != "monarchy" && c.Monarchy != "not monarchy" ||
                c.Monarchy != "unknown" && (String.IsNullOrEmpty(c.MonarchySource) || String.IsNullOrEmpty(c.MonarchyDate) || c.MonarchyTag != "to test")) ||
                result.Countries.GroupBy(c => c.Code).Any(g => g.Count() != 1)) throw new InvalidOperationException("Country catalog schema is invalid.");
            return result;
        }
        internal CountryRecord Find(string code)
        {
            if (String.IsNullOrEmpty(code)) return null;
            if (byCode == null) byCode = Countries.ToDictionary(c => c.Code, StringComparer.Ordinal);
            CountryRecord result; return byCode.TryGetValue(code, out result) ? result : null;
        }
        internal string Display(string code)
        { CountryRecord country = Find(code); return country == null ? (String.IsNullOrEmpty(code) ? "Unknown country" : code + " — unmapped country") : country.Code + " " + country.Name + (country.Monarchy == "monarchy" ? " 👑" : ""); }
    }

    [DataContract] internal sealed class CertificateLabel
    {
        [DataMember] internal string Identity;
        [DataMember] internal string Owner;
        [DataMember] internal string Corporation;
        [DataMember] internal string OwnerCountry;
        [DataMember] internal string Tags;
        [DataMember] internal string Policy = "Unassigned";
        [DataMember] internal string Source = "User-defined";
        [DataMember] internal string Date;
    }
    [DataContract] internal sealed class CountryLabel
    {
        [DataMember] internal string Code;
        [DataMember] internal string Monarchy = "unknown";
        [DataMember] internal string Tags;
        [DataMember] internal string Source = "User-defined";
        [DataMember] internal string Date;
    }
    [DataContract] internal sealed class AnnotationSet
    {
        [DataMember] internal int Version = 1;
        [DataMember] internal string Id = Guid.NewGuid().ToString("N");
        [DataMember] internal string Utc = DateTime.UtcNow.ToString("o");
        [DataMember] internal List<CertificateLabel> Certificates = new List<CertificateLabel>();
        [DataMember] internal List<CountryLabel> Countries = new List<CountryLabel>();
        internal void Validate()
        {
            if (Version != 1 || Certificates == null || Countries == null || Certificates.Any(c => c == null || String.IsNullOrWhiteSpace(c.Identity) ||
                c.Policy != "Enabled" && c.Policy != "Blocked" && c.Policy != "Unassigned" || String.IsNullOrWhiteSpace(c.Source) || String.IsNullOrWhiteSpace(c.Date) ||
                !String.IsNullOrEmpty(c.OwnerCountry) && !Regex.IsMatch(c.OwnerCountry, "^[A-Z]{2}$")) ||
                Certificates.GroupBy(c => c.Identity).Any(g => g.Count() > 1) || Countries.Any(c => c == null || !Regex.IsMatch(c.Code ?? "", "^[A-Z]{2}$") ||
                c.Monarchy != "monarchy" && c.Monarchy != "not monarchy" && c.Monarchy != "unknown" || String.IsNullOrWhiteSpace(c.Source) || String.IsNullOrWhiteSpace(c.Date)) ||
                Countries.GroupBy(c => c.Code).Any(g => g.Count() > 1)) throw new InvalidOperationException("Issuer label schema is invalid; prior version remains authoritative.");
        }
        internal AnnotationSet Next()
        {
            AnnotationSet result = HistoryArchive.Decode<AnnotationSet>(HistoryArchive.Encode(this));
            result.Id = Guid.NewGuid().ToString("N"); result.Utc = DateTime.UtcNow.ToString("o"); return result;
        }
    }

    internal sealed class IssuerEvidence
    {
        internal string SubjectCountry;
        internal string IssuerCountry;
        internal string IssuerOrganization;
        internal string Error;
        internal static IssuerEvidence Read(CertificateRecord record)
        {
            IssuerEvidence result = new IssuerEvidence();
            try
            {
                using (X509Certificate2 certificate = new X509Certificate2(record.Der))
                {
                    result.SubjectCountry = NameAttributes.Single(certificate.SubjectName.RawData, 6);
                    result.IssuerCountry = NameAttributes.Single(certificate.IssuerName.RawData, 6);
                    result.IssuerOrganization = NameAttributes.Single(certificate.IssuerName.RawData, 10);
                }
            }
            catch (Exception ex) { result.Error = ex.GetType().Name + ": " + ex.Message; }
            return result;
        }
    }

    // Read DER name attributes, rather than splitting a formatted DN on commas.
    internal static class NameAttributes
    {
        private sealed class Part { internal int Tag, End, Content; }
        private static Part Read(byte[] data, ref int offset, int limit)
        {
            if (offset + 2 > limit) throw new InvalidOperationException("Truncated name attribute.");
            int tag = data[offset++], length = data[offset++];
            if ((tag & 31) == 31) throw new InvalidOperationException("Unsupported name tag.");
            if ((length & 128) != 0)
            {
                int count = length & 127; if (count == 0 || count > 4 || offset + count > limit || data[offset] == 0) throw new InvalidOperationException("Invalid name length.");
                long actual = 0; for (int i = 0; i < count; i++) actual = (actual << 8) | data[offset++];
                if (actual < 128 || actual > Int32.MaxValue) throw new InvalidOperationException("Invalid name length."); length = (int)actual;
            }
            if (length > limit - offset) throw new InvalidOperationException("Truncated name contents.");
            Part part = new Part { Tag = tag, Content = offset, End = offset + length }; offset = part.End; return part;
        }
        internal static string Single(byte[] bytes, byte attribute)
        {
            int offset = 0; Part name = Read(bytes, ref offset, bytes.Length);
            if (name.Tag != 48 || offset != bytes.Length) throw new InvalidOperationException("Invalid DER name.");
            List<string> found = new List<string>(); int setOffset = name.Content;
            while (setOffset < name.End)
            {
                Part set = Read(bytes, ref setOffset, name.End); if (set.Tag != 49) throw new InvalidOperationException("Invalid name RDN set.");
                int pairOffset = set.Content;
                while (pairOffset < set.End)
                {
                    Part pair = Read(bytes, ref pairOffset, set.End); if (pair.Tag != 48) throw new InvalidOperationException("Invalid name attribute sequence.");
                    int fieldOffset = pair.Content; Part oid = Read(bytes, ref fieldOffset, pair.End), value = Read(bytes, ref fieldOffset, pair.End);
                    if (oid.Tag != 6 || fieldOffset != pair.End) throw new InvalidOperationException("Invalid name attribute fields.");
                    if (oid.End - oid.Content != 3 || bytes[oid.Content] != 85 || bytes[oid.Content + 1] != 4 || bytes[oid.Content + 2] != attribute) continue;
                    string text;
                    if (value.Tag == 12) text = new UTF8Encoding(false, true).GetString(bytes, value.Content, value.End - value.Content);
                    else if (value.Tag == 19 || value.Tag == 22)
                    {
                        if (bytes.Skip(value.Content).Take(value.End - value.Content).Any(b => b > 127)) throw new InvalidOperationException("Invalid ASCII name attribute.");
                        text = Encoding.ASCII.GetString(bytes, value.Content, value.End - value.Content);
                    }
                    else if (value.Tag == 30 && (value.End - value.Content) % 2 == 0) text = new UnicodeEncoding(true, false, true).GetString(bytes, value.Content, value.End - value.Content);
                    else throw new InvalidOperationException("Unsupported name string encoding.");
                    if (attribute == 6) { if (!Regex.IsMatch(text, "^[A-Za-z]{2}$")) throw new InvalidOperationException("Country name attribute is not an alpha-2 code."); text = text.ToUpperInvariant(); }
                    found.Add(text);
                }
            }
            return found.Count == 1 ? found[0] : null; // conflicting/multiple country or organization values remain unresolved
        }
    }

    internal sealed class IssuerLabels
    {
        internal readonly CountryCatalog Catalog;
        internal AnnotationSet Annotations;
        private readonly Dictionary<string, IssuerEvidence> evidence = new Dictionary<string, IssuerEvidence>(StringComparer.Ordinal);
        private AnnotationSet indexedAnnotations;
        private Dictionary<string, CertificateLabel> certificateLabels;
        private Dictionary<string, CountryLabel> countryLabels;
        internal IssuerLabels(CountryCatalog countries, AnnotationSet annotations) { Catalog = countries; Annotations = annotations; }
        private void IndexAnnotations()
        {
            if (indexedAnnotations == Annotations && certificateLabels.Count == Annotations.Certificates.Count && countryLabels.Count == Annotations.Countries.Count) return;
            certificateLabels = Annotations.Certificates.ToDictionary(c => c.Identity, StringComparer.Ordinal);
            countryLabels = Annotations.Countries.ToDictionary(c => c.Code, StringComparer.Ordinal); indexedAnnotations = Annotations;
        }
        internal IssuerEvidence Evidence(CertificateRecord certificate)
        {
            IssuerEvidence result;
            if (!evidence.TryGetValue(certificate.Identity, out result)) { result = IssuerEvidence.Read(certificate); evidence.Add(certificate.Identity, result); }
            return result;
        }
        internal CertificateLabel Label(CertificateRecord certificate)
        { IndexAnnotations(); CertificateLabel result; return certificateLabels.TryGetValue(certificate.Identity, out result) ? result : null; }
        internal CountryLabel CountryOverride(string code)
        { IndexAnnotations(); CountryLabel result; return code != null && countryLabels.TryGetValue(code, out result) ? result : null; }
        internal string Policy(CertificateRecord certificate) { CertificateLabel label = Label(certificate); return label == null ? "Unassigned" : label.Policy; }
        internal string Country(CertificateRecord certificate)
        { CertificateLabel label = Label(certificate); return label != null && !String.IsNullOrEmpty(label.OwnerCountry) ? label.OwnerCountry : Evidence(certificate).IssuerCountry; }
        internal string Monarchy(string code)
        {
            CountryLabel label = CountryOverride(code);
            CountryRecord record = Catalog == null ? null : Catalog.Find(code);
            return label != null ? label.Monarchy : record == null ? "unknown" : record.Monarchy ?? "unknown";
        }
        internal string CountryDisplay(string code)
        {
            CountryRecord country = Catalog == null ? null : Catalog.Find(code);
            return country == null ? String.IsNullOrEmpty(code) ? "Unknown country" : code + " — unmapped country" :
                country.Code + " " + country.Name + (Monarchy(code) == "monarchy" ? " 👑" : "");
        }
        internal string[] Tags(CertificateRecord certificate)
        {
            string code = Country(certificate); SortedSet<string> tags = new SortedSet<string>(StringComparer.Ordinal);
            if (new string[] { "BR", "RU", "IN", "CN" }.Contains(code)) { tags.Add("🌿"); tags.Add("🧱"); }
            if (code == "RU") tags.Add("🇷🇺");
            if (Monarchy(code) == "monarchy") tags.Add("👑");
            CertificateLabel label = Label(certificate); AddTags(tags, label == null ? null : label.Tags);
            CountryLabel country = CountryOverride(code); AddTags(tags, country == null ? null : country.Tags);
            return tags.ToArray();
        }
        private static void AddTags(SortedSet<string> tags, string raw)
        { if (!String.IsNullOrEmpty(raw)) foreach (string tag in raw.Split(new char[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) tags.Add(tag); }
        internal string Describe(CertificateRecord certificate)
        {
            IssuerEvidence facts = Evidence(certificate); CertificateLabel labels = Label(certificate);
            CountryRecord country = Catalog == null ? null : Catalog.Find(Country(certificate));
            StringBuilder text = new StringBuilder();
            text.AppendLine("Issuer DN: " + certificate.Issuer);
            text.AppendLine("Issuer organization attribute O=: " + (facts.IssuerOrganization ?? "Unknown"));
            text.AppendLine("Subject C=: " + (facts.SubjectCountry ?? "Unknown") + " | issuer C=: " + (facts.IssuerCountry ?? "Unknown"));
            text.AppendLine("Mapped CA owner: " + (labels == null || String.IsNullOrEmpty(labels.Owner) ? "Unknown" : labels.Owner));
            text.AppendLine("Corporation/group: " + (labels == null || String.IsNullOrEmpty(labels.Corporation) ? "Unassigned" : labels.Corporation));
            text.AppendLine("Owner country: " + (labels == null || String.IsNullOrEmpty(labels.OwnerCountry) ? "Unknown" : labels.OwnerCountry));
            text.AppendLine("Grouping country basis: " + (labels != null && !String.IsNullOrEmpty(labels.OwnerCountry) ? "Local owner mapping" : "Issuer C= declaration"));
            text.AppendLine("Country/area: " + CountryDisplay(Country(certificate)));
            text.AppendLine("Monarchy classification: " + Monarchy(Country(certificate)));
            if (country != null) text.AppendLine("Classification source/date: " + country.MonarchySource + " | " + country.MonarchyDate + " | " + country.MonarchyTag);
            CountryLabel countryLabel = CountryOverride(Country(certificate));
            if (countryLabel != null) text.AppendLine("Local country override source/date: " + countryLabel.Source + " | " + countryLabel.Date);
            text.AppendLine("Independent tags: " + String.Join(" ", Tags(certificate)));
            text.AppendLine("Requested policy: " + Policy(certificate) + " | OS enforcement: not implemented");
            text.AppendLine("Label source/date: " + (labels == null ? "Unassigned" : labels.Source + " | " + labels.Date));
            text.AppendLine("Label version: " + Annotations.Id + " | " + Annotations.Utc);
            text.AppendLine("BRIC rule uses the four original BR/ RU/ IN/ CN codes requested by the user; expanded BRICS membership is a separate pending dataset.");
            text.AppendLine("Country metadata and owner labels identify grouping evidence. They do not establish control over a certificate or an application's actions.");
            if (facts.Error != null) text.AppendLine("Name decoding: " + facts.Error);
            text.AppendLine("Microsoft: X500DistinguishedName.RawData; X509Certificate2.IssuerName / SubjectName. Extraction and label mapping: to test.");
            return text.ToString();
        }
        internal bool Matches(CertificateRecord certificate, string query)
        {
            if (String.IsNullOrEmpty(query)) return true;
            CertificateLabel label = Label(certificate); IssuerEvidence facts = Evidence(certificate);
            CountryRecord country = Catalog == null ? null : Catalog.Find(Country(certificate));
            string[] fields = new string[] { certificate.Subject, certificate.Issuer, certificate.Sha1, certificate.Sha256, certificate.SpkiSha256,
                certificate.FoundInText, facts.SubjectCountry, facts.IssuerCountry, label == null ? null : label.Owner, label == null ? null : label.Corporation,
                label == null ? null : label.OwnerCountry, country == null ? null : country.Name, country == null ? null : country.Code,
                country == null ? null : country.Alpha3, String.Join(" ", Tags(certificate)) };
            return fields.Any(field => field != null && field.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }
}
