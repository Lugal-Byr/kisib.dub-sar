using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Kisib
{
    // Groups come only from the user's CSV files. Tags stack; every membership keeps its source.
    internal sealed class GroupNode
    {
        internal string Kind, Key, Label, Filter;   // Filter: "all", "enabled", "blocked"
        internal readonly HashSet<string> Members = new HashSet<string>(StringComparer.Ordinal);
        internal readonly Dictionary<string, SortedSet<string>> Why = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        internal GroupNode Parent;
        internal void Add(string identity, string reason)
        {
            Members.Add(identity);
            SortedSet<string> reasons;
            if (!Why.TryGetValue(identity, out reasons)) { reasons = new SortedSet<string>(StringComparer.Ordinal); Why.Add(identity, reasons); }
            reasons.Add(reason);
        }
    }

    internal sealed class GroupsRoot
    {
        internal string Error;
        internal readonly List<GroupNode> Tags = new List<GroupNode>();
        internal readonly List<GroupNode> Countries = new List<GroupNode>();
        internal readonly List<GroupNode> Owners = new List<GroupNode>();
        internal HashSet<string> Blocked = new HashSet<string>(StringComparer.Ordinal);
    }

    internal sealed class CountryRow
    {
        internal string Iso2, Name, CrownOf, BricCore, BricsPlus, Tags, YourGroup;
    }

    internal sealed class OwnerRow
    {
        internal string Owner, Match, Value, Country, Tags;
    }

    internal static class GroupCatalog
    {
        internal const string CountriesFile = "countries_monarchy_bric.csv";
        internal const string OwnersFile = "owners.csv";

        // Minimal RFC 4180 reader: quoted fields, doubled quotes, commas inside quotes.
        internal static List<string[]> ReadCsv(string path) { return ReadCsv(path, 4L * 1024 * 1024); }
        internal static List<string[]> ReadCsv(string path, long maxBytes)
        {
            if (new FileInfo(path).Length > maxBytes) throw new InvalidDataException(Path.GetFileName(path) + " exceeds " + (maxBytes / 1024 / 1024) + " MB.");
            string text = File.ReadAllText(path, new UTF8Encoding(false, true));
            List<string[]> rows = new List<string[]>(); List<string> row = new List<string>(); StringBuilder field = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (quoted)
                {
                    if (c == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; } else quoted = false; }
                    else field.Append(c);
                }
                else if (c == '"') quoted = true;
                else if (c == ',') { row.Add(field.ToString()); field.Length = 0; }
                else if (c == '\n' || c == '\r')
                {
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                    row.Add(field.ToString()); field.Length = 0;
                    if (row.Count > 1 || row[0].Length > 0) rows.Add(row.ToArray());
                    row = new List<string>();
                }
                else field.Append(c);
            }
            if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); rows.Add(row.ToArray()); }
            return rows;
        }

        private static Dictionary<string, int> Header(string[] header, string file, params string[] required)
        {
            Dictionary<string, int> index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < header.Length; i++) index[header[i].Trim().TrimStart('﻿')] = i;
            foreach (string name in required) if (!index.ContainsKey(name)) throw new InvalidDataException(file + " is missing column " + name + ".");
            return index;
        }
        private static string Cell(string[] row, Dictionary<string, int> index, string name)
        {
            int i; return index.TryGetValue(name, out i) && i < row.Length ? row[i].Trim() : "";
        }

        internal static Dictionary<string, CountryRow> ReadCountries(string path)
        {
            List<string[]> rows = ReadCsv(path);
            Dictionary<string, int> h = Header(rows[0], CountriesFile, "iso2", "name", "tags");
            Dictionary<string, CountryRow> result = new Dictionary<string, CountryRow>(StringComparer.OrdinalIgnoreCase);
            foreach (string[] row in rows.Skip(1))
            {
                CountryRow c = new CountryRow { Iso2 = Cell(row, h, "iso2").ToUpperInvariant(), Name = Cell(row, h, "name"), CrownOf = Cell(row, h, "crown_territory_of").ToUpperInvariant(),
                    BricCore = Cell(row, h, "bric_core"), BricsPlus = Cell(row, h, "brics_plus_verify"), Tags = Cell(row, h, "tags"), YourGroup = Cell(row, h, "your_group") };
                if (c.Iso2.Length == 2) result[c.Iso2] = c;
            }
            return result;
        }

        internal static List<OwnerRow> ReadOwners(string path)
        {
            if (!File.Exists(path)) return new List<OwnerRow>();
            List<string[]> rows = ReadCsv(path);
            Dictionary<string, int> h = Header(rows[0], OwnersFile, "owner", "match", "value", "country", "tags");
            return rows.Skip(1).Select(row => new OwnerRow { Owner = Cell(row, h, "owner"), Match = Cell(row, h, "match").ToLowerInvariant(),
                Value = Cell(row, h, "value"), Country = Cell(row, h, "country").ToUpperInvariant(), Tags = Cell(row, h, "tags") })
                .Where(o => o.Owner.Length > 0 && o.Value.Length > 0 && (o.Match == "subject_o" || o.Match == "issuer_o")).ToList();
        }

        // Each tag is one group label; ';' separates several in one cell. Emoji strings such as 🌿🧱 stay whole.
        internal static IEnumerable<string> Split(string cell)
        { return (cell ?? "").Split(';').Select(t => t.Trim()).Where(t => t.Length > 0); }

        internal static GroupsRoot Build(Snapshot snapshot, string sourceDirectory)
        {
            GroupsRoot root = new GroupsRoot();
            root.Blocked = BlockedIdentities(snapshot);
            Dictionary<string, CountryRow> countries;
            List<OwnerRow> owners;
            try
            {
                countries = ReadCountries(Path.Combine(sourceDirectory, "data", CountriesFile));
                owners = ReadOwners(Path.Combine(sourceDirectory, "data", OwnersFile));
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException)) throw;
                root.Error = ex.Message; return root;
            }
            Dictionary<string, GroupNode> tags = new Dictionary<string, GroupNode>(StringComparer.Ordinal);
            Dictionary<string, GroupNode> byCountry = new Dictionary<string, GroupNode>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, GroupNode> byOwner = new Dictionary<string, GroupNode>(StringComparer.OrdinalIgnoreCase);
            Func<Dictionary<string, GroupNode>, string, string, string, GroupNode> get = delegate(Dictionary<string, GroupNode> map, string kind, string key, string label)
            {
                GroupNode node;
                if (!map.TryGetValue(key, out node)) { node = new GroupNode { Kind = kind, Key = kind + ":" + key, Label = label, Filter = "all" }; map.Add(key, node); }
                return node;
            };
            foreach (CertificateRecord cert in snapshot.Certificates.Values)
            {
                List<KeyValuePair<string, string>> countryClaims = new List<KeyValuePair<string, string>>();
                if (!String.IsNullOrEmpty(cert.SubjectCountry)) countryClaims.Add(new KeyValuePair<string, string>(cert.SubjectCountry.ToUpperInvariant(), "subject C="));
                if (!String.IsNullOrEmpty(cert.IssuerCountry)) countryClaims.Add(new KeyValuePair<string, string>(cert.IssuerCountry.ToUpperInvariant(), "issuer C="));
                foreach (OwnerRow owner in owners)
                {
                    string o = owner.Match == "subject_o" ? cert.SubjectOrganization : cert.IssuerOrganization;
                    if (o == null || !String.Equals(o.Trim(), owner.Value, StringComparison.OrdinalIgnoreCase)) continue;
                    string why = "owner " + owner.Owner + " (" + (owner.Match == "subject_o" ? "subject O=" : "issuer O=") + owner.Value + ")";
                    get(byOwner, "owner", owner.Owner, owner.Owner).Add(cert.Identity, why);
                    foreach (string tag in Split(owner.Tags)) get(tags, "tag", tag, tag).Add(cert.Identity, why);
                    if (owner.Country.Length == 2) countryClaims.Add(new KeyValuePair<string, string>(owner.Country, why));
                }
                string ccadbOwner = Ccadb.OwnerOf(cert.Identity);
                if (ccadbOwner != null) get(byOwner, "owner", ccadbOwner, ccadbOwner).Add(cert.Identity, "CCADB CA Owner: " + ccadbOwner);
                foreach (KeyValuePair<string, string> claim in countryClaims)
                {
                    CountryRow row;
                    string name = countries.TryGetValue(claim.Key, out row) ? row.Name : "[not in country CSV]";
                    get(byCountry, "country", claim.Key, claim.Key + " — " + name).Add(cert.Identity, claim.Value);
                    if (row == null) continue;
                    string why = claim.Value + " " + claim.Key;
                    foreach (string tag in Split(row.Tags)) get(tags, "tag", tag, tag).Add(cert.Identity, why);
                    foreach (string group in Split(row.YourGroup)) get(tags, "tag", group, group).Add(cert.Identity, why + " (your_group)");
                    if (String.Equals(row.BricsPlus, "Y", StringComparison.OrdinalIgnoreCase)) get(tags, "tag", "BRICS+ (verify)", "BRICS+ (verify)").Add(cert.Identity, why + " (brics_plus_verify)");
                    CountryRow crown;
                    if (row.CrownOf.Length == 2 && countries.TryGetValue(row.CrownOf, out crown))
                        foreach (string tag in Split(crown.Tags)) get(tags, "tag", tag, tag).Add(cert.Identity, why + " (crown territory of " + row.CrownOf + ")");
                }
            }
            foreach (MyTagHit hit in MyTags.Matches(snapshot)) get(tags, "tag", hit.Tag, hit.Tag).Add(hit.Identity, hit.Why);
            root.Tags.AddRange(tags.Values.OrderBy(g => g.Label, StringComparer.Ordinal));
            root.Countries.AddRange(byCountry.Values.OrderBy(g => g.Label, StringComparer.OrdinalIgnoreCase));
            root.Owners.AddRange(byOwner.Values.OrderBy(g => g.Label, StringComparer.OrdinalIgnoreCase));
            return root;
        }

        // Blocked = observed in a Disallowed system store (Windows' untrusted list), any location.
        internal static HashSet<string> BlockedIdentities(Snapshot snapshot)
        {
            HashSet<string> disallowed = IncidentList.DisallowedPaths(snapshot);
            return new HashSet<string>(snapshot.Certificates.Values.Where(c => c.FoundIn.Any(disallowed.Contains) || c.Collections.Any(disallowed.Contains)).Select(c => c.Identity), StringComparer.Ordinal);
        }

        internal static GroupNode Filtered(GroupNode group, string filter, HashSet<string> blocked)
        {
            GroupNode node = new GroupNode { Kind = group.Kind, Key = group.Key, Label = group.Label, Filter = filter, Parent = group };
            foreach (string id in group.Members)
                if (filter == "blocked" ? blocked.Contains(id) : !blocked.Contains(id))
                    foreach (string why in group.Why[id]) node.Add(id, why);
            return node;
        }
    }
}
