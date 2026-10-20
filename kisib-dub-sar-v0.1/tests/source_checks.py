"""Source audit only. Does not compile C# or execute Windows APIs."""
from pathlib import Path
import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
checks = []


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    checks.append(label)


tokens = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[(){}\[\]]|[^/@"\'(){}\[\]]+|.', re.S)
for path in sorted(list((root / "src").glob("*.cs")) + list((root / "tests").glob("*.cs"))):
    stack = []
    for match in tokens.finditer(path.read_text(encoding="utf-8")):
        token = match.group()
        if token in "{([":
            stack.append(token)
        elif token in "})]":
            assert stack and "{(["["})]".index(token)] == stack.pop(), path.name + " delimiter mismatch"
        elif token in ('"', "'"):
            raise AssertionError(path.name + " unfinished string/character")
    check(not stack, path.name + " complete lexical delimiters")

source = "\n".join(path.read_text(encoding="utf-8") for path in (root / "src").glob("*.cs"))
imports = re.findall(r"extern\s+\w+\s+(\w+)\s*\(", source)
allowed = {"CertEnumSystemStoreLocation", "CertEnumSystemStore", "CertEnumPhysicalStore", "CertOpenStore", "CertEnumCertificatesInStore", "CertGetEnhancedKeyUsage", "CertFreeCertificateContext", "CertCloseStore", "SetLastError"}
archive_allowed = {"CreateFileW", "GetFileInformationByHandle", "GetFinalPathNameByHandleW"}
etw_allowed = {"StartTraceW", "ControlTraceW", "OpenTraceW", "ProcessTrace", "CloseTrace"}
crypto_imports = re.findall(r"extern\s+\w+\s+(\w+)\s*\(", (root / "src/Native.cs").read_text())
check(set(crypto_imports) == allowed, "Certificate native boundary stays restricted to the original read/enumerate/cleanup calls")
check(set(imports) == allowed | etw_allowed | archive_allowed and len(imports) == 17, "Only five ETW and three file-handle validation APIs extend the native boundary")
check(not re.search(r"Cert(?:Add|Delete|Set|Register|Unregister)|PFXImport|CryptAcquireCertificatePrivateKey|Registry.*(?:SetValue|CreateSubKey)", source), "No certificate mutation, private-key acquisition, or registry-write APIs")
check(source.count("Native.CertOpenStore(") == 1, "Single production store-open boundary")
check("location.Flags | Native.ReadFlags" in source and "CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG" in source, "All production store opens use read-only existing archived flags")
check("current = IntPtr.Zero;\n                        current = Native.CertEnumCertificatesInStore(handle, previous)" in source, "Previous context ownership passes to the enumerator")
check("finally\n                {\n                    if (current != IntPtr.Zero) Native.CertFreeCertificateContext(current);" in source, "Outstanding certificate context freed on early exit")
check("tree.ShowLines = true" in source and "tree.ShowRootLines = true" in source and "tree.ShowPlusMinus = true" in source, "Native Explorer tree connectors explicitly enabled")
check(re.findall(r'list.Columns.Add\("([^"]+)"', source) == ["Subject CN", "Issuer CN", "C=", "found in (physical stores)", "not-before", "not-after", "SHA-1", "SHA-256"], "Exactly the eight Screen 1 certificate columns")
check("right.Panel2.Controls.Add(detailTabs)" in source and "Orientation = Orientation.Horizontal" in source and 'new TabPage("Issuer 🏛️")' in source, "Native Details and Issuer temple tabs below list")
check("existing.Der.SequenceEqual(der)" in source, "Hash match checked against full DER before deduplication")
with (root / "docs/feature-sources.csv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream))
check(len(rows) == 126 and all(row["microsoft_term"] and row["learn_url"].startswith("https://learn.microsoft.com/") and row["tag"] in ("documented", "to test") for row in rows), "All 126 registered features have an underlying term/source/tag")
check(not any(row["tag"] == "documented" for row in rows if row["feature"] in {"Chain construction", "Local CSV lists", "Owner standings and country grouping", "CCADB hash lookup and program status"}), "Gated views stay to test")
check(all(row["tag"] == "to test" for row in rows if row["feature"] in {"Key size (bits)", "SPKI SHA-256", "Weak tier", "SHA-1 collision", "Key reuse"}), "Derived metadata and local inspection rules stay to test")
with (root / "docs/function-catalog.csv").open(encoding="utf-8", newline="") as stream:
    functions = list(csv.DictReader(stream))
check([row["function_id"] for row in functions] == ["F%03d" % i for i in range(1, 159)] and all(row["microsoft_term"] and row["learn_url"].startswith("https://learn.microsoft.com/") and row["tag"] in ("documented", "to test") for row in functions), "All 158 stable function IDs retain source/tag fields")
check(all(row["tag"] == "to test" for row in functions[111:142]), "New application/issuer/ETW implementations remain to test")
check("MaxCharactersInDocument = 4 * 1024 * 1024" in source and "DtdProcessing = DtdProcessing.Prohibit" in source and "XmlResolver = null" in source, "CAPI2 parser prohibits DTD/external resolution and bounds interpreted XML")
check('history.RecordActivity(activity)' in source and '!checkpointBlocked && record.Bookmark != null' in source and 'if (!saved) { checkpointBlocked = true;' in source, "CAPI2 source declares durable-before-checkpoint ordering and visible gap handling")
check('a.Covers(time.ToUniversalTime())' in source and 'ProcessId + "|" + (StartedUtc' in source, "PID correlation declares observed lifetime checks rather than name/PID-only identity")
check('Name = "kisib.dub-sar.Syscalls." + id' in source and 'EtwNative.ControlTraceW(session, Name, properties, 1)' in source and 'settings.EnableFlags = 0x00000080' in source, "Syscall controller declares unique ownership and the documented system-call provider flag")
check('settings.MaximumFileSize = 512' in source and 'samplesThisSecond > 500' in source and 'Original ETL page, without live display sampling' in source, "ETL ceiling and separate live display budget are explicit; original archive pager declared")
check('live.Key != app.Key' in source and 'FileShare.Read)' in source and 'X509Certificate.CreateFromSignedFile' in source and 'Not evaluated; embedded signer metadata only' in source, "Application signer declares lifetime/file-read boundaries and leaves signature trust unevaluated")
catalog = json.loads((root / "data/countries.json").read_text(encoding="utf-8"))
countries = catalog["Countries"]
check(catalog["Version"] == 1 and len(countries) == 248 and len({c["Code"] for c in countries}) == 248 and all(re.fullmatch(r"[A-Z]{2}", c["Code"]) and re.fullmatch(r"[A-Z]{3}", c["Alpha3"]) and re.fullmatch(r"[0-9]{3}", c["M49"]) and c["Name"] and c["Source"] and c["Date"] for c in countries), "Country seed preserves 248 unique sourced UN rows and valid code fields")
positive = [c for c in countries if c["Monarchy"] == "monarchy"]
check(len(positive) == 43 and all(c["MonarchySource"] and c["MonarchyDate"] and c["MonarchyTag"] == "to test" for c in positive) and all(c["Monarchy"] == "unknown" for c in countries if c not in positive), "Positive monarchy mappings are sourced/to-test; remaining statuses are explicitly unknown")
check('tags.Add("🌿")' not in source and 'tags.Add("🧱")' not in source and 'if (code == "RU")' not in source, "No hardcoded country-to-affiliation decisions")
check(hashlib.sha256((root / "data/countries_monarchy_bric.csv").read_bytes()).hexdigest() == "4b38d9d33a76e9b6f30fea822757450ebf0df6458b652fd5b304f0a041adaaeb", "Supplied country CSV remains byte-for-byte unchanged for the S3 gate")
manifest = ET.parse(root / "app.manifest")
privilege = manifest.find(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel")
check(privilege is not None and privilege.attrib["level"] == "asInvoker", "Optional executable manifest requests ordinary user privilege")
check(not any(path.suffix.lower() in (".pfx", ".p12", ".pem", ".key") for path in root.rglob("*")), "No private-key file in package")
check(not re.search(r"ExecutionPolicy|RunAs|Invoke-WebRequest|DownloadString", (root / "Start.cmd").read_text(), re.I), "Launcher has no policy bypass, elevation, or download")
explorer = "\n".join((root / ("src/" + name)).read_text() for name in ("ExplorerForm.cs", "ControlExplorer.cs", "ScreenOne.cs"))
check('EventLogConfiguration' not in explorer and 'SaveChanges' not in explorer and 'Process.Start(' not in explorer, "Screen 1 has no diagnostic-channel write or external-tool action")
check('groupBy' not in explorer and 'ExplorerScope' not in explorer and 'new ComboBox' not in (root / 'src/ControlExplorer.cs').read_text(), "Native store paths are the only tree view; no category scaffold or view switch")
check('CountryCatalog.Read' not in explorer and 'new IssuerLabels' not in explorer and 'RefreshApplications' not in explorer and 'activity.Restart' not in explorer, "Screen 1 never loads country decisions, inventories apps or starts CAPI2")
check('options.MenuItems.AddRange(new MenuItem[] { journalToggle, archiveToggle, autoScanToggle, syscallToggle })' in explorer and 'capi2Toggle' not in explorer and 'additionalViewsToggle' not in explorer, "Only the four requested off-by-default optional switches are exposed")
check('CertificateRecord[]' not in (root / "src/ControlExplorer.cs").read_text() and 'TabPage certificates = new TabPage("Certificates")' in explorer, "No issuer, country, application or branch-grid construction in Screen 1")
check('this.archiveDirectory = archiveDirectory;' in source and 'this.sourceDirectory = sourceDirectory;\n            try { history' not in source, "Default GUI creates no persistent archive writer")
check('historyTimer.Start();' not in (root / "src/ExplorerForm.cs").read_text(), "Default window does not start the repeating scan timer")
check('StoreErrors.Add(new StoreError' in source and 'errorsLink.LinkClicked' in source, "Error UI is bound to structured observed source errors")
check('DocumentedStoreReference' in source and 'SystemColors.GrayText' in source and 'enumeration incomplete' in source, "Absent documentation references remain separate and incomplete reads stay unknown")
check('TlsInspection' not in source and 'IncidentForm' not in source and 'manual_tls_observation' not in source and not (root / "data/certificate-incidents.json").exists(), "Later-stage TLS/incident implementation is removed from the active build")
report = "Source/data audit completed in Linux; these source assertions are separate from the hosted Windows runtime tests.\n\n" + "\n".join("PASS: " + label for label in checks) + "\n\nCurrent runtime evidence: docs/screen1-verification.txt. User-PC Screen 1 acceptance remains to test; historical country data is not loaded by Screen 1.\n"
(root / "docs/source-checks.txt").write_text(report, encoding="utf-8")
print(report)
