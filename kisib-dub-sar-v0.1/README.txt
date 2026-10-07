kisib.dub-sar v0.1 — read-only certificate explorer

Windows 11 Home / Pro. Classic native Explorer layout: tree left, list right, details below.

Open the explorer

Extract this folder. Double-click Start.cmd.
The source launcher compiles the included C# in Windows PowerShell and opens the native Windows window. For the compiled download, open kisib.dub-sar.exe directly. No SDK download is required. Hosted Windows tests passed; the Windows 11 Home/Pro acceptance gate remains pending. See docs/windows-verification-report.txt.

The first scan runs automatically. Expand a location, a system store, and a physical store. Click a store to list its certificates. Click a certificate for details. Drag the dividers to resize the panes. Click a list heading to sort. View > History log shows retained dates and sessions. Certificate > Certificate history shows the selected certificate's retained events. The visible History log button opens the same journal. F5 refreshes the current view and adds to history; an automatic non-overlapping scan runs every 60 seconds while the explorer is open.

Implemented source

Native system store location, system store, and physical store enumeration.
Read-only, existing-store opens, including archived certificates.
Native logical collection reads, separately from physical sibling reads.
Subject, Issuer, Not before, Not after, and Found in list columns.
Key algorithm, key size (bits), signature algorithm, and complete-DER SPKI SHA-256 columns.
Requested local weak-tier rule: RSA <2048 bits, MD5 signature, or SHA-1 signature; every reason remains visible.
Inventory-wide SHA-1 collision signal (same SHA-1 / different SHA-256) with a red cell and peer evidence.
Inventory-wide key-reuse signal (same SPKI SHA-256 / different full subjects) with peer evidence.
Native Details and Issuer 🏛️ tabs, plus Activity evidence and Relationships. Issuer name is recorded data; issuer-certificate resolution remains after the gate.
SHA-1 and SHA-256 of certificate DER, with copy buttons.
SPKI SHA-256 has a separate copy button. Metadata extraction and local rules are tagged to test; API names are documented. A no-match or no-listed-criterion result is not a Windows trust verdict.
Key Usage and Windows effective Enhanced Key Usage by store occurrence.
Persistent per-event UTC journal, explicit native errors, and enumeration summary.
Immediate public DER retention and immutable inventory/index history; identical content is stored once.
Restart baseline recovery, successful-source occurrence/EKU comparisons, storage-failure status and dated history pagination.
Application data is retained at %LOCALAPPDATA%\kisib.dub-sar\History; Windows stores stay read-only.
Help > Feature sources supplies Microsoft's terms, Learn URLs, and tags.

Execution status: to test. This package has not run on Windows in the development workspace. It contains source and launch/build commands, not a verified release executable. No sample certificate is loaded into the explorer.

Scope gate

First prove that the explorer opens and accounts for this Windows machine's discoverable stores, including visible access errors and unresolved sources. Follow docs/windows-acceptance.txt. Durable observation history is included as prepared source from the first scan. Native chain, CTL, complete CCADB catalog ingestion, CSV ingestion, and owner-count standings remain specified after their gates. The latest user instruction authorizes preparing issuer grouping and supported application tracing now; these sources still require Windows verification. The whole CA catalog is the required baseline; consumer software is supplemental provenance. No full CA reference dataset has been ingested here; the sourced country/area seed is a separate metadata catalog. No backup, import, store write, private-key access, elevation broker, or certificate mutation API is included.

Optional source build

Double-click Build.cmd to compile bin\kisib.dub-sar.exe with the Windows .NET Framework compiler when available. This path is also to test. Keep the project folder with the EXE so Help can find docs. No signing or Microsoft Store submission is claimed for v0.1.

Verification

Test.cmd includes archive restart/deduplication, successful-source comparisons, denied/canceled reads, concurrency, interrupted-tail handling, storage-failure, altered-index refusal, page coverage and a 10,025-record synthetic codec check, followed by key metadata/SPKI, weak-rule boundaries, collision/key-reuse logic, read-only opening, identity/occurrence, and native inventory checks on Windows. Public synthetic certificates in tests are parser fixtures and are never installed in a store or displayed in the explorer. The collision logic test uses artificial hash labels, not a generated cryptographic collision. The codec check is not a real CA catalog or performance measurement. No fixture private key is included. Manual Home/Pro coverage and UI checks remain required.

docs/specification.txt is the project's scope and feature order.
docs/feature-sources.csv is the feature-to-term/source register.
docs/windows-acceptance.txt is the machine acceptance gate.
docs/function-catalog.csv retains every function with a stable ID, source/tag, implementation state, and verification requirement.
docs/design-decisions.txt records the issuer controls on the far-left tree, retained country/tag grouping requirements, Enabled/Blocked scopes, playoff grid, and history decisions while the GUI is being chosen.
Issuer/country/app views and supported CAPI2/optional ETW monitoring now have prepared source; blocking enforcement remains unimplemented. See docs/live-control-layer.txt for actual source and coverage boundaries.

docs/tag-palette.json retains the proposed independent issuer badges, undefined meanings, existing rule references and future tree/history behavior.

docs/archive-requirements.txt records the continuing archive, full CA baseline, historical source rules, storage assumptions and actual coverage.
Archive runtime tests are prepared but have not run in this Linux development workspace. All-application usage tracing and full CCADB catalog ingestion remain required separate functions.

Application and issuer evidence — prepared source, Windows to test

Find issuer, Group by and Sort by are on the far-left tree. Search includes
complete certificate/SPKI hashes, names, local owner/corporation, countries,
tags and observed store paths. Group by issuer, country, corporation, monarchy,
independent tags or applications. Real Windows location/system/physical paths
remain visible. Requested Enabled/Blocked/Unassigned branches have no OS
enforcement. Issuer labels and Country labels save app-local immutable versions.

Applications lists observed process lifetimes, paths and access errors. Live
activity shows CAPI2 source operations and optional syscall examples. Selecting
an event shows original evidence and its explicit certificate lookup matches.
Relationships displays emitter, reported references, matches and current issuer
labels; it does not invent a Windows certificate chain or political control.

The app follows CAPI2 Operational automatically if enabled, replays available
records and retains every received payload before advancing its bookmark.
Live > Enable Windows CAPI2 logging is an explicit diagnostic-channel setting
change; it does not alter trust stores. Access failures and disabled logging
are visible. Windows log retention bounds replay while this app is closed.

Start syscalls starts an owned 64-bit Windows ETW capture when permissions
allow. Original ETL files are retained, with a 512 MB sequential capture
ceiling. Live display limits do not delete archived payloads. Use Live >
Retained certificate activity or Retained syscall ETLs for 500-record pages.
Automatic syscall rotation/background service coverage is still pending.
No capture is started automatically with elevation.

Live > Selected application's embedded signer reads the selected current
executable's file SHA-256 and public signer certificate. Signature/chain trust
is not evaluated; catalog-only and unsupported files report the gap.

The country seed has 248 UN M49 country/area rows and 43 sourced positive
monarchy classifications; the other 205 are unknown and editable. See per-row
sources/dates in data/countries.json. Current labels cannot rewrite original
event payloads. Full CA ownership/program data and universal verifier coverage
remain required, separate work. Real Windows execution evidence is in docs/windows-verification-report.txt.

Test.cmd also prepares synthetic CAPI2 XML/parser/correlation tests, PID reuse
boundaries, exact DER name extraction, sourced country/tag rules, immutable
label/replay history and 64-bit ETW ABI checks. Test.cmd runs the read-only suite and does not enable a Windows diagnostic log or
start kernel capture. Hosted CI additionally exercised temporary diagnostic logging,
owned kernel capture, the GUI and adversarial fixtures on disposable VMs. Follow the
remaining manual Windows 11 Home/Pro acceptance.

Security and archive handling — 2026-10-07

History pins actual local directories and validates opened file handles before
reading or writing. Reparse paths and multiply linked archive files are refused.
Untrusted retained records get bounded parsing and explicit schema errors.
Ordinary observation rows reach the OS immediately and sync on the next one-second
timer tick under normal scheduling; CAPI2/label/scan commits sync before returning.
Closing flushes outstanding rows. Scheduling delays, disk failures or sudden power
loss can still interrupt the latest ordinary observations; gaps are not hidden.
The full continuing journal remains per event, with every original source row.

This is an unsigned tested preview, not a production security certification or
Microsoft Store package. Source is on the repository verification branch.
