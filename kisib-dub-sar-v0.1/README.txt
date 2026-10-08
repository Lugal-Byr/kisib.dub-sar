kisib.dub-sar v0.1 — Screen 1
Windows 11 Home / Pro; read-only certificate explorer

Open kisib.dub-sar.exe from the fully extracted download folder.
Source launch: Start.cmd. Optional source compilation: Build.cmd.
Neither launcher requests elevation, changes execution policy or downloads code.

Classic Explorer: tree left, list right, details below.
The tree shows Windows location > system store > physical store.
Every returned physical store has its own count, including zero.
A grey “not present” item is a Microsoft documentation reference, not an observed store.
Failed/incomplete enumeration stays unknown and reports the source error.

Columns: Subject CN, Issuer CN, C=, found in (physical stores), not-before,
not-after, SHA-1, SHA-256. Names use CN then O; full DNs stay in Details.
C= is the certificate's own declaration, not an owner or affiliation finding.
Find filters rows while keeping every native branch and count.
Click the bottom error count for the complete Store/Error list.

View > Optional features has exactly four switches, OFF every launch:
Journal, Archive public certificates, 60-second automatic scan, Syscall capture.
Default opening creates no history directory or automatic scan/capture.
Journal logs observations without saving public DER or inventories.
Archive is a separate opt-in requiring Journal. Existing records remain when disabled.
Syscall capture requires Archive; access failures do not trigger elevation.
Stop capture and finish the current scan before changing recording settings.
Original syscall events remain in the ETL; counts do not establish certificate use.

Microsoft terms, Learn URLs and documented/to test tags are in Help > Feature
sources and docs/feature-sources.csv. API documentation, custom display behavior,
hosted verification and user-PC acceptance are separate evidence.

ACCEPTANCE — USER PC, NOT CI [to test]
Leave Optional features off. Expand LOCAL_MACHINE > Root. Type FNMT into Find.
Take the whole-window screenshot on that PC. Children/counts must reflect Windows.
Absent documented siblings remain grey references. CI cannot satisfy this gate.

Only Screen 1 is current. Blocking, country/group integration, chain grids,
observed-app decisions and Explorer associations are parked. Do not build,
stub or scaffold them before the previous acceptance passes.
The supplied country CSV is saved unchanged for S3; Screen 1 does not read it.
Prior implementations and evidence remain in Git and historical documents.

Scope: docs/current-task-and-roadmap.txt and docs/screen1-scope.txt.
Registers: docs/function-catalog.csv and docs/feature-sources.csv.
Test.cmd is the read-only consumer-machine suite. Hosted CI separately runs
collector probes in disposable VMs, GUI regressions and the actual EXE.
Current evidence: docs/screen1-verification.txt. User-PC acceptance is pending.
This is an unsigned preview; no Microsoft Store submission is claimed.
