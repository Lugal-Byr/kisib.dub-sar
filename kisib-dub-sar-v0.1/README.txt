kisib.dub-sar — GETTIN’ ROLLED SINCE -2199
by S-CORP-i0N. Copyright © 2026 S-CORP-ION.
Free for personal, noncommercial use with credit (PolyForm Noncommercial 1.0.0,
see LICENSE). Commercial use needs a license from S-CORP-ION.

kisib.dub-sar v0.1 — Screen 1
Windows 11 Home / Pro; read-only certificate explorer

Open kisib.dub-sar.exe from the fully extracted download folder.
The source repository includes Start.cmd and the optional Build.cmd compiler command.
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
GROUPS AND BLOCKING
The Groups tab sorts every certificate six ways:
  Blocs       👑 monarchy  🏛️ EU  🧱 BRIC  🧱 BRICS+  🌿 Basel / CBDC  💃 supranational
              corporations. Tags stack: Spain is 👑🏛️, the UAE is 👑 🧱+ 🌿.
  Continents  all seven (UN country list); Middle East is a region inside Asia.
  Countries   from the C= on the certificate (subject and issuer).
  Owners      CA owner by O= (data\owners.csv) and every owner listed in CCADB.
  Status      blocked by kisib, blocked before kisib, not on this PC, expired,
              weak, incident (published compromised keys).
  My tags     yours only, kept in PORTABLE BACKUP LISTS, never in the public repo.
Block > Block by bloc and continent (Ctrl+B, or the Blocs... button): click
blocs and continents, and the grid shows every country they catch: owners,
roots, intermediates, blocked now, what this block adds, cross-signs that get
rerouted or cut off, and why. Preview block shows the exact list; Block + keep
blocked also saves rules so new matches get blocked after every scan.
Blocked certificates go into Windows' Disallowed store (this user; whole PC
when kisib runs as administrator). Nothing is deleted. Undo last block puts
it back. Block > Block history shows every change.
Data: data\countries_monarchy_bric.csv (continent, region, monarchy, eu,
bric_core, brics_plus, basel, tags, your_group, with a source on every row)
and data\owners.csv. Edit them and press F5.

PORTABLE BACKUP LISTS
Everything kisib remembers is plain .txt in the PORTABLE BACKUP LISTS folder next
to kisib.dub-sar.exe (File > Open PORTABLE BACKUP LISTS folder). Keep the kisib
folder on a USB stick or another drive. After a reformat, run kisib as
administrator once: every block in "BLOCKED CERTIFICATES (re-applied after
reformat).txt" is put back, and your rules and tags carry on. Unzipping a new
version next to the old one copies the lists over automatically.

ALLOW FOR A WHILE
When something gets refused, the pop-up has Allow 3 / 10 / 60 min buttons.
kisib lifts that block (and its siblings from the same company or key), counts
down in the status bar, and puts it back on time, even if kisib was closed.
Also: Certificate > Allow for N minutes, and the buttons in Certificate denials.

ALWAYS ON
File > Start with Windows (in tray): run kisib as administrator once and tick it.
It then starts at logon in the tray, watching. File > Minimize to tray.
Denials are saved, so View > Certificate denials keeps history across days.

MY TAGS
View > Edit my tags: tag by country code, organization name or certificate.
"Add EU" tags all 27 member states. Certificate > Tag this certificate / Tag
this organization does it from the list. Tags appear under Groups > Tags.

BACK DOORS (CCADB)
Block > Update CCADB list downloads every CA certificate the browser root
programs know, including intermediates and cross-signs never seen on this PC.
Rules then block those too, so a Spanish CA signed by a British root still
gets caught.

DENIAL ALERTS
When any program on this PC is refused a certificate (curl, winget, Edge,
Windows apps), kisib flashes in the taskbar and pops a notice: which program,
which certificate, why, and whether one of your blocks did it.
View > Certificate denials lists them. Run kisib as administrator once so it
can switch on Windows' certificate log (CAPI2); after that it just watches.
View > Watch for certificate denials turns it off and on.

REROUTE CHECK (CROSS-SIGNS)
One CA key can hang under more than one root (a cross-sign). Tools > Reroute
check (Ctrl+R) maps every path offline from this PC, the Microsoft list and CCADB:
  LEAK        a blocked CA that still has a way in, so the block does not hold.
              Right-click > Block the leak.
  rerouted    a CA under a blocked root that still reaches another root you
              trust (e.g. Google's GTS Root R1 when GlobalSign BE is blocked).
              "Windows can find it: no" means the cross-sign is only in CCADB;
              right-click > Install route adds it to Intermediate Certification
              Authorities so Windows can take that path. No root is added and
              nothing is unblocked.
  cut off     no path left; only Allow gets it through.
Certificate denials: right-click > Reroute around the block does the same for one
refusal. The block preview shows what a block cuts off and what gets rerouted.
The Status column marks LEAK / rerouted / cut off; the card shows the path.
Routes live in ROUTES (...).txt and come back after a reformat. Tools > Routes kisib
installed removes them. Windows picks the path itself [to test].

KEEP GROUPS BLOCKED
Block > Update Microsoft root list downloads every root Windows trusts, including
ones not on this PC yet, so they can be blocked before they ever arrive.
In the Block group preview, leave "Keep this group blocked" ticked: kisib saves a
rule and, every 60 seconds, blocks anything new that lands in that group.
Block > Rules lists and removes rules. The status bar shows what rules caught.

MORE VIEWS
View > Standings: CA owners grouped by country with roots, intermediates,
expiring in 12 months, expired, blocked, weak and tags. Click a heading to sort.
Certificate > Show chain: the chain Windows builds, root on the left, with
hashes, where each one is found, blocked or not, and tags.
File > Open certificate file (Ctrl+O): .cer .crt .der .pem .p7b .sst shown
read-only, with whether each is on this PC and blocked. Never installs; .pfx
and .p12 are refused. "Open with" kisib works too (Build.cmd makes the exe).
Status bar: Clock ok | SUSPECT when the PC clock is earlier than the newest
certificate or nearly everything reads as expired.

View > Incident check matches every certificate on this PC against the published eMudhra
hashes and keys: HIT or MISS, where it was found, and whether Windows' Disallowed store
holds it. Read-only; MISS never means safe.
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
