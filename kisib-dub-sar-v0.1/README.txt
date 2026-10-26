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
  Blocs       👑 monarchy  🏛️ EU  🧱 BRIC (Brazil, Russia, India, China and the
              later BRICS members)  🤡 Basel / CBDC  💃 supranational corporations.
              Tags stack: Spain is 👑🏛️, the UAE is 👑 🧱 🤡.
  Continents  all seven (UN country list); Middle East is a region inside Asia.
  Countries   from the C= on the certificate (subject and issuer).
  Owners      CA owner by O= (data\owners.csv) and every owner listed in CCADB.
  Status      blocked by kisib, blocked before kisib, not on this PC, expired,
              weak, incident (published compromised keys).
  My tags     yours only, kept in PORTABLE BACKUP LISTS, never in the public repo.
Block > Block by bloc and continent (Ctrl+B, or the Blocs... button): every
tile shows how things stand: "kept blocked" (a rule keeps it blocked),
"partly blocked" or "not blocked". Click tiles to pick them; the grid shows
every country they catch: owners, roots, intermediates, blocked now, what this
block adds, cross-signs that get rerouted or cut off, and why. Preview block
shows the exact list; Block + keep blocked also saves rules so new matches get
blocked too. Unblock picked (or right-click a tile > Unblock) lifts what kisib
blocked for that bloc and drops its rule in one go; certificates that are also
in another bloc you keep blocked stay blocked.
Blocked certificates go into Windows' Disallowed store (this user; whole PC
when kisib runs as administrator). Nothing is deleted. Undo last block puts
it back. Block > Block history shows every change.
Unblocking by hand always wins: an unblocked certificate (and every one
sharing its key) goes on the never-block list, so a bloc rule can't put it
back. Tools > Never block list shows them and takes them off again.
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

ALLOW
Every window has the same Allow button or menu: for 3, 10 or 60 minutes, until
kisib closes or the PC restarts, always (never block it again), or while a
program runs. kisib lifts that block (and its siblings from the same company
or key) right away, no confirm box, and says in one line what happened:
"Lifted for the whole PC", or "this user only: run as administrator for
lsass, updaters and services". Then it watches the next check and tells you
whether it went through or was still refused. Timed blocks go back on time,
even if kisib was closed. Tray > Open right now lists everything open, with
the time left and Re-block now.
"While <program> runs" (offered when a refusal names the program, like
LibreWolf-WinUpdater.exe): each time that program starts, or gets refused,
the block opens while it runs and closes 2 minutes after it stops. Tray >
Open right now > Stop opening... removes it.

ALWAYS ON
File > Start with Windows (in tray): run kisib as administrator once and tick it.
It then starts at logon in the tray, watching, with admin rights. Because it
starts with admin rights, kisib's folder becomes admin-only to change (the
PORTABLE BACKUP LISTS inside stay yours); turning it off gives the folder its
normal permissions back.
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

LIVES IN THE TRAY
kisib never sits on the taskbar. The seal next to the clock is the way in:
click it to open kisib; right-click for denials, blocs, quiet mode and Exit.
Closing or minimizing the window puts it back in the tray; Exit kisib quits.
The seal gets a red dot when one of your blocks refused something and a yellow
dot for other refusals; hover it for counts, leaks and temp-allow time left.
Starting kisib again just opens the copy already running.
Tool windows (denials, reroute check, rules, standings...) are normal windows:
the main window stays usable, each reopens where you left it, Esc closes it.

POP-UPS AND THE REFUSAL CARD
A refusal pop-up is a small card in the corner, in bold Comic Sans with color emoji
(Microsoft's Fluent Emoji, MIT; docs/third-party-notices.txt) (up to four stack): an emoji for
the kind (🚫 blocked by you, 🔑 root missing, ⛔ revoked or Disallowed, 🌀 a trusted
service can't connect, ❔ anything else), who -> what on one line, why and the time
on a short grey line, and chips: Allow (when it's your block), Fix it (get what it
asked for), Details, Shh 1 h. Click the card for the refusal card; × closes it.
Tray notes show only the first sentence; the whole line stays in the status bar.
The refusal card: who asked (svchost.exe shows the Windows service
inside it; for lsass.exe kisib matches the open connection to name the real app
[to test]), which check Windows ran, the chain in order, why, and every way out:
Allow, Reroute, Keep blocked, Quiet this site for 1 hour.
Side checks: Windows often runs a stricter extra check that fails while the
real check of the same site passes in the same second. Those show grey as
"side check, went through" instead of red, with no pop-up. Quiet mode (tray or File menu) logs refusals with no pop-ups.
The Microsoft list and CCADB refresh weekly by themselves when online; offline
keeps the old copy (Tools menu switch).

DENIAL ALERTS
When any program on this PC is refused a certificate (curl, winget, Edge,
Windows apps), kisib pops a notice in the corner: which program,
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
rule and blocks anything new that lands in that group the moment Windows adds it
(kisib watches the certificate stores, plus a check every 10 minutes).
Tools > Rules lists rules: Remove rule keeps what it blocked; Remove rule and
unblock its certificates undoes it. The status bar shows what rules caught.

REPAIR (STANDARD SEALS)
kisib carries 27 root certificates inside the exe, so it can put them back
without downloading anything: the roots Microsoft lists as required by Windows,
Microsoft's own website and signing roots, and the roots most websites hang
under (DigiCert, Let's Encrypt, Sectigo, GlobalSign, Google). Each is checked
against its fingerprint before use; sources are in data\standard-seals.csv.
Tools > Repair:
  Windows essentials          Microsoft's own roots only.
  Get online                  microsoft.com and the big certificate companies.
  What Windows ships with     Microsoft's required-roots list.
  My trusted categories       the roots your switched-on categories need.
  What this PC uses           blocked or missing roots behind this week's refusals.
  Reset to the standard seals all seals back, one-off blocks lifted; only your
                              blocs stay blocked.
  Put back what was blocked before kisib   re-blocks what you unblocked by hand
                              from Microsoft's untrusted list.
Every row shows the owner, country and bloc, and what it fixes. Rows in a bloc you
keep blocked stay unticked unless you tick them. What a repair puts back goes on
the never-block list. Putting roots into Trusted Root needs kisib run as
administrator; only kisib's own pinned copies ever go there.

TOOLS PAGE
Tools > Tools page (Ctrl+T, or the Tools button): every tool on one list with what
it does and how it stands right now (lists loaded, leaks, rules, open allows,
admin or not). Double-click to run one.

REQUIRED FOR APP
Tools > Required for app (also tray, live map right-click, Tools page): every app
kisib has seen, the roots it used, and the CAs in between, from every check
Windows logged, kept in REQUIRED FOR APP (what each app used).txt. Tick an app,
a root or a single CA and press Keep the ticked ones working: kisib unblocks
them, puts a missing root back (only roots Windows' own list names) and keeps
them on the never-block list. Untick one to let your rules decide again.

IMPORT A CERTIFICATE FILE
Certificate > Import > File..., or right-click the live map > Import > File...:
picks a .cer/.crt/.der/.pem/.p7b/.sst (starts at C:\). Roots go into Trusted Root
(asked first if Windows' own list doesn't name them), CAs into Intermediate CAs,
and a block on what you import comes off. Files with private keys are refused.

GET WHAT IT ASKED FOR
On a refusal (card, live map, denials list, --do get <site|program>): kisib takes
each certificate the program asked for, from this PC, its CCADB / Microsoft lists,
or crt.sh online (checked by SHA-1), and fixes what is in the way. Blocked (that
copy, another copy with the same key, or a CA with the exact same name): unblocked
for good. A CA certificate missing from this PC: imported into Intermediate
Certification Authorities (kept in ROUTES, put back after a reformat). The root
missing: fetched from Microsoft's list. If none of that applies, it says so: a
revoked certificate stays revoked, and no import changes that.

MISSING ROOTS (NOT YOUR BLOCK)
"root not trusted (not your block)" means Windows needed a root it doesn't have and
didn't download it (Apple Root CA for iCloud, say). Right-click the refusal or the
dashed root box > Get <root> from Microsoft: kisib asks Windows Update for
Windows' own trusted-root list (authroot.stl, which Windows keeps in the registry)
whether it names that root by SHA-1. Only then does it take the certificate from
kisib's lists, from the same Windows Update file Windows downloads, or from a fresh
certutil list (checked by SHA-1), and put just that root into Trusted Root, the way
Windows would have. Whole PC as administrator; otherwise this user, and Windows asks first.
Roots Microsoft doesn't list, and roots you blocked, are never added. Repairs do
the same for missing roots on Microsoft's list. When Windows logs "a blocked CA"
without saying which, Allow offers the blocked CAs of whoever owns the site.

KEEP CLAUDE REACHABLE
The Claude app checks certificates through Windows, so blocking a bloc that holds
Let's Encrypt (ISRG) or Google Trust Services can cut it off without a pop-up.
After every scan kisib checks those roots and the CAs under them (claude.ai runs
YE2 <- Root YE <- ISRG Root X2; Claude's bridge runs WE1 <- GTS Root R4). Anything
in that chain that is blocked gets unblocked, and missing roots go back from
kisib's own pinned copies, even inside a blocked bloc. If GTS Root R4 isn't in
Trusted Root (no admin), GlobalSign Root CA, which cross-signs it, stays open
too. Anything blocked behind a refusal of claude.exe or a Claude site goes too.
These CAs sign other sites as well, so every Let's Encrypt and Google Trust
site gets through again, not only Claude.
Tray > Fix Claude's connection does it now. Tools page > Keep Claude reachable
turns the automatic check on or off. The list lives in TRUSTED CATEGORIES.txt
under [Claude (Anthropic)] (keep reachable = on); any category can use it.

CLAUDE CAN RUN KISIB
  kisib.dub-sar.exe --do "status"
asks the kisib already running and prints the answer, so Claude can look and fix
things from the desktop app's shell. Commands: status, claude, fix claude,
keep-claude on|off, denials [n], find <text>, cert <sha1>, rescan,
repair <essentials|online|windows|categories|claude|used|reset|putback> [list],
allow <sha1|site> <3|10|60|restart|always>, unblock <sha1|site>, reblock, rules,
unblock-bloc <name>, get <site|program|name>, get-root <sha1|name>, quiet on|off,
log [n], crashlog [n].
"--do help" lists them.
If kisib isn't running, --do starts it in the tray first. The answer is also
saved in LAST COMMAND (for Claude).txt. Where kisib lives is written to
%LOCALAPPDATA%\kisib.dub-sar\where is kisib.txt each start. Tray > Copy the line
that lets Claude run kisib puts the full command on the clipboard. Only this
Windows user, administrators and SYSTEM can talk to it; nothing from the network.

SPEED
kisib rescans when Windows changes a certificate store, not every minute, and
skips redrawing when nothing changed. Heavy work happens off the window, so it
doesn't freeze with thousands of blocks. If something still goes wrong, kisib
writes it to CRASH LOG.txt in PORTABLE BACKUP LISTS and keeps running. If the
window can't be drawn, it says so in the window (with the error) instead of
going blank, and keeps scanning.

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

Registers: docs/function-catalog.csv and docs/feature-sources.csv.
Test.cmd is the read-only consumer-machine suite. Hosted CI separately runs
collector probes in disposable VMs, GUI regressions and the actual EXE.
Current evidence: docs/screen1-verification.txt. User-PC acceptance is pending.
This is an unsigned preview; no Microsoft Store submission is claimed.
