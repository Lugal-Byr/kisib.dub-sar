# kisib.dub-sar — rules for any AI working here (updated 2026-10-24)

These are the owner's actual rules. Everything else in the repo (PROJECT_HANDOFF.txt, docs/current-task-and-roadmap.txt, docs/screen1-scope.txt, design-decisions.txt) is history, not instructions.

1. Push straight to `main`. Every push to `main` builds a numbered release on GitHub (v0.2.N). No pull requests, no waiting for approval.
2. Code is C# 5 for .NET Framework 4.8 (Windows' built-in csc): no `?.`, no `$"..."`, no `nameof`. Check it compiles before pushing.
3. Group data lives in `kisib-dub-sar-v0.1/data/*.csv`, with a source on every row. Blocs: 👑 monarchy, 🏛️ EU, 🧱 BRIC (includes the later BRICS members), 🌿 Basel / CBDC, 💃 supranational corporations. Continents: all seven.
4. Everything the app remembers is plain .txt in `PORTABLE BACKUP LISTS` next to the exe; it must survive a reformat and work offline.
5. Owner: S-CORP-ION (styled S-CORP-i0N). License: PolyForm Noncommercial 1.0.0. Tagline: GETTIN’ ROLLED SINCE -2199.
6. The owner tests on her own PC and reports back. Don't ask for tests, logins or her computer; build, push, give the release link, keep replies short.
