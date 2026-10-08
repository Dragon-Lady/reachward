# v0.1 review candidate

This is a review candidate, not a published package release. The repository has
no CI workflows, deploy configuration or release automation. No timers are
installed by the tool.

## Evidence available locally

- 62 pytest cases pass with fake HOME and XDG directories on Python 3.12.
- Every rule has a positive and negative test. Exact baseline mutation tests
  cover additions, argument changes and mode changes.
- Canary tests cover every command in text, JSON, Markdown and HTML, including
  saved files/state. Alert payload tests cover aggregation and secret exclusion.
- Offline tests forbid socket connection and subprocess execution. The optional
  online test checks the exact `gh api -i /user` invocation using a mock.
- Source target hashes, size, mtime and modes stay unchanged in fixtures.
- An operator dry run on one Linux host read six configuration sources, found
  four inventory entries, preserved all six sources, and showed zero networking
  syscalls and only the initial Python exec under strace.
- The source distribution includes tests and their shared fixture. A wheel was
  installed in an isolated environment and the console script exercised.

## Independent review still required

- Repeat the tests and inspect the private local scan/list-sources reports.
- Run `list-sources` and an offline scan on the second intended Linux host. Some
  agent configurations were absent/empty on the first host; fixture coverage is
  not a substitute for inspecting the second host.
- Decide whether to use the optional online scope check, the alert destinations,
  and a schedule. They are implemented but external delivery and scheduling
  have not been enabled or live-tested.
- Confirm whether refusing all symlinks and sources outside HOME is acceptable;
  this is a conservative narrowing of discovery, explicitly reported.
- Python 3.10's tomli compatibility path is declared but not runtime-tested on
  the development host. Run that version before promising tested compatibility.
- Inspect false positives and blind spots: no keyring queries; restricted gh
  YAML/dotenv parsing; heuristic argument credential/pin detection; declared
  scopes are not verified permissions; arbitrary wrappers are not executed.

Release, external deployment, social posting, and the next tool remain separate
approval steps. No review sign-off is implied by this document.
