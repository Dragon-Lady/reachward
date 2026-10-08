# v0.1 review candidate

This is a review candidate, not a published package release. The repository has
no CI workflows, deploy configuration or release automation. No timers are
installed by the tool.

## Evidence available locally

- 162 pytest cases pass with fake HOME and XDG directories on Python 3.12.
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

## Independent review corrections

Independent review accepted the initial candidate with two required fixes. Both
are implemented here with regression tests:

- PAT and KEY match whole name tokens, including underscore/hyphen boundaries
  and camelCase API keys. PATH, NODE_PATH, PYTHONPATH, other PATHS names,
  projectPath and KEYBOARD no longer create credential findings or redact paths.
  Recognized token values are still detected even in a variable named PATH.
- Encrypted rclone detection skips leading blank and comment lines before
  checking the first significant line. The fixture now includes rclone's real
  comment header; later markers inside plaintext sections are not misclassified.

The original host scan's inline-secret finding was a PATH-name false positive.
It is withdrawn. The corrected installed-wheel scan is recorded in the private
review handoff. The reviewer also reports the original 62 cases passing on
Python 3.10.22 with tomli and Python 3.13.5; those are independent results for
the original candidate, not claimed runtime verification of this patch.

## Independent review still required

The follow-up retest findings N1–N3 and pre-timer items 4–7 are now addressed in
this candidate:

- Whole semantic credential names exclude token settings while retaining real
  credential names, plural API/OPENAI keys and compact GITHUBPAT.
- Key-file references carry field names and keyed path fingerprints, with an
  informational finding. Targets are never opened. Reference values do not hide
  HOME/source paths, and recognizable tokens override reference hints.
- Source symlinks and missing referenced env files produce partial coverage,
  not a fatal scan. Explicit required env files and actual read/parse errors
  still fail. HOME aliases normalize only the selected root, with a warning;
  nested source symlinks remain skipped.
- Baselines retain source coverage. Skipped sources and hidden env references
  are excluded from comparisons on either side, including coverage recovery;
  comparison warnings remain until a reviewed complete baseline is established.
- Command lookup uses a fixed configurable search path, also printed in the
  timer unit and passed to optional gh execution. Derived lookup/known metadata
  and online-only scope observations do not create configuration changes.

The new tests include every named retest case, target hashes/size/mtime/mode/inode
preservation, no key-file reads, symlink targets inside/outside HOME, HOME aliases,
partial-baseline recovery, required-file failure, unaffected-source changes,
fixed PATH/timer quoting, online/offline diff symmetry, and privacy/schema checks.
The original offline, canary, private-mode and aggregate alert tests remain.

- Retest the correction diff and inspect the updated private scan report.
- Run `list-sources` and an offline scan on the second intended Linux host. Some
  agent configurations were absent/empty on the first host; fixture coverage is
  not a substitute for inspecting the second host.
- Decide whether to use the optional online scope check, the alert destinations,
  and a schedule. They are implemented but external delivery and scheduling
  have not been enabled or live-tested.
- Independently retest the follow-up fixes and coverage semantics before enabling
  alerts/timers. Partial coverage is eligible for a baseline but is never
  represented as complete; exit 1 signals coverage/comparison warnings.
- Re-run the correction tests on Python 3.10; the development host uses 3.12.
- Inspect false positives and blind spots: no keyring queries; restricted gh
  YAML/dotenv parsing; heuristic argument credential/pin detection; declared
  scopes are not verified permissions; arbitrary wrappers are not executed.

Release, external deployment, social posting and scheduling require separate
approval. No final review sign-off is implied by this document.
