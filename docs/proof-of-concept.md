# Reproduce a permission finding

We tested Reach Ward on our own working systems. It identified settings
directories with broader access than intended. We restricted those directories
to the account owner and verified that the permission findings cleared.
Independent review also identified credential-classification edge cases, which
became corrections and regression tests in the review candidate.

This demonstration recreates the directory finding using a fake credential and
a temporary home. It runs the installed scanner twice: before and after a
separate operator permission change. You can inspect the reports and repeat the
experiment without reading or changing your own agent settings.

## Run it

Use Linux and Python 3.10 or newer. From a checkout or extracted source
distribution containing this document:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -B examples/permission_poc.py
```

Installation may download build dependencies, and Python 3.10 needs `tomli`.
The demonstration itself performs no package installation and invokes only
offline scans. It requires Reach Ward to be installed in the same interpreter:
child commands use Python's isolated import mode, so a source checkout or
inherited `PYTHONPATH` cannot substitute for that installed package.

Expected output:

```text
PASS: before: directory 0775, RW-FILE-MODE high, scan exit 1
PASS: after:  directory 0700, no findings, scan exit 0
PASS: fixture file bytes, size, mtime, inode and modes preserved
PASS: fake credential absent from command output, reports and state
PASS: state directory 0700; report and state files 0600
```

The demonstration exits **0** only when every check passes. Its first scanner
invocation intentionally exits **1** for the finding. Setup or verification
failures make the demonstration fail; it does not print captured scanner errors
that might contain the canary. The default run removes only its own temporary
directory on exit.

To retain the synthetic fixture and evidence for inspection:

```sh
.venv/bin/python -B examples/permission_poc.py --keep
```

The script prints the retained directory's location. Under it, `reports/`
contains `before.json`, `after.json`, and `verification.json`. The latter records
the package version, expected exits, findings, and fixture preservation receipts.
Record your checkout's `git rev-parse HEAD` or distribution SHA-256 alongside
these files when reporting results; multiple review candidates can share a
package version. These are local reproduction results, not another reviewer's
sign-off.

## What the demonstration does

1. Create a random temporary root at `0700`, with a fake HOME and private config,
   reports, and state. Set all relevant HOME/XDG/gh/rclone source locations to
   the fixture and pass no account credentials from the parent environment.
2. Write a generated dummy authentication value to a synthetic
   `.codex/auth.json` at `0600`. Set only its temporary parent directory to
   `0775`. No real credential or actual user settings directory is used.
3. Run `scan` with a private configuration containing `alert_channels = []`.
   Require exactly one `RW-FILE-MODE` high finding and one credential fingerprint.
4. Check the fixture files' hashes, sizes, mtimes, inodes, and modes and verify
   the scanner left the directory mode unchanged.
5. Apply `0700` to that temporary parent as an explicit operator action, then
   rescan. Require a complete inventory, zero findings, and the same unchanged
   fixture files. The scanner never performs the permission correction.
6. Check the captured command output and saved reports/state for the fake
   credential, and verify private output modes. The deliberately planted input
   file still contains the dummy value; it is not scanner output.

The restrictive outer temporary directory keeps the experiment private even
while the inner directory has a permissive mode. This reproduces the scanner's
mode finding, not an attempt to read credentials as another operating-system
account. The authentication file itself remains `0600` throughout.

## Observe network behavior independently

If `strace` is already installed and tracing is allowed on your machine, run the
same experiment under it. The shell's restrictive umask keeps the trace private.

```sh
umask 077
trace_dir=$(mktemp -d)
strace -f -e trace=network,execve -o "$trace_dir/trace.txt" \
  .venv/bin/python -B examples/permission_poc.py
```

Inspect `trace.txt` for networking syscalls. Expected: none. Process execution is
expected for the harness, the installed package's version query, and its two
offline scans. The harness does not itself assert a syscall count; tracing is
an independent observation. Keep trace files private because command arguments
contain local paths. No system-wide tracing setting needs to be changed for
this demonstration.

## What this establishes

The example was verified on Linux with Python 3.12.3 and the `0.1.0` review
package's runtime at
[`04b3f176`](https://github.com/Dragon-Lady/reachward/commit/04b3f176e93956fae8e22ac37adadcd9abebed39).
The script extracted from the source distribution passed against a freshly
installed wheel, including a run with deliberately conflicting inherited HOME,
XDG, gh/rclone and Python import settings. Those outside fixture files remained
unchanged. The traced run recorded zero network syscalls and four process
executions, as described above. An empty environment correctly refused to use
the adjacent source checkout in place of an installed package.

The reproduction checks detection of an overly permissive immediate directory,
the finding's disappearance after an operator correction, preservation of the
scanned fixture files, credential fingerprinting without output disclosure, and
private state/report modes. It does not establish that credentials were exposed
on a real machine or that a machine with no findings is secure.

The actual-machine scans and this synthetic reproduction are separate evidence.
The latest recorded development laptop scan preserved six configuration sources,
made zero network calls under tracing, and had no high findings after the
directory correction. One warning and one informational advisory remained.
These observations describe that scan, not every environment or future release.

See [the README](../README.md) for the scanner's complete posture and limitations,
and [the review notes](../REVIEW.md) for the current candidate's validation status.
