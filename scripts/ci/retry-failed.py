"""Rerun the tests that failed in a `cargo test` log, up to twice each.

Several tests time real or emulated networks; on small CI machines a
different one misses its deadline in each run, though each passes in others
and on its own. A test that passes on a retry is reported as flaky (a
warning on the run), one that fails every time fails the job.

    cargo test --no-fail-fast ... 2>&1 | tee test.log
    python3 scripts/ci/retry-failed.py test.log

Run from the workspace root, with the same environment as the test run (so
cargo doesn't rebuild).
"""

import pathlib
import re
import subprocess
import sys

TRIES = 2

ansi = re.compile(r"\x1b\[[0-9;]*m")
log = [ansi.sub("", line) for line in pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()]
running = re.compile(r"^\s*Running (unittests )?(\S+) \((\S+)\)")
doctests = re.compile(r"^\s*Doc-tests (\S+)")
failed = re.compile(r"^test (\S+) \.\.\. FAILED")

where = None  # (kind, crate dir, target) of the test binary whose output follows
retry = []
compile_error = any(line.startswith("error: could not compile") for line in log)

for line in log:
    if m := running.match(line):
        unit, src, binary = m.groups()
        src = src.replace("\\", "/")
        stem = pathlib.PurePath(binary.replace("\\", "/")).name.rsplit("-", 1)[0]
        if unit:
            # the crate's own tests: the binary is named after the crate
            crate = stem.replace("_", "-")
            where = ("lib" if src.endswith("lib.rs") else "bin", crate, None if src.endswith("lib.rs") else stem)
        else:
            dirs = [d.name for d in pathlib.Path("crates").glob("*") if (d / src).is_file()]
            where = ("test", dirs, stem)
    elif m := doctests.match(line):
        where = ("doc", m.group(1).replace("_", "-"), None)
    elif (m := failed.match(line)) and where:
        retry.append((where, m.group(1)))

if compile_error or not retry:
    print("nothing to retry" if not compile_error else "the build failed")
    sys.exit(1)


def run(where, name):
    kind, crate, target = where
    if kind == "test":
        cmds = [["cargo", "test", "-p", c, "--test", target, name, "--", "--exact"] for c in crate]
    elif kind == "lib":
        cmds = [["cargo", "test", "-p", crate, "--lib", name, "--", "--exact"]]
    elif kind == "bin":
        cmds = [["cargo", "test", "-p", crate, "--bin", target, name, "--", "--exact"]]
    else:
        cmds = [["cargo", "test", "-p", crate, "--doc"]]
    for cmd in cmds:
        out = subprocess.run(cmd, capture_output=True, text=True)
        text = out.stdout + out.stderr
        if out.returncode == 0 and re.search(r"test result: ok\. [1-9]", text):
            return True, text
    return False, text


if "--dry" in sys.argv:
    for where, name in retry:
        print(where, name)
    sys.exit(0)

flaky, broken = [], []
for where, name in retry:
    for attempt in range(1, TRIES + 1):
        ok, text = run(where, name)
        if ok:
            print(f"passed on retry {attempt}: {name}")
            flaky.append(name)
            break
    else:
        print(f"failed every time: {name}\n{text[-3000:]}")
        broken.append(name)

for name in flaky:
    print(f"::warning title=Flaky test::{name} failed, then passed on a retry")
for name in broken:
    print(f"::error title=Failing test::{name} failed {TRIES + 1} times")
sys.exit(1 if broken else 0)
