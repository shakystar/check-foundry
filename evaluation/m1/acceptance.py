"""Exercise the real binaries; run on a host permitting the documented OS sandbox."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
for name in ("cli", "scanner", "cache"):
    parser.add_argument(name, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1] / "m0"
spec = json.loads((root / "baseline.json").read_text())

pins = json.loads((root.parents[1] / "config/offline.json").read_text())
assert all(pins[k] == spec[k] for k in ("osv_scanner", "npm_db")), "M0 baseline drift"

def check(target, code, state, db=None):
    p = subprocess.run([str(args.cli.resolve()), "scan", "-json", "-osv",
                        str(args.scanner.resolve()), "-db-cache", str(db or args.cache), str(target)],
                       capture_output=True, timeout=320)
    report = json.loads(p.stdout)
    assert (p.returncode, report["status"]) == (code, state), report
    print(target.name, state, p.returncode, len(report["findings"]), flush=True)
    return report

with tempfile.TemporaryDirectory() as work:
    temp = Path(work)
    for control in spec["dependency_controls"]:
        target = root / control["path"]
        # Patched controls concern one GHSA. Other findings affect the exit code.
        p = subprocess.run([str(args.cli.resolve()), "scan", "-json", "-osv", str(args.scanner.resolve()),
                            "-db-cache", str(args.cache), str(target)], capture_output=True, timeout=320)
        r = json.loads(p.stdout)
        assert r["status"] == "complete" and r["unique_packages_checked"] == 1, r
        assert p.returncode == int(bool(r["findings"]))
        assert any(f["id"] == spec["advisory"] for f in r["findings"]) == control["expected_match"]
        print(target.parent.name, r["status"], p.returncode, len(r["findings"]), flush=True)
    check(temp, 2, "unsupported")
    f = temp / "package-lock.json"
    f.write_text(json.dumps({"lockfileVersion":3, "packages":{"node_modules/is-number":{"version":"7.0.0"}}}))
    check(f, 2, "failed", temp / "absent")
    check(f, 0, "complete")
    d = json.loads(f.read_text())
    d["packages"]["node_modules/local"] = {"link":True}
    f.write_text(json.dumps(d))
    partial = check(f, 2, "partial")
    assert partial["excluded_lock_entries"] == 1 and partial["unique_packages_checked"] == 1
