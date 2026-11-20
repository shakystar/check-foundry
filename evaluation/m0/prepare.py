"""Prepare isolated TypeScript scan inputs. No application code is executed."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

SPEC = json.loads(Path(__file__).with_name("baseline.json").read_text())


def source(repo, revision, path):
    return subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{revision}:{path}"]
    ).decode("utf-8")


def prepare(app, guide):
    revision = SPEC["app_commit"]
    version = json.loads(source(app, revision, "package.json"))["version"]
    attributes = source(guide, SPEC["guide_commit"], SPEC["guide_attributes"])
    if f":juiceShopVersion: v{version}" not in attributes.splitlines():
        raise ValueError("App and companion guide versions differ")

    lines = source(app, revision, "server.ts").splitlines()
    inputs, mapping = {}, {}
    for case in SPEC["cases"]:
        start, end = case["context"]
        selected = []
        targets = []
        for n in range(start, end + 1):
            body, _, annotation = lines[n - 1].partition("// vuln-code-snippet")
            if annotation.startswith(" vuln-line") and case["key"] in annotation.split():
                targets.append(n)
            selected.append(body.rstrip() if "hide-" not in annotation else "")
        if targets != case["locations"]:
            raise ValueError(f"Upstream labels differ for {case['id']}")
        fixed = source(app, revision, case["fix_file"]).splitlines()
        left, right = case["fix_context"]
        projections = [(case["sample"], selected, start, "server.ts"),
                       (case["control"], fixed[left-1:right], left, case["fix_file"])]
        for name, snippet, first, path in projections:
            data = ("\n".join(snippet) + "\n").encode()
            if re.search(rb"Challenge|vuln-code-snippet|verify\.|_correct", data, re.I):
                raise ValueError("Scoring metadata in scan input")
            inputs[name] = data
            mapping[name] = {"upstream_path": path, "first_line": first,
                             "sha256": hashlib.sha256(data).hexdigest()}
    return inputs, mapping


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("app", "guide", "output"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    samples, oracle = prepare(args.app, args.guide)
    expected = json.loads(Path(__file__).with_name("expected-mapping.json").read_text())
    if oracle != expected:
        raise ValueError("Prepared bytes or source mapping differ from the frozen baseline")
    # A new directory prevents stale files from changing the scoring denominator.
    args.output.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(dir=args.output) as staging:
        scan = Path(staging) / "scan"
        scan.mkdir()
        for name, data in samples.items():
            (scan / name).write_bytes(data)
        (args.output / "mapping.json").write_text(json.dumps(oracle, indent=2) + "\n")
        scan.rename(args.output / "scan")
