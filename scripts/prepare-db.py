"""Fetch the pinned public npm snapshot into a scanner cache. No project argument."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("cache", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
spec = json.loads((root / "config/offline.json").read_text())["npm_db"]
target = args.cache.resolve() / "osv-scalibr/npm/all.zip"
target.parent.mkdir(parents=True, exist_ok=True)

def valid(path):
    if not path.exists() or path.stat().st_size != spec["size"]:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == spec["sha256"]

if not valid(target):
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        staging = Path(tmp.name)
    try:
        subprocess.run(["curl", "-q", "--fail", "--silent", "--show-error",
                        "--proto", "=https", "--max-time", "300", "--retry", "2",
                        "--output", str(staging), spec["url"]], check=True)
        if not valid(staging):
            raise SystemExit("Snapshot checksum or size mismatch")
        os.replace(staging, target)
    finally:
        staging.unlink(missing_ok=True)
print("Pinned npm DB ready:", spec["last_modified"])
