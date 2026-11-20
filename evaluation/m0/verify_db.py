"""Verify the frozen database and two advisory-specific npm controls."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

base = Path(__file__).resolve().parent
spec = json.loads((base / "baseline.json").read_text())
db = Path(sys.argv[1])
with db.open("rb") as stream:
    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
if checksum != spec["npm_db"]["sha256"]:
    sys.exit("DB snapshot SHA-256 mismatch")
with zipfile.ZipFile(db) as archive:
    advisory = json.loads(archive.read(spec["advisory"] + ".json"))
item, = (i for i in advisory["affected"] if i["package"]["name"] == "lodash"
         and i["package"]["ecosystem"] == "npm")
# This fixture has a single numeric release interval; this is not a scanner.
if item["ranges"] != [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]:
    sys.exit("Unexpected advisory interval")
for control in spec["dependency_controls"]:
    data = (base / control["path"]).read_bytes()
    version = json.loads(data)["packages"]["node_modules/lodash"]["version"]
    matches = tuple(map(int, version.split("."))) < (4, 17, 21)
    if hashlib.sha256(data).hexdigest() != control["sha256"] or matches != control["expected_match"]:
        sys.exit("Invalid control: " + control["path"])
print("Verified DB SHA-256, advisory interval and 2 dependency controls.")
