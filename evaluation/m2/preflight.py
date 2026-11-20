"""Probe the pinned native CE engine; only generated inputs are mounted."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

VERSION = "1.186.0"
PATTERNS = {
    "echo-input": "$RES.send($REQ.query.$KEY)",
    "dom-html": "$NODE.innerHTML = $VALUE",
}
SAMPLES = {
    "before": {"server.ts": "res.send(req.query.title);", "browser.js": "element.innerHTML = caption;"},
    "after": {"server.ts": 'res.type("text/plain").send(String(req.query.title));',
              "browser.js": "element.textContent = caption;"},
}


def check(ok, message):
    if not ok:
        raise RuntimeError(message)


def probe(engine, image):
    check(image.startswith("sha256:") and len(image) == 71, "use an immutable local image ID")
    rules = {"rules": [{"id": key, "pattern": pattern, "languages": ["typescript", "javascript"],
                        "severity": "WARNING", "message": "Review output context."}
                       for key, pattern in PATTERNS.items()]}
    with tempfile.TemporaryDirectory(dir=engine.parent) as tmp:
        work = Path(tmp)
        (work / "rules.yaml").write_text(json.dumps(rules))
        for name, files in SAMPLES.items():
            (work / name).mkdir()
            for filename, content in files.items():
                (work / name / filename).write_text(content + "\n")
        (work / "invalid.yaml").write_text("rules: 42")
        (work / "empty").mkdir()
        (work / "empty" / "notes.txt").write_text("No supported source files.")
        docker = ["docker","run","--rm","--pull=never","--network","none","--read-only",
                  "--user","65534:65534","--cap-drop","ALL","--security-opt","no-new-privileges",
                  "--cpus","1","--memory","768m","--pids-limit","96",
                  "--tmpfs","/tmp:rw,noexec,nosuid,size=96m,mode=1777","-e","HOME=/tmp",
                  "-e","SEMGREP_SEND_METRICS=off","-e","SEMGREP_ENABLE_VERSION_CHECK=0",
                  "-v",f"{engine}:/engine:ro","-v",f"{work}:/work:ro","-w","/work"]
        work.chmod(0o755)
        def run(entry, *args):
            return subprocess.run([*docker,"--entrypoint",entry,image,*args],
                                  capture_output=True,text=True,timeout=90)

        v = run("/engine/osemgrep","scan","--experimental","--version")
        check(v.returncode == 0 and v.stdout.strip() == VERSION, "unexpected engine version")
        isolation = run("/bin/sh","-exc",
                        'test "$(id -u)" = 65534; test "$(wc -l < /proc/net/route)" -eq 1; '
                        'test ! -S /var/run/docker.sock; touch /tmp/scratch; '
                        '! touch /work/write-test; test ! -e /work/write-test')
        check(isolation.returncode == 0, "isolation probe failed: " + isolation.stderr)
        print("version",VERSION,"rule_sha256",hashlib.sha256((work/"rules.yaml").read_bytes()).hexdigest(),flush=True)
        for case, config in [("before","rules.yaml"),("after","rules.yaml"),
                             ("empty","rules.yaml"),("before","invalid.yaml")]:
            p = run("/engine/osemgrep","scan","--experimental","--metrics=off","--json","--error",
                    "--no-git-ignore","--config",config,case)
            out = json.loads(p.stdout)
            rows = [(r["check_id"].split(".")[-1],Path(r["path"]).name,r["start"]["line"])
                    for r in out.get("results",[])]
            paths = out.get("paths",{}).get("scanned",[])
            print(case,config,"exit",p.returncode,"rows",rows,"scanned",paths,"errors",len(out.get("errors",[])),flush=True)
            if config == "invalid.yaml":
                check(p.returncode not in (0,1) and bool(out["errors"]), "invalid rule appeared successful")
            elif case == "empty":
                check(not paths and not rows, "empty scope reported as scanned")
            else:
                expected = {("echo-input","server.ts",1),("dom-html","browser.js",1)} if case=="before" else set()
                check(set(rows)==expected and len(rows)==len(expected) and not out.get("errors"), "unexpected findings")
                check(p.returncode == int(bool(expected)) and {Path(s).name for s in paths}==set(SAMPLES[case]), "incorrect coverage/exit")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine",type=Path,help="verified wheel bin directory with osemgrep symlink")
    parser.add_argument("image",help="local Linux amd64 runtime image ID")
    args=parser.parse_args()
    probe(args.engine.resolve(strict=True),args.image)
