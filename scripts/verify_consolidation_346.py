"""Verify tracked migration artifacts against their Git blob manifests."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
def git(*args): return subprocess.check_output(["git", "-C", str(root), *args])
tracked = {}
for record in git("ls-files", "--stage", "-z").split(b"\0"):
    if record:
        header, path = record.split(b"\t", 1)
        mode, blob, stage = header.decode().split()
        assert stage == "0"
        tracked[path.decode()] = (mode, blob)
count = 0
for name in sys.argv[1:]:
    manifest = json.loads((root / name).read_text("utf-8"))
    assert len({e["source_path"] for e in manifest["files"]}) == len(manifest["files"])
    for entry in manifest["files"]:
        mode, blob = tracked[entry["target_path"]]
        assert blob == entry["target_git_blob"], entry["target_path"]
        if entry.get("disposition", "").startswith("migrated"):
            assert mode == entry["source_mode"], entry["target_path"]
        if entry.get("archive_path"):
            assert tracked[entry["archive_path"]][1] == entry["source_git_blob"]
        count += 1
print(f"Verified {count} source paths and preserved originals")
