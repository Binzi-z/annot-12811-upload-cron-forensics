"""Baseline forensic triage: greps known-bad strings.

This is what the IR team runs today. It reports every line containing curl, wget
or crontab, without ordering them or linking them to an account.
"""

from __future__ import annotations

import json
import os
import sys

PATTERNS = ("curl", "wget", "crontab", "authorized_keys", "visudo", "systemctl enable")


def scan(root: str) -> list[dict]:
    hits: list[dict] = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            p = os.path.join(dirpath, name)
            with open(p, encoding="utf-8", errors="ignore") as fh:
                for no, line in enumerate(fh, start=1):
                    if any(k in line for k in PATTERNS):
                        hits.append({"file": os.path.relpath(p, root), "line": no, "text": line.strip()[:80]})
    return hits


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "evidence"
    out = sys.argv[2] if len(sys.argv) > 2 else "timeline.json"
    hits = scan(root)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"hits": hits}, fh, ensure_ascii=False, indent=2)
    print(f"{len(hits)} hits -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
