import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(tmp_path):
    out = tmp_path / "timeline.json"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "triage.py"), os.path.join(ROOT, "evidence"), str(out)],
                       capture_output=True, text=True)
    return r, out


def test_evidence_present():
    for name in ("bash_history.txt", "auth_excerpt.log", "files.txt"):
        assert os.path.exists(os.path.join(ROOT, "evidence", name))


def test_labels_have_entry_and_persistence():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    assert labels["entry_vector"]
    assert labels["persistence"]


def test_triage_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "hits" in json.loads(out.read_text(encoding="utf-8"))


def test_hits_have_file_and_line(tmp_path):
    _, out = run(tmp_path)
    for h in json.loads(out.read_text(encoding="utf-8"))["hits"]:
        assert h.get("file") and h.get("line")
