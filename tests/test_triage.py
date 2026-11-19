import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(tmp_path):
    out = tmp_path / "timeline.json"
    r = subprocess.run(
        [sys.executable, "-I", os.path.join(ROOT, "triage.py"),
         os.path.join(ROOT, "evidence"), str(out)],
        capture_output=True, text=True)
    return r, out


def load(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_evidence_present():
    for name in ("bash_history.txt", "auth_excerpt.log", "files.txt"):
        assert os.path.exists(os.path.join(ROOT, "evidence", name))


def test_labels_have_entry_and_persistence():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    assert labels["entry_vector"]
    assert labels["persistence"]


def test_triage_runs(tmp_path):
    report = load(tmp_path)
    assert "hits" in report
    assert "timeline" in report


def test_hits_have_file_and_line(tmp_path):
    report = load(tmp_path)
    for h in report["hits"]:
        assert h.get("file") and h.get("line")


def test_timeline_covers_full_kill_chain_in_order(tmp_path):
    report = load(tmp_path)
    stages = [e["stage"] for e in report["timeline"]]
    # 0 context -> 1 upload/landing -> 2 execution -> 3 cron -> 4 outbound
    assert stages == sorted(stages)
    for required in (0, 1, 2, 3, 4):
        assert required in stages
    chain = [e for e in report["timeline"] if e["classification"] == "malicious"]
    assert chain[0]["stage"] == 1
    assert chain[-1]["stage"] == 4


def test_every_timeline_event_cites_real_file_and_line(tmp_path):
    report = load(tmp_path)
    for e in report["timeline"]:
        if e["classification"] == "context_only":
            continue  # stage 0 intentionally has no artifact
        path = os.path.join(ROOT, e["file"])
        assert os.path.exists(path), e["file"]
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        assert 1 <= e["line"] <= len(lines)
        assert e["raw"].strip() == lines[e["line"] - 1].strip()


def test_noise_commands_never_reported_as_malicious(tmp_path):
    report = load(tmp_path)
    noise = ("git pull", "systemctl status nginx", "tail -f app.log",
             "ls -la", "cd /var/log")
    for h in report["hits"]:
        assert not any(n in h["text"] for n in noise)
    for e in report["timeline"]:
        if e["classification"] == "malicious":
            assert not any(n in e["raw"] for n in noise)
    excluded_text = " ".join(e["raw"] for e in report["excluded_benign"])
    for n in noise:
        assert n in excluded_text


def test_healthcheck_cron_and_ssh_logins_excluded(tmp_path):
    report = load(tmp_path)
    raw_hits = " ".join(h["text"] for h in report["hits"])
    assert "healthcheck.sh" not in raw_hits
    assert "Accepted publickey" not in raw_hits
    excluded = " ".join(e["raw"] for e in report["excluded_benign"])
    assert "healthcheck.sh" in excluded
    assert "Accepted publickey" in excluded


def test_ops_chmod_change_is_excluded_and_explained(tmp_path):
    report = load(tmp_path)
    assessment = report["ops_change_assessment"]
    assert assessment["verdict"] == "benign_misconfiguration_not_intrusion"
    assert assessment["basis"]
    context = [e for e in report["timeline"] if e["stage"] == 0]
    assert len(context) == 1
    assert context[0]["classification"] == "context_only"
    # no chmod artifact exists in the evidence pack; the context_only
    # narrative event is allowed to mention the missing chmod record
    for e in report["timeline"]:
        if e["classification"] == "context_only":
            continue
        assert "chmod" not in e["raw"]


def test_malicious_artifacts_attributed_to_www_data(tmp_path):
    report = load(tmp_path)
    malicious = [e for e in report["timeline"] if e["classification"] == "malicious"]
    assert malicious
    for e in malicious:
        assert e["actor"] in ("www-data", "remote attacker via web")
    assert report["case"]["account"] == "www-data"
    assert report["case"]["c2_host"] == "203.0.113.66"


def test_c2_outbound_event_content_backed(tmp_path):
    report = load(tmp_path)
    outbound = [e for e in report["timeline"] if e["stage"] == 4]
    assert len(outbound) == 1
    e = outbound[0]
    assert e["file"] == "evidence/crontab.txt" and e["line"] == 3
    assert e["evidence_basis"] == "content"
    assert "203.0.113.66" in e["raw"]


def test_evidence_strength_separates_timestamp_from_content(tmp_path):
    report = load(tmp_path)
    strength = report["evidence_strength"]
    assert strength["timestamp_only_or_intra_source_ordering"]
    assert strength["content_backed_cross_source_links"]
    # every cross-source malicious link must point at another cited artifact
    cited = {f"{e['file']}:{e['line']}" for e in report["timeline"]
             if e["classification"] != "context_only"}
    for e in report["timeline"]:
        if e["classification"] == "malicious":
            for link in e["links"]:
                assert link in cited, link
