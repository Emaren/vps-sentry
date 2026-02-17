#!/usr/bin/env python3
"""
vps-sentry.py

Lightweight host integrity + security monitor designed for systemd oneshot timers.

Upgrades in v0.3.1:
- Self-integrity monitoring (hash installed binary + systemd unit)
- Package drift detection (dpkg-query snapshot hash + human diff)
- SSHD config forensic artifacts on change (sshd_config, sshd -T)

FIXES up to v1.0.0 (legacy core; wrapped by vps-sentry runner):
- ACCEPT_BASELINE_NEXT_RUN always accepts the current baseline (even if no baseline_alerts)
- self_integrity diff triggers even when old baseline lacks self_integrity
- packages diff triggers even when old baseline lacks packages (treat as change; supports migration)

Artifacts:
  /var/lib/vps-sentry/last.json
  /var/lib/vps-sentry/diff.json
  /var/lib/vps-sentry/baseline.json
  /var/lib/vps-sentry/forensics/* (when triggered)

Config: /etc/vps-sentry.json
"""

import json
import re
import subprocess
import hashlib
import socket
import urllib.request
import sys
import os
import ipaddress
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Tuple, Dict, List


STATE_DIR = Path("/var/lib/vps-sentry")
STATE_FILE = STATE_DIR / "state.json"
LAST_REPORT_FILE = STATE_DIR / "last.json"
DIFF_FILE = STATE_DIR / "diff.json"
BASELINE_FILE = STATE_DIR / "baseline.json"
CONFIG_FILE = Path("/etc/vps-sentry.json")

# Create this file to accept the *current* snapshots as the new baseline on the next run.
ACCEPT_BASELINE_FLAG = STATE_DIR / "ACCEPT_BASELINE_NEXT_RUN"

# Forensics output
FORENSICS_DIR = STATE_DIR / "forensics"

VERSION = "1.0.0"


# ---------------------------
# Small helpers
# ---------------------------

def run_cmd(args: List[str], timeout: int = 20) -> tuple[int, str]:
    """
    Run a command without shell. Returns (rc, combined_output).
    """
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except Exception as e:
        return 1, str(e)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def sha256_text(s: str) -> str:
    try:
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return ""
    except Exception:
        return ""


def sha256_path(p: Path) -> str:
    """
    Hash files OR directories.
    - file: sha256(contents)
    - dir: sha256 of newline-joined "relative_path:sha256(file_contents)" for all files inside
    """
    try:
        if not p.exists():
            return ""
        if p.is_file():
            return sha256_file(p)
        if p.is_dir():
            items = []
            for fp in sorted(p.rglob("*")):
                if fp.is_file():
                    rel = str(fp.relative_to(p))
                    items.append(f"{rel}:{sha256_file(fp)}")
            return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()
        return ""
    except Exception:
        return ""


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def save_json(p: Path, obj, mode: int = 0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True))
    try:
        p.chmod(mode)
    except Exception:
        pass


def safe_write_text(p: Path, s: str, mode: int = 0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    try:
        p.chmod(mode)
    except Exception:
        pass


def rotate_prev(p: Path):
    """
    If p exists, move it to p + ".prev" (overwriting any existing .prev).
    """
    try:
        if p.exists():
            prev = p.parent / (p.name + ".prev")
            try:
                if prev.exists():
                    prev.unlink()
            except Exception:
                pass
            p.replace(prev)
    except Exception:
        pass


def get_hostname() -> str:
    return socket.gethostname()


def post_webhook(url: str, title: str, body: str):
    """
    Discord-compatible webhook payload; avoids shell/curl entirely.
    """
    try:
        payload = {"content": f"**{title}**\n{body}"}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as _:
            pass
    except Exception:
        return


def clamp(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else (s[:n] + "…")


def make_alert(title: str, detail: str, severity: str = "warn", code: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "title": (title or "Alert").strip()[:160],
        "detail": clamp((detail or "").strip(), 1800),
    }
    sev = (severity or "").strip().lower()
    if sev in ("info", "warn", "critical"):
        out["severity"] = sev
    if code:
        out["code"] = code.strip()[:80]
    return out


def alert_title(a: Any) -> str:
    if isinstance(a, dict):
        return str(a.get("title", "") or "").strip()
    if isinstance(a, (tuple, list)) and len(a) >= 1:
        return str(a[0] or "").strip()
    return str(a or "").strip()


def alert_detail(a: Any) -> str:
    if isinstance(a, dict):
        return str(a.get("detail", "") or "").strip()
    if isinstance(a, (tuple, list)) and len(a) >= 2:
        return str(a[1] or "").strip()
    return ""


def alerts_payload(items: List[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for a in items or []:
        if isinstance(a, dict):
            out.append(make_alert(
                title=str(a.get("title", "") or "Alert"),
                detail=str(a.get("detail", "") or ""),
                severity=str(a.get("severity", "warn") or "warn"),
                code=str(a.get("code", "") or ""),
            ))
        elif isinstance(a, (tuple, list)) and len(a) >= 2:
            out.append(make_alert(title=str(a[0]), detail=str(a[1]), severity="warn"))
        else:
            out.append(make_alert(title="Alert", detail=str(a), severity="warn"))
    return out


def _compile_regex_list(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns or []:
        try:
            s = str(p or "").strip()
            if not s:
                continue
            out.append(re.compile(s, re.IGNORECASE))
        except Exception:
            continue
    return out


def _is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address((host or "").strip())
    except Exception:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_unspecified or ip.is_reserved:
        return False
    return True


# ---------------------------
# CLI
# ---------------------------

def parse_cli(argv: List[str]) -> Dict[str, str]:
    fmt = "json"
    level = "info"
    if "--format" in argv:
        try:
            fmt = argv[argv.index("--format") + 1].strip().lower()
        except Exception:
            fmt = "json"
    if "--log-level" in argv:
        try:
            level = argv[argv.index("--log-level") + 1].strip().lower()
        except Exception:
            level = "info"
    if fmt not in ("json", "text"):
        fmt = "json"
    if level not in ("quiet", "info", "debug"):
        level = "info"
    return {"format": fmt, "log_level": level}


# ---------------------------
# Auth log parsing
# ---------------------------

def read_file_since_offset(path: Path, offset: int) -> Tuple[str, int, bool]:
    """
    Incrementally read file from a byte offset.
    Handles rotation/truncation by rewinding if offset > file size.
    Returns (text, new_offset, rewound)
    """
    if not path.exists():
        return "", 0, False

    rewound = False
    try:
        st = path.stat()
        if offset > st.st_size:
            offset = 0
            rewound = True
    except Exception:
        offset = 0
        rewound = True

    with path.open("rb") as f:
        f.seek(max(0, offset))
        data = f.read()
        new_offset = f.tell()

    return data.decode(errors="replace"), new_offset, rewound


def parse_auth_events(auth_text: str) -> Dict[str, Any]:
    failed = len(re.findall(r"Failed password", auth_text))
    invalid = len(re.findall(r"Invalid user", auth_text))
    accepted = re.findall(r"Accepted \w+ for (\S+) from (\S+)", auth_text)
    sudo = re.findall(r"sudo: (\S+) :", auth_text)

    return {
        "ssh_failed_password": failed,
        "ssh_invalid_user": invalid,
        "ssh_accepted": [{"user": u, "ip": ip} for (u, ip) in accepted][-20:],
        "sudo_users": list(dict.fromkeys(sudo))[-20:],
    }


def purge_seen_map(m: Dict[str, int], ttl_days: int, now_e: int) -> Dict[str, int]:
    ttl = max(1, int(ttl_days)) * 86400
    out = {}
    for k, v in (m or {}).items():
        try:
            ve = int(v)
            if (now_e - ve) <= ttl:
                out[str(k)] = ve
        except Exception:
            continue
    return out


def detect_new_ssh_accepts(
    state: dict,
    accepts: List[Dict[str, str]],
    now_e: int,
    ttl_days: int,
    suppress: bool
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    state.setdefault("known_ssh_ips", {})
    state.setdefault("known_ssh_users", {})

    known_ips = purge_seen_map(state.get("known_ssh_ips", {}), ttl_days, now_e)
    known_users = purge_seen_map(state.get("known_ssh_users", {}), ttl_days, now_e)

    new_accepts: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []

    first_seed = (len(known_ips) == 0 and len(known_users) == 0)

    ttl = max(1, int(ttl_days)) * 86400

    for a in accepts or []:
        ip = (a.get("ip") or "").strip()
        user = (a.get("user") or "").strip()
        if not ip and not user:
            continue

        ip_last = int(known_ips.get(ip, 0) or 0) if ip else 0
        user_last = int(known_users.get(user, 0) or 0) if user else 0

        ip_new = bool(ip) and (ip_last == 0 or (now_e - ip_last) > ttl)
        user_new = bool(user) and (user_last == 0 or (now_e - user_last) > ttl)

        if ip:
            known_ips[ip] = now_e
        if user:
            known_users[user] = now_e

        if suppress or first_seed:
            continue

        if ip_new or user_new:
            new_accepts.append({
                "user": user,
                "ip": ip,
                "ip_new": ip_new,
                "user_new": user_new,
                "ttl_days": int(ttl_days),
            })

    state["known_ssh_ips"] = purge_seen_map(known_ips, ttl_days, now_e)
    state["known_ssh_users"] = purge_seen_map(known_users, ttl_days, now_e)

    if new_accepts:
        ip_news = [x for x in new_accepts if x.get("ip_new")]
        user_news = [x for x in new_accepts if x.get("user_new")]

        lines = []
        if ip_news:
            lines.append("New SSH IP(s):")
            for x in ip_news[:10]:
                lines.append(f"- {x.get('ip','')} (user={x.get('user','')})")
        if user_news:
            lines.append("New SSH user(s):")
            for x in user_news[:10]:
                lines.append(f"- {x.get('user','')} (ip={x.get('ip','')})")

        alerts.append(make_alert(
            title="New SSH accepted login",
            detail="\n".join(lines),
            severity="warn",
            code="new_ssh_accept",
        ))

    return new_accepts, alerts


# ---------------------------
# Listening ports (PUBLIC vs LOCAL)
# ---------------------------

def _norm_addr(a: str) -> str:
    a = a.strip()
    if a.startswith("[") and "]" in a:
        a = a[1:a.index("]")]
    if "%" in a:
        a = a.split("%", 1)[0]
    return a


def _split_host_port(local: str):
    local = local.strip()
    if local.startswith("[") and "]" in local:
        host = local[1:local.rfind("]")]
        port = int(local.rsplit(":", 1)[1])
        return _norm_addr(host), port

    if ":" not in local:
        return _norm_addr(local), 0

    host, port_s = local.rsplit(":", 1)
    return _norm_addr(host), int(port_s)


def port_sig(p: dict) -> str:
    try:
        return f"{p.get('proto','')}|{p.get('host','')}|{int(p.get('port',0))}|{p.get('proc','')}"
    except Exception:
        return ""


def _extract_pid_from_ss_line(line: str) -> int:
    m = re.search(r"\bpid=(\d+)\b", line)
    if not m:
        return 0
    try:
        return int(m.group(1))
    except Exception:
        return 0


def list_listening_ports():
    rc, out = run_cmd(["ss", "-lntupH"], timeout=20)
    if rc != 0 and not out:
        return []

    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0]
        local = parts[4]

        try:
            host, port = _split_host_port(local)
        except Exception:
            continue

        if port <= 0:
            continue

        proc = ""
        pm = re.search(r'users:\(\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)

        pid = _extract_pid_from_ss_line(line)

        host_l = host.lower()
        if host_l in ("0.0.0.0", "::", "*"):
            is_public = True
        else:
            is_loopback = host_l in ("127.0.0.1", "::1", "localhost") or host_l.startswith("127.")
            is_public = (not is_loopback)

        item = {
            "proto": proto,
            "host": host,
            "port": port,
            "proc": proc,
            "pid": pid,
            "public": is_public,
            "raw": line,
        }
        item["sig"] = port_sig(item)
        ports.append(item)

    ports.sort(key=lambda x: (not x["public"], x["proto"], x["host"], x["port"], x["proc"]))
    return ports


def proc_explain(pid: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {"pid": int(pid or 0)}
    if not pid or pid <= 0:
        return out

    try:
        out["exe"] = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        out["exe"] = ""

    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        parts = [p.decode(errors="replace") for p in raw.split(b"\x00") if p]
        out["cmdline"] = " ".join(parts)
    except Exception:
        out["cmdline"] = ""

    unit = ""
    try:
        cg = Path(f"/proc/{pid}/cgroup").read_text(errors="replace")
        m = re.findall(r"/([^/\n]+\.service)\b", cg)
        if m:
            unit = m[-1]
    except Exception:
        unit = ""
    out["unit"] = unit

    return out


# ---------------------------
# Resource vitals
# ---------------------------

def _safe_percent(v: float) -> float:
    try:
        return round(max(0.0, min(100.0, float(v))), 1)
    except Exception:
        return 0.0


def _read_proc_stat_totals() -> Tuple[int, int]:
    """
    Read aggregate CPU counters from /proc/stat.
    Returns (total_jiffies, idle_jiffies).
    """
    try:
        first = Path("/proc/stat").read_text(errors="replace").splitlines()[0]
        parts = first.split()
        if not parts or parts[0] != "cpu":
            return 0, 0

        nums: List[int] = []
        for tok in parts[1:]:
            try:
                nums.append(int(tok))
            except Exception:
                break

        if len(nums) < 4:
            return 0, 0

        idle = int(nums[3]) + (int(nums[4]) if len(nums) > 4 else 0)
        total = int(sum(nums))
        return total, idle
    except Exception:
        return 0, 0


def sample_cpu_used_percent(sample_sec: float = 0.12):
    """
    CPU usage as % of VPS capacity (0..100), sampled over a short window.
    """
    total_1, idle_1 = _read_proc_stat_totals()
    if total_1 <= 0:
        return None

    try:
        time.sleep(max(0.05, min(float(sample_sec), 0.5)))
    except Exception:
        pass

    total_2, idle_2 = _read_proc_stat_totals()
    dt = int(total_2 - total_1)
    if dt <= 0:
        return None

    idle_dt = max(0, int(idle_2 - idle_1))
    used = (1.0 - (float(idle_dt) / float(dt))) * 100.0
    return _safe_percent(used)


def memory_snapshot() -> Dict[str, Any]:
    mem: Dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(errors="replace").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            m = re.search(r"(\d+)", v)
            if not m:
                continue
            mem[k.strip()] = int(m.group(1))
    except Exception:
        pass

    total_kb = int(mem.get("MemTotal", 0) or 0)
    avail_kb = int(mem.get("MemAvailable", mem.get("MemFree", 0)) or 0)
    used_kb = max(0, total_kb - avail_kb)

    total_mb = round(float(total_kb) / 1024.0, 1) if total_kb > 0 else 0.0
    avail_mb = round(float(avail_kb) / 1024.0, 1) if avail_kb > 0 else 0.0
    used_mb = round(float(used_kb) / 1024.0, 1) if used_kb > 0 else 0.0

    used_percent = _safe_percent((float(used_kb) / float(total_kb)) * 100.0) if total_kb > 0 else None

    return {
        "total_mb": total_mb,
        "used_mb": used_mb,
        "available_mb": avail_mb,
        "used_percent": used_percent,
        "capacity_percent": 100.0,
    }


def collect_resource_vitals(top_n: int = 5) -> Dict[str, Any]:
    cores = int(os.cpu_count() or 1)
    cores = max(1, cores)

    cpu_used_percent = sample_cpu_used_percent()
    mem = memory_snapshot()
    mem_total_mb = float(mem.get("total_mb", 0.0) or 0.0)

    rc, out = run_cmd(["ps", "-eo", "pid=,comm=,%cpu=,rss=", "--sort=-%cpu"], timeout=25)
    rows: List[Dict[str, Any]] = []
    if rc == 0 or out:
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue

            parts = line.split(None, 3)
            if len(parts) < 4:
                continue

            try:
                pid = int(parts[0])
            except Exception:
                continue

            name = (parts[1] or "").strip() or "unknown"
            try:
                cpu_raw = float(parts[2])
            except Exception:
                cpu_raw = 0.0
            try:
                rss_kb = float(parts[3])
            except Exception:
                rss_kb = 0.0

            rows.append({
                "pid": max(0, pid),
                "name": name,
                "cpu_raw": max(0.0, cpu_raw),
                "rss_kb": max(0.0, rss_kb),
            })

    total_cpu_raw = sum(float(r.get("cpu_raw", 0.0) or 0.0) for r in rows)
    top_n = max(1, int(top_n or 5))

    def _to_proc_payload(row: Dict[str, Any]) -> Dict[str, Any]:
        cpu_raw = float(row.get("cpu_raw", 0.0) or 0.0)
        rss_kb = float(row.get("rss_kb", 0.0) or 0.0)
        mem_mb = max(0.0, rss_kb / 1024.0)

        cpu_share = (cpu_raw / total_cpu_raw * 100.0) if total_cpu_raw > 0 else 0.0
        cpu_capacity = (cpu_raw / float(cores)) if cores > 0 else 0.0
        mem_capacity = (mem_mb / mem_total_mb * 100.0) if mem_total_mb > 0 else 0.0

        return {
            "pid": int(row.get("pid", 0) or 0),
            "name": str(row.get("name", "") or "unknown"),
            "cpu_share_percent": _safe_percent(cpu_share),
            "cpu_capacity_percent": _safe_percent(cpu_capacity),
            "memory_mb": round(mem_mb, 1),
            "memory_capacity_percent": _safe_percent(mem_capacity),
        }

    ordered = sorted(rows, key=lambda r: (float(r.get("cpu_raw", 0.0) or 0.0), float(r.get("rss_kb", 0.0) or 0.0)), reverse=True)
    top_rows = ordered[:top_n]
    other_rows = ordered[top_n:]

    top_payload = [_to_proc_payload(r) for r in top_rows]

    other_payload = None
    if other_rows:
        other_cpu_raw = sum(float(r.get("cpu_raw", 0.0) or 0.0) for r in other_rows)
        other_rss_kb = sum(float(r.get("rss_kb", 0.0) or 0.0) for r in other_rows)
        other_payload = _to_proc_payload({
            "pid": 0,
            "name": "other-processes",
            "cpu_raw": other_cpu_raw,
            "rss_kb": other_rss_kb,
        })

    cpu_share_total = sum(float(p.get("cpu_share_percent", 0.0) or 0.0) for p in top_payload)
    if other_payload:
        cpu_share_total += float(other_payload.get("cpu_share_percent", 0.0) or 0.0)

    return {
        "cpu": {
            "used_percent": cpu_used_percent,
            "capacity_percent": 100.0,
            "cores": cores,
        },
        "memory": mem,
        "processes": {
            "sampled_count": len(rows),
            "top": top_payload,
            "other": other_payload,
            "cpu_share_total_percent": _safe_percent(cpu_share_total),
        },
    }


# ---------------------------
# Outbound/process IOC detection
# ---------------------------

def list_active_connections() -> List[Dict[str, Any]]:
    rc, out = run_cmd(["ss", "-H", "-ntup"], timeout=25)
    if rc != 0 and not out:
        return []

    rows: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        proto = (parts[0] or "").lower()
        state = (parts[1] or "").upper()
        local = parts[4]
        peer = parts[5]

        try:
            local_host, local_port = _split_host_port(local)
            peer_host, peer_port = _split_host_port(peer)
        except Exception:
            continue

        proc = ""
        pm = re.search(r'users:\(\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)
        pid = _extract_pid_from_ss_line(line)

        rows.append({
            "proto": proto,
            "state": state,
            "local_host": local_host,
            "local_port": int(local_port or 0),
            "peer_host": peer_host,
            "peer_port": int(peer_port or 0),
            "peer_public": _is_public_ip(peer_host),
            "proc": proc,
            "pid": int(pid or 0),
            "raw": line,
        })

    return rows


def detect_outbound_scan_iocs(conns: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[int, Dict[str, Any]]]:
    conn_threshold = int(cfg.get("outbound_scan_conn_threshold", 80))
    unique_dst_threshold = int(cfg.get("outbound_scan_unique_dst_threshold", 30))
    syn_sent_threshold = int(cfg.get("outbound_scan_syn_sent_threshold", 12))
    dominant_port_ratio_threshold = float(cfg.get("outbound_scan_dominant_port_ratio", 0.70))
    outbound_ephemeral_min_port = int(cfg.get("outbound_scan_ephemeral_min_port", 1024))
    allow_re = _compile_regex_list(cfg.get("outbound_scan_allow_process_regex", []))
    max_hits = int(cfg.get("outbound_scan_max_hits", 8))

    by_pid: Dict[int, Dict[str, Any]] = {}

    for c in conns or []:
        pid = int(c.get("pid", 0) or 0)
        if pid <= 1:
            continue
        if not bool(c.get("peer_public", False)):
            continue

        peer_port = int(c.get("peer_port", 0) or 0)
        local_port = int(c.get("local_port", 0) or 0)
        state = str(c.get("state", "") or "").upper()
        if peer_port <= 0:
            continue

        # Outbound-ish traffic: ephemeral source ports or active SYN fanout.
        if not (local_port >= outbound_ephemeral_min_port or state == "SYN-SENT"):
            continue

        st = by_pid.setdefault(pid, {
            "pid": pid,
            "proc": c.get("proc", "") or "",
            "connections": 0,
            "syn_sent": 0,
            "dst_ips": set(),
            "dst_ports": {},
            "sample_dst": [],
        })

        st["connections"] += 1
        if state == "SYN-SENT":
            st["syn_sent"] += 1
        st["dst_ips"].add(str(c.get("peer_host", "") or ""))

        dp = int(peer_port)
        st["dst_ports"][dp] = int(st["dst_ports"].get(dp, 0)) + 1

        if len(st["sample_dst"]) < 12:
            st["sample_dst"].append(f"{c.get('peer_host','')}:{dp} ({state.lower()})")

    summarized: Dict[int, Dict[str, Any]] = {}
    hits: List[Dict[str, Any]] = []
    for pid, st in by_pid.items():
        dst_ports = st.get("dst_ports", {}) or {}
        dominant_port = 0
        dominant_count = 0
        if dst_ports:
            dominant_port, dominant_count = max(dst_ports.items(), key=lambda x: x[1])

        connections = int(st.get("connections", 0) or 0)
        syn_sent = int(st.get("syn_sent", 0) or 0)
        unique_dst_ips = len(st.get("dst_ips", set()) or set())
        dominant_ratio = (float(dominant_count) / float(connections)) if connections > 0 else 0.0

        summary = {
            "pid": pid,
            "proc": st.get("proc", "") or "",
            "connections": connections,
            "syn_sent": syn_sent,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ports": len(dst_ports),
            "dominant_dst_port": int(dominant_port or 0),
            "dominant_dst_port_count": int(dominant_count or 0),
            "dominant_dst_port_ratio": round(dominant_ratio, 4),
            "sample_dst": list(st.get("sample_dst", []) or []),
        }
        summarized[pid] = summary

        strong_syn_fanout = syn_sent >= syn_sent_threshold and unique_dst_ips >= max(8, unique_dst_threshold // 2)
        broad_same_port_fanout = (
            connections >= conn_threshold
            and unique_dst_ips >= unique_dst_threshold
            and dominant_ratio >= dominant_port_ratio_threshold
        )
        if not (strong_syn_fanout or broad_same_port_fanout):
            continue

        ex = proc_explain(pid)
        summary["exe"] = ex.get("exe", "") or ""
        summary["unit"] = ex.get("unit", "") or ""
        summary["cmdline"] = clamp(ex.get("cmdline", "") or "", 240)

        ident = f"{summary.get('proc','')} {summary.get('exe','')} {summary.get('cmdline','')}"
        if any(r.search(ident) for r in allow_re):
            continue

        hits.append(summary)

    hits.sort(key=lambda x: (int(x.get("unique_dst_ips", 0)), int(x.get("connections", 0))), reverse=True)
    return hits[:max_hits], summarized


def detect_suspicious_process_iocs(cfg: Dict[str, Any], outbound_by_pid: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    default_name_patterns = [
        r"\bmasscan\b", r"\bzmap\b", r"\bzgrab\b", r"\bnmap\b", r"\bnaabu\b", r"\brustscan\b",
        r"\bhping3?\b", r"\bnping\b", r"\bnikto\b", r"\bgobuster\b", r"\bferoxbuster\b",
        r"\bxmrig\b", r"\bkdevtmpfsi\b", r"\bkinsing\b", r"\brbot\b", r"\bsys-update-daemon\b",
    ]
    default_cmd_patterns = [
        r"curl\s+[^|;]*\|\s*(bash|sh)\b",
        r"wget\s+[^|;]*\s-O-\s*\|\s*(bash|sh)\b",
        r"base64\s+-d",
        r"/dev/tcp/",
        r"\b(nc|netcat)\b.*\s-e\s",
        r"python[23]?\s+-c\s+.*socket",
    ]
    default_exe_patterns = [r"^/(tmp|var/tmp|dev/shm|run)/"]

    name_re = _compile_regex_list(cfg.get("process_ioc_name_regex", default_name_patterns))
    cmd_re = _compile_regex_list(cfg.get("process_ioc_cmdline_regex", default_cmd_patterns))
    exe_re = _compile_regex_list(cfg.get("process_ioc_exe_regex", default_exe_patterns))
    allow_re = _compile_regex_list(cfg.get("process_ioc_allow_regex", []))

    outbound_unique_threshold = int(cfg.get("process_ioc_outbound_unique_dst_threshold", 20))
    max_hits = int(cfg.get("process_ioc_max_hits", 10))

    rc, out = run_cmd(["ps", "-eo", "pid=,ppid=,user=,comm=,args="], timeout=25)
    if rc != 0 and not out:
        return []

    hits: List[Dict[str, Any]] = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s*(.*)$", line)
        if not m:
            continue

        pid = int(m.group(1))
        if pid <= 1:
            continue
        ppid = int(m.group(2))
        user = m.group(3)
        comm = m.group(4)
        args = (m.group(5) or "").strip()

        reasons: List[str] = []
        text = f"{comm}\n{args}"
        if any(r.search(text) for r in name_re):
            reasons.append("process name/cmdline matches scanner IOC pattern")
        if any(r.search(args) for r in cmd_re):
            reasons.append("cmdline matches execution IOC pattern")

        ob = outbound_by_pid.get(pid) or {}
        if int(ob.get("unique_dst_ips", 0) or 0) >= outbound_unique_threshold:
            reasons.append(
                f"high outbound fanout ({int(ob.get('unique_dst_ips',0) or 0)} unique destinations)"
            )

        # No signal yet, skip expensive /proc reads.
        if not reasons:
            continue

        ex = proc_explain(pid)
        exe = ex.get("exe", "") or ""
        unit = ex.get("unit", "") or ""
        cmdline = ex.get("cmdline", "") or args
        if exe and any(r.search(exe) for r in exe_re):
            reasons.append("executable path is in suspicious writable runtime path")

        ident = f"{comm} {exe} {cmdline}"
        if any(r.search(ident) for r in allow_re):
            continue

        # Keep reasons unique and stable.
        uniq_reasons: List[str] = []
        seen = set()
        for r in reasons:
            if r not in seen:
                uniq_reasons.append(r)
                seen.add(r)

        item: Dict[str, Any] = {
            "pid": pid,
            "ppid": ppid,
            "user": user,
            "proc": comm,
            "exe": exe,
            "unit": unit,
            "cmdline": clamp(cmdline, 240),
            "reasons": uniq_reasons,
        }
        if ob:
            item["outbound"] = {
                "connections": int(ob.get("connections", 0) or 0),
                "syn_sent": int(ob.get("syn_sent", 0) or 0),
                "unique_dst_ips": int(ob.get("unique_dst_ips", 0) or 0),
                "dominant_dst_port": int(ob.get("dominant_dst_port", 0) or 0),
                "dominant_dst_port_ratio": float(ob.get("dominant_dst_port_ratio", 0.0) or 0.0),
            }
        hits.append(item)

    hits.sort(key=lambda x: (len(x.get("reasons", [])), int(x.get("pid", 0))), reverse=True)
    return hits[:max_hits]


def _build_outbound_ioc_detail(hits: List[Dict[str, Any]]) -> str:
    lines = ["High-fanout outbound pattern detected (possible scan activity)."]
    for h in (hits or [])[:6]:
        dominant_port = int(h.get("dominant_dst_port", 0) or 0)
        dominant_ratio = float(h.get("dominant_dst_port_ratio", 0.0) or 0.0)
        ratio_pct = int(round(dominant_ratio * 100.0))
        lines.append(
            f"- pid={h.get('pid')} proc={h.get('proc','?')} dst={h.get('unique_dst_ips',0)} "
            f"conns={h.get('connections',0)} syn_sent={h.get('syn_sent',0)} "
            f"dominant_dport={dominant_port} ({ratio_pct}%)"
        )
        exe = str(h.get("exe", "") or "")
        if exe:
            lines.append(f"  exe={exe}")
        unit = str(h.get("unit", "") or "")
        if unit:
            lines.append(f"  unit={unit}")
        samples = h.get("sample_dst", []) or []
        if samples:
            lines.append("  sample: " + ", ".join(samples[:6]))
    return clamp("\n".join(lines), 1800)


def _build_process_ioc_detail(hits: List[Dict[str, Any]]) -> str:
    lines = ["Suspicious process IOC(s) detected."]
    for h in (hits or [])[:8]:
        lines.append(f"- pid={h.get('pid')} user={h.get('user','?')} proc={h.get('proc','?')}")
        exe = str(h.get("exe", "") or "")
        if exe:
            lines.append(f"  exe={exe}")
        unit = str(h.get("unit", "") or "")
        if unit:
            lines.append(f"  unit={unit}")
        reasons = h.get("reasons", []) or []
        if reasons:
            lines.append("  reasons: " + "; ".join([str(x) for x in reasons[:4]]))
        cmd = str(h.get("cmdline", "") or "")
        if cmd:
            lines.append(f"  cmdline={cmd}")
    return clamp("\n".join(lines), 1800)


# ---------------------------
# Users + watched files + cron + firewall
# ---------------------------

def list_users_snapshot():
    rc, out = run_cmd(["getent", "passwd"], timeout=10)
    if rc != 0 and not out:
        return []

    users = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            users.append({
                "user": parts[0],
                "uid": int(parts[2]),
                "gid": int(parts[3]),
                "home": parts[5],
                "shell": parts[6],
            })
        except Exception:
            continue

    users.sort(key=lambda x: x["uid"])
    return users


def hash_key_files(
    extra_paths,
    tight_ufw_watch: bool = False,
    watch_systemd_dir: bool = True,
):
    ufw_paths = []
    if tight_ufw_watch:
        ufw_paths = [
            Path("/etc/default/ufw"),
            Path("/etc/ufw/ufw.conf"),
            Path("/etc/ufw/user.rules"),
            Path("/etc/ufw/user6.rules"),
            Path("/etc/ufw/applications.d"),
        ]
    else:
        ufw_paths = [Path("/etc/ufw")]

    paths = [
        Path("/root/.ssh"),
        Path("/home/tony/.ssh/authorized_keys"),

        Path("/etc/ssh/sshd_config"),
        Path("/etc/ssh/sshd_config.d"),

        Path("/etc/nginx/sites-enabled"),

        Path("/etc/sudoers"),
        Path("/etc/sudoers.d"),
    ] + ufw_paths + [Path(p) for p in extra_paths]

    if watch_systemd_dir:
        paths.append(Path("/etc/systemd/system"))

    snap = {}
    for p in paths:
        snap[str(p)] = sha256_path(p)
    return snap


def cron_snapshot():
    targets = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]

    snap = {}
    for t in targets:
        if t.is_file():
            snap[str(t)] = sha256_file(t)
        elif t.is_dir():
            items = []
            for fp in sorted(t.glob("*")):
                if fp.is_file():
                    items.append(f"{fp.name}:{sha256_file(fp)}")
            snap[str(t)] = hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()

    crontabs_dir = Path("/var/spool/cron/crontabs")
    snap["user_crontabs_dir_hash"] = sha256_path(crontabs_dir)

    return snap


# ---- Firewall output normalization (avoid counter/handle noise) ----

def _normalize_text(out: str) -> str:
    out = (out or "").replace("\r\n", "\n").replace("\r", "\n")
    out = "\n".join(line.rstrip() for line in out.splitlines())
    return out.strip()


def _normalize_nft_ruleset(out: str) -> str:
    out = _normalize_text(out)
    out = re.sub(r"\bcounter packets\s+\d+\s+bytes\s+\d+\b", "counter packets x bytes x", out)
    out = re.sub(r"\bpackets\s+\d+\s+bytes\s+\d+\b", "packets x bytes x", out)
    out = re.sub(r"\bhandle\s+\d+\b", "handle x", out)
    return out


def _canonicalize_nft_json(obj: Any) -> Any:
    if isinstance(obj, dict) and len(obj) == 1 and "element" in obj:
        return None

    if isinstance(obj, dict):
        noisy_keys = {
            "handle", "packets", "bytes", "counter",
            "timeout", "expires", "expiration", "expire",
            "ttl", "last", "last_used", "since",
        }
        out = {}
        for k, v in obj.items():
            if k in noisy_keys:
                continue
            if k in ("elem", "elements"):
                continue
            cv = _canonicalize_nft_json(v)
            if cv is None:
                continue
            out[k] = cv
        return out

    if isinstance(obj, list):
        out_list = []
        for x in obj:
            cx = _canonicalize_nft_json(x)
            if cx is None:
                continue
            out_list.append(cx)
        return out_list

    return obj


def _nft_ruleset_canon_json() -> Tuple[str, str]:
    rc, out = run_cmd(["nft", "-j", "list", "ruleset"], timeout=30)
    if rc != 0 or not out:
        return "", ""

    try:
        obj = json.loads(out)
        obj = _canonicalize_nft_json(obj)
        canon_compact = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        h = sha256_text(canon_compact)
        canon_pretty = json.dumps(obj, indent=2, sort_keys=True)
        return h, canon_pretty
    except Exception:
        return "", ""


def _nft_ruleset_hash() -> str:
    h, _pretty = _nft_ruleset_canon_json()
    if h:
        return h

    rc, out = run_cmd(["nft", "list", "ruleset"], timeout=30)
    if rc == 0 and out:
        return sha256_text(_normalize_nft_ruleset(out))

    return ""


def _iptables_rules_snapshot(ipv6: bool = False) -> str:
    bin_name = "ip6tables" if ipv6 else "iptables"
    tables = ["filter", "nat", "mangle", "raw", "security"]

    chunks = []
    for t in tables:
        rc, out = run_cmd([bin_name, "-t", t, "-S"], timeout=20)
        if rc == 0 and out:
            chunks.append(f"*{t}\n{_normalize_text(out)}")
    return "\n".join(chunks).strip()


def _ufw_status_verbose() -> Tuple[str, str]:
    rc, out = run_cmd(["ufw", "status", "verbose"], timeout=20)
    if rc == 0 and out:
        norm = _normalize_text(out)
        return sha256_text(norm), norm
    return "", ""


def firewall_snapshot():
    cfg = load_json(CONFIG_FILE, {})
    include_iptables = bool(cfg.get("include_iptables", False))
    include_nft = bool(cfg.get("include_nft", True))

    snap = {}

    ufw_hash, _ufw_text = _ufw_status_verbose()
    if ufw_hash:
        snap["ufw_status_hash"] = ufw_hash

    if include_nft:
        h = _nft_ruleset_hash()
        if h:
            snap["nft_ruleset_hash"] = h

    if include_iptables:
        v4 = _iptables_rules_snapshot(ipv6=False)
        v6 = _iptables_rules_snapshot(ipv6=True)
        if v4:
            snap["iptables_rules_hash"] = sha256_text(v4)
        if v6:
            snap["ip6tables_rules_hash"] = sha256_text(v6)

    return snap


def capture_firewall_forensics(old_fw: dict, new_fw: dict, run_ts: str):
    try:
        cfg = load_json(CONFIG_FILE, {})
        if not bool(cfg.get("capture_firewall_forensics", True)):
            return

        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

        ufw_hash, ufw_text = _ufw_status_verbose()
        ufw_path = FORENSICS_DIR / "ufw_status_verbose.txt"
        if ufw_text:
            rotate_prev(ufw_path)
            safe_write_text(ufw_path, ufw_text + "\n", mode=0o600)

        nft_hash, nft_json_pretty = _nft_ruleset_canon_json()
        nft_path = FORENSICS_DIR / "nft_ruleset_canon.json"
        if nft_json_pretty:
            rotate_prev(nft_path)
            safe_write_text(nft_path, nft_json_pretty + "\n", mode=0o600)

        meta = {
            "ts": run_ts,
            "host": get_hostname(),
            "version": VERSION,
            "old_firewall": old_fw or {},
            "new_firewall": new_fw or {},
            "captured": {
                "ufw_status_hash": ufw_hash,
                "nft_ruleset_hash": nft_hash,
            },
        }
        meta_path = FORENSICS_DIR / "firewall_forensics_meta.json"
        rotate_prev(meta_path)
        safe_write_text(meta_path, json.dumps(meta, indent=2, sort_keys=True) + "\n", mode=0o600)
    except Exception:
        return


# ---------------------------
# Self-integrity snapshot
# ---------------------------

def self_integrity_snapshot() -> Dict[str, str]:
    """
    Hash the installed vps-sentry binary and its systemd unit file.
    """
    snap = {}
    snap["/usr/local/bin/vps-sentry"] = sha256_path(Path("/usr/local/bin/vps-sentry"))
    snap["/etc/systemd/system/vps-sentry.service"] = sha256_path(Path("/etc/systemd/system/vps-sentry.service"))
    return snap


# ---------------------------
# Package snapshot (dpkg-query)
# ---------------------------

def packages_snapshot() -> Dict[str, Any]:
    """
    Snapshot installed packages with dpkg-query.
    Store a hash + a compact map for diffing.
    """
    rc, out = run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
    if rc != 0 or not out:
        return {"hash": "", "count": 0, "map": {}}

    m: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        pkg, ver = line.split("\t", 1)
        pkg = pkg.strip()
        ver = ver.strip()
        if pkg:
            m[pkg] = ver

    canon_lines = [f"{k}\t{m[k]}" for k in sorted(m.keys())]
    canon = "\n".join(canon_lines)
    return {"hash": sha256_text(canon), "count": len(m), "map": m}


def packages_diff(old_map: Dict[str, str], new_map: Dict[str, str], limit: int = 80) -> Dict[str, Any]:
    old_map = old_map or {}
    new_map = new_map or {}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added = sorted(list(new_keys - old_keys))
    removed = sorted(list(old_keys - new_keys))

    changed = []
    for k in sorted(list(old_keys & new_keys)):
        if old_map.get(k) != new_map.get(k):
            changed.append(k)

    lines = []
    if added:
        lines.append("Added packages:")
        for k in added[:limit]:
            lines.append(f"+ {k} {new_map.get(k,'')}")
    if removed:
        lines.append("Removed packages:")
        for k in removed[:limit]:
            lines.append(f"- {k} {old_map.get(k,'')}")
    if changed:
        lines.append("Upgraded/downgraded packages:")
        for k in changed[:limit]:
            lines.append(f"~ {k} {old_map.get(k,'')} -> {new_map.get(k,'')}")

    return {
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "detail": "\n".join(lines).strip(),
    }


# ---------------------------
# SSHD config forensics
# ---------------------------

def capture_sshd_forensics(run_ts: str):
    """
    Capture sshd_config + effective config on sshd config change.
    """
    try:
        cfg = load_json(CONFIG_FILE, {})
        if not bool(cfg.get("capture_sshd_forensics", True)):
            return

        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

        p = Path("/etc/ssh/sshd_config")
        if p.exists() and p.is_file():
            rotate_prev(FORENSICS_DIR / "sshd_config.txt")
            safe_write_text(FORENSICS_DIR / "sshd_config.txt", p.read_text(errors="replace") + "\n", mode=0o600)

        d = Path("/etc/ssh/sshd_config.d")
        rotate_prev(FORENSICS_DIR / "sshd_config.d.hash.txt")
        safe_write_text(
            FORENSICS_DIR / "sshd_config.d.hash.txt",
            f"ts={run_ts}\nsshd_config_d_hash={sha256_path(d)}\n",
            mode=0o600
        )

        rc, out = run_cmd(["sshd", "-T"], timeout=20)
        if rc == 0 and out:
            rotate_prev(FORENSICS_DIR / "sshd_effective_T.txt")
            safe_write_text(FORENSICS_DIR / "sshd_effective_T.txt", out.strip() + "\n", mode=0o600)
    except Exception:
        return


# ---------------------------
# Diff helpers
# ---------------------------

def diff_hash_dict(old: dict, new: dict):
    old = old or {}
    new = new or {}

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    added = sorted(list(new_keys - old_keys))
    removed = sorted(list(old_keys - new_keys))

    changed = []
    for k in sorted(list(old_keys & new_keys)):
        if old.get(k, "") != new.get(k, ""):
            changed.append(k)

    return added, removed, changed


def should_send_webhook_for_alert(title: str, state: dict, cooldown_sec: int) -> bool:
    try:
        last_sent = state.get("webhook_last_sent", {}) or {}
        last = int(last_sent.get(title, 0) or 0)
        now_e = now_epoch()
        return (now_e - last) >= max(0, int(cooldown_sec))
    except Exception:
        return True


def mark_webhook_sent(title: str, state: dict):
    try:
        state.setdefault("webhook_last_sent", {})
        state["webhook_last_sent"][title] = now_epoch()
    except Exception:
        pass


# ---------------------------
# Reporting helpers
# ---------------------------

def build_text_output(report: dict) -> str:
    alerts = report.get("alerts", []) or []
    lines = []
    lines.append(f"VPS Sentry {report.get('version','')} on {report.get('host','')} @ {report.get('ts','')}")
    lines.append(f"Baseline last accepted: {report.get('baseline_last_accepted_ts','') or '(never)'}")
    lines.append(
        f"SSH failed={report.get('auth',{}).get('ssh_failed_password',0)} invalid_user={report.get('auth',{}).get('ssh_invalid_user',0)} "
        f"public_ports={report.get('public_ports_count',0)} alerts={len(alerts)}"
    )
    if alerts:
        lines.append("")
        lines.append("ALERTS:")
        for a in alerts[:10]:
            lines.append(f"- {a.get('title','')}")
            d = (a.get("detail") or "").strip()
            if d:
                lines.append("  " + d.replace("\n", "\n  "))
    return "\n".join(lines).strip() + "\n"


# ---------------------------
# Main
# ---------------------------

def main():
    if "--version" in sys.argv:
        print(VERSION)
        return

    cli = parse_cli(sys.argv)
    fmt = cli["format"]
    log_level = cli["log_level"]

    cfg = load_json(CONFIG_FILE, {})

    webhook = cfg.get("webhook_url", "")
    ignore_ports = set(cfg.get("ignore_ports", [22, 80, 443]))
    extra_watch_files = cfg.get("watch_files", [])
    max_failed_before_alert = int(cfg.get("alert_failed_ssh_threshold", 25))
    max_invalid_user_before_alert = int(cfg.get("alert_invalid_user_threshold", 10))

    quiet_no_alerts = bool(cfg.get("quiet_no_alerts", True))
    print_full_on_alerts = bool(cfg.get("print_full_on_alerts", True))

    webhook_cooldown_sec = int(cfg.get("webhook_cooldown_sec", 900))
    tight_ufw_watch = bool(cfg.get("tight_ufw_watch", False))
    watch_systemd_dir = bool(cfg.get("watch_systemd_dir", True))

    ssh_new_accept_alert = bool(cfg.get("alert_on_new_ssh_accept", True))
    ssh_seen_ttl_days = int(cfg.get("ssh_seen_ttl_days", 30))

    run_ts = now_iso()
    run_e = now_epoch()
    host = get_hostname()

    state = load_json(STATE_FILE, {
        "version": VERSION,
        "auth_offset": 0,
        "baseline": {},
        "baseline_set_ts": "",
        "baseline_last_accepted_ts": "",
        "last_run": "",
        "webhook_last_sent": {},
        "known_ssh_ips": {},
        "known_ssh_users": {},
    })

    state.setdefault("baseline_set_ts", "")
    state.setdefault("baseline_last_accepted_ts", "")
    state.setdefault("last_run", "")
    state.setdefault("webhook_last_sent", {})
    state.setdefault("known_ssh_ips", {})
    state.setdefault("known_ssh_users", {})

    # --- auth log incremental read
    auth_text, new_auth_offset, auth_rewound = read_file_since_offset(
        Path("/var/log/auth.log"),
        int(state.get("auth_offset", 0))
    )
    sec = parse_auth_events(auth_text)

    # --- snapshots
    all_ports = [p for p in list_listening_ports() if p["port"] not in ignore_ports]
    ports_public = [p for p in all_ports if p.get("public")]
    ports_local = [p for p in all_ports if not p.get("public")]

    users = list_users_snapshot()
    keys = hash_key_files(
        extra_watch_files,
        tight_ufw_watch=tight_ufw_watch,
        watch_systemd_dir=watch_systemd_dir,
    )
    cron = cron_snapshot()
    fw = firewall_snapshot()

    self_i = self_integrity_snapshot()
    pkgs = packages_snapshot()

    enable_outbound_ioc = bool(cfg.get("enable_outbound_ioc_detection", True))
    enable_process_ioc = bool(cfg.get("enable_process_ioc_detection", True))

    active_conns = list_active_connections() if (enable_outbound_ioc or enable_process_ioc) else []
    outbound_iocs: List[Dict[str, Any]] = []
    outbound_by_pid: Dict[int, Dict[str, Any]] = {}
    if enable_outbound_ioc:
        outbound_iocs, outbound_by_pid = detect_outbound_scan_iocs(active_conns, cfg)

    process_iocs: List[Dict[str, Any]] = []
    if enable_process_ioc:
        process_iocs = detect_suspicious_process_iocs(cfg, outbound_by_pid)

    ioc_alerts: List[Dict[str, Any]] = []
    threat_indicators: List[Dict[str, Any]] = []
    if outbound_iocs:
        ioc_alerts.append(make_alert(
            title="Outbound scan IOC detected",
            detail=_build_outbound_ioc_detail(outbound_iocs),
            severity="critical",
            code="outbound_scan_ioc",
        ))
        threat_indicators.append({
            "id": "outbound-scan-ioc",
            "severity": "critical",
            "title": "Outbound scan IOC detected",
            "detail": f"{len(outbound_iocs)} process(es) matched outbound scan fanout heuristics.",
        })

    if process_iocs:
        ioc_alerts.append(make_alert(
            title="Suspicious process IOC detected",
            detail=_build_process_ioc_detail(process_iocs),
            severity="critical",
            code="suspicious_process_ioc",
        ))
        threat_indicators.append({
            "id": "suspicious-process-ioc",
            "severity": "critical",
            "title": "Suspicious process IOC detected",
            "detail": f"{len(process_iocs)} suspicious runtime process(es) matched IOC heuristics.",
        })

    threat_payload = {
        "suspicious_processes": process_iocs,
        "outbound_suspicious": outbound_iocs,
        "persistence_hits": [],
        "indicators": threat_indicators,
    }
    vitals_payload = collect_resource_vitals(top_n=int(cfg.get("vitals_top_processes", 5)))

    ports_public_sigs = sorted([p["sig"] for p in ports_public if p.get("sig")])

    baseline = state.get("baseline", {}) or {}
    baseline_present = bool(baseline)

    if baseline_present and not state.get("baseline_set_ts"):
        state["baseline_set_ts"] = state.get("last_run") or run_ts

    current_baseline = {
        "ports_public_sigs": ports_public_sigs,
        "users": users,
        "watch_hashes": keys,
        "cron": cron,
        "firewall": fw,
        "self_integrity": self_i,
        "packages": {"hash": pkgs.get("hash", ""), "count": pkgs.get("count", 0), "map": pkgs.get("map", {})},
    }

    # --- first run: initialize baseline
    if not baseline:
        state["version"] = VERSION
        state["baseline"] = current_baseline
        state["auth_offset"] = new_auth_offset
        state["last_run"] = run_ts
        if not state.get("baseline_set_ts"):
            state["baseline_set_ts"] = run_ts
        save_json(STATE_FILE, state)

        report = {
            "ts": run_ts,
            "host": host,
            "version": VERSION,
            "baseline_initialized": True,
            "baseline_present": True,
            "baseline_set_ts": state.get("baseline_set_ts", ""),
            "baseline_last_accepted_ts": state.get("baseline_last_accepted_ts", ""),
            "auth": sec,
            "new_ssh_accepts": [],
            "ports_public": ports_public[:50],
            "ports_local": ports_local[:50],
            "public_ports_count": len(ports_public),
            "firewall": fw,
            "self_integrity": self_i,
            "packages": {"hash": pkgs.get("hash", ""), "count": pkgs.get("count", 0)},
            "threat": threat_payload,
            "vitals": vitals_payload,
            "alerts": alerts_payload(ioc_alerts),
        }

        save_json(LAST_REPORT_FILE, report)
        save_json(BASELINE_FILE, {"ts": run_ts, "host": host, "version": VERSION, "baseline": current_baseline})
        if fmt == "text":
            print(build_text_output(report), end="")
        else:
            print(json.dumps(report, indent=2))
        return

    # ---------------------------
    # Build alerts
    # ---------------------------

    auth_alerts: List[Dict[str, Any]] = []
    baseline_alerts: List[Dict[str, Any]] = []
    new_accepts: List[Dict[str, Any]] = []

    # --- auth-based alerting
    if sec["ssh_failed_password"] >= max_failed_before_alert or sec["ssh_invalid_user"] >= max_invalid_user_before_alert:
        auth_alerts.append(make_alert(
            title="SSH noise spike",
            detail=f"Failed password: {sec['ssh_failed_password']}, Invalid user: {sec['ssh_invalid_user']}",
            severity="warn",
            code="ssh_noise_spike",
        ))

    if ssh_new_accept_alert and sec.get("ssh_accepted"):
        suppress = bool(auth_rewound)
        new_accepts, new_accept_alerts = detect_new_ssh_accepts(
            state=state,
            accepts=sec.get("ssh_accepted", []),
            now_e=run_e,
            ttl_days=ssh_seen_ttl_days,
            suppress=suppress
        )
        auth_alerts.extend(new_accept_alerts)

    # --- public ports changed
    old_sigs = (baseline.get("ports_public_sigs") or [])
    old_set = set(old_sigs)
    new_set = set(ports_public_sigs)

    port_change_explain: Dict[str, Any] = {}

    if old_set != new_set:
        added = sorted(list(new_set - old_set))
        removed = sorted(list(old_set - new_set))

        sig_to_port = {p.get("sig", ""): p for p in ports_public if p.get("sig")}
        sig_to_raw = {s: (sig_to_port.get(s, {}) or {}).get("raw", "") for s in added}

        detail_lines = []
        if added:
            detail_lines.append("Added public listeners:")
            for s in added[:20]:
                p = sig_to_port.get(s, {}) or {}
                raw = sig_to_raw.get(s, "")
                pid = int(p.get("pid", 0) or 0)
                ex = proc_explain(pid) if pid else {"pid": pid}

                port_change_explain[s] = {
                    "sig": s,
                    "raw": raw,
                    "pid": ex.get("pid", 0),
                    "exe": ex.get("exe", ""),
                    "unit": ex.get("unit", ""),
                    "cmdline": clamp(ex.get("cmdline", ""), 240),
                }

                unit = ex.get("unit", "") or ""
                exe = ex.get("exe", "") or ""
                extra = []
                if unit:
                    extra.append(f"unit={unit}")
                if exe:
                    extra.append(f"exe={exe}")
                if pid:
                    extra.append(f"pid={pid}")
                extra_s = (" (" + ", ".join(extra) + ")") if extra else ""
                detail_lines.append(f"+ {s}{extra_s}" + (f"\n  {raw}" if raw else ""))

        if removed:
            detail_lines.append("Removed public listeners:")
            for s in removed[:20]:
                detail_lines.append(f"- {s}")

        baseline_alerts.append(make_alert(
            title="Public listening ports changed",
            detail="\n".join(detail_lines) or "Public listeners differ from baseline.",
            severity="warn",
            code="public_ports_changed",
        ))

    # --- users changed
    old_users = baseline.get("users", [])
    if old_users and old_users != users:
        old_set_u = {(u["user"], u["uid"], u["shell"]) for u in old_users}
        new_set_u = {(u["user"], u["uid"], u["shell"]) for u in users}
        added_u = sorted(list(new_set_u - old_set_u))
        removed_u = sorted(list(old_set_u - new_set_u))
        msg = []
        if added_u:
            msg.append("Added: " + ", ".join([f"{u[0]}(uid={u[1]})" for u in added_u]))
        if removed_u:
            msg.append("Removed: " + ", ".join([f"{u[0]}(uid={u[1]})" for u in removed_u]))
        if msg:
            baseline_alerts.append(make_alert(
                title="User list changed",
                detail="\n".join(msg),
                severity="warn",
                code="user_list_changed",
            ))

    # --- watched files changed
    old_keys = baseline.get("watch_hashes", {})
    if old_keys is not None and old_keys != keys:
        a, r, c = diff_hash_dict(old_keys, keys)
        msg = []
        if a:
            msg.append("Added watch paths:\n" + "\n".join(a))
        if r:
            msg.append("Removed watch paths:\n" + "\n".join(r))
        if c:
            msg.append("Changed:\n" + "\n".join(c))
        if msg:
            baseline_alerts.append(make_alert(
                title="Watched files changed",
                detail="\n".join(msg),
                severity="warn",
                code="watched_files_changed",
            ))

    # --- cron changed
    old_cron = baseline.get("cron", {})
    if old_cron is not None and old_cron != cron:
        a, r, c = diff_hash_dict(old_cron, cron)
        msg = []
        if a:
            msg.append("Added cron targets:\n" + "\n".join(a))
        if r:
            msg.append("Removed cron targets:\n" + "\n".join(r))
        if c:
            msg.append("Changed:\n" + "\n".join(c))
        baseline_alerts.append(make_alert(
            title="Cron changed",
            detail="\n".join(msg) if msg else "Cron hashes differ from baseline.",
            severity="warn",
            code="cron_changed",
        ))

    # --- firewall changed
    old_fw = baseline.get("firewall", {})
    firewall_changed = False
    if old_fw is not None and old_fw != fw:
        firewall_changed = True
        a, r, c = diff_hash_dict(old_fw, fw)
        msg = []
        if a:
            msg.append("Added firewall keys: " + ", ".join(a))
        if r:
            msg.append("Removed firewall keys: " + ", ".join(r))
        if c:
            msg.append("Changed firewall keys: " + ", ".join(c))
        baseline_alerts.append(make_alert(
            title="Firewall changed",
            detail="\n".join(msg) if msg else "Firewall hashes differ from baseline.",
            severity="warn",
            code="firewall_changed",
        ))

    if firewall_changed:
        capture_firewall_forensics(old_fw or {}, fw or {}, run_ts=run_ts)

    # --- self-integrity changed (treat missing old baseline as change)
    old_self = (baseline.get("self_integrity") or {})
    if old_self != self_i:
        a, r, c = diff_hash_dict(old_self, self_i)
        msg = []
        if c:
            msg.append("Changed:\n" + "\n".join(c))
        if a:
            msg.append("Added:\n" + "\n".join(a))
        if r:
            msg.append("Removed:\n" + "\n".join(r))
        baseline_alerts.append(make_alert(
            title="Self integrity changed",
            detail="\n".join(msg) if msg else "Self hashes differ from baseline.",
            severity="critical",
            code="self_integrity_changed",
        ))

    # --- packages changed (treat missing old baseline as change)
    old_pkgs = (baseline.get("packages") or {})
    old_pkg_hash = old_pkgs.get("hash", "") if isinstance(old_pkgs, dict) else ""
    old_pkg_map = old_pkgs.get("map", {}) if isinstance(old_pkgs, dict) else {}
    new_pkg_hash = pkgs.get("hash", "")

    if new_pkg_hash and old_pkg_hash != new_pkg_hash:
        d = packages_diff(old_pkg_map, pkgs.get("map", {}), limit=int(cfg.get("packages_diff_limit", 60)))
        detail = d.get("detail") or "dpkg package set changed."
        if not old_pkg_hash:
            detail = "Packages baseline missing; seeding package baseline.\n" + detail
        baseline_alerts.append(make_alert(
            title="Packages changed",
            detail=detail,
            severity="warn",
            code="packages_changed",
        ))

    # --- sshd config changed => forensics
    ssh_paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"]
    ssh_changed = False
    for sp in ssh_paths:
        if (baseline.get("watch_hashes", {}) or {}).get(sp, "") != keys.get(sp, ""):
            ssh_changed = True
            break
    if ssh_changed:
        capture_sshd_forensics(run_ts=run_ts)

    alerts = auth_alerts + baseline_alerts + ioc_alerts

    # ---------------------------
    # Accept baseline on demand (ALWAYS accept when flag exists)
    # ---------------------------

    baseline_accept_skipped = False
    baseline_accept_skipped_reason = ""

    if ACCEPT_BASELINE_FLAG.exists():
        try:
            ACCEPT_BASELINE_FLAG.unlink()
        except Exception:
            pass

        # Always accept current baseline snapshot.
        state["version"] = VERSION
        state["baseline"] = current_baseline
        state["auth_offset"] = new_auth_offset
        state["last_run"] = run_ts
        if not state.get("baseline_set_ts"):
            state["baseline_set_ts"] = run_ts
        state["baseline_last_accepted_ts"] = run_ts
        save_json(STATE_FILE, state)

        save_json(BASELINE_FILE, {"ts": run_ts, "host": host, "version": VERSION, "baseline": current_baseline})

        report = {
            "ts": run_ts,
            "host": host,
            "version": VERSION,
            "baseline_accepted": True,
            "baseline_present": True,
            "baseline_set_ts": state.get("baseline_set_ts", ""),
            "baseline_last_accepted_ts": state.get("baseline_last_accepted_ts", ""),
            "baseline_accept_skipped": baseline_accept_skipped,
            "baseline_accept_skipped_reason": baseline_accept_skipped_reason,
            "auth": sec,
            "new_ssh_accepts": new_accepts,
            "ports_public": ports_public[:50],
            "ports_local": ports_local[:50],
            "public_ports_count": len(ports_public),
            "port_change_explain": port_change_explain,
            "firewall": fw,
            "self_integrity": self_i,
            "packages": {"hash": pkgs.get("hash", ""), "count": pkgs.get("count", 0)},
            "threat": threat_payload,
            "vitals": vitals_payload,
            # After accepting, suppress baseline alerts; keep auth + IOC alerts.
            "alerts": alerts_payload(auth_alerts + ioc_alerts),
        }

        save_json(LAST_REPORT_FILE, report)

        diff_art = {
            "ts": run_ts,
            "host": host,
            "version": VERSION,
            "accepted_baseline": True,
            "baseline_diffs": alerts_payload(baseline_alerts),
            "threat": threat_payload,
            "port_change_explain": port_change_explain,
        }
        save_json(DIFF_FILE, diff_art)

        if fmt == "text":
            print(build_text_output(report), end="")
        else:
            print(json.dumps(report, indent=2))

        if webhook and (auth_alerts or ioc_alerts):
            title = f"VPS Sentry ALERT ({host})"
            body_lines = []
            sent_any = False

            for a in (auth_alerts + ioc_alerts)[:6]:
                t = alert_title(a)
                d = alert_detail(a)
                if should_send_webhook_for_alert(t, state, webhook_cooldown_sec):
                    body_lines.append(f"• {t}: {d}")
                    mark_webhook_sent(t, state)
                    sent_any = True

            if sent_any:
                if sec.get("ssh_accepted"):
                    body_lines.append("\nRecent SSH accepted:")
                    for a in sec["ssh_accepted"][-5:]:
                        body_lines.append(f"- {a['user']} from {a['ip']}")

                post_webhook(webhook, title, clamp("\n".join(body_lines), 1800))
                save_json(STATE_FILE, state)

        return

    # ---------------------------
    # Report
    # ---------------------------

    report = {
        "ts": run_ts,
        "host": host,
        "version": VERSION,
        "baseline_present": True,
        "baseline_set_ts": state.get("baseline_set_ts", ""),
        "baseline_last_accepted_ts": state.get("baseline_last_accepted_ts", ""),
        "baseline_accept_skipped": baseline_accept_skipped,
        "baseline_accept_skipped_reason": baseline_accept_skipped_reason,
        "auth": sec,
        "new_ssh_accepts": new_accepts,
        "ports_public": ports_public[:50],
        "ports_local": ports_local[:50],
        "public_ports_count": len(ports_public),
        "port_change_explain": port_change_explain,
        "firewall": fw,
        "self_integrity": self_i,
        "packages": {"hash": pkgs.get("hash", ""), "count": pkgs.get("count", 0)},
        "threat": threat_payload,
        "vitals": vitals_payload,
        "alerts": alerts_payload(alerts),
    }

    save_json(LAST_REPORT_FILE, report)

    if alerts:
        diff_art = {
            "ts": run_ts,
            "host": host,
            "version": VERSION,
            "alerts": alerts_payload(alerts),
            "threat": threat_payload,
            "port_change_explain": port_change_explain,
            "new_ssh_accepts": new_accepts,
        }
        save_json(DIFF_FILE, diff_art)
    else:
        try:
            if DIFF_FILE.exists():
                DIFF_FILE.unlink()
        except Exception:
            pass

    if quiet_no_alerts and not alerts:
        summary = {
            "ts": report["ts"],
            "host": report["host"],
            "version": VERSION,
            "baseline_present": True,
            "baseline_last_accepted_ts": report.get("baseline_last_accepted_ts", ""),
            "ssh_failed_password": sec["ssh_failed_password"],
            "ssh_invalid_user": sec["ssh_invalid_user"],
            "public_ports": len(ports_public),
            "alerts": 0,
        }
        if fmt == "text":
            if log_level != "quiet":
                print(build_text_output(report), end="")
        else:
            if log_level != "quiet":
                print(json.dumps(summary, indent=2))
    else:
        if print_full_on_alerts:
            if fmt == "text":
                print(build_text_output(report), end="")
            else:
                print(json.dumps(report, indent=2))
        else:
            summary = {
                "ts": report["ts"],
                "host": report["host"],
                "version": VERSION,
                "baseline_present": True,
                "baseline_last_accepted_ts": report.get("baseline_last_accepted_ts", ""),
                "ssh_failed_password": sec["ssh_failed_password"],
                "ssh_invalid_user": sec["ssh_invalid_user"],
                "public_ports": len(ports_public),
                "alerts": len(alerts),
            }
            if fmt == "text":
                print(build_text_output(report), end="")
            else:
                print(json.dumps(summary, indent=2))

    # --- webhook on alerts (with cooldown)
    if webhook and alerts:
        title = f"VPS Sentry ALERT ({host})"
        body_lines = []
        sent_any = False

        for a in alerts[:6]:
            t = alert_title(a)
            d = alert_detail(a)
            if should_send_webhook_for_alert(t, state, webhook_cooldown_sec):
                body_lines.append(f"• {t}: {d}")
                mark_webhook_sent(t, state)
                sent_any = True

        if sent_any:
            if sec.get("ssh_accepted"):
                body_lines.append("\nRecent SSH accepted:")
                for a in sec["ssh_accepted"][-5:]:
                    body_lines.append(f"- {a['user']} from {a['ip']}")

            post_webhook(webhook, title, clamp("\n".join(body_lines), 1800))

    # --- update state
    state["version"] = VERSION
    state["auth_offset"] = new_auth_offset
    state["last_run"] = run_ts
    save_json(STATE_FILE, state)


if __name__ == "__main__":
    main()
