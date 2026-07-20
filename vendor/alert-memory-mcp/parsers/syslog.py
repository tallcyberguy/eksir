"""
Syslog parser (RFC 3164 / RFC 5424 and common Linux variants).

Handles formats commonly seen in Wazuh /var/log/messages forwarding:

  RFC 3164 (no priority):
    Apr 22 20:39:19 HOSTNAME process[pid]: message

  RFC 3164 (with priority):
    <14>Apr 22 20:39:19 HOSTNAME process[pid]: message

  RFC 5424:
    <14>1 2026-04-22T20:39:19+03:00 HOSTNAME app - - - message

Sub-format detection and enrichment for:
  - [HIST] bash history entries  → username, file_path, command
  - sudo                         → username, command
  - sshd Accepted/Failed         → username, src_ip
  - useradd / groupadd           → username, threat_category=persistence
  - kernel / audit               → generic
"""

import re
from datetime import datetime
from typing import Optional, Union
from normalizer import NormalizedAlert, infer_category


# ── RFC 3164 timestamp: "Apr  2 08:05:01" or "Apr 22 20:39:19"
RFC3164_TS_RE = re.compile(
    r'^(?:<\d+>)?'                                   # optional <priority>
    r'((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    r'\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'             # timestamp
    r'\s+(\S+)'                                       # hostname
    r'\s+([^:\[]+?)(?:\[(\d+)\])?:\s*(.*)',          # process[pid]: message
    re.DOTALL,
)

# RFC 5424: "<pri>version ISO-timestamp hostname app procid msgid sd msg"
RFC5424_TS_RE = re.compile(
    r'^<\d+>\d+\s+'
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)'
    r'\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)',
    re.DOTALL,
)

# Bash [HIST] format produced by Wazuh bash history rules:
#   hostname [HIST] : :/path/to/dir :command args
HIST_RE = re.compile(
    r'\[HIST\]\s*:+\s*:?(.*?)\s*:(.*)',
    re.DOTALL,
)

# SSH: "Accepted/Failed password for USER from IP port PORT"
SSH_AUTH_RE = re.compile(
    r'(Accepted|Failed)\s+\S+\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)',
)

# sudo: "user : TTY=... ; PWD=/path ; USER=root ; COMMAND=/bin/cmd"
SUDO_RE = re.compile(
    r'(\S+)\s*:\s+TTY=\S+\s*;\s+PWD=(\S+)\s*;\s+USER=(\S+)\s*;\s+COMMAND=(.*)',
)

# useradd / userdel / groupadd
USERADD_RE = re.compile(r'(useradd|userdel|usermod|groupadd|groupdel)\[?\d*\]?:?\s+(.*)')

# CVE reference anywhere in message
CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# IP address in message
IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def _parse_rfc3164_ts(ts_str: str) -> Optional[str]:
    """Convert 'Apr 22 20:39:19' to ISO string (current year assumed)."""
    try:
        parts = ts_str.split()
        month = MONTHS.get(parts[0], 1)
        day = int(parts[1])
        time_parts = parts[2].split(':')
        dt = datetime(
            datetime.now().year, month, day,
            int(time_parts[0]), int(time_parts[1]), int(time_parts[2]),
        )
        return dt.isoformat()
    except (IndexError, ValueError):
        return ts_str


def _parse_hist(message: str, alert: NormalizedAlert) -> NormalizedAlert:
    """Extract path and command from [HIST] bash history messages."""
    m = HIST_RE.search(message)
    if m:
        path = m.group(1).strip()
        command = m.group(2).strip()
        if path:
            alert.file_path = path
        # Store full command in rule_name context if it adds info
        alert.threat_category = infer_category(command)
    return alert


def _parse_ssh(message: str, alert: NormalizedAlert) -> NormalizedAlert:
    """Extract auth result, username, src_ip from sshd messages."""
    m = SSH_AUTH_RE.search(message)
    if m:
        result, user, ip = m.group(1), m.group(2), m.group(3)
        alert.username = user
        alert.src_ip = ip
        if result == "Failed":
            alert.threat_category = "brute_force"
        return alert
    return alert


def _parse_sudo(message: str, alert: NormalizedAlert) -> NormalizedAlert:
    """Extract username and command from sudo log entries."""
    m = SUDO_RE.search(message)
    if m:
        alert.username = m.group(1)
        alert.file_path = m.group(2)       # PWD
        command = m.group(4).strip()
        alert.threat_category = infer_category(f"sudo {command}")
    return alert


def _parse_useradd(message: str, alert: NormalizedAlert) -> NormalizedAlert:
    """Flag account creation/deletion as persistence."""
    m = USERADD_RE.search(message)
    if m:
        alert.threat_category = "persistence"
    return alert


def _extract_fallback_ip(message: str) -> Optional[str]:
    """Last-resort: grab first public IP found in message."""
    for match in IP_RE.finditer(message):
        ip = match.group(1)
        parts = ip.split('.')
        first = int(parts[0])
        # Skip private / loopback / link-local
        if first in (10, 127) or ip.startswith('192.168.') or ip.startswith('169.254.'):
            continue
        if first == 172 and 16 <= int(parts[1]) <= 31:
            continue
        return ip
    return None


def parse(raw: Union[str, dict], customer: str = None) -> NormalizedAlert:
    """
    Parse a syslog line (RFC 3164 / RFC 5424) into NormalizedAlert.

    Args:
        raw:      Log line as string, or envelope dict with 'raw_alert' key.
        customer: Customer identifier.
    """
    if isinstance(raw, dict) and "raw_alert" in raw:
        line = raw["raw_alert"]
        envelope = raw
    else:
        line = raw if isinstance(raw, str) else str(raw)
        envelope = {}

    alert = NormalizedAlert()
    alert.source_product = "syslog"
    alert.customer = customer or envelope.get("customer")
    alert.raw = line

    # ── Try RFC 5424 first (has explicit ISO timestamp)
    m5 = RFC5424_TS_RE.match(line)
    if m5:
        alert.timestamp = m5.group(1)
        alert.hostname = m5.group(2)
        process = m5.group(3)
        message = m5.group(4).strip()
    else:
        # ── Try RFC 3164
        m3 = RFC3164_TS_RE.match(line.strip())
        if m3:
            alert.timestamp = _parse_rfc3164_ts(m3.group(1))
            alert.hostname = m3.group(2)
            process = m3.group(3).strip()
            message = m3.group(5).strip()
        else:
            # Unparseable — store raw, set minimal fields
            alert.rule_name = envelope.get("rule_name", "Syslog alert")
            alert.threat_category = infer_category(line)
            return alert.finalize()

    # ── Rule name: prefer envelope, fall back to process + first line of message
    if envelope.get("rule_name"):
        alert.rule_name = envelope["rule_name"]
    else:
        first_line = message.split('\n')[0][:120]
        alert.rule_name = f"{process}: {first_line}" if process else first_line

    # ── Username: process field is often the acting user in audit logs
    # Only use as username if it's not a daemon name (no 'd' suffix heuristic is fragile,
    # so we whitelist common daemon names to skip)
    DAEMON_NAMES = {
        'sshd', 'sudo', 'su', 'cron', 'kernel', 'systemd', 'auditd',
        'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel',
        'ansible', 'ansible-playbook', 'python', 'python3',
    }
    if process and process.lower() not in DAEMON_NAMES:
        alert.username = process

    # ── Sub-format routing
    msg_lower = message.lower()

    proc_lower = (process or '').lower()

    if '[hist]' in msg_lower:
        alert = _parse_hist(message, alert)

    elif 'sshd' in proc_lower:
        alert = _parse_ssh(message, alert)
        alert.username = alert.username if SSH_AUTH_RE.search(message) else None

    elif 'sudo' in proc_lower or SUDO_RE.search(message):
        alert = _parse_sudo(message, alert)

    elif any(kw in proc_lower for kw in ('useradd', 'userdel', 'usermod', 'groupadd', 'groupdel')) \
            or any(kw in msg_lower for kw in ('useradd', 'userdel', 'usermod', 'groupadd')):
        alert = _parse_useradd(message, alert)
        alert.threat_category = 'persistence'

    # ── CVE extraction
    cve_m = CVE_RE.search(message)
    if cve_m:
        alert.cve = cve_m.group(0).upper()

    # ── Fallback src_ip if not set
    if not alert.src_ip:
        alert.src_ip = _extract_fallback_ip(message)

    # ── Threat category fallback
    if alert.threat_category == "unknown":
        alert.threat_category = infer_category(f"{alert.rule_name} {message}")

    return alert.finalize()
