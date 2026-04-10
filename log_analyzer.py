#!/usr/bin/env python3
"""
================================
Log Analyzer & Alerting System
================================
Analyzes SSH, Apache/Nginx and syslog files for suspicious patterns.
Generates structured alerts and exportable reports.

================================
Author  : Lowingx
License : MIT
================================
"""

import re
import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class Alert:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str          # brute_force / scan / anomaly / …
    source_ip: str
    description: str
    evidence: list         # raw log lines that triggered the alert
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    count: int = 1

    def __str__(self) -> str:
        sev_colors = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[31m",
            "MEDIUM":   "\033[33m",
            "LOW":      "\033[34m",
            "INFO":     "\033[37m",
        }
        reset = "\033[0m"
        color = sev_colors.get(self.severity, "")
        return (
            f"{color}[{self.severity}]{reset} "
            f"{self.timestamp}  {self.category}  "
            f"src={self.source_ip}  hits={self.count}\n"
            f"  -> {self.description}"
        )


# ─────────────────────────────────────────────
#  Regex patterns
# ─────────────────────────────────────────────

RE_SSH_FAILED   = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Failed password.*?from (?P<ip>[\d.]+)"
)
RE_SSH_ACCEPTED = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Accepted password.*?from (?P<ip>[\d.]+)"
)
RE_SSH_INVALID  = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Apache / Nginx access.log  (Common Log Format)
RE_HTTP = re.compile(
    r'(?P<ip>[\d.]+) - - \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)


# ─────────────────────────────────────────────
#  Detection thresholds  (tunable)
# ─────────────────────────────────────────────

THRESHOLD_BRUTE_FORCE_SSH  = 5
THRESHOLD_HTTP_404         = 20
THRESHOLD_HTTP_SCAN        = 50
THRESHOLD_INVALID_USER     = 3


# ─────────────────────────────────────────────
#  Severity ordering
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ─────────────────────────────────────────────
#  Log type detection
# ─────────────────────────────────────────────

def detect_log_type(path: Path) -> str:
    """Auto-detect log type by filename and first lines."""
    name = path.name.lower()
    if any(k in name for k in ("auth", "secure", "sshd")):
        return "ssh"
    if any(k in name for k in ("access", "apache", "nginx", "http")):
        return "http"
    # Peek at content
    try:
        first_lines = path.read_text(errors="replace").splitlines()[:5]
        sample = " ".join(first_lines)
        if "Failed password" in sample or "sshd" in sample:
            return "ssh"
        if "HTTP/" in sample:
            return "http"
    except OSError:
        pass
    return "generic"


# ─────────────────────────────────────────────
#  Parsers
# ─────────────────────────────────────────────

def parse_ssh(lines: list) -> dict:
    """Extract per-IP event counts from SSH/auth logs."""
    failed   = defaultdict(list)
    accepted = defaultdict(list)
    invalid  = defaultdict(set)

    for line in lines:
        m = RE_SSH_FAILED.search(line)
        if m:
            failed[m.group("ip")].append(line.strip())
            continue
        m = RE_SSH_ACCEPTED.search(line)
        if m:
            accepted[m.group("ip")].append(line.strip())
            continue
        m = RE_SSH_INVALID.search(line)
        if m:
            invalid[m.group("ip")].add(m.group("user"))

    return {"failed": failed, "accepted": accepted, "invalid": invalid}


def parse_http(lines: list) -> dict:
    """Extract per-IP HTTP statistics."""
    requests  = defaultdict(list)
    errors404 = defaultdict(list)
    paths     = defaultdict(set)
    methods   = defaultdict(set)

    for line in lines:
        m = RE_HTTP.search(line)
        if not m:
            continue
        ip     = m.group("ip")
        status = m.group("status")
        path   = m.group("path")
        method = m.group("method")

        requests[ip].append(line.strip())
        paths[ip].add(path)
        methods[ip].add(method)

        if status == "404":
            errors404[ip].append(line.strip())

    return {
        "requests":  requests,
        "errors404": errors404,
        "paths":     paths,
        "methods":   methods,
    }


# ─────────────────────────────────────────────
#  Detection logic
# ─────────────────────────────────────────────

def detect_ssh_threats(data: dict) -> list:
    alerts = []
    failed   = data["failed"]
    accepted = data["accepted"]
    invalid  = data["invalid"]

    # Brute force
    for ip, lines in failed.items():
        if len(lines) >= THRESHOLD_BRUTE_FORCE_SSH:
            severity = "CRITICAL" if len(lines) >= 20 else "HIGH"
            alerts.append(Alert(
                severity=severity,
                category="brute_force_ssh",
                source_ip=ip,
                description=(
                    f"SSH brute-force detected: {len(lines)} failed login attempts."
                ),
                evidence=lines[:5],
                count=len(lines),
            ))

    # User enumeration
    for ip, users in invalid.items():
        if len(users) >= THRESHOLD_INVALID_USER:
            alerts.append(Alert(
                severity="HIGH",
                category="user_enumeration_ssh",
                source_ip=ip,
                description=(
                    f"SSH user enumeration: {len(users)} distinct invalid usernames tried."
                ),
                evidence=[f"Users tried: {', '.join(list(users)[:10])}"],
                count=len(users),
            ))

    # Successful login after failures — possible credential stuffing
    for ip in accepted:
        if ip in failed and len(failed[ip]) >= 3:
            alerts.append(Alert(
                severity="CRITICAL",
                category="brute_force_success_ssh",
                source_ip=ip,
                description=(
                    f"SSH login SUCCEEDED after {len(failed[ip])} failures — "
                    "possible credential stuffing."
                ),
                evidence=accepted[ip][:3],
                count=len(accepted[ip]),
            ))

    return alerts


def detect_http_threats(data: dict) -> list:
    alerts = []
    requests  = data["requests"]
    errors404 = data["errors404"]
    paths     = data["paths"]
    methods   = data["methods"]

    # Directory scanning
    for ip, lines in errors404.items():
        if len(lines) >= THRESHOLD_HTTP_404:
            alerts.append(Alert(
                severity="HIGH",
                category="directory_scan_http",
                source_ip=ip,
                description=(
                    f"Possible directory scan: {len(lines)} HTTP 404 errors."
                ),
                evidence=lines[:5],
                count=len(lines),
            ))

    # High request volume
    for ip, lines in requests.items():
        if len(lines) >= THRESHOLD_HTTP_SCAN:
            alerts.append(Alert(
                severity="MEDIUM",
                category="high_request_volume",
                source_ip=ip,
                description=(
                    f"High HTTP request volume: {len(lines)} requests. "
                    f"Unique paths: {len(paths[ip])}."
                ),
                evidence=lines[:3],
                count=len(lines),
            ))

    # Suspicious HTTP methods
    sus_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS"}
    for ip, used in methods.items():
        found = sus_methods & used
        if found:
            alerts.append(Alert(
                severity="MEDIUM",
                category="suspicious_http_method",
                source_ip=ip,
                description=(
                    f"Suspicious HTTP methods used: {', '.join(found)}."
                ),
                evidence=[f"Methods from {ip}: {', '.join(used)}"],
                count=len(found),
            ))

    return alerts


# ─────────────────────────────────────────────
#  Report generation
# ─────────────────────────────────────────────

def generate_report(alerts: list, fmt: str, out: Optional[Path]) -> None:
    alerts_sorted = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))

    if fmt == "text":
        lines = [
            "=" * 60,
            " LOG ANALYZER -- ALERT REPORT",
            f" Generated : {datetime.now().isoformat()}",
            f" Total alerts : {len(alerts_sorted)}",
            "=" * 60,
            "",
        ]
        counts = Counter(a.severity for a in alerts_sorted)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts[sev]:
                lines.append(f"  {sev:<10} {counts[sev]}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("")

        for alert in alerts_sorted:
            lines.append(str(alert))
            if alert.evidence:
                lines.append("  Evidence:")
                for ev in alert.evidence[:3]:
                    lines.append(f"    {ev}")
            lines.append("")

        content = "\n".join(lines)

    elif fmt == "json":
        content = json.dumps(
            [asdict(a) for a in alerts_sorted], indent=2, ensure_ascii=False
        )

    elif fmt == "markdown":
        lines = [
            "# Log Analyzer Report",
            "",
            f"**Generated:** {datetime.now().isoformat()}  ",
            f"**Total Alerts:** {len(alerts_sorted)}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        counts = Counter(a.severity for a in alerts_sorted)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts[sev]:
                lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("")
        lines.append("---")
        lines.append("")
        for alert in alerts_sorted:
            lines.append(f"## [{alert.severity}] {alert.category}")
            lines.append(f"- **Source IP:** `{alert.source_ip}`")
            lines.append(f"- **Time:** {alert.timestamp}")
            lines.append(f"- **Hits:** {alert.count}")
            lines.append(f"- **Description:** {alert.description}")
            if alert.evidence:
                lines.append("- **Evidence:**")
                for ev in alert.evidence[:3]:
                    lines.append(f"  ```\n  {ev}\n  ```")
            lines.append("")
        content = "\n".join(lines)

    else:
        print(f"Unknown format: {fmt}", file=sys.stderr)
        return

    if out:
        out.write_text(content, encoding="utf-8")
        print(f"[+] Report saved -> {out}")
    else:
        print(content)


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Lowingx Log Analyzer -- detect threats in SSH and HTTP logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py auth.log
  python log_analyzer.py /var/log/apache2/access.log --format markdown --output report.md
  python log_analyzer.py auth.log --type ssh --format json --output alerts.json
        """,
    )
    p.add_argument("logs", nargs="+", type=Path, help="Log file(s) to analyze")
    p.add_argument(
        "--type",
        choices=["ssh", "http", "syslog", "auto"],
        default="auto",
        help="Log type (default: auto-detect)",
    )
    p.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Save report to file instead of stdout",
    )
    p.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to include in report",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and progress messages",
    )
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.quiet:
        print("\n  Log Analyzer & Alerting System")
        print("  Blue Team Portfolio | github.com/Lowingx/log-analyzer\n")

    all_alerts = []

    for log_path in args.logs:
        if not log_path.exists():
            print(f"[!] File not found: {log_path}", file=sys.stderr)
            continue

        log_type = args.type if args.type != "auto" else detect_log_type(log_path)

        if not args.quiet:
            print(f"[*] Analyzing {log_path}  (type={log_type})")

        lines = log_path.read_text(errors="replace").splitlines()

        if log_type == "ssh":
            data   = parse_ssh(lines)
            alerts = detect_ssh_threats(data)
        elif log_type == "http":
            data   = parse_http(lines)
            alerts = detect_http_threats(data)
        else:
            if not args.quiet:
                print("    -> Generic/syslog: basic anomaly detection only.")
            alerts = []

        if not args.quiet:
            print(f"    -> {len(lines):,} lines processed -- {len(alerts)} alert(s) generated.")

        all_alerts.extend(alerts)

    # Filter by minimum severity
    min_idx  = SEVERITY_ORDER.get(args.min_severity, 9)
    filtered = [a for a in all_alerts if SEVERITY_ORDER.get(a.severity, 9) <= min_idx]

    if not filtered:
        print("\n[OK] No alerts above minimum severity threshold. Log looks clean.\n")
        return

    print(f"\n[!] {len(filtered)} alert(s) to report.\n")
    generate_report(filtered, args.format, args.output)


if __name__ == "__main__":
    main()
