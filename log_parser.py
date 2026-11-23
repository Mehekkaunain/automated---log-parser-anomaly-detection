"""
=============================================================================
Project: Automated Log Parser for Anomalous Login Detection
File: log_parser.py
Description: A beginner-friendly Python script that uses regular expressions (regex)
             to parse simulated authentication logs, aggregate metrics, and detect
             security anomalies (brute force, threat IPs, account takeovers, and injection).
Author: AI & Cybersecurity Workflow
=============================================================================
"""

import os
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter


# ---------------------------------------------------------------------------
# 1. REGEX PATTERNS DEFINITION
# ---------------------------------------------------------------------------
# This regular expression uses "Named Capture Groups" (?P<name>...) to make
# extracting specific pieces of log information simple and readable.
#
# Pattern breakdown:
#   ^                     : Start of the line
#   (?P<timestamp>...)   : Date and time formatted as YYYY-MM-DD HH:MM:SS
#   \s+-\s+IP:\s+        : Separator text for IP
#   (?P<ip>[\d\.]+)      : IPv4 address (digits separated by periods)
#   \s+-\s+USER:\s+      : Separator text for username
#   (?P<username>.*?)    : Username string (non-greedy match up to the next delimiter)
#   \s+-\s+STATUS:\s+    : Separator text for login status
#   (?P<status>SUCCESS|FAILED) : Login status enum
#   (?:\s+-\s+MSG:\s+(?P<message>.*))? : Optional message detail at the end
#   $                     : End of the line
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+-\s+"
    r"IP:\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+"
    r"USER:\s+(?P<username>.*?)\s+-\s+"
    r"STATUS:\s+(?P<status>SUCCESS|FAILED)"
    r"(?:\s+-\s+MSG:\s+(?P<message>.*))?$"
)

# Regex to detect invalid or suspicious username patterns:
# Valid usernames in typical systems are 3-30 characters long, containing
# only letters, numbers, underscores, dashes, or dots.
# Anything with SQL characters (' or --), HTML tags (<script>),
# directory traversal (..), or command separators (; | &) is flagged.
VALID_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")

# Specific signatures for injection attacks
INJECTION_SIGNATURES = [
    (re.compile(r"('|\bOR\b|--|/\*|\*/)", re.IGNORECASE), "Potential SQL Injection"),
    (re.compile(r"(<script>|javascript:|onerror=)", re.IGNORECASE), "Cross-Site Scripting (XSS) probe"),
    (re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE), "Directory Traversal probe"),
    (re.compile(r"(;|\||&|`|\$\()", re.IGNORECASE), "Command Injection delimiter"),
]

# Known Threat Intelligence Blacklist (Simulated)
SUSPICIOUS_IPS = {
    "203.0.113.195": "Known Botnet Command & Control (C2) node",
    "198.51.100.77": "High-risk anonymous Tor exit proxy",
}


# ---------------------------------------------------------------------------
# 2. LOG PARSING FUNCTIONS
# ---------------------------------------------------------------------------
def parse_log_line(line: str) -> dict | None:
    """
    Parses a single log line using regular expressions.
    Returns a dictionary of extracted fields, or None if the line does not match.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    # Convert timestamp string into a Python datetime object for easy time comparisons
    data["datetime"] = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
    return data


def load_logs(file_path: str) -> list[dict]:
    """
    Reads a log file line by line, parsing each line with regex.
    Returns a list of structured log dictionaries.
    """
    parsed_logs = []
    if not os.path.exists(file_path):
        print(f"[ERROR] Log file not found at: {file_path}")
        return parsed_logs

    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue  # Skip blank lines
            parsed = parse_log_line(line_str)
            if parsed:
                parsed["line_number"] = line_num
                parsed_logs.append(parsed)
            else:
                print(f"[WARNING] Unrecognized log format at line {line_num}: {line_str}")

    return parsed_logs


# ---------------------------------------------------------------------------
# 3. ANOMALY DETECTION MODULES
# ---------------------------------------------------------------------------
def detect_brute_force(logs: list[dict], threshold: int = 3, window_minutes: int = 5) -> list[dict]:
    """
    Anomaly 1: Detects more than `threshold` failed login attempts within `window_minutes`
    originating from the same IP address or targeting user accounts.
    Consolidates clusters to avoid duplicate overlapping alerts.
    """
    anomalies = []
    logs_by_ip = defaultdict(list)
    for log in logs:
        logs_by_ip[log["ip"]].append(log)

    time_window = timedelta(minutes=window_minutes)

    for ip, ip_logs in logs_by_ip.items():
        failed_logs = [entry for entry in ip_logs if entry["status"] == "FAILED"]
        if len(failed_logs) <= threshold:
            continue

        # Identify distinct clusters of rapid failures
        reported_until_index = -1
        for i in range(len(failed_logs)):
            if i < reported_until_index:
                continue

            window_failures = [
                entry for entry in failed_logs
                if 0 <= (entry["datetime"] - failed_logs[i]["datetime"]).total_seconds() <= time_window.total_seconds()
            ]
            if len(window_failures) > threshold:
                targeted_users = sorted(list({e["username"] for e in window_failures}))
                anomalies.append({
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "count": len(window_failures),
                    "targeted_users": targeted_users,
                    "first_attempt": window_failures[0]["timestamp"],
                    "last_attempt": window_failures[-1]["timestamp"],
                    "description": (
                        f"Detected {len(window_failures)} rapid failed login attempts from IP {ip} "
                        f"within {window_minutes} minutes targeting user(s): {', '.join(targeted_users)}."
                    ),
                })
                # Advance past this cluster to avoid redundant sub-window alerts
                reported_until_index = i + len(window_failures)

    return anomalies


def detect_suspicious_ips(logs: list[dict], watchlist: dict[str, str] = SUSPICIOUS_IPS) -> list[dict]:
    """
    Anomaly 2: Identifies any login attempt originating from a blacklisted or suspicious IP.
    """
    anomalies = []
    for log in logs:
        if log["ip"] in watchlist:
            anomalies.append({
                "type": "Suspicious IP Address",
                "ip": log["ip"],
                "username": log["username"],
                "status": log["status"],
                "timestamp": log["timestamp"],
                "threat_intel": watchlist[log["ip"]],
                "description": (
                    f"Login activity observed from blacklisted IP {log['ip']} "
                    f"({watchlist[log['ip']]}) for user '{log['username']}' with status {log['status']}."
                ),
            })
    return anomalies


def detect_repeated_failures_then_success(logs: list[dict], min_failures: int = 3) -> list[dict]:
    """
    Anomaly 3: Detects multiple failed attempts followed immediately by a SUCCESS.
    This pattern strongly indicates credential stuffing or account takeover.
    """
    anomalies = []
    # Track login sequence per (ip, username)
    grouped = defaultdict(list)
    for log in logs:
        key = (log["ip"], log["username"])
        grouped[key].append(log)

    for (ip, username), entries in grouped.items():
        consecutive_failures = 0
        failure_timestamps = []

        for entry in entries:
            if entry["status"] == "FAILED":
                consecutive_failures += 1
                failure_timestamps.append(entry["timestamp"])
            elif entry["status"] == "SUCCESS":
                if consecutive_failures >= min_failures:
                    anomalies.append({
                        "type": "Repeated Failures Followed by Success",
                        "ip": ip,
                        "username": username,
                        "failed_count": consecutive_failures,
                        "success_time": entry["timestamp"],
                        "first_fail_time": failure_timestamps[0],
                        "description": (
                            f"Account Takeover Alert: {consecutive_failures} failed login attempts for user "
                            f"'{username}' from IP {ip} followed immediately by a SUCCESS at {entry['timestamp']}."
                        ),
                    })
                # Reset counter after success
                consecutive_failures = 0
                failure_timestamps = []

    return anomalies


def detect_invalid_usernames(logs: list[dict]) -> list[dict]:
    """
    Anomaly 4: Identifies usernames with malicious injection payloads or illegal characters.
    """
    anomalies = []
    for log in logs:
        username = log["username"]
        threat_reasons = []

        # Check against injection signatures
        for pattern, label in INJECTION_SIGNATURES:
            if pattern.search(username):
                threat_reasons.append(label)

        # Check against valid username pattern if not already caught
        if not threat_reasons and not VALID_USERNAME_PATTERN.match(username):
            threat_reasons.append("Non-standard / illegal character sequence")

        if threat_reasons:
            anomalies.append({
                "type": "Invalid / Malicious Username Pattern",
                "ip": log["ip"],
                "username": username,
                "timestamp": log["timestamp"],
                "reasons": threat_reasons,
                "description": (
                    f"Malicious username probe '{username}' from IP {log['ip']} at {log['timestamp']}. "
                    f"Detected patterns: {', '.join(threat_reasons)}."
                ),
            })

    return anomalies


# ---------------------------------------------------------------------------
# 4. REPORT GENERATION
# ---------------------------------------------------------------------------
def generate_summary_report(
    logs: list[dict],
    brute_force_anomalies: list[dict],
    suspicious_ip_anomalies: list[dict],
    takeover_anomalies: list[dict],
    invalid_username_anomalies: list[dict],
    output_path: str = "anomaly_report.txt",
) -> str:
    """
    Aggregates findings, computes statistics, and generates a formatted text report.
    """
    total_logs = len(logs)
    success_count = sum(1 for log in logs if log["status"] == "SUCCESS")
    failed_count = sum(1 for log in logs if log["status"] == "FAILED")
    success_rate = (success_count / total_logs * 100) if total_logs > 0 else 0
    failure_rate = (failed_count / total_logs * 100) if total_logs > 0 else 0

    # Top IP addresses and usernames
    ip_counter = Counter(log["ip"] for log in logs)
    user_counter = Counter(log["username"] for log in logs)
    failed_ip_counter = Counter(log["ip"] for log in logs if log["status"] == "FAILED")

    total_anomalies = (
        len(brute_force_anomalies)
        + len(suspicious_ip_anomalies)
        + len(takeover_anomalies)
        + len(invalid_username_anomalies)
    )

    report_lines = []
    report_lines.append("=" * 78)
    report_lines.append("       AUTOMATED LOG PARSER - ANOMALOUS LOGIN DETECTION REPORT")
    report_lines.append(f"       Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 78)
    report_lines.append("")
    report_lines.append("1. EXECUTIVE SUMMARY")
    report_lines.append("-" * 78)
    report_lines.append(f"  Total Log Records Analyzed    : {total_logs}")
    report_lines.append(f"  Successful Logins             : {success_count} ({success_rate:.1f}%)")
    report_lines.append(f"  Failed Logins                 : {failed_count} ({failure_rate:.1f}%)")
    report_lines.append(f"  Total Security Anomalies Found: {total_anomalies}")
    report_lines.append("")
    report_lines.append("2. SECURITY ANOMALIES BREAKDOWN")
    report_lines.append("-" * 78)
    report_lines.append(f"  [A] Brute Force Incidents (>3 failures in window)    : {len(brute_force_anomalies)}")
    report_lines.append(f"  [B] Known Suspicious IP Contacts                     : {len(suspicious_ip_anomalies)}")
    report_lines.append(f"  [C] Account Takeovers (Repeated Fails -> Success)    : {len(takeover_anomalies)}")
    report_lines.append(f"  [D] Invalid / Malicious Username Probes              : {len(invalid_username_anomalies)}")
    report_lines.append("")

    report_lines.append("3. DETAILED ANOMALY FINDINGS")
    report_lines.append("-" * 78)

    # Section A
    report_lines.append(">>> [A] BRUTE FORCE ATTACKS:")
    if brute_force_anomalies:
        for idx, item in enumerate(brute_force_anomalies, 1):
            report_lines.append(f"  {idx}. Source IP    : {item['ip']}")
            report_lines.append(f"     Target User(s): {', '.join(item['targeted_users'])}")
            report_lines.append(f"     Failed Attempts: {item['count']}")
            report_lines.append(f"     Time Window   : {item['first_attempt']} to {item['last_attempt']}")
            report_lines.append(f"     Details       : {item['description']}")
            report_lines.append("")
    else:
        report_lines.append("  No brute force attacks detected.\n")

    # Section B
    report_lines.append(">>> [B] LOGINS FROM SUSPICIOUS / BLACKLISTED IPs:")
    if suspicious_ip_anomalies:
        for idx, item in enumerate(suspicious_ip_anomalies, 1):
            report_lines.append(f"  {idx}. Timestamp : {item['timestamp']}")
            report_lines.append(f"     IP Address: {item['ip']} ({item['threat_intel']})")
            report_lines.append(f"     User / Status: {item['username']} [{item['status']}]")
            report_lines.append(f"     Details   : {item['description']}")
            report_lines.append("")
    else:
        report_lines.append("  No logins from blacklisted IPs detected.\n")

    # Section C
    report_lines.append(">>> [C] ACCOUNT TAKEOVER / CREDENTIAL STUFFING (FAILS FOLLOWED BY SUCCESS):")
    if takeover_anomalies:
        for idx, item in enumerate(takeover_anomalies, 1):
            report_lines.append(f"  {idx}. Compromised Account: {item['username']}")
            report_lines.append(f"     Attacker IP        : {item['ip']}")
            report_lines.append(f"     Preceding Failures : {item['failed_count']}")
            report_lines.append(f"     Breach Timestamp   : {item['success_time']}")
            report_lines.append(f"     Details            : {item['description']}")
            report_lines.append("")
    else:
        report_lines.append("  No account takeover patterns detected.\n")

    # Section D
    report_lines.append(">>> [D] MALICIOUS / INJECTION USERNAME PROBES:")
    if invalid_username_anomalies:
        for idx, item in enumerate(invalid_username_anomalies, 1):
            report_lines.append(f"  {idx}. Timestamp: {item['timestamp']} | IP: {item['ip']}")
            report_lines.append(f"     Injected Value: {item['username']}")
            report_lines.append(f"     Threat Type   : {', '.join(item['reasons'])}")
            report_lines.append("")
    else:
        report_lines.append("  No invalid username patterns detected.\n")

    # Section 4: Top Statistics
    report_lines.append("4. TOP TRAFFIC STATISTICS")
    report_lines.append("-" * 78)
    report_lines.append("  Top 5 Source IP Addresses (Total Activity):")
    for ip, count in ip_counter.most_common(5):
        report_lines.append(f"    - {ip:18}: {count} requests")
    report_lines.append("")
    report_lines.append("  Top 5 IP Addresses with Failed Logins:")
    for ip, count in failed_ip_counter.most_common(5):
        report_lines.append(f"    - {ip:18}: {count} failures")
    report_lines.append("")
    report_lines.append("  Top 5 Most Frequent User Accounts:")
    for user, count in user_counter.most_common(5):
        report_lines.append(f"    - {user:18}: {count} attempts")
    report_lines.append("")
    report_lines.append("=" * 78)
    report_lines.append("                          END OF SECURITY REPORT")
    report_lines.append("=" * 78)

    report_text = "\n".join(report_lines)

    # Save to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return report_text


# ---------------------------------------------------------------------------
# 5. MAIN EXECUTION PIPELINE
# ---------------------------------------------------------------------------
def main():
    """
    Main driver function that coordinates loading, parsing, detecting,
    and outputting security anomaly reports.
    """
    # Determine base directory so the script can run from any working directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(script_dir, "sample_logs.txt")
    report_file_path = os.path.join(script_dir, "anomaly_report.txt")

    print("[*] Starting Automated Log Parser...")
    print(f"[*] Reading log file: {log_file_path}")

    logs = load_logs(log_file_path)
    if not logs:
        print("[!] No logs found. Exiting.")
        return

    print(f"[+] Successfully parsed {len(logs)} log entries with regex.")

    # Run detection rules
    print("[*] Running Anomaly Detection rules...")
    brute_force = detect_brute_force(logs, threshold=3, window_minutes=5)
    suspicious_ips = detect_suspicious_ips(logs)
    takeovers = detect_repeated_failures_then_success(logs, min_failures=3)
    invalid_users = detect_invalid_usernames(logs)

    # Generate and save report
    report_content = generate_summary_report(
        logs=logs,
        brute_force_anomalies=brute_force,
        suspicious_ip_anomalies=suspicious_ips,
        takeover_anomalies=takeovers,
        invalid_username_anomalies=invalid_users,
        output_path=report_file_path,
    )

    print("\n" + report_content)
    print(f"\n[+] Security Anomaly Report generated successfully at: {report_file_path}")


if __name__ == "__main__":
    main()
