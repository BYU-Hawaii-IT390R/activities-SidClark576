"""Template script for IT 390R log‑analysis lab

Students: complete the **TODO** sections in `analyze_failed_logins` and
`analyze_successful_creds`.  All other tasks already work, so you can run the
script right away to explore the output format.

Run examples
------------
# Once you fill in the failed‑login logic
python analyze_log.py cowrie-tiny.log --task failed-logins --min-count 5

# Connection volume task (already functional)
python analyze_log.py cowrie-tiny.log --task connections

# Identify bot clients by shared fingerprint (already functional)
python analyze_log.py cowrie-tiny.log --task identify-bots --min-ips 3
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

WGET_PATTERN = re.compile(
    r"\[HoneyPotSSHSession.*?runCommand\] CMD: wget (?P<url>http[s]?://[^\s]+)"
) # Extra credit

# ── Helper to print tables ──────────────────────────────────────────────────

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    """Nicely format a Counter as a two‑column table."""
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── TODO Task 1: fill this in ───────────────────────────────────────────────

def analyze_failed_logins(path: str, min_count: int):
    """Parse *failed* SSH login attempts and show a count per source IP.

    You should:
    1. Iterate over each line in ``path``.
    2. Use ``FAILED_LOGIN_PATTERN`` to search the line.
    3. Increment a Counter keyed by IP when a match is found.
    4. After reading the file, *filter out* any IP whose count is
       below ``min_count``.
    5. Print the results using ``_print_counter``.
    """
    # TODO: replace the placeholder implementation below
    ip_counter = Counter()

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                ip_counter[ip] += 1

    # Filter IPs below threshold
    filtered = {ip: count for ip, count in ip_counter.items() if count >= min_count}

    print(f"Failed logins from ≥ {min_count} attempts")
    _print_counter(Counter(filtered), "IP Address", "Failures")

# ── Task 2 (already done) ───────────────────────────────────────────────────

def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── TODO Task 3: fill this in ───────────────────────────────────────────────

def analyze_successful_creds(path: str):
    """Display username/password pairs that *succeeded* and how many unique IPs used each.

    Steps:
    • Iterate lines and apply ``SUCCESS_LOGIN_PATTERN``.
    • Build a ``defaultdict(set)`` mapping ``(user, pw)`` → set of IPs.
    • After reading, sort the mapping by descending IP count and print a
      three‑column table (Username, Password, IP_Count).
    """
    # TODO: replace the placeholder implementation below
    cred_map = defaultdict(set)

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                user = match.group("user")
                pw = match.group("pw")
                ip = match.group("ip")
                cred_map[(user, pw)].add(ip)

    # Convert to list of ((user, pw), ip_count) and sort by count descending
    sorted_pairs = sorted(
        [(creds, len(ips)) for creds, ips in cred_map.items()],
        key=lambda x: x[1],
        reverse=True
    )

    print("Successful credential pairs")
    width_user = max(len(u) for (u, _) in cred_map) if cred_map else len("Username")
    width_pw = max(len(p) for (_, p) in cred_map) if cred_map else len("Password")
    print(f"{'Username':<{width_user}} {'Password':<{width_pw}} {'Count':>6}")
    print("-" * (width_user + width_pw + 8))
    for (user, pw), count in sorted_pairs:
        print(f"{user:<{width_user}} {pw:<{width_pw}} {count:>6}")

# ── Task 4 (bot fingerprints) already implemented ───────────────────────────

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

# ── Extra credit (wget drops) already implemented ───────────────────────────

def analyze_wget_drops(path: str):
    """List URLs downloaded via 'wget' by bots."""
    url_counter = Counter()

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = WGET_PATTERN.search(line)
            if match:
                url = match.group("url")
                url_counter[url] += 1

    print("Common wget downloads by bots")
    _print_counter(url_counter, "URL", "Count")

# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer — student template")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task",
                        required=True,
                        choices=["failed-logins", "connections",
                                 "successful-creds", "identify-bots", "wget-drops"],
                        help="Which analysis to run")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Min events to report (failed-logins)")
    parser.add_argument("--min-ips", type=int, default=3,
                        help="Min IPs per fingerprint (identify-bots)")
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)
    elif args.task == "wget-drops":  # 🎣 Extra credit
        analyze_wget_drops(args.logfile)


if __name__ == "__main__":
    main()
