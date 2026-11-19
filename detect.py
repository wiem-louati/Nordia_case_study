import csv
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Rule 1: at least 20 failed logins per IP within 10 minutes
failures = defaultdict(list)

with open("auth.csv", encoding="utf-8-sig") as file:
    for row in csv.DictReader(file):
        if row["event"] == "login_failure":
            time = datetime.fromisoformat(
                row["timestamp"].replace("Z", "+00:00")
            )
            failures[row["src_ip"]].append(time)

print("R1: >=20 failed logins within 10 minutes per IP")

for ip, times in failures.items():
    window = []
    for time in sorted(times):
        window = [t for t in window if time - t <= timedelta(minutes=10)]
        window.append(time)
        if len(window) >= 20:
            print(f"ALERT {ip} at {time} UTC")
            break

# Rule 2: over 1,000 requested customer rows per user within 24 hours
exports = defaultdict(list)
pattern = (
    r'^\S+ - (\S+) \[([^\]]+)\] '
    r'"GET /admin/customers/export\?page=\d+&size=(\d+) '
    r'HTTP/1\.1" 200 '
)

with open("access.log", encoding="utf-8-sig") as file:
    for line in file:
        match = re.match(pattern, line)
        if match:
            user, timestamp, size = match.groups()
            time = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
            exports[user].append((time, int(size)))

print("\nR2: >1000 requested rows within 24 hours per user")

for user, events in exports.items():
    window = []
    for time, size in sorted(events):
        window = [
            (t, n) for t, n in window
            if time - t <= timedelta(hours=24)
        ]
        window.append((time, size))
        total = sum(n for t, n in window)
        if total > 1000:
            print(f"ALERT {user} at {time}: {total} requested rows")
            break
    else:
        print(f"OK {user}: no threshold crossing")