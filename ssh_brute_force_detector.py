import re
from collections import defaultdict

filename = input("Enter log file name: ")

fail_counts = defaultdict(int)

with open(filename) as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                fail_counts[ip] += 1

# Show suspicious IPs
print("\nSuspicious IPs (more than 5 failed attempts):")
for ip, count in fail_counts.items():
    if count > 5:
        print(f"{ip} → {count} failed attempts")
