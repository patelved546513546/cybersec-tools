import csv
import re

auth_ips = set()
access_ips = set()
anomaly_ips = set()

# ✅ Parse /var/log/auth.log
with open("/var/log/auth.log", "r") as auth_file:
    for line in auth_file:
        if "Failed password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                auth_ips.add(ip)

# ✅ Parse /var/log/apache2/access.log
with open("/var/log/apache2/access.log", "r") as access_file:
    for line in access_file:
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            ip = match.group(1)
            access_ips.add(ip)

# ✅ Parse anomaly_report.csv (skip header)
try:
    with open("anomaly_report.csv", "r") as anomaly_file:
        next(anomaly_file)
        for line in anomaly_file:
            parts = line.strip().split(",")
            if len(parts) > 1:
                ip = parts[1]
                anomaly_ips.add(ip)
except FileNotFoundError:
    print("⚠️ anomaly_report.csv not found. Continuing without anomaly data.")

# ✅ Debug output
print(f"Auth IPs: {auth_ips}")
print(f"Access IPs: {access_ips}")
print(f"Anomaly IPs: {anomaly_ips}")

# ✅ Correlate IPs
suspicious_ips = auth_ips & access_ips & anomaly_ips

# ✅ Always write the CSV file
with open("correlated_ips.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Suspicious IP"])
    for ip in suspicious_ips:
        writer.writerow([ip])

# ✅ Final console output
if suspicious_ips:
    print(f"🚨 {len(suspicious_ips)} correlated suspicious IP(s) found. Saved to correlated_ips.csv.")
else:
    print("✅ No correlated suspicious IPs found. correlated_ips.csv file created with headers only.")
