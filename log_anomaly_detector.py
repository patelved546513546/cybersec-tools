from sklearn.ensemble import IsolationForest
from datetime import datetime
import pandas as pd
import re

# Step 1: Read log file & extract timestamps of failed logins
with open("sample_auth.log", "r") as file:
    logs = file.readlines()

timestamps = []
for line in logs:
    if "Failed password" in line:
        match = re.match(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
        if match:
            timestamp = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
            timestamps.append(timestamp.replace(year=2025))  # Add a dummy year

# Step 2: Count failures per hour
df = pd.DataFrame(timestamps, columns=["datetime"])
df["hour"] = df["datetime"].dt.strftime("%Y-%m-%d %H:00")
counts = df.groupby("hour").size().reset_index(name="failed_logins")

# Step 3: Train IsolationForest on counts
model = IsolationForest(contamination=0.2)
counts["anomaly"] = model.fit_predict(counts[["failed_logins"]])

# Step 4: Save anomalies
anomalies = counts[counts["anomaly"] == -1]
anomalies.to_csv("anomaly_report.csv", index=False)

print("✅ Anomaly detection complete. Check anomaly_report.csv.")
