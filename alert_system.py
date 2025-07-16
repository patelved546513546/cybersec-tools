import json

log_file = "/var/log/suricata/eve.json"

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)
            if data.get("event_type") == "alert":
                signature = data.get("alert", {}).get("signature", "")
                severity = data.get("alert", {}).get("severity", 5)

                # Example: Alert on SQL Injection attempts or high-severity alerts
                if "SQLi Attempt Detected" in signature or severity <= 2:
                    print(f"[ALERT] {signature} detected! Severity: {severity}")
        except json.JSONDecodeError:
            continue
