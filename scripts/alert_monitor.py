import json

# Path to the Suricata JSON log
log_file = "/var/log/suricata/eve.json"

# Open and read each line of the JSON log
with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)

            # Check if the event is an alert
            if data.get("event_type") == "alert":
                alert = data.get("alert", {})
                signature = alert.get("signature", "")
                severity = alert.get("severity", 5)

                # Trigger alert for SQLi or high-severity events
                if "SQLi Attempt Detected" in signature or severity <= 2:
                    print(f"[ALERT] {signature} detected! Severity: {severity}")

        except json.JSONDecodeError:
            # Skip lines that are not valid JSON
            continue
