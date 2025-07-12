import json

# Base attack patterns
patterns = [
    {"id": "ATTACK_SQLI", "pattern": "select.+from|union.+select|drop\\s+table", "description": "SQL Injection", "severity": "High"},
    {"id": "ATTACK_XSS", "pattern": "<script>|onerror=|alert\\(", "description": "Cross-Site Scripting", "severity": "Medium"},
    {"id": "ATTACK_CMD", "pattern": "cmd\\.exe|powershell|/bin/bash", "description": "Command Injection", "severity": "High"},
    {"id": "ATTACK_SSH", "pattern": "Failed password for|Invalid user", "description": "SSH Brute Force", "severity": "Medium"},
    {"id": "ATTACK_FTP", "pattern": "USER.+PASS|530 Login", "description": "FTP Brute Force", "severity": "Low"},
    {"id": "ATTACK_PATH_TRAVERSAL", "pattern": "\\.\\./|etc/passwd", "description": "Path Traversal", "severity": "High"},
    {"id": "ATTACK_RCE", "pattern": "eval\\(|system\\(|exec\\(", "description": "Remote Code Execution", "severity": "High"},
    {"id": "ATTACK_SCAN", "pattern": "Nmap scan|Nikto", "description": "Recon/Scanning", "severity": "Medium"},
    {"id": "ATTACK_LOGIN", "pattern": "login failed|authentication error", "description": "Login Attempt", "severity": "Low"},
    {"id": "ATTACK_MALWARE", "pattern": "MZ|This program cannot be run", "description": "Malware Signature", "severity": "High"}
]

# Expand patterns to make it large
expanded = []
for i in range(10):
    for pattern in patterns:
        new_pattern = pattern.copy()
        new_pattern["id"] = f"{pattern['id']}_{i+1}"
        expanded.append(new_pattern)

# Write to file
with open("attack_patterns.json", "w") as f:
    json.dump(expanded, f, indent=2)

print("✅ attack_patterns.json generated with", len(expanded), "patterns.")
