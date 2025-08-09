import re
import pandas as pd
import requests

# Path to your access.log
log_file_path = "access.log"

# AbuseIPDB API Key
API_KEY = "320f96424903b45b8a3ed88aad5ca34c7c363b892cbdbae935eb59d4bc65ce212dd178505204552d"

# Function to extract unique IPs from access.log
def extract_ips_from_log(file_path):
    with open(file_path, "r") as f:
        log_data = f.read()
    # Regex for IPv4 addresses
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_data)
    return list(set(ips))  # unique IPs only

# Function to check IP reputation via AbuseIPDB
def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()["data"]["abuseConfidenceScore"]
    return None

# Main logic
ip_list = extract_ips_from_log(log_file_path)
results = []

for ip in ip_list:
    score = check_ip_reputation(ip)
    results.append({"ip": ip, "abuse_score": score})

# Create DataFrame
df = pd.DataFrame(results)
print(df)
