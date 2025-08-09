import requests
import pandas as pd
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_API_KEY")  # safer than hardcoding
API_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip):
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(API_URL, headers=headers, params=params)
    try:
        data = response.json()
    except ValueError:
        return {"error": "Invalid JSON response", "raw": response.text}

    # If the API returns errors, pass them through
    if "errors" in data:
        return {"error": data["errors"], "ip": ip}

    return data

# Example usage
ips_to_check = ["8.8.8.8", "185.220.101.1"]  # known Tor exit node
results = []

for ip in ips_to_check:
    data = check_ip(ip)

    if "data" in data:
        score = data["data"].get("abuseConfidenceScore", 0)
        results.append({"ip": ip, "abuse_score": score})
    else:
        results.append({"ip": ip, "abuse_score": "Error", "details": data.get("error", "Unknown error")})

df = pd.DataFrame(results)
print(df)
