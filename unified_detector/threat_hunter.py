import os
import json
import re
import requests
from termcolor import colored
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Load threat patterns from local file or URL
def load_patterns(source):
    if source.startswith("http://") or source.startswith("https://"):
        print(f"🌐 Downloading pattern file from URL: {source}")
        response = requests.get(source)
        response.raise_for_status()
        return response.json()
    else:
        with open(source, "r") as f:
            return json.load(f)

# Scan logs for patterns
def scan_logs(log_dir, patterns):
    results = []
    print(f"🔍 Scanning logs in directory: {log_dir}")
    for root, _, files in os.walk(log_dir):
        for file in files:
            if file.endswith(".log") or file.endswith(".json"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            for pattern in patterns:
                                if re.search(pattern["regex"], line, re.IGNORECASE):
                                    results.append({
                                        "file": full_path,
                                        "line": i,
                                        "content": line.strip(),
                                        "attack_type": pattern["name"]
                                    })
                                    print(colored(f"[MATCH] {pattern['name']} in {file}:{i}", "red"))
                except Exception as e:
                    print(colored(f"[ERROR] Failed to read {full_path}: {e}", "yellow"))
    return results

# Save results to JSON report
def generate_json_report(results, output_file):
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_matches": len(results),
        "matches": results
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(colored(f"📄 Report saved to: {output_file}", "green"))

# Optional: Generate charts
def generate_visual_report(results):
    attack_types = [match["attack_type"] for match in results]
    if not attack_types:
        print("📉 No attack patterns detected, skipping visual report.")
        return

    sns.set(style="whitegrid")

    # Bar Chart
    plt.figure(figsize=(12, 6))
    sns.countplot(y=attack_types, order=pd.Series(attack_types).value_counts().index, palette="viridis")
    plt.title("Detected Attack Patterns (Bar Chart)")
    plt.xlabel("Count")
    plt.ylabel("Attack Type")
    plt.tight_layout()
    plt.savefig("threat_visual_report.png")
    plt.show()

    # Pie Chart
    plt.figure(figsize=(8, 8))
    pd.Series(attack_types).value_counts().plot.pie(autopct='%1.1f%%', startangle=90, cmap="tab20")
    plt.title("Attack Pattern Distribution (Pie Chart)")
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig("threat_visual_pie.png")
    plt.show()

def main():
    print(colored("🔐 Unified Threat Hunter", "cyan", attrs=["bold"]))
    pattern_source = input("🔗 Enter path or URL to pattern file (e.g., attack_patterns.json or http://...): ").strip()
    log_dir = input("📁 Enter path to log directory (e.g., /var/log or ./logs): ").strip()
    output_path = input("💾 Enter output report filename (e.g., report.json): ").strip()

    try:
        patterns = load_patterns(pattern_source)
    except Exception as e:
        print(colored(f"❌ Failed to load pattern file: {e}", "red"))
        return

    results = scan_logs(log_dir, patterns)
    generate_json_report(results, output_path)
    generate_visual_report(results)

if __name__ == "__main__":
    main()
