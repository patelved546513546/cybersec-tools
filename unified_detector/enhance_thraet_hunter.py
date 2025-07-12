import os
import re
import json
import requests
import matplotlib.pyplot as plt
from datetime import datetime


def load_patterns(path_or_url):
    if path_or_url.startswith("http"):
        print("🌐 Downloading attack patterns from URL...")
        response = requests.get(path_or_url)
        return response.json()
    else:
        with open(path_or_url, "r") as f:
            return json.load(f)


def search_patterns_in_text(text, patterns):
    for pattern in patterns:
        if re.search(pattern["regex"], text, re.IGNORECASE):
            return pattern["name"]
    return None


def scan_log_file(filepath, patterns):
    detections = []
    try:
        if filepath.endswith(".json"):
            with open(filepath, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        combined_text = json.dumps(entry)
                        match = search_patterns_in_text(combined_text, patterns)
                        if match:
                            detections.append({
                                "file": filepath,
                                "line": line.strip(),
                                "pattern": match,
                                "timestamp": entry.get("timestamp", str(datetime.now()))
                            })
                    except json.JSONDecodeError:
                        continue
        else:
            with open(filepath, "r", errors="ignore") as f:
                for line in f:
                    match = search_patterns_in_text(line, patterns)
                    if match:
                        detections.append({
                            "file": filepath,
                            "line": line.strip(),
                            "pattern": match,
                            "timestamp": str(datetime.now())
                        })
    except Exception as e:
        print(f"[ERROR] Failed to read {filepath}: {e}")
    return detections


def generate_report(detections, report_file):
    with open(report_file, "w") as f:
        json.dump(detections, f, indent=2)
    print(f"📄 Report saved to: {report_file}")

    if detections:
        counts = {}
        for d in detections:
            counts[d["pattern"]] = counts.get(d["pattern"], 0) + 1

        plt.bar(counts.keys(), counts.values(), color="orange")
        plt.xticks(rotation=45, ha="right")
        plt.title("Attack Pattern Frequency")
        plt.tight_layout()
        plt.savefig("pattern_chart.png")
        print("📊 Chart saved to: pattern_chart.png")
    else:
        print("📉 No attack patterns detected, skipping visual report.")


def main():
    print("\n🔐 Unified Threat Hunter")
    pattern_source = input("🔗 Enter path or URL to pattern file (e.g., attack_patterns.json or http://...): ").strip()
    log_dir = input("📁 Enter path to log directory (e.g., /var/log or ./logs): ").strip()
    report_file = input("💾 Enter output report filename (e.g., report.json): ").strip()

    patterns = load_patterns(pattern_source)
    all_detections = []

    print(f"🔍 Scanning logs in directory: {log_dir}")
    for root, _, files in os.walk(log_dir):
        for file in files:
            full_path = os.path.join(root, file)
            detections = scan_log_file(full_path, patterns)
            all_detections.extend(detections)

    generate_report(all_detections, report_file)


if __name__ == "__main__":
    main()
