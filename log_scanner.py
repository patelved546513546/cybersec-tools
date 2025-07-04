import re

def scan_log(filename):
    suspicious_keywords = ["Failed password", "Invalid user", "error", "ERROR", "fail", "FAIL"]
    found_ips = []

    try:
        with open(filename, 'r') as file:
            for line in file:
                # Check for suspicious keywords
                if any(keyword in line for keyword in suspicious_keywords):
                    print("Suspicious Line:", line.strip())

                    # Extract IP addresses
                    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    if ips:
                        found_ips.extend(ips)
                        print("IP(s) found:", ", ".join(ips))

        # Remove duplicate IPs
        unique_ips = set(found_ips)
        print("\nUnique Suspicious IPs Found:")
        for ip in unique_ips:
            print(ip)

    except FileNotFoundError:
        print("Log file not found. Please check the file name/path.")

# --------- Main Program ----------
log_file = input("Enter the log file name (e.g., auth.log): ")
scan_log(log_file)
