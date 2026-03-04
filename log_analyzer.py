import re
from collections import defaultdict

def analyze_logs(file_path):
    failed_attempts = defaultdict(int)
    suspicious_ips = []

    with open(file_path, 'r') as file:
        logs = file.readlines()

    for line in logs:
        # Extract IP address
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        if ip_match:
            ip = ip_match.group()

            # Detect failed login attempts
            if "Failed password" in line:
                failed_attempts[ip] += 1

    # Detect brute-force (more than 5 failed attempts)
    for ip, count in failed_attempts.items():
        if count > 5:
            suspicious_ips.append((ip, count))

    return suspicious_ips


if __name__ == "__main__":
    results = analyze_logs("data/sample_logs.txt")

    if results:
        print("⚠️ Suspicious IPs detected:")
        for ip, count in results:
            print(f"{ip} - {count} failed attempts")
    else:
        print("✅ No suspicious activity detected.")
