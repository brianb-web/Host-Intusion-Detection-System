import re
from collections import defaultdict
from datetime import datetime

def parse_web_log(log_path, rule_config):
    incidents = []
    request_counter = defaultdict(list)

    try:
        with open(log_path) as f:
            for line in f:
                # === Extract timestamp ===
                time_match = re.search(r'\[(.*?)\]', line)
                if not time_match:
                    continue

                try:
                    log_timestamp = datetime.strptime(
                        time_match.group(1).split()[0],
                        "%d/%b/%Y:%H:%M:%S"
                    )
                except ValueError:
                    continue

                # === Pattern-based attacks ===
                for attack_type in ["sql_injection", "xss", "directory_traversal", "lfi"]:
                    patterns = rule_config.get(attack_type, {}).get("patterns", [])
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            incidents.append({
                                "type": attack_type.upper(),
                                "summary": f"Possible {attack_type.replace('_', ' ').title()} attack",
                                "timestamp": log_timestamp.strftime("%m-%d-%Y %H:%M:%S"),
                                "severity": rule_config.get(attack_type, {}).get("severity", "Medium"),
                                "source": "access.log",
                                "raw": line.strip()
                            })
                            break

                # === Collect IPs for DoS ===
                ip_match = re.search(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', line)
                if ip_match:
                    ip = ip_match.group()
                    request_counter[ip].append(log_timestamp)

    except FileNotFoundError:
        print(f"Log file not found: {log_path}")

    # === DoS Detection ===
    dos_config = rule_config.get("dos", {})
    threshold = dos_config.get("rate_threshold", 5)
    window = dos_config.get("window_seconds", 5)

    for ip, times in request_counter.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            if (times[i + threshold - 1] - times[i]).total_seconds() <= window:
                incidents.append({
                    "type": "DoS",
                    "summary": f"Potential DoS from {ip}: {threshold}+ requests in {window}s",
                    "timestamp": times[i].strftime("%m-%d-%Y %H:%M:%S"),
                    "severity": dos_config.get("severity", "Critical"),
                    "source": "access.log",
                    "raw": f"Traffic spike detected from {ip}"
                })
                break  # one alert per IP

    return incidents
