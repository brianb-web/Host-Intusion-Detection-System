from parser.web_parser import parse_web_log
from datetime import datetime
import html
import json
import csv
import os

# Load detection rules
with open("rules/rules.json") as f:
    rules = json.load(f)

# Ensure output directory exists
os.makedirs("output", exist_ok=True)


def log_incident(incident):
    """Log each incident to a CSV file for historical tracking."""
    with open("output/incidents.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(incident.values())


def parse_auth_log(log_path, rules):
    """
    Parse the system authentication log for suspicious entries
    based on keywords and patterns defined in rules.json.
    """
    incidents = []
    if not os.path.exists(log_path):
        print(f"[!] Auth log not found at {log_path}")
        return incidents

    with open(log_path, "r", errors="ignore") as log_file:
        for line in log_file:
            for keyword, rule in rules.items():
                if keyword.lower() in line.lower():
                    incidents.append({
                        "type": "Authentication",
                        "severity": rule.get("severity", "Low"),
                        "timestamp": datetime.now().strftime("%m-%d-%Y %H:%M:%S"),
                        "summary": f"Match found: {keyword}",
                        "source": "auth.log"
                    })
    return incidents


def write_html_report(incidents, output_path="/var/www/html/index.html"):
    #Generate a HTML report for display on Apache.
    with open(output_path, "w") as f:
        f.write("<html><head><title>Threat Alerts</title>")
        f.write('<meta http-equiv="refresh" content="10">')  # Auto-refresh every 10 seconds
        f.write("""
            <style>
                body { font-family: 'Times New Roman', Times New Roman; background: #1e1e1e; color: #e0e0e0; padding: 20px; }
                h2 { color: #4997d0; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #444; padding: 10px; text-align: left; }
                th { background-color: #2c2c2c; color: #ffff00; }
                tr:nth-child(even) { background-color: #2b2b2b; }
                tr:nth-child(odd) { background-color: #1e1e1e; }
                td { color: #ccc; }
            </style>
        """)
        f.write("</head><body><h2>Detected Threats</h2>")
        f.write("<table><tr><th>Type</th><th>Severity</th><th>Timestamp</th><th>Summary</th><th>Source</th></tr>")

        for i in incidents:
            summary = html.escape(i.get('summary', 'No summary'))
            source = html.escape(i.get('source', 'Unknown'))

            f.write(f"<tr>")
            f.write(f"<td>{i.get('type', 'Unknown')}</td>")
            f.write(f"<td>{i.get('severity', 'Low')}</td>")
            f.write(f"<td>{i.get('timestamp', 'N/A')}</td>")
            f.write(f"<td>{summary}</td>")
            f.write(f"<td>{source}</td>")
            f.write(f"</tr>")

        f.write("</table></body></html>")


def parse_timestamp(incident):
    #Safely parse timestamps for sorting
    try:
        return datetime.strptime(incident["timestamp"], "%m-%d-%Y %H:%M:%S")
    except:
        return datetime.min  # Fallback if timestamp is missing


def main():
    print("Loading logs...")
    auth_log_path = "/var/log/auth.log"
    web_log_path = "/var/log/apache2/access.log"

    # Check log file paths
    if not os.path.exists(auth_log_path):
        print(f"Auth log not found at {auth_log_path}")
    if not os.path.exists(web_log_path):
        print(f"Web log not found at {web_log_path}")

    # Parse both auth and web logs
    auth_incidents = parse_auth_log(auth_log_path, rules.get("auth", {}))
    web_incidents = parse_web_log(web_log_path, rules.get("web", {}))
    all_incidents = auth_incidents + web_incidents

    # Sort incidents newest → oldest
    all_incidents.sort(key=parse_timestamp, reverse=True)

    print(f"Total incidents found: {len(all_incidents)}")

    for incident in all_incidents:
        print("[ALERT]", incident.get("summary", "No summary"))
        log_incident(incident)

    print("Writing HTML report...")
    try:
        if all_incidents:
            write_html_report(all_incidents)
        else:
            write_html_report([{
                "type": "Info",
                "summary": "No threats detected.",
                "severity": "Low",
                "timestamp": "-",
                "source": "-"
            }])
        print("✔ HTML report written successfully.")
    except Exception as e:
        print("ERROR WRITING HTML REPORT:", e)


if __name__ == "__main__":
    main()
