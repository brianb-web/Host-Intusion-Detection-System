from parser.web_parser import parse_web_log
from auth_parser import parse_auth_log, write_html_report, parse_timestamp
from datetime import datetime
import json
import csv
import os

# Load detection rules
with open("rules/rules.json") as f:
    rules = json.load(f)

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

def log_incident(incident):
    with open("output/incidents.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(incident.values())

def generate_incidents():
    """Parse logs and return all incidents sorted newest first"""
    auth_log_path = "/var/log/auth.log"
    web_log_path = "/var/log/apache2/access.log"

    auth_incidents = parse_auth_log(auth_log_path, rules.get("auth", {})) if os.path.exists(auth_log_path) else []
    web_incidents = parse_web_log(web_log_path, rules.get("web", {})) if os.path.exists(web_log_path) else []

    all_incidents = auth_incidents + web_incidents
    all_incidents.sort(key=parse_timestamp, reverse=True)

    # Save incidents to CSV
    if all_incidents:
        with open("output/incidents.csv", "w", newline="") as f:
            writer = csv.writer(f)
            for incident in all_incidents:
                writer.writerow(incident.values())

    return all_incidents

def main():
    print("Generating incidents and writing HTML report...")

    incidents = generate_incidents()

    if not incidents:
        incidents = [{
            "type": "Info",
            "summary": "No threats detected.",
            "severity": "Low",
            "timestamp": "-",
            "source": "-"
        }]

    # Write HTML output
    write_html_report(incidents, output_path="output/alerts.html")

    # Copy to Apache
    os.system("sudo cp output/alerts.html /var/www/html/alerts.html")

    print("DONE. Open http://localhost/alerts.html")

if __name__ == "__main__":
    main()
