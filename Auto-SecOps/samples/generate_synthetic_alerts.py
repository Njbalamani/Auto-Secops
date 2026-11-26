import csv
import json
import random
from pathlib import Path

random.seed(20261126)

BASE_DIR = Path(__file__).resolve().parent
SOURCE_IPS = ["203.0.113.10", "198.51.100.77", "192.0.2.44"]
USERS = ["alice", "bob", "svc-deploy", "finance-user"]
TYPES = [
    ("failed password brute force login attempts", "HIGH", "authentication_failure"),
    ("malware beacon to command and control domain", "CRITICAL", "edr_malware"),
    ("phishing email with credential harvesting link", "HIGH", "mail_security"),
    ("port scan detected against multiple internal hosts", "MEDIUM", "nids"),
    ("configuration baseline deviation", "LOW", "compliance"),
]

rows = []
for index in range(1, 31):
    description, severity, alert_type = random.choice(TYPES)
    rows.append(
        {
            "external_id": f"GEN-{index:04d}",
            "title": f"Synthetic generated alert {index}",
            "description": description,
            "severity": severity,
            "source_ip": random.choice(SOURCE_IPS),
            "user": random.choice(USERS),
            "alert_type": alert_type,
            "timestamp": f"2026-11-26T{index % 24:02d}:00:00Z",
        }
    )

json_path = BASE_DIR / "synthetic_alerts.json"
csv_path = BASE_DIR / "synthetic_alerts.csv"
json_path.write_text(json.dumps({"alerts": rows}, indent=2), encoding="utf-8")
with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} synthetic alerts to {json_path.name} and {csv_path.name}")
