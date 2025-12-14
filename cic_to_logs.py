import os
import csv
import json
from datetime import datetime

input_path = "/home/preet/datasets/CICDIAD2024/"
output_path = "/home/preet/datasets/CICDIAD2024/json_logs/"

os.makedirs(output_path, exist_ok=True)

def convert_row_to_log(row, attack_type):
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": attack_type,
        "source": "CICDIAD2024",
        "data": row
    }

print("[+] Scanning folders for CSV files...")
print(f"[+] Found {len(csv_files)} CSV files")

log_count = 0

for csv_file in csv_files:
    attack_type = csv_file.split("/")[-2]

    print(f"[+] Processing: {csv_file}")

    with open(csv_file, "r", newline='', encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            json_log = convert_row_to_log(row, attack_type)

            json_filename = f"log_{log_count}.json"
            json_path = os.path.join(output_path, json_filename)

            with open(json_path, "w") as jf:
                json.dump(json_log, jf, indent=4)

            log_count += 1

print("\n[✔] Conversion complete!")
print(f"[✔] Total logs generated: {log_count}")

print(f"[✔] Logs saved to: {output_path}")
