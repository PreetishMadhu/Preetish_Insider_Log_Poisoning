import json
import random
from datetime import datetime, timedelta
from faker import Faker
from netaddr import IPNetwork
import os

fake = Faker()
Faker.seed(42)
random.seed(42)

internal_ips = [str(ip) for ip in IPNetwork("192.168.1.0/24")]
external_ips = [fake.ipv4_private() if random.random() < 0.3 else fake.ipv4_public() for _ in range(1000)]

ports = [80, 443, 53, 123, 22, 21, 3389, 8080, 8443] + list(range(1024, 65536))

def apply_all_evasions(data):
    """Apply ALL 7 evasion techniques cumulatively to a single data dict"""
    data = data.copy()

    # 1. BruteForce evasion: slow down
    data["Flow Duration"] = random.randint(30000000, 120000000)
    data["Total Fwd Packet"] = random.randint(3, 10)
    data["Total Bwd Packet"] = random.randint(2, 8)

    # 2. DDoS evasion: fragmentation
    for key in ["Fwd Packet Length Max", "Bwd Packet Length Max"]:
        if key in data:
            data[key] = random.randint(60, 300)
    if "Flow Bytes/s" in data:
        data["Flow Bytes/s"] = random.uniform(1000, 50000)

    # 3. DoS evasion: mimic long legitimate session
    data["Total Length of Fwd Packet"] = random.randint(50000, 200000)
    data["Total Length of Bwd Packet"] = random.randint(10000, 50000)

    # 4. Mirai evasion: common web ports
    data["Protocol"] = random.choice(["TCP", "UDP"])
    data["Dst Port"] = random.choice([80, 443])
    data["Src Port"] = random.randint(49152, 65535)

    # 5. Recon evasion: very low packet count
    data["Total Fwd Packet"] = random.randint(1, 5)
    data["Total Bwd Packet"] = random.randint(0, 3)

    # 6. Spoofing evasion: internal source IP
    for key in ["Src IP", "Src IP Addr", "Source IP", "src_ip"]:
        if key in data:
            data[key] = random.choice(internal_ips)

    # 7. WebBased evasion: realistic User-Agent + HTTP-like sizes
    data["user_agent"] = fake.user_agent()
    data["Total Length of Fwd Packet"] = random.randint(200, 2000)
    data["Total Length of Bwd Packet"] = random.randint(500, 10000)

    data["Label"] = "Benign"

    # Timestamp jitter
    ts = data.get("Timestamp")
    if ts:
        try:
            dt = datetime.strptime(ts, "%d/%m/%Y %I:%M:%S %p")
            dt += timedelta(seconds=random.randint(-30, 30))
            data["Timestamp"] = dt.strftime("%d/%m/%Y %I:%M:%S %p")
        except:
            pass

    # Remove attack metadata
    for key in ["Attack", "AttackType", "SubType", "Category", "malicious"]:
        data.pop(key, None)

    return data

def generate_synthetic_benign_data():
    start_time = datetime(2024, 1, 1)
    ts = fake.date_time_between(start_date=start_time, end_date='+2y')
    timestamp_str = ts.strftime("%d/%m/%Y %I:%M:%S %p")

    src_ip = random.choice(internal_ips)
    dst_ip = random.choice(external_ips)
    src_port = random.choice(ports + [random.randint(49152, 65535)])
    dst_port = random.choice(ports)

    protocol = random.choice(["TCP", "UDP", "ICMP"])

    duration = random.randint(50, 120000000)
    fwd_packets = random.randint(1, 50)
    bwd_packets = random.randint(0, 50)
    fwd_bytes = random.randint(60, fwd_packets * 1400)
    bwd_bytes = random.randint(0, bwd_packets * 1400)

    data = {
        "Timestamp": timestamp_str,
        "Src IP": src_ip,
        "Dst IP": dst_ip,
        "Src Port": src_port,
        "Dst Port": dst_port,
        "Protocol": protocol,
        "Flow Duration": duration,
        "Total Fwd Packet": fwd_packets,
        "Total Bwd Packet": bwd_packets,
        "Total Length of Fwd Packet": fwd_bytes,
        "Total Length of Bwd Packet": bwd_bytes,
        "Fwd Packet Length Max": min(1400, fwd_bytes // max(1, fwd_packets)),
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": fwd_bytes / max(1, fwd_packets),
        "Bwd Packet Length Max": min(1400, bwd_bytes // max(1, bwd_packets)) if bwd_packets else 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": bwd_bytes / max(1, bwd_packets) if bwd_packets else 0,
        "Flow Bytes/s": (fwd_bytes + bwd_bytes) / max(1, duration / 1000000),
        "Flow Packets/s": (fwd_packets + bwd_packets) / max(1, duration / 1000000),
        "Packet Length Mean": (fwd_bytes + bwd_bytes) / max(1, fwd_packets + bwd_packets),
        "Label": "Benign"
    }
    if random.random() < 0.6:
        data["user_agent"] = fake.user_agent()
    return data

json_dir = os.path.expanduser("~/datasets/CICDIAD2024/json_logs")
output_file = os.path.join(json_dir, "benign.json")

attack_files = [
    "BruteForce.json", "DDOS.json", "DOS.json", "Mirai.json",
    "Recon.json", "Spoofing.json", "WebBased.json"
]

NUM_PER_CATEGORY = 14
NUM_BENIGN = 900
poisoned_logs = []

print("Creating 100 poisoned logs (ALL 7 evasion techniques applied to each)...")
for filename in attack_files:
    file_path = os.path.join(json_dir, filename)
    if not os.path.exists(file_path):
        print(f"Warning: {filename} not found, skipping.")
        continue

    collected = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "data" in entry:
                    collected.append(entry)
            except json.JSONDecodeError:
                continue

    samples = random.sample(collected, min(NUM_PER_CATEGORY, len(collected)))
    for entry in samples:
        modified_data = apply_all_evasions(entry["data"])
        poisoned_entry = {
            "timestamp": entry.get("timestamp", datetime.now().isoformat()),
            "event_type": "Benign",
            "source": "CICDIAD2024",
            "data": modified_data
        }
        poisoned_logs.append(poisoned_entry)

    print(f"  {filename}: {len(samples)} logs poisoned with all 7 techniques")

if len(poisoned_logs) > 100:
    poisoned_logs = random.sample(poisoned_logs, 100)

print(f"\nTotal poisoned logs: {len(poisoned_logs)} (each with ALL 7 evasions)")

print("Generating 900 synthetic benign logs...")
benign_entries = []
for _ in range(NUM_BENIGN):
    data = generate_synthetic_benign_data()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "Benign",
        "source": "CICDIAD2024",
        "data": data
    }
    benign_entries.append(entry)

all_entries = benign_entries + poisoned_logs
random.shuffle(all_entries)

with open(output_file, 'w') as f:
    for entry in all_entries:
        f.write(json.dumps(entry) + "\n")

print("\n" + "="*80)
print("SUCCESS! benign.json created:")
print("   • 900 purely synthetic benign logs")
print("   • 100 poisoned logs — each transformed using ALL 7 evasion techniques")
print(f"   • Total: 1000 logs → {output_file}")

print("="*80)
