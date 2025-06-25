from scapy.all import sniff
import csv
import time
import pandas as pd
import matplotlib
matplotlib.use('TkAgg')  # Necessary for MacOS to display plots
import matplotlib.pyplot as plt
import statistics
from collections import defaultdict

# Packet Capture & Labeling

packet_count = 0
packet_sizes = []

# Track IP request counts over a time window
ip_time_records = defaultdict(list)
flagged_ips = set()
TIME_WINDOW = 5       # seconds
PACKET_THRESHOLD = 10 # requests

# Initialize CSV log file
with open("trafik_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Timestamp", "IP Source", "IP Destination",
        "Source Port", "Destination Port", "Protocol",
        "Packet Size", "Label"
    ])

# Sampling: calculate mean and standard deviation

def sample(pkt):
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        packet_sizes.append(len(pkt))

print("🟡 Sampling first 50 packets to determine mean and deviation...")
sniff(filter="tcp", prn=sample, store=0, count=50)

mean_size = statistics.mean(packet_sizes)
std_deviation = statistics.stdev(packet_sizes)
lower_bound = mean_size - 1.5 * std_deviation
upper_bound = mean_size + 1.5 * std_deviation

print(f"Mean: {mean_size:.2f}, Std Dev: {std_deviation:.2f}")
print(f"Normal range: {lower_bound:.2f} – {upper_bound:.2f}\n")

def get_label(size):
    return "Anomalous" if size < lower_bound or size > upper_bound else "Normal"

# Main packet handling function
def handle_packet(pkt):
    global packet_count
    if not (pkt.haslayer('IP') and pkt.haslayer('TCP')):
        return

    packet_count += 1
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    src = pkt['IP'].src
    dst = pkt['IP'].dst
    sport, dport = pkt['TCP'].sport, pkt['TCP'].dport
    size = len(pkt)
    label = get_label(size)

    # Record times for source IP and remove old entries
    current_time = time.time()
    times = ip_time_records[src]
    times.append(current_time)
    ip_time_records[src] = [t for t in times if current_time - t <= TIME_WINDOW]

    # Flag IP if threshold exceeded
    if len(ip_time_records[src]) > PACKET_THRESHOLD and src not in flagged_ips:
        print(f"⚠️ {TIME_WINDOW}s: More than {PACKET_THRESHOLD} requests from {src}")
        flagged_ips.add(src)

    # Print info only for flagged IPs
    if src in flagged_ips or dst in flagged_ips:
        print(f"{src} -> {dst} | Size: {size} | Label: {label} | Total: {packet_count}")

    # Append to CSV
    with open("trafik_log.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src, dst, sport, dport, "TCP", size, label])

print("🟢 Listening for TCP packets... Press Ctrl+C to stop.\n")
try:
    sniff(filter="tcp", prn=handle_packet, store=0)
except KeyboardInterrupt:
    print(f"\n⛔ Stopped listening. Total packets: {packet_count}")

# Data Analysis & Visualization

df = pd.read_csv("trafik_log.csv")
print("\n📄 First 5 records:\n", df.head())

if not df.empty:
    df['Packet Size'].plot.hist(bins=50, alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid()
    plt.show()

    print("\n📊 Basic Statistics:")
    print(f"Total packets: {len(df)}")
    print(df['Protocol'].value_counts(normalize=True).mul(100).round(2).astype(str) + "%")
    print(df.groupby("Protocol")["Packet Size"].agg(['mean','min','max']).round(2))
else:
    print("⚠️ No data available.")
