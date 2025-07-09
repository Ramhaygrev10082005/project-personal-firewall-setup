# firewall.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime

# Load firewall rules
with open("firewall_rules.json", "r") as f:
    rules = json.load(f)

log_file = "firewall_log.txt"

def log_packet(packet, reason):
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} | {reason} | {packet.summary()}\n")

def packet_filter(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        proto = packet.proto
        
        # Blocked IPs
        if src_ip in rules["block_ips"]:
            log_packet(packet, "Blocked IP")
            return

        # Protocol Filtering
        if proto == 1 and "ICMP" in rules["block_protocols"]:
            log_packet(packet, "Blocked Protocol: ICMP")
            return

        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport

            # Blocked Ports
            if sport in rules["block_ports"] or dport in rules["block_ports"]:
                log_packet(packet, "Blocked Port")
                return

            # Optional: Allow Ports Only
            if "allow_ports" in rules:
                if dport not in rules["allow_ports"] and sport not in rules["allow_ports"]:
                    log_packet(packet, "Port Not Allowed")
                    return

        print(f"Allowed: {packet.summary()}")

# Start sniffing (must run as root)
print("🚨 Firewall is running. Press Ctrl+C to stop.")
sniff(prn=packet_filter, store=0)

