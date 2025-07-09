# firewall.py
from scapy.all import sniff, IP, TCP, UDP
import json
import os
from datetime import datetime

# Load rules
with open("firewall_rules.json", "r") as f:
    rules = json.load(f)

log_file = "firewall_log.txt"
blocked_ips = set()  # To track what we’ve already blocked

def log_packet(packet, reason):
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} | {reason} | {packet.summary()}\n")

def block_ip_with_iptables(ip):
    if ip not in blocked_ips:
        print(f"🚫 Blocking IP with iptables: {ip}")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)

def packet_filter(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        proto = packet.proto

        # Rule 1: Block specific IPs
        if src_ip in rules["block_ips"]:
            log_packet(packet, "Blocked IP (Rule)")
            block_ip_with_iptables(src_ip)
            return

        # Rule 2: Block protocols
        if proto == 1 and "ICMP" in rules["block_protocols"]:
            log_packet(packet, "Blocked Protocol: ICMP")
            block_ip_with_iptables(src_ip)
            return

        # Rule 3: Block ports
        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport

            if sport in rules["block_ports"] or dport in rules["block_ports"]:
                log_packet(packet, "Blocked Port")
                block_ip_with_iptables(src_ip)
                return

            # Optional: Allow ports only
            if "allow_ports" in rules:
                if dport not in rules["allow_ports"] and sport not in rules["allow_ports"]:
                    log_packet(packet, "Port Not Allowed")
                    block_ip_with_iptables(src_ip)
                    return

        print(f"✅ Allowed: {packet.summary()}")

# Start sniffing
print("🛡️ Personal Firewall is running with iptables support. Press Ctrl+C to stop.")
sniff(prn=packet_filter, store=0)

