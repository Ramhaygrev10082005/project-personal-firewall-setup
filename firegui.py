import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
import datetime
import os
import threading
import subprocess

running = False
log_file = "firewall_log.txt"

# Load firewall rules
with open("firewall_rules.json") as f:
    rules = json.load(f)

def log_packet(reason, pkt_summary):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | {reason} | {pkt_summary}\n"
    with open(log_file, "a") as f:
        f.write(log_entry)
    log_output.insert(tk.END, log_entry)
    log_output.yview(tk.END)

def apply_iptables_block(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log_output.insert(tk.END, f"iptables error: {e}\n")

def packet_filter(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        proto = pkt[IP].proto
        summary = pkt.summary()

        # Rule: Block IPs
        if ip in rules["block_ips"]:
            log_packet("Blocked IP", summary)
            apply_iptables_block(ip)
            return

        # Rule: Block Protocols
        if "block_protocols" in rules:
            if ICMP in pkt and "ICMP" in rules["block_protocols"]:
                log_packet("Blocked Protocol (ICMP)", summary)
                apply_iptables_block(ip)
                return

        # Rule: Block Ports
        if TCP in pkt or UDP in pkt:
            sport = pkt.sport
            dport = pkt.dport
            if dport in rules["block_ports"]:
                log_packet(f"Blocked Port {dport}", summary)
                apply_iptables_block(ip)
                return

        log_packet("Allowed", summary)

def sniff_packets():
    sniff(prn=packet_filter, store=0)

def start_firewall():
    global running
    running = True
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    status_label.config(text="Firewall Status: Running 🟢")
    thread = threading.Thread(target=sniff_packets)
    thread.daemon = True
    thread.start()

def stop_firewall():
    global running
    running = False
    os._exit(0)  # Forcefully stops sniffing thread (better than relying on Ctrl+C)
    
# GUI Setup
root = tk.Tk()
root.title("🛡️ Personal Firewall GUI")
root.geometry("700x500")
root.resizable(False, False)

title = tk.Label(root, text="Python Firewall with iptables", font=("Helvetica", 16, "bold"))
title.pack(pady=10)

status_label = tk.Label(root, text="Firewall Status: Stopped 🔴", font=("Helvetica", 12))
status_label.pack()

frame = tk.Frame(root)
frame.pack(pady=10)

start_button = tk.Button(frame, text="Start Firewall", bg="green", fg="white", font=("Helvetica", 12), command=start_firewall)
start_button.grid(row=0, column=0, padx=10)

stop_button = tk.Button(frame, text="Stop Firewall", bg="red", fg="white", font=("Helvetica", 12), state=tk.DISABLED, command=stop_firewall)
stop_button.grid(row=0, column=1, padx=10)

log_output = scrolledtext.ScrolledText(root, width=80, height=20, font=("Courier", 10))
log_output.pack(pady=10)

root.mainloop()

