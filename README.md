# 🛡️ Personal Firewall using Python + iptables

## 🎯 Objective
Build a lightweight **personal firewall** that filters and logs network traffic based on custom rules. The firewall uses **Scapy** for packet sniffing and **iptables** to block suspicious IPs at the system level.

---

## 🧰 Tools & Technologies
- **Python 3**
- [`Scapy`](https://scapy.net/) – for real-time packet sniffing
- [`iptables`](https://linux.die.net/man/8/iptables) – for OS-level packet filtering (Linux)
- `firewall_rules.json` – for rule customization
- `firewall_log.txt` – for logging blocked traffic

---

## 📁 Project Structure

personal_firewall/
├── firewall.py # Main firewall script
├── firewall_rules.json # Define IP, port, and protocol rules
├── firewall_log.txt # Logs of blocked packets (auto-created)


## 🔧 Setup Instructions

### 1. Clone the repository
```
git clone https://github.com/Ramhaygrev10082005/project-personal-firewall-setup

### 2. Install dependencies
 
pip install scapy

sudo apt install iptables

### 3. ⚙️ Sample firewall_rules.json
{
  "block_ips": ["192.168.1.100", "10.0.0.5"],
  "block_ports": [23, 445],
  "allow_ports": [80, 443],
  "block_protocols": ["ICMP"]
}


### 4. Run the firewall

sudo python3 firewall.py

### 5. 📚 How It Works

    Scapy sniffs all incoming/outgoing packets in real time.

    Each packet is matched against the rules in firewall_rules.json.

    If a rule is violated:

        The event is logged in firewall_log.txt.

        The offending IP is blocked using iptables (DROP rule).

    The script prints allowed and blocked packets in the terminal.
