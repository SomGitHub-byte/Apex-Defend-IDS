# Apex-Defend-IDS

ApexDefend v2.1 is an advanced Rule-Based Network Intrusion Detection System (NIDS) and Active Threat Reconnaissance tool. It provides real-time packet sniffing, stateful alert deduplication, configurable detection rules, automated IOC harvesting, and offline PCAP forensics.

## Features

- **Live Alert Triage:** Real-time packet sniffing using custom BPF filters.
- **Stateful Alert Deduplication:** Groups repeated alerts to reduce alert fatigue.
- **Configurable Rules Engine:** 8 customizable detection rules (SYN Flood, Port Sweep, ARP Poisoning, YARA DPI, etc.).
- **Automated IOC Recorder:** Harvests malicious IPs, MACs, and payload hashes dynamically.
- **Active Threat Reconnaissance:** Integrated Nmap to run stealth scans directly from the UI.
- **Offline PCAP Forensics:** Replay `.pcap` files through the full detection pipeline.

## Prerequisites

- Python 3.8+
- Npcap or WinPcap (for Scapy packet sniffing on Windows)
- Nmap installed on the host OS and added to your system PATH

## Installation

```bash
git clone https://github.com/SombitHub-byte/Apex-Defend-IDS.git
cd Apex-Defend-IDS
pip install -r requirements.txt
```

## Usage

```bash
python apex_defend_nids.py
```
*Note: Run as Administrator (Windows) or with `sudo` (Linux) to allow Scapy to capture live network traffic.*

## Rules Configuration

You can dynamically adjust rule thresholds and severities from the **Configurable Rules** tab. Default rules include:
- `APEX-IOC-01`: Threat Intel / C2 Blacklist Match
- `APEX-DOS-02`: TCP SYN Flood Assault
- `APEX-SCAN-03`: Port Reconnaissance Sweep
- `APEX-MITM-04`: ARP Cache Poisoning (MITM)
- `APEX-SCAN-05`: Stealth TCP Scan (Xmas / Null / SYN-FIN)
- `APEX-AUTH-06`: Brute-Force Authentication Sweep
- `APEX-ICMP-07`: ICMP Flood / Covert Tunneling
- `APEX-DPI-08`: Deep Packet Payload Inspection (YARA)
