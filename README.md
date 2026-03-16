# Smart-Firewall

AI Smart Firewall is a Python-based network security tool that captures and analyzes live network traffic to detect suspicious activity such as port scanning attacks. The system automatically blocks malicious IP addresses and provides a graphical dashboard to monitor network activity in real time.

This project demonstrates the basic working principles of network firewalls, intrusion detection systems, and packet monitoring tools.

# Features

Live packet capture and monitoring

Automatic port scan detection

Automatic attacker IP blocking

Geo-location detection of IP addresses

Color-coded traffic logs

Real-time network activity dashboard

Packet statistics tracking

CSV export of complete packet logs

Automatic opening of exported reports

# Technologies Used

Python

Scapy – Packet capture and network analysis

Tkinter – Graphical user interface

Requests – API calls for IP geo-location

CSV – Packet logging and report generation

Windows Firewall (netsh) – Blocking attacker IPs

# System Architecture

<img width="161" height="781" alt="Untitled Diagram drawio" src="https://github.com/user-attachments/assets/164bf10c-6dd6-4b9d-be0b-d01dfaddd96b" />

# Installation
1 Clone the Repository
git clone https://github.com/AayushDarpe/Smart-Firewall.git
cd Smart-Firewall
2 Install Required Libraries
pip install scapy requests
3 Run the Application
python firewall.py

⚠ Run the program with Administrator privileges to allow packet capture and firewall rule creation.

# How the Firewall Works

The application captures live packets from the selected network interface.

Each packet is inspected to extract important information such as source IP, destination IP, protocol, and port.

The firewall checks the packet against predefined security rules.

If a port scanning attack is detected, the system automatically blocks the attacker IP.

The dashboard logs all packet activity and security alerts.

Users can export the packet logs as a CSV report for further analysis.

# Example Packet Log
time                 src            country      dst            protocol  port  action
2026-03-17 14:22:11  10.120.24.1    Unknown      148.113.20.1   TCP       443   ALLOWED
2026-03-17 14:22:12  148.113.20.1   India        10.120.24.1    TCP       62257 ALLOWED
2026-03-17 14:22:13  208.95.11.1    United States 10.120.24.1   TCP       80    ALLOWED

# Screenshots
<img width="1251" height="848" alt="image" src="https://github.com/user-attachments/assets/7b503312-ad5e-4939-83c5-c1ba848cdf9b" />
<img width="890" height="460" alt="image" src="https://github.com/user-attachments/assets/ffc9e409-7aa9-4b6d-9f66-dcd7c7b7dda0" />



