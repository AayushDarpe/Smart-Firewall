from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_working_if
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from datetime import datetime, timedelta
import threading
import requests
import subprocess
import csv
import os

# ---------------- FIREWALL RULES ----------------
blocked_ports = [22, 23]
blocked_ips = set()

# ---------------- STATISTICS ----------------
total_packets = 0
allowed_packets = 0
blocked_packets = 0
attack_count = 0

# ---------------- STORAGE ----------------
scan_tracker = {}
attack_log = []
packet_log = []
country_cache = {}

# ---------------- SNIFF CONTROL ----------------
sniffer_thread = None
stop_sniffing = False

# ---------------- GEO LOCATION ----------------
def get_country(ip):

    if ip in country_cache:
        return country_cache[ip]

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()
        country = data.get("country", "Unknown")
    except:
        country = "Unknown"

    country_cache[ip] = country
    return country

# ---------------- WINDOWS FIREWALL BLOCK ----------------
def block_ip_firewall(ip):

    try:
        subprocess.run([
            "netsh","advfirewall","firewall","add","rule",
            f"name=Block_{ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ], capture_output=True)

    except:
        pass

# ---------------- PORT SCAN DETECTION ----------------
def detect_port_scan(src,port):

    global attack_count

    now = datetime.now()

    if src not in scan_tracker:
        scan_tracker[src] = []

    scan_tracker[src] = [
        (p,t) for p,t in scan_tracker[src]
        if now - t < timedelta(minutes=5)
    ]

    scan_tracker[src].append((port,now))

    unique_ports = len(set(p for p,t in scan_tracker[src]))

    if unique_ports > 10:

        if src not in blocked_ips:

            blocked_ips.add(src)
            attack_count += 1

            block_ip_firewall(src)

            country = get_country(src)

            attack_log.append({
                "ip":src,
                "country":country,
                "ports":unique_ports,
                "time":now.strftime("%Y-%m-%d %H:%M:%S")
            })

            alert = f"PORT SCAN DETECTED from {src} ({country})"
            log_event(alert,"alert")

            messagebox.showwarning("Firewall Alert",alert)

# ---------------- GUI ----------------
root = tk.Tk()
root.title("AI Smart Firewall Dashboard")
root.geometry("1000x650")

tk.Label(root,text="Network Interface").pack()

iface_var = tk.StringVar()

iface_combo = ttk.Combobox(root,textvariable=iface_var,width=40)
iface_combo.pack()

def load_interfaces():

    interfaces = get_if_list()
    iface_combo["values"] = interfaces

    try:
        iface_var.set(get_working_if())
    except:
        pass

load_interfaces()

stats_label = tk.Label(root,font=("Arial",12,"bold"))
stats_label.pack(pady=10)

log_box = tk.Text(root,height=20,width=120,bg="#1e1e1e",fg="white")
log_box.pack()

log_box.tag_config("allowed",foreground="lightgreen")
log_box.tag_config("blocked",foreground="red")
log_box.tag_config("alert",foreground="orange")

# ---------------- LOG EVENTS ----------------
def log_event(text,tag="allowed"):

    timestamp = datetime.now().strftime("%H:%M:%S")

    log_box.insert(tk.END,f"[{timestamp}] {text}\n",tag)
    log_box.see(tk.END)

# ---------------- DASHBOARD ----------------
def update_dashboard():

    stats = f"""
Total Packets: {total_packets}
Allowed Packets: {allowed_packets}
Blocked Packets: {blocked_packets}
Detected Attacks: {attack_count}
Blocked IPs: {len(blocked_ips)}
"""

    stats_label.config(text=stats)

# ---------------- FIREWALL ENGINE ----------------
def firewall(packet):

    global total_packets,allowed_packets,blocked_packets

    if not packet.haslayer(IP):
        return

    total_packets += 1

    src = packet[IP].src
    dst = packet[IP].dst

    protocol = "OTHER"
    port = 0

    if packet.haslayer(TCP):

        protocol = "TCP"
        port = packet[TCP].dport

    elif packet.haslayer(UDP):

        protocol = "UDP"
        port = packet[UDP].dport

    action = "ALLOWED"
    tag = "allowed"

    if src in blocked_ips or port in blocked_ports:

        action = "BLOCKED"
        tag = "blocked"
        blocked_packets += 1

    else:

        allowed_packets += 1

    detect_port_scan(src,port)

    country = get_country(src)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    packet_log.append({
        "time":timestamp,
        "src":src,
        "country":country,
        "dst":dst,
        "protocol":protocol,
        "port":port,
        "action":action
    })

    message = f"{src} ({country}) -> {dst} | {protocol}:{port} | {action}"

    log_event(message,tag)

    update_dashboard()

# ---------------- SNIFFING ----------------
def sniff_packets():

    iface = iface_var.get()

    sniff(
        iface=iface,
        prn=firewall,
        store=False,
        stop_filter=lambda x: stop_sniffing
    )

# ---------------- START ----------------
def start_sniffing():

    global sniffer_thread, stop_sniffing

    iface = iface_var.get()

    if not iface:

        messagebox.showerror("Error","Select network interface")
        return

    stop_sniffing = False

    sniffer_thread = threading.Thread(target=sniff_packets,daemon=True)
    sniffer_thread.start()

    log_event(f"Started sniffing on {iface}")

# ---------------- STOP ----------------
def stop_capture():

    global stop_sniffing
    stop_sniffing = True

    log_event("Packet capture stopped","alert")

# ---------------- CSV EXPORT ----------------
def export_csv():

    if not packet_log:

        messagebox.showwarning("No Data","No packets captured")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files","*.csv")]
    )

    if not file_path:
        return

    with open(file_path,"w",newline="",encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=["time","src","country","dst","protocol","port","action"]
        )

        writer.writeheader()
        writer.writerows(packet_log)

    messagebox.showinfo("Export Complete","Packet log exported")

    try:
        os.startfile(file_path)
    except:
        pass

# ---------------- BUTTONS ----------------
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame,text="Start Sniffing",command=start_sniffing).pack(side=tk.LEFT,padx=5)
tk.Button(btn_frame,text="Stop Capture",command=stop_capture).pack(side=tk.LEFT,padx=5)
tk.Button(btn_frame,text="Export CSV",command=export_csv).pack(side=tk.LEFT,padx=5)

update_dashboard()

root.mainloop()
