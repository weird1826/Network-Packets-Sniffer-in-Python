from scapy.all import *
import tkinter as tk
from tkinter import ttk
import threading
import asyncio

def get_protocol_name(protocol_number):
    protocol_list = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS"
    }
    return protocol_list.get(protocol_number, f"Unknown ({protocol_number})")

def packet_analyzer(packet):
    if packet.haslayer(Ether):
        if packet.haslayer(IP):
            protocol_num = packet[IP].proto
            protocol_name = get_protocol_name(protocol_num)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # payload = packet.payload
            if packet.haslayer(DNS):
                protocol_name = "DNS"
                payload = packet[DNS].summary()
            elif packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                if sport == 80 or dport == 80:
                    protocol_name = "HTTP"
                    payload = packet[TCP].summary()
                elif sport == 443 or dport == 443:
                    protocol_name = "HTTPS"
                    payload = packet[TCP].summary()
                else:
                    payload = packet[TCP].summary()
            elif packet.haslayer(UDP):
                payload = packet[UDP].summary()
            else:
                payload = packet.payload
            packet_info_table.insert("", "end", values=(protocol_name, src_ip, dst_ip, payload))

def sniffing_start():
    while not stop_sniffing_process.is_set():
        sniff(prn=packet_analyzer, stop_filter=lambda x: stop_sniffing_process.is_set(), timeout=1)

def start_onclick():
    global sniff_thread
    if sniff_thread is None or not sniff_thread.is_alive():
        stop_sniffing_process.clear()
        # sniff_thread = threading.Thread(target=asyncio.run, args=(sniffing_start(),))
        sniff_thread = threading.Thread(target=sniffing_start)
        sniff_thread.start()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
    

def stop_onclick():
    stop_sniffing_process.set()
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

root = tk.Tk()
root.title("Packet Sniffer")

columns = ("Protocol", "Source IP", "Destination IP", "Payload")

packet_info_table = ttk.Treeview(root, columns=columns, show="headings", selectmode="browse")
for col in columns:
    packet_info_table.heading(col, text=col)
    packet_info_table.column(col, width=150, stretch=True)

style = ttk.Style()
style.configure("Treeview", rowheight=20)

packet_info_table.pack(fill=tk.BOTH, expand=True)

start_button = tk.Button(root, text="Start Sniffing", command=start_onclick)
start_button.pack(side=tk.LEFT, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_onclick)
stop_button.pack(side=tk.LEFT, padx=10, pady=10)

stop_sniffing_process = threading.Event()
sniff_thread = None

stop_button.config(state=tk.DISABLED)
start_button.config(state=tk.NORMAL)

root.mainloop()