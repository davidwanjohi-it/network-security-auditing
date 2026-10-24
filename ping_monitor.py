"""
================================================================================
SCRIPT OBJECTIVE
================================================================================
The objective of the ping_monitor.py script is to act as a lightweight, 
passive network intrusion detection filter (IDS). It verifies that the 
virtual network interfaces are operating correctly and monitors the traffic 
pattern across the isolated NAT network segment.

Specifically, it achieves three goals:
1. Confirms Live Traffic Visibility: It proves that your Kali Linux VM can 
   interact directly with the shared network layer and intercept raw packets 
   sent by other machines (like your Windows 10 VM).
2. Performs Deep Packet Inspection (DPI): It opens the data frames moving over 
   the network cable, identifies ICMP packets (the protocol used by ping), and 
   separates them into "Requests" and "Replies" based on their protocol header 
   type codes.
3. Logs Source & Destination Trails: It extracts the exact IP addresses of the 
   Communication endpoints in real-time, providing immediate visual proof that 
   your network connections are bridged properly.
================================================================================
"""

# Import the required module classes from Scapy
# 'sniff' intercepts live packets, 'ICMP' isolates ping events, 'IP' reads address headers
from scapy.all import sniff, ICMP, IP

def process_packet(packet):
    """
    Callback function executed automatically for every packet captured on the wire.
    """
    # Verify that the captured frame contains both an IP layer and an ICMP network layer
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        
        # Extract the source and destination IP addresses from the network layer headers
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # ICMP Code Type 8 represents an inbound Echo Request (Ping Request)
        if packet[ICMP].type == 8:
            print(f"[➔] PING REQUEST: {src_ip} is pinging {dst_ip}")
            
        # ICMP Code Type 0 represents an outbound Echo Reply (Ping Response)
        elif packet[ICMP].type == 0:
            print(f"[✔] PING REPLY:   {dst_ip} responded to {src_ip}")

# Print initial telemetry banner to the terminal console
print("[*] Actively monitoring the NAT Network for ping traffic... Press Ctrl+C to stop.")

# Initialize the Scapy sniffing engine
# 'filter="icmp"' locks packet capturing strictly to ping traffic to maximize efficiency
# 'store=0' prevents memory bloat by processing packets instantly without saving logs to RAM
# 'prn=process_packet' binds our custom callback loop to handle every captured frame
sniff(filter="icmp", store=0, prn=process_packet)
