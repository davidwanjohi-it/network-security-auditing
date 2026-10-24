"""
================================================================================
SCRIPT OBJECTIVE: SECURE LAB INTERCEPTION AUTOMATION
================================================================================
This script automates the orchestration of network diagnostics, deep packet 
inspection, and secure protocol testing within an isolated virtualization lab.

Key Engineering Skills Demonstrated:
1. Systems Automation: Programmatic handling of network sockets and packet capture interfaces.
2. Event-Driven Logic: Real-time traffic analysis and validation loops using Scapy.
3. Resource Management: Context-safe environment setup and graceful process closure.
================================================================================
"""

import os
import sys
import time
from scapy.all import sniff, ICMP, IP, ARP

# Core Network Constants
INTERFACE = "eth0"         # Primary NAT Network interface
TARGET_IP = "10.0.2.3"      # Windows 10 Victim Node IP

def verify_privileges():
    """Ensures the automation script is executed with root network permissions."""
    if os.geteuid() != 0:
        print("[!] Execution Error: This automation suite requires administrative privileges.")
        print("    Please re-run using: sudo python3 lab_automation.py")
        sys.exit(1)

def network_callback(packet):
    """Event handler that automatically parses captured network traffic frames."""
    # 1. Automated Detection of ICMP (Ping) Traffic
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src = packet[IP].src
        dst = packet[IP].dst
        if packet[ICMP].type == 8:
            print(f"   [➔ TRAFFIC LOG] Ping Request: {src} -> {dst}")
        elif packet[ICMP].type == 0:
            print(f"   [✔ TRAFFIC LOG] Ping Reply:   {dst} -> {src}")

    # 2. Automated Intrusion Detection (Unsolicited ARP Reply Mapping)
    elif packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc
        # Automatically flag anomaly if an unknown machine broadcasts gateway properties
        if sender_ip == "10.0.2.1" and "00:21:5e" not in sender_mac.lower():
            print(f"\n   [!!! AUTOMATED ALERT !!!] Suspicious ARP mapping detected!")
            print(f"   Gateway 10.0.2.1 claimed by unrecognized MAC address: {sender_mac}\n")

def run_automation_pipeline():
    """Orchestrates the active packet filtering and auditing runtime."""
    print("=" * 80)
    print("         AUTOMATED NETWORK INSPECTION & DEEP PACKET AUDITING ENGINE         ")
    print("=" * 80)
    print(f"[*] Initializing network monitor on interface: {INTERFACE}")
    print(f"[*] Monitoring live communication profiles for node: {TARGET_IP}")
    print("[*] Press Ctrl+C to cleanly stop the automation loop and exit.\n")
    
    try:
        # Start passive network inspection engine
        # filter="icmp or arp" reduces processor overhead via BPF tokenizing
        sniff(iface=INTERFACE, filter="icmp or arp", store=0, prn=network_callback)
    except KeyboardInterrupt:
        print("\n[*] Graceful shutdown initiated. Releasing network interface controls...")
        print("[*] Automation run completed successfully.")
        print("=" * 80)

if __name__ == "__main__":
    verify_privileges()
    run_automation_pipeline()
