from scapy.all import sniff, IP, TCP, UDP
import datetime

def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if protocol == 6:  # TCP
            protocol_name = "TCP"
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
        else:
            protocol_name = "Other"

        print(f"[{timestamp}] {protocol_name} Packet: {ip_src} -> {ip_dst}")
        
        # Additional analysis can be done here (e.g., flagging suspicious activities)
        # For example:
        # if protocol == 6 and packet[TCP].flags == 2:  # SYN flag
        #     print(f"Suspicious activity detected from {ip_src} to {ip_dst} (SYN scan)")

# Start sniffing
sniff(prn=packet_callback, store=0)
