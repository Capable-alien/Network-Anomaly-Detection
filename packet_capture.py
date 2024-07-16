#packet_capture.py
import pandas as pd
from scapy.all import *

# Replace 'Intel(R) Wi-Fi 6E AX211 160MHz' with your actual WiFi interface name
interface = 'Intel(R) Wi-Fi 6E AX211 160MHz'

# Set a filter to capture relevant traffic (adjust as needed)
capture_filter = 'tcp or udp'

# File to save captured packet data
dataset_file = 'dataset/network_traffic.csv'

# Function to handle captured packets and save to dataset file
def packet_handler(packet):
    # Extract relevant features from the packet
    if packet.haslayer(scapy.layers.inet.IP):
        src_ip = packet[scapy.layers.inet.IP].src  # Source IP address
        dst_ip = packet[scapy.layers.inet.IP].dst  # Destination IP address
        src_port = packet.sport  # Source port
        dst_port = packet.dport  # Destination port
        protocol = packet[scapy.layers.inet.IP].proto  # Protocol (TCP=6, UDP=17)

        # Save the extracted features to the dataset file
        with open(dataset_file, 'a') as f:
            f.write(f"{src_ip},{dst_ip},{src_port},{dst_port},{protocol}\n")

        # Print captured packet details (optional)
        print(f"Captured Packet - Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}, Protocol: {protocol}")

# Main function to start packet capture
def start_packet_capture(interface, capture_filter):
    print(f"Starting packet capture on interface '{interface}'...")

    try:
        # Start sniffing packets and call packet_handler for each packet
        sniff(iface=interface, filter=capture_filter, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nPacket capture stopped. Data saved to", dataset_file)

if __name__ == "__main__":
    # Start packet capture
    start_packet_capture(interface, capture_filter)
