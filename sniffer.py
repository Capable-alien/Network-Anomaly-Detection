import joblib
import numpy as np
from scapy.all import *
from datetime import datetime

# Load trained model and label encoder
model_file = 'saved_models/iso_forest_model.joblib'
encoder_file = 'saved_models/label_encoder.joblib'

try:
    model = joblib.load(model_file)
    label_encoder = joblib.load(encoder_file)
except Exception as e:
    print(f"Error loading model: {e}")
    exit()

def real_time_detection(packet):
    try:
        if scapy.layers.inet.IP in packet:
            src_ip = packet[scapy.layers.inet.IP].src
            dst_ip = packet[scapy.layers.inet.IP].dst
            src_port = packet.sport
            dst_port = packet.dport
            timestamp = datetime.now().timestamp()
            flags = packet[scapy.layers.inet.TCP].flags if scapy.layers.inet.TCP in packet else 0

            try:
                src_ip_encoded = label_encoder.transform([src_ip])[0] if src_ip in label_encoder.classes_ else -1
                dst_ip_encoded = label_encoder.transform([dst_ip])[0] if dst_ip in label_encoder.classes_ else -1

                features = np.array([src_ip_encoded, dst_ip_encoded, src_port, dst_port, timestamp, int(flags)]).reshape(1, -1)
                prediction = model.predict(features)

                with open('sniffed_data.txt', 'a') as file:
                    file.write(f"{timestamp},{1 if prediction == -1 else 0}\n")  # Write anomaly or normal timestamp

            except ValueError as ve:
                print(f"Error processing packet: {ve}")
    except Exception as e:
        print(f"Error processing packet: {e}")

def sniff_packets(interface, capture_filter):
    sniff(iface=interface, filter=capture_filter, prn=real_time_detection, store=0)

if __name__ == "__main__":
    interface = 'Intel(R) Wi-Fi 6E AX211 160MHz'  # Replace with your interface name
    capture_filter = 'tcp or udp'  # Adjust filter as needed
    sniff_packets(interface, capture_filter)
