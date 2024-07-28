from flask import Flask, jsonify, request
import scapy.all as scapy
import numpy as np
from sklearn.ensemble import IsolationForest
import subprocess

app = Flask(__name__)

def get_wifi_profiles():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, check=True)
        output = result.stdout
        profiles = [line.split(":")[1].strip() for line in output.split('\n') if "All User Profile" in line]
        return profiles
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []

def capture_packets(interface, duration):
    try:
        packets = scapy.sniff(iface=interface, timeout=duration)
        return packets
    except OSError as e:
        print(f"Error: {e}")
        return []

def extract_features(packets):
    features = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            mac_src = packet[scapy.Ether].src
            mac_dst = packet[scapy.Ether].dst
            length = len(packet)
            features.append([src_ip, dst_ip, mac_src, mac_dst, length])
    return features

def analyze_behavior(features):
    if not features:
        return []

    data = np.array([f[4] for f in features])  # Use packet length as a simple feature
    if data.size == 0:
        return []

    data = data.reshape(-1, 1)
    
    clf = IsolationForest(contamination=0.01)
    clf.fit(data)
    predictions = clf.predict(data)
    
    anomalies = [features[i] for i in range(len(predictions)) if predictions[i] == -1]
    return anomalies

@app.route('/scan', methods=['POST'])
def scan_network():
    interface = "Ethernet"  # Adjust as needed
    duration = 60  # Capture duration in seconds
    packets = capture_packets(interface, duration)
    features = extract_features(packets)
    anomalies = analyze_behavior(features)
    
    result = []
    for anomaly in anomalies:
        result.append({
            "source_ip": anomaly[0],
            "destination_ip": anomaly[1],
            "source_mac": anomaly[2],
            "destination_mac": anomaly[3],
            "length": anomaly[4]
        })
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
