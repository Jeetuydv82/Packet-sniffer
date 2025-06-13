from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def process_packet(packet):
    print(f"\n--- Packet Captured at {datetime.now().strftime('%H:%M:%S')} ---")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} --> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport} | Dest Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport} | Dest Port: {udp_layer.dport}")

        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load.decode("utf-8", errors="replace")
                print(f"Payload:\n{raw_data}")
            except Exception:
                print("Payload: (Could not decode raw data)")

def start_sniffing():
    print("=== Packet Sniffer Started (Press Ctrl+C to stop) ===")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
