import scapy.all as scapy
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import defaultdict

# Store packet counts
traffic_data = defaultdict(int)
protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

def packet_handler(packet):
    """Callback function to process captured packets."""
    if packet.haslayer(scapy.IP):
        proto = packet[scapy.IP].proto
        protocol_name = protocols.get(proto, f'Other({proto})')
        traffic_data[protocol_name] += 1

def update_plot(frame):
    """Update function for live visualization."""
    plt.cla()
    plt.title("Live Network Traffic")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    
    protocols_list = list(traffic_data.keys())
    counts = list(traffic_data.values())
    plt.bar(protocols_list, counts, color=['blue', 'red', 'green', 'purple'])
    
    for i, count in enumerate(counts):
        plt.text(i, count + 0.5, str(count), ha='center')

def start_sniffing():
    """Starts packet sniffing in a separate thread."""
    scapy.sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    print("Starting Network Traffic Visualizer...")
    
    # Start animation
    fig = plt.figure()
    ani = animation.FuncAnimation(fig, update_plot, interval=1000)
    
    # Start sniffing packets
    import threading
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    
    plt.show()
