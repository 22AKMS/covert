from scapy.all import sniff, IP, ICMP

message_bytes = []
is_receiving = False

def handle_packet(packet):
    """Callback function to process each sniffed packet."""
    global is_receiving, message_bytes
    
    # Check if the packet has an IP and ICMP layer
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        ip_id = packet[IP].id
        icmp_seq = packet[ICMP].seq

        if ip_id == 1 and icmp_seq == 0:
            # Start signal
            is_receiving = True
            print("\n--- Scapy CSC Receiver ---")
            print("Start signal received. Listening for data...")
            message_bytes = []
        elif ip_id == 2:
            # End signal
            is_receiving = False
            print("End signal received.")
            print("All packets captured. Decoding message...")
            
            decoded_message = "".join([chr(byte) for byte in message_bytes])
            print(f"Decoded message: {decoded_message}")
        elif is_receiving:
            # Data packet
            message_bytes.append(ip_id)
            print(f"Received data packet: IP ID = {ip_id} (Char: '{chr(ip_id)}')")

def receiver():
    print("--- Scapy CSC Receiver ---")
    print("Sniffing for ICMP packets. Waiting for sender...")
    
    # Filter for ICMP packets and run indefinitely
    # prn=handle_packet specifies the callback function for each packet
    # store=0 disables storing packets in memory
    # You might need to adjust the interface with `iface='eth0'`
    sniff(filter="icmp", prn=handle_packet, store=0)

if __name__ == "__main__":
    receiver()
