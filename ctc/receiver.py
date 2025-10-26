import sys
from scapy.all import sniff, IP, ICMP, UDP

# Configuration
expected_ip = "192.168.1.136" # Sender's IP address
delay_threshold = 0.3 # Threshold to differentiate between a '0' and a '1'
eom_port = 8888 # The unique port for the End-of-Message signal

last_packet_time = 0
binary_buffer = ""
decoded_chars = []

def decode_and_print():
    """Converts the binary buffer to characters and prints the final message."""
    global binary_buffer, decoded_chars
    
    # Process any remaining bits in the buffer
    while len(binary_buffer) >= 8:
        byte = binary_buffer[:8]
        char = chr(int(byte, 2))
        decoded_chars.append(char)
        binary_buffer = binary_buffer[8:]
    
    final_message = "".join(decoded_chars)
    print("\n--- Message received ---")
    print(f"Final decoded message: {final_message}")
    sys.exit(0)

def packet_callback(packet):
    global last_packet_time, binary_buffer
    
    # Check for the End-of-Message marker
    if packet.haslayer(UDP) and packet[UDP].dport == eom_port:
        print("\nEnd-of-Message signal received. Decoding...")
        decode_and_print()
    
    # Process normal ICMP timing packets
    if packet.haslayer(ICMP) and packet[IP].src == expected_ip:
        current_time = packet.time
        if last_packet_time != 0:
            time_diff = current_time - last_packet_time
            if time_diff < delay_threshold:
                binary_buffer += '1'
            else:
                binary_buffer += '0'
            print(f"Received bit. Current binary: {binary_buffer}")
        last_packet_time = current_time

print("Waiting for covert message...")
sniff(filter=f"(icmp or (udp and port {eom_port})) and host {expected_ip}", prn=packet_callback)

