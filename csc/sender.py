
import time
from scapy.all import IP, ICMP, send

def text_to_bytes(text):
    return [ord(char) for char in text]

def sender(target_ip, message):
    print("--- Scapy CSC Sender ---")
    
    # Send a start signal (IP ID = 1)
    print("Sending start signal...")
    start_packet = IP(dst=target_ip)/ICMP(id=1, seq=0)
    send(start_packet, verbose=0)
    time.sleep(1) # Wait for receiver to prepare
    
    bytes_to_send = text_to_bytes(message)
    
    for i, byte in enumerate(bytes_to_send):
        # The IP ID field is 16 bits, which is more than enough for a single ASCII character (8 bits).
        # We can put the byte directly into the IP ID field.
        packet = IP(dst=target_ip, id=byte)/ICMP(seq=i+1)
        print(f"Sending character '{chr(byte)}' ({byte}): {target_ip}/ICMP id={byte} seq={i+1}")
        send(packet, verbose=0)
        time.sleep(0.5) # Time between packets

    # Send an end signal (IP ID = 2)
    print("Sending end signal...")
    end_packet = IP(dst=target_ip)/ICMP(id=2, seq=len(bytes_to_send)+1)
    send(end_packet, verbose=0)
    print("Transmission complete.")

if __name__ == "__main__":
    target_ip = "192.168.1.74" # Change to the receiver's IP address
    secret_message = "covert"
    sender(target_ip, secret_message)
