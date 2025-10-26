import time
from scapy.all import *

# Configuration
target_ip = "192.168.1.74"  # Receiver's IP address
message_to_send = "covert " # leave an empty space at the end
delay_short = 0.1  # Delay for a '1' bit in seconds
delay_long = 0.5   # Delay for a '0' bit in seconds
eom_port = 8888  # A unique port for the End-of-Message signal

# Convert the message to binary
def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

binary_message = string_to_binary(message_to_send)
print(f"Sending message: {message_to_send} ({binary_message})")

# Craft and send packets with timing delays
for bit in binary_message:
    ip_packet = IP(dst=target_ip)
    icmp_packet = ICMP()
    send(ip_packet/icmp_packet, verbose=False)
    
    if bit == '1':
        print("Sending '1'...")
        time.sleep(delay_short)
    else:
        print("Sending '0'...")
        time.sleep(delay_long)

# Send the End-of-Message packet
send(IP(dst=target_ip)/UDP(dport=eom_port)/"EOM", verbose=False)
print("Message sent.")
