from scapy.all import send, IP, TCP, UDP
import time

def send_tcp_packets(dst_ip, src_ips, port, count=10, delay=1):
    """
    Sends TCP packets to the destination IP from a list of source IPs.

    :param dst_ip: Destination IP address
    :param src_ips: List of source IP addresses
    :param port: Destination port
    :param count: Number of packets to send from each source IP
    :param delay: Delay (in seconds) between packets
    """
    print(f"Sending TCP packets to {dst_ip}:{port} from source IPs: {src_ips}")
    for src_ip in src_ips:
        for _ in range(count):
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=port)
            send(pkt, verbose=False)
            print(f"Sent TCP packet from {src_ip} to {dst_ip}:{port}")
            time.sleep(delay)

def send_udp_packets(dst_ip, src_ips, port, count=10, delay=1):
    """
    Sends UDP packets to the destination IP from a list of source IPs.

    :param dst_ip: Destination IP address
    :param src_ips: List of source IP addresses
    :param port: Destination port
    :param count: Number of packets to send from each source IP
    :param delay: Delay (in seconds) between packets
    """
    print(f"Sending UDP packets to {dst_ip}:{port} from source IPs: {src_ips}")
    for src_ip in src_ips:
        for _ in range(count):
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(dport=port)
            send(pkt, verbose=False)
            print(f"Sent UDP packet from {src_ip} to {dst_ip}:{port}")
            time.sleep(delay)

if __name__ == "__main__":
    # Define destination IP and source IPs
    destination_ip = "192.168.1.1"  # Replace with your test backend's IP
    source_ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "192.168.1.103"
    ]

    # Destination port
    destination_port = 80

    # Number of packets to send
    packets_per_ip = 5

    # Send TCP and UDP packets
    send_tcp_packets(destination_ip, source_ips, destination_port, packets_per_ip)
    send_udp_packets(destination_ip, source_ips, destination_port, packets_per_ip)
