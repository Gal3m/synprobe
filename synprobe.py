from scapy.all import *
import select
import socket
import ssl
import sys
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
from scapy.all import getmacbyip, conf

open_ports = []
def parse_arguments():
    usage = """Usage: synprobe.py [-p port_range] target
    -p          Allows for port range specification
                Most commonly used port numbers will be used if unspecified
    port_range  The range of ports to be scanned
    <target>    A single IP address (e.g., 192.168.1.24)"""

    ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]  # Default ports
    target = ""

    if len(sys.argv) == 2:
        target = sys.argv[1]
    elif len(sys.argv) == 4 and sys.argv[1] == '-p':
        port_range = sys.argv[2]
        target = sys.argv[3]
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(port_range)]
    else:
        print(usage)
        sys.exit(1)

    return ports, target

# def syn_scan(ip, ports):
#     results = []
#     for port in ports:
#         # Crafting the SYN packet
#         packet = IP(dst=ip) / TCP(dport=port, flags='S')
#         # Sending the packet and waiting for a response
#         response = sr1(packet, timeout=1, verbose=0)
#         # Check if the response is not None and if it's a TCP packet
#         if response is not None and TCP in response:
#             # Check if the response contains SYN and ACK flags (flags=0x12 means SYN-ACK)
#             if response[TCP].flags & 0x12 == 0x12:
#                 # If SYN-ACK is received, the port is open
#                 results.append(port)
#                 # Send a RST to politely close the connection
#                 send(IP(dst=ip) / TCP(dport=port, flags='R'), verbose=0)
#     return results

def check_port(ip, port, timeout=1):
    """ Check if a single port is open on the specified IP address. """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # The connect_ex method returns 0 if the connection is successful, otherwise an error indicator
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    finally:
        sock.close()

def syn_scan(ip, ports):
    """ Scan a list of ports on a specified IP address. """
    results = []
    for port in ports:
        result = check_port(ip, port)  # Ensure we are passing a single port here, not a list
        if result:
            results.append(result)
    return results
def tls_fingerprint(ip, port):
    # Context for SSL with no certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Try to establish a socket connection
    try:
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssl_sock:
                # Perform the handshake to establish TLS connection
                ssl_sock.do_handshake()
                return True
    except Exception as e:
        #print(e)
        return False
    return False

def probe_service(ip, port):
    is_tls_port = tls_fingerprint(ip, port)
    try:
        if not is_tls_port:
            with socket.create_connection((ip, port), timeout=3) as sock:
                ready = select.select([sock], [], [], 3)
                if ready[0]:
                    data = sock.recv(1024)
                    if data:
                        return "TCP server-initiated", data  # TCP server-initiated
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if str(data).startswith("HTTP/1.1") or "html" in str(data):
                    return "HTTP server", data  # HTTP server response
                sock.sendall(b"\r\n\r\n\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return "Generic TCP server", data  # Generic TCP server response
        if is_tls_port:
            # Context for SSL with no certificate verification
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port)) as sock1:
                with context.wrap_socket(sock1, server_hostname=ip) as ssl_sock1:
                    ssl_sock1.do_handshake()
                    ssl_sock1.settimeout(3)
                    data=""
                    try:
                        data = ssl_sock1.recv(1024)
                    except socket.timeout:
                        pass#print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if data:
                        return "TLS server-initiated", data  # TLS server-initiated
                    # Fall back to sending an HTTP request if no response to custom message
                    ssl_sock1.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    try:
                        data = ssl_sock1.recv(1024)
                    except socket.timeout:
                        pass#print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if str(data).startswith("HTTP/1.1") or "html" in str(data):
                        return "HTTPS server", data  # HTTPS server response

                    # Another attempt with line breaks if all else fails
                    ssl_sock1.sendall(b"\r\n\r\n\r\n\r\n")
                    try:
                        data = ssl_sock1.recv(1024)
                    except socket.timeout:
                        pass#print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if data:
                        return "Generic TLS server", data  # Generic TLS server response
    except Exception as e:
        #print(e)
        return (None, None)
    return (None, None)

def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception as e:
        print(f"Failed to resolve IP address for {target}: {str(e)}")
        return None

def main():
    ports, target = parse_arguments()
    print(f"\n---- Scanning {target} on {len(ports)} port(s) ----")
    open_ports = syn_scan(target, ports)
    for port in open_ports:
        print(f"Port {port} is Open",end = ' ')
        port_type, data = probe_service(target, port)
        if port_type:
            print(f"\t\tType: {port_type}")
        else:
            print(f"\n")
        if data:
            print(hexdump(data))

if __name__ == "__main__":
    main()
