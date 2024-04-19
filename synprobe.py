from scapy.all import *
import select
import socket
import ssl
import sys
from scapy.layers.inet import TCP, IP


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


def syn_scan(ip, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        if response and TCP in response and response[TCP].flags & 0x12:  # SYN-ACK
            send(IP(dst=ip) / TCP(dport=port, flags='AR'), verbose=0)  # RST-ACK
            open_ports.append(port)
    return open_ports

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
                # print(f"Connected to {ip} on port {port} via TLS.")
                # print("SSL/TLS session established. Here are the details:")
                # print("Cipher used:", ssl_sock.cipher())
                # print("SSL version:", ssl_sock.version())
                # print("Server certificate:", ssl_sock.getpeercert())
                # ssl_sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                # data = ssl_sock.recv(1024)
                # print(data.decode('utf-8'))
                return True
    except:
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
                        return 1, data  # TCP server-initiated
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return 3, data  # HTTP server response
                sock.sendall(b"\r\n\r\n\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return 5, data  # Generic TCP server response
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
                        print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if data:
                        return 2, data  # TLS server-initiated
                    # Fall back to sending an HTTP request if no response to custom message
                    ssl_sock1.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    try:
                        data = ssl_sock1.recv(1024)
                    except socket.timeout:
                        print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if data:
                        return 4, data  # HTTPS server response

                    # Another attempt with line breaks if all else fails
                    ssl_sock1.sendall(b"\r\n\r\n\r\n\r\n")
                    try:
                        data = ssl_sock1.recv(1024)
                    except socket.timeout:
                        print(f"Timeout occurred when receiving data from {ip}:{port}")
                    if data:
                        return 6, data  # Generic TLS server response
    except Exception as e:
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
        port_type, data = probe_service(target, port)
        if port_type and data:
            print(f"Port {port}: Open\tType: {port_type}")
            print(hexdump(data))
        else:
            print(f"Port {port}: Closed")


if __name__ == "__main__":
    main()
