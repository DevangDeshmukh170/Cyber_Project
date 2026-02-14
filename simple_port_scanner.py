import socket

def scan_ports(target, start_port, end_port):
    print(f"\nScanning target: {target}")
    print(f"Port range: {start_port} - {end_port}\n")

    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((target, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports


if __name__ == "__main__":

    target_ip = input("Enter target IP address: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    open_ports = scan_ports(target_ip, start_port, end_port)

    print("\nOpen ports:")
    if open_ports:
        for port in open_ports:
            print(f"Port {port} is OPEN")
    else:
        print("No open ports found.")