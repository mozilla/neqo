import socket

HOST = '127.0.0.1'  # Listen on all interfaces
PORT = 12345      # Arbitrary non-privileged port

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    server_socket.bind((HOST, PORT))
    print(f"UDP Echo Server listening on {HOST}:{PORT}")
    while True:
        data, addr = server_socket.recvfrom(1024)
        print(f"Received from {addr}: {data.decode()}")
        server_socket.sendto(data, addr)