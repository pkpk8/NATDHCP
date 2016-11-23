import socket
SERVER_IP2 = "10.0.0.110"
SERVER_CONTROLLER_PORT = 5560

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.connect((SERVER_IP2, SERVER_CONTROLLER_PORT))
s.send("hello")
s.close()
