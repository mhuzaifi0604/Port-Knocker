# Muhammad Huzaifa
# 20i0604
# Port Scanner
# Networks and Cyber II

from scapy.all import *         # importing
from termcolor import colored   # Libraries
import argparse                 # and
import socket, sys              # Header Files
from struct import *
import time
import Asembler
import threading

# Taking Arguments from user on command line
print(colored(Asembler.desc, 'red', attrs=['bold']))
parser= argparse.ArgumentParser(Asembler.desc)
parser.add_argument("-sip", "--sourceIP", help= "Provide the source IP Address")
parser.add_argument("-dip", "--destIP", help= "Provide the Destination IP Address")
parser.add_argument("-l", "--LowerRange", help= "Provide starting range for port scanning")
parser.add_argument("-u", "--UpperRange", help= "Provide ending range for port scanning")
parser.add_argument("-scan", "--SCAN", help = "Enter Scan Type")
args = parser.parse_args()
closed = []
# Creating a raw socket for packet transfer
try:
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)#Creating a Raw Socket
except:
    # Printing errors and exiting while creating sockets
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit() 
print("Socket Created Successfully")

# Function for catching all the responses against port requests
def reciever(packet):
    if int(packet[TCP].sport) != 4455:
        # Just sniff the closed ports packets
        closed.append(packet[TCP].sport)
        # Stop sniffing packets after the argument upper range
        if (packet[TCP].sport >= int(args.UpperRange)):
            sys.exit()# exiting the port scanning


# Function for sniffing packets coming on your local host
def response_catcher():
    print(f"[+] scanning Ports {args.LowerRange} - {args.UpperRange}")
    capture = sniff(iface='eth0',prn=reciever, store=0)# Calling reciever for Port scan
    capture.summary()# Contains Summary for all the packets captured

# creating and starting a thread for catching responses
thread = threading.Thread(target=response_catcher).start()
time.sleep(2)
sent = 0

print(colored(f"[+] - Scanning through {args.SCAN} Scan type", 'green'))
for ports in range(int(args.LowerRange),int(args.UpperRange)+1):
    time.sleep(1)
    #Calling assemble_packet function to return custom made packet
    packet = Asembler.assemble_packet(args.sourceIP, args.destIP, ports, args.SCAN)
    try:
        #Sending the packets to destination IP
        sniffer.sendto(packet, (args.destIP, 0))
        #print(f"packet no {sent} sent."); sent+=1
    except:
        #print(f"packet no {sent} not sent.\n"); sent+=1
        closed.append(ports)# Appending port no if the port is closed
        pass


print("\n--------- Printing Closed and open ports in range ---------\n")
# Printing result of Port scanning
for ports in range(int(args.LowerRange), int(args.UpperRange)+1):
    if ports in closed:# checking closed list for closed ports
        #printing the closed ports
        print(f" [-] - Port {colored(str(ports), 'yellow')}  ▶️  " + colored("[ Closed ]", 'red'))
    else:
        #printing open ports
        print(f" [+] - Port {colored(str(ports), 'yellow')}  ▶️  " + colored("[ Open ]", 'green'))
