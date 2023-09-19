import socket, sys
from struct import *    #importing required libraries

# Description string with banner and information
desc = "\n" + r"""
""""\t\t\t""""__________              __     ____  __.                     __                        
""""\t\t\t""""\______   \____________/  |_  |    |/ _| ____   ____   ____ |  | __ ___________  ______
""""\t\t\t"""" |     ___/  _ \_  __ \   __\ |      <  /    \ /  _ \_/ ___\|  |/ // __ \_  __ \/  ___/
""""\t\t\t"""" |    |  (  <_> )  | \/|  |   |    |  \|   |  (  <_> )  \___|    <\  ___/|  | \/\___ \ 
""""\t\t\t"""" |____|   \____/|__|   |__|   |____|__ \___|  /\____/ \___  >__|_ \\___  >__|  /____  >
""""\t\t\t""""                                      \/    \/            \/     \/    \/           \/ 
""" "\n\t\t\t\tProvide Source and Destination IP as well as range of ports to scan\n\t\t\t\t\tCheck Flags using -h flag"

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

# Function for assembling the packet by packing IP/TCP headers
def assemble_packet(sourceip, destip, dest_port, scan):
    packet = '';
    # source and destination IPs
    source_ip = sourceip
    dest_ip = destip # or socket.gethostbyname('www.google.com')
    
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
    tcp_source = 4455   # source port
    tcp_dest = dest_port   # destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags for NULL scan
    tcp_fin = 0
    tcp_syn = 0
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    # tcp flags fot xmas scan
    if "xmas" in scan:
        tcp_fin = 1
        tcp_psh = 1
        tcp_urg = 1
    # TCP flags for Syn Scan
    elif "syn" in scan:
        tcp_syn = 1
    # TCP flags for fin Scan
    elif "fin" in scan:
        tcp_fin = 1
    # TCP flags for ack Scan
    elif "ack" in scan:
        tcp_ack = 1
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
    # packing TCP header
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header 
    # Getting check sum for the packet
    tcp_check = checksum(psh)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    try:
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
    except:
        return
    # final full packet - syn packets dont have any data
    # Getting the full TCP packet and returning to scan for ports
    packet = ip_header + tcp_header
    return packet