import socket
from struct import *
import binascii
import psutil
from colorama import Fore, Style

def banner():
    print('''\033[92m\033[1m


                   >>> netsniffer\033[0m'''+'''\033[90m@rvizx9\033[0m


    ''')

def print_network_interfaces():
    interfaces = psutil.net_if_addrs()
    for interface, addresses in interfaces.items():
        for address in addresses:
            if address.family == 2:
                print(Fore.LIGHTGREEN_EX + interface + Style.RESET_ALL, end=": ")
                print(Fore.WHITE + address.address + Style.RESET_ALL)

def main():
    ip_address = input("Enter the IP address of the network interface: ")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((ip_address, 0))
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        packet = sock.recvfrom(65565)
        packet = packet[0]
        ip_header = packet[0:20]
        iph = unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        print(Fore.GREEN + "Version: "  + Fore.WHITE + str(version) + Fore.GREEN  + " IP Header Length: "  + Fore.WHITE + str(ihl)+ Fore.GREEN  + " TTL: " + Fore.WHITE + str(ttl) + Fore.GREEN + " Protocol: " + Fore.WHITE  + str(protocol)+ Fore.GREEN  + " Source Address: "  + Fore.WHITE + str(s_addr)+ Fore.GREEN  + " Destination Address: " + Fore.WHITE  + str(d_addr))
        tcp_header = packet[iph_length:iph_length+20]
        tcph = unpack("!HHLLBBHHH", tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        print(Fore.GREEN + "Source Port: " + Fore.WHITE  + str(source_port) + Fore.GREEN+ " Destination Port: "  + Fore.WHITE + str(dest_port)+ Fore.GREEN + " Sequence Number: " + Fore.WHITE  + str(sequence)+ Fore.GREEN + " Acknowledgement: " + Fore.WHITE  + str(acknowledgement)+ Fore.GREEN + " TCP header length: " + Fore.WHITE  + str(tcph_length))
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
        data = packet[h_size:]
        print(Fore.GREEN + "Data: "+ Fore.WHITE , data, "\n"+"\033[2m"+"______"*20+"\033[0m")
         # to output data in hex
        #hex_data = binascii.hexlify(data)
        #print(Fore.GREEN + "Data: "+ Fore.WHITE , hex_data, "\n"+"\033[2m"+"______"*20+"\033[0m")

banner()
print_network_interfaces()
main()
