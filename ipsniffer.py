from scapy.all import *
from scapy.layers.inet import IP, TCP
import time , sys ,os
#COLORS============#
blue = '\033[94m'  #
green = '\033[32m' #
red = '\033[91m'   #
w = '\033[0m'      #
#==================#
os.system("cls")
print(green + "Starting.........." + "\n")
print(w+"\npress"+blue+" double Ctrl+c"+w+" To Stop....\n" + red)
time.sleep(3)
def print_summary(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport
        time.sleep(1)
        print(red + "IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
        print(green + "IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))
        print("")
    if ((pkt[IP].src == "192.168.0.1") or (pkt[IP].dst == "192.168.0.1")):
        print("[!]")
try:
    sniff(filter="ip", prn=print_summary)
    sniff(filter="ip and host 192.168.0.1", prn=print_summary)
    if KeyboardInterrupt:
        print(blue+"exiting...!")
        print(w+"")
        sys.exit()
except:
    pass
