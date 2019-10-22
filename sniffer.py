import dpkt
from scapy.all import *

import ja3


def start_sniffing(interface="lo0"):
    # unlimited packet capture
    print("sniff")
    sniff(iface=interface, prn=ja3.process_ssl, filter="tcp port 4443")



if __name__ == "__main__":
    start_sniffing()
