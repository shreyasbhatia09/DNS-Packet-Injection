#! /usr/bin/python

from scapy.all import *
from optparse import OptionParser
import socket
import netifaces

class DNSDetect:
    def __init__(self, interface, pcap_file, expression):
        self.interface = interface

        if self.interface is None:
            interfaces = netifaces.interfaces()
            interfaces.remove("lo")
            self.interface = str(interfaces[0])
        self.pcap_file = pcap_file
        self.expression = expression

    def start_detection(self):
        packets = []
        def callback(packet):
            if  packet.haslayer(DNS) and packet.haslayer(DNSRR):
                if packet in packets:
                    pass

        sniff(
            filter=self.expression,
            prn=callback,
            store=0,
            iface=self.interface
        )

    def get_local_ip(self):
            # return "127.0.0.1"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]

if __name__ == '__main__':
    optparser = OptionParser()
    optparser.set_conflict_handler("resolve")
    optparser.add_option("-i", "--interface", dest="interface", help="interface")
    optparser.add_option("-r", "--pcapfile", dest="pcapfile", help="read from trace file")

    (options, args) = optparser.parse_args()
    expression = " ".join(args)

