#! /usr/bin/python

from scapy.all import *
from optparse import OptionParser
from scapy.utils import PcapWriter
import netifaces


# https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
class DNSDetect:
    def __init__(self, interface, pcap_file, expression):
        self.interface = interface

        if self.interface is None:
            interfaces = netifaces.interfaces()
            interfaces.remove("lo")
            self.interface = str(interfaces[0])
        self.pcap_file = pcap_file
        self.expression = expression
        self.pcap_dump = PcapWriter(self.pcap_file, append=True, sync=True)

    def start_detection(self):
        packets = []
        def callback(packet):
            if packet.haslayer(DNS) and packet.haslayer(DNSRR) and packet[DNS].qr == 1:
                for prev_packet in packets:
                    if prev_packet[DNS].id  == packet[DNS].id and \
                    packet[DNS].qd.qname == prev_packet[DNS].qd.qname and\
                    packet[1][DNSRR].rdata != prev_packet[1][DNSRR].rdata:
                        print "Spoofing detected"
                        print packet.summary()
                        self.pcap_dump.write(packet)
                packets.append(packet)


        sniff(
            filter=self.expression,
            prn=callback,
            store=0,
            iface=self.interface
        )


if __name__ == '__main__':
    optparser = OptionParser()
    optparser.set_conflict_handler("resolve")
    optparser.add_option("-i", "--interface", dest="interface", help="interface")
    optparser.add_option("-r", "--pcapfile", dest="pcapfile", help="read from trace file")

    (options, args) = optparser.parse_args()
    expression = " ".join(args)

    dnsdetect = DNSDetect(options.interface,
                          options.pcapfile,
                          expression
                          )

    dnsdetect.start_detection()
