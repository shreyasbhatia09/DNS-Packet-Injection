# !/usr/bin/env python
# title           : dnsdetect.py
# description     : script to inject dns packets
# author          : Shreyas Bhatia
# date            : Dec 9th 2017
# usage           : python dnsdetect.py -h [hostnames] -i [interface]
# notes           :
# python_version  :2.7
# ==============================================================================

# Imports!
from scapy.all import *
from optparse import OptionParser
import netifaces
import time
import datetime


# References
# https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file

class DNSDetect:
    def __init__(self, interface, pcap_file, expression):
        self.interface = interface
        # Get default interface if not given
        if self.interface is None:
            interfaces = netifaces.interfaces()
            interfaces.remove("lo")
            self.interface = str(interfaces[0])
        self.pcap_file = pcap_file
        self.expression = expression

    # Begin detection.
    def start_detection(self):
        packets = []

        # Callback for the packet sniffer
        def callback(packet):
            if packet.haslayer(DNS) and packet.haslayer(DNSRR) and packet[DNS].qr == 1:
                for prev_packet in packets:
                    if prev_packet[DNS].id == packet[DNS].id and \
                                    packet[DNS].qd.qname == prev_packet[DNS].qd.qname:

                        # Checking for the list of responses from the dns query.
                        # The responses should be the same if its not spoofed

                        rdata_pack = [packet[DNS].an[i].rdata
                                      for i in range(packet[DNS].ancount)
                                      if packet[DNS].an[i].type == 1]

                        rdata_prev_pack = [prev_packet[DNS].an[i].rdata
                                           for i in range(prev_packet[DNS].ancount)
                                           if prev_packet[DNS].an[i].type == 1]

                        intersection = set(rdata_pack).intersection(rdata_prev_pack)
                        # If there are conflicing IP's then we detect a spoof attack
                        if intersection == set([]):
                            ts = time.time()
                            msg = datetime.datetime.fromtimestamp(ts).strftime(
                                "%Y%m%d %H:%M:%S.%f") + " DNS poisoning attempt" \
                                  + "\n" + \
                                  "TXID " + str(packet[DNS].id) + " Request " + str(packet[DNS].qd.qname.rstrip('.')) \
                                  + "\n" + \
                                  "Answer1  " + str(rdata_pack) \
                                  + "\n" + \
                                  "Answer2 " + str(rdata_prev_pack)
                            print msg
                            return
                packets.append(packet)

        # Callback ends here

        # Let the sniffing begin!
        if self.pcap_file is not None:
            sniff(
                offline=self.pcap_file,
                filter=self.expression,
                prn=callback,
                store=0,
                iface=self.interface
            )
        else:
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

    dns_detect = DNSDetect(options.interface,
                           options.pcapfile,
                           expression
                           )
    print "Starting DNS Spoof attack detection"
    dns_detect.start_detection()
