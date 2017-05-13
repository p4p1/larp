import os, sys

from scapy.all import *
from termcolor import colored

class sniffer():
    def __init__(self, iface, target, path='/tmp/'):
        # -- Get victim info --
        self.interface = iface
        self.target = target
        self.data_path = path + "larp_%s/"
        # -- setup up directory structure --
        if not os.path.exists(self.data_path):
            os.makedirs(self.data_path)

    def sniffer(self, target_ip):
        ''' sniff for http trafic on particular host '''
        bpf_filter = "ip host %s" % target_ip
        f_i = 0
        while True:
            packets = sniff(filter=bpf_filter, iface=self.interface, count=1)
            wrpcap('/tmp/larp_%s/larp_sniffer_%s_%d.cap' % (target_ip, target_ip, f_i), packest)
            f_i += 1

    def img_sniff(self):
        ''' image sniffer function '''
        sniff(iface=self.interface, prn=win.http_header, filter="tcp port 80")

