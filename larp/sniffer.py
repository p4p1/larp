import os, sys
import urllib

from scapy.all import *
from termcolor import colored

class sniffer():
    def __init__(self, iface, target=None, path='/tmp/', dbg=False):
        # -- Get victim info --
        self.interface = iface
        self.target = target
        self.data_path = path + "sniffer_data/"
        self.img_path = path + "sniffed_images/"
        # -- setup up directory structure --
        if not os.path.exists(self.data_path) and target is not None:
            os.makedirs(self.data_path)
        # -- other --
        self.dbg = dbg

    def sniff(self, filter_str):
        ''' sniff for http trafic on particular host '''
        bpf_filter = filter_str
        f_i = 0
        while True:
            packets = sniff(filter=bpf_filter, iface=self.interface, count=10)
            wrpcap(self.data_path+'%d.cap' % (f_i), packest)
            f_i += 1

    def img_extractor(self, pack):
        http_packet = str(pack)
        if http_packet.find('GET') != -1 and \
          (http_packet.find('.jpg') != -1 or http_packet.find(".png") != -1 or \
          http_packet.find('.jpeg') != -1 or http_packet.find('.gif') != -1):
            ret = "\n".join(pack.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
            url = "http://" + str(str(pack[IP].dst) + ret[ret.find("GET")+4:ret.find("HTTP")])
            if self.dbg:
                print url
            urllib.urlretrieve(url, self.img_path + url[url.rfind('/')+1:])

    def img_sniff(self):
        ''' image sniffer function '''
        if not os.path.exists(self.img_path):
            os.makedirs(self.img_path)
        while True:
            sniff(iface=self.interface, prn=self.img_extractor, filter="tcp port 80")

if __name__ == "__main__":
        s = sniffer('en1', dbg=True)
        s.img_sniff()
