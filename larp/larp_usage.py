import sys

def usage():
    print "%s is a script that performs an arp poisonning attack" % sys.argv[0]
    print "-" * 20
    print "Usage:"
    print "\t%s -h    => show this message" % sys.argv[0]
    print "\t%s -a [subnet_mask]  => automate the program" % sys.argv[0]
    print "\t%s -i --interface => provide the interface to use" % sys.argv[0]
    print "\t%s -g --gateway => provide the gateway to arp to" % sys.argv[0]
    print "\t%s -f --file   => provide the file of all of the target" % sys.argv[0]
    print
    print "Example:"
    print "\t%s -i wlan0 -g 192.168.1.1 -t target_ip_list.txt" % sys.argv[0]
    print "\t%s -i wlan0 -g 192.168.1.1" % sys.argv[0]
    print "\t[!] The above one will look for /tmp/t_ip.txt for the targets list"
    print
    print "\t%s" % sys.argv[0]
    print "\t[!] The above one will implicitly think that you are using wlp2s0"
    print "\t[!] for the interface and 192.168.1.1 for the gateway and using"
    print "\t[!] /tmp/t_ip.txt"
    print "-" * 20
    print "Commands:"
    print "\tl | list => list all of the ip's that are beeing arped"
    print "\ta | all => drop all on going arps"
    print "\ts | sniff => sniff a provided ip addr"
    print "\tn | nmap => nmap a provided ip addr"
    print "\tg | gtk => open a graphical sniffer for images on a provided ip addr"
    print
    print "Example:"
    print "\t#> a"
    print "\t[^] Restored: 0.0.0.0"
    print "\t#> l"
    print "\t[^] 0 => 0.0.0.0 / ff:ff:ff:ff:ff:ff"
    print "\t#> s 0"
    print "\t[^] Sniffing 0 => 0.0.0.0"
    print "\t[!] Sniffer packet stored in files 10 by 10 and it only sniffs for http"
    print "\t#> n 0"
    print "\t[nmap output]"

