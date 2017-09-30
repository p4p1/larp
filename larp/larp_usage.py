import sys, os
from termcolor import colored

def usage():
    print "\t%s -h    => show this message" % sys.argv[0]
    print "\t%s -c    => Configure %s" % (sys.argv[0], sys.argv[0])
    print "\t%s -s    => Silent mode" % (sys.argv[0])
    print "\t%s -man  => Man page" % sys.argv[0]
    print

def man():
    print colored("Presentation:", "green")
    print "\tLarp -> Leo ARP"
    print "\tThis is an arp spoofing tool build for doing a MITM attack on an"
    print "\tentire network. Larp needs to be given a list of IP's that are on"
    print "\tthe current network for him to ARP spoof them."
    print
    print colored("Usage:", "green")
    usage()
    print
    print colored("Interactive commands:", "green")
    print colored("\t-> all | a", "magenta")
    print "\t\tDisables ARP spoof on all of the targets and exits larp."
    print colored("\t-> list | l", "magenta")
    print "\t\tLists all of the current targets."
    print colored("\t-> nmap | n", "magenta")
    print "\t\tRun either a basic nmap on a target, syntax: n [id]"
    print "\t\tOr run a full nmap command, syntax: nmap -O 192.168.4.4"
    print colored("\t-> wireshark", "magenta")
    print "\t\tExecute wireshark in the background to spoof the packets that"
    print "\t\tare going through the current session."
    print colored("\t-> add", "magenta")
    print "\t\tAdd an IP to the targets that are being spoofed by Larp."
    print "\t\tsyntax: add [ip addr]"
    print colored("\t-> start", "magenta")
    print "\t\tUsed in silence mode to start the ARP spoof on all of the targets"
    print "\t\tor to update the clients that are beeing arped if a new one is added"
    print colored("\t-> kill", "magenta")
    print "\t\tcloses the program."
    print colored("\t-> ifconfig", "magenta")
    print "\t\tRuns the ifconfig command."
    print colored("\t-> [id]", "magenta")
    print "\t\tIf you enter and ID that is found in the list command, it will"
    print "\t\tstop the ARP spoof on that client"
    print colored("\t-> man", "magenta")
    print "\t\tShow this message..."
    print
    print colored("Where to find the config info?", "green")
    print colored("What is my gateway ip?", "magenta")
    print "It's the default route here, it wont work if you are not on a network"
    os.system("ip route | grep default")
    print colored("What is the interface i wish to use?", "magenta")
    print "It depends,but this tool is built for wireless network, so"
    print "I recomend using either a wlanX or wlpXXsX. replace the X by a digit."
    print "It should be writen up there next to the default gateway"
    print colored("What is an ip list?", "magenta")
    print "Thats the list of IP's you want to ARP. Create a file with an IP"
    print "on each line, you can generate it using fping -g -a if you wish."
    print colored("What is the rate per seconds of arp packets?", "magenta")
    print "This is just a number to enter of how many packets per second you want"
    print "to send on the network. I recommend 5."

