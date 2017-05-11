import os, sys
import getopt
import larp_main

from termcolor import colored

interface = None
gateway = None
target_file = None

if os.geteuid() != 0:
    print >> sys.stderr, colored("[!] RUN THE PROGRAM AS ROOT!", "red")
    larp_main.usage()
    sys.exit(-1)

try:
    optlist, args = getopt.getopt(sys.argv[1:], "ha:ig:f:",\
        ["help", "auto", "interface", "gateway", "file"])
except:
    print >> sys.stderr, colored("[!] YOU DID NOT PROVIDE THE GOOD NUMBER OF ARGUMENTS:\n%s" % str(getopt.GetoptError), 'red')
    larp_main.usage()
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
    interface = "en1"
if not gateway:
    gateway = "192.168.1.1"
if not target_file:
    target_file = "/tmp/t_ip.txt"

#----------------------------------------

ls = larp_main.larp(gateway, interface, target_file)
ls.main()
