# larp
The :lemon:arp software, used to do an arp poisonning attack!
Dude if you are not allowed to do arp poisonning don't use this... please
```
USAGE:  larp [-f file] [-h | -c | -s | -v | -m]

-h | --help     => show this message
-c | --cfg      => Configure %s
-s | --silent   => Silent mode
-v | --verbose  => Verbose mode
-m | --man      => man page
-f | --file     => provides the configuration file path
```

# Installation
```
git clone https://github.com/p4p1/larp.git /tmp/larp/
pip install -U /tmp/larp/
echo "DONE! installation finished
```

# Setup
Put a file in your' /tmp directory called t_ip.txt [Standing for target ip].
In it put all of the ip's you want to spoof. Then run the script as root and
with first argument the ip of your' gateway and the interface you are using
as second argument after that just let it run.

# TODO:
1. On the fly http / tcp / packet analysis
2. graphical view for .jpg files
3. TLS / SSL implementation

# Dependancies
## python packages
termcolor
arp
scapy
netifaces

# License
GNU GENERAL PUBLIC LICENSE
Version 2, June 1991

Copyright (C) 1989, 1991 Free Software Foundation, Inc.
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA


