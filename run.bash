#!/bin/bash
# bash script to automate larp
# Made by papi

BEGIN_IP=192.168.1.1
END_IP=192.168.1.255
GATEWAY=192.168.1.1

exec 3>&2
exec 2> /dev/null

if [ $UID -ne "0" ]; then

    echo "Not running as root"
    exit

fi

fping -g -a $BEGIN_IP $END_IP > /tmp/t_ip.txt
exec 2>&3
python larp.py -g $GATEWAY
