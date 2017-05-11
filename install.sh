#!/bin/sh

cd modules/
python2 -c "import $ARP, $SNIFFER"
mv *.pyc ..

