#!/bin/sh
apt-get update
python --version
apt-get install python-simplejson python-qt4 python-twisted-conch automake autoconf gcc uml-utilities libtool build-essential
apt-get install libssl-dev openssl pkg-config
apt-get install iproute tcpdump
apt-get install linux-headers-`uname -r`
