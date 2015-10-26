#!/bin/sh
./boot.sh
tc
./configure  \
  --prefix=/usr   \
  --bindir=/usr/bin   \
  --sbindir=/usr/sbin   \
  --sysconfdir=/etc   \
  --localstatedir=/var   \
  --libdir=/usr/lib   \
  --includedir=/usr/include   \
  --datarootdir=/usr/share    \
  --with-linux=/lib/modules/`uname -r`/build
make
make install
modprobe libcrc32c
modprobe crc32c
insmod datapath/linux/openvswitch.ko
modinfo datapath/linux/openvswitch.ko
make modules_install
