sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
sudo /sbin/iptables-save
ping -c 2 node4
ping -c 2 node3
ping -c 2 rtr1
ping -c 2 rtr2
sudo /bin/su -c "echo '86400' > /proc/sys/net/ipv4/neigh/default/gc_stale_time"
sudo /bin/su -c "echo '86400' > /proc/sys/net/ipv4/route/gc_timeout"
arp -a
sudo route del -net 10.1.2.0 netmask 255.255.255.0 dev eth4
sudo route del -net 10.10.3.0 netmask 255.255.255.0 dev eth3
sudo route del -net 10.10.1.0 netmask 255.255.255.0 dev eth0
make router
sudo ./router