all: route_lib

route_lib: route_lib.o route.o arp.o
	gcc -g -Wall -lpcap -o route_lib route_lib.o route.o arp.o
	
route_lib.o: route_lib.c route.h
	gcc -g -c -Wall -lpcap route_lib.c
	
route.o: route.c route.h
	gcc -g -c -Wall route.c

arp.o: arp.c
	gcc -c -Wall arp.c		

clean:
	rm -f *.o arp pcap route

