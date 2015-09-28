router: router.o packet_util.o
	gcc -g -Wall -o router router.o packet_util.o -lpcap 
pcaptest: pcaptest.o
	gcc -g -Wall -o pcaptest pcaptest.o -lpcap

router.o: router.c
	gcc -g -Wall -c router.c
pcaptest.o: pcaptest.c
	gcc -g -Wall -c pcaptest.c
packet_util.o: packet_util.c packet_util.h
	gcc -g -Wall -c packet_util.c
	
route_lib: route_lib.o route.o arp.o
	gcc -g -Wall -lpcap -o route_lib route_lib.o route.o arp.o
	
route_lib.o: route_lib.c route.h
	gcc -g -c -Wall -lpcap route_lib.c
	
route.o: route.c route.h
	gcc -g -c -Wall route.c

arp.o: arp.c
	gcc -c -Wall arp.c
clean:
	rm -rf *.o router pcaptest