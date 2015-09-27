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

clean:
	rm -rf *.o router pcaptest