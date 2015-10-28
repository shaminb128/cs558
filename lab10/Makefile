router: router.o routing.o printp.o packet_util.o
	gcc -g -Wall -o router router.o routing.o printp.o packet_util.o -lpthread -lpcap
routing: routing.o
	gcc -g -Wall -o routing routing.o
packet_test: packet_test.o routing.o printp.o packet_util.o
	gcc -g -Wall -o packet_test packet_test.o routing.o printp.o packet_util.o

router.o: router.c packet.h printp.h routing.h packet_util.h
	gcc -g -c -Wall router.c
routing.o: routing.c routing.h packet.h
	gcc -g -c -Wall routing.c
printp.o: printp.c packet.h printp.h packet_util.h
	gcc -g -c -Wall printp.c
packet_util.o: packet_util.c packet.h packet_util.h printp.h
	gcc -g -c -Wall packet_util.c
packet_test.o: packet_test.c packet.h packet_util.h printp.h routing.h
	gcc -g -c -Wall packet_test.c

clean:
	rm -rf *.o *.log router routing packet_test
	