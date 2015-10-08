routing: routing.o
	gcc -g -Wall -o routing routing.o -lpcap -pthread
routing.o: routing.c routing.h packet.h
	gcc -g -c -Wall routing.c


clean:
	rm -rf *.o *.log router routing
	