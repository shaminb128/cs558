receiver: receiver.o routing.o packet_util.o printp.o
	gcc -o receiver -g -pthread receiver.o packet_util.o printp.o routing.o -lpthread -lpcap
receiver.o: receiver.c ../packet.h ../printp.h ../routing.h
	gcc -g -c -Wall receiver.c

sender: sender.o routing.o packet_util.o printp.o
	gcc -o sender -g -pthread sender.o packet_util.o printp.o routing.o -lpthread -lpcap -lrt
sender.o: sender.c ../packet.h ../printp.h ../routing.h
	gcc -g -c -Wall sender.c
routing.o: ../routing.c ../routing.h ../packet.h
	gcc -g -c -Wall ../routing.c
packet_util.o: ../packet_util.c ../packet.h ../packet_util.h 
	gcc -g -c -Wall ../packet_util.c
printp.o: ../printp.c ../packet.h ../printp.h ../packet_util.h
	gcc -g -c -Wall ../printp.c

clean:
	rm -f *.o sender receiver