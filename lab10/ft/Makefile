receiver_n: receiver_n.o routing.o packet_util.o printp.o
	gcc -o receiver_n -g -pthread receiver_n.o packet_util.o printp.o routing.o -lpthread -lpcap
receiver_n.o: receiver_n.c ../packet.h ../printp.h ../routing.h
	gcc -g -c -Wall receiver_n.c

receiver: receiver.o routing.o packet_util.o printp.o
	gcc -o receiver -g -pthread receiver.o packet_util.o printp.o routing.o -lpthread -lpcap
receiver.o: receiver.c ../packet.h ../printp.h ../routing.h
	gcc -g -c -Wall receiver.c
	
sender_n: sender_n.o routing.o packet_util.o printp.o
	gcc -o sender_n -g -pthread sender_n.o packet_util.o printp.o routing.o -lpthread -lpcap -lrt
sender_n.o: sender_n.c ../packet.h ../printp.h ../routing.h
	gcc -g -c -Wall sender_n.c

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