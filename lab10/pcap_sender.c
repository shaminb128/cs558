#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h> //hostent

#include "packet.h"
#include "packet_util.h"
#include "printp.h"

/*int generate_random_packet(u_char* packetOut, int size) {
	memset(packetOut, 0, sizeof(u_char) * 1600);
	sprintf((char*)packetOut, "here is a random packet with size %d*", size);
	int len = strlen((const char*)packetOut);
	int i;
	for (i = len; i < size; i++) {
		packetOut[i] = (u_char) (rand() & 0x000000ff);
	}
	return size;
}
*/


u_char packetOut[PACKET_BUF_SIZE];

void send_test_packet(pcap_t* handle, int testno, int packetsize, int source, int dest) {
	printf("==========> Test %d: generating packets of %d bytes...\n", testno, packetsize);
	int pktlen = generate_openflow_test_packet(packetOut, packetsize, source, dest);
	int ret = 0;
	print_data(stdout, packetOut, pktlen);
	/*printf("generating packets of 8 bytes...\n");
	generate_random_packet(packetOut, 8);*/

	if ((ret = pcap_inject(handle, packetOut, packetsize)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "==========> Test %d: DONE\n", testno);
	//sleep(1);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;
	printf("Received HELLO\n");
	print_data(stdout, (u_char*)packet, size);
}

int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available 
	int count = 0;
	int ret = 0;
	int n = 0;

	srand(time(NULL));

	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	printf("Here are the available devices:\n");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		printf("%d. %s\t-\t%s\n", count, device_ptr->name, device_ptr->description);
		if (device_ptr->name != NULL) {
			strcpy(devices[count], device_ptr->name);
		}
		count++;
	}

	printf("Which device do you want to sniff? Enter the number:\n");
	scanf("%d", &n);
	device_name = devices[n];

	printf("Trying to open device %s to send ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	printf( "DONE\n");

	pcap_loop(handle_sniffed , 3 , process_packet , NULL);

	int i;
	printf("Start to send packets...\n");
	for (i = 0; i < 20; i++) {
		send_test_packet(handle_sniffed, i, 100+i, source, dest);
	}
	



	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}



