#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "packet_util.h"


FILE* logfile;
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main (int argc, char** argv) {
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *pcap_handle = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[5][16];				// For holding all available devices

	int count = 0;
	int n = 0;
	int ret = 0;						// Return val

	if ( (logfile = fopen("packets.log", "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}

	/* Scan devices */
	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	/* Record devices starting with only "eth" */
	printf("Here is a list of ethernet devices we try to listen:\n");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		if (device_ptr->name != NULL && !strncmp(device_ptr->name, "eth", 3)){
			printf("%d. %s\t-\t%s\n", count, device_ptr->name, device_ptr->description);
			strcpy(devices[count], device_ptr->name);
			count++;
		}
	}

	printf("Trying to open device %s to sniff ... ", devices[0]);
	if ( (pcap_handle = pcap_open_live(devices[0], BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", devices[0], err);
		exit(1);
	}
	printf( "DONE\n");

	pcap_loop(pcap_handle , 10 , process_packet , NULL);	// -1 means an infinite loop






	fclose(logfile);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	char err[128];
	int size = (int) header->len;

	// Modify packet
	
	// Look for interface name char*
	// pcap_t* handle = pcap_open_live(char*, BUFSIZE, 1, 100, err)
	// pcap_inject(handle, packet, size);
	// pcap_close(handle);
}

