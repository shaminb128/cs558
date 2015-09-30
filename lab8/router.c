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

#include <pthread.h>

#include "route.h"
#include "packet_util.h"
#include "router_util.h"


typedef struct sniff {
	char dev_name[50];
	char dev_ip[20];
	FILE* logfile;

}sniff_t;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void sniffer(void*);

int main (int argc, char** argv) {
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device

	char err[128];						// Holds the error
	char devices[5][20];				// For holding all available devices
	char device_ips[5][20];

	int count = 0;
	int n = 0;
	int i = 0;
	int ret = 0;						// Return val

	ret = createRT();

	/* Scan devices */
	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	/* Record devices starting with only "eth" */
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		if (device_ptr->name != NULL && !strncmp(device_ptr->name, "eth", 3)){
			char ipaddr[20];
			if ((ret = getIPfromIface(device_ptr->name, ipaddr)) != 0) {
				fprintf(stderr, "ERROR getting IP from Iface for device %s\n", device_ptr->name);
			}
			if (strncmp(ipaddr, "192", 3) != 0) {
				strcpy(devices[count], device_ptr->name);
				strcpy(device_ips[count], ipaddr);
				count++;
			}
		}
	}


	struct sniff* sniff_args = (struct sniff*)malloc( sizeof(struct sniff) * count);
	printf("Here is a list of ethernet devices we try to listen:\n");
	for (i = 0; i < count; i++) {
		strcpy(sniff_args[i].dev_name, devices[i]);
		strcpy(sniff_args[i].dev_ip, device_ips[i]);
		
	}
	for(i = 0; i < count; i++) {
		printf("%d. %s\t-\t%s\n", i, sniff_args[i].dev_name, sniff_args[i].dev_ip);
	}

	pthread_t* threads = (pthread_t*)malloc( sizeof(pthread_t) * count );

	for (i = 0; i < count; i++) {
		if (pthread_create(&(threads[i]), NULL, (void*(*)(void *))sniffer, (void *)(&sniff_args[i]) )) {
        	fprintf(stderr, "ERROR creating thread %d\n", i);
    	}
	}

	for (i = 0; i < count; i++) {
		if (pthread_join(threads[i], NULL)){
        	fprintf(stderr, "ERROR joining thread %d\n", i);
    	}
	}


	printf( "DONE\n");

	return 0;
}

void sniffer(void* param) {
	struct sniff* data = (struct sniff*)param;
	printf("preparing sniffing device %s, ip %s\n", data->dev_name, data->dev_ip);
	char filename[20];
	char err[128];
	pcap_t *pcap_handle = NULL;

	
	sprintf(filename, "%s.log", data->dev_name);
	if ( (data->logfile = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}

	if ( (pcap_handle = pcap_open_live(data->dev_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", data->dev_name, err);
		exit(1);
	}

	pcap_loop(pcap_handle , 10 , process_packet , (u_char*)data );	// -1 means an infinite loop

	fclose(data->logfile);
	printf("thread %s: DONE!\n", data->dev_name);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sniff* data= (struct sniff*)args;
	FILE* logfile = data->logfile;
	pcap_t* handle = NULL;
	char err[128];
	int size = (int) header->len;
	char iface[10];
	u_char packetOut[ETH_DATA_LEN];
	memset(packetOut, 0, ETH_DATA_LEN);
	int ret = 0;
	int packetOutLen = 0;


	//printf("Received a packet, size = %d\n", size);
	memcpy(packetOut, packet, size);
	//print_packet_handler(stdout, packetOut, size);

	ret = routing_opt(packet, data->dev_ip);
	//printf("routing_opt = %d\n", ret);
	switch(ret) {
		case P_FORWARD:
			fprintf(stdout, "thread %s: Ready to modify the packet for forwarding...\n", data->dev_name);
			if ( (packetOutLen = modify_packet_new(packetOut, iface, size)) <= 0 ) {
				fprintf(stderr, "thread %s: fail to modify packet, with ret %d\n", data->dev_name, packetOutLen);
			}
			// printf("\nPACKET MODIFIED: size: %d, This packet is going to be sent to %s\nHere are the details:\n", packetOutLen, iface);
			print_packet_handler(logfile, packetOut, packetOutLen);
			if (packetOutLen > 0){
				if ( (handle = pcap_open_live(iface, BUFSIZ, 1, 100, err)) == NULL) {
					fprintf(stderr, "thread %s: fail to open device %s\n", data->dev_name, iface);
					exit(1);
				}
				if ((ret = pcap_inject(handle, packetOut, packetOutLen)) < 0){
					fprintf(stderr, "thread %s: fail to inject packet %s\n", data->dev_name, iface);
					exit(1);
				}
				fprintf(stdout, "thread %s: successfully injected packet to %s, byte count: %d\n", data->dev_name, iface, ret);
				pcap_close(handle);
				memset(packetOut, 0, ETH_DATA_LEN);
				memset(iface, 0, 10);
			}
			break;
		case P_TIMEOUT:
			fprintf(stdout, "thread %s: This is a timeout packet\n", data->dev_name);
			break;
		case P_ICMPECHOREPLY:
			fprintf(stdout, "thread %s: This packet needs icmp echo reply\n", data->dev_name);
			break;
		default:
			break;
	}

}

