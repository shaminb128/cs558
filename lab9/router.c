#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <pthread.h>

#include "packet.h"
#include "packet_util.h"
#include "routing.h"
#include "printp.h"


typedef struct localIface {
	u_int16_t myaddr;
	pcap_t * handler;
}localIface_t;

typedef struct sniff {
	int tid;
	int iface_cnt;
	char dev_name[50];
	pcap_t** handler_list;
	struct localIface myIface;
	FILE* logfile;
}sniff_t;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void sniffer(void*);

int main (int argc, char** argv) {
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device

	char err[128];						// Holds the error
	char devices[5][20];				// For holding all available devices

	int count = 0;
	int n = 0;
	int i = 0;
	int ret = 0;						// Return val

	createRT();

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
				//strcpy(device_ips[count], ipaddr);
				count++;
			}
		}
	}
	struct sniff* sniff_args = (struct sniff*)malloc( sizeof(struct sniff) * count );
	pcap_t* handler_list[10];
	//struct localIface* ifaces = (struct localIface*)malloc( sizeof(struct localIface) * count);
	printf("Here is a list of ethernet devices we try to listen:\n");
	for (i = 0; i < count; i++) {
		sniff_args[i].tid = i;
		sniff_args[i].iface_cnt = count;
		sniff_args[i].handler_list = handler_list;
		strcpy(sniff_args[i].dev_name, devices[i]);
		sniff_args[i].myIface.myaddr = (u_int16_t)(((i+1) << 4) | 0x0002);
	}
	for(i = 0; i < count; i++) {
		printf("Dev %d, name: %s, assigned address: %04x\n", sniff_args[i].tid, sniff_args[i].dev_name, sniff_args[i].myIface.myaddr);
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
	char filename[20];
	char err[128];
	pcap_t *pcap_handle = NULL;
	sprintf(filename, "iface_%04x.log", (data->myIface).myaddr);
	if ( (data->logfile = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}

	if ( (pcap_handle = pcap_open_live(data->dev_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "thread %d: Error opening device %s, with error message %s\n", data->tid, data->dev_name, err);
		exit(1);
	}
    (data->myIface).handler = pcap_handle;
    (data->handler_list)[data->tid] = pcap_handle;
    fprintf(stdout, "thread %d: START, iface information:\nDev %d, name: %s, assigned address: %04x\n",data->tid, data->tid, data->dev_name, (data->myIface).myaddr);
	pcap_loop(pcap_handle , 1 , process_packet , (u_char*)data );	// -1 means an infinite loop
	fclose(data->logfile);
	pcap_close(pcap_handle);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sniff* data = (struct sniff*)args;
	
	
	FILE* logfile = data->logfile;
	pcap_t* handle;
	char err[128];
	int size = (int) header->len;
	char iface[10];
	u_char packetOut[PACKET_BUF_SIZE];
	memset(packetOut, 0, PACKET_BUF_SIZE);
	int ret = 0;
	int packetOutLen = 0;

    pcap_t* myIfaceHandler = (data->myIface).handler;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
	ret = routing_opt(packet, (data->myIface).myaddr);
	int handle_idx;

	switch(ret) {
		case P_FORWARD:
			memcpy(packetOut, packet, size);
			if ( (packetOutLen = modify_packet_new(packetOut, iface, size, data->ifaces, data->iface_cnt, &handle_idx)) <= 0 ) {
				fprintf(stderr, "thread %s: fail to modify packet, with ret %d\n", data->dev_name, packetOutLen);
			}
			if (packetOutLen > 0){
				if ((ret = pcap_inject((data->ifaces)[handle_idx].handler, packetOut, packetOutLen)) < 0){
					fprintf(stderr, "thread %s: fail to inject packet %s\n", data->dev_name, iface);
					exit(1);
				}
				memset(packetOut, 0, ETH_DATA_LEN);
				memset(iface, 0, 10);
			}
			break;
		case P_APPRESPONSE:
			
			break;
		case P_TIMEOUT:
			
			break;
		case P_ERRCHK:

			break;
		case P_NOT_YET_IMPLEMENTED:

			break;
		default:
			break;
	}
	
}

