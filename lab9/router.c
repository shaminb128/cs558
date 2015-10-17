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
	char dev_list[5][20];
	pcap_t* handler_list[5];
	struct localIface myIface;
	FILE* logfile;
	unsigned int stat_pktnum;
    u_int64_t stat_bytes;
}sniff_t;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void sniffer(void*);

int main (int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: ./router [extra_credit = enter_extra_credit_mode ? 1 : 0]\n");
		exit(1);
	}
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device

	char err[128];						// Holds the error
	char devices[5][20];				// For holding all available devices

	int count = 0;
	int n = 0;
	int i = 0;
	int ret = 0;						// Return val
	int extra = atoi(argv[1]);

	createRT(extra);

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
		//sniff_args[i].handler_list = handler_list;
		//sniff_args[i].dev_list = devices;
		strcpy(sniff_args[i].dev_name, devices[i]);
		int j;
		for (j = 0; j < count; j++) {
			strcpy((sniff_args[i].dev_list)[j], devices[j]);
		}
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
	pcap_t *pcap_private = NULL;
	int i;
	sprintf(filename, "iface_%04x.log", (data->myIface).myaddr);
	if ( (data->logfile = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}
	fprintf(stdout, "thread %d: iface: %s, devices: %s, %s, %s, %s\n", data->tid, data->dev_name, (data->dev_list)[0], (data->dev_list)[1], (data->dev_list)[2], (data->dev_list)[3]);

	if ( (pcap_handle = pcap_open_live(data->dev_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "thread %d: Error opening device %s, with error message %s\n", data->tid, data->dev_name, err);
		exit(1);
	}
    (data->myIface).handler = pcap_handle;
    //(data->handler_list)[data->tid] = pcap_handle;
    for (i = 0; i < data->iface_cnt; i++) {
    	if (i != data->tid) {
    		if ( (pcap_private = pcap_open_live((data->dev_list)[i], BUFSIZ, 1, 100, err)) == NULL ) {
				fprintf(stderr, "thread %d: Error opening device %s, with error message %s\n", data->tid, (data->dev_list)[i], err);
				exit(1);
			}
			(data->handler_list)[i] = pcap_private;
			fprintf(stdout, "thread %d: added private handle for iface %s\n", data->tid, (data->dev_list)[i]);

    	}
    }
    fprintf(stdout, "thread %d: START, iface information:\nDev %d, name: %s, assigned address: %04x\n",data->tid, data->tid, data->dev_name, (data->myIface).myaddr);
	pcap_loop(pcap_handle , -1 , process_packet , (u_char*)data );	// -1 means an infinite loop
	fclose(data->logfile);
	pcap_close(pcap_handle);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sniff* data = (struct sniff*)args;
	
	
	//FILE* logfile = data->logfile;
	//pcap_t* handle;
	//char err[128];
	int size = (int) header->len;
	//char iface[10];
	u_char packetOut[PACKET_BUF_SIZE];
	memset(packetOut, 0, PACKET_BUF_SIZE);
	int ret = 0;
	//int packetOutLen = 0;

    //pcap_t* myIfaceHandler = (data->myIface).handler;
    //struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
	ret = routing_opt(packet, (data->myIface).myaddr);
	//int handle_idx;

	switch(ret) {
		case P_FORWARD:
			data->stat_pktnum ++;
            data->stat_bytes += size;
			memcpy(packetOut, packet, size);
			modify_packet(packetOut);
			struct rthdr* rth = (struct rthdr*)packetOut;
			int index = (int)rt_lookup(rth->daddr);
			fprintf(stdout, "thread %d: received a P_FORWARD packet of size %d, inject to iface[%d]; %d packets (%lld bytes) processed\n", data->tid, size, index, data->stat_pktnum, data->stat_bytes);
			if ((ret = pcap_inject((data->handler_list)[index], packetOut, size)) < 0){
				fprintf(stderr, "thread %d: fail to inject packet to iface[%d]\n", data->tid, index);
				exit(1);
			}
			memset(packetOut, 0, PACKET_BUF_SIZE);
			break;
		case P_APPRESPONSE:
			fprintf(stdout, "thread %d: received a P_APPRESPONSE packet\n", data->tid);
			break;
		case P_TIMEOUT:
			fprintf(stdout, "thread %d: received a P_TIMEOUT packet\n", data->tid);
			break;
		case P_ERRCHK:
			fprintf(stdout, "thread %d: received a P_ERRCHK packet\n", data->tid);
			break;
		case P_NOT_YET_IMPLEMENTED:
			fprintf(stdout, "thread %d: received a P_NOT_YET_IMPLEMENTED packet. Protocol Not Supported\n", data->tid);
			break;
		case P_DO_NOTHING:
			break;
		default:
			fprintf(stderr, "thread %d: ERROR: come to default routine, with return code %d.\n", data->tid, ret);
			break;
	}
	
}

