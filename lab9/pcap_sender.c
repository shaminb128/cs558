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
#include <net/ethernet.h>
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

void print_dummy_packet(const u_char* data, int size){
	int i , j;
	printf("============================== here is a packet of size %d ==============================\n", size);
	for(i=0 ; i < size ; i++) {
    if( i!=0 && i%16==0)   //if one line of hex printing is complete...
    {
      fprintf(stdout , "         ");
      for(j=i-16 ; j<i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
          fprintf(stdout , "%c",(unsigned char)data[j]); //if its a number or alphabet
        
        else fprintf(stdout , "."); //otherwise print a dot
      }
      fprintf(stdout , "\n");
    } 
    
    if(i%16==0) fprintf(stdout , "   ");
      fprintf(stdout , " %02X",(unsigned int)data[i]);
        
    if( i==size-1)  //print the last spaces
    {
      for(j=0;j<15-i%16;j++) 
      {
        fprintf(stdout , "   "); //extra spaces
      }
      
      fprintf(stdout , "         ");
      
      for(j=i-i%16 ; j<=i ; j++)
      {
        if(data[j]>=32 && data[j]<=128) 
        {
          fprintf(stdout , "%c",(unsigned char)data[j]);
        }
        else 
        {
          fprintf(stdout , ".");
        }
      }
      
      fprintf(stdout ,  "\n" );
    }
  }
	printf("============================== end of packet ==============================\n\n\n\n\n\n");
}

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

int main (int argc, char** argv) {
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

	printf("generating packets of 256 bytes...\n");
	int pktlen = generate_route_on_packet(packetOut, 256, ROUTE_ON_RELIABLE);
	struct rthdr* rth = (struct rthdr*)packetOut;
	rth->saddr = 0x0011;
	rth->daddr = 0x0021;
	rth->check = htons(rthdr_chk_gen(rth));
	sprintf((char*)(packetOut + sizeof(struct rthdr) + sizeof(struct rlhdr)), "This is a dummy test packet, with a size of %d. If this packet is successfully received, this sentence should be displayed exactly the same. Here starts the random data:", 256);
	struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
	rlh->check = htons(packet_chk_gen(packetOut, 256));
	fprintp(stdout, packetOut, pktlen);
	/*printf("generating packets of 8 bytes...\n");
	generate_random_packet(packetOut, 8);*/

	if ((ret = pcap_inject(handle_sniffed, packetOut, 256)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 256 bytes...\n");
	pktlen = generate_route_on_packet(packetOut, 1514, ROUTE_ON_RELIABLE);
	rth = (struct rthdr*)packetOut;
	rth->saddr = 0x0011;
	rth->daddr = 0x0021;
	rth->check = htons(rthdr_chk_gen(rth));
	sprintf((char*)(packetOut + sizeof(struct rthdr) + sizeof(struct rlhdr)), "This is a dummy test packet, with a size of %d. If this packet is successfully received, this sentence should be displayed exactly the same. Here starts the random data:", 1514);
	rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
	rlh->check = htons(packet_chk_gen(packetOut, 1514));
	fprintp(stdout, packetOut, pktlen);
	/*printf("generating packets of 8 bytes...\n");
	generate_random_packet(packetOut, 8);*/

	if ((ret = pcap_inject(handle_sniffed, packetOut, 1514)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

/*
	printf("generating packets of 59 bytes...\n");
	generate_random_packet(packetOut, 59);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 59)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 60 bytes...\n");
	generate_random_packet(packetOut, 60);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 60)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 61 bytes...\n");
	generate_random_packet(packetOut, 61);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 61)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 64 bytes...\n");
	generate_random_packet(packetOut, 64);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 64)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 512 bytes...\n");
	generate_random_packet(packetOut, 512);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 512)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 1499 bytes...\n");
	generate_random_packet(packetOut, 1499);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1499)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
	}
	printf( "DONE\n");
	sleep(1);
	printf("generating packets of 1500 bytes...\n");
	generate_random_packet(packetOut, 1500);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1500)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	sleep(1);

	

	printf("generating packets of 1501 bytes...\n");
	generate_random_packet(packetOut, 1501);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1501)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 1513 bytes...\n");
	generate_random_packet(packetOut, 1513);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1513)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
	}
	printf( "DONE\n");
	sleep(1);

	printf("generating packets of 1514 bytes...\n");
	generate_random_packet(packetOut, 1514);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1514)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");

	printf("generating packets of 1515 bytes...\n");
	generate_random_packet(packetOut, 1515);
	if ((ret = pcap_inject(handle_sniffed, packetOut, 1515)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	*/
	//printf( "DONE\n");

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}




