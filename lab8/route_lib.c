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
#include <netinet/in.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include "route.h"
#include "packet_util.h"

/**
* REFERENCE:
* struct sockaddr_in {
*     short            sin_family;   // getMACfromIPe.g. AF_INET
*     unsigned short   sin_port;     // e.g. htons(3490)
*     struct in_addr   sin_addr;     // see struct in_addr, below
*     char             sin_zero[8];  // zero this if you want to
* };

* struct in_addr {
*     unsigned long s_addr;  // load with inet_aton()
* };
*/

void process_packet(u_char *, const struct pcap_pkthdr *,u_char *);
void process_ip_packet(const u_char * , int);
void modify_packet(u_char *, char*);
void updateEtherHeader(struct sockaddr *, struct sockaddr *, struct ethhdr *);
void updateIPHeader(u_char *);
struct arpreq getMACfromIP(char *, char *);
static char *ethernet_mactoa(struct sockaddr *);
struct sockaddr getLocalMac(char *);
/* Global Variables */
FILE* logfile;
struct sockaddr_in source;
struct sockaddr_in dest;

rt_table *rt_tbl_list;

int main (int argc, char** argv) {

	createRT();
//	printRT(rt_tbl_list);

	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *pcap_handle = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available devices

	int count = 0;
	int n = 0;
	int ret = 0;						// Return val

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

	printf("Trying to open device %s to sniff ... ", device_name);
	if ( (pcap_handle = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	printf( "DONE\n");

	if ( (logfile = fopen("packets.log", "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}

	//Put the device in sniff loop
  	pcap_loop(pcap_handle , -1 , process_packet , NULL);	// -1 means an infinite loop

	fclose(logfile);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, u_char *packet) {
	total++;
	FILE *fp = fopen("packet_log.txt", "w");
    if (fp == NULL) {
        fprintf(stderr, "Can't open input!\n");
        exit(1);
    }
	int size = (int) header->len;
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	char *dev_name = (char *)malloc(20);
	modify_packet(packet, dev_name);
	printf("After modification\n");
    printf("Dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("Device Name : %s\n", dev_name );
	printf(" TTL : %d ", (unsigned int)iph->ttl );
    printf("Checksum : %d \n", ntohs(iph->check));

}


//TODO: iface, TTL, checksum
void modify_packet(u_char *pkt_ptr, char* iface)
{


    struct ethhdr *eth = (struct ethhdr *)pkt_ptr;
    struct iphdr *iph = (struct iphdr*)(pkt_ptr + sizeof(struct ethhdr));

    printf("Dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf(" TTL : %d ", (unsigned int)iph->ttl );
    printf("Checksum : %d \n", ntohs(iph->check));

    struct sockaddr_in source;
    struct sockaddr_in dest;


    memset(&source, 0, sizeof(source));
  	source.sin_addr.s_addr = iph->saddr;

  	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;

    rt_table *p = rt_tbl_list;
    char dst[50], gw[50], mask[50];
    int min_metric = 1000;
   // printRT(rt_tbl_list);
        while(p != NULL){
            inet_ntop(AF_INET, &(p->rt_dst.sin_addr), dst, 50);
            inet_ntop(AF_INET, &(p->rt_gateway.sin_addr), gw, 50);
            inet_ntop(AF_INET, &(p->rt_genmask.sin_addr), mask, 50);
            //use dest.sin_addr
            struct sockaddr_in tempDst;
            inet_aton("10.1.0.1", &tempDst.sin_addr);
            // check which network address matches with the destination address
            if ((strlen(p->rt_dev) != 0) &&((tempDst.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr) == ( p->rt_dst.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr))){
                printf("Gateway : %s\n", gw);
                // local network, send to DestIP
                if(p->rt_gateway.sin_addr.s_addr == 0x00000000){
                    struct arpreq  arequest;
                    memset(&arequest, 0, sizeof(arequest));
                    arequest = getMACfromIP("10.1.2.4", p->rt_dev); //put dest.sin_addr here
                    printf("Local Dest: %s ", ethernet_mactoa(&arequest.arp_ha));

                    struct sockaddr addr;
                    memset(&addr, 0, sizeof(addr));
                    addr = getLocalMac(p->rt_dev);
                    printf("Source: %s\n", ethernet_mactoa(&addr));
                    strcpy(iface, p->rt_dev);

                    updateEtherHeader(&addr, &arequest.arp_ha, eth);
                }
                // It ia a remote network
                else{
                    //set the device name and MAC address for gateway
                   if(p->rt_metric < min_metric)
                   {
                        min_metric = p->rt_metric;
                        //printf("Metric : %d, Min M: %d\n" ,p->rt_metric, min_metric);
                        struct arpreq  arequest;
                        memset(&arequest, 0, sizeof(arequest));
                        arequest = getMACfromIP(gw, p->rt_dev);
                        char *gwAddr = ethernet_mactoa(&arequest.arp_ha);
                        printf("Remote Dest: %s ", gwAddr);

                        struct sockaddr addr;
                        memset(&addr, 0, sizeof(addr));
                        addr = getLocalMac(p->rt_dev);
                        char *sourceAddr = ethernet_mactoa(&addr);
                        printf("Source: %s\n", sourceAddr);
                        strcpy(iface, p->rt_dev);
                        updateEtherHeader(&addr, &arequest.arp_ha, eth);
                   }
                }
                updateIPHeader(pkt_ptr);
              }
        p = p->next;
  }
}


// update Ethernet address with new MAC
void updateEtherHeader(struct sockaddr *sourceAddr, struct sockaddr *destAddr, struct ethhdr *eth){

    unsigned char *ptrS = (unsigned char *) sourceAddr->sa_data;
    unsigned char *ptrD = (unsigned char *) destAddr->sa_data;
    int i;
    for (i = 0; i < 6 ; i++){

        eth->h_dest[i] = ptrD[i];
        eth->h_source[i] = ptrS[i];
    }
}

void updateIPHeader(u_char *pkt){

    struct iphdr *iph = (struct iphdr*)(pkt + sizeof(struct ethhdr));
    if(iph->ttl > 1){
        iph->ttl = iph->ttl - 1;
        u_short checksum = calc_ip_checksum(pkt);
        iph->check = (u_int16_t) checksum;
    }
    else if(iph->ttl == 1){
        iph->ttl = iph->ttl - 1;
        //TODO: send ICMP packet
    }
    else {
        //TODO: sned ICMP packet
    }


}

static char *ethernet_mactoa(struct sockaddr *addr)
{
	static char buff[256];
	unsigned char *ptr = (unsigned char *) addr->sa_data;

	sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
		(ptr[0] & 0xff), (ptr[1] & 0xff), (ptr[2] & 0xff),
		(ptr[3] & 0xff), (ptr[4] & 0xff), (ptr[5] & 0xff));

return (buff);

}
