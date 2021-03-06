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
#define ETHERNET_HEADER_LEN 14
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
void print_ethernet_header(const u_char *, int );
void print_ip_packet(const u_char * , int );
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int );
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int );
void modify_packet(u_char *, char*);
int change_ether_addr(u_char *, int);
int updateEtherHeader(struct sockaddr *, struct sockaddr *, struct ethhdr *);
struct arpreq getMACfromIP(char *, char *);
static char *ethernet_mactoa(struct sockaddr *);
struct sockaddr getLocalMac(char *);
/* Global Variables */
FILE* logfile;
struct sockaddr_in source;
struct sockaddr_in dest;
int tcp = 0;
int udp = 0;
int icmp = 0;
int others = 0;
int total = 0;


int main (int argc, char** argv) {

	createRT();
	//rt_list = getRT();
	printRT(rt_tbl_list);

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
	int size = (int) header->len;
	modify_packet(packet, "eth0");
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    const u_char * packet_c = (const u_char *)packet;

	switch (iph->protocol) {
    	case 1:  //ICMP Protocol
      		++icmp;
      		print_icmp_packet( packet_c , size);
      		break;

    	case 6:  //TCP Protocol
      		++tcp;
     	 	print_tcp_packet(packet_c , size);
      		break;

	    case 17: //UDP Protocol
      		++udp;
      		print_udp_packet(packet_c , size);
      		break;

    	default: //Some Other Protocol like ARP etc.
      		others++;
      		break;
  	}
  	printf("TCP : %d   UDP : %d   ICMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , others , total);
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	// adapted from <linux/if_ether.h>
 	struct ethhdr *eth = (struct ethhdr *)Buffer;

  	fprintf(logfile , "\n");
  	fprintf(logfile , "Received a packet of size %d\n", Size);
  	fprintf(logfile , "Ethernet Header\n");
  	fprintf(logfile , "   |-Destination Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  	fprintf(logfile , "   |-Source Address          : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  	fprintf(logfile , "   |-Protocol                : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
  	source.sin_addr.s_addr = iph->saddr;

  	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;

  	fprintf(logfile , "\n");
  	fprintf(logfile , "IP Header\n");
  	fprintf(logfile , "   |-IP Version            : %d\n",(unsigned int)iph->version);
  	fprintf(logfile , "   |-IP Header Length      : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  	fprintf(logfile , "   |-Type Of Service       : %d\n",(unsigned int)iph->tos);
  	fprintf(logfile , "   |-IP Total Length       : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
  	fprintf(logfile , "   |-Identification        : %d\n",ntohs(iph->id));
  	fprintf(logfile , "   |-TTL                   : %d\n",(unsigned int)iph->ttl);
  	fprintf(logfile , "   |-Protocol              : %d\n",(unsigned int)iph->protocol);
  	fprintf(logfile , "   |-Checksum              : %d\n",ntohs(iph->check));
  	fprintf(logfile , "   |-Source IP             : %s\n" , inet_ntoa(source.sin_addr) );
  	fprintf(logfile , "   |-Destination IP        : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");

	print_ip_header(Buffer,Size);

  	fprintf(logfile , "\n");
  	fprintf(logfile , "TCP Header\n");
  	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
  	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
  	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
  	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
  	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
  	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
  	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
  	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
  	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
  	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
  	fprintf(logfile , "\n");
  	fprintf(logfile , "                        DATA Dump                         ");
  	fprintf(logfile , "\n");

  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer,iphdrlen);

  	fprintf(logfile , "TCP Header\n");
  	PrintData(Buffer+iphdrlen,tcph->doff*4);

  	fprintf(logfile , "Data Payload\n");
  	PrintData(Buffer + header_size , Size - header_size );

  	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size)
{

  	unsigned short iphdrlen;

  	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
  	iphdrlen = iph->ihl*4;

  	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

  	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

  	print_ip_header(Buffer,Size);

  	fprintf(logfile , "\nUDP Header\n");
  	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
  	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
  	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
  	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

  	fprintf(logfile , "\n");
  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer , iphdrlen);

  	fprintf(logfile , "UDP Header\n");
  	PrintData(Buffer+iphdrlen , sizeof udph);

  	fprintf(logfile , "Data Payload\n");

  	//Move the pointer ahead and reduce the size of string
  	PrintData(Buffer + header_size , Size - header_size);

  	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(const u_char * Buffer , int Size)
{
  	unsigned short iphdrlen;

  	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
  	iphdrlen = iph->ihl * 4;

  	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

  	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");

  	print_ip_header(Buffer , Size);

  	fprintf(logfile , "\n");

  	fprintf(logfile , "ICMP Header\n");
  	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));

  	if((unsigned int)(icmph->type) == 11)
  	{
    	fprintf(logfile , "  (TTL Expired)\n");
  	}
  	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
  	{
    	fprintf(logfile , "  (ICMP Echo Reply)\n");
  	}

  	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
  	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
  	fprintf(logfile , "\n");

  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer,iphdrlen);

  	fprintf(logfile , "UDP Header\n");
  	PrintData(Buffer + iphdrlen , sizeof icmph);

  	fprintf(logfile , "Data Payload\n");

  	//Move the pointer ahead and reduce the size of string
  	PrintData(Buffer + header_size , (Size - header_size) );

  	fprintf(logfile , "\n###########################################################");
}

void PrintData (const u_char * data , int Size)
{
  int i , j;
  for(i=0 ; i < Size ; i++)
  {
    if( i!=0 && i%16==0)   //if one line of hex printing is complete...
    {
      fprintf(logfile , "         ");
      for(j=i-16 ; j<i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
          fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

        else fprintf(logfile , "."); //otherwise print a dot
      }
      fprintf(logfile , "\n");
    }

    if(i%16==0) fprintf(logfile , "   ");
      fprintf(logfile , " %02X",(unsigned int)data[i]);

    if( i==Size-1)  //print the last spaces
    {
      for(j=0;j<15-i%16;j++)
      {
        fprintf(logfile , "   "); //extra spaces
      }

      fprintf(logfile , "         ");

      for(j=i-i%16 ; j<=i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
        {
          fprintf(logfile , "%c",(unsigned char)data[j]);
        }
        else
        {
          fprintf(logfile , ".");
        }
      }

      fprintf(logfile ,  "\n" );
    }
  }
}
//TODO: iface, TTL, checksum
void modify_packet(u_char *pkt_ptr, char* iface)
{

    struct ethhdr *eth = (struct ethhdr *)pkt_ptr;
    struct iphdr *iph = (struct iphdr*)(pkt_ptr + sizeof(struct ethhdr));

    printf("Dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    struct sockaddr_in source;
    struct sockaddr_in dest;
    memset(&source, 0, sizeof(source));
  	source.sin_addr.s_addr = iph->saddr;

  	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;

    printf("Source IP: %s, Dest IP: %s\n",inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));

    rt_table *p = rt_tbl_list;
    char dst[50], gw[50], mask[50], dev[50];

   // printRT(rt_tbl_list);
        while(p != NULL){
            inet_ntop(AF_INET, &(p->rt_dst.sin_addr), dst, 50);
            inet_ntop(AF_INET, &(p->rt_gateway.sin_addr), gw, 50);
            inet_ntop(AF_INET, &(p->rt_genmask.sin_addr), mask, 50);
            struct sockaddr_in tempDst;
            inet_aton("10.1.0.1", &tempDst.sin_addr);
            // check which network address matches with the destination address
            if ((strlen(p->rt_dev) != 0) &&((tempDst.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr) == ( p->rt_dst.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr))){
                printf("Gateway : %s\n", gw);
                // local network, send to DestIP
                if(p->rt_gateway.sin_addr.s_addr == 0x00000000){

                    printf("change dest to local ip\n");
                    struct arpreq  arequest;
                    memset(&arequest, 0, sizeof(arequest));
                    arequest = getMACfromIP("10.1.2.4", p->rt_dev);

                    printf("Local Dest: %s\n", ethernet_mactoa(&arequest.arp_ha));

                    struct sockaddr addr;
                    memset(&addr, 0, sizeof(addr));
                    addr = getLocalMac(p->rt_dev);

                    printf("Source: %s\n", ethernet_mactoa(&addr));
                    updateEtherHeader(&addr, &arequest.arp_ha, eth);

                }
                // It ia a remote network
                else{
                    //set the device name and MAC address for gateway
                   struct arpreq  arequest;
                   memset(&arequest, 0, sizeof(arequest));
                   arequest = getMACfromIP(gw, p->rt_dev);
                   char *gwAddr = ethernet_mactoa(&arequest.arp_ha);
                   printf("Remote Dest: %s\n", gwAddr);

                   struct sockaddr addr;
                   memset(&addr, 0, sizeof(addr));
                   addr = getLocalMac(p->rt_dev);
                   char *sourceAddr = ethernet_mactoa(&addr);
                   printf("Source: %s\n", sourceAddr);

                   updateEtherHeader(&addr, &arequest.arp_ha, eth);
                }
              }

        p = p->next;
  }
    printf("After modification\n");
    printf("Dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );

    return 1;

}



// update Ethernet address with new MAC
int updateEtherHeader(struct sockaddr *sourceAddr, struct sockaddr *gwAddr, struct ethhdr *eth){

    unsigned char *ptrS = (unsigned char *) sourceAddr->sa_data;
    unsigned char *ptrD = (unsigned char *) gwAddr->sa_data;
    int i;
    for (i = 0; i < 6 ; i++){

        eth->h_dest[i] = ptrD[i];
        eth->h_source[i] = ptrS[i];
        //printf("GWAddr: %.2x, SA : %.2x", ptrD[i],ptrS[i] );
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
