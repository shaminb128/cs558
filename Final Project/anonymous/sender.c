#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h> //For errno - the error number
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define PORT "5000" // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold
#define MAXDATASIZE 200 
#define idDigits 44 //digits of USC ID
#define MY_DEST_MAC0    0xFF
#define MY_DEST_MAC1    0xFF
#define MY_DEST_MAC2    0xFF
#define MY_DEST_MAC3    0xFF
#define MY_DEST_MAC4    0xFF
#define MY_DEST_MAC5    0xFF
#define DEFAULT_IF      "eth4"
#define BUF_SIZ         1501
#define VSIZE 4





void *get_in_addr(struct sockaddr *sa) {
         if (sa->sa_family == AF_INET) {
                return &(((struct sockaddr_in*)sa)->sin_addr);
         }
         return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

extern void packetsraw(int np, int sport, int dport, char * src, char * dest, char * iface, unsigned char * payload, int ttl, int sourceMac[], int destMac[], int payload_size){

    packetRaw (1, sport, dport, src, dest, iface, payload, ttl, sourceMac, destMac, payload_size);
}

extern void packetsraw2(int np, int sport, int dport, char * src, char * dest, char * iface, unsigned char * payload, int ttl, int sourceMac[], int destMac[], int payload_size){

    packetRaw2 (1, sport, dport, src, dest, iface, payload, ttl, sourceMac, destMac, payload_size);
}

/*extern void packeticmp (char * source, char * dest) {
	sendIcmpPacket(source, dest);
}*/

extern void packeticmp (int np, char * source, char * destination, char * iface, unsigned char * payload, int payload_size, int ttl) {
	//sendIcmpPacket(source, dest);
    icmp(np, source, destination, iface, payload, payload_size, ttl);
}

extern void packeticmpport (int np, char * source, char * destination, char * iface, unsigned char * payload, int payload_size, int ttl) {
    //sendIcmpPacket(source, dest);
    icmpport(np, source, destination, iface, payload, payload_size, ttl);
}

//Used References:
// https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/
// http://www.binarytides.com/raw-udp-sockets-c-linux/ 
void packetRaw(int np, int sport, int dport, char * source, char * destination, char * iface, unsigned char * payload, int ttl, int sourceMac[], int destMac[], int payload_size) {

        char interface[10];
        int sockfd;
        int i=0;
        char payloadStr[10];
        struct ifreq if_idx;
        struct ifreq if_mac;
        int tx_len = 0;
	unsigned char packetPayload[1500];
        char sendbuf[BUF_SIZ];
        struct ether_header *eh = (struct ether_header *) sendbuf;
        // struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
        struct sockaddr_ll socket_address;
        char ifName[IFNAMSIZ];

        char myBuf[10];
	int l;
//	for (l=0; l < 1470; l++)
//	printf("%u", (unsigned int) payload[l]);
//	printf("in C code now\n");
//	printf("%d\n", strlen(payload));
	memset(packetPayload,0, 1500);
	strcpy(packetPayload,payload);
//	printf("%s\n",packetPayload);

//	printf("%d",strlen(packetPayload));
        memset(interface,0,10);
        strcat(interface, iface);
        //printf("%s\n",interface);

        /* Open RAW socket to send on */
        if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
            perror("socket");
        }

        // /* Get the index of the interface to send on */
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, interface, strlen(interface));
        if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
            perror("SIOCGIFINDEX");

        /* Get the MAC address of the interface to send on */
        memset(&if_mac, 0, sizeof(struct ifreq));
        strncpy(if_mac.ifr_name, interface, strlen(interface));
        if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
            perror("SIOCGIFHWADDR");

	   int t=0;
	   int counter = 0;
        for(t=0;t< np; t++) {
        // /* Construct the Ethernet header */
        memset(sendbuf, 0, BUF_SIZ);
	    tx_len=0;

        /* Ethernet header */
        //this is the source mac address//change to make generic//sent from lan1 to lan0//10.1.2.3/4 to 10.1.0.1/2
        if (strcmp(source,"10.1.2.3")==0 || strcmp(source,"10.1.2.4")==0)
	{
	eh->ether_shost[0] = 0x00;
        eh->ether_shost[1] = 0x15;
        eh->ether_shost[2] = 0x17;
        eh->ether_shost[3] = 0x57;
        eh->ether_shost[4] = 0xc7;
        eh->ether_shost[5] = 0x8d;


        //replace this with destination mac address
        eh->ether_dhost[0] = 0x00;
        eh->ether_dhost[1] = 0x04;
        eh->ether_dhost[2] = 0x23;
        eh->ether_dhost[3] = 0xc7;
        eh->ether_dhost[4] = 0xa6;
        eh->ether_dhost[5] = 0x34;
	}
        if (strcmp(source,"10.1.0.1")==0 || strcmp(source,"10.1.0.2")==0)
	{
	
	eh->ether_shost[0] = 0x00;
        eh->ether_shost[1] = 0x15;
        eh->ether_shost[2] = 0x17;
        eh->ether_shost[3] = 0x57;
        eh->ether_shost[4] = 0xc7;
        eh->ether_shost[5] = 0x8e;


        //replace this with destination mac address
	if (strcmp(destination,"10.1.2.3")==0)
	{
        eh->ether_dhost[0] = 0x00;
        eh->ether_dhost[1] = 0x14;
        eh->ether_dhost[2] = 0x22;
        eh->ether_dhost[3] = 0x23;
        eh->ether_dhost[4] = 0x89;
        eh->ether_dhost[5] = 0x29;
	}
	if (strcmp(destination,"10.1.2.4")==0)
	{
        eh->ether_dhost[0] = 0x00;
        eh->ether_dhost[1] = 0x15;
        eh->ether_dhost[2] = 0x17;
        eh->ether_dhost[3] = 0x57;
        eh->ether_dhost[4] = 0xc3;
        eh->ether_dhost[5] = 0xd2;
	}
	
	}

        /* Ethertype field */
        eh->ether_type = htons(0x0800);
        tx_len += sizeof(struct ether_header);

        char sipBuf [10];
        char dipBuf [10];
        memset(sipBuf,0,10);
        memset(dipBuf,0,10);

        strcpy (sipBuf,source);
        strcpy(dipBuf,destination);
        
        struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
        /* IP Header */
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 16; // Low delay
        iph->id = htons(54321);
        iph->ttl = ttl; // hops
        iph->protocol = 17; // UDP

        /* Source IP address, can be spoofed */
        iph->saddr = inet_addr(sipBuf);
        // iph->saddr = inet_addr("192.168.0.112");

        /* Destination IP address */
        iph->daddr = inet_addr(dipBuf);
        tx_len += sizeof(struct iphdr);

        struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
        /* UDP Header */
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->check = 0; // skip
        tx_len += sizeof(struct udphdr);
	//printf("length so far %d\n", tx_len);
        // // /* Packet data */
        for (i = 0; i < payload_size; i++) {
        	
            sendbuf[tx_len++] = payload[i];        
        }

        /* Length of UDP payload and header */
        udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
  /* Length of IP payload and header */
        iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);
        /* Index of the network device */
        socket_address.sll_ifindex = if_idx.ifr_ifindex;
        /* Address length*/
        socket_address.sll_halen = ETH_ALEN;

        /* Destination MAC */
	if(strcmp(destination,"10.1.0.1")==0 || strcmp(destination,"10.1.0.2")==0)
	{
        socket_address.sll_addr[0] = 0x00;
        socket_address.sll_addr[1] = 0x04;
        socket_address.sll_addr[2] = 0x23;
        socket_address.sll_addr[3] = 0xc7;
        socket_address.sll_addr[4] = 0xa6;
        socket_address.sll_addr[5] = 0x34;
	}
	if(strcmp(destination,"10.1.2.3")==0)
	{
        socket_address.sll_addr[0] = 0x00;
        socket_address.sll_addr[1] = 0x14;
        socket_address.sll_addr[2] = 0x22;
        socket_address.sll_addr[3] = 0x23;
        socket_address.sll_addr[4] = 0x89;
        socket_address.sll_addr[5] = 0x29;
	}
	if(strcmp(destination,"10.1.2.4")==0)
	{
        socket_address.sll_addr[0] = 0x00;
        socket_address.sll_addr[1] = 0x15;
        socket_address.sll_addr[2] = 0x17;
        socket_address.sll_addr[3] = 0x57;
        socket_address.sll_addr[4] = 0xc3;
        socket_address.sll_addr[5] = 0xd2;
	}

        /* Send packet */
//        int t=0;
       // for(t=0;t< np; t++) {
          // printf("sending packet");
        //usleep (160);
//	printf("packet length %d \n \n ", sizeof(sendbuf));
	  if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                perror("Send failed\n");
		memset(sendbuf, 0, BUF_SIZ);
        }
close(sockfd);
}
