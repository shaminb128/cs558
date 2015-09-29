/**
 * CS558L Lab8
 */

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
#include "router_util.h"
#include "packet_util.h"

rt_table *rt_tbl_list;

struct sockaddr getLocalMac(char *iface) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, iface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        return s.ifr_hwaddr;
  	}
  	printf("ERROR: getLocalMac(): ioctl() returns negative value\n");
  	return s.ifr_hwaddr;
}


struct arpreq getMACfromIP(char *ip, char *iface){
    int                 s;
	struct arpreq       areq;
	struct sockaddr_in *sin;
	struct in_addr      ipaddr;

 //   printf("%s, %s \n", ip, iface);
	/* Get an internet domain socket. */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	/* Make the ARP request. */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;

	if (inet_aton(ip, &ipaddr) == 0) {
		fprintf(stderr, "-- Error: invalid numbers-and-dots IP address %s.\n",
				ip);
		exit(1);
	}

	sin->sin_addr = ipaddr;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	strncpy(areq.arp_dev, iface, 15);

	if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
		perror("-- Error: unable to make ARP request, error");
		exit(1);
	}

	return areq;
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

void modify_packet(u_char *pkt_ptr, char* iface)
{


    struct ethhdr *eth = (struct ethhdr *)pkt_ptr;
    struct iphdr *iph = (struct iphdr*)(pkt_ptr + sizeof(struct ethhdr));

//    printf("Dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
//    printf("Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
//    printf(" TTL : %d ", (unsigned int)iph->ttl );
//    printf("Checksum : %d \n", ntohs(iph->check));

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
                    //printf("Local Dest: %s ", ethernet_mactoa(&arequest.arp_ha));

                    struct sockaddr addr;
                    memset(&addr, 0, sizeof(addr));
                    addr = getLocalMac(p->rt_dev);
                    //printf("Source: %s\n", ethernet_mactoa(&addr));
//                    printf("modify_packet: iface = %s\n", p->rt_dev);
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
                        //char *gwAddr = ethernet_mactoa(&arequest.arp_ha);
                        //printf("Remote Dest: %s ", gwAddr);

                        struct sockaddr addr;
                        memset(&addr, 0, sizeof(addr));
                        addr = getLocalMac(p->rt_dev);
                        //char *sourceAddr = ethernet_mactoa(&addr);
                        //printf("Source: %s\n", sourceAddr);
                        strcpy(iface, p->rt_dev);
                        updateEtherHeader(&addr, &arequest.arp_ha, eth);
                   }
                }
                updateIPHeader(pkt_ptr);
              }
        p = p->next;
  }
}

int routing_opt(u_char* packetIn, char* myIpAddr) {
	/* NOT_YET_IMPLEMENTED */
	return P_NOT_YET_IMPLEMENTED;
}

int modify_packet_new(u_char* packetIn, char* iface) {
	/* NOT_YET_IMPLEMENTED */
	return 0;
}

int rt_lookup(struct iphdr* iph, rt_table* rtp) {
	/* NOT_YET_IMPLEMENTED */
	return 0;
}

int generate_icmp_time_exceed_packet(u_char* packetIn, u_char* packetOut, char* interface, int Size) {
	/* NOT_YET_IMPLEMENTED */
	return 0;
}

int generate_icmp_echo_reply_packet(u_char* packetIn, u_char* packetOut, char* interface, int Size) {
	/* NOT_YET_IMPLEMENTED */
	return 0;
}






