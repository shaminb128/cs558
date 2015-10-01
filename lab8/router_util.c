/**
 * CS558L Lab8
 */

#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/sockios.h>
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

//    printf("%s, %s \n", ip, iface);
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


int getIPfromIface(char* iface, char* ipstr) {
  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to iface */
  strcpy(ifr.ifr_name, iface);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);

  strcpy(ipstr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  return 0;
}

int routing_opt(const u_char* packetIn, char* myIpAddr, char* iface) {
	struct ethhdr *eth = (struct ethhdr *)packetIn;
	struct iphdr* iph= (struct iphdr*)(packetIn + sizeof(struct ethhdr));
	int iphlen = iph->ihl * 4;
	struct sockaddr_in dest;            //this will contain myIpAddr
	struct sockaddr mac_addr;
	memset(&dest, 0, sizeof(dest));
	memset(&mac_addr, 0, sizeof(mac_addr));
	mac_addr = getLocalMac(iface);
    unsigned char *pkt_mac = (unsigned char *)eth->h_source;
	unsigned char *my_mac = (unsigned char *) mac_addr.sa_data;
	int ret = 0;
  	if( (ret = inet_aton(myIpAddr, &(dest.sin_addr))) == 0) {
  		return P_NOT_YET_IMPLEMENTED;
  	}
  	printf("myIPAddr %s\n", myIpAddr );
  	if (iph->saddr == dest.sin_addr.s_addr) {
        printf("Source IP is same as myIP: %s ", myIpAddr);
  		return P_DO_NOTHING;
  	}
  	// check if source MAC address matches this device MAC address
  	if(cmp_mac_addr(pkt_mac, my_mac) == 0){
        //printf("Source MAC is same as myMac ");
        return P_DO_NOTHING;
  	}


  	if (dest.sin_addr.s_addr == iph->daddr) {
  		// This packet targets at this node
  		struct icmphdr* icmph = (struct icmphdr*)(packetIn + sizeof(struct ethhdr) + iphlen);
  		if (icmph->type == ICMP_ECHO) {
  			return P_ICMPECHOREPLY;
  		} else {
  			return P_NOT_YET_IMPLEMENTED;
  		}
  	} else {
  		// This packet targets at some other node
  		if (iph->ttl <= 1) {
  			return P_TIMEOUT;
  		} else {
  			return P_FORWARD;
  		}
  	}
	return P_NOT_YET_IMPLEMENTED;
}

int cmp_mac_addr(unsigned char *mac1,unsigned char *mac2){
    int i;
    for(i = 0; i < ETH_ALEN; i++){
       // printf("Mac1: %.2X Mac2: %.2X ", mac1[i], mac2[i]);
        if(mac1[i] != mac2[i])
            return -1;
    }
    return 0;
}


int modify_packet_new(u_char* packetIn, char* iface, int size) {
	struct ethhdr *eth = (struct ethhdr *)packetIn;
    struct iphdr *iph = (struct iphdr*)(packetIn + sizeof(struct ethhdr));
    struct sockaddr_in source;
    struct sockaddr_in dest;
    struct arpreq  arequest;
    struct sockaddr addr;
    char gw[50];
//    rt_table* p = NULL;
	rt_table p;
    int ret = 0;

    memset(&source, 0, sizeof(source));
  	source.sin_addr.s_addr = iph->saddr;

  	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;
    //fprintf(stdout , "   |-Destination Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  	//fprintf(stdout , "   |-Source Address          : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    //printf("modify_packet_new test: Dest IP: %s, Source IP : %s\n", inet_ntoa(dest.sin_addr), inet_ntoa(source.sin_addr));
  	memset(&arequest, 0, sizeof(arequest));

  	memset(&addr, 0, sizeof(addr));

  	if ((ret = rt_lookup(iph, &p)) < 0) {
  		printf("Destination Unreachable\n");
  		return -1; // destination unreachable
  	}
//	if (p == NULL) {
//	printf("p is NULL after looking up\n");
//}
 	printf("modify_packet_new: successfully did rt lookup, the packet is sent to %d\n", ret);

  	// Now we have the routing table entry and is ready to modify packet
  	(iph->ttl)--;
    //printf("Dest IP: %s, Device : %s", inet_ntoa(dest.sin_addr), p.rt_dev);
  	if (ret == P_LOCAL) {
        //check if destination is me(rtr3), then get LocalMac
        arequest = getMACfromIP(inet_ntoa(dest.sin_addr), p.rt_dev);
//        printf("modify_packet_new: getMACfromIP passed\n");
        addr = getLocalMac(p.rt_dev);
//        printf("modify_packet_new: getLocalMac passed, devname = %s\n", p.rt_dev);
        strcpy(iface, p.rt_dev);
//        printf("modify_packet_new: strcpy passed.\n");
        updateEtherHeader(&addr, &arequest.arp_ha, eth);
//        printf("modify_packet_new: updateEtherHeader passed\n");
  	} else if (ret == P_REMOTE) {
        inet_ntop(AF_INET, &(p.rt_gateway.sin_addr), gw, 50);
        arequest = getMACfromIP(gw, p.rt_dev);
//        printf("modify_packet_new: getMACfromIP passed\n");
		addr = getLocalMac(p.rt_dev);
//		printf("modify_packet_new: getLocalMac passed, devname = %s\n", p.rt_dev);
		strcpy(iface, p.rt_dev);
//		printf("modify_packet_new: strcpy passed.\n");
        updateEtherHeader(&addr, &arequest.arp_ha, eth);
 //       printf("modify_packet_new: updateEtherHeader passed\n");
  	} else {
  		return -1; // not supposed to come to this point
  	}

  	// Finally recalculate checksum
  	u_short ipchk = calc_ip_checksum(packetIn);
//  	printf("modify_packet_new: calc_ip_checksum passed. ipchk = %d\n", ipchk);
  	iph->check = htons(ipchk);
	return size;
}

int rt_lookup(struct iphdr* iph, rt_table* rtp) {
	rt_table* p = rt_tbl_list;
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;
	int min_metric = 1000;
    int match_found = 0;
	while(p != NULL) {
		if ((strlen(p->rt_dev) != 0) &&
			((dest.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr) == ( p->rt_dst.sin_addr.s_addr & p->rt_genmask.sin_addr.s_addr))) {
			// Matches
			//printf("Match found");
			match_found = 1;
			if(p->rt_gateway.sin_addr.s_addr == 0x00000000) {
				// Local network
				//rtp = p;
				memcpy(rtp, p, sizeof(rt_table));
				return P_LOCAL;
			} else {
				// remote network
				if(p->rt_metric < min_metric) {
					min_metric = p->rt_metric;
					//rtp = p;
					memcpy(rtp, p, sizeof(rt_table));
				}
			}
		}
		p = p->next;
	}

	if (!match_found) {
		return -1;
	}
	return P_REMOTE;
}

int generate_icmp_echo_reply_packet(u_char* packetIn, u_char* packetOut, char* interface, int size) {
	//packetOut = malloc(size);
	//memset(packetOut,0,size);
	memcpy(packetOut,packetIn,size);
    eth_pkt_hdr(packetOut);
    ip_pkt_hdr(packetOut);
    icmp_pkt_hdr(packetOut, size);
	return size;
}

int generate_icmp_time_exceed_packet(u_char* packetIn, u_char* packetOut, char* interface, int size) {
	print_packet_handler(stdout, packetIn, size);
	struct iphdr *iph = (struct iphdr *)(packetIn  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
	int new_packet_size = sizeof(struct ethhdr)+iphdrlen+sizeof(struct icmphdr)+iphdrlen+8;
    //packetOut = malloc(new_packet_size);
    //memset(packetOut, 0, new_packet_size);
    // Copy the ethernet header and ipheader from udp packet to packetOut.
	printf("checkpoint 0,addr raw, iph->saddr = %x, ip->daddr = %x\n", iph->saddr, iph->daddr);
  printf("checkpoint 1\n");
	memcpy(packetOut,packetIn, sizeof(struct ethhdr)+iphdrlen);
    // Get the ipheader and 64bits of payload of udp packet to the end of packetout
  printf("checkpoint 2\n");
	memcpy(packetOut + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr),
           packetIn + sizeof(struct ethhdr) , iphdrlen+8 );
  printf("checkpoint 3\n");
    eth_pkt_hdr(packetOut);
    printf("checkpoint 4\n");
    ip_pkt_ttl0_hdr(packetOut,interface);
    printf("checkpoint 5\n");
    icmp_pkt_ttl0_hdr(packetOut, new_packet_size);
    printf("checkpoint 6\n");
    return new_packet_size;
}
//supporting functions for ICMP replies
void eth_pkt_hdr(u_char *packetOut){
    struct ethhdr *eth = (struct ethhdr *)packetOut;
    char src_mac[ETH_HLEN], dest_mac[ETH_HLEN];
    memcpy(dest_mac, eth->h_source, ETH_HLEN);
    memcpy(src_mac, eth->h_dest, ETH_HLEN);
    memcpy((void*)packetOut, (void*)dest_mac, ETH_HLEN);
    memcpy((void*)(packetOut+ETH_HLEN), (void*)src_mac, ETH_HLEN);
}

void ip_pkt_hdr(u_char *packetOut){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr) );
    iph->ttl=64;
    unsigned long src_ip = iph->saddr;
    unsigned long dest_ip = iph->daddr;
	iph->saddr = dest_ip;
    iph->daddr = src_ip;
    unsigned short cksum = calc_ip_checksum(packetOut);
    iph->check = htons(cksum);
}

void icmp_pkt_hdr(u_char *packetOut, int size){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packetOut + iphdrlen  + sizeof(struct ethhdr));
    icmph->type = ICMP_ECHOREPLY;
    unsigned short cksum = calc_icmp_checksum(packetOut,size);
    icmph->checksum = htons(cksum);
}

int update_size_icmp_pkt(u_char *packetIn, int packet_size) {
    struct iphdr *iph = (struct iphdr *)(packetIn  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
    int payload_size = packet_size - header_size;
    int new_payload_size = payload_size + sizeof(struct icmphdr) + iphdrlen;
    return new_payload_size + sizeof(struct icmphdr) + iphdrlen + sizeof(struct ethhdr);
}

void ip_pkt_ttl0_hdr(u_char *packetOut, char* Interface){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr) );
    unsigned short iphdrlen = iph->ihl * 4;
    struct sockaddr_in source;
    int ret = 0;
    iph->ttl = 64;
    //updating the destination IP address
    printf("checkpoint ttl.1, iph->sddr = %x, ip->daddr = %x\n", iph->saddr, iph->daddr);
    unsigned long src_ip = iph->saddr;
    iph->daddr = src_ip;
    //updating the source IP address
    char dst_ip[20];
    if(getIPfromIface(Interface,dst_ip)!=0) printf("Could not obtain source IP address of router.\n");
    printf("checkpoint ttl.2, dst_ip = %s\n", dst_ip);
//	if(inet_aton(dst_ip,iph->saddr)==0) printf("Invalid input address to inet_aton.\n");
    if( (ret = inet_aton(dst_ip, &(source.sin_addr))) == 0) {
      printf("invalid destip\n");
    }
    iph->saddr = htons(source.sin_addr.s_addr);
    printf("checkpoint ttl.3, s_addr = %.8x, saddr = %.8x\n", source.sin_addr.s_addr, htons(source.sin_addr.s_addr));
    iph->tot_len = iphdrlen + sizeof(struct icmphdr) + 8;
    iph->protocol=1;
    printf("checkpoint ttl.4\n");
    unsigned short cksum = calc_ip_checksum(packetOut);
    printf("checkpoint ttl.5\n");
    iph->check = htons(cksum);
}

void icmp_pkt_ttl0_hdr(u_char *packetOut, int packet_size){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packetOut + iphdrlen  + sizeof(struct ethhdr));
    icmph->type = ICMP_TIME_EXCEEDED;
    icmph->code = ICMP_EXC_TTL;
    unsigned short cksum = calc_icmp_checksum(packetOut,packet_size);
    icmph->checksum = htons(cksum);
}





