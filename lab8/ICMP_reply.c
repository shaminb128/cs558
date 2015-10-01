/**
 * CS 558L Lab8
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
#include "pcaptest.h"

void eth_pkt_hdr(u_char *packet);
void icmp_pkt_ttl0_hdr(u_char *packet, int packet_size);
void ip_pkt_ttl0_hdr(u_char *packet, int packet_size);
int update_size_icmp_pkt(u_char *packet, int packet_size);
void ip_pkt_hdr(u_char *packet);
void icmp_pkt_hdr(u_char *packet, int size);

//---------------------------------------------------------------------
void generate_icmp_echo_reply_packet(const u_char *packetIn, u_char *packetOut, char *interface, int size){
	packetOut = malloc(size);
	memset(packetOut,0,size);
	memcpy(packetOut,packetIn,size);
    eth_pkt_hdr(packetOut);
    ip_pkt_hdr(packetOut);
    icmp_pkt_hdr(packetOut, size);
    //return size;
}


//--------------------------------------------------------------------------
void generate_icmp_time_exceed_packet(u_char *packetIn, u_char *packetOut, char *interface, int size) {
    struct iphdr *iph = (struct iphdr *)(packetIn  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;	
	int new_packet_size = sizeof(struct ethhdr)+iphdrlen+sizeof(struct icmphdr)+iphdrlen+8;
    packetOut = malloc(new_packet_size);
    memset(packetOut, 0, new_packet_size);
    // Copy the ethernet header and ipheader from udp packet to packetOut.
	memcpy(packetOut,packetIn, sizeof(struct ethhdr)+iphdrlen);
    // Get the ipheader and 64bits of payload of udp packet to the end of packetout
	memcpy(packetOut + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr),
           packetIn + sizeof(struct ethhdr) , iphdrlen+8 );
    eth_pkt_hdr(packetOut);
    ip_pkt_ttl0_hdr(packetOut,new_packet_size);
    icmp_pkt_ttl0_hdr(packetOut, new_packet_size);
    //return new_packet_size;
}


//----------------------------------------------------------------------
void eth_pkt_hdr(u_char *packet){
    struct ethhdr *eth = (struct ethhdr *)packet;
    char src_mac[ETH_HLEN], dest_mac[ETH_HLEN];
    memcpy(dest_mac, eth->h_source, ETH_HLEN);
    memcpy(src_mac, eth->h_dest, ETH_HLEN);
    memcpy((void*)packet, (void*)dest_mac, ETH_HLEN);
    memcpy((void*)(packet+ETH_HLEN), (void*)src_mac, ETH_HLEN);
}

//-----------------------------------------------------------------

void icmp_pkt_ttl0_hdr(u_char *packetOut, int packet_size){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packetOut + iphdrlen  + sizeof(struct ethhdr));
    icmph->type = ICMP_TIME_EXCEEDED;
    icmph->code = ICMP_EXC_TTL;
    unsigned short cksum = calc_icmp_checksum(packetOut,packet_size);
    icmph->checksum = htons(cksum);
}

//-------------------------------------------------------------

void ip_pkt_ttl0_hdr(u_char *packetOut, int packet_size){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr) );
    unsigned short iphdrlen = iph->ihl * 4;
    iph->ttl = 64;
    unsigned long src_ip = iph->saddr;
    unsigned long dest_ip = iph->daddr;
    iph->saddr = dest_ip;
    iph->daddr = src_ip;
    iph->tot_len = iphdrlen + sizeof(struct icmphdr) + 8;
    iph->protocol=1;
    unsigned short cksum = calc_ip_checksum(packetOut);
    iph->check = htons(cksum);
}
//------------------------------------------------------------------
int update_size_icmp_pkt(u_char *packetIn, int packet_size) {
    struct iphdr *iph = (struct iphdr *)(packetIn  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
    int payload_size = packet_size - header_size;
    int new_payload_size = payload_size + sizeof(struct icmphdr) + iphdrlen;
    return new_payload_size + sizeof(struct icmphdr) + iphdrlen + sizeof(struct ethhdr);
}
//-----------------------------------------------------------------------
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

//------------------------------------------------------------------------

void icmp_pkt_hdr(u_char *packetOut, int size){
    struct iphdr *iph = (struct iphdr *)(packetOut  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packetOut + iphdrlen  + sizeof(struct ethhdr));
    icmph->type = ICMP_ECHOREPLY;
    unsigned short cksum = calc_icmp_checksum(packetOut,size);
    icmph->checksum = htons(cksum);
}
