/**
 * CS558L Lab8
 */


#ifndef _ROUTER_UTIL_H_
#define _ROUTER_UTIL_H_

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/sockios.h>

typedef enum {
	// Routing options
	P_FORWARD,
	P_TIMEOUT,
	P_ICMPREPLY
} r_op;

struct sockaddr getLocalMac(char *);
struct arpreq getMACfromIP(char *, char *);
void updateIPHeader(u_char *);
void updateEtherHeader(struct sockaddr *, struct sockaddr *, struct ethhdr *);
void modify_packet(u_char *, char*);

/**
 * This function takes in a raw packet and ip addr of this interface 
 * and desides what we want to do with it
 *
 * 1. Destination is this node
 * 		1.1 It's an ICMP req -> return P_ICMPREPLY
 * 2. Destination is NOT this node
 * 		2.1 TTL = 1 -> return P_TIMEOUT
 * 		2.2 TTL != 1 -> return P_FORWARD 
 */
int routing_opt(u_char*, char*);

/**
 * This function is a response to P_FORWARD, returned by routing_opt()
 * It takes in a raw packet, find nexthop and gateway information, modifies
 * the packet and device name (second argument), and returns the size of
 * packet
 */
int modify_packet_new(u_char*, char*);

/**
 * This function takes in a packet and find the routing table entry we are
 * going to use to modify the packet. The second argument is used for pointing
 * to that routing table entry
 * 
 * On success, it returns 0; If there is no entry in the routing tablle that
 * contains the target destination, it returns -1
 * 
 * This function should only be called within modify_packet_new()
 */
int rt_lookup(u_char*, *rt_tbl_list);

/**
 * These two functions generates ICMP support packets
 *
 * packetIn is the time-out original packet
 * packetOut is a pointer pointing to the ICMP packet that is ready to be sent
 * interface is a containter where this function is going to put interface name
 * Size is the size of the original packet
 * This function returns the size of packetOut
 */
int generate_icmp_time_exceed_packet(u_char* packetIn, u_char* packetOut, char* interface, int Size);
int generate_icmp_echo_reply_packet(u_char* packetIn, u_char* packetOut, char* interface, int Size);



#endif

