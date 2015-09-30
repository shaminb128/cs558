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
	P_DO_NOTHING,			/* this interface sent the packet, do nothing */
	P_FORWARD,				/* Forward the packet to next hop */
	P_TIMEOUT,				/* Drop the packet and generate ICMP timeout reply */
	P_ICMPECHOREPLY,		/* Response to ICMP echo request */
	P_NOT_YET_IMPLEMENTED	/* Used only for not-yet-implemented functions */
} r_op;

typedef enum {
	// Packet forward type
	P_LOCAL,
	P_REMOTE
} pf_t;

struct sockaddr getLocalMac(char *);
struct arpreq getMACfromIP(char *, char *);
void updateIPHeader(u_char *);
void updateEtherHeader(struct sockaddr *, struct sockaddr *, struct ethhdr *);
void modify_packet(u_char *, char*);

int getIPfromIface(char*, char*);
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
int routing_opt(const u_char*, char*);

/**
 * This function is a response to P_FORWARD, returned by routing_opt()
 * It takes in a raw packet, find nexthop and gateway information, modifies
 * the packet and device name (second argument), and returns the size of
 * packet
 */
int modify_packet_new(u_char*, char*, int);

/**
 * This function takes in a iphdr and find the routing table entry we are
 * going to use to modify the packet. The second argument is used for pointing
 * to that routing table entry
 *
 * On success, it returns 0; If there is no entry in the routing tablle that
 * contains the target destination, it returns -1
 *
 * This function should only be called within modify_packet_new()
 */
int rt_lookup(struct iphdr*, rt_table* );

/**
 * These two functions generates ICMP support packets
 *
 * packetIn is the original packet
 * packetOut is a pointer pointing to the ICMP packet that is ready to be sent
 * interface is a containter where this function is going to put interface name
 * Size is the size of the original packet
 * These functions return the size of packetOut
 *
 * generate_icmp_time_exceed_packet() is a response to P_TIMEOUT
 * generate_icmp_echo_reply_packet() is a response to P_ICMPREPLY
 */
int generate_icmp_time_exceed_packet(u_char*, u_char*, char*, int);
int generate_icmp_echo_reply_packet(u_char*, u_char*, char*, int);



#endif

