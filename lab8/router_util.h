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
#include <net/ethernet.h>
#include <linux/sockios.h>


#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

/**
 * This structures contains the arp table details:
 * 1. IP Address
 * 2. MAC Address
 * 3. Ethernet Device
 */
typedef struct arptable{

    struct sockaddr_in ip_addr;/* given IP               */
    unsigned char hw_addr[ETH_ALEN];     /* stored Hw address   */
    char arp_dev[50];                   /* device name   */
    struct arptable *next;

}arp_table;


arp_table *arp_tbl_list;
int arp_table_size;


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


/**
 * This method reads the arp entries from /proc/net/arp
 * file and stores the result in "arptable" data structure.
 * Returns -1: any failure occured
 * Return 0: success
*/
int read_arp_cache();

/**
 * This method prints the ARP table maintained as
 * a single linked list of struct arptable
*/
void printArpT();

/**
 * This function takes two MAC addresses and compares
 * them by each character
 * Returns 0: if each charater of 8 bits is same
 * Return -1: if mismatch between any character
 */
int cmp_mac_addr(unsigned char *,unsigned char *);
/**
 * This function takes Device name of the interface and
 * returns the corresponding MAC address for that
 * interface
 */
struct sockaddr getLocalMac(char *);

/**
 * This function takes the IP address of remote host as 1st argument
 * and device name of the interface to which the remote is connected
 * as the 2nd argument. It assigns the
 * corresponding MAC address of the remote host from ARP table to
 * the 3rd argument.
 */
int getMACfromIP_new(struct sockaddr_in, char *, unsigned char* );
struct arpreq getMACfromIP(char *, char *);

/**
 * This function takes the entire packet and
 * updates the IP Header fields
 */
void updateIPHeader(u_char *);

/**
 * This function takes the Ethernet header and updates the corresponding
 * source and destination MAC address
 */
void updateEtherHeader(struct sockaddr *, unsigned char *, struct ethhdr *);

/**
 * This function is not used anymore
 */
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
int routing_opt(const u_char*, char*, char*);

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
/**
Following are the supporting functions for icmp generate
*/
void eth_pkt_hdr(u_char *packet);
void ip_pkt_hdr(u_char *packetOut);
void icmp_pkt_hdr(u_char *packetOut, int size);
int update_size_icmp_pkt(u_char *packetIn, int packet_size);
void ip_pkt_ttl0_hdr(u_char *packetOut, char* Interface);
void icmp_pkt_ttl0_hdr(u_char *packetOut, int packet_size);


#endif

