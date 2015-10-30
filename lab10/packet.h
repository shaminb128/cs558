/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */

 #ifndef _PACKET_H_
 #define _PACKET_H_

 #define ETH_ALEN	6		/* Octets in one ethernet addr	 */
 #define ETH_P_IP	0x0800
 #define ETH_HLEN	14		/* Total octets in header.	 */

 typedef struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
}ethhdr_t;

 	/* Routing protocol header */
 	typedef struct rthdr {
 		u_int16_t 		saddr;			/* source address */
 		u_int16_t 		daddr;			/* destination address */
 		u_int8_t		ttl;			/* time-to-live: for killing unintended long path, which might lead to congestion */
 		u_int8_t		protocol;		/* route-on team defined protocol */
 		u_int16_t		size;			/* packet length */
 		u_int16_t		check;			/* routing protocol header checksum */
 		//unsigned char	dummy[4];
 	}  rthdr_t;

 	/* Control protocol header */
 	typedef struct chdr {
 		/* need to be */
 		u_int16_t 		dummy;
 		u_int16_t 		check;			/* control protocol header + data checksum */
 	} chdr_t;

 	/* unreliable transfer protocol */
 	typedef struct urhdr {
 		u_int8_t		port;			/* application instance port */
 		u_int8_t		dummy;
 		u_int16_t		check;			/* unreliable transfer protocol header + data checksum */
 	} urhdr_t;

 	/* reliable transfer protocol */
 	typedef struct rlhdr {
 		u_int8_t		port;			/* application instance port */
 		u_int8_t		dummy;
 		u_int16_t		check;			/* reliable transfer protocol header + data checksum */
 		u_int32_t		seq;			/* transfer sequence number */

 	} rlhdr_t;

 	#define ROUTE_ON_CONTROL 		0								/* control protocol */
 	#define ROUTE_ON_UNRELIABLE		1								/* unreliable protocol */
 	#define ROUTE_ON_RELIABLE 		2								/* reliable protocol */

 	#define PACKET_BUF_SIZE			1600							/* packet buffer size */
 	#define MTU						1514							/* max transfer unit */
 	#define MAX_APP_PKT_LEN			MTU - sizeof(struct rthdr)		/* max data an application can send (including its header) */
 	#define MIN_APP_PKT_LEN			60 - sizeof(struct rthdr)		/* min data an application can send (including its header) */

 #endif
