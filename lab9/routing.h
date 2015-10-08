#ifndef _ROUTING_H_
#define _ROUTING_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "packet.h"
//#include <netinet/in.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>


extern uint64_t routing_table[20];

typedef enum {
	// Routing options
	P_DO_NOTHING,			/* this interface sent the packet, do nothing */
	P_FORWARD,				/* Forward the packet to next hop */
	P_TIMEOUT,				/* Drop the packet and generate ICMP timeout reply */
	P_ERRCHK,				/* Checksum does not match the packet */
	P_NOT_YET_IMPLEMENTED	/* Used only for not-yet-implemented functions */
} r_op;

typedef enum {
	// Packet forward type
	P_LOCAL,
	P_REMOTE
} pf_t;

int rt_tbl_size;


void createRT();
void printRT(uint64_t *);

/* takes in packet, return r_op; */
int routing_opt(u_char* packet);

/* takes in packet, return whether to route locally or remotely. It sets the second parameter to the routing table entry */
int rt_lookup(uint16_t, uint64_t *);

/* takes in packet, modify it for forwarding */
int modify_packet(u_char* packet);
#endif
