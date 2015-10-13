#ifndef _ROUTING_H_
#define _ROUTING_H_

#include <stdint.h>
#include "packet.h"
#include "packet_util.h"
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
	P_APPRESPONSE,
	P_NOT_YET_IMPLEMENTED	/* Used only for not-yet-implemented functions */
} r_op;

typedef enum {
	// Packet forward type
	P_LOCAL,
	P_REMOTE
} pf_t;

int rt_tbl_size;


void createRT(int);
void printRT(uint64_t *);
int getIPfromIface(char*, char*);

/* takes in packet, return r_op; */
int routing_opt(u_char*, u_int16_t);

/* takes in destination addr, return the iface index for the device*/
uint8_t rt_lookup(uint16_t);

/* takes in packet, modify it for forwarding */
void modify_packet(u_char* packet);
#endif
