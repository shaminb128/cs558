#ifndef _ROUTING_H_
#define _ROUTING_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
//#include <netinet/in.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>


//typedef struct rttable{
//
//    struct sockaddr_in dest;         /* target address               */
//    struct sockaddr_in mask;     /* target network mask (IP)     */
//    struct sockaddr_in gateway;     /* gateway addr (RTF_GATEWAY)   */
//    short int metric;               /* ,metric */
//    char dev[50];                   /* device name   */
//    struct rttable *next;
//
//
//}rt_table;

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

/* takes in packet, return r_op */
int routing_opt(u_char* packet);

/* takes in packet, return routing table entry */
uint64_t rt_lookup(u_char* packet);

/* takes in packet, modify it for forwarding */
int modify_packet(u_char* packet);
#endif
