/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */

 #include "packet_util.h"

 u_int16_t rthdr_chk_gen(struct rthdr* rth) {
 	unsigned int sum = 0;
 	sum += rth->saddr;
 	sum += rth->daddr;
 	sum += (u_short)(rth->ttl << 8) | (u_short)(rth->protocol);
 	sum += rth->size;
 	
 	int check = (((u_short)(sum >> 16)) & 0xf) + ((u_short)(sum) & 0xffff); // take carryouts
 	return (u_int16_t)(~check);
 }

 u_int16_t packet_chk_gen(u_char* packet, int size) {
 	u_char* ptr = packet + sizeof(struct rthdr);
 	int packetLen = size - sizeof(struct rthdr);
 	unsigned int sum = 0;
	int i = 0;
	for (; i < packetLen-1; i = i + 2 ) {
		if (i != 2) {
			sum += (*ptr << 8) | *(ptr+1);
		}
		ptr = ptr + 2;
	}
	if (i == packetLen-1) {
		sum += *(ptr+1);
	}

	
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	// Do this once more to prevent the carry outs from causing another unhandled carry out
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	return (u_short)(~sum);
 }
