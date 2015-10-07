/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */

 #ifndef _PACKET_UTIL_H_
 #define _PACKET_UTIL_H_
 #include "packet.h"

/* checksum generation */
 u_int16_t rthdr_chk_gen(struct rthdr*);
 u_int16_t chdr_chk_gen(u_char* packet, int size);
 u_int16_t urhdr_chk_gen(u_char* packet, int size);
 u_int16_t rlhdr_chk_gen(u_char* packet, int size);

 #endif