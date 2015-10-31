/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */

 #ifndef _PACKET_UTIL_H_
 #define _PACKET_UTIL_H_
 #include "packet.h"

 #define TEST_SEQ_CNT 1000
/* checksum generation */
 u_int16_t rthdr_chk_gen(struct rthdr*);
 u_int16_t packet_chk_gen(u_char* packet, int size);

 /* checksum verification */
 int verify_rthdr_chk(struct rthdr*);
 int verify_packet_chk(u_char* packet, int size, int type);

 /* test packet generation */
 int generate_random_packet(u_char* packetOut, int size);
 int generate_route_on_packet(u_char* packetOut, int size, int type);
 int generate_route_on_packet_2(u_char* packetOut, int size, int type, int seq, int source, int dest);
 int generate_openflow_test_packet(u_char* packetOut, int size, int seq, int source, int dest);

 #endif