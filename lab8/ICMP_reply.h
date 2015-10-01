/**
 * CS 558L Lab8
 */

#ifndef _ICMP_REPLY_H_
#define _ICMP_REPLY_H_

void eth_pkt_hdr(u_char *);
void icmp_pkt_ttl0_hdr(u_char *, int);
void ip_pkt_ttl0_hdr(u_char *, int);
int update_size_icmp_pkt(u_char *, int);
void ip_pkt_hdr(u_char *);
void icmp_pkt_hdr(u_char *, int);
void generate_icmp_echo_reply_packet(const u_char *, u_char *, char *, int);
void generate_icmp_time_exceed_packet(const u_char *, u_char *, char *, int);

#endif
