/**
 * CS 558L Lab8
 */

#ifndef _PACKET_UTIL_H_
#define _PACKET_UTIL_H_

FILE* logfile;
struct sockaddr_in source;
struct sockaddr_in dest;

void print_ethernet_header(const u_char *, int);
void print_ip_packet(const u_char * , int);
u_short calc_ip_checksum(const u_char*);
u_short calc_icmp_checksum(const u_char*, int);
void print_tcp_packet(const u_char *  , int);
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int);
void PrintData (const u_char * , int);

#endif