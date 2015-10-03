/**
 * CS 558L Lab8
 */

#ifndef _PACKET_UTIL_H_
#define _PACKET_UTIL_H_

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


struct sockaddr_in source;
struct sockaddr_in dest;


void print_packet_handler(FILE*, const u_char*, int);
void print_ethernet_header(FILE*, const u_char *, int);
void print_ip_packet(FILE*, const u_char * , int);
u_short calc_ip_checksum(const u_char*);
u_short calc_icmp_checksum(const u_char*, int);
void print_tcp_packet(FILE*, const u_char *  , int);
void print_udp_packet(FILE*, const u_char * , int);
void print_icmp_packet(FILE*, const u_char * , int);
void PrintData (FILE*, const u_char * , int);


#endif