/**
 * CS558L Lab8
 */


#ifndef _ROUTER_UTIL_H_
#define _ROUTER_UTIL_H_

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/sockios.h>

struct sockaddr getLocalMac(char *);
struct arpreq getMACfromIP(char *, char *);
void updateIPHeader(u_char *);
void updateEtherHeader(struct sockaddr *, struct sockaddr *, struct ethhdr *);
void modify_packet(u_char *, char*);

#endif