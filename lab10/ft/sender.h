/**
 * CS 558L Lab 9
 *
 * SENDER for reliable transfer
 */
#ifndef SENDER_H
#define SENDER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include "../packet.h"
#include "../packet_util.h"

# define PAYLOAD_SIZE 1400
# define UR_HEADER_SIZE sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct urhdr)
# define RE_HEADER_SIZE sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr)
//Function declaration
void init();
int generate_route_on_file_packet(u_char* ,char *, int , int, int );
void* resend_packet(void* a);

pthread_t resend_thread;
#endif
