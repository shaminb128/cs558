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
# define UR_HEADER_SIZE 14
# define RE_HEADER_SIZE 16

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

uint16_t my_addr, dest_addr;
uint8_t port;
FILE * fp_read;
size_t filesize;
char *data;
int no_of_packets, seqNum=0;

//Function declaration
void init();
int generate_route_on_file_packet(u_char* ,char *, int , int );
void* resend_packet(void* a);

pthread_t resend_thread;
#endif
