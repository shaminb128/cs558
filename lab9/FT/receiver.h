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
#include "../routing.h"
# define PAYLOAD_SIZE 1400

#define TRACK_ARRAY_LENGTH 8000000

int error;
FILE* fp_write;
size_t filesize;
int packets_num, seqNum;
unsigned int last_packet_size;

uint16_t my_addr;
uint8_t port;
long offset = 0;
pcap_t *handle_sniffed = NULL;
/* needed for reliable protocol */
int start_index, last_index;
int *track_packets;
int startCallback;
int loop_index;

int total;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


//methods
void init();
void write_ur_to_file(u_char *, int);
//void receive_file_info_udp_s();
//void receive_file_info_tcp_s();
//void receive_packet_s();
//int updateTrackPacketsArray();
//void* handleFailures(void *);
//void send_nack_s(int end_index);

//int getNackSeqNum();
//void send_nack_to_client(int);
//int check_all_pckt_rcvd();
//void send_end_s();

//threads
pthread_t nack_thread_s;

