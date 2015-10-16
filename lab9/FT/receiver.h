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

//methods
void init();
void write_ur_to_file(u_char *, int);
void write_re_to_file(u_char *, int, int);
int updateTrackPacketsArray();
void* handleFailures(void *);
int check_all_pckt_rcvd();
int getNackSeqNum();
void send_nack_to_client(int, pcap_t *);
void send_end( pcap_t *);
int generate_route_on_resend_packet(u_char*, int , int , int);

//threads
pthread_t nack_thread;

