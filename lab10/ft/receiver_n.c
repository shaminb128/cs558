/**
 * 558l lab9
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <unistd.h>

#include "../routing.h"
#include "receiver_n.h"

#define USAGE "Usage: ./receiver_n [filename1] [filename2] [filesize]"

FILE* fp_write1;
FILE* fp_write2;
size_t filesize;
int packets_num;
unsigned int last_packet_size;

uint16_t my_addr;
unsigned char my_mac[ETH_ALEN];
uint8_t port;
long ur_offset = 0;
pcap_t *handle_sniffed = NULL;
/* needed for reliable protocol */
int start_index, last_index;
int *track_packets1, *track_packets2;
int startCallback;
int loop_index;
int total1 = 0, total2 = 0, ur_total = 0;
int dummy = 1;

char device_name[10];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void print_dummy_packet(const u_char* data, int size){
	int i , j;
	printf("============================== here is a packet of size %d ==============================\n", size);
	for(i=0 ; i < size ; i++) {
    if( i!=0 && i%16==0)   //if one line of hex printing is complete...
    {
      fprintf(stdout , "         ");
      for(j=i-16 ; j<i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
          fprintf(stdout , "%c",(unsigned char)data[j]); //if its a number or alphabet

        else fprintf(stdout , "."); //otherwise print a dot
      }
      fprintf(stdout , "\n");
    }

    if(i%16==0) fprintf(stdout , "   ");
      fprintf(stdout , " %02X",(unsigned int)data[i]);

    if( i==size-1)  //print the last spaces
    {
      for(j=0;j<15-i%16;j++)
      {
        fprintf(stdout , "   "); //extra spaces
      }

      fprintf(stdout , "         ");

      for(j=i-i%16 ; j<=i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
        {
          fprintf(stdout , "%c",(unsigned char)data[j]);
        }
        else
        {
          fprintf(stdout , ".");
        }
      }

      fprintf(stdout ,  "\n" );
    }
  }
	printf("============================== end of packet ==============================\n\n\n\n\n\n");
}

void init(){
    my_addr = 0x0021;
    int ret = getLocalMac(device_name, my_mac);
    //printf("My MAC is %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", my_mac[0] , my_mac[1] , my_mac[2] , my_mac[3] , my_mac[4] , my_mac[5]);

    if(ret != 0)
        printf("Error getting Local MAC with value %d \n", ret);

    start_index = 0, loop_index = 0, last_index = 0;
    packets_num = 0;
    startCallback = 0;
    if((filesize % PAYLOAD_SIZE) != 0){
        packets_num = filesize/PAYLOAD_SIZE + 1;
        last_packet_size = filesize%PAYLOAD_SIZE;
    }
    else{
        packets_num = filesize/PAYLOAD_SIZE;
        last_packet_size = PAYLOAD_SIZE;
    }
    //printf("packet num: %d \n", packets_num);
    track_packets1 = (int *)calloc(packets_num, sizeof (int));
    track_packets2 = (int *)calloc(packets_num, sizeof (int));
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {


    struct rthdr *rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
    u_char *packetIn = (u_char *) packet;
	char err[128];
	int size = (int) header->len;
	//print_rl_packet(stdout, packet, size);
	int ret = 0, hdrlen, payload_size;
	fprintf(stdout,"PP from %d with size %d\n", rth->saddr, size);
	if(rth->saddr == my_addr){
        //fprintf(stdout, "Wrong addr \n");
        return;
	}

	//ret = routing_opt(packetIn, my_addr);
	//printf("Routing opt is %d \n", ret);
    int protocol = rth->protocol;
	switch(protocol) {
                    case ROUTE_ON_RELIABLE:
                        pthread_mutex_lock(&lock);
                        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
                        //printf("hdrlen : %d \n", hdrlen);
                        struct rlhdr* rlh = (struct rlhdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
                        printf("Port : %d \n", rlh->port);
                        if(rlh->port == 11){
                            if (updateTrackPacketsArray(track_packets1, rlh->seq)){
                            track_packets1[rlh->seq] = 1;
                            payload_size = size - hdrlen;
                            write_re_to_file1(packetIn + hdrlen, payload_size, rlh->seq);
                        }
                        }
                        else if(rlh->port == 12){
                            if (updateTrackPacketsArray(track_packets2, rlh->seq)){
                            track_packets2[rlh->seq] = 1;
                            payload_size = size - hdrlen;
                            write_re_to_file2(packetIn + hdrlen, payload_size, rlh->seq);
                        }
                        }
                        else{
                            printf("Incorrect Port \n");
                        }


                        pthread_mutex_unlock(&lock);

                        break;
                    default:
                        break;
                }
}

void write_re_to_file1(u_char * payload, int payload_size, int seqNum){

    fseek( fp_write1, seqNum * PAYLOAD_SIZE, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write1);
    fflush(fp_write1);
    total1++;
    //fprintf(stdout, "total : %d\n", total);
    if(total1 == packets_num){
        //fprintf(stdout, "File successfully written \n");
        fprintf(stdout, "FILE 1 WRITING DONE \n");
        printTime();
        fclose(fp_write1);
        //exit(1);
    }
}

void write_re_to_file2(u_char * payload, int payload_size, int seqNum){

    fseek( fp_write2, seqNum * PAYLOAD_SIZE, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write2);
    fflush(fp_write2);
    total2++;
    //fprintf(stdout, "total : %d\n", total);
    if(total2 == packets_num){
        //fprintf(stdout, "File successfully written \n");
        fprintf(stdout, "FILE 2 WRITING DONE\n");
        printTime();
        fclose(fp_write2);
        //exit(1);
    }
}

int updateTrackPacketsArray(int *track_packets, int seq_num){
    if(seq_num>= 0 && seq_num < packets_num)
    {
        if(track_packets[seq_num] == 0){
            track_packets[seq_num] = 1;
            return 1;
        }
        else return 0;

    }
    return 0;
}

int main(int argc, char *argv[])
{

    if (argc < 4) {
         fprintf(stderr,"%s", USAGE);
         exit(1);
    }
    //read_arp_cache();
    //printArpT();

    filesize = atoi(argv[3]);

    fp_write1 = fopen(argv[1] , "w+");
    fp_write2 = fopen(argv[2] , "w+");

    if(fp_write1 == NULL || fp_write2 == NULL){
        fprintf(stdout, "File open failed");
        exit(1);
    }

    pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
    //handle_sniffed = (pcap_t *) malloc(sizeof (pcap_t));

	char err[128];						// Holds the error

	//char devices[10][64];				// For holding all available
	int count = 0;
	int ret = 0;
	int n = 0;

	srand(time(NULL));

	//printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	//printf("SCANNING DONE\n");

	//printf("Here are the available devices:\n");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		if (device_ptr->name != NULL && !strncmp(device_ptr->name, "eth", 3)){
            char ipaddr[20];
            if ((ret = getIPfromIface(device_ptr->name, ipaddr)) != 0) {
                fprintf(stderr, "ERROR getting IP from Iface for device %s\n", device_ptr->name);
            }
            if (strncmp(ipaddr, "10.", 3) == 0) {
                strcpy(device_name, device_ptr->name);
                fprintf(stdout, "Find iface %s, ip %s\n", device_name, ipaddr);
                break;
            }
        }
	}

	printf("Trying to open device %s to receive ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	fprintf(stdout, "OPEN DONE\n");
    init();
    //    thread to handle failures
//    if((pthread_create(&nack_thread, NULL, handleFailures, NULL )) != 0){
//        fprintf(stderr, "pthread_create[0] \n");
//        pthread_exit(0);
//        exit(1);
//    }
    printf("Receiving .... \n");
	pcap_loop(handle_sniffed, -1, process_packet , NULL);	// -1 means an infinite loop
    //printf("Ret : %d \n", ret);
    //fprintf(stdout, "test pcap loop\n");
    pcap_close(handle_sniffed);
	//fprintf(stdout, "ALL PROCESSING DONE\n");
	//fprintf(stdout, "END OF TEST\n");
    //pthread_join(nack_thread, NULL);
    return 0;
}

