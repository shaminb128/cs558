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
#include "receiver.h"

#define USAGE "Usage: ./receiver [portno] [filename] [filesize]"

int total;

void init(){
    my_addr = 0x0021;

    start_index = 0, last_index = 0, total =0, loop_index = 0;
    packets_num = 0, seqNum = 0;
    startCallback = 0;
    if((filesize % PAYLOAD_SIZE) != 0){
        packets_num = filesize/PAYLOAD_SIZE + 1;
        last_packet_size = filesize%PAYLOAD_SIZE;
    }
    else{
        packets_num = filesize/PAYLOAD_SIZE;
        last_packet_size = PAYLOAD_SIZE;
    }
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct rthdr *rth = (struct rthdr*) packet;
    u_char *packetIn = (u_char *) packet;
	//FILE* logfile = data->logfile;
	char err[128];
	int size = (int) header->len;


	//char iface[10];
	int ret = 0, hdrlen, payload_size;

	ret = routing_opt(packetIn, my_addr);
    int protocol = rth->protocol;
	switch(ret) {
        case P_APPRESPONSE:
                if(verify_packet_chk(packetIn, size, protocol) < 0){
                        fprintf(stderr, "Packet checksum verification failed for protocol %d \n", protocol);
                        exit(1);
                }
                switch(protocol){
                    case ROUTE_ON_UNRELIABLE:
                        printf("Received an UNRELIABLE packet of size: %d \n", size);
                        hdrlen = sizeof(struct rthdr) + sizeof(struct urhdr);
                        struct urhdr *urh = (struct urhdr*)(packetIn + sizeof(struct rthdr));
                        if(urh->port != port){
                            fprintf(stderr, "Requesting port %d doesnot match my port %d\n", urh->port, port);
                            exit(1);
                        }
                        payload_size = size - hdrlen;
                        write_ur_to_file(packetIn + hdrlen, payload_size);
                        break;
                    case ROUTE_ON_RELIABLE:
                        hdrlen = sizeof(struct rthdr) + sizeof(struct rlhdr);
                        //struct rlhdr* rlh = (struct rlhdr*)(packetIn + sizeof(struct rthdr));
                        break;
                    default:
                        break;
                }
            break;
        default:
            break;

	}
}

void write_ur_to_file(u_char * payload, int payload_size){
    //printf("Packet # %d\n", seqNum);

    fseek( fp_write, offset, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write);
    fflush(fp_write);
    offset = offset + PAYLOAD_SIZE;
    seqNum ++;
    if(seqNum >= packets_num  ){
        printf("File successfully written \n");
        printTime();
        fclose(fp_write);
        printf( "DONE\n");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
         fprintf(stderr,"%s", USAGE);
         exit(1);
    }
    port = atoi(argv[1]);

    filesize = atoi(argv[3]);

    fp_write = fopen(argv[2] , "w+");
    if(fp_write == NULL){
        fprintf(stdout, "File open failed");
        exit(1);
    }

    init();

     //thread to handle failures
//    if((errno = pthread_create(&nack_thread_s, NULL, handleFailures, NULL ))){
//        fprintf(stderr, "pthread_create[0] %s\n",strerror(errno));
//        pthread_exit(0);
//    }
//    track_packets = (int *)calloc(packets_num, sizeof (int));
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
    //handle_sniffed = (pcap_t *) malloc(sizeof (pcap_t));

	char err[128];						// Holds the error
	char device_name[10];
	//char devices[10][64];				// For holding all available
	int count = 0;
	int ret = 0;
	int n = 0;

	srand(time(NULL));

	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	printf("Here are the available devices:\n");
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
	printf( "DONE\n");


	pcap_loop(handle_sniffed , -1, process_packet , NULL);	// -1 means an infinite loop


    pcap_close(handle_sniffed);
	printf( "DONE\n");
	printf( "END OF TEST\n");
//    pthread_join(nack_thread_s, NULL);
    return 0;
}

