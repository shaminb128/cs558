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
#include <sys/mman.h>
#include "sender.h"
#include "../routing.h"
#include "../printp.h"
#define USAGE "Usage: ./sender [filename] [hostname] [portno] "

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

uint16_t my_addr, dest_addr;
uint8_t port;
//FILE * fp_read;
int fp;
char * data;
size_t filesize;
char *data;
int no_of_packets;
pcap_t *handle_sniffed = NULL;

void init(){
    my_addr = 0x0011;
    //seqNum=0;
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}


int generate_route_on_file_packet(u_char* packetOut, char * payload, int size, int type, int seqNum) {

	if (size < MIN_APP_PKT_LEN) {
		fprintf(stderr, "ERROR: size should > 60\n");
		return -1;
	}
	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	struct rthdr* rth = (struct rthdr*)packetOut;
	rth->saddr = (u_int16_t)(my_addr & 0xffff);
	rth->daddr = (u_int16_t)(dest_addr & 0xffff);
	rth->ttl = (u_int8_t)(0x10 & 0xff);
	rth->protocol = (u_int8_t)type;
	rth->size = htons((u_int16_t)size);
	rth->check = htons(rthdr_chk_gen(rth));
	//memcpy(&rth, packetOut, sizeof(struct rthdr));
	//print_data(stdout, packetOut, size);
	int i, hdrlen, payload_size;

	switch(type) {
		case ROUTE_ON_CONTROL:
			fprintf(stdout, "WARNING: generate_route_on_packet: does not support ROUTE_ON_CONTROL\n");
			return -1;
		case ROUTE_ON_UNRELIABLE:
			//printf("generating unreliable packets...\n");

            hdrlen = sizeof(struct rthdr) + sizeof(struct urhdr);
            payload_size = size - hdrlen;
            //printf("Size: %d, hdrlen: %d, payload size: %d\n", size, hdrlen, payload_size);
			struct urhdr* urh = (struct urhdr*)(packetOut + sizeof(struct rthdr));
			urh->port = (u_int8_t)(port & 0xff);
			//print_data(stdout, packetOut, size);
			memcpy(packetOut + hdrlen, payload, payload_size);
			urh->check = htons(packet_chk_gen(packetOut, size));
			printf("Sending a UNRELIABLE packet of size: %d\n" , size);
			break;
		case ROUTE_ON_RELIABLE:
		    //printf("generating reliable packets...\n");
			hdrlen = sizeof(struct rthdr) + sizeof(struct rlhdr);
			payload_size = size - hdrlen;
			//printf("Size :%d, Header len: %d, Payload size : %d SeqNo: %d\n", size, hdrlen, payload_size, seqNum);
			struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
			rlh->port = (u_int8_t)(port & 0xff);
			rlh->seq = (u_int16_t)(seqNum & 0xffff);
            memcpy(packetOut + hdrlen, payload, payload_size);

            rlh->check = htons(packet_chk_gen(packetOut, size));
            fprintf(stdout, "Send R_Seq #: %d to %d\n", rlh->seq , rth->daddr   );
			break;
		default:
			fprintf(stderr, "ERROR: protocol not supported\n");
			return -1;
	}
	return size;
}

void* resend_packet(void* a)
{
//    while(1){
//        int n, seq , size=PAYLOAD_SIZE;
//        n = recvfrom(sockfd,&seq,sizeof(int),0,(struct sockaddr *)&serv_addr,&fromlen);
//        if (n < 0) errorMsg("recvfrom");
//        if(seq == -1){
//            printf("Entire file transmitted\n");
//            pthread_exit(0);
//        }
//        if((seq == (no_of_packets-1)) && (0 != filesize % PAYLOAD_SIZE))
//            size = filesize % PAYLOAD_SIZE;
//        packet packet2;
//        memset(packet2.payload,'\0',PAYLOAD_SIZE+1);
//        packet2.seq_num = seq;
//        memcpy(packet2.payload,data+(seq*PAYLOAD_SIZE),size);
//        send_packets(packet2);
//    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_n) {

    struct rthdr *rth = (struct rthdr*) packet_n;
    u_char *packetIn = (u_char *) packet_n;
	char err[128];
	int size = (int) header->len;
	int ret = 0, hdrlen, payload_size;
    if(rth->saddr == my_addr)
        return;
	ret = routing_opt(packetIn, my_addr);
    int protocol = rth->protocol;
	switch(ret) {
        case P_APPRESPONSE:
                if(verify_packet_chk(packetIn, size, protocol) < 0){
                        fprintf(stderr, "Packet checksum verification failed for protocol %d \n", protocol);
                        exit(1);
                }
                hdrlen = sizeof(struct rthdr) + sizeof(struct rlhdr);
                struct rlhdr* rlh = (struct rlhdr*)(packetIn + sizeof(struct rthdr));

                if(rlh->port != port){
                    fprintf(stderr, "Requesting port %d doesnot match my port %d\n", rlh->port, port);
                    exit(1);
                }
                printf("Received NACK for %d with payload %d\n", seqNum, packetIn[hdrlen]);
                if(packetIn[hdrlen] != 0)    //Not a nack packet
                    return;
                int seqNum = rlh->seq;


                u_char packetOut[PACKET_BUF_SIZE];
                char payload[PAYLOAD_SIZE];
                int payload_size;
                if(seqNum == (no_of_packets-1))
                    payload_size = filesize % PAYLOAD_SIZE;
                else
                    payload_size = PAYLOAD_SIZE;
                //fseek(fp_read, seqNum * PAYLOAD_SIZE, SEEK_SET);
                memcpy(payload, data + (seqNum * PAYLOAD_SIZE), payload_size);
                int pktlen = generate_route_on_file_packet(packetOut, payload, payload_size + RE_HEADER_SIZE, ROUTE_ON_RELIABLE, seqNum );

                if ((ret = pcap_inject(handle_sniffed, packetOut, pktlen)) != pktlen){
                    fprintf(stderr, "Fail to inject packet\n");
                    fprintf("Only %d inserted \n", ret);
                // exit(1);
                }
                fprintf(stdout, "Send R_Seq #: %d with %d to %d\n", seqNum, ret, dest_addr);


        default:
            break;

	}
}

void mapfile(char *filename){
    pthread_mutex_lock(&lock);
    if ((fp = open (filename, O_RDONLY)) < 0){
        fprintf(stderr,"can't open %s for reading", filename);
        pthread_mutex_unlock(&lock);
        exit(0);
    }
    filesize = lseek(fp, 0, SEEK_END);
    printf("Filesize is %zu\n",filesize);
    data = mmap((caddr_t)0, filesize, PROT_READ, MAP_SHARED, fp, 0);
    if (data == (caddr_t)(-1)) {
        fprintf(stdout, "MMAP ERROR");
        pthread_mutex_unlock(&lock);
        exit(0);
    }
    pthread_mutex_unlock(&lock);
}


int main(int argc, char *argv[])
{
    pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device


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

	printf("Trying to open device %s to send ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	fprintf(stdout, "OPEN DONE \n");
	printTime();

	printf("generating packets...\n");

	//Create thread to handle resend
//	if((pthread_create(&resend_thread, NULL, resend_packet, NULL)) != 0){
//        fprintf(stderr, "error in creating pthread. n");
//        exit(1);
//    }

    u_char packet[PACKET_BUF_SIZE];
    char payload[PAYLOAD_SIZE];

    int payload_size;
    long offset = 0;
    init();
    mapfile(argv[1]);
//    fp_read = fopen(argv[1], "r");
//    if(fp_read == NULL){
//        fprintf(stderr, "File open failed");
//        exit(1);
//    }
//    fseek(fp_read, 0L, SEEK_END);
//    filesize = ftell(fp_read);
    if((filesize % PAYLOAD_SIZE) != 0)
        no_of_packets = (filesize/PAYLOAD_SIZE) + 1;
    else
        no_of_packets = (filesize/PAYLOAD_SIZE);
    //fseek(fp_read, 0L, SEEK_SET);

    if(strcmp(argv[2], "node1") == 0)
        dest_addr = 0x0011;
    else if(strcmp(argv[2], "node2") == 0)
        dest_addr = 0x0021;
    else if(strcmp(argv[2], "node3") == 0)
        dest_addr = 0x0031;

    port = atoi(argv[3]);
    int seqNum = 0;
    //printf("My Ip: %02x, dest IP : %02x, port no: %d, FS: %d, Packet #: %d\n", my_addr, dest_addr, port, filesize, no_of_packets );
    //printf("Sending RELIABLE packets \n");
    while (seqNum < no_of_packets) {
        //fseek(fp_read, offset, SEEK_SET);
        if(seqNum == (no_of_packets-1))
            payload_size = filesize % PAYLOAD_SIZE;
        else
            payload_size = PAYLOAD_SIZE;
        memcpy(payload, data + offset, payload_size);
        //fread(payload, 1, payload_size, fp_read);
        offset = offset + payload_size;
        //change for RELIABLE/UNRELIABLE
        //int pktlen = generate_route_on_file_packet(packet, payload, payload_size + UR_HEADER_SIZE, ROUTE_ON_UNRELIABLE );
        int pktlen = generate_route_on_file_packet(packet, payload, payload_size + RE_HEADER_SIZE, ROUTE_ON_RELIABLE, seqNum );
        fprintf(stdout, "%d, ", seqNum);
        if ((ret = pcap_inject(handle_sniffed, packet, pktlen)) < 0){
            fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
        }
        seqNum++;
    }
    pcap_loop(handle_sniffed , -1, process_packet , NULL);	// use it to receive NACK
    printf("\n");

    pcap_close(handle_sniffed);
    munmap(data, filesize);
    close(fp);
   // pthread_join(resend_thread, NULL);
    printf( "DONE\n");
    return 1;
}
