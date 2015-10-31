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

FILE* fp_write;
size_t filesize;
int packets_num;
unsigned int last_packet_size;

uint16_t my_addr, dest_addr;
unsigned char my_mac[ETH_ALEN], dest_mac[ETH_ALEN];
uint8_t port;
long ur_offset = 0;
pcap_t *handle_sniffed = NULL;
/* needed for reliable protocol */
int start_index, last_index;
int *track_packets;
int startCallback;
int loop_index;
int total = 0, ur_total = 0;
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
    dest_mac[0] = 0x00;
    dest_mac[1] = 0x04;
    dest_mac[2] = 0x23;
    dest_mac[3] = 0xbb;
    dest_mac[4] = 0x1f;
    dest_mac[5] = 0x61;

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
    track_packets = (int *)calloc(packets_num, sizeof (int));
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
	//fprintf(stdout,"PP from %d with size %d\n", rth->saddr, size);
	if(rth->saddr == my_addr){
        //fprintf(stdout, "Wrong addr \n");
        return;
	}

	ret = routing_opt(packetIn, my_addr);
	//printf("Routing opt is %d \n", ret);
    int protocol = rth->protocol;
	switch(ret) {
        case P_APPRESPONSE:
                if(verify_packet_chk(packetIn, size, protocol) < 0){
                        fprintf(stderr, "Packet checksum verification failed for protocol %d \n", protocol);
                        exit(1);
                }
                switch(protocol){
                    case ROUTE_ON_UNRELIABLE:
                        //printf("Received an UNRELIABLE packet of size: %d from %d \n", size, dest_addr);
                        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct urhdr);
                        struct urhdr *urh = (struct urhdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
                        if(urh->port != port){
                            fprintf(stderr, "Requesting port %d doesnot match my port %d\n", urh->port, port);
                            //exit(1);
                            return;
                        }

                        payload_size = size - hdrlen;
                        write_ur_to_file(packetIn + hdrlen, payload_size);
                        break;
                    case ROUTE_ON_RELIABLE:
                        pthread_mutex_lock(&lock);
                        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
                        //printf("hdrlen : %d \n", hdrlen);
                        struct rlhdr* rlh = (struct rlhdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));

                        if(rlh->port != port){
                            fprintf(stderr, "Requesting port %d doesnot match my port %d\n", rlh->port, port);
                            //exit(1);
                            return;
                        }
                        dest_addr = rth->saddr;
                        //fprintf(stdout, "Received a RELIABLE packet of seqNum: %d from %d \n", rlh->seq, dest_addr);

                        if (updateTrackPacketsArray(rlh->seq)){
                            track_packets[rlh->seq] = 1;
                            if((rlh->seq) > last_index)
                                last_index = rlh->seq;
                            payload_size = size - hdrlen;
                            write_re_to_file(packetIn + hdrlen, payload_size, rlh->seq);
                        }
                        pthread_mutex_unlock(&lock);

                        if(last_index >= 0.7 * packets_num)
                            startCallback = 1;

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

    fseek( fp_write, ur_offset, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write);
    fflush(fp_write);
    ur_offset = ur_offset + PAYLOAD_SIZE;
    ur_total++;
    if(ur_total == packets_num  ){
        //printf("File successfully written \n");
        fprintf(stdout, "WRITING TO FILE DONE\n");
        //printTime();
        fclose(fp_write);
        exit(1);
    }
}

void write_re_to_file(u_char * payload, int payload_size, int seqNum){

    fseek( fp_write, seqNum * PAYLOAD_SIZE, SEEK_SET );
    fwrite(payload , payload_size , 1 , fp_write);
    fflush(fp_write);
    total++;
    //fprintf(stdout, "total : %d\n", total);
    if(total == packets_num){
        //fprintf(stdout, "File successfully written \n");
        fprintf(stdout, "FILE WRITING DONE\n");
        //printTime();
        fclose(fp_write);
        //exit(1);
    }
}

int updateTrackPacketsArray(int seq_num){
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

void* handleFailures(void *a)
{
    pcap_t *handle_sniffed_nack = NULL;

    char err[128];
    if ( (handle_sniffed_nack = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	//printf( "OPEN DONE\n");
    while(1)
    {       if(startCallback){
                if(check_all_pckt_rcvd() == 1){
                printf("SEND END\n");
                send_end(handle_sniffed_nack);
                pcap_close(handle_sniffed_nack);
                //pcap_close(handle_sniffed);
                exit(1);
                //pthread_exit(0);
                }
                usleep(100);
                int i;
                for(i = start_index; i < packets_num ; i++)
                    {
                        if(track_packets[i] == 1){
                        start_index ++;
                        }
                        else break;
                    }

                int reqSeqNum = getNackSeqNum();

                if(reqSeqNum >= 0 && reqSeqNum < packets_num){
                //send_nack_to_client(reqSeqNum, handle_sniffed_nack);
                }
            }

        }

}

int getNackSeqNum(){

    if (track_packets == NULL) return -1;
    int i;

    for (i = loop_index; i < packets_num ; i++)
    {
        if(track_packets[i] == 0){
            if( i == packets_num - 1) loop_index = start_index;
            else loop_index = i+1;
            return i;
        }
    }
    loop_index = start_index;
    return -1;
}

void send_nack_to_client(int seqNum, pcap_t *handle_sniffed_nack)
{

    int n, ret;
    u_char packet[PACKET_BUF_SIZE];
    n = generate_route_on_resend_packet(packet, 70, ROUTE_ON_RELIABLE, seqNum);
   // print_dummy_packet(packet, n);
   fprintf(stdout, "Send nack for seqnum : %d to %d of size %d\n", seqNum, dest_addr, n);
    if ((ret = pcap_inject(handle_sniffed_nack, packet, n)) < 0){
            fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
        }
}

int check_all_pckt_rcvd()
{
    if(total == packets_num) return 1;
    else return 0;
}

void send_end( pcap_t *handle_sniffed_nack){

    int n, ret, i;
    u_char packet[PACKET_BUF_SIZE];
    int seqNum = -1;

    n = generate_route_on_resend_packet(packet, 70, ROUTE_ON_RELIABLE, seqNum);
   // print_dummy_packet(packet, n);
    //fprintf(stdout, "Send End atleaast 10 times to %d of size %d\n", dest_addr, n);
    for (i = 0; i < 30; i++){
        if ((ret = pcap_inject(handle_sniffed_nack, packet, n)) < 0){
            fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
        }
    }


}

int generate_route_on_resend_packet(u_char* packetOut, int size, int type, int seqNum) {

	if (size < MIN_APP_PKT_LEN) {
		fprintf(stderr, "ERROR: size should > 60\n");
		return -1;
	}
	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	struct ethhdr* eth = (struct ethhdr*)packetOut;
	memcpy(eth->h_source, my_mac, ETH_ALEN);
    memcpy(eth->h_dest, dest_mac, ETH_ALEN);
	eth->h_proto = ETH_P_IP;
	struct rthdr* rth = (struct rthdr*)(packetOut + sizeof(struct ethhdr));
	rth->saddr = (u_int16_t)(my_addr & 0xffff);
	rth->daddr = (u_int16_t)(dest_addr & 0xffff);
	rth->ttl = (u_int8_t)(0x10 & 0xff);
	rth->protocol = (u_int8_t)type;
	rth->size = htons((u_int16_t)size);
//	rth->dummy[0] = 0x00;
//	rth->dummy[1] = 0x00;
//	rth->dummy[2] = 0x80;
//	rth->dummy[3] = 0x00;
	rth->check = htons(rthdr_chk_gen(rth));

	int i, hdrlen, payload_size;
    //printf("generating resend packets...\n");
    hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
    payload_size = size - hdrlen;
    struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
    rlh->port = (u_int8_t)(port & 0xff);
    if(seqNum == -1){
        rlh->dummy = dummy;
        //print_dummy_packet(packetOut, size);
    }
    else{
    rlh->seq = (u_int32_t)(seqNum & 0xffffffff);
    }

    for (i = hdrlen; i < size; i++) {
        packetOut[i] = (u_char) (0x00000000 & 0x000000ff);
    }
    rlh->check = htons(packet_chk_gen(packetOut, size));

	return size;
}



int main(int argc, char *argv[])
{

    if (argc < 4) {
         fprintf(stderr,"%s", USAGE);
         exit(1);
    }
    //read_arp_cache();
    //printArpT();
    port = atoi(argv[1]);

    filesize = atoi(argv[3]);

    fp_write = fopen(argv[2] , "w+");
    if(fp_write == NULL){
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
    if((pthread_create(&nack_thread, NULL, handleFailures, NULL )) != 0){
        fprintf(stderr, "pthread_create[0] \n");
        pthread_exit(0);
        exit(1);
    }

	pcap_loop(handle_sniffed, -1, process_packet , NULL);	// -1 means an infinite loop
    //printf("Ret : %d \n", ret);
    //fprintf(stdout, "test pcap loop\n");
    //pcap_close(handle_sniffed);
	//fprintf(stdout, "ALL PROCESSING DONE\n");
	//fprintf(stdout, "END OF TEST\n");
    pthread_join(nack_thread, NULL);
    return 0;
}

