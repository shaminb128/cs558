/**
 * 558l lab9
 */
#include "sender.h"
#include "../printp.h"
#define USAGE "Usage: ./client [filename] [hostname] [portno] "


void init(){
    my_addr = 0x0011;
    seqNum=0;
}

void printTime(){
 time_t rawtime;
  struct tm * timeinfo;

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  printf ( "Current time: %s", asctime (timeinfo) );
}

int generate_route_on_file_packet(u_char* packetOut, char * payload, int size, int type) {

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
			strncpy(packetOut + hdrlen, payload, payload_size);
			urh->check = htons(packet_chk_gen(packetOut, size));
			printf("Sending a UNRELIABLE packet of size: %d\n" , size);
			break;
		case ROUTE_ON_RELIABLE:
		//printf("generating reliable packets...\n");
			hdrlen = sizeof(struct rthdr) + sizeof(struct rlhdr);
			struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
			rlh->port = (u_int8_t)(rand() & 0xff);
			rlh->seq = (u_int16_t)(rand() & 0xffff);
			//memcpy(&rlh, packetOut + sizeof(struct rthdr), sizeof(struct rlhdr));
			//print_data(stdout, packetOut, size);
//			for (i = len; i < size; i++) {
//				packetOut[i] = (u_char) (rand() & 0x000000ff);
//			}
			//struct rlhdr* rlhptr = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
			rlh->check = htons(packet_chk_gen(packetOut, size));
			break;
		default:
			fprintf(stderr, "ERROR: protocol not supported\n");
			return -1;
	}
	return size;
}


int main(int argc, char *argv[])
{
    pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available
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
		printf("%d. %s\t-\t%s\n", count, device_ptr->name, device_ptr->description);
		if (device_ptr->name != NULL) {
			strcpy(devices[count], device_ptr->name);
		}
		count++;
	}

	printf("Which device do you want to sniff? Enter the number:\n");
	scanf("%d", &n);
	device_name = devices[n];

	printf("Trying to open device %s to send ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	printf("DONE \n");
	printTime();
	printf("generating packets...\n");

    u_char packet[PACKET_BUF_SIZE];
    char payload[PAYLOAD_SIZE];
    int payload_size;
    long offset = 0;
    init();
    fp_read = fopen(argv[1], "r");
    if(fp_read == NULL){
        fprintf(stderr, "File open failed");
        exit(1);
    }
    fseek(fp_read, 0L, SEEK_END);
    filesize = ftell(fp_read);

    if((filesize % PAYLOAD_SIZE) != 0)
        no_of_packets = (filesize/PAYLOAD_SIZE)+1;
    else
        no_of_packets = (filesize/PAYLOAD_SIZE);
    fseek(fp_read, 0L, SEEK_SET);

    if(strcmp(argv[2], "node1") == 0)
        dest_addr = 0x0011;
    else if(strcmp(argv[2], "node2") == 0)
        dest_addr = 0x0021;
    else if(strcmp(argv[2], "node3") == 0)
        dest_addr = 0x0031;

    port = atoi(argv[3]);
    //printf("Seq No: %d,  No of packets  %d \n" , seqNum, no_of_packets);
    //printf("My Ip: %02x, dest IP : %02x, port no: %d, FS: %d, Packet #: %d\n", my_addr, dest_addr, port, filesize, no_of_packets );
    while (seqNum < no_of_packets) {

        //printf("Seq: %d, Offset : %d\n", seqNum, offset);
        fseek(fp_read, offset, SEEK_SET);
        if(seqNum == (no_of_packets-1)){
            payload_size = filesize % PAYLOAD_SIZE;
        	//printf("Read the last payload of size %d\n" , filesize% PAYLOAD_SIZE);
        	}
        else{
            payload_size = PAYLOAD_SIZE;
        	}
        fread(payload, 1, payload_size, fp_read);
        offset = offset + payload_size;
        //printf("Read data : %s \n", payload);
        int pktlen = generate_route_on_file_packet(packet, payload, payload_size + UR_HEADER_SIZE, ROUTE_ON_UNRELIABLE );

        if ((ret = pcap_inject(handle_sniffed, packet, pktlen)) < 0){
            fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
        }
        //printf("Size returned:%d\n", pktlen);
        //fprintp(stdout, packet, pktlen);
        seqNum++;
    }
    pcap_close(handle_sniffed);
    printf( "DONE\n");
    return 1;
}
