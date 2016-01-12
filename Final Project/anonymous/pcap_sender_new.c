#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h> //hostent
#include <time.h>
#include <linux/if_ether.h>
#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"
#include "libkeystore.h"
#include "env.h"
#define PAYLOAD_SIZE 1024
#define RETRANSMISSION 1
#define H_LEN 30
#define BUF_SIZ 1024


int numberOfPackets;
int bitSeqNo;
int nackNo;
u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut_e[PACKET_BUF_SIZE];
u_char head_e[30];
u_char payload_e[PAYLOAD_SIZE];
struct timespec start, stop;
double duration;
int * seq_array;
char * bitSeq;
char * buffer;
DES_key_schedule schedule1;
DES_key_schedule schedule2;

struct sockaddr_ll socket_address;

void getBin(int value, char *output)
{
    int i;
    output[9] = '\0';
    for (i = 7; i >= 0; --i, value >>= 1)
    //for (i = 0; i <=7; i++, value >>= 1)
    {
        output[i] = (value & 1) + '0';
    }
}



//Unction to send file Packets
/*
void send_file_packet(int sockfd, unsigned char* payload, int source,int dest, int packetsize, int port, int seq)
{
	
	//u_char payload_e[packetsize];
	//memset(payload_e,0,packetsize);
	
	//encrypt payload
	//encrypt((const u_char *)payload, payload_e, &schedule2, packetsize);
	
	int pktlen = generate_file_packet(packetOut, payload, (u_int16_t)source, (u_int16_t)dest, packetsize, port, seq);
	//print packet
	fprintp(stdout,packetOut,pktlen);
	//memset(head_e,0,30);
	//encrypt header
	//int header_size = 30;
	//encrypt((const u_char *)(packetOut+ETH_HLEN), head_e, &schedule1, sizeof(struct rthdr));
	//memcpy(packetOut+ETH_HLEN,head_e,sizeof(struct rthdr));
	//send packets via raw sockets//
	if (sendto(sockfd, packetOut, packetsize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
	usleep(50);
}
*/
int recv_packets_first(){
	printf("In Receive Packet First New\n");
	int s; /*socketdescriptor*/
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    char* buffer = (char*)malloc(1054); /*Buffer for ethernet frame*/
	//static int seq_array[7128];
	int length = 0; /*length of the received frame*/
	//bitSeq = (char *)calloc(bitSeqNo,sizeof(char));
	u_int8_t dummy=0;
	char str[9];
	u_char * seqNo;
	int array_counter=0;
	int kk=0;
	int value=0;
	int seq=0;
	int ret;
	int size;
	int c;
	u_char * data;
	memset(seq_array,0,numberOfPackets);
    while(1){
    	length = recvfrom(s, buffer, 1054, 0, NULL, NULL);
        if ((ret = validate_packet((u_char*)(buffer))) == ROUTE_ON_RELIABLE) {
        	printf("Got A NACK Packet\n");
        	/*for(c=30;c<length;c++)
        	{
        		printf("%c\n",buffer[c] );
        	}*/
        	//fprintf(stdout, "%s\n",buffer+30);
        	//printf("\n");
        	//struct rthdr* hdr = (struct rthdr*) (buffer + sizeof(struct ethhdr));
        	//size= (int)ntohs((hdr->size));
        	struct rlhdr* rlh = (struct rlhdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct rthdr));
			dummy=(int) rlh->dummy;
			data = buffer + sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof (struct rlhdr);
			seqNo = strtok(data, ",");
			while(seqNo != NULL){
				array_counter = atoi(seqNo);
				seq_array[array_counter]=1;
				//printf("%d",array_counter);
				seqNo =strtok(NULL,",");
			}
			//seq=(int) rlh->seq;
			//array_counter=seq*1024;
			
			if (dummy)
			{
				printf("In DUmmy : Got you fucking Dummy:%d\n",numberOfPackets);
				int ctr=0;
				int l=0;
				for(l=0;l<numberOfPackets;l++)
				{
					if(seq_array[l] == 1)
						ctr=ctr+1;
					//printf("%d\n",seq_array[l]);
				}	
				printf("Total Packets to resend:%d\n",ctr);
				return;
			}
		}
	}
close(s);
}

int lastIndex()
{
	int i=0;
	int index=0;

	for(i=0;i<numberOfPackets;i++){
		if(seq_array[i] == 1)
			index = i;
	}
	return index;
}

void send_packets(char * device_name){
	printf("Sending Missing Packets\n");
	char character;
	int idx = lastIndex();
	int counter;
	int ii=0;
    int tx_len = 0;
    unsigned char sendbuf[BUF_SIZ];
   	int t=0;
	int i=0;
	int s; /*socketdescriptor*/
	FILE *fr;
	fr = fopen ("/tmp/test.txt", "rb");
	fseek(fr, 0, SEEK_END);
	long fsize = ftell(fr);
	fseek(fr, 0, SEEK_SET);
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, device_name, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFINDEX, &if_idx) < 0)
    		perror("SIOCGIFINDEX");

	struct sockaddr_ll socket_address;
	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = if_idx.ifr_ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;		
	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x15;		
	socket_address.sll_addr[2]  = 0x17;
	socket_address.sll_addr[3]  = 0x57;
	socket_address.sll_addr[4]  = 0xc7;
	socket_address.sll_addr[5]  = 0x6f;
		/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

    for(t=0;t< numberOfPackets; t++) {

    	memset(sendbuf, 0, BUF_SIZ);
	    tx_len=0;
        unsigned char ch;
        for (ii = 0; ii < PAYLOAD_SIZE; ii++) {
        	ch=fgetc(fr);
        	counter++;
        	if(((int)fsize < counter))
        		break;
        	else{
                   sendbuf[tx_len++] = ch;
                }
        }
        int pktlen;
        int y=0;
        if (seq_array[t] == 0)
        	continue;
        memset(payload_e,0,PAYLOAD_SIZE);
        memset(head_e,0,30);
        //fprintf(stdout, "source: %.4x; dest: %.4x; len: %d; seq: %d;\n", NODE1_RTR1, NODE2_RTR1, tx_len, t);
        //send_file_packet(sockfd, sendbuf, NODE1_RTR1, NODE2_RTR1, tx_len, 5, t);
        encrypt((const u_char *)sendbuf, payload_e, &schedule2, tx_len);
        printf("Payload Size:%d\n",strlen(payload_e));
        if (t==idx){
        	printf("Last packet\n");
        	pktlen = generate_file_packet(packetOut, payload_e,NODE1_RTR1,NODE2_RTR1, tx_len, 5, t,1);
        }
       	else
       		pktlen = generate_file_packet(packetOut, payload_e,NODE1_RTR1,NODE2_RTR1, tx_len, 5, t,0);
       	int header_size = 30;
		encrypt((const u_char *)(packetOut+ETH_HLEN), head_e, &schedule1, sizeof(struct rthdr));
		memcpy(packetOut+ETH_HLEN,head_e,sizeof(struct rthdr));
		//print_rl_packet(stdout, packetOut, pktlen);
        //fprintp(stdout,packetOut,pktlen);
        if (t==idx){
        	for(y=0;y<10;y++)
        	{
        		if (sendto(s, packetOut, pktlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
		usleep(50);

        	}
        }
        else{
        if (sendto(s, packetOut, pktlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
		usleep(50);
    }
}
   fclose(fr);
   close(s);

}


int open_raw_socket(char * device_name)
{
	int s; /*socketdescriptor*/
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, device_name, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFINDEX, &if_idx) < 0)
    		perror("SIOCGIFINDEX");

	struct sockaddr_ll socket_address;
	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = if_idx.ifr_ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;		
	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x15;		
	socket_address.sll_addr[2]  = 0x17;
	socket_address.sll_addr[3]  = 0x57;
	socket_address.sll_addr[4]  = 0xc7;
	socket_address.sll_addr[5]  = 0x6f;
		/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

	return s;
}

int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	int sockfd;
	int ii=0;
	int tx_len = 0;
    	unsigned char sendbuf[BUF_SIZ];
   	int t=0;
	int counter = 0;
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *handle_sniffed = NULL;
	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available
	int count = 0;
	int ret;
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
	printf( "DONE\n");

	//pcap_loop(handle_sniffed , 5 , process_packet , NULL);
    //initialize keys
	unsigned char key1[8];
    //key = get_key(5);
    //key1[0] = 0x32; key1[1] = 0x12; key1[2]= 0x2f; key1[3] = 0xe3;
    //key1[0] = 0x33; key1[1] = 0x13; key1[2]= 0x3f; key1[3] = 0xe4; key1[4]=0xf5; key1[5]=0xf5; key1[6]=0xf5; key1[7]=0xf5; 
    strcpy(key1,"node1");
    //printKey(key1, 4);
    initDes(key1,&schedule1);
    printKey(&schedule1,8);
	
	unsigned char key2[8];
    //key = get_key(5);
    //key2[0] = 0x33; key2[1] = 0x13; key2[2]= 0x3f; key2[3] = 0xe4; key2[4]=0xf5; key2[5]=0xf5; key2[6]=0xf5; key2[7]=0xf5;
    //printKey(key2, 4);
    strcpy(key2,"node1");
	initDes(key2,&schedule2);
	printKey(&schedule2,8);
	//open raw socket
	int s; /*socketdescriptor*/
	
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, device_name, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFINDEX, &if_idx) < 0)
    		perror("SIOCGIFINDEX");

	struct sockaddr_ll socket_address;
	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = if_idx.ifr_ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;		
	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x15;		
	socket_address.sll_addr[2]  = 0x17;
	socket_address.sll_addr[3]  = 0x57;
	socket_address.sll_addr[4]  = 0xc7;
	socket_address.sll_addr[5]  = 0x6f;
		/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/
	int y;
	//
	FILE *fr;
    fr = fopen ("/tmp/test.txt", "rb");
	fseek(fr, 0, SEEK_END);
	long fsize = ftell(fr);
	fseek(fr, 0, SEEK_SET);
	//int numberOfPackets;
	if ((int)fsize%PAYLOAD_SIZE!=0) 
			numberOfPackets = (int)(fsize/PAYLOAD_SIZE) + 1;
		else 
			numberOfPackets =(int)(fsize/PAYLOAD_SIZE);

	//calculate bitSeqNo
	if (numberOfPackets%8 !=0)
		bitSeqNo = (numberOfPackets/8)+1;
	else
		bitSeqNo = (numberOfPackets/8);
	//calculate No Of NACK PACKETS
	if (bitSeqNo%1024 != 0)
		nackNo = (bitSeqNo/1024) + 1;
	else
		nackNo = (bitSeqNo/1024);

	//Allocate arrays for sequence number
	seq_array = (int *)calloc(numberOfPackets,sizeof(int));
	printf("Sending Initial Trasmission\n");
	//numberOfPackets=0;
    for(t=0;t< numberOfPackets; t++) {
    	memset(sendbuf, 0, BUF_SIZ);
	    tx_len=0;
        unsigned char ch;
        for (ii = 0; ii < PAYLOAD_SIZE; ii++) {
        	ch=fgetc(fr);
        	counter++;
        	if(((int)fsize < counter))
        		break;
        	else{
                    sendbuf[tx_len++] = ch;
                }
        }
        int pktlen;
        memset(payload_e,0,PAYLOAD_SIZE);
        memset(head_e,0,30);
        //fprintf(stdout, "source: %.4x; dest: %.4x; len: %d; seq: %d;\n", NODE1_RTR1, NODE2_RTR1, tx_len, t);
        //send_file_packet(sockfd, sendbuf, NODE1_RTR1, NODE2_RTR1, tx_len, 5, t);
        encrypt((const u_char *)sendbuf, payload_e, &schedule2, tx_len);
        if (t==numberOfPackets-1){
        	printf("Last packet\n");
        	pktlen = generate_file_packet(packetOut, payload_e,NODE1_RTR1,NODE2_RTR1, tx_len, 5, t,1);
        }
       	else
       		pktlen = generate_file_packet(packetOut, payload_e,NODE1_RTR1,NODE2_RTR1, tx_len, 5, t,0);
       	int header_size = 30;
		encrypt((const u_char *)(packetOut+ETH_HLEN), head_e, &schedule1, sizeof(struct rthdr));
		memcpy(packetOut+ETH_HLEN,head_e,sizeof(struct rthdr));
		//print_rl_packet(stdout, packetOut, pktlen);
        //fprintp(stdout,packetOut,pktlen);
        if (t==numberOfPackets-1){
        	for(y=0;y<10;y++)
        	{
        		if (sendto(s, packetOut, pktlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
		usleep(50);

        	}
        }
        else{
        if (sendto(s, packetOut, pktlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
		usleep(50);
	}
    }
    fclose(fr);
    //open socket to receive retransmission

    recv_packets_first();
    //loop till file is sent completed
    int sum=0;
	int p=0;
    while(1){
		for(p=0;p<numberOfPackets;p++){
			if (seq_array[p]==1)
				sum=sum+1;
		}
		printf("Total number of packets to resend: %d\n",sum);
		send_packets(device_name);
		int br=recv_packets_first();			
		if (!sum){
			printf("Got everything, breaking\n");
			break;
		}
	}
    close(s);
	return 0;
}


