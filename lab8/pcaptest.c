#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

/**
* REFERENCE:
* struct sockaddr_in {
*     short            sin_family;   // e.g. AF_INET
*     unsigned short   sin_port;     // e.g. htons(3490)
*     struct in_addr   sin_addr;     // see struct in_addr, below
*     char             sin_zero[8];  // zero this if you want to
* };

* struct in_addr {
*     unsigned long s_addr;  // load with inet_aton()
* };
*/

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ethernet_header(const u_char *, int);
void print_ip_packet(const u_char * , int);
u_short calc_ip_checksum(const u_char*);
u_short calc_icmp_checksum(const u_char*, int);
void print_tcp_packet(const u_char *  , int);
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int);
void PrintData (const u_char * , int);

/* Global Variables */
FILE* logfile;
struct sockaddr_in source;
struct sockaddr_in dest;
int tcp = 0;
int udp = 0;
int icmp = 0;
int others = 0;
int total = 0;


int main (int argc, char** argv) {
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device
	pcap_t *pcap_handle = NULL;

	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available devices

	int count = 0;
	int n = 0;
	int ret = 0;						// Return val

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

	printf("Trying to open device %s to sniff ... ", device_name);
	if ( (pcap_handle = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	printf( "DONE\n");

	if ( (logfile = fopen("packets.log", "w")) == NULL) {
		fprintf(stderr, "Error opening packets.log\n");
		exit(1);
	}

	//Put the device in sniff loop
  	pcap_loop(pcap_handle , 10 , process_packet , NULL);	// -1 means an infinite loop

	fclose(logfile);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	total++;
	int size = (int) header->len;
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	switch (iph->protocol) {
    	case 1:  //ICMP Protocol
      		++icmp;
      		print_icmp_packet( packet , size);
      		break;
    
    	case 6:  //TCP Protocol
      		++tcp;
     	 	print_tcp_packet(packet , size);
      		break;

	    case 17: //UDP Protocol
      		++udp;
      		print_udp_packet(packet , size);
      		break;
    
    	default: //Some Other Protocol like ARP etc.
      		others++;
      		break;
  	}
  	printf("TCP : %d   UDP : %d   ICMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , others , total);
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	// adapted from <linux/if_ether.h>
 	struct ethhdr *eth = (struct ethhdr *)Buffer;
  
  	fprintf(logfile , "\n");
  	fprintf(logfile , "Received a packet of size %d\n", Size);
  	fprintf(logfile , "Ethernet Header\n");
  	fprintf(logfile , "   |-Destination Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  	fprintf(logfile , "   |-Source Address          : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  	fprintf(logfile , "   |-Protocol                : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;
    
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;	/* ip header length is defined in unit of 32-bit word */
  
	memset(&source, 0, sizeof(source));
  	source.sin_addr.s_addr = iph->saddr;
  
  	memset(&dest, 0, sizeof(dest));
  	dest.sin_addr.s_addr = iph->daddr;
  
  	fprintf(logfile , "\n");
  	fprintf(logfile , "IP Header\n");
  	fprintf(logfile , "Header Length: %u\n", iphdrlen);
  	fprintf(logfile , "   |-IP Version            : %d\n",(unsigned int)iph->version);
  	fprintf(logfile , "   |-IP Header Length      : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  	fprintf(logfile , "   |-Type Of Service       : %d\n",(unsigned int)iph->tos);
  	fprintf(logfile , "   |-IP Total Length       : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
  	fprintf(logfile , "   |-Identification        : %d\n",ntohs(iph->id));
  	fprintf(logfile , "   |-TTL                   : %d\n",(unsigned int)iph->ttl);
  	fprintf(logfile , "   |-Protocol              : %d\n",(unsigned int)iph->protocol);
  	fprintf(logfile , "   |-Checksum              : %d\n",ntohs(iph->check));
  	fprintf(logfile , "   |-Source IP             : %s\n" , inet_ntoa(source.sin_addr) );
  	fprintf(logfile , "   |-Destination IP        : %s\n" , inet_ntoa(dest.sin_addr) );

  	fprintf(logfile , "=====> ip_checksum test result: %u\n", calc_ip_checksum(Buffer));
}

u_short calc_ip_checksum(const u_char* Buffer) {
	struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned int sum = 0;
    #if __BYTE_ORDER == __LITTLE_ENDIAN
            sum = (((u_short)iph->version) << 12) | (((u_short)iph->ihl) << 8) | ((u_short)iph->tos);
    #elif __BYTE_ORDER == __BIG_ENDIAN
            sum = (((u_short)iph->ihl) << 12) | (((u_short)iph->version) << 8) | ((u_short)iph->tos);
    #else
    # error "Please fix <bits/endian.h>"
    #endif
    sum += ntohs(iph->tot_len);
    sum += ntohs(iph->id);
    sum += ntohs(iph->frag_off);
    sum += (((u_short)iph->ttl) << 8) | (u_short)iph->protocol;
    sum += (ntohs((iph->saddr) & 0xffff) + ntohs((iph->saddr >> 16) & 0xffff));
    sum += (ntohs((iph->daddr) & 0xffff) + ntohs((iph->daddr >> 16) & 0xffff));

    int chk = (((u_short)(sum >> 16)) & 0xf) + ((u_short)(sum) & 0xffff);
    return ~((u_short)chk);

}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
  
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
  
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
      
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
  
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
    
	print_ip_header(Buffer,Size);
    
  	fprintf(logfile , "\n");
  	fprintf(logfile , "TCP Header\n");
  	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
  	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
  	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
  	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
  	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
  	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
  	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
  	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
  	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
  	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
  	fprintf(logfile , "\n");
  	fprintf(logfile , "                        DATA Dump                         ");
  	fprintf(logfile , "\n");
    
    fprintf(logfile , "Ethernet Header\n");
  	PrintData(Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr), iphdrlen);
    
  	fprintf(logfile , "TCP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr) + iphdrlen, tcph->doff*4);
    
  	fprintf(logfile , "Data Payload\n");  
  	PrintData(Buffer + header_size , Size - header_size );
            
  	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size)
{
  
  	unsigned short iphdrlen;
  
  	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
  	iphdrlen = iph->ihl*4;
  
  	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  
  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udph);
  
  	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
  
  	print_ip_header(Buffer,Size);     
  
  	fprintf(logfile , "\nUDP Header\n");
  	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
  	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
  	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
  	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  
  	fprintf(logfile , "\n");
  	fprintf(logfile , "Ethernet Header\n");
  	PrintData(Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr), iphdrlen);
    
  	fprintf(logfile , "UDP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr) + iphdrlen , sizeof(udph));
    
  	fprintf(logfile , "Data Payload\n");  
  
  	//Move the pointer ahead and reduce the size of string
  	PrintData(Buffer + header_size , Size - header_size);
  
  	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(const u_char * Buffer , int Size)
{
  	unsigned short iphdrlen;
  
  	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
  	iphdrlen = iph->ihl * 4;
  
  	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  
  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
  
  	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
  
  	print_ip_header(Buffer , Size);
      
  	fprintf(logfile , "\n");
    
  	fprintf(logfile , "ICMP Header\n");
  	fprintf(logfile , "Header Length: %lu\n", sizeof(struct icmphdr));
  	fprintf(logfile , "   |-Type 			: %d\n",(unsigned int)(icmph->type));
      
  	if((unsigned int)(icmph->type) == 11)
  	{
    	fprintf(logfile , "  (TTL Expired)\n");
  	}
  	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
  	{
    	fprintf(logfile , "  (ICMP Echo Reply)\n");
  	}
  
  	fprintf(logfile , "   |-Code 			: %d\n",(unsigned int)(icmph->code));
  	fprintf(logfile , "   |-Checksum 		: %d\n",ntohs(icmph->checksum));
  	fprintf(logfile , "   |-Echo id 		: %d\n",ntohs(((icmph->un).echo).id));
  	fprintf(logfile , "   |-Echo sequence 	: %d\n",ntohs(((icmph->un).echo).sequence));
  	fprintf(logfile , "\n");

  	fprintf(logfile , "=====> ICMP checksum test result: %u\n", calc_icmp_checksum(Buffer, Size));

  	fprintf(logfile , "Ethernet Header\n");
  	PrintData(Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr), iphdrlen);

  	fprintf(logfile , "ICMP Header\n");
  	PrintData(Buffer + sizeof(struct ethhdr) + iphdrlen, sizeof(struct icmphdr));
    
  	fprintf(logfile , "Data Payload\n");  
  
  	//Move the pointer ahead and reduce the size of string
  	PrintData(Buffer + header_size , (Size - header_size) );
  
  	fprintf(logfile , "\n###########################################################");
}

u_short calc_icmp_checksum(const u_char* Buffer, int Size) {
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
  	int iphdrlen = iph->ihl * 4;

  	u_char* ptr = Buffer + sizeof(struct ethhdr) + iphdrlen;
  	int packetLen = Size - sizeof(struct ethhdr) + iphdrlen;
  	printf("Icmp Packet Length: %d\n", packetLen);
	unsigned int sum = 0;
	int i = 0;
	for (; i < packetLen-1; i = i + 2 ) {
		if (i != 2) {
			sum += (*ptr << 8) | *(ptr+1);
		}
		ptr = ptr + 2;
	}
	if (i == packetLen-1) {
		sum += *(ptr+1);
	}

	
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	// Do this once more to prevent the carry outs from causing another unhandled carry out
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	return (u_short)(~sum);
}

void PrintData (const u_char * data , int Size)
{
  int i , j;
  for(i=0 ; i < Size ; i++)
  {
    if( i!=0 && i%16==0)   //if one line of hex printing is complete...
    {
      fprintf(logfile , "         ");
      for(j=i-16 ; j<i ; j++)
      {
        if(data[j]>=32 && data[j]<=128)
          fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
        
        else fprintf(logfile , "."); //otherwise print a dot
      }
      fprintf(logfile , "\n");
    } 
    
    if(i%16==0) fprintf(logfile , "   ");
      fprintf(logfile , " %02X",(unsigned int)data[i]);
        
    if( i==Size-1)  //print the last spaces
    {
      for(j=0;j<15-i%16;j++) 
      {
        fprintf(logfile , "   "); //extra spaces
      }
      
      fprintf(logfile , "         ");
      
      for(j=i-i%16 ; j<=i ; j++)
      {
        if(data[j]>=32 && data[j]<=128) 
        {
          fprintf(logfile , "%c",(unsigned char)data[j]);
        }
        else 
        {
          fprintf(logfile , ".");
        }
      }
      
      fprintf(logfile ,  "\n" );
    }
  }
}

