/**
 * CS 558L Lab8
 */

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

#include "packet_util.h"

void print_ethernet_header(FILE* logfile, const u_char *Buffer, int Size)
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

void print_ip_header(FILE* logfile, const u_char * Buffer, int Size)
{
	print_ethernet_header(logfile, Buffer , Size);

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

void print_tcp_packet(FILE* logfile, const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
  
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
  
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
      
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
  
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
    
	print_ip_header(logfile, Buffer, Size);
    
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
  	PrintData(logfile, Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr), iphdrlen);
    
  	fprintf(logfile , "TCP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr) + iphdrlen, tcph->doff*4);
    
  	fprintf(logfile , "Data Payload\n");  
  	PrintData(logfile, Buffer + header_size , Size - header_size );
            
  	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(FILE* logfile, const u_char *Buffer , int Size)
{
  
  	unsigned short iphdrlen;
  
  	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
  	iphdrlen = iph->ihl*4;
  
  	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  
  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udph);
  
  	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
  
  	print_ip_header(logfile, Buffer, Size);     
  
  	fprintf(logfile , "\nUDP Header\n");
  	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
  	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
  	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
  	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  
  	fprintf(logfile , "\n");
  	fprintf(logfile , "Ethernet Header\n");
  	PrintData(logfile, Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr), iphdrlen);
    
  	fprintf(logfile , "UDP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr) + iphdrlen , sizeof(udph));
    
  	fprintf(logfile , "Data Payload\n");  
  
  	//Move the pointer ahead and reduce the size of string
  	PrintData(logfile, Buffer + header_size , Size - header_size);
  
  	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(FILE* logfile, const u_char * Buffer , int Size)
{
  	unsigned short iphdrlen;
  
  	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
  	iphdrlen = iph->ihl * 4;
  
  	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  
  	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
  
  	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
  
  	print_ip_header(logfile, Buffer , Size);
      
  	fprintf(logfile , "\n");
    
  	fprintf(logfile , "ICMP Header\n");
  	fprintf(logfile , "Header Length: %u\n", sizeof(struct icmphdr));
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
  	PrintData(logfile, Buffer, sizeof(struct ethhdr) );

  	fprintf(logfile , "IP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr), iphdrlen);

  	fprintf(logfile , "ICMP Header\n");
  	PrintData(logfile, Buffer + sizeof(struct ethhdr) + iphdrlen, sizeof(struct icmphdr));
    
  	fprintf(logfile , "Data Payload\n");  
  
  	//Move the pointer ahead and reduce the size of string
  	PrintData(logfile, Buffer + header_size , (Size - header_size) );
  
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

void PrintData (FILE* logfile, const u_char * data , int Size)
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