/**
 * CS 558L Lab 9
 * 
 * Print packets
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "packet.h"
#include "packet_util.h"
#include "printp.h"

void fprintp(FILE* logfile, u_char* packet, int size) {
	fprintf(logfile, "============================== packet received, size = %d ==============================\n", size);
	struct rthdr* rth = (struct rthdr*) packet;
	switch(rth->protocol) {
		case ROUTE_ON_CONTROL:
			print_ctl_packet(logfile, packet, size);
			break;
		case ROUTE_ON_UNRELIABLE:
			print_ur_packet(logfile, packet, size);
			break;
		case ROUTE_ON_RELIABLE:
			print_rl_packet(logfile, packet, size);
			break;
		default:
			fprintf(logfile, "this is a non route-on defined packet\n");
			print_data(logfile, packet, size);
			break;
	}
	fprintf(logfile, "============================== end of packet ==============================\n\n\n\n\n\n");
}

void print_rthdr(FILE* logfile, struct rthdr* hdr) {
	// TODO: test if we need any ntohs(); or htons();
	fprintf(logfile, "Routing Header:\n");
	fprintf(logfile, "\t|-source:             %04x\n", hdr->saddr);
	fprintf(logfile, "\t|-destination:        %04x\n", hdr->daddr);
	fprintf(logfile, "\t|-ttl:                %d\n", (unsigned int)(hdr->ttl));
	fprintf(logfile, "\t|-protocol:           %d\n", (unsigned int)(hdr->protocol));
	fprintf(logfile, "\t|-size:               %d\n", (unsigned int)ntohs((hdr->size)));
	fprintf(logfile, "\t|-checksum:           %04x\n", ntohs(hdr->check));
	fprintf(logfile, "checksum test: %04x\n", rthdr_chk_gen(hdr));
	fprintf(logfile, "\n");
}

void print_ctl_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) packet;
	print_rthdr(logfile, rth);
	struct chdr* ch = (struct chdr*)(packet + sizeof(struct rthdr));
	fprintf(logfile, "Control Protocol Header:\n");
	fprintf(logfile, "\t|-checksum:           %d\n", ntohs(ch->check));
	fprintf(logfile, "checksum test: %04x\n", packet_chk_gen(packet, size));
	fprintf(logfile, "\n");
	print_data(logfile, packet, size);
}

void print_ur_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) packet;
	print_rthdr(logfile, rth);
	struct urhdr* urh = (struct urhdr*)(packet + sizeof(struct rthdr));
	fprintf(logfile, "Unreliable Protocol Header:\n");
	fprintf(logfile, "\t|-port:              %d\n", (unsigned int)(urh->port));
	fprintf(logfile, "\t|-checksum:          %04x\n", ntohs(urh->check));
	fprintf(logfile, "checksum test: %04x\n", packet_chk_gen(packet, size));
	fprintf(logfile, "\n");
	print_data(logfile, packet, size);
}

void print_rl_packet(FILE* logfile, u_char* packet, int size) {
	struct rthdr* rth = (struct rthdr*) packet;
	print_rthdr(logfile, rth);
	struct rlhdr* rlh = (struct rlhdr*)(packet + sizeof(struct rthdr));
	fprintf(logfile, "Reliable Protocol Header:\n");
	fprintf(logfile, "\t|-port:              %d\n", (unsigned int)(rlh->port));
	fprintf(logfile, "\t|-sequence number:   %d\n", (unsigned int)ntohs((rlh->seq)));
	fprintf(logfile, "\t|-checksum:          %04x\n", ntohs(rlh->check));
	fprintf(logfile, "checksum test: %04x\n", packet_chk_gen(packet, size));
	fprintf(logfile, "\n");
	print_data(logfile, packet, size);
}


void print_data(FILE* logfile, const u_char* data, int size) {
	fprintf(logfile, "Data:\n");
	int i, j;
	for(i=0 ; i < size ; i++) {
		//if one line of hex printing is complete...
    	if( i!=0 && i%16==0) {
      		fprintf(logfile , "         ");
      		for(j=i-16 ; j<i ; j++) {
        		if(data[j]>=32 && data[j]<=128) {
          			fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
          		} else {
          			fprintf(logfile , "."); //otherwise print a dot
          		}
      		}
      		fprintf(logfile , "\n");
    	} 
    
    	if(i%16==0) {
    		fprintf(logfile , "   ");
   		}

		fprintf(logfile , " %02X",(unsigned int)data[i]);
    	
    	//print the last spaces
    	if( i==size-1) {
	    	for(j=0;j<15-i%16;j++) {
	        	fprintf(logfile , "   "); //extra spaces
	    	}
	    
	    	fprintf(logfile , "         ");
	      
	    	for(j=i-i%16 ; j<=i ; j++) {
		        if(data[j]>=32 && data[j]<=128) {
		        	fprintf(logfile , "%c",(unsigned char)data[j]);
		        } else {
		        	fprintf(logfile , ".");
		        }
	    	}
	    	fprintf(logfile ,  "\n" );
    	}
	}
}
