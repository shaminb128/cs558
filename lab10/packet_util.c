/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <netinet/in.h>
 //#include <net/ethernet.h>
 #include "packet_util.h"
 //#include "printp.h"

u_int16_t rthdr_chk_gen(struct rthdr* rth) {
 	unsigned int sum = 0;
 	sum += rth->saddr;
 	sum += rth->daddr;
 	sum += (u_short)(rth->ttl << 8) | (u_short)(rth->protocol);
 	sum += rth->size;

 	int check = (((u_short)(sum >> 16)) & 0xf) + ((u_short)(sum) & 0xffff); // take carryouts
 	return (u_int16_t)(~check);
}

u_int16_t packet_chk_gen(u_char* packet, int size) {
 	u_char* ptr = packet + sizeof(struct ethhdr) + sizeof(struct rthdr);
 	int packetLen = size - (sizeof(struct ethhdr) + sizeof(struct rthdr));
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
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	return (u_short)(~sum);
}

int verify_rthdr_chk(struct rthdr* rth) {
 	if (rthdr_chk_gen(rth) != ntohs(rth->check)) {
		return -1;
	}
	return 0;
 }

int verify_packet_chk(u_char* packet, int size, int type) {
	struct chdr* ch = NULL;
	struct urhdr* urh = NULL;
	struct rlhdr* rlh = NULL;
	switch(type) {
		case ROUTE_ON_CONTROL:
			ch = (struct chdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
			if (packet_chk_gen(packet, size) != ntohs(ch->check)) {
				//fprintf(stdout, "test check: %04x, packet check: %04x\n", packet_chk_gen(packet, size), ntohs(ch->check));
				return -1;
			}
			break;
		case ROUTE_ON_UNRELIABLE:
			urh = (struct urhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
			if (packet_chk_gen(packet, size) != ntohs(urh->check)) {
				//fprintf(stdout, "test check: %04x, packet check: %04x\n", packet_chk_gen(packet, size), ntohs(ch->check));
				return -1;
			}
			break;
		case ROUTE_ON_RELIABLE:
			rlh = (struct rlhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct rthdr));
			if (packet_chk_gen(packet, size) != ntohs(rlh->check)) {
				//fprintf(stdout, "test check: %04x, packet check: %04x\n", packet_chk_gen(packet, size), ntohs(ch->check));
				return -1;
			}
			break;
		default:
			fprintf(stderr, "ERROR: verify_packet_chk: type not supported\n");
			break;
	}
	return 0;
}

int generate_random_packet(u_char* packetOut, int size) {
	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	sprintf((char*)packetOut, "here is a random packet with size %d*", size);
	int len = strlen((const char*)packetOut);
	int i;
	for (i = len; i < size; i++) {
		packetOut[i] = (u_char) (rand() & 0x000000ff);
	}
	return size;
}
int generate_route_on_packet(u_char* packetOut, int size, int type) {
	if (size < MIN_APP_PKT_LEN) {
		fprintf(stderr, "ERROR: size should > 60\n");
		return -1;
	}
	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	struct rthdr* rth = (struct rthdr*)(packetOut + sizeof(struct ethhdr));
	rth->saddr = (u_int16_t)(rand() & 0xffff);
	rth->daddr = (u_int16_t)(rand() & 0xffff);
	rth->ttl = (u_int8_t)(rand() & 0xff);
	rth->protocol = (u_int8_t)type;
	rth->size = htons((u_int16_t)size);
	rth->check = htons(rthdr_chk_gen(rth));
	//memcpy(&rth, packetOut, sizeof(struct rthdr));
	//print_data(stdout, packetOut, size);
	int i, len;

	switch(type) {
		case ROUTE_ON_CONTROL:
			fprintf(stdout, "WARNING: generate_route_on_packet: does not support ROUTE_ON_CONTROL\n");
			return -1;
		case ROUTE_ON_UNRELIABLE:
			//printf("generating unreliable packets...\n");
			len = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct urhdr);
			struct urhdr* urh = (struct urhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
			urh->port = (u_int8_t)(rand() & 0xff);
			//memcpy(&urh, packetOut + sizeof(struct rthdr), sizeof(struct urhdr));
			//print_data(stdout, packetOut, size);
			for (i = len; i < size; i++) {
				packetOut[i] = (u_char) (rand() & 0x000000ff);
			}
			//struct urhdr* urhptr = (struct urhdr*)(packetOut + sizeof(struct rthdr));
			urh->check = htons(packet_chk_gen(packetOut, size));
			break;
		case ROUTE_ON_RELIABLE:
		//printf("generating reliable packets...\n");
			len = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr);
			struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
			rlh->port = (u_int8_t)(rand() & 0xff);
			rlh->seq = (u_int16_t)(rand() & 0xffff);
			//memcpy(&rlh, packetOut + sizeof(struct rthdr), sizeof(struct rlhdr));
			//print_data(stdout, packetOut, size);
			for (i = len; i < size; i++) {
				packetOut[i] = (u_char) (rand() & 0x000000ff);
			}
			//struct rlhdr* rlhptr = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
			rlh->check = htons(packet_chk_gen(packetOut, size));
			break;
		default:
			fprintf(stderr, "ERROR: protocol not supported\n");
			return -1;
	}
	return size;
}

int generate_route_on_packet_2(u_char* packetOut, int size, int type, int seq, int source, int dest) {
	
	struct rthdr* rth = (struct rthdr*)(packetOut + ETH_HLEN);
	switch(source) {
		case 1:
			rth->saddr = (u_int16_t)(0x0011);
			break;
		case 2:
			rth->saddr = (u_int16_t)(0x0021);
			break;
		case 3:
			rth->saddr = (u_int16_t)(0x0031);
			break;
		default:
			return -1;
	}

	switch(dest) {
		case 1:
			rth->daddr = (u_int16_t)(0x0011);
			break;
		case 2:
			rth->daddr = (u_int16_t)(0x0021);
			break;
		case 3:
			rth->daddr = (u_int16_t)(0x0031);
			break;
		default:
			return -1;
	}

	rth->ttl = (u_int8_t)(64 & 0xff);
	rth->protocol = (u_int8_t)type;
	rth->size = htons((u_int16_t)size);
	rth->check = htons(rthdr_chk_gen(rth));
	//memcpy(&rth, packetOut, sizeof(struct rthdr));
	//print_data(stdout, packetOut, size);
	int i, len;

	switch(type) {
		case ROUTE_ON_CONTROL:
			fprintf(stdout, "WARNING: generate_route_on_packet: does not support ROUTE_ON_CONTROL\n");
			return -1;
		case ROUTE_ON_UNRELIABLE:
			//printf("generating unreliable packets...\n");
			len = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct urhdr);
			struct urhdr* urh = (struct urhdr*)(packetOut + sizeof(struct ethhdr) + sizeof(struct rthdr));
			urh->port = (u_int8_t)(rand() & 0xff);
			//memcpy(&urh, packetOut + sizeof(struct rthdr), sizeof(struct urhdr));
			//print_data(stdout, packetOut, size);
			for (i = len; i < size; i++) {
				packetOut[i] = (u_char) (rand() & 0x000000ff);
			}
			//struct urhdr* urhptr = (struct urhdr*)(packetOut + sizeof(struct rthdr));
			urh->check = htons(packet_chk_gen(packetOut, size));
			break;
		case ROUTE_ON_RELIABLE:
		//printf("generating reliable packets...\n");
			len = ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr) + 67;
			struct rlhdr* rlh = (struct rlhdr*)(packetOut + ETH_HLEN + sizeof(struct rthdr));
			rlh->port = (u_int8_t)(rand() & 0xff);
			rlh->seq = htons(seq);
			//memcpy(&rlh, packetOut + sizeof(struct rthdr), sizeof(struct rlhdr));
			//print_data(stdout, packetOut, size);
			char* content = (char*)(packetOut + ETH_HLEN + sizeof(struct rthdr) + sizeof(struct rlhdr));
			sprintf(content, "!!!this is a test packet with seqnum %04d, from node %d to node %d!!!", seq, source, dest);
			for (i = len; i < size; i++) {
				packetOut[i] = (u_char) (rand() & 0x000000ff);
			}
			//struct rlhdr* rlhptr = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
			rlh->check = htons(packet_chk_gen(packetOut, size));
			break;
		default:
			fprintf(stderr, "ERROR: protocol not supported\n");
			return -1;
	}
	return size;
}

int generate_openflow_test_packet(u_char* packetOut, int size, int seq, int source, int dest) {
	int len = (size < ( sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr) + 67)) ? 
				( sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct rlhdr) + 67 ) : size;

	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	struct ethhdr* eth = (struct ethhdr*) packetOut;
	switch (source) {
		case 1:
			eth->h_source[0] = 0x00;
			eth->h_source[1] = 0x15;
			eth->h_source[2] = 0x17;
			eth->h_source[3] = 0x5d;
			eth->h_source[4] = 0x17;
			eth->h_source[5] = 0x0c;
			break;
		case 2:
			eth->h_source[0] = 0x00;
			eth->h_source[1] = 0x15;
			eth->h_source[2] = 0x17;
			eth->h_source[3] = 0x5d;
			eth->h_source[4] = 0x13;
			eth->h_source[5] = 0x6c;
			break;
		case 3:
			eth->h_source[0] = 0x00;
			eth->h_source[1] = 0x15;
			eth->h_source[2] = 0x17;
			eth->h_source[3] = 0x5d;
			eth->h_source[4] = 0x33;
			eth->h_source[5] = 0x64;
			break;
		default:
			return -1; 
	}

	switch (dest) {
		case 1:
			eth->h_dest[0] = 0x00;
			eth->h_dest[1] = 0x15;
			eth->h_dest[2] = 0x17;
			eth->h_dest[3] = 0x5d;
			eth->h_dest[4] = 0x17;
			eth->h_dest[5] = 0x0c;
			break;
		case 2:
			eth->h_dest[0] = 0x00;
			eth->h_dest[1] = 0x15;
			eth->h_dest[2] = 0x17;
			eth->h_dest[3] = 0x5d;
			eth->h_dest[4] = 0x13;
			eth->h_dest[5] = 0x6c;
			break;
		case 3:
			eth->h_dest[0] = 0x00;
			eth->h_dest[1] = 0x15;
			eth->h_dest[2] = 0x17;
			eth->h_dest[3] = 0x5d;
			eth->h_dest[4] = 0x33;
			eth->h_dest[5] = 0x64;
			break;
		default:
			return -1; 
	}
	eth->h_proto = 0x0000;


	int ret = generate_route_on_packet_2(packetOut, 
								len, 
								ROUTE_ON_RELIABLE, 
								seq,
								source,
								dest);
	/*char* content = (char*)(packetOut + ETH_HLEN);
	sprintf(content, "!!!this is a test packet with seqnum %04d, from node %d to node %d!!!", seq, source, dest);
	int i;
	for (i = 81; i < len; i++) {
		packetOut[i] = (u_char) (rand() & 0x000000ff);
	}*/
	return (ret == -1) ? -1 : len;
}
