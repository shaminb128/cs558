/**
 * CS 558L Lab 9
 *
 * Packet related data structures and methods
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <netinet/in.h>
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
 	u_char* ptr = packet + sizeof(struct rthdr);
 	int packetLen = size - sizeof(struct rthdr);
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
			ch = (struct chdr*)(packet + sizeof(struct rthdr));
			if (packet_chk_gen(packet, size) != ntohs(ch->check)) {
				//fprintf(stdout, "test check: %04x, packet check: %04x\n", packet_chk_gen(packet, size), ntohs(ch->check));
				return -1;
			}
			break;
		case ROUTE_ON_UNRELIABLE:
			urh = (struct urhdr*)(packet + sizeof(struct rthdr));
			if (packet_chk_gen(packet, size) != ntohs(urh->check)) {
				//fprintf(stdout, "test check: %04x, packet check: %04x\n", packet_chk_gen(packet, size), ntohs(ch->check));
				return -1;
			}
			break;
		case ROUTE_ON_RELIABLE:
			rlh = (struct rlhdr*)(packet + sizeof(struct rthdr));
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
	struct rthdr* rth = (struct rthdr*)packetOut;
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
			len = sizeof(struct rthdr) + sizeof(struct urhdr);
			struct urhdr* urh = (struct urhdr*)(packetOut + sizeof(struct rthdr));
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
			len = sizeof(struct rthdr) + sizeof(struct rlhdr);
			struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
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
