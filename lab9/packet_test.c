#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>

#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "routing.h"


int main (int argc, char** argv) {
	srand(time(NULL));
	u_char packetOut[PACKET_BUF_SIZE];
	struct rthdr* rth;
	int ret;

	int pktlen = generate_route_on_packet(packetOut, 128, ROUTE_ON_RELIABLE);
	fprintp(stdout, packetOut, pktlen);

	pktlen = generate_route_on_packet(packetOut, 128, ROUTE_ON_UNRELIABLE);
	fprintp(stdout, packetOut, pktlen);

// routing_ops tests
	pktlen = generate_route_on_packet(packetOut, 128, ROUTE_ON_UNRELIABLE);
	fprintp(stdout, packetOut, pktlen);

	rth = (struct rthdr*)packetOut;
	rth->daddr = 0x1234;
	rth->check = htons(rthdr_chk_gen(rth));
	if ((ret = routing_opt(packetOut, 0x1234)) == P_APPRESPONSE) {
		fprintf(stdout, "test: P_APPRESPONSE                                                        [OK]\n");
	} else {
		fprintf(stdout, "test: P_APPRESPONSE FAILED, ret = %d, expected %d\n", ret, P_APPRESPONSE);
	}

	if ((ret = routing_opt(packetOut, 0x2345)) == P_FORWARD) {
		fprintf(stdout, "test: P_FORWARD                                                            [OK]\n");
	} else {
		fprintf(stdout, "test: P_FORWARD FAILED, ret = %d, expected %d\n", ret, P_FORWARD);
	}

	rth->ttl = 1;
	rth->check = htons(rthdr_chk_gen(rth));
	if ((ret = routing_opt(packetOut, 0x2345)) == P_TIMEOUT) {
		fprintf(stdout, "test: P_TIMEOUT                                                            [OK]\n");
	} else {
		fprintf(stdout, "test: P_TIMEOUT FAILED, ret = %d, expected %d\n", ret, P_TIMEOUT);
	}

	rth->check = 0x0000;

	if ((ret = routing_opt(packetOut, 0x2345)) == P_ERRCHK) {
		fprintf(stdout, "test: P_ERRCHK                                                             [OK]\n");
	} else {
		fprintf(stdout, "test: P_ERRCHK FAILED, ret = %d, expected %d\n", ret, P_ERRCHK);
	}


// unreliable packet checksum tests
	pktlen = generate_route_on_packet(packetOut, 64, ROUTE_ON_UNRELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 64 verify_packet_chk success                     [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 64 verify_packet_chk success FAILED\n");
	}

	struct urhdr* urh = (struct urhdr*)(packetOut + sizeof(struct rthdr));
	urh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 64 verify_packet_chk not success                 [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 64 verify_packet_chk not success FAILED\n");
	}

	pktlen = generate_route_on_packet(packetOut, 512, ROUTE_ON_UNRELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 512 verify_packet_chk success                    [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 512 verify_packet_chk success FAILED\n");
	}

	urh = (struct urhdr*)(packetOut + sizeof(struct rthdr));
	urh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 512 verify_packet_chk not success                [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 512 verify_packet_chk not success FAILED\n");
	}

	pktlen = generate_route_on_packet(packetOut, 1500, ROUTE_ON_UNRELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 1500 verify_packet_chk success                   [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 1500 verify_packet_chk success FAILED\n");
	}

	urh = (struct urhdr*)(packetOut + sizeof(struct rthdr));
	urh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_UNRELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 1500 verify_packet_chk not success               [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_UNRELIABLE 1500 verify_packet_chk not success FAILED\n");
	}


// reliable packet checksum tests
	pktlen = generate_route_on_packet(packetOut, 64, ROUTE_ON_RELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 64 verify_packet_chk success                       [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 64 verify_packet_chk success FAILED\n");
	}

	struct rlhdr* rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
	urh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 64 verify_packet_chk not success                   [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 64 verify_packet_chk not success FAILED\n");
	}

	pktlen = generate_route_on_packet(packetOut, 512, ROUTE_ON_RELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 512 verify_packet_chk success                      [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 512 verify_packet_chk success FAILED\n");
	}

	rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
	rlh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 512 verify_packet_chk not success                  [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 512 verify_packet_chk not success FAILED\n");
	}

	pktlen = generate_route_on_packet(packetOut, 1500, ROUTE_ON_RELIABLE);
	//fprintp(stdout, packetOut, pktlen);
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) == 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 1500 verify_packet_chk success                     [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 1500 verify_packet_chk success FAILED\n");
	}

	rlh = (struct rlhdr*)(packetOut + sizeof(struct rthdr));
	rlh->check = 0x0000;
	if (verify_packet_chk(packetOut, pktlen, ROUTE_ON_RELIABLE) != 0) {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 1500 verify_packet_chk not success                 [OK]\n");
	} else {
		fprintf(stdout, "test: ROUTE_ON_RELIABLE 1500 verify_packet_chk not success FAILED\n");
	}


	return 0;
}