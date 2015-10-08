#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "packet.h"
#include "packet_util.h"
#include "printp.h"


int main (int argc, char** argv) {
	srand(time(NULL));
	u_char packetOut[PACKET_BUF_SIZE];
	int pktlen = generate_route_on_packet(packetOut, 128, ROUTE_ON_RELIABLE);
	fprintp(stdout, packetOut, pktlen);

	pktlen = generate_route_on_packet(packetOut, 128, ROUTE_ON_UNRELIABLE);
	fprintp(stdout, packetOut, pktlen);
	return 0;
}