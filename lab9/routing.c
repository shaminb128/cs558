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

#include "packet_util.h"
#include "routing.h"
#include "packet.h"


 uint64_t routing_table[20];

void createRT(int extra)
{
    //Iface :"01", Metric : "00",Gateway : "0000", Mask : "fff0",destination network:  "0010"
    routing_table[0] = 0x00000000fff00010;
    rt_tbl_size++;
    routing_table[1] = 0x01000000fff00020;
    rt_tbl_size++;
    routing_table[2] = 0x02000000fff00030;
    rt_tbl_size++;
    if (extra == 1) {
    	routing_table[3] = 0x03000000fff00040;
    	rt_tbl_size++;
    }
    printf("Routing table created\n");
}


void printRT(uint64_t * rt_table)
{
    int i;
    for(i = 0; i < rt_tbl_size; i++){
         uint16_t dest = rt_table[i] & 0xffff;
         uint16_t mask = (rt_table[i] >> 16) & 0xffff;
         uint16_t gateway = (rt_table[i] >> 32) & 0xffff;
         uint8_t metric = (rt_table[i] >> 48) & 0xff;
         uint8_t iface = (rt_table[i] >> 56) & 0xff;
        printf("Dest: %02X Mask: %02X Gateway: %02X Metric: %02X Iface: %02X\n", dest, mask, gateway, metric, iface);
    }

}

int getIPfromIface(char* iface, char* ipstr) {
  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* Get IP address attached to iface */
  strcpy(ifr.ifr_name, iface);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);

  strcpy(ipstr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  return 0;
}


int routing_opt(u_char* packet, u_int16_t myaddr) {
	struct rthdr* rth = (struct rthdr*) packet;
	if (verify_rthdr_chk(rth) != 0) {
		//printf("test check = %04x, packet check = %04x\n", rthdr_chk_gen(rth), ntohs(rth->check));
		return P_ERRCHK;
	}
	if (rth->daddr == myaddr) {
		/* sending to this port... TODO: need to test with real situation DNS
		 * coz sometimes the packet is sent to this device, but different port
		 */
		if ((rth->protocol) == ROUTE_ON_CONTROL || (rth->protocol) == ROUTE_ON_UNRELIABLE || (rth->protocol) == ROUTE_ON_RELIABLE) {
			return P_APPRESPONSE;
		} else {
			return P_NOT_YET_IMPLEMENTED;
		}
	} else {
		// sending to somewhere else
		if (((rth->daddr) & 0x00f0) == (myaddr & 0x00f0)) {
			return P_DO_NOTHING;
		}
		if (rth->ttl == 1) {
			return P_TIMEOUT;
		} else {
			return P_FORWARD;
		}
	}
	return P_DO_NOTHING;
}


uint8_t rt_lookup(uint16_t dest) {

	//uint16_t dest = 0x0011;

	int min_metric = 1000, i;
	uint8_t rt_index;
    int match_found = 0;
	for(i = 0; i < rt_tbl_size; i++){
         uint16_t rt_dest = routing_table[i] & 0xffff;
         uint16_t rt_mask = (routing_table[i] >> 16) & 0xffff;
         uint16_t rt_gateway = (routing_table[i] >> 32) & 0xffff;
         uint8_t rt_metric = (routing_table[i] >> 48) & 0xff;
         uint8_t rt_iface = (routing_table[i] >> 56) & 0xff;
		 if ((dest & rt_mask) == (rt_dest & rt_mask)) {
			// Matches
			match_found = 1;
			if(rt_gateway == 0x0000) {
				// Local network
				//*rt_entry = routing_table[i];
				return rt_iface;
			} else {
				// remote network
				if(rt_metric < min_metric) {
					min_metric = rt_metric;
					//rtp = p;
					//*rt_entry = routing_table[i];
					rt_index = rt_iface;
				}
			}
		}
	}

	if (!match_found) {
		return -1;
	}
	return rt_index;
}

/* takes in packet, modify it for forwarding */
void modify_packet(u_char* packet) {
	struct rthdr* rth = (struct rthdr*)packet;
	rth->ttl--;
	rth->check = htons(rthdr_chk_gen(rth));
}

int generate_packet(u_char* packetOut, int size) {
	if (size < MIN_APP_PKT_LEN) {
		fprintf(stderr, "ERROR: size should > 60\n");
		return -1;
	}
	memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	struct rthdr* rth = (struct rthdr*)packetOut;
	rth->saddr = (u_int16_t)(0x0011 & 0xffff);
	// Test it for different subnets
	//rth->daddr = (u_int16_t)(0x0012 & 0xffff);
	rth->daddr = (u_int16_t)(0x0031 & 0xffff);
	rth->ttl = (u_int8_t)(0x12 & 0xff);
	rth->protocol = 1;
	rth->size = (u_int16_t)size;
	return size;
}

//int main()
//{
//    createRT();
//    uint64_t * rt_p = routing_table;
//    printRT(rt_p);
//    u_char packetOut[PACKET_BUF_SIZE];
//	int pktlen = generate_packet(packetOut, 128);
//	//fprintp(stdout, packetOut, pktlen);
//    struct rthdr *rth = (struct rthdr*) packetOut;
//    //printf("string %02X", packet);
//	uint16_t dest = (uint16_t) rth->daddr;    // TODO: not working
//	printf("Dest from header %02x\n", dest);
//    uint64_t rt_entry;
//
//    int index = (int) rt_lookup(dest);
//    //printf("Matching Entry : %016llx\n" , rt_entry);
//    printf("Matching Index : %d\n" , index);
//    return 0;
//}
//


