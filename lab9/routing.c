#include "routing.h"
#include "packet.h"

 uint64_t routing_table[20];

void createRT()
{
    //Iface :"01", Metric : "00",Gateway : "0000", Mask : "fff0",destination network:  "0010"
    routing_table[0] = 0x01000000fff00010;
    rt_tbl_size++;
    routing_table[1] = 0x02000000fff00020;
    rt_tbl_size++;
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

int rt_lookup(uint16_t dest, uint64_t* rt_entry) {

	//uint16_t dest = 0x0011;

	int min_metric = 1000, i;
    int match_found = 0;
	for(i = 0; i < rt_tbl_size; i++){
         uint16_t rt_dest = routing_table[i] & 0xffff;
         uint16_t rt_mask = (routing_table[i] >> 16) & 0xffff;
         uint16_t rt_gateway = (routing_table[i] >> 32) & 0xffff;
         uint8_t rt_metric = (routing_table[i] >> 48) & 0xff;
		 if ((dest & rt_mask) == (rt_dest & rt_mask)) {
			// Matches
			match_found = 1;
			if(rt_gateway == 0x0000) {
				// Local network
				*rt_entry = routing_table[i];
				return P_LOCAL;
			} else {
				// remote network
				if(rt_metric < min_metric) {
					min_metric = rt_metric;
					//rtp = p;
					*rt_entry = routing_table[i];
				}
			}
		}
	}

	if (!match_found) {
		return -1;
	}
	return P_REMOTE;
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
	rth->daddr = (u_int16_t)(0x0022 & 0xffff);
	rth->ttl = (u_int8_t)(0x12 & 0xff);
	rth->protocol = 1;
	rth->size = (u_int16_t)size;

}
int main()
{
    createRT();
    uint64_t * rt_p = routing_table;
    printRT(rt_p);
    u_char packetOut[PACKET_BUF_SIZE];
	int pktlen = generate_packet(packetOut, 128);
	//fprintp(stdout, packetOut, pktlen);
    struct rthdr *rth = (struct rthdr*) packetOut;
    //printf("string %02X", packet);
	uint16_t dest = (uint16_t) rth->daddr;    // TODO: not working
	printf("Dest from header %02x\n", dest);
    uint64_t rt_entry;

    rt_lookup(dest, &rt_entry);
    printf("Matching Entry : %016llx\n" , rt_entry);

    return 0;
}



