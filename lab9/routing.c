#include "routing.h"

 uint64_t routing_table[20];

void createRT()
{
    //Iface :"01", Metric : "00",Gateway : "0000", Mask : "fff0",destination network:  "0010"
    routing_table[0] = 0x01000000fff00010;
    rt_tbl_size++;
    printf("Routing table created\n");

    return 0;

}


void printRT(uint64_t * rt_table)
{
    int i;
    for(i = 0; i < rt_tbl_size; i++){
         uint16_t dest = routing_table[i] & 0xffff;
         uint16_t mask = (routing_table[i] >> 16) & 0xffff;
         uint16_t gateway = (routing_table[i] >> 32) & 0xffff;
         uint8_t metric = (routing_table[i] >> 48) & 0xff;
         uint8_t iface = (routing_table[i] >> 56) & 0xff;
        printf("Dest: %02X Mask: %02X Gateway: %02X Metric: %02X Iface: %02X\n", dest, mask, gateway, metric, iface);
    }

}


int main()
{

    createRT();
    uint64_t * rt_p = routing_table;
    printRT(rt_p);
    return 0;
}



