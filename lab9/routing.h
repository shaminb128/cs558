#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
//#include <netinet/in.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>


//typedef struct rttable{
//
//    struct sockaddr_in dest;         /* target address               */
//    struct sockaddr_in mask;     /* target network mask (IP)     */
//    struct sockaddr_in gateway;     /* gateway addr (RTF_GATEWAY)   */
//    short int metric;               /* ,metric */
//    char dev[50];                   /* device name   */
//    struct rttable *next;
//
//
//}rt_table;

extern uint64_t routing_table[20];

int rt_tbl_size;


void createRT();
void printRT(uint64_t *);

