#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


typedef struct rttable{

    struct sockaddr_in rt_dst;         /* target address               */
    struct sockaddr_in rt_gateway;     /* gateway addr (RTF_GATEWAY)   */
    struct sockaddr_in rt_genmask;     /* target network mask (IP)     */
    short int rt_metric;               /* ,metric */
    char rt_dev[50];                   /* device name   */
    struct rttable *next;


}rt_table;

extern rt_table *rt_tbl_list;

int total_tbl_size;


int createRT();
int printRT(rt_table *);

