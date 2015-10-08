/**
 * CS 558L Lab 9
 * 
 * Print packets
 */

 #ifndef _PRINTP_H_
 #define _PRINTP_H_

 #include "packet.h"

 void fprintp(FILE*, u_char*, int);
 void print_rthdr(FILE*, struct rthdr*);
 void print_ctl_packet(FILE*, u_char*, int);
 void print_ur_packet(FILE*, u_char*, int);
 void print_rl_packet(FILE*, u_char*, int);
 void print_data(FILE*, const u_char*, int);

 #endif