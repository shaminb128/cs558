#include <stdio.h>
#include <stdlib.h>

int main () {
        printf("%lu, %lu, %lu, %lu\n", sizeof(unsigned int), sizeof(long int), sizeof(unsigned long), sizeof(unsigned long long int));
        u_int64_t routing_table[10];
        routing_table[0] = 0x01050001fff00030;
//      printf("routing_table[0] = %016x", routing_table[0]);
        printf("getting bit 0~15: %04x\n", (unsigned short)(routing_table[0] & 0xffff));
        // testing bits 16~31:
        if ((routing_table[0] & 0xffff0000) == 0xabcd0000) {
                printf("bit 16 ~ 31 is 0xabcd\n");
        } else if ((routing_table[0] & 0xffff0000) == 0xfff00000) {
                printf("bit 16 ~ 31 is 0xfff0\n");
        }
        // store bit 8~23 into an unsigned short
        unsigned short n = (unsigned short)(routing_table[0] >> 8);
        printf("store bit 8~23 into an unsigned short: decimal value is %d; hex value is %.4x;\n", n, n);

        // print memory byte-by-byte
        unsigned char* memory = (unsigned char*)(&(routing_table[0]));
        printf("printing memroy byte by byte:\n%.2x\n%.2x\n%.2x\n%.2x\n%.2x\n%.2x\n%.2x\n%.2x\n",
                memory[0], memory[1], memory[2], memory[3], memory[4], memory[5], memory[6], memory[7]);
        return 0;
}
