#include <stdio.h>
#include <string.h>
int main(){
	int packetR[]={1,0,0,0,0,1,0,1,1,0,1,1};
	int i;
	char payload[1024];
	int *ptr=(int *)payload;
	int packet_counter=0;
	int seq_count=3;
	int j;

	for (i=0;i<=9;i++){
		if(packetR[i]==0){
			ptr[packet_counter]=i;
			packet_counter++;

		}
		if (seq_count==packet_counter){
			packet_counter=0;
			for(j=0;j<seq_count;j++){
				printf("%d\n",ptr[j]);
			}
			memset(payload,0,1024);
			ptr=(int *)payload;
			printf("\n");

		}
	}

	printf("The packet count %d\n",packet_counter);
	if(packet_counter!=0){
		int balance=seq_count-packet_counter;
		for(j=balance;j<seq_count;j++)
			ptr[j]=ptr[packet_counter-1];
		for(j=0;j<seq_count;j++){
			printf("%d\n",ptr[j]);
		}

	}
	return 0;

}
