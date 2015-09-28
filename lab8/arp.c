#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <string.h>
#include "arp.h"



static char *ethernet_mactoa(struct sockaddr *addr)
{
	static char buff[256];
	unsigned char *ptr = (unsigned char *) addr->sa_data;

	sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
		(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
		(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

return (buff);

}


struct arpreq getMACfromIP(char *ip, char *iface){

    int                 s;
	struct arpreq       areq;
	struct sockaddr_in *sin;
	struct in_addr      ipaddr;

    printf("%s, %s \n", ip, iface);
	/* Get an internet domain socket. */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	/* Make the ARP request. */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;

	if (inet_aton(ip, &ipaddr) == 0) {
		fprintf(stderr, "-- Error: invalid numbers-and-dots IP address %s.\n",
				ip);
		exit(1);
	}

	sin->sin_addr = ipaddr;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	strncpy(areq.arp_dev, iface, 15);

	if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
		perror("-- Error: unable to make ARP request, error");
		exit(1);
	}

	return areq;
}

struct sockaddr getLocalMac(char *iface){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int i;
    strcpy(s.ifr_name, iface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        return s.ifr_hwaddr;
  }

}

//int main()
//{
//
//    char ip[20] = "10.10.3.2";
//    char iface[20] = "eth0";
//    struct sockaddr_in *hwaddr;
//    //struct arpreq  arequest = getArpAddr(ip, iface, hwaddr );
//    //printf("%s -> %s\n", ip,
//		//	ethernet_mactoa(&arequest.arp_ha));
//    char  mac[13];
//
//    struct sockaddr addr = getLocalMac("eth0");
//    printf("%s\n",
//			ethernet_mactoa(&addr));
//
//}

