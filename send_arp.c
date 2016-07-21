#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PROMISCUOUS 1
#define MAC_LEN 6

int eth0_MAC(unsigned char* mac){
	int sock, i;
	struct ifreq ifr;
	int success = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == 0){
		return success;
	}
	strcpy(ifr.ifr_name, "eth0");
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
		success = 1;
	if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return success;
}

int eth0_IP(unsigned char* ipadd){
	struct ifreq ifr;
	int sock = 0;
	int i;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == 0){
		printf("socket error!\n");
		return 0;
	}
	strcpy(ifr.ifr_name, "eth0");
	if(ioctl(sock,SIOCGIFADDR, &ifr) == 0)
		memcpy(ipadd, &ifr.ifr_addr.sa_data[2], 4);
	// trash in sa_data[0~1] - why? T.T
	return 1;
}

int main(int argc, char* argv[]){
	char* device = NULL;// = "eth0";
	pcap_t* pd;
	int i;
	u_char ippp;
	int chk;
	int snaplen = 100;
	char ebuf[PCAP_ERRBUF_SIZE];
	unsigned char s_mac[6];
	unsigned char d_mac[6];
	//struct pcap_pkthdr *header;
	u_char arp_data[42];

	if(argc != 2){
		printf("Please give target ip address!\n");
		return 0;
	}
	chk = 0;
	for(i=0;i<strlen(argv[1]);i++){
		if(argv[1][i] == '.'){
			printf("%d\n",chk);
			chk = 0;
		}
		else{
			chk = chk*10 + argv[1][i] -0x30;
		}
	}
	printf("%d",chk);
	printf("\n");

	if(device == NULL){
		if( (device = pcap_lookupdev(ebuf)) == NULL){
			perror(ebuf);
			exit(-1);
		}
	}
	pd = pcap_open_live(device, snaplen, PROMISCUOUS, 1000, ebuf);
	if(pd == NULL){
		perror(ebuf);
		exit(-1);
	}

	if(eth0_MAC(&arp_data[6]) == 1){
		printf("source mac : ");
		for(i=0;i<6;i++)
			printf("%02x:",arp_data[6+i]);
		printf("\n");
	}
	if(eth0_IP(&arp_data[28]) == 1){
		printf("my IP : ");
		for(i=0;i<4;i++)
			printf("%d.",arp_data[28+i]);
		printf("\n");
	}
	else{
		printf("error\n");
	}
/*

	// destination MAC
	// memcpy(d_mac,packetadressadress,6)
	arp_data[0]=
	arp_data[1]=
	arp_data[2]=
	arp_data[3]=
	arp_data[4]=
	arp_data[5]=
	// source MAC
	arp_data[6]=
	arp_data[7]=
	arp_data[8]=
	arp_data[9]=
	arp_data[10]=
	arp_data[11]=
	// type (ARP = 0x0806)
	arp_data[12]=0x08;
	arp_data[13]=0x06;
	// Ethernet = 0x0001
	arp_data[14]=0x00;
	arp_data[15]=0x01;
	// IP = 0x0800
	arp_data[16]=0x08;
	arp_data[17]=0x00;
	// MAC length (06)
	arp_data[18]=0x06;
	// IP length (04)
	arp_data[19]=0x04;
	// ARP type ( reply = 0x0002 )
	arp_data[20]=0x00;
	arp_data[21]=0x02;
	// Sender MAC
	arp_data[22]=
	arp_data[23]=
	arp_data[24]=
	arp_data[25]=
	arp_data[26]=
	arp_data[27]=
	// Sender IP
	arp_data[28]=
	arp_data[29]=
	arp_data[30]=
	arp_data[31]=
	// Target MAC
	arp_data[32]=
	arp_data[33]=
	arp_data[34]=
	arp_data[35]=
	arp_data[36]=
	arp_data[37]=
	// Target IP
	arp_data[38]=
	arp_data[39]=
	arp_data[40]=
	arp_data[41]=

*/

	return 0;
}