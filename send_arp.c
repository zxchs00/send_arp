#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

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

int gatewayIP(unsigned char* ipadd){
	FILE *f;
	char line[100], *p, *c, *g, *saveptr;
	int nRet = 0;
	int tmp;
	int i;
	f = fopen("/proc/net/route","r");

	while(fgets(line, 100, f)){
		p = strtok_r(line, " \t",&saveptr);
		c = strtok_r(NULL, " \t",&saveptr);
		g = strtok_r(NULL, " \t",&saveptr);
		if(p!=NULL && c!=NULL){
			if(strcmp(c,"00000000") == 0){
				//printf("Default gateway IP is : %s \n",g);
				for(i=0;i<8;i++){
					if(g[i] >= 'A')
						g[i] -= 7;
				}
				for(i=0;i<4;i++){
					ipadd[3-i] = (g[2*i]-0x30)*16+(g[2*i+1]-0x30);
					//printf("%d\n",(g[2*i]-0x30)*16+(g[2*i+1]-0x30));
				}
				if(g){
					nRet = 1;
				}
				break;
			}
		}
	}
	fclose(f);
	return nRet;
}

int make_request(u_char* pdata, u_char* tip){
	int i;

	for(i=0;i<6;i++)
		pdata[i] = 0xFF;
	if(eth0_MAC(&pdata[6]) == 0){
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	pdata[12] = 0x08;
	pdata[13] = 0x06;
	pdata[14] = 0x00;
	pdata[15] = 0x01;
	pdata[16] = 0x08;
	pdata[17] = 0x00;
	pdata[18] = 0x06;
	pdata[19] = 0x04;
	pdata[20] = 0x00;
	pdata[21] = 0x01; // request
	if(eth0_MAC(&pdata[22]) == 0){
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	if(eth0_IP(&pdata[28]) == 0){
		printf("Error : Writing my IP! \n");
		return 0;
	}
	for(i=0;i<6;i++)
		pdata[32+i] = 0x00;
	for(i=0;i<4;i++)
		pdata[38+i] = tip[i];

	return 1;

}

int main(int argc, char* argv[]){
	char* device = NULL;// = "eth0";
	pcap_t* pd;
	int i;
	u_char ippp;
	int chk, cnt;
	int snaplen = 100;
	char ebuf[PCAP_ERRBUF_SIZE];

	u_char arp_data[42];
	u_char req_data[42];
	u_char targetip[4];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;

	if(argc != 2){
		printf("Please give target ip address!\n");
		return 0;
	}

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

	chk = 0;
	cnt = 0;
	for(i=0;i<strlen(argv[1]);i++){
		if(argv[1][i] == '.'){
			targetip[cnt] = chk;
			chk = 0;
			cnt++;
		}
		else{
			chk = chk*10 + argv[1][i] -0x30;
		}
	}
	targetip[cnt] = chk;

	for(i=0;i<4;i++){
		arp_data[38+i] = targetip[i];
	}

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

	if(eth0_MAC(&arp_data[6]) == 0){
		printf("Error : Writing my MAC address at packet ! \n");
	}
	if(eth0_MAC(&arp_data[22]) == 0){
		printf("Error : Writing my MAC address at packet ! \n");
	}
	/*
	if(eth0_IP(&arp_data[28]) == 1){
		printf("my IP : ");
		for(i=0;i<4;i++)
			printf("%d.",arp_data[28+i]);
		printf("\n");
	}
	else{
		printf("error\n");
	}
	*/

	if(gatewayIP(&arp_data[28]) == 0){
		printf("Error : Can't read gateway address! \n");
	}

	if(make_request(req_data, targetip) == 0){
		printf("Error : Making Request \n");
	}

	if(pcap_sendpacket(pd,req_data,42) != 0){
		printf("Error : Sending request packet!\n");
	}

	while((res = pcap_next_ex( pd, &header, &pkt_data)) >= 0){
		if(res == 0)
		/* Timeout elapsed */
			continue;
		
		// type check
		if( ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0806 ){
			// it's not ARP
			continue;
		}
		else{ // It's ARP !
			if( ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002 ){
				if( ((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)(&req_data[38]))[0] ){
					/*
					printf("     Target's Mac   ");
					printf("%02x",pkt_data[6]);
					for(i=7;i<12;i++){
						printf(":");
						printf("%02x", pkt_data[i]);
					}
					printf("\n");
					*/
					for(i=0;i<6;i++){
						arp_data[i] = pkt_data[6+i];
						arp_data[32+i] = pkt_data[6+i];
					}
					break;
				}
			}
		}
	}
	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(pd));
		return -1;
	}

	if(pcap_sendpacket(pd,arp_data,42) != 0){
		printf("Error : Sending request packet!\n");
	}


/*
	printf("gateway IP : ");
	for(i=0;i<4;i++)
		printf("%d.",arp_data[28+i]);
	printf("\n");


	printf("target IP : ");
	for(i=0;i<4;i++)
		printf("%d.",arp_data[38+i]);
	printf("\n");
*/

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