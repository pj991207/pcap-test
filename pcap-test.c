#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define SIZE_ETHERNET 14
/*Ethernet header*/
struct sniff_ethernet{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /*IP인지 ARP인지 RARP 인지 기타 등등 */
};
/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	u_char ip_dhost[IP_ADDR_LEN];
	u_char ip_shost[IP_ADDR_LEN];
};
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_off;	/* data offset, rsvd */
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
//여기까지 dev_가 ifconfig 에서 ens33의 값을 받는것까지 알겠다.

int main(int argc, char* argv[]) {
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;
    u_int ip_size;
    u_int tcp_size;
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	//pcap_t* pcap = pcap_open_offline("arp.pcap",errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("\npcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//res -1 or -2 임
		//printf("%u bytes captured\n", header->caplen);
		int length = header->len;
		ethernet = (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
		int ip_version = (ip->ip_vhl & 0xf0)>>4;
        int ip_hl = (ip->ip_vhl & 0x0f);
        int ip_size = ip_version * ip_hl;
        tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+ip_size);
        tcp_size = ((tcp->th_off&0xf0)>>4)*4+((tcp->th_off&0x0f))*4*16;
        int packet_size = header -> caplen; //packet size
        int total_size = SIZE_ETHERNET+ip_size+tcp_size; // tcp, ip, ethernet size
        payload = (u_char*)(packet+SIZE_ETHERNET+ip_size+tcp_size);

		if(ntohs(ethernet->ether_type)==0x0800)
		{
		    if(ip_version == 4)
		    {
                if(ip->ip_p == 0x06)
                {
                    printf("\n\nEthernet information\n");
                    printf("\n ETH dhost : ");
                    for (int i=0;i<6;i++)
                    {
                        printf("%02x",ethernet->ether_dhost[i]);
                    }
                    printf("\n\n ETH shost : ");
                    for (int i=0;i<6;i++)
                    {
                        printf("%02x",ethernet->ether_shost[i]);
                    }
                    printf("\n\nIP information\n");
                    printf("\n IP DHOST :");
                    for (int i = 0; i<4;i ++)
                    {
                        printf("%d",ip->ip_dhost[i]);
                        if(i!=3)
                        {
                            printf(".");
                        }
                        else
                        {
                            break;
                        }
                    }
                    printf("\n\n IP SHOST :");
                    for (int i = 0; i<4;i ++)
                    {
                        printf("%d",ip->ip_shost[i]);
                        if(i!=3)
                        {
                            printf(".");
                        }
                        else
                        {
                            break;
                        }
                    }
                    printf("\n\nTCP information\n");
                    printf("\n TCP SPORT : %d",ntohs(tcp->th_sport));
                    printf("\n\n TCP DPORT : %d\n",ntohs(tcp->th_dport));
                    printf("\nPayload\n");
                    printf("\n DATA :");
                    if(packet_size-total_size == 0)
                    {
                        printf("no data\n");
                    }
                    else
                    {
                        for(int i=0;i<packet_size-total_size;i++)
                        {
                            printf("%02x |",payload[i]);
                            if(i==9)
                            {
                                break;
                            }
                        }
                    }
                    printf("\n\n");
                }
                else
                {
                    //tcp가아닌경우
                    continue;
                }
		    }
		    else
		    {
		        //ip가 v6인 경우
		        continue;
		    }
		}
		else
		{
		    //ip가아닌경우
		    continue;
		}
		printf("\n\n");
		/*printf(" ETH ENTIRE :");
		while(length--)
		{
		    printf("%02x", *(packet++));
		}
		break;*/
	}
	pcap_close(pcap);
}
