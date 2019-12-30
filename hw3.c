#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define MAC_ADDRSTRLEN 18

int tmp=0,bytes=0,dd=1;

struct sta{
	char src_ip[30];
	char dst_ip[30];
	int cnt;
};

char *mac_ntoa(u_char *d){
	static char str[MAC_ADDRSTRLEN]={0};

	snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0],d[1],d[2],d[3],d[4],d[5]);
	return str;
}

char *ip_ntoa(void *d){
	static char str[INET_ADDRSTRLEN]={0};

	inet_ntop(AF_INET, d, str, sizeof(str));
	return str;
}

void dump_udp(u_int32_t length, const u_char *content){
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

	u_int16_t src_port = ntohs(udp->uh_sport);
	u_int16_t dst_port = ntohs(udp->uh_dport);
	u_int16_t len = ntohs(udp->uh_ulen);
	u_int16_t checksum = ntohs(udp->uh_sum);

	printf("\nLength : %u\tChecksum : %u\n",len,checksum);
	printf("\nSource port      : %5u\nDestination port : %5u\n",src_port,dst_port);
}

void dump_tcp(u_int32_t length, const u_char *content){
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl <<2));

	u_int16_t src_port = ntohs(tcp->th_sport);
	u_int16_t dst_port = ntohs(tcp->th_dport);
	u_int16_t checksum = ntohs(tcp->th_sum);
	u_int32_t seq = ntohl(tcp->th_seq);
	u_int32_t ack = ntohl(tcp->th_ack);
	u_int8_t header_len = tcp->th_off << 2;
	u_int16_t window = ntohs(tcp->th_win);

	printf("\nHL : %5u\tChecksum : %5u\tWindow size : %5u\n",header_len,checksum,window);
	printf("\nSequence number : %10u\n",seq);
	printf("Ack number      : %10u\n",ack);
	printf("\nSource port      : %5u\nDestination port : %5u\n",src_port,dst_port);
}

struct sta pkt[1000];

void dump_ip(u_int32_t length, const u_char *content){
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	u_int version = ip->ip_v;
	u_int header_len = ip->ip_hl << 2;
	u_int16_t total_len = ntohs(ip->ip_len);
	u_int16_t id = ntohs(ip->ip_id);
	u_int16_t offset = ntohs(ip->ip_off);
	u_char ttl = ip->ip_ttl;
	u_char protocol = ip->ip_p;
	u_int16_t checksum = ntohs(ip->ip_sum);
	int i,flag;

	printf("\nIPv : %3u\tHL       : %3u\tTotal len : %5u\n",version,header_len,total_len);
	printf("TTL : %3u\tProtocol : %3u\tChecksum  : %5u\n",ttl,protocol,checksum);
	printf("\nSource IP address      : %s\n",ip_ntoa(&ip->ip_src));
	printf("Destination IP address : %s\n\n",ip_ntoa(&ip->ip_dst));

	flag=0;
	for (i=0;i<tmp;i++){
		if (!strcmp(pkt[i].src_ip, ip_ntoa(&ip->ip_src)) && !strcmp(pkt[i].dst_ip, ip_ntoa(&ip->ip_dst))){
			flag = 1;
			pkt[i].cnt++;
			break;
		}
	}
	if (!flag){
		strcpy(pkt[i].src_ip, ip_ntoa(&ip->ip_src));
		strcpy(pkt[i].dst_ip, ip_ntoa(&ip->ip_dst));
		pkt[i].cnt = 1;
		tmp++;
	}

	if (protocol == IPPROTO_UDP){
		printf("Protocol : UDP\n");
		dump_udp(length, content);
	}
	else if (protocol == IPPROTO_TCP){
		printf("Protocol : TCP\n");
		dump_tcp(length, content);
	}
	else if (protocol == IPPROTO_ICMP)
		printf("Protocol : ICMP\n");
	else if (protocol == 89)
		printf("Protocol : OSPF\n");
	else 
		printf("Protocol : %d\n",protocol);
}

void dump_ethernet(u_int32_t length, const u_char *content){
	struct ether_header *ethernet = (struct ether_header *)content;
	char src_mac[MAC_ADDRSTRLEN] = {0};
	char dst_mac[MAC_ADDRSTRLEN] = {0};
	u_int16_t type;
	
	strncpy(src_mac, mac_ntoa(ethernet->ether_shost), 17);
	strncpy(dst_mac, mac_ntoa(ethernet->ether_dhost), 17);
	type = ntohs(ethernet->ether_type);
	
	printf("\nSource mac address      : %17s\nDestination mac address : %17s\n\n",src_mac,dst_mac);

	if (type == ETHERTYPE_IP){
		printf("Ethernet type : IPv4\n");
		dump_ip(length, content);
	}
	else if (type == ETHERTYPE_ARP)
		printf("Ethernet type : ARP\n");
	else if (type == ETHERTYPE_REVARP)
		printf("Ethernet type : RARP\n");
	else if (type == ETHERTYPE_IPV6)
		printf("Ethernet type : IPv6\n");
	else
		printf("Ethernet type : %#06x\n",type);
	
}

void packetHandler(u_char *arg, const struct pcap_pkthdr *header, const u_char *content){
	struct tm *ltime;
	char timestr[30]={0};
	time_t local_tv_sec;
	
	if (arg != NULL){
		if (dd != (atoi(arg))){
			dd++;
			return;
		}
	}

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%F/%R:%S", ltime);

	printf("Packet : %d\n\n",dd);
	dd++;
	bytes += header->len;
	printf("Timestamp : %s.%.6d\n",timestr,(int)header->ts.tv_usec);
	printf("Packet size  : %d bytes\n",header->len);
	printf("Capture size : %d bytes\n",header->caplen);

	dump_ethernet(header->caplen, content);

	printf("\n---------------------------------------\n\n");
}

int main(int argc, char **argv){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int num=-1;
	u_char *n=NULL;

	if ((strcmp(argv[1],"-r") == 0))
		fp = pcap_open_offline(argv[2], errbuf);
	else if (strcmp(argv[1],"-h") == 0){
		printf("Usage : \n");
		printf("-r filename <read a file>\n");
		printf("-w filename <output filename>\n");
		printf("-c number <packet count>\n");
		printf("-g number <packet number>\n");
		printf("-h for help\n");
		return 0;
	}
	
	if (argc > 3){
		if (strcmp(argv[3],"-w") == 0){
			char *result = argv[4];
			freopen(result,"w",stdout);
		}
		else if (strcmp(argv[3],"-c") == 0)
			num = atoi(argv[4]);
		else if (strcmp(argv[3],"-g") == 0)
			n = argv[4];
	}

	if (pcap_loop(fp, num, packetHandler, n) < 0)
		fprintf(stderr, "pcap_loop : %s\n",pcap_geterr(fp));
	
	int i;
	for (i=0;i<tmp;i++){
		printf("Source IP      : %s\nDestination IP : %s\n",pkt[i].src_ip,pkt[i].dst_ip);
		printf("Packet count   : %d\n\n",pkt[i].cnt);
	}

	printf("Total packet count : ");
	if (n == NULL)
		printf("%d\n",dd-1);
	else 
		printf("1\n");
	
	printf("Total packet size(bytes) : %d\n",bytes);

	pcap_close(fp);
	return 0;
}
