#include <string.h>
#include <stdint.h>
#include <netinet/ether.h>

#include <netinet/ether.h>
#include <arpa/inet.h>

#include "packet.h"

namespace packet {

void fillEthHeader(EthHeader *eth, const char *src_mac_str, const char *dst_mac_str, uint16_t type) {
	/** fill Ethernet header : MAC address
	* output : (indirect) filled EthHeader*
	* **/
	// in this case, ether_aton() is better than ether_aton_r().
	memcpy(&eth->src_addr, ether_aton(src_mac_str), Len::MAC_ADDR);
	memcpy(&eth->dst_addr, ether_aton(dst_mac_str), Len::MAC_ADDR);
	eth->ether_type = htons(type);
}
void fillArpPacket(ArpPacket *arp, const char *src_mac_str, const char *dst_mac_str,
				   const char *src_ip_str, const char *dst_ip_str, uint16_t opcode) {
	/** fill ARP pakcet
	* output : (indirect) filled ArpPacket*
	* **/
	arp->hd_type = htons(1); // Ethernet일 경우 1
	arp->protocol_type = htons(ETH_P_IP);
	arp->hd_size = Len::MAC_ADDR;
	arp->protocol_size = Len::IP_ADDR;
	arp->opcode = htons(opcode);
	memcpy(&arp->src_mac, ether_aton(src_mac_str), Len::MAC_ADDR);
	arp->src_ip = inet_addr(src_ip_str); // inet_aton()와 struct in_addr을 사용해도 된다.
	memcpy(&arp->dst_mac, ether_aton(dst_mac_str), Len::MAC_ADDR);
	arp->dst_ip = inet_addr(dst_ip_str);
}

}
