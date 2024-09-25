
#ifndef PACKET_H
#define PACKET_H
#include <stdint.h>

namespace packet {
enum Len {
	IP_ADDR         = 4,
	MAC_ADDR        = 6
};

#pragma pack(push, 1)
typedef struct _EthHeader {
	uint8_t dst_addr[Len::MAC_ADDR];
	uint8_t src_addr[Len::MAC_ADDR];
	uint16_t ether_type; // next protocol type
} EthHeader;

typedef struct _ArpPacket {
	uint16_t hd_type;
	uint16_t protocol_type;
	uint8_t hd_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t src_mac[Len::MAC_ADDR];
	uint32_t src_ip;
	uint8_t dst_mac[Len::MAC_ADDR];
	uint32_t dst_ip;
} ArpPacket;

typedef struct _EthArpPacket {
	EthHeader eth;
	ArpPacket arp;
	// uint8_t padding[18];
} EthArpPacket;
#pragma pack(pop)

void fillEthHeader(EthHeader *, const char *, const char *, uint16_t);
void fillArpPacket(ArpPacket *, const char *, const char *, const char *, const char *, uint16_t);

}

#endif