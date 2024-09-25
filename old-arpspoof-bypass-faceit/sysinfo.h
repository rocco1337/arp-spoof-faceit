#ifndef SYSINFO_H
#define SYSINFO_H

namespace sysinfo {
enum Len {	
	IP_STR_BUF      = 16,
	MAC_STR_BUF     = 18,
	SYS_NET_PATH    = 24,
	INT_NAME_MAX    = 15,
	ARP_TABLE_ENTRY = 128
};
enum NI {
	MAXHOST     = 1025,
	NUMERICHOST = 1
};

namespace Path {
extern const char* const SYS_NET;  //= "/sys/class/net/%s/address";
extern const char* const PROC_ARP; //= "/proc/net/arp";
};

void getSrcIPStr(char *dev, char *ip_str);
void getDevMac(char *dev, char *mac_str);
int getMacFromArpTable(const char *ip_str, const char *mac_str);

}

#endif