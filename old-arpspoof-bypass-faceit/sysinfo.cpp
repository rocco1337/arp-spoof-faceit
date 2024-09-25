#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "sysinfo.h"

namespace sysinfo {
namespace Path {
const char * const SYS_NET  = "/sys/class/net/%s/address";
const char * const PROC_ARP = "/proc/net/arp";
};

void getSrcIPStr(char *dev, char *ip_str) {
	/**
	 * input  : device ( interface )
	 * output : interface's ip str
	 */
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
							ip_str, NI::MAXHOST, NULL, 0, NI::NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}
			else if (!strncmp(ifa->ifa_name, dev, Len::INT_NAME_MAX)) {
				break;
			}
		}
	}
	// printf("\t\taddress: %s <%s>\n", ifa->ifa_name, ip_str);
	freeifaddrs(ifaddr);
}
void getDevMac(char *dev, char *mac_str) {
	size_t mac_path_len = Len::SYS_NET_PATH + strlen(dev);
	char mac_path[mac_path_len];
	snprintf(mac_path, mac_path_len, Path::SYS_NET, dev);

	FILE *fp = fopen(mac_path, "r");
	if (!fp) {
		fprintf(stderr, "[*] fopen(%s) error\n", mac_path);
		exit(EXIT_FAILURE);
	}
	fscanf(fp, "%s", mac_str);
	fclose(fp);
}
/////////////////////// unused func ///////////////////////////////
int getMacFromArpTable(const char *ip_str, const char *mac_str) {
	/**
	* input  : ip_str
	* output : mac_str (indirect)
	* return : 0, -1
	* */
	FILE *fp = fopen(Path::PROC_ARP, "r");
	if (!fp) {
		fprintf(stderr, "[*] fopen(%s) error\n", Path::PROC_ARP);
		return -1;
	}

	char column[Len::ARP_TABLE_ENTRY];
	if (!fgets(column, sizeof(column), fp)) {
		perror("[*] fgets error");
		return -1;
	}
	// printf("%s\n", column);

	char parsed_ip[Len::IP_STR_BUF] = {0};
	fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
	while (strncmp(ip_str, parsed_ip, Len::IP_STR_BUF - 1) != 0) {
		if (feof(fp) != 0) {
			fprintf(stderr, "[*] There is no %s entry in ARP table\n", ip_str);
			return -1;
		}
		fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
	}

	fclose(fp);
	return 0;
}
}