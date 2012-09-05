#include <mapi.h>

struct filter_t {
	int fd_in;
	int fd_out;
	int fid_in;
	int fid_out;
	int top_in;
	int top_out;
	char *name;
	enum {F_BPF, F_TRACKER} type;
	char *f;
	enum {ACTIVE, INACTIVE} state;
	char *color;
};

struct filter_t filter[] = {
	{0,0,0,0,0,0, "Total", F_BPF, NULL, ACTIVE, "666666"}, // this should always be first
	//	{0,0,0,0,0,0, "HTTP", F_BPF, "(port 80 or port 443)", ACTIVE, "00F500"},
	//{0,0,0,0,0,0, "SSH", F_BPF, "(port 22 or port 23 or port 107 or port 614 or port 992)", ACTIVE, "B800B8"},
	//{0,0,0,0,0,0, "SMTP", F_BPF, "((tcp and port 25) or (udp and port 995))", ACTIVE, "FFFF00"},
	//{0,0,0,0,0,0, "DNS", F_BPF, "port 53", ACTIVE, "CC9900"},
	//{0,0,0,0,0,0, "NETBIOS", F_BPF, "(port 137 or port 138 or port 139 or port 445)", ACTIVE, "FF8000"},
	//{0,0,0,0,0,0, "RTSP", F_BPF, "(port 554 or port 8554 or port 322)", ACTIVE, "FF0000"},
	//{0,0,0,0,0,0, "ICMP", F_BPF, "icmp", ACTIVE, "FF00EE"},
	//{0,0,0,0,0,0, "OpenVPN", F_BPF, "port 1194", ACTIVE, "0000FF"},
	{0,0,0,0,0,0, "WoW", F_BPF, "port 3724", ACTIVE, "336666"},
	{0,0,0,0,0,0, "FTP", F_TRACKER, "TRACK_FTP", ACTIVE, "99CC00"},
	{0,0,0,0,0,0, "Gnutella", F_TRACKER, "TRACK_GNUTELLA", ACTIVE, "FF0000"},
	{0,0,0,0,0,0, "BitTorrent", F_TRACKER, "TRACK_TORRENT", ACTIVE, "9933FF"},
	{0,0,0,0,0,0, "eDonkey", F_TRACKER, "TRACK_EDONKEY", ACTIVE, "33CCFF"},
	{0,0,0,0,0,0, "DC++", F_TRACKER, "TRACK_DC", ACTIVE, "CCFFCC"},
	//{0,0,0,0,0,0, "IP-in-IP", F_BPF, "ip[9] == 4", ACTIVE, "3300CC"},
	//{0,0,0,0,0,0, "MAPI", F_BPF, "(tcp and port 2233)", ACTIVE, "CCFF99"},
};

#define NUMFILTERS (int)(sizeof(filter)/sizeof(filter[0]))
