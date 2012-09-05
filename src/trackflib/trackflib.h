#ifndef __TRACKLIB_H__
	#define __TRACKLIB_H__

#define ETHERTYPE_8021Q 0x8100
#define MPLS_MASK 0x8847

#define HASHTABLESIZE 4096
#define __WITH_AHO__

#define EDONKEY_COLOR 1
#define TORRENT_COLOR 2
#define GNUTELLA_COLOR 3
#define DC_COLOR 4
#define FTP_COLOR 5
#define SKYPE_COLOR 6
#define WEB_COLOR 7
#define COWEB_COLOR 8
#define MAPI_COLOR 9

//static int color;


struct vlan_802q_header {
	u_int16_t priority_cfi_vid;
	u_int16_t ether_type;
};

#endif 

