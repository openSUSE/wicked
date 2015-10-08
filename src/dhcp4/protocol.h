/*
 * Build and parse DHCP4 packets
 *
 * Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcpcd, which was written by Roy Marples <roy@marples.name>
 */

#ifndef __WICKED_DHCP4_PROTOCOL_H__
#define __WICKED_DHCP4_PROTOCOL_H__

#include <netinet/in.h>
#include <stdint.h>
#include <wicked/netinfo.h>

/* Max MTU - defines dhcp4 option length */
#define MTU_MAX             1500
#define MTU_MIN             576

/* UDP port numbers for DHCP4 */
#define DHCP4_SERVER_PORT    67
#define DHCP4_CLIENT_PORT    68

#define DHCP4_DEFAULT_LEASETIME	3600

#define MAGIC_COOKIE        0x63825363
#define BROADCAST_FLAG      0x8000

/* DHCP4 message OP code */
#define DHCP4_BOOTREQUEST    1
#define DHCP4_BOOTREPLY      2

/* DHCP4 message type */
#define DHCP4_DISCOVER       1
#define DHCP4_OFFER          2
#define DHCP4_REQUEST        3
#define DHCP4_DECLINE        4
#define DHCP4_ACK            5
#define DHCP4_NAK            6
#define DHCP4_RELEASE        7
#define DHCP4_INFORM         8

/* DHCP4 options */
enum DHCP4_OPTIONS {
	DHCP4_PAD                    = 0,
	DHCP4_NETMASK                = 1,
	DHCP4_TIMEROFFSET            = 2,
	DHCP4_ROUTERS                = 3,
	DHCP4_TIMESERVER             = 4,
	DHCP4_NAMESERVER             = 5,
	DHCP4_DNSSERVER              = 6,
	DHCP4_LOGSERVER              = 7,
	DHCP4_COOKIESERVER           = 8,
	DHCP4_LPRSERVER              = 9,
	DHCP4_IMPRESSSERVER          = 10,
	DHCP4_RLSSERVER              = 11,
	DHCP4_HOSTNAME               = 12,
	DHCP4_BOOTFILESIZE           = 13,
	DHCP4_MERITDUMPFILE          = 14,
	DHCP4_DNSDOMAIN              = 15,
	DHCP4_SWAPSERVER             = 16,
	DHCP4_ROOTPATH               = 17,
	DHCP4_EXTENTIONSPATH         = 18,
	DHCP4_IPFORWARDING           = 19,
	DHCP4_NONLOCALSOURCEROUTING  = 20,
	DHCP4_POLICYFILTER           = 21,
	DHCP4_MAXDGRAMREASMSIZE      = 22,
	DHCP4_DEFAULTIPTTL           = 23,
	DHCP4_PATHMTUAGINGTIMEOUT    = 24,
	DHCP4_PATHMTUPLATEAUTABLE    = 25,
	DHCP4_MTU                    = 26,
	DHCP4_ALLSUBNETSLOCAL        = 27,
	DHCP4_BROADCAST              = 28,
	DHCP4_MASKDISCOVERY          = 29,
	DHCP4_MASKSUPPLIER           = 30,
	DHCP4_ROUTERDISCOVERY        = 31,
	DHCP4_ROUTERSOLICITATIONADDR = 32,
	DHCP4_STATICROUTE            = 33,
	DHCP4_TRAILERENCAPSULATION   = 34,
	DHCP4_ARPCACHETIMEOUT        = 35,
	DHCP4_ETHERNETENCAPSULATION  = 36,
	DHCP4_TCPDEFAULTTTL          = 37,
	DHCP4_TCPKEEPALIVEINTERVAL   = 38,
	DHCP4_TCPKEEPALIVEGARBAGE    = 39,
	DHCP4_NISDOMAIN              = 40,
	DHCP4_NISSERVER              = 41,
	DHCP4_NTPSERVER              = 42,
	DHCP4_VENDORSPECIFICINFO     = 43,
	DHCP4_NETBIOSNAMESERVER      = 44,
	DHCP4_NETBIOSDDSERVER        = 45,
	DHCP4_NETBIOSNODETYPE        = 46,
	DHCP4_NETBIOSSCOPE           = 47,
	DHCP4_XFONTSERVER            = 48,
	DHCP4_XDISPLAYMANAGER        = 49,
	DHCP4_ADDRESS                = 50,
	DHCP4_LEASETIME              = 51,
	DHCP4_OPTIONSOVERLOADED      = 52,
	DHCP4_MESSAGETYPE            = 53,
	DHCP4_SERVERIDENTIFIER       = 54,
	DHCP4_PARAMETERREQUESTLIST   = 55,
	DHCP4_MESSAGE                = 56,
	DHCP4_MAXMESSAGESIZE         = 57,
	DHCP4_RENEWALTIME            = 58,
	DHCP4_REBINDTIME             = 59,
	DHCP4_CLASSID                = 60,
	DHCP4_CLIENTID               = 61,
	DHCP4_USERCLASS              = 77,  /* RFC 3004 */
	DHCP4_SLPSERVERS             = 78,  /* RFC 2610 */
	DHCP4_SLPSCOPES              = 79,
	DHCP4_FQDN                   = 81,
	DHCP4_NDS_SERVER             = 85,  /* RFC 2241 */
	DHCP4_NDS_TREE               = 86,  /* RFC 2241 */
	DHCP4_NDS_CTX                = 87,  /* RFC 2241 */
	DHCP4_POSIX_TZ_STRING        = 100, /* RFC 4833 */
	DHCP4_POSIX_TZ_DBNAME        = 101, /* RFC 4833 */
	DHCP4_DNSSEARCH              = 119, /* RFC 3397 */
	DHCP4_SIPSERVER              = 120, /* RFC 3361 */
	DHCP4_CSR                    = 121, /* RFC 3442 */
	DHCP4_MSCSR                  = 249, /* MS code for RFC 3442 */
	DHCP4_END                    = 255
};

#define DHCP4_OVERLOAD_BOOTFILE		0x01
#define DHCP4_OVERLOAD_SERVERNAME	0x02

/* SetFQDNHostName values - lsnybble used in flags
 * byte (see buildmsg.c), hsnybble to create order
 * and to allow 0x00 to mean disable
 */
enum FQQN {
	FQDN_DISABLE    = 0x00,
	FQDN_NONE       = 0x18,
	FQDN_PTR        = 0x20,
	FQDN_BOTH       = 0x31
};

/* Sizes for DHCP4 options */
#define DHCP4_CHADDR_LEN         16
#define SERVERNAME_LEN          64
#define BOOTFILE_LEN            128

#define BOOTP_MESSAGE_LENGTH_MIN (20 + 8 + 300)

struct ni_dhcp4_message {
	unsigned char		op;		/* message type */
	unsigned char		hwtype;		/* hardware address type */
	unsigned char		hwlen;		/* hardware address length */
	unsigned char		hwopcount;	/* should be zero in client message */
	uint32_t		xid;		/* transaction id */
	uint16_t		secs;		/* elapsed time in sec. from boot */
	uint16_t		flags;
	uint32_t		ciaddr;		/* (previously allocated) client IP */
	uint32_t		yiaddr;		/* 'your' client IP address */
	uint32_t		siaddr;		/* should be zero in client's messages */
	uint32_t		giaddr;		/* should be zero in client's messages */
	unsigned char		chaddr[DHCP4_CHADDR_LEN]; /* client's hardware address */
	unsigned char		servername[SERVERNAME_LEN]; /* server host name */
	unsigned char		bootfile[BOOTFILE_LEN]; /* boot file name */
	uint32_t		cookie;		/* DHCP4 magic cookie */
};

/* Work out if we have a private address or not
 * 10/8
 * 172.16/12
 * 192.168/16
 */
#ifndef IN_PRIVATE
# define IN_PRIVATE(addr) (((addr & IN_CLASSA_NET) == 0x0a000000) || \
			   ((addr & 0xfff00000)    == 0xac100000) || \
			   ((addr & IN_CLASSB_NET) == 0xc0a80000))
#endif

#define LINKLOCAL_ADDR  0xa9fe0000
#define LINKLOCAL_MASK  0xffff0000
#define LINKLOCAL_BRDC  0xa9feffff

#ifndef IN_LINKLOCAL
# define IN_LINKLOCAL(addr) ((addr & IN_CLASSB_NET) == LINKLOCAL_ADDR)
#endif

extern const char *	ni_dhcp4_message_name(unsigned int);
extern const char *	ni_dhcp4_option_name(unsigned int);

#endif /* __WICKED_DHCP4_PROTOCOL_H__ */
