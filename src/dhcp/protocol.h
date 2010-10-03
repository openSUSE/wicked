/*
 * Build and parse DHCP packets
 *
 * Copyright (C) 2010, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcpcd, which was written by Roy Marples <roy@marples.name>
 */

#ifndef __WICKED_DHCP_PROTOCOL_H__
#define __WICKED_DHCP_PROTOCOL_H__

#include <netinet/in.h>
#include <stdint.h>
#include <wicked/netinfo.h>

/* Max MTU - defines dhcp option length */
#define MTU_MAX             1500
#define MTU_MIN             576

/* UDP port numbers for DHCP */
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_DEFAULT_LEASETIME	3600

#define MAGIC_COOKIE        0x63825363
#define BROADCAST_FLAG      0x8000

/* DHCP message OP code */
#define DHCP_BOOTREQUEST    1
#define DHCP_BOOTREPLY      2

/* DHCP message type */
#define DHCP_DISCOVER       1
#define DHCP_OFFER          2
#define DHCP_REQUEST        3
#define DHCP_DECLINE        4
#define DHCP_ACK            5
#define DHCP_NAK            6
#define DHCP_RELEASE        7
#define DHCP_INFORM         8

/* DHCP options */
enum DHCP_OPTIONS {
	DHCP_PAD                    = 0,
	DHCP_NETMASK                = 1,
	DHCP_TIMEROFFSET            = 2,
	DHCP_ROUTERS                = 3,
	DHCP_TIMESERVER             = 4,
	DHCP_NAMESERVER             = 5,
	DHCP_DNSSERVER              = 6,
	DHCP_LOGSERVER              = 7,
	DHCP_COOKIESERVER           = 8,
	DHCP_LPRSERVER              = 9,
	DHCP_IMPRESSSERVER          = 10,
	DHCP_RLSSERVER              = 11,
	DHCP_HOSTNAME               = 12,
	DHCP_BOOTFILESIZE           = 13,
	DHCP_MERITDUMPFILE          = 14,
	DHCP_DNSDOMAIN              = 15,
	DHCP_SWAPSERVER             = 16,
	DHCP_ROOTPATH               = 17,
	DHCP_EXTENTIONSPATH         = 18,
	DHCP_IPFORWARDING           = 19,
	DHCP_NONLOCALSOURCEROUTING  = 20,
	DHCP_POLICYFILTER           = 21,
        DHCP_MAXDGRAMREASMSIZE      = 22,
	DHCP_DEFAULTIPTTL           = 23,
	DHCP_PATHMTUAGINGTIMEOUT    = 24,
	DHCP_PATHMTUPLATEAUTABLE    = 25,
	DHCP_MTU                    = 26,
	DHCP_ALLSUBNETSLOCAL        = 27,
	DHCP_BROADCAST              = 28,
	DHCP_MASKDISCOVERY          = 29,
	DHCP_MASKSUPPLIER           = 30,
	DHCP_ROUTERDISCOVERY        = 31,
	DHCP_ROUTERSOLICITATIONADDR = 32,
	DHCP_STATICROUTE            = 33,
	DHCP_TRAILERENCAPSULATION   = 34,
	DHCP_ARPCACHETIMEOUT        = 35,
	DHCP_ETHERNETENCAPSULATION  = 36,
	DHCP_TCPDEFAULTTTL          = 37,
	DHCP_TCPKEEPALIVEINTERVAL   = 38,
	DHCP_TCPKEEPALIVEGARBAGE    = 39,
	DHCP_NISDOMAIN              = 40,
	DHCP_NISSERVER              = 41,
	DHCP_NTPSERVER              = 42,
	DHCP_VENDORSPECIFICINFO     = 43,
	DHCP_NETBIOSNAMESERVER      = 44,
	DHCP_NETBIOSDDSERVER        = 45,
	DHCP_NETBIOSNODETYPE        = 46,
	DHCP_NETBIOSSCOPE           = 47,
	DHCP_XFONTSERVER            = 48,
	DHCP_XDISPLAYMANAGER        = 49,
	DHCP_ADDRESS                = 50,
	DHCP_LEASETIME              = 51,
	DHCP_OPTIONSOVERLOADED      = 52,
	DHCP_MESSAGETYPE            = 53,
	DHCP_SERVERIDENTIFIER       = 54,
	DHCP_PARAMETERREQUESTLIST   = 55,
	DHCP_MESSAGE                = 56,
	DHCP_MAXMESSAGESIZE         = 57,
	DHCP_RENEWALTIME            = 58,
	DHCP_REBINDTIME             = 59,
	DHCP_CLASSID                = 60,
	DHCP_CLIENTID               = 61,
	DHCP_USERCLASS              = 77,  /* RFC 3004 */
	DHCP_SLPSERVERS             = 78,  /* RFC 2610 */
	DHCP_SLPSCOPES              = 79,
	DHCP_FQDN                   = 81,
	DHCP_DNSSEARCH              = 119, /* RFC 3397 */
	DHCP_SIPSERVER              = 120, /* RFC 3361 */
	DHCP_CSR                    = 121, /* RFC 3442 */
	DHCP_MSCSR                  = 249, /* MS code for RFC 3442 */
	DHCP_END                    = 255
};

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

/* Sizes for DHCP options */
#define DHCP_CHADDR_LEN         16
#define SERVERNAME_LEN          64
#define BOOTFILE_LEN            128

#define BOOTP_MESSAGE_LENGTH_MIN 300

struct ni_dhcp_message {
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
	unsigned char		chaddr[DHCP_CHADDR_LEN]; /* client's hardware address */
	unsigned char		servername[SERVERNAME_LEN]; /* server host name */
	unsigned char		bootfile[BOOTFILE_LEN]; /* boot file name */
	uint32_t		cookie;		/* DHCP magic cookie */
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

extern const char *	ni_dhcp_message_name(unsigned int);
extern const char *	ni_dhcp_option_name(unsigned int);

#endif /* __WICKED_DHCP_PROTOCOL_H__ */
