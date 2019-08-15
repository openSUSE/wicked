/*
 *	Build and parse DHCP6 packets
 *
 *	Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 */

#ifndef __WICKED_DHCP6_PROTOCOL_H__
#define __WICKED_DHCP6_PROTOCOL_H__


/*
 * Socket buffer size defaults
 */
#define NI_DHCP6_RBUF_SIZE		65536		/* max. UDP packet  */
#define NI_DHCP6_WBUF_SIZE		1280		/* initial size     */

/*
 * We use the preferred lifetime (== lease time) to adjust
 * all the life / renew / rebind times.
 *
 * T1 / renew : preferred * 0.5		(30 -> renew  after 15 sec)
 * T2 / rebind: preferred * 0.8		(30 -> rebind after 24 sec)
 */
#define NI_DHCP6_PREFERRED_LIFETIME	(3600*10)	/* 10 hours */
#define NI_DHCP6_MIN_PREF_LIFETIME	(30)		/* min. accepted from config */

/*
 * Client/Server Message Formats, transaction-id
 * http://tools.ietf.org/html/rfc3315#section-6
 */
#define NI_DHCP6_XID_MASK		0x00ffffff	/* xid is 24 bit    */

/*
 * DHCPv6 Multicast Addresses
 * http://tools.ietf.org/html/rfc3315#section-5.1
 */
#define	NI_DHCP6_ALL_RAGENTS		"ff02::1:2"	/* relays & servers */
#define NI_DHCP6_ALL_SRVONLY		"ff05::1:3"	/* all servers only */

/*
 * DHCPv6 UDP Ports
 * http://tools.ietf.org/html/rfc3315#section-5.2
 */
#define NI_DHCP6_CLIENT_PORT		546
#define NI_DHCP6_SERVER_PORT		547
#define NI_DHCP6_CLIENT_SERVICE		"dhcpv6-client"
#define NI_DHCP6_SERVER_SERVICE		"dhcpv6-server"

/*
 * "Infinity" life time
 *
 * http://tools.ietf.org/html/rfc3315#section-5.6
 */
#define NI_DHCP6_INFINITE_LIFETIME	0xffffffff

/*
 * DHCPv6 Message Types
 *
 * http://tools.ietf.org/html/rfc3315#section-5.3
 *  and others from:
 * http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xml
 */
enum NI_DHCP6_MSG_TYPE {
	NI_DHCP6_SOLICIT		= 1,	/* RFC3315 */
	NI_DHCP6_ADVERTISE		= 2,
	NI_DHCP6_REQUEST		= 3,
	NI_DHCP6_CONFIRM		= 4,
	NI_DHCP6_RENEW			= 5,
	NI_DHCP6_REBIND			= 6,
	NI_DHCP6_REPLY			= 7,
	NI_DHCP6_RELEASE		= 8,
	NI_DHCP6_DECLINE		= 9,
	NI_DHCP6_RECONFIGURE		= 10,
	NI_DHCP6_INFO_REQUEST		= 11,
	NI_DHCP6_RELAY_FORWARD		= 12,
	NI_DHCP6_RELAY_REPLY		= 13,
	NI_DHCP6_LEASEQUERY		= 14,	/* RFC5007 */
	NI_DHCP6_LEASEQUERY_REPLY	= 15,
	NI_DHCP6_LEASEQUERY_DONE	= 16,	/* RFC5460 */
	NI_DHCP6_LEASEQUERY_DATA	= 17,

	__NI_DHCP6_MSG_TYPE_MAX
};

/*
 * DHCPv6 Timings
 *
 * http://tools.ietf.org/html/rfc3315#section-5.5
 *
 *      Parameter		  Value    Description
 * ---------------------------------------------------------------------------
 */
#define	NI_DHCP6_SOL_MAX_DELAY	   1000	/* Max delay of first Solicit  */
#define NI_DHCP6_SOL_TIMEOUT	   1000	/* Initial Solicit timeout     */
#define NI_DHCP6_SOL_MAX_RT	 120000	/* Max Solicit timeout value   */
#define NI_DHCP6_REQ_TIMEOUT	   1000	/* Initial Request timeout     */
#define NI_DHCP6_REQ_MAX_RC	     10	/* Max Request retry attempts  */
#define NI_DHCP6_REQ_MAX_RT	  30000	/* Max Request timeout value   */
#define NI_DHCP6_CNF_MAX_DELAY	   1000	/* Max delay of first Confirm  */
#define NI_DHCP6_CNF_TIMEOUT	   1000	/* Initial Confirm timeout     */
#define NI_DHCP6_CNF_MAX_RT	   4000	/* Max Confirm timeout         */
#define NI_DHCP6_CNF_MAX_RD	  10000	/* Max Confirm duration        */
#define NI_DHCP6_REN_TIMEOUT	  10000	/* Initial Renew timeout       */
#define NI_DHCP6_REN_MAX_RT	 600000	/* Max Renew timeout value     */
#define NI_DHCP6_REB_TIMEOUT	  10000	/* Initial Rebind timeout      */
#define NI_DHCP6_REB_MAX_RT	 600000	/* Max Rebind timeout value    */
#define NI_DHCP6_INF_MAX_DELAY	   1000	/* Max delay of first Info-req */
#define NI_DHCP6_INF_TIMEOUT	   1000	/* Initial Info-req timeout    */
#define NI_DHCP6_INF_MAX_RT	 120000	/* Max Info-req timeout value  */
#define NI_DHCP6_REL_TIMEOUT	   1000	/* Initial Release timeout     */
#define NI_DHCP6_REL_MAX_RC	      5	/* Max Release attempts        */
#define NI_DHCP6_DEC_TIMEOUT	   1000	/* Initial Decline timeout     */
#define NI_DHCP6_DEC_MAX_RC	      5	/* Max Decline attempts        */
#define NI_DHCP6_REC_TIMEOUT	   2000	/* Initial Reconfigure timeout */
#define NI_DHCP6_REC_MAX_RC	      8	/* Max Reconfigure attempts    */
#define NI_DHCP6_HOP_COUNT_LIMIT     32	/* Max hop count in Relay-fwd  */
#define NI_DHCP6_MAX_JITTER	    100	/* Randomization factor [± 0.1]*/

/*
 * Information-Request Refresh-Time
 * https://tools.ietf.org/html/rfc4242#section-3.1
 */
#define NI_DHCP6_IRT_DEFAULT	  86400	/* default refresh time in sec  */
#define NI_DHCP6_IRT_MINIMUM	    600 /* minimum refresh time         */

/*
 * Option Format
 * http://tools.ietf.org/html/rfc3315#section-22.1
 */
typedef struct ni_dhcp6_option_header {
	uint16_t			code;
	uint16_t			len;
	unsigned char			data[];
} ni_dhcp6_option_header_t;

/*
 * Client/Server Message Formats
 * http://tools.ietf.org/html/rfc3315#section-6
 */
typedef union ni_dhcp6_client_header {
	uint8_t				type;
	uint32_t			xid;
} ni_dhcp6_client_header_t;

/*
 * Relay Agent/Server Message Formats
 *
 * http://tools.ietf.org/html/rfc3315#section-7
 */
typedef struct ni_dhcp6_relay_header {
	uint8_t				type;
	uint8_t				hop_count;
	struct in6_addr 		link_addr;
	struct in6_addr 		peer_addr;
} ni_dhcp6_relay_header_t;


/*
 * Union of Client/Server and Relay/Agent Messages
 */
typedef union ni_dhcp6_packet_header {
	uint8_t				type;
	ni_dhcp6_client_header_t	client;
	ni_dhcp6_relay_header_t		relay;
} ni_dhcp6_packet_header_t;

/*
typedef struct ni_dhcp6_option {
	uint16_t			code;
	uint16_t			len;
	unsigned char			data[];
} ni_dhcp6_option_t;

typedef struct ni_dhcp6_option_array {
	unsigned int			count;
	ni_dhcp6_option_t *		data;
} ni_dhcp6_option_array_t;
*/

/*
 * Option request option code array
 */
typedef struct ni_dhcp6_option_request {
	unsigned int			count;
	uint16_t *			options;
} ni_dhcp6_option_request_t;

#define NI_DHCP6_OPTION_REQUEST_INIT	{ .count = 0, .options = NULL }


/*
 * DHCPv6 specific FQDN option bits/flags
 * https://tools.ietf.org/html/rfc4704#section-4.1
 */
enum {
	NI_DHCP6_FQDN_FLAG_S		= NI_BIT(0),
	NI_DHCP6_FQDN_FLAG_O		= NI_BIT(1),
	NI_DHCP6_FQDN_FLAG_N		= NI_BIT(2),
	NI_DHCP6_FQDN_UPDATE_PTR	= 0x00,
	NI_DHCP6_FQDN_UPDATE_BOTH	= NI_DHCP6_FQDN_FLAG_S,
	NI_DHCP6_FQDN_UPDATE_NONE	= NI_DHCP6_FQDN_FLAG_N,
	NI_DHCP6_FQDN_UPDATE_MASK	= NI_DHCP6_FQDN_FLAG_S
					| NI_DHCP6_FQDN_FLAG_N,
	NI_DHCP6_FQDN_OVERRIDE		= NI_DHCP6_FQDN_FLAG_O,
};


/*
 * functions used in device.c and fsm.c
 */
extern const char *	ni_dhcp6_message_name(unsigned int);
extern unsigned int	ni_dhcp6_message_xid(unsigned int);

extern int		ni_dhcp6_init_message(	ni_dhcp6_device_t *, unsigned int,
						const ni_addrconf_lease_t *);
extern int		ni_dhcp6_build_message( ni_dhcp6_device_t *, unsigned int,
						ni_buffer_t *,
						const ni_addrconf_lease_t *);

extern ni_int_range_t	ni_dhcp6_jitter_rebase(unsigned int msec, int lower, int upper);
extern ni_bool_t	ni_dhcp6_set_message_timing(ni_dhcp6_device_t *dev, unsigned int msg_type);


extern int		ni_dhcp6_parse_client_header(ni_buffer_t *msgbuf,
							unsigned int *msg_type, unsigned int *msg_xid);

extern int		ni_dhcp6_parse_client_options(ni_dhcp6_device_t *dev, ni_buffer_t *buffer,
							ni_addrconf_lease_t *lease);

extern int		ni_dhcp6_check_client_header(ni_dhcp6_device_t *dev, const struct in6_addr *sender,
							unsigned int msg_type, unsigned int msg_xid);

extern int		ni_dhcp6_mcast_socket_open(ni_dhcp6_device_t *);
extern void		ni_dhcp6_mcast_socket_close(ni_dhcp6_device_t *);
extern ssize_t		ni_dhcp6_socket_send(ni_socket_t *, const ni_buffer_t *, const ni_sockaddr_t *);


/* FIXME: cleanup */
extern ni_bool_t	ni_dhcp6_ia_addr_is_usable(const ni_dhcp6_ia_addr_t *);
extern int		ni_dhcp6_ia_addr_list_copy(ni_dhcp6_ia_addr_t **, const ni_dhcp6_ia_addr_t *, ni_bool_t);

extern unsigned int	ni_dhcp6_ia_release_matching(ni_dhcp6_ia_t *, struct in6_addr *,
									unsigned int);
extern void		ni_dhcp6_ia_set_default_lifetimes(ni_dhcp6_ia_t *, unsigned int);

extern unsigned int	ni_dhcp6_ia_min_preferred_lft(ni_dhcp6_ia_t *);
extern unsigned int	ni_dhcp6_ia_max_preferred_lft(ni_dhcp6_ia_t *);
extern unsigned int	ni_dhcp6_ia_max_valid_lft(ni_dhcp6_ia_t *);

extern unsigned int	ni_dhcp6_ia_get_rebind_time(ni_dhcp6_ia_t *);
extern unsigned int	ni_dhcp6_ia_get_renewal_time(ni_dhcp6_ia_t *);

extern ni_bool_t	ni_dhcp6_ia_is_active(ni_dhcp6_ia_t *, struct timeval *);
extern unsigned int	ni_dhcp6_ia_list_count_active(ni_dhcp6_ia_t *, struct timeval *now);
extern int		ni_dhcp6_ia_list_copy(ni_dhcp6_ia_t **, const ni_dhcp6_ia_t *, ni_bool_t);
extern unsigned int	ni_dhcp6_ia_copy_to_lease_addrs(const ni_dhcp6_device_t *, ni_addrconf_lease_t *);

extern const char *	ni_dhcp6_print_timeval(const struct timeval *);

extern const char *	ni_dhcp6_address_print(const struct in6_addr *);

extern void		ni_dhcp6_option_request_init(ni_dhcp6_option_request_t *);
extern ni_bool_t	ni_dhcp6_option_request_append(ni_dhcp6_option_request_t *, uint16_t);
extern ni_bool_t	ni_dhcp6_option_request_contains(ni_dhcp6_option_request_t *, uint16_t);
extern void		ni_dhcp6_option_request_destroy(ni_dhcp6_option_request_t *);

#endif /* __WICKED_DHCP6_PROTOCOL_H__ */
