/*
 * Type declarations for netinfo.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#ifndef __WICKED_TYPES_H__
#define __WICKED_TYPES_H__

#include <stdint.h>

typedef struct ni_handle	ni_handle_t;
typedef struct ni_syntax	ni_syntax_t;
typedef struct ni_interface	ni_interface_t;
typedef struct ni_bridge	ni_bridge_t;
typedef struct ni_bonding	ni_bonding_t;
typedef struct ni_addrconf	ni_addrconf_t;
typedef struct ni_nis_info	ni_nis_info_t;
typedef struct ni_addrconf_request ni_addrconf_request_t;
typedef struct ni_addrconf_lease  ni_addrconf_lease_t;

typedef struct ni_socket	ni_socket_t;
typedef struct ni_buffer	ni_buffer_t;
typedef struct ni_extension	ni_extension_t;
typedef struct ni_script_action	ni_script_action_t;

/*
 * These are used by the XML and XPATH code.
 */
typedef struct xpath_format xpath_format_t;
typedef struct xpath_enode xpath_enode_t;
typedef struct xml_document xml_document_t;
typedef struct xml_node xml_node_t;

typedef struct xpath_format_array {
	unsigned int		count;
	xpath_format_t **	data;
} xpath_format_array_t;

/*
 * Policies
 */
typedef struct ni_policy {
	struct ni_policy *	next;
	xml_node_t *		match;
	const char *		action;
	xml_node_t *		transform;
} ni_policy_t;

typedef struct ni_policy_info {
	xml_document_t *	document;
	ni_policy_t *		event_policies;
} ni_policy_info_t;

typedef union ni_uuid {
	unsigned char		octets[16];
	uint32_t		words[4];
} ni_uuid_t;

#endif /* __WICKED_TYPES_H__ */
