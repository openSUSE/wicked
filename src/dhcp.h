/*
 *	Common DHCP related utilities
 *
 *	Copyright (C) 2016 Marius Tomaschewski <mt@suse.de>
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef   WICKED_DHCP_H
#define   WICKED_DHCP_H

#include <wicked/addrconf.h>


/*
 * Generic (raw data) dhcp option
 */
struct ni_dhcp_option {
	ni_dhcp_option_t *		next;

	unsigned int			code;
	unsigned int			len;
	unsigned char *			data;
};

extern ni_dhcp_option_t *		ni_dhcp_option_new(unsigned int, unsigned int, const unsigned char *);
extern ni_bool_t			ni_dhcp_option_append(ni_dhcp_option_t *, unsigned int, const unsigned char *);
extern void				ni_dhcp_option_free(ni_dhcp_option_t *);


/*
 * Generic dhcp option list
 */
extern void				ni_dhcp_option_list_destroy(ni_dhcp_option_t **);
extern ni_bool_t			ni_dhcp_option_list_append(ni_dhcp_option_t **, ni_dhcp_option_t *);
extern ni_dhcp_option_t *		ni_dhcp_option_list_find(ni_dhcp_option_t *, unsigned int);
extern ni_dhcp_option_t *		ni_dhcp_option_list_pull(ni_dhcp_option_t **);


/*
 * "Scalar" dhcp option type ops
 */
typedef struct ni_dhcp_option_type	ni_dhcp_option_type_t;

struct ni_dhcp_option_type {
	const char *			name;
	uint8_t				elen;	/* nr of len bytes prepended in the data, */
	ni_uint_range_t			flen;	/* fixed length range of the data         */

	ni_bool_t			(*parse_args)(const xml_node_t *, ni_dhcp_option_decl_t *);
	ni_bool_t			(*opt_to_str)(const ni_dhcp_option_decl_t *, ni_buffer_t *, char **);
	ni_bool_t			(*str_to_opt)(const ni_dhcp_option_decl_t *, const char *, ni_dhcp_option_t *);
};

extern const ni_dhcp_option_type_t *	ni_dhcp_option_type_find(const char *);
extern const char *			ni_dhcp_option_type_name(const ni_dhcp_option_type_t *);


/*
 * Complex/nested option declaration kind
 */
typedef enum {
	NI_DHCP_OPTION_KIND_SCALAR,
	NI_DHCP_OPTION_KIND_STRUCT,
	NI_DHCP_OPTION_KIND_ARRAY,
} ni_dhcp_option_kind_t;

const char *				ni_dhcp_option_kind_name(ni_dhcp_option_kind_t);


/*
 * Complex/nested custom option declaration
 */
struct ni_dhcp_option_decl {
	ni_dhcp_option_decl_t *		next;

	char *				name;
	unsigned int			code;

	ni_dhcp_option_kind_t		kind;
	const ni_dhcp_option_type_t *	type;
	ni_dhcp_option_decl_t *		member;

	struct {
		uint8_t			elen;
		ni_uint_range_t		flen;
		ni_bool_t		hex;
	} args;
};

extern ni_dhcp_option_decl_t *		ni_dhcp_option_decl_new(const char *, unsigned int,
								const ni_dhcp_option_kind_t,
								const ni_dhcp_option_type_t *);
extern ni_dhcp_option_decl_t *		ni_dhcp_option_decl_clone(const ni_dhcp_option_decl_t *);
extern void				ni_dhcp_option_decl_free(ni_dhcp_option_decl_t *);


/*
 * Custom option declaration list
 */
extern void				ni_dhcp_option_decl_list_destroy(ni_dhcp_option_decl_t **);
extern ni_bool_t			ni_dhcp_option_decl_list_append(ni_dhcp_option_decl_t **, ni_dhcp_option_decl_t *);
extern ni_bool_t			ni_dhcp_option_decl_list_copy(ni_dhcp_option_decl_t **, const ni_dhcp_option_decl_t *);
extern const ni_dhcp_option_decl_t *	ni_dhcp_option_decl_list_find_by_name(const ni_dhcp_option_decl_t *, const char *);
extern const ni_dhcp_option_decl_t *	ni_dhcp_option_decl_list_find_by_code(const ni_dhcp_option_decl_t *, unsigned int);


/*
 * Custom option xml declaration parser
 */
extern ni_bool_t			ni_dhcp_option_decl_parse_xml(ni_dhcp_option_decl_t **, xml_node_t *,
									unsigned int, unsigned int,
									const char *, int);

/*
 * Format and parse custom option xml nodes
 */
extern xml_node_t *			ni_dhcp_option_to_xml(const ni_dhcp_option_t *, const ni_dhcp_option_decl_t *);
extern ni_dhcp_option_t *		ni_dhcp_option_from_xml(const xml_node_t *, const ni_dhcp_option_decl_t *);

/*
 * Format custom option into a variable array
 */
extern ni_var_array_t *			ni_dhcp_option_to_vars(const ni_dhcp_option_t *, const ni_dhcp_option_decl_t *);

/*
 * Utility functions
 */
extern ni_bool_t			ni_dhcp_domain_encode(ni_buffer_t *, const char *, ni_bool_t);
extern ni_bool_t			ni_dhcp_domain_decode(ni_buffer_t *, char **);

extern ni_bool_t			ni_dhcp_check_user_class_id(const char *, size_t);

#endif /* WICKED_DHCP_H */
