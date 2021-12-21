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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <endian.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include "dhcp.h"
#include "buffer.h"


/*
 * Generic (raw data) dhcp option
 */
ni_dhcp_option_t *
ni_dhcp_option_new(unsigned int code, unsigned int len, const unsigned char *data)
{
	ni_dhcp_option_t *opt;

	opt = calloc(1, sizeof(*opt));
	if (opt) {
		opt->code = code;
		if (!data || !len || len == UINT_MAX)
			return opt;

		opt->data = malloc(len + 1);
		if (opt->data) {
			opt->len = len;
			memcpy(opt->data, data, len);
			opt->data[len] = '\0';
			return opt;
		}

		ni_dhcp_option_free(opt);
		return NULL;
	}
	return opt;
}

ni_bool_t
ni_dhcp_option_append(ni_dhcp_option_t *opt, unsigned int len, const unsigned char *data)
{
	size_t         newsize;
	unsigned char *newdata;

	if (!opt || !data || !len || len == UINT_MAX)
		return FALSE;

	newsize = opt->len + len;
	if (newsize == SIZE_MAX || newsize < opt->len)
		return FALSE;

	newdata = realloc(opt->data, newsize + 1);
	if (!newdata)
		return FALSE;

	opt->data = newdata;
	memcpy(opt->data + opt->len, data, len);
	opt->len  = newsize;
	return TRUE;
}

void
ni_dhcp_option_free(ni_dhcp_option_t *opt)
{
	if (opt) {
		free(opt->data);
		free(opt);
	}
}


/*
 * Generic dhcp option list
 */
void
ni_dhcp_option_list_destroy(ni_dhcp_option_t **list)
{
	ni_dhcp_option_t *opt;

	if (list) {
		while ((opt = *list) != NULL) {
			*list = opt->next;
			ni_dhcp_option_free(opt);
		}
	}
}

ni_bool_t
ni_dhcp_option_list_append(ni_dhcp_option_t **list, ni_dhcp_option_t *opt)
{
	if (!list || !opt)
		return FALSE;

	while (*list)
		list = &(*list)->next;
	*list = opt;
	return TRUE;
}

ni_dhcp_option_t *
ni_dhcp_option_list_find(ni_dhcp_option_t *list, unsigned int code)
{
	ni_dhcp_option_t *opt;

	for (opt = list; opt; opt = opt->next) {
		if (opt->code == code)
			return opt;
	}
	return NULL;
}

ni_dhcp_option_t *
ni_dhcp_option_list_pull(ni_dhcp_option_t **list)
{
	ni_dhcp_option_t *opt;

	if (!list)
		return NULL;

	if ((opt = *list)) {
		*list = opt->next;
		opt->next = NULL;
	}
	return opt;
}

/*
 * "Scalar" dhcp option type ops
 */
static ni_bool_t
ni_dhcp_option_get_range_len(const ni_uint_range_t *range, size_t len, unsigned int *ret)
{
	/* require at least min, but don't fetch more than max len */
	if (range && ret && len >= (size_t)range->min) {
		if (len >= (size_t)range->max)
			*ret = range->max;
		else
			*ret = len;
		return TRUE;
	}
	return FALSE;
}

static ni_bool_t
ni_dhcp_option_pad_range_len(const ni_uint_range_t *range, size_t len, unsigned int *ret)
{
	/* put len if in range and pad to max, except max is -1U */
	if (!range || !ret || len > (size_t)-1U || !ni_uint_in_range(range, len))
		return FALSE;

	if (range->max != -1U)
		*ret = range->max;
	else
		*ret = len;
	return TRUE;
}

static ni_bool_t
ni_dhcp_option_get_embedded_len(ni_buffer_t *buf, uint8_t size, unsigned int *len)
{
	union {
		uint8_t  u8;
		uint16_t u16;
	} elen = { .u16 = 0 };

	switch (size) {
	case sizeof(elen.u8):
		if (ni_buffer_get(buf, &elen.u8, sizeof(elen.u8)) < 0)
			return FALSE;
		*len = elen.u8;
		return TRUE;

	case sizeof(elen.u16):
		if (ni_buffer_get(buf, &elen.u16, sizeof(elen.u16)) < 0)
			return FALSE;
		*len = ntohs(elen.u16);
		return TRUE;

	default:
		return FALSE;
	}
}

static ni_bool_t
ni_dhcp_option_put_embedded_len(ni_dhcp_option_t *opt, uint8_t size, unsigned int len)
{
	union {
		uint8_t  u8;
		uint16_t u16;
	} elen = { .u16 = 0 };

	switch (size) {
	case sizeof(elen.u8):
		if (len > UINT8_MAX)
			return FALSE;
		elen.u8 = len;
		return ni_dhcp_option_append(opt, sizeof(elen.u8), (unsigned char *)&elen.u8);

	case sizeof(elen.u16):
		if (len > UINT16_MAX)
			return FALSE;
		elen.u16 = htons(len);
		return ni_dhcp_option_append(opt, sizeof(elen.u16), (unsigned char *)&elen.u16);

	default:
		return FALSE;
	}
}

static ni_bool_t
ni_dhcp_option_type_parse_args_opaque(const xml_node_t *node, ni_dhcp_option_decl_t *decl)
{
	unsigned int length;
	const char *embedded;

	if (xml_node_get_attr_uint(node, "fixed-length", &length))
		decl->args.flen.min = decl->args.flen.max = length;
	else
	if ((embedded = xml_node_get_attr(node, "embedded-length"))) {
		if (ni_string_eq(embedded, "uint8")  || ni_string_eq(embedded, "1"))
			decl->args.flen.min = decl->args.elen = 1;
		else
		if (ni_string_eq(embedded, "uint16") || ni_string_eq(embedded, "2"))
			decl->args.flen.min = decl->args.elen = 2;
		else
			return FALSE;
	}
	return TRUE;
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_opaque(const ni_dhcp_option_decl_t *decl, ni_buffer_t *buf,
					char **str)
{
	const char *ptr;
	unsigned int len;

	ni_string_free(str);
	if (decl->args.elen) {
		if (!ni_dhcp_option_get_embedded_len(buf, decl->args.elen, &len))
			return FALSE;
	} else {
		if (!ni_dhcp_option_get_range_len(&decl->args.flen, ni_buffer_count(buf), &len))
			return FALSE;
	}

	if (len) {
		if (!(ptr = ni_buffer_pull_head(buf, len)))
			return FALSE;

		*str = ni_sprint_hex((const unsigned char *)ptr, len);
		return !ni_string_empty(*str);
	}
	return TRUE;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_opaque(const ni_dhcp_option_decl_t *decl, const char *str,
					ni_dhcp_option_t *opt)
{
	size_t len = ni_string_len(str);
	unsigned char *data;
	unsigned int pad;
	ssize_t hex;

	len = (len / 3) + 1; /* xx:xx:xx string len -> raw data len */
	if (decl->args.elen) {
		if (!ni_dhcp_option_put_embedded_len(opt, decl->args.elen, len))
			return FALSE;
		pad = len;
	} else {
		if (!ni_dhcp_option_pad_range_len(&decl->args.flen, len, &pad))
			return FALSE;
	}

	if (pad == 0)
		return TRUE;

	data = calloc(1, pad);
	if (!data)
		return FALSE;

	hex = ni_parse_hex(str, data, pad);
	if (hex > 0 && ni_dhcp_option_append(opt, pad, data)) {
		free(data);
		return TRUE;
	} else {
		free(data);
		return FALSE;
	}
}

static ni_bool_t
ni_dhcp_option_type_parse_args_string(const xml_node_t *node, ni_dhcp_option_decl_t *decl)
{
	unsigned int length;
	const char *embedded;

	if (xml_node_get_attr_uint(node, "fixed-length", &length))
		decl->args.flen.min = decl->args.flen.max = length;
	else
	if ((embedded = xml_node_get_attr(node, "embedded-length"))) {
		if (ni_string_eq(embedded, "uint8")  || ni_string_eq(embedded, "1"))
			decl->args.flen.min = decl->args.elen = 1;
		else
		if (ni_string_eq(embedded, "uint16") || ni_string_eq(embedded, "2"))
			decl->args.flen.min = decl->args.elen = 2;
		else
			return FALSE;
	}
	return TRUE;
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_string(const ni_dhcp_option_decl_t *decl, ni_buffer_t *buf,
					char **str)
{
	const char *ptr;
	unsigned int len;

	ni_string_free(str);
	if (decl->args.elen) {
		if (!ni_dhcp_option_get_embedded_len(buf, decl->args.elen, &len))
			return FALSE;
	} else {
		if (!ni_dhcp_option_get_range_len(&decl->args.flen, ni_buffer_count(buf), &len))
			return FALSE;
	}

	if (len) {
		if (!(ptr = ni_buffer_pull_head(buf, len)))
			return FALSE;

		if (!ni_string_set(str, ptr, len))
			return FALSE;

		len = ni_string_len(*str);
		if (len && !ni_check_printable(*str, len)) {
			ni_string_free(str);
			return FALSE;
		}
	}
	return TRUE;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_string(const ni_dhcp_option_decl_t *decl, const char *str,
					ni_dhcp_option_t *opt)
{
	size_t len = ni_string_len(str);
	unsigned char *data;
	unsigned int pad;

	if (decl->args.elen) {
		if (!ni_dhcp_option_put_embedded_len(opt, decl->args.elen, len))
			return FALSE;
		pad = len;
	} else {
		if (!ni_dhcp_option_pad_range_len(&decl->args.flen, len, &pad))
			return FALSE;
	}

	if (pad == 0)
		return TRUE;

	if (len == pad)
		return ni_dhcp_option_append(opt, pad, (const unsigned char *)str);

	data = calloc(1, pad);
	if (!data)
		return FALSE;

	memcpy(data, str, len);
	if (ni_dhcp_option_append(opt, pad, (const unsigned char *)data)) {
		free(data);
		return TRUE;
	} else {
		free(data);
		return FALSE;
	}
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_bool(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	ni_bool_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	return ni_string_dup(str, ni_format_boolean(value));
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_bool(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	ni_bool_t value;

	if (ni_parse_boolean(str, &value) != 0)
		return FALSE;

	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}

static ni_bool_t
ni_dhcp_option_type_parse_args_int(const xml_node_t *node, ni_dhcp_option_decl_t *decl)
{
	const char *notation = xml_node_get_attr(node, "notation");

	if (ni_string_empty(notation))
		decl->args.hex = FALSE;
	else
	if (ni_string_eq(notation, "dec"))
		decl->args.hex = FALSE;
	else
	if (ni_string_eq(notation, "hex"))
		decl->args.hex = TRUE;
	else
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_int8(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	int8_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	return ni_string_printf(str, decl->args.hex ? "%"PRIx8 : "%"PRId8, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_int8(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	int8_t value;
	long temp;

	if (ni_parse_long(str, &temp, decl->args.hex ? 16 : 10) < 0 ||
			temp < INT8_MIN || temp > INT8_MAX)
		return FALSE;

	value = temp;
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_uint8(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	uint8_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	return ni_string_printf(str, decl->args.hex ? "%"PRIx8 : "%"PRIu8, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_uint8(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	unsigned long temp;
	uint8_t value;

	if (ni_parse_ulong(str, &temp, decl->args.hex ? 16 : 10) < 0 ||
			temp > UINT8_MAX)
		return FALSE;

	value = temp;
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_int16(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	int16_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = ntohs(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx16 : "%"PRId16, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_int16(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	int16_t value;
	long temp;

	if (ni_parse_long(str, &temp, decl->args.hex ? 16 : 10) < 0 ||
			temp < INT16_MIN || temp > INT16_MAX)
		return FALSE;

	value = htons(temp);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_uint16(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	uint16_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = ntohs(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx16 : "%"PRIu16, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_uint16(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	unsigned long temp;
	uint16_t value;

	if (ni_parse_ulong(str, &temp, decl->args.hex ? 16 : 10) < 0 ||
			temp > UINT16_MAX)
		return FALSE;

	value = htons(temp);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_int32(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	int32_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = ntohl(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx32 : "%"PRId32, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_int32(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	int value;

	if (ni_parse_int(str, &value, decl->args.hex ? 16 : 10) < 0)
		return FALSE;

	value = htonl(value);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_uint32(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	uint32_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = ntohl(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx32 : "%"PRIu32, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_uint32(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	unsigned int value;

	if (ni_parse_uint(str, &value, decl->args.hex ? 16 : 10) < 0)
		return FALSE;

	value = htonl(value);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_int64(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	int64_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = be64toh(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx64 : "%"PRId64, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_int64(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	int64_t value;

	if (ni_parse_int64(str, &value, decl->args.hex ? 16 : 10) < 0)
		return FALSE;

	value = htobe64(value);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}
static ni_bool_t
ni_dhcp_option_type_opt_to_str_uint64(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	uint64_t value;

	if (ni_buffer_get(buf, &value, sizeof(value)) < 0)
		return FALSE;

	value = be64toh(value);
	return ni_string_printf(str, decl->args.hex ? "%"PRIx64 : "%"PRIu64, value) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_uint64(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	uint64_t value;

	if (ni_parse_uint64(str, &value, decl->args.hex ? 16 : 10) < 0)
		return FALSE;

	value = htobe64(value);
	return ni_dhcp_option_append(opt, sizeof(value), (unsigned char *)&value);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_ipv4address(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	ni_sockaddr_t addr;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = AF_INET;
	ni_string_free(str);

	if (ni_buffer_get(buf, &addr.sin.sin_addr, sizeof(addr.sin.sin_addr)) < 0)
		return FALSE;
	return ni_string_dup(str, ni_sockaddr_print(&addr));
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_ipv4address(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	ni_sockaddr_t addr;

	if (ni_sockaddr_parse(&addr, str, AF_INET) < 0)
		return FALSE;
	return ni_dhcp_option_append(opt, sizeof(addr.sin.sin_addr),
				(unsigned char *)&addr.sin.sin_addr);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_ipv4prefix(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	ni_sockaddr_t addr;
	uint8_t plen;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = AF_INET;
	ni_string_free(str);

	if (ni_buffer_get(buf, &plen, sizeof(plen)) < 0 ||
			plen > ni_af_address_prefixlen(addr.ss_family))
		return FALSE;
	if (ni_buffer_get(buf, &addr.sin.sin_addr, (plen + 7) / 8) < 0)
		return FALSE;
	return ni_string_printf(str, "%s/%u", ni_sockaddr_print(&addr), plen) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_ipv4prefix(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	ni_sockaddr_t addr;
	unsigned long temp;
	char *address = NULL;
	char *prefix;
	uint8_t plen;

	if (ni_string_empty(str) || !ni_string_dup(&address, str))
		return FALSE;

	if (!(prefix = strchr(address, '/'))) {
		ni_string_free(&address);
		return FALSE;
	}
	*prefix++ = '\0';

	if (ni_sockaddr_parse(&addr, address, AF_INET) < 0 ||
		ni_parse_ulong(prefix, &temp, 10) < 0 ||
		temp > ni_af_address_prefixlen(addr.ss_family)) {
		ni_string_free(&address);
		return FALSE;
	}
	plen = temp;

	ni_string_free(&address);
	return  ni_dhcp_option_append(opt, sizeof(plen), (unsigned char *)&plen) &&
		ni_dhcp_option_append(opt, (plen + 7) / 8, (unsigned char *)&addr.sin.sin_addr);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_ipv6address(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	ni_sockaddr_t addr;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = AF_INET6;
	ni_string_free(str);

	if (ni_buffer_get(buf, &addr.six.sin6_addr, sizeof(addr.six.sin6_addr)) < 0)
		return FALSE;
	return ni_string_dup(str, ni_sockaddr_print(&addr));
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_ipv6address(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	ni_sockaddr_t addr;

	if (ni_sockaddr_parse(&addr, str, AF_INET6) < 0)
		return FALSE;
	return ni_dhcp_option_append(opt, sizeof(addr.six.sin6_addr),
				(unsigned char *)&addr.six.sin6_addr);
}

static ni_bool_t
ni_dhcp_option_type_opt_to_str_ipv6prefix(const ni_dhcp_option_decl_t *decl,
					ni_buffer_t *buf, char **str)
{
	ni_sockaddr_t addr;
	uint8_t plen;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = AF_INET6;
	ni_string_free(str);

	if (ni_buffer_get(buf, &plen, sizeof(plen)) < 0 ||
			plen > ni_af_address_prefixlen(addr.ss_family))
		return FALSE;
	if (ni_buffer_get(buf, &addr.six.sin6_addr, (plen + 7) / 8) < 0)
		return FALSE;

	return ni_string_printf(str, "%s/%u", ni_sockaddr_print(&addr), plen) != NULL;
}
static ni_bool_t
ni_dhcp_option_type_str_to_opt_ipv6prefix(const ni_dhcp_option_decl_t *decl,
					const char *str, ni_dhcp_option_t *opt)
{
	ni_sockaddr_t addr;
	unsigned long temp;
	char *address = NULL;
	char *prefix;
	uint8_t plen;

	if (ni_string_empty(str) || !ni_string_dup(&address, str))
		return FALSE;

	if (!(prefix = strchr(address, '/'))) {
		ni_string_free(&address);
		return FALSE;
	}
	*prefix++ = '\0';

	if (ni_sockaddr_parse(&addr, address, AF_INET6) < 0 ||
		ni_parse_ulong(prefix, &temp, 10) < 0 ||
		temp > ni_af_address_prefixlen(addr.ss_family)) {
		ni_string_free(&address);
		return FALSE;
	}
	plen = temp;

	ni_string_free(&address);
	return  ni_dhcp_option_append(opt, sizeof(plen), (unsigned char *)&plen) &&
		ni_dhcp_option_append(opt, (plen + 7) / 8, (unsigned char *)&addr.six.sin6_addr);
}

static const ni_dhcp_option_type_t	ni_dhcp_option_types[] = {
#define	FIXED_LEN(length)	{ length, length }
	{
		.name = "opaque",
		.flen = { 0, -1U },
		.parse_args = ni_dhcp_option_type_parse_args_opaque,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_opaque,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_opaque,
	},
	{
		.name = "string",
		.flen = { 0, -1U },
		.parse_args = ni_dhcp_option_type_parse_args_string,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_string,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_string,
	},

	{
		.name = "bool",
		.flen = FIXED_LEN(sizeof(uint8_t)),
		.opt_to_str = ni_dhcp_option_type_opt_to_str_bool,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_bool,
	},

	{
		.name = "int8",
		.flen = FIXED_LEN(sizeof(int8_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_int8,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_int8,
	},
	{
		.name = "uint8",
		.flen = FIXED_LEN(sizeof(uint8_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_uint8,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_uint8,
	},

	{
		.name = "int16",
		.flen = FIXED_LEN(sizeof(int16_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_int16,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_int16,
	},
	{
		.name = "uint16",
		.flen = FIXED_LEN(sizeof(uint16_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_uint16,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_uint16,
	},

	{
		.name = "int32",
		.flen = FIXED_LEN(sizeof(int32_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_int32,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_int32,
	},
	{
		.name = "uint32",
		.flen = FIXED_LEN(sizeof(uint32_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_uint32,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_uint32,
	},

	{
		.name = "int64",
		.flen = FIXED_LEN(sizeof(int64_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_int64,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_int64,
	},
	{
		.name = "uint64",
		.flen = FIXED_LEN(sizeof(uint64_t)),
		.parse_args = ni_dhcp_option_type_parse_args_int,
		.opt_to_str = ni_dhcp_option_type_opt_to_str_uint64,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_uint64,
	},

	{
		.name = "ipv4-address",
		.flen = FIXED_LEN(sizeof(struct in_addr)),
		.opt_to_str = ni_dhcp_option_type_opt_to_str_ipv4address,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_ipv4address,
	},
	{
		.name = "ipv4-prefix",		/* rfc3442 destination  */
		.elen = sizeof(uint8_t),	/* len embedded in data */
		.flen = { sizeof(uint8_t), sizeof(uint8_t) + sizeof(struct in_addr) },
		.opt_to_str = ni_dhcp_option_type_opt_to_str_ipv4prefix,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_ipv4prefix,
	},

	{
		.name = "ipv6-address",
		.flen = FIXED_LEN(sizeof(struct in6_addr)),
		.opt_to_str = ni_dhcp_option_type_opt_to_str_ipv6address,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_ipv6address,
	},
	{
		.name = "ipv6-prefix",		/* rfc7227 section 5.3  */
		.elen = sizeof(uint8_t),	/* len embedded in data */
		.flen = { sizeof(uint8_t), sizeof(uint8_t) + sizeof(struct in6_addr) },
		.opt_to_str = ni_dhcp_option_type_opt_to_str_ipv6prefix,
		.str_to_opt = ni_dhcp_option_type_str_to_opt_ipv6prefix,
	},

	{	.name = NULL, }
#undef FIXED_LEN
};

const ni_dhcp_option_type_t *
ni_dhcp_option_type_find(const char *name)
{
	const ni_dhcp_option_type_t *type = ni_dhcp_option_types;

	for ( ; type->name; ++type) {
		if (ni_string_eq(type->name, name))
			return type;
	}
	return NULL;
}

const char *
ni_dhcp_option_type_name(const ni_dhcp_option_type_t *type)
{
	return type ? type->name : NULL;
}

/*
 * Complex/nested option declaration kind
 */
static const ni_intmap_t	ni_dhcp_option_kind_names[] = {
	{ "scalar",		NI_DHCP_OPTION_KIND_SCALAR	},
	{ "struct",		NI_DHCP_OPTION_KIND_STRUCT	},
	{ "array",		NI_DHCP_OPTION_KIND_ARRAY	},

	{ NULL,			-1U				}
};

const char *
ni_dhcp_option_kind_name(ni_dhcp_option_kind_t kind)
{
	return ni_format_uint_mapped(kind, ni_dhcp_option_kind_names);
}


/*
 * Complex/nested custom option declaration
 */
ni_dhcp_option_decl_t *
ni_dhcp_option_decl_new(const char *name, unsigned int code,
			const ni_dhcp_option_kind_t  kind,
			const ni_dhcp_option_type_t *type)
{
	ni_dhcp_option_decl_t *decl;

	if (ni_string_empty(name))
		return NULL;

	decl = calloc(1, sizeof(*decl));
	if (decl) {
		decl->kind = kind;
		decl->type = type;

		decl->code = code;
		if (ni_string_dup(&decl->name, name))
			return decl;

		ni_dhcp_option_decl_free(decl);
	}
	return NULL;
}

ni_dhcp_option_decl_t *
ni_dhcp_option_decl_clone(const ni_dhcp_option_decl_t *src)
{
	ni_dhcp_option_decl_t *decl;

	if (!src)
		return NULL;

	decl = ni_dhcp_option_decl_new(src->name, src->code, src->kind, src->type);
	if (decl && ni_dhcp_option_decl_list_copy(&decl->member, src->member))
		return decl;

	ni_dhcp_option_decl_free(decl);
	return NULL;
}

void
ni_dhcp_option_decl_free(ni_dhcp_option_decl_t *decl)
{
	if (decl) {
		decl->code = 0;
		decl->type = NULL;
		ni_string_free(&decl->name);
		free(decl);
	}
}

void
ni_dhcp_option_decl_list_destroy(ni_dhcp_option_decl_t **list)
{
	ni_dhcp_option_decl_t *decl;

	if (list) {
		while ((decl = *list)) {
			*list = decl->next;
			ni_dhcp_option_decl_free(decl);
		}
	}
}

ni_bool_t
ni_dhcp_option_decl_list_append(ni_dhcp_option_decl_t **list, ni_dhcp_option_decl_t *decl)
{
	if (!list || !decl)
		return FALSE;

	while (*list)
		list = &(*list)->next;
	*list = decl;
	return TRUE;
}

ni_bool_t
ni_dhcp_option_decl_list_copy(ni_dhcp_option_decl_t **list, const ni_dhcp_option_decl_t *src)
{
	const ni_dhcp_option_decl_t *sdecl;
	ni_dhcp_option_decl_t *decl, **tail;

	if (!(tail = list))
		return FALSE;

	ni_dhcp_option_decl_list_destroy(list);
	for (sdecl = src; sdecl; sdecl = sdecl->next) {
		decl = ni_dhcp_option_decl_clone(sdecl);
		if (!(*tail = decl)) {
			ni_dhcp_option_decl_list_destroy(list);
			return FALSE;
		}
		tail = &decl->next;
	}
	return TRUE;
}

const ni_dhcp_option_decl_t *
ni_dhcp_option_decl_list_find_by_name(const ni_dhcp_option_decl_t *list, const char *name)
{
	const ni_dhcp_option_decl_t *decl;

	for (decl = list; decl; decl = decl->next) {
		if (ni_string_eq(decl->name, name))
			return decl;
	}
	return NULL;
}

const ni_dhcp_option_decl_t *
ni_dhcp_option_decl_list_find_by_code(const ni_dhcp_option_decl_t *list, unsigned int code)
{
	const ni_dhcp_option_decl_t *decl;

	for (decl = list; decl; decl = decl->next) {
		if (decl->code == code)
			return decl;
	}
	return NULL;
}

/*
 * Parsing of a custom option declaration xml node:
 *   <option>
 *     <code/>                          option code
 *
 *     <name/>                          option name
 *     <type|array|struct/>             option type
 *   </option>
 *   ...
 *
 * with following option types:
 *
 *   <type>type-name</type>               scalar type
 *
 *   <array>
 *     <name/>                            element name
 *     <type|array|struct/>               element type
 *   </array>
 *
 *   <struct>
 *     <member>
 *       <name/>                          member name
 *       <type|array|struct/>             member type
 *     </member>
 *     ...
 *   </struct>
 *
 */
static ni_dhcp_option_decl_t *
ni_dhcp_option_decl_parse_xml_type(ni_dhcp_option_decl_t **, xml_node_t *,
				const char *, unsigned int,
				const char *, int);

static ni_bool_t
ni_dhcp_option_decl_fixed_length(ni_dhcp_option_decl_t *decl)
{
	ni_dhcp_option_decl_t *member;

	if (decl->args.flen.min != decl->args.flen.max && !decl->args.elen)
		return FALSE;

	for (member = decl->member; member; member = member->next) {
		if (!ni_dhcp_option_decl_fixed_length(member))
			return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_dhcp_option_decl_parse_xml_args(const xml_node_t *node, ni_dhcp_option_decl_t *decl)
{
	if (!node || !decl)
		return FALSE;

	switch (decl->kind) {
	case NI_DHCP_OPTION_KIND_SCALAR:
		if (!decl->type)
			return FALSE;

		decl->args.elen     = decl->type->elen;
		decl->args.flen.min = decl->type->flen.min;
		decl->args.flen.max = decl->type->flen.max;
		if (decl->type->parse_args)
			return decl->type->parse_args(node, decl);
		break;

	case NI_DHCP_OPTION_KIND_ARRAY:
	case NI_DHCP_OPTION_KIND_STRUCT:
	default:
		break;
	}
	return TRUE;
}

static ni_dhcp_option_decl_t *
ni_dhcp_option_decl_parse_xml_member(ni_dhcp_option_decl_t **list, xml_node_t *node,
				const char *context, int depth)
{
	ni_stringbuf_t ctx = NI_STRINGBUF_INIT_DYNAMIC;
	ni_dhcp_option_decl_t *member;
	xml_node_t *nn;

	if (!(nn = xml_node_get_child(node, "name")) || ni_string_empty(nn->cdata)) {
		ni_warn("missed %s member name in declaration (%s)",
				context, xml_node_location(node));
		return FALSE;
	}

	ni_stringbuf_printf(&ctx, "%s.%s", context, nn->cdata);
	member = ni_dhcp_option_decl_parse_xml_type(list, node, nn->cdata, 0, ctx.string, depth - 1);
	ni_stringbuf_destroy(&ctx);
	return member;
}

static ni_bool_t
ni_dhcp_option_decl_parse_xml_members(ni_dhcp_option_decl_t **list, xml_node_t *node,
				const char *context, int depth)
{
	ni_dhcp_option_decl_t *member = NULL;
	ni_dhcp_option_decl_t *prev = NULL;
	xml_node_t *mn = NULL;

	while ((mn = xml_node_get_next_child(node, "member", mn))) {
		member = ni_dhcp_option_decl_parse_xml_member(list, mn, context, depth);
		if (!member)
			return FALSE;
		if (prev && !ni_dhcp_option_decl_fixed_length(prev)) {
			ni_warn("custom option %s member '%s' follows a variable-length member '%s' (%s)",
					context, member->name, prev->name, xml_node_location(node));
			return FALSE;
		}
		prev = member;
	}
	return member != NULL;
}

static ni_dhcp_option_decl_t *
ni_dhcp_option_decl_parse_xml_type(ni_dhcp_option_decl_t **list, xml_node_t *node,
				const char *name, unsigned int code,
				const char *context, int depth)
{
	ni_stringbuf_t ctx = NI_STRINGBUF_INIT_DYNAMIC;
	const ni_dhcp_option_type_t *type;
	ni_dhcp_option_decl_t *decl = NULL;
	xml_node_t *child;

	if (!list || !node || !context)
		return NULL;

	if (!depth) {
		ni_warn("maximal custom %s option definition depth reached (%s)",
				context, xml_node_location(node));
		return NULL;
	}

	if ((child = xml_node_get_child(node, "struct"))) {
		decl = ni_dhcp_option_decl_new(name, code, NI_DHCP_OPTION_KIND_STRUCT, NULL);
		if (!decl || !ni_dhcp_option_decl_parse_xml_members(&decl->member, child,
								context, depth))
			goto failure;
		if (!ni_dhcp_option_decl_parse_xml_args(child, decl)) {
			ni_warn("failed to parse %s.%s struct arguments (%s)",
					context, name, xml_node_location(node));
			goto failure;
		}
	} else
	if ((child = xml_node_get_child(node, "array"))) {
		decl = ni_dhcp_option_decl_new(name, code, NI_DHCP_OPTION_KIND_ARRAY, NULL);
		if (!decl || !ni_dhcp_option_decl_parse_xml_member(&decl->member, child,
								context, depth))
			goto failure;
		if (!ni_dhcp_option_decl_parse_xml_args(child, decl)) {
			ni_warn("failed to parse %s.%s array arguments (%s)",
					context, name, xml_node_location(node));
			goto failure;
		}
		if (!ni_dhcp_option_decl_fixed_length(decl)) {
			ni_warn("cannot define %s.%s array with variable-length element %s (%s)",
					context, name, decl->member->name,
					xml_node_location(node));
			goto failure;
		}
	} else
	if ((child = xml_node_get_child(node, "type"))) {
		type = ni_dhcp_option_type_find(child->cdata);
		if (!type) {
			ni_warn("invalid %s type '%s' in custom option declaration (%s)",
				context,
				ni_print_suspect(child->cdata, ni_string_len(child->cdata)),
				xml_node_location(node));
			goto failure;
		}
		decl = ni_dhcp_option_decl_new(name, code, NI_DHCP_OPTION_KIND_SCALAR, type);
		if (!ni_dhcp_option_decl_parse_xml_args(child, decl)) {
			ni_warn("failed to parse custom option %s %s type arguments (%s)",
					context, type->name, xml_node_location(node));
			goto failure;
		}
	} else {
		for (type = NULL, child = node->children; child; child = child->next) {
			if ((type = ni_dhcp_option_type_find(child->name)))
				break;
		}
		if (!type) {
			ni_warn("missed valid custom %s option type in declaration (%s)",
					context, xml_node_location(node));
			goto failure;
		}
		decl = ni_dhcp_option_decl_new(name, code, NI_DHCP_OPTION_KIND_SCALAR, type);
		if (!ni_dhcp_option_decl_parse_xml_args(child, decl)) {
			ni_warn("failed to parse custom option %s %s type arguments (%s)",
					context, type->name, xml_node_location(node));
			goto failure;
		}
	}

	if (ni_dhcp_option_decl_list_append(list, decl))
		return decl;

failure:
	ni_stringbuf_destroy(&ctx);
	ni_dhcp_option_decl_free(decl);
	return NULL;
}

ni_bool_t
ni_dhcp_option_decl_parse_xml(ni_dhcp_option_decl_t **list, xml_node_t *node,
				unsigned int code_min, unsigned int code_max,
				const char *context, int depth)
{
	ni_stringbuf_t ctx = NI_STRINGBUF_INIT_DYNAMIC;
	const ni_dhcp_option_decl_t *decl;
	const xml_node_t *child;
	unsigned int code;
	const char *name;

	if (!list || !node || !context)
		return FALSE;

	if (!depth) {
		ni_warn("maximal custom %s option definition depth reached (%s)",
				context, xml_node_location(node));
		return FALSE;
	}

	if (!(child = xml_node_get_child(node, "name"))) {
		ni_warn("missed custom %s option name in declaration (%s)",
			context, xml_node_location(node));
		return FALSE;
	}
	if (!ni_check_domain_name(child->cdata, ni_string_len(child->cdata), -1) ||
			strchr(child->cdata, '_')) {
		ni_warn("invalid name '%s' in custom %s option definition (%s)",
			ni_print_suspect(child->cdata, ni_string_len(child->cdata)),
			context, xml_node_location(node));
		return FALSE;
	}

	name = child->cdata;
	if ((decl = ni_dhcp_option_decl_list_find_by_name(*list, name))) {
		ni_warn("custom %s option name %s already exists with code %u (%s)",
			context, name, decl->code, xml_node_location(node));
		return FALSE;
	}

	if (!(child = xml_node_get_child(node, "code"))) {
		ni_warn("missed code in custom %s option %s definition (%s)",
			context, name, xml_node_location(node));
		return FALSE;
	}
	if (ni_parse_uint(child->cdata, &code, 10)) {
		ni_warn("invalid code %s in custom %s option %s definition (%s)",
			ni_print_suspect(child->cdata, ni_string_len(child->cdata)),
			context, name, xml_node_location(node));
		return FALSE;
	}
	if (code < code_min || code_max < code) {
		ni_warn("code %u in custom %s option %s definition is out of range %u..%u (%s)",
			code, context, name, code_min, code_max, xml_node_location(node));
		return FALSE;
	}
	if ((decl = ni_dhcp_option_decl_list_find_by_code(*list, code))) {
		ni_warn("custom %s option code %u already exists with name %s (%s)",
				context, code, decl->name, xml_node_location(node));
		return FALSE;
	}

	ni_stringbuf_printf(&ctx, "%s.%s", context, name);
	if ((decl = ni_dhcp_option_decl_parse_xml_type(list, node, name, code, ctx.string, depth))) {
		ni_debug_application("defined custom %s.%s as %s option type for code %u",
			context, name, decl->kind == NI_DHCP_OPTION_KIND_SCALAR ?
			ni_dhcp_option_type_name(decl->type) :
			ni_dhcp_option_kind_name(decl->kind), code);
		ni_stringbuf_destroy(&ctx);
		return TRUE;
	} else {
		ni_warn("failed to define %s.%s as custom option type for code %u (%s)",
			context, name, code, xml_node_location(node));
		ni_stringbuf_destroy(&ctx);
		return FALSE;
	}
}

/*
 * declared dhcp option to xml node
 */
static xml_node_t *
ni_dhcp_option_kind_to_xml(const ni_dhcp_option_t *, const ni_dhcp_option_decl_t *,
				ni_buffer_t *, xml_node_t *);

static xml_node_t *
ni_dhcp_option_scalar_to_xml(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, xml_node_t *parent)
{
	const ni_dhcp_option_type_t *type;
	xml_node_t *node = NULL;

	if (!decl || !(type = decl->type))
		goto failure;

	if (!(node = xml_node_new(decl->name, parent)))
		goto failure;

	if (!type->opt_to_str(decl, buf, &node->cdata))
		goto failure;

	return node;
failure:
	xml_node_free(node);
	return NULL;
}

static xml_node_t *
ni_dhcp_option_array_to_xml(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, xml_node_t *parent)
{
	const ni_dhcp_option_decl_t *member;
	xml_node_t *node = NULL;
	xml_node_t *child;
	size_t guard;

	if (!decl || !(member = decl->member))
		goto failure;

	if (!(node = xml_node_new(decl->name, parent)))
		goto failure;

	while ((guard = ni_buffer_count(buf))) {
		child = ni_dhcp_option_kind_to_xml(opt, member, buf, node);
		if (!child || guard <= ni_buffer_count(buf))
			goto failure;
	}

	return node;
failure:
	xml_node_free(node);
	return NULL;
}

static xml_node_t *
ni_dhcp_option_struct_to_xml(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, xml_node_t *parent)
{
	const ni_dhcp_option_decl_t *member;
	xml_node_t *node = NULL;
	xml_node_t *child;
	size_t guard;

	if (!decl || !decl->member)
		goto failure;

	if (!(node = xml_node_new(decl->name, parent)))
		goto failure;

	for (member = decl->member; member; member = member->next) {
		if (!(guard = ni_buffer_count(buf)) && member->next)
			goto failure;

		child = ni_dhcp_option_kind_to_xml(opt, member, buf, node);
		if (!child || (guard <= ni_buffer_count(buf) && member->next))
			goto failure;
	}

	return node;
failure:
	xml_node_free(node);
	return NULL;
}

static xml_node_t *
ni_dhcp_option_kind_to_xml(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, xml_node_t *parent)
{
	switch (decl->kind) {
	case NI_DHCP_OPTION_KIND_SCALAR:
		return ni_dhcp_option_scalar_to_xml(opt, decl, buf, parent);
	case NI_DHCP_OPTION_KIND_STRUCT:
		return ni_dhcp_option_struct_to_xml(opt, decl, buf, parent);
	case NI_DHCP_OPTION_KIND_ARRAY:
		return ni_dhcp_option_array_to_xml (opt, decl, buf, parent);
	default:
		return NULL;
	}
}

xml_node_t *
ni_dhcp_option_to_xml(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl)
{
	xml_node_t *node;
	ni_buffer_t buf;

	if (!decl || !opt || !opt->code)
		return NULL;

	ni_buffer_init_reader(&buf, opt->data, opt->len);
	node = ni_dhcp_option_kind_to_xml(opt, decl, &buf, NULL);
	ni_buffer_destroy(&buf);
	return node;
}

static ni_bool_t
ni_dhcp_option_kind_from_xml(const xml_node_t *, const ni_dhcp_option_decl_t *, ni_dhcp_option_t *);

static ni_bool_t
ni_dhcp_option_scalar_from_xml(const xml_node_t *node, const ni_dhcp_option_decl_t *decl,
				ni_dhcp_option_t *opt)
{
	const ni_dhcp_option_type_t *type;

	if (!decl || !(type = decl->type))
		goto failure;

	if (!type->str_to_opt(decl, node->cdata, opt))
		goto failure;

	return TRUE;
failure:
	return FALSE;
}

static ni_bool_t
ni_dhcp_option_array_from_xml(const xml_node_t *node, const ni_dhcp_option_decl_t *decl,
				ni_dhcp_option_t *opt)
{
	const ni_dhcp_option_decl_t *member;
	xml_node_t *mn = NULL;
	ni_bool_t ret = FALSE;

	if (!decl || !(member = decl->member) || !member->name)
		return ret;

	while ((mn = xml_node_get_next_child(node, member->name, mn))) {
		if (!(ret = ni_dhcp_option_kind_from_xml(mn, member, opt)))
			return FALSE;
	}
	return ret;
}

static ni_bool_t
ni_dhcp_option_struct_from_xml(const xml_node_t *node, const ni_dhcp_option_decl_t *decl,
				ni_dhcp_option_t *opt)
{
	const ni_dhcp_option_decl_t *member;
	xml_node_t *mn = NULL;
	ni_bool_t ret = FALSE;

	if (!decl || !decl->member)
		return ret;

	for (member = decl->member; member; member = member->next) {
		if (ni_string_empty(member->name))
			return FALSE;
		if (!(mn = xml_node_get_child(node, member->name)))
			return FALSE;
		if (!(ret = ni_dhcp_option_kind_from_xml(mn, member, opt)))
			return FALSE;
	}
	return ret;
}

static ni_bool_t
ni_dhcp_option_kind_from_xml(const xml_node_t *node, const ni_dhcp_option_decl_t *decl,
				ni_dhcp_option_t *opt)
{
	switch (decl->kind) {
	case NI_DHCP_OPTION_KIND_SCALAR:
		return ni_dhcp_option_scalar_from_xml(node, decl, opt);
	case NI_DHCP_OPTION_KIND_STRUCT:
		return ni_dhcp_option_struct_from_xml(node, decl, opt);
	case NI_DHCP_OPTION_KIND_ARRAY:
		return ni_dhcp_option_array_from_xml (node, decl, opt);
	default:
		return FALSE;
	}
}

ni_dhcp_option_t *
ni_dhcp_option_from_xml(const xml_node_t *node, const ni_dhcp_option_decl_t *decl)
{
	ni_dhcp_option_t *opt = NULL;

	if (!node || !decl)
		return NULL;

	if (!(opt = ni_dhcp_option_new(decl->code, 0, NULL)))
		goto failure;

	if (ni_dhcp_option_kind_from_xml(node, decl, opt))
		return opt;

failure:
	ni_dhcp_option_free(opt);
	return NULL;
}

/*
 * declared custom dhcp option to var array
 */
static ni_bool_t		ni_dhcp_option_kind_to_vars(const ni_dhcp_option_t *,
							const ni_dhcp_option_decl_t *,
							ni_buffer_t *, ni_var_array_t *,
							const char *, const char *);

static ni_bool_t
ni_dhcp_option_name_join(char **result, const char *prefix, const char *name, const char *suffix)
{
	if (!result || ni_string_empty(name))
		return FALSE;

	if (ni_string_empty(prefix)) {
		if (ni_string_empty(suffix))
			return ni_string_dup(result, name);
		else
			return ni_string_printf(result, "%s.%s", name, suffix) != NULL;
	} else {
		if (ni_string_empty(suffix))
			return ni_string_printf(result, "%s.%s", prefix, name) != NULL;
		else
			return ni_string_printf(result, "%s.%s.%s", prefix, name, suffix) != NULL;
	}
}

static ni_bool_t
ni_dhcp_option_scalar_to_vars(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, ni_var_array_t *vars,
				const char *prefix, const char *suffix)
{
	const ni_dhcp_option_type_t *type;
	char *name = NULL, *value = NULL;

	if (!decl || !(type = decl->type))
		return FALSE;

	if (!ni_dhcp_option_name_join(&name, prefix, decl->name, suffix))
		return FALSE;

	if (!type->opt_to_str(decl, buf, &value)) {
		ni_string_free(&name);
		ni_string_free(&value);
		return FALSE;
	} else {
		ni_var_array_set(vars, name, value);
		ni_string_free(&name);
		ni_string_free(&value);
		return TRUE;
	}
}

static ni_bool_t
ni_dhcp_option_struct_to_vars(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, ni_var_array_t *vars,
				const char *prefix, const char *suffix)
{
	const ni_dhcp_option_decl_t *member;
	char *name = NULL;
	size_t guard;

	if (!decl || !decl->member)
		return FALSE;

	if (!ni_dhcp_option_name_join(&name, prefix, decl->name, suffix))
		return FALSE;

	for (member = decl->member; member; member = member->next) {
		if (!(guard = ni_buffer_count(buf)) && member->next)
			goto failure;
		if (!ni_dhcp_option_kind_to_vars(opt, member, buf, vars, name, NULL))
			goto failure;
		if (guard <= ni_buffer_count(buf) && member->next)
			goto failure;
	}

	ni_string_free(&name);
	return TRUE;
failure:
	ni_string_free(&name);
	return FALSE;
}

static ni_bool_t
ni_dhcp_option_array_to_vars(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, ni_var_array_t *vars,
				const char *prefix, const char *suffix)
{
	const ni_dhcp_option_decl_t *member;
	unsigned int idx = 0;
	char *index = NULL;
	char *name = NULL;
	size_t guard;

	if (!decl || !(member = decl->member))
		return FALSE;

	while ((guard = ni_buffer_count(buf))) {
		if (!ni_string_dup(&index, ni_sprint_uint(idx++)) ||
		    !ni_dhcp_option_name_join(&name, prefix, decl->name, suffix) ||
		    !ni_dhcp_option_kind_to_vars(opt, member, buf, vars, name, index) ||
		    guard <= ni_buffer_count(buf)) {
			ni_string_free(&index);
			ni_string_free(&name);
			return FALSE;
		}
	}
	ni_string_free(&index);
	ni_string_free(&name);
	return TRUE;
}

static ni_bool_t
ni_dhcp_option_kind_to_vars(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl,
				ni_buffer_t *buf, ni_var_array_t *vars,
				const char *prefix, const char *suffix)
{
	switch (decl->kind) {
	case NI_DHCP_OPTION_KIND_SCALAR:
		return ni_dhcp_option_scalar_to_vars(opt, decl, buf, vars, prefix, suffix);
	case NI_DHCP_OPTION_KIND_STRUCT:
		return ni_dhcp_option_struct_to_vars(opt, decl, buf, vars, prefix, suffix);
	case NI_DHCP_OPTION_KIND_ARRAY:
		return ni_dhcp_option_array_to_vars (opt, decl, buf, vars, prefix, suffix);
	default:
		return FALSE;
	}
}

ni_var_array_t *
ni_dhcp_option_to_vars(const ni_dhcp_option_t *opt, const ni_dhcp_option_decl_t *decl)
{
	ni_var_array_t *vars;
	ni_buffer_t buf;

	if (!decl || !opt || !opt->code)
		return NULL;

	if (!(vars = ni_var_array_new()))
		return NULL;

	ni_buffer_init_reader(&buf, opt->data, opt->len);
	if (ni_dhcp_option_kind_to_vars(opt, decl, &buf, vars, NULL, NULL)) {
		ni_buffer_destroy(&buf);
		return vars;
	} else {
		ni_buffer_destroy(&buf);
		ni_var_array_free(vars);
		return NULL;
	}
}

/*
 * Utility functions
 */
ni_bool_t
ni_dhcp_domain_encode(ni_buffer_t *bp, const char *domain, ni_bool_t qualify)
{
	unsigned int dot = 0;
	const char *end;
	size_t tot, len;
	uint8_t cc;

	tot = ni_string_len(domain);
	if (!tot || tot > 254)
		return FALSE;

	while (domain && *domain) {
		end = strchr(domain, '.');
		if( end) {
			len = (size_t)(end - domain);
			tot -= len + 1;
			end++;
			dot++;
		} else {
			len = tot;
		}

		if (!len || len > 63)
			return FALSE;

		cc = len;
		if (ni_buffer_put(bp, &cc, 1) < 0)
			return FALSE;

		if (ni_buffer_put(bp, domain, len) < 0)
			return FALSE;

		domain = end;
	}

	if (domain || (qualify && dot)) {
		cc = 0;
		if (ni_buffer_put(bp, &cc, 1) < 0)
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_dhcp_domain_decode(ni_buffer_t *bp, char **domain)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	char label[64] = {'\0'};
	size_t len;

	while (ni_buffer_count(bp) && !bp->underflow) {
		if ((ssize_t)(len = ni_buffer_getc(bp)) == EOF) {
			bp->underflow = 1;
			goto failure;
		}

		if (len & 0xC0)
			goto failure;

		if (!ni_stringbuf_empty(&out))
			ni_stringbuf_putc(&out, '.');

		if (len == 0)
			break;

		if (ni_buffer_get(bp, label, len) < 0)
			goto failure;

		label[len] = '\0';
		ni_stringbuf_puts(&out, label);
	}

	if (ni_string_dup(domain, out.string)) {
		ni_stringbuf_destroy(&out);
		return TRUE;
	}

failure:
	ni_stringbuf_destroy(&out);
	return FALSE;
}

/*
 * DHCP fqdn option utilities
 */
static const ni_intmap_t	ni_dhcp_fqdn_update_mode_map[] = {
	{ "both",		NI_DHCP_FQDN_UPDATE_BOTH	},
	{ "none",		NI_DHCP_FQDN_UPDATE_NONE	},
	{ "ptr",		NI_DHCP_FQDN_UPDATE_PTR		},

	{ NULL,			-1U				}
};

const char *
ni_dhcp_fqdn_update_mode_to_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, ni_dhcp_fqdn_update_mode_map);
}

ni_bool_t
ni_dhcp_fqdn_update_name_to_mode(const char *name, unsigned int *mode)
{
	return ni_parse_uint_mapped(name, ni_dhcp_fqdn_update_mode_map, mode) == 0;
}

void
ni_dhcp_fqdn_init(ni_dhcp_fqdn_t *fqdn)
{
	if (fqdn) {
		fqdn->enabled = NI_TRISTATE_DEFAULT;
		fqdn->update  = NI_DHCP_FQDN_UPDATE_BOTH;
		fqdn->encode  = TRUE;
		fqdn->qualify = TRUE;
	}
}

ni_bool_t
ni_dhcp_check_user_class_id(const char *id, size_t len)
{
	const unsigned char *ptr = (const unsigned char *)id;

	if (!id || len == 0)
		return FALSE;

	for (; *ptr && len-- > 0; ++ptr) {
		switch (*ptr) {
		case '+':
		case '-':
		case '_':
		case '.':
		case ':':
		case '/':
			break;
		default:
			if (!isalnum(*ptr))
				return FALSE;
			break;
		}
	}
	return TRUE;
}

