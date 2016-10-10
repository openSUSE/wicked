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
#include <netinet/in.h>

#include <wicked/util.h>
#include <wicked/address.h>
#include "dhcp.h"


/*
 * Generic dhcp options
 */
ni_dhcp_option_t *
ni_dhcp_option_new(unsigned int code, unsigned int len, unsigned char *data)
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
ni_dhcp_option_append(ni_dhcp_option_t *opt, unsigned int len, unsigned char *data)
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

