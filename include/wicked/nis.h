/*
 *	NIS definitions for wicked
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2010-2022 SUSE LLC
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
 *		Olaf Kirch
 *		Marius Tomaschewski
 */

#ifndef NI_WICKED_NIS_H
#define NI_WICKED_NIS_H

#include <wicked/util.h>

#define NI_PATH_YP_CONF		"/etc/yp.conf"

typedef enum ni_nis_binding {
	NI_NISCONF_STATIC,
	NI_NISCONF_BROADCAST,
	NI_NISCONF_SLP,
} ni_nis_binding_t;

typedef struct ni_nis_domain {
	char *			domainname;
	ni_nis_binding_t	binding;		/* static, broadcast, slp */
	ni_string_array_t	servers;
} ni_nis_domain_t;

typedef struct ni_nis_domain_array {
	unsigned int		count;
	ni_nis_domain_t **	data;
} ni_nis_domain_array_t;

struct ni_nis_info {
	char *			domainname;
	ni_nis_binding_t	default_binding;	/* static, broadcast, slp */
	ni_string_array_t	default_servers;

	ni_nis_domain_array_t	domains;
};

extern ni_nis_info_t *		ni_nis_info_new(void);
extern ni_nis_info_t *		ni_nis_info_clone(const ni_nis_info_t *);
extern void			ni_nis_info_free(ni_nis_info_t *);
extern ni_nis_domain_t *	ni_nis_domain_find(const ni_nis_info_t *, const char *);
extern ni_nis_domain_t *	ni_nis_domain_new(ni_nis_info_t *, const char *);
extern ni_nis_binding_t		ni_nis_binding_name_to_type(const char *);
extern const char *		ni_nis_binding_type_to_name(ni_nis_binding_t);

extern ni_nis_info_t *		ni_nis_parse_yp_conf(const char *);
extern int			ni_nis_write_yp_conf(const char *, const ni_nis_info_t *, const char *);

#endif /* NI_WICKED_NIS_H */
