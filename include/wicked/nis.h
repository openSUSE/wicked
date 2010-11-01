/*
 * NIS definitions for wicked
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_NIS_H__
#define __WICKED_NIS_H__

#include <wicked/util.h>

#define _PATH_YP_CONF		"/etc/yp.conf"

typedef enum nis_nis_binding {
	NI_NISCONF_STATIC,
	NI_NISCONF_BROADCAST,
	NI_NISCONF_SLP,
} nis_nis_binding_t;

typedef struct ni_nis_domain {
	char *			domainname;
	nis_nis_binding_t	binding;		/* static, broadcast, slp */
	ni_string_array_t	servers;
} ni_nis_domain_t;

typedef struct ni_nis_domain_array {
	unsigned int		count;
	ni_nis_domain_t **	data;
} ni_nis_domain_array_t;

struct ni_nis_info {
	char *			domainname;
	nis_nis_binding_t	default_binding;	/* static, broadcast, slp */
	ni_string_array_t	default_servers;

	ni_nis_domain_array_t	domains;
};

extern ni_nis_info_t *		ni_nis_info_new(void);
extern void			ni_nis_info_free(ni_nis_info_t *);
extern ni_nis_domain_t *	ni_nis_domain_find(const ni_nis_info_t *, const char *);
extern ni_nis_domain_t *	ni_nis_domain_new(ni_nis_info_t *, const char *);
extern nis_nis_binding_t	ni_nis_binding_name_to_type(const char *);
extern const char *		ni_nis_binding_type_to_name(nis_nis_binding_t);

extern ni_nis_info_t *		ni_nis_parse_yp_conf(const char *);
extern int			ni_nis_write_yp_conf(const char *, const ni_nis_info_t *, const char *);

#endif /* __WICKED_NIS_H__ */
