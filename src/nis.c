/*
 *	NIS definitions for wicked
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2010-2021 SUSE LLC
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/nis.h>
#include <wicked/logging.h>
#include <stdlib.h>
#include <ctype.h>

static void	ni_nis_domain_array_append(ni_nis_domain_array_t *, ni_nis_domain_t *);
static void	ni_nis_domain_array_destroy(ni_nis_domain_array_t *);
static void	ni_nis_domain_free(ni_nis_domain_t *);

ni_nis_info_t *
ni_nis_parse_yp_conf(const char *filename)
{
	ni_nis_info_t *nis;
	char buffer[256];
	FILE *fp;

	ni_debug_readwrite("%s(%s)", __FUNCTION__, filename);
	if ((fp = fopen(filename, "r")) == NULL) {
		ni_error("cannot open %s: %m", filename);
		return NULL;
	}

	nis = ni_nis_info_new();
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *sp, *kwd, *argv[4];
		int argc = 0;

		buffer[strcspn(buffer, "#\r\n")] = '\0';
		for (sp = buffer; isspace(*sp); ++sp)
			;

		if (*sp == '\0')
			continue;

		sp = strtok(sp, " \t");
		while (sp && argc < 4) {
			argv[argc++] = sp;
			sp = strtok(NULL, " \t");
		}

		kwd = argv[0];
		if (!kwd)
			continue;

		if (!strcmp(kwd, "broadcast")) {
			nis->default_binding = NI_NISCONF_BROADCAST;
		} else if (!strcmp(kwd, "domain") && argc >= 3) {
			ni_nis_domain_t *dom;

			if (!(dom = ni_nis_domain_find(nis, argv[1])))
				dom = ni_nis_domain_new(nis, argv[1]);
			if (!strcmp(argv[2], "broadcast"))
				dom->binding = NI_NISCONF_BROADCAST;
			else if (!strcmp(argv[2], "slp"))
				dom->binding = NI_NISCONF_SLP;
			else if (!strcmp(argv[2], "server") && argc == 4)
				ni_string_array_append(&dom->servers, argv[3]);
		} else if (!strcmp(kwd, "ypserver") && argc == 2) {
			ni_string_array_append(&nis->default_servers, argv[1]);
		} else {
			ni_warn("%s: ignoring unknown keyword \"%s\"", filename, kwd);
		}
	}
	fclose(fp);

	return nis;
}

int
ni_nis_write_yp_conf(const char *filename, const ni_nis_info_t *nis, const char *header)
{
	FILE *fp;
	unsigned int i, j;

	if (nis->default_binding != NI_NISCONF_STATIC
	 && nis->default_binding != NI_NISCONF_BROADCAST) {
		ni_error("cannot write %s: unsupported binding mode %s",
				filename,
				ni_nis_binding_type_to_name(nis->default_binding));
		return -1;
	}

	if ((fp = fopen(filename, "w")) == NULL) {
		ni_error("cannot open %s: %m", filename);
		return -1;
	}

	if (header)
		fprintf(fp, "%s\n", header);

	if (nis->default_binding == NI_NISCONF_BROADCAST)
		fprintf(fp, "broadcast\n");

	for (i = 0; i < nis->domains.count; ++i) {
		ni_nis_domain_t *dom = nis->domains.data[i];
		unsigned int j;

		if (dom->binding == NI_NISCONF_BROADCAST)
			fprintf(fp, "domain %s broadcast\n", dom->domainname);
		if (dom->binding == NI_NISCONF_SLP)
			fprintf(fp, "domain %s slp\n", dom->domainname);
		for (j = 0; j < dom->servers.count; ++j)
			fprintf(fp, "domain %s server %s\n", dom->domainname, dom->servers.data[j]);
	}

	for (j = 0; j < nis->default_servers.count; ++j)
		fprintf(fp, "ypserver %s\n", nis->default_servers.data[j]);

	fclose(fp);
	return 0;
}


ni_nis_info_t *
ni_nis_info_new(void)
{
	return calloc(1, sizeof(ni_nis_info_t));
}

void
ni_nis_info_free(ni_nis_info_t *nis)
{
	ni_string_free(&nis->domainname);
	ni_string_array_destroy(&nis->default_servers);
	ni_nis_domain_array_destroy(&nis->domains);
}

ni_nis_domain_t *
ni_nis_domain_find(const ni_nis_info_t *nis, const char *domainname)
{
	unsigned int i;

	for (i = 0; i < nis->domains.count; ++i) {
		ni_nis_domain_t *dom = nis->domains.data[i];

		if (!strcasecmp(dom->domainname, domainname))
			return dom;
	}

	return NULL;
}

ni_nis_domain_t *
ni_nis_domain_new(ni_nis_info_t *nis, const char *domainname)
{
	ni_nis_domain_t *dom;

	dom = calloc(1, sizeof(*dom));
	if (dom) {
		ni_string_dup(&dom->domainname, domainname);
		dom->binding = NI_NISCONF_STATIC;

		ni_nis_domain_array_append(&nis->domains, dom);
	}
	return dom;
}

void
ni_nis_domain_free(ni_nis_domain_t *dom)
{
	ni_string_free(&dom->domainname);
	ni_string_array_destroy(&dom->servers);
}

void
ni_nis_domain_array_append(ni_nis_domain_array_t *nda, ni_nis_domain_t *dom)
{
	nda->data = realloc(nda->data, (nda->count + 1) * sizeof(dom));
	nda->data[nda->count++] = dom;
}

void
ni_nis_domain_array_destroy(ni_nis_domain_array_t *nda)
{
	unsigned int i;

	for (i = 0; i < nda->count; ++i)
		ni_nis_domain_free(nda->data[i]);
	free(nda->data);
	memset(nda, 0, sizeof(*nda));
}

/*
 * Map NIS binding modes to names and vice versa
 */
static ni_intmap_t	__nis_bindings[] = {
	{ "static",	NI_NISCONF_STATIC	},
	{ "broadcast",	NI_NISCONF_BROADCAST	},
	{ "slp",	NI_NISCONF_SLP		},

	{ NULL }
};

ni_nis_binding_t
ni_nis_binding_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __nis_bindings, &value) < 0)
		return -1;
	return value;
}

const char *
ni_nis_binding_type_to_name(ni_nis_binding_t mode)
{
	return ni_format_uint_mapped(mode, __nis_bindings);
}
