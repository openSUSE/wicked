/*
 * Resolver functions for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/resolver.h>
#include <wicked/logging.h>
#include <stdlib.h>
#include <ctype.h>

ni_resolver_info_t *
ni_resolver_parse_resolv_conf(const char *filename)
{
	ni_resolver_info_t *resolv;
	char buffer[256];
	FILE *fp;

	ni_debug_readwrite("%s(%s)", __FUNCTION__, filename);
	if ((fp = fopen(filename, "r")) == NULL) {
		ni_error("cannot open %s: %m", filename);
		return NULL;
	}

	resolv = ni_resolver_info_new();
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *sp, *kwd, *value;

		buffer[strcspn(buffer, "#\r\n")] = '\0';
		for (sp = buffer; isspace(*sp); ++sp)
			;

		if (*sp == '\0')
			continue;

		kwd = strtok(sp, " \t");
		if (!kwd)
			continue;
		value = strtok(NULL, " \t");

		if (!strcmp(kwd, "domain")) {
			ni_string_dup(&resolv->default_domain, value);
		} else if (!strcmp(kwd, "nameserver")) {
			if (value)
				ni_string_array_append(&resolv->dns_servers, value);
		} else if (!strcmp(kwd, "search")) {
			ni_string_array_destroy(&resolv->dns_search);

			if (value) {
				do {
					ni_string_array_append(&resolv->dns_search, value);
				} while ((value = strtok(NULL, " \t")) != NULL);
			}
		} else {
			ni_warn("%s: ignoring unknown keyword \"%s\"", filename, kwd);
		}
	}
	fclose(fp);

	return resolv;
}

int
ni_resolver_write_resolv_conf(const char *filename, const ni_resolver_info_t *resolv, const char *header)
{
	FILE *fp;
	unsigned int i;

	ni_debug_readwrite("Writing resolver info to %s", filename);
	if ((fp = fopen(filename, "w")) == NULL) {
		ni_error("cannot open %s: %m", filename);
		return -1;
	}

	if (header)
		fprintf(fp, "%s\n", header);

	if (resolv->default_domain)
		fprintf(fp, "domain %s\n", resolv->default_domain);

	for (i = 0; i < resolv->dns_servers.count; ++i)
		fprintf(fp, "nameserver %s\n", resolv->dns_servers.data[i]);

	if (resolv->dns_search.count) {
		fprintf(fp, "search");
		for (i = 0; i < resolv->dns_search.count; ++i)
			fprintf(fp, " %s", resolv->dns_search.data[i]);
		fprintf(fp, "\n");
	}

	fclose(fp);
	return 0;
}


ni_resolver_info_t *
ni_resolver_info_new(void)
{
	return calloc(1, sizeof(ni_resolver_info_t));
}

void
ni_resolver_info_free(ni_resolver_info_t *resolv)
{
	ni_string_free(&resolv->default_domain);
	ni_string_array_destroy(&resolv->dns_search);
	ni_string_array_destroy(&resolv->dns_servers);
}
