/*
 * Handling ppp interface information.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/ppp.h>
#include "netinfo_priv.h"

#define NI_PPPDEV_TAG	"pppdev"

static ni_bool_t	__ni_ppp_tag_to_index(const char *, unsigned int *);
static const char *	__ni_ppp_path(const char *tag, const char *file);

ni_ppp_t *
ni_ppp_new(const char *tag)
{
	static unsigned int next_index;
	char tagbuf[64];
	ni_ppp_t *ppp;

	if (tag != NULL) {
		unsigned int index;

		if (!__ni_ppp_tag_to_index(tag, &index))
			return NULL;
		if (index >= next_index)
			next_index = index + 1;
	} else {
		snprintf(tagbuf, sizeof(tagbuf), NI_PPPDEV_TAG "%u", next_index++);
		tag = tagbuf;
	}


	ppp = xcalloc(1, sizeof(*ppp));

	ni_string_dup(&ppp->ident, tag);
	ppp->unit = -1;
	ppp->devfd = -1;
	return ppp;
}

void
ni_ppp_close(ni_ppp_t *ppp)
{
	if (ppp->devfd >= 0)
		close(ppp->devfd);
	ppp->unit = -1;
	ppp->devfd = -1;
}

int
ni_ppp_mkdir(ni_ppp_t *ppp)
{
	if (ppp->dirpath == NULL) {
		const char *path;

		path = __ni_ppp_path(ppp->ident, NULL);
		if (mkdir(path, 0700) < 0) {
			ni_error("unable to create directory %s: %m", path);
			return -1;
		}

		ni_string_dup(&ppp->dirpath, path);
	}
	return 0;
}

void
ni_ppp_free(ni_ppp_t *ppp)
{
	ni_ppp_close(ppp);

	if (ppp->dirpath)
		ni_file_remove_recursively(ppp->dirpath);

	ni_string_free(&ppp->ident);
	ni_string_free(&ppp->dirpath);
	free(ppp);
}

/*
 * Given a tag like "pppdev0", return the path name of the config file, pid file,
 * or of the directory itself.
 * FIXME: share this code with openvpn
 */
static const char *
__ni_ppp_path(const char *tag, const char *filename)
{
	static char pathbuf[PATH_MAX];

	if (filename)
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s/%s", CONFIG_WICKED_STATEDIR, tag, filename);
	else
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", CONFIG_WICKED_STATEDIR, tag);
	return pathbuf;
}

/*
 * Given a tag like "pppdev0", extract the index.
 */
static ni_bool_t
__ni_ppp_tag_to_index(const char *tag, unsigned int *indexp)
{
	static const unsigned int prefixlen = sizeof(NI_PPPDEV_TAG) - 1;

	if (strncmp(tag, NI_PPPDEV_TAG, prefixlen))
		return FALSE;
	return ni_parse_int(tag + prefixlen, indexp) >= 0;
}
