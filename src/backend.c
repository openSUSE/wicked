#include <stdlib.h>
#include <dirent.h>
#include <wicked/backend.h>
#include "backend-priv.h"
#include "config.h"

#define _PATH_HOSTNAME	"/etc/HOSTNAME"

#if 0

/*
 * Build path relative to root directory, if one is given. Otherwise,
 * just return pathname as-is.
 */
static const char *
__ni_backend_build_path(ni_backend_t *be, const char *path)
{
	ni_fatal("%s: not implemented right now", __func__);
}

/*
 * Read/write /etc/HOSTNAME
 * We should allow runtime configuration to change the location of the
 * file, and to specify an "updater" script that can be called to rewrite
 * other depedencies (eg if we have a special entry in the hosts file,
 * or httpd.conf, or whatever)
 */
const char *
ni_backend_hostname_get(ni_backend_t *be, char *buffer, size_t size)
{
	int rv = 0;

	if (syntax->get_hostname) {
		rv = syntax->get_hostname(syntax, buffer, size);
		if (rv < 0) {
			ni_error("Cannot read hostname: %s", ni_strerror(rv));
			return NULL;
		}
	} else {
		const char *path;
		FILE *fp;

		path = __ni_backend_build_path(be, _PATH_HOSTNAME);
		if ((fp = fopen(path, "r")) == NULL) {
			ni_error("cannot open %s: %m", path);
			return NULL;
		}

		if (fgets(buffer, size, fp) == NULL) {
			fclose(fp);
			return NULL;
		}
		/* strip off trailing newline */
		buffer[strcspn(buffer, "\r\n")] = '\0';
		fclose(fp);
	}

	return buffer;
}

int
ni_backend_hostname_put(ni_backend_t *be, const char *hostname)
{
	ni_syntax_t *syntax = be->syntax;

	if (syntax->put_hostname) {
		if (syntax->put_hostname(syntax, hostname) < 0)
			return -1;
	} else {
		const char *path;
		FILE *fp;

		path = __ni_backend_build_path(be, _PATH_HOSTNAME);
		if ((fp = fopen(path, "w")) == NULL) {
			ni_error("cannot open %s: %m", path);
			return -1;
		}
		fprintf(fp, "%s\n", hostname);
		fclose(fp);
	}

	return 0;
}
#endif
