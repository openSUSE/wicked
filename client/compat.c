/*
 * Compat functions for parsing traditional config file formats
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/logging.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include "wicked-client.h"

ni_bool_t
__ni_compat_get_interfaces(const char *format, const char *path, xml_document_t *doc)
{
	if (format == NULL) {
		/* Guess what system we're on */
		if (ni_file_exists("/etc/SuSE-release"))
			format = "suse";
		else
		if (ni_file_exists("/etc/redhat-release"))
			format = "redhat";
		else
			ni_fatal("Cannot determine what file format to read");
	}

	if (ni_string_eq(format, "suse"))
		return __ni_suse_get_interfaces(path, doc);

	/* TBD: add support for more formats */

	ni_fatal("Unsupported configuration file format %s", format);
}
