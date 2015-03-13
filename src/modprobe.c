/*
 * Helper to call modprobe
 *
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include "process.h"
#include "modprobe.h"

int
ni_modprobe(const char *options, const char *module, const char *moptions)
{
	ni_string_array_t argv;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(options) || ni_string_empty(module))
		return -1;

	ni_string_array_init(&argv);
	if (ni_string_array_append(&argv, NI_MODPROBE_BIN) < 0 ||
	    ni_string_array_append(&argv, options) < 0 ||
	    ni_string_array_append(&argv, "--") < 0 ||
	    ni_string_array_append(&argv, module) < 0 ||
	    (!ni_string_empty(moptions) && ni_string_split(&argv, moptions, " \t", 0) == 0)) {
		ni_string_array_destroy(&argv);
		return -1;
	}

	if ((cmd = ni_shellcmd_new(&argv)) == NULL) {
		ni_string_array_destroy(&argv);
		return -1;
	}
	ni_string_array_destroy(&argv);

	if ((pi = ni_process_new(cmd)) == NULL) {
		ni_shellcmd_release(cmd);
		return -1;
	}
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	return rv;
}

