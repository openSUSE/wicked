/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/logging.h>
#include "wicked-client.h"
#include "fsm.h"

int
do_zookeeper(int argc, char **argv)
{
	enum { OPT_FOREGROUND };
	static struct option options[] = {
		{ "foreground",	no_argument,		 NULL,	OPT_FOREGROUND },
		{ NULL }
	};
	ni_objectmodel_fsm_t *fsm;
	int opt_foreground = 0;
	int c;

	fsm = ni_objectmodel_fsm_new();

	optind = 1;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] zookeeper [zookeeper-options]\n"
				"\nSupported zookeeper-options:\n"
				"  --foreground\n"
				"      Run zookeeper in the foreground rather than as a daemon\n"
				);
			return 1;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Too many arguments\n");
		goto usage;
	}

	if (!ni_ifworkers_create_client(fsm))
		return 1;

	ni_ifworkers_refresh_state(fsm);

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	ni_ifworkers_kickstart(fsm);
	if (ni_ifworker_fsm(fsm) != 0)
		ni_ifworker_mainloop(fsm);

	return 1;
}

