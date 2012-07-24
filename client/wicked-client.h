/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

#include <wicked/client.h>

extern const char *		program_name;
extern int			opt_global_dryrun;
extern char *			opt_global_rootdir;
extern int			opt_global_progressmeter;

extern int			do_ifup(int argc, char **argv);
extern int			do_ifdown(int argc, char **argv);

/* We may want to move this into the library. */
extern int			ni_resolve_hostname_timed(const char *, int, ni_sockaddr_t *, unsigned int);
extern int			ni_host_is_reachable(const char *, const ni_sockaddr_t *);

#endif /* WICKED_CLIENT_H */
