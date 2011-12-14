/*
 * Private header file for system config backends.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BACKEND_PRIV_H__
#define __WICKED_BACKEND_PRIV_H__

#include <stdio.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

#include "netinfo_priv.h"	/* for now */

struct ni_backend {
	ni_syntax_t *		syntax;

	ni_interface_t *	interfaces;
};


#endif /* __WICKED_BACKEND_PRIV_H__ */
