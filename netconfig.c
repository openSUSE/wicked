/*
 * Routines for loading and storing all network configuration
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include "netinfo_priv.h"
#include "sysconfig.h"
#include "config.h"

static int	__ni_config_refresh(ni_handle_t *nih);
static void	__ni_config_close(ni_handle_t *nih);

static struct ni_ops ni_config_ops = {
	.refresh	= __ni_config_refresh,
	.close		= __ni_config_close,
};

ni_handle_t *
ni_netconfig_open(ni_syntax_t *syntax)
{
	ni_handle_t *nih;

	nih = __ni_handle_new(&ni_config_ops);
	if (nih)
		nih->default_syntax = syntax;

	return nih;
}

static void
__ni_config_close(ni_handle_t *nih)
{
	if (nih->default_syntax)
		ni_syntax_free(nih->default_syntax);
}

static int
__ni_config_refresh(ni_handle_t *nih)
{
	if (nih->default_syntax == NULL) {
		error("__ni_config_refresh: no syntax object associated");
		return -1;
	}
	return ni_syntax_parse_all(nih->default_syntax, nih);
}
