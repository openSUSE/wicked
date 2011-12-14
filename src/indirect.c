/*
 * Routines for accessing interface state through the wicked server
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>

#include <wicked/xml.h>
#include <wicked/wicked.h>
#include "netinfo_priv.h"
#include "config.h"

#define XML_ERR_PTR	((xml_node_t *) -1)
#define XML_IS_ERR(p)	((p) == XML_ERR_PTR)

static void    __ni_indirect_close(ni_handle_t *nih);

static struct ni_ops ni_indirect_ops = {
	.close			= __ni_indirect_close,
};

typedef struct ni_indirect {
	ni_handle_t		base;
	char *			namespace;
	char *			root_dir;
} ni_indirect_t;

static inline ni_indirect_t *
__to_indirect(ni_handle_t *nih)
{
	assert(nih->op == &ni_indirect_ops);
	return (ni_indirect_t *) nih;
}

ni_handle_t *
ni_indirect_open(const char *basepath)
{
	ni_indirect_t *nih;

	if (!basepath)
		return NULL;

	nih = (ni_indirect_t *) __ni_handle_new(sizeof(*nih), &ni_indirect_ops);
	ni_string_dup(&nih->namespace, basepath);

	return &nih->base;
}

void
ni_indirect_set_root(ni_handle_t *nih, const char *root_dir)
{
	ni_indirect_t *nid = __to_indirect(nih);

	ni_string_dup(&nid->root_dir, root_dir);
}

static void
__ni_indirect_close(ni_handle_t *nih)
{
	ni_indirect_t *nid = __to_indirect(nih);

	ni_string_free(&nid->namespace);
	ni_string_free(&nid->root_dir);
}
