/*
 *	Simple XPATH-style expression evaluation
 *
 *	Copyright (C) 2010  Olaf Kirch <okir@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __WICKED_XPATH_H__
#define __WICKED_XPATH_H__

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <wicked/types.h>
#include <wicked/xml.h>

typedef enum xpath_node_type {
	XPATH_VOID = 0,
	XPATH_ELEMENT,
	XPATH_STRING,
	XPATH_BOOLEAN,
	XPATH_INTEGER,
	XPATH_ANY,

	__XPATH_NODE_TYPE_MAX
} xpath_node_type_t;

typedef long		xpath_integer_t;

typedef struct xpath_node {
	xpath_node_type_t	type;
	union {
		xml_node_t *	node;
		char *		string;
		xpath_integer_t	integer;
		char		boolean;
	} value;
} xpath_node_t;

typedef struct xpath_result {
	unsigned int		users;
	xpath_node_type_t	type;
	unsigned int		count;
	xpath_node_t *		node;
} xpath_result_t;

extern xpath_enode_t *	xpath_expression_parse(const char *);
extern void		xpath_expression_free(xpath_enode_t *);
extern xpath_result_t *	xpath_expression_eval(const xpath_enode_t *, xml_node_t *);

extern xpath_format_t *	xpath_format_parse(const char *);
extern int		xpath_format_eval(xpath_format_t *, xml_node_t *, ni_string_array_t *);
extern void		xpath_format_free(xpath_format_t *);
extern void		xpath_format_array_init(xpath_format_array_t *);
extern void		xpath_format_array_append(xpath_format_array_t *, xpath_format_t *);
extern void		xpath_format_array_destroy(xpath_format_array_t *);

extern xpath_result_t *	xpath_result_new(xpath_node_type_t);
extern xpath_result_t *	xpath_result_dup(xpath_result_t *);
extern xpath_result_t *	xpath_result_to_strings(xpath_result_t *);
extern void		xpath_result_append_element(xpath_result_t *, xml_node_t *);
extern void		xpath_result_append_string(xpath_result_t *, const char *);
extern void		xpath_result_append_integer(xpath_result_t *, xpath_integer_t);
extern void		xpath_result_append_boolean(xpath_result_t *, int);
extern void		xpath_result_print(const xpath_result_t *, FILE *);
extern void		xpath_result_free(xpath_result_t *);

extern const char *	xpath_node_type_name(xpath_node_type_t);

/*
 * Build normalized boolean result
 */
static inline xpath_result_t *
__xpath_build_boolean(int bv)
{
	xpath_result_t *result;

	result = xpath_result_new(XPATH_BOOLEAN);
	if (bv)
		xpath_result_append_boolean(result, bv);
	return result;
}

/*
 * Other helper functions for building xpath_result_t's
 */
static inline xpath_result_t *
__xpath_build_string(const char *value)
{
	xpath_result_t *result = NULL;

	if (value) {
		result = xpath_result_new(XPATH_STRING);
		xpath_result_append_string(result, value);
	}
	return result;
}

static inline xpath_result_t *
__xpath_build_integer(xpath_integer_t value)
{
	xpath_result_t *result;

	result = xpath_result_new(XPATH_INTEGER);
	xpath_result_append_integer(result, value);
	return result;
}


/*
 * Test normalized boolean result
 */
static inline int
__xpath_test_boolean(const xpath_result_t *in)
{
	if (in->count == 0)
		return 0;
	if (in->count == 1) {
		assert(in->node[0].type == XPATH_BOOLEAN);
		assert(in->node[0].value.boolean);
		return 1;
	}

	/* Non-normalized boolean result - should not happen */
	assert(0);
}


#endif /* __WICKED_XPATH_H__ */
