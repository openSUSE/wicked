/*
 *	Simple format strings using XPATH expressions.
 *
 *	Copyright (C) 2010-2012  Olaf Kirch <okir@suse.de>
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write 
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 *	Boston, MA 02110-1301 USA.
 *
 *
 * xpath format strings are supposed to be used by shell script that need to
 * extract individual values from an XML configuration file, without having to
 * have code a huge amount of XML or (beware) XSLT.
 *
 * To use this stuff, consider a netcf interface description netcf.xml.
 * To display all IP addresses with their corresponding prefixes, you would
 * run
 *
 *	wicked xpath --file netcf.xml --reference //protocol/ip '%{@address}/%{@prefix}'
 *
 * The "--reference" argument does a look up of a set of nodes; specifically,
 * this looks up all <ip> elements that occur inside a <protocol> element
 * anywhere in the file. Then it retrieves attributes address and prefix for
 * each of these, and displays them separated by a slash.
 *
 * Alternatively, you could do things like
 *
 *	wicked xpath --file netcf.xml --reference "//protocol[@family = 'ipv4']" '%{dhcp/set-hostname or false}'
 *
 * The "--reference" argument will look up the <protocol> element with a "family"
 * attribute of "ipv4", and then expand the format string.
 *
 * The "dhcp/" term looks up any <dhcp> element inside the <protocol> node.
 * The "or false" clause will turn what is an XML element into a boolean value (empty list
 * means false, non-empty means true), which will then be printed as either "true" or "false"
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/xml.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>


typedef struct xpath_fnode {
	ni_stringbuf_t		before;
	ni_stringbuf_t		expression;
	xpath_enode_t *		enode;
	xpath_result_t *	result;

	unsigned int		optional : 1;
} xpath_fnode_t;

struct xpath_format {
	unsigned int		count;
	xpath_fnode_t *		node;
};

static xpath_format_t *	xpath_format_new(void);
static xpath_fnode_t *	xpath_format_extend(xpath_format_t *);

xpath_format_t *
xpath_format_parse(const char *format)
{
	xpath_format_t *pieces;
	xpath_fnode_t *cur = NULL;
	const char *sf;

	pieces = xpath_format_new();
	for (sf = format; *sf; ) {
		char cc = *sf++;

		if (cur == NULL)
			cur = xpath_format_extend(pieces);

		if (cc != '%') {
			ni_stringbuf_putc(&cur->before, cc);
			continue;
		}

		cc = *sf++;
		switch (cc) {
		case '%':
			ni_stringbuf_putc(&cur->before, cc);
			continue;

		case '{':
			while (1) {
				cc = *sf++;
				if (!cc) {
					ni_error("xpath: bad format string, unclosed %%{...} format");
					goto failed;
				}
				if (cc == '}')
					break;
				ni_stringbuf_putc(&cur->expression, cc);
			}

			if (ni_stringbuf_empty(&cur->expression)) {
				ni_error("xpath: empty %%{} in format string");
				goto failed;
			} else {
				const char *expression = cur->expression.string;

				if (expression[0] == '?') {
					cur->optional = 1;
					expression++;
				}
				cur->enode = xpath_expression_parse(expression);
				if (!cur->enode)
					goto failed;

				cur = NULL;
			}
			break;

		default:
			/* '%' followed by unknown char: copy as is */
			ni_stringbuf_putc(&cur->before, '%');
			ni_stringbuf_putc(&cur->before, cc);
			break;
		}
	}

	return pieces;

failed:
	xpath_format_free(pieces);
	return NULL;
}

/*
 * Evaluate a format string containing XPATH expressions
 */
int
xpath_format_eval(xpath_format_t *pieces, xml_node_t *xn, ni_string_array_t *result)
{
	ni_stringbuf_t formatted;
	const xpath_fnode_t *max_node = NULL;
	unsigned int num_expansions = -1;
	unsigned int m, n;

	ni_stringbuf_init(&formatted);

	for (m = 0; m < pieces->count; ++m) {
		xpath_fnode_t *fnode = &pieces->node[m];

		if (fnode->result) {
			xpath_result_free(fnode->result);
			fnode->result = NULL;
		}

		if (fnode->enode) {
			xpath_result_t *result;

			fnode->result = result = xpath_expression_eval(fnode->enode, xn);
			if (!result) {
				ni_error("xpathfmt: error evaluation expression \"%s\"",
						fnode->expression.string);
				return 0;
			}

			fnode->result = xpath_result_to_strings(result);
			xpath_result_free(result);

			if (max_node == NULL) {
				num_expansions = fnode->result->count;
				max_node = fnode;
			} else
			if (num_expansions < fnode->result->count) {
				if (max_node->optional)
					max_node = fnode;
			} else
			if (num_expansions > fnode->result->count) {
				if (!fnode->optional) {
					ni_error("xpathfmt: problem evaluating expression \"%s\" - "
						 "inconsistent item count",
						 fnode->expression.string);
					return 0;
				}
			}
		}
	}

	if (num_expansions == -1U)
		num_expansions = 1;

	for (n = 0; n < num_expansions; ++n) {
		for (m = 0; m < pieces->count; ++m) {
			xpath_fnode_t *fnode = &pieces->node[m];

			if (!ni_stringbuf_empty(&fnode->before))
				ni_stringbuf_puts(&formatted, fnode->before.string);
			if (fnode->result && n < fnode->result->count)
				ni_stringbuf_puts(&formatted, fnode->result->node[n].value.string);
		}

		/* FIXME: avoid extraneous strdup here? */
		ni_string_array_append(result, formatted.string ?: "");
		ni_stringbuf_destroy(&formatted);
	}

	return 1;
}

xpath_format_t *
xpath_format_new(void)
{
	return calloc(1, sizeof(xpath_format_t));
}

void
xpath_format_free(xpath_format_t *na)
{
	xpath_fnode_t *fnp;
	unsigned int n;

	for (n = 0, fnp = na->node; n < na->count; ++n, ++fnp) {
		ni_stringbuf_destroy(&fnp->before);
		ni_stringbuf_destroy(&fnp->expression);
		if (fnp->enode)
			xpath_expression_free(fnp->enode);
		if (fnp->result)
			xpath_result_free(fnp->result);
	}
	free(na->node);
	free(na);
}

xpath_fnode_t *
xpath_format_extend(xpath_format_t *na)
{
	xpath_fnode_t *fnp;

	if ((na->count % 4) == 0) {
		na->node = realloc(na->node, (na->count + 4) * sizeof(xpath_fnode_t));
		assert(na->node);
	}
	fnp = &na->node[na->count++];
	memset(fnp, 0, sizeof(*fnp));
	ni_stringbuf_init(&fnp->before);
	ni_stringbuf_init(&fnp->expression);

	return fnp;
}

/*
 * Handle array of xpath formats.
 */
void
xpath_format_array_init(xpath_format_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
xpath_format_array_append(xpath_format_array_t *array, xpath_format_t *fmt)
{
	if ((array->count % 4) == 0) {
		array->data = realloc(array->data, (array->count + 4) * sizeof(array->data[0]));
		assert(array->data);
	}
	array->data[array->count++] = fmt;
}

void
xpath_format_array_destroy(xpath_format_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		xpath_format_free(array->data[i]);
	free(array->data);
	memset(array, 0, sizeof(*array));
}
