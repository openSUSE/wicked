/*
 *	Simple XPATH-style expression evaluation.
 *	This does not claim to be a complete XPATH implementation.
 *	XPATH is just way too weird :-)
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/xml.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>
#include "util_priv.h"

#include "debug.h"	/* NI_XPATH_DEBUG_LEVEL */

enum {
	XPATH_INFIXPRIO_NONE = 0,
	XPATH_INFIXPRIO_OR,
	XPATH_INFIXPRIO_AND,
	XPATH_INFIXPRIO_COMPARE,
	XPATH_INFIXPRIO_ADD,
	XPATH_INFIXPRIO_MULT,
};

typedef int __xpath_node_comp_fn_t(const xpath_node_t *, const xpath_node_t *);

typedef struct xpath_operator {
	const char *		name;
	int			intype;
	xpath_node_type_t	outtype;
	int			priority;
	unsigned int		constant : 1;
	const char *		(*print)(const xpath_enode_t *);
	xpath_result_t *	(*evaluate)(const xpath_enode_t *, xpath_result_t *);
	xpath_result_t *	(*evaluate2)(const xpath_enode_t *, xpath_result_t *, xpath_result_t *);

	__xpath_node_comp_fn_t **comparison_table;
} xpath_operator_t;

struct xpath_enode {
	const xpath_operator_t *ops;

	xpath_enode_t *		left;
	xpath_enode_t *		right;

	char *			identifier;
	xpath_integer_t		integer;
};

static xpath_operator_t	__xpath_operator_node;
static xpath_operator_t	__xpath_operator_child;
static xpath_operator_t	__xpath_operator_descendant;
static xpath_operator_t	__xpath_operator_getattr;
static xpath_operator_t	__xpath_operator_predicate;
static xpath_operator_t	__xpath_operator_stringconst;
static xpath_operator_t	__xpath_operator_intconst;
static xpath_operator_t *xpath_get_axis_ops(const char *);
static xpath_operator_t *xpath_get_comparison_ops(const char **);
static xpath_operator_t *xpath_get_infix_ops(const char *);
static xpath_operator_t *xpath_get_function(const char *);

static xpath_result_t *	__xpath_expression_eval(const xpath_enode_t *, xpath_result_t *);
static xpath_result_t *	__xpath_build_boolean(int);

static xpath_enode_t *	__xpath_build_expr(const char **, char, int infixprio);
static int		__xpath_enode_assert_element(xpath_enode_t **);
static const char *	__xpath_next_identifier(const char **);
static void		__xpath_skipws(const char **);

static xpath_enode_t *	xpath_enode_new(const xpath_operator_t *);
static void		xpath_enode_free(xpath_enode_t *);

#ifdef NI_XPATH_DEBUG_LEVEL
# define xtrace(fmt, args...)	ni_debug_verbose(NI_XPATH_DEBUG_LEVEL, NI_TRACE_XPATH, fmt, ##args)
#else
# define xtrace			ni_debug_none
#endif


/*
 * Parse/compile an XPATH expression into a tree of nodes
 */
xpath_enode_t *
xpath_expression_parse(const char *expr)
{
	const char *orig_expr = expr;
	xpath_enode_t *tree;

	if (!expr)
		return NULL;

	if (!strcmp(expr, "/") || !strcmp(expr, "//")) {
		tree = xpath_enode_new(&__xpath_operator_node);
		expr = "";
	} else {
		tree = __xpath_build_expr(&expr, '\0', 0);
	}

	if (!tree)
		goto failed;

	if (*expr)
		goto failed;

	return tree;

failed:
	ni_error("unable to parse XPATH expression \"%s\"", orig_expr);
	if (tree)
		xpath_expression_free(tree);
	return NULL;
}

/*
 * Evaluate a parsed XPATH expression
 */
xpath_result_t *
xpath_expression_eval(const xpath_enode_t *enode, xml_node_t *xn)
{
	xpath_result_t *in = xpath_result_new(XPATH_ELEMENT);
	xpath_result_t *result;

	xpath_result_append_element(in, xn);
	result = __xpath_expression_eval(enode, in);
	xpath_result_free(in);
	return result;
}

/*
 * Free a parsed XPATH expression
 */
static inline void
xpath_expr_free(xpath_enode_t *enode, unsigned int depth, const char *info)
{
	if (!enode)
		return;
	xtrace("xpath_expression_free(%*.s%s %s %s)", depth, " ", info,
		enode->ops ? enode->ops->name : NULL, enode->identifier);
	xpath_expr_free(enode->left,  depth + 2, "left ");
	xpath_expr_free(enode->right, depth + 2, "right");
	xpath_enode_free(enode);
}

void
xpath_expression_free(xpath_enode_t *enode)
{
	xpath_expr_free(enode, 0, "expr ");
}

/*
 * Convenience function: parse XPATH expression, evaluate it once,
 * and return the resulting string.
 */
char *
xml_xpath_eval_string(xml_document_t *doc, xml_node_t *xn, const char *expr)
{
	xpath_result_t *xresult;
	xpath_enode_t *expr_tree;
	char *result = NULL;

	expr_tree = xpath_expression_parse(expr);
	if (!expr_tree)
		return NULL;

	xresult = xpath_expression_eval(expr_tree, xn);
	xpath_expression_free(expr_tree);

	if (!xresult)
		return NULL;
	if (xresult->type == XPATH_STRING && xresult->count)
		result = xstrdup(xresult->node[0].value.string);
	xpath_result_free(xresult);

	return result;
}

/*
 * Parse an XPATH expression.
 * Sorry this is such a spaghetti code implementation :-(
 */
static xpath_enode_t *
__xpath_build_expr(const char **pp, char terminator, int infixprio)
{
	xpath_enode_t *current = NULL;
	const char *pos = *pp;

	xtrace("__xpath_build_expr(\"%s\", '%c', %d)", pos, terminator?: '^', infixprio);
	while (*pos != terminator) {
		xpath_enode_t *newnode;
		xpath_operator_t *ops = NULL;
		const char *ident;
		const char *token_begin;

		__xpath_skipws(&pos);
		xtrace("     current %p - \"%s\"", current, pos);

		if (*pos == '\0')
			return NULL;

		token_begin = pos;
		if (pos[0] == '/') {
			char *colons;

			/* Skip over first slash */
			++pos;

			if (pos[0] == '/') {
				/* "//" is shorthand for "descendant::" */
				ops = &__xpath_operator_descendant;
				++pos;
			} else if (pos[0] == '@') {
handle_atsign:
				/* "@" is shorthand for "attribute::" */
				ops = &__xpath_operator_getattr;
				++pos;
			} else {
				/* FIXME handle "." and ".." */
				ops = NULL;
			}

			/* path/Name */
			if (!(ident = __xpath_next_identifier(&pos))) {
				ni_error("XPATH: expected identifier at \"%s\"", pos);
				goto failed;
			}

handle_name_or_axis:
			if (!__xpath_enode_assert_element(&current))
				goto failed;

			if (ops != NULL) {
				/* Okay, we've been using a shorthand identifier */;
			} else if ((colons = strstr(ident, "::")) != NULL) {
				*colons = '\0';
				ops = xpath_get_axis_ops(ident);
				if (!ops) {
					ni_error("XPATH: unknown operator %s::", ident);
					goto failed;
				}

				ident = NULL;
				if (colons[2] != '\0') {
					/* This one has form "axis::Name" */
					ident = colons + 2;
				} else if (*pos == '*') {
					/* This one has form "axis::*" */
					++pos;
				} else {
					ni_error("operator %s:: must be followed by Name or *", ident);
					goto failed;
				}
			} else if (*pos == '(') {
				goto handle_function;
			} else {
				/* "path/Name" really means "path/child::Name" */
				ops = &__xpath_operator_child;
			}

			newnode = xpath_enode_new(ops);
			if (ident)
				ni_string_dup(&newnode->identifier, ident);

			newnode->left = current;
			current = newnode;
		} else
		if (pos[0] == '@') {
			goto handle_atsign;
		} else
		if (pos[0] == '[') {
			if (!__xpath_enode_assert_element(&current))
				goto failed;

			newnode = xpath_enode_new(&__xpath_operator_predicate);
			newnode->left = current;
			current = newnode;

			++pos;
			current->right = __xpath_build_expr(&pos, ']', 0);
			if (!current->right)
				goto failed;
			if (*pos != ']') {
				ni_error("XPATH: Missing closing ]");
				goto failed;
			}
			++pos;
		} else
		if (pos[0] == '(') {
			if (current != NULL)
				goto failed;

			++pos;
			current = __xpath_build_expr(&pos, ')', 0);
			if (!current || *pos != ')')
				goto failed;
			++pos;
		} else
		if ((ops = xpath_get_comparison_ops(&pos)) != NULL) {
			ident = ops->name;
			goto handle_infix_operator;
		} else
		if (current && (pos[0] == '+' || pos[0] == '-' || pos[0] == '*')) {
			char infixbuf[2];

			infixbuf[0] = *pos++;
			infixbuf[1] = '\0';
			ident = infixbuf;

find_infix_operator:
			ops = xpath_get_infix_ops(ident);
			if (!ops) {
				ni_error("operator %s not implemented", ident);
				goto failed;
			}

handle_infix_operator:
			if (current == NULL) {
				ni_error("Operator %s without LHS expression", ident);
				goto failed;
			}

			xtrace("     found infix operator %s - prio %u; current limit %u",
					ops->name, ops->priority, infixprio);
			if (ops->priority <= infixprio) {
				/* stop processing before the infix
				 * operator and return to previous level */
				pos = token_begin;
				break;
			}

			newnode = xpath_enode_new(ops);
			newnode->left = current;
			current = newnode;

			current->right = __xpath_build_expr(&pos, terminator, ops->priority);
			if (!current->right)
				goto failed;
		} else
		if (isalpha(pos[0])) {
			/* can be
			 *  axis::<something>
			 *  function(something)
			 *  boolean infix operator (and, or)
			 *  boolean constant (true, false)
			 */
			if (!(ident = __xpath_next_identifier(&pos)))
				goto failed;

			if (strstr(ident, "::") != NULL) {
				goto handle_name_or_axis;
			} else
			if (!strcasecmp(ident, "and")
			 || !strcasecmp(ident, "or")
			 || !strcasecmp(ident, "div")
			 || !strcasecmp(ident, "mod")) {
				goto find_infix_operator;
			} else if (pos[0] == '(') {
handle_function:
				/* find named function */;
				ops = xpath_get_function(ident);
				if (!ops) {
					ni_error("XPATH: unknown function \"%s\"", ident);
					goto failed;
				}

				newnode = xpath_enode_new(ops);
				newnode->left = current;
				current = newnode;

				++pos;
				__xpath_skipws(&pos);
				if (*pos == ')') {
					/* This is a function taking no arguments, or
					 * operates on the current node. */
					++pos;
				} else {
					if (current->left != NULL)
						goto failed;
					current->left = __xpath_build_expr(&pos, ')', 0);
					if (!current->left)
						goto failed;
					++pos;
				}
			} else if (!strcasecmp(ident, "true")
				|| !strcasecmp(ident, "false")) {
				/* true and false can appear as constants as well as
				 * functions. The function part is handled above;
				 * we just treat the constant appearance here. */
				if (current != NULL)
					goto failed;
				current = xpath_enode_new(xpath_get_function(ident));
			} else {
				goto handle_name_or_axis;
			}
		} else
		if (pos[0] == '\'') {
			/* string constant */
			const char *begin = ++pos;
			unsigned int n;

			if (current != NULL)
				goto failed;

			current = xpath_enode_new(&__xpath_operator_stringconst);
			for (n = 0; pos[n] != '\''; ++n) {
				if (pos[n] == '\0')
					goto failed;
			}

			current->identifier = malloc(n + 1);
			memcpy(current->identifier, begin, n);
			current->identifier[n] = '\0';

			pos += n + 1;
		} else if (isdigit(pos[0])) {
			if (current != NULL)
				goto failed;

			current = xpath_enode_new(&__xpath_operator_intconst);
			current->integer = strtol(pos, (char **) &pos, 0);
		} else {
			goto failed;
		}
	}

	*pp = pos;
	return current;

failed:
	/* ni_error("xpath: syntax error in expression \"%s\" at position %s", expr, pos); */
	if (current)
		xpath_expression_free(current);
	return NULL;
}

static int
__xpath_enode_assert_element(xpath_enode_t **epp)
{
	xpath_enode_t *enode = *epp;

	if (enode == NULL) {
		*epp = xpath_enode_new(&__xpath_operator_node);
	} else if (enode->ops->outtype != XPATH_ELEMENT)
		return 0;
	return 1;
}


const char *
__xpath_next_identifier(const char **pp)
{
	static char identbuf[1024 + 1];
	unsigned int n = 0;
	const char *pos = *pp;

	if (!isalpha(*pos))
		return NULL;

	while (isalnum(pos[n]) || pos[n] == '-' || pos[n] == ':')
		++n;
	if (n >= sizeof(identbuf)) {
		ni_error("xpath: identifier too long");
		return NULL;
	}

	memcpy(identbuf, pos, n);
	identbuf[n] = '\0';

	*pp = pos + n;
	__xpath_skipws(pp);

	return identbuf;
}

static void
__xpath_skipws(const char **pp)
{
	const char *pos = *pp;

	while (isspace(*pos))
		++pos;
	*pp = pos;
}

/*
 * Cast an xpath_result to the type expected as input of an operation.
 * Currently implemented
 * 	any to boolean
 *	any to integer
 */
static int
__xpath_expression_cast(const xpath_enode_t *enode, xpath_result_t **nap)
{
	xpath_node_type_t type, expected = enode->ops->intype;
	xpath_result_t *na = *nap;
	xpath_node_t *xnp;
	unsigned int n;

	if (na == NULL)
		return 0;

	if (expected == XPATH_ANY
	 || expected == XPATH_VOID)
		return 1;

	type = na->type;
	if (expected == type)
		return 1;

	if (expected == XPATH_BOOLEAN) {
		int bv = 0;

		for (n = 0, xnp = na->node; n < na->count && !bv; ++n, ++xnp) {
			switch (type) {
			case XPATH_ELEMENT:
				bv = (xnp->value.node != NULL);
				break;

			case XPATH_STRING:
				bv = (xnp->value.string[0] != '\0');
				break;

			case XPATH_INTEGER:
				bv = (xnp->value.integer != '\0');
				break;

			default:
				goto cannot_convert;
			}
		}

		xpath_result_free(na);
		*nap = __xpath_build_boolean(bv);
		return 1;
	}

	if (expected == XPATH_INTEGER) {
		xpath_result_t *result = xpath_result_new(XPATH_INTEGER);

		for (n = 0, xnp = na->node; n < na->count; ++n, ++xnp) {
			char *strval = NULL, *end;
			xpath_integer_t ival;

			switch (type) {
			case XPATH_ELEMENT:
				strval = xnp->value.node->cdata;
				break;

			case XPATH_STRING:
				strval = xnp->value.string;
				break;

			default:
				goto cannot_convert;
			}

			ival = strtol(strval, &end, 0);
			if (*end)
				continue;

			xpath_result_append_integer(result, ival);
		}

		xpath_result_free(na);
		*nap = result;
		return 1;
	}

cannot_convert:
	ni_error("XPATH expression \"%s\" expects %s value, got %s",
			enode->ops->name,
			xpath_node_type_name(expected),
			xpath_node_type_name(type));
	return 0;
}


/*
 * Debug printing for EVAL tracing
 */
#ifdef NI_XPATH_DEBUG_LEVEL
static char *
__xpath_node_array_print_short(const xpath_result_t *na)
{
	ni_stringbuf_t buf;
	unsigned int n;

	if (na->type == XPATH_BOOLEAN)
		return xstrdup(__xpath_test_boolean(na)? "[true]" : "[false]");

	if (na->count == 0)
		return xstrdup("[]");

	ni_stringbuf_init(&buf);
	ni_stringbuf_putc(&buf, '[');

	for (n = 0; n < na->count; ++n) {
		const char *string;

		if (n)
			ni_stringbuf_puts(&buf, ", ");
		if (n >= 7) {
			ni_stringbuf_puts(&buf, "...");
			break;
		}

		switch (na->type) {
		case XPATH_ELEMENT:
			string = na->node[n].value.node->name;
			ni_stringbuf_printf(&buf, "<%s>", string?: "ROOT");
			break;

		case XPATH_INTEGER:
			ni_stringbuf_printf(&buf, "%ld", na->node[n].value.integer);
			break;

		case XPATH_STRING:
			string = na->node[n].value.string;
			if (strlen(string) > 32)
				ni_stringbuf_printf(&buf, "\"%.32s ...\"", string);
			else
				ni_stringbuf_printf(&buf, "\"%s\"", string);
			break;

		default:
			ni_stringbuf_puts(&buf, "???");
		}
	}

	ni_stringbuf_putc(&buf, ']');
	return buf.string;
}

static void
__xpath_expression_eval_print_input(const xpath_enode_t *enode,
			const xpath_result_t *left,
			const xpath_result_t *right)
{
	char *leftval = NULL, *rightval = NULL;
	const char *name;
	char namebuf[256];

	if (enode->ops->print) {
		name = enode->ops->print(enode);
	} else if (enode->identifier == NULL) {
		name = enode->ops->name;
	} else {
		snprintf(namebuf, sizeof(namebuf), "%s %s",
				enode->ops->name,
				enode->identifier);
		name = namebuf;
	}

	if (left)
		leftval = __xpath_node_array_print_short(left);
	if (right)
		rightval = __xpath_node_array_print_short(right);
	if (leftval == NULL)
		xtrace("  EVAL %s []", name);
	else if (rightval == NULL)
		xtrace("  EVAL %s %s", name, leftval);
	else
		xtrace("  EVAL %s %s %s", name, leftval, rightval);

	ni_string_free(&leftval);
	ni_string_free(&rightval);
}

static void
__xpath_expression_eval_print_output(const xpath_enode_t *enode,
			const xpath_result_t *result)
{
	char *rval = NULL;

	if (result == NULL) {
		xtrace("  ERROR");
	} else {
		rval = __xpath_node_array_print_short(result);
		xtrace("   => %s", rval);
		ni_string_free(&rval);
	}
}

#else
#define __xpath_expression_eval_print_input(a, b, c) do { } while (0)
#define __xpath_expression_eval_print_output(a, b) do { } while (0)
#endif

/*
 * Recursively evaluate a compiled XPATH expression
 */
xpath_result_t *
__xpath_expression_eval(const xpath_enode_t *enode, xpath_result_t *in)
{
	xpath_result_t *result = NULL;

	assert(enode);
	assert(in);

	if (enode->ops->evaluate2) {
		xpath_result_t *left = NULL, *right = NULL;

		left = __xpath_expression_eval(enode->left, in);
		right = __xpath_expression_eval(enode->right, in);

		__xpath_expression_eval_print_input(enode, left, right);

		if (__xpath_expression_cast(enode, &left)
		 && __xpath_expression_cast(enode, &right)) {
			result = enode->ops->evaluate2(enode, left, right);
		}

		xpath_result_free(left);
		xpath_result_free(right);
	} else {
		xpath_result_t *left = NULL;

		if (enode->left) {
			left = __xpath_expression_eval(enode->left, in);
			if (!left)
				return NULL;
		} else {
			left = xpath_result_dup(in);
		}

		if (__xpath_expression_cast(enode, &left)) {
			__xpath_expression_eval_print_input(enode, left, NULL);
			result = enode->ops->evaluate(enode, left);
		}

		xpath_result_free(left);
	}

	if (result && enode->ops->outtype != result->type) {
		ni_error("XPATH expression \"%s\" should produce %s value, but returns %s",
				enode->ops->name,
				xpath_node_type_name(enode->ops->outtype),
				xpath_node_type_name(result->type));
		xpath_result_free(result);
		result = NULL;
	} 

	__xpath_expression_eval_print_output(enode, result);
	return result;
}

/*
 * Constant expressions
 */
static xpath_result_t *
__xpath_enode_stringconst_evaluate(const xpath_enode_t *enode, xpath_result_t *in)
{
	return __xpath_build_string(enode->identifier);
}

static const char *
__xpath_enode_stringconst_print(const xpath_enode_t *enode)
{
	static char buffer[128];

	snprintf(buffer, sizeof(buffer), "\"%s\"", enode->identifier);
	return buffer;
}

static xpath_operator_t __xpath_operator_stringconst = {
	.name = "string-const",
	.intype = XPATH_VOID,
	.outtype = XPATH_STRING,
	.constant = 1,
	.print = __xpath_enode_stringconst_print,
	.evaluate = __xpath_enode_stringconst_evaluate
};

static xpath_result_t *
__xpath_enode_intconst_evaluate(const xpath_enode_t *enode, xpath_result_t *in)
{
	return __xpath_build_integer(enode->integer);
}

static const char *
__xpath_enode_intconst_print(const xpath_enode_t *enode)
{
	static char buffer[128];

	snprintf(buffer, sizeof(buffer), "%ld", enode->integer);
	return buffer;
}

static xpath_operator_t __xpath_operator_intconst = {
	.name = "intconst",
	.intype = XPATH_VOID,
	.outtype = XPATH_INTEGER,
	.constant = 1,
	.print = __xpath_enode_intconst_print,
	.evaluate = __xpath_enode_intconst_evaluate
};

static xpath_result_t *
__xpath_enode_true_evaluate(const xpath_enode_t *enode, xpath_result_t *in)
{
	return __xpath_build_boolean(1);
}

static xpath_operator_t __xpath_operator_true = {
	.name = "true",
	.intype = XPATH_VOID,
	.outtype = XPATH_BOOLEAN,
	.constant = 1,
	.evaluate = __xpath_enode_true_evaluate
};

static xpath_result_t *
__xpath_enode_false_evaluate(const xpath_enode_t *enode, xpath_result_t *in)
{
	return __xpath_build_boolean(0);
}

static xpath_operator_t __xpath_operator_false = {
	.name = "false",
	.intype = XPATH_VOID,
	.outtype = XPATH_BOOLEAN,
	.constant = 1,
	.evaluate = __xpath_enode_false_evaluate
};

/*
 * Check if an expression is constant
 */
static int
__xpath_expression_constant(const xpath_enode_t *enode)
{
	int constant = 1;

	if (enode->left == NULL) {
		constant = enode->ops->constant;
	} else {
		constant = __xpath_expression_constant(enode->left);
		if (enode->right && !__xpath_expression_constant(enode->right))
			constant = 0;
	}
	return constant;
}

/*
 * node()
 */
static xpath_result_t *
__xpath_enode_node_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	return xpath_result_dup(in);
}

static xpath_operator_t __xpath_operator_node = {
	.name = "node()",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_ELEMENT,
	.evaluate = __xpath_enode_node_evaluate
};

/*
 * self()
 */
static xpath_result_t *
__xpath_enode_self_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	xpath_result_t *result = xpath_result_new(XPATH_ELEMENT);
	const char *match_name = op->identifier;
	unsigned int n;

	for (n = 0; n < in->count; ++n) {
		xml_node_t *xn = in->node[n].value.node;

		if (!match_name || !strcmp(xn->name, match_name))
			xpath_result_append_element(result, xn);
	}

	return result;
}

static xpath_operator_t __xpath_operator_self = {
	.name = "self::",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_ELEMENT,
	.evaluate = __xpath_enode_self_evaluate
};

/*
 * child()
 */
static xpath_result_t *
__xpath_enode_child_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	xpath_result_t *result = xpath_result_new(XPATH_ELEMENT);
	const char *match_name = op->identifier;
	unsigned int n;

	for (n = 0; n < in->count; ++n) {
		xml_node_t *xn = in->node[n].value.node;
		xml_node_t *cn;

		for (cn = xn->children; cn; cn = cn->next) {
			if (!match_name || !strcmp(cn->name, match_name))
				xpath_result_append_element(result, cn);
		}
	}

	return result;
}

static xpath_operator_t __xpath_operator_child = {
	.name = "child::",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_ELEMENT,
	.evaluate = __xpath_enode_child_evaluate
};

/*
 * descendant()
 */
static void
__xpath_enode_descendants_match(xml_node_t *node, const char *match_name, xpath_result_t *result)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (!match_name || !strcmp(child->name, match_name))
			xpath_result_append_element(result, child);
		if (child->children)
			__xpath_enode_descendants_match(child, match_name, result);
	}
}

static xpath_result_t *
__xpath_enode_descendants_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	xpath_result_t *result = xpath_result_new(XPATH_ELEMENT);
	const char *match_name = op->identifier;
	unsigned int n;

	for (n = 0; n < in->count; ++n) {
		xml_node_t *xn = in->node[n].value.node;

		__xpath_enode_descendants_match(xn, match_name, result);
	}

	return result;
}

static xpath_operator_t __xpath_operator_descendant = {
	.name = "descendant::",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_ELEMENT,
	.evaluate = __xpath_enode_descendants_evaluate
};

/*
 * @attribute
 */
static xpath_result_t *
__xpath_enode_getattr_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	xpath_result_t *result = xpath_result_new(XPATH_STRING);
	const char *attr_name = op->identifier;
	unsigned int n;

	for (n = 0; n < in->count; ++n) {
		xml_node_t *xn = in->node[n].value.node;
		const char *attrval;

		if ((attrval = xml_node_get_attr(xn, attr_name)) != NULL) {
			xtrace("  found node <%s %s=\"%s\">", xn->name, attr_name, attrval? : "");
			xpath_result_append_string(result, attrval);
		}
	}

	return result;
}

static xpath_operator_t __xpath_operator_getattr = {
	.name = "attribute::",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_STRING,
	.evaluate = __xpath_enode_getattr_evaluate
};

static xpath_operator_t *
xpath_get_axis_ops(const char *name)
{
	if (!strcmp(name, "child"))
		return &__xpath_operator_child;
	if (!strcmp(name, "descendant"))
		return &__xpath_operator_descendant;
	if (!strcmp(name, "attribute"))
		return &__xpath_operator_getattr;
	if (!strcmp(name, "self"))
		return &__xpath_operator_self;

	return NULL;
}

/*
 * predicate
 */
static xpath_result_t *
__xpath_enode_predicate_evaluate(const xpath_enode_t *enode, xpath_result_t *left)
{
	xpath_result_t *result = xpath_result_new(XPATH_ELEMENT);
	unsigned int m, n;

	assert(enode->right);
	if (left->count == 0)
		return result;

	/* FIXME: special case - right hand side is a constant expression */
	if (__xpath_expression_constant(enode->right)) {
		xpath_result_t *right;
		xpath_integer_t index;

		/* evaluate right expression once, then apply */
		xtrace("    subscript expression is constant");

		right = __xpath_expression_eval(enode->right, left);
		if (!right) {
			xpath_result_free(result);
			result = NULL;
			goto out;
		}

		for (n = 0; n < right->count; ++n) {
			xpath_node_t *rn = &right->node[n];

			switch (rn->type) {
			case XPATH_INTEGER:
				/* Predicate indices are 1 based */
				index = rn->value.integer;
				if (0 < index && index - 1 < left->count)
					xpath_result_append_element(result,
							left->node[index-1].value.node);
				break;

			case XPATH_BOOLEAN:
				/* Just return all elements */
				if (rn->value.boolean) {
					xpath_result_free(result);
					return left;
				}
				break;

			default:
				break;
			}
		}
		xpath_result_free(right);
		goto out;
	}

	/* For every node element in the left expression, evaluate
	 * the subscript (right) expression. */
	for (m = 0; m < left->count; ++m) {
		xpath_result_t *tmp, *right;
		xml_node_t *xn;

		if (left->node[m].type != XPATH_ELEMENT)
			return NULL;
		xn = left->node[m].value.node;

		tmp = xpath_result_new(XPATH_ELEMENT);
		xpath_result_append_element(tmp, xn);

		right = __xpath_expression_eval(enode->right, tmp);
		xpath_result_free(tmp);

		if (!right)
			continue;

		for (n = 0; n < right->count; ++n) {
			xpath_node_t *rn = &right->node[n];

			switch (rn->type) {
			case XPATH_ELEMENT:
				if (rn->value.node != 0) {
					xpath_result_append_element(result, xn);
					goto appended;
				}
				break;

			case XPATH_INTEGER:
				/* Predicate indices are 1 based */
				if (rn->value.integer == (xpath_integer_t) (m + 1))
					xpath_result_append_element(result, xn);
				break;

			case XPATH_BOOLEAN:
				if (rn->value.boolean)
					xpath_result_append_element(result, xn);
				break;

			default:
				break;
			}
		}

appended:
		xpath_result_free(right);
	}

out:
	return result;
}

static xpath_operator_t __xpath_operator_predicate = {
	.name = "predicate[]",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_ELEMENT,
	.evaluate = __xpath_enode_predicate_evaluate
};

/*
 * Boolean AND
 */
static xpath_result_t *
__xpath_enode_and_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_build_boolean(__xpath_test_boolean(left) && __xpath_test_boolean(right));
}

static xpath_operator_t __xpath_operator_and = {
	.name = "and",
	.intype = XPATH_BOOLEAN,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_AND,
	.evaluate2 = __xpath_enode_and_evaluate
};

/*
 * Boolean OR
 */
static xpath_result_t *
__xpath_enode_or_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_build_boolean(__xpath_test_boolean(left) || __xpath_test_boolean(right));
}

static xpath_operator_t __xpath_operator_or = {
	.name = "or",
	.intype = XPATH_BOOLEAN,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_OR,
	.evaluate2 = __xpath_enode_or_evaluate
};

/*
 * Arithmetic infix operators
 */
static int
__xpath_arith_add(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint)
{
	*resp = lint + rint;
	return 1;
}

static int
__xpath_arith_subtract(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint)
{
	*resp = lint - rint;
	return 1;
}

static int
__xpath_arith_multiply(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint)
{
	*resp = lint * rint;
	return 1;
}

static int
__xpath_arith_divide(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint)
{
	if (!rint)
		return 0;
	*resp = lint / rint;
	return 1;
}

static int
__xpath_arith_modulo(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint)
{
	if (!rint)
		return 0;
	*resp = lint % rint;
	return 1;
}

static xpath_result_t *
__xpath_enode_generic_arith(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right,
		int (*oper)(xpath_integer_t *resp, xpath_integer_t lint, xpath_integer_t rint))
{
	xpath_result_t *result = xpath_result_new(XPATH_INTEGER);
	unsigned int m, n;

	for (m = 0; m < left->count; ++m) {
		xpath_integer_t lint = left->node[m].value.integer;
		for (n = 0; n < right->count; ++n) {
			xpath_integer_t rint = right->node[n].value.integer, rv;

			if (oper(&rv, lint, rint))
				xpath_result_append_integer(result, rv);
		}
	}

	return result;
}

static xpath_result_t *
__xpath_enode_add_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_enode_generic_arith(op, left, right, __xpath_arith_add);
}

static xpath_operator_t __xpath_operator_add = {
	.name = "add",
	.intype = XPATH_INTEGER,
	.outtype = XPATH_INTEGER,
	.priority = XPATH_INFIXPRIO_ADD,
	.evaluate2 = __xpath_enode_add_evaluate
};

static xpath_result_t *
__xpath_enode_subtract_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_enode_generic_arith(op, left, right, __xpath_arith_subtract);
}

static xpath_operator_t __xpath_operator_subtract = {
	.name = "subtract",
	.intype = XPATH_INTEGER,
	.outtype = XPATH_INTEGER,
	.priority = XPATH_INFIXPRIO_ADD,
	.evaluate2 = __xpath_enode_subtract_evaluate
};

static xpath_result_t *
__xpath_enode_multiply_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_enode_generic_arith(op, left, right, __xpath_arith_multiply);
}

static xpath_operator_t __xpath_operator_multiply = {
	.name = "multiply",
	.intype = XPATH_INTEGER,
	.outtype = XPATH_INTEGER,
	.priority = XPATH_INFIXPRIO_MULT,
	.evaluate2 = __xpath_enode_multiply_evaluate
};

static xpath_result_t *
__xpath_enode_divide_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_enode_generic_arith(op, left, right, __xpath_arith_divide);
}

static xpath_operator_t __xpath_operator_divide = {
	.name = "divide",
	.intype = XPATH_INTEGER,
	.outtype = XPATH_INTEGER,
	.priority = XPATH_INFIXPRIO_MULT,
	.evaluate2 = __xpath_enode_divide_evaluate
};

static xpath_result_t *
__xpath_enode_modulo_evaluate(const xpath_enode_t *op, xpath_result_t *left, xpath_result_t *right)
{
	return __xpath_enode_generic_arith(op, left, right, __xpath_arith_modulo);
}

static xpath_operator_t __xpath_operator_modulo = {
	.name = "modulo",
	.intype = XPATH_INTEGER,
	.outtype = XPATH_INTEGER,
	.priority = XPATH_INFIXPRIO_MULT,
	.evaluate2 = __xpath_enode_modulo_evaluate
};

static xpath_operator_t *
xpath_get_infix_ops(const char *name)
{
	if (!strcmp(name, "and"))
		return &__xpath_operator_and;
	if (!strcmp(name, "or"))
		return &__xpath_operator_or;
	if (!strcmp(name, "+"))
		return &__xpath_operator_add;
	if (!strcmp(name, "-"))
		return &__xpath_operator_subtract;
	if (!strcmp(name, "*"))
		return &__xpath_operator_multiply;
	if (!strcmp(name, "div"))
		return &__xpath_operator_divide;
	if (!strcmp(name, "mod"))
		return &__xpath_operator_modulo;
	return NULL;
}

/*
 * Functions
 */
static xpath_result_t *
__xpath_enode_last_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	return __xpath_build_integer(in->count);
}

static xpath_operator_t __xpath_operator_last = {
	.name = "last()",
	.intype = XPATH_ELEMENT,
	.outtype = XPATH_INTEGER,
	.constant = 1,
	.evaluate = __xpath_enode_last_evaluate
};

static xpath_result_t *
__xpath_enode_not_evaluate(const xpath_enode_t *op, xpath_result_t *in)
{
	return __xpath_build_boolean(!__xpath_test_boolean(in));
}

static xpath_operator_t __xpath_operator_not = {
	.name = "not()",
	.intype = XPATH_BOOLEAN,
	.outtype = XPATH_BOOLEAN,
	.constant = 1,
	.evaluate = __xpath_enode_not_evaluate
};

static xpath_operator_t *
xpath_get_function(const char *name)
{
	if (!strcmp(name, "true"))
		return &__xpath_operator_true;
	if (!strcmp(name, "false"))
		return &__xpath_operator_false;
	if (!strcmp(name, "last"))
		return &__xpath_operator_last;
	if (!strcmp(name, "not"))
		return &__xpath_operator_not;
	return NULL;
}

/*
 * Compare values
 */
static int
xstrcmp(const char *s1, const char *s2)
{
	if (!s1)
		s1 = "";
	if (!s2)
		s2 = "";
	return strcmp(s1, s2);
}


#define __xpath_comparison_fn(name, member, expr) \
static int \
__xpath_##name(const xpath_node_t *ln, const xpath_node_t *rn) \
{ \
	typeof(ln->value.member) __left = ln->value.member; \
	typeof(rn->value.member) __right = rn->value.member; \
 \
	return expr; \
}

#define __xpath_comparison_set(name, xop) \
__xpath_comparison_fn(element_##name,	 node,		 (xstrcmp(__left->cdata, __right->cdata) xop 0)) \
__xpath_comparison_fn(str_##name,	 string,	 (xstrcmp(__left, __right) xop 0)) \
__xpath_comparison_fn(int_##name,	 integer,	 (__left xop __right)) \
__xpath_comparison_fn(bool_##name,	 boolean,	 (__left xop __right)) \
 \
static __xpath_node_comp_fn_t *	__xpath_node_comp_##name[__XPATH_NODE_TYPE_MAX] = { \
[XPATH_ELEMENT] =	__xpath_element_##name, \
[XPATH_STRING] =	__xpath_str_##name, \
[XPATH_INTEGER] =	__xpath_int_##name, \
[XPATH_BOOLEAN] =	__xpath_bool_##name, \
}

__xpath_comparison_set(eq, ==);	/* equal */
__xpath_comparison_set(ne, !=);	/* not equal */
__xpath_comparison_set(lt, <);	/* less than */
__xpath_comparison_set(gt, >);	/* greater than */
__xpath_comparison_set(le, <=);	/* less or equal than */
__xpath_comparison_set(ge, >=);	/* greater or equal than */

/*
 * Generic comparison function
 */
static xpath_result_t *
__xpath_enode_generic_comparison(const xpath_enode_t *enode, xpath_result_t *left, xpath_result_t *right)
{
	__xpath_node_comp_fn_t *nodecomp;
	xpath_node_t *ln, *rn;
	unsigned int m, n;
	int bv = 1;

	xtrace("   compare-%s(%s, %s)", enode->ops->name, xpath_node_type_name(left->type), xpath_node_type_name(right->type));
	if (left->type != right->type) {
		/* Different types; convert everything to strings and compare those */
		left = xpath_result_to_strings(left);
		right = xpath_result_to_strings(right);
	} else {
		xpath_result_dup(left);
		xpath_result_dup(right);
	}

	if ((nodecomp = enode->ops->comparison_table[left->type]) != NULL) {
		for (m = 0, ln = left->node; m < left->count; ++m, ++ln) {
			for (n = 0, rn = right->node; n < right->count; ++n, ++rn) {
				if (nodecomp(ln, rn))
					goto done;
			}
		}
	}

	bv = 0;

done:
	xpath_result_free(left);
	xpath_result_free(right);
	return __xpath_build_boolean(bv);
}

/*
 * Comparison operators
 */
static xpath_operator_t __xpath_operator_eq = {
	.name = "equal",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_eq,
};

static xpath_operator_t __xpath_operator_ne = {
	.name = "not-equal",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_ne,
};

static xpath_operator_t __xpath_operator_lt = {
	.name = "less-than",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_lt,
};

static xpath_operator_t __xpath_operator_gt = {
	.name = "greater-than",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_gt,
};

static xpath_operator_t __xpath_operator_ge = {
	.name = "less-or-equal",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_ge,
};

static xpath_operator_t __xpath_operator_le = {
	.name = "greater-or-equal",
	.intype = XPATH_ANY,
	.outtype = XPATH_BOOLEAN,
	.priority = XPATH_INFIXPRIO_COMPARE,
	.evaluate2 = __xpath_enode_generic_comparison,
	.comparison_table = __xpath_node_comp_le,
};

static xpath_operator_t *
xpath_get_comparison_ops(const char **pp)
{
	const char *pos = *pp;

	if (*pos == '=') {
		*pp = pos + 1;
		return &__xpath_operator_eq;
	}
	if (*pos == '<') {
		*pp = pos + 1;
		return &__xpath_operator_lt;
	}
	if (*pos == '>') {
		*pp = pos + 1;
		return &__xpath_operator_gt;
	}
	if (!strncmp(pos, "!=", 2)) {
		*pp = pos + 2;
		return &__xpath_operator_ne;
	}
	if (!strncmp(pos, "<=", 2)) {
		*pp = pos + 2;
		return &__xpath_operator_le;
	}
	if (!strncmp(pos, ">=", 2)) {
		*pp = pos + 2;
		return &__xpath_operator_ge;
	}

	return NULL;
}

/*
 * Houskeeping functions for expression nodes
 */
static xpath_enode_t *
xpath_enode_new(const xpath_operator_t *ops)
{
	xpath_enode_t *enode;

	enode = calloc(1, sizeof(*enode));
	enode->ops = ops;

	return enode;
}

static void
xpath_enode_free(xpath_enode_t *enode)
{
	ni_string_free(&enode->identifier);
	free(enode);
}

static void
__xpath_node_destroy(xpath_node_t *xpn)
{
	if (xpn->type == XPATH_STRING)
		free(xpn->value.string);
}

/*
 * Housekeeping functions for managing xpath_results
 */
xpath_result_t *
xpath_result_new(xpath_node_type_t type)
{
	xpath_result_t *na;

	na = calloc(1, sizeof(xpath_result_t));
	na->users = 1;
	na->type = type;
	return na;
}

xpath_result_t *
xpath_result_dup(xpath_result_t *na)
{
	assert(na->users);
	na->users++;
	return na;
}

void
xpath_result_free(xpath_result_t *na)
{
	if (!na)
		return;

	assert(na->users);
	if (--(na->users))
		return;
	while (na->count)
		__xpath_node_destroy(&na->node[--(na->count)]);
	free(na->node);
	memset(na, 0, sizeof(*na));
	free(na);
}

void
xpath_result_print(const xpath_result_t *na, FILE *fp)
{
	xpath_node_t *xpn;
	unsigned int n;

	switch (na->type) {
	case XPATH_VOID:
		fprintf(stderr, "<EMPTY>\n");
		break;

	case XPATH_ELEMENT:
		for (n = 0, xpn = na->node; n < na->count; ++n, ++xpn) {
			fprintf(fp, "-- ELEMENT[%u] --\n", n);
			xml_node_print(xpn->value.node, fp);
		}
		break;

	case XPATH_STRING:
		for (n = 0, xpn = na->node; n < na->count; ++n, ++xpn) {
			/* fprintf(fp, "-- STRING[%u] --\n", n); */
			fprintf(fp, "%s\n", xpn->value.string);
		}
		break;

	case XPATH_INTEGER:
		for (n = 0, xpn = na->node; n < na->count; ++n, ++xpn) {
			/* fprintf(fp, "-- INTEGER[%u] --\n", n); */
			fprintf(fp, "%ld\n", xpn->value.integer);
		}
		break;

	case XPATH_BOOLEAN:
		fprintf(fp, __xpath_test_boolean(na)? "true" : "false");
		break;

	default:
		fprintf(fp, " UNKNOWN --\n");
		break;
	}
}

static xpath_node_t *
__xpath_node_array_append(xpath_result_t *na, xpath_node_type_t type)
{
	xpath_node_t *xpn;

	if ((na->count & 15) == 0) {
		na->node = realloc(na->node, (na->count + 16) * sizeof(xpath_node_t));
		assert(na->node);
	}

	xpn = &na->node[na->count++];
	memset(xpn, 0, sizeof(*xpn));
	xpn->type = type;
	return xpn;
}

void
xpath_result_append_element(xpath_result_t *na, xml_node_t *xn)
{
	xpath_node_t *xpn;

	xpn = __xpath_node_array_append(na, XPATH_ELEMENT);
	xpn->value.node = xn;
}

void
xpath_result_append_string(xpath_result_t *na, const char *string)
{
	xpath_node_t *xpn;

	xpn = __xpath_node_array_append(na, XPATH_STRING);
	xpn->value.string = xstrdup(string);
}

void
xpath_result_append_boolean(xpath_result_t *na, int bv)
{
	xpath_node_t *xpn;

	xpn = __xpath_node_array_append(na, XPATH_BOOLEAN);
	xpn->value.boolean = bv;
}

void
xpath_result_append_integer(xpath_result_t *na, xpath_integer_t iv)
{
	xpath_node_t *xpn;

	xpn = __xpath_node_array_append(na, XPATH_INTEGER);
	xpn->value.integer = iv;
}

xpath_result_t *
xpath_result_to_strings(xpath_result_t *in)
{
	xpath_result_t *result;

	if (in->type == XPATH_STRING
	 || in->type == XPATH_VOID) {
		xpath_result_dup(in);
		return in;
	}

	result = xpath_result_new(XPATH_STRING);
	if (in->type == XPATH_BOOLEAN) {
		xpath_result_append_string(result,
				__xpath_test_boolean(in)? "true" : "false");
	} else if (in->type == XPATH_INTEGER) {
		xpath_node_t *xn;
		unsigned int n;
		char temp[64];

		for (n = 0, xn = in->node; n < in->count; ++n, ++xn) {
			snprintf(temp, sizeof(temp), "%lu", xn->value.integer);
			xpath_result_append_string(result, temp);
		}
	} else if (in->type == XPATH_ELEMENT) {
		xpath_node_t *xn;
		unsigned int n;

		for (n = 0, xn = in->node; n < in->count; ++n, ++xn) {
			xpath_result_append_string(result, xn->value.node->cdata);
		}
	}

	return result;
}


const char *
xpath_node_type_name(xpath_node_type_t type)
{
	switch (type) {
	case XPATH_VOID:
		return "void";
	case XPATH_ELEMENT:
		return "element";
	case XPATH_STRING:
		return "string";
	case XPATH_INTEGER:
		return "integer";
	case XPATH_BOOLEAN:
		return "boolean";
	case XPATH_ANY:
		return "any";
	case __XPATH_NODE_TYPE_MAX:
		break;
	}

	return "unknown";
}
