/*
 * This command line utility generates HTML documentation from the
 * DBus XML schema
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/wireless.h>
#include <wicked/modem.h>
#include "xml-schema.h"

#define CLASS_MAX		128
#define METHOD_MAX		128
#define SERVICE_MAX		128

struct class_tracker {
	const ni_dbus_class_t *	dbus_class;
	unsigned int		nservices;
	const ni_xs_service_t *	services[SERVICE_MAX];
};

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_OUTDIR,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "outdir",		required_argument,	NULL,	OPT_OUTDIR },

	{ NULL }
};

#define SCOPE_PATH_MAX	512

static const char *	program_name;
static ni_xs_scope_t *	schema;
static const char *	opt_outdir = "html";

static void		render(void);
static const char *	ni_xs_service_get_attribute(const ni_xs_service_t *, const char *, const char *);
static void		describe_type(FILE *fp, const char *lead, const ni_xs_scope_t *myscope, const ni_xs_type_t *);
static void		describe_typedefs(FILE *fp, const ni_xs_scope_t *);
static void		describe_service(FILE *fp, const ni_xs_service_t *);
static void		render_scope(const ni_xs_scope_t *scope);
static void		describe_scope(FILE *, const ni_xs_scope_t *);

static const char *	absolute_namespace_path(const ni_xs_scope_t *);
static int		cmpclass(const void *__a, const void *__b);

int
main(int argc, char **argv)
{
	int c;

	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"%s [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"  --outdir path\n"
				"        Where to place the generated html files\n",
				program_name
			       );
			return 1;

		case OPT_CONFIGFILE:
			if (!ni_set_global_config_path(optarg)) {
				fprintf(stderr, "Unable to set config file '%s': %m\n", optarg);
				return 1;
			}
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help();
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_OUTDIR:
			opt_outdir = optarg;
			break;
		}
	}

	if (ni_init("server") < 0)
		return 1;

	if (optind != argc)
		goto usage;

	render();
	return 0;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
render(void)
{
	ni_xs_service_t *xs_service;
	struct class_tracker classes[CLASS_MAX];
	unsigned int nclasses = 0;
	char pathname[PATH_MAX], filename[PATH_MAX];

	schema = ni_objectmodel_init(NULL);
	if (schema == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");

	memset(classes, 0, sizeof(classes));
	for (xs_service = schema->services; xs_service; xs_service = xs_service->next) {
		const char *classname;
		FILE *fp;

		snprintf(pathname, sizeof(pathname), "%s/%s.html", opt_outdir, xs_service->interface);
		if (!(fp = fopen(pathname, "w")))
			ni_fatal("Cannot open %s: %m", pathname);
		printf("Writing %s\n", pathname);
		describe_service(fp, xs_service);
		fclose(fp);

		if (xs_service->name) {
			snprintf(pathname, sizeof(pathname), "%s/%s.html", opt_outdir, xs_service->name);
			snprintf(filename, sizeof(filename), "%s.html", xs_service->interface);
			if (symlink(filename, pathname) < 0)
				perror(pathname);
		}

		classname = ni_xs_service_get_attribute(xs_service, "object-class", NULL);
		if (classname) {
			struct class_tracker *ct;
			const ni_dbus_class_t *class;
			unsigned int i;

			class = ni_objectmodel_get_class(classname);
			for (i = 0, ct = classes; i < nclasses; ++i, ++ct) {
				if (ct->dbus_class == class)
					break;
			}
			if (i >= nclasses) {
				ct->dbus_class = class;
				nclasses++;
			}
			ct->services[ct->nservices++] = xs_service;
		}
	}

	qsort(classes, nclasses, sizeof(classes[0]), cmpclass);
	if (nclasses) {
		unsigned int i, j;
		FILE *fp;

		snprintf(pathname, sizeof(pathname), "%s/classes.html", opt_outdir);
		if (!(fp = fopen(pathname, "w")))
			ni_fatal("Cannot open %s: %m", pathname);
		printf("Writing %s\n", pathname);

		fprintf(fp,
			"<h1>Class index</h1>\n"
			"This lists all object classes defined by the schema, and the DBus services\n"
			"bound to them.\n"
			"<p>\n"
			);

		fprintf(fp, "<table border=\"1\">\n");
		fprintf(fp,
			"<tr>\n"
			"  <th style=\"width:100px\">Class</th>\n"
			"  <th style=\"width:200px\">Base class</th>\n"
			"  <th style=\"width:400px\">Interface</th>\n"
			"</tr>\n"
			);
			
		for (i = 0; i < nclasses; ++i) {
			struct class_tracker *ct = &classes[i];

			fprintf(fp,
				"<tr>\n"
				" <td rowspan=\"%u\" valign=\"top\">%s</td>\n"
				" <td rowspan=\"%u\" valign=\"top\">%s</td>\n",
				ct->nservices, ct->dbus_class->name,
				ct->nservices, ct->dbus_class->superclass? ct->dbus_class->superclass->name : "n/a"
				);
			for (j = 0; j < ct->nservices; ++j) {
				const ni_xs_service_t *xs_service = ct->services[j];

				if (j)
					fprintf(fp, "<tr>\n");
				fprintf(fp, " <td><a href=\"%s.html\">%s</a></td>\n</tr>\n",
						xs_service->interface,
						xs_service->interface);
			}
		}
		fprintf(fp, "</table>\n");
	}

	render_scope(schema);
}

static void
render_scope(const ni_xs_scope_t *scope)
{
	if (scope->defined_by.service == NULL && scope->types.count != 0) {
		char pathname[PATH_MAX];
		FILE *fp;

		snprintf(pathname, sizeof(pathname), "%s/%s.html", opt_outdir, absolute_namespace_path(scope));
		unlink(pathname);
		if (!(fp = fopen(pathname, "w")))
			ni_fatal("Cannot open %s: %m", pathname);

		printf("Writing %s\n", pathname);
		describe_scope(fp, scope);
		fclose(fp);
	}

	for (scope = scope->children; scope; scope = scope->next)
		render_scope(scope);
}

static int
cmpclass(const void *__a, const void *__b)
{
	const struct class_tracker *a = __a;
	const struct class_tracker *b = __b;
	int diff;

	if (ni_dbus_class_is_subclass(a->dbus_class, b->dbus_class))
		return 1;
	if (ni_dbus_class_is_subclass(b->dbus_class, a->dbus_class))
		return -1;

	diff = b->nservices - a->nservices;
	if (diff)
		return diff;

	return strcmp(b->dbus_class->name, a->dbus_class->name);
}

static ni_bool_t
render_description(FILE *fp, const char *string)
{
	unsigned int printed = 0;

	if (string == NULL)
		return FALSE;

	while (*string) {
		ni_bool_t bol = FALSE;

		while (isspace(*string)) {
			if (*string == '\n') {
				if (bol) {
					fprintf(fp, "<p>\n");
					printed++;
				} else {
					fprintf(fp, " ");
				}
				bol = TRUE;
			}
			++string;
		}

		while (*string && *string != '\n') {
			fputc(*string++, fp);
			printed++;
		}
	}

	return printed != 0;
}

static const char *
type_class(const ni_xs_type_t *type)
{
	switch (type->class) {
	case NI_XS_TYPE_SCALAR:
		return type->u.scalar_info->basic_name;
	case NI_XS_TYPE_STRUCT:
		return "struct";
	case NI_XS_TYPE_ARRAY:
		return "array";
	case NI_XS_TYPE_DICT:
		return "dict";
	}

	return "unknown";
}

static inline ni_bool_t
__namespace_is_ancestor(const ni_xs_scope_t *ancestor, const ni_xs_scope_t *candidate)
{
	for (; candidate; candidate = candidate->parent) {
		if (candidate == ancestor)
			return TRUE;
	}

	return FALSE;
}

static const char *
__namespace_path(const ni_xs_scope_t *src, const ni_xs_scope_t *dst, char *buffer, size_t size)
{
	unsigned int len = 0;

	ni_assert(dst);
	if (dst->parent != src) {
		if (!__namespace_path(src, dst->parent, buffer, size))
			return NULL;
		len = strlen(buffer);
		if (len + 1 >= size)
			ni_fatal("%s: path too long", __func__);
		buffer[len++] = '.';
	}

	if (len + strlen(dst->name) + 1 >= size)
		ni_fatal("%s: path too long", __func__);
	strcpy(buffer + len, dst->name);
	return buffer;
}

static const char *
absolute_namespace_path(const ni_xs_scope_t *dst)
{
	static char buffer[SCOPE_PATH_MAX];

	if (dst == schema)
		return schema->name;

	return __namespace_path(schema, dst, buffer, sizeof(buffer));
}

static const char *
relative_namespace_path(const ni_xs_scope_t *src, const ni_xs_scope_t *dst)
{
	static char buffer[SCOPE_PATH_MAX];
	const ni_xs_scope_t *orig_src = src;

	if (__namespace_is_ancestor(dst, src))
		return NULL;

	do {
		if (__namespace_is_ancestor(src, dst))
			return __namespace_path(src, dst, buffer, sizeof(buffer));
		src = src->parent;
	} while(src);

	ni_warn("Unable to determine path of scope");
	ni_trace("src=%s", absolute_namespace_path(orig_src));
	ni_trace("dst=%s", absolute_namespace_path(dst));
	return absolute_namespace_path(dst);
}

static const char *
reference_type(const ni_xs_scope_t *src_scope, const ni_xs_scope_t *dst_scope, const char *name)
{
	static char buffer[2 * SCOPE_PATH_MAX];
	const char *relative_path;

	if ((relative_path = relative_namespace_path(src_scope, dst_scope)) == NULL) {
		snprintf(buffer, sizeof(buffer), "<a href=\"%s.html#%s\">%s</a>",
				absolute_namespace_path(dst_scope), name, name);
	} else {
		snprintf(buffer, sizeof(buffer), "<a href=\"%s.html#%s\">%s:%s</a>",
				absolute_namespace_path(dst_scope), name,
				relative_path, name);
	}
	return buffer;
}

static const char *
chase_typedef(const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	return reference_type(myscope, type->origdef.scope, type->origdef.name);
}

static const char *
describe_type_short(const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	if (type == NULL)
		return "void";
	if (type->origdef.name)
		return chase_typedef(myscope, type);
	return type_class(type);
}

static void
describe_scalar(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	ni_xs_scalar_info_t *scalar_info = type->u.scalar_info;

	fprintf(fp, "a %s", scalar_info->basic_name);
	if (scalar_info->constraint.enums) {
		const ni_intmap_t *map;

		fprintf(fp, " enumerated type, which can take the following values:\n<p><ul>");
		for (map = scalar_info->constraint.enums->bits; map->name; ++map)
			fprintf(fp, " <li>%s (%u)</li>\n", map->name, map->value);
		fprintf(fp, "</ul><p>\n");
	}
	if (scalar_info->constraint.bitmap) {
		const ni_intmap_t *map;

		fprintf(fp, " bitmap type, which is a combination of zero or more of the following flags:\n<p><ul>");
		for (map = scalar_info->constraint.bitmap->bits; map->name; ++map)
			fprintf(fp, " <li>%s (%u)</li>\n", map->name, map->value);
		fprintf(fp, "</ul><p>\n");
	}
	if (scalar_info->constraint.range) {
		unsigned long min = scalar_info->constraint.range->min;
		unsigned long max = scalar_info->constraint.range->max;

		if (max < ULONG_MAX)
			fprintf(fp, " range type with values from %lu to %lu, inclusively", min, max);
		else
			fprintf(fp, " range type with values from %lu to infinity", min);
	}
}

static void
__describe_dict(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *type, const char *anchor_prefix)
{
	ni_xs_dict_info_t *dict_info = type->u.dict_info;
	unsigned int j;

	ni_assert(type->class == NI_XS_TYPE_DICT);
	fprintf(fp, "<ul>\n");
	for (j = 0; j < dict_info->children.count; ++j) {
		ni_xs_name_type_t *cnt = &dict_info->children.data[j];
		ni_xs_type_t *ctype = cnt->type;

		fprintf(fp, "<li>");
		if (anchor_prefix == NULL)
			fprintf(fp, "<bold>%s</bold>", cnt->name);
		else
			fprintf(fp, "<a name=\"%s:%s\"/><bold>%s</bold>",
					anchor_prefix, cnt->name, cnt->name);

		fprintf(fp, " (%s). ", describe_type_short(myscope, ctype));
		if (ctype && ctype->origdef.name == NULL) {
			describe_type(fp, "This is ", myscope, ctype);
		} else
		if (cnt->description) {
			render_description(fp, cnt->description);
		} else
		if (ctype && ctype->description) {
			render_description(fp, ctype->description);
		}
		fprintf(fp, "</li>\n");
	}
	fprintf(fp, "</ul>\n");
	fprintf(fp, "<p>\n");
}

static void
describe_dict(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	fprintf(fp, "a dict-based type that provides the following members:\n");
	__describe_dict(fp, myscope, type, NULL);
}

static void
describe_array(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	ni_xs_array_info_t *array_info = type->u.array_info;
	const ni_xs_type_t *element_type;

	element_type = array_info->element_type;
	fprintf(fp, "an array of %s", describe_type_short(myscope, element_type));

	if (array_info->minlen == 0 && array_info->maxlen == ULONG_MAX)
		;
	else if (array_info->minlen == array_info->maxlen)
		fprintf(fp, "[%lu]", array_info->minlen);
	else if (array_info->minlen && array_info->maxlen < ULONG_MAX)
		fprintf(fp, "[%lu .. %lu]", array_info->minlen, array_info->maxlen);
	else if (array_info->minlen)
		fprintf(fp, "[%lu .. infinity]", array_info->minlen);
	else
		fprintf(fp, "[0 .. %lu]", array_info->maxlen);

	if (array_info->notation)
		fprintf(fp, " (notation %s)", array_info->notation->name);
	fprintf(fp, ".\n");

	if (element_type->origdef.name == NULL) {
		describe_type(fp, "Each element is ", myscope, element_type);
	}
}

static void
describe_type(FILE *fp, const char *lead, const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	if (render_description(fp, type->description))
		fprintf(fp, "<p>\n");

	if (lead)
		fprintf(fp, "%s", lead);

	switch (type->class) {
	case NI_XS_TYPE_DICT:
		describe_dict(fp, myscope, type);
		break;
	
	case NI_XS_TYPE_ARRAY:
		describe_array(fp, myscope, type);
		break;

	case NI_XS_TYPE_SCALAR:
		describe_scalar(fp, myscope, type);
		break;

	default:
		fprintf(fp, "an %s", type_class(type));
	}

}

static void
describe_typedefs(FILE *fp, const ni_xs_scope_t *scope)
{
	unsigned int i;

	if (scope->types.count == 0
	 || (scope->types.count == 1 && ni_string_eq(scope->types.data[0].name, "properties")))
		return;

	fprintf(fp, "<h2>Types defined in this scope</h2>\n");
	fprintf(fp, 
		"\n<p>\n<table border=\"1\">\n"
		"<tr>\n"
		" <th style=\"width:200px\">Type name</th>\n"
		" <th style=\"width:100px\">Kind</th>\n"
		" <th style=\"width:400px\">Definition</th>\n"
		"</tr>\n");

	for (i = 0; i < scope->types.count; ++i) {
		ni_xs_name_type_t *nt = &scope->types.data[i];
		ni_xs_type_t *type = nt->type;

		if (ni_string_eq(nt->name, "properties"))
			continue;

		fprintf(fp, "<tr><td>%s</td><td>%s</td>", nt->name, type_class(type));
		if (type->origdef.scope == scope)
			fprintf(fp, "<td>below</td>");
		else
			fprintf(fp, "<td>%s</td>", chase_typedef(scope, type));
		fprintf(fp, "</tr>\n");
	}
	fprintf(fp, "</table>\n");

	for (i = 0; i < scope->types.count; ++i) {
		ni_xs_name_type_t *nt = &scope->types.data[i];
		ni_xs_type_t *type = nt->type;

		if (ni_string_eq(nt->name, "properties"))
			continue;
		if (type->origdef.scope != scope)
			continue;

		fprintf(fp, "\n<a name=\"%s\"/>\n", nt->name);
		fprintf(fp, "<h3>Type %s</h3>\n", nt->name);

		fprintf(fp, "<p>\n");
		describe_type(fp, "This is ", scope, type);
	}
}

static void
describe_properties(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *properties)
{
	if (properties == NULL)
		return;

	fprintf(fp, "<h2>Properties</h2>\n");
	__describe_dict(fp, myscope, properties, "property");
}

static void
describe_methods(FILE *fp, const ni_xs_scope_t *myscope, const char *what, const ni_xs_method_t *list)
{
	const ni_xs_method_t *method;

	if (list == NULL)
		return;

	fprintf(fp, "<h2>%ss</h2>\n", what);

	fprintf(fp, "<dl>\n");
	for (method = list; method; method = method->next) {
		unsigned int i;

		fprintf(fp, "<dt><em><a name=\"%s\"/>%s %s(",
				method->name,
				describe_type_short(myscope, method->retval),
				method->name);
		for (i = 0; i < method->arguments.count; ++i) {
			const ni_xs_name_type_t *nt = &method->arguments.data[i];

			if (i)
				fprintf(fp, ", ");
			fprintf(fp, "%s %s", describe_type_short(myscope, nt->type), nt->name);
		}
		fprintf(fp, ")</em></dt>\n");

		fprintf(fp, "<dd>\n");
		if (method->description)
			fprintf(fp, "%s\n", method->description);

		for (i = 0; i < method->arguments.count; ++i) {
			const ni_xs_name_type_t *nt = &method->arguments.data[i];
			const ni_xs_type_t *type = nt->type;
			const xml_node_t *mapnode;
			ni_bool_t printed = FALSE;

			if (type->meta && (mapnode = xml_node_get_child(type->meta, "mapping")) != NULL) {
				const char *docnode;

				if ((docnode = xml_node_get_attr(mapnode, "document-node")) != NULL) {
					while (*docnode == '/')
						++docnode;

					fprintf(fp, "<p>Argument <em>%s</em> is mapped to ", nt->name);
					if (*docnode == '\0')
						fprintf(fp, "the root element of the device document.\n");
					else if (strchr(docnode, '/') == NULL)
						fprintf(fp, "element &lt;%s&gt; of the device document.\n",
							docnode);
					else
						fprintf(fp, "an element of the device document referenced via xpath \"%s\".\n",
							docnode);
					printed = TRUE;
				}
			}
			if (render_description(fp, nt->description))
				printed = TRUE;
			if (type->refcount == 1) {
				if (!printed)
					fprintf(fp, "<p>Argument <em>%s</em> is ", nt->name);
				else
					fprintf(fp, "It is ");
				describe_type(fp, NULL, myscope, type);
				printed = TRUE;
			}
		}
		fprintf(fp, "<p></dd>\n");
	}
	fprintf(fp, "</dl>\n");
}

const char *
ni_xs_service_get_attribute(const ni_xs_service_t *xs_service, const char *name, const char *defval)
{
	const ni_var_t *var;

	if ((var = ni_var_array_get(&xs_service->attributes, name)) != NULL)
		return var->value;
	return defval;
}

static unsigned int
__ni_xs_service_count_methods(const ni_xs_method_t *list)
{
	unsigned int count = 0;

	while (list) {
		list = list->next;
		++count;
	}

	return count;
}

static void
describe_method_list_table(FILE *fp, const char *what, const ni_xs_method_t *list)
{
	const ni_xs_method_t *method;
	unsigned int count;

	if (list == NULL) {
		fprintf(fp, "<tr>\n");
		fprintf(fp, " <td>%s</td>\n", what);
		fprintf(fp, " <td>none</td>\n");
		fprintf(fp, "</tr>\n");
		return;
	}

	fprintf(fp, "<tr>\n");
	fprintf(fp, " <td rowspan=\"%u\" valign=\"top\">%s</td>\n", __ni_xs_service_count_methods(list), what);
	for (count = 0, method = list; method != NULL; ++count, method = method->next) {
		if (count)
			fprintf(fp, "<tr>\n");
		fprintf(fp, " <td><a href=\"#%s\">%s()</a></td>\n", method->name, method->name);
		fprintf(fp, "</tr>\n");
	}
}

static void
describe_properties_table(FILE *fp, const ni_xs_scope_t *myscope, const ni_xs_type_t *type)
{
	ni_xs_dict_info_t *dict_info = type? type->u.dict_info : NULL;
	unsigned int j;

	if (dict_info == NULL || dict_info->children.count == 0) {
		fprintf(fp, "<tr>\n");
		fprintf(fp, " <td>Properties</td>\n");
		fprintf(fp, " <td>none</td>\n");
		fprintf(fp, "</tr>\n");
		return;
	}

	fprintf(fp, "<tr>\n");
	fprintf(fp, " <td rowspan=\"%u\" valign=\"top\">Properties</td>\n", dict_info->children.count);

	for (j = 0; j < dict_info->children.count; ++j) {
		ni_xs_name_type_t *nt = &dict_info->children.data[j];

		if (j)
			fprintf(fp, "<tr>\n");
		fprintf(fp, " <td><a href=\"#property:%s\">%s</a></td>\n", nt->name, nt->name);
		fprintf(fp, "</tr>\n");
	}
}

static void
describe_service(FILE *fp, const ni_xs_service_t *xs_service)
{
	const ni_xs_scope_t *scope = NULL;
	const ni_xs_type_t *properties;

	fprintf(fp, "<h1>%s</h1>\n", xs_service->interface);

	if (xs_service->description) {
		fprintf(fp, "\n<h2>Synopsis</h2>\n");
		render_description(fp, xs_service->description);
	}

	scope = ni_xs_scope_lookup_scope(schema, xs_service->name);
	if (scope == NULL)
		ni_fatal("service %s has no namespace", xs_service->interface);

	properties = ni_xs_scope_lookup_local(scope, "properties");


	fprintf(fp, "\n<h2>Namespace</h2>\n");

	fprintf(fp, "\n<p>\n<table border=\"1\">\n");
	fprintf(fp, "<tr>\n");
	fprintf(fp, " <td style=\"width:200px\">Namespace</td>\n");
	fprintf(fp, " <td style=\"width:500px\">%s</td>\n", xs_service->name);
	fprintf(fp, "</tr>\n");
	fprintf(fp, "<tr>\n");
	fprintf(fp, " <td>Class compat</td>\n");
	fprintf(fp, " <td>%s</td>\n", ni_xs_service_get_attribute(xs_service, "object-class", "none"));
	fprintf(fp, "</tr>\n");
	fprintf(fp, "<tr>\n");
	fprintf(fp, " <td>Typedefs</td>\n");
	fprintf(fp, " <td>%u</td>\n", scope->types.count);
	fprintf(fp, "</tr>\n");

	describe_properties_table(fp, scope, properties);
	describe_method_list_table(fp, "Methods", xs_service->methods);
	describe_method_list_table(fp, "Signals", xs_service->signals);

	fprintf(fp, "</table><p>\n");

	describe_properties(fp, scope, properties);

	describe_methods(fp, scope, "Method", xs_service->methods);
	describe_methods(fp, scope, "Signal", xs_service->signals);
	describe_typedefs(fp, scope);

	fprintf(fp, "\n\n");
}

/*
 * Describe scopes not defined by a <service> definition
 */
static void
describe_scope(FILE *fp, const ni_xs_scope_t *scope)
{
	fprintf(fp, "<h1>Namespace %s</h1>\n", absolute_namespace_path(scope));

	describe_typedefs(fp, scope);
	fprintf(fp, "\n\n");
}
