/*
 *	VERY limited XML read/write implementation
 *	This basically parses tags, attributes and CDATA, and that's
 *	just about it.
 *
 *	Copyright (C) 2009-2012  Olaf Kirch <okir@suse.de>
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

#include <ctype.h>
#include <sys/param.h>

#include <wicked/xml.h>
#include <wicked/logging.h>
#include "buffer.h"

#undef XMLDEBUG_PARSER

typedef enum {
	Initial = 0,
	Tag,
	Error
} xml_parser_state_t;

typedef enum {
	None = 0,
	EndOfDocument,
	LeftAngle, RightAngle,
	LeftAngleQ, RightAngleQ,
	LeftAngleSlash, RightAngleSlash,
	LeftAngleExclam,
	Identifier, Equals, QuotedString,
	CData,
	Comment,
} xml_token_type_t;

#define XML_READER_BUFSZ	512
typedef struct xml_reader {
	const char *		filename;

	ni_buffer_t *		in_buffer;

	FILE *			file;
	unsigned char *		buffer;		/* FIXME: use in_buffer for this as well */

	unsigned int		no_close : 1;

	char *			doctype;

	/* This pointer must be unsigned char, else 0xFF would
	 * be expanded to EOF */
	unsigned char *		pos;

	xml_parser_state_t	state;
	unsigned int		lineCount;

	struct xml_location_shared *shared_location;
} xml_reader_t;

static xml_document_t *	xml_process_document(xml_reader_t *);
static ni_bool_t	xml_process_element_nested(xml_reader_t *, xml_node_t *, unsigned int);
static ni_bool_t	xml_get_identifier(xml_reader_t *, ni_stringbuf_t *);
static xml_token_type_t	xml_get_token(xml_reader_t *, ni_stringbuf_t *);
static xml_token_type_t	xml_get_token_initial(xml_reader_t *, ni_stringbuf_t *);
static xml_token_type_t	xml_get_token_tag(xml_reader_t *, ni_stringbuf_t *);
static xml_token_type_t	xml_skip_comment(xml_reader_t *);
static xml_token_type_t	xml_get_tag_attributes(xml_reader_t *, xml_node_t *);
static ni_bool_t	xml_expand_entity(xml_reader_t *, ni_stringbuf_t *);
static void		xml_skip_space(xml_reader_t *, ni_stringbuf_t *);
static void		xml_parse_error(xml_reader_t *, const char *, ...);
static const char *	xml_parser_state_name(xml_parser_state_t);
static const char *	xml_token_name(xml_token_type_t token);

static xml_location_t *	xml_location_new(struct xml_location_shared *, unsigned int);

#ifdef XMLDEBUG_PARSER
static void		xml_debug(const char *, ...);
#else
#define xml_debug(fmt, ...) do { } while (0)
#endif

static int		xml_reader_init_file(xml_reader_t *xr, FILE *fp, const char *location);
static int		xml_reader_init_buffer(xml_reader_t *xr, ni_buffer_t *buf, const char *location);
static int		xml_reader_open(xml_reader_t *xr, const char *filename);
static int		xml_reader_destroy(xml_reader_t *xr);
static int		xml_getc(xml_reader_t *xr);
static void		xml_ungetc(xml_reader_t *xr, int cc);

/*
 * Document reader implementation
 */
xml_document_t *
xml_document_read(const char *filename)
{
	xml_reader_t reader;
	xml_document_t *doc;

	if (!strcmp(filename, "-")) {
		if (xml_reader_init_file(&reader, stdin, NULL) < 0)
			return NULL;
	} else
	if (xml_reader_open(&reader, filename) < 0)
		return NULL;

	doc = xml_process_document(&reader);
	if (xml_reader_destroy(&reader) < 0) {
		xml_document_free(doc);
		return NULL;
	}
	return doc;
}

xml_document_t *
xml_document_from_string(const char *string, const char *location)
{
	ni_buffer_t buf;

	if (string == NULL) {
		ni_error("%s: argument string is NULL", __func__);
		return NULL;
	}
	ni_buffer_init_reader(&buf, (char *) string, strlen(string));
	return xml_document_from_buffer(&buf, location);
}

xml_document_t *
xml_document_from_buffer(ni_buffer_t *in_buffer, const char *location)
{
	xml_reader_t reader;
	xml_document_t *doc;

	if (xml_reader_init_buffer(&reader, in_buffer, location) < 0)
		return NULL;

	doc = xml_process_document(&reader);
	if (xml_reader_destroy(&reader) < 0) {
		xml_document_free(doc);
		return NULL;
	}
	return doc;
}

xml_document_t *
xml_document_scan(FILE *fp, const char *location)
{
	xml_reader_t reader;
	xml_document_t *doc;

	if (xml_reader_init_file(&reader, fp, location) < 0)
		return NULL;

	doc = xml_process_document(&reader);
	if (xml_reader_destroy(&reader) < 0) {
		xml_document_free(doc);
		return NULL;
	}
	return doc;
}

xml_document_t *
xml_process_document(xml_reader_t *xr)
{
	xml_document_t *doc;
	xml_node_t *root;

	doc = xml_document_new();

	root = xml_document_root(doc);
	if (xr->shared_location)
		root->location = xml_location_new(xr->shared_location, xr->lineCount);

	/* Note! We do not deal with properly formatted XML documents here.
	 * Specifically, we do not expect them to have a document header. */
	if (!xml_process_element_nested(xr, root, 0)) {
		xml_document_free(doc);
		return NULL;
	}
	return doc;
}

xml_node_t *
xml_node_scan(FILE *fp, const char *location)
{
	xml_reader_t reader;
	xml_node_t *root = xml_node_new(NULL, NULL);

	if (xml_reader_init_file(&reader, fp, location) < 0)
		return NULL;

	if (reader.shared_location)
		root->location = xml_location_new(reader.shared_location, reader.lineCount);

	/* Note! We do not deal with properly formatted XML documents here.
	 * Specifically, we do not expect them to have a document header. */
	if (!xml_process_element_nested(&reader, root, 0)) {
		xml_node_free(root);
		return NULL;
	}

	if (xml_reader_destroy(&reader) < 0) {
		xml_node_free(root);
		return NULL;
	}
	return root;
}

static void
xml_process_pi_node(xml_reader_t *xr, xml_node_t *pi)
{
	const char *attrval;

	if (!strcmp(pi->name, "xml")) {
		if ((attrval = xml_node_get_attr(pi, "version")) != NULL
		 && strcmp(attrval, "1.0"))
			ni_warn("unexpected XML version %s", attrval);

		if ((attrval = xml_node_get_attr(pi, "encoding")) != NULL
		 && strcasecmp(attrval, "utf8")) {
			/* TBD: set up iconv to translate from encoding to utf8,
			   and make sure we process all input that way. */
		}
	}
		
}

ni_bool_t
xml_process_element_nested(xml_reader_t *xr, xml_node_t *cur, unsigned int nesting)
{
	ni_stringbuf_t tokenValue, identifier;
	xml_token_type_t token;
	xml_node_t *child;

	ni_stringbuf_init(&tokenValue);
	ni_stringbuf_init(&identifier);

	while (1) {
		token = xml_get_token(xr, &tokenValue);

		switch (token) {
		case CData:
			/* process element content */
			xml_node_set_cdata(cur, tokenValue.string);
			break;

		case LeftAngleExclam:
			/* Most likely <!DOCTYPE ...> */
			if (!xml_get_identifier(xr, &identifier)) {
				xml_parse_error(xr, "Bad element: tag open <! not followed by identifier");
				goto error;
			}

			if (strcmp(identifier.string, "DOCTYPE")) {
				xml_parse_error(xr, "Unexpected element: <!%s ...> not supported", identifier.string);
				goto error;
			}

			while (1) {
				token = xml_get_token(xr, &identifier);
				if (token == RightAngle)
					break;
				if (token == Identifier && !xr->doctype)
					ni_string_dup(&xr->doctype, identifier.string);
				if (token != Identifier && token != QuotedString) {
					xml_parse_error(xr, "Error parsing <!DOCTYPE ...> attributes");
					goto error;
				}
			}
			break;

		case LeftAngle:
			/* New element start */
			if (!xml_get_identifier(xr, &identifier)) {
				xml_parse_error(xr, "Bad element: tag open < not followed by identifier");
				goto error;
			}

			child = xml_node_new(identifier.string, cur);
			if (xr->shared_location)
				child->location = xml_location_new(xr->shared_location, xr->lineCount);

			token = xml_get_tag_attributes(xr, child);
			if (token == None) {
				xml_parse_error(xr, "Error parsing <%s ...> tag attributes", child->name);
				goto error;
			} else
			if (token == RightAngle) {
				/* Handle <foo>...</foo> */
				xml_debug("%*.*s<%s>\n", nesting, nesting, "", child->name);
				if (!xml_process_element_nested(xr, child, nesting + 2))
					goto error;
			} else if (token == RightAngleSlash) {
				/* We parsed a "<foo/>" element - nothing left to do, we're done */
				xml_debug("%*.*s<%s/>\n", nesting, nesting, "", child->name);
			} else {
				xml_parse_error(xr, "Unexpected token %s at end of <%s ...",
						xml_token_name(token), child->name);
				goto error;
			}

			break;

		case LeftAngleSlash:
			/* Element end */
			if (!xml_get_identifier(xr, &identifier)) {
				xml_parse_error(xr, "Bad element: end tag open </ not followed by identifier");
				goto error;
			}

			if (xml_get_token(xr, &tokenValue) != RightAngle) {
				xml_parse_error(xr, "Bad element: </%s - missing tag close", identifier.string);
				goto error;
			}

			if (cur->parent == NULL) {
				xml_parse_error(xr, "Unexpected </%s> tag", identifier.string);
				goto error;
			}
			if (strcmp(cur->name, identifier.string)) {
				xml_parse_error(xr, "Closing tag </%s> does not match <%s>",
						identifier.string, cur->name);
				goto error;
			}

			xml_debug("%*.*s</%s>\n", nesting, nesting, "", cur->name);
			goto success;

		case LeftAngleQ:
			/* New PI node starts here */
			if (!xml_get_identifier(xr, &identifier)) {
				xml_parse_error(xr, "Bad element: tag open <? not followed by identifier");
				goto error;
			}

			child = xml_node_new(identifier.string, NULL);
			if (xr->shared_location)
				child->location = xml_location_new(xr->shared_location, xr->lineCount);

			token = xml_get_tag_attributes(xr, child);
			if (token == None) {
				xml_parse_error(xr, "Error parsing <?%s ...?> tag attributes", child->name);
				xml_node_free(child);
				goto error;
			} else
			if (token == RightAngleQ) {
				xml_debug("%*.*s<%s>\n", nesting, nesting, "", child->name);
				xml_process_pi_node(xr, child);
				xml_node_free(child);
			} else {
				xml_parse_error(xr, "Unexpected token %s at end of <?%s ...",
						xml_token_name(token), child->name);
				xml_node_free(child);
				goto error;
			}

			break;

		case EndOfDocument:
			if (cur->parent) {
				xml_parse_error(xr, "End of document while processing element <%s>", cur->name);
				goto error;
			}
			goto success;

		case None:
			/* parser error */
			goto error;

		default:
			xml_parse_error(xr, "Unexpected token %s", xml_token_name(token));
			goto error;
		}
	}

success:
	ni_stringbuf_destroy(&tokenValue);
	ni_stringbuf_destroy(&identifier);
	return TRUE;

error:
	ni_stringbuf_destroy(&tokenValue);
	ni_stringbuf_destroy(&identifier);
	return FALSE;
}

ni_bool_t
xml_get_identifier(xml_reader_t *xr, ni_stringbuf_t *res)
{
	return xml_get_token(xr, res) == Identifier;
}

xml_token_type_t
xml_get_tag_attributes(xml_reader_t *xr, xml_node_t *node)
{
	ni_stringbuf_t tokenValue, attrName, attrValue;
	xml_token_type_t token;

	ni_stringbuf_init(&tokenValue);
	ni_stringbuf_init(&attrName);
	ni_stringbuf_init(&attrValue);

	token = xml_get_token(xr, &tokenValue);
	while (1) {
		if (token == RightAngle || token == RightAngleQ || token == RightAngleSlash)
			break;

		if (token != Identifier) {
			xml_parse_error(xr, "Unexpected token in tag attributes");
			token = None;
			break;
		}

		ni_stringbuf_move(&attrName, &tokenValue);

		token = xml_get_token(xr, &tokenValue);
		if (token != Equals) {
			xml_node_add_attr(node, attrName.string, NULL);
			continue;
		}

		token = xml_get_token(xr, &tokenValue);
		if (token != QuotedString) {
			xml_parse_error(xr, "Attribute value not a quoted string!");
			token = None;
			break;
		}

		xml_debug("  attr %s=%s\n", attrName.string, tokenValue.string);
		xml_node_add_attr(node, attrName.string, tokenValue.string);

		token = xml_get_token(xr, &tokenValue);
	}

	ni_stringbuf_destroy(&tokenValue);
	ni_stringbuf_destroy(&attrName);
	ni_stringbuf_destroy(&attrValue);
	return token;
}

/*
 * Get the next token from the XML stream
 */
xml_token_type_t
xml_get_token(xml_reader_t *xr, ni_stringbuf_t *res)
{
#ifdef XMLDEBUG_PARSER
	xml_parser_state_t old_state = xr->state;
#endif
	xml_token_type_t token;

	ni_stringbuf_clear(res);
	switch (xr->state) {
	default:
		xml_parse_error(xr, "Unexpected state %u in XML reader", xr->state);
		return None;

	case Error:
		return None;

	case Initial:
		token = xml_get_token_initial(xr, res);
		break;

	case Tag:
		token = xml_get_token_tag(xr, res);
		break;
	}

	xml_debug("++ %3u %-7s %-10s (%s)\n",
			xr->lineCount,
			xml_parser_state_name(old_state),
			xml_token_name(token),
			res->string?: "");
	return token;
}


/*
 * While in state Initial, obtain the next token
 */
xml_token_type_t
xml_get_token_initial(xml_reader_t *xr, ni_stringbuf_t *res)
{
	xml_token_type_t token;
	int cc;

restart:
	/* Eat initial white space and store it in @res */
	xml_skip_space(xr, res);

	cc = xml_getc(xr);
	if (cc == EOF) {
		ni_stringbuf_clear(res);
		return EndOfDocument;
	}

	if (cc == '<') {
		/* Discard the white space in @res - we're not interested in that. */
		ni_stringbuf_clear(res);

		ni_stringbuf_putc(res, cc);

		if (xr->state != Initial) {
			xml_parse_error(xr, "Unexpected < in XML stream (state %s)",
					xml_parser_state_name(xr->state));
			return None;
		}

		/* tag is legal here */
		xr->state = Tag;

		cc = xml_getc(xr);
		switch (cc) {
		case '/':
			ni_stringbuf_putc(res, cc);
			return LeftAngleSlash;
		case '?':
			ni_stringbuf_putc(res, cc);
			return LeftAngleQ;
		case '!':
			ni_stringbuf_putc(res, cc);

			/* If it's <!IDENTIFIER, return LeftAngleExclam */
			cc = xml_getc(xr);
			if (cc != '-') {
				xml_ungetc(xr, cc);
				return LeftAngleExclam;
			}

			token = xml_skip_comment(xr);
			if (token == Comment) {
				xr->state = Initial;
				ni_stringbuf_clear(res);
				goto restart;
			}
			return token;
		default:
			xml_ungetc(xr, cc);
			break;
		}
		return LeftAngle;
	}

	// Looks like CDATA. 
	// Ignore initial newline, then scan to next <
	do {
		if (cc == '<') {
			/* Looks like we're done.
			 * FIXME: handle comments within CDATA?
			 */
			xml_ungetc(xr, cc);
			break;
		} else
		if (cc == '&') {
			if (!xml_expand_entity(xr, res))
				return None;
		} else {
			ni_stringbuf_putc(res, cc);
		}

		cc = xml_getc(xr);
	} while (cc != EOF);

	ni_stringbuf_trim_empty_lines(res);

	return CData;
}


xml_token_type_t
xml_get_token_tag(xml_reader_t *xr, ni_stringbuf_t *res)
{
	int cc, oc;

	xml_skip_space(xr, NULL);

	cc = xml_getc(xr);
	if (cc == EOF) {
		xml_parse_error(xr, "Unexpected EOF while parsing tag");
		return None;
	}

	ni_stringbuf_putc(res, cc);

	switch (cc) {
	case '<':
		goto error;

	case '?':
		if ((cc = xml_getc(xr)) != '>')
			goto error;
		ni_stringbuf_putc(res, cc);
		xr->state = Initial;
		return RightAngleQ;

	case '>':
		xr->state = Initial;
		return RightAngle;

	case '/':
		if ((cc = xml_getc(xr)) != '>')
			goto error;
		ni_stringbuf_putc(res, cc);
		xr->state = Initial;
		return RightAngleSlash;

	case '=':
		return Equals;

	case 'a' ... 'z':
	case 'A' ... 'Z':
	case '_':
	case '!':
		while ((cc = xml_getc(xr)) != EOF) {
			if (!isalnum(cc) && cc != '_' && cc != '!' && cc != ':' && cc != '-') {
				xml_ungetc(xr, cc);
				break;
			}
			ni_stringbuf_putc(res, cc);
		}
		return Identifier;

	case '\'':
	case '"':
		ni_stringbuf_clear(res);
		oc = cc;
		while (1) {
			cc = xml_getc(xr);
			if (cc == EOF) {
				xml_parse_error(xr, "Unexpected EOF while parsing quoted string");
				return None;
			}
			if (cc == oc)
				break;
			ni_stringbuf_putc(res, cc);
		}
		return QuotedString;

	default:
		break;
	}

error:
	xml_parse_error(xr, "Unexpected character %c in XML document", cc);
	return None;
}

/*
 * Process command. When we get here, we've processed "<!-"
 */
xml_token_type_t
xml_skip_comment(xml_reader_t *xr)
{
	int match = 0, cc;

	if (xml_getc(xr) != '-') {
		xml_parse_error(xr, "Unexpected <!-...> element");
		return None;
	}

	while ((cc = xml_getc(xr)) != EOF) {
		if (cc == '-') {
			match++;
		} else {
			if (cc == '>' && match >= 2) {
#ifdef XMLDEBUG_PARSER
				xml_debug("Processed comment\n");
#endif
				return Comment;
			}
			match = 0;
		}
	}

	xml_parse_error(xr, "Unexpected end of file while parsing comment");
	return None;
}


/*
 * Expand an XML entity.
 * For now, we support &<number>; as well as symbolic entities
 *   lt gt amp
 */
ni_bool_t
xml_expand_entity(xml_reader_t *xr, ni_stringbuf_t *res)
{
	char temp[128];
	ni_stringbuf_t entity = NI_STRINGBUF_INIT_BUFFER(temp);
	int cc, expanded;

	while ((cc = xml_getc(xr)) != ';') {
		if (cc == EOF) {
			xml_parse_error(xr, "Unexpenced EOF in entity");
			return FALSE;
		}
		if (isspace(cc))
			continue;
		if (entity.len + sizeof(char) >= entity.size) {
			xml_parse_error(xr, "Entity is too long");
			return FALSE;
		}
		ni_stringbuf_putc(&entity, cc);
	}

	if (ni_string_empty(entity.string)) {
		xml_parse_error(xr, "Empty entity &;");
		return FALSE;
	}

	if (!strcasecmp(entity.string, "lt"))
		expanded = '<';
	else if (!strcasecmp(entity.string, "gt"))
		expanded = '>';
	else if (!strcasecmp(entity.string, "amp"))
		expanded = '&';
	else {
		const char *es = entity.string;

		if (*es == '#') {
			expanded = strtoul(es + 1, (char **) &es, 0);
			if (*es == '\0')
				goto good;
		}

		xml_parse_error(xr, "Cannot expand unknown entity &%s;", entity.string);
		return FALSE;
	}

good:
	ni_stringbuf_putc(res, expanded);
	return TRUE;
}

/*
 * Skip any space in the input stream, and copy if to @result
 */
void
xml_skip_space(xml_reader_t *xr, ni_stringbuf_t *result)
{
	int cc;

	while ((cc = xml_getc(xr)) != EOF) {
		if (!isspace(cc)) {
			xml_ungetc(xr, cc);
			break;
		}

		if (result)
			ni_stringbuf_putc(result, cc);
	}
}

void
xml_parse_error(struct xml_reader *reader, const char *fmt, ...)
{
	char errmsg[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
	va_end(ap);

	ni_error("%s: line %u: %s", reader->filename, reader->lineCount, errmsg);
	reader->state = Error;
}

const char *
xml_token_name(xml_token_type_t token)
{
	switch (token) {
	case None:
		return "None";
	case EndOfDocument:
		return "EndOfDocument";
	case LeftAngle:
		return "LeftAngle";
	case RightAngle:
		return "RightAngle";
	case LeftAngleQ:
		return "LeftAngleQ";
	case RightAngleQ:
		return "RightAngleQ";
	case LeftAngleSlash:
		return "LeftAngleSlash";
	case RightAngleSlash:
		return "RightAngleSlash";
	case LeftAngleExclam:
		return "LeftAngleExclam";
	case Identifier:
		return "Identifier";
	case Equals:
		return "Equals";
	case QuotedString:
		return "QuotedString";
	case CData:
		return "CData";
	case Comment:
		return "Comment";
	}

	return "???";
}

const char *
xml_parser_state_name(xml_parser_state_t state)
{
	switch (state) {
	case Initial:
		return "Initial";
	case Tag:
		return "Tag";
	case Error:
		return "Error";
	}
	return "Unknown";
}

#ifdef XMLDEBUG_PARSER
void
xml_debug(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, ":: ");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#endif

/*
 * Location handling
 */
inline const char *
xml_node_location_filename(const xml_node_t *node)
{
	return node->location ? node->location->shared->filename : NULL;
}

inline unsigned int
xml_node_location_line(const xml_node_t *node)
{
	return node->location ? node->location->line : 0;
}

const char *
xml_node_location(const xml_node_t *node)
{
	static char buffer[PATH_MAX];

	if (node && node->location) {
		snprintf(buffer, sizeof(buffer), "%s:%u",
				node->location->shared->filename,
				node->location->line);
		return buffer;
	}

	return "<orphan xml node>";
}

struct xml_location_shared *
xml_location_shared_new(const char *filename)
{
	struct xml_location_shared *shared_location;

	shared_location = xcalloc(1, sizeof(*shared_location));
	shared_location->filename = xstrdup(filename);
	shared_location->refcount = 1;

	return shared_location;
}

static inline struct xml_location_shared *
xml_location_shared_hold(struct xml_location_shared *sl)
{
	if (sl)
		sl->refcount++;
	return sl;
}

static inline void
xml_location_shared_release(struct xml_location_shared *sl)
{
	ni_assert(sl->refcount);
	if (--(sl->refcount) == 0) {
		free(sl->filename);
		free(sl);
	}
}

xml_location_t *
xml_location_new(struct xml_location_shared *shared_location, unsigned int line)
{
	xml_location_t *location;

	shared_location->refcount++;
	location = xcalloc(1, sizeof(*location));
	location->shared = shared_location;
	location->line = line;

	return location;
}

inline xml_location_t *
xml_location_create(const char *filename, unsigned int line)
{
	xml_location_t *location;

	if (ni_string_empty(filename))
		return NULL;

	location = xml_location_new(xml_location_shared_new(filename), line);
	xml_location_shared_release(location->shared);
	return location;
}

void
xml_node_location_modify(xml_node_t *node, const char *filename)
{
	if (!node || ni_string_empty(filename))
		return;

	if (node->location) {
		struct xml_location_shared *sl;

		if ((sl = node->location->shared)) {
			ni_string_dup(&sl->filename, filename);
			return;
		}
	}
	xml_node_location_set(node, xml_location_create(filename, 0));
}

static void
__xml_node_location_relocate(xml_node_t *node, struct xml_location_shared *shared)
{
	xml_node_t *child;

	if (node->location) {
		if (node->location->shared)
			xml_location_shared_release(node->location->shared);
		node->location->shared = xml_location_shared_hold(shared);
	} else {
		xml_node_location_set(node, xml_location_new(shared, 0));
	}

	for (child = node->children; child; child = child->next)
		__xml_node_location_relocate(child, shared);
}

void
xml_node_location_relocate(xml_node_t *node, const char *filename)
{
	struct xml_location_shared *shared;

	if (node && !ni_string_empty(filename)) {
		if ((shared = xml_location_shared_new(filename))) {
			__xml_node_location_relocate(node, shared);
			xml_location_shared_release(shared);
		}
	}
}

void
xml_node_location_set(xml_node_t *node, xml_location_t *loc)
{
	if (node->location == loc)
		return;
	if (node->location)
		xml_location_free(node->location);

	node->location = loc;
}

xml_location_t *
xml_location_clone(const xml_location_t *loc)
{
	if (loc == NULL)
		return NULL;
	return xml_location_new(loc->shared, loc->line);
}

void
xml_location_free(xml_location_t *loc)
{
	xml_location_shared_release(loc->shared);
	free(loc);
}

/*
 * XML Reader object
 */
static int
xml_reader_open(xml_reader_t *xr, const char *filename)
{
	memset(xr, 0, sizeof(*xr));
	xr->filename = filename;

	xr->file = fopen(filename, "r");
	if (xr->file == NULL) {
		ni_error("Unable to open %s: %m", filename);
		return -1;
	}

	xr->buffer = xmalloc(XML_READER_BUFSZ);
	xr->state = Initial;
	xr->lineCount = 1;
	xr->shared_location = xml_location_shared_new(filename);
	return 0;
}

static int
xml_reader_init_file(xml_reader_t *xr, FILE *fp, const char *location)
{
	if (ni_string_empty(location))
		location = "<stdin>";

	memset(xr, 0, sizeof(*xr));
	xr->filename = location;
	xr->file = fp;
	xr->no_close = 1;

	xr->buffer = xmalloc(XML_READER_BUFSZ);
	xr->state = Initial;
	xr->lineCount = 1;
	xr->shared_location = xml_location_shared_new(location);

	return 0;
}

static int
xml_reader_init_buffer(xml_reader_t *xr, ni_buffer_t *buf, const char *location)
{
	if (ni_string_empty(location))
		location = "<buffer>";

	memset(xr, 0, sizeof(*xr));
	xr->filename = location;
	xr->in_buffer = buf;
	xr->no_close = 1;

	xr->state = Initial;
	xr->lineCount = 1;
	xr->shared_location = xml_location_shared_new(location);

	return 0;
}

int
xml_reader_destroy(xml_reader_t *xr)
{
	int rv = 0;

	if (xr->file && ferror(xr->file))
		rv = -1;
	if (xr->file && !xr->no_close) {
		fclose(xr->file);
		xr->file = NULL;
	}
	if (xr->buffer) {
		free(xr->buffer);
		xr->buffer = NULL;
	}

	if (xr->shared_location) {
		xml_location_shared_release(xr->shared_location);
		xr->shared_location = NULL;
	}
	return rv;
}

int
xml_getc(xml_reader_t *xr)
{
	int cc;

	if (xr->in_buffer) {
		cc = ni_buffer_getc(xr->in_buffer);
		if (cc == '\n')
			xr->lineCount++;
		return cc;
	}

	while (1) {
		if (xr->pos) {
			cc = *xr->pos++;
			if (cc == '\n')
				xr->lineCount++;
			if (cc != '\0')
				return cc;
			xr->pos = NULL;
		}

		if (xr->file == NULL) {
			/* Parsing just a string, no file backing */
			break;
		}

		if (fgets((char *)xr->buffer, XML_READER_BUFSZ, xr->file) == NULL)
			break;

		xr->pos = xr->buffer;
	}

	return EOF;
}

void
xml_ungetc(xml_reader_t *xr, int cc)
{
	if (xr->in_buffer) {
		if (ni_buffer_ungetc(xr->in_buffer, cc) < 0)
			ni_error("xml_ungetc: cannot put back");
		if (cc == '\n')
			xr->lineCount--;
		return;
	}

	if (xr->pos == NULL
	 || xr->pos == xr->buffer
	 || xr->pos[-1] != cc) {
		ni_error("xml_ungetc: cannot put back");
		ni_error("  buffer=%p pos=%p *pos=0x%x cc=0x%x",
				xr->buffer, xr->pos,
				xr->pos? xr->pos[-1] : 0,
				cc);
		return;
	}

	if (cc == '\n')
		xr->lineCount--;
	xr->pos--;
}

