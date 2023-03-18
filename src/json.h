/*
 *	An elementary JSON implementation
 *
 *	Copyright (C) 2015-2023 SUSE LLC
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
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski
 *		Jorik Cronenberg
 */
#ifndef NI_JSON_H
#define NI_JSON_H

#include <stdint.h>
#include <wicked/util.h>


typedef enum {
	NI_JSON_TYPE_NONE = 0U,
	NI_JSON_TYPE_NULL,
	NI_JSON_TYPE_BOOL,
	NI_JSON_TYPE_INT64,
	NI_JSON_TYPE_DOUBLE,
	NI_JSON_TYPE_STRING,
	NI_JSON_TYPE_OBJECT,
	NI_JSON_TYPE_ARRAY
} ni_json_type_t;

typedef struct ni_json			ni_json_t;
typedef struct ni_json_array		ni_json_array_t;
typedef struct ni_json_pair		ni_json_pair_t;
typedef struct ni_json_object		ni_json_object_t;

extern	ni_json_type_t			ni_json_type(const ni_json_t *);
extern	const char *			ni_json_type_name(ni_json_type_t type);
#define	ni_json_is_null(json)		(ni_json_type(json) == NI_JSON_TYPE_NULL)
#define	ni_json_is_bool(json)		(ni_json_type(json) == NI_JSON_TYPE_BOOL)
#define	ni_json_is_int64(json)		(ni_json_type(json) == NI_JSON_TYPE_INT64)
#define	ni_json_is_double(json)		(ni_json_type(json) == NI_JSON_TYPE_DOUBLE)
#define	ni_json_is_number(json)		(ni_json_is_int64(json) || ni_json_is_double(json))
#define	ni_json_is_string(json)		(ni_json_type(json) == NI_JSON_TYPE_STRING)
#define	ni_json_is_object(json)		(ni_json_type(json) == NI_JSON_TYPE_OBJECT)
#define	ni_json_is_array(json)		(ni_json_type(json) == NI_JSON_TYPE_ARRAY)

extern	ni_json_t *			ni_json_new_null(void);
extern	ni_json_t *			ni_json_new_bool(ni_bool_t);
extern	ni_json_t *			ni_json_new_int64(int64_t);
extern	ni_json_t *			ni_json_new_double(double);
extern	ni_json_t *			ni_json_new_string(const char *);
extern	ni_json_t *			ni_json_new_object(void);
extern	ni_json_t *			ni_json_new_array(void);
extern	ni_json_t *			ni_json_new_number(const char *);
extern	ni_json_t *			ni_json_new_literal(const char *);

extern	ni_json_t *			ni_json_clone(const ni_json_t *);
extern	ni_json_t *			ni_json_ref(ni_json_t *);
extern	void				ni_json_free(ni_json_t *);

extern	ni_bool_t			ni_json_bool_get(ni_json_t *, ni_bool_t *);
extern	ni_bool_t			ni_json_int64_get(ni_json_t *, int64_t *);
extern	ni_bool_t			ni_json_double_get(ni_json_t *, double *);
extern	ni_bool_t			ni_json_string_get(ni_json_t *, char **);

extern	ni_json_t *			ni_json_array_get(ni_json_t *, unsigned int);
extern	ni_json_t *			ni_json_array_ref(ni_json_t *, unsigned int);
extern  ni_bool_t			ni_json_array_set(ni_json_t *, unsigned int, ni_json_t *);
extern  ni_bool_t			ni_json_array_insert(ni_json_t *, unsigned int, ni_json_t *);
extern  ni_bool_t			ni_json_array_append(ni_json_t *, ni_json_t *);
extern	unsigned int			ni_json_array_entries(ni_json_t *);
extern	ni_json_t *			ni_json_array_remove_at(ni_json_t *, unsigned int);
extern	ni_bool_t			ni_json_array_delete_at(ni_json_t *, unsigned int);

extern	ni_json_pair_t *		ni_json_pair_new(const char *name, ni_json_t *value);
extern	ni_json_pair_t *		ni_json_pair_ref(ni_json_pair_t *);
extern	void				ni_json_pair_free(ni_json_pair_t *);
extern	const char *			ni_json_pair_get_name(ni_json_pair_t *);
extern	ni_json_t *			ni_json_pair_get_value(ni_json_pair_t *);
extern	ni_json_t *			ni_json_pair_ref_value(ni_json_pair_t *);
extern	ni_bool_t			ni_json_pair_set_value(ni_json_pair_t *, ni_json_t *);

extern	ni_json_pair_t *		ni_json_object_get_pair(ni_json_t *, const char *);
extern	ni_json_pair_t *		ni_json_object_get_pair_at(ni_json_t *, unsigned int);
extern	ni_json_t *			ni_json_object_get_value(ni_json_t *, const char *);
extern	ni_json_pair_t *		ni_json_object_ref_pair_at(ni_json_t *, unsigned int);
extern	ni_json_pair_t *		ni_json_object_ref_pair(ni_json_t *, const char *);
extern	ni_json_t *			ni_json_object_ref_value(ni_json_t *, const char *);
extern	ni_bool_t			ni_json_object_set(ni_json_t *, const char *, ni_json_t *);
extern	ni_json_t *			ni_json_object_remove(ni_json_t *, const char *);
extern	ni_json_t *			ni_json_object_remove_at(ni_json_t *, unsigned int);
extern	ni_bool_t			ni_json_object_delete(ni_json_t *, const char *);
extern	ni_bool_t			ni_json_object_delete_at(ni_json_t *, unsigned int);
extern	unsigned int			ni_json_object_entries(ni_json_t *);


typedef enum {
	NI_JSON_ESCAPE_SLASH	= NI_BIT(0),
} ni_json_format_flags_t;

typedef struct {
	ni_json_format_flags_t	flags;
	unsigned int		indent;
} ni_json_format_options_t;

#define NI_JSON_INDENT_DEPTH		2	/* default indent depth */
#define NI_JSON_OPTIONS_INIT		{ .flags = 0, .indent = NI_JSON_INDENT_DEPTH }

extern	const char *			ni_json_format_string(ni_stringbuf_t *,
							const ni_json_t *,
							const ni_json_format_options_t *);

extern	ni_json_t *			ni_json_parse_string(const char *str);

#endif /* NI_JSON_H */
