/**
 *	Copyright (C) 2021 SUSE LLC
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
 *		Clemens Famulla-Conrad <cfamullaconrad@suse.com>
 *
 *	Description:
 *		Test for bitmap util functions
 *		* ni_parse_bitmap_array()
 *		* ni_parse_bitmap_string()
 *		* ni_format_bitmap_array()
 *		* ni_format_bitmap_string()
 *		* ni_format_bitmap()
 */

#include <stdarg.h>
#include <wicked/util.h>
#include <wicked/logging.h>


void string_array_set(ni_string_array_t *arr, ...)
{
	va_list ap;
	const char *s;

	ni_string_array_destroy(arr);

	va_start(ap, arr);
	while((s = va_arg(ap, const char *))){
		ni_string_array_append(arr, s);
	}
	va_end(ap);
}

ni_bool_t string_array_eq(ni_string_array_t *arr, ...)
{
	va_list ap;
	const char *s;
	size_t cnt = 0;

	va_start(ap, arr);
	while((s = va_arg(ap, const char *))){
		cnt++;
		if (ni_string_array_index(arr, s) < 0){
			va_end(ap);
			return FALSE;
		}
	}
	va_end(ap);
	return arr->count == cnt;
}

int main(int argc, char *argv[])
{
	enum {
		MY_GET = 0,
		MY_SET
	};

	ni_intmap_t map[] =  {
		{ "GET",	MY_GET},
		{ "SET",	MY_SET},
		/* aliases */
		{ "READ",	MY_GET},
		{ "WRITE",	MY_SET},
	};

	unsigned int mask_out = 0;
	unsigned int done_out = 0;
	unsigned int mask_in = 0;
	ni_string_array_t array_in = NI_STRING_ARRAY_INIT;
	ni_string_array_t array_out = NI_STRING_ARRAY_INIT;
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;
	ni_stringbuf_t string_out = NI_STRINGBUF_INIT_DYNAMIC;

#define CLEANUP() \
	ni_string_array_destroy(&array_in);	\
	ni_string_array_destroy(&array_out);	\
	ni_string_array_destroy(&invalid);	\
	ni_stringbuf_destroy(&string_out);	\
	mask_out = done_out = mask_in = 0;

	/* ni_parse_bitmap_array() */
	CLEANUP();
	mask_out = NI_BIT(MY_SET);
	ni_string_array_append(&invalid, "invalid");
	string_array_set(&array_in, "GET", NULL);
	ni_assert(ni_parse_bitmap_array(&mask_out, map, &array_in, NULL) == 0);
	ni_assert(string_array_eq(&invalid, "invalid", NULL));
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));

	CLEANUP();
	string_array_set(&array_in, "GET", "SET", NULL);
	ni_assert(ni_parse_bitmap_array(&mask_out, map, &array_in, &invalid) == 0);
	ni_assert(invalid.count == 0);
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));

	CLEANUP();
	string_array_set(&array_in, "GET", "SET", "WRITE", NULL);
	ni_assert(ni_parse_bitmap_array(&mask_out, map, &array_in, &invalid) == 0);
	ni_assert(invalid.count == 0);
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));

	CLEANUP();
	string_array_set(&array_in, "GET", "SET", "WRITE", "DUMP", NULL);
	ni_assert(ni_parse_bitmap_array(&mask_out, map, &array_in, &invalid) == 1);
	ni_assert(string_array_eq(&invalid, "DUMP", NULL));
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));
	ni_string_array_destroy(&invalid);

	CLEANUP();
	string_array_set(&array_in, "GET", "SET", "WRITE", "DUMP", "BLUMP", NULL);
	ni_assert(ni_parse_bitmap_array(&mask_out, map, &array_in, &invalid) == 2);
	ni_assert(string_array_eq(&invalid, "DUMP", "BLUMP", NULL));
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));
	ni_string_array_destroy(&invalid);

	/* ni_parse_bitmap_string() */
	CLEANUP();
	mask_out = NI_BIT(MY_SET);
	ni_string_array_append(&invalid, "Some garbage!!");
	ni_assert(ni_parse_bitmap_string(&mask_out, map, "GET", "|", &invalid) == 0);
	ni_assert(string_array_eq(&invalid, "Some garbage!!", NULL));
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));

	CLEANUP();
	ni_assert(ni_parse_bitmap_string(&mask_out, map, "WRITE|GET", "|", &invalid) == 0);
	ni_assert(invalid.count == 0);
	ni_assert(mask_out == (NI_BIT(MY_GET) | NI_BIT(MY_SET)));


	/* ni_format_bitmap_array() */
	CLEANUP();
	mask_in = 0;
	done_out = 0;
	ni_string_array_append(&array_out, "Some garbage!!");
	ni_assert(ni_format_bitmap_array(&array_out, map, mask_in, &done_out) == 0);
	ni_assert(string_array_eq(&array_out, "Some garbage!!", NULL));
	ni_assert(done_out == mask_in);

	CLEANUP();
	mask_in = NI_BIT(MY_GET);
	ni_assert(ni_format_bitmap_array(&array_out, map, mask_in, &done_out) == 0);
	ni_assert(string_array_eq(&array_out, "GET", NULL));
	ni_assert(done_out == mask_in);

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET);
	ni_assert(ni_format_bitmap_array(&array_out, map, mask_in, &done_out) == 0);
	ni_assert(string_array_eq(&array_out, "GET", "SET", NULL));
	ni_assert(done_out == mask_in);

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET) | NI_BIT(5);
	ni_assert(ni_format_bitmap_array(&array_out, map, mask_in, &done_out) == NI_BIT(5));
	ni_assert(string_array_eq(&array_out, "GET", "SET", NULL));
	ni_assert((done_out ^ mask_in) == NI_BIT(5));


	/* ni_format_bitmap_string() */
	CLEANUP();
	mask_in = 0;
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, NULL, "|"), NULL));

	CLEANUP();
	mask_in = 0;
	done_out = 0xf0;
	ni_stringbuf_puts(&string_out, "Some garbage!!");
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, NULL, "|"), ""));
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, "|"), ""));
	ni_assert(done_out == 0xf0);
	ni_assert(ni_string_eq(string_out.string, "Some garbage!!"));

	CLEANUP();
	mask_in = NI_BIT(MY_GET);
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, "|"), "GET"));
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, "#"), "#GET"));
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, NULL), "|GET"));
	ni_assert(done_out == mask_in);
	ni_assert(ni_string_eq(string_out.string, "GET#GET|GET"));

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET);
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, "|"), "GET|SET"));
	ni_assert(done_out == mask_in);

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET) | NI_BIT(5);
	ni_assert(ni_string_eq(ni_format_bitmap_string(&string_out, map, mask_in, &done_out, "|"), "GET|SET"));
	ni_assert((done_out ^ mask_in) == NI_BIT(5));

	/* ni_format_bitmap() */
	CLEANUP();
	mask_in = 0;
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "|"), NULL));

	CLEANUP();
	mask_in = 0;
	ni_stringbuf_puts(&string_out, "Some garbage!!");
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "|"), ""));
	ni_assert(ni_string_eq(string_out.string, "Some garbage!!"));

	CLEANUP();
	mask_in = NI_BIT(MY_GET);
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "|"), "GET"));
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, NULL), "|GET"));
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "#"), "#GET"));
	ni_assert(ni_string_eq(string_out.string, "GET|GET#GET"));

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET);
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "|"), "GET|SET"));

	CLEANUP();
	mask_in = NI_BIT(MY_GET) | NI_BIT(MY_SET) | NI_BIT(5);
	ni_assert(ni_string_eq(ni_format_bitmap(&string_out, map, mask_in, "|"), "GET|SET"));

	printf("ALL TEST SUCCESSFUL!\n");
	return 0;
}
