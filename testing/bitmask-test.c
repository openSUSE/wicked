/**
 *	Copyright (C) 2022 SUSE LLC
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
 *		Clemens Famulla-Conrad
 *
 *	Description:
 *		Test for bitmask util functions
 *		* ni_parse_bitmask_array()
 *		* ni_parse_bitmask_string()
 *		* ni_parse_bitmask()
 *		* ni_format_bitmask_array()
 *		* ni_format_bitmask_string()
 *		* ni_format_bitmask()
 */

#include <wicked/util.h>
#include "wunit.h"


enum {
	MY_GET        = NI_BIT(0),
	MY_SET        = NI_BIT(1),
	MY_READ       = NI_BIT(2),
	MY_WRITE      = NI_BIT(3),
	UNKNOWN_VALUE = NI_BIT(15)
};

static const ni_intmap_t map[] =  {
	{ "ALL",        MY_GET | MY_SET | MY_READ | MY_WRITE	},
	{ "GS",         MY_GET | MY_SET				},
	{ "RW",         MY_READ | MY_WRITE			},
	{ "GET",	MY_GET					},
	{ "SET",	MY_SET					},
	{ "READ",	MY_READ					},
	{ "WRITE",	MY_WRITE				},
	/* aliases */
	{ "READ_WRITE",	MY_GET | MY_SET				},
	{ "GETTER",	MY_GET					},
	{ "SETTER",	MY_SET					},
	{ NULL }
};

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

TESTCASE(ni_parse_bitmask_array) {
	unsigned int mask_out = 0;
	ni_string_array_t array_in = NI_STRING_ARRAY_INIT;
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;

	/* Check simple mapping */
	string_array_set(&array_in, "GET", NULL);
	ni_parse_bitmask_array(&mask_out, map, &array_in, &invalid);
	CHECK(mask_out == MY_GET);
	CHECK(invalid.count == 0);

	/* Check if mask_out get extended on subsequence call */
	string_array_set(&array_in, "SET", NULL);
	ni_parse_bitmask_array(&mask_out, map, &array_in, &invalid);
	CHECK(mask_out == (MY_GET | MY_SET));

	/*  Check for invalid values and multiple BIT aliases */
	mask_out = 0;
	string_array_set(&array_in, "GET", "RW", "INVALID", "SETTER", NULL);
	CHECK(ni_parse_bitmask_array(&mask_out, map, &array_in, &invalid) != 0);
	CHECK(mask_out == (MY_GET | MY_SET | MY_READ | MY_WRITE));
	CHECK(invalid.count == 1);
	CHECK(ni_string_eq(invalid.data[0], "INVALID"));
}

TESTCASE(ni_parse_bitmask_string)
{
	unsigned int mask_out;
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;

	/* Simple check if BIT's get mapped successful */
	mask_out = 0;
	ni_parse_bitmask_string(&mask_out, map, "GET|READ", NULL, &invalid);
	CHECK(mask_out == (MY_GET | MY_READ));
	CHECK(invalid.count == 0);

	/* Check that mask_out get extended on subsequence call */
	mask_out = 0;
	ni_parse_bitmask_string(&mask_out, map, "GET", NULL, &invalid);
	ni_parse_bitmask_string(&mask_out, map, "WRITE", NULL, &invalid);
	CHECK(mask_out == (MY_GET | MY_WRITE));

	/* Test muliple seperators and numbers are invalid */
	mask_out = 0;
	ni_parse_bitmask_string(&mask_out, map, "GET|SET READ\tWRITE\n0x10,0x20", " ,|\t\n", &invalid);
	CHECK(mask_out == (MY_GET | MY_SET | MY_READ | MY_WRITE));
	CHECK(invalid.count == 2);
	CHECK(ni_string_eq(invalid.data[0], "0x10"));
	CHECK(ni_string_eq(invalid.data[1], "0x20"));

	/* Check with invalid name and multi BIT alias */
	ni_string_array_destroy(&invalid);
	mask_out = 0;
	CHECK(ni_parse_bitmask_string(&mask_out, map, "GET RW INVALID SETTER", " ", &invalid) != 0);
	CHECK(mask_out == (MY_GET | MY_SET | MY_READ | MY_WRITE));
	CHECK(invalid.count == 1);
	CHECK(ni_string_eq(invalid.data[0], "INVALID"));

	ni_string_array_destroy(&invalid);
}

TESTCASE(ni_parse_bitmask)
{
	unsigned int mask_out;
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;

	/* Check various number format parsing */
	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "1", NULL, NULL) == 0);
	CHECK(mask_out == MY_GET);

	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "0x1", NULL, NULL) == 0);
	CHECK(mask_out == MY_GET);

	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "0xf", NULL, NULL) == 0);
	CHECK(mask_out == (MY_GET | MY_SET | MY_WRITE | MY_READ));

	/* There are only hex values alowed! */
	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "15", NULL, NULL) == 0);
	CHECK(mask_out != (MY_GET | MY_SET | MY_WRITE | MY_READ));
	CHECK(mask_out == 0x15);

	/* Negative numeric values are not permitted */
	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "-1", NULL, NULL) != 0);
	CHECK(mask_out == 0);

	/* Check if numeric values get parsed as well*/
	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "GET|0x2|0xf0", NULL, NULL) == 0);
	CHECK(mask_out == (MY_GET | MY_SET | 0xf0));

	/* Check invalid named values*/
	mask_out = 0;
	CHECK(ni_parse_bitmask(&mask_out, map, "GET|0x2|0xf0|FOO", NULL, &invalid) != 0);
	CHECK(mask_out == (MY_GET | MY_SET | 0xf0));
	CHECK(invalid.count == 1);
	CHECK(ni_string_eq(invalid.data[0], "FOO"));

	ni_string_array_destroy(&invalid);
}

TESTCASE(ni_format_bitmask_array)
{
	ni_string_array_t array_out = NI_STRING_ARRAY_INIT;
	unsigned int mask_in = 0;
	unsigned int done = 0;

	/* Simple check for bitmask */
	mask_in = MY_GET;
	CHECK2(ni_format_bitmask_array(&array_out, map, mask_in, &done) == 0,
			"Simple format from single flag");
	CHECK(done == mask_in);
	CHECK(array_out.count == 1 && ni_string_eq(array_out.data[0], "GET"));

	/* Check that multi BIT aliases get used */
	mask_in = MY_READ | MY_WRITE;
	done = 0;
	ni_string_array_destroy(&array_out);
	CHECK2(ni_format_bitmask_array(&array_out, map, mask_in, &done) == 0,
			"Format of multi flag");
	CHECK(done == mask_in);
	CHECK2(array_out.count == 1 && ni_string_eq(array_out.data[0], "RW"),
			"Use multi flag alias");

	/* Check multi BIT alias with single BIT values */
	mask_in = MY_READ | MY_WRITE | MY_SET;
	done = 0;
	ni_string_array_destroy(&array_out);
	CHECK(ni_format_bitmask_array(&array_out, map, mask_in, &done) == 0);
	CHECK(done == mask_in);
	CHECK(array_out.count == 2);
	CHECK2(ni_string_eq(array_out.data[0], "RW"), "Use multi flag alias");
	CHECK2(ni_string_eq(array_out.data[1], "SET"), "Left over flag is shown");

	/* Check unkown values do not get expanded to numbers */
	mask_in = MY_READ | UNKNOWN_VALUE;
	done = 0;
	ni_string_array_destroy(&array_out);
	CHECK2(ni_format_bitmask_array(&array_out, map, mask_in, &done) == UNKNOWN_VALUE,
			"Return unknown flags");
	CHECK(done == MY_READ);
	CHECK(array_out.count == 1);
	CHECK(ni_string_eq(array_out.data[0], "READ"));

	ni_string_array_destroy(&array_out);
}

TESTCASE(ni_format_bitmask_string)
{
	ni_stringbuf_t buf_out = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int mask_in = 0;
	unsigned int done = 0;

	/* Check return value, if bitmask is 0 */
	CHECK(ni_format_bitmask_string(&buf_out, map, 0, NULL, NULL) == NULL);
	ni_stringbuf_puts(&buf_out, "FOO");
	CHECK(ni_string_eq(ni_format_bitmask_string(&buf_out, map, 0, NULL, NULL), ""));

	/* Check expanding of buf_out on subsequence calls */
	ni_stringbuf_clear(&buf_out);
	done = 0;
	CHECK(ni_string_eq(ni_format_bitmask_string(&buf_out, map, MY_GET, &done, NULL), "GET"));
	CHECK(done == MY_GET);
	CHECK(ni_string_eq(ni_format_bitmask_string(&buf_out, map, MY_WRITE, &done, NULL), " | WRITE"));
	CHECK(done == (MY_GET | MY_WRITE));
	CHECK(ni_string_eq(ni_format_bitmask_string(&buf_out, map, MY_READ, &done, "#"), "#READ"));
	CHECK(done == (MY_GET | MY_WRITE | MY_READ));
	CHECK2(ni_string_eq(buf_out.string, "GET | WRITE#READ"), "Append to given stringbuf");

	/* Check multi BIT alias have precedence corresponding to map order */
	ni_stringbuf_clear(&buf_out);
	mask_in = MY_READ | MY_WRITE;
	done = 0;
	CHECK2(ni_string_eq(ni_format_bitmask_string(&buf_out, map, mask_in, &done, NULL), "RW"),
		"Use multi flag alias");
	CHECK(done == mask_in);

	/* Unknown values are not expanded in `ni_format_bitmask_string()` */
	ni_stringbuf_clear(&buf_out);
	mask_in = MY_READ | MY_WRITE | UNKNOWN_VALUE;
	done = 0;
	CHECK2(ni_string_eq(ni_format_bitmask_string(&buf_out, map, mask_in, &done, NULL), "RW"),
		"Format known values, if unknown exists");
	CHECK(done == (MY_READ | MY_WRITE));

	/* Check zero map return NULL */
	ni_stringbuf_clear(&buf_out);
	CHECK2(ni_string_eq(ni_format_bitmask_string(&buf_out, map ,0 ,NULL, NULL), NULL),
			"Return NULL on empty mask");

	ni_stringbuf_destroy(&buf_out);
}

TESTCASE(ni_format_bitmask)
{
	ni_stringbuf_t buf_out = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int mask_in = 0;

	/* Check that NULL is returned if the buf_out is null before */
	CHECK(ni_format_bitmask(&buf_out, map, 0, NULL) == NULL);

	/* Check that the formated string gets printed, if no named BIT's are there */
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, 0xf0, NULL), "0xf0"));

	/* Check that empty string is retruned, if buf_out wasn't NULL */
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, 0, NULL), ""));

	/* Check that unknown values get added in hex format */
	ni_stringbuf_clear(&buf_out);
	mask_in = MY_GET | 0xf0;
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, mask_in, " "), "GET 0xf0"));

	/* Check subsequent calles append to buf_out */
	ni_stringbuf_clear(&buf_out);
	mask_in = MY_GET | 0xf0;
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, mask_in, NULL), "GET | 0xf0"));
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, MY_SET, "\t"), "\tSET"));
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, 0xf00, ","), ",0xf00"));
	mask_in = MY_GET | MY_SET | MY_READ | MY_WRITE;
	CHECK(ni_string_eq(ni_format_bitmask(&buf_out, map, mask_in, NULL), " | ALL"));
	CHECK(ni_string_eq(buf_out.string, "GET | 0xf0\tSET,0xf00 | ALL"));

	ni_stringbuf_destroy(&buf_out);
}

TESTMAIN();
