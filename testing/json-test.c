/*
 *	Small test app for our JSON routines
 *
 *	Copyright (C) 2015 SÜSE Linux GmbH, Nuernberg, Germany.
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
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json.h"

static ni_json_t *
init1_1(void)
{
	return ni_json_new_null();
}

static ni_json_t *
init1_2(void)
{
	return ni_json_new_int64(42);
}

static ni_json_t *
init1_3(void)
{
	return ni_json_new_double(0.42);
}

static ni_json_t *
init1_4(void)
{
	return ni_json_new_bool(FALSE);
}

static ni_json_t *
init1_5(void)
{
	return ni_json_new_string("string1_5");
}

static ni_json_t *
init1_6_foo(void)
{
	ni_json_t *json = ni_json_new_array();
	ni_json_array_append(json, ni_json_new_string("string1_6_foo"));
	ni_json_array_append(json, ni_json_new_bool(TRUE));
	return json;
}

static ni_json_t *
init1_6_bar(void)
{
	ni_json_t *json = ni_json_new_object();
	ni_json_object_set(json, "a", ni_json_new_string("string1_6_bar_a"));
	ni_json_object_set(json, "b", ni_json_new_string("string1_6_bar_b"));
	ni_json_object_set(json, "c", ni_json_new_string("\"\\/\t\n\r\a\b"));
	return json;
}

static ni_json_t *
init1_6(void)
{
	ni_json_t *json = ni_json_new_object();
	ni_json_object_set(json, "foo", init1_6_foo());
	ni_json_object_set(json, "bar", init1_6_bar());
	return json;
}

static ni_json_t *
init1(void)
{
	/*
		[
		  null,
		  42,
		  0.42,
		  false,
		  "string1_5",
		  {
		    "foo": [
		      "string1_6_foo",
		      true
		    ],
		    "bar": {
		      "a": "string1_6_bar_a",
		      "b": "string1_6_bar_b",
		      "c": "\"\\\/\t\n\r\u0007\b"
		    }
		  }
		]
	*/
	ni_json_t *json = ni_json_new_array();
	ni_json_array_append(json, init1_1());
	ni_json_array_append(json, init1_2());
	ni_json_array_append(json, init1_3());
	ni_json_array_append(json, init1_4());
	ni_json_array_append(json, init1_5());
	ni_json_array_append(json, init1_6());
	return json;
}

static ni_json_t *
init2(void)
{
	/*
		{
		  "obj2-a": "string2_a",
		  "obj2-b": "string2_b",
		  "obj2-c": null,
		  "obj2-d": 64
		}
	*/
	ni_json_t *json = ni_json_new_object();
	ni_json_object_set(json, "obj2-a", ni_json_new_string("string2_a €"));
	ni_json_object_set(json, "obj2-b", ni_json_new_string("string2_b ©"));
	ni_json_object_set(json, "obj2-c", ni_json_new_null());
	ni_json_object_set(json, "obj2-d", ni_json_new_int64(64));
	return json;
}

void
test_parse(const char *string)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json = ni_json_parse_string(string);

	if (json) {
		ni_json_format_string(&buf, json, NULL);
		printf("type<%s>: %s\n",
			ni_json_type_name(ni_json_type(json)), buf.string);
		ni_stringbuf_destroy(&buf);

		ni_json_free(json);
	} else {
		printf("parse error\n");
	}
}

void
test_case1()
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json;

	json = init1();

	ni_json_format_string(&buf, json, NULL);
	printf("#--> j1:\n%s\n", buf.string);
	printf("#<-- j1:\n");
	test_parse(buf.string);
	printf("\n");
	ni_stringbuf_destroy(&buf);
	ni_json_free(json);
}

void
test_case2()
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json;

	json = init2();

	ni_json_format_string(&buf, json, NULL);
	printf("#--> j2:\n%s\n", buf.string);
	printf("#<-- j2:\n");
	test_parse(buf.string);
	printf("\n");
	ni_stringbuf_destroy(&buf);
	ni_json_free(json);
}

int
main(int argc, char **argv)
{
	int n;

	if (argc == 1) {
		test_case1();
		test_case2();
	}

	for (n = 1; n < argc; ++n) {
		printf("argv[%d]: ", n);
		test_parse(argv[n]);
		printf("\n");
	}

	return 0;
}

