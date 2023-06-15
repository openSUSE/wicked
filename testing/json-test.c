/*
 *	Small test app for our JSON routines
 *
 *	Copyright (C) 2023 SUSE LLC
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
 *	along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 *	Authors:
 *		Marius Tomaschewski
 *		Jorik Cronenberg
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json.h"
#include "wunit.h"

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
	ni_json_t *json;

	if ((json = ni_json_new_array()) &&
	    ni_json_array_append(json, ni_json_new_string("string1_6_foo")) &&
	    ni_json_array_append(json, ni_json_new_bool(TRUE)))
		return json;

	ni_json_free(json);
	return NULL;
}

static ni_json_t *
init1_6_bar(void)
{
	ni_json_t *json;

	if ((json = ni_json_new_object()) &&
	    ni_json_object_set(json, "a", ni_json_new_string("string1_6_bar_a")) &&
	    ni_json_object_set(json, "b", ni_json_new_string("string1_6_bar_b")) &&
	    ni_json_object_set(json, "c", ni_json_new_string("\"\\/\t\n\r\a\b\f")))
		return json;

	ni_json_free(json);
	return NULL;
}

static ni_json_t *
init1_6(void)
{
	ni_json_t *json;

	if ((json = ni_json_new_object()) &&
	    ni_json_object_set(json, "foo", init1_6_foo()) &&
	    ni_json_object_set(json, "bar", init1_6_bar()))
		return json;

	ni_json_free(json);
	return NULL;
}

static ni_json_t *
init1_7(void)
{
	ni_json_t *json = ni_json_new_array();
	return json;
}

static ni_json_t *
init1(void)
{
	/*
	 *	[
	 *	  null,
	 *	  42,
	 *	  0.42,
	 *	  false,
	 *	  "string1_5",
	 *	  {
	 *	    "foo": [
	 *	      "string1_6_foo",
	 *	      true
	 *	    ],
	 *	    "bar": {
	 *	      "a": "string1_6_bar_a",
	 *	      "b": "string1_6_bar_b",
	 *	      "c": "\"\\\/\t\n\r\u0007\b\f"
	 *	    }
	 *	  },
	 *	  []
	 *	]
	 */
	ni_json_t *json;

	if ((json = ni_json_new_array()) &&
	    ni_json_array_append(json, init1_1()) &&
	    ni_json_array_append(json, init1_2()) &&
	    ni_json_array_append(json, init1_3()) &&
	    ni_json_array_append(json, init1_4()) &&
	    ni_json_array_append(json, init1_5()) &&
	    ni_json_array_append(json, init1_6()) &&
	    ni_json_array_append(json, init1_7()))
		return json;

	ni_json_free(json);
	return NULL;
}

static ni_json_t *
init2(void)
{
	/*
	 *	{
	 *	  "obj2-a": "string2_a",
	 *	  "obj2-b": "string2_b",
	 *	  "obj2-c": null,
	 *	  "obj2-d": 64,
	 *	  "obj2-e": {}
	 *	}
	 */
	ni_json_t *json;

	if ((json = ni_json_new_object()) &&
	    ni_json_object_set(json, "obj2-a", ni_json_new_string("string2_a €")) &&
	    ni_json_object_set(json, "obj2-b", ni_json_new_string("string2_b ©")) &&
	    ni_json_object_set(json, "obj2-c", ni_json_new_null()) &&
	    ni_json_object_set(json, "obj2-d", ni_json_new_int64(64)) &&
	    ni_json_object_set(json, "obj2-e", ni_json_new_object()))
		return json;

	ni_json_free(json);
	return NULL;
}

TESTCASE(ni_json_array_format_string)
{
	ni_stringbuf_t buf1 = NI_STRINGBUF_INIT_DYNAMIC;
	ni_stringbuf_t buf2 = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json_array1, *json_array2;

	CHECK((json_array1 = init1()));
	CHECK(ni_json_format_string(&buf1, json_array1, NULL));

	CHECK((json_array2 = ni_json_parse_string(buf1.string)));
	CHECK(ni_json_format_string(&buf2, json_array2, NULL));

	CHECK(ni_string_eq(buf1.string, buf2.string));

	ni_stringbuf_destroy(&buf1);
	ni_stringbuf_destroy(&buf2);
	ni_json_free(json_array1);
	ni_json_free(json_array2);
}

TESTCASE(ni_json_object_format_string)
{
	ni_stringbuf_t buf1 = NI_STRINGBUF_INIT_DYNAMIC;
	ni_stringbuf_t buf2 = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json_object1, *json_object2;

	CHECK((json_object1 = init2()));
	CHECK(ni_json_format_string(&buf1, json_object1, NULL));

	CHECK((json_object2 = ni_json_parse_string(buf1.string)));
	CHECK(ni_json_format_string(&buf2, json_object2, NULL));

	CHECK(ni_string_eq(buf1.string, buf2.string));

	ni_stringbuf_destroy(&buf1);
	ni_stringbuf_destroy(&buf2);
	ni_json_free(json_object1);
	ni_json_free(json_object2);
}

TESTCASE(ni_json_format_string_indent)
{
	char *expected_str = "[\n"
			     "  null,\n"
			     "  42,\n"
			     "  0.42,\n"
			     "  false,\n"
			     "  \"string1_5\",\n"
			     "  {\n"
			     "    \"foo\": [\n"
			     "      \"string1_6_foo\",\n"
			     "      true\n"
			     "    ],\n"
			     "    \"bar\": {\n"
			     "      \"a\": \"string1_6_bar_a\",\n"
			     "      \"b\": \"string1_6_bar_b\",\n"
			     "      \"c\": \"\\\"\\\\/\\t\\n\\r\\u0007\\b\\f\"\n"
			     "    }\n"
			     "  },\n"
			     "  []\n"
			     "]";

	ni_json_format_options_t options = { .indent = 2 };
	ni_stringbuf_t buf1 = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *json;

	CHECK((json = init1()));
	CHECK(ni_json_format_string(&buf1, json, &options));

	CHECK(ni_string_eq(expected_str, buf1.string));

	ni_stringbuf_destroy(&buf1);
	ni_json_free(json);
}

TESTCASE(ni_json_parse_string)
{
	char *valid_json_str = "{\"obj1\": \"string2\",\"obj2\": null,\"obj3\": 64,\"obj4\": 0.4,\"obj5\": true}";
	char *invalid_json_str = "{\"obj1\": [}";
	ni_json_t *json, *obj1, *obj2, *obj3, *obj4, *obj5;

	CHECK((json = ni_json_parse_string(valid_json_str)));
	CHECK(ni_json_type(json) == NI_JSON_TYPE_OBJECT);

	CHECK((obj1 = ni_json_object_get_value(json, "obj1")));
	CHECK(ni_json_type(obj1) == NI_JSON_TYPE_STRING);

	CHECK((obj2 = ni_json_object_get_value(json, "obj2")));
	CHECK(ni_json_type(obj2) == NI_JSON_TYPE_NULL);

	CHECK((obj3 = ni_json_object_get_value(json, "obj3")));
	CHECK(ni_json_type(obj3) == NI_JSON_TYPE_INT64);

	CHECK((obj4 = ni_json_object_get_value(json, "obj4")));
	CHECK(ni_json_type(obj4) == NI_JSON_TYPE_DOUBLE);

	CHECK((obj5 = ni_json_object_get_value(json, "obj5")));
	CHECK(ni_json_type(obj5) == NI_JSON_TYPE_BOOL);

	CHECK(!ni_json_parse_string(invalid_json_str));

	ni_json_free(json);
}

TESTCASE(ni_json_bool_get)
{
	ni_json_t *valid_json, *invalid_bool;
	ni_bool_t ret = TRUE;

	CHECK((valid_json = ni_json_new_bool(FALSE)));
	CHECK(ni_json_bool_get(valid_json, &ret));
	CHECK(!ret);

	CHECK((invalid_bool = ni_json_new_null()));
	CHECK(!ni_json_bool_get(invalid_bool, &ret));

	ni_json_free(valid_json);
	ni_json_free(invalid_bool);
}

TESTCASE(ni_json_int64_get)
{
	const int64_t n = 42;
	ni_json_t *valid_json, *invalid_int64;
	int64_t ret = 0;

	CHECK((valid_json = ni_json_new_int64(n)));
	CHECK(ni_json_int64_get(valid_json, &ret));
	CHECK(ret == n);

	CHECK((invalid_int64 = ni_json_new_null()));
	CHECK(!ni_json_int64_get(invalid_int64, &ret));

	ni_json_free(valid_json);
	ni_json_free(invalid_int64);
}

TESTCASE(ni_json_double_get)
{
	const double n = 0.42;
	ni_json_t *valid_json, *invalid_double;
	double ret = 0.0;

	CHECK((valid_json = ni_json_new_double(n)));
	CHECK(ni_json_double_get(valid_json, &ret));
	CHECK(ret == n);

	CHECK((invalid_double = ni_json_new_null()));
	CHECK(!ni_json_double_get(invalid_double, &ret));

	ni_json_free(valid_json);
	ni_json_free(invalid_double);
}

TESTCASE(ni_json_string_get)
{
	const char *str = "test_string";
	ni_json_t *valid_json, *invalid_string;
	char *ret = NULL;

	CHECK((valid_json = ni_json_new_string(str)));
	CHECK(ni_json_string_get(valid_json, &ret));
	CHECK(ni_string_eq(str, ret));

	CHECK((invalid_string = ni_json_new_null()));
	CHECK(!ni_json_string_get(invalid_string, &ret));

	free(ret);
	ni_json_free(valid_json);
	ni_json_free(invalid_string);
}

TESTCASE(ni_json_pair_get_name)
{
	ni_json_pair_t *pair;
	const char *ret = NULL;

	CHECK((pair = ni_json_pair_new("test_name", ni_json_new_null())));
	CHECK((ret = ni_json_pair_get_name(pair)));
	CHECK(ni_string_eq(ret, "test_name"));

	ni_json_pair_free(pair);
}

TESTCASE(ni_json_pair_get_value)
{
	ni_json_t *json;
	ni_json_pair_t *pair;

	CHECK((json = ni_json_new_null()));
	CHECK((pair = ni_json_pair_new("test_name", json)));
	CHECK(ni_json_pair_get_value(pair) == json);

	ni_json_pair_free(pair);
}

TESTCASE(ni_json_pair_set_value)
{
	ni_json_t *json;
	ni_json_pair_t *pair;

	CHECK((json = ni_json_new_null()));
	CHECK((pair = ni_json_pair_new("test_name", ni_json_new_null())));
	CHECK(ni_json_pair_set_value(pair, json));
	CHECK(ni_json_pair_get_value(pair) == json);
	CHECK(!ni_json_pair_set_value(pair, NULL));

	ni_json_pair_free(pair);
}

TESTCASE(ni_json_clone_null)
{
	ni_json_t *json_clone, *json_null;

	CHECK((json_null = ni_json_new_null()));
	CHECK((json_clone = ni_json_clone(json_null)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_NULL);

	ni_json_free(json_null);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_bool)
{
	ni_json_t *json_clone, *json_bool;
	ni_bool_t bool_ret = FALSE;

	CHECK((json_bool = ni_json_new_bool(TRUE)));
	CHECK((json_clone = ni_json_clone(json_bool)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_BOOL);
	CHECK(json_bool != json_clone);
	CHECK(ni_json_bool_get(json_clone, &bool_ret));
	CHECK(bool_ret == TRUE);

	ni_json_free(json_bool);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_int64)
{
	ni_json_t *json_clone, *json_int64;
	int64_t int64_ret = 0;

	CHECK((json_int64 = ni_json_new_int64(42)));
	CHECK((json_clone = ni_json_clone(json_int64)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_INT64);
	CHECK(json_int64 != json_clone);
	CHECK(ni_json_int64_get(json_clone, &int64_ret));
	CHECK(int64_ret == 42);

	ni_json_free(json_int64);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_double)
{
	ni_json_t *json_clone, *json_double;
	double double_ret = 0.0;

	CHECK((json_double = ni_json_new_double(0.42)));
	CHECK((json_clone = ni_json_clone(json_double)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_DOUBLE);
	CHECK(json_double != json_clone);
	CHECK(ni_json_double_get(json_clone, &double_ret));
	CHECK(double_ret == 0.42);

	ni_json_free(json_double);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_string)
{
	ni_json_t *json_clone, *json_string;
	char *string_ret = NULL;

	CHECK((json_string = ni_json_new_string("test_string")));
	CHECK((json_clone = ni_json_clone(json_string)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_STRING);
	CHECK(json_string != json_clone);
	CHECK(ni_json_string_get(json_clone, &string_ret));
	CHECK(ni_string_eq(string_ret, "test_string"));

	free(string_ret);
	ni_json_free(json_string);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_object)
{
	ni_json_t *json_clone, *object_ret, *json_object;
	char *object_ret_string = NULL;

	CHECK((json_object = ni_json_new_object()));
	ni_json_object_set(json_object, "test_name", ni_json_new_string("test_string"));

	CHECK((json_clone = ni_json_clone(json_object)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_OBJECT);
	CHECK(json_object != json_clone);
	CHECK((object_ret = ni_json_object_get_value(json_clone, "test_name")));
	CHECK(ni_json_string_get(object_ret, &object_ret_string));
	CHECK(ni_string_eq(object_ret_string, "test_string"));

	free(object_ret_string);
	ni_json_free(json_object);
	ni_json_free(json_clone);
}

TESTCASE(ni_json_clone_array)
{
	ni_json_t *json_clone, *array_ret, *json_array;
	char *array_ret_string = NULL;

	CHECK((json_array = ni_json_new_array()));
	ni_json_array_append(json_array, ni_json_new_string("test_string"));

	CHECK((json_clone = ni_json_clone(json_array)));
	CHECK(ni_json_type(json_clone) == NI_JSON_TYPE_ARRAY);
	CHECK(json_array != json_clone);
	CHECK((array_ret = ni_json_array_get(json_clone, 0)));
	CHECK(ni_json_string_get(array_ret, &array_ret_string));
	CHECK(ni_string_eq(array_ret_string, "test_string"));

	free(array_ret_string);
	ni_json_free(json_array);
	ni_json_free(json_clone);
}

ni_json_t *
setup_test_object()
{
	ni_json_t *json_object;

	if ((json_object = ni_json_new_object()) &&
	    ni_json_object_set(json_object, "test_name1", ni_json_new_string("test_string1")) &&
	    ni_json_object_set(json_object, "test_name2", ni_json_new_string("test_string2")))
		return json_object;

	ni_json_free(json_object);
	return NULL;
}

TESTCASE(ni_json_object_get_pair_at)
{
	ni_json_t *json_object, *pair_value;
	ni_json_pair_t *pair;
	const char *pair_name = NULL;
	char *pair_value_string = NULL;

	CHECK((json_object = setup_test_object()));
	CHECK((pair = ni_json_object_get_pair_at(json_object, 0)));
	CHECK((pair_name = ni_json_pair_get_name(pair)));
	CHECK(ni_string_eq(pair_name, "test_name1"));
	CHECK((pair_value = ni_json_pair_get_value(pair)));
	CHECK(ni_json_type(pair_value) == NI_JSON_TYPE_STRING);
	CHECK(ni_json_string_get(pair_value, &pair_value_string));
	CHECK(ni_string_eq(pair_value_string, "test_string1"));

	ni_json_free(json_object);
	free(pair_value_string);
}

TESTCASE(ni_json_object_remove)
{
	ni_json_t *json_object, *deleted_value;
	char *deleted_value_string = NULL;

	CHECK((json_object = setup_test_object()));
	CHECK((deleted_value = ni_json_object_remove(json_object, "test_name1")));
	CHECK(ni_json_type(deleted_value) == NI_JSON_TYPE_STRING);
	CHECK(ni_json_string_get(deleted_value, &deleted_value_string));
	CHECK(ni_string_eq(deleted_value_string, "test_string1"));
	CHECK(ni_json_object_entries(json_object) < 2);

	free(deleted_value_string);
	ni_json_free(json_object);
	ni_json_free(deleted_value);
}

TESTCASE(ni_json_object_remove_at)
{
	ni_json_t *json_object, *deleted_value;
	char *deleted_value_string = NULL;

	CHECK((json_object = setup_test_object()));
	CHECK((deleted_value = ni_json_object_remove_at(json_object, 0)));
	CHECK(ni_json_type(deleted_value) == NI_JSON_TYPE_STRING);
	CHECK(ni_json_string_get(deleted_value, &deleted_value_string));
	CHECK(ni_string_eq(deleted_value_string, "test_string1"));
	CHECK(ni_json_object_entries(json_object) < 2);

	free(deleted_value_string);
	ni_json_free(json_object);
	ni_json_free(deleted_value);
}

TESTCASE(ni_json_object_delete)
{
	ni_json_t *json_object;

	CHECK((json_object = setup_test_object()));
	CHECK(ni_json_object_delete(json_object, "test_name1"));
	CHECK(ni_json_object_entries(json_object) < 2);

	ni_json_free(json_object);
}

TESTCASE(ni_json_object_delete_at)
{
	ni_json_t *json_object;

	CHECK((json_object = setup_test_object()));
	CHECK(ni_json_object_delete_at(json_object, 0));
	CHECK(ni_json_object_entries(json_object) < 2);

	ni_json_free(json_object);
}

TESTCASE(ni_json_array_insert)
{
	ni_json_t *json_array, *value, *value2, *value3;

	CHECK((json_array = ni_json_new_array()));
	CHECK((value = ni_json_new_null()));
	CHECK((value2 = ni_json_new_bool(TRUE)));
	CHECK((value3 = ni_json_new_int64(0)));
	CHECK(ni_json_array_insert(json_array, 0, value));
	CHECK(ni_json_array_insert(json_array, 0, value2));
	CHECK(ni_json_array_insert(json_array, 2, value3));
	CHECK(ni_json_array_entries(json_array) == 3);
	CHECK(ni_json_type(ni_json_array_get(json_array, 0)) == NI_JSON_TYPE_BOOL);
	CHECK(ni_json_type(ni_json_array_get(json_array, 1)) == NI_JSON_TYPE_NULL);
	CHECK(ni_json_type(ni_json_array_get(json_array, 2)) == NI_JSON_TYPE_INT64);
	CHECK(!ni_json_array_insert(NULL, 0, value));
	CHECK(!ni_json_array_insert(json_array, 0, NULL));

	ni_json_free(json_array);
}

TESTCASE(ni_json_array_append)
{
	ni_json_t *json_array, *value, *value2;

	CHECK((json_array = ni_json_new_array()));
	CHECK((value = ni_json_new_null()));
	CHECK((value2 = ni_json_new_bool(TRUE)));
	CHECK(!ni_json_array_append(json_array, NULL));
	CHECK(!ni_json_array_append(NULL, value));
	CHECK(ni_json_array_append(json_array, value));
	CHECK(ni_json_array_append(json_array, value2));
	CHECK(ni_json_array_entries(json_array) == 2);
	CHECK(ni_json_type(ni_json_array_get(json_array, 1)) == NI_JSON_TYPE_BOOL);

	ni_json_free(json_array);
}

ni_json_t *
setup_test_array()
{
	ni_json_t *json_array, *value = NULL, *value2 = NULL;

	if ((json_array = ni_json_new_array()) &&
	    (value = ni_json_new_null()) &&
	    (value2 = ni_json_new_bool(TRUE)) &&
	    ni_json_array_append(json_array, value) &&
	    ni_json_array_append(json_array, value2))
		return json_array;

	ni_json_free(json_array);
	ni_json_free(value);
	ni_json_free(value2);
	return NULL;
}

TESTCASE(ni_json_array_set)
{
	ni_json_t *json_array, *value;

	CHECK((json_array = ni_json_new_array()));
	CHECK((value = ni_json_new_int64(42)));
	CHECK(!ni_json_array_set(json_array, 0, value));

	ni_json_free(json_array);

	CHECK((json_array = setup_test_array()));
	CHECK(ni_json_array_set(json_array, 1, value));
	CHECK(ni_json_type(ni_json_array_get(json_array, 1)) == NI_JSON_TYPE_INT64);

	ni_json_free(json_array);
}

TESTCASE(ni_json_array_remove_at)
{
	ni_json_t *json_array, *value;

	CHECK((json_array = setup_test_array()));
	CHECK(ni_json_array_remove_at(json_array, 2) == NULL);
	CHECK((value = ni_json_array_remove_at(json_array, 1)));
	CHECK(ni_json_type(value) == NI_JSON_TYPE_BOOL);
	CHECK(ni_json_array_entries(json_array) == 1);

	ni_json_free(value);
	ni_json_free(json_array);
}

TESTCASE(ni_json_array_delete_at)
{
	ni_json_t *json_array;

	CHECK((json_array = setup_test_array()));
	CHECK(ni_json_array_delete_at(json_array, 1));
	CHECK(ni_json_array_entries(json_array) == 1);

	ni_json_free(json_array);
}

TESTCASE(ni_json_type_name)
{
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_NULL), "null"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_BOOL), "bool"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_INT64), "int64"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_DOUBLE), "double"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_STRING), "string"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_OBJECT), "object"));
	CHECK(ni_string_eq(ni_json_type_name(NI_JSON_TYPE_ARRAY), "array"));
}

TESTCASE(ni_json_parse_file)
{
	ni_json_t *json, *array_value, *escaped, *control;
	char *escaped_str = NULL, *control_str = NULL;
	unsigned int i;
	char path[4096] = "json-test.json";

	if (getenv("srcdir"))
		snprintf(path, sizeof(path), "%s/json-test.json", getenv("srcdir"));

	CHECK((json = ni_json_parse_file(path)));
	CHECK(ni_string_eq(ni_json_type_name(ni_json_type(json)), "array"));

	for (i = 0; (array_value = ni_json_array_get(json, i)); i++) {
		CHECK(ni_string_eq(ni_json_type_name(ni_json_type(array_value)), "object"));
		CHECK((escaped = ni_json_object_get_value(array_value, "escaped")));
		CHECK((control = ni_json_object_get_value(array_value, "control")));
		CHECK(ni_json_string_get(escaped, &escaped_str));
		CHECK(ni_json_string_get(control, &control_str));
		CHECK(ni_string_eq(escaped_str, control_str));
	}

	free(escaped_str);
	free(control_str);
	ni_json_free(json);
}

TESTMAIN();
