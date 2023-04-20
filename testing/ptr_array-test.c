/*
 *	Pointer array unit tests
 *
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "wunit.h"
#include <wicked/array.h>
#include "array_priv.h"

typedef struct {
	int age;
	char *name;
} ni_data_t;

#define NI_DATA_ARRAY_CHUNK 32
ni_declare_ptr_array_type(ni_data);
ni_declare_ptr_array_cmp_fn(ni_data);

static ni_declare_ptr_array_init(ni_data);
static ni_declare_ptr_array_destroy(ni_data);
static ni_declare_ptr_array_realloc(ni_data);
static ni_declare_ptr_array_append(ni_data);
static ni_declare_ptr_array_insert(ni_data);
static ni_declare_ptr_array_remove_at(ni_data);
static ni_declare_ptr_array_delete_at(ni_data);
static ni_declare_ptr_array_at(ni_data);
static ni_declare_ptr_array_index(ni_data);
static ni_declare_ptr_array_qsort(ni_data);

static void
ni_data_free(ni_data_t *d)
{
	if (d->name)
		free(d->name);
	free(d);
}

static ni_define_ptr_array_init(ni_data);
static ni_define_ptr_array_destroy(ni_data);
static ni_define_ptr_array_realloc(ni_data, NI_DATA_ARRAY_CHUNK);
static ni_define_ptr_array_append(ni_data);
static ni_define_ptr_array_insert(ni_data);
static ni_define_ptr_array_remove_at(ni_data);
static ni_define_ptr_array_delete_at(ni_data);
static ni_define_ptr_array_at(ni_data);
static ni_define_ptr_array_index(ni_data);
static ni_define_ptr_array_qsort(ni_data);


TESTCASE(append_remove)
{
	ni_data_array_t arr = NI_ARRAY_INIT;
	ni_data_t e1 =  {
		.age = 1,
		.name = "Foo"
	};

	CHECK(ni_data_array_append(&arr, &e1));
	CHECK(arr.data[0]->age == 1);
	CHECK(arr.count == 1);

	CHECK(ni_data_array_remove_at(&arr, 0) == &e1);
	CHECK(arr.count == 0);

	CHECK(ni_data_array_insert(&arr, 99, &e1));
	CHECK(ni_data_array_at(&arr, 0) == &e1);
	CHECK(ni_data_array_at(&arr, 1) == NULL);
	CHECK(ni_data_array_index(&arr, &e1) == 0);
	CHECK(ni_data_array_remove_at(&arr, 0) == &e1);
	CHECK(arr.count == 0);

	ni_data_array_destroy(&arr);
}

TESTCASE(destroy)
{
	ni_data_array_t arr = NI_ARRAY_INIT;
	ni_data_t *ptr;
	int i;

	for (i = 0; i < 100; i++) {
		ptr = calloc(1, sizeof(ni_data_t));
		if (ptr) {
			ptr->age = i;
			ni_string_printf(&ptr->name, "%d", i);
			CHECK(ni_data_array_append(&arr, ptr));
		}
	}
	CHECK(arr.count == 100);

	ni_data_array_destroy(&arr);
	CHECK(arr.count == 0);
}

static int
ni_data_cmp_age(const ni_data_t *a, const ni_data_t *b)
{
	return a->age > b->age ? 1 : (a->age < b->age ? -1 : 0);
}

static void
append_new_age(ni_data_array_t * arr, unsigned int age, const char *name)
{
	ni_data_t * ptr = calloc(1, sizeof(ni_data_t));

	if (ptr) {
		ptr->age = age;
		CHECK(ni_string_dup(&ptr->name, name));
		CHECK(ni_data_array_append(arr, ptr));
	}
}

TESTCASE(qsort)
{
	ni_data_array_t arr = NI_ARRAY_INIT;

	append_new_age(&arr, 7, "seven");
	append_new_age(&arr, 23, "twentythree");
	append_new_age(&arr, 13, "thirteen");
	append_new_age(&arr, 5, "five");
	append_new_age(&arr, 17, "seventeen");

	CHECK(arr.data[3]->age == 5);

	ni_data_array_qsort(&arr, ni_data_cmp_age);

	CHECK(arr.data[0]->age == 5);
	CHECK(arr.data[1]->age == 7);
	CHECK(arr.data[2]->age == 13);
	CHECK(arr.data[3]->age == 17);
	CHECK(arr.data[4]->age == 23);

	ni_data_array_destroy(&arr);
}

TESTCASE(remove_vs_delete_vs_destroy)
{
	ni_data_array_t arr = NI_ARRAY_INIT;
	ni_data_t *p;

	append_new_age(&arr, 7, "seven");
	append_new_age(&arr, 23, "twentythree");
	append_new_age(&arr, 97, "ninety seven");

	CHECK(ni_data_array_delete_at(&arr, 0));
	CHECK((p = ni_data_array_remove_at(&arr, 0)));
	ni_data_free(p);

	ni_data_array_destroy(&arr);
}


typedef struct {
	int age;
	char *name;
} ni_data2_t;

#define NI_DATA2_ARRAY_CHUNK 1
ni_declare_ptr_array_type(ni_data2);

static ni_declare_ptr_array_init(ni_data2);
static ni_declare_ptr_array_destroy(ni_data2);
static ni_declare_ptr_array_realloc(ni_data2);
static ni_declare_ptr_array_append(ni_data2);
static ni_declare_ptr_array_insert(ni_data2);
static ni_declare_ptr_array_remove_at(ni_data2);
static ni_declare_ptr_array_delete_at(ni_data2);

static void
ni_data2_free(ni_data2_t *d)
{
	free(d->name);
	free(d);
}

static ni_define_ptr_array_init(ni_data2);
static ni_define_ptr_array_destroy(ni_data2);
static ni_define_ptr_array_realloc(ni_data2, NI_DATA2_ARRAY_CHUNK);
static ni_define_ptr_array_append(ni_data2);
static ni_define_ptr_array_insert(ni_data2);
static ni_define_ptr_array_remove_at(ni_data2);
static ni_define_ptr_array_delete_at(ni_data2);

TESTCASE(chunk_size_1)
{
	ni_data2_array_t arr = NI_ARRAY_INIT;
	unsigned int i;
	ni_data2_t *d;

	ni_data2_array_init(&arr);

	for (i = 0; i < 10; i++) {
		d = calloc(1, sizeof(ni_data2_t));
		if (d) {
			d->age = i;
			ni_string_printf(&d->name, "Name:%u", i);
			CHECK(ni_data2_array_append(&arr, d));
		}
	}

	CHECK(arr.count == 10);
	CHECK((d = ni_data2_array_remove_at(&arr, 0)));
	ni_data2_free(d);
	CHECK(arr.count == 9);
	CHECK((d = ni_data2_array_remove_at(&arr, arr.count - 1)));
	ni_data2_free(d);
	CHECK(arr.count == 8);

	CHECK(ni_data2_array_delete_at(&arr, 0));
	CHECK(arr.count == 7);
	CHECK(ni_data2_array_delete_at(&arr, arr.count - 1));
	CHECK(arr.count == 6);

	for (i = 0; i < 10; i++) {
		d = calloc(1, sizeof(ni_data2_t));
		if (d) {
			d->age = i;
			ni_string_printf(&d->name, "Name:%u", i);
			CHECK(ni_data2_array_insert(&arr, i, d));
		}
	}
	CHECK(arr.count == 16);

	ni_data2_array_destroy(&arr);
}


TESTMAIN();
