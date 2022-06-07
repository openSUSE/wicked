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
 *		Clemens Famulla-Conrad <cfamullaconrad@suse.com>
 *
 *	Description:
 *		Simple macro collection to write unit tests for wicked.
 *
 *	Example:
 *		cat > testing/my_unit_test.c <<'EOT'
 *		#include "wunit.h"
 *
 *		TESTCASE(foo1) {
 *			CHECK(1==1);
 *		}
 *
 *		TESTMAIN();
 *		EOT
 *
 *		MFILE=testing/Makefile.am
 *		echo "TESTS += my_unit_test" >> $MFILE
 *		echo "my_unit_test_SOURCES = my_unit_test.c" >> $MFILE
 *		echo "noinst_PROGRAMS += my_unit_test" >> $MFILE
 *		make check
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wicked/logging.h>

typedef struct wunit_s wunit_t;
typedef void (*wunit_test_fn)();

#define MAX_TESTCASES 512

struct wunit_s {
	unsigned int testcases_idx, fail, ok;
	struct {
		wunit_test_fn func;
		const char *name;
		unsigned int checks, fail, ok;
	}
	testcases[MAX_TESTCASES],
	*current;
};

__attribute__((unused)) static wunit_t wunit_ctx = {
	.testcases_idx = 0,
	.fail = 0,
	.ok = 0,
	.current = NULL
};

#define MSG(name, ...)							\
	do {								\
		int __printed__;					\
		printf("[%03d/line:%-4d] ",				\
				wunit_ctx.current->checks, __LINE__);	\
		__printed__ = printf(name, ##__VA_ARGS__);		\
		if (__printed__ >= 0 && __printed__ < 50) {		\
			for (; __printed__ < 50; __printed__++)		\
				printf(" ");				\
		}							\
	} while (0)

#define OK(name, ...)							\
	do {								\
		wunit_ctx.current->ok++;				\
		MSG(name, ##__VA_ARGS__); printf(" OK\n");		\
	} while (0)

#define FAIL(name, ...)							\
	do {								\
		wunit_ctx.current->fail++;				\
		MSG(name, ##__VA_ARGS__); printf(" FAILED\n");		\
	} while (0)

#define CHECK2(stm, name, ...)						\
	do {								\
		wunit_ctx.current->checks++;				\
		if (stm) {						\
			OK(name, ##__VA_ARGS__);			\
		} else {						\
			FAIL(name, ##__VA_ARGS__);			\
		}							\
	} while (0)

#define CHECK(stm)		CHECK2(stm, #stm)

#define TESTCASE(ts_name)								\
	static void testcase_##ts_name(void);						\
	static void wunit_register_##ts_name(void)     __attribute__((constructor));	\
	static void wunit_register_##ts_name(void)					\
	{										\
		unsigned int i = wunit_ctx.testcases_idx;				\
		ni_assert((i + 1) < MAX_TESTCASES);					\
		memset(&wunit_ctx.testcases[i], 0, sizeof(wunit_ctx.testcases[0]));	\
		wunit_ctx.testcases[i].func = testcase_##ts_name;			\
		wunit_ctx.testcases[i].name = #ts_name;					\
		wunit_ctx.testcases_idx++;						\
	}										\
	static void testcase_##ts_name(void)

#define TESTMAIN()									\
	int main(int argc, char *argv[])						\
	{										\
		unsigned int i;								\
		for (i = 0; i < wunit_ctx.testcases_idx; i++) {				\
			printf("\n#### %s\n", wunit_ctx.testcases[i].name);		\
			wunit_ctx.current = &wunit_ctx.testcases[i];			\
			wunit_ctx.testcases[i].func();					\
			if (wunit_ctx.current->fail > 0)				\
				wunit_ctx.fail++;					\
			else								\
				wunit_ctx.ok++;						\
		}									\
		printf("\n\nResults of %d testcases: ", wunit_ctx.testcases_idx);	\
		printf("(failed: %d) ", wunit_ctx.fail);				\
		printf("(ok: %d)\n", wunit_ctx.ok);					\
		printf("==============================================================="\
				"=========\n");						\
		for (i = 0; i < wunit_ctx.testcases_idx; i++)				\
			printf(" %3d: %-59.*s %s\n", i + 1,				\
				60, wunit_ctx.testcases[i].name,			\
				wunit_ctx.testcases[i].fail > 0 ? "FAILED" : "OK");	\
											\
		return wunit_ctx.fail > 0 ? 1 : 0;					\
	}
