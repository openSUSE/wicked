/*
 *	Extensions aka external commands and bindings defined in appconfig.
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>

#include "appconfig.h"
#include "extension.h"
#include "process.h"
#include "util_priv.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <dlfcn.h>

/*
 * basic list operation macro helper function bodies
 */
#define ni_slist_tail(tail)						\
	while (tail && tail->next) {					\
		tail = tail->next;					\
	}

#define ni_slist_insert(list, head, tail)				\
	if (list && head) {						\
		tail->next = *list;					\
		*list = head;						\
		return TRUE;						\
	}

#define ni_slist_append(list, item) 					\
	if (list && item) {						\
		while (*list)						\
			list = &(*list)->next;				\
		*list = item;						\
		return TRUE;						\
	}

#define ni_slist_remove(list, item, pos, cur)				\
	if (list && item) {						\
		for (pos = list; (cur = *pos); pos = &cur->next) {	\
			if (item == cur) {				\
				*pos = cur->next;			\
				cur->next = NULL;			\
				return TRUE;				\
			}						\
		}							\
	}

#define ni_slist_destroy(list, item, free_fn)				\
	if (list) {							\
		while ((item = *list)) {				\
			*list = item->next;				\
			free_fn(item);					\
		}							\
	}

#define ni_slist_find_member(head, item, member, cmp_fn)		\
	for (item = head; item; item = item->next) {			\
		if (cmp_fn(item->member, member))			\
			return item;					\
	}

/*
 * C Binding / builtin action
 */
ni_c_binding_t *
ni_c_binding_new(const char *name, const char *library, const char *symbol)
{
	ni_c_binding_t *binding;

	if (!(binding = calloc(1, sizeof(*binding))))
		return NULL;

	binding->enabled = TRUE;
	if (!ni_string_dup(&binding->name, name) ||
	    !ni_string_dup(&binding->library, library) ||
	    !ni_string_dup(&binding->symbol, symbol))
		ni_c_binding_free(binding);
	else
		return binding;

	return NULL;
}

void
ni_c_binding_free(ni_c_binding_t *binding)
{
	if (binding) {
		ni_string_free(&binding->name);
		ni_string_free(&binding->library);
		ni_string_free(&binding->symbol);
		free(binding);
	}
}

void *
ni_c_binding_get_address(const ni_c_binding_t *binding)
{
	void *handle;
	void *addr;

	if (!binding)
		return NULL;

	handle = dlopen(binding->library, RTLD_LAZY);
	if (handle == NULL) {
		ni_error("invalid binding for %s - cannot dlopen(%s): %s",
				binding->name, binding->library?: "<main>", dlerror());
		return NULL;
	}

	addr = dlsym(handle, binding->symbol);
	dlclose(handle);

	if (addr == NULL) {
		ni_error("invalid binding for %s - no such symbol in %s: %s",
				binding->name, binding->library?: "<main>", binding->symbol);
		return NULL;
	}

	return addr;
}

ni_bool_t
ni_c_binding_list_insert(ni_c_binding_t **list, ni_c_binding_t *item)
{
	ni_c_binding_t *tail = item;

	ni_slist_tail(tail);
	ni_slist_insert(list, item, tail);
	return FALSE;
}

ni_bool_t
ni_c_binding_list_append(ni_c_binding_t **list, ni_c_binding_t *item)
{
	ni_slist_append(list, item);
	return FALSE;
}

ni_bool_t
ni_c_binding_list_remove(ni_c_binding_t **list, ni_c_binding_t *item)
{
	ni_c_binding_t **pos, *cur;

	ni_slist_remove(list, item, pos, cur);
	return FALSE;
}

ni_bool_t
ni_c_binding_list_replace(ni_c_binding_t **list, ni_c_binding_t *oitem,
		ni_c_binding_t *nitem)
{
	ni_c_binding_t **pos, *cur, *tail = nitem;

	if (!list || !oitem || !nitem)
		return FALSE;

	while (tail && tail->next)
		tail = tail->next;

	for (pos = list; (cur = *pos); pos = &cur->next) {
		if (oitem == cur) {
			tail->next = cur->next;
			cur->next = NULL;
			*pos = nitem;
			return TRUE;
		}
	}
	return FALSE;
}

void
ni_c_binding_list_destroy(ni_c_binding_t **list)
{
	ni_c_binding_t *item;

	ni_slist_destroy(list, item, ni_c_binding_free);
}

ni_c_binding_t *
ni_c_binding_list_find(ni_c_binding_t *head, const char *name)
{
	ni_c_binding_t *item;

	ni_slist_find_member(head, item, name, ni_string_eq);
	return NULL;
}


/*
 * Script action
 */
ni_script_action_t *
ni_script_action_new(const char *name, const char *command)
{
	ni_script_action_t *script;

	if (!(script = calloc(1, sizeof(*script))))
		return NULL;

	script->enabled = TRUE;
	if (!ni_string_dup(&script->name, name) ||
	    !(script->process = ni_shellcmd_parse(command)))
		ni_script_action_free(script);
	else
		return script;

	return NULL;
}

void
ni_script_action_free(ni_script_action_t *script)
{
	if (script) {
		ni_string_free(&script->name);
		if (script->process)
			ni_shellcmd_release(script->process);
		free(script);
	}
}

ni_bool_t
ni_script_action_list_insert(ni_script_action_t **list, ni_script_action_t *item)
{
	ni_script_action_t *tail = item;

	ni_slist_tail(tail);
	ni_slist_insert(list, item, tail);
	return FALSE;
}

ni_bool_t
ni_script_action_list_append(ni_script_action_t **list, ni_script_action_t *item)
{
	ni_slist_append(list, item);
	return FALSE;
}

ni_bool_t
ni_script_action_list_remove(ni_script_action_t **list, ni_script_action_t *item)
{
	ni_script_action_t **pos, *cur;

	ni_slist_remove(list, item, pos, cur);
	return FALSE;
}

ni_bool_t
ni_script_action_list_replace(ni_script_action_t **list, ni_script_action_t *oitem,
		ni_script_action_t *nitem)
{
	ni_script_action_t **pos, *cur, *tail = nitem;

	if (!list || !oitem || !nitem)
		return FALSE;

	while (tail && tail->next)
		tail = tail->next;

	for (pos = list; (cur = *pos); pos = &cur->next) {
		if (oitem == cur) {
			tail->next = cur->next;
			cur->next = NULL;
			*pos = nitem;
			return TRUE;
		}
	}
	return FALSE;
}

void
ni_script_action_list_destroy(ni_script_action_t **list)
{
	ni_script_action_t *item;

	ni_slist_destroy(list, item, ni_script_action_free);
}

ni_script_action_t *
ni_script_action_list_find(ni_script_action_t *head, const char *name)
{
	ni_script_action_t *item;

	ni_slist_find_member(head, item, name, ni_string_eq);
	return NULL;
}


/*
 * Extension
 */
ni_extension_t *
ni_extension_new(const char *interface)
{
	ni_extension_t *ex;

	if (!(ex = calloc(1, sizeof(*ex))))
		return NULL;

	ex->enabled = TRUE;
	if (!ni_string_dup(&ex->name, interface) ||
	    !ni_string_dup(&ex->interface, interface))
		ni_extension_free(ex);
	else
		return ex;

	return NULL;
}

void
ni_extension_free(ni_extension_t *ex)
{
	if (ex) {
		ni_string_free(&ex->name);
		ni_string_free(&ex->interface);

		ni_script_action_list_destroy(&ex->actions);
		ni_c_binding_list_destroy(&ex->c_bindings);

		ni_var_array_destroy(&ex->environment);
		ni_config_fslocation_destroy(&ex->statedir);
	}
}

ni_bool_t
ni_extension_list_insert(ni_extension_t **list, ni_extension_t *item)
{
	ni_extension_t *tail = item;

	ni_slist_tail(tail);
	ni_slist_insert(list, item, tail);
	return FALSE;
}

ni_bool_t
ni_extension_list_append(ni_extension_t **list, ni_extension_t *item)
{
	ni_slist_append(list, item);
	return FALSE;
}

ni_bool_t
ni_extension_list_remove(ni_extension_t **list, ni_extension_t *item)
{
	ni_extension_t **pos, *cur;

	ni_slist_remove(list, item, pos, cur);
	return FALSE;
}

ni_bool_t
ni_extension_list_replace(ni_extension_t **list, ni_extension_t *oitem,
		ni_extension_t *nitem)
{
	ni_extension_t **pos, *cur, *tail = nitem;

	if (!list || !oitem || !nitem)
		return FALSE;

	while (tail && tail->next)
		tail = tail->next;

	for (pos = list; (cur = *pos); pos = &cur->next) {
		if (oitem == cur) {
			tail->next = cur->next;
			cur->next = NULL;
			*pos = nitem;
			return TRUE;
		}
	}
	return FALSE;
}

void
ni_extension_list_destroy(ni_extension_t **list)
{
	ni_extension_t *item;

	ni_slist_destroy(list, item, ni_extension_free);
}

ni_extension_t *
ni_extension_list_find(ni_extension_t *head, const char *interface)
{
	ni_extension_t *item;

	ni_slist_find_member(head, item, interface, ni_string_eq);
	return NULL;
}

/*
 * Helper utils
 */
ni_shellcmd_t *
ni_extension_find_script(ni_extension_t *ex, const char *name)
{
	ni_script_action_t *script;

	if (ex && (script = ni_script_action_list_find(ex->actions, name)))
		return script->enabled ? script->process : NULL;
	return NULL;
}

const ni_c_binding_t *
ni_extension_find_c_binding(const ni_extension_t *ex, const char *name)
{
	const ni_c_binding_t *binding;

	if (ex && (binding = ni_c_binding_list_find(ex->c_bindings, name)))
		return binding->enabled ? binding : NULL;
	return NULL;
}
