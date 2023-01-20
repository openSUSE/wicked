/*
 * Handle extensions (aka external commands to configure aspects of
 * the network).
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
 * C Bindings
 */
ni_c_binding_t *
ni_c_binding_new(ni_c_binding_t **list, const char *name, const char *library, const char *symbol)
{
	ni_c_binding_t *binding, **pos;

	for (pos = list; (binding = *pos) != NULL; pos = &binding->next)
		;

	binding = xcalloc(1, sizeof(*binding));
	ni_string_dup(&binding->name, name);
	ni_string_dup(&binding->library, library);
	ni_string_dup(&binding->symbol, symbol);

	*pos = binding;
	return binding;
}

static void
ni_c_binding_free(ni_c_binding_t *binding)
{
	ni_string_free(&binding->name);
	ni_string_free(&binding->library);
	ni_string_free(&binding->symbol);
	free(binding);
}

void *
ni_c_binding_get_address(const ni_c_binding_t *binding)
{
	void *handle;
	void *addr;

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

/*
 * Script action
 */
static ni_script_action_t *
ni_script_action_new(const char *name, ni_script_action_t **list)
{
	ni_script_action_t *script;

	while ((script = *list) != NULL)
		list = &script->next;

	script = calloc(1, sizeof(*script));
	ni_string_dup(&script->name, name);
	*list = script;

	return script;
}

static void
ni_script_action_free(ni_script_action_t *script)
{
	ni_string_free(&script->name);
	if (script->process)
		ni_shellcmd_release(script->process);
	free(script);
}

/*
 * Extension
 */
ni_extension_t *
ni_extension_new(ni_extension_t **list, const char *interface)
{
	ni_extension_t *ex;

	ex = calloc(1, sizeof(*ex));
	ni_string_dup(&ex->name, interface);
	ni_string_dup(&ex->interface, interface);

	while (*list)
		list = &(*list)->next;
	*list = ex;

	return ex;
}

void
ni_extension_free(ni_extension_t *ex)
{
	ni_script_action_t *act;
	ni_c_binding_t *binding;

	ni_string_free(&ex->name);
	ni_string_free(&ex->interface);

	ni_config_fslocation_destroy(&ex->statedir);

	while ((act = ex->actions) != NULL) {
		ex->actions = act->next;
		ni_script_action_free(act);
	}

	while ((binding = ex->c_bindings) != NULL) {
		ex->c_bindings = binding->next;
		ni_c_binding_free(binding);
	}

	ni_var_array_destroy(&ex->environment);
}

void
ni_extension_list_destroy(ni_extension_t **list)
{
	ni_extension_t *ex;

	while ((ex = *list) != NULL) {
		*list = ex->next;
		ni_extension_free(ex);
	}
}

ni_extension_t *
ni_extension_list_find(ni_extension_t *head, const char *name)
{
	ni_extension_t *ex;

	for (ex = head; ex; ex = ex->next) {
		if (!strcmp(ex->interface, name))
			return ex;
	}

	return NULL;
}

ni_extension_t *
ni_extension_by_name(ni_extension_t *head, const char *name)
{
	ni_extension_t *ex;

	for (ex = head; ex; ex = ex->next) {
		if (!strcmp(ex->name, name))
			return ex;
	}

	return NULL;
}

ni_shellcmd_t *
ni_extension_script_new(ni_extension_t *extension, const char *name, const char *command)
{
	ni_script_action_t *script;

	script = ni_script_action_new(name, &extension->actions);
	script->process = ni_shellcmd_parse(command);

	return script->process;
}

ni_shellcmd_t *
ni_extension_script_find(ni_extension_t *extension, const char *name)
{
	ni_script_action_t *script;

	for (script = extension->actions; script; script = script->next) {
		if (!strcmp(script->name, name))
			return script->process;
	}
	return NULL;
}

ni_script_action_t *
ni_extension_get_action(const ni_extension_t *ex, const char *name)
{
	ni_script_action_t *script;

	for (script = ex->actions; script; script = script->next) {
		if (!strcmp(script->name, name))
			return script;
	}
	return NULL;
}

const ni_c_binding_t *
ni_extension_find_c_binding(const ni_extension_t *extension, const char *name)
{
	ni_c_binding_t *binding;

	for (binding = extension->c_bindings; binding; binding = binding->next) {
		if (!strcmp(binding->name, name))
			return binding;
	}
	return NULL;
}
