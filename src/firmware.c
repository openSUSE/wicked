/*
 * Discover network interfaces configured by the firmware (eg iBFT)
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include <wicked/xml.h>
#include "buffer.h"
#include "appconfig.h"
#include "process.h"
#include "debug.h"

/*
 * Run all the netif firmware discovery scripts and return their output
 * as one large buffer.
 */
static ni_buffer_t *
__ni_netconfig_firmware_discovery(void)
{
	ni_buffer_t *result;
	ni_config_t *config = ni_global.config;
	ni_extension_t *ex;

	result = calloc(1, sizeof(*result));
	ni_buffer_init_dynamic(result, 1024);

	ni_assert(config);
	for (ex = config->fw_extensions; ex; ex = ex->next) {
		ni_script_action_t *script;

		if (ex->c_bindings)
			ni_warn("builtins specified in a netif-firmware-discovery element: not supported");

		for (script = ex->actions; script; script = script->next) {
			ni_process_t *process;
			int rv;

			ni_debug_objectmodel("trying to discover netif config via firmware service \"%s\"", script->name);

			/* Create an instance of this command */
			process = ni_process_new(script->process);

			rv = ni_process_run_and_capture_output(process, result);
			ni_process_free(process);

			if (rv < 0) {
				ni_error("error in firmware discovery script \"%s\"", script->name);
				ni_buffer_free(result);
				return NULL;
			}
		}
	}

	return result;
}

/*
 * Run all the netif firmware discovery scripts and return their output
 * as an XML document
 */
xml_document_t *
ni_netconfig_firmware_discovery(void)
{
	ni_buffer_t *buffer;
	xml_document_t *doc;

	buffer = __ni_netconfig_firmware_discovery();
	if (buffer == NULL)
		return NULL;

	ni_trace("%s: buffer has %u bytes", __func__, ni_buffer_count(buffer));
	doc = xml_document_from_buffer(buffer);
	ni_buffer_free(buffer);

	if (doc == NULL)
		ni_error("%s: error processing document", __func__);

	return doc;
}
