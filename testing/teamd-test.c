#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <wicked/types.h>
#include <wicked/netinfo.h>

#include "teamd.h"
#include "json.h"

int main(int argc, char **argv)
{
	ni_teamd_client_t *tdc;
	const char *command, *param1, *param2, *val = NULL;
	ni_json_t *json;
	int rv = 0;

	if (argc < 3) {
		printf("Usage: teamd-test ifname command [param1] [param2]\n");
		return -2;
	}
	command = argv[2];
	param1 = argv[3];
	param2 = argv[4];

	tdc = ni_teamd_client_open(argv[1]);

	if (ni_string_eq(command, "state-item-get"))
		val = ni_teamd_ctl_state_get_item(tdc, param1);
	else if (ni_string_eq(command, "state-item-set"))
		rv = ni_teamd_ctl_state_set_item(tdc, param1, param2);
	else if (ni_string_eq(command, "state-dump"))
		val = ni_teamd_ctl_state_dump(tdc);
	else if (ni_string_eq(command, "config-dump"))
		val = ni_teamd_ctl_config_dump(tdc, FALSE);
	else if (ni_string_eq(command, "config-dump-actual"))
		val = ni_teamd_ctl_config_dump(tdc, TRUE);

	printf("%s\n", val ? val : ni_format_boolean(!!rv));

	if (val && (json = ni_json_parse_string(val))) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		ni_json_format_string(&buf, json, NULL);
		printf("type<%s>: %s\n",
			ni_json_type_name(ni_json_type(json)), buf.string);
		ni_stringbuf_destroy(&buf);
		ni_json_free(json);
	} else if (val) {
		printf("json parsing error\n");
	}

	return rv;
}
