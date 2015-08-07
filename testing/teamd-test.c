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

int main(int argc, char **argv)
{
	ni_teamd_client_t *tdc;
	const char *command, *param1, *param2, *val = NULL;
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
	return rv;
}
