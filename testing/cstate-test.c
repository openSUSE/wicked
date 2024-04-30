#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <signal.h>
#include <stdio.h>

#include <wicked/fsm.h>

#include "appconfig.h"
#include "client/client_state.h"

extern ni_global_t ni_global;

int main(int argc, char **argv)
{
	ni_client_state_t *cs;
	const unsigned int ifindex1 = 1, ifindex2 = 2;

	ni_global.config = ni_config_new();
	ni_enable_debug("all");

	if (!(cs = ni_client_state_new()))
		return 1;

	ni_client_state_debug("Test0", cs, "print");

	ni_client_state_save(cs, ifindex1);
	ni_client_state_load(cs, ifindex1);
	ni_client_state_debug("Test1", cs, "print");

	ni_client_state_save(cs, ifindex1);
	ni_client_state_load(cs, ifindex1);
	ni_client_state_debug("Test2", cs, "print");

	ni_client_state_move(ifindex1, ifindex2);
	ni_client_state_load(cs, ifindex2);
	ni_client_state_debug("Test3", cs, "print");

	ni_client_state_free(cs);
	ni_client_state_drop(ifindex2);

	ni_config_free(ni_global.config);
	return 0;
}
