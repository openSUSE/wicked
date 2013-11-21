#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <signal.h>
#include <stdio.h>

#include <wicked/fsm.h>
#include <wicked/ifstate.h>

int main(int argc, char **argv)
{
	ni_ifstate_t *ifstate;

	ifstate = ni_ifstate_new(NI_FSM_STATE_DEVICE_DOWN);
	if (!ifstate)
		return 1;

	ni_ifstate_save(ifstate, "foo");
	ni_ifstate_load(ifstate, "foo");
	printf("ifstate.init_state: %s\n", ni_ifworker_state_name(ifstate->init_state));
	printf("ifstate.init_time: %ld.%ld\n", ifstate->init_time.tv_sec, ifstate->init_time.tv_usec);
	printf("ifstate.last_time: %ld.%ld\n", ifstate->last_time.tv_sec, ifstate->last_time.tv_usec);

	ni_ifstate_set_state(ifstate, NI_FSM_STATE_ADDRCONF_UP);
	ni_ifstate_save(ifstate, "foo");
	ni_ifstate_load(ifstate, "foo");
	printf("ifstate.init_state: %s\n", ni_ifworker_state_name(ifstate->init_state));
	printf("ifstate.init_time: %ld.%ld\n", ifstate->init_time.tv_sec, ifstate->init_time.tv_usec);
	printf("ifstate.last_time: %ld.%ld\n", ifstate->last_time.tv_sec, ifstate->last_time.tv_usec);

	ni_ifstate_move("foo", "bar");
	ni_ifstate_load(ifstate, "bar");
	printf("ifstate.init_state: %s\n", ni_ifworker_state_name(ifstate->init_state));
	printf("ifstate.init_time: %ld.%ld\n", ifstate->init_time.tv_sec, ifstate->init_time.tv_usec);
	printf("ifstate.last_time: %ld.%ld\n", ifstate->last_time.tv_sec, ifstate->last_time.tv_usec);

	ni_ifstate_free(ifstate);
	ni_ifstate_drop("bar");

	return 0;
}
