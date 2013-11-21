#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <signal.h>
#include <stdio.h>

#include <wicked/fsm.h>

#include "client/client_state.h"

int main(int argc, char **argv)
{
	ni_client_state_t *client_state;

	client_state = ni_client_state_new(NI_FSM_STATE_DEVICE_DOWN);
	if (!client_state)
		return 1;

	ni_client_state_save(client_state, "foo");
	ni_client_state_load(client_state, "foo");
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_set_state(client_state, NI_FSM_STATE_ADDRCONF_UP);
	ni_client_state_save(client_state, "foo");
	ni_client_state_load(client_state, "foo");
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_move("foo", "bar");
	ni_client_state_load(client_state, "bar");
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_free(client_state);
	ni_client_state_drop("bar");

	return 0;
}
