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
	ni_client_state_t *client_state;
	const unsigned int ifindex1 = 1, ifindex2 = 2;

	ni_global.config = ni_config_new();

	client_state = ni_client_state_new(NI_FSM_STATE_DEVICE_DOWN);
	if (!client_state)
		return 1;

	ni_client_state_save(client_state, ifindex1);
	ni_client_state_load(client_state, ifindex1);
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_set_state(client_state, NI_FSM_STATE_ADDRCONF_UP);
	ni_client_state_save(client_state, ifindex1);
	ni_client_state_load(client_state, ifindex1);
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_move(ifindex1, ifindex2);
	ni_client_state_load(client_state, ifindex2);
	printf("client_state.init_state: %s\n", ni_ifworker_state_name(client_state->init_state));
	printf("client_state.init_time: %ld.%ld\n", client_state->init_time.tv_sec, client_state->init_time.tv_usec);
	printf("client_state.last_time: %ld.%ld\n", client_state->last_time.tv_sec, client_state->last_time.tv_usec);

	ni_client_state_free(client_state);
	ni_client_state_drop(ifindex2);

	ni_config_free(ni_global.config);
	return 0;
}
