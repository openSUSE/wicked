
#include <wicked/types.h>
#include <wicked/lldp.h>
#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <stdlib.h>
#include "util_priv.h"
#include "debug.h"

ni_lldp_t *
ni_lldp_new(void)
{
	ni_lldp_t *lldp;

	lldp = xcalloc(1, sizeof(*lldp));
	return lldp;
}

void
ni_lldp_free(ni_lldp_t *lldp)
{
	if (lldp) {
		ni_string_free(&lldp->chassis_id.string_value);
		ni_string_free(&lldp->port_id.string_value);
		free(lldp);
	}
}

int
ni_system_lldp_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_lldp_t *lldp)
{
	ni_trace("ni_system_lldp_setup(%s, lldp=%p)", dev->name, lldp);
	if (lldp) {
		if (lldp->chassis_id.type == NI_LLDP_CHASSIS_ID_MAC_ADDRESS) {
			ni_trace("chassis-id subtype=%u macaddr=%s", lldp->chassis_id.type,
					ni_link_address_print(&lldp->chassis_id.mac_addr_value));
		} else 
			ni_trace("chassis-id subtype=%u string=%s", lldp->chassis_id.type, lldp->chassis_id.string_value);
		ni_trace("port-id subtype=%u string=%s", lldp->port_id.type, lldp->port_id.string_value);
	}
	return 0;
}
