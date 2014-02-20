#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <wicked/types.h>
#include <wicked/netinfo.h>

#include "ibft.h"

int main(void)
{
	ni_ibft_nic_array_t nics = NI_IBFT_NIC_ARRAY_INIT;
	const char *root = NULL;
	unsigned int i;

	/* Use local directory */
	if (!ni_file_exists("/sys/firmware/ibft"))
		root = "./ibft";

	if(ni_sysfs_ibft_scan_nics(&nics, root) <= 0)
		return 0;

	for(i = 0; i < nics.count; ++i) {
		ni_ibft_nic_t *nic = nics.data[i];

		printf("node: %s\n", nic->node);
		printf("  devpath  : %s\n", nic->devpath);
		printf("  ifname   :  %s\n", nic->ifname);
		printf("  ifindex  : %u\n", nic->ifindex);

		printf("  index    : %u\n",  nic->index);
		printf("  flags    : %u\n",  nic->flags);
		printf("  origin   : %u\n", nic->origin);
		printf("  vlan     : %u\n",   nic->vlan);

		printf("  hwaddr   : %s\n", ni_link_address_print(&nic->hwaddr));
		printf("  ipaddr   : %s/%u\n", ni_sockaddr_print(&nic->ipaddr),
						nic->prefix_len);

		printf("  dhcp     : %s\n", ni_sockaddr_print(&nic->dhcp));
		printf("  gateway  : %s\n", ni_sockaddr_print(&nic->gateway));
		printf("  pri_dns  : %s\n", ni_sockaddr_print(&nic->primary_dns));
		printf("  sec_dns  : %s\n", ni_sockaddr_print(&nic->secondary_dns));

		printf("  hostname : %s\n", nic->hostname);

		printf("\n");
	}

	ni_ibft_nic_array_destroy(&nics);

	return 0;
}
