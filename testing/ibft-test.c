#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/ibft.h>
#include "src/sysfs.h"

int main(void)
{
	ni_ibft_nic_array_t nics = NI_IBFT_NIC_ARRAY_INIT;

	unsigned int i;

	if(ni_sysfs_ibft_scan_nics(&nics) <= 0)
		return 0;

	for(i = 0; i < nics.count; ++i) {
		char buf[64] = {'\0'};

		ni_ibft_nic_t *nic = nics.data[i];
		printf("node: %s\n", nic->node);
		printf(" devpath: %s\n", nic->devpath);
		printf(" ifname:  %s\n", nic->ifname);
		printf(" ifindex: %u\n", nic->ifindex);

		printf(" index: %u\n",  nic->index);
		printf(" flags: %u\n",  nic->flags);
		printf(" origin: %u\n", nic->origin);
		printf(" vlan: %u\n",   nic->vlan);

		ni_link_address_format(&nic->hwaddr, buf, sizeof(buf));
		printf(" hwaddr   : %s\n", buf);
		printf(" ipaddr   : %s/%u\n", ni_sockaddr_format(&nic->ipaddr, buf, sizeof(buf)), nic->prefix_len);

		printf(" dhcp     : %s\n", ni_sockaddr_format(&nic->dhcp, buf, sizeof(buf)));
		printf(" gateway  : %s\n", ni_sockaddr_format(&nic->gateway, buf, sizeof(buf)));
		printf(" pri_dns  : %s\n", ni_sockaddr_format(&nic->primary_dns, buf, sizeof(buf)));
		printf(" sec_dns  : %s\n", ni_sockaddr_format(&nic->secondary_dns, buf, sizeof(buf)));

		printf(" hostname: %s\n", nic->hostname);

		printf("\n");
	}

	ni_ibft_nic_array_destroy(&nics);

	return 0;
}
