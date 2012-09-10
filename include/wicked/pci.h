/*
 * Routines for identifying PCI devices
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifndef __NETINFO_PCI_H__
#define __NETINFO_PCI_H__

/*
 * Identify a network PCI device
 */
struct ni_pci_dev {
	char *		path;		/* path relative to /sys/devices */
	uint16_t	vendor;
	uint16_t	device;
};

extern ni_pci_dev_t *	ni_pci_dev_new(const char *path);
extern void		ni_pci_dev_free(ni_pci_dev_t *pci_dev);

#endif /* __NETINFO_PCI_H__ */
