/*
 *	Discover network interfaces config provided by firmware (eg iBFT)
 *
 *	Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2023 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 *
 */
#ifndef NI_WICKED_FIRMWARE_UTILS_H
#define NI_WICKED_FIRMWARE_UTILS_H

typedef struct ni_netif_firmware_ifnames	ni_netif_firmware_ifnames_t;

struct ni_netif_firmware_ifnames {
	ni_netif_firmware_ifnames_t *	next;
	char *				fwname;
	ni_string_array_t 		ifnames;
};

extern void				ni_netif_firmware_ifnames_free(ni_netif_firmware_ifnames_t *);
extern ni_netif_firmware_ifnames_t *	ni_netif_firmware_ifnames_new(const char *);
extern ni_bool_t			ni_netif_firmware_ifnames_list_append(ni_netif_firmware_ifnames_t **,
									ni_netif_firmware_ifnames_t *);
extern void				ni_netif_firmware_ifnames_list_destroy(ni_netif_firmware_ifnames_t **);

extern ni_bool_t			ni_netif_firmware_discover_ifnames(ni_netif_firmware_ifnames_t **,
							const char *, const char *, const char *);

extern ni_bool_t			ni_netif_firmware_discover_ifconfig(xml_document_array_t *,
							const char *, const char *, const char *);

#endif /* NI_WICKED_FIRMWARE_UTILS_H */
