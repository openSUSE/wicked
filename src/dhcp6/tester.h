/*
 *	wicked dhcp6 in test (request offer/lease) mode
 *
 *	Copyright (C) 2013-2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifndef   __WICKED_DHCP6_TESTER_H__
#define   __WICKED_DHCP6_TESTER_H__

enum {
	NI_DHCP6_TESTER_OUT_LEASE_INFO,
	NI_DHCP6_TESTER_OUT_LEASE_XML,
};

typedef struct ni_dhcp6_tester {
	const char *	ifname;
	unsigned int	timeout;
	const char *	request;
	const char *	output;
	unsigned int	outfmt;
	ni_dhcp6_mode_t	mode;
} ni_dhcp6_tester_t;

extern ni_dhcp6_tester_t *	ni_dhcp6_tester_init(void);
extern ni_bool_t		ni_dhcp6_tester_set_outfmt(const char *, unsigned int *);

extern int			ni_dhcp6_tester_run(ni_dhcp6_tester_t *);

#endif /* __WICKED_DHCP6_TESTER_H__ */
