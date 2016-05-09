/*
 *	Interfacing with systemd using systemctl
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef NI_SYSTEMCTL_H
#define NI_SYSTEMCTL_H

/*
 * Systemd helpers
 */
extern int		ni_systemctl_service_start(const char *);
extern int		ni_systemctl_service_stop(const char *);

extern const char *	ni_systemctl_service_show_property(const char *, const char *, char **);

#endif /* NI_SYSTEMCTL_H */
