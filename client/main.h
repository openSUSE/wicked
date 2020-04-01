/*
 *	wicked client main commands
 *
 *	Copyright (C) 2017 SÜSE LINUX GmbH, Nuernberg, Germany.
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
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
 *
 */
#ifndef   WICKED_CLIENT_MAIN_H
#define   WICKED_CLIENT_MAIN_H

extern int	ni_do_arp(const char *caller, int argc, char **argv);
extern int	ni_do_test(const char *caller, int argc, char **argv);
extern int	ni_do_duid(const char *caller, int argc, char **argv);
extern int	ni_do_iaid(const char *caller, int argc, char **argv);
extern int	ni_do_ethtool(const char *caller, int argc, char **argv);

extern int	ni_wicked_convert(const char *caller, int argc, char **argv);

#endif /* WICKED_CLIENT_MAIN_H */
