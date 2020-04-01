/*
 *	wicked client utilities to parse sysctl/ifsysctl files.
 *
 *	Copyright (C) 2011-2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
#ifndef   __WICKED_CLIENT_SÜSE_IFSYSCTL_H__
#define   __WICKED_CLIENT_SÜSE_IFSYSCTL_H__

#include <wicked/util.h>

/*
 * In default sysctl format, a '.' in the interface name has
 * to be rewritten into '/', e.g.:
 * 	"net.ipv6.conf.eth0/42.forwarding".
 *
 * There is an alternative format allowing a normal ifnames:
 * 	"net/ipv6/conf/eth0.42/forwarding"
 *
 * The keys in the array are stored in the native slash format,
 * but the set/get functions to access it accept both formats,
 * so you don't need to rewrite interface names to use a slash
 * instead of a dot before calling them.
 */


/*
 * Loads sysctl settings from file and adds them to a var array.
 * Array is not cleared, so it can be used with multiple files.
 */
extern ni_bool_t	ni_ifsysctl_file_load(ni_var_array_t *vars,
					const char *filename);

/*
 * A ni_var_array_get variant allowing to use a printf format
 * to construct the sysctl attribute path.
 */
extern ni_var_t *	ni_ifsysctl_vars_get(const ni_var_array_t *vars,
					const char *keyfmt, ...);

/*
 * A ni_var_array_set variant allowing to use a printf format
 * to construct the sysctl attribute path.
 */
extern ni_bool_t	ni_ifsysctl_vars_set(ni_var_array_t *vars,
					const char *value,
					const char *keyfmt, ...);

#endif /* __WICKED_CLIENT_SÜSE_IFSYSCTL_H__ */
