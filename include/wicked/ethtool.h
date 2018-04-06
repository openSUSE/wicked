/*
 *	ethtool support
 *
 *	Copyright (C) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 *		Olaf Kirch <okir@suse.de>
 */
#ifndef WICKED_ETHTOOL_H
#define WICKED_ETHTOOL_H

#include <wicked/types.h>

/*
 * driver-info
 */
typedef enum {
	NI_ETHTOOL_DRIVER_SUPP_PRIV_FLAGS,
	NI_ETHTOOL_DRIVER_SUPP_STATS,
	NI_ETHTOOL_DRIVER_SUPP_TEST,
	NI_ETHTOOL_DRIVER_SUPP_EEPROM,
	NI_ETHTOOL_DRIVER_SUPP_REGDUMP,
} ni_ethtool_driver_supports_bit_t;

typedef struct ni_ethtool_driver_info {
	char *			driver;
	char *			version;
	char *			bus_info;
	char *			fw_version;
	char *			erom_version;

	struct {
		unsigned int	bitmap;

		unsigned int	n_priv_flags;
		unsigned int	n_stats;
		unsigned int	testinfo_len;
		unsigned int	eedump_len;
		unsigned int	regdump_len;
	} supports;
} ni_ethtool_driver_info_t;


/*
 * driver specific priv-flags
 */
typedef struct ni_ethtool_priv_flags {
	ni_string_array_t		names;
	unsigned int			bitmap;
} ni_ethtool_priv_flags_t;


/*
 * device ethtool structure
 */
struct ni_ethtool {
	ni_bitfield_t			supported;

	/* read-only info        */
	ni_ethtool_driver_info_t *	driver_info;

	/* configurable (later)  */
	ni_ethtool_priv_flags_t *	priv_flags;
};

extern ni_ethtool_t *			ni_ethtool_new(void);
extern void				ni_ethtool_free(ni_ethtool_t *);

extern ni_ethtool_driver_info_t *	ni_ethtool_driver_info_new(void);
extern void				ni_ethtool_driver_info_free(ni_ethtool_driver_info_t *);
extern const char *			ni_ethtool_driver_supports_map_bit(ni_ethtool_driver_supports_bit_t);
extern int				ni_ethtool_get_driver_info(const ni_netdev_ref_t *, ni_ethtool_t *);

extern ni_ethtool_priv_flags_t *	ni_ethtool_priv_flags_new(void);
extern void				ni_ethtool_priv_flags_free(ni_ethtool_priv_flags_t *);
extern int				ni_ethtool_get_priv_flags(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_priv_flags(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_priv_flags_t *);

#endif /* WICKED_ETHTOOL_H */
