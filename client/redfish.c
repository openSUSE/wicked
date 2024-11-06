/*
 *	redfish -- utils for firmware:redfish source and updater extensions
 *
 *	Copyright (C) 2022 SUSE LLC
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
 *		Marius Tomaschewski
 *
 *	--------------------------------------------------------------------
 *
 *	These utilities implement decoding of the Redfish over IP protocol
 *	settings from SMBIOS (3.0) Management Controller Host Interface
 *	(Type 42) structure to and expose the settings as "firmware:redfish"
 *	wicked interface configuration in the firmware discovery and updater
 *	extensions to setup the Network Host Interface to access to the
 *	Redfish Service used to manage the computer system available via
 *	the "redfish-localhost" or the hostname specified by redfish.
 *
 *	See also the DMTF specificatons:
 *	- https://www.dmtf.org/standards/redfish
 *	  DSP0270 1.3.0 Redfish Host Interface Specification
 *	- https://www.dmtf.org/standards/smbios
 *	  DSP0134 3.5.0 System Management BIOS (SMBIOS) Reference Specification
 *
 *	TODO:
 *	- PCI/PCIe Interface v2 decoding and processing.
 *	- Credential Bootstrapping (see jsc#SLE-17624).
 *	- "Prefered IP" address in autoconf
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <endian.h>
#include <net/if_arp.h>

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/xml.h>
#include "buffer.h"
#include "sysfs.h"
#include "main.h"

#define NI_REDFISH_CONFIG_EXTENSION	WICKED_EXTENSIONSDIR"/redfish-config"
#define NI_REDFISH_CONFIG_ORIGIN	"firmware:redfish"
#define NI_REDFISH_HOSTNAME		"redfish-localhost"
#define NI_REDFISH_HOSTS_FILE		"/etc/hosts"

#define NI_SYS_FIRMWARE_DIR		"/sys/firmware"
#define NI_SMBIOS_ENTRY_FILE		NI_SYS_FIRMWARE_DIR"/dmi/tables/smbios_entry_point"
#define NI_SMBIOS_TABLE_FILE		NI_SYS_FIRMWARE_DIR"/dmi/tables/DMI"
#define NI_SMBIOS_EPS_MAX_LEN		32
#define NI_SMBIOS_EPS_LEN_2_1		31
#define NI_SMBIOS_EPS_LEN_3_0		24
#define NI_SMBIOS_EPS_REV_2_1		0x00
#define NI_SMBIOS_EPS_REV_3_0		0x01
#define NI_SMBIOS_SIGNATURE_32		"_SM_"
#define NI_SMBIOS_SIGNATURE_64		"_SM3_"
#define NI_SMBIOS_SIGNATURE_DMI		"_DMI_"
#define NI_SMBIOS_VERSION_MAJ		0x030000
#define NI_SMBIOS_NO_FILE_OFFSET	NI_BIT(0)

typedef struct ni_smbios_epi		ni_smbios_epi_t;
typedef struct ni_smbios_header		ni_smbios_header_t;

typedef struct ni_smbios_decoder	ni_smbios_decoder_t;
typedef struct ni_smbios_handler	ni_smbios_handler_t;
typedef struct ni_smbios_entry		ni_smbios_entry_t;

typedef void				ni_smbios_entry_free_fn_t(ni_smbios_entry_t *);
typedef ni_bool_t			ni_smbios_entry_decode_fn_t(ni_smbios_decoder_t *,
							const ni_smbios_epi_t *,
							const ni_string_array_t *,
							const ni_smbios_header_t *,
							ni_buffer_t *);

static ni_bool_t			ni_smbios_epi_init(ni_smbios_epi_t *, unsigned int);

static void				ni_smbios_entry_free(ni_smbios_entry_t *);
static ni_bool_t			ni_smbios_entry_list_append(ni_smbios_entry_t **,
							ni_smbios_entry_t *);
static void				ni_smbios_entry_list_destroy(ni_smbios_entry_t **);

static ni_bool_t			ni_smbios_decoder_init(ni_smbios_decoder_t *,
							const ni_smbios_handler_t *,
							const char *);
static ni_bool_t			ni_smbios_decode(ni_smbios_decoder_t *);
static void				ni_smbios_decoder_destroy(ni_smbios_decoder_t *);

/*
 * SMBIOS (3.0) entry point info
 *  - effective unpacked info -
 */
struct ni_smbios_epi {
	/* eps info */
	unsigned int			version;
	uint8_t				eps_rev;
	uint8_t				bcd_rev;

	uint16_t			ent_max;
	uint16_t			ent_num;

	uint32_t			max_len;
	uint64_t			offset;

	/* own info */
	unsigned int			flags;
};

struct ni_smbios_header {
	uint8_t				type;
	uint8_t				length;
	uint16_t			handle;
};

struct ni_smbios_entry {
	ni_smbios_entry_t *		next;
	ni_smbios_entry_free_fn_t *	free;

	uint8_t				type;
	uint16_t			handle;
};

struct ni_smbios_handler {
	unsigned int			type;
	ni_smbios_entry_decode_fn_t *	decode;
};

struct ni_smbios_decoder {
	const ni_smbios_handler_t *	handler;
	ni_smbios_entry_t *		entries;
	char *				rootdir;
};

typedef enum {
	NI_SMBIOS_TYPE_MCHI			= 0x2a,	/* 42 */
} ni_smbios_type_t;

typedef enum {
	NI_MCHI_TYPE_NET			= 0x40,	/* 64 */
} ni_mchi_type_t;

typedef enum {
	NI_MCHI_NET_DEV_USBv1_VENDOR_ID		= 0x00,
	NI_MCHI_NET_DEV_USBv1_PRODUCT_ID	= 0x02,
	NI_MCHI_NET_DEV_USBv1_SN_LENGTH 	= 0x04,
	NI_MCHI_NET_DEV_USBv1_SN_DTYPE		= 0x05,
	NI_MCHI_NET_DEV_USBv1_SN_STRING		= 0x06,
} ni_mchi_net_dev_usb_v1_var_t;

typedef enum {
	NI_MCHI_NET_DEV_PCIv1_VENDOR_ID		= 0x00,
	NI_MCHI_NET_DEV_PCIv1_DEVICE_ID		= 0x02,
	NI_MCHI_NET_DEV_PCIv1_SUB_VENDOR_ID	= 0x04,
	NI_MCHI_NET_DEV_PCIv1_SUB_DEVICE_ID	= 0x06,
} ni_mchi_net_dev_pci_v1_var_t;

typedef enum {
	NI_MCHI_NET_DEV_USBv1			= 0x02,
	NI_MCHI_NET_DEV_PCIv1			= 0x03,
	NI_MCHI_NET_DEV_USBv2			= 0x04,
	NI_MCHI_NET_DEV_PCIv2			= 0x05,
} ni_mchi_net_dev_type_t;

typedef enum {
	NI_MCHI_NET_PCONF_REDFISH		= 0x04,
} ni_mchi_net_pconf_type_t;

typedef enum {
	NI_MCHI_NET_IP_SETUP_STATIC		= 0x01,
	NI_MCHI_NET_IP_SETUP_DHCP		= 0x02,
	NI_MCHI_NET_IP_SETUP_AUTO		= 0x03,
	NI_MCHI_NET_IP_SETUP_HOST		= 0x04,
} ni_mchi_net_ip_setup_t;

typedef enum {
	NI_MCHI_NET_IP_FAMILY_IPV4		= 0x01,
	NI_MCHI_NET_IP_FAMILY_IPV6		= 0x02,
} ni_mchi_net_ip_family_t;

typedef struct	ni_mchi_net_dev		ni_mchi_net_dev_t;
typedef struct	ni_mchi_net_dev_usb	ni_mchi_net_dev_usb_t;
typedef struct	ni_mchi_net_dev_pci	ni_mchi_net_dev_pci_t;
typedef	struct	ni_mchi_net_redfish	ni_mchi_net_redfish_t;
typedef struct	ni_mchi_net_pconf	ni_mchi_net_pconf_t;
typedef struct	ni_mchi_net		ni_mchi_net_t;
typedef struct	ni_mchi_entry		ni_mchi_entry_t;

struct	ni_mchi_net_dev_usb {
	unsigned int			vendor_id;
	unsigned int			product_id;
	char *				serial_nr;
	ni_hwaddr_t			hwaddr;
};
struct	ni_mchi_net_dev_pci {
	unsigned int			vendor_id;
	unsigned int			device_id;
	struct {
		unsigned int		vendor_id;
		unsigned int		device_id;
	} subsys;
};
struct  ni_mchi_net_dev {
	unsigned int			refcount;
	ni_netdev_ref_t			device;
	ni_mchi_net_dev_type_t		type;
	ni_mchi_net_dev_usb_t		usb;
	ni_mchi_net_dev_pci_t		pci;
};
struct	ni_mchi_net_redfish {
	ni_uuid_t			uuid;
	struct {
		ni_mchi_net_ip_family_t	family;
		ni_mchi_net_ip_setup_t	setup;
		ni_sockaddr_t		addr;
		unsigned int		plen;
	} host;
	struct {
		ni_mchi_net_ip_family_t	family;
		ni_mchi_net_ip_setup_t	setup;
		ni_sockaddr_t		addr;
		unsigned int		plen;
		unsigned int		port;
		unsigned int		vlan;
		char *			host;
	} service;
};
struct	ni_mchi_net_pconf {
	ni_mchi_net_pconf_t *		next;

	ni_mchi_net_pconf_type_t	type;
	ni_mchi_net_redfish_t		redfish;
};
struct  ni_mchi_net {
	ni_mchi_net_dev_t *		dev;
	ni_mchi_net_pconf_t *		plist;
};
struct ni_mchi_entry
{
	ni_smbios_entry_t		entry;
	ni_mchi_type_t			type;
	ni_mchi_net_t			net;
};


static const ni_intmap_t		smbios_type_name_map[] = {
	{ "Management Controller Host Interface",	NI_SMBIOS_TYPE_MCHI	},
	{ NULL }
};
static const ni_intmap_t		mchi_type_map[] = {
	/* We're using the network type only, no KCS, no UARTs */
	{ "Network",					NI_MCHI_TYPE_NET	},
	{ NULL }
};
static const ni_intmap_t		mchi_net_dev_type_map[] = {
	{ "USB",			NI_MCHI_NET_DEV_USBv1			},
	{ "PCI/PCIe",			NI_MCHI_NET_DEV_PCIv1			},
	{ "USB v2",			NI_MCHI_NET_DEV_USBv2			},
	{ NULL }
};
static const ni_intmap_t		mchi_net_protocol_map[] = {
	{ "Redfish over IP",		NI_MCHI_NET_PCONF_REDFISH		},
	{ NULL }
};
static const ni_intmap_t		mchi_net_ip_setup_map[] = {
	{ "static",			NI_MCHI_NET_IP_SETUP_STATIC		},
	{ "dhcp",			NI_MCHI_NET_IP_SETUP_DHCP		},
	{ "autoconf",			NI_MCHI_NET_IP_SETUP_AUTO		},
	{ NULL }
};
static const ni_intmap_t		mchi_net_ip_family_map[] = {
	{ "ipv4",			NI_MCHI_NET_IP_FAMILY_IPV4		},
	{ "ipv6",			NI_MCHI_NET_IP_FAMILY_IPV6		},
	{ NULL }
};

static ni_bool_t			ni_smbios_decode_mchi(ni_smbios_decoder_t *,
							const ni_smbios_epi_t *,
							const ni_string_array_t *,
							const ni_smbios_header_t *,
							ni_buffer_t *);

static const ni_smbios_handler_t	smbios_entry_decoder[] = {
	{ NI_SMBIOS_TYPE_MCHI,		ni_smbios_decode_mchi	},
	{ -1U,				NULL			}
};

typedef struct ni_hosts_entry		ni_hosts_entry_t;
typedef struct ni_hosts_entry_array	ni_hosts_entry_array_t;

struct ni_hosts_entry {
	ni_sockaddr_t		addr;
	ni_string_array_t	names;
};

#define NI_HOSTS_ENTRY_ARRAY_INIT	{ .count = 0, .data = NULL }
#define NI_HOSTS_ENTRY_ARRAY_CHUNK	2

struct ni_hosts_entry_array {
	unsigned int		count;
	ni_hosts_entry_t **	data;
};

static int				fw_ext_config_modify(const char *, char *);
static int				list_interface_names(const ni_smbios_entry_t *);
static int				show_wicked_xml_config(const ni_smbios_entry_t *);
static int				service_hosts_update(const ni_smbios_entry_t *);
static int				service_hosts_remove(void);

extern char *				opt_global_rootdir;

int
ni_wicked_redfish(const char *caller, int argc, char **argv)
{
	enum {
		OPTION_HELP	= 'h',
	};
	enum {
		ACTION_ENABLE,
		ACTION_DISABLE,
		ACTION_SHOW_CONFIG,
		ACTION_LIST_IFNAMES,
		ACTION_HOSTS_UPDATE,
		ACTION_HOSTS_REMOVE,
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ NULL }
	};
	static const ni_intmap_t	actions[] = {
		{ "enable",		ACTION_ENABLE		},
		{ "disable",		ACTION_DISABLE		},
		{ "show-config",	ACTION_SHOW_CONFIG	},
		{ "list-ifnames",	ACTION_LIST_IFNAMES	},
		{ "hosts-update",	ACTION_HOSTS_UPDATE	},
		{ "hosts-remove",	ACTION_HOSTS_REMOVE	},
		{ NULL,			-1U			}
	};
	int opt, status = NI_WICKED_RC_USAGE;
	ni_smbios_decoder_t decoder;
	unsigned int action = -1U;
	char *program = NULL, *argv0;

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "redfish");
	argv0 = argv[0];
	argv[0] = program;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL))  != -1) {
		switch (opt) {
		case OPTION_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"%s [options] <action>\n"
				"\n"
				"Options:\n"
				"  --help, -h		show this help text and exit.\n"
				"\n"
				"Actions:\n"
				"  enable		alias to `wicked firmware enable` command\n"
				"  disable		alias to `wicked firmware disable` command\n"
				"  show-config		show wicked host interface configuration\n"
				"  list-ifnames		list host interface names (incuding vlan)\n"
				"  hosts-update		update "NI_REDFISH_HOSTNAME
							" entries in "NI_REDFISH_HOSTS_FILE"\n"
				"  hosts-remove		remove "NI_REDFISH_HOSTNAME
							" entries from "NI_REDFISH_HOSTS_FILE"\n"
				"\n", program);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind]) ||
	    ni_parse_uint_mapped(argv[optind], actions, &action)) {
		fprintf(stderr, "%s: please specify an action\n", program);
		goto usage;
	}
	argv[0] = argv0;

	/* execute actions that do not need decoding */
	switch (action) {
		case ACTION_ENABLE:
		case ACTION_DISABLE:
			status = fw_ext_config_modify(caller, argv[optind]);
			goto cleanup;

		case ACTION_HOSTS_REMOVE:
			status = service_hosts_remove();
			goto cleanup;
		default:
			break;
	}

	/* decode and execute actions that need it */
	ni_smbios_decoder_init(&decoder, smbios_entry_decoder, opt_global_rootdir);
	if (!ni_smbios_decode(&decoder)) {
		switch (errno) {
			case ENOENT:
				status = NI_WICKED_RC_NOT_CONFIGURED;
				ni_info("SMBIOS sysfs tables not available");
				break;
			case EACCES:
				status = NI_WICKED_RC_NOT_ALLOWED;
				ni_info("SMBIOS decode failed: %m");
				break;
			default:
				if (errno)
					ni_error("SMBIOS decode failed[%d]: %m", errno);
				status = NI_WICKED_RC_ERROR;
				break;
		}
		ni_smbios_decoder_destroy(&decoder);
		goto cleanup;
	}
	switch (action) {
		case ACTION_HOSTS_UPDATE:
			status = service_hosts_update(decoder.entries);
			break;

		case ACTION_LIST_IFNAMES:
			status = list_interface_names(decoder.entries);
			break;

		case ACTION_SHOW_CONFIG:
			status = show_wicked_xml_config(decoder.entries);
			break;

		default:
			break;
	}
	ni_smbios_decoder_destroy(&decoder);

cleanup:
	ni_string_free(&program);
	return status;
}

static ni_hosts_entry_t *
ni_hosts_entry_new(const ni_sockaddr_t *addr, const char *name)
{
	ni_hosts_entry_t *entry;

	if (!addr || !ni_sockaddr_is_specified(addr) ||
	    !ni_check_domain_name(name, ni_string_len(name), 0))
		return NULL;

	if (!(entry = calloc(1, sizeof(*entry))))
		return NULL;

	entry->addr = *addr;
	if (ni_string_array_append(&entry->names, name) == 0)
		return entry;

	free(entry);
	return NULL;
}

static ni_bool_t
ni_hosts_entry_add_name(ni_hosts_entry_t *entry, const char *name)
{
	if (!entry || !ni_check_domain_name(name, ni_string_len(name), 0))
		return FALSE;

	if (ni_string_array_find(&entry->names, 0, name,
			ni_string_eq_nocase, NULL) != -1U)
		return FALSE;

	return ni_string_array_append(&entry->names, name) == 0;
}

static void
ni_hosts_entry_free(ni_hosts_entry_t *entry)
{
	if (entry) {
		memset(&entry->addr, 0, sizeof(entry->addr));
		ni_string_array_destroy(&entry->names);
	}
}

static ni_hosts_entry_t *
ni_hosts_entry_array_find_addr(ni_hosts_entry_array_t *array, const ni_sockaddr_t *addr)
{
	ni_hosts_entry_t *item;
	unsigned int i;

	if (!array || !addr)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		item = array->data[i];
		if (ni_sockaddr_equal(&item->addr, addr))
			return item;
	}
	return NULL;
}

static ni_bool_t
ni_hosts_entry_array_realloc(ni_hosts_entry_array_t *array, unsigned int count)
{
	ni_hosts_entry_t **newdata;
	size_t             newsize;
	unsigned int       i;

	if ((UINT_MAX - array->count) <= count)
		return FALSE;

	newsize = array->count + count;
	if ((SIZE_MAX / sizeof(*newdata)) < newsize)
		return FALSE;

	newdata = realloc(array->data, newsize * sizeof(*newdata));
	if (!newdata)
		return FALSE;

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
	return TRUE;
}

static ni_bool_t
ni_hosts_entry_array_append(ni_hosts_entry_array_t *array, ni_hosts_entry_t *entry)
{
	if (!array || !entry)
		return FALSE;

	if ((array->count % NI_HOSTS_ENTRY_ARRAY_CHUNK) == 0 &&
	    !ni_hosts_entry_array_realloc(array, NI_HOSTS_ENTRY_ARRAY_CHUNK))
		return FALSE;

	array->data[array->count++] = entry;
	return TRUE;
}

static void
ni_hosts_entry_array_destroy(ni_hosts_entry_array_t *array)
{
	ni_hosts_entry_t *item;

	if (array) {
		while (array->count) {
			array->count--;
			item = array->data[array->count];
			array->data[array->count] = NULL;
			ni_hosts_entry_free(item);
		}
		free(array->data);
		array->data = NULL;
	}
}

static FILE *
hosts_tempfile_open(const char *filename, char **tempname)
{
#if !defined(ALLPERMS)
	const mode_t allperms = (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
#else
	const mode_t allperms = ALLPERMS;
#endif
	const char *dirname, *basename;
	struct stat st;
	FILE *fp;
	int fd;

	if (ni_string_empty(filename) || !tempname ||
		!(dirname = ni_dirname(filename)) ||
		!(basename = ni_basename(filename)))
		return NULL;

	if (!ni_string_printf(tempname, "%s/.%s.XXXXXX",
			dirname, basename))
		return NULL;

	if ((fd = mkstemp(*tempname)) < 0) {
		ni_string_free(tempname);
		return NULL;
	}

	/* inherit the access permissions from filename */
	if (stat(filename, &st) < 0 || !S_ISREG(st.st_mode) ||
	    fchmod(fd, st.st_mode & allperms) < 0) {
		close(fd);
		unlink(*tempname);
		ni_string_free(tempname);
		return NULL;
	}

	if (!(fp = fdopen(fd, "we"))) {
		close(fd);
		unlink(*tempname);
		ni_string_free(tempname);
		return NULL;
	}
	return fp;
}

static ni_bool_t
hosts_entries_dump(FILE *out, const ni_hosts_entry_array_t *entries)
{
	const ni_hosts_entry_t *entry;
	unsigned int i, n;
	const char *name;

	if (!out || !entries)
		return FALSE;

	for (i = 0; i < entries->count; ++i) {
		entry = entries->data[i];

		/* should never happen, but ... */
		if (!entry || !entry->names.count)
			continue;
		if (ni_string_empty(entry->names.data[0]))
			continue;

		fputs(ni_sockaddr_print(&entry->addr), out);
		for (n = 0; n < entry->names.count; ++n) {
			name = entry->names.data[n];
			fputs(n == 0 ? "\t" : " ", out);
			fputs(name, out);
		}
		fputs("\n", out);
	}
	return TRUE;
}

static ni_bool_t
hosts_file_omit_match(const char *line, const char *omit)
{
	ni_string_array_t row = NI_STRING_ARRAY_INIT;
	char *temp = NULL;
	const char *name;
	unsigned int i;

	if (!omit || !ni_string_dup(&temp, line))
		return FALSE;

	temp[strcspn(temp, "#\n")] = '\0';
	if (ni_string_split(&row, temp, " \t", 0) < 2) {
		ni_string_array_destroy(&row);
		ni_string_free(&temp);
		return FALSE;
	}

	for (i = 1; i < row.count; ++i) {
		name = row.data[i];
		if (ni_string_eq_nocase(name, omit)) {
			ni_string_array_destroy(&row);
			ni_string_free(&temp);
			return TRUE;
		}
	}

	ni_string_array_destroy(&row);
	ni_string_free(&temp);
	return FALSE;
}

static ni_bool_t
hosts_file_update_data(FILE *file, FILE *temp, const char *omit,
			const ni_hosts_entry_array_t *entries)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t cnt;

	while ((cnt = getline(&line, &len, file)) > 0) {
		if (!isxdigit((unsigned char)line[0]) ||
		    !hosts_file_omit_match(line, omit))
			fputs(line, temp);
	}
	if (line)
		free(line);

	if (entries)
		return hosts_entries_dump(temp, entries);
	else
		return TRUE;
}

static ni_bool_t
hosts_file_update(const char *filename, const char *omit,
			const ni_hosts_entry_array_t *entries)
{
	char *realname = NULL;
	char *tempname = NULL;
	FILE *file, *temp;

	if (!omit || !ni_realpath(filename, &realname))
		return FALSE;

	if (!(file = fopen(realname, "re"))) {
		ni_string_free(&realname);
		return FALSE;
	}

	if (!(temp = hosts_tempfile_open(realname, &tempname))) {
		fclose(file);
		ni_string_free(&realname);
		return FALSE;
	}

	if (!hosts_file_update_data(file, temp, omit, entries)) {
		fclose(file);
		fclose(temp);
		unlink(tempname);
		ni_string_free(&realname);
		ni_string_free(&tempname);
		return FALSE;
	}

	fclose(temp);
	if (rename(tempname, realname) < 0) {
		fclose(file);
		unlink(tempname);
		ni_string_free(&realname);
		ni_string_free(&tempname);
		return FALSE;
	} else {
		fclose(file);
		ni_string_free(&realname);
		ni_string_free(&tempname);
		return TRUE;
	}
}


static int
service_hosts_remove(void)
{
	int status = NI_WICKED_RC_SUCCESS;

	if (!hosts_file_update(NI_REDFISH_HOSTS_FILE, NI_REDFISH_HOSTNAME, NULL)) {
		switch (errno) {
			case EROFS:
			case EACCES:
				status = NI_WICKED_RC_NOT_ALLOWED;
				break;
			default:
				status = NI_WICKED_RC_ERROR;
				break;
		}
	}
	return status;
}

static int
service_hosts_update(const ni_smbios_entry_t *entries)
{
	ni_hosts_entry_array_t hentries = NI_HOSTS_ENTRY_ARRAY_INIT;
	ni_hosts_entry_t *     hentry;
	const ni_smbios_entry_t *entry;
	const ni_mchi_entry_t *mchi;
	const ni_mchi_net_pconf_t *pconf;
	int status = NI_WICKED_RC_SUCCESS;

	for (entry = entries; entry; entry = entry->next) {
		if (entry->type != NI_SMBIOS_TYPE_MCHI)
			continue;

		mchi = (ni_mchi_entry_t *)entry;
		if (mchi->type != NI_MCHI_TYPE_NET)
			continue;

		if (!mchi->net.plist || !mchi->net.dev ||
		    ni_string_empty(mchi->net.dev->device.name))
			continue;

		for (pconf = mchi->net.plist; pconf; pconf = pconf->next) {
			if (pconf->type != NI_MCHI_NET_PCONF_REDFISH)
				continue;

			if ((hentry = ni_hosts_entry_array_find_addr(&hentries, &pconf->redfish.service.addr))) {
				ni_hosts_entry_add_name(hentry, pconf->redfish.service.host);
			} else
			if ((hentry = ni_hosts_entry_new(&pconf->redfish.service.addr, NI_REDFISH_HOSTNAME))) {
				ni_hosts_entry_add_name(hentry, pconf->redfish.service.host);
				if (!ni_hosts_entry_array_append(&hentries, hentry))
					ni_hosts_entry_free(hentry);
			}
		}
	}

	if (!hosts_file_update(NI_REDFISH_HOSTS_FILE, NI_REDFISH_HOSTNAME, &hentries)) {
		switch (errno) {
			case EROFS:
			case EACCES:
				status = NI_WICKED_RC_NOT_ALLOWED;
				break;
			default:
				status = NI_WICKED_RC_ERROR;
				break;
		}
	}
	ni_hosts_entry_array_destroy(&hentries);
	return status;
}

static int
fw_ext_config_modify(const char *caller, char *action)
{
	char *argv[] = { "firmware", action, "redfish", NULL };
	return ni_wicked_firmware(caller, 3, argv);
}

static int
list_interface_names(const ni_smbios_entry_t *entries)
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	const ni_smbios_entry_t *entry;
	const ni_mchi_entry_t *mchi;
	const ni_mchi_net_pconf_t *pconf;
	const char *name = NULL;
	char *vlan = NULL;
	unsigned int n;

	for (entry = entries; entry; entry = entry->next) {
		if (entry->type != NI_SMBIOS_TYPE_MCHI)
			continue;

		mchi = (ni_mchi_entry_t *)entry;
		if (mchi->type != NI_MCHI_TYPE_NET)
			continue;

		if (!mchi->net.plist || !mchi->net.dev ||
		    ni_string_empty(mchi->net.dev->device.name))
			continue;

		name = mchi->net.dev->device.name;
		for (pconf = mchi->net.plist; pconf; pconf = pconf->next) {
			if (pconf->type != NI_MCHI_NET_PCONF_REDFISH)
				continue;

			if (ni_string_array_index(&names, name) == -1)
				ni_string_array_append(&names, name);

			if (pconf->redfish.service.vlan) {
				ni_string_printf(&vlan, "%s.%u",
						mchi->net.dev->device.name,
						pconf->redfish.service.vlan);

				if (ni_string_array_index(&names, vlan) == -1)
					ni_string_array_append(&names, vlan);
				ni_string_free(&vlan);
			}
		}
	}

	if (names.count) {
		for (n = 0; n < names.count; ++n) {
			name = names.data[n];
			printf("%s\n", name);
		}
		ni_string_array_destroy(&names);
		return NI_WICKED_RC_SUCCESS;
	} else {
		ni_string_array_destroy(&names);
		return NI_LSB_RC_NOT_CONFIGURED;
	}
}

static xml_node_t *
xml_config_find_ifname(xml_node_t *root, const char *ifname)
{
	xml_node_t *node, *name, *action;

	for (node = root ? root->children : NULL; node; node = node->next) {
		if (ni_string_eq(node->name, "interface")) {
			name = xml_node_get_child(node, "name");
			if (name && ni_string_eq(ifname, name->cdata))
				return node;
		} else
		if (ni_string_eq(node->name, "policy")) {
			if ((action = xml_node_get_child(node, "merge")))
				name = xml_node_get_child(action, "name");
			else
			if ((action = xml_node_get_child(node, "replace")))
				name = xml_node_get_child(action, "name");
			else
				name = NULL;
			if (name && ni_string_eq(ifname, name->cdata))
				return node;
		}
	}
	return NULL;
}

static xml_node_t *
xml_config_init_scripts(xml_node_t *conf)
{
	xml_node_t *scripts, *script;

	if (!(scripts = xml_node_create(conf, "scripts")))
		return NULL;

	if ((script = xml_node_create(scripts, "post-up")))
		xml_node_new_element_unique("script", script, "wicked:redfish-update");

	if ((script = xml_node_create(scripts, "pre-down")))
		xml_node_new_element_unique("script", script, "wicked:redfish-update");

	return scripts;
}

static xml_node_t *
xml_config_init_ifname(xml_node_t *root, const char *ifname)
{
	xml_node_t *conf, *node;

	if ((conf = xml_config_find_ifname(root, ifname)))
		return conf;

	if (!(conf = xml_node_new("interface", root)))
		return NULL;

	xml_node_add_attr(conf, "origin", NI_REDFISH_CONFIG_ORIGIN);

	if (!(node = xml_node_create(conf, "name")))
		return NULL;

	xml_node_set_cdata(node, ifname);

	if (!(node = xml_config_init_scripts(conf)))
		return NULL;

	return conf;
}

static xml_node_t *
xml_config_init_vlan(xml_node_t *conf, const char *ifname, unsigned int vlan)
{
	xml_node_t *node;

	if ((node = xml_node_create(conf, "vlan"))) {
		xml_node_new_element_unique("device", node, ifname);
		xml_node_new_element_unique("tag", node, ni_sprint_uint(vlan));
	}
	return node;
}

static xml_node_t *
xml_config_init_ifvlan(xml_node_t *root, const char *ifname, unsigned int vlan)
{
	xml_node_t *conf;
	char *vname = NULL;

	if (!ni_string_printf(&vname, "%s.%u", ifname, vlan))
		return NULL;

	conf = xml_config_init_ifname(root, vname);
	ni_string_free(&vname);
	if (conf && xml_config_init_vlan(conf, ifname, vlan))
		return conf;

	return NULL;
}

static xml_node_t *
xml_config_setup_ipv4(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node;

	if ((node = xml_node_create(conf, "ipv4"))) {
		xml_node_new_element_unique("enabled", node, "true");
	}
	return node;
}

static xml_node_t *
xml_config_setup_ipv6(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node;

	if ((node = xml_node_create(conf, "ipv6"))) {
		xml_node_new_element_unique("enabled", node, "true");
	}
	return node;
}

static xml_node_t *
xml_config_setup_auto4(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto;

	if (!(proto = xml_config_setup_ipv4(conf, redfish)))
		return NULL;

	if ((node = xml_node_create(conf, "ipv4:auto"))) {
		xml_node_new_element_unique("enabled", node, "true");
	}
	return node;
}

static xml_node_t *
xml_config_setup_auto6(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto;

	if (!(proto = xml_config_setup_ipv6(conf, redfish)))
		return NULL;

	/* Make sure, we process RA even host is using forwarding=1 */
	xml_node_new_element_unique("accept-ra", proto,
			ni_ipv6_devconf_accept_ra_to_name(NI_IPV6_ACCEPT_RA_ROUTER));
	/* and SLAAC is not disabled by e.g. all/default settings   */
	xml_node_new_element_unique("autoconf", proto,
			ni_tristate_to_name(NI_TRISTATE_ENABLE));

	if ((node = xml_node_create(conf, "ipv6:auto"))) {
		xml_node_new_element_unique("enabled", node, "true");
	}
	return node;
}

static xml_node_t *
xml_config_setup_dhcp4(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto, *peer;

	if (!(proto = xml_config_setup_ipv4(conf, redfish)))
		return NULL;

	if ((node = xml_node_create(conf, "ipv4:dhcp"))) {
		xml_node_new_element_unique("enabled", node, "true");
		xml_node_new_element_unique("update", node, NULL);
		if ((peer = xml_node_get_child(conf, "ipv6:dhcp"))) {
			/* when there is also dhcp6, permit one to fail */
			xml_node_new_element_unique("flags", peer, "group");
			xml_node_new_element_unique("flags", node, "group");
		}
	}
	return node;
}

static xml_node_t *
xml_config_setup_dhcp6(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto, *peer;

	if (!(proto = xml_config_setup_ipv6(conf, redfish)))
		return NULL;

	/* Make sure, we process RA even host is using forwarding=1 */
	xml_node_new_element_unique("accept-ra", proto,
			ni_ipv6_devconf_accept_ra_to_name(NI_IPV6_ACCEPT_RA_ROUTER));

	if ((node = xml_node_create(conf, "ipv6:dhcp"))) {
		xml_node_new_element_unique("enabled", node, "true");
		xml_node_new_element_unique("update", node, NULL);
		if ((peer = xml_node_get_child(conf, "ipv4:dhcp"))) {
			/* when there is also dhcp4, permit one to fail */
			xml_node_new_element_unique("flags", peer, "group");
			xml_node_new_element_unique("flags", node, "group");
		}
		/*
		 * The whole purpose is to get an ip address to contact BMC,
		 * but it's a /128 address -> (prefix) route to reach the
		 * peer is set by RA...
		 * We expect, that there is an RA enabling managed/address
		 * mode, prefix (route), but no default route (lifetime 0).
		 *
		xml_node_new_element_unique("mode", node, "managed");
		 */
	}
	return node;
}

static ni_bool_t
xml_config_ip_node_exists(xml_node_t *node, const char *ip)
{
	xml_node_t *addr = NULL, *local;

	while ((addr = xml_node_get_next_child(node, "address", addr))) {
		if (!(local = xml_node_get_child(addr, "local")))
			continue;

		if (ni_string_eq(ip, local->cdata))
			return TRUE;
	}
	return FALSE;
}

static xml_node_t *
xml_config_setup_static4(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto, *addr;
	const char *ipaddr;

	if (!(proto = xml_config_setup_ipv4(conf, redfish)))
		return NULL;

	if (!(node = xml_node_create(conf, "ipv4:static")))
		return NULL;

	if (!ni_sockaddr_is_ipv4_specified(&redfish->host.addr) || !redfish->host.plen)
		return NULL;
	if (!(ipaddr = ni_sockaddr_prefix_print(&redfish->host.addr, redfish->host.plen)))
		return NULL;

	if (xml_config_ip_node_exists(node, ipaddr))
		return node;

	if ((addr = xml_node_new("address", node))) {
		xml_node_new_element("local", addr, ipaddr);
	}
	return node;
}

static xml_node_t *
xml_config_setup_static6(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	xml_node_t *node, *proto, *addr;
	const char *ipaddr;

	if (!(proto = xml_config_setup_ipv6(conf, redfish)))
		return NULL;

	if (!(node = xml_node_create(conf, "ipv6:static")))
		return NULL;

	if (!ni_sockaddr_is_ipv6_specified(&redfish->host.addr) || !redfish->host.plen)
		return NULL;
	if (!(ipaddr = ni_sockaddr_prefix_print(&redfish->host.addr, redfish->host.plen)))
		return NULL;

	if (xml_config_ip_node_exists(node, ipaddr))
		return node;

	if ((addr = xml_node_new("address", node))) {
		xml_node_new_element("local", addr, ipaddr);
	}
	return node;
}

static xml_node_t *
xml_config_setup_redfish(xml_node_t *conf, const ni_mchi_net_redfish_t *redfish)
{
	/* we've seen host with multiple mchi entries using a combination
	 * of ipv4 link-local host ip and ipv6 link-local service ip...
	 * thus explicitly enable the service address family protocol.
	 */
	switch (redfish->service.family) {
		case NI_MCHI_NET_IP_FAMILY_IPV4:
			xml_config_setup_ipv4(conf, redfish);
			break;
		case NI_MCHI_NET_IP_FAMILY_IPV6:
			xml_config_setup_ipv6(conf, redfish);
			break;
		default:
			break;
	}
	switch (redfish->host.setup) {
		case NI_MCHI_NET_IP_SETUP_AUTO:
			switch (redfish->host.family) {
				case NI_MCHI_NET_IP_FAMILY_IPV4:
					return xml_config_setup_auto4(conf, redfish);
				case NI_MCHI_NET_IP_FAMILY_IPV6:
					return xml_config_setup_auto6(conf, redfish);
				default:
					return NULL;
			}
		break;
		case NI_MCHI_NET_IP_SETUP_DHCP:
			switch (redfish->host.family) {
				case NI_MCHI_NET_IP_FAMILY_IPV4:
					return xml_config_setup_dhcp4(conf, redfish);
				case NI_MCHI_NET_IP_FAMILY_IPV6:
					return xml_config_setup_dhcp6(conf, redfish);
				default:
					return NULL;
			}
		break;
		case NI_MCHI_NET_IP_SETUP_STATIC:
			switch (redfish->host.family) {
				case NI_MCHI_NET_IP_FAMILY_IPV4:
					return xml_config_setup_static4(conf, redfish);
				case NI_MCHI_NET_IP_FAMILY_IPV6:
					return xml_config_setup_static6(conf, redfish);
				default:
					return NULL;
			}
		break;
	default:
		return NULL;
	}
}

int
show_wicked_xml_config(const ni_smbios_entry_t *entries)
{
	xml_node_t *root = NULL, *conf;
	const ni_smbios_entry_t *entry;
	const ni_mchi_entry_t *mchi;
	const ni_mchi_net_pconf_t *pconf;
	const char *name = NULL;
	unsigned int vlan;

	if (!(root = xml_node_new(NULL, NULL)))
		return NI_WICKED_RC_SUCCESS;

	for (entry = entries; entry; entry = entry->next) {
		if (entry->type != NI_SMBIOS_TYPE_MCHI)
			continue;

		mchi = (ni_mchi_entry_t *)entry;
		if (mchi->type != NI_MCHI_TYPE_NET)
			continue;

		if (!mchi->net.plist || !mchi->net.dev ||
		    ni_string_empty(mchi->net.dev->device.name))
			continue;

		name = mchi->net.dev->device.name;
		for (pconf = mchi->net.plist; pconf; pconf = pconf->next) {
			if (pconf->type != NI_MCHI_NET_PCONF_REDFISH)
				continue;

			if (!(conf = xml_config_init_ifname(root, name)))
				goto failure;

			vlan = pconf->redfish.service.vlan;
			if (vlan && !(conf = xml_config_init_ifvlan(root, name, vlan)))
				goto failure;

			xml_config_setup_redfish(conf, &pconf->redfish);
		}
	}

	if (root->children) {
		xml_node_print(root, stdout);
		xml_node_free(root);
		return NI_WICKED_RC_SUCCESS;
	} else {
		xml_node_free(root);
		return NI_WICKED_RC_NOT_CONFIGURED;
	}

failure:
	xml_node_free(root);
	return NI_WICKED_RC_ERROR;
}

static ni_bool_t
ni_file_read_fd(int fd, ni_buffer_t *bp, off_t off, size_t max_len)
{
	struct stat stbuf;
	ssize_t len = -1;

	if (fstat(fd, &stbuf) == 0) {

		if (off >= stbuf.st_size)
			return FALSE;

		if (!max_len || max_len > (size_t)stbuf.st_size - off)
			max_len = (size_t)stbuf.st_size - off;
	}

	if (off && lseek(fd, off, SEEK_SET) == (off_t)-1)
		return FALSE;

	if (ni_buffer_ensure_tailroom(bp, max_len)) do {

		if (!ni_buffer_tailroom(bp))
			break;

		do {
			len = read(fd, ni_buffer_tail(bp), ni_buffer_tailroom(bp));
			if (len > 0)
				ni_buffer_push_tail(bp, len);
		} while (len < 0 && errno == EINTR);

	} while (len > 0);

	return len != -1;
}

static void
ni_file_close_fd(int fd)
{
	int err;

	err = errno;
	while (close(fd) < 0 && errno == EINTR)
		;
	errno = err;
}

static ni_bool_t
ni_sysfs_smbios_entry_point_read(ni_buffer_t *bp, off_t off, size_t max_len,
				const char *rootdir)
{
	char *filename = NULL;
	ni_bool_t ret;
	int fd;

	if (ni_string_empty(rootdir))
		ni_string_dup(&filename, NI_SMBIOS_ENTRY_FILE);
	else
		ni_string_printf(&filename, "%s%s", rootdir, NI_SMBIOS_ENTRY_FILE);

	if (!bp || (fd = open(filename, O_RDONLY|O_CLOEXEC)) == -1) {
		ni_string_free(&filename);
		return FALSE;
	}

	ret = ni_file_read_fd(fd, bp, off, max_len);
	ni_file_close_fd(fd);
	ni_string_free(&filename);
	return ret;
}

static ni_bool_t
ni_sysfs_smbios_tables_read(ni_buffer_t *bp, off_t off, size_t max_len,
				const char *rootdir)
{
	char *filename = NULL;
	ni_bool_t ret;
	int fd;

	if (ni_string_empty(rootdir))
		ni_string_dup(&filename, NI_SMBIOS_TABLE_FILE);
	else
		ni_string_printf(&filename, "%s%s", rootdir, NI_SMBIOS_TABLE_FILE);

	if (!bp || (fd = open(filename, O_RDONLY|O_CLOEXEC)) == -1) {
		ni_string_free(&filename);
		return FALSE;
	}

	ret = ni_file_read_fd(fd, bp, off, max_len);
	ni_file_close_fd(fd);
	ni_string_free(&filename);
	return ret;
}

static ni_bool_t
ni_smbios_epi_init(ni_smbios_epi_t *epi, unsigned int flags)
{
	if (epi) {
		memset(epi, 0, sizeof(*epi));
		epi->flags = flags;
		return TRUE;
	}
	return FALSE;
}

static inline int
ni_smbios_buffer_get_uint8(ni_buffer_t *bp, uint8_t *var)
{
	uint8_t *u8;

	if (!(u8 = ni_buffer_pull_head(bp, sizeof(*u8))))
		return -1;

	*var = *u8;
	return 0;
}

static inline int
ni_smbios_buffer_get_le16(ni_buffer_t *bp, uint16_t *var)
{
	uint16_t *le16;

	if (!(le16 = ni_buffer_pull_head(bp, sizeof(*le16))))
		return -1;

	*var = le16toh(*le16);
	return 0;
}

static inline int
ni_smbios_buffer_get_le32(ni_buffer_t *bp, uint32_t *var)
{
	uint32_t *le32;

	if (!(le32 = ni_buffer_pull_head(bp, sizeof(*le32))))
		return -1;

	*var = le32toh(*le32);
	return 0;
}

static inline int
ni_smbios_buffer_get_le64(ni_buffer_t *bp, uint64_t *var)
{
	uint64_t *le64;

	if (!(le64 = ni_buffer_pull_head(bp, sizeof(*le64))))
		return -1;

	*var = le64toh(*le64);
	return 0;
}

static inline int
ni_smbios_buffer_get_uuid(ni_buffer_t *bp, ni_uuid_t *var)
{
	ni_uuid_t *uuid;

	if (!(uuid = ni_buffer_pull_head(bp, sizeof(*uuid))))
		return -1;
	/*
	 * The uuid is using non-RFC4122 wired "wire format" with
	 * first tree fields (half or the uuid) in little-endian;
	 * convert it to a RFC4122 uuid in network byte order.
	 */
	var->octets[0] = uuid->octets[3]; /* dword */
	var->octets[1] = uuid->octets[2];
	var->octets[2] = uuid->octets[1];
	var->octets[3] = uuid->octets[0];
	var->octets[4] = uuid->octets[5]; /* word  */
	var->octets[5] = uuid->octets[4];
	var->octets[6] = uuid->octets[7]; /* word  */
	var->octets[7] = uuid->octets[6];
	var->words[2]  = uuid->words[2];  /* dword */
	var->words[3]  = uuid->words[3];  /* dword */
	return 0;
}

static inline int
ni_smbios_buffer_get_ipv4(ni_buffer_t *bp, ni_sockaddr_t *var)
{
	/* ipv4 addresses are stored in 1st 4 bytes */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} *ip;

	if (!(ip = ni_buffer_pull_head(bp, sizeof(*ip))))
		return -1;

	ni_sockaddr_set_ipv4(var, ip->v4, 0);
	return 0;
}

static inline int
ni_smbios_buffer_get_ipv6(ni_buffer_t *bp, ni_sockaddr_t *var)
{
	union {
		struct in6_addr v6;
		struct in_addr  v4;
	} *ip;

	if (!(ip = ni_buffer_pull_head(bp, sizeof(*ip))))
		return -1;

	ni_sockaddr_set_ipv6(var, ip->v6, 0);
	return 0;
}

static size_t
ni_smbios_signature(ni_buffer_t *bp, const unsigned char *sig, size_t len)
{
	const unsigned char *ptr;
	ptr = ni_buffer_peek_head(bp, len);
	if (!ptr || memcmp(ptr, sig, len))
		return 0;
	return len;
}

static inline size_t
ni_smbios_signature_32(ni_buffer_t *bp)
{
	const unsigned char sig[] = NI_SMBIOS_SIGNATURE_32;
	return ni_smbios_signature(bp, sig, sizeof(sig) - 1);
}

static inline size_t
ni_smbios_signature_64(ni_buffer_t *bp)
{
	const unsigned char sig[] = NI_SMBIOS_SIGNATURE_64;
	return ni_smbios_signature(bp, sig, sizeof(sig) - 1);
}

static inline size_t
ni_smbios_signature_dmi(ni_buffer_t *bp)
{
	const unsigned char sig[] = NI_SMBIOS_SIGNATURE_DMI;
	return ni_smbios_signature(bp, sig, sizeof(sig) - 1);
}

static ni_bool_t
ni_smbios_checksum(const unsigned char *ptr, size_t len)
{
	uint8_t sum = 0;
	size_t i;

	for (i = 0; i < len; ++i)
		sum += ptr[i];
	return (sum == 0);
}

static ni_bool_t
ni_smbios_decode_eps_32(ni_smbios_epi_t *epi, ni_buffer_t *eps, unsigned int flags)
{
	/*
	 * DSP0134 System Management BIOS (SMBIOS) Reference Specification
	 * Version 3.5.0, Clause 5.2.1 SMBIOS 2.1 (32-bit) Entry Point
	 * Acc. to Table 1 - SMBIOS 2.1 (32-bit) Entry Point structure
	 *
	 * From 5.2 Table convention:
	 * "[...]
	 * allows SMBIOS structure table to reside anywhere in 32-bit
	 * physical address space (that is, fewer than 4 GB).
	 *  [...]
	 * If an implementation provides both a 32-bit and a 64-bit entry
	 * point, they must both report the same SMBIOS major.minor
	 * specification version, and if they point to distinct SMBIOS
	 * structure tables, the 32-bit table must be a consistent subset
	 * of the 64-bit table.
	 *  [...]"
	 */
	unsigned char ver[2] = {0,0};
	const unsigned char *ptr;
	ni_buffer_t buf;
	size_t len, n;
	uint16_t tbl_len;
	uint32_t tbl_off;
	int c;

	/* smbios entry-point length: 31		*/
	if (ni_buffer_count(eps) < NI_SMBIOS_EPS_LEN_2_1)
		return FALSE;

	/* signature bytes: off 0x00, len 4		*/
	if (!(len = ni_smbios_signature_32(eps)))
		return FALSE;

	/* init/reset epi and apply flags */
	ni_smbios_epi_init(epi, flags);

	/* init reader for checksum, starts at anchor string, off 0x00 */
	ni_buffer_init_reader(&buf, ni_buffer_head(eps), ni_buffer_count(eps));

	/* skip signature + eps checksum byte		*/
	if (!ni_buffer_pull_head(&buf, len + 1))
		return FALSE;

	/* eps (csum) length: off 0x05, len 1		*/
	if ((c = ni_buffer_getc(&buf)) < 0       ||
	    !(ptr = ni_buffer_pull_head(eps, c)) ||
	    !ni_smbios_checksum(ptr, c))
		return FALSE;

	/* version x.x: off 0x06, len 2			*/
	for (n = 0; n < sizeof(ver); ++n) {
		if ((c = ni_buffer_getc(&buf)) < 0)
			return FALSE;
		ver[n] = c;
	}
	epi->version = (ver[0] << 16) + (ver[1] << 8);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
			"SMBIOS %u.%u (0x%06x)",
			ver[0], ver[1], epi->version);

	/* max struct size: off 0x08, word	*/
	if (ni_smbios_buffer_get_le16(&buf, &epi->ent_max) < 0)
		return FALSE;

	/* eps revision: off 0x0a, len 1		*/
	if ((c = ni_buffer_getc(&buf)) < 0)
		return FALSE;
	epi->eps_rev = (c & 0xff);

	/* formatted area: 0xb .. 0xf, len 5		*/
	if (!ni_buffer_pull_head(&buf, 5))
		return FALSE;

	/* Intermediate Anchor, off 0x10, len 5		*/
	if (!(len = ni_smbios_signature_dmi(&buf)))
		return FALSE;

	/* Verify immediate checksum at 0x10, len 0x0f */
	if (!(ptr = ni_buffer_peek_head(&buf, 0x0f)) ||
	    !ni_smbios_checksum(ptr, 0x0f))
		return FALSE;

	/* Intermediate Checksum, off 0x15, len 1	*/
	if (!ni_buffer_pull_head(&buf, len + 1))
		return FALSE;

	/* table length: 0x16, len 2 (word)		*/
	if (ni_smbios_buffer_get_le16(&buf, &tbl_len) < 0)
		return FALSE;
	epi->max_len = tbl_len;

	/* table offset: 0x18, len 4 (dword)		*/
	if (ni_smbios_buffer_get_le32(&buf, &tbl_off) < 0)
		return FALSE;
	epi->offset = tbl_off;

	/* entry count: 0x1c, len 2 (word)		*/
	if (ni_smbios_buffer_get_le16(&buf, &epi->ent_num) < 0)
		return FALSE;

	/* BCD Revision, off 0x1e, len 1		*/
	if ((c = ni_buffer_getc(&buf)) < 0)
		return FALSE;
	epi->bcd_rev = (c & 0xff);

	return TRUE;
}

static ni_bool_t
ni_smbios_decode_eps_64(ni_smbios_epi_t *epi, ni_buffer_t *eps, unsigned int flags)
{
	/*
	 * DSP0134 System Management BIOS (SMBIOS) Reference Specification
	 * Version 3.5.0, Clause 5.2.2 SMBIOS 3.0 (64-bit) Entry Point
	 * Acc. to Table 2 - SMBIOS 3.0 (64-bit) Entry Point structure
	 *
	 * From 5.2 Table convention:
	 * "[...]
	 * allows SMBIOS structure table anywhere in 64-bit memory.
	 *  [...]
	 * The 64-bit table may contain structure types not found in
	 * the 32-bit table.
	 *  [...]"
	 */
	unsigned char ver[3] = {0,0,0};
	const unsigned char *ptr;
	ni_buffer_t buf;
	size_t len, n;
	int c;

	/* smbios entry-point length: 24	*/
	if (!epi || ni_buffer_count(eps) < NI_SMBIOS_EPS_LEN_3_0)
		return FALSE;

	/* signature bytes: off 0x00, len: 5	*/
	if (!(len = ni_smbios_signature_64(eps)))
		return FALSE;

	/* init/reset epi and apply flags */
	ni_smbios_epi_init(epi, flags);

	/* init reader for checksum, starts at anchor string, off 0x00 */
	ni_buffer_init_reader(&buf, ni_buffer_head(eps), ni_buffer_count(eps));

	/* skip signature + eps checksum byte	*/
	if (!ni_buffer_pull_head(&buf, len + 1))
		return FALSE;

	/* eps length: off 0x06, len: 1		*/
	if ((c = ni_buffer_getc(&buf)) < 0       ||
	    !(ptr = ni_buffer_pull_head(eps, c)) ||
	    !ni_smbios_checksum(ptr, c))
		return FALSE;

	/* version 3.x.x: off 0x07, 0x08, 0x09	*/
	for (n = 0; n < sizeof(ver); ++n) {
		if ((c = ni_buffer_getc(&buf)) < 0)
			return FALSE;
		ver[n] = c;
	}
	epi->version = (ver[0] << 16) + (ver[1] << 8) + ver[2];
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
			"SMBIOS %u.%u.%u (0x%06x)",
			ver[0], ver[1], ver[2], epi->version);

	/* eps revision: off 0x0a, len 1	*/
	if ((c = ni_buffer_getc(&buf)) < 0)
		return FALSE;
	epi->eps_rev = (c & 0xff);

	/* check if we're using major version 3 and
	 * eps is based on SMBIOS 3.0 definition. */
	if (!(epi->version >= NI_SMBIOS_VERSION_MAJ) ||
	    !(epi->eps_rev == NI_SMBIOS_EPS_REV_3_0))
		return FALSE;

	/* reserved: off 0x0b, len 1		*/
	if (!ni_buffer_pull_head(&buf, 1))
		return FALSE;

	/* table length: 0x0c, len 4 (dword)	*/
	if (ni_smbios_buffer_get_le32(&buf, &epi->max_len) < 0)
		return FALSE;

	/* table offset: 0x10, len 8 (quad)	*/
	if (ni_smbios_buffer_get_le64(&buf, &epi->offset) < 0)
		return FALSE;

	/* 64bit offset on 32bit (off_t) system */
	if ((epi->offset >> 32) && sizeof(off_t) < 8)
		return FALSE;

	return TRUE;
}

static ni_bool_t
ni_smbios_decode_eps(ni_smbios_epi_t *epi, const char *root)
{
	unsigned int flags = epi->flags;
	ni_buffer_t buf;

	ni_buffer_init(&buf, NULL, 0);
	if (ni_sysfs_smbios_entry_point_read(&buf, 0, NI_SMBIOS_EPS_MAX_LEN, root)) {
		/* sysfs files expose smbios without offset */
		flags |= NI_SMBIOS_NO_FILE_OFFSET;
	} else {/* other sources,  e.g. efi */
		ni_buffer_destroy(&buf);
		return FALSE;
	}

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
			"SMBIOS Entry Point (hexdump): %s",
			ni_sprint_hex(ni_buffer_head(&buf),
				      ni_buffer_count(&buf)));

	if (ni_smbios_decode_eps_64(epi, &buf, flags)) {
		ni_buffer_destroy(&buf);
		return TRUE;
	}

	if (ni_smbios_decode_eps_32(epi, &buf, flags)) {
		ni_buffer_destroy(&buf);
		return TRUE;
	}

	ni_buffer_destroy(&buf);
	return FALSE;
}

/*
 * This string array does not copy the string, but stores the
 * buffer pointer only. Read-only ni_string_array functions
 * remain usable.
 */
static ni_bool_t
ni_smbios_string_array_append(ni_string_array_t *array, char *ptr)
{
	static const unsigned int chunk = 16;
	if (!array || !ptr)
		return FALSE;

	if ((array->count % chunk) == 0) {
		size_t newsize;
		char **newdata;
		unsigned int i;

		newsize = array->count + chunk + 1;
		newdata = realloc(array->data, newsize * sizeof(char *));
		if (!newdata)
			return FALSE;

		array->data = newdata;
		for (i = array->count; i < newsize; ++i)
			array->data[i] = NULL;
	}

	array->data[array->count++] =  ptr;
	return TRUE;
}

static void
ni_smbios_string_array_reset(ni_string_array_t *array)
{
	if (array) {
		while (array->count) {
			array->count--;
			array->data[array->count] = NULL;
		}
	}
}

static void
ni_smbios_string_array_destroy(ni_string_array_t *array)
{
	if (array) {
		ni_smbios_string_array_reset(array);
		free(array->data);
		array->data = NULL;
	}
}

static ni_bool_t
ni_smbios_decode_strings(ni_string_array_t *strings, ni_buffer_t *bp)
{
	char *beg, *end;

	if (!(beg = ni_buffer_pull_head(bp, 1)))
		return FALSE;
	if (!(end = ni_buffer_pull_head(bp, 1)))
		return FALSE;

	while (beg[0] || end[0]) {
		if (!end[0] && beg[0]) {
			ni_smbios_string_array_append(strings, beg);
			beg = end;
		} else if (!beg[0])
			beg = end;

		if (!(end = ni_buffer_pull_head(bp, 1)))
			return FALSE;
	}
	return TRUE;
}

static void
ni_smbios_decode_entry(ni_smbios_decoder_t *decoder,
			const ni_smbios_epi_t *epi,
			const ni_string_array_t *strings,
			const ni_smbios_header_t *header,
			ni_buffer_t *buffer)
{
	const ni_smbios_handler_t *handler;
	unsigned int i;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
			"Handle 0x%04x, DMI type %u, %u bytes",
			header->handle, header->type, header->length);

	for (i = 0; i < strings->count; ++i) {
		const char *str = strings->data[i];
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"	String[%u]: `%s`", i, str);
	}

	for (handler = decoder->handler; handler->decode; ++handler) {
		if (handler->type != header->type)
			continue;

		if (!handler->decode(decoder, epi, strings, header, buffer)) {
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
					"Unable to decode DMI type %u, Handle %04x",
					header->type, header->handle);
		}
	}
}

static ni_bool_t
ni_smbios_decode_tables(ni_smbios_decoder_t *decoder, const ni_smbios_epi_t *epi,
			ni_buffer_t *tab)
{
	ni_string_array_t strings = NI_STRING_ARRAY_INIT;
	const ni_smbios_header_t *header;
	ni_buffer_t buffer;
	unsigned char *ptr;
	unsigned int num = 0;
	ni_bool_t ret = TRUE;

	while ((header = ni_buffer_peek_head(tab, sizeof(*header)))) {
		/* Entry structure length must include header length  */
		if (header->length < sizeof(*header)) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"SMBIOS stucture length must include header length");
			ret = FALSE;
			break;
		}

		/* Stop at End of Table type or if numEntries reached */
		if (header->type == 0x7f) {
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"Handle 0x%04x, DMI type %u, %u bytes",
				header->handle, header->type, header->length);
		}
		if (header->type == 0x7f ||
		    (epi->ent_num && ++num > epi->ent_num)) {
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"End Of Table");
			break;
		}

		/* Extract type structure buffer including header */
		if (!(ptr = ni_buffer_pull_head(tab, header->length))) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Truncated SMBIOS structure or invalid length");
			ret = FALSE;
			break;
		}

		ni_buffer_init_reader(&buffer, ptr, header->length);

		/* Entry [strings +] structure terminator */
		ni_smbios_string_array_reset(&strings);
		if (!ni_smbios_decode_strings(&strings, tab)) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Unable to decode SMBIOS structure strings and terminator");
			ret = FALSE;
			break;
		}

		/* Call handler to decode and process valid and supported entries */
		ni_smbios_decode_entry(decoder, epi, &strings, header, &buffer);
	}

	ni_smbios_string_array_destroy(&strings);
	return ret;
}

static void
ni_smbios_entry_free(ni_smbios_entry_t *entry)
{
	if (entry) {
		if (entry->free) {
			entry->free(entry);
		} else {
			memset(entry, 0, sizeof(*entry));
			free(entry);
		}
	}
}

ni_bool_t
ni_smbios_entry_list_append(ni_smbios_entry_t **list, ni_smbios_entry_t *entry)
{
	ni_smbios_entry_t *item;

	if (list && entry) {
		while ((item = *list))
			list = &item->next;
		*list = entry;
		return TRUE;
	}
	return FALSE;
}

static void
ni_smbios_entry_list_destroy(ni_smbios_entry_t **list)
{
	ni_smbios_entry_t *item;

	if (list) {
		while ((item = *list)) {
			*list = item->next;
			ni_smbios_entry_free(item);
		}
	}
}

static ni_bool_t
ni_smbios_decoder_init(ni_smbios_decoder_t *decoder, const ni_smbios_handler_t *handler,
							const char *rootdir)
{
	if (decoder) {
		memset(decoder, 0, sizeof(*decoder));
		if ((decoder->handler = handler) &&
		    ni_string_dup(&decoder->rootdir, rootdir))
			return TRUE;
	}
	return FALSE;
}

static void
ni_smbios_decoder_destroy(ni_smbios_decoder_t *decoder)
{
	if (decoder) {
		ni_string_free(&decoder->rootdir);
		ni_smbios_entry_list_destroy(&decoder->entries);
		memset(decoder, 0, sizeof(*decoder));
	}
}

static ni_bool_t
ni_smbios_decode(ni_smbios_decoder_t *decoder)
{
	ni_smbios_epi_t epi;
	ni_buffer_t buf;
	off_t off = 0;

	ni_smbios_epi_init(&epi, 0);
	if (!ni_smbios_decode_eps(&epi, decoder->rootdir))
		return FALSE;

	if (!(epi.flags & NI_SMBIOS_NO_FILE_OFFSET))
		off = epi.offset;

	ni_buffer_init(&buf, NULL, 0);
	if (!ni_sysfs_smbios_tables_read(&buf, off, epi.max_len, decoder->rootdir)) {
		ni_buffer_destroy(&buf);
		return FALSE;
	}

	if (!ni_smbios_decode_tables(decoder, &epi, &buf)) {
		ni_buffer_destroy(&buf);
		return FALSE;
	}

	ni_buffer_destroy(&buf);
	return TRUE;
}

static void
ni_mchi_net_dev_usb_init(ni_mchi_net_dev_usb_t *usb)
{
	if (usb) {
		memset(usb, 0, sizeof(*usb));
		ni_link_address_init(&usb->hwaddr);
	}
}

static ni_bool_t
ni_mchi_net_dev_usb_copy(ni_mchi_net_dev_usb_t *dst, const ni_mchi_net_dev_usb_t *src)
{
	if (dst && src) {
		dst->vendor_id = src->vendor_id;
		dst->product_id = src->product_id;
		ni_link_address_set(&dst->hwaddr, src->hwaddr.type,
				src->hwaddr.data, src->hwaddr.len);
		return ni_string_dup(&dst->serial_nr, src->serial_nr);
	}
	return FALSE;
}

static ni_bool_t
ni_mchi_net_dev_usb_eq(const ni_mchi_net_dev_usb_t *u1, const ni_mchi_net_dev_usb_t *u2)
{
	if (u1->vendor_id != u2->vendor_id ||
	    u1->product_id != u2->product_id)
		return FALSE;
	if (!ni_link_address_equal(&u1->hwaddr, &u2->hwaddr))
		return FALSE;
	return ni_string_eq(u1->serial_nr, u2->serial_nr);
}

static void
ni_mchi_net_dev_usb_destroy(ni_mchi_net_dev_usb_t *usb)
{
	if (usb) {
		ni_string_free(&usb->serial_nr);
		ni_mchi_net_dev_usb_init(usb);
	}
}

static void
ni_mchi_net_dev_pci_init(ni_mchi_net_dev_pci_t *pci)
{
	if (pci) {
		memset(pci, 0, sizeof(*pci));
	}
}

static ni_bool_t
ni_mchi_net_dev_pci_copy(ni_mchi_net_dev_pci_t *dst, const ni_mchi_net_dev_pci_t *src)
{
	if (dst && src) {
		dst->vendor_id = src->vendor_id;
		dst->device_id = src->device_id;
		dst->subsys.vendor_id = src->subsys.vendor_id;
		dst->subsys.device_id = src->subsys.device_id;
		return TRUE;
	}
	return FALSE;
}

static ni_bool_t
ni_mchi_net_dev_pci_eq(const ni_mchi_net_dev_pci_t *p1, const ni_mchi_net_dev_pci_t *p2)
{
	if (p1->vendor_id != p2->vendor_id ||
	    p1->device_id != p2->device_id ||
	    p1->subsys.vendor_id != p2->subsys.vendor_id ||
	    p1->subsys.device_id != p2->subsys.device_id)
		return FALSE;
	return TRUE;
}

static void
ni_mchi_net_dev_pci_destroy(ni_mchi_net_dev_pci_t *pci)
{
	if (pci) {
		memset(pci, 0, sizeof(*pci));
	}
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_new(ni_mchi_net_dev_type_t type)
{
	ni_mchi_net_dev_t *dev;

	dev = calloc(1, sizeof(*dev));
	if (dev) {
		dev->refcount = 1;
		dev->type = type;
		ni_netdev_ref_init(&dev->device);
		ni_mchi_net_dev_usb_init(&dev->usb);
		ni_mchi_net_dev_pci_init(&dev->pci);
	}
	return dev;
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_ref(ni_mchi_net_dev_t *dev)
{
	if (dev) {
		ni_assert(dev->refcount);
		dev->refcount++;
	}
	return dev;
}

static void
ni_mchi_net_dev_destroy(ni_mchi_net_dev_t *dev)
{
	if (dev) {
		dev->type = 0;
		ni_netdev_ref_destroy(&dev->device);
		ni_mchi_net_dev_usb_destroy(&dev->usb);
		ni_mchi_net_dev_pci_destroy(&dev->pci);
	}
}

static void
ni_mchi_net_dev_free(ni_mchi_net_dev_t *dev)
{
	if (dev) {
		ni_assert(dev->refcount);
		dev->refcount--;
		if (dev->refcount == 0) {
			ni_mchi_net_dev_destroy(dev);
			free(dev);
		}
	}
}

static ni_bool_t
ni_mchi_net_redfish_init(ni_mchi_net_redfish_t *redfish)
{
	if (redfish) {
		memset(redfish, 0, sizeof(*redfish));
		return TRUE;
	}
	return FALSE;
}

static void
ni_mchi_net_redfish_destroy(ni_mchi_net_redfish_t *redfish)
{
	if (redfish) {
		ni_string_free(&redfish->service.host);
		ni_mchi_net_redfish_init(redfish);
	}
}

static ni_mchi_net_pconf_t *
ni_mchi_net_pconf_new(ni_mchi_net_pconf_type_t type)
{
	ni_mchi_net_pconf_t *pconf;

	if ((pconf = calloc(1, sizeof(*pconf)))) {
		pconf->type = type;
		ni_mchi_net_redfish_init(&pconf->redfish);
	}
	return pconf;
}

static void
ni_mchi_net_pconf_free(ni_mchi_net_pconf_t *pconf)
{
	if (pconf) {
		ni_mchi_net_redfish_destroy(&pconf->redfish);
		pconf->type = 0;
		pconf->next = NULL;
		free(pconf);
	}
}

static ni_bool_t
ni_mchi_net_pconf_list_append(ni_mchi_net_pconf_t **list, ni_mchi_net_pconf_t *pconf)
{
	ni_mchi_net_pconf_t *item;

	if (list && pconf) {
		while ((item = *list))
			list = &item->next;
		*list = pconf;
		return TRUE;
	}
	return FALSE;
}

static void
ni_mchi_net_pconf_list_destroy(ni_mchi_net_pconf_t **list)
{
	ni_mchi_net_pconf_t *item;

	if (list) {
		while ((item = *list)) {
			*list = item->next;
			ni_mchi_net_pconf_free(item);
		}
	}
}

static void
ni_mchi_entry_free(ni_mchi_entry_t *mchi)
{
	if (mchi) {
		ni_mchi_net_dev_free(mchi->net.dev);
		mchi->net.dev = NULL;
		ni_mchi_net_pconf_list_destroy(&mchi->net.plist);
		free(mchi);
	}
}

static void
ni_smbios_mchi_entry_free(ni_smbios_entry_t *entry)
{
	if (!entry || entry->free != ni_smbios_mchi_entry_free)
		return;

	ni_mchi_entry_free((ni_mchi_entry_t *)entry);
}

static ni_mchi_entry_t *
ni_mchi_entry_new(uint8_t type, uint16_t handle)
{
	ni_mchi_entry_t *mchi;

	if (!(mchi = calloc(1, sizeof(*mchi))))
		return NULL;

	mchi->entry.free = ni_smbios_mchi_entry_free;
	mchi->entry.type = type;
	mchi->entry.handle = handle;
	return mchi;
}

static int
sysfs_netif_get_attr(const char *rootdir, const char *ifname, const char *attr, char **result)
{
	char buffer[256] = {'\0'};
	char *filename = NULL;
	FILE *fp;

	/* TODO: ni_sysfs_netif_get_string or the like with rootdir ? */

	if (ni_string_empty(rootdir))
		ni_string_printf(&filename, "/sys/class/net/%s/%s",
					ifname, attr);
	else
		ni_string_printf(&filename, "%s/sys/class/net/%s/%s",
					rootdir, ifname, attr);

	fp = fopen(filename, "r");
	ni_string_free(&filename);
	if (!fp)
		return -1;

	if (fgets(buffer, sizeof(buffer), fp)) {
		buffer[strcspn(buffer, "\n")] = '\0';
		ni_string_dup(result, buffer);
	}
	fclose(fp);
	return 0;
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_usb_lookup_sysfs(ni_mchi_net_dev_type_t type,
				const ni_mchi_net_dev_usb_t *usb,
				const char *rootdir)
{
	ni_netdev_ref_array_t devs = NI_NETDEV_REF_ARRAY_INIT;
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	ni_mchi_net_dev_t *dev = NULL;
	const ni_netdev_ref_t *ref;
	char *val = NULL;
	unsigned int i;

	/* Match USB device sysfs properties */
	if (!ni_string_printf(&val, "%04x", usb->vendor_id) ||
	    !ni_var_array_set(&vars, "idVendor", val))
		return NULL;

	if (!ni_string_printf(&val, "%04x", usb->product_id) ||
	    !ni_var_array_set(&vars, "idProduct", val))
		return NULL;

	if (!ni_string_empty(usb->serial_nr) &&
	    !ni_var_array_set(&vars, "serial", usb->serial_nr))
		return NULL;
	ni_string_free(&val);

	if (ni_sysfs_bus_usb_device_netdev_scan(&devs, &vars, NULL, rootdir) <= 0) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Unable to find specified MCHI USB network device");
		ni_netdev_ref_array_destroy(&devs);
		ni_var_array_destroy(&vars);
		return NULL;
	}

	if (devs.count > 1) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_READWRITE,
			"Multiple network devices are matching MCHI USB properties:");
		for (i = 0; i < devs.count; ++i) {
			ref = &devs.data[i];
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_READWRITE,
				"* usb network device[%u]: ifname %s, ifindex %u\n",
				i, ref->name, ref->index);
		}
	}

	/* Match USBv2 network device sysfs properties (if any) */
	ref = NULL;
	if (usb->hwaddr.len) {
		ni_hwaddr_t hwaddr;

		for (i = 0; i < devs.count; ++i) {
			ref = &devs.data[i];

			if (sysfs_netif_get_attr(rootdir, ref->name, "address", &val) ||
			    ni_link_address_parse(&hwaddr, ARPHRD_ETHER, val) ||
			    !ni_link_address_equal(&hwaddr, &usb->hwaddr))
				ref = NULL;

			ni_string_free(&val);
		}
	} else {
		/* take 1st matching one ... ? */
		ref = ni_netdev_ref_array_at(&devs, 0);
	}

	if (ref && (dev = ni_mchi_net_dev_new(type))) {
		ni_netdev_ref_set(&dev->device, ref->name, ref->index);
		ni_mchi_net_dev_usb_copy(&dev->usb, usb);
	} else {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Unable to find matching USB device");
	}

	ni_netdev_ref_array_destroy(&devs);
	ni_var_array_destroy(&vars);
	return dev;
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_usb_lookup(const ni_smbios_decoder_t *decoder,
			ni_mchi_net_dev_type_t type,
			const ni_mchi_net_dev_usb_t *usb)
{
	ni_smbios_entry_t *entry;
	ni_mchi_entry_t *mchi;

	for (entry = decoder->entries; entry; entry = entry->next) {
		if (entry->type != NI_SMBIOS_TYPE_MCHI)
			continue;

		mchi = (ni_mchi_entry_t *)entry;
		if (mchi->type != NI_MCHI_TYPE_NET)
			continue;

		if (!mchi->net.dev || mchi->net.dev->type != type)
			continue;

		if (ni_mchi_net_dev_usb_eq(&mchi->net.dev->usb, usb))
			return ni_mchi_net_dev_ref(mchi->net.dev);
	}

	return ni_mchi_net_dev_usb_lookup_sysfs(type, usb, decoder->rootdir);
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_pci_lookup_sysfs(ni_mchi_net_dev_type_t type,
			const ni_mchi_net_dev_pci_t *pci,
			const char *rootdir)
{
	ni_netdev_ref_array_t devs = NI_NETDEV_REF_ARRAY_INIT;
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	ni_mchi_net_dev_t *dev = NULL;
	const ni_netdev_ref_t *ref;
	char *val = NULL;
	unsigned int i;

	/* Match PCI device sysfs properties */
	if (!ni_string_printf(&val, "0x%04x", pci->vendor_id) ||
	    !ni_var_array_set(&vars, "vendor", val))
		return NULL;

	if (!ni_string_printf(&val, "0x%04x", pci->device_id) ||
	    !ni_var_array_set(&vars, "device", val))
		return NULL;

	if (!ni_string_printf(&val, "0x%04x", pci->subsys.vendor_id) ||
	    !ni_var_array_set(&vars, "subsystem_vendor", val))
		return NULL;

	if (!ni_string_printf(&val, "0x%04x", pci->subsys.device_id) ||
	    !ni_var_array_set(&vars, "subsystem_device", val))
		return NULL;
	ni_string_free(&val);

	if (ni_sysfs_bus_pci_device_netdev_scan(&devs, &vars, NULL, rootdir) <= 0) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Unable to find specified MCHI PCI network device");
		ni_netdev_ref_array_destroy(&devs);
		ni_var_array_destroy(&vars);
		return NULL;
	}

	/* TODO: Implement NI_MCHI_NET_DEV_PCIv2 type decoding.
	 *       It contains further network device properties
	 *       like mac address, ... needed to be matched on
	 *       the devices (devs array) we've found.
	 *       The NI_MCHI_NET_DEV_PCIv1 type contains only
	 *       PCI properties we've matched above -> done.
	 */
	if (devs.count > 1) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
			"Multiple network devices are matching MCHI PCI properties:");
		for (i = 0; i < devs.count; ++i) {
			ref = &devs.data[i];
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"* pci network device[%u]: ifname %s, ifindex %u\n",
				i, ref->name, ref->index);
		}
	}

	ref = ni_netdev_ref_array_at(&devs, 0);
	if (ref && (dev = ni_mchi_net_dev_new(type))) {
		ni_netdev_ref_set(&dev->device, ref->name, ref->index);
		ni_mchi_net_dev_pci_copy(&dev->pci, pci);
	} else {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"Unable to find matching USB device");
	}

	ni_netdev_ref_array_destroy(&devs);
	ni_var_array_destroy(&vars);
	return dev;
}

static ni_mchi_net_dev_t *
ni_mchi_net_dev_pci_lookup(const ni_smbios_decoder_t *decoder,
			ni_mchi_net_dev_type_t type,
			const ni_mchi_net_dev_pci_t *pci)
{
	ni_smbios_entry_t *entry;
	ni_mchi_entry_t *mchi;

	for (entry = decoder->entries; entry; entry = entry->next) {
		if (entry->type != NI_SMBIOS_TYPE_MCHI)
			continue;

		mchi = (ni_mchi_entry_t *)entry;
		if (mchi->type != NI_MCHI_TYPE_NET)
			continue;

		if (!mchi->net.dev || mchi->net.dev->type != type)
			continue;

		if (ni_mchi_net_dev_pci_eq(&mchi->net.dev->pci, pci))
			return ni_mchi_net_dev_ref(mchi->net.dev);
	}

	return ni_mchi_net_dev_pci_lookup_sysfs(type, pci, decoder->rootdir);
}

static ni_bool_t
ni_smbios_mchi_net_dev_usbv1_decode(ni_mchi_net_dev_usb_t *usb, ni_buffer_t *bp)
{
	uint16_t word;
	uint8_t  type;
	uint8_t  len;

	/* off: 0x00, len: 2, vendor id			*/
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	usb->vendor_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"idVendor", usb->vendor_id);

	/* off: 0x02, len: 2, product id		*/
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	usb->product_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"idProduct", usb->product_id);

	/* off: 0x04, len: 1, serial number data num of bytes */
	if (ni_smbios_buffer_get_uint8(bp, &len) < 0)
		return FALSE;

	if (len > 2 && (len % 2) == 0) {
		/* "The number of bytes of the Serial Number, Serial Number
		 *  Descriptor Type, and Serial Number Descriptor Length
		 *  [...] This field has a minimum value of 0x02."
		 */
		len -= 2;

		/* off: 0x05, len: 1, sn descriptor type - 0x03	*/
		if (ni_smbios_buffer_get_uint8(bp, &type) < 0)
			return FALSE;

		/* off: 0x06, len: N, sn string - unterminated  */
		if (type == 0x03 && len) {
			ni_stringbuf_t sn = NI_STRINGBUF_INIT_DYNAMIC;

			/* iSerialNumber.bString is UTF-16LE encoded (Unicode
			 * 16 bits per character in little-endian byte order).
			 * We use it only, when all code points convert to
			 * a printable, 7-bit ascii unsigned char.
			 */
			while (ni_smbios_buffer_get_le16(bp, &word) == 0) {
				if (word < 0x7f && isascii((unsigned char)word)
						&& isprint((unsigned char)word)) {
					ni_stringbuf_putc(&sn, word);
				} else {
					ni_stringbuf_clear(&sn);
					break;
				}
			}
			if (sn.string)
				ni_string_dup(&usb->serial_nr, sn.string);
			ni_stringbuf_destroy(&sn);

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
				"serial", usb->serial_nr);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_smbios_mchi_net_dev_usbv2_decode(ni_mchi_net_dev_usb_t *usb, ni_buffer_t *bp,
					const ni_string_array_t *strings)
{
	unsigned char *ptr;
	const char *str;
	uint16_t word;
	uint8_t  len;
	uint8_t  snn;

	/* off: 0x00, len: 1, version depending structure len:
	 * 	- 0Dh for 1.2 and older
	 * 	- 11h for 1.3 with new:
	 * 	  - Device Characteristics (word)
	 * 	  - Credential Bootstrapping Handle (word)
	 * 	  fields, does not matter yet (unused).
	 */
	if (ni_smbios_buffer_get_uint8(bp, &len) < 0)
		return FALSE;

	/* off: 0x01, len: 2, vendor id			*/
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	usb->vendor_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"idVendor", usb->vendor_id);

	/* off: 0x03, len: 2, product id		*/
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	usb->product_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"idProduct", usb->product_id);

	/* off: 0x05, len: 1, serial string number	*/
	if (ni_smbios_buffer_get_uint8(bp, &snn) < 0)
		return FALSE;

	if (snn && (str = ni_string_array_at(strings, snn - 1))) {
		ni_string_dup(&usb->serial_nr, str);

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
				"serial", usb->serial_nr);
	}

	/* off: 0x06, len: 6, MAC Address */
	len = ni_link_address_length(ARPHRD_ETHER);
	if (!(ptr = ni_buffer_pull_head(bp, len)))
		return FALSE;

	ni_link_address_set(&usb->hwaddr, ARPHRD_ETHER, ptr, len);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"MAC Address", ni_link_address_print(&usb->hwaddr));

	return TRUE;
}

static ni_bool_t
ni_smbios_mchi_net_dev_pciv1_decode(ni_mchi_net_dev_pci_t *pci, ni_buffer_t *bp)
{
	uint16_t word;

	/* off: 0x00, len  2, Vendor ID of the PCI/PCIe device (LSB first). */
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	pci->vendor_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"VendorID", pci->vendor_id);

	/* off: 0x02, len  2, Device ID of the PCI/PCIe device (LSB first). */
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	pci->device_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"DeviceID", pci->device_id);

	/* off: 0x04, len  2, Subsystem Vendor ID of the PCI/PCIe device (LSB first). */
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	pci->subsys.vendor_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"SubVendorID", pci->subsys.vendor_id);

	/* off: 0x06, len  2, Subsystem (Device) ID of the PCI/PCIe device (LSB first). */
	if (ni_smbios_buffer_get_le16(bp, &word) < 0)
		return FALSE;

	pci->subsys.device_id = word;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: 0x%04x",
			"SubDeviceID", pci->subsys.device_id);

	return TRUE;
}

static ni_mchi_net_dev_t *
ni_smbios_mchi_net_dev_decode(ni_smbios_decoder_t *decoder,
		const ni_smbios_epi_t *epi,
		const ni_string_array_t *strings,
		ni_buffer_t *buf)
{
	ni_mchi_net_dev_t *dev = NULL;
	ni_mchi_net_dev_usb_t usb;
	ni_mchi_net_dev_pci_t pci;
	const char *str;
	uint8_t type;

	/* off: 0x00, len: 1, device type		*/
	if (ni_smbios_buffer_get_uint8(buf, &type))
		return NULL;

	str = ni_format_uint_mapped(type, mchi_net_dev_type_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t%s: %s",
			"Device Type", str ? str : "-Unsupported-");

	/* off: 0x01, len: N, device descriptor	*/
	switch (type) {
		case NI_MCHI_NET_DEV_USBv1:
			ni_mchi_net_dev_usb_init(&usb);
			if (!ni_smbios_mchi_net_dev_usbv1_decode(&usb, buf)) {
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
						"Unable to decode %s device description", str);
				ni_mchi_net_dev_usb_destroy(&usb);
				return NULL;
			}
			dev = ni_mchi_net_dev_usb_lookup(decoder, type, &usb);
			ni_mchi_net_dev_usb_destroy(&usb);
			break;

		case NI_MCHI_NET_DEV_USBv2:
			ni_mchi_net_dev_usb_init(&usb);
			if (!ni_smbios_mchi_net_dev_usbv2_decode(&usb, buf, strings)) {
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
						"Unable to decode %s device description", str);
				ni_mchi_net_dev_usb_destroy(&usb);
				return NULL;
			}
			dev = ni_mchi_net_dev_usb_lookup(decoder, type, &usb);
			ni_mchi_net_dev_usb_destroy(&usb);
			break;

		case NI_MCHI_NET_DEV_PCIv1:
			ni_mchi_net_dev_pci_init(&pci);
			if (!ni_smbios_mchi_net_dev_pciv1_decode(&pci, buf)) {
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
						"Unable to decode %s device description", str);
				ni_mchi_net_dev_pci_destroy(&pci);
				return NULL;
			}
			dev = ni_mchi_net_dev_pci_lookup(decoder, type, &pci);
			ni_mchi_net_dev_pci_destroy(&pci);
			break;

		case NI_MCHI_NET_DEV_PCIv2:
		default:
			return NULL;
	}
	return dev;
}

static ni_bool_t
ni_smbios_mchi_redfish_decode(ni_mchi_net_redfish_t *redfish,
				const ni_smbios_epi_t *epi,
				const ni_string_array_t *strings,
				ni_buffer_t *buf)
{
	ni_sockaddr_t mask, *addr;
	const unsigned char *ptr;
	const char *str;
	uint8_t  family;
	uint8_t  setup;
	uint16_t port;
	uint32_t vlan; /* dword ?! */
	uint8_t  hlen;

	/* off: 0x00, len: 16, Redfish Service UUID		*/
	if (ni_smbios_buffer_get_uuid(buf, &redfish->uuid) < 0)
		return FALSE;

	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Service UUID", ni_uuid_print(&redfish->uuid));

	/* off: 0x10, len:  1, Host IP Assignment Type		*/
	if (ni_smbios_buffer_get_uint8(buf, &setup) < 0)
		return FALSE;

	redfish->host.setup = setup;
	str = ni_format_uint_mapped(setup, mchi_net_ip_setup_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Host IP Assignment Type",
			str ? str : "-Unsupported-");

	/* off: 0x11, len:  1, Host IP Address Format (family)	*/
	if (ni_smbios_buffer_get_uint8(buf, &family) < 0)
		return FALSE;

	redfish->host.family = family;
	str = ni_format_uint_mapped(family, mchi_net_ip_family_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Host IP Address Format",
			str ? str : "-Unsupported-");

	switch (redfish->host.family) {
		case NI_MCHI_NET_IP_FAMILY_IPV4:
			/* off: 0x12, len: 16, Host IP Address	*/
			addr = &redfish->host.addr;
			if (ni_smbios_buffer_get_ipv4(buf, addr) < 0)
				return FALSE;

			/* off: 0x22, len: 16, Host IP Mask	*/
			if (ni_smbios_buffer_get_ipv4(buf, &mask) < 0)
				return FALSE;
			redfish->host.plen = ni_sockaddr_netmask_bits(&mask);

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"\t\t\t%s: %s",
				"Host IP Address",
				ni_sockaddr_prefix_print(addr, redfish->host.plen));
			break;
		case NI_MCHI_NET_IP_FAMILY_IPV6:
			/* off: 0x12, len: 16, Host IP Address	*/
			addr = &redfish->host.addr;
			if (ni_smbios_buffer_get_ipv6(buf, addr) < 0)
				return FALSE;

			/* off: 0x22, len: 16, Host IP Mask	*/
			if (ni_smbios_buffer_get_ipv6(buf, &mask) < 0)
				return FALSE;
			redfish->host.plen = ni_sockaddr_netmask_bits(&mask);

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"\t\t\t%s: %s",
				"Host IP Address",
				ni_sockaddr_prefix_print(addr, redfish->host.plen));
		break;
		default:
			return FALSE;
	}

	/* off: 0x32, len:  1, Redfish Service IP Discovery Type*/
	if (ni_smbios_buffer_get_uint8(buf, &setup) < 0)
		return FALSE;

	redfish->service.setup = setup;
	str = ni_format_uint_mapped(setup, mchi_net_ip_setup_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Redfish Service IP Discovery Type",
			str ? str : "-Unsupported-");

	/* off: 0x33, len:  1, Redfish Service IP Address Format*/
	if (ni_smbios_buffer_get_uint8(buf, &family) < 0)
		return FALSE;

	redfish->service.family = family;
	str = ni_format_uint_mapped(family, mchi_net_ip_family_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Redfish Service IP Address Format",
			str ? str : "-Unsupported-");

	switch (redfish->service.family) {
		case NI_MCHI_NET_IP_FAMILY_IPV4:
			/* off: 0x34, len: 16, Service IP	*/
			addr = &redfish->service.addr;
			if (ni_smbios_buffer_get_ipv4(buf, addr) < 0)
				return FALSE;

			/* off: 0x44, len: 16, Service IP Mask	*/
			if (ni_smbios_buffer_get_ipv4(buf, &mask) < 0)
				return FALSE;
			redfish->service.plen = ni_sockaddr_netmask_bits(&mask);

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
					"\t\t\t%s: %s",
					"Redfish Service Address",
					ni_sockaddr_prefix_print(addr, redfish->service.plen));

			/* off: 0x54, len:  2, Service Port	*/
			if (ni_smbios_buffer_get_le16(buf, &port) < 0)
				return FALSE;

			redfish->service.addr.sin.sin_port = htons(port);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %u",
				"Redfish Service Port", port);
			break;
		case NI_MCHI_NET_IP_FAMILY_IPV6:
			/* off: 0x34, len: 16, Service IP	*/
			addr = &redfish->service.addr;
			if (ni_smbios_buffer_get_ipv6(buf, addr) < 0)
				return FALSE;

			/* off: 0x44, len: 16, Service IP Mask	*/
			if (ni_smbios_buffer_get_ipv6(buf, &mask) < 0)
				return FALSE;
			redfish->service.plen = ni_sockaddr_netmask_bits(&mask);

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
					"\t\t\t%s: %s",
					"Redfish Service Address",
					ni_sockaddr_prefix_print(addr, redfish->service.plen));

			/* off: 0x54, len:  2, Service Port	*/
			if (ni_smbios_buffer_get_le16(buf, &port) < 0)
				return FALSE;

			redfish->service.addr.six.sin6_port = htons(port);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %u",
				"Redfish Service Port", port);
			break;
		default:
			return FALSE;
	}

	/* off: 0x56, len:  4, Redfish Service VLAN ID		*/
	if (ni_smbios_buffer_get_le32(buf, &vlan) < 0)
		return FALSE;

	redfish->service.vlan = vlan;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %u",
			"Redfish Service Vlan", redfish->service.vlan);

	/* off: 0x5a, len:  1, Redfish Service Hostname Length	*/
	if (ni_smbios_buffer_get_uint8(buf, &hlen) < 0)
		return FALSE;

	/* off: 0x5b, len:  H, Redfish Service Hostname Length	*/
	if (hlen) {
		if (!(ptr = ni_buffer_pull_head(buf, hlen)))
			return FALSE;

		if (!ni_string_set(&redfish->service.host, (const char *)ptr, hlen))
			return FALSE;

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t\t\t%s: %s",
			"Redfish Service Hostname", redfish->service.host);
	}

	return TRUE;
}

static ni_bool_t
ni_smbios_decode_mchi(ni_smbios_decoder_t *decoder,
		const ni_smbios_epi_t *epi,
		const ni_string_array_t *strings,
		const ni_smbios_header_t *header,
		ni_buffer_t *buffer)
{
	ni_mchi_entry_t *mchi = NULL;
	ni_mchi_net_dev_t *dev = NULL;
	unsigned char *head;
	uint8_t     type;
	uint8_t     nlen;
	ni_buffer_t nbuf;
	uint8_t	    pcnt;
	uint8_t	    pidx;
	const char *str;

	/* off: 0x00, len:  4, entry struct header	*/
	if (!ni_buffer_pull_head(buffer, sizeof(*header)))
		return FALSE;

	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "%s",
			ni_format_uint_mapped(header->type, smbios_type_name_map));

	/* off: 0x04, len:  1, host interface type	*/
	if (ni_smbios_buffer_get_uint8(buffer, &type) < 0)
		return FALSE;

	str = ni_format_uint_mapped(type, mchi_type_map);
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE, "\t%s: %s",
			"Host Interface Type", str ? str : "-Unsupported-");

	/* off: 0x05, len:  1, host interface data len	*/
	if (ni_smbios_buffer_get_uint8(buffer, &nlen) < 0)
		return FALSE;

	if (!(mchi = ni_mchi_entry_new(header->type, header->handle)))
		return FALSE;

	switch (type) {
		case NI_MCHI_TYPE_NET:
			/* no network interface specified.. ?! */
			if (!nlen)
				break;

			if (!(head = ni_buffer_pull_head(buffer, nlen)) ||
			    !ni_buffer_init_reader(&nbuf, head, nlen))
				goto failure;

			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
					"MCHI %s device data (hexdump): %s", str,
					ni_sprint_hex(ni_buffer_head(&nbuf),
						      ni_buffer_count(&nbuf)));

			if (!(dev = ni_smbios_mchi_net_dev_decode(decoder,
							epi, strings, &nbuf)))
				goto failure;

			mchi->type = type;
			mchi->net.dev = dev;
			break;
		default:
			/* we're not interested in them */
			goto failure;
	}

	/* off: 0x06 + iflen, len: 1, number of protocol records */
	if (ni_smbios_buffer_get_uint8(buffer, &pcnt) < 0)
		goto failure;

	for (pidx = 0; pidx < pcnt; ++pidx) {
		ni_mchi_net_pconf_t *pconf;
		ni_buffer_t pbuf;
		uint8_t ptype;
		uint8_t plen;

		/* off: 0x00, len:  1, protocol type		*/
		if (ni_smbios_buffer_get_uint8(buffer, &ptype) < 0)
			goto failure;

		/* off: 0x01, len:  1, protocol record length	*/
		if (ni_smbios_buffer_get_uint8(buffer, &plen) < 0)
			goto failure;

		/* off: 0x02, len: plen, protocol redord data	*/
		if (!(head = ni_buffer_pull_head(buffer, plen)) ||
		    !ni_buffer_init_reader(&pbuf, head, plen))
			goto failure;

		str = ni_format_uint_mapped(ptype, mchi_net_protocol_map);
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
				"\t\t%s[%u]: %02u (%s)",
				"Protocol ID", pidx,
				ptype, str ? str : "-Unsupported-");

		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"MCHI %s protocol data (hexdump): %s", str,
				ni_sprint_hex(ni_buffer_head(&pbuf),
					      ni_buffer_count(&pbuf)));

		switch (ptype) {
			case NI_MCHI_NET_PCONF_REDFISH:
				pconf = ni_mchi_net_pconf_new(ptype);
				if (!ni_smbios_mchi_redfish_decode(&pconf->redfish,
									epi, strings, &pbuf) ||
				    !ni_mchi_net_pconf_list_append(&mchi->net.plist, pconf)) {
					ni_mchi_net_pconf_free(pconf);
					goto failure;
				}
				break;
			default:
				break;
		}
	}

	if (!mchi->net.dev || !mchi->net.plist ||
	    !ni_smbios_entry_list_append(&decoder->entries, &mchi->entry))
		goto failure;

	return TRUE;

failure:
	ni_mchi_entry_free(mchi);
	return FALSE;
}

