/*
 * Modem related functionality
 */

#ifndef __WICKED_MODEM_H__
#define __WICKED_MODEM_H__

typedef enum ni_modem_type {
	MM_MODEM_TYPE_UNKNOWN = 0,
	MM_MODEM_TYPE_GSM = 1,
	MM_MODEM_TYPE_CDMA = 2,

	__MM_MODEM_TYPE_MAX,
} ni_modem_type_t;

typedef enum ni_modem_ipmethod {
	MM_MODEM_IP_METHOD_PPP = 0,
	MM_MODEM_IP_METHOD_STATIC = 1,
	MM_MODEM_IP_METHOD_DHCP = 2,
} ni_modem_ipmethod_t;

struct ni_modem {
	unsigned int		refcount;
	struct {
		ni_modem_t **	prev;
		ni_modem_t *	next;
	} list;

	/* The dbus path of the ModemManager device */
	char *			real_path;

	char *			device;
	char *			master_device;
	char *			driver;
	ni_modem_type_t		type;
	ni_modem_ipmethod_t	ip_config_method;
	dbus_bool_t		enabled;

	struct {
		char *		device;
		char *		equipment;
	} identify;

	struct {
		char *		required;
		uint32_t	retries;
	} unlock;

	struct {
		char *		imei;
		uint32_t	supported_bands;
		uint32_t	supported_modes;
	} gsm;
};

extern ni_bool_t	ni_modem_manager_init(void (*event_handler)(ni_modem_t *, ni_event_t));

extern ni_modem_t *	ni_modem_new(void);
extern ni_modem_t *	ni_modem_hold(ni_modem_t *);
extern void		ni_modem_release(ni_modem_t *);

#endif /* __WICKED_MODEM_H__ */


