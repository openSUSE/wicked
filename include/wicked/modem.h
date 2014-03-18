/*
 * Modem related functionality
 */

#ifndef __WICKED_MODEM_H__
#define __WICKED_MODEM_H__

typedef enum ni_modem_ipmethod {
	MM_MODEM_IP_METHOD_PPP = 0,
	MM_MODEM_IP_METHOD_STATIC = 1,
	MM_MODEM_IP_METHOD_DHCP = 2,
} ni_modem_ipmethod_t;

/*
 * The bits and enum values used seem to have been chosen in an
 * attempt to make it as random as possible.
 */
typedef enum ni_modem_gsm_allowed_mode { 
	MM_MODEM_GSM_ALLOWED_MODE_ANY = 0,		/* Any mode can be used */
	MM_MODEM_GSM_ALLOWED_MODE_2G_PREFERRED = 1,	/* Prefer 2G (GPRS or EDGE) */
	MM_MODEM_GSM_ALLOWED_MODE_3G_PREFERRED = 2,	/* Prefer 3G (UMTS or HSxPA) */
	MM_MODEM_GSM_ALLOWED_MODE_2G_ONLY = 3,		/* Use only 2G (GPRS or EDGE) */
	MM_MODEM_GSM_ALLOWED_MODE_3G_ONLY = 4,		/* Use only 3G (UMTS or HSxPA) */
} ni_modem_gsm_allowed_mode_t;

typedef enum ni_modem_gsm_access_tech {
	MM_MODEM_GSM_ACCESS_TECH_UNKNOWN = 0,		/* The access technology used is unknown */
	MM_MODEM_GSM_ACCESS_TECH_GSM = 1,		/* GSM */
	MM_MODEM_GSM_ACCESS_TECH_GSM_COMPACT = 2,	/* Compact GSM */
	MM_MODEM_GSM_ACCESS_TECH_GPRS = 3,		/* GPRS */
	MM_MODEM_GSM_ACCESS_TECH_EDGE = 4,		/* EDGE (ETSI 27.007: "GSM w/EGPRS") */
	MM_MODEM_GSM_ACCESS_TECH_UMTS = 5,		/* UMTS (ETSI 27.007: "UTRAN") */
	MM_MODEM_GSM_ACCESS_TECH_HSDPA = 6,		/* HSDPA (ETSI 27.007: "UTRAN w/HSDPA") */
	MM_MODEM_GSM_ACCESS_TECH_HSUPA = 7,		/* HSUPA (ETSI 27.007: "UTRAN w/HSUPA") */
	MM_MODEM_GSM_ACCESS_TECH_HSPA = 8,		/* HSPA (ETSI 27.007: "UTRAN w/HSDPA and HSUPA") */
} ni_modem_gsm_access_tech_t;

typedef enum ni_modem_state {
	MM_MODEM_STATE_UNKNOWN = 0,
	MM_MODEM_STATE_DISABLED = 10,
	MM_MODEM_STATE_DISABLING = 20,
	MM_MODEM_STATE_ENABLING = 30,
	MM_MODEM_STATE_ENABLED = 40,
	MM_MODEM_STATE_SEARCHING = 50,
	MM_MODEM_STATE_REGISTERED = 60,
	MM_MODEM_STATE_DISCONNECTING = 70,
	MM_MODEM_STATE_CONNECTING = 80,
	MM_MODEM_STATE_CONNECTED = 90,

	__MM_MODEM_STATE_MAX
} ni_modem_state_t;

typedef enum ni_gsm_modem_reg_state {
	MM_MODEM_GSM_NETWORK_REG_STATUS_IDLE = 0,
	MM_MODEM_GSM_NETWORK_REG_STATUS_HOME = 1,
	MM_MODEM_GSM_NETWORK_REG_STATUS_SEARCHING = 2,
	MM_MODEM_GSM_NETWORK_REG_STATUS_DENIED = 3,
	MM_MODEM_GSM_NETWORK_REG_STATUS_UNKNOWN = 4,
	MM_MODEM_GSM_NETWORK_REG_STATUS_ROAMING = 5,
} ni_gsm_modem_reg_state_t;

/* We may want to turn this into a more generic type and
 * use it elsewhere, too */
typedef struct ni_modem_pin {
	struct ni_modem_pin *	next;

	char *			kind;
	char *			value;
	unsigned int		cache_lifetime;
} ni_modem_pin_t;

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
	ni_modem_state_t	state;
	ni_modem_ipmethod_t	ip_config_method;
	ni_bool_t		enabled;

	/* The uuid of a pending event */
	ni_uuid_t		event_uuid;

	struct {
		char *		manufacturer;
		char *		model;
		char *		version;

		char *		device;
		char *		equipment;
	} identify;

	struct {
		char *		required;
		uint32_t	retries;

		ni_modem_pin_t *auth;
	} unlock;

	struct {
		char *		imei;
		unsigned int	signal_quality;
		unsigned int	reg_status;
		char *		operator_code;
		char *		operator_name;

		ni_modem_gsm_allowed_mode_t allowed_mode;	/* Gsm.Network.AllowedMode */
		ni_modem_gsm_access_tech_t selected_mode;	/* Gsm.Network.AccessTechnology */
	} gsm;

	struct {
		char *		number;				/* the phone number to call */
	} pots;

	/* Configuration and policy */
	ni_bool_t		use_lock_file;			/* Use a LCK..* lock file when we claim this device */
	ni_client_state_t *client_state;
};

typedef void		ni_modem_manager_event_handler_fn_t(ni_modem_t *, ni_event_t);
extern ni_bool_t	ni_modem_manager_init(ni_modem_manager_event_handler_fn_t *);

extern ni_modem_t *	ni_modem_new(void);
extern ni_modem_t *	ni_modem_hold(ni_modem_t *);
extern void		ni_modem_release(ni_modem_t *);
extern void		ni_modem_set_client_state(ni_modem_t *, ni_client_state_t *);
extern ni_client_state_t *	ni_modem_get_client_state(ni_modem_t *);

extern int		ni_modem_manager_unlock(ni_modem_t *modem, const ni_modem_pin_t *pin);
extern int		ni_modem_manager_enable(ni_modem_t *modem);
extern int		ni_modem_manager_connect(ni_modem_t *modem, const ni_modem_t *config);
extern int		ni_modem_manager_disconnect(ni_modem_t *modem);

#endif /* __WICKED_MODEM_H__ */


