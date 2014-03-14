/*
 * Track openvpn client end point state
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#if OPENVPN
#ifndef __WICKED_OPENVPN_H__
#define __WICKED_OPENVPN_H__

#include <wicked/netinfo.h>

/*
 * For every openvpn tunnel end point, we track its state in one
 * of these.
 * This is very minimalistic, as most of the handling is done in
 * an extension script.
 */
struct ni_openvpn {
	char *			ident;
	ni_tempstate_t *	temp_state;
};

extern int			ni_openvpn_discover(ni_netconfig_t *);
extern ni_openvpn_t *		ni_openvpn_new(const char *tag);
extern int			ni_openvpn_mkdir(ni_openvpn_t *);
extern void			ni_openvpn_free(ni_openvpn_t *);

#endif /* __WICKED_OPENVPN_H__ */
#endif
