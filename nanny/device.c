/*
 * Generic device management functions
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>
#include <wicked/client.h>
#include "manager.h"

/*
 * managed_modem objects
 */
ni_managed_device_t *
ni_managed_device_new(ni_manager_t *mgr, ni_ifworker_t *w, ni_managed_device_t **list)
{
	ni_managed_device_t *mdev;

	if (w->modem == NULL)
		ni_warn("%s(%s): device not bound", __func__, w->name);

	mdev = calloc(1, sizeof(*mdev));
	mdev->manager = mgr;
	mdev->worker = ni_ifworker_get(w);

	if (list) {
		mdev->next = *list;
		*list = mdev;
	}

	return mdev;
}

void
ni_managed_device_free(ni_managed_device_t *mdev)
{
	ni_trace("%s(%s): obj=%p", __func__,
			mdev->worker? mdev->worker->name : "anon",
			mdev->object);
	ni_assert(mdev->object == NULL);

	if (mdev->worker) {
		ni_ifworker_release(mdev->worker);
		mdev->worker = NULL;
	}

	free(mdev);
}

void
ni_objectmodel_unregister_managed_device(ni_managed_device_t *mdev)
{
	if (mdev->object) {
		ni_dbus_object_free(mdev->object);
		mdev->object = NULL;
	}
}

