/*
 * General functions for AF_LOCAL sockets
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "netinfo_priv.h"
#include "logging.h"

int
ni_local_socket_listen(const char *path, unsigned int permissions)
{
	int fd, bound = 0;

	permissions &= 0777;
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		error("cannot open AF_LOCAL socket: %m");
		return -1;
	}

	if (path) {
		struct sockaddr_un sun;
		unsigned int len = strlen(path);

		if (len + 1 > sizeof(sun.sun_path)) {
			error("can't set AF_LOCAL address: path too long!");
			return -1;
		}

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_LOCAL;
		strcpy(sun.sun_path, path);

		unlink(path);
		if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
			error("bind(%s) failed: %m", path);
			goto failed;
		}
		bound = 1;

		if (chmod(path, permissions) < 0) {
			error("chmod(%s, 0%3o) failed: %m", path, permissions);
			goto failed;
		}

	}

	if (listen(fd, 128) < 0) {
		error("cannot listen on local socket: %m");
		goto failed;
	}
	return fd;

failed:
	if (bound && path)
		unlink(path);
	close(fd);
	return -1;
}

int
ni_local_socket_connect(const char *path)
{
	int fd;

	if (!path) {
		error("cannot connect to server - no server socket path specified");
		return -1;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		error("cannot open AF_LOCAL socket: %m");
		return -1;
	}

	{
		struct sockaddr_un sun;
		unsigned int len = strlen(path);

		if (len + 1 > sizeof(sun.sun_path)) {
			error("can't set AF_LOCAL address: path too long!");
			return -1;
		}

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_LOCAL;
		strcpy(sun.sun_path, path);

		if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
			error("bind(%s) failed: %m", path);
			goto failed;
		}
	}

	return fd;

failed:
	close(fd);
	return -1;
}

int
ni_local_socket_accept(int master, uid_t *uidp, gid_t *gidp)
{
	struct ucred cred;
	socklen_t clen;
	int fd;

	fd = accept(master, NULL, NULL);
	if (fd < 0)
		return -1;

	clen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0) {
		error("failed to get client credentials: %m");
		return -1;
	}

	*uidp = cred.uid;
	*gidp = cred.gid;

	return fd;
}
