/*
 * No REST for the wicked!
 *
 * This command line utility provides a daemon interface to the network
 * configuration/information facilities.
 *
 * It uses a RESTful interface (even though it's a command line utility).
 * The idea is to make it easier to extend this to some smallish daemon
 * with a AF_LOCAL socket interface.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOFORK,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },
	{ "no-fork",		no_argument,		NULL,	OPT_NOFORK },

	{ NULL }
};

static int		opt_foreground = 0;
static int		opt_nofork = 0;

static void		wicked_interface_event(ni_handle_t *, ni_interface_t *, ni_event_t);
static void		wicked_process_network_restcall(int fd);

int
main(int argc, char **argv)
{
	ni_handle_t *listener;
	int sockfd;
	int c;

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./wickedd [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help(stdout);
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		case OPT_NOFORK:
			opt_nofork = 1;
			break;

		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind != argc)
		goto usage;

	if ((sockfd = ni_server_listen()) < 0)
		ni_fatal("unable to initialize server socket");

	/* open global RTNL socket to listen for kernel events */
	ni_server_set_event_handler(wicked_interface_event);
	if ((listener = ni_rtevent_open()) == NULL)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background() < 0)
			return 1;
		ni_log_destination_syslog("wickedd");
	}

	/* We don't care about the exit status of children */
	signal(SIGCHLD, SIG_IGN);

	while (1) {
		struct pollfd pfd[3];
		int nfds = 0;

		pfd[nfds].fd = sockfd;
		pfd[nfds].events = POLLIN;
		nfds++;

		pfd[nfds].fd = ni_rtevent_fd(listener);
		pfd[nfds].events = POLLIN;
		nfds++;

		if (poll(pfd, nfds, -1) < 0) {
			if (errno == EINTR)
				continue;
			ni_fatal("poll returns error: %m");
		}

		if (pfd[0].revents & POLLIN) {
			uid_t uid;
			gid_t gid;
			pid_t pid;
			int fd;

			fd = ni_local_socket_accept(sockfd, &uid, &gid);
			if (fd < 0)
				continue;
			if (uid != 0) {
				ni_error("refusing attempted connection by user %u", uid);
				goto drop_connection;
			}

			ni_trace("accepted connection from uid=%u", uid);

			if (opt_nofork == 0) {
				/* Now fork the worker child */
				pid = fork();
				if (pid < 0) {
					ni_error("unable to fork worker child: %m");
					goto drop_connection;
				}

				if (pid == 0) {
					close(sockfd);
					wicked_process_network_restcall(fd);
					exit(0);
				}
			} else {
				wicked_process_network_restcall(fd);
			}

drop_connection:
			close(fd);
		}

		if (pfd[1].revents & POLLIN) {
			ni_refresh(listener);
		}
	}

	exit(0);
}

void
wicked_process_network_restcall(int fd)
{
	ni_wicked_request_t req;
	char buffer[1024];
	char *cmd, *path, *s;
	FILE *sock;

	ni_wicked_request_init(&req);

	if (!(sock = fdopen(fd, "w+"))) {
		ni_error("unable to fdopen socket: %m");
		return;
	}

	if (fgets(buffer, sizeof(buffer), sock) == NULL)
		return;

	for (cmd = s = buffer; *s && !isspace(*s); ++s)
		;

	while (isspace(*s))
		*s++ = '\0';
	path = s;

	s = path + strlen(path);
	while (s > path && isspace(s[-1]))
		*--s = '\0';

	if (*cmd == '\0' || *path == '\0') {
		werror(&req, "cannot parse REST request");
		goto error;
	}

	/* Now get the XML document, if any */
	req.xml_in = xml_node_scan(sock);
	if (req.xml_in == NULL) {
		werror(&req, "unable to parse xml document");
		goto error;
	}

	if (ni_wicked_call_direct(&req, cmd, path) >= 0) {
		fprintf(sock, "OK\n");
		if (req.xml_out)
			xml_node_print(req.xml_out, sock);
	} else {
error:
		if (req.error_msg == NULL) {
			fprintf(sock, "ERROR: unable to process request\n");
		} else {
			fprintf(sock, "ERROR: %s\n", req.error_msg);
		}
	}

	fflush(sock);
	ni_wicked_request_destroy(&req);
}

/*
 * Handle network layer events.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
wicked_interface_event(ni_handle_t *nih, ni_interface_t *ifp, ni_event_t event)
{
	static const char *evtype[__NI_EVENT_MAX] =  {
		[NI_EVENT_LINK_CREATE]	= "link-create",
		[NI_EVENT_LINK_DELETE]	= "link-delete",
		[NI_EVENT_LINK_UP]	= "link-up",
		[NI_EVENT_LINK_DOWN]	= "link-down",
		[NI_EVENT_NETWORK_UP]	= "network-up",
		[NI_EVENT_NETWORK_DOWN]	= "network-down",
	};
	xml_node_t *evnode = NULL;
	xml_node_t *ifnode = NULL;
	ni_policy_t *policy;

	if (event >= __NI_EVENT_MAX || !evtype[event])
		return;

	ni_debug_events("%s: %s event", ifp->name, evtype[event]);

	evnode = xml_node_new("event", NULL);
	xml_node_add_attr(evnode, "type", evtype[event]);

	ifnode = ni_syntax_xml_from_interface(ni_default_xml_syntax(), nih, ifp);
	if (!ifnode)
		goto out;

	xml_node_replace_child(evnode, ifnode);
	policy = ni_policy_match_event(ni_default_policies(), evnode);
	if (!policy)
		goto out;

	ni_debug_events("matched a policy (action=%s)", policy->action);
	if (ni_policy_apply(policy, ifnode) < 0)
		goto out;

#if 0
	ni_debug_events("Policy transformation: apply %s to %s", policy->action, ifp->name);
	xml_node_print(ifnode, stderr);
#endif

	/* Finally, invoke REST function */
	{
		char restpath[256];

		snprintf(restpath, sizeof(restpath), "/system/interface/%s", ifp->name);
		/* wicked_rest_call(policy->action, restpath, ifnode); */
	}

out:
	/* No need to free ifnode; it's a child of evnode */
	if (evnode)
		xml_node_free(evnode);
}
