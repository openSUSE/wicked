/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/wicked.h>
#include <wicked/logging.h>
#include <wicked/nis.h>
#include <wicked/resolver.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "config.h"


static ni_rest_node_t *	ni_rest_node_lookup(ni_rest_node_t *, const char *, ni_wicked_request_t *);
static void		ni_rest_generate_meta(ni_rest_node_t *, xml_node_t *);
static char *		ni_request_get_domain_element(ni_wicked_request_t *, const char *);

/*
 * construct and destroy wicked request object
 */
void
ni_wicked_request_init(ni_wicked_request_t *req)
{
	memset(req, 0, sizeof(*req));
	req->cmd = -1;
}

void
ni_wicked_request_destroy(ni_wicked_request_t *req)
{
	unsigned int i;

	ni_string_free(&req->path);
	xml_node_free(req->xml_out);

	ni_var_array_destroy(&req->options);
	ni_string_free(&req->error_msg);

	for (i = 0; i < __NI_REST_ARGS_MAX; ++i)
		ni_string_free(&req->argv[i]);
	memset(req, 0, sizeof(*req));
}

/*
 * Pass "options" along with a wicked request.
 * The main motivation for having this kludge is to pass
 * in the "root" parameter, i.e. the directory relative
 * to which we should look for sysconfig files.
 * Needed to support netcf.
 */
int
ni_wicked_request_add_option(ni_wicked_request_t *req,
		const char *name, const char *value)
{
	if (!name || !value)
		return 0;
	if (strchr(name, '\n')) {
		ni_error("bad option name \"%s\"", name);
		return -1;
	}
	if (strchr(value, '\n')) {
		ni_error("Bad value for option %s", name);
		return -1;
	}
	ni_var_array_set(&req->options, name, value);
	return 0;
}

const char *
ni_wicked_request_get_option(ni_wicked_request_t *req, const char *name)
{
	ni_var_t *var;

	var = ni_var_array_get(&req->options, name);
	if (var && var->value && var->value[0])
		return var->value;
	return NULL;
}

/*
 * Map GET/PUT/POST/DELETE strings
 */
int
ni_wicked_rest_op_parse(const char *cmd)
{
	if (!strcasecmp(cmd, "get"))
		return NI_REST_OP_GET;
	if (!strcasecmp(cmd, "put"))
		return NI_REST_OP_PUT;
	if (!strcasecmp(cmd, "post"))
		return NI_REST_OP_POST;
	if (!strcasecmp(cmd, "delete"))
		return NI_REST_OP_DELETE;
	return -1;
}

const char *
ni_wicked_rest_op_print(int cmd)
{
	static const char *op_name[__NI_REST_OP_MAX] = {
		[NI_REST_OP_GET] = "get",
		[NI_REST_OP_PUT] = "put",
		[NI_REST_OP_POST] = "post",
		[NI_REST_OP_DELETE] = "delete",
	};

	if (cmd < 0 || cmd >= __NI_REST_OP_MAX)
		return "unknown";

	return op_name[cmd];
}

/*
 * Parse a WICKED request, usually reading from a socket.
 */
int
ni_wicked_request_parse(ni_socket_t *sock, ni_wicked_request_t *req)
{
	char buffer[1024];
	char *cmd, *s;

	ni_wicked_request_init(req);

	if (ni_socket_gets(sock, buffer, sizeof(buffer)) == NULL) {
		werror(req, "unable to read request from socket");
		return - 1;
	}

	for (cmd = s = buffer; *s && !isspace(*s); ++s)
		;

	while (isspace(*s))
		*s++ = '\0';
	ni_string_dup(&req->path, s);

	s = req->path + strlen(req->path);
	while (s > req->path && isspace(s[-1]))
		*--s = '\0';

	if (cmd[0] == '\0' || req->path[0] == '\0') {
		werror(req, "cannot parse REST request");
		return -1;
	}

	req->cmd = ni_wicked_rest_op_parse(cmd);
	if (req->cmd < 0) {
		werror(req, "unknown command \"%s\"", cmd);
		return -1;
	}

	/* Get options */
	while (ni_socket_gets(sock, buffer, sizeof(buffer)) != NULL) {
		int len = strlen(buffer);
		char *s;

		while (len && isspace(buffer[len-1]))
			buffer[--len] = '\0';

		if (buffer[0] == '\0')
			break;

		for (s = buffer; isalpha(*s); ++s)
			*s = tolower(*s);
		while (*s == ':' || isspace(*s))
			*s++ = '\0';

		ni_wicked_request_add_option(req, buffer, s);
	}

	/* Now get the XML document, if any */
	req->xml_in = ni_socket_recv_xml(sock);
	if (req->xml_in == NULL) {
		werror(req, "unable to parse xml document");
		return -1;
	}

	return 0;
}

/*
 * Print the response to a WICKED REST call
 */
int
ni_wicked_response_print(ni_socket_t *sock, ni_wicked_request_t *req, int status)
{
	if (status >= 0) {
		ni_socket_printf(sock, "OK\n");
		if (req->xml_out)
			ni_socket_send_xml(sock, req->xml_out);
	} else {
		if (req->error_msg == NULL) {
			ni_socket_printf(sock, "ERROR: unable to process request\n");
		} else {
			ni_socket_printf(sock, "ERROR: %s\n", req->error_msg);
		}
	}
	return 0;
}

/*
 * Call the local wicked server to process a REST call
 * This is what wicked clients usually call.
 */
int
__ni_wicked_call_indirect(ni_socket_t *sock, ni_wicked_request_t *req, int expect_response)
{
	char respbuf[256];
	unsigned int i;

	ni_debug_wicked("ni_wicked_call_indirect: %s %s", ni_wicked_rest_op_print(req->cmd), req->path);
	ni_socket_printf(sock, "%s %s\n", ni_wicked_rest_op_print(req->cmd), req->path);
	for (i = 0; i < req->options.count; ++i) {
		ni_var_t *var = &req->options.data[i];

		ni_socket_printf(sock, "%s: %s\n", var->name, var->value);
	}
	ni_socket_printf(sock, "\n");

	if (req->xml_in) {
		ni_debug_wicked_xml(req->xml_in, "Arguments:");
		if (ni_socket_send_xml(sock, req->xml_in) < 0) {
			werror(req, "write error on socket: %m");
			return -1;
		}
	}

	/* Explicitly flush out all data. */
	ni_socket_push(sock);

	if (!expect_response)
		return 0;

	if (ni_socket_gets(sock, respbuf, sizeof(respbuf)) == NULL) {
		if (sock->error)
			goto report_error;
		goto report_eof;
	}
	respbuf[strcspn(respbuf, "\r\n")] = '\0';
	if (strcmp(respbuf, "OK")) {
		ni_string_dup(&req->error_msg, respbuf);
		return -1;
	}

	if ((req->xml_out = ni_socket_recv_xml(sock)) == NULL) {
		werror(req, "error receiving response from server: %m");
		return -1;
	} else {
		ni_debug_wicked_xml(req->xml_out, "Server response:");
	}

	return 0;

report_error:
	werror(req, "error receiving response from server: %m");
	return -1;

report_eof:
	werror(req, "error receiving response from server: EOF");
	return -1;
}

int
ni_wicked_call_indirect(ni_wicked_request_t *req)
{
	ni_socket_t *sock;
	int rv;

	sock = ni_server_connect();
	if (sock == NULL)
		return -1;

	rv = __ni_wicked_call_indirect(sock, req, 1);
	ni_socket_close(sock);
	return rv;
}

int
ni_wicked_call_indirect_dgram(ni_socket_t *sock, ni_wicked_request_t *req)
{
	return __ni_wicked_call_indirect(sock, req, 1);
}

int
ni_wicked_send_event(ni_socket_t *sock, ni_wicked_request_t *req)
{
	return __ni_wicked_call_indirect(sock, req, 0);
}

/*
 * Proxies (or supplicants) are driven through a DGRAM socket,
 * and are usually subprocesses.
 */
static ni_proxy_t *	all_proxies;

ni_proxy_t *
ni_proxy_find(const char *name)
{
	ni_proxy_t *proxy;

	for (proxy = all_proxies; proxy; proxy = proxy->next) {
		if (!strcmp(proxy->name, name))
			return proxy;
	}
	return NULL;
}

ni_proxy_t *
ni_proxy_fork_subprocess(const char *name, void (*mainloop)(ni_socket_t *))
{
	ni_socket_t *sock_parent, *sock_child;
	ni_proxy_t *proxy;
	pid_t pid;

	if (ni_local_socket_pair(&sock_parent, &sock_child) < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		ni_error("unable to fork proxy subprocess: %m");
		ni_socket_close(sock_parent);
		ni_socket_close(sock_child);
		return NULL;
	}

	if (pid != 0) {
		/* Parent process */
		proxy = calloc(1, sizeof(*proxy));
		ni_string_dup(&proxy->name, name);
		proxy->pid = pid;

		ni_socket_activate(sock_child);
		proxy->sock = sock_child;
		ni_socket_close(sock_parent);

		proxy->next = all_proxies;
		all_proxies = proxy;
		return proxy;
	}

	/* Child process */

	/* Don't interfere with parent process sockets. */
	ni_socket_deactivate_all();

	ni_socket_close(sock_child);
	mainloop(sock_parent);

	exit(1);

}

/*
 * Stop proxies
 */
static void
__ni_proxy_free(ni_proxy_t *proxy)
{
	if (proxy->sock)
		ni_socket_close(proxy->sock);
	if (proxy->pid)
		kill(proxy->pid, SIGTERM);
	ni_string_free(&proxy->name);
	free(proxy);
}

void
ni_proxy_stop(ni_proxy_t *proxy)
{
	ni_proxy_t **pos;

	for (pos = &all_proxies; *pos; pos = &(*pos)->next) {
		if (*pos == proxy) {
			*pos = proxy->next;
			break;
		}
	}

	__ni_proxy_free(proxy);
}

void
ni_proxy_stop_all(void)
{
	ni_proxy_t *proxy;

	while ((proxy = all_proxies) != NULL) {
		all_proxies = proxy->next;
		__ni_proxy_free(proxy);
	}
}

int
ni_proxy_get_request(const ni_proxy_t *proxy, ni_wicked_request_t *req)
{
	int rv;

#if  0
	if (proxy->sotype == SOCK_DGRAM) {
		char dgram[65536];
		int r;
		FILE *fp;

		r = recv(fileno(proxy->sock), dgram, sizeof(dgram), 0);
		if (r < 0) {
			ni_error("unable to receive from %s proxy: %m", proxy->name);
			return -1;
		}

		fp = fmemopen(dgram, r, "r");
		if (!fp) {
			ni_error("unable to open memstream for request from %s proxy",
					proxy->name);
			return -1;
		}

		/* Parse the request */
		rv = ni_wicked_request_parse(req, fp);
		fclose(fp);
	} else
#endif
	{
		rv = ni_wicked_request_parse(proxy->sock, req);
	}

	return rv;
}

/*
 * Process a REST call directly.
 * This is what the wicked server calls to handle an incoming request.
 */
int
ni_wicked_call_direct(ni_wicked_request_t *req)
{
	return __ni_wicked_call_direct(req, &ni_rest_root_node);
}

int
__ni_wicked_call_direct(ni_wicked_request_t *req, ni_rest_node_t *root_node)
{
	ni_rest_node_t *node;

	if (ni_debug & NI_TRACE_WICKED) {
		unsigned int i;
		ni_trace("Processing REST request %s \"%s\"",
				ni_wicked_rest_op_print(req->cmd), req->path);
		if (req->options.count)
			ni_trace("Options:");
		for (i = 0; i < req->options.count; ++i) {
			ni_var_t *var = &req->options.data[i];

			ni_trace("  %s=\"%s\"", var->name, var->value);
		}
		if (req->xml_in)
			ni_debug_wicked_xml(req->xml_in, "Arguments:");
	}

	node = ni_rest_node_lookup(root_node, req->path, req);
	if (!node) {
		werror(req, "unknown path \"%s\"", req->path);
		return -1;
	}

	if (node->ops.fn[req->cmd] == NULL) {
		werror(req, "%s command not supported for this path",
				ni_wicked_rest_op_print(req->cmd));
		return -1;
	}

	if (req->cmd == NI_REST_OP_DELETE && req->argc == 0)
		ni_warn("oops, this looks like a bug: DELETE command but argc == 0");

	if (node->ops.fn[req->cmd](req) < 0)
		return -1;

	if (req->cmd != NI_REST_OP_GET && node->update.callback) {
		ni_debug_wicked("Running update extension");
		ni_extension_run(node->update.extension, node->update.callback);
	}

	if (req->xml_out)
		ni_debug_wicked_xml(req->xml_out, "REST call returns:");
	return 0;
}

static ni_handle_t *
system_handle(ni_wicked_request_t *req)
{
	ni_handle_t *nih;

	if (!(nih = ni_global_state_handle())) {
		werror(req, "unable to obtain netinfo handle");
		return NULL;
	}
	if (ni_refresh(nih, NULL) < 0) {
		werror(req, "cannot refresh interface list!");
		return NULL;
	}

	return nih;
}

static ni_handle_t *
config_handle(ni_wicked_request_t *req)
{
	const char *root_dir;
	ni_handle_t *nih;

	root_dir = ni_wicked_request_get_option(req, "root");
	nih = ni_netconfig_open(ni_netconfig_default_syntax(root_dir));
	if (nih == NULL) {
		werror(req, "unable to obtain netinfo handle");
		return NULL;
	}
	if (ni_refresh(nih, NULL) < 0) {
		werror(req, "cannot refresh interface list!");
		ni_close(nih);
		return NULL;
	}

	return nih;
}

static int
generic_interface_response(ni_handle_t *nih, ni_interface_t *ifp, ni_wicked_request_t *req)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();

	if (ifp == NULL) {
		xml_document_t *doc;

		doc = ni_syntax_xml_from_all(xmlsyntax, nih);
		if (doc) {
			req->xml_out = xml_document_take_root(doc);
			xml_document_free(doc);
		}
	} else {
		req->xml_out = ni_syntax_xml_from_interface(xmlsyntax, nih, ifp);
	}

	if (req->xml_out == NULL) {
		werror(req, "cannot render interface information");
		return -1;
	}

	return 0;
}

static int
generic_interface_get(ni_handle_t *nih, ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_interface_t *ifp = NULL;

	if (nih == NULL)
		return -1;

	if (ifname != NULL) {
		/* select interface and display only that */
		if (!(ifp = ni_interface_by_name(nih, ifname))) {
			werror(req, "interface %s not known", ifname);
			return -1;
		}
	}

	return generic_interface_response(nih, ifp, req);
}

static int
system_interface_get(ni_wicked_request_t *req)
{
	return generic_interface_get(system_handle(req), req);
}

static int
config_interface_get(ni_wicked_request_t *req)
{
	return generic_interface_get(config_handle(req), req);
}

static int
generic_interface_put(ni_handle_t *nih, ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_interface_t *ifp = NULL;
	ni_handle_t *cnih = NULL;
	int rv = -1;

	if (nih == NULL)
		return -1;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	cnih = ni_dummy_open();
	if (cnih == NULL) {
		werror(req, "unable to create netinfo dummy handle");
		goto failed;
	}

	if (__ni_syntax_xml_to_all(ni_default_xml_syntax(), cnih, req->xml_in) < 0) {
		werror(req, "unable to parse interface configuration");
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(cnih, ifname))) {
		werror(req, "cannot find configuration for interface %s", ifname);
		goto failed;
	}

#ifdef not_used
	/* Find the XML intrface element - we want to pass it to the configure
	 * routine. This helps us write flexible extensions */
	for (cfg_xml = req->xml_in->children; cfg_xml; cfg_xml = cfg_xml->next) {
		const char *name;

		if (strcmp(cfg_xml->name, "interface"))
			continue;
		if ((name = xml_node_get_attr(cfg_xml, "name")) && !strcmp(name, ifname))
			break;
	}
	if (cfg_xml == NULL) {
		werror(req, "surprising, found interface %s but no xml?!", ifname);
		goto failed;
	}
#endif

	/* Deduplicate address list */
	if (__ni_address_list_dedup(&ifp->addrs) < 0) {
		ni_error("%s: configuration contains duplicate/conflicting addresses", ifname);
		goto failed;
	}

	if (ni_interface_configure(nih, ifp) < 0) {
		werror(req, "error configuring interface %s", ifname);
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find current status for interface %s", ifname);
		goto failed;
	}

	rv = generic_interface_response(nih, ifp, req);

failed:
	if (cnih)
		ni_close(cnih);
	return rv;
}

static int
system_interface_put(ni_wicked_request_t *req)
{
	return generic_interface_put(system_handle(req), req);
}

static int
config_interface_put(ni_wicked_request_t *req)
{
	return generic_interface_put(config_handle(req), req);
}

static int
generic_interface_delete(ni_handle_t *nih, ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];

	if (nih == NULL)
		return -1;

	if (ifname == NULL) {
		werror(req, "DELETE: no interface name given");
		return -1;
	}

	if (ni_interface_delete(nih, ifname) < 0) {
		werror(req, "unable to delete %s", ifname);
		return -1;
	}

	return 0;
}

static int
system_interface_delete(ni_wicked_request_t *req)
{
	return generic_interface_delete(system_handle(req), req);
}

static int
config_interface_delete(ni_wicked_request_t *req)
{
	return generic_interface_delete(config_handle(req), req);
}

static int
system_interface_stats_get(ni_wicked_request_t *req)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();
	const char *ifname = req->argv[0];
	ni_interface_t *ifp;
	ni_handle_t *nih;

	if (ifname == NULL) {
		werror(req, "Missing interface name");
		return -1;
	}

	if ((nih = system_handle(req)) == NULL)
		return -1;

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find interface %s", ifname);
		return -1;
	}

	if (ni_interface_stats_refresh(nih, ifp) < 0) {
		werror(req, "Unable to refresh interface stats");
		return -1;
	}

	req->xml_out = ni_syntax_xml_from_interface_stats(xmlsyntax, nih, ifp);
	if (!req->xml_out) {
		werror(req, "could not generate xml");
		return -1;
	}

	return 0;
}

static ni_rest_node_t	ni_rest_system_interface_stats_node = {
	.name		= "stats",
	.ops = {
	    .byname = {
		.get	= system_interface_stats_get,
	    },
	},
};

static int
system_interface_scan_put(ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_interface_t *ifp;
	ni_handle_t *nih;

	if (ifname == NULL) {
		werror(req, "Missing interface name");
		return -1;
	}

	if ((nih = system_handle(req)) == NULL)
		return -1;

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find interface %s", ifname);
		return -1;
	}

	if (ni_interface_request_scan(nih, ifp) < 0) {
		werror(req, "Unable to scan for networks");
		return -1;
	}

	return 0;
}

static int
system_interface_scan_get(ni_wicked_request_t *req)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();
	const char *ifname = req->argv[0];
	ni_interface_t *ifp;
	ni_handle_t *nih;

	if (ifname == NULL) {
		werror(req, "Missing interface name");
		return -1;
	}

	if ((nih = system_handle(req)) == NULL)
		return -1;

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find interface %s", ifname);
		return -1;
	}

	ni_interface_get_scan_results(nih, ifp);
	if (ifp->wireless_scan != NULL) {
		req->xml_out = ni_syntax_xml_from_wireless_scan(xmlsyntax, nih, ifp->wireless_scan);
		if (!req->xml_out) {
			werror(req, "could not generate xml");
			return -1;
		}
	}

	return 0;
}

static int
system_interface_scan_delete(ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_interface_t *ifp;
	ni_handle_t *nih;

	if (ifname == NULL) {
		werror(req, "Missing interface name");
		return -1;
	}

	if ((nih = system_handle(req)) == NULL)
		return -1;

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find interface %s", ifname);
		return -1;
	}

	/* Note, this should also cancel any pending scan */

	ni_interface_set_wireless_scan(ifp, NULL);
	return 0;
}

static ni_rest_node_t	ni_rest_system_interface_scan_node = {
	.name		= "scan",
	.ops = {
	    .byname = {
		.get	= system_interface_scan_get,
		.put	= system_interface_scan_put,
		.delete	= system_interface_scan_delete,
	    },
	},
};

static ni_rest_node_t	ni_rest_system_interface_wildcard_node = {
	.name		= NULL,
	.ops = {
	    .byname = {
		.get	= system_interface_get,
		.put	= system_interface_put,
		.delete	= system_interface_delete,
	    },
	},
	.children = {
		&ni_rest_system_interface_stats_node,
		&ni_rest_system_interface_scan_node,
	},
};

static ni_rest_node_t	ni_rest_system_interface_node = {
	.name		= "interface",
	.ops = {
	    .byname = {
		.get	= system_interface_get,
	    },
	},
	.wildcard = &ni_rest_system_interface_wildcard_node,
};

static ni_rest_node_t	ni_rest_config_interface_wildcard_node = {
	.name		= NULL,
	.ops = {
	    .byname = {
		.get	= config_interface_get,
		.put	= config_interface_put,
		.delete	= config_interface_delete,
	    },
	},
};

static ni_rest_node_t	ni_rest_config_interface_node = {
	.name		= "interface",
	.ops = {
	    .byname = {
		.get	= config_interface_get,
	    },
	},
	.wildcard = &ni_rest_config_interface_wildcard_node,
};

static int
system_policy_post(ni_wicked_request_t *req)
{
	ni_handle_t *nih = ni_global_state_handle();
	ni_policy_info_t policy_info = { NULL };
	ni_policy_t *policy;
	int rv = -1;

	if (__ni_syntax_xml_to_policy_info(ni_default_xml_syntax(), &policy_info, req->xml_in) < 0) {
		werror(req, "unable to parse interface policies");
		goto failed;
	}

	if (ni_refresh(nih, NULL) < 0) {
		werror(req, "could not refresh interface list");
		goto failed;
	}

	for (policy = policy_info.event_policies; policy; policy = policy->next) {
		rv = ni_policy_update(nih, policy);
		if (rv < 0) {
			werror(req, "failed to update policy");
			goto failed;
		}
	}

	rv = 0;

failed:
	ni_policy_info_destroy(&policy_info);
	return rv;
}

static int
system_policy_get(ni_wicked_request_t *req)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();
	ni_handle_t *nih = ni_global_state_handle();

	req->xml_out = __ni_syntax_xml_from_policy_info(xmlsyntax, &nih->policy);
	if (req->xml_out == NULL) {
		werror(req, "unable to represent policies as XML");
		return -1;
	}

	return 0;
}

static ni_rest_node_t	ni_rest_system_policy_node = {
	.name		= "policy",
	.ops = {
	    .byname = {
		.get	= system_policy_get,
		.post	= system_policy_post,
	    },
	},
};

static int
generic_hostname_get(ni_handle_t *nih, ni_wicked_request_t *req)
{
	char hostname[256];

	if (nih->op->hostname_get(nih, hostname, sizeof(hostname)) < 0) {
		werror(req, "error getting hostname");
		return -1;
	}

	req->xml_out = xml_node_new("hostname", NULL);
	xml_node_set_cdata(req->xml_out, hostname);
	return 0;
}

static int
generic_hostname_put(ni_handle_t *nih, ni_wicked_request_t *req)
{
	char *hostname;

	hostname = ni_request_get_domain_element(req, "hostname");
	if (hostname == NULL)
		return -1;

	if (nih->op->hostname_put(nih, hostname) < 0) {
		werror(req, "error setting hostname");
		return -1;
	}

	req->xml_out = xml_node_new("hostname", NULL);
	xml_node_set_cdata(req->xml_out, hostname);
	return 0;
}

static int
system_hostname_get(ni_wicked_request_t *req)
{
	return generic_hostname_get(system_handle(req), req);
}

static int
system_hostname_put(ni_wicked_request_t *req)
{
	return generic_hostname_put(system_handle(req), req);
}

static ni_rest_node_t	ni_rest_system_hostname_node = {
	.name		= "hostname",
	.ops = {
	    .byname = {
		.get	= system_hostname_get,
		.put	= system_hostname_put,
	    },
	},
};

static int
config_hostname_get(ni_wicked_request_t *req)
{
	return generic_hostname_get(config_handle(req), req);
}

static int
config_hostname_put(ni_wicked_request_t *req)
{
	return generic_hostname_put(config_handle(req), req);
}

static ni_rest_node_t	ni_rest_config_hostname_node = {
	.name		= "hostname",
	.ops = {
	    .byname = {
		.get	= config_hostname_get,
		.put	= config_hostname_put,
	    },
	},
};

/*
 * NIS objects
 */
static int
generic_nis_domain_get(ni_handle_t *nih, ni_wicked_request_t *req)
{
	char domainname[256];

	if (nih->op->nis_domain_get == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	if (nih->op->nis_domain_get(nih, domainname, sizeof(domainname)) < 0) {
		werror(req, "error getting NIS domain");
		return -1;
	}

	req->xml_out = xml_node_new("domain", NULL);
	xml_node_set_cdata(req->xml_out, domainname);
	return 0;
}

static int
generic_nis_domain_put(ni_handle_t *nih, ni_wicked_request_t *req)
{
	char *domainname;

	if (nih->op->nis_domain_put == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	domainname = ni_request_get_domain_element(req, "domain");
	if (domainname == NULL)
		return -1;

	if (nih->op->nis_domain_put(nih, domainname) < 0) {
		werror(req, "error setting NIS domain");
		return -1;
	}

	req->xml_out = xml_node_new("domain", NULL);
	xml_node_set_cdata(req->xml_out, domainname);
	return 0;
}

static int
system_nis_domain_get(ni_wicked_request_t *req)
{
	return generic_nis_domain_get(system_handle(req), req);
}

static int
system_nis_domain_put(ni_wicked_request_t *req)
{
	return generic_nis_domain_put(system_handle(req), req);
}

static ni_rest_node_t	ni_rest_system_nis_domain_node = {
	.name		= "domain",
	.ops = {
	    .byname = {
		.get	= system_nis_domain_get,
		.put	= system_nis_domain_put,
	    },
	},
};

/*
 * NIS Configuration
 */
static int
generic_nis_response(ni_wicked_request_t *req, const ni_nis_info_t *nis)
{
	req->xml_out = ni_syntax_xml_from_nis(ni_default_xml_syntax(), nis, NULL);
	if (req->xml_out == NULL) {
		werror(req, "unable to render NIS information");
		return -1;
	}
	return 0;
}

static int
generic_nis_get(ni_handle_t *nih, ni_wicked_request_t *req)
{
	ni_nis_info_t *nis;
	int rv;

	if (nih->op->nis_get == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	if ((nis = nih->op->nis_get(nih)) == NULL) {
		werror(req, "error getting NIS domain");
		return -1;
	}

	rv = generic_nis_response(req, nis);
	ni_nis_info_free(nis);
	return rv;
}

static int
generic_nis_put(ni_handle_t *nih, ni_wicked_request_t *req)
{
	ni_nis_info_t *nis = NULL;
	const xml_node_t *arg;
	int rv = -1;

	if (nih == NULL)
		return -1;

	if (nih->op->nis_put == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	if ((arg = req->xml_in) == NULL) {
		werror(req, "no xml arguments given");
		return -1;
	}
	if (arg->name == NULL && arg->children)
		arg = arg->children;

	if (!(nis = ni_syntax_xml_to_nis(ni_default_xml_syntax(), arg))) {
		werror(req, "unable to parse nis XML");
		goto failed;
	}

	if (nih->op->nis_put(nih, nis) < 0) {
		werror(req, "error configuring NIS");
		goto failed;
	}

	rv = generic_nis_response(req, nis);

failed:
	if (nis)
		ni_nis_info_free(nis);
	return rv;
}

static int
system_nis_get(ni_wicked_request_t *req)
{
	return generic_nis_get(system_handle(req), req);
}

static int
system_nis_put(ni_wicked_request_t *req)
{
	return generic_nis_put(system_handle(req), req);
}

static ni_rest_node_t	ni_rest_system_nis_node = {
	.name		= "nis",
	.ops = {
	    .byname = {
		.get	= system_nis_get,
		.put	= system_nis_put,
	    },
	},
	.children = {
		&ni_rest_system_nis_domain_node,
	},
};

/*
 * Name resolver Configuration
 */
static int
generic_resolver_response(ni_wicked_request_t *req, const ni_resolver_info_t *resolver)
{
	req->xml_out = ni_syntax_xml_from_resolver(ni_default_xml_syntax(), resolver, NULL);
	if (req->xml_out == NULL) {
		werror(req, "unable to render resolver information");
		return -1;
	}
	return 0;
}

static int
generic_resolver_get(ni_handle_t *nih, ni_wicked_request_t *req)
{
	ni_resolver_info_t *resolver;
	int rv;

	if (nih->op->resolver_get == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	if ((resolver = nih->op->resolver_get(nih)) == NULL) {
		werror(req, "error getting resolver domain");
		return -1;
	}

	rv = generic_resolver_response(req, resolver);
	ni_resolver_info_free(resolver);
	return rv;
}

static int
generic_resolver_put(ni_handle_t *nih, ni_wicked_request_t *req)
{
	ni_resolver_info_t *resolver = NULL;
	const xml_node_t *arg;
	int rv = -1;

	if (nih == NULL)
		return -1;

	if (nih->op->resolver_put == NULL) {
		werror(req, "operation not supported");
		return -1;
	}

	if ((arg = req->xml_in) == NULL) {
		werror(req, "no xml arguments given");
		return -1;
	}
	if (arg->name == NULL && arg->children)
		arg = arg->children;

	if (!(resolver = ni_syntax_xml_to_resolver(ni_default_xml_syntax(), arg))) {
		werror(req, "unable to parse resolver XML");
		goto failed;
	}

	if (nih->op->resolver_put(nih, resolver) < 0) {
		werror(req, "error configuring resolver");
		goto failed;
	}

	rv = generic_resolver_response(req, resolver);

failed:
	if (resolver)
		ni_resolver_info_free(resolver);
	return rv;
}

static int
system_resolver_get(ni_wicked_request_t *req)
{
	return generic_resolver_get(system_handle(req), req);
}

static int
system_resolver_put(ni_wicked_request_t *req)
{
	return generic_resolver_put(system_handle(req), req);
}

static ni_rest_node_t	ni_rest_system_resolver_node = {
	.name		= "resolver",
	.ops = {
	    .byname = {
		.get	= system_resolver_get,
		.put	= system_resolver_put,
	    },
	},
};

/*
 * Event receiver
 */
static int
system_event_post(ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_handle_t *nih = system_handle(req);
	ni_interface_t *ifp = NULL;
	const xml_node_t *arg;

	if (nih == NULL)
		return -1;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	ifp = ni_interface_by_name(nih, ifname);
	if (ifp == NULL) {
		ni_warn("event for unknown interface %s", ifname);
		return 0;
	}

	if ((arg = req->xml_in) == NULL) {
		werror(req, "no xml arguments given");
		return -1;
	}

	if (arg->name == NULL && arg->children)
		arg = arg->children;

	if (!strcmp(arg->name, "lease")) {
		ni_addrconf_lease_t *lease;

		lease = ni_syntax_xml_to_lease(ni_default_xml_syntax(), arg);
		if (!lease)
			goto syntax_error;

		if (ni_interface_update_lease(nih, ifp, lease) < 0)
			ni_addrconf_lease_free(lease);
	} else {
		ni_debug_wicked("%s: received %s event", ifname, arg->name);
	}

	return 0;

syntax_error:
	werror(req, "unable to parse event argument");
	return -1;
}

static ni_rest_node_t	ni_rest_system_event_wildcard_node = {
	.name		= NULL,
	.ops = {
	    .byname = {
		.post	= system_event_post,
	    },
	},
};
static ni_rest_node_t	ni_rest_system_event_node = {
	.name		= "event",
	.wildcard	= &ni_rest_system_event_wildcard_node,
};

/*
 * 	/wicked/debug subtree
 */
static int
ni_rest_debug_add(unsigned int facility, const char *title, const char *comment, xml_node_t *xml_parent)
{
	xml_node_t	*node;

	node = xml_node_new(title, xml_parent);
	if (comment)
		xml_node_add_attr(node, "comment", comment);
	xml_node_add_attr_uint(node, "enabled", !!(ni_debug & facility));
	return 0;
}

static int
debug_get(ni_wicked_request_t *req)
{
	unsigned long i;

	req->xml_out = xml_node_new("debug", NULL);
	for (i = 1; i; i = i << 1) {
		const char *name = ni_debug_facility_to_name(i);

		if (name)
			ni_rest_debug_add(i, name,
					ni_debug_facility_to_description(i),
					req->xml_out);
	}
	return 0;
}

static int
__wicked_debug_put(ni_wicked_request_t *req, unsigned int *newflags)
{
	const xml_node_t *node = NULL;

	node = req->xml_in;
	if (node && !node->name)
		node = node->children;
	if (!node)
		return 0;
	if (strcmp(node->name, "debug")) {
		werror(req, "expected <debug> element");
		return -1;
	}

	for (node = node->children; node; node = node->next) {
		unsigned int facility, ena = 0;

		if (ni_debug_name_to_facility(node->name, &facility) < 0) {
			werror(req, "debug facility %s not known", node->name);
			return -1;
		}
		if (xml_node_get_attr_uint(node, "enabled", &ena) < 0) {
			werror(req, "debug facility %s: cannot parse attr enabled=\"...\"",
					node->name);
			return -1;
		}
		if (ena)
			*newflags |= facility;
		else
			*newflags &= ~facility;
	}
	return 0;
}

static int
debug_put(ni_wicked_request_t *req)
{
	unsigned int newflags = 0;

	if (__wicked_debug_put(req, &newflags) < 0)
		return -1;

	ni_debug = newflags;
	return 0;
}

static int
debug_post(ni_wicked_request_t *req)
{
	unsigned int newflags = ni_debug;

	if (__wicked_debug_put(req, &newflags) < 0)
		return -1;

	ni_debug = newflags;
	return 0;
}

static ni_rest_node_t	ni_rest_wicked_debug_node = {
	.name		= "debug",
	.ops = {
	    .byname = {
		.get	= debug_get,
		.put	= debug_put,
		.post	= debug_post,
	    },
	},
};

static int
system_meta_get(ni_wicked_request_t *req)
{
	req->xml_out = xml_node_new("meta", NULL);
	ni_rest_generate_meta(NULL, req->xml_out);
	return 0;
}

static ni_rest_node_t	ni_rest_wicked_meta_node = {
	.name		= "meta",
	.ops = {
	    .byname = {
		.get	= system_meta_get,
	    },
	},
};

static ni_rest_node_t	ni_rest_system_node = {
	.name		= "system",
	.children = {
		&ni_rest_system_interface_node,
		&ni_rest_system_policy_node,
		&ni_rest_system_hostname_node,
		&ni_rest_system_nis_node,
		&ni_rest_system_resolver_node,
		&ni_rest_system_event_node,
	},
};

static ni_rest_node_t	ni_rest_config_node = {
	.name		= "config",
	.children = {
		&ni_rest_config_interface_node,
		&ni_rest_config_hostname_node,
	},
};

/*
 *	/wicked subtree
 */
static ni_rest_node_t	ni_rest_wicked_node = {
	.name		= "wicked",
	.children = {
		&ni_rest_wicked_meta_node,
		&ni_rest_wicked_debug_node,
	},
};

ni_rest_node_t	ni_rest_root_node = {
	.name		= "/",
	.children = {
		&ni_rest_config_node,
		&ni_rest_system_node,
		&ni_rest_wicked_node,
	},
};

static ni_rest_node_t *
ni_rest_node_find_child(ni_rest_node_t *node, const char *name)
{
	unsigned int i;

	for (i = 0; i < __NI_REST_CHILD_MAX; ++i) {
		ni_rest_node_t *child = node->children[i];

		if (child == NULL)
			break;
		if (!strcmp(child->name, name))
			return child;
	}
	return NULL;
}

ni_rest_node_t *
ni_wicked_rest_lookup(const char *path)
{
	return ni_rest_node_lookup(&ni_rest_root_node, path, NULL);
}

ni_rest_node_t *
ni_rest_node_lookup(ni_rest_node_t *root, const char *path, ni_wicked_request_t *req)
{
	ni_rest_node_t *node = root;
	char *copy, *pos;

	copy = pos = xstrdup(path);
	while (*pos) {
		ni_rest_node_t *child;
		char *comp;

		while (*pos == '/')
			++pos;
		comp = pos;

		/* Find end of component, and NUL terminate it */
		pos += strcspn(pos, "/");
		while (*pos == '/')
			*pos++ = '\0';

		child = ni_rest_node_find_child(node, comp);
		if (child == NULL) {
			if ((child = node->wildcard) == NULL)
				goto failed;

			if (req) {
				/* request may be NULL if we're just checking for
				 * resolvability of a path. */
				if (req->argc >= __NI_REST_ARGS_MAX) {
					ni_error("too many lookups in REST node tree");
					goto failed;
				}
				ni_string_dup(&req->argv[req->argc], comp);
				req->argc++;
			}
		}

		node = child;
	}

	free(copy);
	return node;

failed:
	free(copy);
	return NULL;
}

void
ni_rest_node_add_update_callback(ni_rest_node_t *node, ni_extension_t *ex, ni_script_action_t *act)
{
	/* For now, we support just a single update callback */
	if (node->update.callback) {
		ni_error("duplicate update callback for node %s", node->name);
		return;
	}
	node->update.extension = ex;
	node->update.callback = act;
}

/*
 * Check whether the named REST node supports the given operation
 */
int
ni_rest_node_supports_operation(const char *path, ni_rest_op_t op)
{
	ni_rest_node_t *node;

	if (op >= __NI_REST_OP_MAX)
		return 0;

	node = ni_rest_node_lookup(&ni_rest_root_node, path, NULL);
	return node && node->ops.fn[op] != NULL;
}

static void
ni_rest_generate_meta(ni_rest_node_t *node, xml_node_t *xml_parent)
{
	unsigned int i, j;

	if (node == NULL)
		node = &ni_rest_root_node;

	for (j = 0; j < __NI_REST_OP_MAX; j++) {
		if (node->ops.fn[j] != NULL) {
			xml_node_add_attr(xml_parent,
					ni_wicked_rest_op_print(j),
					"1");
		}		
	}

	for (i = 0; i < __NI_REST_CHILD_MAX; ++i) {
		ni_rest_node_t *child = node->children[i];
		xml_node_t *child_xml;

		if (child == NULL)
			break;
		child_xml = xml_node_new(child->name, xml_parent);
		ni_rest_generate_meta(child, child_xml);
	}
}

static char *
ni_request_get_domain_element(ni_wicked_request_t *req, const char *element_name)
{
	char *hostname, *sp;
	xml_node_t *hnode;
	unsigned int n;

	if (!req->xml_in
	 || !(hnode = xml_node_get_child(req->xml_in, element_name))
	 || !(sp = hnode->cdata)) {
		werror(req, "bad or missing XML document");
		return NULL;
	}

	while (isspace(*sp))
		++sp;
	hostname = sp;

	n = strlen(hostname);
	while (n && isspace(hostname[n-1]))
		hostname[--n] = '\0';

	/* Be strict - do not accept garbage in hostnames. Note that
	 * this also excludes UTF8 encoded names */
	for (n = 0; hostname[n]; ++n) {
		unsigned char cc = hostname[n];

		if (cc <= 0x20 || cc >= 0x7f) {
			werror(req, "illegal character in %s element", element_name);
			return NULL;
		}
	}

	return hostname;
}

void
werror(ni_wicked_request_t *req, const char *fmt, ...)
{
	char buffer[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	ni_string_dup(&req->error_msg, buffer);
	va_end(ap);
}
