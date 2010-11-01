/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_H__
#define __WICKED_H__

#include <wicked/types.h>

enum {
	NI_REST_OP_GET = 0,
	NI_REST_OP_PUT,
	NI_REST_OP_POST,
	NI_REST_OP_DELETE,

	__NI_REST_OP_MAX
};

typedef struct ni_wicked_request {
	int			cmd;		/* GET/PUT/POST/DELETE */
	char *			path;		/* path to operate on */

	const xml_node_t *	xml_in;		/* XML blob passed in */
	xml_node_t *		xml_out;	/* XML blob returned, or NULL */

	ni_var_array_t		options;	/* Additional option, such as "root" */

	char *			error_msg;	/* error message while processing req. */
} ni_wicked_request_t;

typedef int (*ni_rest_handler_t)(const char *, ni_wicked_request_t *req);

#define __NI_REST_CHILD_MAX	8
typedef struct ni_rest_node {
	const char *		name;
	union {
		ni_rest_handler_t fn[__NI_REST_OP_MAX];
		struct {
			ni_rest_handler_t get;
			ni_rest_handler_t put;
			ni_rest_handler_t post;
			ni_rest_handler_t delete;
		} byname;
	} ops;

	struct {
		ni_extension_t *	extension;
		ni_script_action_t *	callback;
	} update;
	struct ni_rest_node *	children[__NI_REST_CHILD_MAX];
} ni_rest_node_t;

extern ni_rest_node_t		ni_rest_root_node;

extern int			ni_wicked_call_direct(ni_wicked_request_t *);
extern int			ni_wicked_call_indirect(ni_wicked_request_t *);
extern int			ni_wicked_call_indirect_dgram(ni_socket_t *, ni_wicked_request_t *);
extern int			ni_wicked_send_event(ni_socket_t *, ni_wicked_request_t *);
extern void			ni_wicked_request_init(ni_wicked_request_t *);
extern void			ni_wicked_request_destroy(ni_wicked_request_t *);
extern int			ni_wicked_request_add_option(ni_wicked_request_t *,
					const char *, const char *);
extern const char *		ni_wicked_request_get_option(ni_wicked_request_t *,
					const char *);
extern int			ni_wicked_request_parse(ni_socket_t *, ni_wicked_request_t *);
extern int			ni_wicked_response_print(ni_socket_t *, ni_wicked_request_t *, int status);

extern int			ni_wicked_rest_op_parse(const char *);
extern const char *		ni_wicked_rest_op_print(int);
extern ni_rest_node_t *		ni_wicked_rest_lookup(const char *, const char **);

extern void			ni_rest_node_add_update_callback(ni_rest_node_t *,
						ni_extension_t *, ni_script_action_t *);

/*
 * This is for functionality moved into separate processes,
 * with which we communicate through messages and events.
 */
typedef struct ni_proxy {
	struct ni_proxy *	next;
	char *			name;
	pid_t			pid;
	ni_socket_t *		sock;
} ni_proxy_t;

extern ni_proxy_t *		ni_proxy_find(const char *);
extern ni_proxy_t *		ni_proxy_fork_subprocess(const char *, void (*mainloop)(ni_socket_t *));
extern int			ni_proxy_get_request(const ni_proxy_t *, ni_wicked_request_t *);
extern void			ni_proxy_stop(ni_proxy_t *);
extern void			ni_proxy_stop_all(void);

extern int			__ni_wicked_call_direct(ni_wicked_request_t *, ni_rest_node_t *);

extern void			werror(ni_wicked_request_t *, const char *, ...);

#endif /* __WICKED_H__ */
