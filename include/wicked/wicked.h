/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_H__
#define __WICKED_H__

enum {
	NI_REST_OP_GET = 0,
	NI_REST_OP_PUT,
	NI_REST_OP_POST,
	NI_REST_OP_DELETE,

	__NI_REST_OP_MAX
};

typedef struct ni_wicked_request {
	char *			error_msg;
	const xml_node_t *	xml_in;
	xml_node_t *		xml_out;

	ni_var_array_t		options;
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
	struct ni_rest_node *	children[__NI_REST_CHILD_MAX];
} ni_rest_node_t;

extern int			ni_wicked_call_direct(ni_wicked_request_t *,
					const char *, const char *);
extern int			ni_wicked_call_indirect(ni_wicked_request_t *,
					const char *, const char *);
extern void			ni_wicked_request_init(ni_wicked_request_t *);
extern void			ni_wicked_request_destroy(ni_wicked_request_t *);
extern int			ni_wicked_request_add_option(ni_wicked_request_t *,
					const char *, const char *);
extern const char *		ni_wicked_request_get_option(ni_wicked_request_t *,
					const char *);

extern ni_rest_node_t *		ni_rest_node_lookup(const char *, const char **);
extern void			werror(ni_wicked_request_t *, const char *, ...);

#endif /* __WICKED_H__ */
