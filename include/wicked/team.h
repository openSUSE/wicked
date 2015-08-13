/*
 *	Team device support
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef NI_WICKED_TEAM_H
#define NI_WICKED_TEAM_H

/*
 * runner
 */
typedef enum {
	NI_TEAM_RUNNER_ROUND_ROBIN = 0,
	NI_TEAM_RUNNER_ACTIVE_BACKUP,
	NI_TEAM_RUNNER_LOAD_BALANCE,
	NI_TEAM_RUNNER_BROADCAST,
	NI_TEAM_RUNNER_RANDOM,
	NI_TEAM_RUNNER_LACP,
} ni_team_runner_type_t;


/*
 * runner type union
 */
typedef struct ni_team_runner {
	ni_team_runner_type_t			type;
} ni_team_runner_t;


/*
 * link watch
 */
typedef enum {
	NI_TEAM_LINK_WATCH_ETHTOOL = 0,
	NI_TEAM_LINK_WATCH_ARP_PING,
	NI_TEAM_LINK_WATCH_NSNA_PING,
	NI_TEAM_LINK_WATCH_TIPC,
} ni_team_link_watch_type_t;

/*
 * link watch type structs
 */
typedef struct ni_team_link_watch_arp {
	char *					source_host;
	char *					target_host;

	unsigned int				interval;
	unsigned int				init_wait;
	ni_bool_t				validate_active;
	ni_bool_t				validate_inactive;
	ni_bool_t				send_always;
	unsigned int				missed_max;
	unsigned int				missed;
} ni_team_link_watch_arp_t;

typedef struct ni_team_link_watch_tipc {
	char *					bearer;
} ni_team_link_watch_tipc_t;

typedef struct ni_team_link_watch_nsna {
	char *					target_host;

	unsigned int				interval;
	unsigned int				init_wait;
	unsigned int				missed_max;
	unsigned int				missed;
} ni_team_link_watch_nsna_t;

typedef struct ni_team_link_watch_ethtool {
	unsigned int				delay_up;
	unsigned int				delay_down;
} ni_team_link_watch_ethtool_t;


/*
 * link watch type union
 */
typedef struct ni_team_link_watch {
	ni_team_link_watch_type_t		type;

	union {
		ni_team_link_watch_arp_t	arp;
		ni_team_link_watch_tipc_t	tipc;
		ni_team_link_watch_nsna_t	nsna;
		ni_team_link_watch_ethtool_t	ethtool; /* default */
	};
} ni_team_link_watch_t;

typedef struct ni_team_link_watch_array {
	unsigned int				count;
	ni_team_link_watch_t **			data;
} ni_team_link_watch_array_t;


/*
 * team device
 */
struct ni_team {
	ni_team_runner_t			runner;
	ni_team_link_watch_array_t		link_watch;
};


extern ni_team_t *				ni_team_new();
extern void					ni_team_free(ni_team_t *);

extern const char *				ni_team_runner_type_to_name(ni_team_runner_type_t);
extern ni_bool_t				ni_team_runner_name_to_type(const char *, ni_team_runner_type_t *);

extern const char *				ni_team_link_watch_type_to_name(ni_team_link_watch_type_t);
extern ni_bool_t				ni_team_link_watch_name_to_type(const char *, ni_team_link_watch_type_t *);

extern ni_team_link_watch_t *			ni_team_link_watch_new(ni_team_link_watch_type_t);
extern void					ni_team_link_watch_free(ni_team_link_watch_t *);
extern ni_bool_t				ni_team_link_watch_array_append(ni_team_link_watch_array_t *, ni_team_link_watch_t *);
extern ni_bool_t				ni_team_link_watch_array_delete_at(ni_team_link_watch_array_t *, unsigned int);

#endif /* NI_WICKED_TEAM_H */
