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

typedef enum {
	NI_TEAM_RUNNER_ROUND_ROBIN = 0,
	NI_TEAM_RUNNER_ACTIVE_BACKUP,
	NI_TEAM_RUNNER_LOAD_BALANCE,
	NI_TEAM_RUNNER_BROADCAST,
	NI_TEAM_RUNNER_RANDOM,
	NI_TEAM_RUNNER_LACP,
} ni_team_runner_type_t;

typedef struct ni_team_runner {
	ni_team_runner_type_t			type;
} ni_team_runner_t;

struct ni_team {
	ni_team_runner_t			runner;
};

extern ni_team_t *				ni_team_new();
extern void					ni_team_free(ni_team_t *);

extern const char *				ni_team_runner_type_to_name(ni_team_runner_type_t);
extern ni_bool_t				ni_team_runner_name_to_type(const char *, ni_team_runner_type_t *);

#endif /* NI_WICKED_TEAM_H */
