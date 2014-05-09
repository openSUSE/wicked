/*
 *	wicked client ifconfig structures and objects
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 */
#ifndef   __WICKED_CLIENT_IFCONFIG_H__
#define   __WICKED_CLIENT_IFCONFIG_H__

#define NI_CLIENT_IFCONFIG		"interface"
#define NI_CLIENT_IFCONFIG_MATCH_NAME	"name"

#define NI_NANNY_IFPOLICY		"policy"
#define NI_NANNY_IFTEMPLATE		"template"

#define NI_NANNY_IFPOLICY_MATCH		"match"
#define NI_NANNY_IFPOLICY_MATCH_DEV	"device"
#define NI_NANNY_IFPOLICY_MERGE		"merge"

#define NI_NANNY_IFPOLICY_NAME		"name"
#define NI_NANNY_IFPOLICY_ORIGIN	"origin"
#define NI_NANNY_IFPOLICY_UUID		"uuid"

extern xml_node_t *		ni_convert_cfg_into_policy_node(xml_node_t *, const char *);
extern xml_document_t *	ni_convert_cfg_into_policy_doc(xml_document_t *);

#endif /* __WICKED_CLIENT_IFCONFIG_H__ */
