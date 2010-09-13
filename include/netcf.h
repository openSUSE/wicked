/*
 * netcf.h: public interface for libnetcf
 *
 * Copyright (C) 2007 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David Lutterkort <dlutter@redhat.com>
 */

#ifndef NETCF_H_
#define NETCF_H_

/*
 * FIXME: NM needs a way to be notified of changes to the underlying
 * network files, either we provide a way to register callbacks for an
 * interface, or we hand out a list of files that contain the configs for
 * the interface.
 *
 */

/* The main object for netcf, for internal state tracking */
struct netcf;

/* An individual interface (connection) */
struct netcf_if;

/* The error codes returned by ncf_error */
typedef enum {
    NETCF_NOERROR = 0,   /* no error, everything ok */
    NETCF_EINTERNAL,     /* internal error, aka bug */
    NETCF_EOTHER,        /* other error, copout for being more specific */
    NETCF_ENOMEM,        /* allocation failed */
    NETCF_EXMLPARSER,    /* XML parser choked */
    NETCF_EXMLINVALID,   /* XML invalid in some form */
    NETCF_ENOENT,        /* Required entry in a tree is missing */
    NETCF_EEXEC,         /* external program execution failed or returned
                          * non-0 */
    NETCF_EINUSE,        /* attempt to close a netcf instance that is still
                          * used by other data structures */
    NETCF_EXSLTFAILED,   /* XSLT transformation failed */
    NETCF_EFILE,         /* Some file access failed */
    NETCF_EIOCTL,        /* An ioctl call failed */
    NETCF_ENETLINK       /* something related to the netlink socket failed */
} netcf_errcode_t;


/*
 * flags accepted by ncf_num_of_interfaces and ncf_list_interfaces.
 * IMPORTANT NOTE: These are bits, so you should assign only powers of two
 * (Default behavior is to match NO interfaces)
 */
typedef enum {
    NETCF_IFACE_INACTIVE = 1,     /* match down interfaces */
    NETCF_IFACE_ACTIVE = 2,       /* match up interfaces */
} netcf_if_flag_t;


/*
 * Initialize netcf. This function must be called before any other netcf
 * function can be called.
 *
 * Use ROOT as the filesystem root. If ROOT is NULL, use "/".
 *
 * Return 0 on success, -2 if allocation of *NETCF failed, and -1 on any
 * other failure. When -2 is returned, *NETCF is NULL.
 */
int ncf_init(struct netcf **netcf, const char *root);

/* Close the connection to netcf and release any resources associated with
 * it. It is an error to call this function before all data structeres
 * retrieved using this netcf instance have been free'd; in particular, any
 * struct netcf_if retrieved with this netcf instance must be cleaned up
 * with NCF_IF_FREE before calling this function.
 *
 * Returns 0 on success, and -1 on error.
 */
int ncf_close(struct netcf *);

/* Number of known interfaces and list of them. For listing, interfaces are
 * identified by their name. FLAGS is a bitmask of NETCF_IF_FLAG_T and
 * makes it possible to filter which interfaces are returned
 * (active/inactive/all)
 */
int
ncf_num_of_interfaces(struct netcf *, unsigned int flags);
int
ncf_list_interfaces(struct netcf *, int maxnames, char **names, unsigned int flags);


/* Look interface up by name.
 *
 * Returns the interface, which must later be freed with a call to
 * NCF_IF_FREE, or NULL on error.
 */
struct netcf_if *
ncf_lookup_by_name(struct netcf *, const char *name);

/* Find all interfaces with the given hardware address MAC. Generally, MAC
 * should be in hex notation aa:bb:cc:dd:ee:ff.
 *
 * Up to MAXIFACES interfaces are returned in the array IFACES, which must
 * be allocated by the caller to hold at least MAXIFACES pointers to struct
 * netcf_if. It is permissible to pass in MAXIFACES == 0, in which case
 * IFACES is ignored. If there are more than MAXIFACES interfaces with the
 * given MAC, only MAXIFACES many will be returned.
 *
 * The function returns -1 on error, or a nonnegative number indicating the
 * number of interfaces with the given MAC, which can be larger than
 * MAXIFACES.
 */
int
ncf_lookup_by_mac_string(struct netcf *, const char *mac,
                         int maxifaces, struct netcf_if **ifaces);

/*
 * Define/start/stop/undefine interfaces
 */

/* Define a new interface */
struct netcf_if *
ncf_define(struct netcf *, const char *xml);

/* Return the name of the interface. The string can be used up until the
 * next call to a function that takes this NETCF_IF as argument
 */
const char *ncf_if_name(struct netcf_if *);

/* Return the MAC address of an interface.
 */
const char *ncf_if_mac_string(struct netcf_if *);

/* Bring the interface up */
int ncf_if_up(struct netcf_if *);

/* Take it down */
int ncf_if_down(struct netcf_if *);

/* Delete the definition */
int ncf_if_undefine(struct netcf_if *);

/* Produce an XML description for the static (stored) interface
 * config, in the same format that NCF_DEFINE expects
 */
char *ncf_if_xml_desc(struct netcf_if *);

/* Produce an XML description of the current live state of the
 * interface, in the same format that NCF_DEFINE expects, but
 * potentially with extra info not contained in the static config (ie
 * the current IP address of an interface that uses DHCP)
 */
char *ncf_if_xml_state(struct netcf_if *);

/* Report various status info about the interface as bits in
 * "flags". The meaning of the bits is in the enum type netcf_if_flag_t.
 * Returns 0 on success, -1 on failure
 */
int ncf_if_status(struct netcf_if *nif, unsigned int *flags);

/* Release any resources used by this NETCF_IF; the pointer is invalid
 * after this call
 */
void ncf_if_free(struct netcf_if *);

/* Return the error code when a previous call failed. The return value is
 * one of NETCF_ERRCODE_T.
 *
 * ERRMSG is a human-readable explanation of the error. For some errors,
 * DETAILS will contain additional information, for others it will be NULL.
 * The pointer passed in to store either of these can be NULL with no ill
 * effects (useful if you just want the code)
 *
 * Both the ERRMSG pointer and the DETAILS pointer are only valid until the
 * next call to another function in this API.
 */
int ncf_error(struct netcf *, const char **errmsg, const char **details);
#endif


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
