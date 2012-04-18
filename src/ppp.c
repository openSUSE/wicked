/*
 * Handling ppp interface information.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/ppp.h>
#include <wicked/modem.h>
#include "netinfo_priv.h"

#define NI_PPPDEV_TAG	"pppdev"

static ni_bool_t	__ni_ppp_tag_to_index(const char *, unsigned int *);

ni_ppp_t *
ni_ppp_new(const char *tag)
{
	static unsigned int next_index;
	char tagbuf[64];
	ni_ppp_t *ppp;

	if (tag != NULL) {
		unsigned int index;

		if (!__ni_ppp_tag_to_index(tag, &index))
			return NULL;
		if (index >= next_index)
			next_index = index + 1;
	} else {
		snprintf(tagbuf, sizeof(tagbuf), NI_PPPDEV_TAG "%u", next_index++);
		tag = tagbuf;
	}


	ppp = xcalloc(1, sizeof(*ppp));

	ppp->temp_state = ni_tempstate_new(tag);
	ppp->unit = -1;
	ppp->devfd = -1;
	return ppp;
}

void
ni_ppp_close(ni_ppp_t *ppp)
{
	if (ppp->devfd >= 0)
		close(ppp->devfd);
	ppp->unit = -1;
	ppp->devfd = -1;
}

void
ni_ppp_free(ni_ppp_t *ppp)
{
	ni_ppp_close(ppp);

	ni_tempstate_finish(ppp->temp_state);
	ppp->temp_state = NULL;

	if (ppp->config)
		ni_ppp_config_free(ppp->config);

	free(ppp);
}

/*
 * Handle ppp_config
 */
ni_ppp_config_t *
ni_ppp_config_new(void)
{
	ni_ppp_config_t *conf;

	conf = xcalloc(1, sizeof(*conf));
	return conf;
}

void
ni_ppp_config_free(ni_ppp_config_t *conf)
{
	ni_string_free(&conf->device.object_path);
	ni_string_free(&conf->device.name);
	if (conf->device.modem) {
		ni_modem_release(conf->device.modem);
		conf->device.modem = NULL;
	}
	if (conf->device.ethernet) {
		ni_netdev_put(conf->device.ethernet);
		conf->device.ethernet = NULL;
	}
	ni_string_free(&conf->number);
	if (conf->auth) {
		ni_ppp_authconfig_free(conf->auth);
		conf->auth = NULL;
	}

	free(conf);
}

ni_ppp_authconfig_t *
ni_ppp_authconfig_new(void)
{
	ni_ppp_authconfig_t *auth;

	auth = xcalloc(1, sizeof(*auth));
	return auth;
}

void
ni_ppp_authconfig_free(ni_ppp_authconfig_t *auth)
{
	ni_string_free(&auth->username);
	ni_string_free(&auth->password);
	ni_string_free(&auth->hostname);
	free(auth);
}

/*
 * Write the configuration file
 */
int
ni_ppp_write_config(const ni_ppp_t *ppp)
{
	ni_ppp_config_t *conf;
	char *configpath;
	FILE *fp;

	if ((conf = ppp->config) == NULL) {
		ni_error("no configuration attached to ppp device");
		return -1;
	}

	configpath = ni_tempstate_mkfile(ppp->temp_state, "config");
	if ((fp = fopen(configpath, "w")) == NULL) {
		ni_error("unable to open %s for writing: %m", configpath);
		return -1;
	}

	fprintf(fp, "ifname %s\n", ppp->devname);
	fprintf(fp, "unit %u\n", ppp->unit);

	fprintf(fp, "usepeerdns\n");
	fprintf(fp, "defaultroute\n");
	if (conf->device.modem) {
		ni_modem_t *modem = conf->device.modem;
		
		fprintf(fp, "modem\n");
		if (modem->use_lock_file)
			fprintf(fp, "lock\n");
	}
	if (conf->mru)
		fprintf(fp, "mru %u\n", conf->mru);
	if (conf->idle_timeout)
		fprintf(fp, "idle %u\n", conf->idle_timeout);

	if (conf->auth) {
		ni_ppp_authconfig_t *auth = conf->auth;

		configpath = ni_tempstate_mkfile(ppp->temp_state, "auth");
		fprintf(fp, "file %s\n", configpath);
		fclose(fp);

		fp = fopen(configpath, "w");
		if (fp == NULL) {
			ni_error("unable to open %s for writing: %m", configpath);
			return -1;
		}

		if (auth->hostname)
			fprintf(fp, "name %s\n", auth->hostname);
		if (auth->username)
			fprintf(fp, "user %s\n", auth->username);
		if (auth->password)
			fprintf(fp, "password %s\n", auth->password);
	}

	if (fp)
		fclose(fp);
	return -1;
}

/*
 * Given a tag like "pppdev0", extract the index.
 */
static ni_bool_t
__ni_ppp_tag_to_index(const char *tag, unsigned int *indexp)
{
	static const unsigned int prefixlen = sizeof(NI_PPPDEV_TAG) - 1;

	if (strncmp(tag, NI_PPPDEV_TAG, prefixlen))
		return FALSE;
	return ni_parse_int(tag + prefixlen, indexp) >= 0;
}
