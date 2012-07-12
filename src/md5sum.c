/*
 *	Functions for hashing data. Even though this uses md5, this is not supposed
 *	to by cryptographically safe in any way. The main purpose of this code is to
 *	hash an XML document for "fingerprinting" a configuration.
 *
 *	Copyright (C) 2012  Olaf Kirch <okir@suse.de>
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/logging.h>
#include <wicked/util.h>
#include <gcrypt.h>

struct ni_hashctx {
	gcry_md_hd_t		handle;
	unsigned int		md_length;
};

/*
 * Create a new hash context
 */
ni_hashctx_t *
__ni_hashctx_new(int algo)
{
	ni_hashctx_t *ctx;
	gcry_error_t err;

	ctx = calloc(1, sizeof(*ctx));
	err = gcry_md_open(&ctx->handle, algo, 0);
	if (err) {
		ni_error("%s: gcry_md_open failed", __func__);
		ni_hashctx_free(ctx);
		return NULL;
	}

	ctx->md_length = gcry_md_get_algo_dlen(algo);
	return ctx;
}

ni_hashctx_t *
ni_hashctx_new(void)
{
	return __ni_hashctx_new(GCRY_MD_MD5);
}

/*
 * Destroy hash context
 */
void
ni_hashctx_free(ni_hashctx_t *ctx)
{
	if (ctx->handle) {
		gcry_md_close(ctx->handle);
		ctx->handle = NULL;
	}
	free(ctx);
}

/*
 * Begin hashing
 */
void
ni_hashctx_begin(ni_hashctx_t *ctx)
{
	gcry_md_reset(ctx->handle);
}

void
ni_hashctx_finish(ni_hashctx_t *ctx)
{
	gcry_md_final(ctx->handle);
}

int
ni_hashctx_get_digest(ni_hashctx_t *ctx, void *md_buffer, size_t md_size)
{
	void *md;

	if (ctx->handle == NULL)
		return -1;
	if (md_size < ctx->md_length) {
		ni_error("%s: digest too large for buffer", __func__);
		return -1;
	}

	if (!(md = gcry_md_read(ctx->handle, 0))) {
		ni_error("%s: failed to obtain digest", __func__);
		return -1;
	}

	memcpy(md_buffer, md, ctx->md_length);
	return ctx->md_length;
}

/*
 * Add data for hashing
 */
void
ni_hashctx_puts(ni_hashctx_t *ctx, const char *string)
{
	if (string)
		gcry_md_write(ctx->handle, string, strlen(string));
}
