/*
 * Compiler specific definitions
 *
 * Copyright (C) 2024 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NI_WICKED_COMPILER_H
#define NI_WICKED_COMPILER_H

#ifdef __GNUC__

# define ni__printf(a, b)	__attribute__ ((format (printf, a, b)))
# define ni__noreturn		__attribute__ ((noreturn))
# define ni__packed		__attribute__ ((__packed__))
# define ni__unused		__attribute__ ((unused))
# define ni__constructor	__attribute__ ((constructor))

#else /* __GNUC__ */

# define ni__printf(a, b)	/* */
# define ni__noreturn		/* */
# define ni__packed		/* */
# define ni__unused		/* */
# define ni__constructor	/* */

#endif

#endif /* NI_WICKED_COMPILER_H */
