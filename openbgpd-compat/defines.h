/* $Id: defines.h,v 1.17 2004/10/26 12:45:54 dtucker Exp $ */

/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#if !defined(SA_LEN)
# if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
#  define SA_LEN(x)	((x)->sa_len)
# else
#  define SA_LEN(x)	(sizeof(struct sockaddr))
# endif
#endif

#if !defined(SS_LEN)
# if defined(HAVE_STRUCT_SOCKADDR_SS_LEN)
#  define SS_LEN(x)  ((x)->ss_len)
# else
#  define SS_LEN(x)  SA_LEN((struct sockaddr *)&(x))
# endif
#endif

#ifndef SYSCONFDIR
# define SYSCONFDIR "/usr/local/etc"
#endif

#ifndef IOV_MAX
# if defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#  define IOV_MAX 1024	/* FreeBSD 4/Mac OS X don't define this in userspace */
# endif
#endif

#ifndef INFTIM
# define INFTIM          (-1)
#endif

#ifndef HAVE_BZERO
# define bzero(a,b)	 memset((a), 0, (b))
#endif

#ifdef MODEMASK
# undef MODEMASK
#endif

#if 0
/* FreeBSD 5.x does not have EAI_NODATA */
#ifndef EAI_NODATA
# define EAI_NODATA EAI_NONAME
#endif
#endif

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#endif

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ifndef HAVE_U_INT
typedef unsigned int u_int;
#endif

#ifndef HAVE_INTXX_T
# if (SIZEOF_CHAR == 1)
typedef char int8_t;
# else
#  error "8 bit int type not found."
# endif
# if (SIZEOF_SHORT_INT == 2)
typedef short int int16_t;
# else
#  ifdef _UNICOS
#   if (SIZEOF_SHORT_INT == 4)
typedef short int16_t;
#   else
typedef long  int16_t;
#   endif
#  else
#   error "16 bit int type not found."
#  endif /* _UNICOS */
# endif
# if (SIZEOF_INT == 4)
typedef int int32_t;
# else
#  ifdef _UNICOS
typedef long  int32_t;
#  else
#   error "32 bit int type not found."
#  endif /* _UNICOS */
# endif
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# else
#  if (SIZEOF_CHAR == 1)
typedef unsigned char u_int8_t;
#  else
#   error "8 bit int type not found."
#  endif
#  if (SIZEOF_SHORT_INT == 2)
typedef unsigned short int u_int16_t;
#  else
#   ifdef _UNICOS
#    if (SIZEOF_SHORT_INT == 4)
typedef unsigned short u_int16_t;
#    else
typedef unsigned long  u_int16_t;
#    endif
#   else
#    error "16 bit int type not found."
#   endif
#  endif
#  if (SIZEOF_INT == 4)
typedef unsigned int u_int32_t;
#  else
#   ifdef _UNICOS
typedef unsigned long  u_int32_t;
#   else
#    error "32 bit int type not found."
#   endif
#  endif
# endif
#define __BIT_TYPES_DEFINED__
#endif

/* 64-bit types */
#ifndef HAVE_INT64_T
# if (SIZEOF_LONG_INT == 8)
typedef long int int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef long long int int64_t;
#  endif
# endif
#endif
#ifndef HAVE_U_INT64_T
# if (SIZEOF_LONG_INT == 8)
typedef unsigned long int u_int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef unsigned long long int u_int64_t;
#  endif
# endif
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* FSF bison 1.875 wants this to prevent conflicting definitions of YYSTYPE */
#define YYSTYPE_IS_DECLARED 1

#if defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
# define seteuid(a)	(setreuid(-1, a))
#endif
#if defined(HAVE_SETEGID) && defined(HAVE_SETREGID)
# define setegid(a)	(setregid(-1, a))
#endif

#if !defined(IOV_MAX) && defined(DEF_IOV_MAX)
# define IOV_MAX	DEF_IOV_MAX
#endif

#if !defined(HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY) && \
    defined(HAVE_STRUCT_SOCKADDR_STORAGE___SS_FAMILY)
# define ss_family __ss_family
#endif

/* Necessary OpenBSD definitions from systemwide .h files */
size_t	strlcat(char *, const char *, size_t);
size_t	strlcpy(char *, const char *, size_t);

long long
        strtonum(const char *, long long, long long, const char **);

void	*bsearch(const void *, const void *, size_t, size_t,
            int (*)(const void *, const void *));

void	setproctitle(const char *, ...);

#include <stdlib.h>
#include <time.h>
