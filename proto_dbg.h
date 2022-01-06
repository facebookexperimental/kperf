/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef PROTO_DBG_H
#define PROTO_DBG_H 1

#include <stdarg.h>
#include <stdio.h>

#include "proto.h"

extern int verbose;

#define __kpm_cmd_dbg(pfx, msg, hdr)					\
	({								\
		struct kpm_header *_hdr = (hdr);			\
									\
		if (verbose)						\
			fprintf(stderr, "D%s %s%s%s T%d (seq:%d, len:%d)\n", \
				pfx, __FILE__,				\
				strlen(msg) ? " " : "", msg,		\
				_hdr->type, _hdr->id, _hdr->len);	\
	})

#define __kpm_cmd_dbg_start(name, hdr)	__kpm_cmd_dbg("|>", name, hdr)
#define __kpm_cmd_dbg_end(name, hdr)	__kpm_cmd_dbg("|<", name, hdr)

#define kpm_cmd_dbg_start(hdr)	__kpm_cmd_dbg_start("", hdr)
#define kpm_cmd_dbg_end(hdr)	__kpm_cmd_dbg_end("", hdr)

static inline void ____kpm_trace(int level, const char *fn, const char *pfx,
				 const char *fmt, ...)
{
	const char *letters = "!EWIDT ";
	va_list ap;

	if (verbose < level)
		return;
	if (level > 6)
		level = 6;

	fprintf(stderr, "%c%s %s: ", letters[level], pfx, fn);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define __kpm_info(pfx, msg...)		____kpm_trace(3, __FILE__, pfx, msg)
#define kpm_info(msg...)		__kpm_info("  ", msg)

#define __kpm_dbg(pfx, msg...)		____kpm_trace(4, __FILE__, pfx, msg)
#define kpm_dbg(msg...)			__kpm_dbg("  ", msg)

#define __kpm_trace(pfx, msg...)	____kpm_trace(5, __FILE__, pfx, msg)
#define kpm_trace(msg...)		__kpm_trace("  ", msg)

#endif
