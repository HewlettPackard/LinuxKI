/***************************************************************************
Copyright 2017 Hewlett Packard Enterprise Development LP.
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version. This program is distributed in the
hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details. You
should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <err.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "conv.h"


static inline int 
print_cache_insert_rec(cache_insert_t *rec_ptr)
{
	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%cpage=0x%llx%cino=%d%cindex=0x%llx%cdev=0x%x",
		fsep, rec_ptr->page, 
		fsep, rec_ptr->i_ino, 
		fsep, rec_ptr->index,
		fsep, rec_ptr->dev);
	printf ("\n");

	return 0;
}

static inline int
print_cache_evict_rec(cache_evict_t *rec_ptr)
{
	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%cpage=0x%llx%cino=%d%cindex=0x%llx%cdev=0x%x", 
		fsep, rec_ptr->page,
		fsep, rec_ptr->i_ino,
		fsep, rec_ptr->index,
		fsep, rec_ptr->dev);

	if (rec_ptr->stack_depth) {
		print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, 0, rec_ptr->pid);
		/* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth);  */
	}
	printf ("\n");

	return 0;
}
	
int
cache_insert_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	cache_insert_t tt_rec_ptr;
	cache_insert_t *rec_ptr;
	pid_info_t *pidp;
	pgcache_t *pgcachep;
	fdata_info_t *fdatap;

	if (debug) printf ("pid_cache_insert_func\n");
	rec_ptr = conv_cache_insert(trcinfop, &tt_rec_ptr);

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		pidp->cache_insert_cnt++;

		pgcachep = GET_PGCACHEP(&pidp->pgcache_hash, rec_ptr->dev, rec_ptr->i_ino);
		pgcachep->cache_insert_cnt++;
	}

	if (global_stats) {
		fdatap = GET_FDATAP(&globals->fdata_hash, rec_ptr->dev, rec_ptr->i_ino);
		fdatap->node = rec_ptr->i_ino;
		fdatap->dev = rec_ptr->dev;
		fdatap->cache_insert_cnt++;

		globals->cache_insert_cnt++;
	}

	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);

	if (kitrace_flag) print_cache_insert_rec(rec_ptr);
}
	
int
cache_evict_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	cache_evict_t tt_rec_ptr;
	cache_evict_t *rec_ptr;
	pid_info_t *pidp;
	pgcache_t *pgcachep;
	fdata_info_t *fdatap;

	if (debug) printf ("cache_evict_func\n");

	rec_ptr = conv_cache_evict(trcinfop, &tt_rec_ptr);

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		pidp->cache_evict_cnt++;

		pgcachep = GET_PGCACHEP(&pidp->pgcache_hash, rec_ptr->dev, rec_ptr->i_ino);
		pgcachep->cache_evict_cnt++;
	}

	if (global_stats) { 
		fdatap = GET_FDATAP(&globals->fdata_hash, rec_ptr->dev, rec_ptr->i_ino);
		fdatap->node = rec_ptr->i_ino;
		fdatap->dev = rec_ptr->dev;
		fdatap->cache_evict_cnt++;

		globals->cache_evict_cnt++;
	}

	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);

	if (kitrace_flag) print_cache_evict_rec(rec_ptr);
}
	
