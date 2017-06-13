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
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include "ki_tool.h"
#include "liki.h"
#include "liki_extra.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "conv.h"

static inline int 
print_workqueue_insertion_rec(void *a)
{
	workqueue_enqueue_t *rec_ptr = (workqueue_enqueue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	printf ("%cfunc=", fsep);
	print_kernel_sym((uint64)rec_ptr->funcp, 0);
	printf ("\n");
	
	return 0;
}

int
workqueue_insertion_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	workqueue_enqueue_t tt_rec_ptr;
	workqueue_enqueue_t *rec_ptr;

	if (debug) printf ("trace_workqueue_insertion_func()\n");
	rec_ptr = conv_workqueue_insertion(trcinfop, &tt_rec_ptr);

	print_workqueue_insertion_rec(rec_ptr);	
}

static inline int
print_workqueue_execution_rec(void *a) 
{
	workqueue_execute_t *rec_ptr = (workqueue_execute_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	printf ("%cfunc=", fsep);
	print_kernel_sym((uint64)rec_ptr->funcp, 0);
	printf ("\n");
	
	return 0;
}

int
workqueue_execution_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	workqueue_execute_t tt_rec_ptr;
	workqueue_execute_t *rec_ptr;

	if (debug) printf ("trace_workqueue_execution_func()\n");

	rec_ptr = conv_workqueue_execution(trcinfop, &tt_rec_ptr);
	print_workqueue_execution_rec(rec_ptr);	
}

static inline int
print_workqueue_enqueue_rec(void *a)
{
	workqueue_enqueue_t *rec_ptr = (workqueue_enqueue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	
	printf ("%cfunc=", fsep);
	print_kernel_sym((uint64)rec_ptr->funcp, 0);
	printf ("%ctarget_cpu=%d", fsep, rec_ptr->tgt_cpu);
	printf ("\n");

	return 0;
}

int
workqueue_enqueue_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	workqueue_enqueue_t tt_rec_ptr;
	workqueue_enqueue_t *rec_ptr;

	if (debug) printf ("trace_workqueue_enqueue_func()\n");

	rec_ptr = conv_workqueue_enqueue(trcinfop, &tt_rec_ptr);
	print_workqueue_enqueue_rec(rec_ptr);
}

static inline int
print_workqueue_execute_rec(void *a)
{
	workqueue_execute_t *rec_ptr = (workqueue_execute_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	
	printf ("%cfunc=", fsep);
	print_kernel_sym((uint64)rec_ptr->funcp, 0);
	printf ("\n");

	return 0;
}	

workqueue_execute_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	workqueue_execute_t tt_rec_ptr;
	workqueue_execute_t *rec_ptr;

	if (debug) printf ("trace_workqueue_execute_func()\n");

	rec_ptr = conv_workqueue_execute(trcinfop, &tt_rec_ptr);
	print_workqueue_execute_rec(rec_ptr);
}
