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
#include <time.h>
#include <string.h>
#include <sys/errno.h>
#include "ki_tool.h"
#include "liki.h"
#include "liki_v1.h"
#include "liki_v2.h"
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "hash.h"
#include "info.h"
#include "conv.h"

void    (*init_func)(void *) = info_init_func;
extern void (*tool_init_func)(void *);

int info_syscall_func(uint64, int, void *);

void
info_init_func(void *v)
{
	if (debug) printf ("info_init_func()\n");

	/* default functions */
        filter_func = NULL;
        sort_func = NULL;
        process_func = NULL;
        print_func = info_print_func;
	report_func = info_report_func;
	bufmiss_func = NULL;
	bufswtch_func = NULL;
	alarm_func = info_alarm_func;

	if (tool_init_func)
		tool_init_func(v);
}

/*
** this is the generic filter function 
*/
void *
info_filter_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	common_t tt_rec_ptr;
	common_t *rec_ptr;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);
	
	if (!ki_actions[rec_ptr->id].execute) {
		return NULL;
	}

	if (rec_ptr->id == TRACE_PRINT) return rec_ptr;
	CHECK_TIME_FILTER(rec_ptr->hrtime);

	return rec_ptr;
}

/* 
**
*/
int
info_dummy_func(uint64 rec_ptr, int cor, void *v)
{
	return 0;
}


/*
** Called for every SYSCALL record we found
*/
int
info_syscall_func(uint64 rec_ptr, int cor, void *v)
{ 
	uint64 *id = v;

	return 0;
}
/*
** Called for every record we found
*/
int
info_process_func(uint64 rec_ptr, void *v)
{
	uint64 id;

	return 0;
}

/*
**
*/
int
info_print_func(void *v)
{
	int i;
	struct timeval tod;

	if (print_flag) {
		if (is_alive) {
			gettimeofday(&tod, NULL);
			printf ("\n%s\n", ctime(&tod.tv_sec));
		}

		print_flag = 0;
	}

	return 0;

}

int
info_report_func(void *v)
{

	if (debug) printf ("Entering info_report_func %d\n", is_alive);
	if (is_alive == 0) {
		print_flag=1;
	}

	return 0;

}

/* bufmiss_func() should contain code for the 
 * tool to handle missed buffers if needed
 */

int
info_bufmiss_func(void *v, void *a)
{
	 trace_info_t *trcinfop = v;
	 kd_rec_t *rec_ptr = a;

	 /* printf ("Lost %d kitrace buffers\n", nmiss);  */
	
	return 0;
}

/* bufswtch_func() should contain code for the 
 * tool to do special processing at the end of
 * processing a set of KI buffers.
 * 
 * Typical globals that may be useful are:
 *
 * cur_buf_num
 * time_hwm      - highest cur_time found in set of buffers
 * time_lwm      - lowest cur_time found in set of buffers
 */

int
info_bufswtch_func(void *v)
{
int arg;
	 arg = *(int *)v;

	 /* printf ("Switching buffers\n";  */
	
	return 0;
}

/* alarm_func() should contain code any 
 * extra code to handle the alarm
 */

int
info_alarm_func(void *v)
{
	print_flag = 1;
	return 0;
}
