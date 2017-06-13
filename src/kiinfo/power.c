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
#include <linux/kdev_t.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "sort.h"
#include "hash.h"
#include "html.h"
#include "conv.h"

static inline int
print_power_start_rec(void *a)
{
        power_start_t *rec_ptr = (power_start_t *)a;

        PRINT_COMMON_FIELDS(rec_ptr);
        PRINT_EVENT(rec_ptr->id);
        printf ("%cstate=%lld", fsep, rec_ptr->state);
        printf ("\n");

        return 0;
}

static inline int
print_power_end_rec(void *a)
{
        power_end_t *rec_ptr = (power_end_t *)a;

        PRINT_COMMON_FIELDS(rec_ptr);
        PRINT_EVENT(rec_ptr->id);
        printf ("\n");
        return 0;
}

static inline int
print_power_freq_rec(void *a)
{
        power_freq_t *rec_ptr = (power_freq_t *)a;

        PRINT_COMMON_FIELDS(rec_ptr);
        PRINT_EVENT(rec_ptr->id);

        if (IS_LIKI_V1)  {
                printf ("%ctarget_cpu=???", fsep);
        } else {
                printf ("%ctarget_cpu=%d", fsep, rec_ptr->tgt_cpu);
        }

        printf ("%cfreq=%lld", fsep, rec_ptr->freq);
        printf ("\n");

        return 0;
}

static inline int
incr_power_start_stats(power_start_t *rec_ptr)
{
	cpu_info_t *cpuinfop;
	power_info_t *powerp, *gpowerp;
	int cpu;

	cpu = rec_ptr->cpu;
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	powerp = GET_POWERP(cpuinfop->powerp);

	if (powerp->last_cstate_time) {
		powerp->cstate_times[powerp->cur_cstate] += (rec_ptr->hrtime - powerp->last_cstate_time);
	} else {	
		/* if we are starting a new cstate, assume we are coming from cstate 0 */
		powerp->cstate_times[0] = rec_ptr->hrtime - FILTER_START_TIME;
	}

	if (global_stats) {
		gpowerp = GET_POWERP(globals->powerp);

		if (powerp->last_cstate_time) {
			gpowerp->cstate_times[powerp->cur_cstate] += (rec_ptr->hrtime - powerp->last_cstate_time);
		} else {	
			/* if we are starting a new cstate, assume we are coming from cstate 0 */
			gpowerp->cstate_times[0] = rec_ptr->hrtime - FILTER_START_TIME;
		}
		gpowerp->power_start_cnt++;
	}
		
	powerp->power_start_cnt++;
	powerp->cur_cstate = rec_ptr->state;
	powerp->last_cstate_time = rec_ptr->hrtime;
	max_cstate = MAX(rec_ptr->state, max_cstate);
}

static inline int
incr_power_end_stats(power_end_t *rec_ptr)
{
	cpu_info_t *cpuinfop;
	power_info_t *powerp, *gpowerp;
	int cpu;
	
	cpu = rec_ptr->cpu;
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	powerp = GET_POWERP(cpuinfop->powerp);

	if (powerp->last_cstate_time) {
		powerp->cstate_times[powerp->cur_cstate] += (rec_ptr->hrtime - powerp->last_cstate_time);
	}

	if (global_stats) {
		gpowerp = GET_POWERP(globals->powerp);

		if (powerp->last_cstate_time) {
			gpowerp->cstate_times[powerp->cur_cstate] += (rec_ptr->hrtime - powerp->last_cstate_time);
		}

		gpowerp->power_end_cnt++;
	}

	powerp->power_end_cnt++;
	powerp->cur_cstate = 0;
	powerp->last_cstate_time = rec_ptr->hrtime;
	
}

static inline int
incr_power_freq_stats(power_freq_t *rec_ptr) 
{
	cpu_info_t *cpuinfop;
	power_info_t *powerp, *gpowerp;
	int cpu;
	
	cpu = rec_ptr->tgt_cpu;
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	powerp = GET_POWERP(cpuinfop->powerp);
	
	powerp->power_freq_cnt++;
	powerp->freq_hi = MAX(powerp->freq_hi, rec_ptr->freq);
	powerp->freq_low = powerp->freq_low ? MIN(powerp->freq_low, rec_ptr->freq) : rec_ptr->freq;

	if (global_stats) {
		gpowerp = GET_POWERP(globals->powerp);
		gpowerp->freq_hi = MAX(powerp->freq_hi, rec_ptr->freq);
		gpowerp->freq_low = gpowerp->freq_low ? MIN(gpowerp->freq_low, rec_ptr->freq) : rec_ptr->freq;
		gpowerp->power_freq_cnt++;
	}
}


int
power_start_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	power_start_t tt_rec_ptr;
	power_start_t *rec_ptr;
	
	rec_ptr = conv_power_start(a, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);	
	if (power_stats) incr_power_start_stats(rec_ptr);

	if (kitrace_flag) print_power_start_rec(rec_ptr);
}

int
power_end_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	power_end_t tt_rec_ptr;
	power_end_t *rec_ptr;
	
	rec_ptr = conv_power_end(a, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	if (power_stats) incr_power_end_stats(rec_ptr);
	if (kitrace_flag) print_power_end_rec(rec_ptr);
}

int
power_freq_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	power_freq_t tt_rec_ptr;
	power_freq_t *rec_ptr;
	
	rec_ptr = conv_power_freq(a, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	if (power_stats) incr_power_freq_stats(rec_ptr);
	if (kitrace_flag) print_power_freq_rec(rec_ptr);
}

int
cpu_freq_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	power_freq_t tt_rec_ptr;
	power_freq_t *rec_ptr;
	
	if (IS_LIKI) return 0;

	rec_ptr = conv_cpu_freq(a, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	if (power_stats) incr_power_freq_stats(rec_ptr);
	if (kitrace_flag) print_power_freq_rec(rec_ptr);
}

int
cpu_idle_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	power_start_t tt_rec_ptr;
	power_start_t *rec_ptr;
	
	if (IS_LIKI) return 0;
	
	rec_ptr = conv_cpu_idle(a, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);

	if (power_stats) {
		if (rec_ptr->state == -1ull)
			incr_power_end_stats((power_end_t *)rec_ptr);
		else
			incr_power_start_stats(rec_ptr);
	}

	if (kitrace_flag) print_power_start_rec(rec_ptr);
}
