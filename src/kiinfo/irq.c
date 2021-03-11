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
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "sort.h"
#include "hash.h"
#include "conv.h"

static inline void
update_perirq_stats(irq_info_t *irqinfop, int irq, uint64 delta, int irqtype)
{
	irq_entry_t *irqentryp;

	irqinfop->count++;
	irqinfop->total_time += delta;

	irqentryp = GET_IRQENTRYP(&irqinfop->irq_entry_hash, irq);
	irqentryp->count++;
	irqentryp->total_time += delta;
	return;
}

int
update_softirq_times(irq_info_t *irqinfop, int irq, uint64 delta, int irqtype)
{
	irq_entry_t *irqentryp;
	
	irqinfop->total_time += delta;
	irqentryp = GET_IRQENTRYP(&irqinfop->irq_entry_hash, irq);
	irqentryp->total_time += delta;
	return 0;
}

void
irq_entry_update_stats(uint64 hrtime, int cpu, int pid, int irq, int irqtype)
{
	cpu_info_t *cpuinfop;
	sched_info_t *schedp;
	sched_stats_t *statp;
	irq_info_t *irqinfop;
	pid_info_t *pidp;
	int new_state, old_state;
	uint64 delta;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
	statp = &schedp->sched_stats;
	
	old_state = statp->state;
	new_state = old_state | irqtype;
	statp->state = new_state;
	delta = update_sched_time(statp, hrtime);
	update_sched_state(statp, old_state, statp->state, delta);

	if (irqtype==SOFTIRQ) {
		cpuinfop->last_softirq_vec = irq;
		cpuinfop->last_softirq_time = hrtime; 
	} else if (cpuinfop->last_softirq_vec) {
		/* upate softirq time if we are entering a hardirq
		 * while in a softirq context
		 */
		if (global_stats && perirq_stats) {
			irqinfop = GET_ADD_IRQINFOP(&globals->softirqp);
			update_softirq_times(irqinfop, cpuinfop->last_softirq_vec, delta, irqtype);
		}

		if (perirq_stats) {
			irqinfop = GET_ADD_IRQINFOP(&cpuinfop->softirqp);
			update_softirq_times(irqinfop, cpuinfop->last_softirq_vec, delta, irqtype);
		}
	}

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, pid);
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		old_state = statp->state;
		new_state = statp->state = old_state | irqtype;
		delta = update_sched_time(statp, hrtime);
		update_sched_state(statp, old_state, statp->state, delta);	
	}

	return;
}

uint64
irq_exit_update_stats(uint64 hrtime, int cpu, int pid, int irq, int irqtype)
{
	cpu_info_t *cpuinfop;
	sched_info_t *schedp;
	sched_stats_t *statp;
	pid_info_t *pidp;
	irq_info_t **irqp;
	irq_info_t *irqinfop;
	irq_entry_t *irqentryp;
	int new_state, old_state;
	uint64 delta;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	schedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
	statp = &schedp->sched_stats;
	
	old_state = statp->state;

	if ((old_state & irqtype) == 0) {
		/* we are not in the expected state for an irq exit */
		/* assume we missed a buffer and ignore this one */
		cpuinfop->last_softirq_vec = 0;
		cpuinfop->last_softirq_time = 0;
		return 0;		
	}

	new_state = old_state & ~irqtype;
	statp->state = new_state;
	delta = update_sched_time(statp, hrtime);
	update_sched_state(statp, old_state, statp->state, delta);
	if (irqtype == HARDIRQ) {
		statp->C_hardirq_cnt++;
	} else {
		statp->C_softirq_cnt++;
	}

	if (global_stats && perirq_stats) {
		irqp = ((irqtype == HARDIRQ) ? &globals->irqp : &globals->softirqp);
		irqinfop = GET_ADD_IRQINFOP(irqp);
		update_perirq_stats(irqinfop, irq, delta, irqtype);
	}

	if (perirq_stats) {
		irqp = ((irqtype == HARDIRQ) ? &cpuinfop->irqp : &cpuinfop->softirqp);
		irqinfop = GET_ADD_IRQINFOP(irqp);
		update_perirq_stats(irqinfop, irq, delta, irqtype);
	}
	
	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, pid);
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		old_state = statp->state;
		new_state = statp->state = old_state & ~irqtype;
		delta = update_sched_time(statp, hrtime);
		update_sched_state(statp, old_state, statp->state, delta);	
		irqtype == HARDIRQ ? statp->C_hardirq_cnt++ : statp->C_softirq_cnt++;
	}
	
	return delta;
}


static inline int
print_irq_handler_entry_rec(void *a)
{
	irq_handler_entry_t *rec_ptr = (irq_handler_entry_t *)a;
	char irqname[IRQ_NAME_LEN+4];

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	strncpy(&irqname[0], rec_ptr->name, IRQ_NAME_LEN);
	irqname[IRQ_NAME_LEN] = 0;
	
	printf ("%cirq=%d", fsep, rec_ptr->irq);
	printf ("%cname=%-16s", fsep, irqname);
	printf ("\n");

	return 0;
}

static inline int
print_irq_handler_exit_rec(void *a, uint64 irqtm)
{
	irq_handler_exit_t *rec_ptr = (irq_handler_exit_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	printf ("%cirq=%d%cret=%s", 
		fsep, rec_ptr->irq,
		fsep, rec_ptr->ret ? "handled" : "unhandled");
	if (irqtm) printf ("%cirqtm=%11.6f", fsep, SECS(irqtm));
	printf ("\n");

	return 0;
}
	

static inline int
print_softirq_entry_rec(void *a)
{
	softirq_entry_t *rec_ptr = (softirq_entry_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	printf ("%cvec=%d%caction=%s\n", 
		fsep, rec_ptr->vec, 
		fsep, softirq_name[rec_ptr->vec]);

	return 0;
}

static inline int
print_softirq_exit_rec(void *a, uint64 irqtm)
{
	softirq_exit_t *rec_ptr = (softirq_exit_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	printf ("%cvec=%d%caction=%s", 
		fsep, rec_ptr->vec, 
		fsep, softirq_name[rec_ptr->vec]);

	if (irqtm) printf ("%cirqtm=%11.6f", fsep, SECS(irqtm));
	printf ("\n");

	return 0;
}
	
int
irq_handler_entry_func(void *a, void *v)
{
	trace_info_t *trcinfo = (trace_info_t *)a;
	irq_handler_entry_t tt_rec_ptr;
	irq_handler_entry_t *rec_ptr;
	irq_name_t *irqnamep;
	char irqname[IRQ_NAME_LEN+4];
	int irq;
	
	if (debug) printf ("irq_handler_entry_func()\n");
	
	rec_ptr = conv_irq_handler_entry(a, &tt_rec_ptr);

	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	if (perirq_stats) {	
		irq = rec_ptr->irq;

		irqnamep = GET_IRQNAMEP(&globals->irqname_hash, irq);
        	if (irqnamep->name == NULL) {
			strncpy(&irqname[0], rec_ptr->name, IRQ_NAME_LEN);
			irqname[IRQ_NAME_LEN] = 0;

                	add_command(&irqnamep->name, irqname);
        	}

	}

	irq_entry_update_stats(rec_ptr->hrtime, rec_ptr->cpu, rec_ptr->pid, rec_ptr->irq, HARDIRQ);

	if (kitrace_flag) print_irq_handler_entry_rec(rec_ptr);
	return 0;
}

int
irq_handler_exit_func(void *a, void *v)
{
	trace_info_t *trcinfo = (trace_info_t *)a;
	irq_handler_exit_t tt_rec_ptr;
	irq_handler_exit_t *rec_ptr;
	uint64 delta;

	if (debug) printf ("irq_handler_exit_func()\n"); 
	rec_ptr = conv_irq_handler_exit(a, &tt_rec_ptr);

	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	delta = irq_exit_update_stats(rec_ptr->hrtime, rec_ptr->cpu, rec_ptr->pid, rec_ptr->irq, HARDIRQ);
	if (kitrace_flag) print_irq_handler_exit_rec(rec_ptr, delta);

	return 0;
}

int
softirq_entry_func(void *a, void *v)
{
	trace_info_t *trcinfo = (trace_info_t *)a;
	softirq_entry_t tt_rec_ptr;
	softirq_entry_t *rec_ptr;
	int irq;
	
	if (debug) printf ("softirq_entry_func()\n");
	
	rec_ptr = conv_softirq_entry(a, &tt_rec_ptr);

	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	irq_entry_update_stats(rec_ptr->hrtime, rec_ptr->cpu, rec_ptr->pid, rec_ptr->vec, SOFTIRQ);
	if (kitrace_flag) print_softirq_entry_rec(rec_ptr);

	return 0;
}

int
softirq_exit_func(void *a, void *v)
{
	trace_info_t *trcinfo = (trace_info_t *)a;
	softirq_exit_t tt_rec_ptr;
	softirq_exit_t *rec_ptr;
	uint64 delta;
	cpu_info_t *cpuinfop;

	rec_ptr = conv_softirq_exit(a, &tt_rec_ptr);
	cpuinfop = GET_CPUP(&globals->cpu_hash, rec_ptr->cpu);

	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
	delta = irq_exit_update_stats(rec_ptr->hrtime, rec_ptr->cpu, rec_ptr->pid, rec_ptr->vec, SOFTIRQ);
	if (kitrace_flag) {
		print_softirq_exit_rec(rec_ptr, cpuinfop->last_softirq_time ? rec_ptr->hrtime - cpuinfop->last_softirq_time : delta);
	}

	cpuinfop->last_softirq_vec = 0;
	cpuinfop->last_softirq_time = 0;

	return 0;
}

int
softirq_raise_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
        softirq_exit_t tt_rec_ptr;
        softirq_exit_t *rec_ptr;

        if (debug) printf ("trace_softirq_raise_func()\n");

        rec_ptr = conv_softirq_raise(trcinfop, &tt_rec_ptr);
	if (pertrc_stats) incr_trc_stats(rec_ptr, NULL);
        if (kitrace_flag) print_softirq_exit_rec(rec_ptr, 0);
}
