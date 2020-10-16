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
#include "globals.h"
#include "developers.h" 
#include "kd_types.h"
#include "info.h"
#include "conv.h"
#include "hash.h"


#if 0
/* this function is not used yet */
int stack_hardclock_start = 0;

int
find_hardclock_start(uint64 ip, uint64 *stack)
{
        char *symptr;
        int i;

        if (stack_hardclock_start) return stack_hardclock_start;

        for (i=0; i < LEGACY_STACK_DEPTH; i++) {
                if (ip == stack[i]) return i;
        }

        return 0;
}
#endif

static inline int
get_cpu_state(void *arg1) {
	hardclock_t *rec_ptr = arg1;
	int preempt_cnt = rec_ptr->preempt_count;

        if (preempt_cnt == PREEMPT_USER) {
                return HC_USER;
        } else if (HARDIRQ_VAL(preempt_cnt) > 1 || SOFTIRQ_VAL(preempt_cnt)) {
                return HC_INTR;
        } else if ((rec_ptr->pid == 0)) {
                return HC_IDLE;
        } else {
                return HC_SYS;
        }
}

static inline int
collect_pc_info(hardclock_t *rec_ptr, hc_info_t *hcinfop, pid_info_t *pidp)
{
	pc_info_t *pcinfop;
	int state;
	uint64 offset;
	vtxt_preg_t *pregp = NULL;
	uint64 key = UNKNOWN_SYMIDX;
	uint64 pc;

	hcinfop->total++;
	state = get_cpu_state(rec_ptr);
	hcinfop->cpustate[state]++;

	/* printf ("collect_pc_info(): state: %d stack_depth: %d  ips: 0x%llx 0x%llx ", state, rec_ptr->stack_depth, rec_ptr->ips[0], rec_ptr->ips[1]);  */
	if (state==HC_IDLE) return 0;
	if (rec_ptr->stack_depth >= 2) {
	    pc = rec_ptr->ips[1];
	    if (rec_ptr->ips[0] == STACK_CONTEXT_USER) {	
		if (objfile_preg.elfp && (pc < 0x10000000)) {
			if (symlookup(&objfile_preg, pc, &offset)) {
				key = pc - offset;
			}
		} else if (pidp) {
			/* if multi-threaded, use TGID */
			if (pidp->PID != pidp->tgid) pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);

			if (pregp = find_vtext_preg(pidp, pc)) {
				if (symlookup(pregp, pc, &offset)) {
					key = pc - offset;
				} else if (maplookup(pidp->mapinfop, pc, &offset)) {
					pregp = pidp->mapinfop;
					key = pc - offset;
				}
			} else if (maplookup(pidp->mapinfop, pc, &offset)) {
				pregp = pidp->mapinfop;
				key = pc - offset;
			}
		}
	    } else {
	 	key = convert_pc_to_key(pc);
	    }
	}

	pcinfop = GET_PCINFOP(&hcinfop->pc_hash, key);
	pcinfop->state = state;
	pcinfop->count++;
	pcinfop->pregp = pregp;
}

static inline int
collect_hc_stktrc(hardclock_t *rec_ptr, hc_info_t *hcinfop, pid_info_t *pidp)
{
	stktrc_info_t *stktrcp;
	uint64 key;
	uint64 stktrc[LEGACY_STACK_DEPTH];
	uint64 cnt;
	int len, i;
	int state;

	if (cluster_flag) return 0;		/* don't collect stack traces for cluster-wide reports */
	if (rec_ptr->stack_depth == 0) return 0;

	state = get_cpu_state(rec_ptr);

	if (state == HC_IDLE) return 0;

	/* Only collect USER stack traces if we have potential mappings avaiable and
	 * there is more then one function in the trace 
	 */
	if (rec_ptr->ips[0] == STACK_CONTEXT_USER) {
		if (rec_ptr->stack_depth <= 2) return 0;
		if (pidp == NULL) return 0;
	    	if (pidp && (pidp->vtxt_pregp == NULL)) return 0;
	}

	if (pidp) {
		cnt = save_entire_stack(&stktrc[0], &rec_ptr->ips[1], MIN(rec_ptr->stack_depth-1, LEGACY_STACK_DEPTH));
	} else {
		cnt = save_kernel_stack(&stktrc[0], &rec_ptr->ips[1], MIN(rec_ptr->stack_depth-1, LEGACY_STACK_DEPTH));
	}
		
	if (cnt == 0) return 0;

	for (i = 0; i < cnt; i++) {
		stktrc[i] = convert_pc_to_key(stktrc[i]);
	}

	len = cnt * sizeof(uint64);
	key = doobsHash(&stktrc[0], len, 0xff);
	stktrcp = (stktrc_info_t *)find_add_stkhash_entry((stklle_t ***)&hcinfop->hc_stktrc_hash,
                                                STKTRC_HSIZE,
                                                STKTRC_HASH(key),
                                                sizeof(stktrc_info_t),
                                                &stktrc[0],
                                                cnt);
	stktrcp->pidp = pidp;
        stktrcp->cnt++;
        stktrcp->stklen = cnt;
	stktrcp->state = state;
}

static inline void 
hc_update_sched_state(sched_info_t *schedp, int state, uint64 cur_time)
{
	if (schedp->sched_stats.state==UNKNOWN) {
		schedp->sched_stats.last_cur_time = cur_time;
	}

	if ((schedp->sched_stats.state==RUNNING) || (schedp->sched_stats.state==UNKNOWN)) {
		switch (state) {
			case HC_USER: schedp->sched_stats.state=USER | RUNNING; break;
			case HC_SYS: schedp->sched_stats.state=SYS | RUNNING; break;
			case HC_IDLE: schedp->sched_stats.state=IDLE; break;
			default: break;
		}	
	}
}

static inline int
hc_bypid_hardclock(hardclock_t *rec_ptr, pid_info_t *pidp)
{
	pid_t pid;
	int state;
	hc_info_t *hcinfop;
	sched_info_t *schedp;


	pid = rec_ptr->pid;
	state = get_cpu_state(rec_ptr);

	if (pid != 0) {
		hcinfop = GET_HCINFOP(pidp->hcinfop);
		/* do not collect HC info for IDLE CPU) */
		collect_pc_info(rec_ptr, hcinfop, pidp);
		collect_hc_stktrc(rec_ptr, hcinfop, pidp);
	}

	if (sched_flag) {
		schedp = find_sched_info(pidp);
		hc_update_sched_state(schedp, state, rec_ptr->hrtime);
	}

	return 0;
}

static inline int
hc_bycpu_hardclock(hardclock_t *rec_ptr)
{
	int cpu, state;
	cpu_info_t *cpuinfop;
	hc_info_t *hcinfop;
	sched_info_t *schedp;

	cpu = rec_ptr->cpu;
	state = get_cpu_state(rec_ptr);

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu); 
	hcinfop = GET_HCINFOP(cpuinfop->hcinfop); 
	collect_pc_info(rec_ptr, hcinfop, NULL);
	collect_hc_stktrc(rec_ptr, hcinfop, NULL);

	if (sched_flag) {
		schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
		hc_update_sched_state(schedp, state, rec_ptr->hrtime);
	}

	return 0;
}

static inline int
hc_glob_hardclock(hardclock_t *rec_ptr)
{
	hc_info_t *hcinfop;
	sched_info_t *schedp;
	int state;

	state = get_cpu_state(rec_ptr);
	hcinfop = GET_HCINFOP(globals->hcinfop);
	collect_pc_info(rec_ptr, hcinfop, NULL);
	collect_hc_stktrc(rec_ptr, hcinfop, NULL);
}

static inline int
print_hardclock_rec(void *a)
{
        hardclock_t *rec_ptr = (hardclock_t *)a;
        int state;

        PRINT_COMMON_FIELDS(rec_ptr);
        PRINT_EVENT(rec_ptr->id);
#if 0
	if (rec_ptr->preempt_count == PREEMPT_USER) {
		printf ("%chardirq=%d%csoftirq=%d%cpreempt=%d", fsep, 0, fsep, 0, fsep, 0);
	} else {
		printf ("%chardirq=%d%csoftirq=%d%cpreempt=%d", 
		fsep, HARDIRQ_VAL(rec_ptr->preempt_count),
		fsep, SOFTIRQ_VAL(rec_ptr->preempt_count),
		fsep, PREEMPT_VAL(rec_ptr->preempt_count));
	}
#endif

        state = get_cpu_state(rec_ptr);
        printf ("%cstate=%s", fsep, cpustate_name_index[state]);

        /* if ((state != HC_IDLE) && (state != HC_INTR) && (rec_ptr->stack_depth)) { */
        if ((state != HC_IDLE) && (rec_ptr->stack_depth)) {
                print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, 0, rec_ptr->pid);
                /* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth);  */
        }

        printf ("\n");
        return 0;
}

int 
hardclock_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	char tt_rec_ptr[MAX_REC_LEN];
	hardclock_t *rec_ptr;
	pid_info_t *pidp;

	rec_ptr = conv_hardclock(trcinfop, &tt_rec_ptr);

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	}

	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);
	if (global_stats) hc_glob_hardclock(rec_ptr);
	if (percpu_stats) hc_bycpu_hardclock(rec_ptr);
	if (perpid_stats) hc_bypid_hardclock(rec_ptr, pidp);

	if (kitrace_flag) print_hardclock_rec(rec_ptr);
	return 0 ;
}
