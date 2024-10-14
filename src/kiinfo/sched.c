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
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kdev_t.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "sort.h"
#include "hash.h"
#include "html.h"
#include "futex.h"
#include "conv.h"
#include "oracle.h"
#include <ncurses.h>
#include <curses.h>

static uint64 rq_times[RUNQ_NBUCKETS-1]={
	5, 10, 20, 50, 100, 500, 1000, 2000, 10000, 20000};

#define LDOM 1
int ldom_cnt = 0;
int cpu_cnt = 0;

void *
find_sched_info(void *arg1)
{
	pid_info_t *pidp = arg1;
	sched_info_t *schedp;
	
	if (pidp->schedp==NULL) {
		if ((pidp->schedp = malloc(sizeof(sched_info_t))) == NULL) {
			FATAL(errno, "malloc failed", NULL, -1);
		}

		MALLOC_LOG(pidp->schedp, sizeof(sched_info_t));
		bzero(pidp->schedp, sizeof(sched_info_t));
		schedp = pidp->schedp;
		schedp->cpu = -1;
	}
	
	return (void *)pidp->schedp;
}

static inline unsigned long *
get_msr_ptr(sched_switch_t *rec_ptr) 
{
	unsigned long *msrptr;
        int recsz;
	
	recsz = sizeof(sched_switch_t) + (rec_ptr->stack_depth * sizeof(unsigned long));
	if ((rec_ptr->reclen - recsz) == (sizeof(unsigned long) * MSR_NREGS)) {
		msrptr = (unsigned long *)((char *)rec_ptr + recsz);
	} else { 
		msrptr = NULL;
	}
	return msrptr;
}

static inline int
update_swoff_msr_stats(sched_switch_t *rec_ptr, sched_stats_t *statp)
{
	unsigned long *msrptr;
	unsigned long *last_msrptr = (unsigned long *)&statp->msr_last[0];
	unsigned long *total_msrptr = (unsigned long *)&statp->msr_total[0];
	int i;

	/* if this is for a CPU, don't erase the SMI_Count */
	if (msrptr = get_msr_ptr(rec_ptr)) {
		if (last_msrptr[RET_INSTR]) {
			for (i=0; i < MSR_NREGS; i++) {
				total_msrptr[i] += msrptr[i] - last_msrptr[i];
			}
		}
	
		for (i=0; i < MSR_NREGS; i++) {
			last_msrptr[i] = 0;
		}
	}
}	

static inline int
update_swon_msr_stats(sched_switch_t *rec_ptr, sched_stats_t *statp)
{
	unsigned long *msrptr;
	unsigned long *last_msrptr = (unsigned long *)&statp->msr_last[0];
	unsigned long *total_msrptr = (unsigned long *)&statp->msr_total[0];
	int i;

	if (msrptr = get_msr_ptr(rec_ptr)) {
		SET(MSR_FLAG);
		for (i=0; i < MSR_NREGS; i++) {
			last_msrptr[i] = msrptr[i];
		}
	}
}	

static inline int
update_cpu_msr_stats(sched_switch_t *rec_ptr, sched_stats_t *statp)
{
	unsigned long *msrptr;
	unsigned long *last_msrptr = (unsigned long *)&statp->msr_last[0];
	unsigned long *total_msrptr = (unsigned long *)&statp->msr_total[0];
	int i;

	if (msrptr = get_msr_ptr(rec_ptr)) {
		if (last_msrptr[RET_INSTR] == 0) {
			/* for SMIs, the total is actually the initial */
                        total_msrptr[SMI_CNT] = msrptr[SMI_CNT];
		} else {
			for (i=0; i < MSR_NREGS-1; i++) {
				total_msrptr[i]+= msrptr[i] - last_msrptr[i];
			}
		}

		for (i=0; i < MSR_NREGS; i++) {
			last_msrptr[i] = msrptr[i];
		}
	}
}	

static inline int
futex_update_wakeup_stats(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	pid_info_t *tpidp = (pid_info_t *)arg2;
	pid_futex_info_t	*pid_futex_infop;
	gbl_futex_info_t	*gbl_futex_infop;
	futex_dup_t *fudupp;
	futex_reque_t *freqp;
	uint64 uaddr1,wuaddr1,op;
	int tgid = 0;

	if ((is_alive) && (tpidp->tgid == 0)) tpidp->tgid = get_status_int(tpidp->PID, "Tgid:");

	uaddr1 =  tpidp->last_syscall_args[0];
	wuaddr1 =  pidp->last_syscall_args[0];
	op = tpidp->last_syscall_args[1];
	if (op = FUTEX_PRIVATE_FLAG) tgid = tpidp->tgid;

	pid_futex_infop = GET_FUTEXP(&tpidp->futex_hash,FUTEX_KEY(tgid, uaddr1));
	pid_futex_infop->last_waker = pidp->PID;
	pid_futex_infop->last_waker_uaddr1 = pidp->last_syscall_args[0];

	if (global_stats && (tpidp->last_syscall_id == pidp->last_syscall_id) && (uaddr1 != wuaddr1)) {
		gbl_futex_infop = GET_GFUTEXP(&globals->futex_hash,FUTEX_KEY(tgid, uaddr1));
		/* either a requeued wakeup or two addrs mapped to the same futex */
		if (gbl_futex_infop->uaddr2_hash) {
			if (freqp = FIND_REQP(gbl_futex_infop->uaddr2_hash,FUTEX_KEY(tgid,wuaddr1))) {
				fudupp = GET_FUDUPP(&gbl_futex_infop->dup_hash,FUTEX_KEY(tgid, wuaddr1));
				fudupp->cnt++;
				fudupp->addr =  wuaddr1;
			}
		}
	}
	return 0;
}

uint64
update_sched_time(void *arg, uint64 curtime)
{
	sched_stats_t *statp = arg;
	uint64 delta;

	/* fprintf (stderr, "update_sched_time() statp: %p  curtime: %lld  last_cur_time: %lld\n", statp, curtime, statp->last_cur_time);  */

	if (statp->state & ZOMBIE) {
		statp->last_cur_time = curtime;
		return 0;
	}

	if (statp->last_cur_time) {
		delta = curtime - statp->last_cur_time;
	} else {
		delta = curtime - (IS_WINKI ? CONVERT_WIN_TIME(winki_start_time) : FILTER_START_TIME);
	}
	
	statp->last_cur_time = curtime;
	return delta;
}

void 
update_sched_prio(void *arg, int pri) 
{
	sched_info_t *schedp = arg;
	schedp->pri_high = MAX(schedp->pri_high, pri);
	if (schedp->pri_low == 0) {
		schedp->pri_low = pri;	
	} else {
		schedp->pri_low = MIN (schedp->pri_low, pri);
	}
}

void 
update_sched_cpu(void *arg, int cpu) 
{
	sched_info_t *schedp = arg;
	cpu_info_t *cpuinfop1, *cpuinfop2;

	if ((schedp->cpu != -1) && (schedp->cpu != cpu)) {
		cpuinfop1 = GET_CPUP(&globals->cpu_hash, schedp->cpu);
		cpuinfop2 = GET_CPUP(&globals->cpu_hash, cpu);

		schedp->cpu_migrations++;
		if (cpuinfop1->ldom != cpuinfop2->ldom) {
			schedp->ldom_migrations++;
		}
	}

	schedp->cpu = cpu;
}

void 
update_sched_state(void *arg, int old_state, int new_state, uint64 delta)
{
	sched_stats_t *statp = arg;

	/* if (debug) {
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - run: %12.9f sys: %12.9f user: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_run_time), SECS(statp->T_sys_time), SECS(statp->T_user_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - sleep: %12.9f runq: %12.9f idle: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_sleep_time), SECS(statp->T_runq_time), SECS(statp->T_idle_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - hirq-s %12.9f hirq-u: %12.9f hirq-i: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_hardirq_sys_time), SECS(statp->T_hardirq_user_time), SECS(statp->T_hardirq_idle_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - sirq-s %12.9f sirq-u: %12.9f sirq-i: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_softirq_user_time), SECS(statp->T_softirq_user_time), SECS(statp->T_softirq_user_time)); 
	}
	*/

	if (old_state & RUNNING) {
		statp->T_run_time += delta;
		if ((old_state & USER) && (old_state & HARDIRQ)) {
			statp->T_hardirq_user_time += delta;
		} else if ((old_state & USER) && (old_state & SOFTIRQ)) {
			statp->T_softirq_user_time += delta;
		} else if (old_state & USER) {
			statp->T_user_time += delta;
		} else if ((old_state & SYS) && (old_state & HARDIRQ)) {
			statp->T_hardirq_sys_time += delta;
		} else if ((old_state & SYS) && (old_state & SOFTIRQ)) {
			statp->T_softirq_sys_time += delta;
		} else if (old_state & SYS) {
			statp->T_sys_time += delta;
		} else if (old_state & HARDIRQ) {
			/* assume process was running in the kernel? */
			statp->T_hardirq_sys_time += delta;
		} else if (old_state & SOFTIRQ) {
			/* assume process was running in the kernel? */
			statp->T_softirq_user_time += delta;
		} else {
			/* assume process was running in the kernel? */
			statp->T_sys_time += delta;
		}
	} else if (old_state & RUNQ) {
		statp->T_runq_time += delta;
		statp->C_runq_cnt++;
		if (old_state & IDLE) {
			statp->C_runq_idle_cnt++;
			statp->T_runq_idle_time += delta;
		} else {
                        if (old_state & USER) {
				statp->C_runq_usrpri_cnt++;
                        	statp->T_runq_usrpri_time += delta;
			} 
			statp->C_runq_pri_cnt++;
			statp->T_runq_pri_time += delta;
		}
	} else if (old_state & SWTCH) {
		statp->T_sleep_time += delta;
	} else if (old_state & IDLE) {
		if (old_state & HARDIRQ) {
			statp->T_hardirq_idle_time += delta;
		} else if (old_state & SOFTIRQ) {
			statp->T_softirq_idle_time += delta;
		} else {
			statp->T_idle_time += delta;
		}
	} else {
		/* if the oldstate is UNKNOWN, we just dont account for it */
	}

	statp->state = new_state;
	/* if (debug) {
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - run: %12.9f sys: %12.9f user: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_run_time), SECS(statp->T_sys_time), SECS(statp->T_user_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - sleep: %12.9f runq: %12.9f idle: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_sleep_time), SECS(statp->T_runq_time), SECS(statp->T_idle_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - hirq-s %12.9f hirq-u: %12.9f hirq-i: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_hardirq_sys_time), SECS(statp->T_hardirq_user_time), SECS(statp->T_hardirq_idle_time)); 
	printf ("- statp: %p  old_state 0x%x, new_state 0x%x, delta %12.9f - sirq-s %12.9f sirq-u: %12.9f sirq-i: %12.9f\n", statp, old_state, new_state, SECS(delta), SECS(statp->T_softirq_user_time), SECS(statp->T_softirq_user_time), SECS(statp->T_softirq_user_time)); 
	}
	*/

}

void 
update_cpu_times(uint64 lasttime)
{
        int i;
        cpu_info_t *cpuinfop;
        sched_info_t *schedp;
        sched_stats_t *statp;
        uint64 delta;

        for (i = 0; i < MAXCPUS; i++) {
                if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
                        schedp = cpuinfop->schedp;
                        if (schedp) {
                                statp = &schedp->sched_stats;
                                delta = update_sched_time(statp, lasttime);
                                update_sched_state(statp, statp->state, statp->state, delta);
                        }
                }
        }
}

int 
update_pid_sched_stats(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	sched_info_t *schedp = pidp->schedp;
	sched_stats_t *statp;
	pid_info_t *tgidp;
	uint64 delta;

	if (pidp->tgid) {
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		if ((pidp->cmd == NULL) && (tgidp->cmd)) {
			add_command(&pidp->cmd, tgidp->cmd);
		}
		
		if ((pidp->hcmd == NULL) && (tgidp->hcmd)) {
			add_command(&pidp->cmd, tgidp->cmd);
		}
	}

	if (schedp) {
		statp = &schedp->sched_stats;
		delta = update_sched_time(statp, end_time);
		update_sched_state(statp, statp->state, statp->state, delta);
	}
	return 0;
}

void
update_perpid_sched_stats()
{
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))update_pid_sched_stats,
                           NULL, 0, NULL);
	return;
}



void
update_slp_info(pid_info_t *pidp, void *arg2, uint64 delta, uint64 wpid)
{
        slp_info_t ***slp_hash = arg2;
        slp_info_t *slpinfop;
        uint64          key;

        if (pidp->last_stack_depth == 0) return;
	if (key == STACK_CONTEXT_USER) return;

        key = convert_pc_to_key(STACK_CONTEXT_KERNEL, pidp, pidp->last_stktrc[0]);

	/* this means no kernel stack was collected */

        slpinfop = GET_SLPINFOP(slp_hash, key);
        slpinfop->count++;
        slpinfop->sleep_time += delta;
        slpinfop->max_time = MAX(slpinfop->max_time, delta);

	if (wpid && (coop_detail_enabled || vis)) {
		/* POK - adding a list of wakers to the syscall detail info sleep_function element */
        	scd_waker_info_t *scd_wpidp = GET_SCDWINFOP(&slpinfop->scd_wpid_hash, wpid);
        	scd_wpidp->count++;
        	scd_wpidp->sleep_time += delta;
        	scd_wpidp->max_time = MAX(scd_wpidp->max_time, delta);
	}
}

void
update_stktrc_info(uint64 last_stktrc[], uint64 stack_depth, void ***arg2, uint64 delta, void *pidp)
{
	stktrc_info_t ***stktrc_hash = (stktrc_info_t ***)arg2;
	stktrc_info_t *stktrcp;
	uint64		key;
	uint64 stktrc[LEGACY_STACK_DEPTH];
	uint64		mode = STACK_CONTEXT_KERNEL;
	int cnt, i, len;

	if (cluster_flag) return;   /* don't collect stack traces for cluster-wide reporting */
	if (stack_depth == 0) return;

	for (i = 0; i < stack_depth && i < LEGACY_STACK_DEPTH;  i++) {
		if ((pidp == NULL) && (last_stktrc[i] == STACK_CONTEXT_USER)) {
			break;
		}
		if (last_stktrc[i] == STACK_CONTEXT_USER) mode = STACK_CONTEXT_USER;
		stktrc[i] = convert_pc_to_key(mode, pidp, last_stktrc[i]);
	}

	len = i * sizeof(uint64);
	key = doobsHash(&stktrc[0], len, 0xff);
	stktrcp = (stktrc_info_t *)find_add_stkhash_entry((stklle_t ***)stktrc_hash, 
						STKTRC_HSIZE,	
						STKTRC_HASH(key),
						sizeof(stktrc_info_t),
						&stktrc[0],
						i);

	stktrcp->pidp = pidp;
	stktrcp->cnt++;
	stktrcp->slptime += delta ;
	stktrcp->stklen = i;
}

void
incr_setrq_stats (setrq_info_t ***setrq_hashp, uint64 pid, uint64 old_state, uint64 delta) 
{
	setrq_info_t *setrq_infop;

	setrq_infop = GET_SETRQP(setrq_hashp, pid);
	setrq_infop->cnt++;
	if (old_state == UNKNOWN) {
		setrq_infop->unknown_time +=delta;
		return;
	} else if (!(old_state & SWTCH)) {
		return;
	} else {
		setrq_infop->sleep_time+=delta;
	}

	return;
}

/*
** We follow two lists, recording the sleeper/waker sclass, args, slpfuncs(of sleepers only).
** The setrq_src_list of the SLEEPER is list of tasks that have woken him up.  The data structures
** are chained together as :
**      setrq_src_list -> wakers_scall -> wakers_scall_arg0 -> sleepers_scall -> sleeper_scall_arg0
**              -> sleeper_arg0_sleep_function
**
** The setrq_tgt_list of the WAKER is a list of tasks that We have woken up.  The data structures
** are chained together as :
**      setrq_tgt_list -> sleepers_scall -> sleeper_scall_arg0 -> sleeper_arg0_sleep_function
**              -> wakers_scall -> wakers_scall_arg0
**
** For each element in the data chain we have a count and a tally of sleep_time associated.  The
** reporting format can be count based or sleep time based.
**
**
**/

void
update_coop_stats(sched_info_t *w_schedp, sched_info_t *s_schedp, pid_info_t *pidp, pid_info_t *tpidp, uint64 delta, int old_state, int which)
{
    uint64 w_pid;
    uint64 s_pid;
    uint64 start;
    uint64 syscallno;
    coop_scall_t *sw_scallp;
    coop_scall_t *ss_scallp;
    coop_scall_t *ws_scallp;
    coop_scall_t *ww_scallp;
   
    if (!(old_state & SWTCH))  return;
    if (!coop_detail_enabled) return;

    if (globals->nsyms==0) return;

    w_pid = pidp->lle.key;
    s_pid = tpidp->lle.key;

    start = find_switch_start(&tpidp->last_stktrc[0], tpidp->last_stack_depth);


        /* We can only deal with task states where waker & sleeper are in a known
        ** syscall+arg0.  Partial interactions we catch at the begining of traces
        ** or after missed-buffer events we have to ignore. We can take the sleep
        ** time and dump it into an 'unknown' bucket for now.
        */

        /* We record the information for tasks that woke me up...
        ** If the setrq_src_hash list or 'which' = SLEEPER
        */

    if (which == SLEEPER) {
        setrq_info_t *slpr_setrqp = GET_SETRQP(&s_schedp->setrq_src_hash, w_pid);

	syscallno = pidp->last_syscall_time ? SYSCALL_NO(pidp->last_syscall_id) : SYSCALL_NO(DUMMY_SYSCALL);
        sw_scallp = GET_COOP_SCALLP(&slpr_setrqp->coop_scall_hash, syscallno);
        sw_scallp->cnt++;
        sw_scallp->sleep_time+=delta;

        coop_scall_arg_t *sw_argp = GET_COOP_SCALL_ARGSP(&sw_scallp->coop_args_hash, pidp->last_syscall_args[0]);
        sw_argp->cnt++;
        sw_argp->sleep_time+=delta;

	syscallno = tpidp->last_syscall_time ? SYSCALL_NO(tpidp->last_syscall_id) : SYSCALL_NO(DUMMY_SYSCALL);
        ss_scallp = GET_COOP_SCALLP(&sw_argp->coop_sleeper_scall_hash, syscallno);
        ss_scallp->cnt++;
        ss_scallp->sleep_time+=delta;

        coop_scall_arg_t *ss_argp = GET_COOP_SCALL_ARGSP(&ss_scallp->coop_args_hash, tpidp->last_syscall_args[0]);
        ss_argp->cnt++;
        ss_argp->sleep_time+=delta;

        coop_slpfunc_t *ss_slpfuncp = GET_COOP_SLPFUNCP(&ss_argp->coop_slpfunc_hash, tpidp->last_stktrc[start]);
        ss_slpfuncp->cnt++;
        ss_slpfuncp->sleep_time+=delta;

    } else {
             
        /* This is the WAKER's setrq stats so we record the information for the tasks
        ** that we are waking... the setrq_tgt_hash list track tasks that we wake.
        */

        setrq_info_t *waker_setrqp = GET_SETRQP(&w_schedp->setrq_tgt_hash, s_pid);

	if (tpidp->cmd && (strcmp("kiinfo", tpidp->cmd) != 0))
		w_schedp->sched_stats.T_total_waited4_time += delta;

        if (!coop_detail_enabled) return;

	syscallno = tpidp->last_syscall_time ? SYSCALL_NO(tpidp->last_syscall_id) : SYSCALL_NO(DUMMY_SYSCALL);
        ws_scallp = GET_COOP_SCALLP(&waker_setrqp->coop_scall_hash, syscallno);
        ws_scallp->cnt++;
        ws_scallp->sleep_time+=delta;

        coop_scall_arg_t *ws_argp = GET_COOP_SCALL_ARGSP(&ws_scallp->coop_args_hash, tpidp->last_syscall_args[0]);
        ws_argp->cnt++;
        ws_argp->sleep_time+=delta;

        coop_slpfunc_t *ws_slpfuncp = GET_COOP_SLPFUNCP(&ws_argp->coop_slpfunc_hash, tpidp->last_stktrc[start]);
        ws_slpfuncp->cnt++;
        ws_slpfuncp->sleep_time+=delta;

	syscallno = pidp->last_syscall_time ? SYSCALL_NO(pidp->last_syscall_id) : SYSCALL_NO(DUMMY_SYSCALL);
        ww_scallp = GET_COOP_SCALLP(&ws_slpfuncp->coop_waker_sc_hash, syscallno);
        ww_scallp->cnt++;
        ww_scallp->sleep_time+=delta;

        coop_scall_arg_t *ww_argp = GET_COOP_SCALL_ARGSP(&ww_scallp->coop_args_hash, pidp->last_syscall_args[0]);
        ww_argp->cnt++;
        ww_argp->sleep_time+=delta;
    }
    return;
}



void
incr_runq_migr(runq_info_t *rqinfop, int migrated, int ldom_migrated)
{
        if (!migrated) return;

        if (migrated == 1) rqinfop->migrations++;
        if (ldom_migrated == 1) rqinfop->ldom_migrations_in++;
        if (ldom_migrated == 3) rqinfop->ldom_migrations_out++;
}

void
incr_runq_stats(runq_info_t *rqinfop, int old_state, uint64 time, int migrated, int ldom_migrated)
{
        int     i;

        if (old_state == UNKNOWN) return;

        if (time > rq_times[RUNQ_NBUCKETS-2]) {
                rqinfop->rqhist[RUNQ_NBUCKETS-1]++;
        }

        for (i=0; i < RUNQ_NBUCKETS-1; i++) {
                if (time < rq_times[i]) {
                        rqinfop->rqhist[i]++;
                        break;
                } else {
                        continue;
                }
        }

        rqinfop->total_time += time;
        rqinfop->cnt++;
        if (time > rqinfop->max_time)  rqinfop->max_time = time;
        if (time > rqinfop->max_time_int)  rqinfop->max_time_int = time;
        if ( old_state == SWTCH )  rqinfop->idle_handoff++;

	incr_runq_migr(rqinfop, migrated+2, ldom_migrated); 
}

void
sched_rqhist_wakeup(int cpu, pid_info_t *pidp, int old_state, uint64 runq_time)
{
	cpu_info_t *prev_cpuinfop, *cpuinfop;
	sched_info_t *schedp, *gschedp, *prev_cschedp, *cschedp;
        runq_info_t *prev_rqinfop, *rqinfop, *grqinfop, *prev_crqinfop, *crqinfop, *trqinfop;

        int time = 0;
        int prev_cpu, migrated=0;
        int ldom_migrated=0;
        double reltime;

	/* if (debug) fprintf (stderr, "sched_rqhist_wakeup() - PID=%d pidp=0x%llx schedp=0x%llx CPU=%d\n", pidp->PID, pidp, schedp, runq_time, cpu); */

	/* likely first wakeup for a PID has no value for schedp->cpu */
	schedp = GET_ADD_SCHEDP(&pidp->schedp);
	if (schedp->cpu == -1) schedp->cpu = cpu; 
	prev_cpu = schedp->cpu;

	if (cpu == -1) return;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	prev_cpuinfop = GET_CPUP(&globals->cpu_hash, prev_cpu);
        if (cpu != prev_cpu) {
                if (cpuinfop->ldom != prev_cpuinfop->ldom) {
                        ldom_migrated = 1;
                }
                migrated = 1;
        }

        time = runq_time / 1000;
        if (perpid_stats || kparse_flag) {
                trqinfop = GET_ADD_RQINFOP(&schedp->rqinfop);
                incr_runq_stats (trqinfop, old_state, time, migrated, ldom_migrated);

                rqinfop = GET_RQINFOP(&schedp->rqh, cpu);
                incr_runq_stats (rqinfop, old_state, time, migrated, ldom_migrated);

                prev_rqinfop = GET_RQINFOP(&schedp->rqh, prev_cpu);
                incr_runq_migr (prev_rqinfop, migrated, ldom_migrated+2);
        }

        if (percpu_stats) {
                cschedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
                crqinfop = GET_ADD_RQINFOP(&cschedp->rqinfop);
                incr_runq_stats (crqinfop, old_state, time, migrated, ldom_migrated);

                prev_cschedp = GET_ADD_SCHEDP(&prev_cpuinfop->schedp);
                prev_crqinfop = GET_ADD_RQINFOP(&prev_cschedp->rqinfop);
		incr_runq_migr (prev_crqinfop, migrated, ldom_migrated+2);
        }

	if (global_stats) {
		gschedp = GET_ADD_SCHEDP(&globals->schedp);
		grqinfop = GET_ADD_RQINFOP(&gschedp->rqinfop);
		incr_runq_stats(grqinfop, old_state, time, migrated, ldom_migrated);
		incr_runq_migr(grqinfop, migrated, ldom_migrated+2);
	}
}

void
sched_rqhist_resume(int cpu, pid_info_t *pidp, int old_state, uint64 runq_time)
{
	cpu_info_t *prev_cpuinfop, *cpuinfop;
	sched_info_t *schedp, *gschedp, *prev_cschedp, *cschedp;
        runq_info_t *prev_rqinfop, *rqinfop, *grqinfop, *prev_crqinfop, *crqinfop, *trqinfop;

        int time = 0;
        int prev_cpu, migrated=0;
        int ldom_migrated=0;
        double reltime;

	if ((old_state & RUNQ) == 0) return; 

	/* if (debug) printf ("sched_rqhist_resume() - PID=%d pidp=0x%llx schedp=0x%llx old_state: 0x%x runq_time: %lld\n", pidp->PID, pidp, schedp, old_state, runq_time);  */

	schedp = GET_ADD_SCHEDP(&pidp->schedp);
	if (schedp->cpu == -1) schedp->cpu = cpu; 
	prev_cpu = schedp->cpu;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	prev_cpuinfop = GET_CPUP(&globals->cpu_hash, prev_cpu);
        if (cpu != prev_cpu) {
                if (cpuinfop->ldom != prev_cpuinfop->ldom) {
                        ldom_migrated = 1;
                }
                migrated = 1;
        }

/*
** ldom_migrated = 0 means no migration
** ldom_migrated = 1 means migrated in
** ldom_migrated = 2 means no migration
** ldom_migrated = 3 mean migrated out
*/
        time = runq_time / 1000;

        if (perpid_stats || kparse_flag) {
                trqinfop = GET_ADD_RQINFOP(&schedp->rqinfop);
                incr_runq_stats (trqinfop, old_state, time, migrated, ldom_migrated);

                rqinfop = GET_RQINFOP(&schedp->rqh, cpu);
                incr_runq_stats (rqinfop, old_state, time, migrated, ldom_migrated);

                prev_rqinfop = GET_RQINFOP(&schedp->rqh, prev_cpu);
		incr_runq_migr (prev_rqinfop, migrated, ldom_migrated+2);
        }

        if (percpu_stats) {
                cschedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
                crqinfop = GET_ADD_RQINFOP(&cschedp->rqinfop);
                incr_runq_stats (crqinfop, old_state, time, migrated, ldom_migrated);

                prev_cschedp = GET_ADD_SCHEDP(&prev_cpuinfop->schedp);
                prev_crqinfop = GET_ADD_RQINFOP(&prev_cschedp->rqinfop);
		incr_runq_migr (prev_crqinfop, migrated, ldom_migrated+2);
        }

	if (global_stats) {
		gschedp = GET_ADD_SCHEDP(&globals->schedp);
		grqinfop = GET_ADD_RQINFOP(&gschedp->rqinfop);
		incr_runq_stats (grqinfop, old_state, time, migrated, ldom_migrated);
		incr_runq_migr (grqinfop, migrated, ldom_migrated+2);
	}

}

void
check_rq_delay(sched_switch_t *rec_ptr, pid_info_t *pidp, uint64 runq_time)
{
	int time = 0;

	time = runq_time / 1000;
	if (time > rqwait) {
		PRINT_COMMON_FIELDS(rec_ptr);
		PRINT_EVENT(rec_ptr->id);
		printf (" RUNQ Delay! %6.3fms next_pid=%d prev_state=%s prio=%d",
			MSECS(runq_time), 
			rec_ptr->next_pid,
			rec_ptr->prev_state ? "SLEEPING" : "PREEMPTED", 
			rec_ptr->next_prio);
		if (pidp->last_syscall_time && (pidp->last_syscall_id >= 0))  {
			printf (" lsyscall=");
			PRINT_SYSCALL(pidp, pidp->last_syscall_id); 
		}
		printf ("\n");
	}

#if DEBUG
	if (debug && (time > 2000)) {
			printf ("check_rq_delay() : delay > 2ms : ");
			PRINT_COMMON_FIELDS(rec_ptr);
			printf (" delay=%6.3fms next_pid=%d, lastcpu=%d resumed on cpu=%d", 
				SECS(runq_time), rec_ptr->next_pid, prev_cpu, cpu);
			if (pidp->last_syscall_time && (pidp->last_syscall_id >= 0)) 
				PRINT_SYSCALL(pidp, pidp->last_syscall_id);
			printf ("\n");
	}
#endif 
}

void
cpu_missed_buffer(void *arg)
{
	trace_info_t *trcinfop = arg;
	cpu_info_t *cpuinfop;
	sched_info_t *schedp;
	sched_stats_t *statp;

	cpuinfop = FIND_CPUP(globals->cpu_hash, trcinfop->cpu);
	if (cpuinfop == NULL) return;

	schedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
	statp = &schedp->sched_stats;
	statp->state = UNKNOWN;
	statp->last_cur_time = trcinfop->cur_time;
}

void
pid_missed_buffer(void *arg1, void *arg2)
{
	pid_info_t *pidp = arg1;
	trace_info_t *trcinfop = arg2;
	sched_info_t *schedp;
	sched_stats_t *statp;

	schedp = (sched_info_t *)find_sched_info(pidp);

	if (schedp->cpu == trcinfop->cpu) {
		statp = &schedp->sched_stats;

		if ((statp->state & RUNQ) || (statp->state & RUNNING)) {
			uint64 lost_time;
			lost_time =  trcinfop->cur_time - statp->last_cur_time;
			if (debug) printf ("pid_missed_buffer() - PID %d  CPU: %d  state: 0x%x lost_time: %7.6f\n", pidp->PID, schedp->cpu, statp->state, SECS(lost_time)); 
			statp->state = UNKNOWN;
			statp->last_cur_time = trcinfop->cur_time;
			pidp->last_syscall_time = 0;
			pidp->last_syscall_id = 0;
			pidp->missed_buffers++;
		}
	}
}

static inline int
print_sched_wakeup_rec(sched_wakeup_t *rec_ptr)
{
        PRINT_COMMON_FIELDS(rec_ptr);
        PRINT_EVENT(rec_ptr->id);

        printf ("%ctarget_pid=%d", fsep, rec_ptr->target_pid);
        printf ("%cprio=%d%ctarget_cpu=%d%csuccess=%d",
                fsep, rec_ptr->target_pri,
                fsep, rec_ptr->target_cpu,
                fsep, rec_ptr->success);
        printf ("\n");

        return 0;
}

int
sched_wakeup_func(void *a, void *v)
{
        filter_t *f = v;
	sched_wakeup_t tt_rec_ptr;
	sched_wakeup_t *rec_ptr;
        pid_info_t *pidp, *tpidp, *tgidp;
        sched_info_t *schedp, *tschedp, *gschedp;
	sched_stats_t *statp, *tstatp, *sstatp, *fd_sstatp;
	syscall_info_t *tsyscallp, *fdsyscallp;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	int old_state, new_state, coop_old_state;
	uint64 delta = 0, coop_delta = 0;
	int fd;
	fd_info_t *fdinfop, *tfdinfop;
        uint64 tgid = 0;

	rec_ptr = conv_sched_wakeup(a, &tt_rec_ptr);

	tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->target_pid);

	if (!check_filter(f->f_P_pid, (uint64)rec_ptr->target_pid) &&
	    !check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
	    !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu) &&
	    !check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid) &&
	    !check_filter(f->f_P_tgid, (uint64)tpidp->tgid))
		return 0;

	schedp = tschedp = NULL;
	pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);

	/* update Source PID stats */
	if ((rec_ptr->pid && check_filter(f->f_P_pid, (uint64)rec_ptr->pid)) ||
	    (rec_ptr->tgid && check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid))) {
        	/* printf ("%9.6f sched_wakeup_func() pid: %d\n", SECS(rec_ptr->hrtime), rec_ptr->pid); */
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		statp->C_wakeup_cnt++;
		
		/* Thundering Herd Detection (only if wakeup is successful) */
		if (rec_ptr->success && (rec_ptr->target_pid != schedp->last_target_pid)) {
			schedp->cur_wakeup_cnt++;
			if (schedp->cur_wakeup_cnt == schedp->max_wakeup_cnt) {
					schedp->max_wakeup_cnt_hit++;
			}
			if (schedp->cur_wakeup_cnt > schedp->max_wakeup_cnt) {
				schedp->max_wakeup_cnt = schedp->cur_wakeup_cnt;
				schedp->max_wakeup_time =  rec_ptr->hrtime;
				schedp->max_wakeup_cnt_hit = 1;
			}
			schedp->last_target_pid = rec_ptr->target_pid;
		}
	} else {
		/* woken from idle CPU */
	}

	/* update Target PID stats */
	/* if success=0, then target pid is already running */
	if (rec_ptr->success &&
	    (rec_ptr->target_pid && check_filter(f->f_P_pid, (uint64)rec_ptr->target_pid)) ||
	    (tpidp->tgid && check_filter(f->f_P_tgid, (uint64)tpidp->tgid))) {
        	tschedp = (sched_info_t *)find_sched_info(tpidp);
		tstatp = &tschedp->sched_stats;
        	/* printf ("%9.6f sched_wakeup_func() target_pid: %d\n", SECS(rec_ptr->hrtime), rec_ptr->target_pid); */

		/* if thread is already running, skip the processing */
		if ((tstatp->state & RUNNING) == 0) { 
		    tstatp->C_setrq_cnt++;			/* thread was placed on RunQ */
		    /* copies of some local vars for coop */ 
		    old_state = coop_old_state = tstatp->state;
		    if (rec_ptr->id == TRACE_SCHED_WAKEUP_NEW) tstatp->last_cur_time = rec_ptr->hrtime;
		    new_state = tstatp->state = RUNQ | (old_state & (USER | SYS));	
		    coop_delta = delta = update_sched_time(tstatp, rec_ptr->hrtime);

		    update_sched_state(tstatp, old_state, new_state, delta);
		    update_sched_prio(tschedp, rec_ptr->target_pri);

		    /* update runq stats, specifically for the CPU/LDOM migrations
		     * MR: I think this is a bug.   No need to increment RunQ stats on the wakeup.  We'll do it on the resume
		     */
		    if (runq_histogram)  {
			    sched_rqhist_wakeup(rec_ptr->target_cpu, tpidp, old_state, 0);
		    }

		    update_sched_cpu(tschedp, rec_ptr->target_cpu);

		    if (sleep_stats) update_slp_info(tpidp, &tpidp->slp_hash, delta, 0);
		    if (stktrc_stats) update_stktrc_info(&tpidp->last_stktrc[0], tpidp->last_stack_depth, &tpidp->stktrc_hash, delta, tpidp);
		    if (tpidp->last_ora_wait) update_oracle_wait_event(tpidp, delta);
		    if (global_stats) {
			gschedp = GET_ADD_SCHEDP(&globals->schedp);
			if (sleep_stats) update_slp_info(tpidp, &globals->slp_hash, delta, 0);
		        if (stktrc_stats) update_stktrc_info(&tpidp->last_stktrc[0], tpidp->last_stack_depth, &globals->stktrc_hash, delta, NULL);
			update_sched_state(gschedp, SWTCH, RUNQ, delta);
		    }

		    if ((old_state & SYS) && tpidp->last_syscall_time) {
			/* update syscall stats */
			tsyscallp = GET_SYSCALLP(&tpidp->scallhash, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
		        sstatp = &tsyscallp->sched_stats;
        		old_state = sstatp->state;
			sstatp->state = RUNQ | SYS;

	        	delta = update_sched_time(sstatp, rec_ptr->hrtime);
        		update_sched_state(sstatp, old_state, sstatp->state, delta);

                        if (sleep_stats || scdetail_flag) update_slp_info(tpidp, &tsyscallp->slp_hash, delta, rec_ptr->pid);

			/* update per-FD syscall statistics */
        		if (perfd_stats && (KS_ACTION(tpidp, tpidp->last_syscall_id).scallop & FILEOP)) {

				fd = tpidp->last_syscall_args[0];
				if ((fd < 65536) && (fd >= 0)) {
					fdinfop = GET_FDINFOP(&tpidp->fdhash, fd);
					tsyscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
		        		sstatp = &tsyscallp->sched_stats;
        				old_state = sstatp->state;
					sstatp->state = RUNQ | SYS;

		        		delta = update_sched_time(sstatp, rec_ptr->hrtime);
       		 			update_sched_state(sstatp, old_state, sstatp->state, delta);
					if (sleep_stats || scdetail_flag) update_slp_info(tpidp, &tsyscallp->slp_hash, delta, 0);

					/* update globals syscall slpinfo */
					if (global_stats && (sleep_stats || scdetail_flag)) {
						if (is_alive) get_filename(fdinfop, pidp);
		
						tfdinfop = fdinfop;	
               					/* inherit fdinfop from primary thread. */
					        if ((fdinfop->ftype == 0) && (tpidp->tgid)) {
                					tgidp = GET_PIDP(&globals->pid_hash, tpidp->tgid);
                					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                					if (tfdinfop == NULL) tfdinfop = fdinfop; 
        					}

						if (tfdinfop->lsock) {
							sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(tfdinfop->lsock), SIN_PORT(tfdinfop->lsock), 
												  SIN_ADDR(tfdinfop->rsock), SIN_PORT(tfdinfop->rsock));
							cp_sockaddr (&sdatap->laddr, tfdinfop->lsock);
							cp_sockaddr (&sdatap->raddr, tfdinfop->rsock);
							fdsyscallp = GET_SYSCALLP(&sdatap->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
							update_slp_info(tpidp, &fdsyscallp->slp_hash, delta, 0);
						} else {
							fdatap = GET_FDATAP(&globals->fdata_hash, tfdinfop->dev, tfdinfop->node);
							fdsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
							update_slp_info(tpidp, &fdsyscallp->slp_hash, delta, 0);
						}
					}
				}
			}
			/* Update the futex info with the wakers pid */
                        if ((futex_stats) && (KS_ACTION(tpidp, tpidp->last_syscall_id).scallop & FUTEXOP)) {
				futex_update_wakeup_stats(pidp, tpidp);
                        }
		    } else { /* this should be a wakeup from a blocking userspace fault condition */
			/* 
			tschedp = (sched_info_t *)find_sched_info(tpidp);
			tstatp = &tschedp->sched_stats;
			 */
			tstatp->T_uflt_sleep_time += delta;
			tstatp->C_uflt_sleep_cnt++;
			old_state = tstatp->state;

			if (sleep_stats) update_slp_info(tpidp, &tpidp->user_slp_hash, delta, rec_ptr->pid);
		    }
		    tpidp->last_stack_depth = 0;
		}
	}

	/* Partial interactions we catch at trace start/stop time or at missed buffer boundaries
 	** will result in some 'unknown' syscalls and sleep functions.  Plus idle task and ICS
	** will show unknown for wakers scall, etc.
	*/

        if (coop_stats && (rec_ptr->target_pid != rec_ptr->pid)) { 
		tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->target_pid);
                if (schedp && rec_ptr->target_pid) {
                        incr_setrq_stats((setrq_info_t ***)&schedp->setrq_tgt_hash, rec_ptr->target_pid, 
					coop_old_state, coop_delta);
			update_coop_stats(schedp, tschedp, pidp, tpidp, coop_delta, coop_old_state, WAKER);
                }
                if (tschedp)  {
                        incr_setrq_stats((setrq_info_t ***)&tschedp->setrq_src_hash, rec_ptr->pid,
					coop_old_state, coop_delta);
			update_coop_stats(schedp, tschedp, pidp, tpidp, coop_delta, coop_old_state, SLEEPER);
                }
        }

	if (kitrace_flag) print_sched_wakeup_rec(rec_ptr);
        return 0;
}

void 
sched_idle_timing_swtch(void *a)
{
        sched_switch_t *rec_ptr = (sched_switch_t *)a;
        int cpu = rec_ptr->cpu;
        uint64 hrtime = rec_ptr->hrtime;
        cpu_info_t *cpuinfop;
	uint64 usec_idle_time;
	int i;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	if (cpuinfop->last_swtch_time == 0) cpuinfop->last_swtch_time = FILTER_START_TIME;

	if (rec_ptr->pid == 0) {
		/* CPU was idle, must be going busy */
		if (cpuinfop->state_post_itime == ITIME_UNKNOWN) {
			if ((hrtime - FILTER_START_TIME) >= (itime*1000)) {
				cpuinfop->state_post_itime = ITIME_IDLE;
				cpuinfop->idle_time = hrtime - cpuinfop->last_swtch_time;
			}
		}
	
		usec_idle_time = (hrtime - cpuinfop->last_swtch_time) / 1000;

		if (usec_idle_time > idle_time_buckets[IDLE_TIME_NBUCKETS-2])
	                cpuinfop->idle_hist[IDLE_TIME_NBUCKETS-1]++;

		for (i=0; i < IDLE_TIME_NBUCKETS-1; i++) {
        	        if (usec_idle_time < idle_time_buckets[i]) {
                        	cpuinfop->idle_hist[i]++;
                        	break;
                	} else {
                        	continue;
                	}
        	}
	} else  if (rec_ptr->next_pid == 0) {
		/* CPU was busy, going idle */
        	if ((hrtime - FILTER_START_TIME) < (itime * 1000))   {
                	cpuinfop->state_post_itime = ITIME_UNKNOWN; 
        	} else {
                	if (cpuinfop->state_post_itime == ITIME_UNKNOWN)
                        	cpuinfop->state_post_itime = ITIME_BUSY;
        	}
	} else {
		/* CPU was busy, still busy */
	}
			
	cpuinfop->last_swtch_time = hrtime;
}

void
HT_switch_stats(int cpu, uint64 hrtime, uint64 starttime, int pid, int next_pid)
{
	int lcpu1, lcpu2;
	int i, j;
	uint64 timedelta;
        uint64 di_time, sys_max_di_time, pset_max_di_time, ldom_max_di_time;
        uint64 sys_max_di_usecs, pset_max_di_usecs, ldom_max_di_usecs;
        cpu_info_t *cpuinfop, *sibinfop, *tmp_cpu1infop, *tmp_cpu2infop;
        pcpu_info_t *pcpuinfop, *tmp_pcpuinfop;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	sibinfop = GET_CPUP(&globals->cpu_hash, cpuinfop->lcpu_sibling);
	pcpuinfop = GET_PCPUP(&globals->pcpu_hash, cpuinfop->pcpu_idx);

	if (pcpuinfop->last_time == 0) {
		pcpuinfop->last_time = starttime;
	}

	timedelta = hrtime - pcpuinfop->last_time;

	if (pid) {
		/* LCPU was BUSY */
                if (sibinfop->lcpu_state == LCPU_UNKNOWN) {
                        pcpuinfop->unknown_busy += timedelta;
                } else if (sibinfop->lcpu_state == LCPU_IDLE) {
                        cpuinfop->lcpu_busy += timedelta;
                } else if (sibinfop->lcpu_state == LCPU_BUSY) {
                        pcpuinfop->busy_time += timedelta;
                }
        } else {
                /* CPU was IDLE */
                if (sibinfop->lcpu_state == LCPU_UNKNOWN) {
                        pcpuinfop->unknown_idle += timedelta;
                } else if (sibinfop->lcpu_state == LCPU_IDLE) {
                        pcpuinfop->idle_time += timedelta + pcpuinfop->unknown_idle;
                        sibinfop->lcpu_busy += pcpuinfop->unknown_busy;
                        pcpuinfop->unknown_idle = 0;
                        pcpuinfop->unknown_busy = 0;
                } else if (sibinfop->lcpu_state == LCPU_BUSY) {
                        sibinfop->lcpu_busy += timedelta + pcpuinfop->unknown_busy;
                        pcpuinfop->idle_time += pcpuinfop->unknown_idle;
                        pcpuinfop->unknown_idle = 0;
                        pcpuinfop->unknown_busy = 0;
                }
        }

	pcpuinfop->last_time = hrtime;	

        if (next_pid && (sibinfop->lcpu_state == LCPU_BUSY)) {
            /* HT CPU Pair is becoming double busy */
            pcpuinfop->last_db_time = hrtime;

            /* checked to see if other PCPUs are double-idle.
	     * If so, record the time of the PCPU that was double-busy
	     * the longest in the double-idle histogram.
	     * Do this system-wide, per-LDOM, and per PSET.
             */

            if (HT_DBDI_histogram) {
                sys_max_di_time = 0;
                ldom_max_di_time = 0;
                for (i=0; i < MAXCPUS; i++) {
		    if (tmp_pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i)) {
			tmp_cpu1infop = FIND_CPUP(globals->cpu_hash, tmp_pcpuinfop->lcpu1);
			tmp_cpu2infop = FIND_CPUP(globals->cpu_hash, tmp_pcpuinfop->lcpu2);
                        if ((tmp_cpu1infop->lcpu_state == LCPU_IDLE) &&
                            (tmp_cpu2infop->lcpu_state == LCPU_IDLE)) {

                            di_time = hrtime - tmp_pcpuinfop->last_di_time;

                            if (debug) printf ("%12.6f CPU pair [%d %d] becoming double busy when double idle CPU [%d %d] is available - double_idle_time: %9.6f\n",
                                        SECS(hrtime - FILTER_START_TIME),
                                        pcpuinfop->lcpu1, pcpuinfop->lcpu2,
                                        tmp_pcpuinfop->lcpu1, tmp_pcpuinfop->lcpu2, SECS(di_time));

                            if (di_time > sys_max_di_time) {
                                sys_max_di_time =  di_time;
                            }


                            if ((cpuinfop->ldom == tmp_cpu1infop->ldom) &&
                                (di_time > ldom_max_di_time)) {
                                ldom_max_di_time =  di_time;
                            }
                        }
                    }
                }

                sys_max_di_usecs = sys_max_di_time / 1000;
                ldom_max_di_usecs = ldom_max_di_time / 1000;

                if (sys_max_di_usecs > idle_time_buckets[IDLE_TIME_NBUCKETS-2])
                        pcpuinfop->sys_DBDI_hist[IDLE_TIME_NBUCKETS-1]++;
                if (ldom_max_di_usecs > idle_time_buckets[IDLE_TIME_NBUCKETS-2])
                        pcpuinfop->ldom_DBDI_hist[IDLE_TIME_NBUCKETS-1]++;

                for (j=0; j < IDLE_TIME_NBUCKETS-1; j++) {
                        if (sys_max_di_usecs < idle_time_buckets[j])  {
                                pcpuinfop->sys_DBDI_hist[j]++;
                                break;
                        }
                }

                for (j=0; j < IDLE_TIME_NBUCKETS-1; j++) {
                        if (ldom_max_di_usecs < idle_time_buckets[j])  {
                                pcpuinfop->ldom_DBDI_hist[j]++;
                                break;
                        }
                }
            }
        } else if ((next_pid == 0) && (sibinfop->lcpu_state == LCPU_IDLE)) {
		/* HT CPU Pair has just become double idle */
		pcpuinfop->last_di_time = hrtime;
	}
	
	/* update LCPU time and state*/
	if (next_pid) {
		cpuinfop->lcpu_state = LCPU_BUSY;
	} else {
		cpuinfop->lcpu_state = LCPU_IDLE;
	}
}

void
sched_HT_switch(void *a)
{
        sched_switch_t *rec_ptr = (sched_switch_t *)a;

	HT_switch_stats(rec_ptr->cpu, rec_ptr->hrtime, FILTER_START_TIME, rec_ptr->pid, rec_ptr->next_pid);
}

int		
update_cpu_last_pid(int cpu, int pid)
{
	cpu_info_t *cpuinfop;
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	cpuinfop->pid = pid;
	return 0;
}

static inline int
cpu_switch_stats(sched_switch_t *rec_ptr, pid_info_t *tpidp)
{
	cpu_info_t *cpuinfop;
	sched_info_t *schedp, *gschedp;
	sched_stats_t *statp, *pstatp;
	int old_state;
	uint64 delta;
	int cpu;

	cpu = rec_ptr->cpu;
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
	statp = &schedp->sched_stats;
	gschedp = GET_ADD_SCHEDP(&globals->schedp);

        if ((rec_ptr->pid == 0) && (statp->state == UNKNOWN)) {
                old_state = IDLE;
        } else {
                old_state = statp->state;
        }

        if (rec_ptr->next_pid) {
                /* need to inherit SYS | USER field from target pid */
                schedp = (sched_info_t *)find_sched_info(tpidp);
                pstatp = &schedp->sched_stats;
                statp->state = RUNNING | (pstatp->state & (USER | SYS));
        } else {
                statp->state = IDLE;
        }

        delta = update_sched_time(statp, rec_ptr->hrtime);
        update_sched_state(statp, old_state, statp->state, delta);
        if (STEAL_ON) {
                if (rec_ptr->pid > 0)  {
                        statp->T_stealtime += rec_ptr->stealtime;
                } else {
                        statp->T_stealtime_idle += rec_ptr->stealtime;
                }
        }

	/* update per-cpu MSR fields */
	update_cpu_msr_stats(rec_ptr, statp);
        return 0;
}

static inline int
print_msr_stats(sched_switch_t *rec_ptr)
{
	unsigned long *msrptr;

	if (msrptr = get_msr_ptr(rec_ptr)) {
		printf ("%cllcref=%lld", fsep, msrptr[LLC_REF]); 
		printf ("%cllcmiss=%lld", fsep, msrptr[LLC_MISSES]); 
		printf ("%cinstrs=%lld", fsep, msrptr[RET_INSTR]); 
		printf ("%ccycles=%lld", fsep, msrptr[CYC_NOHALT_CORE]); 
		printf ("%cfixed_clkfreq=%lld", fsep, msrptr[4]);
		printf ("%cactual_clkfreq=%lld", fsep, msrptr[5]);
		printf ("%csmicnt=%lld", fsep, msrptr[6]);
	}
}	

static inline int
print_sched_switch_rec(sched_switch_t *rec_ptr, pid_info_t *pidp)
{
	int start;
	unsigned long *msrptr;

	PRINT_COMMON_FIELDS(rec_ptr);
	if (printcmd_flag) printf ("%ccomm=%s", fsep, &rec_ptr->prev_comm[0]);
	PRINT_EVENT(rec_ptr->id);

	if (rec_ptr->pid)  {
		printf ("%csyscall=", fsep);
		PRINT_SYSCALL(pidp, rec_ptr->syscallno);	
		pidp->tgid = rec_ptr->tgid;
		printf ("%cprio=%d%cstate=%s%cnext_pid=%d",
			fsep, rec_ptr->prev_prio, 
			fsep, pstate(rec_ptr->prev_state), 
			fsep, rec_ptr->next_pid);
	} else {
		printf ("%csyscall=idle", fsep);
		printf ("%cprio=n/a%cstate=n/a%cnext_pid=%d", fsep, fsep, fsep, rec_ptr->next_pid);
	}

	printf ("%cnext_prio=%d", fsep, rec_ptr->next_prio);
	if (IS_LIKI) {
		if (rec_ptr->next_pid)  {
			printf ("%cnext_tgid=%d%cpolicy=%s", 
				fsep, rec_ptr->next_tgid, 
				fsep, sched_policy_name[rec_ptr->next_policy & SCHED_POLICY_MASK]) ;
		} else {
			printf ("%cnext_tgid=n/a%cpolicy=n/a", fsep, fsep);
		}
	}

	if (IS_LIKI_V2_PLUS) {
		printf ("%cvss=%lld%crss=%lld", 
			fsep, rec_ptr->total_vm, 
			fsep, rec_ptr->total_rss);
		/* printf ("%cirq_time=%12.06f%csoftirq_time=%12.06f", fsep, SECS(rec_ptr->irq_time), fsep, SECS(rec_ptr->softirq_time)); */
	}

	if (STEAL_ON) printf ("%cstealtime=%12.06f", fsep, SECS(rec_ptr->stealtime));
 
	if (msr_flag) print_msr_stats(rec_ptr);

	start = find_switch_start(&rec_ptr->ips[0], rec_ptr->stack_depth);
	/* printf (" start: %d, depth: %d", start, rec_ptr->stack_depth); */
	if (rec_ptr->stack_depth) {
		print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, start, rec_ptr->pid); 
		/* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth);   */
	}

	printf ("\n");

	return 0;
}

int 
futex_sched_wakeup_func(void *a, void *v)
{
	sched_wakeup_t tt_rec_ptr;
	sched_wakeup_t *rec_ptr;
	pid_info_t *pidp, *tpidp;

	if (futex_stats == 0) return 0;
	rec_ptr = conv_sched_wakeup(a, &tt_rec_ptr);

	pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->target_pid);
	if (tpidp->last_syscall_time == 0) return 0;

	if (KS_ACTION(tpidp, tpidp->last_syscall_id).scallop & FUTEXOP) {
		futex_update_wakeup_stats(pidp, tpidp);
	}

	return 0;
}

int
trace_sched_switch_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	char tt_rec_ptr[MAX_REC_LEN];
	sched_switch_t *rec_ptr;
	pid_info_t *next_pidp, *pidp;

	rec_ptr = conv_sched_switch(trcinfop, &tt_rec_ptr);

	next_pidp = GET_PIDP(&globals->pid_hash, rec_ptr->next_pid);
	pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	
	if (!check_filter(f->f_P_pid, (uint64)rec_ptr->next_pid) && 
	    !check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
	    !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu) && 
	    !check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid) &&
	    !check_filter(f->f_P_tgid, (uint64)next_pidp->tgid))
		return 0;

	print_sched_switch_rec(rec_ptr, pidp);
}

int
trace_sched_wakeup_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	sched_wakeup_t tt_rec_ptr;
	sched_wakeup_t *rec_ptr;
	pid_info_t *tpidp; 

	rec_ptr = conv_sched_wakeup(trcinfop, &tt_rec_ptr);

        tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->target_pid);
	
	if (!check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid) &&
	    !check_filter(f->f_P_tgid, (uint64)tpidp->tgid) &&
	    !check_filter(f->f_P_pid, (uint64)rec_ptr->target_pid) && 
	    !check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
	    !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu)) 
		return 0;

	print_sched_wakeup_rec(rec_ptr);
}

static inline int
print_sched_migrate_task_rec(void *a)
{
	sched_migrate_task_t *rec_ptr = (sched_migrate_task_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	
	printf ("%ctarget_pid=%d%ctarget_prio=%d%corig_cpu=%d%cdest_cpu=%d", 
		fsep, rec_ptr->target_pid,
		fsep, rec_ptr->target_pri, 
		fsep, rec_ptr->orig_cpu, 
		fsep, rec_ptr->dest_cpu);

	if (rec_ptr->stack_depth) {
        	print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, 0, rec_ptr->pid);
		/* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth);  */
	}

	printf ("\n");
	return 0;
}

int
trace_sched_migrate_task_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	char tt_rec_ptr[MAX_REC_LEN];
	sched_migrate_task_t *rec_ptr;
	pid_info_t *tpidp;

	rec_ptr = conv_sched_migrate_task(trcinfop, &tt_rec_ptr);

        tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->target_pid);
	if (!check_filter(f->f_P_tgid, rec_ptr->tgid) &&
		!check_filter(f->f_P_tgid, (uint64)tpidp->tgid) &&
		!check_filter(f->f_P_pid, (uint64)rec_ptr->target_pid) && 
		!check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
		!check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu)) 
		return 0;

	print_sched_migrate_task_rec(rec_ptr);
}

/* special lightweight sched_switch function to just get process/thread names */
int
sched_switch_thread_names_func(void *a, void *v)
{
        filter_t *f = v;
        char tt_rec_ptr[MAX_REC_LEN];
        sched_switch_t *rec_ptr;
        pid_info_t *pidp, *tpidp, *tgidp;

        rec_ptr = conv_sched_switch(a, &tt_rec_ptr);

	if (rec_ptr->pid > 0) {	
        	pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		if (pidp->tgid && (pidp->tgid != pidp->PID) &&
		    (strstr(rec_ptr->prev_comm, "db2sysc") == NULL) &&
		    (strstr(rec_ptr->prev_comm, "java") == NULL) ) {
			repl_command(&pidp->thread_cmd, rec_ptr->prev_comm);
		}
		add_command(&pidp->cmd, rec_ptr->prev_comm);
	}

        if ((IS_LIKI) && rec_ptr->next_pid) {
                tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->next_pid);
                if ((tpidp->tgid == 0) && (tpidp->tgid != rec_ptr->next_pid))  {
			tpidp->tgid = rec_ptr->next_tgid;

			/* Inherit TGID command name if available and target pid command name is null */
			if (rec_ptr->next_pid != rec_ptr->next_tgid) {
				tgidp = GET_PIDP(&globals->pid_hash, rec_ptr->next_tgid);
				if (tgidp->cmd) repl_command(&tpidp->cmd, tgidp->cmd);
			}
		}
	}

	return 0;
}


int
sched_switch_func(void *a, void *v)
{
        filter_t *f = v;
	char tt_rec_ptr[MAX_REC_LEN];
	sched_switch_t *rec_ptr;

        pid_info_t *pidp, *tpidp, *tgidp;
        sched_info_t *schedp, *tschedp, *gschedp;
	syscall_info_t *syscallp, *tsyscallp, *fdsyscallp;
	sched_stats_t *statp, *tstatp, *sstatp, *fd_sstatp;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	int old_state;
	uint64 delta;
	int fd;
	fd_info_t *fdinfop, *tfdinfop;
	int old_cpu;

	rec_ptr = conv_sched_switch(a, &tt_rec_ptr);	

	tpidp = GET_PIDP(&globals->pid_hash, rec_ptr->next_pid);
	if (!check_filter(f->f_P_pid, (uint64)rec_ptr->next_pid) &&
            !check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
            !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu) &&
            !check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid) &&
            !check_filter(f->f_P_tgid, (uint64)tpidp->tgid))
                return 0;

	/* if (debug) fprintf (stderr, "%12.6f cpu: %d  sched_switch  pid: %d  target pid: %d\n", SECS(rec_ptr->hrtime), rec_ptr->cpu, rec_ptr->pid, rec_ptr->next_pid); */

	if (globals->HT_enabled && ht_stats) sched_HT_switch(rec_ptr);
	if (idle_stats) sched_idle_timing_swtch(rec_ptr);
	cpu_switch_stats(rec_ptr, tpidp);

        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
        if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);

	/* update Source PID stats */
	if ((rec_ptr->pid && check_filter(f->f_P_pid, (uint64)rec_ptr->pid)) ||
	    (rec_ptr->tgid && check_filter(f->f_P_tgid, (uint64)rec_ptr->tgid))) {
		if ((pidp->tgid == 0) && IS_LIKI_V2_PLUS) pidp->tgid = rec_ptr->tgid;
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		statp->C_switch_cnt++;
		old_state = statp->state;
		if (rec_ptr->prev_state) {
			statp->state = SWTCH | (old_state & (USER | SYS));
			statp->C_sleep_cnt++;
		} else {
			if (old_state == UNKNOWN && (rec_ptr->syscallno > MAXSYSCALLS)) {
				old_state = RUNNING | USER;
			}
			statp->state = RUNQ | (old_state & (USER | SYS));
			statp->C_preempt_cnt++;
		}
		delta = update_sched_time(statp, rec_ptr->hrtime);
		update_sched_state(statp, old_state, statp->state, delta);
		update_sched_prio(schedp, rec_ptr->prev_prio);
		update_sched_cpu(schedp, rec_ptr->cpu);
		update_swoff_msr_stats(rec_ptr, statp);

		if (STEAL_ON && rec_ptr->stealtime) {
			statp->T_stealtime += rec_ptr->stealtime;
		}
		if (perpid_stats) {
			/* if zero, then thread is likely dead, so don't overwrite */
			if (rec_ptr->total_rss) pidp->rss = rec_ptr->total_rss;
			if (rec_ptr->total_vm) pidp->vss = rec_ptr->total_vm;

			if (pidp->tgid && (pidp->tgid != pidp->PID) &&
		    	(strstr(rec_ptr->prev_comm, "db2sysc") == NULL) &&
		    	(strstr(rec_ptr->prev_comm, "java") == NULL) ) {
				repl_command(&pidp->thread_cmd, rec_ptr->prev_comm);
			}
			add_command(&pidp->cmd, rec_ptr->prev_comm);
		}

		if (global_stats) {
			gschedp = GET_ADD_SCHEDP(&globals->schedp);
			gschedp->sched_stats.C_switch_cnt++;
			if (rec_ptr->prev_state) {
				gschedp->sched_stats.C_sleep_cnt++;
			} else {
				gschedp->sched_stats.C_preempt_cnt++;
			}
		}

		/* save sleep details in pid_info_t */
		if ((statp->state & SWTCH) && (stktrc_stats || sleep_stats)) {
			pidp->last_stack_depth = 0;
			if (rec_ptr->stack_depth) {
				uint64 start;
				start = find_switch_start(&rec_ptr->ips[0], rec_ptr->stack_depth);
				pidp->last_stack_depth = save_entire_stack(&pidp->last_stktrc[0], &rec_ptr->ips[start], rec_ptr->stack_depth-start);
				pidp->last_ora_wait = get_oracle_wait_event(pidp, &rec_ptr->ips[start], rec_ptr->stack_depth-start);
			}
		} else if ((statp->state & RUNQ) && (stktrc_stats || sleep_stats) && rec_ptr->stack_depth) {
				uint64 start;
				start = find_switch_start(&rec_ptr->ips[0], rec_ptr->stack_depth);
				update_stktrc_info(&rec_ptr->ips[start], rec_ptr->stack_depth - start, &pidp->runq_stktrc_hash, 0, pidp);
		}

		schedp->cur_wakeup_cnt = 0;

		/* update syscall stats */
		if (scall_flag && (old_state & SYS) && pidp->last_syscall_time) {
			syscallp = GET_SYSCALLP(&pidp->scallhash, SYSCALL_KEY(pidp->elf, 0ul, pidp->last_syscall_id));
		        sstatp = &syscallp->sched_stats;
        		old_state = sstatp->state;
			if (rec_ptr->prev_state) {
				sstatp->state = SWTCH | (old_state & (USER | SYS));
				sstatp->C_sleep_cnt++;
			} else {
				sstatp->state = RUNQ | (old_state & (USER | SYS));
				sstatp->C_preempt_cnt++;
			}

	        	delta = update_sched_time(sstatp, rec_ptr->hrtime);
        		update_sched_state(sstatp, old_state, sstatp->state, delta);

			if (perfd_stats && (KS_ACTION(pidp, pidp->last_syscall_id).scallop & FILEOP)) {
				fd = pidp->last_syscall_args[0];
				if ((fd < 65536) && (fd >= 0)) {
					fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
					syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, pidp->last_syscall_id));

			        	sstatp = &syscallp->sched_stats;
        				old_state = sstatp->state;
					if (rec_ptr->prev_state) {
						sstatp->state = SWTCH | (old_state & (USER | SYS));
						sstatp->C_sleep_cnt++;
					} else {
						sstatp->state = RUNQ | (old_state & (USER | SYS));
						sstatp->C_preempt_cnt++;
					}

	        			delta = update_sched_time(sstatp, rec_ptr->hrtime);
        				update_sched_state(sstatp, old_state, sstatp->state, delta);

					/* update globals syscall slpinfo */
					if (global_stats && (sleep_stats || scdetail_flag)) {
						if (is_alive) get_filename(fdinfop, pidp);

						tfdinfop = fdinfop;	
               					/* inherit fdinfop from primary thread. */
					        if ((fdinfop->ftype == 0) && (pidp->tgid)) {
                					tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                					if (tfdinfop == NULL) tfdinfop = fdinfop; 
        					}

						if (fdinfop->lsock) {
							sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(tfdinfop->lsock), SIN_PORT(tfdinfop->lsock), 
												  SIN_ADDR(tfdinfop->rsock), SIN_PORT(tfdinfop->rsock));
							cp_sockaddr (&sdatap->laddr, tfdinfop->lsock);
							cp_sockaddr (&sdatap->raddr, tfdinfop->rsock);
							fdsyscallp = GET_SYSCALLP(&sdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, pidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							if (rec_ptr->prev_state) {
								fd_sstatp->C_sleep_cnt++;
							} else {
								fd_sstatp->C_preempt_cnt++;
							}
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
						} else {
							fdatap = GET_FDATAP(&globals->fdata_hash, tfdinfop->dev, tfdinfop->node);
							fdsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, pidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							if (rec_ptr->prev_state) {
								fd_sstatp->C_sleep_cnt++;
							} else {
								fd_sstatp->C_preempt_cnt++;
							}
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
						}
					}
				}
			}
		}
		/* special case for zombie processes, this is done AFTER update_sched_time() */
		if (rec_ptr->prev_state & (EXIT_ZOMBIE | EXIT_DEAD | TASK_DEAD)) {
			statp->state = ZOMBIE;
			statp->C_terminated_cnt++;
		} 

	} else {
		/* CPU was idle */
	}

	/* update Target PID stats */
	if ((rec_ptr->next_pid && check_filter(f->f_P_pid, (uint64)rec_ptr->next_pid)) ||
	    (tpidp->tgid && check_filter(f->f_P_tgid, (uint64)tpidp->tgid))) {
		update_cpu_last_pid(rec_ptr->cpu, rec_ptr->next_pid);
		tgidp = GET_PIDP(&globals->pid_hash, rec_ptr->next_tgid);
		if (IS_LIKI && (tpidp->tgid == 0)) {
			tpidp->tgid = rec_ptr->next_tgid;

			/* Inherit TGID command name if available and target pid command name is null */
			if (rec_ptr->next_pid != rec_ptr->next_tgid) {
				if (tgidp->cmd) repl_command(&tpidp->cmd, tgidp->cmd);
			}
		}

        	tschedp = (sched_info_t *)find_sched_info(tpidp);
		if (IS_LIKI) tschedp->policy = rec_ptr->next_policy;
		tstatp = &tschedp->sched_stats;
		old_state = tstatp->state;
		old_cpu = tschedp->cpu;
		tstatp->state = RUNNING | (old_state & (USER | SYS));	
	
		/* the following accounts wakeups on an idle CPU */
		if ((rec_ptr->pid == 0) && (old_state & RUNQ) && (rec_ptr->cpu == old_cpu)) 
			old_state = RUNQ_IDLE | (old_state & (USER | SYS));

		delta = update_sched_time(tstatp, rec_ptr->hrtime);
		update_sched_state(tstatp, old_state, tstatp->state, delta);
		update_swon_msr_stats(rec_ptr, tstatp);

		if (sleep_stats) update_slp_info(tpidp, &tpidp->slp_hash, delta, 0);
		if (global_stats) {
			gschedp = GET_ADD_SCHEDP(&globals->schedp);
			/* update_sched_state(&gschedp->sched_stats, old_state, tstatp->state, delta); */
			if (sleep_stats) update_slp_info(tpidp, &globals->slp_hash, delta, 0);
		}

		/* update runq stats */
		if (runq_histogram)  {
			/* this must be called before update_sched_cpu() */
			sched_rqhist_resume(rec_ptr->cpu, tpidp, old_state, delta);
			check_rq_delay(rec_ptr, tpidp, delta);
		}

		update_sched_prio(tschedp, rec_ptr->next_prio);
		update_sched_cpu(tschedp, rec_ptr->cpu);

		/* update syscall stats */
		if (scall_flag && (old_state & SYS) && tpidp->last_syscall_time) {
			tsyscallp = GET_SYSCALLP(&tpidp->scallhash, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
		        sstatp = &tsyscallp->sched_stats;
        		old_state = sstatp->state;
			sstatp->state = RUNNING | SYS;

			if ((rec_ptr->pid == 0) && (old_state & RUNQ) && (rec_ptr->cpu == old_cpu)) 
				old_state = RUNQ_IDLE | (old_state & (USER | SYS));

	        	delta = update_sched_time(sstatp, rec_ptr->hrtime);
        		update_sched_state(sstatp, old_state, sstatp->state, delta);

			if (sleep_stats || scdetail_flag) update_slp_info(tpidp, &tsyscallp->slp_hash, delta, 0);

			if (KS_ACTION(tpidp, tpidp->last_syscall_id).scallop & FILEOP) {
				fd = tpidp->last_syscall_args[0];
				if ((fd < 65536) && (fd >= 0)) {
					fdinfop = GET_FDINFOP(&tpidp->fdhash, fd);
					tsyscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
		        		sstatp = &tsyscallp->sched_stats;
        				old_state = sstatp->state;
					sstatp->state = RUNNING | SYS;

					if ((rec_ptr->pid == 0) && (old_state & RUNQ) && (rec_ptr->cpu == old_cpu)) 
						old_state = RUNQ_IDLE | (old_state & (USER | SYS));
	        	
					delta = update_sched_time(sstatp, rec_ptr->hrtime);
        				update_sched_state(sstatp, old_state, sstatp->state, delta);

					if (sleep_stats || scdetail_flag) update_slp_info(tpidp, &tsyscallp->slp_hash, delta, 0);

					/* update globals syscall slpinfo */
					if (global_stats && (sleep_stats || scdetail_flag)) {
						if (is_alive) get_filename(fdinfop, tpidp);
					
						tfdinfop = fdinfop;	
               					/* inherit fdinfop from primary thread. */
					        if ((fdinfop->ftype == 0) && (tpidp->tgid)) {
                					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                					if (tfdinfop == NULL) tfdinfop = fdinfop; 
        					}

						if (tfdinfop->lsock) {
							sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(tfdinfop->lsock), SIN_PORT(tfdinfop->lsock), 
												  SIN_ADDR(tfdinfop->rsock), SIN_PORT(tfdinfop->rsock));
							cp_sockaddr (&sdatap->laddr, tfdinfop->lsock);
							cp_sockaddr (&sdatap->raddr, tfdinfop->rsock);
							fdsyscallp = GET_SYSCALLP(&sdatap->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
							update_slp_info(tpidp, &fdsyscallp->slp_hash, delta, 0);
						} else {
						 	fdatap = GET_FDATAP(&globals->fdata_hash, tfdinfop->dev, tfdinfop->node);
							fdsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, tpidp->last_syscall_id));
							fd_sstatp = &fdsyscallp->sched_stats;
							update_sched_state(fd_sstatp, old_state, sstatp->state, delta);
							update_slp_info(tpidp, &fdsyscallp->slp_hash, delta, 0);
						}
					}
				}
			}
		}
		tpidp->last_stack_depth = 0;
	} else {
		update_cpu_last_pid(rec_ptr->cpu, rec_ptr->next_pid);
		/* CPU is going idle */
	}

	if (kitrace_flag) print_sched_switch_rec(rec_ptr, pidp);	
}

