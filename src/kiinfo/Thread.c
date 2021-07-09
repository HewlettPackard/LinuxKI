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
#include <time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "scsi.h"

#include "Pdb.h"
#include "winki_util.h"

void 
winki_update_slp_info(pid_info_t *pidp, void *arg2, winki_stack_info_t *stkinfop, uint64 delta, uint64 wpid)
{
	slp_info_t ***slp_hash = arg2;
	slp_info_t *slpinfop;
	uint64	key, ip;
	uint64 symaddr = 0;
	char *symptr;
	vtxt_preg_t *pregp = NULL;
	int i;

	if (stkinfop->depth == 0) return;

        for (i = 0; i < stkinfop->depth; i++) {
		key = ip = stkinfop->Stack[i];
                if (pregp = get_win_pregp(ip, pidp)) {
			if (symptr = win_symlookup(pregp, ip, &symaddr)) {
				if (strncmp(symptr, "SwapContext", 11) == 0) continue;
				else if (strncmp(symptr, "KiSwapContext", 13) == 0) continue;
				else if (strncmp(symptr, "KiSwapThread", 12) == 0) continue;
				else if (strncmp(symptr, "KiCommitThreadWait", 18) == 0) continue;
                                key = pregp->p_vaddr + symaddr;
                        }
		}
		break;
	}


	slpinfop = GET_SLPINFOP(slp_hash, key);
	slpinfop->count++;
	if (pidp->last_sleep_delta) {
		slpinfop->sleep_time += pidp->last_sleep_delta;
	}
	slpinfop->max_time = MAX(slpinfop->max_time, delta);
}

void
winki_update_stktrc_info(pid_info_t *pidp, void *arg1,  winki_stack_info_t *stkinfop, uint64 delta, int sys_only)
{
        stktrc_info_t ***stktrc_hash = arg1;
        stktrc_info_t *stktrcp;
        uint64  key, ip;
	int len, depth, i, j;
	uint64 symaddr = 0;
	char *symptr;
	vtxt_preg_t *pregp = NULL;
	uint64 stktrc[LEGACY_STACK_DEPTH];

        if (stkinfop->depth == 0) return;
	if (cluster_flag) return;

        for (i = 0, j = 0; i < stkinfop->depth && j < LEGACY_STACK_DEPTH; i++) {
		key = ip = stkinfop->Stack[i];
		if (sys_only && !WINKERN_ADDR(ip)) break;
                if (pregp = get_win_pregp(ip, pidp)) {
			if (symptr = win_symlookup(pregp, ip, &symaddr)) {
				if (strncmp(symptr, "SwapContext", 11) == 0) continue;
				else if (strncmp(symptr, "KiSwapContext", 13) == 0) continue;
				else if (strncmp(symptr, "KiSwapThread", 12) == 0) continue;
				else if (strncmp(symptr, "KiCommitThreadWait", 18) == 0) continue;
                                key = pregp->p_vaddr + symaddr;
                        }
		}

		stktrc[j] = key;
		j++;
	}

	depth = j;
	len = depth * sizeof(uint64);
	key = doobsHash(&stktrc[0], len, 0xff);
	stktrcp = (stktrc_info_t *)find_add_stkhash_entry((stklle_t ***)stktrc_hash,
					STKTRC_HSIZE,
					STKTRC_HASH(key),
					sizeof(stktrc_info_t),
					&stktrc[0],
					depth);

	stktrcp->pidp = pidp;
	stktrcp->cnt++;
	/* stktrcp->slptime += delta; */
	if (pidp->last_sleep_delta) {
		stktrcp->slptime += pidp->last_sleep_delta;
	}
	stktrcp->stklen = depth; 
}


void
winki_idle_timing_swtch(int cpu, int pid, int next_pid, uint64 wintime)
{
        cpu_info_t *cpuinfop;
        uint64 usec_idle_time;
        int i;
	uint64 hrtime = CONVERT_WIN_TIME(wintime);

        cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
        if (cpuinfop->last_swtch_time == 0)  cpuinfop->last_swtch_time = CONVERT_WIN_TIME(winki_start_time);

        if (pid == 0) {
                /* CPU was idle, must be going busy */
                if (cpuinfop->state_post_itime == ITIME_UNKNOWN) {
                        if ((hrtime - (CONVERT_WIN_TIME(winki_start_time))) >= (itime*1000)) {
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
        } else  if (next_pid == 0) {
                /* CPU was busy, going idle */
                if ((hrtime - CONVERT_WIN_TIME(winki_start_time)) < (itime * 1000))   {
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

int
global_cswitch_stats(int prev_state)
{
	sched_info_t *gschedp;

	gschedp = GET_ADD_SCHEDP(&globals->schedp);
	gschedp->sched_stats.C_switch_cnt++;
	if (prev_state == Waiting) {
		gschedp->sched_stats.C_sleep_cnt++;
	} else {
		gschedp->sched_stats.C_preempt_cnt++;
	}
}

int
perpid_source_cswitch_stats(int cpu, Cswitch_t *p, pid_info_t *pidp)
{
        sched_info_t *schedp, *gschedp;
        sched_stats_t *statp, *sstatp;
	syscall_info_t *syscallp;
	pid_info_t *syspidp;
	win_syscall_save_t *entry;
        int old_state;
        uint64 delta, hrtime;
	short syscall_id;

	hrtime = CONVERT_WIN_TIME(p->TimeStamp);
	schedp = (sched_info_t *)find_sched_info(pidp);
	statp = &schedp->sched_stats;
	statp->C_switch_cnt++;
	old_state = statp->state;

	/* not sure how to tell if the task is preempted or sleeping */
	if (p->OldThreadState == Waiting || p->OldThreadState==Terminated) {
		statp->state = SWTCH | (old_state & (USER | SYS));
		statp->C_sleep_cnt++;
	} else {
		statp->state = RUNQ | (old_state & (USER | SYS));
		statp->C_preempt_cnt++;
	}

	delta = update_sched_time(statp, hrtime); 
	winki_update_sched_state(statp, old_state, statp->state, delta);
	update_sched_prio(schedp, p->OldThreadPriority);
	update_sched_cpu(schedp, cpu);

	entry = (win_syscall_save_t *)pidp->win_active_syscalls;
	if (scall_stats && entry) {
		syspidp = GET_PIDP(&globals->pid_hash, 0);
		syscall_id = syscall_addr_to_id(entry->addr);
		syscallp = GET_SYSCALLP(&pidp->scallhash, syscall_id);
		sstatp = &syscallp->sched_stats;
		old_state = sstatp->state;
		if (p->OldThreadState == Waiting) {
			sstatp->state = SWTCH | (old_state & (USER | SYS));
			sstatp->C_sleep_cnt++;
		} else {
			sstatp->state = RUNQ | (old_state & (USER | SYS));
			sstatp->C_preempt_cnt++;
		}

		delta = update_sched_time(sstatp, hrtime);
		winki_update_sched_state(sstatp, old_state, sstatp->state, delta);
	}	

	if (global_stats) {
		gschedp = GET_ADD_SCHEDP(&globals->schedp);
		gschedp->sched_stats.C_switch_cnt++;
		if (p->OldThreadState == Waiting) {
			gschedp->sched_stats.C_sleep_cnt++;
		} else {
			gschedp->sched_stats.C_preempt_cnt++;
		}
	}

	if (p->OldThreadState==Terminated) {
		statp->state = ZOMBIE;
	}
}


int
perpid_target_cswitch_stats(int cpu, Cswitch_t *p, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
        sched_info_t *schedp, *gschedp;
        sched_stats_t *statp, *tstatp;
	syscall_info_t *syscallp;
	win_syscall_save_t *entry;
        int old_state, new_state;
	int old_cpu;
        uint64 delta, hrtime;
	short syscall_id;

	hrtime = CONVERT_WIN_TIME(p->TimeStamp);
	update_cpu_last_pid(cpu, pidp->PID);

	schedp = (sched_info_t *)find_sched_info(pidp);
	statp = &schedp->sched_stats;
	old_state = statp->state;
	old_cpu = schedp->cpu;

	/* the following accounts wakeups on an idle CPU */
	if ((p->OldThreadId == 0) && (old_state & RUNQ) && (cpu == old_cpu)) {
                        old_state = RUNQ_IDLE | (old_state & (USER | SYS));
	}

	delta = update_sched_time(statp, hrtime);

	if (runq_histogram) {
		/* this needs to be done before update_sched_cpu() is called */
		sched_rqhist_resume(cpu, pidp, old_state, delta); 
	}

	/* printf ("Cswitch: PID: %d old_state: 0x%x new_state: 0x%x  delta: %9.6f\n", pidp->PID, old_state, new_state, SECS(delta)); */
	winki_update_sched_state(statp, old_state, new_state, delta);
	update_sched_prio(schedp, p->OldThreadPriority);
	update_sched_cpu(schedp, cpu);

	if (sleep_stats) winki_update_slp_info(pidp, &pidp->slp_hash, stkinfop, delta, 0);
	if (stktrc_stats) winki_update_stktrc_info(pidp, &pidp->stktrc_hash, stkinfop, delta, 0);

	entry = (win_syscall_save_t *)pidp->win_active_syscalls;
	if (scall_stats && entry) {
		syscall_id = syscall_addr_to_id(entry->addr);
		syscallp = GET_SYSCALLP(&pidp->scallhash, syscall_id);
		tstatp = &syscallp->sched_stats;
		old_state = tstatp->state;
		tstatp->state = RUNNING | SYS;

		delta = update_sched_time(tstatp, hrtime);
		winki_update_sched_state(tstatp, old_state, tstatp->state, delta);

		if (sleep_stats) winki_update_slp_info(pidp, &syscallp->slp_hash, stkinfop, delta, 0);
	}	

	if (global_stats) {
		gschedp = GET_ADD_SCHEDP(&globals->schedp);
		if (sleep_stats) winki_update_slp_info(pidp, &globals->slp_hash, stkinfop, delta, 0);
		if (stktrc_stats) winki_update_stktrc_info(pidp, &globals->stktrc_hash, stkinfop, delta, 1);
	}

	/* reset for the next sleep */
	pidp->last_sleep_delta = 0;
}

static inline int
cpu_cswitch_stats(int cpu, Cswitch_t *p, pid_info_t *tpidp)
{
	cpu_info_t *cpuinfop;
        sched_info_t *schedp, *pschedp;
        sched_stats_t *statp, *pstatp;
        int old_state;
        uint64 delta, hrtime;

	hrtime = CONVERT_WIN_TIME(p->TimeStamp);
	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
	statp = &schedp->sched_stats;

	if ((p->OldThreadId == 0) && (statp->state == UNKNOWN)) {
		old_state = IDLE;
	} else {
		old_state = statp->state;
	}

        if (p->NewThreadId) {
                /* need to inherit SYS | USER field from target pid */
                pschedp = (sched_info_t *)find_sched_info(tpidp);
                pstatp = &schedp->sched_stats;
                statp->state = RUNNING | (pstatp->state & (USER | SYS));
        } else {
                statp->state = IDLE;
        }

	delta = update_sched_time(statp, hrtime);
	winki_update_sched_state(statp, old_state, statp->state, delta);

	return 0;	
}

int
print_thread_cswitch_func (trace_info_t *trcinfop, pid_info_t *pidp, pid_info_t *tpidp, winki_stack_info_t *stkinfop)
{
        Cswitch_t *p = (Cswitch_t *)trcinfop->cur_event;
        uint64 *s;

	PRINT_COMMON_FIELDS_C011(p, p->OldThreadId , pidp->tgid);

        printf (" target_tid=%d target_pid=%d", p->NewThreadId, tpidp->tgid);
        printf (" oldpri=%d newpri=%d", p->NewThreadPriority, p->OldThreadPriority);
        printf (" prev_cstate=%d wait_reason=%s",
                p->PreviousCstate,
                win_thread_wait_reason[p->OldThreadWaitReason]);

	if (p->OldThreadWaitMode < MaxThreadWaitMode) {
		printf (" wait_mode=%s", win_thread_mode[p->OldThreadWaitMode]);
	} else {
		printf (" wait_mode=%d", p->OldThreadWaitMode);
	}

        printf (" state=%s ideal_cpu=%d new_thread_waittime=%d",
                win_thread_state[p->OldThreadState],
                p->OldThreadWaitIdealProcessor,
                p->NewThreadWaitTime);

	printf (" StackTrace: ");
	PRINT_WIN_STKTRC2(tpidp, stkinfop);
        printf ("\n");

        if (debug) hex_dump(p, 6);
}

int
thread_cswitch_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        Cswitch_t *p = (Cswitch_t *)trcinfop->cur_event;
        StackWalk_t *stk = NULL;
        pid_info_t *tpidp, *pidp, *tgidp, *ttgidp;
	int tid = 0, pid = 0;
	winki_stack_info_t stkinfo;
	

        /* we have to peak to see if the next event for the buffer it a StackWalk event */
        /* However, if we are at the end of the buffer, we need to move to the next one */
        if (trcinfop->next_event == (char *)GETNEWBUF) {
                get_new_buffer(trcinfop, trcinfop->cpu);
        }
        stk = (StackWalk_t *)trcinfop->next_event;
	stkinfo.depth = 0;
        if (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820)) {
                tid = stk->StackThread;
                pid = stk->StackProcess;
                update_pid_ids(tid, pid);
		trcinfop->pid = tid; 

		winki_save_stktrc(trcinfop, stk, &stkinfo.Stack[0]);
        }

        tpidp = GET_PIDP(&globals->pid_hash, p->NewThreadId);
        pidp = GET_PIDP(&globals->pid_hash, p->OldThreadId);

	if (p->OldThreadState != DeferredReady) { 
		if (idle_stats) winki_idle_timing_swtch(trcinfop->cpu, p->OldThreadId, p->NewThreadId, p->TimeStamp);
		if (percpu_stats) cpu_cswitch_stats(trcinfop->cpu, p, tpidp);
		if (perpid_stats) {
			perpid_source_cswitch_stats(trcinfop->cpu, p, pidp);
			perpid_target_cswitch_stats(trcinfop->cpu, p, tpidp, &stkinfo);
		}
		if (global_stats) global_cswitch_stats(p->OldThreadState);
		if (globals->HT_enabled && ht_stats) {
			HT_switch_stats(trcinfop->cpu, CONVERT_WIN_TIME(p->TimeStamp), CONVERT_WIN_TIME(winki_start_time), 
					p->OldThreadId, p->NewThreadId);
		}
	}
	
	if (kitrace_flag) print_thread_cswitch_func (trcinfop, pidp, tpidp, &stkinfo);

        trcinfop->pid = p->NewThreadId;
}

int
print_thread_group1_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        Thread_TypeGroup1_v3_t *p = (Thread_TypeGroup1_v3_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C002(p);
        update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 

        printf (" StackBase=0x%llx StackLimit=0x%llx UserStackBase=0x%llx UserStackLimit=0x%llx Affinity=0x%x",
                p->StackBase,
                p->StackLimit,
                p->UserStackBase,
                p->UserStackLimit,
                p->Affinity);

        printf (" Win32StartAddr=0x%llx TebBase=0x%llx SubProcessTag=0x%x BasePri=%d PagePri=%d IoPri=%d Flags=0x%x",
                p->Win32StartAddr,
                p->TebBase,
                p->SubProcessTag,
                p->BasePriority,
                p->PagePriority,
                p->IoPriority,
                p->ThreadFlags);

        printf ("\n");

        if (debug) hex_dump(p, 4);
}

int
print_thread_readythread_func (void *a, ReadyThread_t *p, pid_info_t *pidp, pid_info_t *tpidp, winki_stack_info_t *stkinfop) 
{
        trace_info_t *trcinfop = (trace_info_t *)a;

        PRINT_COMMON_FIELDS_C011(p, pidp->PID, pidp->tgid);

        printf (" target_tid=%d target_pid=%d adjreason=%d adjincr=%d flag=%x",
                p->TThreadId,
                tpidp->tgid,
                p->AdjustReason,
                p->AdjustIncrement,
                p->Flag);

	printf (" StackTrace: ");
	PRINT_WIN_STKTRC2(tpidp, stkinfop);

        printf ("\n");
}

int
check_for_tcp_timeouts(pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
	int i, cnt=0;
	char *symptr=NULL;

	for (i=0; i < stkinfop->depth; i++) {
		if (symptr = get_win_sym(stkinfop->Stack[i], pidp)) {
			if (strncmp(symptr, "TcpPeriodicTimeoutHandler", 25) == 0) cnt++;
			if (strncmp(symptr, "TcpCompleteClientReceiveRequest", 31) == 0) cnt++;
		}
	}

	return ((cnt > 1) ? 1 : 0);
}	

int
thread_readythread_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        ReadyThread_t *p = (ReadyThread_t *)trcinfop->cur_event;
        pid_info_t *pidp = NULL, *tpidp = NULL, *tgidp = NULL, *syspidp; 
        sched_info_t *schedp, *tschedp, *gschedp;
        sched_stats_t *statp, *tstatp, *sstatp, *fd_sstatp;
        syscall_info_t *tsyscallp;
	win_syscall_save_t *entry;
        StackWalk_t *stk = NULL;
        uint32 pid=0, tid=0;
	int old_state, new_state, coop_old_state;
	uint64 delta = 0, coop_delta = 0, hrtime;
        uint64 *s;
	short syscall_id;
	winki_stack_info_t stkinfo;

        /* we have to peak to see if the next event for the buffer it a StackWalk event */
        /* However, if we are at the end of the buffer, we need to move to the next one */
        if (trcinfop->next_event == (char *)GETNEWBUF) {
                get_new_buffer(trcinfop, trcinfop->cpu);
        }

	hrtime = CONVERT_WIN_TIME(p->TimeStamp);

        stk = (StackWalk_t *)trcinfop->next_event;
	stkinfo.depth = 0;

        if (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820)) {
                tid = stk->StackThread;
                pid = stk->StackProcess;
                update_pid_ids(tid, pid);
		trcinfop->pid = tid; 

		winki_save_stktrc(trcinfop, stk, &stkinfo);
        }

        pidp = GET_PIDP(&globals->pid_hash, tid);

        tpidp = GET_PIDP(&globals->pid_hash, p->TThreadId);
	tschedp = (sched_info_t *)find_sched_info(tpidp);
	tstatp = &tschedp->sched_stats;
	old_state = coop_old_state = tstatp->state;
	delta = coop_delta = update_sched_time(tstatp, hrtime); 
	tpidp->last_sleep_delta = delta;

	/* update Source PID stats */
	if (perpid_stats) {
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		statp->C_wakeup_cnt++;
	}

	if (runq_histogram) {
		sched_rqhist_wakeup(tschedp->cpu, tpidp, old_state, 0); 
	}

	if (global_stats) {
		gschedp = GET_ADD_SCHEDP(&globals->schedp);
		winki_update_sched_state(gschedp, SWTCH, RUNQ, delta);
	}

	/* update Target PID stats */
	if (perpid_stats && ((tstatp->state & RUNNING) == 0)) {
		tstatp->C_setrq_cnt++;
		new_state = RUNQ | (old_state & (USER | SYS));
		/* printf ("readythread: PID: %d old_state: 0x%x new_state: 0x%x  delta: %9.6f\n", tpidp->PID, old_state, new_state, SECS(delta)); */
		winki_update_sched_state(tstatp, old_state, new_state, delta);
			
		entry = (win_syscall_save_t *) tpidp->win_active_syscalls;
		if (scall_stats && entry) {
			syscall_id = syscall_addr_to_id(entry->addr);
			tsyscallp = GET_SYSCALLP(&tpidp->scallhash, syscall_id);
			tstatp = &tsyscallp->sched_stats;
			old_state = tstatp->state;
			tstatp-> state = RUNQ | SYS;

	               	delta = update_sched_time(tstatp, hrtime);
                	winki_update_sched_state(tstatp, old_state, tstatp->state, delta);
		}
	}

	if (coop_stats && (p->TThreadId != tid)) {
		if (schedp && p->TThreadId) {
			incr_setrq_stats((setrq_info_t ***)&schedp->setrq_tgt_hash, p->TThreadId, 
					coop_old_state, coop_delta);
			/* update_coop_stats(schedp, tschedp, pidp, tpidp, coop_delta, coop_old_state, WAKER); */
		}
		if (tschedp)  {
			incr_setrq_stats((setrq_info_t ***)&tschedp->setrq_src_hash, tid,
					coop_old_state, coop_delta);
			/* update_coop_stats(schedp, tschedp, pidp, tpidp, coop_delta, coop_old_state, SLEEPER); */
		}
	}

	if (kparse_flag && stkinfo.depth) {
	       	if (check_for_tcp_timeouts(pidp, &stkinfo)) {
			if (debug) printf ("TCP Timeout Detected - delay= %12.6f\n ", SECS(delta));
			globals->num_tcp_timeouts++;
			globals->tcp_timeout_time += delta;
		}
        }

	if (kitrace_flag) print_thread_readythread_func(trcinfop, p, pidp, tpidp, &stkinfo);
}



int
print_thread_setname_func (trace_info_t *trcinfop, void *v)
{
        ThreadName_t *p = (ThreadName_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, p->Tid, p->Pid);
        printf (" threadname=");
        PRINT_WIN_FILENAME(&p->ThreadName[0]);
        printf ("\n");

        if (debug)  hex_dump(p, 2);
}

int
thread_setname_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        ThreadName_t *p = (ThreadName_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	uint16 *chr;

        update_pid_ids(p->Tid, p->Pid);
	trcinfop->pid = p->Tid; 
	pidp = GET_PIDP(&globals->pid_hash, p->Tid);

	chr = &p->ThreadName[0];
	PRINT_WIN_NAME2_STR(util_str, chr);
	add_command (&pidp->thread_cmd, util_str);

	if (kitrace_flag) print_thread_setname_func(a, v);
}


int
print_thread_autoboost_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        ThreadAutoBoost_t *p = (ThreadAutoBoost_t *)trcinfop->cur_event;
        pid_info_t *pidp;

        pidp = GET_PIDP(&globals->pid_hash, p->Tid);
        PRINT_COMMON_FIELDS_C011(p, p->Tid, pidp->tgid);

        printf (" addr=0x%llx value=%d",
                p->Addr,
                p->Value);

        printf ("\n");

        if (debug)  hex_dump(p, 2);

}

