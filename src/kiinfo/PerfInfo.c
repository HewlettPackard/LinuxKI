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

static inline int
profile_get_cpu_state(uint64 ip, pid_info_t *pidp) 
{
	/*MCR - Need to improve this to see if we can tell if the CPU is in USER or SYS code **/
	if (pidp->PID == 0) {
		return HC_IDLE;
	} else if (WINKERN_ADDR(ip)) {
		return HC_SYS;
	} else {
		return HC_USER;
	}
}

static inline int
collect_profile_stk(pid_info_t *pidp, hc_info_t *hcinfop, winki_stack_info_t *stkinfop, int state, int sys_only)
{
	stktrc_info_t *stktrcp;
	uint64 ip, key;
	uint64 stktrc[LEGACY_STACK_DEPTH];
	uint64 cnt;
	int len, i;
	uint64 symaddr = 0;
	char *symptr;
	vtxt_preg_t *pregp = NULL;

	if (stkinfop->depth == 0) return 0;
	if (cluster_flag) return 0;
	if (state == HC_IDLE) return 0;

	cnt = MIN(stkinfop->depth, LEGACY_STACK_DEPTH);

	/* Get the start of each function for profile stk traces */
	for (i = 0; i < cnt; i++) {
		ip = stkinfop->Stack[i];
		if (sys_only && !WINKERN_ADDR(ip)) break;
		if (pregp = get_win_pregp(ip, pidp)) {
			symptr = win_symlookup(pregp, ip, &symaddr);
			if (symptr == NULL) {
				ip = pregp->p_vaddr;
			} else {
				ip = pregp->p_vaddr + symaddr;
			}
		}
		stktrc[i] = ip;
	}

	cnt = i;

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


static inline int
collect_profile_info(uint64 ip, pid_info_t *pidp, hc_info_t *hcinfop, int state)
{
	pc_info_t *pcinfop;
	uint64 symaddr = 0;
	char *symptr;
	vtxt_preg_t *pregp = NULL;
	uint64 key = ip;

	if (pregp = get_win_pregp(ip, pidp)) {
		symptr = win_symlookup(pregp, ip, &symaddr);
		if (symptr == NULL) {
			key = pregp->p_vaddr;
		} else {
			key = pregp->p_vaddr + symaddr;
		}
	/* printf ("collect_profile__info() preg_vaddr: 0x%llx  symaddr: 0x%llx pc: 0x%llx symptr: %s\n", pregp->p_vaddr, symaddr, ip, symptr); */
	}
	
	pcinfop = GET_PCINFOP(&hcinfop->pc_hash, key);
	pcinfop->state = state;
	pcinfop->count++;
	pcinfop->pregp = pregp;
}
	

static inline int
profile_global_stats(SampleProfile_t *p, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
	hc_info_t *hcinfop;
	sched_info_t *schedp;
	int state;
	uint64 ip = p->InstructionPointer;

	hcinfop = GET_HCINFOP(globals->hcinfop);
	char *symptr;

	state = profile_get_cpu_state(ip, pidp);
	hcinfop->total++;
	hcinfop->cpustate[state]++;

	if (!WINKERN_ADDR(ip)) ip = UNKNOWN_SYMIDX;
	
	collect_profile_info(ip, pidp, hcinfop, state);
	if (state == HC_SYS) collect_profile_stk(pidp, hcinfop, stkinfop, state, 1);
}

static inline int
profile_percpu_stats(SampleProfile_t *p, pid_info_t *pidp, int cpu, winki_stack_info_t *stkinfop)
{
	cpu_info_t *cpuinfop;
	hc_info_t *hcinfop;
	sched_info_t *schedp;
	int state;
	uint64 ip = p->InstructionPointer;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);	
	hcinfop = GET_HCINFOP(cpuinfop->hcinfop);

	state = profile_get_cpu_state(ip, pidp);
	hcinfop->total++;
	hcinfop->cpustate[state]++;

	if (!WINKERN_ADDR(ip)) ip = UNKNOWN_SYMIDX;
	
	collect_profile_info(ip, pidp, hcinfop, state);
	if (state == HC_SYS) collect_profile_stk(pidp, hcinfop, stkinfop, state, 1);
}

static inline int
profile_perpid_stats(SampleProfile_t *p, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
	hc_info_t *hcinfop;
	sched_info_t *schedp;
	int state;
	uint64 ip = p->InstructionPointer;

	hcinfop = GET_HCINFOP(pidp->hcinfop);

	state = profile_get_cpu_state(ip, pidp);
	hcinfop->total++;
	hcinfop->cpustate[state]++;

	collect_profile_info(ip, pidp , hcinfop, state);
	collect_profile_stk(pidp, hcinfop, stkinfop, state, 0);

	if (sched_flag) {
		schedp = find_sched_info(pidp);
		hc_update_sched_state(schedp, state, CONVERT_WIN_TIME(p->TimeStamp)); 
	}
}

int
print_perfinfo_profile_func(trace_info_t *trcinfop, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
        SampleProfile_t *p = (SampleProfile_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, pidp->PID, pidp->tgid);

        printf (" addr=");
        print_win_sym(p->InstructionPointer, pidp);

        printf (" count=0x%llx", p->Count);

	if (stkinfop->depth) {
		printf (" Stacktrace: ");
        	PRINT_WIN_STKTRC2(pidp, stkinfop);
	}

        printf ("\n");

        if (debug) hex_dump(p, 6);
}

int
perfinfo_profile_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        SampleProfile_t *p = (SampleProfile_t *)trcinfop->cur_event;
        pid_info_t *pidp, *tgidp;
        StackWalk_t *stk = NULL;
	int stklen=0;
	winki_stack_info_t stkinfo;

        /* we have to peak to see if the next event for the buffer it a StackWalk event */
        /* However, if we are at the end of the buffer, we need to move to the next one */
        if (trcinfop->next_event == (char *)GETNEWBUF) {
                get_new_buffer(trcinfop, trcinfop->cpu);
        }

        pidp = GET_PIDP(&globals->pid_hash, p->ThreadId);
        stk = (StackWalk_t *)trcinfop->next_event;
	stkinfo.depth = 0;

        if (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820)) {
                update_pid_ids(stk->StackThread, stk->StackProcess);
		trcinfop->pid = stk->StackThread;

		winki_save_stktrc(trcinfop, stk, &stkinfo);
	}

	if (global_stats) profile_global_stats(p, pidp, &stkinfo);
	if (percpu_stats) profile_percpu_stats(p, pidp, trcinfop->cpu, &stkinfo);
	if (perpid_stats) profile_perpid_stats(p, pidp, &stkinfo);

	if (kitrace_flag) print_perfinfo_profile_func(trcinfop, pidp, &stkinfo);
}

int
print_perfinfo_isr_func (trace_info_t *trcinfop, pid_info_t *pidp)
{
        ISR_t *p = (ISR_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, -1 , -1);

        printf (" addr=");
        printf ("0x%llx ", p->Routine);
        print_win_sym(p->Routine, pidp);

        printf (" vec=%d ret=%d",
                p->Vector,
                p->ReturnValue);

        printf (" starttime=");
        PRINT_TIME(p->InitialTime);
        printf (" elptime=");
        PRINT_TIME_DIFF(p->InitialTime, p->TimeStamp);

        printf ("\n");

        if (debug) hex_dump(p, 2);
}

int
perfinfo_isr_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        ISR_t *p = (ISR_t *)trcinfop->cur_event;
        pid_info_t *pidp;
	vtxt_preg_t *pregp = NULL;
	irq_name_t *irqnamep;
	char *symptr;
	uint64 symaddr;
	int vec;

	vec = p->Vector;
        pidp = GET_PIDP(&globals->pid_hash, 0);

	pregp = get_win_pregp(p->Routine, pidp);
	if (pregp) symptr = win_symlookup(pregp, p->Routine, &symaddr);

	/* WinKI doesn't have ISR entry functions, so we need to take this into account */
	if (perirq_stats) {
		irqnamep = GET_IRQNAMEP(&globals->irqname_hash, vec);
		/* Lookup ISR name from address */

		if (irqnamep->name == NULL) {
			if (symptr) {
				add_command(&irqnamep->name, symptr);
			} else {
				sprintf (util_str, "0x%llx", p->Routine);	
				add_command(&irqnamep->name, util_str);
			}
		}
	}

	irq_entry_update_stats(CONVERT_WIN_TIME(p->InitialTime), trcinfop->cpu, trcinfop->pid, vec, HARDIRQ);
		
	irq_exit_update_stats(CONVERT_WIN_TIME(p->TimeStamp), trcinfop->cpu, trcinfop->pid, vec, HARDIRQ);

	if (kitrace_flag) print_perfinfo_isr_func(trcinfop, pidp);
}

int
print_perfinfo_dpc_func (trace_info_t *trcinfop, pid_info_t *pidp)
{
        DPC_t *p = (DPC_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, -1 , -1);

        printf (" addr=");
        printf ("0x%llx ", p->Routine);
        print_win_sym(p->Routine, pidp);

        printf (" starttime=");
        PRINT_TIME(p->InitialTime);
        printf (" elptime=");
        PRINT_TIME_DIFF(p->InitialTime, p->TimeStamp);

        printf ("\n");

        if (debug) hex_dump(p, 2);
}

int
perfinfo_dpc_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        DPC_t *p = (DPC_t *)trcinfop->cur_event;
        pid_info_t *pidp;
	cpu_info_t *cpuinfop;
	vtxt_preg_t *pregp = NULL;
	irq_name_t *irqnamep;
	char *symptr = NULL;
	uint64 symaddr;
	int vec;
	
	/* DPC recs do not have a IRQ Vector like SoftIRQs, so invent one */
	vec = dpc_addr_to_idx(p->Routine);

        pidp = GET_PIDP(&globals->pid_hash, 0);
	cpuinfop = GET_CPUP(&globals->cpu_hash, trcinfop->cpu);

	pregp = get_win_pregp(p->Routine, pidp);
	if (pregp) symptr = win_symlookup(pregp, p->Routine, &symaddr);

	/* printf ("addr: 0x%llx   sym: %s\n", p->Routine, symptr); */

	/* WinKI doesn't have ISR entry functions, so we need to take this into account */
	if (perirq_stats) {
		irqnamep = GET_IRQNAMEP(&globals->dpcname_hash, vec);
		/* Lookup ISR name from address */

		if (irqnamep->name == NULL) {
			if (symptr) {
				add_command(&irqnamep->name, symptr);
			} else {
				sprintf (util_str, "0x%llx", p->Routine);	
				add_command(&irqnamep->name, util_str);
			}
		}
	}

	irq_entry_update_stats(CONVERT_WIN_TIME(p->InitialTime), trcinfop->cpu, trcinfop->pid, vec, SOFTIRQ);
		
	irq_exit_update_stats(CONVERT_WIN_TIME(p->TimeStamp), trcinfop->cpu, trcinfop->pid, vec, SOFTIRQ);
	if (kitrace_flag) print_perfinfo_dpc_func (trcinfop, pidp);

	cpuinfop->last_softirq_vec = 0;
	cpuinfop->last_softirq_time = 0;
}


int
print_perfinfo_interval_func (trace_info_t *trcinfop)
{
	Interval_t *p = (Interval_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C002(p);

        printf (" src=%d oldinterval=%d newinterval=%d",
                p->ProfileSource,
                p->OldInterval,
                p->NewInterval);

        printf (" name=\"");
        PRINT_WIN_FILENAME(&p->SourceName[0]);
        printf ("\"\n");

        if (debug) hex_dump(p, 2);
}


int
perfinfo_interval_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	Interval_t *p = (Interval_t *)trcinfop->cur_event;

	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 

	if (kitrace_flag) print_perfinfo_interval_func (trcinfop);
}


int
print_perfinfo_sysclenter_func(trace_info_t *trcinfop, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
	SysClEnter_t *p = (SysClEnter_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, pidp->PID , pidp->tgid);

	printf (" addr=");
	print_win_sym(p->SysCallAddress, pidp);

	if (stkinfop->depth) {
		printf (" Stacktrace: ");
		PRINT_WIN_STKTRC2(pidp, stkinfop);
	}

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

int
perfinfo_sysclenter_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        SysClEnter_t *p = (SysClEnter_t *)trcinfop->cur_event;
        StackWalk_t *stk = NULL;
        pid_info_t *pidp, *tgidp = NULL;
	cpu_info_t *cpuinfop;
	sched_info_t *schedp;
	sched_stats_t *statp;
	syscall_info_t *syscallp;
	int old_state, new_state;
	uint64 delta, hrtime;
	short syscall_id;
	winki_stack_info_t stkinfo;

        /* we have to peak to see if the next event for the buffer it a StackWalk event */
        /* However, if we are at the end of the buffer, we need to move to the next one */
        if (trcinfop->next_event == (char *)GETNEWBUF) {
                get_new_buffer(trcinfop, trcinfop->cpu);
        }

	hrtime = CONVERT_WIN_TIME(p->TimeStamp);

        pidp = GET_PIDP(&globals->pid_hash, trcinfop->pid);
        stk = (StackWalk_t *)trcinfop->next_event;
	stkinfo.depth = 0;

        if (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820)) {
		update_pid_ids(stk->StackThread, stk->StackProcess);
		trcinfop->pid = stk->StackThread;

		winki_save_stktrc(trcinfop, trcinfop->next_event, &stkinfo);
	}

	if ((pidp->tgid) && (pidp->PID != pidp->tgid)) {
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
	} else {
		tgidp = pidp;
	}

	push_win_syscall(pidp, p->SysCallAddress, p->TimeStamp);

	if (perpid_stats) {
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		
		old_state = statp->state;
		new_state = RUNNING | SYS;

		/* update state of current PID */
		delta = update_sched_time(statp, hrtime);
		winki_update_sched_state(statp, old_state, new_state, delta);
        	update_sched_cpu(schedp, trcinfop->cpu);

		if (scall_stats) {
			syscall_id = syscall_addr_to_id(p->SysCallAddress);
			
			syscallp = GET_SYSCALLP(&pidp->scallhash, syscall_id);
			delta = update_sched_time(&syscallp->sched_stats, hrtime);
			winki_update_sched_state(&syscallp->sched_stats, old_state, new_state, 0);
		}
	}

	if (percpu_stats) {
		cpuinfop = GET_CPUP(&globals->cpu_hash, trcinfop->cpu);
		schedp = GET_ADD_SCHEDP(&cpuinfop->schedp); 
		statp = &schedp->sched_stats;
		
		old_state = statp->state;
		new_state = RUNNING | SYS;

		/* update state of current PID */
		delta = update_sched_time(statp, hrtime);
		winki_update_sched_state(statp, old_state, new_state, delta);
	}


	if (kitrace_flag) print_perfinfo_sysclenter_func (trcinfop, pidp, &stkinfo);
}

int
print_perfinfo_sysclexit_func(trace_info_t *trcinfop, pid_info_t *pidp, uint64 addr, uint64 win_starttime)
{
        SysClExit_t *p = (SysClExit_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, trcinfop->pid, pidp->tgid);

	printf (" ret=0x%x", p->SysCallNtStatus);

	if (addr && win_starttime) {
		printf (" addr=");
		print_win_sym(addr, pidp);
		printf (" elptime=");
		PRINT_TIME_DIFF(win_starttime, p->TimeStamp);
	}

	printf ("\n");

	if (debug) hex_dump(p, 1);
}

int
perfinfo_sysclexit_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        SysClExit_t *p = (SysClExit_t *)trcinfop->cur_event;
        pid_info_t *pidp;
	cpu_info_t *cpuinfop;
        uint64 addr=0;
        uint64 win_starttime=0, starttime=0, hrtime;
	sched_info_t *schedp;
	sched_stats_t *statp;
	syscall_info_t *syscallp;
	int old_state, new_state;
	uint64 delta, elptime;
	uint64 syscall_id;

	pidp = GET_PIDP(&globals->pid_hash, trcinfop->pid);

	/* I haven't quite figured out how to handing nested system calls yet.   Here, we 
	 * could have some really long system call values.  
	 */
	pop_win_syscall(pidp, &addr, &win_starttime);
	starttime = CONVERT_WIN_TIME(win_starttime);
	hrtime = CONVERT_WIN_TIME(p->TimeStamp);

	if (perpid_stats) {
		schedp = (sched_info_t *)find_sched_info(pidp);
		statp = &schedp->sched_stats;
		
		old_state = statp->state;
		new_state = RUNNING | USER;

		/* update state of current PID */
		delta = update_sched_time(statp, hrtime);
		winki_update_sched_state(statp, old_state, new_state, delta);
        	update_sched_cpu(schedp, trcinfop->cpu);

		pidp->syscall_cnt++;
		if (scall_stats) {
			syscall_id = syscall_addr_to_id(addr);
			
			syscallp = GET_SYSCALLP(&pidp->scallhash, syscall_id);
			delta = update_sched_time(&syscallp->sched_stats, hrtime);
			winki_update_sched_state(&syscallp->sched_stats, old_state, new_state, delta);
			if (starttime != 0) {
				elptime = hrtime - starttime;
				incr_syscall_stats(&syscallp->stats, p->SysCallNtStatus, elptime, 0);
			}
		}
	}

	if (percpu_stats) {
		cpuinfop = GET_CPUP(&globals->cpu_hash, trcinfop->cpu);
		schedp = GET_ADD_SCHEDP(&cpuinfop->schedp); 
		statp = &schedp->sched_stats;
		
		old_state = statp->state;
		new_state = RUNNING | USER;

		/* update state of current PID */
		delta = update_sched_time(statp, hrtime);
		winki_update_sched_state(statp, old_state, new_state, delta);
	}

	if (kitrace_flag) print_perfinfo_sysclexit_func(trcinfop, pidp, addr, win_starttime);
}
