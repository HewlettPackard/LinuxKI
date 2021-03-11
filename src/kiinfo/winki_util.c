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
#include "Pdb.h"

extern int trace_winki_header_func(void *, void *);

int
winki_header_func (void *a, void *v)
{
        trace_winki_header_func(a, v);

        ki_actions[0].execute = 0;
}

void
winki_update_sched_state(void *arg, int old_state, int new_state, uint64 delta)
{
        sched_stats_t *statp = arg;

	if (debug) printf ("statp: 0x%llx old_state: 0x%x new_state: 0x%x delta: %lld  ", statp, old_state, new_state, delta); 
	if (debug) printf ("RunTime: %12.6f  UserTime: %12.6f  SysTime: %12.6f  IdleTime: %12.6f \n",
			SECS(statp->T_run_time), SECS(statp->T_user_time), SECS(statp->T_sys_time), SECS(statp->T_idle_time));

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
	if (debug) printf ("\n");
}

static int last_syscall_idx = 0;

short 
syscall_addr_to_id(uint64 ip)
{
	addr_to_idx_hash_entry_t *syscall_hash_entryp;
	pid_info_t *syspidp;
	short idx;
	int i;
	char *name;

	if (ip == 0ull) return 0;

	syscall_hash_entryp = (addr_to_idx_hash_entry_t *)GET_ADDR_TO_IDX_HASH_ENTRYP(&globals->win_syscall_hash, ip);
	if (syscall_hash_entryp->idx == 0) {
		syspidp = GET_PIDP(&globals->pid_hash, 0);
		name = get_win_sym(ip, syspidp);
		if (name == NULL) { 
			return 0;
		}	
		idx = (last_syscall_idx++);
		syscall_hash_entryp->idx = idx;
		globals->syscall_index_64[idx] = idx;
		win_syscall_arg_list[idx].name = name;
		win_syscall_arg_list[idx].retval.label = "ret";
		win_syscall_arg_list[idx].retval.format = HEX;
		for (i = 0; i < MAXARGS; i++) {
			win_syscall_arg_list[idx].args[i].label=NULL;
			win_syscall_arg_list[idx].args[i].format=SKIP;
		}
		/* printf ("syscall_addr_to_id():   ip: 0x%llx  name %s   id: %d\n",
			ip, win_syscall_arg_list[idx].name, idx); */
	}

	return syscall_hash_entryp->idx;
}

static int last_dpc_idx = 0;

int 
dpc_addr_to_idx(uint64 ip)
{
	addr_to_idx_hash_entry_t *dpc_hash_entryp;
	pid_info_t *syspidp;
	short idx;
	int i;
	char *name;

	if (ip == 0ull) return 0;

	dpc_hash_entryp = (addr_to_idx_hash_entry_t *)GET_ADDR_TO_IDX_HASH_ENTRYP(&globals->win_dpc_hash, ip);
	if (dpc_hash_entryp->idx == 0) {
		idx = (last_dpc_idx++);
		dpc_hash_entryp->idx = idx;
	}

	return dpc_hash_entryp->idx;
}
