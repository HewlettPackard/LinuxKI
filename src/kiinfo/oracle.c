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
#include <err.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "globals.h"
#include "kd_types.h"
#include "info.h"
#include "oracle.h"
#include "hash.h"
#include "sort.h"

char *oracle_proc[NORACLE] = {
   "ora_lg",
   "ora_arc",
   "ora_dbw",
   "ora_i",
   "ora_p",
   "ora_s",
   "ora_j",
   "ora_d0",
   "ora_ckpt",
   "ora_pmon",
   "ora_smon",
   "ora_reco",
   "ora_ukn",
   "ora_ukn",
   "other",
   "oracle"
};

char *oracle_procname[NORACLE] = {
    "Oracle Log Writer",
    "Oracle Archive Processes",
    "Oracle DB Writers",
    "Oracle Parallel Writers",
    "Oracle Parallel Query Processes",
    "Oracle Shared Server Processes",
    "Oracle Job Queue Processes",
    "Oracle Dispatcher Processes",
    "Oracle Checkpoint Process",
    "Oracle Process Monitor Process",
    "Oracle System Monitor Process",
    "Oracle Recoverer Process",
    "Oracle Unknown Processes",
    "Oracle Unknown Processes",
    "Other Oracle Processes",
    "Oracle Shadow Processes"
};

char *oracle_wait_event[ORA_NEVENTS] = {
    "None",
    "db file sequential read",
    "log file sync",
    "log file sync (polling)",
    "cursor: pin S wait on X",
    "SQL*Net message from client",
    "SQL*Net message from dblink",
    "enq: TX - row lock contention",
    "DB asynchronous IO",
    "log file switch",
    "buffer busy wait",
    "gc current block",
    "gc current multi block request",
    "latch: cache_buffers chains",
    "latch free: sequence cache",
    "latch: undo global data"
};

int oracle_pid_stats(void *arg1, void *arg2)
{
        sid_pid_t *sidpidp = (sid_pid_t *)arg1;
        ora_stats_t *orastatsp = (ora_stats_t *)arg2;
        pid_info_t *pidp = sidpidp->pidinfop;
	sched_info_t *schedp;

	if (pidp == NULL) return 0;
	schedp = (sched_info_t *)pidp->schedp;

        orastatsp->pid_cnt++;
	if (pidp->schedp) {
		orastatsp->run_time += schedp->sched_stats.T_run_time;
		orastatsp->runq_time += schedp->sched_stats.T_runq_time;
		orastatsp->sched_policy = schedp->policy;
	}

	sum_iostats(&pidp->iostats, &orastatsp->iostats);

        return 0;
}

int 
get_oracle_wait_event(void *arg, unsigned long *stktrc, unsigned int depth)
{
	pid_info_t *pidp = (pid_info_t *)arg;
	int i;
	int is_user = ORA_NONE;
	char *sym;
	char skt_read=FALSE, ntwk_read=FALSE, ntwk_poll=FALSE, shrd_exam=FALSE, nanoslp=FALSE, latch_free=FALSE;
	char shared_latch=FALSE;

        if (depth == 0) return ORA_NONE;
	if (pidp->ora_sid == -1) return ORA_NONE;

        for (i=0; i < depth; i++) {
		sym = NULL;
                switch (stktrc[i]) {
                        case END_STACK: continue;
                        case STACK_CONTEXT_KERNEL:     is_user = 0; continue;
                        case STACK_CONTEXT_USER:
                                is_user = 1;
                                continue;
                }

                if (is_user) {
                        if (sym = get_user_sym(stktrc[i], pidp)) {
				if (strncmp(sym, "kgxSharedExamine", 16) == 0) {
					shrd_exam = TRUE;
				} else if (strncmp(sym, "snttread", 8) == 0) {
					skt_read = TRUE;
				} else if (strncmp(sym, "nanosleep", 9) == 0) {
					nanoslp = TRUE;
				} else if (strncmp(sym, "epoll_wait", 9) == 0) {
					ntwk_poll = TRUE;
				} else if (strncmp(sym, "kslgetl", 7) == 0) {
					latch_free = TRUE;
				} else if (strncmp(sym, "ksl_get_shared_latch", 20) == 0) {
					shared_latch = TRUE;
				} else if (strncmp(sym, "ksfdread", 8) == 0) {
					return ORA_DB_FILE_SEQ_READ;
				} else if (strncmp(sym, "kcrfws", 6) == 0) {
					return ORA_LOG_FILE_SWITCH;
				} else if (strncmp(sym, "ktuGetTxForXid", 14) == 0) {
					return ORA_ENQ_TX_ROW_LOCK;
				} else if (strncmp(sym, "kcbzwb", 6) == 0) {
					return ORA_BUFFER_BUSY_WAIT;
				} else if (strncmp(sym, "kcbget", 6) == 0) {
					if (shared_latch) return ORA_LATCH_CACHE_BUF;
				} else if (strncmp(sym, "kcbzibmlt", 9) == 0) {
					if (ntwk_poll) return ORA_GC_CUR_MB_READ;
				} else if (strncmp(sym, "kcbzib", 6) == 0) {
					if (ntwk_poll) return ORA_GC_CUR_READ;
				} else if (strncmp(sym, "kcrf_commit_force_int", 21) == 0) {
					if (nanoslp) return ORA_LOG_FILE_SYNC_POLLING;
					else return ORA_LOG_FILE_SYNC_PWWAIT;
				} else if (strncmp(sym, "npixfc", 6) == 0) {
					if (skt_read) return ORA_NET_FROM_DBLINK;
				} else if (strncmp(sym, "ttcdrv", 6) == 0) {
					if (skt_read) return ORA_NET_FROM_DBLINK;
				} else if (strncmp(sym, "opitsk", 6) == 0) {
					if (skt_read) return ORA_NET_FROM_CLIENT;
				} else if (strncmp(sym, "kkscsCheckCursor", 16) == 0) {
					if (shrd_exam) return ORA_CURSOR_PIN_S;
				} else if (strncmp(sym, "kdn", 3) == 0) {
					if (latch_free) return ORA_LATCH_SEQ;
				} else if (strncmp(sym, "ktuisonline1", 12) == 0) {
					if (latch_free) return ORA_LATCH_UNDO;
				}
			}
                } else {
			if (sym = get_kernel_sym(stktrc[i])) {
				if (strncmp(sym, "read_events", 11) == 0) {
					return ORA_DB_ASYNC_IO;
				}
			}
                }

        }

        return 0;
}

void 
update_oracle_wait_event(void *arg, unsigned long delta)
{
	pid_info_t *pidp = (pid_info_t *)arg;
	sid_info_t *sidp;
	ora_wait_info_t *ora_waitp;

	ora_waitp = GET_ORA_WAITINFOP(&pidp->ora_wait_hash, pidp->last_ora_wait);
	/* if (debug) printf(, "PID %d  update_oracle_wait_event %d\n", pidp->PID, ora_waitp->lle.key); */
	ora_waitp->count++;
	ora_waitp->sleep_time += delta;
	ora_waitp->max_time = MAX(delta, ora_waitp->max_time);

	if (pidp->ora_sid >= 0) {
		/* update Oracle SID table */
		sidp = &sid_table[pidp->ora_sid];
		ora_waitp = GET_ORA_WAITINFOP(&sidp->ora_wait_hash, pidp->last_ora_wait);
	        ora_waitp->count++;
       		ora_waitp->sleep_time += delta;
        	ora_waitp->max_time = MAX(delta, ora_waitp->max_time);
	}
	pidp->last_ora_wait = ORA_NONE;
}

int
print_ora_wait_events(void *arg1, void *arg2)
{
        ora_wait_info_t *ora_waitp = (ora_wait_info_t *)arg1;
	FILE *pidfile = (FILE *)arg2;
	uint32 ora_wait_idx = ora_waitp->lle.key;
        pid_printf(pidfile, "%s%8d  %9.3f  %9.3f  %9.3f  %s\n", tab,
                        ora_waitp->count,
                        MSECS(ora_waitp->sleep_time*1.0 / ora_waitp->count),
                        MSECS(ora_waitp->max_time),
                        MSECS(ora_waitp->sleep_time),
                        oracle_wait_event[ora_wait_idx]);
}

void
ora_wait_report(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
        FILE *pidfile = (FILE *)arg2;
        if (pidp->ora_wait_hash == NULL) return;
	pid_printf(pidfile, "\n%s******** COMMON ORACLE WAIT EVENTS ********\n", tab);

        pid_printf(pidfile, "%s   Count  AvgWaitMs  MaxWaitMs  TotWaitMs  WaitEvent\n", tab);
        foreach_hash_entry((void **)pidp->ora_wait_hash, ORA_WAIT_HSIZE, print_ora_wait_events, ora_wait_sort_by_time, nsym, pidfile);

        return;
}

void
sid_wait_report(void *arg1, void *arg2)
{
	sid_info_t *sidp = (sid_info_t *)arg1;

	tab=tab0;
        if (sidp->ora_wait_hash == NULL) return;
	printf("\n%s******** COMMON ORACLE WAIT EVENTS ********\n", tab);

        printf("%s   Count  AvgWaitMs  MaxWaitMs  TotWaitMs  WaitEvent\n", tab);
        foreach_hash_entry((void **)sidp->ora_wait_hash, ORA_WAIT_HSIZE, print_ora_wait_events, ora_wait_sort_by_time, nsym, NULL);

        return;
}

