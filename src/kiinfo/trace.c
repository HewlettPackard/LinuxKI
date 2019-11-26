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
#include <poll.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/kdev_t.h>
#include <linux/in.h>
#include <linux/futex.h>
#include <linux/aio_abi.h>
#include <unistd.h>
#include "ki_tool.h"
#include "liki.h"
#include "liki_extra.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "block.h"
#include "syscalls.h"
#include "sched.h"
#include "power.h"
#include "irq.h"
#include "hardclock.h"
#include "workqueue.h"
#include "scsi.h"
#include "cache.h"
#include "conv.h"

int trace_generic_func(void *, void *);
int trace_ftrace_print_func(void *, void *);
int trace_listen_overflow_func(void *, void *);
int trace_page_fault_user_func(void *, void *);
int trace_page_fault_kernel_func(void *, void *);
int trace_anon_fault_func(void *, void *);
int trace_filemap_fault_func(void *, void *);
int trace_kernel_pagefault_func(void *, void *);
int trace_tasklet_enqueue_func(void *, void *);
int trace_sched_switch_func(void *, void *);
int trace_sched_wakeup_func(void *, void *);
int trace_sched_migrate_task(void *, void *);
int trace_mm_page_alloc_func(void *, void *);
int trace_mm_page_free_func(void *, void *);

static inline void
set_tgid(int pid, int tgid) {
        pid_info_t *pidp;
        pidp = GET_PIDP(&globals->pid_hash, pid);
        if (tgid) pidp->tgid = tgid;
}

int 
check_for_missed_buffer(void *arg1, void *arg2, int next_pid)
{
	trace_info_t *trcinfop = arg1;
	common_t *rec_ptr = arg2;
	int retval = FALSE;

	if (trcinfop->check_flag && (trcinfop->pid != rec_ptr->pid)) {
		if (printmb_flag) {
			printf ("%12.06f%ccpu=%d%cMissed Buffer\n",
				fsep, SECS(rec_ptr->hrtime),
				fsep, rec_ptr->cpu);
		}
		trcinfop->missed_buffers++;
		retval = TRUE;
	}

	trcinfop->pid = next_pid;
	trcinfop->check_flag=1;

	return retval;
}

static inline void
set_trace_funcs()
{
	int i;

	for (i = 0; i < KI_MAXTRACECALLS; i++) {
		ki_actions[i].func = trace_generic_func;
	}

	ki_actions[TRACE_SYS_EXIT].func = trace_sys_exit_func;
	ki_actions[TRACE_SYS_ENTER].func = trace_sys_enter_func;
	ki_actions[TRACE_SCHED_SWITCH].func = trace_sched_switch_func;
	ki_actions[TRACE_SCHED_WAKEUP].func = trace_sched_wakeup_func;
	ki_actions[TRACE_SCHED_WAKEUP_NEW].func = trace_sched_wakeup_func;
	ki_actions[TRACE_SCHED_MIGRATE_TASK].func = trace_sched_migrate_task_func;
	ki_actions[TRACE_BLOCK_RQ_ISSUE].func = block_rq_issue_func;
	ki_actions[TRACE_BLOCK_RQ_INSERT].func = block_rq_insert_func;
	ki_actions[TRACE_BLOCK_RQ_REQUEUE].func = block_rq_requeue_func;
	ki_actions[TRACE_BLOCK_RQ_COMPLETE].func = block_rq_complete_func; 
	ki_actions[TRACE_BLOCK_RQ_ABORT].func = block_rq_abort_func; 
	ki_actions[TRACE_HARDCLOCK].func = hardclock_func;
	if (TRACE_POWER_START) ki_actions[TRACE_POWER_START].func = power_start_func;
	if (TRACE_POWER_END) ki_actions[TRACE_POWER_END].func = power_end_func;
	if (TRACE_POWER_FREQ) ki_actions[TRACE_POWER_FREQ].func = power_freq_func;
	if (TRACE_CPU_FREQ) ki_actions[TRACE_CPU_FREQ].func = cpu_freq_func;
	if (TRACE_CPU_IDLE) ki_actions[TRACE_CPU_IDLE].func = cpu_idle_func;
        ki_actions[TRACE_IRQ_HANDLER_ENTRY].func = irq_handler_entry_func;
        ki_actions[TRACE_IRQ_HANDLER_EXIT].func = irq_handler_exit_func;
        ki_actions[TRACE_SOFTIRQ_ENTRY].func = softirq_entry_func;
        ki_actions[TRACE_SOFTIRQ_EXIT].func = softirq_exit_func;
        ki_actions[TRACE_SOFTIRQ_RAISE].func =  softirq_raise_func;
        ki_actions[TRACE_SCSI_DISPATCH_CMD_START].func = scsi_dispatch_cmd_start_func;
        ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].func = scsi_dispatch_cmd_done_func;
        ki_actions[TRACE_LISTEN_OVERFLOW].func = trace_listen_overflow_func;
	if (IS_LIKI_V4_PLUS) 
		ki_actions[TRACE_WALLTIME].func = trace_startup_func;
	else
        	ki_actions[TRACE_WALLTIME].func = trace_walltime_func;
	if (TRACE_WORKQUEUE_INSERTION) ki_actions[TRACE_WORKQUEUE_INSERTION].func = workqueue_insertion_func;	/* ftrace only */
	if (TRACE_WORKQUEUE_EXECUTION) ki_actions[TRACE_WORKQUEUE_EXECUTION].func = workqueue_execution_func;	/* ftrace only */
	if (TRACE_WORKQUEUE_ENQUEUE) ki_actions[TRACE_WORKQUEUE_ENQUEUE].func = workqueue_enqueue_func;
	if (TRACE_WORKQUEUE_EXECUTE) ki_actions[TRACE_WORKQUEUE_EXECUTE].func = workqueue_execute_func;
	ki_actions[TRACE_TASKLET_ENQUEUE].func = trace_tasklet_enqueue_func;
	ki_actions[TRACE_CACHE_INSERT].func = cache_insert_func;
	ki_actions[TRACE_CACHE_EVICT].func = cache_evict_func;
	if (TRACE_PAGE_FAULT_USER) ki_actions[TRACE_PAGE_FAULT_USER].func = trace_page_fault_user_func;
	if (TRACE_PAGE_FAULT_KERNEL) ki_actions[TRACE_PAGE_FAULT_KERNEL].func = trace_page_fault_kernel_func;
	if (TRACE_ANON_FAULT) ki_actions[TRACE_ANON_FAULT].func = trace_anon_fault_func;
	if (TRACE_FILEMAP_FAULT) ki_actions[TRACE_FILEMAP_FAULT].func = trace_filemap_fault_func;
	if (TRACE_KERNEL_PAGEFAULT) ki_actions[TRACE_KERNEL_PAGEFAULT].func = trace_kernel_pagefault_func;
	if (TRACE_MM_PAGE_ALLOC) ki_actions[TRACE_MM_PAGE_ALLOC].func = trace_mm_page_alloc_func;
	if (TRACE_MM_PAGE_FREE) ki_actions[TRACE_MM_PAGE_FREE].func = trace_mm_page_free_func;
	if (TRACE_MM_PAGE_FREE_DIRECT) ki_actions[TRACE_MM_PAGE_FREE_DIRECT].func = trace_mm_page_free_func;

	ki_actions[TRACE_PRINT].func = trace_ftrace_print_func;
}

/*
 ** The initialization function
 */
void
trace_init_func(void *v)
{
	int i;

	if (debug) printf ("trace_init_func()\n");
        process_func = NULL;
        print_func = trace_print_func;
        report_func = trace_report_func;
        filter_func  = trace_filter_func;
	alarm_func = trace_alarm_func;
        bufmiss_func = NULL;

	set_trace_funcs();

	if (is_alive) {
		if (set_events_options(filter_func_arg) == 0) set_events_default();
	} else if (IS_LIKI || nomarker_flag) {
		set_events_all(1);
	} else {
		/* We will disgard the trace records until the Marker is found */
		set_events_all(0);
		ki_actions[TRACE_PRINT].func = trace_ftrace_print_func;
		ki_actions[TRACE_PRINT].execute = 1;
	}

	parse_kallsyms();

	if (is_alive) {
		 load_objfile_and_shlibs();
	}

	if (timestamp) {
		if (objfile) load_elf(objfile, &objfile_preg);
		parse_pself();
		parse_maps();
		parse_edus();
		parse_jstack();
		parse_lsof();
		if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
	}
}

int
trace_alarm_func(void *v)
{
        struct timeval tod;
        if (print_flag && is_alive) {
                gettimeofday(&tod, NULL);
                printf ("\n%s", ctime(&tod.tv_sec));
                print_flag = 0;
        }
	return 0; 
}

void * 
trace_filter_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	common_t tt_rec_ptr;
        common_t *rec_ptr;
        filter_t *f = v;
        filter_item_t *fi;
        void *ret1;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);
	set_tgid(rec_ptr->pid, rec_ptr->tgid);

        if (!ki_actions[rec_ptr->id].execute) {
		if (debug) printf ("Execute field not set: ki_action[%d]\n", rec_ptr->id);
                return NULL;
        }

        if (rec_ptr->id == TRACE_PRINT) return rec_ptr;
	if (rec_ptr->id == TRACE_WALLTIME) return rec_ptr;
	CHECK_TIME_FILTER(rec_ptr->hrtime);
	ret1 = rec_ptr;

        if (fi = f->f_P_pid) {
                ret1 = NULL;
                while (fi) {
                        if (rec_ptr->pid == fi->fi_item) {
                                return rec_ptr;
                        }
                        fi = fi->fi_next;
                }

		if ((rec_ptr->id == TRACE_SCHED_SWITCH) || (rec_ptr->id == TRACE_SCHED_WAKEUP) || 
		    (rec_ptr->id == TRACE_SCHED_WAKEUP_NEW) || 
		    (rec_ptr->id == TRACE_BLOCK_RQ_ISSUE) || (rec_ptr->id == TRACE_BLOCK_RQ_ABORT) ||
		    (rec_ptr->id == TRACE_BLOCK_RQ_REQUEUE) || (rec_ptr->id == TRACE_BLOCK_RQ_COMPLETE))  {
			return rec_ptr;
		}
        }

        if (fi = f->f_P_tgid) {
		/* the tgid is not valid on LIKI V1 */
		if (!IS_LIKI_V2_PLUS) return rec_ptr;

                ret1 = NULL;
                while (fi) {
                        if (rec_ptr->tgid == fi->fi_item) {
                                return rec_ptr;
                        }
                        fi = fi->fi_next;
                }

		if ((rec_ptr->id == TRACE_SCHED_SWITCH) || (rec_ptr->id == TRACE_SCHED_WAKEUP) || 
		    (rec_ptr->id == TRACE_SCHED_WAKEUP_NEW) || (rec_ptr->id == TRACE_SCHED_MIGRATE_TASK) ||
		    (rec_ptr->id == TRACE_BLOCK_RQ_ISSUE) || (rec_ptr->id == TRACE_BLOCK_RQ_ABORT) ||
		    (rec_ptr->id == TRACE_BLOCK_RQ_REQUEUE) || (rec_ptr->id == TRACE_BLOCK_RQ_COMPLETE)) 
			return rec_ptr;
        }

	if (fi = f->f_dev) {
                ret1 = NULL;
		if ((rec_ptr->id == TRACE_BLOCK_RQ_INSERT) || 
		    (rec_ptr->id == TRACE_BLOCK_RQ_ISSUE) || (rec_ptr->id == TRACE_BLOCK_RQ_ABORT) ||
		    (rec_ptr->id == TRACE_BLOCK_RQ_REQUEUE) || (rec_ptr->id == TRACE_BLOCK_RQ_COMPLETE))  
			return rec_ptr;
        }

	if (fi = f->f_P_cpu) {
                ret1 = NULL;
                while (fi) {
                        if (rec_ptr->cpu == fi->fi_item) {
                                return rec_ptr;
                        }
                        fi = fi->fi_next;
                }
	}

	return ret1;
}

int
trace_process_func(void *a, void *v) 
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	return 0;
}

int
trace_generic_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	common_t tt_rec_ptr;
	common_t *rec_ptr;
	char *ptr;
	event_t *eventp;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);
	PRINT_COMMON_FIELDS(rec_ptr);
	printf (" id=%d", rec_ptr->id);
	PRINT_EVENT(rec_ptr->id);
	
	if (!IS_LIKI) {
		eventp = (event_t *)trcinfop->cur_event;
		ptr = (char *)trcinfop->cur_event + sizeof(kd_rec_t);
		while (ptr < (char *)eventp + get_event_len(eventp)) {
			printf (" 0x%x", *(uint32 *)ptr);
			ptr+=sizeof(uint32);
		}
	}			
	printf ("\n");
}

int
trace_ftrace_print_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
	int i;
	char print_rec = FALSE;
	char flag_changed = 0;
	if (debug) printf ("trace_ftrace_print_func) %s\n", buf);

	if ( strstr(buf, ts_begin_marker)) {
		print_rec = TRUE;
		start_time = trcinfop->cur_time;
        	bufmiss_func = trace_bufmiss_func;
		set_events_all(1);
                start_time = KD_CUR_TIME;
	} else if (strstr(buf, ts_end_marker)) {
		print_rec = TRUE;
		end_time = trcinfop->cur_time;
        	bufmiss_func = NULL;
		set_events_all(0);
	} else if (strstr(buf, "kitrace_marker")) {
		print_rec = FALSE;
	} else {
		print_rec = TRUE;
	}

	if (print_rec) {
		PRINT_KD_REC(rec_ptr);
		PRINT_EVENT(rec_ptr->KD_ID);
		printf (" %s", buf);
	}
}

int
trace_print_func(void *v)
{
        return 0;
}

int
trace_report_func(void *v)
{
        if (debug) printf ("Entering trace_report_func()\n");
        return 0;
}

int
trace_bufmiss_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	char tt_rec_ptr[MAX_REC_LEN];
	sched_switch_t *rec_ptr;
	int old_pid, next_pid;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);
	old_pid = trcinfop->pid;
	if (rec_ptr->id == TRACE_SCHED_SWITCH) {
		rec_ptr = conv_sched_switch(a, &tt_rec_ptr);
		next_pid = rec_ptr->next_pid;
	} else {
		next_pid = rec_ptr->pid;
	}

	check_for_missed_buffer(trcinfop, rec_ptr, next_pid);
        return 0;
}

int
print_anon_fault_rec(void *a)
{
	fault_t *rec_ptr = (fault_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%caddr=%p", fsep, rec_ptr->addr);
	if (rec_ptr->ip) {
		printf ("%cip=", fsep);
		print_user_sym((uint64)rec_ptr->ip, rec_ptr->pid, 0);
	}

	printf ("\n");

	return 0;
}

int
trace_anon_fault_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	fault_t tt_rec_ptr;
	fault_t *rec_ptr;

	if (debug) printf ("trace_anon_fault_func()\n");

	rec_ptr = conv_anon_fault(trcinfop, &tt_rec_ptr);
	print_anon_fault_rec(rec_ptr);

	return 0;
}

int
print_filemap_fault_rec(void *a)
{
	fault_t *rec_ptr = (fault_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%caddr=%p", fsep, rec_ptr->addr);
	if (rec_ptr->ip) {
		printf ("%cip=", fsep);
		print_user_sym((uint64)rec_ptr->ip, rec_ptr->pid, 0);
	}

	printf ("%cflag=%s", fsep, rec_ptr->flag ? "pagein" : "primary_fault");
	printf ("\n");

	return 0;
}

int
trace_filemap_fault_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	fault_t tt_rec_ptr;
	fault_t *rec_ptr;

	if (debug) printf ("trace_filemap_fault_func()\n");

	rec_ptr = conv_filemap_fault(trcinfop, &tt_rec_ptr);
	print_filemap_fault_rec(rec_ptr);
	
	return 0;
}

int
print_mm_page_alloc_rec(void *a)
{
	mm_page_alloc_t *rec_ptr = (mm_page_alloc_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%cpage=0x%llx", fsep, rec_ptr->page);
	printf ("%corder=%d", fsep, rec_ptr->order);
	printf ("%cflags=%s", fsep, gfp_flags_str(rec_ptr->flags));
	printf ("%cmigratetype=0x%x", fsep, rec_ptr->migratetype);

	if (rec_ptr->stack_depth) {
		print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, 0, rec_ptr->pid);
		/* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth); */ 
	}

	printf ("\n");

	return 0;
}

int
trace_mm_page_alloc_func(void *a, void *v)
{	
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	mm_page_alloc_t tt_rec_ptr;
	mm_page_alloc_t *rec_ptr;

	if (debug) fprintf (stderr, "trace_mm_page_alloc()\n");

	rec_ptr = conv_mm_page_alloc(trcinfop, &tt_rec_ptr);
	print_mm_page_alloc_rec(rec_ptr);
	
	return 0;
}

int
print_mm_page_free_rec(void *a)
{
	mm_page_free_t *rec_ptr = (mm_page_free_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%cpage=0x%llx", fsep, rec_ptr->page);
	printf ("%corder=%d", fsep, rec_ptr->order);

	if (rec_ptr->stack_depth) {
		print_stacktrace(&rec_ptr->ips[0], rec_ptr->stack_depth, 0, rec_ptr->pid); 
		/* print_stacktrace_hex(&rec_ptr->ips[0], rec_ptr->stack_depth);  */
	}

	printf ("\n");

	return 0;
}

int
trace_mm_page_free_func(void *a, void *v)
{	
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	mm_page_free_t tt_rec_ptr;
	mm_page_free_t *rec_ptr;

	if (debug) fprintf (stderr, "trace_mm_page_free()\n");

	rec_ptr = conv_mm_page_free(trcinfop, &tt_rec_ptr);
	print_mm_page_free_rec(rec_ptr);
	
	return 0;
}

int
print_kernel_pagefault_rec(void *a)
{
	fault_t *rec_ptr = (fault_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%caddr=%p", fsep, rec_ptr->addr);
	if (rec_ptr->ip) {
		printf ("%cip=", fsep);
		print_kernel_sym((uint64)rec_ptr->ip, 1);
	}

	printf ("\n");

	return 0;
}

int
trace_kernel_pagefault_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	fault_t tt_rec_ptr;
	fault_t *rec_ptr;

	if (debug) printf ("trace_kernel_pagefault_func()\n");

	rec_ptr = conv_kernel_pagefault(trcinfop, &tt_rec_ptr);
	print_kernel_pagefault_rec(rec_ptr);

	return 0;
}

int
print_page_fault_kernel_rec(void *a)
{
	fault_t *rec_ptr = (fault_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%caddr=%p", fsep, rec_ptr->addr);
	if (rec_ptr->ip) {
		printf ("%cip=", fsep);
		print_kernel_sym((uint64)rec_ptr->ip, 1);
	}

	printf ("%cerr=%s", fsep, flt_err_codes(rec_ptr->error_code));
	printf ("\n");

	return 0;
}

int
trace_page_fault_kernel_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	fault_t tt_rec_ptr;
	fault_t *rec_ptr;

	if (debug) printf ("trace_page_fault_func()\n");

	rec_ptr = conv_page_fault(trcinfop, &tt_rec_ptr);
	print_page_fault_kernel_rec(rec_ptr);

	return 0;
}

int
print_page_fault_user_rec(void *a)
{
	fault_t *rec_ptr = (fault_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%caddr=%p", fsep, rec_ptr->addr);
	if (rec_ptr->ip) {
		printf ("%cip=", fsep);
		print_user_sym((uint64)rec_ptr->ip, rec_ptr->pid, 0);
	}

	printf ("%cerr=%s", fsep, flt_err_codes(rec_ptr->error_code));
	printf ("\n");

	return 0;
}

int
trace_page_fault_user_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	fault_t tt_rec_ptr;
	fault_t *rec_ptr;

	if (debug) printf ("trace_page_fault_func()\n");

	rec_ptr = conv_page_fault(trcinfop, &tt_rec_ptr);
	print_page_fault_user_rec(rec_ptr);

	return 0;
}

int
print_tasklet_enqueue_rec(void *a)
{
	tasklet_enqueue_t *rec_ptr = (tasklet_enqueue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%chi=0x%llx", fsep, rec_ptr->hi);
	printf ("%cfunc=", fsep);
	print_kernel_sym((uint64)rec_ptr->funcp, 0);
	printf ("%carg=0x%llx\n", fsep, rec_ptr->arg);

	return 0;
}

int
trace_tasklet_enqueue_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	tasklet_enqueue_t *rec_ptr = (tasklet_enqueue_t *)trcinfop->cur_rec;

	if (debug) printf ("tasklet_enqueue_func()\n");
	/* record type is only available for LIKI V3 and above */
	print_tasklet_enqueue_rec(rec_ptr);

	return 0;
}
	
int
print_listen_overflow_rec(void *a)
{
	listen_overflow_t *rec_ptr = (listen_overflow_t *)a;
	
	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);

	printf ("%csk_flags=0x%llx\n", fsep, rec_ptr->sock_flags);
	printf ("\n");

	return 0;
}

int
trace_listen_overflow_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	listen_overflow_t *rec_ptr = (listen_overflow_t *)trcinfop->cur_rec;

	if (debug) printf ("trace_listen_overflow_func()\n");
	/* record type is only available on LIKI V2 and above */
	print_listen_overflow_rec(rec_ptr);

	return 0;
}

int
print_walltime_rec (void *a)
{
	walltime_t *rec_ptr = (walltime_t *)a;

	start_time = rec_ptr->hrtime;
	begin_time = rec_ptr->walltime;
	interval_start = interval_end = FILTER_START_TIME;  /* for VIS */
	if (info_flag) {
		PRINT_COMMON_FIELDS(rec_ptr);
		PRINT_EVENT(rec_ptr->id);
	}
	if (!kilive) printf ("%s", ctime(&rec_ptr->walltime.tv_sec));

	return 0;
}

int 
trace_walltime_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	walltime_t *rec_ptr = (walltime_t *)trcinfop->cur_rec;

	if (debug) printf ("trace_walltime_func()\n");
	print_walltime_rec(rec_ptr);

	return 0;
}

int
print_startup_rec(void *a)
{
	startup_t *rec_ptr = (startup_t *)a;

	if (!kilive) printf ("%s", ctime(&rec_ptr->walltime.tv_sec));
	start_time = rec_ptr->hrtime;
	begin_time = rec_ptr->walltime;
	interval_start = interval_end = FILTER_START_TIME;  /* for VIS */
	if (info_flag) {
		PRINT_COMMON_FIELDS(rec_ptr);
		PRINT_EVENT(rec_ptr->id);
		printf (" tracemask=0x%016llx features=0x%08x\n", rec_ptr->tracemask, rec_ptr->enabled_features);
	}

	return 0;
}

int 
trace_startup_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	startup_t *rec_ptr = (startup_t *)trcinfop->cur_rec;

	if (debug) printf ("trace_startup_func()\n");
	print_startup_rec(rec_ptr);

	return 0;
}
