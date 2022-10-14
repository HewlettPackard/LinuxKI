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
#include "winki.h"
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

#include "Pdb.h"
#include "DiskIo.h"
#include "Thread.h"
#include "PerfInfo.h"
#include "SysConfig.h"
#include "Process.h"
#include "Image.h"
#include "FileIo.h"
#include "Provider.h"
#include "NetIp.h"
#include "winki_util.h"

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

int trace_winki_generic_func(void *, void *);
int trace_winki_common_func(void *, void *);
int trace_winki_cstate_func(void *, void *);
int trace_winki_hardfault_func(void *, void *);
int trace_winki_mjfnret_func(void *, void *);
int trace_winki_mjfncall_func(void *, void *);
int trace_winki_complrout_func(void *, void *);
int trace_winki_complreq_func(void *, void *);
int trace_winki_complreqret_func(void *, void *);
int trace_winki_sysconfig_cpu_func(void *, void *);
int trace_winki_sysconfig_nic_func(void *, void *);
int trace_winki_sysconfig_logdisk_func(void *, void *);
int trace_winki_sysconfig_power_func(void *, void *);
int trace_winki_sysconfig_pnp_func(void *, void *);
int trace_winki_sysconfig_irq_func(void *, void *);
int trace_winki_image_func(void *, void *);
int trace_winki_process_func(void *, void *);
int trace_winki_process_terminate_func(void *, void *);
int trace_winki_header_func(void *, void *);
int trace_winki_provider_func(void *, void *);

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
win_set_trace_funcs()
{
	winki_init_actions(trace_winki_generic_func);

	winki_enable_event(0, trace_winki_header_func);
	winki_enable_event(0x5, trace_winki_common_func);
	winki_enable_event(0x8, trace_winki_common_func);
	winki_enable_event(0x20, trace_winki_common_func);
	winki_enable_event(0x50, trace_winki_common_func);
	winki_enable_event(0x10a, print_diskio_readwrite_func);
	winki_enable_event(0x10b, print_diskio_readwrite_func);
	winki_enable_event(0x10c, diskio_init_func);
	winki_enable_event(0x10d, diskio_init_func);
	winki_enable_event(0x10e, print_diskio_flush_func);
	winki_enable_event(0x10f, diskio_init_func);
	winki_enable_event(0x122, trace_winki_mjfncall_func);
	winki_enable_event(0x123, trace_winki_mjfncall_func);
	winki_enable_event(0x125, trace_winki_complrout_func);
	winki_enable_event(0x134, trace_winki_complreq_func);
	winki_enable_event(0x135, trace_winki_complreqret_func);
	winki_enable_event(0x220, trace_winki_hardfault_func);
	winki_enable_event(0x301, trace_winki_process_func);
	winki_enable_event(0x302, trace_winki_process_func);
	winki_enable_event(0x303, trace_winki_process_func);
	winki_enable_event(0x304, trace_winki_process_func);
	winki_enable_event(0x30a, print_process_load_func);
	winki_enable_event(0x30b, trace_winki_process_terminate_func);
	winki_enable_event(0x327, trace_winki_process_func);
	winki_enable_event(0x400, print_fileio_name_func);
	winki_enable_event(0x420, print_fileio_name_func);
	winki_enable_event(0x423, print_fileio_name_func);
	winki_enable_event(0x424, print_fileio_name_func);
	winki_enable_event(0x440, print_fileio_create_func);
	winki_enable_event(0x441, print_fileio_simpleop_func);
	winki_enable_event(0x442, print_fileio_simpleop_func);
	winki_enable_event(0x443, print_fileio_readwrite_func);
	winki_enable_event(0x444, print_fileio_readwrite_func);
	winki_enable_event(0x445, print_fileio_info_func);
	winki_enable_event(0x446, print_fileio_info_func);
	winki_enable_event(0x447, print_fileio_info_func);
	winki_enable_event(0x449, print_fileio_simpleop_func);
	winki_enable_event(0x44a, print_fileio_info_func);
	winki_enable_event(0x44b, print_fileio_info_func);
	winki_enable_event(0x44c, print_fileio_opend_func);
	winki_enable_event(0x44d, print_fileio_direnum_func);
	winki_enable_event(0x44f, print_fileio_name_func);
	winki_enable_event(0x450, print_fileio_name_func);
	winki_enable_event(0x501, print_thread_group1_func);
	winki_enable_event(0x502, print_thread_group1_func);
	winki_enable_event(0x503, print_thread_group1_func);
	winki_enable_event(0x504, print_thread_group1_func);
	winki_enable_event(0x524, thread_cswitch_func);
	winki_enable_event(0x532, thread_readythread_func);
	winki_enable_event(0x542, print_thread_autoboost_func);
	winki_enable_event(0x543, print_thread_autoboost_func);
	winki_enable_event(0x544, print_thread_autoboost_func);
	winki_enable_event(0x548, thread_setname_func);
	winki_enable_event(0x60a, print_tcpsendipv4_func);
	winki_enable_event(0x60b, print_tcpgroup1_func);
	winki_enable_event(0x60c, print_tcpgroup2_func);
	winki_enable_event(0x60d, print_tcpgroup1_func);
	winki_enable_event(0x60e, print_tcpgroup1_func);
	winki_enable_event(0x60f, print_tcpgroup2_func);
	winki_enable_event(0x610, print_tcpgroup1_func);
	winki_enable_event(0x611, print_tcpudpfail_func);
	winki_enable_event(0x612, print_tcpgroup1_func);
	winki_enable_event(0x61a, print_tcpsendipv6_func);
	winki_enable_event(0x61b, print_tcpgroup3_func);
	winki_enable_event(0x61c, print_tcpgroup4_func);
	winki_enable_event(0x61d, print_tcpgroup3_func);
	winki_enable_event(0x61e, print_tcpgroup3_func);
	winki_enable_event(0x61f, print_tcpgroup4_func);
	winki_enable_event(0x620, print_tcpgroup3_func);
	winki_enable_event(0x622, print_tcpgroup3_func);
	winki_enable_event(0x80a, print_udpgroup1_func);
	winki_enable_event(0x80b, print_udpgroup1_func);
	winki_enable_event(0x811, print_tcpudpfail_func);
	winki_enable_event(0x81a, print_udpgroup2_func);
	winki_enable_event(0x81b, print_udpgroup2_func);
	winki_enable_event(0xb0a, trace_winki_sysconfig_cpu_func);
	winki_enable_event(0xb0b, print_sysconfig_physdisk_func);
	winki_enable_event(0xb0c, trace_winki_sysconfig_logdisk_func);
	winki_enable_event(0xb0d, trace_winki_sysconfig_nic_func);
	winki_enable_event(0xb0f, print_sysconfig_services_func);
	winki_enable_event(0xb10, trace_winki_sysconfig_power_func);
	winki_enable_event(0xb15, trace_winki_sysconfig_irq_func);
	winki_enable_event(0xb15, trace_winki_sysconfig_pnp_func);
	winki_enable_event(0xf2e, perfinfo_profile_func);
	winki_enable_event(0xf32, perfinfo_isr_func);
	winki_enable_event(0xf33, perfinfo_sysclenter_func);
	winki_enable_event(0xf34, perfinfo_sysclexit_func);
	winki_enable_event(0xf35, perfinfo_dpc_func);
	winki_enable_event(0xf42, perfinfo_dpc_func);
	winki_enable_event(0xf43, perfinfo_isr_func);
	winki_enable_event(0xf44, perfinfo_dpc_func);
	winki_enable_event(0xf45, perfinfo_dpc_func);
	winki_enable_event(0xf48, perfinfo_interval_func);
	winki_enable_event(0xf49, perfinfo_interval_func);
	winki_enable_event(0xf4a, perfinfo_interval_func);
	winki_enable_event(0x1235, trace_winki_cstate_func);
	winki_enable_event(0x1402, print_image_func);
	winki_enable_event(0x1403, print_image_func);
	winki_enable_event(0x1404, print_image_func);
	winki_enable_event(0x140a, print_image_func);
	winki_enable_event(0x1421, print_image_func);
	ki_actions[0x1820].func=NULL;

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
        ki_actions[TRACE_CALL_FUNCTION_ENTRY].func = call_function_entry_func;
        ki_actions[TRACE_CALL_FUNCTION_EXIT].func = call_function_exit_func;
        ki_actions[TRACE_CALL_FUNCTION_SINGLE_ENTRY].func = call_function_entry_func;
        ki_actions[TRACE_CALL_FUNCTION_SINGLE_EXIT].func = call_function_exit_func;

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

	if (debug) printf ("trace_init_func()\n"); 
	if (IS_WINKI) { 
		win_set_trace_funcs();
		set_events_all(1);
	} else {
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
	uint32 id;

	if (IS_WINKI) return trcinfop->cur_event;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);

	if (rec_ptr->id >= 65536) {
		printf ("trace_filter_func() - Bad rec id: %d for cpu %d\n", rec_ptr->id, rec_ptr->cpu);
		hex_dump(rec_ptr,4);
		exit(-231);
	}

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
	if (IS_WINKI) printf (" id=0x%x", rec_ptr->id);
	else printf (" id=%d", rec_ptr->id);
	PRINT_EVENT(rec_ptr->id);
	
	if (IS_FTRACE) {
		eventp = (event_t *)trcinfop->cur_event;
		ptr = (char *)trcinfop->cur_event + sizeof(kd_rec_t);
		while (ptr < (char *)eventp + get_event_len(eventp)) {
			printf (" 0x%x", *(uint32 *)ptr);
			ptr+=sizeof(uint32);
		}
	}			
	printf ("\n");

	hex_dump(trcinfop->cur_event, 2);
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

/* Windows related functions */

int
trace_winki_generic_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	etw_common_t *p = (etw_common_t *)trcinfop->cur_event;
	etw_common_c002_t *p2 = (etw_common_c002_t *)trcinfop->cur_event;;
	etw_common_c011_t *p11 = (etw_common_c011_t *)trcinfop->cur_event;;

	if (p->ReservedHeaderField == 0xc014) { 
		trace_winki_provider_func(trcinfop, v);
		return 0;
	}

	if (p->ReservedHeaderField == 0xc002) {
		PRINT_COMMON_FIELDS_C002(p2);
		update_pid_ids(p2->tid, p2->pid);
	} else if (p->ReservedHeaderField == 0xc011) { 
		PRINT_COMMON_FIELDS_C011(p11, 0, 0);
	} else {
		 printf ("*Unknown ReservedHeaderField: 0x%x\n", p->ReservedHeaderField);
	}
	printf (" id=0x%x\n", p->EventType);

	if (debug) hex_dump(trcinfop->cur_event, 8);
	hex_dump(trcinfop->cur_event, 8);
	printf ("\n");
}

int
trace_winki_common_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	etw_common_t *p = (etw_common_t *)trcinfop->cur_event;
	etw_common_c002_t *p2 = (etw_common_c002_t *)trcinfop->cur_event;;
	etw_common_c011_t *p11 = (etw_common_c011_t *)trcinfop->cur_event;;
	etw_common_c014_t *p14 = (etw_common_c014_t *)trcinfop->cur_event;;

	if (p->ReservedHeaderField == 0xc002) {
		PRINT_COMMON_FIELDS_C002(p2);
		update_pid_ids(p2->tid, p2->pid);
	} else if (p->ReservedHeaderField == 0xc011) { 
		PRINT_COMMON_FIELDS_C011(p11, 0, 0);
	} else if (p->ReservedHeaderField == 0xc014) { 
		PRINT_COMMON_FIELDS_C014(p14);
	} else {
		 printf ("*Unknown ReservedHeaderField: 0x%x\n", p->ReservedHeaderField);
	}

	if (debug) hex_dump(trcinfop->cur_event, 8);
	printf ("\n");
}

int
trace_winki_cstate_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	Cstate_t *p = (Cstate_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0 , 0);

	printf (" prev_state=C%d", p->prev_state+1);
	printf (" next_state=C%d", p->next_state+1);
	printf (" cpumask=0x%x", p->cpumask);
	printf ("\n");

	if (debug) hex_dump(p, 2);
}


int
trace_winki_hardfault_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	HardFault_t *p = (HardFault_t *)trcinfop->cur_event;
	pid_info_t *pidp, *tgidp;
	StackWalk_t *stk = NULL;
	winki_stack_info_t stkinfo, *stkinfop;;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	pidp = GET_PIDP(&globals->pid_hash, p->TThreadId);
	stk = (StackWalk_t *)trcinfop->next_event;
	stkinfop = &stkinfo;
	stkinfop->depth = 0;

	if (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820)) {
		PRINT_COMMON_FIELDS_C011(p, stk->StackThread, stk->StackProcess);
		update_pid_ids(stk->StackThread, stk->StackProcess);
		winki_save_stktrc(trcinfop, stk, stkinfop);	
	} else {
		PRINT_COMMON_FIELDS_C011(p, p->TThreadId , pidp->tgid);
	}

	if ((pidp->tgid) && (pidp->PID != pidp->tgid)) {
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
	} else {
		tgidp = pidp;
	}

	printf (" offset=0x%llx vaddr=0x%llx count=%d obj=0x%llx tid=%d",
		p->ReadOffset,
		p->VirtualAddress,
		p->ByteCount,
		p->FileObject,
		p->TThreadId);

	printf (" starttime=");
	PRINT_TIME(p->InitialTime);
	printf (" elptime=");
	PRINT_TIME_DIFF(p->InitialTime, p->TimeStamp);

	if (stkinfop->depth) {
		printf (" Stacktrace: ");
		PRINT_WIN_STKTRC2(pidp, stkinfop);
	}

	printf ("\n");

	if (debug) hex_dump(p, 2);
}




int 
trace_winki_mjfncall_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_DrvMjFnCall_t *p = (DiskIo_DrvMjFnCall_t *)trcinfop->cur_event;
	
	PRINT_COMMON_FIELDS_C011(p, 0, 0);
	
	printf (" majfunc=%d minfunc=%d",
		p->MajorFunction,
		p->MinorFunction);
	printf (" addr=");
	print_win_sym(p->RoutineAddr, NULL);
	printf (" obj=0x%llx irp=0x%llx id=%d", 
		p->FileObject,
		p->Irp,
		p->UniqMatchId);
	
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int 
trace_winki_mjfnret_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_DrvMjFnRet_t *p = (DiskIo_DrvMjFnRet_t *)trcinfop->cur_event;
	
	PRINT_COMMON_FIELDS_C011(p, 0, 0);
	
	printf (" irp=0x%llx id=%d", 
		p->Irp,
		p->UniqMatchId);
	
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int 
trace_winki_complreq_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_DrvComplReq_t *p = (DiskIo_DrvComplReq_t *)trcinfop->cur_event;
	
	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" addr=");
	print_win_sym(p->RoutineAddr, NULL);
	printf (" irp=0x%llx id=%d", 
		p->Irp,
		p->UniqMatchId);
	
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int 
trace_winki_complreqret_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_DrvComplReqRet_t *p = (DiskIo_DrvComplReqRet_t *)trcinfop->cur_event;
	
	PRINT_COMMON_FIELDS_C011(p, 0, 0);
	
	printf (" irp=0x%llx id=%d", 
		p->Irp,
		p->UniqMatchId);
	
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int 
trace_winki_complrout_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_DrvComplRout_t *p = (DiskIo_DrvComplRout_t *)trcinfop->cur_event;
	
	PRINT_COMMON_FIELDS_C011(p, 0, 0);
	
	printf (" addr=");
	print_win_sym(p->Routine, NULL);
	printf (" irp=0x%llx id=%d", 
		p->Irp,
		p->UniqMatchId);
	
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int
trace_winki_process_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	Process_TypeGroup1_t *p = (Process_TypeGroup1_t *)trcinfop->cur_event;
	pid_info_t *pidp, *ppidp;

	pidp = GET_PIDP(&globals->pid_hash, p->ProcessID);
	ppidp = GET_PIDP(&globals->pid_hash, p->ParentID);
	pidp->ppid = p->ParentID;

	PRINT_COMMON_FIELDS_C002(p);
	printf (" key=0x%x pid=%d ppid=%d sessionid=%d exitstatus=%d dirbase=0x%llx userSID=%d", 
		p->UniqueProcessKey,
		p->ProcessID,
		p->ParentID,
		p->SessionID,
	 	p->ExitStatus,
		p->DirectoryTableBase,
		p->UserSID);

	printf ("\n");	

	if (debug) hex_dump(p, 6);
}

int
trace_winki_process_terminate_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	ProcessTerminate_t *p = (ProcessTerminate_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);

	printf (" pid=%d status=%d", 
		p->ProcessID,
		p->Status);

	printf ("\n");	

	if (debug) hex_dump(p, 2);
}

int
trace_winki_sysconfig_cpu_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_CPU_t *p = (SysConfig_CPU_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);
	
	printf (" ncores=%d mhz=%d memsize=%d pagesize=%d ht=0x%x",
		p->NumberOfProcessors,
		p->MHz,
		p->MemSize,
		p->PageSize,
		p->HyperThreadingFlag);

	chr = &p->ComputerName[0];
	printf (" ComputerName=\"");
	PRINT_WIN_NAME2(chr);

	chr = &p->DomainName[0];
	printf ("\" DomainName=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int
trace_winki_sysconfig_nic_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_NIC_t *p = (SysConfig_NIC_t *)trcinfop->cur_event;
	uint16 *chr;

	chr = &p->Name[0];

	PRINT_COMMON_FIELDS_C011(p, 0, 0);
	
	printf (" addr=0x%llx len=%d",
		p->PhysicalAddr,
		p->PhysicalAddrLen);

	printf (" desc=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" ipaddr=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" dns=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}
		
int
trace_winki_sysconfig_logdisk_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_LogDisk_t *p = (SysConfig_LogDisk_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);
	
	printf (" disknum=%d partitionnum=%d offset=0x%llx partitionsize=%lld size=%d type=%d bps=%d",
		p->DiskNumber,
		p->PartitionNumber,
		p->StartOffset,
		p->PartitionSize,
		p->Size,
		p->DriveType,
		p->BytesPerSector);

	chr = &p->DriveLetterString[0];
	printf (" Drive=\"");
	PRINT_WIN_NAME2(chr);

	chr = &p->FileSystem[0];
	printf ("\" FileSystem=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int
trace_winki_sysconfig_pnp_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_PnP_t *p = (SysConfig_PnP_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);
	
	chr = &p->Name[0];
	printf (" DeviceID=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" Description=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" FriendlyName=\"");
	PRINT_WIN_NAME2(chr);

	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int
trace_winki_sysconfig_irq_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_IRQ_t *p = (SysConfig_IRQ_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);

	printf (" irq=%d affinity=0x%llx",
		p->IRQNum,
		p->IRQAffinity);
	
	chr = &p->DeviceDescription[0];
	printf (" Description=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int
trace_winki_sysconfig_power_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_Power_t *p = (SysConfig_Power_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);

	printf (" states:");

	if (p->s1) printf (" s1");
	if (p->s2) printf (" s2");
	if (p->s3) printf (" s3");
	if (p->s4) printf (" s4");
	if (p->s5) printf (" s5");
	
	printf ("\n");

	if (debug) hex_dump(p, 3);
}

/* These traces are very tricky */
int
trace_winki_provider_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	Provider_t *p = (Provider_t *)trcinfop->cur_event;
	int i;

	PRINT_COMMON_FIELDS_C014(p);

	printf (" guid={");
	for (i=0; i<4; i++) {
		if (i != 0) printf ("-");
		printf ("%x", p->guid[i]);
	}
	printf ("}");

	if ((p->guid[0] == 0x9b79ee91) && (p->guid[1] == 0x41c0b5fd) && (p->guid[2] == 0x484243a2) && (p->guid[3] == 0xd0e966e2)) {	
	    if ((p->EventType >=32) && (p->EventType <=35)) {
		uint16 *chr;
		printf(" \"");
		chr = &p->Name[0];	
		PRINT_WIN_NAME2(chr);
		printf (" ");
		PRINT_WIN_NAME2(chr);
		printf("\"");	
	    }
	}

	if ((p->guid[0] == 0xb3e675d7) && (p->guid[1] == 0x4f182554) && (p->guid[2] == 0x62270b83) && (p->guid[3] == 0xde602573)) {	
		if (p->EventType == 64) {
			print_control_image((ControlImage_t *)p);
			control_image_func((ControlImage_t *)p);
		} else if (p->EventType == 36) {
			print_pdb_image((PdbImage_t *)p);
		}
	}

	printf ("\n");
	if (debug) hex_dump(p, 32);

}

int
trace_winki_header_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	EventTraceHdr_t *p = (EventTraceHdr_t *)trcinfop->cur_event;
	etw_common_c014_t *p014 = (etw_common_c014_t *)trcinfop->cur_event;

	/* this is a special case */
	if (p->ReservedHeaderField == 0xc014) {
		trace_winki_provider_func(trcinfop, v);
		return 0;
	}

	/* PRINT_TIME(p->TimeStamp); */
	if (winki_hdr == NULL) winki_hdr = p;

	PRINT_TIME(p->TimeStamp);
	printf ("%ccpu=%d", fsep, trcinfop->cpu);
	printf ("%cpid=%d%ctgid=%d", fsep, p->tid, fsep, p->pid); 	/* Windows uses PID/TID rather than TGID/TID */

	PRINT_EVENT(p->EventType);

	printf (" Bufsz=%d Vers=0x%x nCPUs=%d", p->BufferSize, p->Version, p->NumberOfProcessors);
	printf (" MHz=%d EventsLost=%d", p->CPUSpeed, p->EventsLost);
	printf (" BootTime= ");  PRINT_WIN_FMTTIME(p->BootTime);
	printf (" StartTime= ");  PRINT_WIN_FMTTIME(p->StartTime);
	printf (" EndTime= ");  PRINT_WIN_FMTTIME(p->EndTime);
	
	printf ("\n");

	/* The start time will be the first traced event after the header, so set it to zero here */
	winki_start_time = 0;

	/* this should be identified by the corelist file processed earlier, but just in case... */
	if (globals->ncpu == 0) globals->ncpu = p->NumberOfProcessors;
	if (globals->nlcpu == 0) globals->nlcpu = p->NumberOfProcessors;

	if (debug) hex_dump(p, 4);
}
