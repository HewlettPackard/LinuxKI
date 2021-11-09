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
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "block.h"
#include "syscalls.h"
#include "power.h"
#include "irq.h"
#include "hardclock.h"
#include "cache.h"
#include "hash.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include "kprint.h"

int kparse_dummy_func(uint64, int, void *);
int kparse_generic_func(void *, void *);
int kparse_ftrace_print_func(void *, void *);

#include "Thread.h"
#include "Process.h"
#include "PerfInfo.h"
#include "DiskIo.h"
#include "NetIp.h"
#include "FileIo.h"
#include "winki_util.h"

static inline void
kparse_winki_trace_funcs()
{
	winki_init_actions(NULL);
	winki_enable_event(0x10a, diskio_readwrite_func);
	winki_enable_event(0x10b, diskio_readwrite_func);
	winki_enable_event(0x10c, diskio_init_func);
	winki_enable_event(0x10d, diskio_init_func);
	winki_enable_event(0x10e, diskio_flush_func);
	winki_enable_event(0x30a, process_load_func);
	winki_enable_event(0x400, fileio_name_func);
	winki_enable_event(0x420, fileio_name_func);
	winki_enable_event(0x423, fileio_name_func);
	winki_enable_event(0x424, fileio_name_func);
	winki_enable_event(0x440, fileio_create_func);
	winki_enable_event(0x443, fileio_readwrite_func);
	winki_enable_event(0x444, fileio_readwrite_func);
	winki_enable_event(0x524, thread_cswitch_func);
	winki_enable_event(0x532, thread_readythread_func);
	winki_enable_event(0x548, thread_setname_func);
	winki_enable_event(0x60a, tcpip_sendipv4_func);
	winki_enable_event(0x60b, tcpip_recvipv4_func);
	winki_enable_event(0x60e, tcpip_retransmitipv4_func);
	winki_enable_event(0x61a, tcpip_sendipv6_func);
	winki_enable_event(0x61b, tcpip_recvipv6_func);
	winki_enable_event(0x61e, tcpip_retransmitipv6_func);
	winki_enable_event(0x80a, udpip_sendipv4_func);
	winki_enable_event(0x80b, udpip_recvipv4_func);
	winki_enable_event(0x81a, udpip_sendipv6_func);
	winki_enable_event(0x81b, udpip_recvipv6_func);
	winki_enable_event(0xf33, perfinfo_sysclenter_func);
	winki_enable_event(0xf34, perfinfo_sysclexit_func);
	winki_enable_event(0xf2e, perfinfo_profile_func);
	winki_enable_event(0xf32, perfinfo_isr_func);
	winki_enable_event(0xf42, perfinfo_dpc_func);
	winki_enable_event(0xf43, perfinfo_isr_func);
	winki_enable_event(0xf44, perfinfo_dpc_func);
	winki_enable_event(0xf45, perfinfo_dpc_func);
}

/*
 ** The initialisation function
 */
void
kparse_init_func(void *v)
{
        int i;

	if (debug) printf ("kparse_init_func()\n");
        process_func = NULL;
        print_func = kparse_print_func;
        report_func = kparse_report_func;
	filter_func = info_filter_func;   /* no filter func for kparse, use generic */
	bufmiss_func = pid_bufmiss_func;

        /* We will disregard the trace records until the Marker is found */
        for (i = 0; i < KI_MAXTRACECALLS; i++) {
                ki_actions[i].execute = 0;
        }

        if (IS_WINKI) {
                kparse_winki_trace_funcs();

		parse_systeminfo();
                parse_cpulist();
                parse_corelist();
		parse_SQLThreadList();
                return;
        }

        /* go ahead and initialize the trace functions, but do not set the execute field */
        ki_actions[TRACE_BLOCK_RQ_ISSUE].func = block_rq_issue_func;
        ki_actions[TRACE_BLOCK_RQ_INSERT].func = block_rq_insert_func;
        ki_actions[TRACE_BLOCK_RQ_COMPLETE].func = block_rq_complete_func;
        ki_actions[TRACE_BLOCK_RQ_REQUEUE].func = block_rq_requeue_func;
        ki_actions[TRACE_BLOCK_RQ_ABORT].func = block_rq_abort_func;
        ki_actions[TRACE_SYS_EXIT].func = sys_exit_func;
        ki_actions[TRACE_SYS_ENTER].func = sys_enter_func;
        ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_func;
        ki_actions[TRACE_SCHED_WAKEUP_NEW].func = sched_wakeup_func;
        ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;
	ki_actions[TRACE_SCHED_MIGRATE_TASK].func = kparse_generic_func;
	ki_actions[TRACE_HARDCLOCK].func = hardclock_func;
	ki_actions[TRACE_POWER_START].func = power_start_func;
	ki_actions[TRACE_POWER_END].func = power_end_func;
	ki_actions[TRACE_POWER_FREQ].func = power_freq_func;
	ki_actions[TRACE_CPU_FREQ].func = cpu_freq_func;
	ki_actions[TRACE_CPU_IDLE].func = cpu_idle_func;
	ki_actions[TRACE_IRQ_HANDLER_ENTRY].func = irq_handler_entry_func;
	ki_actions[TRACE_IRQ_HANDLER_EXIT].func = irq_handler_exit_func;
	ki_actions[TRACE_SOFTIRQ_ENTRY].func = softirq_entry_func;
	ki_actions[TRACE_SOFTIRQ_EXIT].func = softirq_exit_func;
	ki_actions[TRACE_SOFTIRQ_RAISE].func = kparse_generic_func;
	SET_KIACTION_FUNCTION(TRACE_SCSI_DISPATCH_CMD_START, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_SCSI_DISPATCH_CMD_DONE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_INSERTION, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_EXECUTION, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_ENQUEUE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_EXECUTE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_TASKLET_ENQUEUE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_PAGE_FAULT_USER, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_PAGE_FAULT_KERNEL, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_ANON_FAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_FILEMAP_FAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_KERNEL_PAGEFAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_ALLOC, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_FREE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_FREE_DIRECT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_LISTEN_OVERFLOW, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_CACHE_INSERT, cache_insert_func);
	SET_KIACTION_FUNCTION(TRACE_CACHE_EVICT, cache_evict_func);
	SET_KIACTION_FUNCTION(TRACE_WALLTIME, trace_walltime_func);
        if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (is_alive) {
		if (set_events_options(filter_func_arg) == 0) set_events_default();
	} else if (IS_LIKI) {
		set_events_all(1);
	} else {
		set_events_all(0);
        	ki_actions[TRACE_PRINT].func = kparse_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

        dsk_io_sizes[0]= 5ull;
        dsk_io_sizes[1]= 10;
        dsk_io_sizes[2]= 20;
        dsk_io_sizes[3]= 50;
        dsk_io_sizes[4]= 100;
        dsk_io_sizes[5]= 200;
        dsk_io_sizes[6]= 300;
        dsk_io_sizes[7]= 500;
        dsk_io_sizes[8]= 1000;

	parse_cpuinfo();
	parse_mem_info();
	parse_kallsyms();
	parse_devices();
	parse_docker_ps();
        parse_ll_R();
	if (is_alive) {
		parse_cpumaps();
		return;	
	}

	if (timestamp) {
		parse_mpsched();
		parse_proc_cgroup();
		parse_uname(0);
        	parse_lsof();
        	parse_pself();
		parse_edus();
		parse_jstack();
        	parse_mpath();
	}
}

int
kparse_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int
kparse_bufmiss_func(void *v, void *a)
{
        trace_info_t *trcinfop = v;
	char tt_rec_ptr[MAX_REC_LEN];
        sched_switch_t *rec_ptr;
        int old_pid, next_pid;

	rec_ptr = conv_common_rec(v, &tt_rec_ptr);

        old_pid = rec_ptr->pid;

        if (rec_ptr->id == TRACE_SCHED_SWITCH) {
		rec_ptr = conv_sched_switch(v, &tt_rec_ptr);
                next_pid = rec_ptr->next_pid;
        } else {
                next_pid = rec_ptr->pid;
        }

        if (check_for_missed_buffer(trcinfop, rec_ptr, next_pid)) {
                cpu_missed_buffer(trcinfop);

                foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))pid_missed_buffer,
                           NULL, 0, trcinfop);
        }
        return 0;
}

/*
 **
 */
int
kparse_dummy_func(uint64 rec_ptr, int cor, void *v)
{
        return 0;
}

int
kparse_generic_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        common_t      tt_rec_ptr;
        common_t      *rec_ptr;

        if (debug) printf ("kparse_generic_func()\n");

        rec_ptr = conv_common_rec(trcinfop, &tt_rec_ptr);
	incr_trc_stats(rec_ptr, NULL);

        return 0;
}

int kparse_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("pid_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
                ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 1;
		ki_actions[TRACE_POWER_START].execute = 1;
		ki_actions[TRACE_POWER_END].execute = 1;
		ki_actions[TRACE_POWER_FREQ].execute = 1;
		ki_actions[TRACE_CPU_FREQ].execute = 1;
		ki_actions[TRACE_CPU_IDLE].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
                SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_START, 1);
                SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_DONE, 1);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_INSERTION, 1);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTION, 1);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_ENQUEUE, 1);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTE, 1);
                SET_KIACTION_EXECUTE(TRACE_TASKLET_ENQUEUE, 1);
                SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_USER, 1);
                SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_KERNEL, 1);
                SET_KIACTION_EXECUTE(TRACE_ANON_FAULT, 1);
                SET_KIACTION_EXECUTE(TRACE_FILEMAP_FAULT, 1);
                SET_KIACTION_EXECUTE(TRACE_KERNEL_PAGEFAULT, 1);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_ALLOC, 1);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE, 1);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE_DIRECT, 1);
                SET_KIACTION_EXECUTE(TRACE_LISTEN_OVERFLOW, 1);
                SET_KIACTION_EXECUTE(TRACE_CACHE_INSERT, 1);
                SET_KIACTION_EXECUTE(TRACE_CACHE_EVICT, 1);
                start_time = KD_CUR_TIME;
		/* bufmiss_func = kparse_bufmiss_func; */
        }
        if (strstr(buf, ts_end_marker)) {
                ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 0;
                ki_actions[TRACE_SYS_EXIT].execute = 0;
                ki_actions[TRACE_SYS_ENTER].execute = 0;
                ki_actions[TRACE_SCHED_SWITCH].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
		ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 0;
		ki_actions[TRACE_POWER_START].execute = 0;
		ki_actions[TRACE_POWER_END].execute = 0;
		ki_actions[TRACE_POWER_FREQ].execute = 0;
		ki_actions[TRACE_CPU_FREQ].execute = 0;
		ki_actions[TRACE_CPU_IDLE].execute = 0;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 0;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 0;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 0;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 0;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 0;
                SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_START, 0);
                SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_DONE, 0);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_INSERTION, 0);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTION, 0);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_ENQUEUE, 0);
                SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTE, 0);
                SET_KIACTION_EXECUTE(TRACE_TASKLET_ENQUEUE, 0);
                SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_USER, 0);
                SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_KERNEL, 0);
                SET_KIACTION_EXECUTE(TRACE_ANON_FAULT, 0);
                SET_KIACTION_EXECUTE(TRACE_FILEMAP_FAULT, 0);
                SET_KIACTION_EXECUTE(TRACE_KERNEL_PAGEFAULT, 0);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_ALLOC, 0);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE, 0);
                SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE_DIRECT, 0);
                SET_KIACTION_EXECUTE(TRACE_LISTEN_OVERFLOW, 0);
                SET_KIACTION_EXECUTE(TRACE_CACHE_INSERT, 0);
                SET_KIACTION_EXECUTE(TRACE_CACHE_EVICT, 0);
                SET_KIACTION_EXECUTE(TRACE_PRINT, 0);
                end_time = KD_CUR_TIME;
                bufmiss_func =  NULL;
        }

        if (debug)  {
                PRINT_KD_REC(rec_ptr);
                PRINT_EVENT(rec_ptr->KD_ID);
                printf (" %s", buf);

                printf ("\n");
        }
}
int
kparse_print_report(void *v)
{
	docker_info_t *dockerp;

	/* calculate per-device totals */
	update_cpu_times(end_time);
	foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
	foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
	foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
	foreach_hash_entry((void **)globals->fobj_hash, FOBJ_HSIZE, calc_fobj_totals, NULL, 0, 0);

	update_perpid_sched_stats();
	calc_global_cpu_stats(globals, NULL);
	calc_io_totals(&globals->iostats[0], NULL);

	if (globals->docker_hash) {
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_docker_pid_totals, NULL, 0, NULL);
        	dockerp = GET_DOCKERP(&globals->docker_hash, 0);
        	dockerp->name = "system";
	}

        parse_cstates();
        if (globals->HT_enabled) calc_global_HT_stats(globals, NULL);

	kp_sys_summary();	
	kp_toc();

	kp_whats_it_doing();				/* Section 1.0 */
	kp_global_cpu();				/* Section 1.1 */
	kp_per_cpu_usage();				/* Section 1.1.1 */
	if (globals->nldom) 
		kp_per_ldom_usage(); 			/* Section 1.1.2 */
	if (globals->powerp)
		kp_power_report();			/* Section 1.1.3 */
        if (globals->HT_enabled)
                kp_HT_usage();          		/* Section 1.1.4 */
	
	kp_busy_pids();					/* Section 1.2 */
	kp_top_pids_runtime();				/* Section 1.2.1 */
	kp_top_pids_systime();				/* Section 1.2.2 */
	if (STEAL_ON)
		kp_top_pids_stealtime();		/* Section 1.2.3 */

	kp_trace_types();				/* Section 1.3 */
	kp_global_trace_types();			/* Section 1.3.1 */
	kp_top_pid_trace_counts();			/* Section 1.3.2 */
	if (kparse_full) kp_top_pid_trace_types(); 	/* Section 1.3.3 */
	kp_hardclocks();				/* Section 1.4 */

	hc_info_t *hcinfop = globals->hcinfop;
        if (hcinfop && hcinfop->total) {
		kp_cpustates();					/* Section 1.4.1 */
		kp_hc_bycpu();					/* Section 1.4.2 */
		kp_hc_kernfuncs();				/* Section 1.4.3 */
		if (kparse_full) kp_hc_stktraces();		/* Section 1.4.4 */
		if (kparse_full) kp_hc_funcbypid();		/* Section 1.4.5 */
	}
	kp_th_detection();				/* Section 1.5 */
	if (globals->irqp || globals->softirqp) {
		kp_irq();					/* Section 1.6 */
		kp_hardirqs();					/* Section 1.6.1 */
		kp_hardirqs_by_cpu();				/* Section 1.6.2 */
		kp_softirqs();					/* Section 1.6.3 */
	}

	kp_whats_it_waiting_for();			/* Section 2.0 */
	kp_swtch_reports();				/* Section 2.1 */
	kp_freq_swtch_funcs();				/* Section 2.1.1 */
	kp_freq_swtch_stktrc();				/* Section 2.1.2 */
	kp_top_swtch_pids();				/* Section 2.1.3 */
	if (kparse_full) kp_top_swtch_pid_funcs();	/* Section 2.1.4 */
        kp_wait_for_cpu();  	 			/* Section 2.2 */
        kp_runq_statistics();				/* Section 2.2.2 */
        kp_top_runq_pids();				/* Section 2.2.3 */
	if (!IS_WINKI) {
		kp_futex();					/* Section 2.3 */
		kp_futex_summary_by_cnt();			/* Section 2.3.1 */
		kp_futex_summary_by_time();			/* Section 2.3.2 */
	}

	kp_file_activity();				/* Section 3.0 */
	if (IS_WINKI) {
		kp_file_logio();			/* Section 3.1 */
		kp_file_physio();			/* Section 3.2 */
	} else {
		kp_file_ops();				/* Section 3.1 */
		kp_file_time();				/* Section 3.2 */
		kp_file_errs();				/* Section 3.3 */
		if (kparse_full) kp_top_files();	/* Section 3.4 */
	}

        kp_device_report();            			/* Section 4.0 */
        kp_device_globals();     			/* Section 4.1 */
        kp_perdev_reports();				/* Section 4.2 */
        kp_active_disks();				/* Section 4.2.1 */
        kp_highserv1_disks();				/* Section 4.2.2 */
        kp_highserv2_disks();				/* Section 4.2.3 */
        kp_highwait_disks();				/* Section 4.2.4 */
        kp_requeue_disks();				/* Section 4.2.5 */
        kp_dsk_histogram();				/* Section 4.2.6 */
	if (!IS_WINKI) {
		kp_mapper_report();				/* Section 4.3 */
		kp_active_mapper_devs();			/* Section 4.3.1 */
		kp_hiserv_mapper_devs();			/* Section 4.3.2 */
		kp_fc_totals();					/* Section 4.4 */
		kp_wwn_totals();				/* Section 4.5 */
		kp_perpid_mdev_totals();			/* Section 4.6 */
	}
	kp_perpid_dev_totals();				/* Section 4.7 */
	if (!IS_WINKI) {
		if (dskblk_stats) {
        		kp_dskblk_read(); 	        /* Section 4.8 */
        		kp_dskblk_write();	        /* Section 4.9 */
		}
		kp_io_controllers();	
	}

	kp_network();					/* Section 5.0 */
	kp_ipip();					/* Section 5.1 */
	kp_remoteip();					/* Section 5.2 */
	kp_remoteport();				/* Section 5.3 */
	kp_localip();					/* Section 5.4 */
	kp_localport();					/* Section 5.5 */
	kp_socket();					/* Section 5.6 */
	if (IS_WINKI) kp_timeo_retrans();		/* Section 5.7 */


	if (!IS_WINKI) {
		kp_memory();					/* Section 6.0 */
		kp_dimm();					/* Section 6.1 */
		if (IS_LIKI_V2_PLUS) {
			kp_rss();				/* Section 6.2 */
			kp_vss();				/* Section 6.3 */
		}
	}

	if (next_sid > 1) {
		kp_oracle();				/* Section 7.0 */
		kp_oracle_sids();			/* Section 7.1 */
		kp_lgwr_analysis();			/* Section 7.2 */
		kp_arch_analysis();  			/* Section 7.3 */
		kp_dbw_analysis();			/* Section 7.4 */
		kp_pquery_analysis();			/* Section 7.5 */
		kp_shared_server_analysis();		/* Section 7.6 */
		kp_ioslave_analysis();			/* Section 7.7 */
	}
	
	if (globals->docker_hash) {
		kp_dockers();				/* Section 8.0 */
		kp_docker_ps();				/* Section 8.1 */
		kp_docker_cpu();			/* Section 8.2 */
		kp_docker_io();				/* Section 8.3 */
	}

	if (HTML) {
		kp_file_links();	    		/* Section 9.0 */
		kp_txt_links();				/* Section 9.1 */
		kp_csv_links();				/* Section 9.2 */
		kp_misc_links();			/* Section 9.3 */
		if (vis) kp_vis_links();		/* Section 9.4 */
	}
	kp_warnings_report();    			/* Section 10.0 */
	globals->next_warning=0;
	return 0;
}

int
kparse_print_func(void *v)
{
        int i;
        struct timeval tod;

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                kparse_print_report(v);
                print_flag=0;
        }
        return 0;
}

int
kparse_report_func(void *v)
{

        if (debug) printf ("Entering kparse_report_func %d\n", is_alive);
        if (passes != 0) {
                kparse_print_report(v);
        }

	HR;
	printf ("\n");

        return 0;
}
