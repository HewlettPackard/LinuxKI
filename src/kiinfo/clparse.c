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
#include "power.h"
#include "syscalls.h"
#include "irq.h"
#include "hardclock.h"
#include "hash.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include "clprint.h"

int clparse_report_func(void *v);
int clparse_print_func(void *v);
/*
 ** The initialisation function
 */
void
clparse_init_func(void *v)
{
        int i;

	if (debug) printf ("clparse_init_func()\n");
        process_func = NULL;
        print_func = clparse_print_func;
        report_func = clparse_report_func;
	bufmiss_func = pid_bufmiss_func;
	filter_func = info_filter_func;   /* no filter func for kirunq, use generic */

        /* We will disregard the trace records until the Marker is found */
        for (i = 0; i < KI_MAXTRACECALLS; i++) {
                ki_actions[i].execute = 0;
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
	ki_actions[TRACE_SCSI_DISPATCH_CMD_START].func = kparse_generic_func;
	ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].func = kparse_generic_func;
	ki_actions[TRACE_LISTEN_OVERFLOW].func = kparse_generic_func;

	if (IS_LIKI) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
		ki_actions[TRACE_SYS_ENTER].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
		ki_actions[TRACE_SCHED_SWITCH].execute = 1;
		ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
		ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 1;
		ki_actions[TRACE_HARDCLOCK].execute = 1;
		ki_actions[TRACE_POWER_START].execute = 1;
		ki_actions[TRACE_POWER_END].execute = 1;
		ki_actions[TRACE_POWER_FREQ].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
		ki_actions[TRACE_SCSI_DISPATCH_CMD_START].execute = 1;
		ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].execute = 1;
		ki_actions[TRACE_LISTEN_OVERFLOW].execute = 1;
        	/* bufmiss_func = kparse_bufmiss_func; */
	} else {
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
	parse_mpsched();
	parse_kallsyms();
	parse_devices();
        parse_ll_R();

	if (timestamp) {
		parse_docker_ps();
		parse_proc_cgroup();
        	parse_lsof();
        	parse_pself();
        	parse_edus();
        	parse_jstack();
        	parse_mpath();
		parse_mem_info();
		parse_scavuln(0);
		parse_uname(cluster_flag);
		parse_irqlist();

		if (vis) vis_clparse_init();
	}
}

int
clparse_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int
clparse_bufmiss_func(void *v, void *a)
{
        trace_info_t *trcinfop = v;
	sched_switch_t tt_rec_ptr;
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

int
calc_totals(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;

        foreach_hash_entry((void **)serverp->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
        foreach_hash_entry((void **)serverp->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
	foreach_hash_entry((void **)serverp->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
	calc_global_cpu_stats(serverp, NULL);
	calc_io_totals(&serverp->iostats[0], NULL);	
	if (serverp->HT_enabled) calc_global_HT_stats(serverp, NULL);

	foreach_hash_entry((void **)serverp->futex_hash, GFUTEX_HSIZE, hash_count_entries, NULL, 0, &serverp->futex_cnt);
}

int
add_clpid_entry(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	clpid_info_t *clpidp;

	clpidp = GET_CLPIDP(&clpid_hash, globals->server_id, pidp->PID);
	clpidp->globals = globals;
	clpidp->pidp = pidp;
}
	
int
build_clpid_hash(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;	
	foreach_hash_entry((void **)serverp->pid_hash, PID_HASHSZ, 
		(int (*)(void *, void *))add_clpid_entry,
		NULL, 0, NULL);
}

int
add_clfdata_entry(void *arg1, void *arg2)
{
	fdata_info_t *fdatap = (fdata_info_t *)arg1;
	clfdata_info_t *clfdatap;

	clfdatap = GET_CLFDATAP(&clfdata_hash, globals->server_id, fdatap->dev, fdatap->node);
	clfdatap->globals = globals;
	clfdatap->fdatap = fdatap;
	clfdatap->dev = fdatap->dev;
	clfdatap->node = fdatap->node;
}

int
build_clfdata_hash(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;	
	foreach_hash_entry((void **)serverp->fdata_hash, FDATA_HASHSZ, 
		(int (*)(void *, void *))add_clfdata_entry,
		NULL, 0, NULL);
}

int
add_cldev_entry(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	cldev_info_t *cldevp;
	uint32 dev = devinfop->lle.key;

	cldevp = GET_CLDEVP(CLDEVHASHP(dev), globals->server_id, dev);
	cldevp->globals = globals;
	cldevp->devinfop = devinfop;
}

int
build_cldev_hash(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;	
	foreach_hash_entry((void **)serverp->devhash, DEV_HSIZE, 
		(int (*)(void *, void *))add_cldev_entry,
		NULL, 0, NULL);

	foreach_hash_entry((void **)serverp->mdevhash, DEV_HSIZE, 
		(int (*)(void *, void *))add_cldev_entry,
		NULL, 0, NULL);
}

int
add_clfutex_entry(void *arg1, void *arg2)
{
	gbl_futex_info_t *futexp = (gbl_futex_info_t *)arg1;
	clfutex_info_t *clfutexp;

	/* current, there is no good way to do public futexes.  Just not enough bits in the lle.key */
	clfutexp = GET_CLFUTEXP(&clfutex_hash, globals->server_id, futexp->addr);
	clfutexp->globals = globals;
	clfutexp->futexp = futexp;
}
	
int
build_clfutex_hash(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;	
	foreach_hash_entry((void **)serverp->futex_hash, GFUTEX_HSIZE, 
		(int (*)(void *, void *))add_clfutex_entry,
		NULL, 0, NULL);
}

int
add_clipip_entry(void *arg1, void *arg2)
{
	ipip_info_t *ipipp = (ipip_info_t *)arg1;
	clipip_info_t *clipipp;

	clipipp = GET_CLIPIPP(&clipip_hash, ipipp->lle.key1, ipipp->lle.key2);
	clipipp->globals = globals;
	clipipp->ipipp = ipipp;
}

int
build_clipip_hash(void *arg1, void *arg2)
{
	if (debug) printf ("build_clipip_hash\n");

	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;
	foreach_hash_entry((void **)serverp->ipip_hash, IPIP_HASHSZ, 
		(int (*)(void *, void *))add_clipip_entry,
		NULL, 0, NULL);
}

int
add_cllip_entry(void *arg1, void *arg2)
{
	ip_info_t *ipp = (ip_info_t *)arg1;
	clip_info_t *cllipp;

	cllipp = GET_CLIPP(&cllip_hash, ipp->lle.key);
	cllipp->globals = globals;
	cllipp->ipp = ipp;
}

int
build_cllip_hash(void *arg1, void *arg2)
{
	if (debug) printf ("build_cllip_hash\n");

	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;
	foreach_hash_entry((void **)serverp->lip_hash, IP_HASHSZ, 
		(int (*)(void *, void *))add_cllip_entry,
		NULL, 0, NULL);
}

int
add_clsdata_entry(void *arg1, void *arg2)
{
	sdata_info_t *sdatap = (sdata_info_t *)arg1;
	clsdata_info_t *clsdatap;

	clsdatap = GET_CLSDATAP(&clsdata_hash, SOCK_IP(sdatap->lle.key1), SOCK_PORT(sdatap->lle.key1), 
					       SOCK_IP(sdatap->lle.key2), SOCK_PORT(sdatap->lle.key2));
	clsdatap->globals = globals;
	clsdatap->sdatap = sdatap;
}

int
build_clsdata_hash(void *arg1, void *arg2)
{
	if (debug) printf ("build_clsdata_hash\n");

	server_info_t *serverp = (server_info_t *)arg1;
	globals = serverp;
	foreach_hash_entry((void **)serverp->sdata_hash, SDATA_HASHSZ, 
		(int (*)(void *, void *))add_clsdata_entry,
		NULL, 0, NULL);
}

int
cp_parse_cstate(void *arg1, void *arg2)
{
	parse_cstates();
}

int
clparse_print_report(void *v)
{
	int i;

	foreach_server(cp_parse_cstate, NULL, 0, NULL);
	foreach_server(calc_totals, NULL, 0, NULL);
	foreach_server(build_clpid_hash, NULL, 0, NULL);
	foreach_server(build_clfdata_hash, NULL, 0, NULL);
	foreach_server(build_cldev_hash, NULL, 0, NULL);
	foreach_server(build_clfutex_hash, NULL, 0, NULL);
	foreach_server(build_clipip_hash, NULL, 0, NULL);
	foreach_server(build_cllip_hash, NULL, 0, NULL);
	foreach_server(build_clsdata_hash, NULL, 0, NULL);

	cl_sys_summary();
	cl_toc();

	cl_whats_it_doing();			/* Section 1.0 */
	cl_global_summary();
	cl_global_cpu();
	cl_global_cpu_by_runtime();
	cl_global_cpu_by_systime();
	cl_power_report();
	cl_HT_usage();
	cl_busy_pids();
	cl_top_pids_runtime();
	cl_top_pids_systime();
	cl_hardclocks();
	cl_hc_states();
	cl_hc_funcbypid();
	cl_th_detection();

	cl_whats_it_waiting_for();		/* Section 2.0 */
	cl_switch_reports();
	cl_top_switch_pids();
	cl_top_switch_pid_funcs();
	cl_wait_for_cpu();
	cl_runq_statistics();
	cl_top_pids_runqtime();
	cl_futex();
	cl_futex_summary_by_cnt();
	cl_futex_summary_by_time();

	cl_file_activity();			/* Section 3.0 */
	cl_file_ops();
	cl_file_time();
	cl_file_errs();

	cl_device_report();			/* Section 4.0 */
	cl_device_globals();
	cl_perdev_reports();
	cl_active_disks();
	cl_permdev_reports();
	cl_active_mdevs();
	cl_perpid_mdev_totals();
	cl_perpid_dev_totals();

	cl_network_report();			/* Section 5.0 */
	cl_network_globals();
	cl_network_ipip();
	cl_network_local_ip();
	cl_network_top_sockets();

	cl_warnings_report();

	if (csv_flag)  {
		cl_server_csv();
		cl_network_csv();
	}
	return 0;
}

int
clparse_print_func(void *v)
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
clparse_report_func(void *v)
{

        if (debug) printf ("Entering kparse_report_func %d\n", is_alive);
        if (passes != 0) {
                clparse_print_report(v);
        }

	HR;
	printf ("\n");

        return 0;
}
