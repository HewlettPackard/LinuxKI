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
#include <unistd.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/aio_abi.h>
#include <linux/in.h>
#include <linux/kdev_t.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"

#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "block.h"
#include "syscalls.h"
#include "sched.h"
#include "irq.h"
#include "hardclock.h"
#include "cache.h"
#include "oracle.h"
#include "hash.h"
#include "sort.h"
#include "conv.h"
#include "json.h"
#include "html.h"

int kvm_print_report(void *);

int pid_ftrace_print_func(void *, void *);

/*
 ** The initialization function
 */ 
void
kvm_init_func(void *v)
{
	int i;
	int ret;
	if (debug) printf ("kvm_init_func()\n");

	if (IS_WINKI) {
		fprintf (stderr, "KVM Activity Report is not availble for Windows traces\n");
		return;
	}	

	process_func =  NULL;
        report_func = kvm_report_func;

        bufmiss_func = pid_bufmiss_func;
        alarm_func = pid_alarm_func;
	filter_func = trace_filter_func;
	report_func_arg  = filter_func_arg;

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
	ki_actions[TRACE_HARDCLOCK].func = hardclock_func;
	ki_actions[TRACE_IRQ_HANDLER_ENTRY].func = irq_handler_entry_func;
	ki_actions[TRACE_IRQ_HANDLER_EXIT].func = irq_handler_exit_func;
	ki_actions[TRACE_SOFTIRQ_ENTRY].func = softirq_entry_func;
	ki_actions[TRACE_SOFTIRQ_EXIT].func = softirq_exit_func;
	ki_actions[TRACE_CACHE_INSERT].func = cache_insert_func;
	ki_actions[TRACE_CACHE_EVICT].func = cache_evict_func;
        if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (is_alive) {
		if (IS_LIKI) ki_actions[TRACE_WALLTIME].execute = 1;
		if (set_events_options(filter_func_arg) == 0) {
			/* if no filters, set up default tracing */
			if (dsk_flag) {
				ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
			}
			if (ISSET(SCALL_FLAG | FUTEX_FLAG | SOCK_FLAG | SCDETAIL_FLAG)) {
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
			}
			if (sched_flag) {
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
			}
			if (hc_flag) ki_actions[TRACE_HARDCLOCK].execute = 1;
		}
	} else if (IS_LIKI) {
		if (dsk_flag) {
			ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
			ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
			ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
			ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
			ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
		}
		if (pgcache_flag) {
			ki_actions[TRACE_CACHE_INSERT].execute = 1;
			ki_actions[TRACE_CACHE_EVICT].execute = 1;
		}
		if (ISSET(SCALL_FLAG | FUTEX_FLAG | SOCK_FLAG | SCDETAIL_FLAG | FILE_FLAG)) {
			ki_actions[TRACE_SYS_EXIT].execute = 1;
			ki_actions[TRACE_SYS_ENTER].execute = 1;
		}
		if (ISSET(SCHED_FLAG | MEMORY_FLAG | SCDETAIL_FLAG)) {
			ki_actions[TRACE_SCHED_SWITCH].execute = 1;
			ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
			ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
			ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
			ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
			ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
			ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
		}
		if (hc_flag) ki_actions[TRACE_HARDCLOCK].execute = 1;
	} else {
		set_events_all(0);
		ki_actions[TRACE_PRINT].func = pid_ftrace_print_func;
		ki_actions[TRACE_PRINT].execute = 1;
	}

	parse_cpuinfo();
	if (is_alive) parse_cpumaps();
	parse_kallsyms();
	parse_devices();
        parse_ll_R();
	parse_pself();

	if (objfile) {
		load_elf(objfile, &objfile_preg);
	} else {
		if (is_alive) load_objfile_and_shlibs();
	}

	pid_csvfile = open_csv_file("kipid", 1);

	if (is_alive) return;
	parse_mpsched();
	parse_proc_cgroup();
	parse_lsof();
	parse_edus();
	parse_maps();
        parse_mpath();
	parse_jstack();

	if (kvmtree) {
		ret = mkdir("VIDS", 0777);
		if (ret && (errno != EEXIST)) {
			fprintf (stderr, "Unable to make VIDS directory, errno %d\n", errno);
			fprintf (stderr, "  Continuing... it may alreaady exist \n");
			CLEAR(KVMTREE_FLAG);
		}
	}
}

int
kvm_report_func(void *v)
{
        printf ("\n***************************************************\n");
        kvm_print_report(v);

        return 0;
}


int
calc_vm_totals(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	vm_info_t *vminfop = pidp->vminfop;
	vmpid_info_t *vmpidp;
	sched_info_t *pschedp;
	sched_stats_t *pstatp, *vstatp;
	pid_info_t *tgidp;
	int i;

	if (pidp->PID < 1) return 0;
	if (pidp->vminfop == NULL) return 0;

        vmpidp = GET_VMPIDP(&vminfop->vmpid_hash, pidp->PID);
	if (vmpidp->pidp == NULL) {
		printf ("BAD PIDP value\n");
		exit (10);
	}

	if (pidp->schedp) {
		pschedp = GET_ADD_SCHEDP(&pidp->schedp);	
		pstatp = &pschedp->sched_stats;
		vstatp = &vminfop->sched_stats;

		pstatp->T_irq_time = 0;
		for (i=IRQ_BEGIN; i <= IRQ_END; i++) 
			pstatp->T_irq_time += pstatp->time[i];

		for (i=0; i < N_TIME_STATS; i++) 
			vstatp->time[i] += pstatp->time[i];

		for (i=0; i < N_CNT_STATS; i++)
			vstatp->cnt[i] += pstatp->cnt[i];
	}

	sum_iostats(&pidp->iostats, &vminfop->iostats);

	vminfop->netstats.total_time += pidp->netstats.total_time;
	vminfop->netstats.max_time = MAX(vminfop->netstats.max_time, pidp->netstats.max_time);
	vminfop->netstats.rd_bytes += pidp->netstats.rd_bytes;
	vminfop->netstats.wr_bytes += pidp->netstats.wr_bytes;
	vminfop->netstats.errors += pidp->netstats.errors;
	vminfop->netstats.syscall_cnt += pidp->netstats.syscall_cnt;
	vminfop->netstats.rd_cnt += pidp->netstats.rd_cnt;
	vminfop->netstats.wr_cnt += pidp->netstats.wr_cnt;
	vminfop->netstats.last_pid = 0;

	return 0;
}

int
calc_vm_pid_totals(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;

	if (is_alive) get_pid_cgroup(pidp, NULL);
	calc_pid_iototals(pidp, NULL);
	calc_vm_totals(pidp, NULL);
}

uint64
find_vm_by_name(char *name)
{
	int i;
	vm_info_t *vminfop;

	if (globals->vm_hash == NULL) return 0;

	for (i = 0; i < PID_HASHSZ; i++) {
		vminfop = globals->vm_hash[i];
		while (vminfop) {
			if (strcmp(name, vminfop->vm_name) == 0) {
				return vminfop->PID;
			}

			vminfop = (vm_info_t *)vminfop->lle.next;
		}
	}

	return 0ull;
}

int
print_vm_summary(void *arg1, void *arg2)
{
	vm_info_t *vminfop = (vm_info_t *)arg1;
	sched_stats_t *statp = &vminfop->sched_stats;

	if (kvmfile) {
		aux_printf ("%8d", vminfop->PID);
	}

	aux_printf (" %12.6f %12.6f %12.6f %12.6f %12.6f",
		SECS(statp->T_run_time),
		SECS(statp->T_sys_time),
		SECS(statp->T_user_time),
		SECS(statp->T_irq_time),
		SECS(statp->T_runq_time));

	aux_printf (" %8.1f %8.1f",
		vminfop->iostats[IOTOT].compl_cnt / secs,
		((vminfop->iostats[IOTOT].sect_xfrd / 2.0)/1024.0) / secs);
	aux_printf (" %8.1f %8.1f",
                (vminfop->netstats.rd_cnt+vminfop->netstats.wr_cnt)/secs,
                ((vminfop->netstats.rd_bytes+vminfop->netstats.wr_bytes)/(1024*1024))/secs);


	aux_printf ("  %s", vminfop->vm_name);
	aux_printf ("\n");
	return 0;

}
int
print_vm_info(void *arg1, void *arg2)
{
        vm_info_t *vminfop = (vm_info_t *)arg1;
        sched_stats_t *statp = &vminfop->sched_stats;
        KVM_URL_FIELD(vminfop->PID);
	printf ("  %5d  %s  -smp %s\n", vminfop->nlwp, vminfop->vm_name, vminfop->smp_arg);
	return 0;
}



int
print_vm_totals(void *arg1, void *arg2)
{
	vm_info_t *vminfop = (vm_info_t *)arg1;
	sched_stats_t *statp = &vminfop->sched_stats;
	KVM_URL_FIELD(vminfop->PID);
	printf (" %12.6f %12.6f %12.6f %12.6f",
		SECS(statp->T_run_time),
		SECS(statp->T_sys_time),
		SECS(statp->T_user_time),
		SECS(statp->T_runq_time));

	if (statp->time[IRQ_TIME]) 
		printf (" %12.6f %12.6f %12.6f %12.6f",
			SECS(statp->T_hardirq_sys_time),
			SECS(statp->T_hardirq_user_time),
			SECS(statp->T_softirq_sys_time),
			SECS(statp->T_softirq_user_time));

	printf ("  %s", vminfop->vm_name);
	printf ("\n");
	return 0;
}

int 
print_vm_iototals(void *arg1, void *arg2)
{
        vm_info_t *vminfop = (vm_info_t *)arg1;

	KVM_URL_FIELD(vminfop->PID);
	printf ("  ");
	print_iostats_totals(globals, &vminfop->iostats[0], NULL);
	printf (" %s", vminfop->vm_name);
	printf ("\n");
}


int
print_vmpid_runtime_summary(void *arg1, void *arg2)
{
	vmpid_info_t *vmpidp = (vmpid_info_t *)arg1;
	print_pid_runtime_summary(vmpidp->pidp, NULL);
}

int
print_vmpid_rss(void *arg1, void *arg2)
{
	vmpid_info_t *vmpidp = (vmpid_info_t *)arg1;
	print_pid_memory(vmpidp->pidp, NULL);
}

int
print_vmpid_iosum(void *arg1, void *arg2)
{
	vmpid_info_t *vmpidp = (vmpid_info_t *)arg1;
	print_pid_iosum(vmpidp->pidp, NULL);
}
	
int
print_vm_detail(void *arg1, void *arg2)
{
	vm_info_t *vminfop = (vm_info_t *)arg1;
	char kvm_fname[20];

	if (kvmtree) {
		sprintf (kvm_fname, "VIDS/%d", vminfop->PID);
		if ((kvmfile = fopen(kvm_fname, "w")) == NULL) {
			fprintf (stderr, "Unable to open VM file %s, errno %d\n", kvm_fname, errno);
			fprintf (stderr, "  Continuing without VIDS output\n");
			CLEAR(KVMTREE_FLAG);
		}
	} else {
		kvmfile = NULL;
	}

	aux_printf ("\n---------------------------------------------------\n");
	aux_printf ("TGID: %8d  VM name: %s  -smp %s\n", vminfop->PID, vminfop->vm_name, vminfop->smp_arg);

	aux_printf ("\n    TGID         busy          sys         user          irq         runq");
        aux_printf ("     IOPS     MB/s");
        aux_printf ("   NetOPS  NetMB/s");
	aux_printf ("  VM Name\n");

	print_vm_summary(vminfop, NULL);
	aux_printf ("\nTop Tasks sorted by RunTime\n");
        aux_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)vminfop->vmpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_vmpid_runtime_summary,
                           (int (*)()) vmpid_sort_by_runtime,
                           npid, NULL);
/*	
	aux_printf ("\nTop Tasks sorted by SysTime\n");
        aux_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)vminfop->vmpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_vmpid_runtime_summary,
                           (int (*)()) vmpid_sort_by_systime,
                           npid, NULL);
*/
	aux_printf ("\nTop Tasks sorted by RunQTime\n");
        aux_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)vminfop->vmpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_vmpid_runtime_summary,
                           (int (*)()) vmpid_sort_by_runqtime,
                           npid, NULL);
/*
	aux_printf ("\nTop Tasks sorted by Memory Usage\n");
	aux_printf("     vss      rss      PID Command\n");
        foreach_hash_entry((void **)vminfop->vmpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_vmpid_rss,
                           (int (*)()) vmpid_sort_by_rss,
                           npid, NULL);
*/

	aux_printf ("\nTop Tasks sorted by physical IO\n");
	aux_printf ("     Cnt      r/s      w/s    KB/sec    Avserv      PID  Process\n");
	aux_printf ("---------------------  Total  --------------------- ----------------------  Write  -------------------- ----------------------  Read  ---------------------\n");
	aux_printf ("   IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    PID    Process\n");
        foreach_hash_entry((void **)vminfop->vmpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_vmpid_iosum,
                           (int (*)()) vmpid_sort_by_iocnt,
                           npid, NULL);

	if (kvmfile) {
	       fprintf(kvmfile, "\nKVM ps listing\n\n%s", vminfop->vm_detail);
       	       fclose(kvmfile);
	}
	return 0;
}

int
vm_print_info_report()
{
	BOLD ("KVM VMs detected: %d\n", globals->nvms);
	BOLD ("    TGID   nlwp  VM Name\n");
	foreach_hash_entry((void **)globals->vm_hash, PID_HASHSZ, print_vm_info, vm_sort_by_runtime, 0, NULL);
	NLt;
}

int
vm_print_cpu_report()
{
	BOLD ("    TGID         busy          sys         user         runq");
	if (globals->schedp->sched_stats.T_irq_time)
		BOLD ("  hardirq_sys hardirq_user  softirq_sys softirq_user");
	BOLD ("  VM Name\n");
	foreach_hash_entry((void **)globals->vm_hash, PID_HASHSZ, print_vm_totals, vm_sort_by_runtime, 0, NULL);
}

int
vm_print_io_report()
{
	BOLD("          ---------------------  Total  --------------------- ----------------------  Write  -------------------- ----------------------  Read  ---------------------\n");
        BOLD("    TGID     IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv  KVM Name\n");
	foreach_hash_entry((void **)globals->vm_hash, PID_HASHSZ, print_vm_iototals, vm_sort_by_iocnt, 0, NULL);
}

int
kvm_print_report(void *v)
{
	vm_info_t *vminfop;

	if (!kiall_flag) {
		update_perpid_sched_stats();
		calc_global_cpu_stats(globals, NULL);
	}

	vm_print_info_report();
	BOLD ("KVM CPU Statistics\n\n");
	vm_print_cpu_report();

	
	BOLD ("\nKVM IO Statistics\n\n"); 
	vm_print_io_report();

	/* print detail VM reports for each VM */
	foreach_hash_entry((void **)globals->vm_hash, PID_HASHSZ, print_vm_detail, vm_sort_by_runtime, 0, NULL);

	return 0;
}
