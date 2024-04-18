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

int docker_print_report(void *);

int pid_ftrace_print_func(void *, void *);

/*
 ** The initialization function
 */ 
void
docker_init_func(void *v)
{
	int i;
	int ret;
	if (debug) printf ("docker_init_func()\n");

	if (IS_WINKI) {
		fprintf (stderr, "Container Activity Report is not availble for Windows traces\n");
		return;
	}	

	process_func =  NULL;
        report_func = docker_report_func;

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
	parse_docker_ps();
	parse_pods();

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
	parse_pself();
	parse_edus();
	parse_maps();
        parse_mpath();
	parse_jstack();

	if (docktree) {
                ret = mkdir("CIDS", 0777);
                if (ret && (errno != EEXIST)) {
	                fprintf (stderr, "Unable to make CIDS directory, errno %d\n", errno);
                        fprintf (stderr, "  Continuing... it may alreaady exist \n");
			CLEAR(DOCKTREE_FLAG);
                }
        }
}

int
docker_report_func(void *v)
{
        printf ("\n***************************************************\n");
        docker_print_report(v);

        return 0;
}


int
calc_docker_totals(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	docker_info_t *dockerp = pidp->dockerp;
	dkpid_info_t *dkpidp;
	sched_info_t *pschedp;
	sched_stats_t *pstatp, *dstatp;
	pid_info_t *tgidp;
	int i;

	if (pidp->PID < 1) return 0;

        if (dockerp == NULL) {
		/* Use TGID dockerp if its exists */
		if (pidp->tgid) {
			tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
			if (tgidp->dockerp) {
				dockerp = tgidp->dockerp;
			} else {
				dockerp = GET_DOCKERP(&globals->docker_hash, 0);
			}
		} else {
                	dockerp = GET_DOCKERP(&globals->docker_hash, 0);
		}

                dkpidp = GET_DKPIDP(&dockerp->dkpid_hash, pidp->PID);
                dkpidp->dockerp = dockerp;
                dkpidp->pidp = pidp;
        }

	if (pidp->schedp) {
		pschedp = GET_ADD_SCHEDP(&pidp->schedp);	
		pstatp = &pschedp->sched_stats;
		dstatp = &dockerp->sched_stats;

		pstatp->T_irq_time = 0;
		for (i=IRQ_BEGIN; i <= IRQ_END; i++) 
			pstatp->T_irq_time += pstatp->time[i];

		for (i=0; i < N_TIME_STATS; i++) 
			dstatp->time[i] += pstatp->time[i];

		for (i=0; i < N_CNT_STATS; i++)
			dstatp->cnt[i] += pstatp->cnt[i];
	}

	sum_iostats(&pidp->iostats, &dockerp->iostats);

	dockerp->netstats.total_time += pidp->netstats.total_time;
	dockerp->netstats.max_time = MAX(dockerp->netstats.max_time, pidp->netstats.max_time);
	dockerp->netstats.rd_bytes += pidp->netstats.rd_bytes;
	dockerp->netstats.wr_bytes += pidp->netstats.wr_bytes;
	dockerp->netstats.errors += pidp->netstats.errors;
	dockerp->netstats.syscall_cnt += pidp->netstats.syscall_cnt;
	dockerp->netstats.rd_cnt += pidp->netstats.rd_cnt;
	dockerp->netstats.wr_cnt += pidp->netstats.wr_cnt;
	dockerp->netstats.last_pid = 0;

	return 0;
}

int
calc_docker_pid_totals(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;

	if (is_alive) get_pid_cgroup(pidp, NULL);
	calc_pid_iototals(pidp, NULL);
	calc_docker_totals(pidp, NULL);
}

uint64
find_docker_by_name(char *name)
{
	int i;
	docker_info_t *dockerp;

	if (globals->docker_hash == NULL) return 0;

	for (i = 0; i < DOCKER_HASHSZ; i++) {
		dockerp = globals->docker_hash[i];
		while (dockerp) {
			if (strcmp(name, dockerp->name) == 0) {
				return dockerp->ID;
			}

			dockerp = (docker_info_t *)dockerp->lle.next;
		}
	}

	return NO_DOCKID;
}

int
print_docker_summary(void *arg1, void *arg2)
{
	docker_info_t *dockerp = (docker_info_t *)arg1;
	sched_stats_t *statp = &dockerp->sched_stats;
	if (dockfile) {
		dock_printf ("%012llx", dockerp->ID);
	} else {
		DOCKER_URL_FIELD(dockerp->ID);
	}

	dock_printf (" %12.6f %12.6f %12.6f %12.6f %12.6f",
		SECS(statp->T_run_time),
		SECS(statp->T_sys_time),
		SECS(statp->T_user_time),
		SECS(statp->T_irq_time),
		SECS(statp->T_runq_time));

	dock_printf (" %8.1f %8.1f",
		dockerp->iostats[IOTOT].compl_cnt / secs,
		((dockerp->iostats[IOTOT].sect_xfrd / 2.0)/1024.0) / secs);
	dock_printf (" %8.1f %8.1f",
                (dockerp->netstats.rd_cnt+dockerp->netstats.wr_cnt)/secs,
                ((dockerp->netstats.rd_bytes+dockerp->netstats.wr_bytes)/(1024*1024))/secs);


	dock_printf ("\n");
	return 0;
}

int
print_docker_totals(void *arg1, void *arg2)
{
	docker_info_t *dockerp = (docker_info_t *)arg1;
	sched_stats_t *statp = &dockerp->sched_stats;
	DOCKER_URL_FIELD(dockerp->ID);
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

	printf ("\n");
	return 0;
}

int 
print_docker_iototals(void *arg1, void *arg2)
{
        docker_info_t *dockerp = (docker_info_t *)arg1;

	DOCKER_URL_FIELD(dockerp->ID);
	printf ("  ");
	print_iostats_totals(globals, &dockerp->iostats[0], NULL);
	printf ("\n");
}


int
print_dkpid_runtime_summary(void *arg1, void *arg2)
{
	dkpid_info_t *dkpidp = (dkpid_info_t *)arg1;
	print_pid_runtime_summary(dkpidp->pidp, NULL);
}

int
print_dkpid_rss(void *arg1, void *arg2)
{
	dkpid_info_t *dkpidp = (dkpid_info_t *)arg1;
	print_pid_memory(dkpidp->pidp, NULL);
}

int
print_dkpid_iosum(void *arg1, void *arg2)
{
	dkpid_info_t *dkpidp = (dkpid_info_t *)arg1;
	print_pid_iosum(dkpidp->pidp, NULL);
}
	

int
print_docker_detail(void *arg1, void *arg2)
{
	docker_info_t *dockerp = (docker_info_t *)arg1;
	char dock_fname[20];

        if (docktree) {
                sprintf (dock_fname, "CIDS/%012llx", dockerp->ID);
                if ((dockfile = fopen(dock_fname, "w")) == NULL) {
                        fprintf (stderr, "Unable to open Container file %s, errno %d\n", dock_fname, errno);
                        fprintf (stderr, "  Continuing without CIDS output\n");
			CLEAR(DOCKTREE_FLAG);
                }
        } else {
                dockfile = NULL;
        }

	dock_printf ("\n---------------------------------------------------\n");
	dock_printf ("Container ID: %012llx  name: %s\n", dockerp->ID, dockerp->name);

	dock_printf ("\nContainer            busy          sys         user          irq         runq");
        dock_printf ("     IOPS     MB/s");
        dock_printf("   NetOPS  NetMB/s\n");

	print_docker_summary(dockerp, NULL);

	dock_printf ("\nTop Tasks sorted by RunTime\n");
        dock_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_dkpid_runtime_summary,
                           (int (*)()) dkpid_sort_by_runtime,
                           npid, NULL);
	
	dock_printf ("\nTop Tasks sorted by SysTime\n");
        dock_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_dkpid_runtime_summary,
                           (int (*)()) dkpid_sort_by_systime,
                           npid, NULL);

	dock_printf ("\nTop Tasks sorted by RunQTime\n");
        dock_printf ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
        foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_dkpid_runtime_summary,
                           (int (*)()) dkpid_sort_by_runqtime,
                           npid, NULL);

	dock_printf ("\nTop Tasks sorted by Memory Usage\n");
	dock_printf("     vss      rss      PID Command\n");
        foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_dkpid_rss,
                           (int (*)()) dkpid_sort_by_rss,
                           npid, NULL);

	dock_printf ("\nTop Tasks sorted by physical IO\n");
	dock_printf ("     Cnt      r/s      w/s    KB/sec    Avserv      PID  Process\n");
	dock_printf ("---------------------  Total  --------------------- ----------------------  Write  -------------------- ----------------------  Read  ---------------------\n");
	dock_printf ("   IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    PID    Process\n");
        foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_dkpid_iosum,
                           (int (*)()) dkpid_sort_by_iocnt,
                           npid, NULL);

	if (dockfile) fclose(dockfile);
	return 0;
}

int
docker_print_cpu_report()
{
	BOLD ("Container            busy          sys         user         runq");
	if (globals->schedp->sched_stats.T_irq_time)
		BOLD ("  hardirq_sys hardirq_user  softirq_sys softirq_user");
	printf ("\n");
	foreach_hash_entry((void **)globals->docker_hash, DOCKER_HASHSZ, print_docker_totals, docker_sort_by_runtime, 0, NULL);
}

int
docker_print_io_report()
{
	BOLD("              ---------------------  Total  --------------------- ----------------------  Write  -------------------- ----------------------  Read  ---------------------\n");
        BOLD("Container        IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv    IO/s    MB/s  AvIOsz AvInFlt    Avwait    Avserv\n");
	foreach_hash_entry((void **)globals->docker_hash, DOCKER_HASHSZ, print_docker_iototals, docker_sort_by_iocnt, 0, NULL);
}

int
docker_print_report(void *v)
{
	docker_info_t *dockerp;

	if (!kiall_flag) {
		update_perpid_sched_stats();
		calc_global_cpu_stats(globals, NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_docker_pid_totals, NULL, 0, NULL);
		dockerp = GET_DOCKERP(&globals->docker_hash, 0);
		dockerp->name = "system";
	}

	BOLD ("Containers\n\n");
	print_docker_ps();
	print_pods();

	BOLD ("CPU Statistics\n\n");
	docker_print_cpu_report();

	
	BOLD ("\nIO Statistics\n\n");
	docker_print_io_report();

	/* print detail docker reports for each container */
	foreach_hash_entry((void **)globals->docker_hash, DOCKER_HASHSZ, print_docker_detail, NULL, 0, NULL);

	return 0;
}
