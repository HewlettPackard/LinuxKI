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
#include "futex.h"

#include "Thread.h"
#include "Process.h"
#include "PerfInfo.h"
#include "DiskIo.h"
#include "NetIp.h"
#include "FileIo.h"
#include "winki_util.h"


int pid_bufmiss_func(void *, void *);
int pid_print_report(void *);

int pid_ftrace_print_func(void *, void *);

static inline void
pid_winki_trace_funcs()
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
 ** The initialization function
 */ 

void
pid_init_func(void *v)
{
	int i;
	int ret;
	char piddir[8];
	if (debug) printf ("pid_init_func()\n");

	process_func =  NULL;
	preprocess_func = NULL;
	if (vis) preprocess_func = kiall_preprocess_func;
        report_func = pid_report_func;

        bufmiss_func = pid_bufmiss_func;
        /* bufswtch_func = pid_bufswtch_func; */
        alarm_func = pid_alarm_func;
	filter_func = trace_filter_func;
	report_func_arg  = filter_func_arg;

	sprintf (piddir, "%sS", tlabel);
	if (pidtree) {
                ret = mkdir(piddir, 0777);
                if (ret && (errno != EEXIST)) {
	                fprintf (stderr, "Unable to make %s directory, errno %d\n", piddir, errno);
                        fprintf (stderr, "  Continuing... it may alreaady exist \n");
			CLEAR(PIDTREE_FLAG);
                }
        }

	pid_csvfile = open_csv_file("kipid", 1);

	if (IS_WINKI) {
		pid_winki_trace_funcs();

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
	parse_kallsyms();
	parse_devices();
	parse_docker_ps();
        parse_ll_R();

	if (is_alive) {
		parse_cpumaps();
		load_objfile_and_shlibs();
		return;
	}

	parse_mpsched();
	parse_proc_cgroup();
	parse_pself();
	parse_edus();
	parse_lsof();
	parse_maps();
        parse_mpath();
	parse_jstack();
	if (objfile) load_elf(objfile, &objfile_preg);
	if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);

      /*
      ** For visualization kipid charts we create a VIS/<PID> directory to hold copy (link actually) 
      ** of the pid_detail.html file and the per-pid json file data.
      */

        if (vis) vis_kipid_init();
}

int
pid_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	
        return 0;
}

/* alarm_func() should contain any
 *  * extra code to handle the alarm
 *   */

int pid_alarm_func(void *v)
{
        print_flag = 1;
        return 0;
}

int
pid_report_func(void *v)
{
        printf ("\n***************************************************\n");
        pid_print_report(v);

        return 0;
}

int
pid_bufmiss_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	trace_info_t *mytrcp = trcinfop;
	char tt_rec_ptr[MAX_REC_LEN];
        sched_switch_t *rec_ptr;
        int old_pid, next_pid;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);
        old_pid = rec_ptr->pid;
        if (rec_ptr->id == TRACE_SCHED_SWITCH) {
		rec_ptr = conv_sched_switch(a, &tt_rec_ptr);
                next_pid = rec_ptr->next_pid;
        } else {
                next_pid = rec_ptr->pid;
        }

	if (IS_LIKI) { 
		mytrcp = &trace_files[rec_ptr->cpu];
		mytrcp->cpu = rec_ptr->cpu;
	}
        if (check_for_missed_buffer(mytrcp, rec_ptr, next_pid)) {
                cpu_missed_buffer(mytrcp);

                foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))pid_missed_buffer,
                           NULL, 0, mytrcp);
        }
        return 0;
}

void 
track_submit_ios2(syscall_enter_t *rec_ptr)
{
	pid_info_t *pidp, *tgidp;
	ctx_info_t *ctxp;
	iocb_info_t *iocbp;
	uint64 ctx_id = rec_ptr->args[0];
	uint64 nr     = rec_ptr->args[1];
	uint64 iocbpp = rec_ptr->args[2];
	char *varptr = (char *)rec_ptr + sizeof(syscall_enter_t);
	iocbsum_t *iocb = (iocbsum_t *)varptr;
	syscall_info_t *syscallp, *gsyscallp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	int i = 0;
	int fd, oldfd = -1;

	ctxp = GET_CTX(&globals->ctx_hash, ctx_id);
	ctxp->pid = rec_ptr->pid;
	ctxp->syscallno = rec_ptr->syscallno;
	while ((char *)iocb < ((char *)rec_ptr + rec_ptr->reclen)) {
		iocbp =  GET_IOCB(&ctxp->iocb_hash, (uint64)iocb->iocbp);
		iocbp->hrtime = rec_ptr->hrtime;
		iocbp->op = iocb->aio_lio_opcode;
		iocbp->offset = iocb->aio_offset;
		iocbp->fd = iocb->aio_fildes;
		iocbp->bytes = iocb->aio_nbytes;
		iocb++;

		/* We also want to track the io_submit() system calls per fd */
		pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		fd = iocbp->fd;
		if ((fd < 65536) && (fd >= 0)) {
			fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
			syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
			if (fd != oldfd) {
				fdinfop->stats.syscall_cnt++;
	 			syscallp->stats.count++;
				if (pidp->tgid && (fdinfop->node == 0) && (fdinfop->ftype == 0)) {
					/* inherit fdinfop from primary thread */
					tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
					if (tfdinfop) fdinfop = tfdinfop;
				}

				if (global_stats && fdinfop->dev && fdinfop->node) {
					fdatap = GET_FDATAP(&globals->fdata_hash, fdinfop->dev, fdinfop->node);
					fdatap->stats.syscall_cnt++;
					gsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
					gsyscallp->stats.count++;
				}
				oldfd = fd;
			}
		}
	}


	return;
}


void
cpu_report(pid_info_t *pidp, FILE *pidfile)
{
	hc_info_t *hcinfop;
	print_pc_args_t print_pc_args;
	uint64 runtime;
	
	if (pidp->hcinfop == NULL) { 
		csv_printf(pid_csvfile, ",0,0,0,0");
		return;
	} 

	hcinfop = pidp->hcinfop;
        print_pc_args.hcinfop = hcinfop;
        print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = pidfile;

	runtime = sched_get_runtime(pidp);

	csv_printf (pid_csvfile, ",%d,%d,%d,%d", hcinfop->total, 
			hcinfop->cpustate[HC_USER],
			hcinfop->cpustate[HC_SYS],
			hcinfop->cpustate[HC_INTR]);


        pid_printf (pidfile, "\n    ******** CPU ACTIVITY REPORT ********\n");
        pid_printf (pidfile, "    The percentages below reflect the percentage \n");
        pid_printf (pidfile, "    of the Thread's total RunTime spent in either\n");
        pid_printf (pidfile, "    User code or System code \n");

        pid_printf (pidfile, "    RunTime: %8.4f\n\n", SECS(runtime));

        if (hcinfop->total == 0) {
                pid_printf (pidfile, "    No CPU activity detected for this process during the sampling interval\n");
                return;
        }

        pid_printf (pidfile, "      Count    USER     SYS    INTR\n");
        pid_printf (pidfile, "    %7d %7d %7d %7d\n", hcinfop->total, 
						hcinfop->cpustate[HC_USER], 
						hcinfop->cpustate[HC_SYS],
						hcinfop->cpustate[HC_INTR]);
	pid_printf (pidfile, "             %6.2f%% %6.2f%% %6.2f%%\n",
						hcinfop->cpustate[HC_USER]*100.0/hcinfop->total, 
					    	hcinfop->cpustate[HC_SYS]*100.0/hcinfop->total,
					    	hcinfop->cpustate[HC_INTR]*100.0/hcinfop->total);

        pid_printf (pidfile, "\n    HARDCLOCK entries\n");

        if (hcinfop->pc_hash==NULL) return;

        pid_printf (pidfile, "       Count     Pct  State  Function\n");
        foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc, pc_sort_by_count, nsym, (void *)&print_pc_args);  

        if (hcinfop->hc_stktrc_hash==NULL) return;

        pid_printf (pidfile, "\n       Count     Pct  HARDCLOCK Stack trace\n", tab);
        pid_printf (pidfile, "       ============================================================\n", tab);
        foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, hc_print_stktrc, stktrc_sort_by_cnt, nsym, (void *)&print_pc_args);
	
}

int
print_futex_info(void *arg1, void *arg2)
{
        pid_futex_info_t *pfutexp = arg1;
        FILE *pidfile = arg2;
	var_arg_t vararg;

	if (pfutexp->cnt == 0) return 0;

        pid_printf (pidfile, "%s0x%-29llx %7d   %26s %11.6f %11.6f %11.6f\n", tab,
                        pfutexp->addr,
                        pfutexp->cnt,
                        "-",
                        SECS(pfutexp->total_time),
                        SECS(pfutexp->total_time)/pfutexp->cnt,
                        SECS(pfutexp->max_time));

	vararg.arg1 = pidfile;
	vararg.arg2 = NULL;
        foreach_hash_entry((void **)pfutexp->ops_hash, FUTEXOP_HSIZE, futex_print_ops_detail, futexops_sort_by_op, 0, &vararg);
        return 0;
}

void
pid_futex_report(pid_info_t *pidp, FILE *pidfile) {

	int futex_cnt = 0;
        
	if (pidp->syscall_cnt == 0) return;

        foreach_hash_entry((void **)pidp->futex_hash, FUTEX_HSIZE, hash_count_entries, NULL, 0, &futex_cnt);

	if (futex_cnt) {
		pid_printf (pidfile, "\n\n%s******** FUTEX REPORT ********\n", tab);
		pid_printf (pidfile, "%sTop Futex Addrs by elapsed time\n", tab, nfutex);
		pid_printf (pidfile, "%sTotal Futex count = %d (Top %d listed)\n", tab, futex_cnt, MIN(futex_cnt, nfutex));

		pid_printf (pidfile, "\n%sMutex Addr                        Count  EAGAIN  ETIMEDOUT  AvRetVal     ElpTime         Avg         Max   Max_Waker\n", tab);

		foreach_hash_entry((void **)pidp->futex_hash, FUTEX_HSIZE, print_futex_info, futex_sort_by_time, nfutex, pidfile);
	}
        return;
}

int
print_syscall_info(void *arg1, void *arg2)
{
	syscall_info_t *syscallp = arg1;
	var_arg_t *vararg = (var_arg_t *)arg2;
	FILE *pidfile = (FILE *)vararg->arg1;
	pid_info_t	*pidp = (pid_info_t *)vararg->arg2;
	syscall_stats_t *statp = &syscallp->stats;
	sched_stats_t *sstatp = &syscallp->sched_stats;
	short  *syscall_index;
	iov_stats_t *iovstatp;
	var_arg_t lvararg;
	uint64 tot_cnt;

	if (statp->count == 0) return 0;

	syscall_index = (SYSCALL_MODE(syscallp->lle.key) == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;
	 
	pid_printf (pidfile, "%s%-30s%8d %8.1f %11.6f %10.6f %10.6f %7d", tab,
		syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name,
		statp->count,
		statp->count / secs,
		SECS(statp->total_time),
		SECS(statp->total_time / statp->count),
		SECS(statp->max_time),
		statp->errors);

	if (statp->bytes && statp->count)  {
		pid_printf (pidfile, " %7lld %8.1f",
			(statp->bytes) / MAX((statp->count - statp->errors), statp->count),
			(statp->bytes) / (secs * 1024.0));
	}

	pid_printf (pidfile, "\n");

	if (scdetail_flag) {
 		if (sstatp->T_sleep_time && sstatp->C_sleep_cnt) {
			pid_printf (pidfile, "%s   %-27s%8d %8.1f %11.6f %10.6f\n", tab,
				"SLEEP",
				sstatp->C_sleep_cnt,
				sstatp->C_sleep_cnt/secs,
				SECS(sstatp->T_sleep_time),
				SECS(sstatp->T_sleep_time / sstatp->C_sleep_cnt));


			if ((IS_LIKI || IS_WINKI) && syscallp->slp_hash) {
				lvararg.arg1 = pidfile;
				lvararg.arg2 = NULL;
				foreach_hash_entry_l((void **)syscallp->slp_hash,
						SLP_HSIZE,
						print_slp_info,
						slp_sort_by_time, 0, &lvararg);
			}
		}
	
		if (sstatp->T_runq_time)
			pid_printf (pidfile, "%s   %-27s                  %11.6f\n",  tab,
				"RUNQ",
				SECS(sstatp->T_runq_time));

		if (sstatp->T_run_time &&  (sstatp->T_run_time != statp->total_time) )
			pid_printf (pidfile, "%s   %-27s                  %11.6f\n",  tab,
				"CPU",
				SECS(sstatp->T_run_time));
	}

	if (syscallp->iov_stats) {
		iovstatp = syscallp->iov_stats;
		tot_cnt = iovstatp->rd_cnt + iovstatp->wr_cnt;
		if (iovstatp->rd_cnt) 
			pid_printf (pidfile, "%s   %-27s%8d %8.1f %11s %10.6f %10.6f %7s %7lld %8.1f\n", tab,
					"AIO Reads",
					iovstatp->rd_cnt,
					iovstatp->rd_cnt/secs,
					" ",/* SECS(iovstatp->rd_time), */
					SECS(iovstatp->rd_time / iovstatp->rd_cnt),
					SECS(iovstatp->rd_max_time),
					" ",
					iovstatp->rd_bytes / iovstatp->rd_cnt,
					(iovstatp->rd_bytes) / (secs * 1024.0));
		if (iovstatp->wr_cnt) 
			pid_printf (pidfile, "%s   %-27s%8d %8.1f %11s %10.6f %10.6f %7s %7lld %8.1f\n", tab,
					"AIO Writes",
					iovstatp->wr_cnt,
					iovstatp->wr_cnt/secs,
					" ",/* SECS(iovstatp->wr_time), */
					SECS(iovstatp->wr_time / iovstatp->wr_cnt),
					SECS(iovstatp->wr_max_time),
					" ",
					iovstatp->wr_bytes / iovstatp->wr_cnt,
					(iovstatp->wr_bytes) / (secs * 1024.0));
		}
	
	return 0;	
}

void 
pid_syscall_report(pid_info_t *pidp, FILE *pidfile) { 
	var_arg_t vararg;
	if (pidp->syscall_cnt == 0) return;

	pid_printf (pidfile, "\n%s******** SYSTEM CALL REPORT ********\n", tab);
	pid_printf (pidfile, "%sSystem Call Name                 Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\n", tab);

	vararg.arg1 = pidfile;
	vararg.arg2 = pidp;
	foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, print_syscall_info, syscall_sort_by_time, 0, &vararg);

	return;
}

int
print_fd_info(void *arg1, void *arg2)
{
	fd_info_t *fdinfop = arg1, *tfdinfop;
	var_arg_t *vararg = (var_arg_t *)arg2;
	FILE *pidfile = (FILE *)vararg->arg1;
	pid_info_t *pidp = (pid_info_t *)vararg->arg2, *tgidp;
	fdata_info_t *fdatap, *tfdatap;
	struct sockaddr_in6 *lsock, *rsock;
	
	if (fdinfop->stats.syscall_cnt == 0) 
		return 0;

	pid_printf (pidfile, "%sFD: %d", tab, fdinfop->FD);

	if (fdinfop->lsock) {
		lsock = fdinfop->lsock;
		rsock = fdinfop->rsock;
		pid_printf (pidfile, " %s    ", (fdinfop->ftype == F_IPv4) ? "IPv4" : "IPv6");
		if (fdinfop->node == TCP_NODE) {
			pid_printf (pidfile, " TCP ");
		} else if (fdinfop->node == UDP_NODE) {
			pid_printf (pidfile, " UDP ");
		} else {
			pid_printf (pidfile, " UKN ");
		}
	 	print_ip_port_v6(fdinfop->lsock, 0, pidfile);	
		if (fdinfop->node == TCP_NODE) {
			pid_printf (pidfile, "->");
	 		print_ip_port_v6(fdinfop->rsock, 0, pidfile);	
			pid_printf (pidfile, " (ESTABLISHED)");
		}
	} else if (fdinfop->ftype) {
		pid_printf (pidfile, " %-8s", ftype_name_index[fdinfop->ftype]);
		if ((fdinfop->ftype == F_IPv4) || (fdinfop->ftype == F_IPv6)) {
			if (fdinfop->node == TCP_NODE) {
				pid_printf (pidfile, " TCP");
			} else if (fdinfop->node == UDP_NODE) {
				pid_printf (pidfile, " UDP");
			} else {
				pid_printf (pidfile, " UKN");
			}
		} else if (fdinfop->ftype == F_unix) {
			pid_printf (pidfile, " %u", fdinfop->node);	
		} else {	
			pid_printf (pidfile, " dev: 0x%x", fdinfop->dev);
		} 
		fdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash, 
						FDATA_KEY(fdinfop->dev, fdinfop->node),
						FDATA_HASH(fdinfop->dev, fdinfop->node));
		if (fdatap && fdatap->fnameptr) {
			pid_printf (pidfile, " %s", fdatap->fnameptr);
		} else {
			if (fdinfop->fnamep) {
				pid_printf (pidfile, " %s", fdinfop->fnamep);
				if (fdinfop->multiple_fnames) pid_printf (pidfile, " (multiple)");
			} else {
				pid_printf (pidfile, "     - filename not found");
			}
		}
	} else if (pidp->tgid) {
		/* inherit filenames from primary thread */
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
		if (tfdinfop) {
			pid_printf (pidfile, " %-8s", ftype_name_index[tfdinfop->ftype]);
			if ((tfdinfop->ftype == F_IPv4) || (tfdinfop->ftype == F_IPv6)) {
				if (tfdinfop->node == TCP_NODE) {
					pid_printf (pidfile, " TCP");
				} else if (tfdinfop->node == UDP_NODE) {
					pid_printf (pidfile, " UDP");
				} else {
					pid_printf (pidfile, " UKN");
				}
			} else if (tfdinfop->ftype == F_unix) {
				pid_printf (pidfile, " %d", tfdinfop->node);	
			} else {	
				pid_printf (pidfile, " dev: 0x%x", tfdinfop->dev);
			} 
	
                	tfdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash,
                                                FDATA_KEY(tfdinfop->dev, tfdinfop->node),
                                                FDATA_HASH(tfdinfop->dev, tfdinfop->node));
                	if (tfdatap && tfdatap->fnameptr) {
                        	pid_printf (pidfile, " %s", tfdatap->fnameptr);
				if (tfdinfop->multiple_fnames) pid_printf (pidfile, " (multiple)");
                	} else if (tfdinfop->fnamep) {
				pid_printf (pidfile, " %s", tfdinfop->fnamep);
				if (tfdinfop->multiple_fnames) pid_printf (pidfile, " (multiple)");
			} else {
				pid_printf (pidfile, "     - filename not found");
                	}
		} else {
			if (fdinfop->fnamep) {
				pid_printf (pidfile, " %s", fdinfop->fnamep);
				if (fdinfop->multiple_fnames) pid_printf (pidfile, " (multiple)");
			} else {
				pid_printf (pidfile, "     - filename not found");
			}
		}
	} else {
		if (fdinfop->fnamep) {
			pid_printf (pidfile, " %s", fdinfop->fnamep);
			if (fdinfop->multiple_fnames) pid_printf (pidfile, " (multiple)");
		} else {
			pid_printf (pidfile, "     - filename not found");
		}
	}

	pid_printf (pidfile, "\n");
	
	pid_printf (pidfile, "%sSystem Call Name                 Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\n", tab);
	foreach_hash_entry((void **)fdinfop->syscallp, SYSCALL_HASHSZ, print_syscall_info, syscall_sort_by_time, 0, vararg);
	pid_printf (pidfile, "\n");

}

void 
pid_fd_report(pid_info_t *pidp, FILE *pidfile) { 

	var_arg_t vararg;
	if ((pidp->fdhash == NULL) && (pidp->fobj_hash == NULL))  {
		return;
	}

	pid_printf (pidfile, "\n%s******** FILE ACTIVITY REPORT ********\n", tab);

	if (is_alive) foreach_hash_entry(pidp->fdhash, FD_HSIZE, get_filename, NULL, 0, pidp);

	vararg.arg1 = pidfile;
	vararg.arg2 = pidp;

	if (pidp->fobj_hash) {
	        printf ("%s                    -------  Total  ------- -------  Write  -------- --------  Read  --------\n", tab);
		                printf ("%sObject                 IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz  filename\n", tab);
		foreach_hash_entry(pidp->fobj_hash, FOBJ_HSIZE, calc_fobj_totals, NULL, 0, 0);
		foreach_hash_entry((void **)pidp->fobj_hash, FOBJ_HSIZE, file_print_fobj_logio,
				fobj_sort_by_logio,
				0, &vararg);
	}

	if (pidp->fdhash) {
		foreach_hash_entry((void **)pidp->fdhash, FD_HSIZE, print_fd_info,
				fd_sort_by_time,
				0, &vararg);
	}


	return;
}

void 
pid_socket_report(pid_info_t *pidp, FILE *pidfile) { 

	var_arg_t vararg;
	if (pidp->sdata_hash == NULL) {
		return;
	}

	pid_printf (pidfile, "\n%s******** SOCKET ACTIVITY REPORT ********\n", tab);

	vararg.arg1 = pidfile;
	vararg.arg2 = pidp;

	if (pidp->sdata_hash) {
		pid_printf (pidfile, "%sRequests      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection\n", tab);
		pid_printf (pidfile, "%s================================================================================\n", tab);
		foreach_hash_entry2((void **)pidp->sdata_hash, SDATA_HASHSZ, 
			   socket_print_perpid_sdata,
                           (int (*)())sdata_sort_by_syscalls,
                           0, pidfile);
	}

	return;
}

int
print_pid_memory(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	docker_info_t *dockerp = pidp->dockerp;
        sched_info_t *schedp;
        uint64 *warnflagp = (uint64 *)arg2;

        dock_printf ("%8d %8d %8d %s",
                pidp->vss,
                pidp->rss,
		pidp->PID,
		pidp->cmd);
        if (pidp->hcmd) dock_printf ("  {%s}", pidp->hcmd);
        if (pidp->thread_cmd) dock_printf (" (%s)", pidp->thread_cmd);
	if (dockerp && (dockfile == NULL)) {
        	printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", dockerp->ID);
	}

        dock_printf ("\n");

        return 0;
}

int
print_pgcache_info(void *arg1, void *arg2)
{
	pgcache_t *pgcachep = (pgcache_t *)arg1;
	FILE *pidfile = (FILE *)arg2;
	fdata_info_t *fdatap;
	uint64 dev;
	uint64 node;
	uint32 ftype;
	char *fnameptr;

	if ((pgcachep->cache_evict_cnt + pgcachep->cache_insert_cnt) == 0) return 0;	

	dev = (pgcachep->lle.key >> 32 ) & 0xffffffff;
	node = pgcachep->lle.key & 0xffffffff;
	fdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash, 
					PGCACHE_KEY(dev, node),
					PGCACHE_HASH(dev, node));

	if (fdatap == NULL) {
		ftype = 0;
		fnameptr = "???";
	} else {
		ftype = fdatap->ftype;
		fnameptr = fdatap->fnameptr;
	}

        pid_printf (pidfile, "%s%8d %8d  0x%08llx %10d %8s  %s\n", tab,
                        pgcachep->cache_insert_cnt,
                        pgcachep->cache_evict_cnt,
                        dev,
                        node,
                        ftype_name_index[ftype],
                        fnameptr ? fnameptr : "???");

	return 0;
}

void 
pid_cache_report(pid_info_t *pidp, FILE *pidfile) {
	if ((pidp->cache_insert_cnt + pidp->cache_evict_cnt) == 0) {
		return;
	}

	pid_printf (pidfile, "\n%s******** PAGE CACHE REPORT ********\n", tab);
	pid_printf (pidfile, "%s Inserts   Evicts         dev       node     type  Filename\n", tab);
	foreach_hash_entry((void **)pidp->pgcache_hash, PGCACHE_HASHSZ, print_pgcache_info,
				pgcache_sort_by_cnt,
				0, pidfile);
}

void 
pid_sock_report(pid_info_t *pidp, FILE *pidfile) { 

	csv_printf(pid_csvfile,",%3.1f,%2.1f,%2.1f,%2.1f", pidp->netstats.rd_cnt/secs, (pidp->netstats.rd_bytes/secs)/1024,
	                                                  pidp->netstats.wr_cnt/secs, (pidp->netstats.wr_bytes/secs)/1024);
}

void 
pid_dsk_report(pid_info_t *pidp, FILE *pidfile) 
{ 
	calc_pid_iototals(pidp, NULL);

	if (pid_csvfile) print_pid_iototals_csv(pidp);

	if (pidp->iostats[IO_TOTAL].compl_cnt) {
		pid_printf (pidfile, "\n    ******** PHYSICAL DEVICE REPORT ********\n");
		pid_printf (pidfile, "%s    device   rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
		foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
		foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, dsk_print_dev_iostats, dev_sort_by_dev, 0, pidfile);

		print_pid_iototals(&pidp->iostats[0], pidfile);
	} 

	if (pidp->miostats[IO_TOTAL].compl_cnt) {
		pid_printf (pidfile, "\n    ******** DEVICE-MAPPER REPORT ********\n");
		pid_printf (pidfile, "%s    device   rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, dsk_print_dev_iostats, dev_sort_by_dev, 0, pidfile);

		print_pid_iototals(&pidp->miostats[0], pidfile);
	}
}

/*
 **
 */
int
pid_report(void *arg1, void *v)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	filter_t *f = (filter_t *)v;
	char pid_fname[20];
	char vis_dir[20];
	char vis_fname[32];
	char vis_tl_fname[32];
	char wtree_fname[32];
        char json_fname[32];
	char json_wtree_fname[32];
        char sym_pid_fname[32];
        char sym_detail_fname[32];
	pid_info_t *ppidp, *tgidp;
	sched_info_t *schedp;
	docker_info_t *dockerp;
	unsigned long *msrptr;
	int ret;
	FILE *pid_jsonfile;
	FILE *pid_wtree_jsonfile;
	FILE *pidfile;

	dockerp = pidp->dockerp;

	/* we can remove the check for IS_WINKI when we do the trc stats */
	if (!IS_WINKI && pidp->num_tr_recs == 0) return 0;
	if ((pidp->PID == -1) || (pidp->PID==0)) return 0;

	if (!check_filter(f->f_P_pid, (uint64)pidp->PID) &&
            !check_filter(f->f_P_tgid, (uint64)pidp->tgid))
                return 0;

	load_perpid_objfile_and_shlibs(pidp); 

        if (pidtree) {
                sprintf (pid_fname, "%sS/%d", tlabel, (int)pidp->PID);
                if ((pidfile = fopen(pid_fname, "w")) == NULL) {
                        fprintf (stderr, "Unable to open PID file %s, errno %d\n", pid_fname, errno);
                        fprintf (stderr, "  Continuing without PID output\n");
                }
        } else {
		pidfile = NULL;
	}

        /* Set up the VIS/pid dir data files if visualizations are requested */

        if (vis) {
/**		if (wtree_build(pidp)) {
**			 fprintf (stderr, "Unable to create the wait tree.\n");
*/

		sprintf (vis_dir, "VIS/%d", (int)pidp->PID);
		sprintf (vis_fname, "VIS/%d/pid_detail.html", (int)pidp->PID);
		sprintf (vis_tl_fname, "VIS/%d/pid_timeline.html", (int)pidp->PID);
		sprintf (wtree_fname, "VIS/%d/pid_wtree.html", (int)pidp->PID);
                sprintf(sym_pid_fname, "../../%sS/%d", tlabel, (int)pidp->PID);
                sprintf(sym_detail_fname, "VIS/%d/detail.txt", (int)pidp->PID);

		ret = mkdir(vis_dir, 0777);
                if (ret && (errno != EEXIST)) 
                        fprintf (stderr, "Unable to make VIS/_pid_ directory, errno %d\n", errno);
                sprintf (json_fname, "VIS/%d/pid_detail.json", (int)pidp->PID);
		sprintf (json_wtree_fname, "VIS/%d/pid_wtree.json", (int)pidp->PID);
                if ((pid_jsonfile = fopen(json_fname, "w")) == NULL) {
                        fprintf (stderr, "Unable to open JSON file %s, errno %d\n", json_fname, errno);
                        fprintf (stderr, "  Continuing without pidvisualize option\n");
			CLEAR(VIS_FLAG);
                }
		if ((pid_wtree_jsonfile = fopen(json_wtree_fname, "w")) == NULL) {
                        fprintf (stderr, "Unable to open JSON file %s, errno %d\n", json_wtree_fname, errno);
                        fprintf (stderr, "  Continuing without pidvisualize option\n");
			CLEAR(VIS_FLAG);
                }
		ret = symlink("../../pid_detail.html", vis_fname);
		if (ret) {
			if (errno != EEXIST) {
				fprintf (stderr, "Unable to make symlink to pid_detail.html\n", errno);
				fprintf (stderr, "  Continuing without pidvisualize option\n"); 
				CLEAR(VIS_FLAG);
			}
		}
		 ret = symlink("../../pid_timeline.html", vis_tl_fname);
                if (ret) {
                        if (errno != EEXIST) {
                                fprintf (stderr, "Unable to make symlink to pid_timeline.html\n", errno);
                                fprintf (stderr, "  Continuing without pidvisualize option\n");
                                CLEAR(VIS_FLAG);
                        }
                }
		ret = symlink("../../pid_wtree.html", wtree_fname);
                if (ret) {
			if (errno != EEXIST) {
                        	fprintf (stderr, "Unable to make symlink to pid_wtree.html\n", errno);
                        	fprintf (stderr, "  Continuing without pidvisualize option\n");
				CLEAR(VIS_FLAG);
			}
                }
		ret = symlink(sym_pid_fname, sym_detail_fname);
                if (ret) {
			if (errno != EEXIST) {
                        	fprintf (stderr, "Unable to make symlink for detail.txt file\n", errno);
                        	fprintf (stderr, "  Continuing without pidvisualize option\n");
				CLEAR(VIS_FLAG);
			}
                }
        } else {
                pid_jsonfile = NULL;
		pid_wtree_jsonfile = NULL;
        }

	pid_printf (pidfile, "\n%s %d  %s", tlabel, (int)pidp->PID, (char *)pidp->cmd);
	if (pidp->hcmd) pid_printf (pidfile, "  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) pid_printf (pidfile, "  (%s)", pidp->thread_cmd);

	pid_printf (pidfile, "\n");
	
	if (pidp->ppid) {
		ppidp = GET_PIDP(&globals->pid_hash, pidp->ppid);
		pid_printf (pidfile, "  PPID %d  %s", ppidp->PID, (char *)ppidp->cmd);
		if (ppidp->hcmd) pid_printf (pidfile, "  {%s}", ppidp->hcmd);
		if (ppidp->thread_cmd) pid_printf (pidfile, "  (%s)", ppidp->thread_cmd);
		pid_printf (pidfile, "\n");
	}
	if (pidp->tgid && (pidp->tgid != pidp->PID)) {
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		dockerp = tgidp->dockerp;
		pid_printf (pidfile, "  %s %d  %s", plabel, tgidp->PID, (char *)tgidp->cmd);
		if (tgidp->hcmd) pid_printf (pidfile, "  {%s}", tgidp->hcmd);
		if (tgidp->thread_cmd) pid_printf (pidfile, "  (%s)", tgidp->thread_cmd);
		pid_printf (pidfile, "\n");
	}
	if (pidp->nlwp > 1) {
		pid_printf (pidfile, "    NLWP: %d\n", pidp->nlwp);
	}

	if (dockerp) {
		printf ("\n    Container ID: %012llx  Name: %s\n", dockerp->ID, dockerp->name);
	}

	csv_printf (pid_csvfile, "%d,%s,%s,%s,%d,%d,%d,%s,%llx,%d,%d", (int)pidp->PID, 
					pidp->cmd,
					pidp->thread_cmd ? pidp->thread_cmd : " ",
					pidp->hcmd ? pidp->hcmd : " ",
					pidp->ppid,pidp->tgid,pidp->nlwp,
					dockerp ? dockerp->name : " ",
					dockerp ? dockerp->ID : 0,
					pidp->elf,pidp->syscall_cnt);

	

	tab=tab4;
	if (sched_flag) sched_report(pidp, pidfile, pid_jsonfile, pid_wtree_jsonfile);
	if (hc_flag) cpu_report(pidp, pidfile);
	if (scall_flag) pid_syscall_report(pidp, pidfile);
	if (file_flag) pid_fd_report(pidp, pidfile);
	if (file_flag) pid_socket_report(pidp, pidfile);
	if (pgcache_flag) pid_cache_report(pidp, pidfile);
	if (futex_flag) pid_futex_report(pidp, pidfile);
	if (sock_flag) pid_sock_report(pidp, pidfile);
	if (dsk_flag) pid_dsk_report(pidp, pidfile);

	if (msr_flag && pidp->schedp) 	{
		schedp = pidp->schedp;
		msrptr = &schedp->sched_stats.msr_total[0];
	                csv_printf (pid_csvfile, ",%lld,%lld,%3.2f%%,%lld,%lld,%3.2f,%3.2f,%lld",
				msrptr[LLC_REF], msrptr[LLC_REF] - msrptr[LLC_MISSES],
                                (1.0 - (msrptr[LLC_MISSES]*1.0 / msrptr[LLC_REF])) * 100.0,
				msrptr[RET_INSTR], msrptr[CYC_NOHALT_CORE],
                                msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
				msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                                msrptr[SMI_CNT]);
	}

	if (hthr == 0) printf ("\n---------------------------------------------------------------------------------------------\n");

	if (pidfile) {
		fclose(pidfile);
		pidfile = NULL;
	}
	if (pid_jsonfile) {
                fclose(pid_jsonfile);
                pid_jsonfile = NULL;
        }
        if (pid_wtree_jsonfile) {
                fclose(pid_wtree_jsonfile);
                pid_wtree_jsonfile = NULL;
        }

	csv_printf (pid_csvfile, "\n");

	/* fprintf (stderr, "pid_report() %s=%d - completed\n", label, pidp->PID);  */

	return 0;
}

void
sid_report(void *v)
{
        int i, oraproc_idx;
        sid_pid_t *sidpidp;
        pid_info_t *pidp;
        int ppid;

        printf ("\nOracle Instances running on system:\n");
        for (i = 1; i < next_sid; i++) {
                printf ("    %s\n", sid_table[i].sid_name);
        }

        for (i = 1; i < next_sid; i++) {
                printf ("\n*********************************************************\n");
                printf ("**            Oracle Instance: %-20s    **\n", sid_table[i].sid_name);
                printf ("*********************************************************\n");

                for (oraproc_idx=0; oraproc_idx <= ORACLE; oraproc_idx++) {
                        sidpidp = sid_table[i].sid_pid[oraproc_idx];
                        if (sidpidp) {
                                printf ("\n---------------------------------------------------------\n");
                                printf ("--            %-34s       --\n",
                                                (char *)oracle_procname[oraproc_idx]);
                                printf ("---------------------------------------------------------\n\n");
                        }

                        while (sidpidp != NULL) {
                                pidp = sidpidp->pidinfop;

                                if ((pidp->num_tr_recs == 0) && (oraproc_idx == ORACLE)) {
                                        pidp->num_tr_recs = 0;
                                        sidpidp = (sid_pid_t *)sidpidp->lle.next;
                                        continue;
                                }

                                pidp = sidpidp->pidinfop;

                                if (pidp->num_tr_recs) {
                                        /* Only print traced threads */
                                        pid_report(pidp, v);
                                } else {
                                        printf ("No trace events recorded for this process\n");
                                }

                                if (is_alive) pidp->num_tr_recs = 0;
                                sidpidp = (sid_pid_t *)sidpidp->lle.next;

                        }

                }
        }

	if (is_alive) {
		clear_all_stats();
		load_objfile_and_shlibs();
	}

        return;
}

int
pid_print_report(void *v)
{
	if (is_alive) {
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_command, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
		update_perpid_sched_stats();
	}
	if (IS_LIKI && !kiall_flag) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);

	update_perpid_sched_stats();

	if (oracle) {
		sid_report(v);
	} else {
		csv_printf(pid_csvfile,"%s,Command,Thread,Hadoop Proc,ppid,%s,nlwp,Container Name,Container ID,elf64,syscalls", tlabel, plabel);
		if (sched_flag) csv_printf (pid_csvfile,",policy,runtime,systime,usertime,runqtime,sleeptime,irqtime,stealtime,switch,sleep,preempt,wakeup,runtime/swtch,lastcpu,lastldom,migr,nodemigr,vss,rss");
		if (hc_flag) csv_printf (pid_csvfile,",TotHC,UserHC,SysHC,IntHC");
		if (sock_flag) csv_printf(pid_csvfile,",Net Rd/s,Net Rd KB/s,Net Wr/s,Net KB Wr/s");
		if (dsk_flag)  {
                        csv_printf(pid_csvfile,",Phys Rd Cnt,Phys Rd KB,Phys Rd ElpTm,Phys Rd Rt,Phys Rd KB Rt,Phys Rd Avsz,Phys Rd Avwait,Phys Rd Avserv,Phys Rd Requeue,Phys Rd Abort, Phys Rd Flush,Phys Rd Maxwait,Phys Rd Maxserv");
                        csv_printf(pid_csvfile,",Phys Wr Cnt,Phys Wr KB,Phys Wr ElpTm,Phys Wr Rt,Phys Wr KB Rt,Phys Wr Avsz,Phys Wr Avwait,Phys Wr Avserv,Phys Wr Requeue,Phys Wr Abort, Phys Wr Flush,Phys Wr Maxwait,Phys Wr Maxserv");
		}
		if (msr_flag)  csv_printf(pid_csvfile,",LLC_Ref,LLC_Hits,LLC_hit%%,Instrs,Cycles,CPI,Avg MHz,SMI Count");
		csv_printf(pid_csvfile,"\n");

        	foreach_hash_entry_mt((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))pid_report,
                           (int (*)()) pid_sort_by_runtime,
                           0, v);

		if (is_alive) {
			clear_all_stats();
			load_objfile_and_shlibs();
		}
	}

	return 0;
}

int
pid_print_func(void *v)
{
        struct timeval tod;
        if (debug) printf ("pid_print_func\n");
        printf ("pid_print_func\n");

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                pid_print_report(v);
                print_flag = 0;
        }
        return 0;
}


int
pid_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("pid_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
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
                start_time = KD_CUR_TIME;
        	bufmiss_func = pid_bufmiss_func;
        }

        if (strstr(buf, ts_end_marker)) {
		set_events_all(0);
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
