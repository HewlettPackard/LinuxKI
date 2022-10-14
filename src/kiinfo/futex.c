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
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "hash.h"
#include "info.h"
#include "syscalls.h"
#include "sched.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include "futex.h"
#include "msgcat.h"

int futex_ftrace_print_func(void *, void *);

/* 
 ** The initialisation function 
 */
void 
futex_init_func(void *v)
{
	if (debug) printf ("futex_init_func()\n");
	process_func = NULL;
	print_func = futex_print_func;
	report_func = futex_report_func;
	bufmiss_func = pid_bufmiss_func;
	bufmiss_func = NULL;
	filter_func = info_filter_func;   /* no filter func for kirunq, use generic */

	/* go ahead and initialize the trace functions, but do not set the execute field */
	ki_actions[TRACE_SYS_EXIT].func = futex_sys_exit_func;
	ki_actions[TRACE_SYS_ENTER].func = futex_sys_enter_func;
	ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;
	ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_thread_names_func;

	if (IS_LIKI || is_alive) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
		ki_actions[TRACE_SYS_ENTER].execute = 1;
		if (!is_alive) {
			ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
			ki_actions[TRACE_SCHED_SWITCH].execute = 1;
		}
	} else {
		set_events_all(0);
		ki_actions[TRACE_PRINT].func = futex_ftrace_print_func;
		ki_actions[TRACE_PRINT].execute = 1;
	}

	if (timestamp) {
		parse_lsof();
		parse_pself();
		parse_edus();
		parse_jstack();

		/* futex_csvfile = open_csv_file("kifutex", 1); */
	}
}

int
futex_process_func(void *a, void *arg)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	return 0;
}

int futex_ftrace_print_func(void *a, void *arg)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
	if (debug) printf ("futex_ftrace_print_func()\n");

	if (strstr(buf, ts_begin_marker)) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
		ki_actions[TRACE_SYS_ENTER].execute = 1;
		ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_SCHED_SWITCH].execute = 1;
		start_time = KD_CUR_TIME;
	}

	if (strstr(buf, ts_end_marker)) {
		ki_actions[TRACE_SYS_EXIT].execute = 0;
		ki_actions[TRACE_SYS_ENTER].execute = 0;
		ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
		ki_actions[TRACE_SCHED_SWITCH].execute = 0;
		end_time = KD_CUR_TIME;
		bufmiss_func = NULL;
	}
	
	if (debug) {
		PRINT_KD_REC(rec_ptr);
		PRINT_EVENT(rec_ptr->KD_ID);
		printf (" %s\n", buf);
	}
}

int
futex_print_pids_detail(void *arg1, void *arg2)
{
        futex_pids_t	*fpidp = arg1;
	pid_info_t	*pidp;
        pid_info_t      *wpidp;

	if (fpidp->cnt == 0) return 0;

	pidp = GET_PIDP(&globals->pid_hash, fpidp->lle.key);
	printf("%s    PID= ",tab);
	PID_URL_FIELD8(fpidp->lle.key);
        printf("%-14s %7d %7d %10d   %7.2f %11.3f %11.6f %11.6f  ",tab, 
                        fpidp->cnt,
                        fpidp->n_eagain,
                        fpidp->n_etimedout,
                        (fpidp->ret_total* 1.0)/fpidp->cnt,
                        SECS(fpidp->total_time),
                        SECS(fpidp->total_time)/fpidp->cnt,
                        SECS(fpidp->max_time));

	if (pidp->cmd) printf (" %s", pidp->cmd);
	if (pidp->hcmd) printf (" {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);

#if 0
	/* This is being removed for now */	
	if ((int32)fpidp->max_waker > 0) {
		PID_URL_FIELD8_2(fpidp->max_waker);
	} else 
		printf("%-8d",fpidp->max_waker);
	printf(" (%s)", (fpidp->max_waker == -1) ? "ICS" : (wpidp->cmd ? wpidp->cmd : "NA"));
#endif
	printf ("\n");

        if (fpidp->n_othererr) printf ("%s    %-27s %7d\n\n",tab,"Other Errors", fpidp->n_othererr);
        return 0;
}

int
futex_clear_pids_detail(void *arg1, void *arg2)
{
        futex_pids_t	*fpidp = arg1;

	fpidp->cnt = 0;
	fpidp->total_time = 0;
	fpidp->max_time = 0;
	fpidp->max_waker = 0;
	fpidp->ret_total = 0;
	fpidp->n_eagain = 0;
	fpidp->n_etimedout = 0;
	fpidp->n_othererr = 0;

        return 0;
}


int
futex_print_ops_detail(void *arg1, void *arg2)
{
        futex_op_t      *fopsp = arg1;
	var_arg_t *vararg = (var_arg_t *)arg2;
	FILE *pidfile = (FILE *)vararg->arg1;
        gbl_futex_info_t *gfp = (gbl_futex_info_t *)vararg->arg2;
        pid_info_t      *wpidp;
	int		pid_cnt = 0;

	if (fopsp->cnt == 0) return 0;

        pid_printf (pidfile, "%s  %-29s %7d %7d %10d   %7.2f %11.3f %11.6f %11.6f  ",tab, 
                        (fopsp->lle.key & FUTEX_PRIVATE_FLAG) ? futex_privopcode_name[fopsp->lle.key & FUTEX_CMD_MASK] : futex_opcode_name[fopsp->lle.key & FUTEX_CMD_MASK],
                        fopsp->cnt,
                        fopsp->n_eagain,
                        fopsp->n_etimedout,
                        (fopsp->ret_total* 1.0)/fopsp->cnt,
                        SECS(fopsp->total_time),
                        SECS(fopsp->total_time)/fopsp->cnt,
                        SECS(fopsp->max_time));

	if (fopsp->pids_hash) {
		pid_printf (pidfile, "\n");
		foreach_hash_entry((void **)fopsp->pids_hash,FUTEXPID_HSIZE,
                        (int (*)(void *, void *))hash_count_entries,
                        NULL, 0, &pid_cnt);
		
		if (npid && pid_cnt) {
			foreach_hash_entry((void **)fopsp->pids_hash,FUTEXPID_HSIZE,
                       		(int (*)(void *, void *))futex_print_pids_detail,
                        	futex_pidsort_by_time, npid, NULL);
		}
	} else if ((uint32)fopsp->max_waker > 0) {
	       	wpidp = GET_PIDP(&globals->pid_hash, fopsp->max_waker);
                pid_printf(pidfile, "%-8d", (int)fopsp->max_waker);
                /* PID_URL_FIELD8_2(fopsp->max_waker); */

		if (wpidp->cmd) pid_printf (pidfile, " %s", wpidp->cmd);
		if (wpidp->hcmd) pid_printf (pidfile," {%s}", wpidp->hcmd);
		if (wpidp->thread_cmd) pid_printf (pidfile, " (%s)", wpidp->thread_cmd);
		if (wpidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(wpidp->dockerp))->ID);
		pid_printf (pidfile, "\n");
	} else if (fopsp->max_waker == -1) {
		pid_printf (pidfile, "ICS\n");
	} else {
		pid_printf (pidfile, "\n");
	}
		
        if (fopsp->n_othererr) pid_printf (pidfile, "    %-27s %7d\n","Other Errors", fopsp->n_othererr);
	if (npid && pid_cnt && fopsp->pids_hash)  {
		pid_printf (pidfile, "    Total PID count = %d (Top %d listed)\n", pid_cnt, MIN(pid_cnt, npid));
	}

        return 0;
}

int
futex_clear_ops_detail(void *arg1, void *arg2)
{
        futex_op_t      *fopsp = arg1;

	fopsp->cnt = 0;
	fopsp->total_time = 0;
	fopsp->max_time = 0;
	fopsp->max_waker = 0;
	fopsp->ret_total = 0;
	fopsp->n_eagain = 0;
	fopsp->n_etimedout = 0;
	fopsp->n_othererr = 0;

	if (fopsp->pids_hash) {
		foreach_hash_entry((void **)fopsp->pids_hash,FUTEXPID_HSIZE,
                        (int (*)(void *, void *))futex_clear_pids_detail,
                        NULL, 0, NULL);
	}
        return 0;
}

int
futex_print_reque_detail(void *arg1, void *arg2)
{
        futex_reque_t      *freqp = arg1;

	if (freqp->cnt) {
        	printf("%s  0x%-27llx %7d\n",tab, freqp->lle.key, freqp->cnt);
	}

        return 0;
}

int
futex_clear_reque_detail(void *arg1, void *arg2)
{
	futex_reque_t	*freqp = arg1;

	freqp->cnt = 0;
	return 0;
}

int
futex_print_dup_detail(void *arg1, void *arg2)
{
        futex_dup_t      *fdupp = arg1;

	if (fdupp->cnt) {
        	printf("%s  0x%-27llx %7d\n",tab, fdupp->addr, fdupp->cnt);
	}
        return 0;
}

int
futex_clear_dup_detail(void *arg1, void *arg2)
{
	futex_dup_t	*fdupp = arg1;

	fdupp->cnt = 0;
	return 0;
}

int
futex_print_detail(void *arg1, void *arg2)
{
	gbl_futex_info_t        *gfp = arg1;
	pid_info_t              *pidp;
	int			pid_cnt = 0;
	pid_info_t		*wpidp;
	var_arg_t		vararg;

	if (gfp->cnt == 0) return 0;

	wpidp = GET_PIDP(&globals->pid_hash, gfp->max_waker);
	foreach_hash_entry((void **)gfp->pids_hash,FUTEXPID_HSIZE,
                        (int (*)(void *, void *))hash_count_entries,
                        NULL, 0, &pid_cnt);

	CAPTION_GREY;
	BOLD ("Futex 0x%-16llx - Total PID count = %-8d",
			gfp->addr,
			pid_cnt);

	if (cluster_flag) {SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_2_3); }

	_CAPTION;
	BOLD ("%sOperation                         Count  EAGAIN  ETIMEDOUT  AvRetVal     ElpTime         Avg         Max   Process/Thread name\n", tab);
	printf("  %-29s %7d %7d %10d   %7.2f %11.3f %11.6f %11.6f   ", 
                        "ALL",
                        gfp->cnt,
                        gfp->n_eagain,
                        gfp->n_etimedout,
                        (gfp->ret_total* 1.0)/gfp->cnt,
                        SECS(gfp->total_time),
                        SECS(gfp->total_time)/gfp->cnt,
                        SECS(gfp->max_time));

	NL;

	if (gfp->uaddr2_hash) {
		BOLD ("%s  Requeued Addresses              Count\n",tab);
		foreach_hash_entry((void **)gfp->uaddr2_hash,FUTEX_HSIZE,
                        (int (*)(void *, void *))futex_print_reque_detail,
                        futex_reqsort_by_cnt, nfutex, NULL);		
	}	

	if (gfp->dup_hash) {
                BOLD ("%s  Proc-shared Addresses           Count\n",tab);
                foreach_hash_entry((void **)gfp->dup_hash,FUTEX_HSIZE,
                        (int (*)(void *, void *))futex_print_dup_detail,
                        futex_dupsort_by_cnt, nfutex, NULL);
        }

	vararg.arg1 = NULL;
	vararg.arg2 = gfp;
	foreach_hash_entry((void **)gfp->ops_hash,FUTEXOP_HSIZE,
                        (int (*)(void *, void *))futex_print_ops_detail,
                        futexops_sort_by_op, 0, &vararg);

	NL;
	return 0;
}

int
futex_clear_stats(void *arg1, void *arg2)
{
	gbl_futex_info_t        *gfp = arg1;
	pid_info_t              *pidp;
	int			pid_cnt = 0;
	pid_info_t		*wpidp;

	gfp->total_time = 0;
	gfp->max_time = 0;
	gfp->max_waker = 0;
	gfp->cnt = 0;
	gfp->ret_total = 0;
	gfp->n_eagain = 0;
	gfp->n_etimedout = 0;
	gfp->n_othererr = 0;

	if (gfp->uaddr2_hash) {
		foreach_hash_entry((void **)gfp->uaddr2_hash,FUTEX_HSIZE,
                        (int (*)(void *, void *))futex_clear_reque_detail,
                        NULL, 0, NULL);		
	}	

	if (gfp->dup_hash) {
                foreach_hash_entry((void **)gfp->dup_hash,FUTEX_HSIZE,
                        (int (*)(void *, void *))futex_clear_dup_detail,
                        NULL, 0, NULL);
        }

	foreach_hash_entry((void **)gfp->ops_hash,FUTEXOP_HSIZE,
                        (int (*)(void *, void *))futex_clear_ops_detail,
                        NULL, 0, NULL);
	return 0;
}
	
void
futex_print_report_by_time(int futex_cnt)
{
        foreach_hash_entry((void **)globals->futex_hash,GFUTEX_HSIZE,
                        (int (*)(void *, void *))futex_print_detail,
                        futex_gblsort_by_time, nfutex, NULL);

}
	
void
futex_print_report_by_cnt(int futex_cnt)
{
        foreach_hash_entry((void **)globals->futex_hash,GFUTEX_HSIZE,
                        (int (*)(void *, void *))futex_print_detail,
                        futex_gblsort_by_cnt, nfutex, NULL);
}
	
void
futex_print_report()
{
	if (is_alive) {
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_command, NULL, 0, NULL);
	}

	foreach_hash_entry((void **)globals->futex_hash, GFUTEX_HSIZE,
			(int (*)(void *, void *))hash_count_entries,
			NULL, 0, &globals->futex_cnt);

	BOLD ("\n%s******** GLOBAL FUTEX REPORT ********\n", tab);
	printf ("\nTop Futex Addrs & top PIDs by count\n");
	printf("%sTotal Futex count = %d (Top %d listed)\n", tab, globals->futex_cnt, MIN(globals->futex_cnt, nfutex));
	futex_print_report_by_cnt(globals->futex_cnt);

	if (globals->futex_cnt > 1) {
		printf("Top Futex Addrs & top PIDs by elapsed time\n");
		printf("%sTotal Futex count = %d (Top %d listed)\n", tab, globals->futex_cnt, MIN(globals->futex_cnt, nfutex));
		futex_print_report_by_time(globals->futex_cnt);
	}

	if (is_alive) {
		foreach_hash_entry((void **)globals->futex_hash,GFUTEX_HSIZE,
        		futex_clear_stats,
        		NULL, 0, NULL);
	}

	return;
}

int 
futex_print_func(void *v)
{
	struct timeval tod;
	
	if ((print_flag) && (is_alive)) {
		gettimeofday(&tod, NULL);
		printf ("\n%s\n", ctime(&tod.tv_sec));
		futex_print_report();
		print_flag=0;
	}
	return 0;
}

int
futex_report_func(void *v)
{
	if (debug) printf ("futex_report_func %d\n", is_alive);
	if (passes !=0) {
		futex_print_report();
	}

	return 0;
}

