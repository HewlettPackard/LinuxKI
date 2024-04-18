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
#include "hash.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "syscalls.h"
#include "sched.h"
#include "sort.h"
#include "html.h"
#include "conv.h"

#include "Thread.h"
#include "Process.h"
#include "PerfInfo.h"
#include "winki_util.h"

int wait_dummy_func(void *, void *);
void wait_init_func(void *);
int wait_ftrace_print_func(void *, void *);

static inline void
wait_winki_trace_funcs()
{
	winki_init_actions(NULL);
	winki_enable_event(0x30a, process_load_func);
        winki_enable_event(0x524, thread_cswitch_func);
        winki_enable_event(0x532, thread_readythread_func);
        winki_enable_event(0x548, thread_setname_func);
        winki_enable_event(0xf33, perfinfo_sysclenter_func);
        winki_enable_event(0xf34, perfinfo_sysclexit_func);
}

/*
 ** The initialisation function
 */
void
wait_init_func(void *v)
{
        int i;

	if (debug) printf ("wait_init_func()\n");

        process_func = NULL;
        report_func = wait_report_func;
        bufmiss_func =  NULL;
	filter_func = info_filter_func;   /* no filter func for kiwait, use generic */

	if (IS_WINKI) {
		wait_winki_trace_funcs();

		parse_systeminfo();	
		parse_cpulist();
		parse_corelist();
		parse_SQLThreadList();
		wait_csvfile = open_csv_file("kiwait", 1);
		return;
	} else if (!IS_LIKI) {
                printf ("No switch functions or stack traces captured\n\n");
                _exit(0);
        }

        /* go ahead and initialize the trace functions, but do not set the execute field */
	ki_actions[TRACE_SYS_EXIT].func = sys_exit_func;
        ki_actions[TRACE_SYS_ENTER].func = sys_enter_func;
        ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_func;
        ki_actions[TRACE_SCHED_WAKEUP_NEW].func = sched_wakeup_func;
        ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;

	if (IS_LIKI || is_alive) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
        	ki_actions[TRACE_SYS_ENTER].execute = 1;
        	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
        	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
        	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
	} else {
		set_events_all(0);
        	ki_actions[TRACE_PRINT].func = wait_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

	parse_dmidecode1();	
	parse_cpuinfo(); 
	if (is_alive) parse_cpumaps();
	parse_kallsyms();
	parse_docker_ps();
	parse_pods();

	if (timestamp) {
		parse_mpsched(); 
		parse_proc_cgroup();
		parse_pself();
		parse_edus();
		parse_jstack();

		wait_csvfile = open_csv_file("kiwait", 1);
	}

}

int
wait_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int
wait_bufmiss_func(void *v, void *a)
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
wait_dummy_func(void *rec_ptr, void *v)
{
        return 0;
}

int wait_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("pid_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
        	ki_actions[TRACE_SYS_ENTER].execute = 1;
        	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
        	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
        	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
                start_time = KD_CUR_TIME;
        }

        if (strstr(buf, ts_end_marker)) {
		ki_actions[TRACE_SYS_EXIT].execute = 0;
        	ki_actions[TRACE_SYS_ENTER].execute = 0;
        	ki_actions[TRACE_SCHED_SWITCH].execute = 0;
        	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 0;
        	ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
                ki_actions[TRACE_PRINT].execute = 0;
                end_time = KD_CUR_TIME;
        }

        if (debug)  {
                PRINT_KD_REC(rec_ptr);
                PRINT_EVENT(rec_ptr->KD_ID);
                printf (" %s", buf);

                printf ("\n");
        }

	return 0;
}

void
print_global_sleeps()
{
        sched_info_t *schedp  = (sched_info_t *)globals->schedp;
        sched_stats_t *statsp;
	uint64 run_time;

        printf ("\n********* GLOBAL SCHEDULER ACTIVITY REPORT ********\n");
        if (schedp == NULL) return;
        statsp = &schedp->sched_stats;
	statsp->T_run_time = statsp->T_sys_time + statsp->T_user_time + statsp->T_irq_time;

        printf ("    CPUs: %8d  Seconds : %8.2f  Migrations: %8d\n",
                globals->ncpu,
                secs,
                schedp->cpu_migrations);
        printf ("Switches: %8d  Forced  : %8d   Voluntary: %8d\n",
                statsp->C_switch_cnt,
                statsp->C_preempt_cnt,
                statsp->C_sleep_cnt);
        printf (" TotTime: %8.4f  RunTime : %8.4f    CPU Util: %7.2f%%\n",
                secs * globals->ncpu,
                SECS(statsp->T_run_time),
                (100 * (SECS(statsp->T_run_time) / (secs * globals->ncpu))))  ;
}

void
print_global_swtch_stktraces()
{
	sched_info_t *gschedp;
	print_stktrc_args_t print_stktrc_args;
	var_arg_t vararg;

        if (globals->stktrc_hash == NULL) return;
	gschedp = (sched_info_t *)find_add_info((void **)&globals->schedp, sizeof(sched_info_t));

	print_stktrc_args.schedp = gschedp;
	print_stktrc_args.pidp = NULL;
	print_stktrc_args.warnflag = 0;

	vararg.arg1 = NULL;
	vararg.arg2 = &print_stktrc_args;
        printf("\nGlobals switch stack traces (sort by count):\n");
        printf("   count   wpct       avg   Stack trace\n");
        printf("              %%     msecs              \n");
        printf("============================================================\n");
        foreach_hash_entry((void **)globals->stktrc_hash, STKTRC_HSIZE, print_stktrc_info, stktrc_sort_by_cnt, nsym, (void *)&vararg);
}

int
print_pid_swtch_summary(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
        sched_info_t *schedp;
        sched_stats_t *statp;

        if (pidp->PID == 0ull) return 0;
	
	schedp = pidp->schedp;
	if (schedp == NULL) return 0;
	statp = &schedp->sched_stats;
        if (statp->C_switch_cnt == 0) return 0;

        printf("%s", tab);
        PID_URL_FIELD8(pidp->PID);
        printf(" %8d %8d %8d %10.6f %10.3f  %s",
                statp->C_sleep_cnt,
                statp->C_preempt_cnt,
                schedp->cpu_migrations,
                SECS(statp->T_sleep_time),
                (statp->T_sleep_time / 1000000.0) / statp->C_switch_cnt,
                pidp->cmd);

	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);

	if (cluster_flag) { DSPACE; SERVER_URL_FIELD_BRACKETS(globals) }
        NL;

        return 0;
}

void		
print_perpid_sleep_csv(pid_info_t *pidp) 
{
	sched_info_t *schedp = (sched_info_t *)pidp->schedp;

	if (pidp->PID == (uint64) -1) return ;
	if (schedp == NULL) return;
	if (pidp->slp_hash == NULL) return ;
	
	foreach_hash_entry_l((void **)pidp->slp_hash, SLP_HSIZE, print_slp_info_csv, slp_sort_by_count, 0, pidp);
	
	return;
}

int 
print_pid_sleeps_csv (void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
        sched_info_t *schedp;

        if (pidp->PID == 0ull) return 0;
	
	if (pidp->slp_hash) {
		print_perpid_sleep_csv(pidp);
	}
}

int 
print_pid_sleeps (void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	pid_info_t *tgidp;
        sched_info_t *schedp;
        sched_stats_t *statp;

        if (pidp->PID == 0ull) return 0;
	
	schedp = pidp->schedp;
	if (schedp == NULL) return 0;
	statp = &schedp->sched_stats;

        printf ("---------------------------------------------------\n");

        printf ("%s %ld  %s", tlabel,
                        pidp->PID,
                        pidp->cmd);

	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	printf ("\n");

	if (pidp->tgid) { 
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
        	printf ("  %s %ld  %s\n", plabel,
                        tgidp->PID,
                        tgidp->cmd);
	}

        printf ("%sRunTime    : %9.6f  SysTime   : %9.6f   UserTime   : %9.6f\n",  tab,
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time));
        printf ("%sSleepTime  : %9.6f  Sleep Cnt : %9d   Wakeup Cnt : %9d\n", tab,
                SECS(statp->T_sleep_time),
                statp->C_sleep_cnt,
                statp->C_wakeup_cnt);
        printf ("%sRunQTime   : %9.6f  PreemptCnt: %9d   Switch Cnt : %9d\n",  tab,
                SECS(statp->T_runq_time),
                statp->C_preempt_cnt,
                statp->C_switch_cnt);
        printf ("%sLast CPU   : %9d  CPU Migrs : %9d   NODE Migrs : %9d\n", tab,
                schedp->cpu,
                schedp->cpu_migrations,
                schedp->ldom_migrations);
        if (IS_LIKI) printf ("%sschedpolicy: %s\n", tab,
		sched_policy_name[schedp->policy]);

	if (pidp->slp_hash) {
		sleep_report(pidp->slp_hash, schedp, slp_sort_by_count, NULL);
	}

	return 0;

}

void
print_perpid_sleeps()
{
        printf ("\n********* PER-%s SCHEDULER ACTIVITY REPORTS ********\n", tlabel);
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_sleeps,
                                   pid_sort_by_sleep_cnt,
                                   npid, NULL);
	printf ("\n");

	if (wait_csvfile) {
        	csv_printf (wait_csvfile, "%s,Command,TotSlps,TotSlpTime,Function,Count,%%Count,SlpTime,%%SlpTime,%%TotTime,AvgSlpTime,MaxSlpTime\n", tlabel);
        	foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_sleeps_csv, pid_sort_by_sleep_cnt, 0, NULL);
	}
}

int
wait_print_report(void *v)
{
	sched_info_t *schedp = globals->schedp;

	if (schedp==NULL) return 0;
	calc_global_cpu_stats(globals, NULL);
	print_global_sleeps();
	printf ("\n********* GLOBAL SWITCH REPORT ********\n\n"); 
        sleep_report(globals->slp_hash, (sched_info_t *)globals->schedp, slp_sort_by_count, NULL);
	print_global_swtch_stktraces();
	if (npid)  {
		update_perpid_sched_stats();
		if (is_alive) {
			foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_command, NULL, 0, NULL);	
		}
		if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
		print_perpid_sleeps();
	}

	if (is_alive) {
		clear_all_stats();
	}
	return 0;
}

int
wait_report_func(void *v)
{

        if (debug) printf ("Entering wait_report_func %d\n", is_alive);
        if (passes > 0) wait_print_report(v);

        return 0;
}
