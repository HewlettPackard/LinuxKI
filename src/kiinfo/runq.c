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
#include "info.h"
#include "syscalls.h"
#include "power.h"
#include "irq.h"
#include "sort.h"
#include "hash.h"
#include "html.h"
#include "json.h"
#include "conv.h"

extern int pc_sleep_on_page;
extern int pc_migration_entry_wait;
extern int pc_msleep;
extern int pc_ixgbe_read_i2c_byte_generic;
extern int pc_mutex_lock;
extern int pc_xfs_file_aio_read;
extern int pc_xfs_file_read_iter;
extern int pc_inode_dio_wait;
extern int pc_xfs_file_dio_aio_write;
extern int pc_md_flush_request;
extern int pc_blkdev_issue_flush;

int runq_ftrace_print_func(void *, void *);

#define NETRX_SOFTIRQ 4
#define BLOCK_SOFTIRQ 4
#define TASKLET_SOFTIRQ 6
#define SCHED_SOFTIRQ 7
#define RCU_SOFTIRQ 9

/*
** The initialization function
*/
void
runq_init_func(void *v)
{
	int i;
	filter_item_t *fi;
	filter_t *f;

        if (debug) printf ("runq_init_func()\n");
        process_func = runq_process_func;
        report_func = runq_report_func;
	bufmiss_func = NULL;
        alarm_func = runq_alarm_func;
        filter_func = info_filter_func;   /* no filter func for kirunq, use generic */

        ki_actions[TRACE_SYS_EXIT].func = sys_exit_func;
        ki_actions[TRACE_SYS_ENTER].func = sys_enter_func;
        ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_func;
        ki_actions[TRACE_SCHED_WAKEUP_NEW].func = sched_wakeup_func;
        ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;	
	ki_actions[TRACE_POWER_START].func = power_start_func;
	ki_actions[TRACE_POWER_END].func = power_end_func;
	ki_actions[TRACE_POWER_FREQ].func = power_freq_func;
	ki_actions[TRACE_CPU_FREQ].func = cpu_freq_func;
	ki_actions[TRACE_CPU_IDLE].func = cpu_idle_func;
	ki_actions[TRACE_IRQ_HANDLER_ENTRY].func = irq_handler_entry_func;
	ki_actions[TRACE_IRQ_HANDLER_EXIT].func = irq_handler_exit_func;
	ki_actions[TRACE_SOFTIRQ_ENTRY].func = softirq_entry_func;
	ki_actions[TRACE_SOFTIRQ_EXIT].func = softirq_exit_func;
	if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (is_alive) {
                ki_actions[TRACE_WALLTIME].execute = 1;
		if (set_events_options(filter_func_arg) == 0) {
                	ki_actions[TRACE_SYS_EXIT].execute = 1;
                	ki_actions[TRACE_SYS_ENTER].execute = 1;
                	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
			ki_actions[TRACE_POWER_FREQ].execute = 1;
			ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
			ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
			ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
			ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
		}
	} else if (IS_LIKI) {
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
                ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_POWER_START].execute = 1;
		ki_actions[TRACE_POWER_END].execute = 1;
		ki_actions[TRACE_POWER_FREQ].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
                ki_actions[TRACE_WALLTIME].execute = 1;
	} else {
		set_events_all(0);
        	ki_actions[TRACE_PRINT].func = runq_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

	parse_cpuinfo();
	parse_scavuln(0);
	if (is_alive) parse_cpumaps();

	/* clear the system call specific actions as they aren't needed with kirunq */
	/* may need to revist for fork/clone/exec calls */
	for (i=0; i < KI_MAXSYSCALLS; i++) {
		ks_actions[i].execute = 0;
	}

	if (timestamp) {
		parse_mpsched();
		parse_pself();
		parse_edus();
		parse_jstack();

		runq_csvfile = open_csv_file("kirunq", 1);
	}
}

void
print_perldom_stats(uint64 *warnflagp)
{
        int i;
        ldom_info_t *ldominfop;
	sched_info_t *gschedp;
        sched_stats_t *statp, *gstatp;
	uint64 total_time, ldom_total_time;

	gschedp = GET_ADD_SCHEDP(&globals->schedp);
	gstatp = &gschedp->sched_stats;
	unsigned long *msrptr;

	TEXT("\n");
	if (!kparse_flag) {
            BOLD("%snode  ncpu          Total          sys         user         idle", tab);
	    if (gstatp->T_irq_time) BOLD ("  hardirq_sys hardirq_user hardirq_idle  softirq_sys softirq_user softirq_idle");
	    if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	    /* if (msr_flag) BOLD ("        MIPS"); */
	    printf("\n");

            for (i=0;i<MAXLDOMS;i++) {
                if (ldominfop = FIND_LDOMP(globals->ldom_hash, i)) {
                        statp = &ldominfop->sched_stats;

                        printf ("%s%4d [%3d] : %12.6f %12.6f %12.6f %12.6f", tab, i, 
				ldominfop->ncpus,
				SECS(statp->T_total_time),
                                SECS(statp->T_sys_time),
                                SECS(statp->T_user_time),
                                SECS(statp->T_idle_time));

	    		if (gstatp->T_irq_time)
			    printf (" %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f",
				SECS(statp->T_hardirq_sys_time),
				SECS(statp->T_hardirq_user_time), 
				SECS(statp->T_hardirq_idle_time),
				SECS(statp->T_softirq_sys_time),
				SECS(statp->T_softirq_user_time),
				SECS(statp->T_softirq_idle_time));

			if (msr_flag) {
				msrptr = &statp->msr_total[0];
        			printf ("   %6.2f%%  %5.2f   %7.2f     %4lld",
						(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                        			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               				        msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     				statp->msr_last[SMI_CNT]);
			}
			/*
			if (msr_flag) {
				printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
			}
			*/ 
                        printf ("\n");
                }
            }

  	    total_time = gstatp->T_total_time;
	    BOLD ("%sTotal                     %11.2f%% %11.2f%% %11.2f%%", tab,
		(gstatp->T_sys_time * 100.0) / total_time,
		(gstatp->T_user_time * 100.0) / total_time,
		(gstatp->T_idle_time * 100.0) / total_time);
	    if (gstatp->T_irq_time) 
	      BOLD (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
		(gstatp->T_hardirq_sys_time * 100.0) / total_time,
		(gstatp->T_hardirq_user_time * 100.0) / total_time,
		(gstatp->T_hardirq_idle_time * 100.0) / total_time,
		(gstatp->T_softirq_sys_time * 100.0) / total_time,
		(gstatp->T_softirq_user_time * 100.0) / total_time,
		(gstatp->T_softirq_idle_time * 100.0) / total_time);
	    if (msr_flag) {
		msrptr = &gstatp->msr_total[0];
        	BOLD ("   %6.2f%% %6.2f   %7.2f     %4lld",
				(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                       		msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
				msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     		gstatp->msr_last[SMI_CNT]);
	    }
	/*
	    if (msr_flag) {
		printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	    }
	*/

	    printf("\n\n");
	}

	BOLD ("node  ncpu     Total Busy          sys          usr         idle");
	if (gstatp->T_irq_time) BOLD ("  hardirq_sys hardirq_user hardirq idle  softirq_sys softirq_user softirq_idle");
	if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	/* if (msr_flag) BOLD ("        MIPS"); */
	printf("\n");

        for (i=0;i<MAXLDOMS;i++) {
                if (ldominfop = FIND_LDOMP(globals->ldom_hash, i)) {
                        statp = &ldominfop->sched_stats;

                        ldom_total_time = statp->T_total_time;
			if (ldom_total_time == 0) {
				/* if NO time logged, assume entire ldom is idle the entire time */
				ldom_total_time = globals->total_secs;
				statp->T_idle_time = globals->total_secs;
			}

                        printf ("%s%4d [%3d] : %11.2f%% %11.2f%% %11.2f%% %11.2f%%", tab, i, 
				ldominfop->ncpus,
				(statp->T_run_time * 100.0) / ldom_total_time,
                                (statp->T_sys_time * 100.0) / ldom_total_time,
                                (statp->T_user_time * 100.0) / ldom_total_time,
                                (statp->T_idle_time * 100.0) / ldom_total_time);

			if (gstatp->T_irq_time)
			    printf (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
				(statp->T_hardirq_sys_time * 100.0) / ldom_total_time,
				(statp->T_hardirq_user_time * 100.0) / ldom_total_time,
				(statp->T_hardirq_idle_time * 100.0) / ldom_total_time,
				(statp->T_softirq_sys_time * 100.0) / ldom_total_time,
				(statp->T_softirq_user_time * 100.0) / ldom_total_time,
				(statp->T_softirq_idle_time * 100.0) / ldom_total_time);

	    		if (msr_flag) {
				msrptr = &statp->msr_total[0];
        			printf("   %6.2f%% %6.2f   %7.2f     %4lld",
					(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                       			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               				msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     			statp->msr_last[SMI_CNT]);
			}			
			/*
	    		if (msr_flag) {
				printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	   		}
			*/
                        printf ("\n");
                }
        }

  	total_time = gstatp->T_total_time;

        BOLD ("%sTotal        %11.2f%% %11.2f%% %11.2f%% %11.2f%%", tab, i, 
		(gstatp->T_run_time * 100.0) / total_time,
		(gstatp->T_sys_time * 100.0) / total_time,
		(gstatp->T_user_time * 100.0) / total_time,
		(gstatp->T_idle_time * 100.0) / total_time);

	if (gstatp->T_irq_time)
	    BOLD (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
		(gstatp->T_hardirq_sys_time * 100.0) / total_time,
		(gstatp->T_hardirq_user_time * 100.0) / total_time,
		(gstatp->T_hardirq_idle_time * 100.0) / total_time,
		(gstatp->T_softirq_sys_time * 100.0) / total_time,
		(gstatp->T_softirq_user_time * 100.0) / total_time,
		(gstatp->T_softirq_idle_time * 100.0) / total_time);

	if (msr_flag) {
		msrptr = &gstatp->msr_total[0];
       		BOLD("   %6.2f%% %6.2f   %7.2f     %4lld",
				(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                  		msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
				msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
               			gstatp->msr_last[SMI_CNT]);
	}

	/*
	if (msr_flag) {
		printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	}
	*/

	printf("\n");
        return;
}

void
print_percpu_runq_histogram()
{
        int i, j;
        cpu_info_t *cpuinfop;
        sched_info_t *schedp;
        runq_info_t *rqinfop;

        printf(" cpu       <5    <10    <20    <50   <100   <500  <1000  <2000 <10000 <20000 >20000 \n");
        for (i=0;i<MAXCPUS;i++) {
                if ((cpuinfop = FIND_CPUP(globals->cpu_hash, i)) &&
                    (schedp = (sched_info_t *)cpuinfop->schedp) &&
                    (rqinfop = (runq_info_t *)schedp->rqinfop)) {
                        printf (" %3d :", i);
                        for (j = 0; j < RUNQ_NBUCKETS; j++) {
                                ldrq[cpuinfop->ldom].rqhist[j] += rqinfop->rqhist[j];
                                printf(" %6d", rqinfop->rqhist[j]);
                        }
                        printf ("\n");
                }
	}
}

int 
print_runq_stats(void *arg1, void *arg2)
{
	runq_info_t *rqinfop = (runq_info_t *)arg1;
	double	    avg;

        avg = (rqinfop->total_time * 1.0) / (rqinfop->cnt ? rqinfop->cnt : 1);
        printf("%9.1f %9lld %11lld %10d %11d %13d %14d",
                avg,
                rqinfop->max_time,
                rqinfop->total_time,
                rqinfop->cnt,
                rqinfop->migrations,
                rqinfop->ldom_migrations_in,
                rqinfop->ldom_migrations_out);
}

void
print_percpu_runq_stats()
{
        int             i,j;
        uint64          tt,tc;
        float           avg,total_avg;
        cpu_info_t *cpuinfop;
        sched_info_t *schedp;
        runq_info_t *rqinfop;
        int ldom;

        tt = tc = 0;

        printf(" cpu       Avg       Max  Total_time  Total_cnt  Migrations  NODE_migr_in  NODE_migr_out\n");
        for (i=0;i<MAXCPUS;i++) {
                if ((cpuinfop = FIND_CPUP(globals->cpu_hash, i)) &&
                    (schedp = (sched_info_t *)cpuinfop->schedp) &&
                    (rqinfop = (runq_info_t *)schedp->rqinfop)) {

                        printf(" %3d ", i);
			print_runq_stats(rqinfop, NULL);
			printf("\n");

                        ldom = cpuinfop->ldom;
                        tt+=rqinfop->total_time;
                        tc+=rqinfop->cnt;
                        if (rqinfop->max_time > ldrq[ldom].max_time)
                                ldrq[ldom].max_time = rqinfop->max_time;
                        ldrq[ldom].total_time += rqinfop->total_time;
                        ldrq[ldom].cnt += rqinfop->cnt;
                        ldrq[ldom].migrations += rqinfop->migrations;
                        ldrq[ldom].ldom_migrations_in += rqinfop->ldom_migrations_in;
                        ldrq[ldom].ldom_migrations_out += rqinfop->ldom_migrations_out;
                        ldrq[ldom].idle_handoff += rqinfop->idle_handoff;

                        /* zero out the stats EXECPT for the hash pointers */
                        if (is_alive) bzero((char *)rqinfop+sizeof(lle_t), sizeof(runq_info_t) - sizeof(lle_t));
                }
        }
        total_avg = ((tt * 1.0)/tc);
        printf("\nTOTAL_AVG = %-9.1f usecs runq latency per context switch \n",total_avg);
        /* fprintf (stderr, "\nTOTAL_AVG = %-9.1f usecs runq latency per context switch \n",total_avg); */
}

void
print_global_runq_histogram()
{

        int             i,j;
        float           avg;
        sched_info_t    *schedp;
        cpu_info_t      *cpuinfop;
        runq_info_t     *rqinfop;

        bzero((char *)ldrq, MAXLDOMS * sizeof(runq_info_t) );

        printf("\nSystem-wide runq stats\n");
        printf ("\nRUNQ latency histogram (in usecs)\n");
        print_percpu_runq_histogram();
        printf ("\nRUNQ latency statistics (in usecs)\n");
        print_percpu_runq_stats();
        printf("\n\nNODE runq latencies in Usecs\nNODE        <5    <10    <20    <50   <100   <500  <1000  <2000 <10000 <20000 >20000 \n");

        for (i=0;i<MAXLDOMS;i++) {
                if (ldrq[i].cnt > 0) {
                        printf (" %3d  :", i);
                        for (j = 0; j < RUNQ_NBUCKETS; j++) {
                                printf(" %6d", ldrq[i].rqhist[j]);
                        }
                        printf ("\n");
                }
        }


        printf("\nNODE runq/scheduling stats in Usecs\nNODE       Avg       Max  Total_time  Total_cnt  Migrations  NODE_migr_in  NODE_migr_out\n");
        for (i=0;i<MAXLDOMS;i++) {
                if (ldrq[i].cnt > 0) {

                        avg = ( (ldrq[i].total_time * 1.0)/ldrq[i].cnt);
                        printf(" %3d %9.1f %9lld %11lld %10d %11d %13d %14d\n",
                                i,
                                avg,
                                ldrq[i].max_time,
                                ldrq[i].total_time,
                                ldrq[i].cnt,
                                ldrq[i].migrations,
                                ldrq[i].ldom_migrations_in,
                                ldrq[i].ldom_migrations_out);
                }
        }

        printf("\n");
}

int
calc_global_cpu_stats( void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	int i, j;
	cpu_info_t *cpuinfop;
	ldom_info_t *ldominfop;
        sched_info_t *gschedp, *cschedp, *lschedp;
	sched_stats_t *gstatp, *cstatp, *lstatp;
	char skip_cpu_incr = FALSE;

	gschedp = GET_ADD_SCHEDP(&serverp->schedp);
	gstatp = &gschedp->sched_stats;

	/* clear the globals stats */
	for (i = 0; i <= IRQ_END; i++)
		gstatp->time[i] = 0;

	for (i = 0; i <= IRQ_CNT_END; i++)
		gstatp->cnt[i] = 0;

	/* the idle_time is the only stat we need to calculate */
        for (i=0;i<MAXCPUS;i++) {
                if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			cschedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
                        cstatp = &cschedp->sched_stats;

			cstatp->T_irq_time = 0;
			for (j = IRQ_BEGIN; j <= IRQ_END; j++)
				cstatp->T_irq_time += cstatp->time[j];

			cstatp->T_total_time = cstatp->T_idle_time + cstatp->T_sys_time + cstatp->T_user_time + cstatp->T_irq_time;

                        ldominfop = GET_LDOMP(&serverp->ldom_hash, cpuinfop->ldom);
			/* we only want to increment once per live interval.  So for
			 * the first CPU only, if ncpus is non-zero, then skip the 
			 * increment of ncpus 
			 */
			if ((i == 0) && ldominfop->ncpus) skip_cpu_incr = TRUE;
			if (!skip_cpu_incr) ldominfop->ncpus++;

                        lstatp = &ldominfop->sched_stats;

			for (j = 0; j <= IRQ_END; j++) {
				lstatp->time[j] += cstatp->time[j];
				gstatp->time[j] += cstatp->time[j];
			}

			for (j = 0; j <= IRQ_CNT_END; j++) {
				lstatp->cnt[j] += cstatp->cnt[j];
				gstatp->cnt[j] += cstatp->cnt[j]; 
			}

			if (msr_flag) {
				for (j = 0; j < MSR_NREGS-1; j++) {
					lstatp->msr_total[j] += cstatp->msr_total[j];
					gstatp->msr_total[j] += cstatp->msr_total[j];
				}
				lstatp->msr_last[SMI_CNT] += cstatp->msr_last[SMI_CNT];
				gstatp->msr_last[SMI_CNT] += cstatp->msr_last[SMI_CNT];
			}

		}
	}

	gbl_irq_time = gstatp->T_irq_time;
}

int 
print_global_cpu_stats(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	uint64 *warnflagp = (uint64 *)arg2;
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	unsigned long *msrptr;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	int red_font = 0;

	gschedp = GET_ADD_SCHEDP(&serverp->schedp);
	if (gschedp == NULL) return 0;

	gstatp = &gschedp->sched_stats;
  	total_time = gstatp->T_total_time;

	if (warnflagp) {
		if (((gstatp->T_idle_time * 100.0) / total_time) < 10.0) {
			(*warnflagp) |= WARNF_CPU_BOTTLENECK;
			red_font = TRUE;
		} 
		if (((gstatp->T_stealtime * 100.0) / total_time) >= 10.0) {
			(*warnflagp) |= WARNF_STEALTIME;
			red_font = TRUE;
		} 
		if (red_font) RED_FONT;
	}
	
	if (cluster_flag) { 
		SERVER_URL_FIELD16(serverp);
	}
	printf ("%8d  %11.2f%% %11.2f%% %11.2f%%", serverp->nlcpu,
		(gstatp->T_sys_time * 100.0) / total_time,
		(gstatp->T_user_time * 100.0) / total_time,
		(gstatp->T_idle_time * 100.0) / total_time);
	if (gstatp->T_irq_time)
	    printf (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
		(gstatp->T_hardirq_sys_time * 100.0) / total_time,
		(gstatp->T_hardirq_user_time * 100.0) / total_time,
		(gstatp->T_hardirq_idle_time * 100.0) / total_time,
		(gstatp->T_softirq_sys_time * 100.0) / total_time,
		(gstatp->T_softirq_user_time * 100.0) / total_time,
		(gstatp->T_softirq_idle_time * 100.0) / total_time);
	if (STEAL_ON)
	    printf (" %11.2f%% %11.2f%%",
		(gstatp->T_stealtime * 100.0) / total_time,
		(gstatp->T_stealtime_idle * 100.0) / total_time);
	if (msr_flag) {
		msrptr = &gstatp->msr_total[0];
        	printf ("   %6.2f%% %6.2f   %7.2f     %4lld",
				(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
               			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
				msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
               			gstatp->msr_last[SMI_CNT]);
	}
	/*
 	if (msr_flag) {
		printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	}
	*/

	BLACK_FONT;
	printf("\n");
	TEXT("\n");
}

void
print_percpu_stats(uint64 *warnflagp)
{
        int i;
        cpu_info_t *cpuinfop;
	sched_info_t *schedp, *gschedp;
        sched_stats_t *statp, *gstatp;
	uint64 cpu_total_time, total_time;
	unsigned long *msrptr;

	gschedp = GET_ADD_SCHEDP(&globals->schedp);
	gstatp = &gschedp->sched_stats;
  	total_time = gstatp->T_total_time;

	TEXT("\n");
	if (!kparse_flag) { 
	/* if (1) { */
            BOLD ("%scpu node          Total          sys         user         idle", tab);
	    if (gstatp->T_irq_time) BOLD ("  hardirq_sys hardirq_user hardirq_idle  softirq_sys softirq_user softirq_idle");
	    if (STEAL_ON) BOLD ("    stealbusy    stealidle");
	    if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
		/* if (msr_flag) BOLD ("        MIPS"); */
	    printf("\n");

            for (i=0;i<MAXCPUS;i++) {
                if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			schedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
                        statp = &schedp->sched_stats;

			cpu_total_time = statp->T_total_time;

                        printf ("%s%3d [%2d] : %12.6f %12.6f %12.6f %12.6f", tab, i, 
				cpuinfop->ldom,
				SECS(cpu_total_time),
                                SECS(statp->T_sys_time),
                                SECS(statp->T_user_time),
                                SECS(statp->T_idle_time));
		
	    		if (gstatp->T_irq_time)
			    printf (" %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f", 
				SECS(statp->T_hardirq_sys_time),
				SECS(statp->T_hardirq_user_time),
				SECS(statp->T_hardirq_idle_time),
				SECS(statp->T_softirq_sys_time),
				SECS(statp->T_softirq_user_time),
				SECS(statp->T_softirq_idle_time));

			if (STEAL_ON) 
				printf (" %12.6f %12.6f", SECS(statp->T_stealtime),SECS(statp->T_stealtime_idle));

			if (msr_flag) {
				msrptr = &statp->msr_total[0];
        			printf ("   %6.2f%% %6.2f   %7.2f     %4lld",
						(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                        			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               					msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     				statp->msr_last[SMI_CNT]);
			}
			/*
			if (msr_flag) {
				printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
			}
			*/

			printf ("\n");
                }
            }

	    BOLD ("%sTotal                   %11.2f%% %11.2f%% %11.2f%%", tab,
		(gstatp->T_sys_time * 100.0) / total_time,
		(gstatp->T_user_time * 100.0) / total_time,
		(gstatp->T_idle_time * 100.0) / total_time);

	    if (gstatp->T_irq_time)
	      BOLD (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
		(gstatp->T_hardirq_sys_time * 100.0) / total_time,
		(gstatp->T_hardirq_user_time * 100.0) / total_time,
		(gstatp->T_hardirq_idle_time * 100.0) / total_time,
		(gstatp->T_softirq_sys_time * 100.0) / total_time,
		(gstatp->T_softirq_user_time * 100.0) / total_time,
		(gstatp->T_softirq_idle_time * 100.0) / total_time);
	    if (STEAL_ON)
	      BOLD (" %11.2f%% %11.2f%%", (gstatp->T_stealtime * 100.0) / total_time, (gstatp->T_stealtime_idle * 100.0) / total_time);
	    if (msr_flag) {
		msrptr = &gstatp->msr_total[0];
        	printf ("   %6.2f%% %6.2f   %7.2f     %4lld",
						(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                        			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
						msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     				gstatp->msr_last[SMI_CNT]);
	    }
	/*
	    if (msr_flag) {
		printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	    }
	*/

	    printf ("\n\n");
	    TEXT("\n");
	}

	BOLD("cpu node     Total Busy          sys          usr         idle");
	if (gstatp->T_irq_time) BOLD ("  hardirq_sys hardirq_user hardirq idle  softirq_sys softirq_user softirq_idle");
	if (STEAL_ON) BOLD ("    stealbusy    stealidle");
	if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	/* if (msr_flag) BOLD ("        MIPS"); */
	printf("\n");
	
        for (i=0;i<MAXCPUS;i++) {
                if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			schedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
                        statp = &schedp->sched_stats;

			cpu_total_time = statp->T_total_time;
			if (cpu_total_time == 0) {
				/* if NO time logged, assume processor is idle the entire time */
				cpu_total_time = globals->total_secs;
				statp->T_idle_time = globals->total_secs;
			}

			if (warnflagp && (((statp->T_stealtime * 100.0) / cpu_total_time) >= 10.0)) {
				(*warnflagp) |= WARNF_STEALTIME;
				RED_FONT;
			} 

                        printf ("%s%3d [%2d] : %11.2f%% %11.2f%% %11.2f%% %11.2f%%", tab, i, 
				cpuinfop->ldom,
				(statp->T_run_time * 100.0) / cpu_total_time,
                                (statp->T_sys_time * 100.0) / cpu_total_time,
                                (statp->T_user_time * 100.0) / cpu_total_time,
                                (statp->T_idle_time * 100.0) / cpu_total_time);

			if (gstatp->T_irq_time)
				printf (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%", 
					(statp->T_hardirq_sys_time * 100.0) / cpu_total_time,
					(statp->T_hardirq_user_time * 100.0) / cpu_total_time,
					(statp->T_hardirq_idle_time * 100.0) / cpu_total_time,
					(statp->T_softirq_sys_time * 100.0) / cpu_total_time,
					(statp->T_softirq_user_time * 100.0) / cpu_total_time,
					(statp->T_softirq_idle_time * 100.0) / cpu_total_time);
			if (STEAL_ON) 
				printf (" %11.2f%% %11.2f%%", (statp->T_stealtime * 100.0) / cpu_total_time, 
							      (statp->T_stealtime_idle * 100.0) / cpu_total_time);
	    		if (msr_flag) {
				msrptr = &statp->msr_total[0];
        			printf ("   %6.2f%% %6.2f   %7.2f     %4lld",
						(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                        			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               					msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                     				statp->msr_last[SMI_CNT]);
	    		}
			/* 
			if (msr_flag) {
				printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
			} 
			*/

			BLACK_FONT;
			printf ("\n");
                }
        }

        BOLD ("%sTotal      %11.2f%% %11.2f%% %11.2f%% %11.2f%%", tab, i, 
		(gstatp->T_run_time * 100.0) / total_time,
		(gstatp->T_sys_time * 100.0) / total_time,
		(gstatp->T_user_time * 100.0) / total_time,
		(gstatp->T_idle_time * 100.0) / total_time);

	if (gstatp->T_irq_time)
	    BOLD (" %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%% %11.2f%%",
		(gstatp->T_hardirq_sys_time * 100.0) / total_time,
		(gstatp->T_hardirq_user_time * 100.0) / total_time,
		(gstatp->T_hardirq_idle_time * 100.0) / total_time,
		(gstatp->T_softirq_sys_time * 100.0) / total_time,
		(gstatp->T_softirq_user_time * 100.0) / total_time,
		(gstatp->T_softirq_idle_time * 100.0) / total_time);
	if (STEAL_ON)
	    BOLD (" %11.2f%% %11.2f%%", (gstatp->T_stealtime * 100.0) / total_time,
			       (gstatp->T_stealtime_idle * 100.0) / total_time);
	if (msr_flag) {
		msrptr = &gstatp->msr_total[0];
        	BOLD ("   %6.2f%% %6.2f   %7.2f     %4lld",
				(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
                      		msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               			msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
               			gstatp->msr_last[SMI_CNT]);
	}
	/*
	if (msr_flag) {
		printf ("   %9.2f",  (msrptr[RET_INSTR]/1000000)/globals->total_secs);
	}
	*/

	printf("\n");
	TEXT("\n");
        return ;
}

int
calc_global_HT_stats(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
        int i;
        int lcpu1,lcpu2;
        pcpu_info_t *pcpuinfop;
        cpu_info_t *cpu1infop, *cpu2infop;
	
        for (i = 0; i < MAXCPUS; i++) {
                pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i);
                if (pcpuinfop) {
                        lcpu1 = pcpuinfop->lcpu1;
                        lcpu2 = pcpuinfop->lcpu2;
                        cpu1infop = FIND_CPUP(globals->cpu_hash, lcpu1); 
                        cpu2infop = FIND_CPUP(globals->cpu_hash, lcpu2);

                        serverp->ht_double_idle += pcpuinfop->idle_time;
                        serverp->ht_lcpu1_busy += cpu1infop->lcpu_busy;
                        serverp->ht_lcpu2_busy += cpu2infop->lcpu_busy;
                        serverp->ht_double_busy += pcpuinfop->busy_time;
                }
        }

        serverp->ht_total_time = serverp->ht_double_idle + serverp->ht_lcpu1_busy + serverp->ht_lcpu2_busy + serverp->ht_double_busy;
}

void 
print_HT_report()
{
        int i;
        int lcpu1,lcpu2;
        pcpu_info_t *pcpuinfop;
        cpu_info_t *cpu1infop, *cpu2infop;
        uint64 HT_total_time, total_double_idle=0, total_lcpu1_busy=0, total_lcpu2_busy=0, total_double_busy=0;

	TEXT("\n");
	if (!kparse_flag) {
            BOLD ("%s     PCPU     double idle   lcpu1 busy   lcpu2 busy  double busy\n", tab);
            for (i = 0; i < MAXCPUS; i++) {
                pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i);
                if (pcpuinfop) {
                        lcpu1 = pcpuinfop->lcpu1;
                        lcpu2 = pcpuinfop->lcpu2;
                        cpu1infop = FIND_CPUP(globals->cpu_hash, lcpu1);
                        cpu2infop = FIND_CPUP(globals->cpu_hash, lcpu2);

                        printf ("%s  [%3d %3d]: %12.6f %12.6f %12.6f %12.6f\n", tab,
                                lcpu1, lcpu2,
                                SECS(pcpuinfop->idle_time),
                                SECS(cpu1infop->lcpu_busy),
                                SECS(cpu2infop->lcpu_busy),
                                SECS(pcpuinfop->busy_time));
                }
            }
	}

	TEXT("\n");
        BOLD("%s     PCPU     double idle   lcpu1 busy   lcpu2 busy  double busy\n", tab);
        for (i = 0; i < MAXCPUS; i++) {
                pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i);
                if (pcpuinfop) {
                        lcpu1 = pcpuinfop->lcpu1;
                        lcpu2 = pcpuinfop->lcpu2;
                        cpu1infop = FIND_CPUP(globals->cpu_hash, lcpu1); 
                        cpu2infop = FIND_CPUP(globals->cpu_hash, lcpu2);

                        HT_total_time = pcpuinfop->idle_time + cpu1infop->lcpu_busy + cpu2infop->lcpu_busy + pcpuinfop->busy_time;

			if (HT_total_time == 0) {
				/* if NO time logged, assume HT pair is idle the entire time */
				HT_total_time = globals->total_secs;
				pcpuinfop->idle_time = globals->total_secs;
			}

                        printf ("%s  [%3d %3d]: %11.1f%% %11.1f%% %11.1f%% %11.1f%%\n", tab,
                                pcpuinfop->lcpu1, pcpuinfop->lcpu2,
                                (pcpuinfop->idle_time * 100.0) / HT_total_time,
                                (cpu1infop->lcpu_busy * 100.0) / HT_total_time,
                                (cpu2infop->lcpu_busy * 100.0) / HT_total_time,
                                (pcpuinfop->busy_time * 100.0) / HT_total_time);
                }
        }

        BOLD ("%s  Total      %11.1f%% %11.1f%% %11.1f%% %11.1f%%\n", tab,
                globals->ht_total_time ? (globals->ht_double_idle * 100.0) / globals->ht_total_time : 0,
                globals->ht_total_time ? (globals->ht_lcpu1_busy * 100.0) / globals->ht_total_time : 0,
                globals->ht_total_time ? (globals->ht_lcpu2_busy * 100.0) / globals->ht_total_time : 0,
                globals->ht_total_time ? (globals->ht_double_busy * 100.0) / globals->ht_total_time : 0);
	TEXT("\n");
}

void
print_HT_DBDI_histogram()
{
        int i,j;
        pcpu_info_t *pcpuinfop;
	cpu_info_t *cpuinfop;
        uint64 HT_total_time;

        printf("\n%sSystem-Wide Double-Busy Double-Idle CPU Time Histogram\n", tab);
        printf("%sIdle time in Usecs\n", tab);
        printf("%s     PCPU        <10    <20    <50    <100   <250   <500   <750  <1000  <1250  <1500  <2000  <3000  <5000 <10000 <20000 >20000\n", tab);
        for (i = 0; i < MAXCPUS; i++) {
                pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i);
                if (pcpuinfop) {
                        printf ("%s  [%3d %3d]: ", tab, pcpuinfop->lcpu1, pcpuinfop->lcpu2);
                        for (j = 0; j < IDLE_TIME_NBUCKETS; j++) {
                                printf(" %6lld", pcpuinfop->sys_DBDI_hist[j]);
                        }
                        printf ("\n");
                }
        }

        printf("\n%sLocality-Wide Double-Busy Double-Idle CPU Time Histogram\n", tab);
        printf("%sIdle time in Usecs\n", tab);
        printf("%s     PCPU  NODE      <10    <20    <50    <100   <250   <500   <750  <1000  <1250  <1500  <2000  <3000  <5000 <10000 <20000 >20000\n", tab);
        for (i = 0; i < MAXCPUS; i++) {
                pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i);
                if (pcpuinfop) {
			cpuinfop = FIND_CPUP(globals->cpu_hash, pcpuinfop->lcpu1);
                        printf ("%s  [%3d %3d][%2d]: ", tab, pcpuinfop->lcpu1, pcpuinfop->lcpu2, cpuinfop->ldom);
                        for (j = 0; j < IDLE_TIME_NBUCKETS; j++) {
                                printf(" %6lld", pcpuinfop->ldom_DBDI_hist[j]);
                        }
                        printf ("\n");
                }
        }
}

/*
* When we get to the find_coop_ss_slpfuncs() call below we are at the end of our chain
* of associated calls.  We have:
*
*   Processing the setrq_src_list displaying 'tasks that have woken me up'
*   wakers scall
*     wakers_arg0
*       sleepers (me) scall
*         sleepers (me) arg0
*           sleepers (me) slpfunction
*
* We have filled in the coop_info_t along the way as it is passed down with all the
* details and are ready to print it all out.
*
*/

int
find_coop_ss_slpfuncs(void *arg1,  void *arg2)
{
        coop_slpfunc_t *slpfuncp = (coop_slpfunc_t *)arg1;
        coop_info_t    *coopinfop = (coop_info_t *)arg2;
        pid_info_t *pidp;
        coopinfop->slpfunc = slpfuncp->lle.key;
        pidp = coopinfop->pidp;
        uint64 offset,idx;
        char strbuf[128];
        short *s_syscall_index;
        short *w_syscall_index;
	short sidx, widx;
        /* EOL */
        bzero(strbuf,128);

        if (coopinfop->which == SLEEPER) {   
		/* processing the setrq_src_list meaning we are sleeper  */
		s_syscall_index = ( coopinfop->elf == ELF32 ? globals->syscall_index_32 : globals->syscall_index_64 );
		w_syscall_index = ( (pidp && pidp->elf == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64 );
        } else {
		/* processing the setrq_tgt_list meaning we are WAKER   */
		w_syscall_index = ( coopinfop->elf == ELF32 ? globals->syscall_index_32 : globals->syscall_index_64 );
		s_syscall_index = ( (pidp && pidp->elf == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64 );
        }

        /*  We use a common format regardless of SLEEPER or WAKER list we're printing  */


        if (coop_detail_enabled) { /* should always be true ... */
/*
                pid_printf ("%44.2f%%    %6.2f%%/%6.2f%%  %8d/%-8d ", slpfuncp->cnt*100.0/coopinfop->total_cnt,
                                                    coopinfop->scall_slptime*100.0/coopinfop->total_slp_time,
                                                    slpfuncp->sleep_time*100.0/coopinfop->total_slp_time,
                                                    slpfuncp->cnt,coopinfop->scall_cnt);
*/
                pid_printf ("               %8d   %6.2f%%   %9.6f                    ",
						slpfuncp->cnt,
						slpfuncp->sleep_time*100.0/coopinfop->total_slp_time,
						SECS(slpfuncp->sleep_time));
						
						
                if (coopinfop->waker_is_ICS == 1)  {
                    sprintf(strbuf,"  %s","notavail-ICS");
                } else if (coopinfop->waker_scall == DUMMY_SYSCALL)  {
                    sprintf(strbuf,"  %s","notavail");
                } else if (coopinfop->waker_scall >= UNKNOWN_SCALL)  {
                    sprintf(strbuf,"  %s","unknown_scall");
                } else {
		    widx = w_syscall_index[coopinfop->waker_scall];
                    sprintf (strbuf, (syscall_arg_list[widx].args[0].format == DECIMAL) ? "  %s(%s=%lld)" : " %s(%s=0x%llx)",
                    				syscall_arg_list[widx].name,
                                                syscall_arg_list[widx].args[0].label,
                                                coopinfop->waker_arg0);
                }
                pid_printf ("%-36s ",strbuf);
                bzero(strbuf,128);

                if (coopinfop->sleeper_scall == DUMMY_SYSCALL)  {
                    sprintf(strbuf,"  %s","notavail");
                } else if (coopinfop->sleeper_scall >= UNKNOWN_SCALL)  {
                    sprintf(strbuf,"  %s","unknown_scall");
                } else {

		    sidx = s_syscall_index[coopinfop->sleeper_scall];
                    sprintf (strbuf, (syscall_arg_list[sidx].args[0].format == DECIMAL) ? "  %s(%s=%lld)" : " %s(%s=0x%llx)",
                    				syscall_arg_list[sidx].name,
                                                syscall_arg_list[sidx].args[0].label,
                                                coopinfop->sleeper_arg0);
                }
                pid_printf ("%-36s ",strbuf);
                if (coopinfop->slpfunc && (coopinfop->slpfunc != END_STACK)) {
			idx = 0;
			offset = 0;
			if (globals->nsyms) {
                        	idx = findsym_idx(coopinfop->slpfunc);
                        	offset = coopinfop->slpfunc - globals->symtable[idx].addr;
			}
                        if ((idx > 0) && (idx < globals->nsyms-1) && (offset < 0x10000))
                                pid_printf ("%s+0x%llx  ", globals->symtable[idx].nameptr, offset);
                        else
                                pid_printf ("PC=0x%llx  ", coopinfop->slpfunc);
                }
                else
                        pid_printf ("%12s","unknown");
                pid_printf ("\n");
        }
}



/*
* When we get to the find_coop_ww_args() call below we are at the end of our chain
* of associated calls.  We have:
*
* Processing the setrq_tgt_list displaying 'tasks that I have woken up'
*   sleepers scall
*     sleepers arg0
*       sleepers slpfunc
*         wakers scall
*           wakers arg0
*
* We have filled in the coop_info_t along the way as it is passed down with all the
* details and are ready to print it all out.
*
*/

int
find_coop_ww_args(void *arg1, void *arg2)
{
        coop_scall_arg_t *argp = (coop_scall_arg_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;
        uint64 offset,idx;
        coopinfop->waker_arg0 = argp->lle.key;

        pid_info_t *pidp;
        pidp = coopinfop->pidp;
        char strbuf[128];

        /* EOL */

        short *s_syscall_index;
        short *w_syscall_index;
	short sidx, widx;

        if (coopinfop->which == SLEEPER) {   
		/* processing the setrq_src_list meaning we are sleeper  */
		s_syscall_index = ( coopinfop->elf == ELF32 ? globals->syscall_index_32 : globals->syscall_index_64 );
		w_syscall_index = ( (pidp && pidp->elf == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64 );
        } else {                            
		/* processing the setrq_tgt_list meaning we are WAKER   */
		w_syscall_index = ( coopinfop->elf == ELF32 ? globals->syscall_index_32 : globals->syscall_index_64 );
		s_syscall_index = ( (pidp && pidp->elf == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64 );
	}

        /*  We use a common format regardless of SLEEPER or WAKER list we're printing  */


        if (coop_detail_enabled) { /* should always be true ... */
/*
                pid_printf ("%44.2f%%    %6.2f%%/%6.2f%%  %8d/%-8d ",  argp->cnt*100.0/coopinfop->total_cnt,
                                                    coopinfop->scall_slptime*100.0/coopinfop->total_slp_time,
                                                    argp->sleep_time*100.0/coopinfop->total_slp_time,
                                                    argp->cnt,coopinfop->scall_cnt);
*/
                pid_printf ("               %8d   %6.2f%%   %9.6f                    ",
                                                argp->cnt,
                                                argp->sleep_time*100.0/coopinfop->total_slp_time,
                                                SECS(argp->sleep_time));

                if (coopinfop->waker_is_ICS == 1)  {
                    sprintf(strbuf,"  %s","notavail-ICS");
                } else if (coopinfop->waker_scall == DUMMY_SYSCALL)  {
                    sprintf(strbuf,"  %s","notavail");
                } else if (coopinfop->waker_scall >= UNKNOWN_SCALL)  {
                    sprintf(strbuf,"  %s","unknown_scall");
                } else {
		    widx = w_syscall_index[coopinfop->waker_scall];
                    sprintf (strbuf, (syscall_arg_list[widx].args[0].format == DECIMAL) ? "  %s(%s=%lld)" : " %s(%s=0x%llx)",
                        		syscall_arg_list[widx].name,
                                        syscall_arg_list[widx].args[0].label,
                                        coopinfop->waker_arg0);
                }
                pid_printf ("%-36s ",strbuf);
                bzero(strbuf,128);

                if (coopinfop->sleeper_scall == DUMMY_SYSCALL)  {
                    sprintf(strbuf,"  %s","notavail");
                } else if (coopinfop->sleeper_scall >= UNKNOWN_SCALL)  {
                    sprintf(strbuf,"  %s","unknown_scall");
                } else {
		    sidx = s_syscall_index[coopinfop->sleeper_scall];
                    sprintf (strbuf, (syscall_arg_list[sidx].args[0].format == DECIMAL) ? "  %s(%s=%lld)" : " %s(%s=0x%llx)",
							syscall_arg_list[sidx].name,
                                                        syscall_arg_list[sidx].args[0].label,
                                                        coopinfop->sleeper_arg0);
                }
                pid_printf ("%-36s ",strbuf);
                if (coopinfop->slpfunc && (coopinfop->slpfunc != END_STACK)) {
			idx = 0;
			offset = 0;
			if (globals->nsyms) {
                        	idx = findsym_idx(coopinfop->slpfunc);
                        	offset = coopinfop->slpfunc - globals->symtable[idx].addr;
			}
                        if ((idx > 0) && (idx < globals->nsyms-1) && (offset < 0x10000))
                                pid_printf ("%s+0x%llx  ", globals->symtable[idx].nameptr, offset);
                        else
                                pid_printf ("PC=0x%llx  ", coopinfop->slpfunc);
                }
                else
                        pid_printf ("%12s","unknown");
                pid_printf ("\n");
        }
}



int
find_coop_ww_scall(void *arg1, void *arg2)
{
        coop_scall_t *scallp = (coop_scall_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->waker_scall = scallp->lle.key;

	foreach_hash_entry((void **)scallp->coop_args_hash, ARGS_HSIZE,
				find_coop_ww_args,
				coop_sort_args_by_sleep_time,
				npid, (void *)coopinfop);
}


int
find_coop_ss_args(void *arg1, void *arg2)
{
        coop_scall_arg_t *argp = (coop_scall_arg_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->sleeper_arg0  = argp->lle.key;

	foreach_hash_entry((void **)argp->coop_slpfunc_hash, SLP_HSIZE, 
				find_coop_ss_slpfuncs, 
				coop_sort_slpfuncs_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_ss_scall(void *arg1, void *arg2)
{
        coop_scall_t *scallp = (coop_scall_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->sleeper_scall = scallp->lle.key;

	foreach_hash_entry((void **)scallp->coop_args_hash, ARGS_HSIZE,
				find_coop_ss_args,
				coop_sort_args_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_ws_slpfuncs(void *arg1,  void *arg2)
{
        coop_slpfunc_t *slpfuncp = (coop_slpfunc_t *)arg1;
        coop_info_t    *coopinfop = (coop_info_t *)arg2;

        coopinfop->slpfunc = slpfuncp->lle.key;

	foreach_hash_entry((void **)slpfuncp->coop_waker_sc_hash, SYSCALL_HASHSZ,
				find_coop_ww_scall, 
				coop_sort_scall_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_ws_args(void *arg1, void *arg2)
{
        coop_scall_arg_t *argp = (coop_scall_arg_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->sleeper_arg0  = argp->lle.key;

        foreach_hash_entry((void **)argp->coop_slpfunc_hash, SLP_HSIZE,
				find_coop_ws_slpfuncs, 
				coop_sort_slpfuncs_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_ws_scall(void *arg1, void *arg2)
{
        coop_scall_t *scallp = (coop_scall_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->sleeper_scall = scallp->lle.key;
        coopinfop->scall_cnt = scallp->cnt;
        coopinfop->scall_slptime = scallp->sleep_time;

	foreach_hash_entry((void **)scallp->coop_args_hash, ARGS_HSIZE,
				find_coop_ws_args,
				coop_sort_args_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_sw_args(void *arg1, void *arg2)
{
        coop_scall_arg_t *argp = (coop_scall_arg_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->waker_arg0 = argp->lle.key;

	foreach_hash_entry((void **)argp->coop_sleeper_scall_hash, SYSCALL_HASHSZ,
				find_coop_ss_scall, 
				coop_sort_scall_by_sleep_time,
				npid, (void *)coopinfop);
}

int
find_coop_sw_scall(void *arg1, void *arg2)
{
        coop_scall_t *scallp = (coop_scall_t *)arg1;
        coop_info_t *coopinfop = (coop_info_t *)arg2;

        coopinfop->waker_scall = scallp->lle.key;
        coopinfop->scall_cnt = scallp->cnt;
        coopinfop->scall_slptime = scallp->sleep_time;

	foreach_hash_entry((void **)scallp->coop_args_hash, ARGS_HSIZE,
				find_coop_sw_args, 
				coop_sort_args_by_sleep_time,
				npid, (void *)coopinfop);
}

int
print_wakeup_pids(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        sched_info_t *schedp;
        sched_stats_t *statsp;

        if ((int)pidp->PID <= 0) return 0;
        if (pidp->schedp == NULL) return 0;

        schedp = pidp->schedp;
        if (schedp->max_wakeup_cnt < 8) return 0;

        statsp = &schedp->sched_stats;
        printf("%s", tab);
        PID_URL_FIELD8(pidp->PID);
        printf(" %8d %10d %8d %13.6f  %s",
                statsp->C_wakeup_cnt,
                schedp->max_wakeup_cnt,
                schedp->max_wakeup_cnt_hit,
                abstime_flag ? SECS(schedp->max_wakeup_time) : SECS(schedp->max_wakeup_time - FILTER_START_TIME),
                pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
        if (pidp->thread_cmd) printf ("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
        if (cluster_flag) { SPACE; SERVER_URL_FIELD_BRACKETS(globals) }
        printf ("\n");

        return 0;
}

/*
* We follow two lists, reporting the sleeper/waker sclass, args, slpfuncs(of sleepers only).
* The setrq_src_list of the SLEEPER is list of tasks that have woken him up.  The data structures
* are chained together as :
*      setrq_src_list -> wakers_scall -> wakers_scall_arg0 -> sleepers_scall -> sleeper_scall_arg0
*              -> sleeper_arg0_sleep_function
*
* The setrq_tgt_list of the WAKER is a list of tasks that We have woken up.  The data structures
* are chained together as :
*      setrq_tgt_list -> sleepers_scall -> sleeper_scall_arg0 -> sleeper_arg0_sleep_function
*              -> wakers_scall -> wakers_scall_arg0
*
* For each element in the data chain we have a count and a tally of sleep_time associated.  The
* reporting format can be count based or sleep time based.
*
*
*/

int
sched_print_setrq_pids(void *arg1, void *arg2)
{
        setrq_info_t *setrq_infop = (setrq_info_t *)arg1;
        pid_info_t *pidp;
        sched_info_t *schedp;
        sched_stats_t *statp;

        coop_info_t *coopinfop = (coop_info_t *)arg2;

	pidp = GET_PIDP(&globals->pid_hash, setrq_infop->PID);
        schedp = (sched_info_t *)find_sched_info(pidp);
        statp = &schedp->sched_stats;

	/* If WAKER, pidp, schedp, statp, are those of the pid we are waking up */

        coopinfop->total_cnt = (uint64)setrq_infop->cnt;
        coopinfop->pidp = pidp;
        if(coopinfop->which == WAKER)
                coopinfop->total_slp_time = statp->T_sleep_time;

	/* If we're the WAKER, the total sleeptime we're comparing is that of the task we are waking */

        pid_printf ("      %8d   %6d   %6.2f%%   %9.6f",
                    (int)setrq_infop->PID,
                    setrq_infop->cnt,
                    setrq_infop->sleep_time*100.0/coopinfop->total_slp_time,
		    SECS(setrq_infop->sleep_time));

        if ((setrq_infop->PID == 0) || ((uint64)setrq_infop->PID == -1)) {
                pid_printf ("  %s", " ICS ");
		coopinfop->waker_is_ICS = 1;
        } else {
        	if (pidp->cmd) pid_printf ("  %s", pidp->cmd);
		if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
		if (pidp->thread_cmd) pid_printf ("  (%s)", pidp->thread_cmd);
		if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	        coopinfop->waker_is_ICS = 0;
        }
        pid_printf ("\n");

	foreach_hash_entry((void **)setrq_infop->coop_scall_hash, SYSCALL_HASHSZ,
					coopinfop->which == SLEEPER ? find_coop_sw_scall : find_coop_ws_scall,
					coop_sort_scall_by_sleep_time,
					npid, (void *)coopinfop);
	
	if (coop_detail_enabled)
        	pid_printf ("\n");
	if (is_alive)
        	setrq_infop->cnt = 0;
        return 0;
}

int
print_scd_slp_info(void *arg1,void *arg2)
{
        scd_waker_info_t *scdwinfop = (scd_waker_info_t *)arg1;
        uint64 pid;

        if (scdwinfop->count == 0) return 0;

        pid = scdwinfop->lle.key;

        pid_printf("%s            %6d  %6d          %11.6f %10.6f %10.6f  \n", tab,
                    pid,
                    scdwinfop->count,
                    SECS(scdwinfop->sleep_time),
                    SECS((scdwinfop->sleep_time*1.0) / scdwinfop->count),
                    SECS(scdwinfop->max_time*1.0));

        return 0;
}

int
print_slp_info(void *arg1, void *arg2)
{
	slp_info_t *slpinfop = (slp_info_t *)arg1;
	sched_stats_t *statsp = (sched_stats_t *)arg2;
	sched_info_t *gschedp;
	uint64 idx;

	if (slpinfop->count == 0) return 0;
	gschedp = globals->schedp;

	idx = slpinfop->lle.key;
	if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;

	if (gschedp && statsp == &gschedp->sched_stats) {
            pid_printf("%s%8d %6.2f%% %10.4f %6.2f%% %10.3f %10.3f %s\n", tab, 
                    slpinfop->count,
                    (slpinfop->count * 100.0) / statsp->C_sleep_cnt,
                    SECS(slpinfop->sleep_time),
                    (slpinfop->sleep_time *100.0) / statsp->T_sleep_time,
                    MSECS(slpinfop->sleep_time / slpinfop->count),
                    MSECS(slpinfop->max_time),
		    idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr);
	} else if (statsp != NULL) {
            pid_printf("%s%8d %6.2f%% %10.4f %6.2f%% %9.2f%% %10.3f %10.3f  %s\n", tab, 
                    slpinfop->count,
                    (slpinfop->count * 100.0) / statsp->C_sleep_cnt,
                    SECS(slpinfop->sleep_time),
                    (slpinfop->sleep_time *100.0) / statsp->T_sleep_time,
		    (slpinfop->sleep_time *100.0) / (statsp->T_sleep_time + statsp->T_runq_time + statsp->T_run_time),
                    MSECS(slpinfop->sleep_time / slpinfop->count),
                    MSECS(slpinfop->max_time),
		    idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr);
         } else {
             pid_printf("%s      Sleep Func    %6d          %11.6f %10.6f %10.6f  %s\n", tab,
                    slpinfop->count,
                    SECS(slpinfop->sleep_time),
                    SECS(slpinfop->sleep_time / slpinfop->count),
                    SECS(slpinfop->max_time),
		    idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr);

                    if (IS_LIKI && slpinfop->scd_wpid_hash) {
                        pid_printf("%s       Waker PID  \n",tab);
                        foreach_hash_entry_l((void **)slpinfop->scd_wpid_hash,
                                                WPID_HSIZE,
                                                print_scd_slp_info,
                                                slp_scd_sort_by_time, 0, NULL);
                    }

        }

	return 0;
}

int
print_slp_info_csv(void *arg1, void *arg2)
{
	slp_info_t *slpinfop = (slp_info_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	sched_info_t *schedp = pidp->schedp;
	sched_stats_t *statsp = &schedp->sched_stats;
	uint64 idx;

	if (slpinfop->count == 0) return 0;

	idx = slpinfop->lle.key;
	if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;
	csv_printf (wait_csvfile,"%lld,%s,%d,%7.6f,%s,%d,%3.2f,%7.6f,%3.2f,%3.2f,%7.6f,%7.6f\n", 
		pidp->PID,
		pidp->cmd,
		statsp->C_sleep_cnt,
		SECS(statsp->T_sleep_time),
		idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr,
		slpinfop->count,
                (slpinfop->count * 100.0) / statsp->C_sleep_cnt,
		SECS(slpinfop->sleep_time),
                (slpinfop->sleep_time *100.0) / statsp->T_sleep_time,
		(slpinfop->sleep_time *100.0) / (statsp->T_sleep_time + statsp->T_runq_time + statsp->T_run_time),
                SECS(slpinfop->sleep_time / slpinfop->count),
                SECS(slpinfop->max_time));

	return 0;
}

int
print_stktrc_info(void *p1, void *p2)
{
	stktrc_info_t *stktrcp = (stktrc_info_t *)p1;
	print_stktrc_args_t *print_stktrc_args = (print_stktrc_args_t *)p2;
	sched_info_t *schedp;
	pid_info_t *pidp;
	vtxt_preg_t *pregp;
	float avg, wpct;
	int i; 
	uint64 key, offset;
	char *sym;
	int migrate_warn_cnt = 0;
	int ixgbe_read_warn_cnt = 0;
	int xfs_dio_align_warn_cnt = 0;
	int xfs_dioread_warn_cnt = 0;
	int md_flush_warn_cnt = 0;
	int kstat_irqs_warn_cnt = 0;

	if (print_stktrc_args == NULL) return 0;
	if (stktrcp->cnt == 0) return 0;
	schedp = print_stktrc_args->schedp;

	/* make a first pass and check for warnings */
	if (kparse_flag) {
        	for (i=0;i<stktrcp->stklen; i++) {
			key = stktrcp->stklle.key[i];
			if (key == STACK_CONTEXT_USER)  break;
			if ((globals->symtable) && (key < globals->nsyms-1)) {
				if (stktrcp->cnt > 10000) {
					if ((key == pc_md_flush_request)  || (key == pc_blkdev_issue_flush)) md_flush_warn_cnt++;
				} else if (stktrcp->cnt > 1000) {
					if ((key == pc_sleep_on_page)  || (key == pc_migration_entry_wait)) migrate_warn_cnt++; 
				} else if (stktrcp->cnt > 500) {
					if ((key == pc_mutex_lock) || ((key == pc_xfs_file_aio_read) || (key == pc_xfs_file_read_iter)))
						xfs_dioread_warn_cnt++;
				} else if (stktrcp->cnt > 100) {
					if ((key == pc_inode_dio_wait) || (key == pc_xfs_file_dio_aio_write)) xfs_dio_align_warn_cnt++;
				} else if (stktrcp->cnt > 50) {
					if ((key == pc_msleep) || (key == pc_ixgbe_read_i2c_byte_generic)) ixgbe_read_warn_cnt++;
				}
			}
		}

		if (migrate_warn_cnt >= 2) {
			RED_FONT;
			print_stktrc_args->warnflag |= WARNF_MIGRATE_PAGES;
		} else  if (ixgbe_read_warn_cnt >= 2) {
			RED_FONT;
			print_stktrc_args->warnflag |= WARNF_IXGBE_READ;
		} else if (xfs_dio_align_warn_cnt >= 2) {
			RED_FONT;
			print_stktrc_args->warnflag |= WARNF_XFS_DIO_ALIGN;
		} else if (xfs_dioread_warn_cnt >= 2) {
			RED_FONT;
			print_stktrc_args->warnflag |= WARNF_XFS_DIOREAD;
		} else if (md_flush_warn_cnt >= 2) {
			RED_FONT;
			print_stktrc_args->warnflag |= WARNF_MD_FLUSH;
		}
	}

	if (schedp) {
        	wpct = ((float)stktrcp->slptime *100.0)/(schedp->sched_stats.T_sleep_time);
        	avg = MSECS(stktrcp->slptime)/stktrcp->cnt;
        	pid_printf("%s%8d %6.2f %9.3f ",tab, stktrcp->cnt, wpct, avg); 
	} else {
		pid_printf("%s%8d ", tab, stktrcp->cnt);
	}	

        for (i=0;i<stktrcp->stklen; i++) {
		key = stktrcp->stklle.key[i];
		if (key == 0ll)  continue;

		if (key == STACK_CONTEXT_USER) {
			pid_printf ("  |");
		} else if ((globals->symtable) && (key < globals->nsyms-1)) {
			if (globals->symtable[key].nameptr) {
				pid_printf ("  %s", globals->symtable[key].nameptr);
			} else {
				pid_printf ("  %p", globals->symtable[key].addr);
			}
		} else if (key == UNKNOWN_SYMIDX) {
			pid_printf ("  unknown");
	        } else if (stktrcp->pidp) {
                        pidp = stktrcp->pidp;
                        if (pidp->PID != pidp->tgid) {
                                pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        }

                        if (pregp = find_vtext_preg(pidp, key)) {
                                if (sym = symlookup(pregp, key, &offset)) {
                                	pid_printf ("  %s", dmangle(sym));
                                } else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
                                	pid_printf ("  %s", dmangle(sym));
				} else {
                                	pid_printf ("  0x%llx", sym);
				}
                        } else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
                                pid_printf ("  %s", dmangle(sym));
                        } else {
                                pid_printf ("  0x%llx", key);
                        }
                } else {
                        pid_printf ("  0x%llx", key);
                }
        }
	BLACK_FONT;
        pid_printf("\n");
        return 0;

}

void
sleep_report(void *arg1, void *arg2, int (*sort_func)(const void *, const void *), void *v)
{
	slp_info_t	**slp_hash = arg1;
        sched_info_t    *schedp = (sched_info_t *)arg2;
        sched_stats_t   *statsp;
        int             i;


	if (slp_hash == NULL) return;

	statsp = &schedp->sched_stats;

        pid_printf ("%sKernel Functions calling sleep()", tab);
	if (nsym && (nsym != 0x7fffffff)) pid_printf (" - Top %d Functions", nsym);
	pid_printf ("\n");

	if (globals->schedp == schedp) {
		pid_printf ("%s   Count     Pct    SlpTime    Slp%%   Msec/Slp   MaxMsecs  Func\n", tab);
	} else { 
		pid_printf ("%s   Count     Pct    SlpTime    Slp%% TotalTime%%   Msec/Slp   MaxMsecs  Func\n", tab);
	}	
	foreach_hash_entry_l((void **)slp_hash, SLP_HSIZE, print_slp_info, sort_func, nsym, statsp);

}

void
stktrc_report(void *arg1, void *arg2, int (*sort_func)(const void *, const void *), void *v)
{
	stktrc_info_t	**stktrc_hash = arg1;
        sched_info_t    *schedp = (sched_info_t *)arg2;
	print_stktrc_args_t print_stktrc_args;

	print_stktrc_args.schedp = schedp;
	print_stktrc_args.warnflag = 0;

	if (schedp) {
		pid_printf("\n%sProcess Sleep stack traces (sort by %% of total wait time)", tab);
	} else {
		pid_printf("\n%sProcess RunQ stack traces (sort by count)", tab);
	}
		
	if (nsym && (nsym != 0x7fffffff)) pid_printf (" - Top %d stack traces", nsym);
	pid_printf("\n");

        pid_printf("%s   count%s Stack trace\n", tab, schedp ? "    wpct      avg" : " ");
        if (schedp) pid_printf("%s              %%     msecs\n", tab);
        pid_printf("%s===============================================================\n",tab);

        foreach_hash_entry((void **)stktrc_hash, STKTRC_HSIZE, print_stktrc_info, sort_func, nsym, (void *)&print_stktrc_args);
}

int
wait_scallwakers_json(void *arg1,void *arg2)
{
        scd_waker_info_t *scdwinfop = (scd_waker_info_t *)arg1;
        uint64 pid;
        char waker[128];
        char waker_link[128];

        if (scdwinfop->count == 0) return 0;

        pid = scdwinfop->lle.key;
        sprintf (waker, "Waker %d", pid);
        sprintf (waker_link, "../../VIS/%d/pid_detail.html", pid);

        START_WAKE_OBJ_PRINT(waker, SECS(scdwinfop->sleep_time), scdwinfop->count, JSWAITING, "click to follow", "", waker_link);
        EMPTY_KIDS_PRINT;
        ENDCURR_OBJ_PRINT;
        return 0;
}

int
wait_scallsym_json(void *arg1, void *arg2)
{
        slp_info_t *slpinfop = (slp_info_t *)arg1;
        sched_stats_t *statsp = (sched_stats_t *)arg2;
        uint64 idx;
        char *symb_p = NULL;
        char *c_p;

        if (slpinfop->count == 0) return 0;

        idx = slpinfop->lle.key;
	if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;

        /*
        ** symbol names from /proc have embedded tabs that have to
        ** be stripped out....usually only one per string in front of the module name
        */

        bzero(json_detail, 8192);

        if (idx != UNKNOWN_SYMIDX) {
                symb_p = strdup(globals->symtable[idx].nameptr);
                if (c_p = strstr(symb_p, "\t"))
                    *c_p = 0x20;
        }
        if (statsp != NULL) {
            sprintf(json_temp, "%s%8d %6.2f%% %10.4f %6.2f%% %9.2f%% %10.3f %10.3f  %s\\n", tab,
                    slpinfop->count,
                    (slpinfop->count * 100.0) / statsp->C_sleep_cnt,
                    SECS(slpinfop->sleep_time),
                    (slpinfop->sleep_time *100.0) / statsp->T_sleep_time,
                    (slpinfop->sleep_time *100.0) / (statsp->T_sleep_time + statsp->T_runq_time + statsp->T_run_time),
                    MSECS((slpinfop->sleep_time*1.0) / slpinfop->count),
                    MSECS(slpinfop->max_time*1.0),
                    idx == UNKNOWN_SYMIDX ? "unknown" : symb_p);
            strcat(json_detail,json_temp);
        }
        START_OBJ_PRINT((idx == UNKNOWN_SYMIDX ? "unknown" : symb_p), SECS(slpinfop->sleep_time), slpinfop->count, JSWAITING, json_detail, "");

        if (symb_p)
        	FREE(symb_p);

        /*
        ** Do we have the list of wakers tied to each sleep function?  This
        ** would only be the case for LIKI with the scdetail option used.
        */

        if (IS_LIKI && slpinfop->scd_wpid_hash) {
                ADD_KIDS_PRINT;
                foreach_hash_entry_l((void **)slpinfop->scd_wpid_hash,
                        WPID_HSIZE,
                        wait_scallwakers_json,
                        slp_scd_sort_by_time, 0, NULL);
                NULL_OBJ_PRINT;
                END_KIDS_PRINT;
        }
        ENDCURR_OBJ_PRINT;
        return 0;
}



int
print_slp_info_json(void *arg1, void *arg2)
{
        slp_info_t *slpinfop = (slp_info_t *)arg1;
        sched_stats_t *statsp = (sched_stats_t *)arg2;
        uint64 idx;
        char *symb_p = NULL;
        char *c_p;

        if (slpinfop->count == 0) return 0;

        idx = slpinfop->lle.key;
	if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;

        /*
        ** symbol names from /proc have embedded tabs that have to
        ** be stripped out....usually only one per string in front of the module name
        */

        if (!(idx == UNKNOWN_SYMIDX)) {
                symb_p = strdup(globals->symtable[idx].nameptr);
                if (c_p = strstr(symb_p, "\t"))
                    *c_p = 0x20;
        }
        if (statsp != NULL) {
            sprintf(json_temp, "%s%8d %6.2f%% %10.4f %6.2f%% %9.2f%% %10.3f %10.3f  %s\\n", tab,
                    slpinfop->count,
                    (slpinfop->count * 100.0) / statsp->C_sleep_cnt,
                    SECS(slpinfop->sleep_time),
                    (slpinfop->sleep_time *100.0) / statsp->T_sleep_time,
                    (slpinfop->sleep_time *100.0) / (statsp->T_sleep_time + statsp->T_runq_time + statsp->T_run_time),
                    MSECS((slpinfop->sleep_time*1.0) / slpinfop->count),
                    MSECS(slpinfop->max_time*1.0),
                    idx == UNKNOWN_SYMIDX ? "unknown" : symb_p);
            strcat(json_detail,json_temp);
        }
        if (symb_p)
                FREE(symb_p);
        return 0;
}

void
wait_summary_json(void *arg1, void *arg2, int (*sort_func)(const void *, const void *))
{
        slp_info_t      **slp_hash = arg1;
        sched_info_t    *schedp = (sched_info_t *)arg2;
        sched_stats_t   *statsp;
        int             i;


        if (slp_hash == NULL) return;
        bzero(json_detail,8192);
        statsp = &schedp->sched_stats;

        bzero(json_temp, 4096);
        bzero(json_detail, 8192);
        sprintf(json_temp, "\\n%sKernel Functions calling sleep()", tab);
        strcat(json_detail,json_temp);
        if (nsym && (nsym != 0x7fffffff)) {
            sprintf(json_temp, " - Top %d Functions", nsym);
            strcat(json_detail,json_temp);
        }

        sprintf(json_temp, "\\n%s   Count     Pct    SlpTime    Slp%% TotalTime%%   Msec/Slp   MaxMsecs  Func\\n", tab);
        strcat(json_detail,json_temp);

        foreach_hash_entry_l((void **)slp_hash, SLP_HSIZE, print_slp_info_json, sort_func, nsym, statsp);

}

int
runq_scall_json(void *arg1, void *arg2)
{
        syscall_info_t *syscallp = arg1;
        pid_info_t      *pidp = arg2;
        syscall_stats_t *statp = &syscallp->stats;
        sched_stats_t *sstatp = &syscallp->sched_stats;
        short *syscall_index;

        if ((statp->count == 0) || (sstatp->T_sys_time == 0)) return 0;

	syscall_index = (SYSCALL_MODE(syscallp->lle.key) == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;

        bzero(json_detail, 8192);
        sprintf(json_temp, "%sSystem Call Name     Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\\n", tab);
        strcat(json_detail,json_temp);

        sprintf (json_temp, "%s%-18s%8d %8.1f %11.6f %10.6f %10.6f %7d", tab,
                syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name,
                statp->count,
                statp->count / secs,
                SECS(statp->total_time),
                SECS(statp->total_time / statp->count),
                SECS(statp->max_time),
                statp->errors);
        strcat(json_detail, json_temp);

        if (statp->bytes)  {
                sprintf (json_temp, " %7lld %8.1f",
                        (statp->bytes) / statp->count,
                        (statp->bytes) / (secs * 1024.0));
                strcat(json_detail, json_temp);
        }

        sprintf (json_temp, "\\n");
        strcat(json_detail, json_temp);

        if (sstatp->T_runq_time) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,
                                "RUNQ",
                                SECS(sstatp->T_runq_time));
                        strcat(json_detail, json_temp);
        }

        if (sstatp->T_run_time &&  (sstatp->T_run_time != statp->total_time) ) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,
                                "CPU",
                                SECS(sstatp->T_run_time));
                        strcat(json_detail, json_temp);
        }

        if (sstatp->C_sleep_cnt) {
            sprintf (json_temp, "%s   %-15s%8d %8.1f %11.6f %10.6f\\n", tab,
                                "SLEEP",
                                sstatp->C_sleep_cnt,
                                sstatp->C_sleep_cnt/secs,
                                SECS(sstatp->T_sleep_time),
                                SECS(sstatp->T_sleep_time / sstatp->C_sleep_cnt));
            strcat(json_detail, json_temp);
        }

        START_OBJ_PRINT(syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name, SECS(sstatp->T_runq_time), statp->count, JSRUNQ, json_detail, "");

        ENDCURR_OBJ_PRINT;
        return 0;
}

int
runsys_scall_json(void *arg1, void *arg2)
{
        syscall_info_t *syscallp = arg1;
        pid_info_t      *pidp = arg2;
        syscall_stats_t *statp = &syscallp->stats;
        sched_stats_t *sstatp = &syscallp->sched_stats;
        short  *syscall_index;

        if ((statp->count == 0) || (sstatp->T_sys_time == 0)) return 0;

	syscall_index = (SYSCALL_MODE(syscallp->lle.key) == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;

        bzero(json_detail, 8192);
        sprintf(json_temp, "%sSystem Call Name     Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\\n", tab);
        strcat(json_detail,json_temp);


        sprintf (json_temp, "%s%-18s%8d %8.1f %11.6f %10.6f %10.6f %7d", tab,
                syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name,
                statp->count,
                statp->count / secs,
                SECS(statp->total_time),
                SECS(statp->total_time / statp->count),
                SECS(statp->max_time),
                statp->errors);
        strcat(json_detail, json_temp);

        if (statp->bytes)  {
                sprintf (json_temp, " %7lld %8.1f",
                        (statp->bytes) / statp->count,
                        (statp->bytes) / (secs * 1024.0));
                strcat(json_detail, json_temp);
        }

        sprintf (json_temp, "\\n");
        strcat(json_detail, json_temp);

        if (sstatp->T_runq_time) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,
                                "RUNQ",
                                SECS(sstatp->T_runq_time));
                        strcat(json_detail, json_temp);
        }

        if (sstatp->T_run_time &&  (sstatp->T_run_time != statp->total_time) ) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,
                                "CPU",
                                SECS(sstatp->T_run_time));
                        strcat(json_detail, json_temp);
        }

        if (sstatp->C_sleep_cnt) {
            sprintf (json_temp, "%s   %-15s%8d %8.1f %11.6f %10.6f\\n", tab,
                                "SLEEP",
                                sstatp->C_sleep_cnt,
                                sstatp->C_sleep_cnt/secs,
                                SECS(sstatp->T_sleep_time),
                                SECS(sstatp->T_sleep_time / sstatp->C_sleep_cnt));
            strcat(json_detail, json_temp);
        }

        START_OBJ_PRINT(syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name, SECS(sstatp->T_run_time), statp->count, JSRUNNING, json_detail, "");

        ENDCURR_OBJ_PRINT;
        return 0;
}


int
wait_scall_json(void *arg1, void *arg2)
{
        syscall_info_t *syscallp = arg1;
        pid_info_t      *pidp = arg2;
        syscall_stats_t *statp = &syscallp->stats;
        sched_stats_t *sstatp = &syscallp->sched_stats;
        short  *syscall_index;

        if ((statp->count == 0) || (sstatp->T_sleep_time == 0)) return 0;

	syscall_index = (SYSCALL_MODE(syscallp->lle.key) == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;

        bzero(json_detail, 8192);
        sprintf(json_temp, "%sSystem Call Name     Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\\n", tab);
        strcat(json_detail,json_temp);


        sprintf (json_temp, "%s%-18s%8d %8.1f %11.6f %10.6f %10.6f %7d", tab,
                syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name,
                statp->count,
                statp->count / secs,
                SECS(statp->total_time),
                SECS(statp->total_time / statp->count),
                SECS(statp->max_time),
                statp->errors);
        strcat(json_detail, json_temp);

        if (statp->bytes)  {
                sprintf (json_temp, " %7lld %8.1f",
                        (statp->bytes) / statp->count,
                        (statp->bytes) / (secs * 1024.0));
                strcat(json_detail, json_temp);
        }

        sprintf (json_temp, "\\n");
        strcat(json_detail, json_temp);

        if (sstatp->T_runq_time) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,
                                "RUNQ",
                                SECS(sstatp->T_runq_time));
                        strcat(json_detail, json_temp);
        }

        if (sstatp->T_run_time &&  (sstatp->T_run_time != statp->total_time) ) {
                        sprintf (json_temp, "%s   %-15s                  %11.6f\\n",  tab,                                "CPU",
                                SECS(sstatp->T_run_time));
                        strcat(json_detail, json_temp);
        }

        sprintf (json_temp, "%s   %-15s%8d %8.1f %11.6f %10.6f\\n", tab,
                                "SLEEP",
                                sstatp->C_sleep_cnt,
                                sstatp->C_sleep_cnt/secs,
                                SECS(sstatp->T_sleep_time),
                                SECS(sstatp->T_sleep_time / sstatp->C_sleep_cnt));
        strcat(json_detail, json_temp);

        START_OBJ_PRINT(syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name, SECS(sstatp->T_sleep_time), sstatp->C_switch_cnt, JSWAITING, json_detail, "");

        if (IS_LIKI && syscallp->slp_hash) {
                ADD_KIDS_PRINT;
                                foreach_hash_entry_l((void **)syscallp->slp_hash,
                                                SLP_HSIZE,
                                                wait_scallsym_json,
                                                slp_sort_by_time, 0, NULL);
                NULL_OBJ_PRINT;
                END_KIDS_PRINT;
        }

/*      START_OBJ_PRINT("WAITING", SECS(sstatp->T_sleep_time), sstatp->C_switch_cnt, JSWAITING, json_detail);    */
        ENDCURR_OBJ_PRINT;
        return 0;
}

void
pid_scall_json(pid_info_t *pidp, int type, sched_stats_t *statsp) {
	/* if ((pidp->syscall_cnt == 0) && (statsp->uflt_sleep_cnt == 0)) return; */

        switch (type) {
            case JSRUNQ:
                START_OBJ_PRINT("Usr preempt", SECS(statsp->T_runq_usrpri_time), (statsp->C_runq_usrpri_cnt), JSRUNQ, 0, "");
		ENDCURR_OBJ_PRINT;
                foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, runq_scall_json, syscall_sort_by_time, 0, pidp);
                NULL_OBJ_PRINT;
                break;
/*          case JSRUNNING_USER:
                foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, runuser_scall_json, syscall_sort_by_time, 0, pidp);
                break;
*/
            case JSRUNNING_SYS:
                foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, runsys_scall_json, syscall_sort_by_time, 0, pidp);
                NULL_OBJ_PRINT;
                break;
            case JSWAITING:
		START_OBJ_PRINT("No_scall/Fault/Trap", SECS(statsp->T_uflt_sleep_time), statsp->C_uflt_sleep_cnt, JSWAITING, json_detail, "");
		    ADD_KIDS_PRINT;
		    foreach_hash_entry_l((void **)pidp->user_slp_hash, SLP_HSIZE, wait_scallsym_json, slp_sort_by_time, 0, NULL);
		    NULL_OBJ_PRINT;
		    END_KIDS_PRINT;
		ENDCURR_OBJ_PRINT;

                foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, wait_scall_json, syscall_sort_by_time, 0, pidp);
                NULL_OBJ_PRINT;
                break;
            default:
                break;
        }
}

void
runq_summary_json(sched_stats_t *statp)
{

        bzero(json_detail,8192);
        sprintf(json_temp, "\\n    ******** PID RUNQ LATENCY REPORT ********\\n");
        strcat(json_detail,json_temp);

        sprintf(json_temp, "%sRunQTime   : %9.6f  RunQCnt   : %9d   AvRunQTime : %9.6f\\n",  tab,
                SECS(statp->T_runq_time),
                statp->C_runq_cnt,
                SECS(statp->T_runq_time*1.0 / statp->C_runq_cnt));
        strcat(json_detail,json_temp);

        sprintf(json_temp, "%sRunQPri    : %9.6f  RunQPriCt : %9d   AvRunQPri  : %9.6f\\n", tab,
                SECS(statp->T_runq_pri_time),
                statp->C_runq_pri_cnt,
                SECS(statp->T_runq_pri_time*1.0 / statp->C_runq_pri_cnt));
        strcat(json_detail,json_temp);

        sprintf(json_temp, "%sRunQIdle   : %9.6f  RunQIdleCt: %9d   AvRunQIdle : %9.6f\\n", tab,
                SECS(statp->T_runq_idle_time),
                statp->C_runq_idle_cnt,
                SECS(statp->T_runq_idle_time*1.0 / statp->C_runq_idle_cnt));
        strcat(json_detail,json_temp);
}

void
running_summary_json(sched_stats_t *statp)
{
	uint64 total_time;
        bzero(json_detail,8192);
	statp->T_irq_time = statp->T_hardirq_user_time + statp->T_hardirq_sys_time +
                   statp->T_hardirq_user_time + statp->T_hardirq_sys_time;
        total_time = statp->T_sys_time + statp->T_user_time + statp->T_runq_time + statp->T_sleep_time + statp->T_irq_time;
        if (total_time) {
                sprintf(json_temp, "\\n%srunning: %9.2f%%\\n", tab, (statp->T_run_time*100.0) / total_time );
                strcat(json_detail,json_temp);
                sprintf(json_temp, "%s  sys  : %9.2f%%\\n", tab, (statp->T_sys_time*100.0) / total_time );
                strcat(json_detail,json_temp);
                sprintf(json_temp, "%s  user : %9.2f%%\\n", tab, (statp->T_user_time*100.0) / total_time );
                strcat(json_detail,json_temp);
                if ((statp->C_softirq_cnt + statp->C_hardirq_cnt) > 0) {
                        sprintf(json_temp, "%s  irq  : %9.2f%%\\n", tab,
                        (statp->T_irq_time * 100.0) / total_time);
                        strcat(json_detail,json_temp);
                }
                sprintf(json_temp, "%srunQ   : %9.2f%%\\n", tab, (statp->T_runq_time*100.0) / total_time );
                strcat(json_detail,json_temp);
                sprintf(json_temp, "%swaiting: %9.2f%%\\n", tab, (statp->T_sleep_time*100.0) / total_time );
                strcat(json_detail,json_temp);
        }
}



void
pid_json_print_summary(pid_info_t *pidp, sched_stats_t *statp)
{

        char json_pidname[128];
        sched_info_t *schedp = pidp->schedp;
        uint64  total_time;
        pid_info_t *ppidp, *tgidp;
        int print_irq_stats = 0;

	statp->T_irq_time = statp->T_hardirq_user_time + statp->T_hardirq_sys_time +
		   statp->T_softirq_user_time + statp->T_softirq_sys_time;
	total_time = statp->T_sys_time + statp->T_user_time + statp->T_runq_time + statp->T_sleep_time + statp->T_irq_time;

        bzero(json_detail,8192);
        print_irq_stats = statp->C_softirq_cnt + statp->C_hardirq_cnt;

        sprintf (json_temp, "\\nPID %d  %s", (int)pidp->PID, (char *)pidp->cmd);
        strcat(json_detail,json_temp);

        if (pidp->thread_cmd) {
		if (pidp->hcmd) sprintf (json_temp, "  {%s}", pidp->hcmd);
                else sprintf (json_temp, "  (%s)", pidp->thread_cmd);
                strcat(json_detail,json_temp);
        }
	if (pidp->dockerp) sprintf (json_temp, HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
        sprintf (json_temp, "\\n");
        strcat(json_detail,json_temp);

        if (pidp->ppid) {
                ppidp = GET_PIDP(&globals->pid_hash, pidp->ppid);
                sprintf (json_temp, "  PPID %d  %s\\n", ppidp->PID, (char *)ppidp->cmd);
                strcat(json_detail,json_temp);
        }
        if (pidp->tgid && (pidp->tgid != pidp->PID)) {
                tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                sprintf (json_temp, "  TGID %d  %s\\n", tgidp->PID, (char *)tgidp->cmd);
                strcat(json_detail,json_temp);
        }
        if (pidp->nlwp > 1) {
                sprintf (json_temp, "  NLWP: %d\\n", pidp->nlwp);
                strcat(json_detail,json_temp);
        }
        sprintf (json_temp, "\\n%s********* SCHEDULER ACTIVITY REPORT ********\\n", tab);
        strcat(json_detail,json_temp);

        sprintf (json_temp, "%sRunTime    : %9.6f  SysTime   : %9.6f   UserTime   : %9.6f\\n",  tab,
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time));
        strcat(json_detail,json_temp);
        sprintf (json_temp, "%sSleepTime  : %9.6f  Sleep Cnt : %9d   Wakeup Cnt : %9d\\n", tab,
                SECS(statp->T_sleep_time),
                statp->C_sleep_cnt,
                statp->C_wakeup_cnt);
        strcat(json_detail,json_temp);
        sprintf (json_temp, "%sRunQTime   : %9.6f  Switch Cnt: %9d   PreemptCnt : %9d\\n",  tab,
                SECS(statp->T_runq_time),
                statp->C_switch_cnt,
                statp->C_preempt_cnt);
        strcat(json_detail,json_temp);
        if (print_irq_stats > 0) {
            sprintf (json_temp, "%sHardIRQ    : %9.6f  HardIRQ-S : %9.6f    HardIRQ-U : %9.6f\\n", tab,
                SECS(statp->T_hardirq_user_time + statp->T_hardirq_sys_time),
                SECS(statp->T_hardirq_sys_time),
                SECS(statp->T_hardirq_user_time));
            strcat(json_detail,json_temp);
            sprintf (json_temp, "%sSoftIRQ    : %9.6f  SoftIRQ-S : %9.6f    SoftIRQ-U : %9.6f\\n", tab,
                SECS(statp->T_softirq_user_time + statp->T_softirq_sys_time),
                SECS(statp->T_softirq_sys_time),
                SECS(statp->T_softirq_user_time));
            strcat(json_detail,json_temp);
        }
        sprintf (json_temp,"%sLast CPU   : %9d  CPU Migrs : %9d   NODE Migrs : %9d\\n", tab,
                schedp->cpu,
                schedp->cpu_migrations,
                schedp->ldom_migrations);
        strcat(json_detail,json_temp);
        if (IS_LIKI) {
                sprintf (json_temp, "%sPolicy     : %-12s", tab, sched_policy_name[schedp->policy]);
                strcat(json_detail,json_temp);
                if (IS_LIKI_V2_PLUS) {
                        sprintf (json_temp, "     vss :  %8lld          rss :  %8lld", pidp->vss, pidp->rss);
                        strcat(json_detail,json_temp);
                }
                sprintf (json_temp, "\\n");
                strcat(json_detail,json_temp);
        }

        sprintf (json_pidname, "PID %d", (int)pidp->PID);

	START_OBJ_PRINT((char *)json_pidname, SECS(total_time), statp->C_switch_cnt, JSPARENT, json_detail, "");
        ADD_KIDS_PRINT;

        /*
        ** The order we add things to the JSON file does not matter.  The
        ** D3 html will sort and present the data based on size/count fields
        ** regardless of their order in the JSON file.
        **
        ** The json_detail pointer below is the buffer that is used used
        ** to construct the 'tooltip' popup text.  For now I'll squander CPU
        ** resources and pre-build the text content via multiple sprintf
        ** and strcat calls before writing it out.
        **
        ** For JSON format rules/details see http://www.json.org
        */


          if (schedp->rqh) runq_summary_json(statp);
          START_OBJ_PRINT("RUNQ", SECS(statp->T_runq_time), statp->C_switch_cnt, JSRUNQ, json_detail, "");
          ADD_KIDS_PRINT;
            pid_scall_json(pidp, JSRUNQ, statp);
          END_KIDS_PRINT;
          ENDCURR_OBJ_PRINT;

          running_summary_json(statp);
          START_OBJ_PRINT("RUNNING", SECS(statp->T_run_time), statp->C_preempt_cnt, JSRUNNING, json_detail, "");
          ADD_KIDS_PRINT;
            START_OBJ_PRINT("Userspace", SECS(statp->T_user_time), statp->C_preempt_cnt, JSRUNNING, json_detail, "");
            ADD_KIDS_PRINT;
              pid_scall_json(pidp, JSRUNNING_USER, statp);
            END_KIDS_PRINT;
            ENDCURR_OBJ_PRINT;
            START_OBJ_PRINT("System", SECS(statp->T_sys_time), statp->C_preempt_cnt, JSRUNNING, json_detail, "");
            ADD_KIDS_PRINT;
              pid_scall_json(pidp, JSRUNNING_SYS, statp);
            END_KIDS_PRINT;
            ENDLAST_OBJ_PRINT;
          END_KIDS_PRINT;
          ENDCURR_OBJ_PRINT;

	  if (pidp->slp_hash || pidp->user_slp_hash) wait_summary_json(pidp->slp_hash, schedp, slp_sort_by_time);
	  START_OBJ_PRINT("WAITING", SECS(statp->T_sleep_time), statp->C_sleep_cnt, JSWAITING, json_detail, "");
          ADD_KIDS_PRINT;
            pid_scall_json(pidp, JSWAITING, statp);
          END_KIDS_PRINT;
          ENDLAST_OBJ_PRINT;

        END_KIDS_PRINT;
        ENDLAST_OBJ_PRINT;  /* temp end of json file for now */
}

void 
print_runq_latency_report(sched_info_t *schedp)
{
	sched_stats_t *statp = &schedp->sched_stats;

        pid_printf("\n%s******** PID RUNQ LATENCY REPORT ********\n", tab);
        pid_printf ("%sRunQTime   : %9.6f  RunQCnt   : %9d   AvRunQTime : %9.6f\n",  tab,
                SECS(statp->T_runq_time),
		statp->C_runq_cnt,
		statp->C_runq_cnt ? SECS(statp->T_runq_time / statp->C_runq_cnt) : 0.0);
	pid_printf ("%sRunQPri    : %9.6f  RunQPriCt : %9d   AvRunQPri  : %9.6f\n", tab,
		SECS(statp->T_runq_pri_time),
		statp->C_runq_pri_cnt,
		statp->C_runq_pri_cnt ? SECS(statp->T_runq_pri_time / statp->C_runq_pri_cnt) : 0.0);
	pid_printf ("%sRunQIdle   : %9.6f  RunQIdleCt: %9d   AvRunQIdle : %9.6f\n", tab,
		SECS(statp->T_runq_idle_time),
		statp->C_runq_idle_cnt,
		statp->C_runq_idle_cnt ? SECS(statp->T_runq_idle_time / statp->C_runq_idle_cnt) : 0.0);

	return;
}

void
print_runq_histogram(sched_info_t *schedp)
{
        int i, j, avg;
        runq_info_t *rqinfop;
	sched_stats_t *statp = &schedp->sched_stats;

        if (schedp->rqh == NULL)
                return;

        pid_printf("\n    runq latency in Usecs\n");
        pid_printf("    cpu    <5     <10    <20    <50    <100   <500   <1000  <2000  <10000 <20000 >20000\n");

        for (i=0;i<MAXCPUS;i++) {
                rqinfop = (runq_info_t *)find_entry((lle_t **)schedp->rqh, i, CPU_HASH(i));

                if (rqinfop == NULL) continue;
		if (rqinfop->cnt == 0) continue;

                pid_printf ("    %-3d  :", i);
                for (j = 0; j < RUNQ_NBUCKETS; j++) {
                        pid_printf(" %-6d", rqinfop->rqhist[j]);
                }
                pid_printf ("\n");

        }
        pid_printf("\n    runq latency in Usecs\n    cpu   Avg.      Max       Total_time  Total_cnt  Migrations  NODE_migr_in  NODE_migr_out\n");

        for (i=0;i<MAXCPUS;i++) {
                rqinfop = (runq_info_t *)find_entry((lle_t **)schedp->rqh, i, CPU_HASH(i));

                if (rqinfop == NULL) continue;

                if ( rqinfop->cnt )
                        avg = ( rqinfop->total_time/rqinfop->cnt);
                else
                        continue;

                pid_printf("    %-3d   %-9d %-9lld %-11lld %-10d %-11d %-13d %-14d\n",
                                i,
                                avg,
                                rqinfop->max_time,
                                rqinfop->total_time,
                                rqinfop->cnt,
                                rqinfop->migrations,
                                rqinfop->ldom_migrations_in,
                                rqinfop->ldom_migrations_out);

                if (is_alive) bzero((char *)rqinfop+sizeof(lle_t), sizeof(runq_info_t) - sizeof(lle_t));
	}
}

void
msr_report(pid_info_t *pidp, void *v)
{
	sched_info_t *schedp = pidp->schedp;
	unsigned long *msrptr;

	if (schedp == NULL) return;
	msrptr = &schedp->sched_stats.msr_total[0];

	if (msrptr[0] == 0) return;

	pid_printf ("\n    ******** CPU MSR REPORT *******\n");
	pid_printf ("        LLC_ref   LLC_hits  LLC_hit%%     Instrs     Cycles      CPI   Avg_MHz  SMI_cnt\n");
	pid_printf ("     %9lldk %9lldk %8.2f%% %9lldm %9lldm %8.2f   %7.2f     %4lld\n",
			msrptr[LLC_REF]/1000, (msrptr[LLC_REF]-msrptr[LLC_MISSES])/1000,
			(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
			msrptr[RET_INSTR]/1000000, msrptr[CYC_NOHALT_CORE]/1000000,
			msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               		msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
			msrptr[SMI_CNT]);
}


int
sched_report(void *arg1, void *v)
{
	pid_info_t *pidp = arg1;
        sched_info_t *schedp = pidp->schedp;
	cpu_info_t *cpuinfop;
        sched_stats_t *statp;
	uint64 total_time;
	int print_irq_stats = 0;
        char temp[4096];
        char detail[8192];
        char json_pidname[128];

        coop_info_t coopinfo;
        if (schedp == NULL) {
		csv_printf(pid_csvfile, ",IDLE,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0,0,0,0,0,0,0,0");
                if (pid_jsonfile) { 
			fclose(pid_jsonfile);
			pid_jsonfile = NULL;
		}
		return 0;
	}
        bzero(&coopinfo,sizeof(coop_info_t));
	coopinfo.rep_pidp =  pidp;

	cpuinfop = FIND_CPUP(globals->cpu_hash, schedp->cpu);

	if (debug) printf ("sched_report: 0x%llx\n", schedp);

        statp = &schedp->sched_stats;
	statp->T_irq_time = statp->T_hardirq_user_time + statp->T_hardirq_sys_time + 
		   statp->T_softirq_user_time + statp->T_softirq_sys_time;
        total_time = statp->T_run_time + statp->T_sleep_time + statp->T_runq_time;

	print_irq_stats = statp->C_softirq_cnt + statp->C_hardirq_cnt;

        pid_printf ("\n%s********* SCHEDULER ACTIVITY REPORT ********\n", tab);

        pid_printf ("%sRunTime    : %9.6f  SysTime   : %9.6f   UserTime   : %9.6f\n",  tab,
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time));
	if (STEAL_ON) 
		pid_printf ("%sStealTime  : %9.6f\n",  tab,
                	SECS(statp->T_stealtime));
        pid_printf ("%sSleepTime  : %9.6f  Sleep Cnt : %9d   Wakeup Cnt : %9d\n", tab,
                SECS(statp->T_sleep_time),
                statp->C_sleep_cnt,
                statp->C_wakeup_cnt);
        pid_printf ("%sRunQTime   : %9.6f  Switch Cnt: %9d   PreemptCnt : %9d\n",  tab,
                SECS(statp->T_runq_time),
                statp->C_switch_cnt,
                statp->C_preempt_cnt);
	if (print_irq_stats > 0) {
	    pid_printf ("%sHardIRQ    : %9.6f  HardIRQ-S : %9.6f    HardIRQ-U : %9.6f\n", tab,
		SECS(statp->T_hardirq_user_time + statp->T_hardirq_sys_time),
		SECS(statp->T_hardirq_sys_time),
		SECS(statp->T_hardirq_user_time));	
	    pid_printf ("%sSoftIRQ    : %9.6f  SoftIRQ-S : %9.6f    SoftIRQ-U : %9.6f\n", tab,
		SECS(statp->T_softirq_user_time + statp->T_softirq_sys_time),
		SECS(statp->T_softirq_sys_time),
		SECS(statp->T_softirq_user_time));
	}
        pid_printf ("%sLast CPU   : %9d  CPU Migrs : %9d   NODE Migrs : %9d\n", tab,
                schedp->cpu,
                schedp->cpu_migrations,
		schedp->ldom_migrations);
        if (IS_LIKI) {
		pid_printf ("%sPolicy     : %-12s", tab, sched_policy_name[schedp->policy]);
		if (IS_LIKI_V2_PLUS) {
			pid_printf ("     vss :  %8lld          rss :  %8lld", pidp->vss, pidp->rss);
		}
		pid_printf ("\n");
	}

	if (total_time) {
		pid_printf ("\n%sbusy    : %9.2f%%\n", tab, (statp->T_run_time*100.0) / total_time );
		pid_printf ("%s  sys   : %9.2f%%\n", tab, (statp->T_sys_time*100.0) / total_time );
		pid_printf ("%s  user  : %9.2f%%\n", tab, (statp->T_user_time*100.0) / total_time );
		if (STEAL_ON) {
			pid_printf ("%s  steal : %9.2f%%\n", tab, (statp->T_stealtime*100.0) / total_time );
		}
		if (print_irq_stats > 0) {
		    pid_printf ("%s  irq   : %9.2f%%\n", tab, 
			(statp->T_irq_time * 100.0) / total_time);
		}
		pid_printf ("%srunQ    : %9.2f%%\n", tab, (statp->T_runq_time*100.0) / total_time );
		pid_printf ("%ssleep   : %9.2f%%\n", tab, (statp->T_sleep_time*100.0) / total_time );
	}

	csv_printf(pid_csvfile, ",%s,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%d,%d,%d,%d,%7.6f,%d,%d,%d,%d,%d,%d",
		sched_policy_name[schedp->policy],
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time),
                SECS(statp->T_runq_time),
                SECS(statp->T_sleep_time),
		SECS(statp->T_irq_time),
		SECS(statp->T_stealtime),
                statp->C_switch_cnt,
                statp->C_sleep_cnt,
                statp->C_preempt_cnt,
                statp->C_wakeup_cnt,
		SECS((statp->T_run_time * 1.0) / statp->C_switch_cnt),
		schedp->cpu,
		cpuinfop->ldom,
                schedp->cpu_migrations,
		schedp->ldom_migrations,
		pidp->vss,
		pidp->rss);

	if (msr_flag) msr_report(pidp, NULL);

        if (pid_jsonfile) {
                pid_json_print_summary(pidp, statp);
        }

	if (pid_wtree_jsonfile) {
                wtree_build(pidp);
        }

	print_runq_latency_report(schedp);
	if (runq_histogram) {
		print_runq_histogram(schedp);
	}

        if (npid) {
		pid_printf ("\n%s******** COOPERATING/COMPETING TASKS REPORT ********\n", tab);
                if (npid == ALL) {
                        pid_printf ("\n%sTasks woken up by this task\n", tab);
                } else {
                        pid_printf ("\n%sTasks woken up by this task (Top %d)\n", tab, npid);
                }
                coopinfo.elf = pidp->elf;

                pid_printf ("%s       PID    Count   SlpPcnt     Slptime  Command ", tab);
                if (coop_detail_enabled) 
			pid_printf ("          WakerSyscall+arg0                    SleeperSyscall+arg0                Sleep function\n");
		pid_printf ("\n");

                if (schedp->sched_stats.C_wakeup_cnt != 0) {
                        coopinfo.which = WAKER;
                        coopinfo.cnt = schedp->sched_stats.C_wakeup_cnt;
                        foreach_hash_entry((void **)schedp->setrq_tgt_hash, WPID_HSIZE,
                                        sched_print_setrq_pids, setrq_sort_by_sleep_time, npid, (void *)&coopinfo);
                } else {
                        pid_printf ("%s    None\n", tab);
                }

                if (npid == ALL) {
                        pid_printf ("\n%sTasks that have woken up this task\n", tab);
                } else  {
                        pid_printf ("\n%sTasks that have woken up this task(Top %d)\n", tab, npid);
                }

                pid_printf ("%s       PID    Count   SlpPcnt     Slptime  Command ", tab);
                if (coop_detail_enabled) 
			pid_printf ("          WakerSyscall+arg0                    SleeperSyscall+arg0                Sleep function\n");
                pid_printf ("\n");

                if (schedp->sched_stats.C_setrq_cnt != 0) {
                        coopinfo.which = SLEEPER;
                        coopinfo.cnt = schedp->sched_stats.C_setrq_cnt;
                        coopinfo.total_slp_time = statp->T_sleep_time;
                        foreach_hash_entry((void **)schedp->setrq_src_hash, WPID_HSIZE,
                                        sched_print_setrq_pids, setrq_sort_by_sleep_time, npid, (void *)&coopinfo);
                } else {
                        pid_printf ("%s    None\n", tab);
                }
        }

        if (pidp->slp_hash) {
        	pid_printf ("\n%s******** SLEEP REPORT ********\n\n", tab);
        	sleep_report(pidp->slp_hash, schedp, slp_sort_by_time, v);
        	if (pidp->stktrc_hash) stktrc_report(pidp->stktrc_hash, schedp, stktrc_sort_by_slptime, v);
        	if (pidp->runq_stktrc_hash) stktrc_report(pidp->runq_stktrc_hash, NULL, stktrc_sort_by_cnt, v);
	}
}


uint64
sched_get_runtime(void *arg)
{
	pid_info_t *pidp = (pid_info_t *)arg;
	sched_info_t 	*schedp;
	sched_stats_t	*statsp;

        if ((schedp = pidp->schedp) == NULL) return 0;

        statsp = &schedp->sched_stats;

        return (uint64)statsp->T_run_time;
}

void 
print_cstate_stats(uint64 *warnflagp)
{
	int i, j;
	cpu_info_t	*cpuinfop;
	power_info_t	*powerp;
	uint64		cstate_total_time=0;
	int warn_cnt = 0;

	TEXT("\n");
	BOLD("cpu node    Events");
	for (j=1; j<=max_cstate;j++) {
		BOLD("   Cstate%d", j);
	}
	BOLD ("  freq_changes    freq_hi   freq_low\n");

	for (i=0;i<MAXCPUS;i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			if (powerp = cpuinfop->powerp) {
				/* sum up final state */
				if (powerp->power_start_cnt || powerp->power_end_cnt) {
					powerp->cstate_times[powerp->cur_cstate] += (end_time - powerp->last_cstate_time);
				}	

				cstate_total_time = 0;
				for (j=1;j<=max_cstate;j++) {
					cstate_total_time += powerp->cstate_times[j];
				}
	
				printf ("%-3d [%2d]  %8d", i, cpuinfop->ldom, powerp->power_start_cnt);
				for (j=1; j<=max_cstate;j++) {
					if ((j > 1) && powerp->cstate_times[j]) { 
						warn_cnt++;
						RED_FONT;
					}
					printf ("  %7.2f%%", cstate_total_time ?  (powerp->cstate_times[j] * 100.0) / cstate_total_time : 0);
					BLACK_FONT;
				}
				if (powerp->power_freq_cnt)  {
					warn_cnt++;
					RED_FONT;
				}
				printf ("   %10d %10lld %10lld", powerp->power_freq_cnt, powerp->freq_hi, powerp->freq_low); 
				BLACK_FONT;


#if 0
				if (debug) {
					for (j=0;j<=NCSTATES ;j++) {
						printf (" %10d", powerp->cstate_times[j]);
					}
				}
#endif
				printf ("\n");
			}
		}
	}

	if (warnflagp && warn_cnt) {
		*warnflagp |= WARNF_POWER;
	}
}

int 
print_hardirq_entry(void *arg1, void *arg2)
{
	irq_entry_t *irqentryp = (irq_entry_t *)arg1;
	int *warnflagp = (int *)arg2;
	int irq = irqentryp->lle.key;
	irq_name_t *irqname_entry;

	irqname_entry = (irq_name_t *)find_entry((lle_t **)globals->irqname_hash, irq, IRQ_HASH(irq));
	if (irqname_entry) {
		printf ("%3d %-16s", irq, irqname_entry->name);
	} else {
		printf ("%3d %-16s", irq, " ");
	}
	printf (" %8d %12.6f %12.6f\n", irqentryp->count, SECS(irqentryp->total_time), 
					(SECS(irqentryp->total_time) / irqentryp->count)*1000000.0);
}

int 
print_softirq_entry(void *arg1, void *arg2)
{
	irq_entry_t *irqentryp = (irq_entry_t *)arg1;
	int *warnflagp = (int *)arg2;
	int irq = irqentryp->lle.key;
	irq_name_t *irqname_entry;

	if (warnflagp) {
		/* if we use more than 1/2 core worth of time for BLOCK interrupts */
		if ((irq == TASKLET_SOFTIRQ) && (irqentryp->count > 100000) && (SECS(irqentryp->total_time) > (globals->total_secs*0.5))) {
			(*warnflagp) |= WARNF_TASKLET;
			RED_FONT;
		} 

		/* if we use more than 1 core worth of time for BLOCK interrupts */
		if ((irq == BLOCK_SOFTIRQ) && (irqentryp->count > 10000) && (SECS(irqentryp->total_time) > (globals->total_secs*1.0))) {
			(*warnflagp) |= WARNF_ADD_RANDOM;
			RED_FONT;
		} 
	}

	printf ("%3d %-16s %8d %12.6f %12.3f\n", irq, softirq_name[irq], 
					irqentryp->count,
					SECS(irqentryp->total_time),
					(SECS(irqentryp->total_time) / irqentryp->count)*1000000.0);

	BLACK_FONT;


}

void
print_percpu_irq_stats(int irqtype)
{
	cpu_info_t *cpuinfop;
	irq_info_t *irqinfop;
	int i;
	int func(void *, void*);

	for (i = 0; i < MAXCPUS; i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			irqinfop = (irqtype == HARDIRQ) ? cpuinfop->irqp : cpuinfop->softirqp;
			if (irqinfop) {
				TEXT("\n");
				CAPTION_GREY;
				BOLD ("CPU %3d      Events: %8d  ElpTime: %9.6f\n", i, irqinfop->count, SECS(irqinfop->total_time));
				_CAPTION;
				BOLD ("IRQ Name                Count      ElpTime    Avg(usec)\n");
				foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
							irqtype == HARDIRQ ? print_hardirq_entry : print_softirq_entry,
				 			irq_sort_by_time, 0, NULL);
			}
		}
	}
	return;
}

void 
print_global_hardirq_stats(void *arg1)
{
	uint64 *warnflagp = (uint64 *)arg1;
	irq_info_t *irqinfop = globals->irqp;

	if (irqinfop == NULL) return;

	BOLD ("IRQ Name                Count      ElpTime    Avg(usec)\n");
	foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
					print_hardirq_entry, irq_sort_by_time, 0, NULL);
	printf ("    Total:           %8d %12.6f\n", irqinfop->count, SECS(irqinfop->total_time));
	return;
}

void 
print_global_softirq_stats(void *arg1)
{
	uint64 *warnflagp = (uint64 *)arg1;
	irq_info_t *irqinfop = globals->softirqp;

	if (irqinfop == NULL) return;

	BOLD ("IRQ Name                Count      ElpTime    Avg(usec)\n");
	foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
					print_softirq_entry, irq_sort_by_time, 0, warnflagp);
	printf ("    Total:           %8d %12.6f\n", irqinfop->count, SECS(irqinfop->total_time));
	return;
}

int
print_pid_runtime_summary(void *arg1, void *arg2)
{
	pid_info_t *pidp = arg1;
	sched_info_t *schedp;
	sched_stats_t *statp;
	uint64 *warnflagp = (uint64 *)arg2;

	if (pidp->PID == 0ull) return 0;
	if ((schedp = pidp->schedp) == NULL) return 0;
	statp = &schedp->sched_stats;

	if (dockfile) {
		dock_printf ("%-8d", pidp->PID);
	} else {
		PID_URL_FIELD8(pidp->PID);
	}

        dock_printf (" %12.6f %12.6f %12.6f %12.6f %12.6f", 
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time),
                SECS(statp->T_runq_time),
                SECS(statp->T_sleep_time));

	if (pidp->cmd) dock_printf ("  %s", (char *)pidp->cmd);
	if (pidp->hcmd) dock_printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) dock_printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp && (dockfile == NULL)) {
		printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	}

        if (cluster_flag && dockfile == NULL) { SPACE; SERVER_URL_FIELD_BRACKETS(globals) }

        dock_printf ("\n");

        return 0;

}

int
print_pid_stealtime_summary(void *arg1, void *arg2)
{
	pid_info_t *pidp = arg1;
	sched_info_t *schedp;
	sched_stats_t *statp;
	uint64 *warnflagp = (uint64 *)arg2;

	if (pidp->PID == 0ull) return 0;
	if ((schedp = pidp->schedp) == NULL) return 0;
	statp = &schedp->sched_stats;
	if (statp->T_stealtime == 0) return 0;

	PID_URL_FIELD8(pidp->PID);
        printf (" %12.6f %12.6f %12.6f %12.6f %12.6f", 
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time),
                SECS(statp->T_runq_time),
                SECS(statp->T_stealtime));

	if (pidp->cmd) printf ("  %s", (char *)pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
        if (cluster_flag) { SPACE; SERVER_URL_FIELD_BRACKETS(globals) }

        printf ("\n");

        return 0;

}

int 
print_systime_pids(uint64 *warnflagp)
{
	BOLD ("    PID       RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_runtime_summary,
                           (int (*)()) pid_sort_by_systime,
                           npid, warnflagp);
}

int
print_runtime_pids(uint64 *warnflagp)
{
	BOLD ("    PID       RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_runtime_summary,
                           (int (*)()) pid_sort_by_runtime,
                           npid, warnflagp);
}

int 
print_runq_pids(uint64 *warnflagp)
{
	BOLD ("    PID       RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_runtime_summary,
                           (int (*)()) pid_sort_by_runqtime,
                           npid, warnflagp);
}

int 
print_stealtime_pids(uint64 *warnflagp)
{
	BOLD ("    PID       RunTime      SysTime     UserTime     RunqTime    StealTime Command\n");
	foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_stealtime_summary,
                           (int (*)()) pid_sort_by_stealtime,
                           npid, warnflagp);
}

void
print_runq_itime_analysis()
{
        int i, j, total_idle_cnt=0, max_idle_cpu;
        cpu_info_t *cpuinfop;
        float avg_idle;
        uint64 cum_idle=0, max_idle=0;

        if (itime_flag) {
            printf("\n\nIdle time analysis at timestamp %12.6f requested :\n\n", itime/1000000.0);
            printf("  num idle CPUs    avg idle time (ms)     max idle  (ms) \n");
            printf("  =============    ==================     ============== \n");
            for (i=0;i<MAXCPUS;i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
                        if (cpuinfop->state_post_itime == IDLE) {
                                total_idle_cnt++;
                                cum_idle += cpuinfop->idle_time;
                                if (cpuinfop->idle_time > max_idle) {
                                        max_idle = cpuinfop->idle_time;
                                        max_idle_cpu = i;
                                }
                        }
                }
            }
            avg_idle = (cum_idle/1000000.0)/total_idle_cnt;

            printf("  %d         %12.3f ms        %12.3f ms  on CPU %d \n", total_idle_cnt, avg_idle, max_idle/1000000.0, max_idle_cpu);

        }

        printf("\nIdle CPU Time Histogram\n");
        printf("Idle time in Usecs\ncpu    <10    <20    <50    <100   <250   <500   <750  <1000  <1250  <1500  <2000  <3000  <5000 <10000 <20000 >20000 \n");

        for (i=0;i<MAXCPUS;i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
                        printf (" %-2d  :", i);
                        for (j = 0; j < IDLE_TIME_NBUCKETS; j++) {
                                printf(" %-6lld", cpuinfop->idle_hist[j]);
                        }
                        printf ("\n");
                }

        }
        printf("\nNote - Idle time in the <10 Usec bucket is likely just context switch time and not true IDLE time.\n");
	printf("\n");
}

void print_percpu_csv(cpu_info_t *cpuinfop)
{
	sched_info_t *schedp = cpuinfop->schedp;
	power_info_t *powerp = cpuinfop->powerp;
	irq_info_t *irqp, *softirqp;
	sched_stats_t *statsp = &schedp->sched_stats;
	uint64 total_time, gbl_total_time;
	unsigned long *msrptr;
	int i, j;
	
	statsp->T_irq_time = 0;
	for (i = IRQ_BEGIN; i <= IRQ_END; i++) 
		statsp->T_irq_time += statsp->time[i];

	total_time = statsp->T_user_time + statsp->T_sys_time + statsp->T_idle_time + statsp->T_irq_time;
	
	if (total_time == 0) total_time = statsp->T_idle_time = gbl_total_time = globals->total_secs;

	csv_printf(runq_csvfile,"%d,%d,%d,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%3.2f,%3.2f,%3.2f,%3.2f,%3.2f,%3.2f,%3.2f,%3.2f,%3.2f",
		cpuinfop->cpu,
		cpuinfop->ldom,
		cpuinfop->lcpu_sibling,
		SECS(total_time),
		SECS(statsp->T_user_time),
		SECS(statsp->T_sys_time),
		SECS(statsp->T_idle_time),
		SECS(statsp->T_hardirq_user_time),
		SECS(statsp->T_hardirq_sys_time),
		SECS(statsp->T_hardirq_idle_time),
		SECS(statsp->T_softirq_user_time),
		SECS(statsp->T_softirq_sys_time),
		SECS(statsp->T_softirq_idle_time),
		(statsp->T_user_time*100.0)/total_time,
		(statsp->T_sys_time*100.0)/total_time,
		(statsp->T_idle_time*100.0)/total_time,
		(statsp->T_hardirq_user_time*100.0)/total_time,
		(statsp->T_hardirq_sys_time*100.0)/total_time,
		(statsp->T_hardirq_idle_time*100.0)/total_time,
		(statsp->T_softirq_user_time*100.0)/total_time,
		(statsp->T_softirq_sys_time*100.0)/total_time,
		(statsp->T_softirq_idle_time*100.0)/total_time);

	csv_printf(runq_csvfile,",%3.2f,%3.2f", (statsp->T_stealtime * 100.0) / total_time, 
						(statsp->T_stealtime_idle * 100.0) / total_time);

	if (powerp) {
		csv_printf(runq_csvfile,",%d,%d,%d", powerp->power_freq_cnt, powerp->freq_hi, powerp->freq_low);

		gbl_total_time = 0;
		if (powerp->power_start_cnt) {
                	powerp->cstate_times[powerp->cur_cstate] += (end_time - powerp->last_cstate_time);
		}

                for (j=1;j<=max_cstate;j++) {
                        gbl_total_time += powerp->cstate_times[j];
                }

		if (gbl_total_time == 0) gbl_total_time = globals->total_secs;

		csv_printf(runq_csvfile,",%d", powerp->power_start_cnt);
                for (j=1;j<=max_cstate;j++) {
			csv_printf(runq_csvfile,",%3.2f", (powerp->cstate_times[j] * 100.0) / gbl_total_time);
		}
	} else {
		csv_printf(runq_csvfile,",0,0,0,0");
		csv_printf(runq_csvfile,",0");   
                for (j=1;j<=max_cstate;j++) {
			csv_printf(runq_csvfile,",0.00");
		}
	}	

	if (msr_flag)  {
		msrptr = &statsp->msr_total[0];
		csv_printf (runq_csvfile, ",%lld,%lld,%3.2f%%,%lld,%lld,%3.2f,%3.2f,%lld",
				msrptr[LLC_REF], msrptr[LLC_REF]-msrptr[LLC_MISSES],
				(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
				msrptr[RET_INSTR], msrptr[CYC_NOHALT_CORE],
				msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               			msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
				statsp->msr_last[SMI_CNT]);
	}

	csv_printf(runq_csvfile,"\n");

}

void print_cpu_csv()
{
	int i;
	cpu_info_t *cpuinfop;
	sched_info_t *schedp;

	csv_printf(runq_csvfile, "CPU,node,sibling,TotTime,User,Sys,Idle,HirqUser,HirqSys,HirqIdle,SirqUser,SirqSys,SirqIdle");
	csv_printf(runq_csvfile, ",%%User,%%Sys,%%Idle,%%HirqUser,%%HirqSys,%%HirqIdle,%%SirqUser,%%SirqSys,%%SirqIdle");
	csv_printf(runq_csvfile, ",%%StlTm,%%StlTmIdle");
	csv_printf(runq_csvfile,",FreqEvents,FreqHi,FreqLo");
	csv_printf(runq_csvfile,",CstateEvents");
	for (i=1; i<=max_cstate; i++) {
		csv_printf(runq_csvfile,",Cstate%d", i);
	}
	if (msr_flag)  csv_printf(runq_csvfile,",LLC ref,LLC hit,LLC hit%%,Instrs,Cycles,CPI,Avg MHz,SMI Count");
	csv_printf(runq_csvfile, "\n");

        for (i=0;i<MAXCPUS;i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			print_percpu_csv(cpuinfop);
                }

        }
	
}

int
runq_print_report(void *v)
{
	power_info_t *powerp;

	update_cpu_times(end_time);
	update_perpid_sched_stats();
	calc_global_cpu_stats(globals, NULL);
        parse_cstates();

	printf("\n%sGlobal CPU Counters\n", tab);
	print_percpu_stats(NULL);
	if (runq_csvfile) print_cpu_csv();

	if (globals->nldom > 1) {
		printf ("\n%sPer-NODE CPU Counters\n", tab);
		print_perldom_stats(NULL);
	}
	
	if (globals->irqp || globals->softirqp) {
		printf ("\n%sHard IRQ Events\n", tab);
		printf ("%s===============\n", tab);
		print_global_hardirq_stats(NULL);

		printf ("\n%sHard IRQ Events by CPU\n", tab);
		printf ("%s======================\n", tab);
		print_percpu_irq_stats(HARDIRQ);

		printf ("\n%sSoft IRQ events\n", tab);
		printf ("%s===============\n", tab);
		print_global_softirq_stats(NULL);

		printf ("\n%sSoft IRQ Events by CPU\n", tab);
		printf ("%s======================\n", tab);
		print_percpu_irq_stats(SOFTIRQ);
	}

	if (globals->powerp) {
		printf ("\n%sProcessor C-States and Power Events\n", tab);
		print_cstate_stats(NULL);
	}
	
	if (globals->HT_enabled) {
		printf ("\nHyper-threading CPU pair status\n");
		calc_global_HT_stats(globals, NULL);
		print_HT_report(NULL);
		if (HT_DBDI_histogram) {
			print_HT_DBDI_histogram();
		}	
	}

	print_global_runq_histogram();

        printf ("\nTop PIDs Waiting on RunQ (in secs):\n");
        print_runq_pids(NULL);

        printf ("\nTop PIDs using most CPU  (in secs):\n");
        print_runtime_pids(NULL);

        printf ("\nTop PIDs using most Sys CPU  (in secs):\n");
        print_systime_pids(NULL);

	if (STEAL_ON) {
		printf ("\nTop PIDs with most Steal Time (in secs):\n");
		print_stealtime_pids(NULL);
	}

	print_runq_itime_analysis();


	/* need to clear stats for multiple passes */
	if (is_alive) {
		clear_all_stats();
	}

	return 0;
} 

int
runq_print_func(void *v)
{
	struct timeval tod;
	if (debug) printf ("runq_print_func()\n");

	if ((print_flag) && (is_alive)) {
		gettimeofday(&tod, NULL);
		printf ("\n%s\n", ctime(&tod.tv_sec));
		runq_print_report(v);
		print_flag = 0;
	}
	return 0;
}

int
runq_ftrace_print_func(void *a, void *arg)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
	if (debug) printf ("runq_ftrace_print_func()\n");

	if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
                ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_POWER_START].execute = 1;
		ki_actions[TRACE_POWER_END].execute = 1;
		ki_actions[TRACE_POWER_FREQ].execute = 1;
		ki_actions[TRACE_CPU_FREQ].execute = 1;
		ki_actions[TRACE_CPU_IDLE].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
                start_time = trcinfop->cur_time;
        	bufmiss_func = runq_bufmiss_func;
        }

	if (strstr(buf, ts_end_marker)) {
		set_events_all(0);
                end_time = trcinfop->cur_time;
        	bufmiss_func = NULL;
        }

	if (debug) {
		PRINT_KD_REC(rec_ptr);
		PRINT_EVENT(rec_ptr->KD_ID);
		printf (" %s", buf);

		printf ("\n");
	}
}

int
runq_process_func(void *a, void *arg)
{
	return 0;
}

int 
runq_alarm_func(void *v)
{
	return 0;
}

int
runq_report_func(void *v)
{
	if (passes > 1) {
		printf ("\n***************************************************\n");
	}

        if (passes != 0) {
                runq_print_report(v);
        }

        return 0;
}

int
runq_bufmiss_func(void *a, void *v)
{
        trace_info_t *trcinfop = a;
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

        if (check_for_missed_buffer(trcinfop, rec_ptr, next_pid)) {
		cpu_missed_buffer(trcinfop);

		foreach_hash_entry((void **)&globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))pid_missed_buffer,      
                           NULL, 0, trcinfop);
	}
	return 0;
}
