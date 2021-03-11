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
#include "sort.h"
#include "html.h"
#include "clmsgcat.h"
#include "msgcat.h"
#include "hash.h"
#include "oracle.h"

typedef struct kp_trc_type_args {
        uint64          warnflag;
        int             total_recs;
} kp_trc_type_args_t;

warn_t *cl_warnings = NULL;
int	next_warning = 0;

int
cl_perserver_csv (void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	power_info_t *powerp;
	hc_info_t *hcinfop;
	runq_info_t *rqinfop;
	uint64 *gtime;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	uint64 busy_time = 0;
	uint64 cstate_total_time = 0;
	int i;
	struct iostats *iostatsp;
	if (debug) printf ("cl_perserver_csv\n");

	csv_printf (cluster_csvfile,"%s,%s,%d,%s,%d,%dM,%3.2f",
		serverp->hostname, 
		serverp->os_vers,
		serverp->nlcpu,
		serverp->HT_enabled ? "Y" : "N",
	        serverp->nldom > 0 ? serverp->nldom : 1,
		serverp->memkb / 1024,
		serverp->total_secs,
		serverp->subdir);

	gschedp = GET_ADD_SCHEDP(&serverp->schedp);
	gstatp = &gschedp->sched_stats;
	gtime = &gstatp->time[0];

	for (i = SOFTIRQ_USER_TIME; i <= HARDIRQ_IDLE_TIME; i++) irq_time += gtime[i];
        total_time = gtime[IDLE_TIME] + gtime[SYS_TIME] + gtime[USER_TIME] + irq_time;
	busy_time = gtime[SYS_TIME] + gtime[USER_TIME] + gtime[HARDIRQ_SYS_TIME] + gtime[HARDIRQ_USER_TIME],
			+ gtime[SOFTIRQ_SYS_TIME] + gtime[SOFTIRQ_USER_TIME];

	csv_printf (cluster_csvfile, ",%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%", 
		(busy_time * 100.0) / total_time,
		(gtime[SYS_TIME] * 100.0) / total_time,
                (gtime[USER_TIME] * 100.0) / total_time,
                (gtime[IDLE_TIME] * 100.0) / total_time,
                (gtime[HARDIRQ_SYS_TIME] * 100.0) / total_time,
                (gtime[HARDIRQ_USER_TIME] * 100.0) / total_time,
                (gtime[HARDIRQ_IDLE_TIME] * 100.0) / total_time,
                (gtime[SOFTIRQ_SYS_TIME] * 100.0) / total_time,
                (gtime[SOFTIRQ_USER_TIME] * 100.0) / total_time,
                (gtime[SOFTIRQ_IDLE_TIME] * 100.0) / total_time);

	csv_printf (cluster_csvfile, ",%4.2f%%,%4.2f%%,%4.2f%%,%4.2f%%",
		serverp->ht_total_time ? (serverp->ht_double_idle * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_lcpu1_busy * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_lcpu2_busy * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_double_busy * 100.0) / serverp->ht_total_time : 0);

	if ((hcinfop = serverp->hcinfop) && hcinfop->total) {
		csv_printf(cluster_csvfile, ",%d,%3.2f%%,%3.2f%%,%3.2f%%,%3.2f%%", 
			hcinfop->total,
                        (hcinfop->cpustate[HC_USER]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_SYS]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_INTR]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_IDLE]*100.0)/hcinfop->total);
	} else {
		csv_printf(cluster_csvfile, ",%d,%3.2f%%,%3.2f%%,%3.2f%%,%3.2f%%", 0,0.0,0.0,0.0,0.0);
	}

	csv_printf(cluster_csvfile, ",%4.2f,%4.2f,%4.2f", 
		gstatp->cnt[SWITCH_CNT] /  serverp->total_secs,
		gstatp->cnt[SLEEP_CNT] / serverp->total_secs,
		gstatp->cnt[PREEMPT_CNT] / serverp->total_secs);

	if (rqinfop = gschedp->rqinfop) {
		csv_printf(cluster_csvfile,",%3.1f,%lld,%lld,%d,%d,%d,%d",
			(rqinfop->total_time * 1.0) / (rqinfop->cnt ? rqinfop->cnt : 1),
	                rqinfop->max_time,
	                rqinfop->total_time,
	                rqinfop->cnt,
	                rqinfop->migrations,
	                rqinfop->ldom_migrations_in,
	                rqinfop->ldom_migrations_out);
	} else {
		csv_printf(cluster_csvfile,",%3.1f,%lld,%lld,%d,%d,%d,%d", 0.0,0,0,0,0,0,0);
	}

	i = IOTOT;
	while (i >= 0) {
        	iostatsp = &serverp->iostats[i];
		csv_printf(cluster_csvfile, ",%2.0f,%2.0f,%d,%3.1f,%5.3f,%5.3f", 
			iostatsp->compl_cnt/serverp->total_secs,
			(iostatsp->sect_xfrd/2048)/serverp->total_secs,
			(iostatsp->sect_xfrd/2)/MAX(iostatsp->compl_cnt,1),
			(iostatsp->cum_async_inflight + iostatsp->cum_sync_inflight) / (MAX(iostatsp->issue_cnt,1) * 1.0),
			(iostatsp->cum_iowait/MAX(iostatsp->compl_cnt,1) / 1000000.0),
			(iostatsp->cum_ioserv/MAX(iostatsp->compl_cnt,1) / 1000000.0));	
		i--;
	}
        iostatsp = &globals->iostats[IOTOT];
	csv_printf(cluster_csvfile,",%9.0f,%9.0f",
		iostatsp->requeue_cnt/serverp->total_secs,
		iostatsp->barrier_cnt/serverp->total_secs);
		
	csv_printf(cluster_csvfile, ",%8d,%9.1f,%11.1f,%9.1f,%11.1f",
                serverp->netstats.syscall_cnt,
               	serverp->netstats.rd_cnt / serverp->total_secs,
                (serverp->netstats.rd_bytes / 1024) / serverp->total_secs,
                serverp->netstats.wr_cnt / serverp->total_secs,
                (serverp->netstats.wr_bytes / 1024) / serverp->total_secs);

	csv_printf(cluster_csvfile, ",%d,%d,%d,%d", 
		serverp->total_events,
		serverp->total_buffers,
		serverp->missed_events,
		serverp->missed_buffers);
	
	if (powerp = serverp->powerp) {
		for (i=1; i < NCSTATES; i++) {
			cstate_total_time += powerp->cstate_times[i];
		}

		csv_printf(cluster_csvfile, ",%d", powerp->power_start_cnt);
		for (i=1; i < NCSTATES; i++) {
                	csv_printf(cluster_csvfile, ",%3.2f%%", cstate_total_time ?  (powerp->cstate_times[i] * 100.0) / cstate_total_time : 0);
		}
		csv_printf(cluster_csvfile, ",%d,%d,%d", powerp->power_freq_cnt, powerp->freq_hi, powerp->freq_low);
	} else {
		csv_printf(cluster_csvfile, ",0");
		for (i=1; i < NCSTATES; i++) {
			csv_printf(cluster_csvfile, ",0.00%%");
		}
		csv_printf(cluster_csvfile, ",0,0,0");
	}

	csv_printf(cluster_csvfile, "\n");
}

void
cl_server_csv()
{
	int i;

	cluster_csvfile = open_csv_file("kiall", 1);
	csv_printf(cluster_csvfile,"hostname,OS,LCPUs,HT,nLDOM,MemMB,TotalSecs");
	csv_printf(cluster_csvfile,",busy%%,sys%%,user%%,idle%%,hardirq_sys%%,hardirq_user%%,hardirq_idle%%,softirq_sys%%,softirq_user%%,softirq_idle%%");
	csv_printf(cluster_csvfile,",dblidle,lcpu1busy,lcpu2busy,dblbusy");
	csv_printf(cluster_csvfile,",HC Cnt,USER%,SYS%,INTR%,IDLE%");
	csv_printf(cluster_csvfile,",switch/s,vol/s,forced/s");
	csv_printf(cluster_csvfile,",AvRunqTm,MaxRunqTm,TotRunqTm,Cnt,Migrs,LdomMigIn,LdomMigOut");
	csv_printf(cluster_csvfile,",IO/s,MB/s,AvIOsz,AvInFlt,QuTm,SvcTm,wIO/s,wMB/s,wAvIOsz,wAvInFlt,wQuTm,wSvcTm,rIO/s,rMB/s,rAvIOsz,rAvInFlt,rQuTm,rSvcTm,requeues/s,barriers/s");
	csv_printf(cluster_csvfile,",NetSyscalls,NetRd/s,NetRd/KB,NetWr/s,NetWr/KB");
	csv_printf(cluster_csvfile,",Events,Buffers,MissedEvents,MissedBufs");
	csv_printf(cluster_csvfile,",CstateEvts");
	for (i=1; i < NCSTATES; i++) {
		csv_printf(cluster_csvfile,",cstate%d", i);
	}
	csv_printf(cluster_csvfile,",FreqEvts,FreqHi,FreqLo");
	csv_printf(cluster_csvfile,"\n");
	foreach_server(cl_perserver_csv, NULL, 0, NULL);
	close_csv_file(cluster_csvfile);
}

int
clipip_print_csv(void *arg1, void *arg2)
{
	clipip_info_t *clipipp = (clipip_info_t *)arg1;
	ipip_info_t *ipipp = clipipp->ipipp;
	sd_stats_t *statsp = &ipipp->stats;
	clip_info_t *ripp;
	uint64 rip;
	server_info_t *rglobals;

	if (statsp->syscall_cnt == 0) return 0;	

	globals = clipipp->globals;
	rip = clipipp->lle.key2;
	ripp = (clip_info_t *)FIND_CLIPP((void **)cllip_hash, rip);

	if (ripp) {
		rglobals = ripp->globals;
		csv_printf(cluster_network_csvfile, "%s,%s,%1.0f,%1.0f,%1.0f,%1.0f\n", globals->hostname, rglobals->hostname, 
							    statsp->rd_cnt/secs, (statsp->rd_bytes/1024)/secs,
							    statsp->wr_cnt/secs, (statsp->wr_bytes/1024)/secs);
	} else {
		csv_printf(cluster_network_csvfile, "%s,%d.%d.%d.%d,%1.0f,%1.0f,%1.0f,%1.0f\n", globals->hostname,
								IP1(rip), IP2(rip), IP3(rip), IP4(rip),
								statsp->rd_cnt/secs, (statsp->rd_bytes/1024)/secs,
								statsp->wr_cnt/secs, (statsp->wr_bytes/1024)/secs);
	}
}

void
cl_network_csv()
{
	cluster_network_csvfile = open_csv_file("cluster_network", 0);
	csv_printf(cluster_network_csvfile,"Source,Dest,NetRx,NetRxKB,NetTx,NetTxKB\n");
	
        foreach_hash_entry((void **)clipip_hash, IPIP_HASHSZ, clipip_print_csv, NULL, 0, NULL);
}

int
cl_warning (warn_t *warning, int indx, char *sect)
{
        int msg_idx = warning[indx].idx;

        ANM(SPF(line, "%s%d", _LNK_WARN, indx));
        if (warning[indx].type == WARN) {
                RED_FONT;
                T(warnmsg[msg_idx].msg);
                T(" ");
                if (warnmsg[msg_idx].url) {
                        AERx(warnmsg[msg_idx].url, T("[INFO]"));
                }
                ARFx(SPF(line,"%s%d", _LNK_WARN, indx+1), _MSG_NEXT_NOTE);
                BLACK_FONT;
        } else {
                BOLD(warnmsg[msg_idx].msg);
                T(" ");
                if (sect) {
                        ARFx(sect, "[Sect]");
                }
                if (warnmsg[msg_idx].url) {
                        AERx(warnmsg[msg_idx].url, T("[INFO]"));
                }
                ARFx(SPF(line,"%s%d", _LNK_WARN, indx+1), _MSG_NEXT_NOTE);
        }

        return 0;
}

int
cl_perserver_info (void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	char scavuln;

	if (debug) printf ("cl_perserver_info\n");

	switch (serverp->scavuln) {
		case SCA_MITIGATED:  scavuln = 'Y'; break; 
		case SCA_VULNERABLE:  scavuln = 'N'; break; 
		default:  scavuln = '?'; 
	}

	if (serverp->scavuln == SCA_UNKNOWN) scavuln = '?';
	

	SERVER_URL_FIELD16(serverp);
	printf (" %-30s %5d %4s %5d   %8dM   %6c   %7.2f   %s",
		serverp->os_vers,
		serverp->nlcpu,
		serverp->HT_enabled ? "Y" : "N",
	        serverp->nldom > 0 ? serverp->nldom : 1,
		serverp->memkb / 1024,
		scavuln,
		serverp->total_secs,
		serverp->subdir);

	printf("\n");
}

void
cl_sys_summary()
{
	if (debug) printf ("cl_sys_summary\n");
	
	ITALIC_U("basic system info"); printf("\n");
	BOLD("Server           Linux Version                   CPUs   HT Nodes      Memory   SCAfix   TotTime  Subdir\n");
	foreach_server(cl_perserver_info, NULL, 0, NULL);
	CSV_FIELD("kiall", "[CSV]");
}

void cl_toc()
{	
	HR;
	BLUE_TABLE;
	TEXT("\n");
	ANM(_LNK_TOC);
	HEAD3(_MSG_TOC);
	_TABLE;

        UL; LI; RED_FONT; T(_MSG_LINK); T(" "); ARFx(SPF(line,"%s%d", _LNK_WARN, 0), _MSG_NEXT_NOTE); BLACK_FONT; _UL; NLt;
        T(_MSG_LINK_INFO); NLt;

	COLLAPSE_START("toc");
        UL;
          LI; ARF(_LNK_1_0, _MSG_1_0); NLt;
          UL;
            LI; ARF(_LNK_1_1, _MSG_1_1); NLt;
            LI; ARF(_LNK_1_2, _MSG_1_2); NLt;
	    UL;
              LI; ARF(_LNK_1_2_1, _MSG_1_2_1); NLt;
              LI; ARF(_LNK_1_2_2, _MSG_1_2_2); NLt;
              LI; ARF(_LNK_1_1_3, _MSG_1_2_3); NLt;
	    _UL;
	  _UL;
          UL;
            LI; ARF(_LNK_1_3, _MSG_1_3); NLt;
	    UL;
              LI; ARF(_LNK_1_3_1, _MSG_1_3_1); NLt;
              LI; ARF(_LNK_1_3_2, _MSG_1_3_2); NLt;
	    _UL;
	  _UL;
          UL;
            LI; ARF(_LNK_1_4, _MSG_1_4); NLt;
	    UL;
              LI; ARF(_LNK_1_4_1, _MSG_1_4_1); NLt;
              LI; ARF(_LNK_1_4_2, _MSG_1_4_2); NLt;
	    _UL;
	  _UL;
          UL;
            LI; ARF(_LNK_1_5, _MSG_1_5); NLt; _UL;
          LI; ARF(_LNK_2_0, _MSG_2_0); NLt;
          UL;
            LI; ARF(_LNK_2_1, _MSG_2_1); NLt;
	    UL;
              LI; ARF(_LNK_2_1_1, _MSG_2_1_1); NLt;
              LI; ARF(_LNK_2_1_2, _MSG_2_1_2); NLt;
	    _UL;
            LI; ARF(_LNK_2_2, _MSG_2_2); NLt;
	    UL;
              LI; ARF(_LNK_2_2_1, _MSG_2_2_1); NLt;
              LI; ARF(_LNK_2_2_2, _MSG_2_2_2); NLt;
	    _UL;
            LI; ARF(_LNK_2_3, _MSG_2_3); NLt;
	    UL;
              LI; ARF(_LNK_2_3_1, _MSG_2_3_1); NLt;
              LI; ARF(_LNK_2_3_2, _MSG_2_3_2); NLt;
	    _UL;
          _UL;
          LI; ARF(_LNK_3_0, _MSG_3_0); NLt;
          UL;
            LI; ARF(_LNK_3_1, _MSG_3_1); NLt;
            LI; ARF(_LNK_3_2, _MSG_3_2); NLt;
            LI; ARF(_LNK_3_3, _MSG_3_3); NLt;
          _UL;
          LI; ARF(_LNK_4_0, _MSG_4_0); NLt;
          UL;
            LI; ARF(_LNK_4_1, _MSG_4_1); NLt;
            LI; ARF(_LNK_4_2, _MSG_4_2); NLt;
            UL;
              LI; ARF(_LNK_4_2_1, _MSG_4_2_1); NLt;
            _UL;
            LI; ARF(_LNK_4_3, _MSG_4_3); NLt;
            UL;
              LI; ARF(_LNK_4_3_1, _MSG_4_3_1); NLt;
            _UL;
            LI; ARF(_LNK_4_4, _MSG_4_4); NLt;
            LI; ARF(_LNK_4_5, _MSG_4_5); NLt;
          _UL;
          LI; ARF(_LNK_5_0, _MSG_5_0); NLt;
          UL;
            LI; ARF(_LNK_5_1, _MSG_5_1); NLt;
            LI; ARF(_LNK_5_2, _MSG_5_2); NLt;
            LI; ARF(_LNK_5_3, _MSG_5_3); NLt;
            LI; ARF(_LNK_5_4, _MSG_5_4); NLt;
	  _UL;
          LI; ARF(_LNK_6_0, _MSG_6_0); NLt;
        _UL;
	COLLAPSE_END;
}

void 
cl_whats_it_doing()			/* Section 1.0 */
{
	HR; T("\n");
        BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_0);
        HEAD2(_MSG_1_0); T("\n");
        FONT_SIZE(-1);
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	return;
}

int 
cl_perserver_summary(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	runq_info_t *rqinfop;
	uint64 *gtime;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	uint64 busy_time = 0;
	struct iostats *iostatsp;
	struct sd_stats_t *netstatp;
	int i;

	if (debug) printf ("cl_perserver_summary\n");

        SERVER_URL_FIELD16_SECTION(serverp, _LNK_1_0);

	gschedp = GET_ADD_SCHEDP(&serverp->schedp);
	gstatp = &gschedp->sched_stats;
	gtime = &gstatp->time[0];

	for (i = SOFTIRQ_USER_TIME; i <= HARDIRQ_IDLE_TIME; i++) irq_time += gtime[i];
        total_time = gtime[IDLE_TIME] + gtime[SYS_TIME] + gtime[USER_TIME] + irq_time;
	busy_time = gtime[SYS_TIME] + gtime[USER_TIME] + gtime[HARDIRQ_SYS_TIME] + gtime[HARDIRQ_USER_TIME],
			+ gtime[SOFTIRQ_SYS_TIME] + gtime[SOFTIRQ_USER_TIME];

	printf (" %6.2f%% %6.2f%% %6.2f%%",
		(busy_time * 100.0) / total_time,
		((gtime[SYS_TIME] + gtime[HARDIRQ_SYS_TIME] + gtime[SOFTIRQ_SYS_TIME]) * 100.0) / total_time,
		((gtime[USER_TIME] + gtime[HARDIRQ_USER_TIME] + gtime[SOFTIRQ_USER_TIME]) *100.0) / total_time);

	if (rqinfop = gschedp->rqinfop) {
		printf (" %10.1f", (rqinfop->total_time * 1.0) / (rqinfop->cnt ? rqinfop->cnt : 1));
	} else {
		printf (" %10.1f", 0.0);
	}

        iostatsp = &serverp->iostats[IOTOT];
	printf(" %9.1f %9.1f",
		iostatsp->compl_cnt/serverp->total_secs,
		(iostatsp->sect_xfrd/2048)/serverp->total_secs);
		
	printf(" %9.1f %9.1f",
               	(serverp->netstats.rd_cnt + serverp->netstats.wr_cnt) / serverp->total_secs,
                ((serverp->netstats.rd_bytes + serverp->netstats.wr_bytes) / 1024) / serverp->total_secs);


	/* printf (" %9.3f %9.3f %9.3f %9.3f %9.3f", SECS(total_time), SECS(busy_time), SECS(gtime[USER_TIME]), SECS(gtime[SYS_TIME]), SECS(gtime[IDLE_TIME])); */

	printf("\n");
}

void 
cl_global_summary()				/* Section 1.1 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_1);
        HEAD3(_MSG_1_1); T("\n");
        FONT_SIZE(-1);
        ARFx(_LNK_1_1_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("Server             Busy%%    Sys%%   User%%  AvgRunQTm      IO/s      KB/s   NetRq/s   NetKB/s\n");
	foreach_server(cl_perserver_summary, server_sort_by_busy, top, NULL);
        if (nservers > top) {
                COLLAPSE_START("gcpusum1");
		foreach_server(cl_perserver_summary, server_sort_by_busy, -top, NULL);
                COLLAPSE_END;
        }
}

void 
cl_global_cpu()				/* Section 1.2 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_2);
        HEAD3(_MSG_1_2); T("\n");
        FONT_SIZE(-1);
        ARFx(_LNK_1_2_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
cl_global_cpu_by_runtime()				/* Section 1.2.1 */
{
	uint64 warnflag = 0;
	int warn_indx;

	ORANGE_TABLE;
	TEXT("\n");
	ANM(_LNK_1_2_1);
	HEAD3(_MSG_1_2_1);
	FONT_SIZE(-1);
	ARFx(_LNK_1_2, "[Prev Subsection]");
	ARFx(_LNK_1_2_2, "[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
	_TABLE;

	BOLD("Server              nCPU          sys%%        user%%        idle%%", tab);
	if (gbl_irq_time) BOLD("  hardirq_sys hardirq_user hardirq idle  softirq_sys softirq_user softirq_idle");
	if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	printf("\n");
	
	foreach_server(print_global_cpu_stats, server_sort_by_busy, top, &warnflag);
	if (nservers > top) {
		COLLAPSE_START("gcpu1");
		foreach_server(print_global_cpu_stats, server_sort_by_busy, -top, &warnflag);
		COLLAPSE_END;
	}

	if (warnflag & WARNF_CPU_BOTTLENECK) {
		warn_indx = add_warning((void **)&cl_warnings, &next_warning, WARN_CPU_BOTTLENECK, _LNK_1_1);
                cl_warning(cl_warnings, warn_indx, _LNK_1_1); T("\n");
	}
	if (warnflag & WARNF_STEALTIME) {
		warn_indx = add_warning((void **)&cl_warnings, &next_warning, WARN_STEALTIME, _LNK_1_1);
                cl_warning(cl_warnings, warn_indx, _LNK_1_1); T("\n");
	}
}

void
cl_global_cpu_by_systime()				/* Section 1.2.2 */
{
	uint64 warnflag = 0;
	int warn_indx;

	ORANGE_TABLE;
	TEXT("\n");
	ANM(_LNK_1_2_2);
	HEAD3(_MSG_1_2_2);
	FONT_SIZE(-1);
	ARFx(_LNK_1_2_1, "[Prev Subsection]");
	ARFx(_LNK_1_2_3, "[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
	_TABLE;

	BOLD("Server              nCPU          sys%%        user%%        idle%%", tab);
	if (gbl_irq_time) BOLD("  hardirq_sys hardirq_user hardirq idle  softirq_sys softirq_user softirq_idle");
	if (STEAL_ON) BOLD("   stealbusy%%   stealidle%%");
	if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	printf("\n");
	
	COLLAPSE_START("gcpu2");
	foreach_server(print_global_cpu_stats, server_sort_by_systime, 0, &warnflag);
	COLLAPSE_END;
}

int 
cl_print_power_events(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	int *cnt = (int *)arg2;
	power_info_t *powerp;
	uint64	cstate_total_time = 0;
	int	i;

	if ((powerp = serverp->powerp) == NULL) return 0;

	if (cnt) (*cnt)++;
	for (i = 0; i < NCSTATES; i++) {
		cstate_total_time += powerp->cstate_times[i];
	}

	SERVER_URL_FIELD16_SECTION(serverp, _LNK_1_1_3);
	printf (" %8d",
		powerp->power_start_cnt + powerp->power_end_cnt);
	for (i = 1; i < NCSTATES; i++) {
		printf (" %7.2f%%%", cstate_total_time ?  (powerp->cstate_times[i] * 100.0) / cstate_total_time : 0);
	}
	printf ("    %10d %10lld %10lld\n",
		powerp->power_freq_cnt,
		powerp->freq_hi,
		powerp->freq_low);
}	

void 
cl_power_report()				/* Section 1.2.3 */
{
	int	cnt = 0, i;

        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_2_3);
        HEAD3(_MSG_1_2_3); T("\n");
        FONT_SIZE(-1);
	ARFx(_LNK_1_2_2, "[Prev Subsection]");
        ARFx(_LNK_1_2_4,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("Server             Events");
	for (i=1; i < NCSTATES; i++) {
		BOLD ("  Cstate%d", i);
	}
	BOLD("  freq_changes    freq_hi   freq_low\n");
	foreach_server(cl_print_power_events, server_sort_by_power, top, &cnt);

	if (cnt == 0) {
		printf("-- No Power Events Captured --\n");
	}
}

int 
cl_print_HT_stats(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	int *cnt = (int *)arg2;

	if (serverp->HT_enabled == FALSE) return 0;

	if (cnt) (*cnt)++;
	SERVER_URL_FIELD16_SECTION (serverp, _LNK_1_1_4);
	printf(" %11.1f%% %11.1f%% %11.1f%% %11.1f%%\n",
		serverp->ht_total_time ? (serverp->ht_double_idle * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_lcpu1_busy * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_lcpu2_busy * 100.0) / serverp->ht_total_time : 0,
                serverp->ht_total_time ? (serverp->ht_double_busy * 100.0) / serverp->ht_total_time : 0);
}

void
cl_HT_usage()                           /* Section 1.2.4 */
{
	int	cnt = 0;

        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_2_4);
        HEAD3(_MSG_1_2_4);
        FONT_SIZE(-1);
        ARFx(_LNK_1_1_3,"[Prev Subsection]");
        ARFx(_LNK_1_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("Server            double idle   lcpu1 busy   lcpu2 busy  double busy\n");
	foreach_server(cl_print_HT_stats, server_sort_by_dbusy, top, &cnt);

	if (cnt == 0) {
		printf("-- HT is disabled for all servers\n");
	}
}


void 
cl_busy_pids()				/* Section 1.3 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_3);
        HEAD3(_MSG_1_3); T("\n");
        FONT_SIZE(-1);
        ARFx(_LNK_1_2,"[Next Subsection]");
        ARFx(_LNK_1_3_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

}

int 
cl_print_pid_runtime_summary(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;

	globals = clpidp->globals;
	print_pid_runtime_summary(clpidp->pidp, NULL);
}	

void 
cl_top_pids_runtime()			/* Section 1.3.1 */
{
	uint64	warnflag = 0;
	int warn_indx;

	ORANGE_TABLE;
	TEXT("\n");
	ANM(_LNK_1_3_1);
	HEAD3(_MSG_1_3_1);
	FONT_SIZE(-1);
	ARFx(_LNK_1_3,"[Prev Subsection]");
	ARFx(_LNK_1_3_2,"[Next Subsection]");
	ARFx(_LNK_1_0,"---[Prev Section]");
	ARFx(_LNK_2_0,"[Next Section]");
	ARFx(_LNK_TOC,"[Table of Contents]");
	_TABLE;
	TEXT("\n");

	BOLD ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_pid_runtime_summary, clpid_sort_by_runtime, top, &warnflag);
        return;
}	


void 
cl_top_pids_systime()			/* Section 1.3.2 */
{
	uint64	warnflag = 0;
	int warn_indx;

	ORANGE_TABLE;
	TEXT("\n");
	ANM(_LNK_1_3_2);
	HEAD3(_MSG_1_3_2);
	FONT_SIZE(-1);
	ARFx(_LNK_1_3_1,"[Prev Subsection]");
	ARFx(_LNK_1_3_3,"[Next Subsection]");
	ARFx(_LNK_1_0,"---[Prev Section]");
	ARFx(_LNK_2_0,"[Next Section]");
	ARFx(_LNK_TOC,"[Table of Contents]");
	_TABLE;
	TEXT("\n");

	BOLD ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	COLLAPSE_START("toppids2");
	foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_pid_runtime_summary, clpid_sort_by_systime, top, &warnflag);
	COLLAPSE_END;
        return;
}	

void
cl_hardclocks()				/* Section 1.4 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_4);
        HEAD3(_MSG_1_4);
        FONT_SIZE(-1);
        ARFx(_LNK_1_3,"[Prev Subsection]");
        ARFx(_LNK_1_4_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");
}

int
cl_print_hc_stats(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	int *cnt = (int *)arg2;
	hc_info_t *hcinfop = serverp->hcinfop;

	if (hcinfop == NULL) return 0;
	if (hcinfop->total == 0) return 0;

	if (cnt) (*cnt)++;
	SERVER_URL_FIELD16_SECTION (serverp, _LNK_1_4);
	SPACE;
	prof_print_summary(hcinfop);
	printf ("\n");
}

void
cl_hc_states()                          /* Section 1.4.1 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_4_1);
        HEAD3(_MSG_1_4_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_2_2,"[Prev Subsection]");
        ARFx(_LNK_1_4_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");

	BOLD ("Server             Count   USER%%    SYS%%   INTR%%   IDLE%%\n");
	lineno=0;
	foreach_server(cl_print_hc_stats, server_sort_by_hc, top, NULL);
}

int
cl_print_hc_sys_pids(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;
	hc_info_t *hcinfop;

	globals = clpidp->globals;
	if ((hcinfop = globals->hcinfop) == NULL) return 0;
	
	print_pid_symbols(clpidp->pidp, &hcinfop->total);
}

void
cl_hc_funcbypid()                          /* Section 1.4.2 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_4_2);
        HEAD3(_MSG_1_4_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4_1,"[Prev Subsection]");
        ARFx(_LNK_1_5,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");
	
	COLLAPSE_START("hcsyspids");
        foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_hc_sys_pids, clpid_sort_by_hc, top, NULL);
	COLLAPSE_END;
}

int
cl_print_wakeup_pids(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;

	globals = clpidp->globals;
	print_wakeup_pids(clpidp->pidp, NULL);
}

void
cl_th_detection()                       /* Section 1.5 */
{
        uint64 warnflag = 0ull;
        int warn_indx=0;

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_5);
        HEAD3(_MSG_1_5);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4,"[Prev Subsection]");
        if (globals->irqp || globals->softirqp) {
                ARFx(_LNK_1_6,"[Next Subsection]");
        }
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");

        BOLD("PID       Wakeups MaxWakeups    Count     TimeStamp  cmd abstime_flag: %d\n", abstime_flag);
        foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_wakeup_pids, clpid_sort_by_wakeups, top, NULL);
}

void
cl_whats_it_waiting_for()               /* Section 2.0 */
{

        HR;
        BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_0);
        HEAD2(_MSG_2_0);
        FONT_SIZE(-1);
        ARFx(_LNK_1_0,"[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void

cl_switch_reports()		/* Section 2.1 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_2_1);
        HEAD3(_MSG_2_1);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
cl_print_sleep_pids_summary(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;

	globals = clpidp->globals;
	print_pid_swtch_summary(clpidp->pidp, NULL);
}

void
cl_top_switch_pids()                       /* Section 2.1.1 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_1_1);
        HEAD3(_MSG_2_1_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_1,"[Prev Subsection]");
        ARFx(_LNK_2_1_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");

	BOLD("PID        VolSlp ForceSlp  MigrCnt    SlpTime     AvMsec  Command\n");
        foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_sleep_pids_summary, clpid_sort_by_sleep_cnt, top, NULL);
}

int
cl_print_sleep_pids(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;

	globals = clpidp->globals;
	kp_print_sleep_pids(clpidp->pidp, NULL);
}

void
cl_top_switch_pid_funcs()                       /* Section 2.1.2 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_1_2);
        HEAD3(_MSG_2_1_2);
        FONT_SIZE(-1);
        ARFx(_LNK_2_1_1,"[Prev Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        TEXT("\n");

	COLLAPSE_START("pidsleep");
        foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_sleep_pids, clpid_sort_by_sleep_cnt, top, NULL);
	COLLAPSE_END;
}

void
cl_wait_for_cpu()                       /* Section 2.2 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_2_2);
        HEAD3(_MSG_2_2);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1,"[Prev Subsection]");
        ARFx(_LNK_2_2_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
cl_print_runq_stats(void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	sched_info_t *schedp = serverp->schedp;
	runq_info_t *rqinfop;

	if (schedp == NULL) return 0;

	rqinfop = schedp->rqinfop;
	if ((rqinfop == NULL) || (rqinfop->cnt == 0)) return 0;

	SERVER_URL_FIELD16_SECTION (serverp, _LNK_2_2_1);
	SPACE;
        print_runq_stats(rqinfop, NULL);
	printf ("\n");
}

void
cl_runq_statistics()                    /* Section 2.2.1 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_2_1);
        HEAD3(_MSG_2_2_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_2,"[Prev Subsection]");
        ARFx(_LNK_2_2_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("server                 Avg       Max  Total_time  Total_cnt  Migrations  NODE_migr_in  NODE_migr_out\n");
	foreach_server(cl_print_runq_stats, server_sort_by_avrqtime, top, NULL);
}

void
cl_top_pids_runqtime()                         /* Section 2.2.2 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_2_2);
        HEAD3(_MSG_2_2_2);
        FONT_SIZE(-1);
        ARFx(_LNK_2_2_1,"[Prev Subsection]");
        ARFx(_LNK_2_3,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("PID           RunTime      SysTime     UserTime     RunqTime    SleepTime  Command\n");
	foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, cl_print_pid_runtime_summary, clpid_sort_by_runqtime, top, NULL);
}

void cl_futex()				/* Section 2.3 */
{
	GREEN_TABLE;
	TEXT("\n");
	ANM(_LNK_2_3);
	HEAD3(_MSG_2_3);

	FONT_SIZE(-1);
        ARFx(_LNK_2_2_2,"[Prev Subsection]");
        ARFx(_LNK_2_3_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
cl_print_futex_stats(void *arg1, void *arg2)
{
	clfutex_info_t *clfutexp = (clfutex_info_t *)arg1;

	globals = clfutexp->globals;
	futex_print_detail(clfutexp->futexp, NULL);
}

void
cl_futex_summary_by_cnt()                              /* Section 2.3.1 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_3_1);
        HEAD3(_MSG_2_3_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_3,"[Prev Subsection]");
        ARFx(_LNK_2_3_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        foreach_hash_entry((void **)clfutex_hash, CLFUTEX_HASHSZ, cl_print_futex_stats, clfutex_sort_by_cnt, top, NULL); 
}

void
cl_futex_summary_by_time()                              /* Section 2.3.2 */
{
        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_2_3_2);
        HEAD3(_MSG_2_3_2);
        FONT_SIZE(-1);
        ARFx(_LNK_2_3_1,"[Prev Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
	
	COLLAPSE_START("futextime");
        foreach_hash_entry((void **)clfutex_hash, CLFUTEX_HASHSZ, cl_print_futex_stats, clfutex_sort_by_time, top, NULL); 
	COLLAPSE_END;
}

void
cl_file_activity()                      /* Section 3.0 */
{
        HR;
        BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_3_0);
        HEAD2(_MSG_3_0);
        FONT_SIZE(-1);
        ARFx(_LNK_2_0,"[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int 
cl_file_print_fdata(void *arg1, void *arg2)
{
	clfdata_info_t *clfdatap = (clfdata_info_t *)arg1;

	globals = clfdatap->globals;
	file_print_fdata(clfdatap->fdatap, NULL);

}	

void
cl_file_ops()                           /* Section 3.1 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_3_1);
        HEAD3(_MSG_3_1);

        FONT_SIZE(-1);
        ARFx(_LNK_3_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;


        lineno = 1;
        tab=tab0;

        BOLD("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)clfdata_hash, CLFDATA_HASHSZ, cl_file_print_fdata, clfdata_sort_by_syscalls, top, NULL); 
}

void
cl_file_time()                           /* Section 3.2 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_3_2);
        HEAD3(_MSG_3_2);

        FONT_SIZE(-1);
        ARFx(_LNK_3_1,"[Prev Subsection]");
        ARFx(_LNK_3_3,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;


        lineno = 1;
        tab=tab0;

        BOLD("%sSyscalls   ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)clfdata_hash, CLFDATA_HASHSZ, cl_file_print_fdata, clfdata_sort_by_elptime, top, NULL); 
}

void
cl_file_errs()                           /* Section 3.3 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_3_3);
        HEAD3(_MSG_3_3);

        FONT_SIZE(-1);
        ARFx(_LNK_3_2,"[Prev Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;


        lineno = 1;
        tab=tab0;

        BOLD("%sSyscalls   ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)clfdata_hash, CLFDATA_HASHSZ, cl_file_print_fdata, clfdata_sort_by_errs, top, NULL);
}

void
cl_device_report()                      /* Section 4.0 */
{
        HR;
        BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_4_0);
        HEAD2(_MSG_4_0);
        FONT_SIZE(-1);
        ARFx(_LNK_3_0,"[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}


int
cl_print_global_disk_stats (void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	struct iostats *iostatsp = &serverp->iostats[IOTOT];
	int i;

	SERVER_URL_FIELD16_SECTION(serverp, _LNK_4_0);
	SPACE;
	print_iostats_totals(serverp, &serverp->iostats[0], arg2);
	if (iostatsp->barrier_cnt) {
		printf (" barriers: %d", iostatsp->barrier_cnt);
	}
	if (iostatsp->requeue_cnt) {
		printf (" requeues: %d", iostatsp->requeue_cnt);
	}
	printf ("\n");
}
	

void
cl_device_globals()                     /* Section 4.1 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_4_1);
        HEAD3(_MSG_4_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2,"[Next Subsection]");
        ARFx(_LNK_3_0,"---[Prev Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("                 --------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------\n");
	BOLD("Server              IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv\n");
	foreach_server(cl_print_global_disk_stats, server_sort_by_iops, top, NULL);
}

void
cl_perdev_reports()                     /* Section 4.2.0 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_4_2);
        HEAD3(_MSG_4_2);

        FONT_SIZE(-1);
        ARFx(_LNK_4_1,"[Prev Subsection]");
        ARFx(_LNK_4_2_1,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
cl_print_dev_iostats(void *arg1, void *arg2)
{
	cldev_info_t *cldevp = (cldev_info_t *)arg1;
	dev_info_t *devinfop = cldevp->devinfop;

	if (devinfop->iostats[IOTOT].compl_cnt == 0) return 0;

	globals = cldevp->globals;
	print_iostats_totals(globals, &devinfop->iostats[0], arg2);
	SPACE;
	PRINT_DEVNAME(devinfop);
	SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_4_2_1);
	printf ("\n");

}

void
cl_permdev_reports()                     /* Section 4.3.0 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_4_3);
        HEAD3(_MSG_4_3);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_1,"[Prev Subsection]");
        ARFx(_LNK_4_3_1,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
cl_active_mdevs()                       /* Section 4.3.1 */
{
        uint64 warnflag = 0ull;
        int warn_indx;

        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_4_3_1);
        HEAD3(_MSG_4_3_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_3,"[Prev Subsection]");
        ARFx(_LNK_4_4,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	lineno=1;
	BOLD("--------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------\n");
	BOLD("   IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv  Device\n");
	foreach_hash_entry((void **)clmdev_hash, CLDEV_HSIZE, cl_print_dev_iostats, cldev_sort_by_iops, top, &warnflag);
}
 

void
cl_active_disks()                       /* Section 4.2.1 */
{
        uint64 warnflag = 0ull;
        int warn_indx;

        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_4_2_1);
        HEAD3(_MSG_4_2_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2,"[Prev Subsection]");
        ARFx(_LNK_4_2_2,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("--------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------\n");
	BOLD("   IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv  Device\n");
	foreach_hash_entry((void **)cldev_hash, CLDEV_HSIZE, cl_print_dev_iostats, cldev_sort_by_iops, top, &warnflag);

        if (warnflag & WARNF_AVSERV) {
                warn_indx = add_warning((void **)&cl_warnings, &next_warning, WARN_HIGH_AVSERV, _LNK_4_2_1);
                cl_warning(cl_warnings, warn_indx, _LNK_4_2_1); T("\n");
        }
}

int 
clpid_print_miostats(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;
	pid_info_t *pidp = clpidp->pidp;

	if (pidp->miostats[IOTOT].compl_cnt == 0) return 0;
	
	globals = clpidp->globals;
	PID_URL_FIELD8(pidp->PID);	
	SPACE;
	print_iostats_totals(globals, &pidp->miostats[0], NULL);
	printf (" %s", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf ("  (%s)", pidp->thread_cmd);	
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	DSPACE;
	SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_4_2_1);
	printf ("\n");
}

void
cl_perpid_mdev_totals()                  /* Section 4.4.0 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_4_4);
        HEAD3(_MSG_4_4); 
        FONT_SIZE(-1);
        ARFx(_LNK_4_3,"[Prev Subsection]");
        ARFx(_LNK_4_5,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("         --------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------\n");
	BOLD("PID         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv  Command\n");
	foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, clpid_print_miostats, clpid_sort_by_miops, top, NULL);
}
 
int 
clpid_print_iostats(void *arg1, void *arg2)
{
	clpid_info_t *clpidp = (clpid_info_t *)arg1;
	pid_info_t *pidp = clpidp->pidp;

	if (pidp->iostats[IOTOT].compl_cnt == 0) return 0;
	
	globals = clpidp->globals;
	PID_URL_FIELD8(pidp->PID);	
	SPACE;
	print_iostats_totals(globals, &pidp->iostats[0], NULL);
	printf (" %s", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf ("  (%s)", pidp->thread_cmd);	
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	DSPACE;
	SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_4_2_1);
	printf ("\n");
}

void
cl_perpid_dev_totals()                  /* Section 4.4.0 */
{
        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_4_5);
        HEAD3(_MSG_4_5);

        FONT_SIZE(-1);
        ARFx(_LNK_4_4,"[Prev Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("         --------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------\n");
	BOLD("PID         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv  Command\n");
	foreach_hash_entry((void **)clpid_hash, CLPID_HASHSZ, clpid_print_iostats, clpid_sort_by_iops, top, NULL);
}
 
void
cl_network_report()                      /* Section 5.0 */
{
        HR;
        BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_5_0);
        HEAD2(_MSG_5_0);
        FONT_SIZE(-1);
        ARFx(_LNK_4_0,"[Prev Section]");
        ARFx(_LNK_6_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
cl_print_global_net_stats (void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	sd_stats_t *statsp = &serverp->netstats;

	if (debug) printf ("cl_print_global_net_stats\n");

        printf ("%8d %9.1f %11.1f %9.1f %11.1f  ",
                statsp->syscall_cnt,
                statsp->rd_cnt / serverp->total_secs,
                (statsp->rd_bytes / 1024) / serverp->total_secs,
                statsp->wr_cnt / serverp->total_secs,
                (statsp->wr_bytes / 1024) / serverp->total_secs);
 
	SERVER_URL_FIELD_SECTION(serverp, _LNK_5_1);
	printf("\n");
}

void
cl_network_globals()                     /* Section 5.1 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_5_1);
        HEAD3(_MSG_5_1);

        FONT_SIZE(-1);
        ARFx(_LNK_5_2,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_6_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Server\n");
	foreach_server(cl_print_global_net_stats, server_sort_by_netxfrd, 0, NULL);
}

int
clipip_print_stats(void *arg1, void *arg2)
{
	clipip_info_t *clipipp = (clipip_info_t *)arg1;
	ipip_info_t *ipipp = clipipp->ipipp;
	sd_stats_t *statsp = &ipipp->stats;

	if (statsp->syscall_cnt == 0) return 0;	

	globals = clipipp->globals;
	socket_print_ipip(ipipp, NULL);
}

void
cl_network_ipip()                     /* Section 5.2 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_5_2);
        HEAD3(_MSG_5_2);

        FONT_SIZE(-1);
        ARFx(_LNK_5_1,"[Prev Subsection]");
        ARFx(_LNK_5_3,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_6_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection\n");
        foreach_hash_entry((void **)clipip_hash, IPIP_HASHSZ, clipip_print_stats, clipip_sort_by_netxfrd, top, NULL);
}

int
clip_print_stats(void *arg1, void *arg2)
{
	clip_info_t *cllipp = (clip_info_t *)arg1;
	ip_info_t *ipp = cllipp->ipp;
	sd_stats_t *statsp = &ipp->stats;

	if (statsp->syscall_cnt == 0) return 0;	

	globals = cllipp->globals;
	socket_print_lip(ipp, NULL);
}

void
cl_network_local_ip()                     /* Section 5.3 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_5_3);
        HEAD3(_MSG_5_3);

        FONT_SIZE(-1);
        ARFx(_LNK_5_2,"[Prev Subsection]");
        ARFx(_LNK_5_4,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_6_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Local IP Addr\n");
        foreach_hash_entry((void **)cllip_hash, IP_HASHSZ, clip_print_stats, clip_sort_by_netxfrd, top, NULL);

}

int
clsdata_print_stats(void *arg1, void *arg2)
{
	clsdata_info_t *clsdatap = (clsdata_info_t *)arg1;
	sdata_info_t *sdatap = clsdatap->sdatap;
	sd_stats_t *statsp = &sdatap->stats;

	if (statsp->syscall_cnt == 0) return 0;	

	globals = clsdatap->globals;
	socket_print_sdata(sdatap, NULL);
}

void
cl_network_top_sockets()                     /* Section 5.4 */
{

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_5_4);
        HEAD3(_MSG_5_4);

        FONT_SIZE(-1);
        ARFx(_LNK_5_3,"[Prev Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_6_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection\n");
        foreach_hash_entry((void **)clsdata_hash, SDATA_HASHSZ, clsdata_print_stats, clsdata_sort_by_netxfrd, top, NULL);
}

void
cl_warnings_report()			/* Section 5.0 */
{
	int i, msg_idx;
	warn_t *warnp;

	HR;
	BLUE_TABLE;
	TEXT("\n");
	ANM(_LNK_6_0);
	ANM(SPF(line,"%s%d", _LNK_WARN, next_warning));
	HEAD2(_MSG_6_0);
	FONT_SIZE(-1);

        ARFx(_LNK_5_0,"[Prev Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (next_warning == 0) {
		TEXT("\n");
		BOLD("No Warnings Found\n");
		return;
	}

	RED_FONT;
	UL;
	for (i = 0; i < next_warning; i++) {
		warnp = cl_warnings;
	 	if (warnp[i].type == NOTE) continue;
		msg_idx = warnp[i].idx;

		if (HTML) {	
			if (warnp[i].lnk) {
				LI; ARFx(SPF(line, "%s", warnp[i].lnk), warnmsg[msg_idx].msg);	
			} else {
				LI; ARFx(SPF(line,"%s%d", _LNK_WARN, i), warnmsg[msg_idx].msg);
			}
		} else {
			printf ("%s\n", warnmsg[msg_idx].msg);
		}
	}
	_UL;
	BLACK_FONT;
}

