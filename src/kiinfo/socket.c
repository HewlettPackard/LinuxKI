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
#include <linux/kdev_t.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <unistd.h>
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
#include "msgcat.h"

int socket_ftrace_print_func(void *, void *);

/*
 ** The initialisation function
 */
void
socket_init_func(void *v)
{
	if (debug) printf ("socket_init_func()\n");
        process_func = NULL;
        print_func = socket_print_func;
        report_func = socket_report_func;
	filter_func = info_filter_func;   /* no filter func for kisock, use generic */
        bufmiss_func = pid_bufmiss_func;

        /* go ahead and initialize the trace functions, but do not set the execute field */
        ki_actions[TRACE_SYS_EXIT].func = sys_exit_func;
        ki_actions[TRACE_SYS_ENTER].func = sys_enter_func;
        ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_func;
        ki_actions[TRACE_SCHED_WAKEUP_NEW].func = sched_wakeup_func;
        ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;
        if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (IS_LIKI || is_alive) {
		ki_actions[TRACE_SYS_EXIT].execute = 1;
		ki_actions[TRACE_SYS_ENTER].execute = 1;
		ki_actions[TRACE_WALLTIME].execute = 1;
		if (scdetail_flag) {
			ki_actions[TRACE_SCHED_SWITCH].execute = 1;
			ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
			ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
		}
	} else {
		set_events_all(0);
        	ki_actions[TRACE_PRINT].func = socket_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

        parse_kallsyms();
	if (timestamp) {
        	parse_lsof();
		parse_pself();
		parse_edus();
		parse_jstack();

		socket_csvfile = open_csv_file("kisock", 1);
	}

}

int
socket_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int socket_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("socket_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
		if (scdetail_flag) {
                	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		}
                start_time = KD_CUR_TIME;
                bufmiss_func = NULL;
        }
        if (strstr(buf, ts_end_marker)) {
                ki_actions[TRACE_SYS_EXIT].execute = 0;
                ki_actions[TRACE_SYS_ENTER].execute = 0;
                ki_actions[TRACE_SCHED_SWITCH].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
                ki_actions[TRACE_PRINT].execute = 0;
                end_time = KD_CUR_TIME;
                bufmiss_func =  NULL;
        }

        if (debug)  {
                PRINT_KD_REC(rec_ptr);
                PRINT_EVENT(rec_ptr->KD_ID);
                printf (" %s\n", buf);
        }
}

int
socket_print_info(sd_stats_t *statsp, struct sockaddr_in6 *lsock, struct sockaddr_in *rsock) 
{
	printf ("%8d %9.1f %11.1f %9.1f %11.1f  ",
		statsp->syscall_cnt,
		statsp->rd_cnt / globals->total_secs,
		(statsp->rd_bytes / 1024) / globals->total_secs,
		statsp->wr_cnt / globals->total_secs,
		(statsp->wr_bytes / 1024) / globals->total_secs);

	if (lsock) {
		printf ("L=");
		print_ip_port_v6(lsock, 0);
		if (rsock) printf (" ");
	}
	
	if (rsock) {
		printf ("R=");
		print_ip_port_v6(rsock, 0);
	}

	if (cluster_flag) {
		printf ("  ");
		SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_5_1);
	}

	printf ("\n");
}

int
socket_print_detail(sd_stats_t *statsp, void **syscallp, struct sockaddr_in6 *lsock, struct sockaddr_in6 *rsock, uint64 *scallflagp)
{

        if (scallflagp == NULL) return 0;
        if (*scallflagp == 0) return 0;

	printf("\n");
	if (lsock) {
		BOLD ("L=");
		print_ip_port_v6(lsock, 0);
		if (rsock) BOLD (" -> ");
	}
	
	if (rsock) {
		BOLD ("R=");
		print_ip_port_v6(rsock, 0);
	}

        CAPTION_GREY;
	BOLD ("   Syscalls: %d", statsp->syscall_cnt);
	if (cluster_flag) {
		printf ("  [");
		SERVER_URL_FIELD_SECTION(globals, _LNK_3_0);
		printf ("]");
	}
        _CAPTION;

        if (scallflagp && *scallflagp) {
                BOLD("System Call Name     Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\n");
                        foreach_hash_entry((void **)syscallp, SYSCALL_HASHSZ,
                                        (int (*)(void *, void *))print_syscall_info,
                                        (int (*)()) syscall_sort_by_time,
                                        0, scallflagp);
		TEXT("\n");
        }
	return 0;
}
int 
socket_print_ipip(void *arg1, void *arg2)
{
	ipip_info_t *ipipp = (ipip_info_t *)arg1;
	uint64 *scallflagp = (uint64 *)arg2;
	uint64 key1, key2;

        if (ipipp->stats.syscall_cnt == 0) return 0;

	key1 = ipipp->lle.key1;
	key2 = ipipp->lle.key2;
	if (scallflagp) {
		socket_print_detail(&ipipp->stats, ipipp->syscallp, ipipp->laddr, ipipp->raddr, scallflagp);
	} else {
		socket_print_info(&ipipp->stats, ipipp->laddr, ipipp->raddr);
	}
}

int socket_print_lip(void *arg1, void *arg2)
{
	ip_info_t *ipp = (ip_info_t *)arg1;
	uint64 *scallflagp = (uint64 *)arg2;
	uint64 key;

        if (ipp->stats.syscall_cnt == 0) return 0;

	key = ipp->lle.key;
	if (scallflagp) {
		socket_print_detail(&ipp->stats, ipp->syscallp, ipp->saddr, NULL, scallflagp);
	} else {
		socket_print_info(&ipp->stats, ipp->saddr, NULL);
	}
}

int socket_print_rip(void *arg1, void *arg2)
{
	ip_info_t *ipp = (ip_info_t *)arg1;
	uint64 *scallflagp = (uint64 *)arg2;
	uint64 key;

        if (ipp->stats.syscall_cnt == 0) return 0;

	key = ipp->lle.key;
	if (scallflagp) {
		socket_print_detail(&ipp->stats, ipp->syscallp, NULL, ipp->saddr, scallflagp);
	} else {
		socket_print_info(&ipp->stats, NULL, ipp->saddr);
	}
}

int socket_print_lsock(void *arg1, void *arg2)
{
	sock_info_t *sockp = (sock_info_t *)arg1;
	uint64 *scallflagp = (uint64 *)arg2;
	uint64 key;

        if (sockp->stats.syscall_cnt == 0)  {
			printf ("syscall_cnt == 0\n");
			return 0;
	}

	key = sockp->lle.key;
	if (scallflagp) {
		socket_print_detail(&sockp->stats, sockp->syscallp, sockp->saddr, NULL, scallflagp);
	} else {
		socket_print_info(&sockp->stats, sockp->saddr, NULL);
	}
}

int socket_print_rsock(void *arg1, void *arg2)
{
	sock_info_t *sockp = (sock_info_t *)arg1;
	uint64 *scallflagp = (uint64 *)arg2;
	uint64 key;

        if (sockp->stats.syscall_cnt == 0) return 0;

	key = sockp->lle.key;
	if (scallflagp) {
		socket_print_detail(&sockp->stats, sockp->syscallp, NULL, sockp->saddr, scallflagp);
	} else {
		socket_print_info(&sockp->stats, NULL, sockp->saddr);
	}
}

int socket_print_sdata(void *arg1, void *arg2)
{
        sdata_info_t *sdatap = (sdata_info_t *)arg1;
        uint64 *scallflagp = (uint64 *)arg2;
	uint64 key1, key2;

        if (sdatap->stats.syscall_cnt == 0) return 0;

	key1 = sdatap->lle.key1;
	key2 = sdatap->lle.key2;

	if (scallflagp) {
		socket_print_detail(&sdatap->stats, sdatap->syscallp, sdatap->laddr, sdatap->raddr, scallflagp);
	} else {
		socket_print_info(&sdatap->stats, sdatap->laddr, sdatap->raddr); 
	}

        return 0;
}

int 
socket_print_sdata_errs(void *arg1, void *arg2)
{
        sdata_info_t *sdatap = (sdata_info_t *)arg1;

        if (sdatap->stats.errors == 0) return 0;

        socket_print_sdata((void *)sdatap, arg2);

        return 0;
}

int
print_socket_csv(void *arg1, void *arg2)
{
	syscall_info_t *syscallp = (syscall_info_t *)arg1;
	syscall_stats_t *sysstatp = &syscallp->stats;
	struct arg_info *workarg = (struct arg_info *)arg2;
	pid_info_t *pidp = (pid_info_t *)workarg->arg0;
	pid_info_t *tgidp;
	fd_info_t *fdinfop = (fd_info_t *)workarg->arg1;
	fd_info_t *tfdinfop;
	sdata_info_t *sdatap;
	char *fnameptr, *cmdstr;
	uint64 key, fdtype, syscallno;

        if (sysstatp->count == 0) return 0;
	if ((fdinfop->lsock == NULL) || (fdinfop->rsock == NULL)) return 0;

	syscallno = SYSCALL_NO(syscallp->lle.key);

	if ((fdinfop->ftype == 0) && (pidp->tgid)) { 
		/* inherit filenames from primary thread */
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
		if (tfdinfop) fdinfop = tfdinfop;  /* set fdinfop to point to main tasks fdinfop */
	}

	csv_printf (socket_csvfile,"%lld,%s,%s,%d,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d,PID %d@%d.%d.%d.%d.%d,%d.%d.%d.%d.%d,%s,%d,%d,%3.2f,%7.6f,%7.6f,%7.6f,%d",
		pidp->PID,
		pidp->cmd,
		pidp->thread_cmd,
		fdinfop->FD,
		IP1(SIN_ADDR(fdinfop->lsock)),
		IP2(SIN_ADDR(fdinfop->lsock)),
		IP3(SIN_ADDR(fdinfop->lsock)),
		IP4(SIN_ADDR(fdinfop->lsock)),
		SIN_PORT(fdinfop->lsock),		
		IP1(SIN_ADDR(fdinfop->rsock)),
		IP2(SIN_ADDR(fdinfop->rsock)),
		IP3(SIN_ADDR(fdinfop->rsock)),
		IP4(SIN_ADDR(fdinfop->rsock)),
		SIN_PORT(fdinfop->rsock),		
		pidp->PID,IP1(SIN_ADDR(fdinfop->lsock)),
                IP2(SIN_ADDR(fdinfop->lsock)),
                IP3(SIN_ADDR(fdinfop->lsock)),
                IP4(SIN_ADDR(fdinfop->lsock)),
                SIN_PORT(fdinfop->lsock),
                IP1(SIN_ADDR(fdinfop->rsock)),
                IP2(SIN_ADDR(fdinfop->rsock)),
                IP3(SIN_ADDR(fdinfop->rsock)),
                IP4(SIN_ADDR(fdinfop->rsock)),
                SIN_PORT(fdinfop->rsock),
		syscall_arg_list[pidp->syscall_index[syscallno]].name,
		syscallno,
		sysstatp->count,
		sysstatp->count / secs,
		SECS(sysstatp->total_time),
		SECS(sysstatp->total_time / sysstatp->count),
		SECS(sysstatp->max_time),
		sysstatp->errors);

        if (sysstatp->bytes)  {
                csv_printf (socket_csvfile, ",%d,%2.1f",
                        (sysstatp->bytes) / sysstatp->count,
                        (sysstatp->bytes) / (secs * 1024.0));
        } else {
                csv_printf (socket_csvfile, ",0,0.0");
        }
	csv_printf (socket_csvfile, "\n");

	return 0;
}

int
socket_fd_csv(void *arg1, void *arg2)
{
        fd_info_t *fdinfop = (fd_info_t *)arg1;
        pid_info_t *pidp = (pid_info_t *)arg2;
        struct arg_info  workarg;

        workarg.arg0 = (uint64)pidp;
        workarg.arg1 = (uint64)fdinfop;

        foreach_hash_entry((void **)fdinfop->syscallp, SYSCALL_HASHSZ,
                                (int (*)(void *, void *))print_socket_csv,
                                NULL, 0,  &workarg);

}

int
print_socket_summary_csv(void *arg1, void *arg2)
{
        fd_info_t *fdinfop = (fd_info_t *)arg1, *tfdinfop, *ofdinfop;
        pid_info_t *pidp = (pid_info_t *)arg2, *tgidp;
	fd_stats_t *statsp;

	/* save this for later in case the fdinfop changes */
	statsp = &fdinfop->stats;
	
	if ((fdinfop->ftype == 0) && (pidp->tgid)) { 
		/* inherit filenames from primary thread */
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
		if (tfdinfop) fdinfop = tfdinfop;  /* set fdinfop to point to main tasks fdinfop */
	}

	if ((fdinfop->lsock == NULL) || (fdinfop->rsock == NULL)) return 0;

	if ((statsp->rd_bytes + statsp->wr_bytes) == 0 )
		return 0;

	csv_printf (socket_csvfile,"%lld,%s,%s,%d,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d,PID %d@%d.%d.%d.%d.%d,%d.%d.%d.%d.%d,%1.0f,%1.0f,%1.0f,%1.0f\n",
		pidp->PID,
		pidp->cmd,
		pidp->thread_cmd,
		fdinfop->FD,
		IP1(SIN_ADDR(fdinfop->lsock)),
		IP2(SIN_ADDR(fdinfop->lsock)),
		IP3(SIN_ADDR(fdinfop->lsock)),
		IP4(SIN_ADDR(fdinfop->lsock)),
		SIN_PORT(fdinfop->lsock),		
		IP1(SIN_ADDR(fdinfop->rsock)),
		IP2(SIN_ADDR(fdinfop->rsock)),
		IP3(SIN_ADDR(fdinfop->rsock)),
		IP4(SIN_ADDR(fdinfop->rsock)),
		SIN_PORT(fdinfop->rsock),
		pidp->PID,IP1(SIN_ADDR(fdinfop->lsock)),
                IP2(SIN_ADDR(fdinfop->lsock)),
                IP3(SIN_ADDR(fdinfop->lsock)),
                IP4(SIN_ADDR(fdinfop->lsock)),
                SIN_PORT(fdinfop->lsock),
                IP1(SIN_ADDR(fdinfop->rsock)),
                IP2(SIN_ADDR(fdinfop->rsock)),
                IP3(SIN_ADDR(fdinfop->rsock)),
                IP4(SIN_ADDR(fdinfop->rsock)),
                SIN_PORT(fdinfop->rsock),
		statsp->rd_cnt/secs,
		(statsp->rd_bytes/1024)/secs,
		statsp->wr_cnt/secs,
		(statsp->wr_bytes/1024)/secs);
}


int
socket_pid_csv(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
        foreach_hash_entry((void **)pidp->fdhash, FD_HSIZE,
                                (int (*)(void *, void *))print_socket_summary_csv,
                                NULL, 0, pidp);
}

void
socket_print_csv()
{
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                                        (int (*)(void *, void *))socket_pid_csv,
                                        NULL, 0, NULL);
}

int
socket_print_report(void *v)
{
	uint64 scallflag=1;
	tab=tab0;

	printf ("\n%s******** NETWORK SOCKET ACTIVITY REPORT ********\n", tab);

        printf ("\nTop IP->IP dataflows sorted by System Call Count\n");
	printf ("==================================================\n");
	printf ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection\n");
        foreach_hash_entry2((void **)globals->ipip_hash, IPIP_HASHSZ, socket_print_ipip,
                           (int (*)())ipip_sort_by_syscalls,
                           nfile, NULL);

        printf ("\nLocal IP Statistics\n");
	printf ("==================================================\n");
        foreach_hash_entry((void **)globals->lip_hash, IP_HASHSZ, socket_print_lip,
                           (int (*)())ip_sort_by_syscalls,
                           nfile, &scallflag);

        printf ("\nLocal IP:Port Statistics\n");
	printf ("==================================================\n");
        foreach_hash_entry((void **)globals->lsock_hash, SOCK_HASHSZ, socket_print_lsock,
                           (int (*)())sock_sort_by_syscalls,
                           nfile, &scallflag);

        printf ("\nRemote IP Statistics\n");
	printf ("==================================================\n");
        foreach_hash_entry((void **)globals->rip_hash, IP_HASHSZ, socket_print_rip,
                           (int (*)())ip_sort_by_syscalls,
                           nfile, &scallflag);

        printf ("\nRemote IP:Port Statistics\n");
	printf ("==================================================\n");
        foreach_hash_entry((void **)globals->rsock_hash, SOCK_HASHSZ, socket_print_rsock,
                           (int (*)())sock_sort_by_syscalls,
                           nfile, &scallflag);


        printf ("\nTop Sockets sorted by System Call Count\n", tab);
	printf ("Syscalls      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection\n");
	printf ("==================================================\n");
        foreach_hash_entry2((void **)globals->sdata_hash, SDATA_HASHSZ, socket_print_sdata,
                           (int (*)())sdata_sort_by_syscalls,
                           nfile, NULL);

        printf ("\nTop Sockets sorted by System Call Count (Detailed)\n", tab);
	printf ("==================================================\n");
        foreach_hash_entry2((void **)globals->sdata_hash, SDATA_HASHSZ, socket_print_sdata,
                           (int (*)())sdata_sort_by_syscalls,
                           nfile, &scallflag);
/*
        printf ("\n%s---  Top Sockets sorted by Errors  ---\n", tab);
        printf("%sSyscalls   ElpTime  Lseeks   Reads  Writes    Errs  Connection\n", tab);
        foreach_hash_entry((void **)globals->sdata_hash, SDATA_HASHSZ, socket_print_sdata_errs,
                           (int (*)())sdata_sort_by_errs,
                           nfile, NULL);

        printf ("\n%s---  Top Sockets sorted by Elapsed Time  ---\n", tab);
        printf("%sSyscalls   ElpTime  Lseeks   Reads  Writes    Errs  Connection\n", tab);
        foreach_hash_entry((void **)globals->sdata_hash, FDATA_HASHSZ, socket_print_sdata,
                            (int (*)())sdata_sort_by_elptime,
                            nfile, NULL);
*/

	printf ("\n");

	if (socket_csvfile) {
		csv_printf(socket_csvfile, "PID,Command,ThreadCmd,FD,Local_IP,Local_Port,Remote_IP,Remote_Port,Local_conn,Remote_conn,NetRx,NetRxKB,NetTx,NetTxKB\n");
		socket_print_csv();
	}

	if (is_alive) clear_all_stats();
}

int
socket_print_func(void *v)
{
        struct timeval tod;

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                socket_print_report(v);
                print_flag=0;
        }
        return 0;
}

int
socket_report_func(void *v)
{

        if (debug) printf ("Entering socket_report_func %d\n", is_alive);
        if (passes != 0) {
                socket_print_report(v);
        }

        return 0;
}
