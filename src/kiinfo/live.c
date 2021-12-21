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
#include <linux/aio_abi.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kdev_t.h>
#include <err.h>
#include <fcntl.h>
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
#include "oracle.h"
#include "hash.h"
#include "sort.h"
#include "conv.h"
#include "json.h"
#include "futex.h"
#include <sys/utsname.h>
#include <ncurses.h>
#include <curses.h>
#include "live.h"

#include "winki.h"
#include "Pdb.h"
#include "Thread.h"
#include "Process.h"
#include "PerfInfo.h"
#include "DiskIo.h"
#include "NetIp.h"
#include "FileIo.h"
#include "winki_util.h"

extern struct utsname  utsname;

#define LINES_AVAIL ((LINES-1)-lineno) 
#define PRINT_IODETAIL_HDR(str)													\
        if (COLS > (152+strlen(str))) {												\
		mvprintw (lineno++, strlen(str)+2, "------------------- Total I/O -------------------- ------------------- Write I/O ------------------- -------------------- Read I/O -------------------");     \
		mvprintw (lineno, 0, "%s", str);										\
                mvprintw (lineno++, strlen(str)+2, "    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv");	\
        } else {														\
		mvprintw (lineno++, strlen(str)+2, "------------------- Total I/O --------------------");		\
		mvprintw (lineno, 0, "%s", str);										\
                mvprintw (lineno++, strlen(str)+2, "    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv");		\
        }

static int 	next_step = FALSE;
static int	input_pending = FALSE;
static pthread_t	termiotid;

static WINDOW   *mainwin;
static int	curwin = WINMAIN;
static int	prevwin = WINMAIN;
static int	curpid = 0;
static int	lastpid = 0;
static int	curldom = -1;
static int	lastldom = -1;
static int	curcpu = -1;
static int	lastcpu = -1;
static uint32	curdev = 0;
static uint32	lastdev = 0;
static uint64   curfaddr = 0;
static uint64	lastfaddr = 0;
static int	curtgid = -1;
static int	lasttgid = -1; 
static int	curhirq = -1;
static int	lasthirq = -1;
static int	cursirq = -1;
static int	lastsirq = -1;
static uint64	curhba = NO_HBA;
static uint64	lasthba = NO_HBA;
static uint64	curwwn = NO_WWN;
static uint64	lastwwn = NO_WWN;
static uint64	curdockid = NO_DOCKID;
static uint64	lastdockid = NO_DOCKID;

int print_ldom_window();
int print_cpu_window();
int print_ht_window();
int print_dsk_window();
int print_mpath_window();
int print_iotop_window();
int print_irq_window();
int print_file_window();
int print_net_window();
int print_wait_window();
int print_futex_window();
int print_hc_window();
int print_help_window();
int print_main_window();
int print_pid_window();
int print_piddsk_window();
int print_pidmpath_window();
int print_pidscall_window();
int print_pidwait_window();
int print_pidhc_window();
int print_pidfile_window();
int print_pidcoop_window();
int print_pidfutex_window();
int print_select_ldom_window();
int print_select_cpu_window();
int print_select_dsk_window();
int print_select_futex_window();
int print_scall_excl_window();
int print_hba_window();
int print_select_hba_window();
int print_select_irq_window();
int print_docker_window();
int print_select_docker_window();
int print_wwn_window();
int print_select_wwn_window();
int print_select_file_window();
void *live_termio_thread();

win_action_t win_actions[MAX_WIN] = {
	{ print_main_window, WINMAIN_FLAGS, WINMAIN_STATS, WINMAIN_TRACEMASK },
	{ print_pid_window, WINPID_FLAGS, WINPID_STATS, WINPID_TRACEMASK },
	{ print_help_window, WINMAIN_FLAGS, WINHELP_STATS, WINHELP_TRACEMASK },
	{ print_ldom_window, WINLDOM_FLAGS, WINLDOM_STATS, WINLDOM_TRACEMASK },
	{ print_cpu_window, WINCPU_FLAGS, WINCPU_STATS, WINCPU_TRACEMASK },
	{ print_dsk_window, WINDSK_FLAGS, WINDSK_STATS, WINDSK_TRACEMASK },
	{ print_mpath_window, WINMPATH_FLAGS, WINMPATH_STATS, WINMPATH_TRACEMASK },
	{ print_iotop_window, WINIOTOP_FLAGS, WINIOTOP_STATS, WINIOTOP_TRACEMASK },
	{ print_irq_window, WINIRQ_FLAGS, WINIRQ_STATS, WINIRQ_TRACEMASK },
	{ print_piddsk_window, WINPID_DSK_FLAGS, WINPID_DSK_STATS, WINPID_DSK_TRACEMASK },
	{ print_pidmpath_window, WINPID_DSK_FLAGS, WINPID_DSK_STATS, WINPID_DSK_TRACEMASK },
	{ print_pidscall_window, WINPID_SCALL_FLAGS, WINPID_SCALL_STATS, WINPID_SCALL_TRACEMASK },
	{ print_pidwait_window, WINPID_WAIT_FLAGS, WINPID_WAIT_STATS, WINPID_WAIT_TRACEMASK },
	{ print_pidhc_window, WINPID_HC_FLAGS, WINPID_HC_STATS, WINPID_HC_TRACEMASK },
	{ print_pidfile_window, WINPID_FILE_FLAGS, WINPID_FILE_STATS, WINPID_FILE_TRACEMASK },
	{ print_file_window, WINFILE_FLAGS, WINFILE_STATS, WINFILE_TRACEMASK },
	{ print_select_ldom_window, WINLDOM_SEL_FLAGS, WINLDOM_SEL_STATS, WINLDOM_SEL_TRACEMASK },
	{ print_select_cpu_window, WINCPU_SEL_FLAGS, WINCPU_SEL_STATS, WINCPU_SEL_TRACEMASK },
	{ print_wait_window, WINWAIT_FLAGS, WINWAIT_STATS, WINWAIT_TRACEMASK },
	{ print_net_window, WINNET_FLAGS, WINNET_STATS, WINNET_TRACEMASK },
	{ print_select_dsk_window, WINDSK_SEL_FLAGS, WINDSK_SEL_STATS, WINDSK_SEL_TRACEMASK },
	{ print_pidcoop_window, WINPID_COOP_FLAGS, WINPID_COOP_STATS, WINPID_COOP_TRACEMASK },
	{ print_futex_window, WINFUT_FLAGS, WINFUT_STATS, WINFUT_TRACEMASK },
	{ print_select_futex_window, WINFUT_SEL_FLAGS, WINFUT_SEL_STATS, WINFUT_SEL_TRACEMASK },
	{ print_pidfutex_window, WINPID_FUTEX_FLAGS, WINPID_FUTEX_STATS, WINPID_FUTEX_TRACEMASK },
	{ print_hc_window, WINHC_FLAGS, WINHC_STATS, WINHC_TRACEMASK },
	{ print_ht_window, WINHT_FLAGS, WINHT_STATS, WINHT_TRACEMASK },
	{ print_scall_excl_window, WINSCALL_EXCL_FLAGS, WINSCALL_EXCL_STATS, WINSCALL_EXCL_TRACEMASK },
	{ print_hba_window, WINHBA_FLAGS, WINHBA_STATS, WINHBA_TRACEMASK},
	{ print_select_hba_window, WINHBA_FLAGS, WINHBA_STATS, WINHBA_TRACEMASK},
	{ print_select_irq_window, WINIRQ_FLAGS, WINIRQ_STATS, WINIRQ_TRACEMASK },
	{ print_docker_window, WINMAIN_FLAGS, WINMAIN_STATS, WINMAIN_TRACEMASK },
	{ print_select_docker_window, WINMAIN_FLAGS, WINMAIN_STATS, WINMAIN_TRACEMASK },
	{ print_wwn_window, WINWWN_FLAGS, WINWWN_STATS, WINWWN_TRACEMASK},
	{ print_select_wwn_window, WINWWN_FLAGS, WINWWN_STATS, WINWWN_TRACEMASK},
	{ print_select_file_window, WINFILE_SEL_FLAGS, WINFILE_SEL_STATS, WINFILE_SEL_TRACEMASK },
};

static char * iolabels[3] = {
	"Read",
	"Write",
	"Total"
};

static inline int
cols_avail()
{
	int dummy;
	getyx(mainwin, dummy, col);
	return ((COLS-1)-col);
}

void
load_symbols()
{
	pid_info_t *pidp;

	if (curpid <= 0) return;

	pidp = GET_PIDP(&globals->pid_hash, curpid);
	load_perpid_objfile_and_shlibs(pidp);
	load_perpid_mapfile(pidp, NULL);
}

int 
live_ftrace_print_func(void *a, void *arg)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);

	if (strstr(buf, ts_begin_marker)) {
		set_events_all(1);
		start_time = KD_CUR_TIME;
	} else if (strstr(buf, ts_end_marker)) {
		set_events_all(0);
	}
}
		
void
print_top_line()
{	
	struct timeval tod;

	lineno=0; col=0;
	clear();

	if (is_alive) {
		gettimeofday(&tod, NULL);
		mvprintw (lineno,0, "%s", ctime(&tod.tv_sec));	
	} else if (kistep) {
		mvprintw (lineno,0, "%7.6f - %7.6f", (start_filter/1000000000.0), (end_filter/1000000000.0)) ;
	} else {
		mvprintw (lineno,0, "%s", timestamp);
	}
	mvprintw (lineno,30, "Sample Time: %3.6f secs", secs);
	save_and_clear_server_stats(0);
	mvprintw (lineno++,60, "Events: %d/%d", globals->missed_events, globals->total_events);
}


int
print_global_header()
{
	print_top_line();
	lineno++;

	mvprintw (lineno++,0, "Server           OS Version                            CPUs   HT Nodes    Memory");
	mvprintw (lineno++,0, "%-16s %-36s %5d %4s %5d %8dM", 
		globals->hostname,
		globals->os_vers,
		globals->nlcpu,
		globals->HT_enabled ? "Y" : "N",
		globals->nldom > 0 ? globals->nldom : 1,
		globals->memkb / 1024);
}

static inline void
live_winki_trace_funcs()
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
 ** this function can be called more than once if using kistep
 */ 
void
live_init_func(void *v)
{
	int err;
	char msr_flag_save = 0;

	process_func =  NULL;
        report_func = live_report_func;

        bufmiss_func = live_bufmiss_func;
        alarm_func = live_alarm_func;
	filter_func = live_filter_func;
	report_func_arg  = filter_func_arg;

	mainwin = initscr();
	cbreak();
	noecho();
	clear();

	if (IS_WINKI) {
		live_winki_trace_funcs();
	} else {

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
		ki_actions[TRACE_POWER_START].func = power_start_func;
       		ki_actions[TRACE_POWER_END].func = power_end_func;
       		ki_actions[TRACE_POWER_FREQ].func = power_freq_func;
       		ki_actions[TRACE_CPU_FREQ].func = cpu_freq_func;
       		ki_actions[TRACE_CPU_IDLE].func = cpu_idle_func;
		ki_actions[TRACE_SOFTIRQ_RAISE].func = kparse_generic_func;
       		ki_actions[TRACE_SCSI_DISPATCH_CMD_START].func = kparse_generic_func;
       		ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].func = kparse_generic_func;
       		ki_actions[TRACE_LISTEN_OVERFLOW].func = kparse_generic_func;
       		if (IS_LIKI_V4_PLUS) {
               		ki_actions[TRACE_WALLTIME].func = trace_startup_func;
       		} else if (IS_LIKI) {
               		ki_actions[TRACE_WALLTIME].func = trace_walltime_func;
		} else {
        		/* We will disgard the trace records until the Marker is found */
               		set_events_all(0);
               		ki_actions[TRACE_PRINT].func = live_ftrace_print_func;
               		ki_actions[TRACE_PRINT].execute = 1;
		}
	}

	/* set initial trace flags and functions */

	if (is_alive) {
		if (msr_flag) msr_flag_save=1;
		INIT_FLAG();
		if (msr_flag_save) SET(MSR_FLAG);
		SET(win_actions[WINMAIN].flags);
		SET_STAT(win_actions[WINMAIN].stats);
		SET_EXECUTE_BITS(win_actions[WINMAIN].tracemask);
	} else if (IS_LIKI) {
		SET(0x3ffull);
		if (futex_stats) {
			SET_STAT(0xffffffffffffffffull) ;
		} else {
			SET_STAT(0xffffffffffffffffull);
			CLEAR_STAT(FUTEX_STATS);
		}
		SET_EXECUTE_BITS(TT_BITMASK_ALL_TRACES);
	} else {
		SET(0x3ffull);
		if (futex_stats) {
			SET_STAT(0xffffffffffffffffull);
		} else {
			SET_STAT(0xffffffffffffffffull);
			CLEAR_STAT(FUTEX_STATS);
		}
		/* events already set above */
        }

	if (IS_WINKI) {
		parse_systeminfo();
		parse_cpulist();
		parse_corelist();
		parse_SQLThreadList();
	} else {
		parse_cpuinfo();
		parse_mem_info();
		parse_uname(0);
		parse_kallsyms();
		parse_devices();
		parse_docker_ps();
        	parse_ll_R();
	}

	if (is_alive) {
		parse_cpumaps();
		parse_edus();
		print_global_header();	
		lineno++;
		mvprintw (lineno++,0, "Collecting data, please wait for %d seconds", alarm_secs);
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	} 

	if ((err = pthread_create(&termiotid, NULL, live_termio_thread, (void *)NULL)) != 0) {
		fprintf(stderr, "failed to spawn terminal IO thread, err = %d", err);
		FATAL(err, "pthread_create failure", NULL, -1);
	}

	if (timestamp && !IS_WINKI) {
		parse_mpsched();
		parse_proc_cgroup();
		parse_pself();
		parse_edus();
		parse_jstack();
        	parse_lsof();
        	parse_maps();
        	parse_mpath();
		if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
	}
}

void
live_cleanup_func(void *v)
{
	clear();
	endwin();
}

void *
live_filter_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	common_t tt_rec_ptr;
	common_t *rec_ptr;
	filter_t *f = v;
	filter_item_t *fi;
	void *ret1;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);

        if (!ki_actions[rec_ptr->id].execute) {
                return NULL;
        }

        if (rec_ptr->id == TRACE_PRINT) return rec_ptr;
	CHECK_TIME_FILTER(rec_ptr->hrtime);

	if ((rec_ptr->id >= TRACE_SCHED_SWITCH) && (rec_ptr->id <= TRACE_SCHED_WAKEUP)) return rec_ptr;
	if ((rec_ptr->id >= TRACE_BLOCK_RQ_COMPLETE) && (rec_ptr ->id <= TRACE_BLOCK_RQ_ABORT)) return rec_ptr;

        ret1 = rec_ptr;

        if (fi = f->f_P_pid) {
                ret1 = NULL;
                while (fi) {
                        if (rec_ptr->pid == fi->fi_item) {
                                return rec_ptr;
                        }
                        fi = fi->fi_next;
                }
        }

	return ret1;
}

int
live_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	
        return 0;
}

/* alarm_func() should contain any
 *  * extra code to handle the alarm
 *   */

int live_alarm_func(void *v)
{
        print_flag = 1;
        return 0;
}

int
live_print_window()
{
	if (input_pending == FALSE) {
		/* if (curwin != prevwin) clear(); */
		clear();
		win_actions[curwin].func();
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
	}
 
	return 0;
}

int
refresh_screen()
{
	/* this option will refresh the screen with intermediate data */
	input_pending = FALSE;
	live_print_window();
	input_pending = TRUE;
	return 0;
}

int
live_report_func(void *v)
{
	docker_info_t *dockerp;

        if (passes != 0) {
		if (!is_alive) {
		        /* calculate per-device totals */
        		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
        		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
        		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);

			update_cpu_times(end_time);
        		calc_global_cpu_stats(globals, NULL);
        		calc_io_totals(&globals->iostats[0], NULL);
        		if (globals->HT_enabled) calc_global_HT_stats(globals, NULL);
			update_perpid_sched_stats();

			if (globals->docker_hash) {
				foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_docker_pid_totals, NULL, 0, NULL);
				dockerp = GET_DOCKERP(&globals->docker_hash, 0);
				dockerp->name = "system";
			} else {
				foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
			}
			if (globals->fobj_hash) foreach_hash_entry(globals->fobj_hash, FOBJ_HSIZE, calc_fobj_totals, NULL, 0, 0);
		}
		live_print_window();
		if (is_alive) { 
			clear_all_stats();
			load_symbols();
			parse_edus();
			parse_docker_ps();
		}
        }

	if (!is_alive) {
		while ((done == FALSE) && (next_step == FALSE)) {
			sleep(1);
		}
	}
	
	next_step = FALSE;
        return 0;
}

int
live_bufmiss_func(void *a, void *v)
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

int
print_stktrc_info_live(void *arg1, void *arg2)
{
	stktrc_info_t *stktrcp = (stktrc_info_t *)arg1;
	sched_info_t *schedp = (sched_info_t *)arg2;
	pid_info_t *pidp;
	vtxt_preg_t *pregp;
	float avg, wpct;
	int i, namelen;
	uint64 key, offset, symaddr;
	char *sym, *dsym;
	char symname[256];
	
	wpct = ((float)stktrcp->slptime *100.0)/(schedp->sched_stats.T_sleep_time);
	avg = MSECS(stktrcp->slptime)/stktrcp->cnt;
	mvprintw (lineno, 0, "%8d %6.2f %9.3f ", stktrcp->cnt, wpct, avg);
	col=26;
        for (i=0;i<stktrcp->stklen; i++) {
		if (LINES_AVAIL <= 0) break;
                key = stktrcp->stklle.key[i];
		
		if (IS_WINKI) {
                        pidp = stktrcp->pidp;
                        pregp = get_win_pregp(key, pidp);
                        if (pregp) {
                                sym = win_symlookup(pregp, key, &symaddr);
                        }

                        if (sym) {
                                sprintf (symname, "  %s", sym);
                        } else if (pregp) {
                                sprintf (symname, "  [%s]", pregp->filename);
                        } else {
                                sprintf (symname, "  0x%llx", key);
                        }
                } else if (key == STACK_CONTEXT_USER) {
                        sprintf (symname, "|");
                } else if ((globals->symtable) && (key < globals->nsyms-1)) {
                        if (globals->symtable[key].nameptr) {
                                sprintf (symname, "%s", globals->symtable[key].nameptr);
                        } else {
                                sprintf (symname, "%p", globals->symtable[key].addr);
                        }
                } else if (key == UNKNOWN_SYMIDX) {
                        sprintf (symname, "unknown");
                } else if (stktrcp->pidp) {
                        pidp = stktrcp->pidp;
                        if (pidp->PID != pidp->tgid) {
                                pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        }

                        if (pregp = find_vtext_preg(pidp->vtxt_pregp, key)) {
                                if (sym = symlookup(pregp, key, &offset)) {
                                	sprintf (symname, "%s", sym);
				} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
					sprintf (symname, "%s", sym);
                        	} else {
                                	sprintf (symname, "0x%llx", key);
				}
			} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
				sprintf (symname, "%s", sym);
                        } else {
                                sprintf (symname, "0x%llx", key);
                        }
                } else {
                        sprintf (symname, "0x%llx", key);
                }

		dsym = dmangle(symname);
		namelen = strlen(dsym)+2;
		if (col+namelen > COLS)  { 
			col=26;
			lineno++;
		}
		mvprintw (lineno, col, "  %s", dsym);
		col = col + namelen;	
        }
	lineno++;
	col=0;
        return 0;
}

int
print_hc_stktrc_live(void *arg1, void *arg2)
{
	stktrc_info_t *stktrcp = (stktrc_info_t *)arg1;
	hc_info_t *hcinfop = (hc_info_t *)arg2;
	pid_info_t *pidp;
	vtxt_preg_t *pregp;
	float wpct;
	int i, namelen;
	uint64 key, offset, symaddr;
	char *sym, *dsym;
	char symname[256];
	
	if (stktrcp->cnt == 0) return 0;

	wpct = ((float)stktrcp->cnt *100.0)/(hcinfop->total);
	mvprintw (lineno, 0, "%8d %6.2f%% ", stktrcp->cnt, wpct);

	col=15;
        for (i=0;i<stktrcp->stklen; i++) {
		if (LINES_AVAIL <= 0) break;
                key = stktrcp->stklle.key[i];

		if (IS_WINKI) {
                        pidp = stktrcp->pidp;
                        pregp = get_win_pregp(key, pidp);
                        if (pregp) {
                                sym = win_symlookup(pregp, key, &symaddr);
                        }

                        if (sym) {
                                sprintf (symname, "  %s", sym);
                        } else if (pregp) {
                                sprintf (symname, "  [%s]", pregp->filename);
                        } else {
                                sprintf (symname, "  0x%llx", key);
                        }
                } else if (key == STACK_CONTEXT_USER) {
                        sprintf (symname, "|");
                } else if ((globals->symtable) && (key < globals->nsyms-1)) {
                        if (globals->symtable[key].nameptr) {
                                sprintf (symname, "%s", globals->symtable[key].nameptr);
                        } else {
                                sprintf (symname, "%p", globals->symtable[key].addr);
                        }
                } else if (key == UNKNOWN_SYMIDX) {
                        sprintf (symname, "unknown");
                } else if (stktrcp->pidp) {
                        pidp = stktrcp->pidp;
                        if (pidp->PID != pidp->tgid) {
                                pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        }

                        if (pregp = find_vtext_preg(pidp->vtxt_pregp, key)) {
                                if (sym = symlookup(pregp, key, &offset)) {
                                	sprintf (symname, "%s", sym);
				} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
					sprintf (symname, "%s", sym);
                        	} else {
                                	sprintf (symname, "0x%llx", key);
                        	}
			} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
				sprintf (symname, "%s", sym);
                        } else {
                                sprintf (symname, "0x%llx", key);
                        }
                } else {
                        sprintf (symname, "0x%llx", key);
                }

		dsym = dmangle(symname);
		namelen = strlen(dsym)+2;
		if (col+namelen > COLS)  { 
			col=15;
			lineno++;
		}
		mvprintw (lineno, col, "  %s", dsym);
		col = col + namelen;	
        }
	lineno++;
	col=0;
        return 0;
}



int
print_slp_info_live (void *arg1, void *arg2)
{
	slp_info_t *slpinfop = arg1;
        uint64 idx, symaddr;
	char *sym = NULL, *symfile = NULL;
	vtxt_preg_t *pregp = NULL;

        if (slpinfop->count == 0) return 0;
	if (IS_WINKI) {
		/* We should be in kernel space here */
		if (pregp = get_win_pregp(slpinfop->lle.key, NULL)) {
			sym = win_symlookup(pregp, slpinfop->lle.key, &symaddr);
			symfile = pregp->filename;
		}
	} else {
		idx = slpinfop->lle.key;
		if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;
	}

        mvprintw(lineno++, col, "%8d %11.6f %9.3f %9.3f  %s",
                        slpinfop->count,
                        SECS(slpinfop->sleep_time),
                        MSECS(slpinfop->sleep_time / slpinfop->count),
                        MSECS(slpinfop->max_time),
			IS_WINKI ? (sym ? sym : (symfile ? symfile : "unknown")) : (idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr));
        return 0;
}

int
print_slpinfo_scall_live (void *arg1, void *arg2)
{
	slp_info_t *slpinfop = arg1;
        uint64 idx, symaddr;
	char *sym = NULL, *symfile = NULL;
	vtxt_preg_t *pregp = NULL;


        if (slpinfop->count == 0) return 0;

	if (IS_WINKI) {
		/* We should be in kernel space here */
		if (pregp = get_win_pregp(slpinfop->lle.key, NULL)) {
			sym = win_symlookup(pregp, slpinfop->lle.key, &symaddr);
			symfile = pregp->filename;
		}
	} else {
		idx = slpinfop->lle.key;
		if (idx > globals->nsyms-1) idx = UNKNOWN_SYMIDX;
	}

        mvprintw(lineno++, 0, "      Sleep Func             %9d          %11.6f %10.6f  %s",
                        slpinfop->count,
                        SECS(slpinfop->sleep_time),
                        SECS(slpinfop->sleep_time / slpinfop->count),
			IS_WINKI ? (sym ? sym : (symfile ? symfile : "unknown")) : (idx == UNKNOWN_SYMIDX ? "unknown" : globals->symtable[idx].nameptr));
        return 0;
}

int
print_iostats_summary_live (void *arg1, void *arg2)
{
	server_info_t *serverp = (server_info_t *)arg1;
	struct iostats *iostats = (iostats_t *)arg2;
	struct iostats *iostatsp;
	int i = IORD;
	uint64 aviosz;
	double avserv, avinflt;
	char *label;

	while (i <= IOTOT) {
		iostatsp = &iostats[i];
        	avserv = iostatsp->cum_ioserv/MAX(iostatsp->compl_cnt,1) / 1000000.0;
		avinflt = (iostatsp->cum_async_inflight + iostatsp->cum_sync_inflight) / (MAX(iostatsp->issue_cnt,1) * 1.0);

		switch(i) {
                	case IO_READ: label="Read"; break;
                	case IO_WRITE: label="Write"; break;
                	case IO_TOTAL: label="Total"; break;
		}

		mvprintw (lineno++, 0, "%6s  %7.0f %7.0f %7d %7.2f %8.2f %8.2f ",
			label,
                        iostatsp->compl_cnt / secs,
                        (iostatsp->sect_xfrd/2048) / secs,
                        (iostatsp->sect_xfrd/2)/MAX(iostatsp->compl_cnt,1),
			avinflt,
                        (iostatsp->cum_iowait/MAX(iostatsp->compl_cnt,1) / 1000000.0),
			avserv);

                i++;
        }
}


int
live_print_fobj_logio(void *arg1, void *arg2)
{
	fileobj_t *fobjinfop = (fileobj_t *)arg1;
	fileobj_t *gfobjinfop;
	fstats_t *fstatsp;
	int rw;

	col=0;
	mvprintw (lineno, col, "0x%016llx", fobjinfop->FOBJ);
	col = 20;
	for (rw = IOTOT; rw >= IORD; rw--) {
		fstatsp = &fobjinfop->liostats[rw];
		mvprintw (lineno, col, "%7.0f %7.0f %7d",
			fstatsp->cnt / globals->total_secs*1.0,
			(fstatsp->bytes/1024)/globals->total_secs*1.0,
			fstatsp->bytes / MAX(fstatsp->cnt, 1));
		col+=25;
		if ((COLS - col) < 75) break;
	}

	/* get the fobj filename from the global fobj */
	if (fobjinfop->filename == NULL) {
		gfobjinfop = FIND_FOBJP(globals->fobj_hash, fobjinfop->FOBJ);
		if (gfobjinfop && gfobjinfop->filename) {
			mvprintw (lineno++, col, "%s", gfobjinfop->filename);
		}
        } else {
                mvprintw (lineno++, col, "%s", fobjinfop->filename);
        }
}

/* this is used to print an I/O summary on one line.  It does not include a nl character */
int
print_iostats_totals_live(struct iostats *iostats)
{
	struct iostats *iostatsp;
	int i = IOTOT;
	int j = 0;
	uint64 aviosz;
	double avserv, avinflt;

	while (i >= IORD) {
		iostatsp = &iostats[i];
        	avserv = iostatsp->cum_ioserv/MAX(iostatsp->compl_cnt,1) / 1000000.0;
		avinflt = (iostatsp->cum_async_inflight + iostatsp->cum_sync_inflight) / (MAX(iostatsp->issue_cnt,1) * 1.0);

		mvprintw (lineno, col+(j*50), "%7.0f %7.0f %7d %7.2f %8.2f %8.2f",
                        iostatsp->compl_cnt/secs,
                        (iostatsp->sect_xfrd/2048)/secs,
                        (iostatsp->sect_xfrd/2)/MAX(iostatsp->compl_cnt,1),
			avinflt,
                        (iostatsp->cum_iowait/MAX(iostatsp->compl_cnt,1) / 1000000.0),
			avserv);

                i--; j++;

		/* only print totals if we have a wide screen */
		if (COLS < col+150) break;
        }
}

int
print_iostats_dev_live(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	struct iostats *statsp=&devinfop->iostats[0];
	dev_info_t *gdevinfop;
	uint32 dev;

        if (devinfop->iostats[IOTOT].compl_cnt == 0) return 0; 

        dev = devinfop->lle.key;

	if (devinfop->devname) {
		mvprintw (lineno, 0, "%-10s", devinfop->devname);
	} else {
		/* try to get device name from global dev */
		gdevinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
		if (gdevinfop->devname) {
			mvprintw (lineno, 0, "%-10s", gdevinfop->devname);
		} else {
			mvprintw (lineno, 0, "0x%08x", devinfop->lle.key);
		}
	}

        print_iostats_totals_live(&devinfop->iostats[0]);

	if (COLS > col+191) {
        	if (statsp[IOTOT].requeue_cnt) {
                	mvprintw (lineno, col+151, "requeue: %d", statsp[IOTOT].requeue_cnt);
        	}

        	if (statsp[IOTOT].barrier_cnt) {
                	mvprintw (lineno, col+171, "barriers: %d", statsp[IOTOT].barrier_cnt);
        	}
	}

	lineno++;
}

int
print_iostats_fcdev_live(void *arg1, void *arg2)
{
	fc_dev_t *fcdevp = (fc_dev_t *)arg1;
	dev_info_t *devinfop = fcdevp->devinfop;

	print_iostats_dev_live(devinfop, NULL);
}


int
print_iostats_fc_live(void *arg1, void *arg2)
{
	fc_info_t *fcinfop = (fc_info_t *)arg1;
	struct iostats *statsp = &fcinfop->iostats[0];
	uint64 devpath;

        if (statsp[IOTOT].compl_cnt == 0) return 0;

        devpath = fcinfop->lle.key;

	if (devpath != NO_HBA) {
		mvprintw (lineno, 0, "%d:%d:%d", FCPATH1(devpath), FCPATH2(devpath), FCPATH3(devpath));
	} else {
		mvprintw (lineno, 0, "ukn");
	}

        print_iostats_totals_live(statsp);

	if (COLS > 191) {
        	if (statsp[IOTOT].requeue_cnt) {
                	mvprintw (lineno, col+151, "requeue: %d", statsp[IOTOT].requeue_cnt);
        	}

        	if (statsp[IOTOT].barrier_cnt) {
			col=171;
                	mvprintw (lineno, col+171, "barriers: %d", statsp[IOTOT].barrier_cnt);
        	}
	}

	lineno++;
}

int
print_iostats_wwndev_live(void *arg1, void *arg2)
{
	wwn_dev_t *wwndevp = (wwn_dev_t *)arg1;
	dev_info_t *devinfop = wwndevp->devinfop;

	print_iostats_dev_live(devinfop, NULL);
}

int
print_iostats_wwn_live(void *arg1, void *arg2)
{
	wwn_info_t *wwninfop = (wwn_info_t *)arg1;
	struct iostats *statsp = &wwninfop->iostats[0];
	uint64 wwn;

        if (statsp[IOTOT].compl_cnt == 0) return 0;

        wwn = wwninfop->lle.key;

	if (wwn != 0) {
		mvprintw (lineno, 0, "0x%016llx", wwn);
	} else {
		mvprintw (lineno, 0, "none");
	}

	col=21;
        print_iostats_totals_live(statsp);

	if (COLS > col+191) {
        	if (statsp[IOTOT].requeue_cnt) {
                	mvprintw (lineno, col+151, "requeue: %d", statsp[IOTOT].requeue_cnt);
        	}

        	if (statsp[IOTOT].barrier_cnt) {
                	mvprintw (lineno, col+171, "barriers: %d", statsp[IOTOT].barrier_cnt);
        	}
	}

	lineno++;
}

int
print_syscall_info_live(void *arg1, void *arg2)
{
        syscall_info_t *syscallp = arg1;
        syscall_stats_t *statp = &syscallp->stats;
        sched_stats_t *sstatp = &syscallp->sched_stats;
        short  *syscall_index;
        iov_stats_t *iovstatp;
        uint64 tot_cnt;

        if (statp->count == 0) return 0;

        syscall_index = (SYSCALL_MODE(syscallp->lle.key) == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;

        mvprintw (lineno++, 0, "%-30s%8d %8.1f %11.6f %10.6f", 
                syscall_arg_list[syscall_index[SYSCALL_NO(syscallp->lle.key)]].name,
                statp->count,
                statp->count / secs,
                SECS(statp->total_time),
                SECS(statp->total_time / statp->count));

        if (COLS > 107) {
                printw (" %10.6f %7d",
                	SECS(statp->max_time),
                	statp->errors);
		if (statp->bytes && statp->count) {
                	printw (" %7lld %8.1f",
                        	(statp->bytes) / MAX((statp->count - statp->errors), statp->count),
                       		(statp->bytes) / (secs * 1024.0));
		}
        }

	if (scdetail_flag) {
		if (LINES_AVAIL < 4) return 0;
                if (sstatp->T_sleep_time && sstatp->C_sleep_cnt) {
                        mvprintw (lineno++, 0, "   %-27s%8d %8.1f %11.6f %10.6f", 
                                "SLEEP",
                                sstatp->C_sleep_cnt,
                                sstatp->C_sleep_cnt/secs,
                                SECS(sstatp->T_sleep_time),
                                SECS(sstatp->T_sleep_time / sstatp->C_sleep_cnt));

                        if (syscallp->slp_hash) {
                                foreach_hash_entry_l((void **)syscallp->slp_hash,
                                                SLP_HSIZE,
                                                print_slpinfo_scall_live,
                                                slp_sort_by_time, LINES_AVAIL-2, NULL);
                        }
                }

		if (sstatp->T_runq_time) 
                        mvprintw (lineno++, 0, "   %-27s                  %11.6f", 
                                "RUNQ",
                                SECS(sstatp->T_runq_time));

                if (sstatp->T_run_time &&  (sstatp->T_run_time != statp->total_time) )
                        mvprintw (lineno++, 0, "   %-27s                  %11.6f", 
                                "CPU",
                                SECS(sstatp->T_run_time));

        	if ((LINES_AVAIL > 2) && syscallp->iov_stats) {
               		iovstatp = syscallp->iov_stats;
               		tot_cnt = iovstatp->rd_cnt + iovstatp->wr_cnt;
                	if (iovstatp->rd_cnt)
                        	mvprintw (lineno++, 0, "   %-27s%8d %8.1f %11s %10.6f %10.6f %7s %7lld %8.1f", 
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
                        	mvprintw (lineno++, 0, "   %-27s%8d %8.1f %11s %10.6f %10.6f %7s %7lld %8.1f",
                                        "AIO Writes",
                                        iovstatp->wr_cnt,
                                        iovstatp->wr_cnt/secs,
                                        " ",/* SECS(iovstatp->rd_time), */
                                        SECS(iovstatp->wr_time),
                                        SECS(iovstatp->wr_time / iovstatp->wr_cnt),
                                        SECS(iovstatp->wr_max_time),
                                        " ",
                                        iovstatp->wr_bytes / iovstatp->wr_cnt,
                                        (iovstatp->wr_bytes) / (secs * 1024.0));
                }
        }

        return 0;
}

int
print_fd_info_live(void *arg1, void *arg2)
{
	fd_info_t *fdinfop = arg1, *tfdinfop;
	pid_info_t *pidp = arg2, *tgidp;
	fdata_info_t *fdatap, *tfdatap;
	int pos = 0;
	char fdesc[1024];
	char lstr[80], rstr[80];

        if (fdinfop->stats.syscall_cnt == 0)
                return 0;

	if (LINES_AVAIL < 2) return 0;

        if (fdinfop->lsock) {
		uint64 lkey, rkey;
	        uint32 lport, rport;

		lport = SIN_PORT(fdinfop->lsock);
		lkey = SOCK_KEY(SIN_ADDR(fdinfop->lsock), lport);
		rport = SIN_PORT(fdinfop->rsock);
		rkey = SOCK_KEY(SIN_ADDR(fdinfop->rsock), rport);

		printstr_ip_port_v6(lstr, fdinfop->lsock, 0);
		printstr_ip_port_v6(rstr, fdinfop->rsock, 0);
                sprintf (fdesc, " %s     TCP %s->%s (ESTABLISHED)", 
				(fdinfop->ftype == F_IPv4) ? "IPv4" : "IPv6", lstr, rstr);
        } else if (fdinfop->ftype) {
                pos += sprintf (&fdesc[pos], " %-8s", ftype_name_index[fdinfop->ftype]);
                if ((fdinfop->ftype == F_IPv4) || (fdinfop->ftype == F_IPv6)) {
                        if (fdinfop->node == TCP_NODE) {
                                pos += sprintf (&fdesc[pos], " TCP");
                        } else if (fdinfop->node == UDP_NODE) {
                                pos += sprintf (&fdesc[pos], " UDP");
                        } else {
                                pos += sprintf (&fdesc[pos], " UKN");
                        }
                } else if (fdinfop->ftype == F_unix) {
                        pos += sprintf (&fdesc[pos], " %u", fdinfop->node);
                } else {
                        pos += sprintf (&fdesc[pos], " dev: 0x%x", fdinfop->dev);
                }
                fdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash,
                                                FDATA_KEY(fdinfop->dev, fdinfop->node),
                                                FDATA_HASH(fdinfop->dev, fdinfop->node));
                if (fdatap && fdatap->fnameptr) {
                        pos += sprintf (&fdesc[pos], " %s", fdatap->fnameptr);
                } else {
                        if (fdinfop->fnamep) {
                        	pos += sprintf (&fdesc[pos], " %s", fdinfop->fnamep);
                                if (fdinfop->multiple_fnames) 
                        		pos += sprintf (&fdesc[pos], " (multiple)");
                        } else {
                        	pos += sprintf (&fdesc[pos], "     - filename not found");
                        }
                }
        } else if (pidp->tgid) {
                /* inherit filenames from primary thread */
                tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                if (tfdinfop) {
                	pos += sprintf (&fdesc[pos], " %-8s", ftype_name_index[tfdinfop->ftype]);
                        if ((tfdinfop->ftype == F_IPv4) || (tfdinfop->ftype == F_IPv6)) {
                                if (tfdinfop->node == TCP_NODE) {
                                	pos += sprintf (&fdesc[pos], " TCP");
                                } else if (tfdinfop->node == UDP_NODE) {
                                	pos += sprintf (&fdesc[pos], " UDP");
                                } else {
                                	pos += sprintf (&fdesc[pos], " UKN");
                                }
                        } else if (tfdinfop->ftype == F_unix) {
                                pos += sprintf (&fdesc[pos], " %d", tfdinfop->node);
                        } else {
                                pos += sprintf (&fdesc[pos], " dev: 0x%x", tfdinfop->dev);
                        }

                        tfdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash,
                                                FDATA_KEY(tfdinfop->dev, tfdinfop->node),
                                                FDATA_HASH(tfdinfop->dev, tfdinfop->node));
                        if (tfdatap && tfdatap->fnameptr) {
                                pos += sprintf (&fdesc[pos], " %s", tfdatap->fnameptr);
                                if (tfdinfop->multiple_fnames) 
					pos += sprintf (&fdesc[pos], " (multiple)");
                        } else if (tfdinfop->fnamep) {
                                pos += sprintf (&fdesc[pos], " %s", tfdinfop->fnamep);
                                if (tfdinfop->multiple_fnames) 
					pos += sprintf (&fdesc[pos], " (multiple)");
                        } else {
                                pos += sprintf (&fdesc[pos], "     - filename not found");
                        }
                } else {
                        if (fdinfop->fnamep) {
                                pos += sprintf (&fdesc[pos], " %s", fdinfop->fnamep);
                                if (fdinfop->multiple_fnames) 
					pos += sprintf (&fdesc[pos], " (multiple)");
                        } else {
                                pos += sprintf (&fdesc[pos], "     - filename not found");
                        }
                }
        } else {
                if (fdinfop->fnamep) {
                        pos += sprintf (&fdesc[pos], " %s", fdinfop->fnamep);
                        if (fdinfop->multiple_fnames)
				pos += sprintf (&fdesc[pos], " (multiple)");
                } else {
                        pos += sprintf (&fdesc[pos], "     - filename not found");
                }
        }
	lineno++;
	mvprintw (lineno++, 0, "FD: %d %s", fdinfop->FD, fdesc);
	foreach_hash_entry((void **)fdinfop->syscallp, SYSCALL_HASHSZ, print_syscall_info_live, syscall_sort_by_time, LINES_AVAIL, NULL);

	return 0;
}

int
print_fdata_live(void *arg1, void *arg2)
{
	fdata_info_t *fdatap = (fdata_info_t *)arg1;

	if (fdatap->stats.syscall_cnt == 0) return 0;
	if (LINES_AVAIL < 2) return 0;

	/* skip the liki related files */
	if (fdatap->fnameptr && (strstr(fdatap->fnameptr, "/liki/sync") || strstr(fdatap->fnameptr, "/liki/cpu"))) {
			return 0;
	}

        mvprintw (lineno++, 0, "File: %s", fdatap->fnameptr ? fdatap->fnameptr : "unknown");
	printw ("   dev/ino: %d:%d/%u",
		(fdatap->dev < 0xffffffffull) ? dev_major(fdatap->dev) : 0,
		(fdatap->dev < 0xffffffffull) ? lun(fdatap->dev) : 0,
		(fdatap->node >= 0) ? fdatap->node : 0);

	if (fdatap->stats.last_pid > 0) {
		printw (" Last PID: %d\n", fdatap->stats.last_pid);
	}

	foreach_hash_entry((void **)fdatap->syscallp, SYSCALL_HASHSZ, print_syscall_info_live, syscall_sort_by_time, LINES_AVAIL, NULL);

	return 0;
}

int
print_socket_detail_live(sd_stats_t *statsp, struct sockaddr_in6 *lsock, struct sockaddr_in6 *rsock, int type, void **syscallp)
{
	char ipstr[64];

	if (LINES_AVAIL < 3) return 0;
	move(lineno++, 0);

	if (lsock) {
		printstr_ip_port_v6(ipstr, lsock, 0);
		printw ("L=%s",ipstr);
                if (rsock) printw (" ");
        }

        if (rsock) {
		printstr_ip_port_v6(ipstr, rsock, 0);
                printw ("R=%s", ipstr);
        }

	if (type > 0 && type < 11) {
		printw (" (%s)", socktype_name_index[type]);
	}

	if (statsp->last_pid > 0) {
		printw (" Last PID: %d\n", statsp->last_pid);
	}

	if (syscallp) {	
		mvprintw (lineno++, 0, "System Call Name                 Count     Rate     ElpTime        Avg");
        	if (COLS > 107) printw ("        Max    Errs    AvSz     KB/s");
		foreach_hash_entry((void **)syscallp, SYSCALL_HASHSZ, print_syscall_info_live, syscall_sort_by_time, LINES_AVAIL, NULL);
	}
}

int
print_socket_info_live(sd_stats_t *statsp, struct sockaddr_in6 *lsock, struct sockaddr_in6 *rsock, int type,  int print_lpid) 
{
	uint64 total_time;
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	char ipstr[64];

        gschedp = GET_ADD_SCHEDP(&globals->schedp);
        gstatp = &gschedp->sched_stats;
        total_time = gstatp->T_total_time;

        mvprintw (lineno++, 0, "%8d %9.1f %11.1f %9.1f %11.1f  ",
                statsp->syscall_cnt,
                (statsp->rd_cnt*1.0) / secs,
                (statsp->rd_bytes / 1024.0) / secs,
                (statsp->wr_cnt*1.0) / secs, 
                (statsp->wr_bytes / 1024.0) / secs);

	if (print_lpid) printw ("%10d  ", statsp->last_pid);

	printstr_ip_port_v6(ipstr, lsock, 0);
        if (lsock) {
                printw ("L=%s", ipstr);
                if (rsock) printw (" ");
        }
	
	printstr_ip_port_v6(ipstr, rsock, 0);
        if (rsock) {
                printw ("R=%s", ipstr);
        }

	if (type > 0 && type < 11) {
		printw (" (%s)", socktype_name_index[type]);
	}

}

int
print_ipip_live(void *arg1, void *arg2)
{
        ipip_info_t *ipipp = (ipip_info_t *)arg1;
        uint64 key1, key2;
	sd_stats_t *statsp;

	statsp = &ipipp->stats;

        if (statsp->syscall_cnt == 0) return 0;

	print_socket_info_live(statsp, ipipp->laddr, ipipp->raddr, 0, 0);
}

int
print_sdata_live(void *arg1, void *arg2)
{
	sdata_info_t *sdatap = (sdata_info_t *)arg1;
	uint64 key1, key2;
	sd_stats_t *statsp;

	statsp = &sdatap->stats;
	if (statsp->syscall_cnt == 0) return 0;

	if (IS_WINKI) { 
		print_socket_info_live(statsp, sdatap->laddr, sdatap->raddr, sdatap->type, 1);
	} else {
		print_socket_detail_live(statsp, sdatap->laddr, sdatap->raddr, sdatap->type, sdatap->syscallp);
		lineno++;
	}
}

int 
print_pid_header(pid_info_t *pidp)
{
	sched_info_t *schedp;
	sched_stats_t *statp;
	pid_info_t *tgidp, *ppidp;
	docker_info_t *dockerp;

	print_top_line();
	lineno++;
	mvprintw (lineno++,0, "%s %d", tlabel, pidp->PID);

	if (pidp->cmd) printw (" %s", pidp->cmd);
	if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);

	if (pidp->tgid && (pidp->tgid != pidp->PID)) {
	        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
 		dockerp = tgidp->dockerp;
		mvprintw (lineno++,2, "%s %d  %s", plabel, tgidp->PID, (char *)tgidp->cmd);
        }

	if (pidp->ppid) {
		ppidp = GET_PIDP(&globals->pid_hash, pidp->ppid);
		mvprintw (lineno++,2, "PPID %d  %s", ppidp->PID, (char *)ppidp->cmd);
	}

	schedp = pidp->schedp;
	if (schedp) {
		statp = &schedp->sched_stats;
		lineno++;
		mvprintw (lineno++, 0, "RunTime    : %9.6f  SysTime   : %9.6f   UserTime   : %9.6f",
			SECS(statp->T_run_time),
			SECS(statp->T_sys_time),
			SECS(statp->T_user_time));
		if (COLS > 96 && !IS_WINKI) {
			printw ("   StealTime  : %9.6f", SECS(statp->T_stealtime));
		}
		mvprintw (lineno++, 0, "SleepTime  : %9.6f  Sleep Cnt : %9d   Wakeup Cnt : %9d",
                	SECS(statp->T_sleep_time),
                	statp->C_sleep_cnt,
                	statp->C_wakeup_cnt);
        	mvprintw (lineno++, 0, "RunQTime   : %9.6f  Switch Cnt: %9d   PreemptCnt : %9d",
                	SECS(statp->T_runq_time),
                	statp->C_switch_cnt,
                	statp->C_preempt_cnt);
        	mvprintw (lineno++, 0, "Last CPU   : %9d  CPU Migrs : %9d   NODE Migrs : %9d",
                	schedp->cpu,
                	schedp->cpu_migrations,
                	schedp->ldom_migrations);
        	mvprintw (lineno++, 0, "Policy     : %-12s", sched_policy_name[schedp->policy]);
        	if (IS_LIKI_V2_PLUS) {
                	printw ("     vss :  %8lld          rss :  %8lld", pidp->vss, pidp->rss);
        	}
	}
	return 0;
}

int
print_pidmpath_window()
{
	pid_info_t *pidp;
	pidp = GET_PIDP(&globals->pid_hash, curpid);	

	if (is_alive) {
		update_cpu_times(end_time);
		calc_io_totals(&pidp->iostats[0], NULL);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0; col=0;
	clear();
	print_pid_header(pidp);

	lineno++;
	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All       ");
	col=13;
	print_iostats_totals_live(&pidp->iostats[0]);
	lineno++;

	lineno+=2;
	col=13;
	if ((LINES_AVAIL>1) && pidp->mdevhash) {
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		mvprintw (lineno++, 0, "Multipath Devices");
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}
	return 0;
}

int
print_piddsk_window(pid_info_t *pidp)
{
	pidp = GET_PIDP(&globals->pid_hash, curpid);	

	if (is_alive) {
		update_cpu_times(end_time);
		calc_io_totals(&pidp->iostats[0], NULL);
                foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
                foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
                foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, get_pathname, NULL, 0, NULL);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);

	lineno++;
	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All       ");
	col=13;
	print_iostats_totals_live(&pidp->iostats[0]);
	lineno++;

	col=13;
	if ((LINES_AVAIL>1) && pidp->devhash) {
		foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}

	col=13;
	if ((LINES_AVAIL>2) && pidp->mdevhash) {
		lineno++;
		mvprintw (lineno++, 0, "Multipath Devices");
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}
	return 0;
}

int
print_pidfile_window()
{
	pid_info_t *pidp;
	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	if (is_alive) { 
		update_cpu_times(end_time);
		calc_io_totals(&pidp->iostats[0], NULL);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);
	lineno++;

	if ((pidp->fdhash == NULL) && (pidp->fobj_hash == NULL)) {
		mvprintw(lineno++, 0, "*** No File Activity Found ***");
		return 0;
	}


	if (pidp->fobj_hash) {
		mvprintw (lineno++, 0, "                    -------  Total  ------- -------  Write  -------- --------  Read  --------");
		mvprintw (lineno++, 0, "Object                 IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz  filename");

		foreach_hash_entry(pidp->fobj_hash, FOBJ_HSIZE, calc_fobj_totals, NULL, 0, 0);
		foreach_hash_entry((void **)pidp->fobj_hash, FOBJ_HSIZE, live_print_fobj_logio,
				fobj_sort_by_logio,
				0, NULL);
	}

	else if (pidp->fdhash) {
		mvprintw (lineno++, 0, "System Call Name                 Count     Rate     ElpTime        Avg");
        	if (COLS > 107) printw ("        Max    Errs    AvSz     KB/s");
	
		if (is_alive) foreach_hash_entry(pidp->fdhash, FD_HSIZE, get_filename, NULL, 0, pidp);
	
		foreach_hash_entry((void **)pidp->fdhash, FD_HSIZE, print_fd_info_live,
			fd_sort_by_time, 0, pidp);
	
		return 0;
	}
}

int
print_pidhc_window()
{
	pid_info_t *pidp;
	hc_info_t *hcinfop;
	int nlines;
	print_pc_args_t print_pc_args;

	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	if (is_alive) { 
		update_cpu_times(end_time);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);
	lineno++;

	if (IS_FTRACE) {
		mvprintw (lineno++, 0, " *** No Hardclock Tracing with Ftrace ***");
		return 0;
	}

	nlines = LINES_AVAIL / 2;
	hcinfop = pidp->hcinfop;
	print_pc_args.hcinfop = hcinfop;
	print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = NULL;
	if (!IS_FTRACE && hcinfop && hcinfop->pc_hash) {
		mvprintw (lineno++, 0, "---- Top Hardclock Functions ----");
	        mvprintw (lineno++, 0, "   Count     Pct  State  Function");
		nlines = LINES_AVAIL / 2;
        	foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc, pc_sort_by_count, nlines, (void *)&print_pc_args);
	}

	if (!IS_FTRACE && (LINES_AVAIL > 3) && hcinfop &&  hcinfop->hc_stktrc_hash ) {
		lineno++;
		mvprintw (lineno++, 0, "---- Top Hardclock Stack Traces ----");
		mvprintw (lineno++, 0, "   count    pct  Stack trace");
		foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, print_hc_stktrc_live, stktrc_sort_by_cnt, LINES_AVAIL, (void *)hcinfop);
	}
		
}

int
print_pidwait_window()
{
	pid_info_t *pidp;
	sched_info_t *schedp;
	int nlines;

	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	if (is_alive) { 
		update_cpu_times(end_time);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);
	if (IS_FTRACE) {
		lineno++;
		mvprintw (lineno++, 0, " *** No Sleep Functions with Ftrace ***");
		return 0;
	}

	nlines = LINES_AVAIL / 2;
	schedp = pidp->schedp;
	if (pidp->slp_hash && schedp) {
		lineno++;
		mvprintw (lineno++, 0, "---------------------------- Top Wait Functions -----------------------------");
		mvprintw (lineno++, 0, "   Count     SlpTime  Msec/Slp  MaxMsecs  Func");
		nlines = LINES_AVAIL / 2;
		foreach_hash_entry_l((void **)pidp->slp_hash, SLP_HSIZE, print_slp_info_live, slp_sort_by_time, nlines, &schedp->sched_stats);
	}

	if ((LINES_AVAIL > 3) && pidp->stktrc_hash && schedp) {
		lineno++;
		mvprintw (lineno++, 0, "-------------------------- Top Wait Stack Traces ----------------------------");
		mvprintw (lineno++, 0, "   count  wait%%    avwait   Stack trace");
		foreach_hash_entry((void **)pidp->stktrc_hash, STKTRC_HSIZE, print_stktrc_info_live, stktrc_sort_by_slptime, LINES_AVAIL, (void *)schedp);
	}
}

int
live_print_setrq_pids(void *arg1, void *arg2)
{
        setrq_info_t *setrq_infop = (setrq_info_t *)arg1;
        pid_info_t *pidp;
        sched_info_t *schedp;
        sched_stats_t *statp;

        coop_info_t *coopinfop = (coop_info_t *)arg2;
        pidp = GET_PIDP(&globals->pid_hash, setrq_infop->PID);
	if (is_alive) { 
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	if (pidp->cmd && strstr(pidp->cmd,"kiinfo")) return 0;

        schedp = (sched_info_t *)find_sched_info(pidp);
        statp = &schedp->sched_stats;

        /* If WAKER, pidp, schedp, statp, are those of the pid we are waking up */

        coopinfop->total_cnt = (uint64)setrq_infop->cnt;
        coopinfop->pidp = pidp;
        if(coopinfop->which == WAKER) {
                coopinfop->total_slp_time = statp->T_sleep_time;
	}

        /* If we're the WAKER, the total sleeptime we're comparing is that of the task we are waking */

        mvprintw (lineno++, col, "%8d   %6d   %6.2f%%   %9.6f",
                    (int)setrq_infop->PID,
                    setrq_infop->cnt,
                    setrq_infop->sleep_time*100.0/coopinfop->total_slp_time,
                    SECS(setrq_infop->sleep_time));

        if ((setrq_infop->PID == 0) || ((uint64)setrq_infop->PID == -1)) {
                printw ("  %s", " ICS ");
        } else {
                if (pidp->cmd) printw ("  %s", pidp->cmd);
                if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
                if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
		if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
        }
}

int
print_pidcoop_window()
{
	pid_info_t *pidp;
	sched_info_t *schedp;
	int nlines;
	coop_info_t coopinfo;

	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	if (is_alive) { 
		update_cpu_times(end_time);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);
	nlines = LINES_AVAIL / 4;

	schedp = pidp->schedp;
	if (pidp->slp_hash && schedp) {
		lineno++;
		mvprintw (lineno++, 0, "---------------------------- Top Wait Functions -----------------------------");
		mvprintw (lineno++, 0, "   Count     SlpTime  Msec/Slp  MaxMsecs  Func");
		nlines = LINES_AVAIL / 2;
		foreach_hash_entry_l((void **)pidp->slp_hash, SLP_HSIZE, print_slp_info_live, slp_sort_by_time, nlines, &schedp->sched_stats);
	}

	if (pidp->schedp) {
		nlines = LINES_AVAIL / 2;
		if ((schedp->sched_stats.C_wakeup_cnt != 0) && LINES_AVAIL > 3) {
			lineno++;
			mvprintw(lineno++, col, "Tasks woken up by this task");
			mvprintw(lineno++, col, "     %s    Count   SlpPcnt     Slptime  Command", tlabel);
			coopinfo.which = WAKER;
			coopinfo.cnt = schedp->sched_stats.C_wakeup_cnt;
			foreach_hash_entry((void **)schedp->setrq_tgt_hash, WPID_HSIZE,
                             	 	live_print_setrq_pids, setrq_sort_by_sleep_time, nlines-2, (void *)&coopinfo);
		}

	
		if ((schedp->sched_stats.C_setrq_cnt != 0) && LINES_AVAIL > 3) {
			lineno++;
			mvprintw(lineno++, col, "Tasks that have woken up this task");
			mvprintw(lineno++, col, "     %s    Count   SlpPcnt     Slptime  Command", tlabel);
			coopinfo.which = SLEEPER;
			coopinfo.cnt = schedp->sched_stats.C_setrq_cnt;
			coopinfo.total_slp_time =  schedp->sched_stats.T_sleep_time;
			foreach_hash_entry((void **)schedp->setrq_src_hash, WPID_HSIZE,
                              		live_print_setrq_pids, setrq_sort_by_sleep_time, LINES_AVAIL, (void *)&coopinfo);
		}
	}
}

int
print_pidscall_window()
{
	pid_info_t *pidp;

	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	if (is_alive) { 
		update_cpu_times(end_time);
		get_command(pidp, NULL);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);

	if ((LINES_AVAIL > 4) && pidp->scallhash) {
		lineno++;
		mvprintw (lineno++, 0, "----------------------------- Top System Calls ------------------------------");
	        mvprintw (lineno++, 0, "System Call Name                 Count     Rate     ElpTime        Avg");
                if (COLS > 107) printw ("        Max    Errs    AvSz     KB/s");
		foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, print_syscall_info_live, syscall_sort_by_time, LINES_AVAIL, NULL);
	}
}

void
live_print_msr_stats(sched_stats_t *statp, char iscpu)
{
	unsigned long *msrptr;

	msrptr = &statp->msr_total[0];
	if (msrptr[RET_INSTR] == 0) return; 

	lineno++;
	mvprintw (lineno++, col, "   LLC_ref   LLC_hits  LLC_hit%%     Instrs     Cycles      CPI   Avg_MHz  SMI_cnt");
	mvprintw (lineno++, col, "%9lldk %9lldk %8.2f%% %9.1fm %9.1fm %8.2f   %7.2f     %4lld",
			msrptr[LLC_REF]/1000, (msrptr[LLC_REF]-msrptr[LLC_MISSES])/1000,
			(msrptr[LLC_REF]-msrptr[LLC_MISSES])*100.0 / msrptr[LLC_REF],
			msrptr[RET_INSTR] / 1000000.0, msrptr[CYC_NOHALT_CORE] / 1000000.0,
                        msrptr[CYC_NOHALT_CORE] * 1.0 / msrptr[RET_INSTR],
               		msrptr[REF_CLK_FREQ] ? globals->clk_mhz * (msrptr[ACT_CLK_FREQ]*1.0 / msrptr[REF_CLK_FREQ]) : 0.0,
                        iscpu ? statp->msr_last[SMI_CNT] - msrptr[SMI_CNT] : msrptr[SMI_CNT]);
}

	
int
print_pid_window()
{
	pid_info_t *pidp;
	hc_info_t *hcinfop;
	sched_info_t *schedp;
	iostats_t *iostatp;
	int i;
	int nlines;
	print_pc_args_t print_pc_args;

	pidp = GET_PIDP(&globals->pid_hash, curpid);	
	schedp = pidp->schedp;
	if (is_alive) { 
		update_cpu_times(end_time);
		calc_io_totals(&pidp->iostats[0], NULL);
                foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
                foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
		get_command(pidp, NULL); 
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

	lineno=0;
	clear();
	print_pid_header(pidp);

	if (schedp && msr_flag && (LINES_AVAIL > 2))
		live_print_msr_stats(&schedp->sched_stats, 0);

	hcinfop = pidp->hcinfop;
	print_pc_args.hcinfop = hcinfop;
	print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = NULL;
	if (IS_FTRACE) {
		lineno++;
		mvprintw(lineno++, 0, "*** No Hardclock Traces with Ftrace ***");
	} else if (hcinfop && hcinfop->pc_hash && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw (lineno++, 0, "------------------------- Top Hardclock Functions ---------------------------");
	        mvprintw (lineno++, 0, "   Count     Pct  State  Function");
		(LINES_AVAIL > 13) ? (nlines=5) : (nlines=1);
        	foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc, pc_sort_by_count, nlines, (void *)&print_pc_args);
	}

	if (IS_FTRACE) {
		lineno++;
		mvprintw(lineno++, 0, "*** No Sleep Functions with Ftrace ***");
	} else if (pidp->slp_hash && schedp && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw (lineno++, 0, "---------------------------- Top Wait Functions -----------------------------");
		mvprintw (lineno++, 0, "   Count     SlpTime  Msec/Slp  MaxMsecs  Func");
		(LINES_AVAIL > 13) ? (nlines=5) : (nlines=1);
		foreach_hash_entry_l((void **)pidp->slp_hash, SLP_HSIZE, print_slp_info_live, slp_sort_by_time, nsym, &schedp->sched_stats);
	}

	if (pidp->iostats[IOTOT].compl_cnt && (LINES_AVAIL > 3)) {
		lineno++;
		PRINT_IODETAIL_HDR("device    ");
		mvprintw (lineno, 0, "All       ");
		col=13;
		print_iostats_totals_live(&pidp->iostats[0]);
		lineno++;
		(LINES_AVAIL > 13) ? (nlines=5) : (nlines=1);
        	if ((LINES_AVAIL) && pidp->devhash) {
                	foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
                	foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, nlines, NULL);
		}
		col=0;
	}

	if ((LINES_AVAIL > 3) && pidp->scallhash) {
		lineno++;
		mvprintw (lineno++, 0, "----------------------------- Top System Calls ------------------------------");
		mvprintw (lineno++, 0, "System Call Name                 Count     Rate     ElpTime        Avg");
        	if (COLS > 107) printw ("        Max    Errs    AvSz     KB/s");
		foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, print_syscall_info_live, syscall_sort_by_time, LINES_AVAIL, NULL);
	}
}

int
live_pid_runtime_summary(void *arg1, void *arg2)
{
	pid_info_t *pidp = arg1;
	sched_info_t *schedp;
	sched_stats_t *statp;

	if (pidp == NULL) return 0;
	if (pidp->PID == 0ull) return 0;
	if ((pidp->cmd && strncmp(pidp->cmd, "kiinfo", 6) == 0)) return 0; 
	if ((schedp = pidp->schedp) == NULL) return 0;
	statp = &schedp->sched_stats;

	move(lineno, 0); clrtoeol();
	
	mvprintw (lineno++, 0, "%7d %5.1f%% %5.1f%% %5.1f%% %5.1f%% %5.1f%% %5.1f%%",
		pidp->PID,
		(SECS(statp->T_run_time)*100.0)/secs,
		(SECS(statp->T_sys_time)*100.0)/secs,
		(SECS(statp->T_user_time)*100.0)/secs,
		(SECS(statp->T_runq_time)*100.0)/secs,
		(SECS(statp->T_sleep_time)*100.0)/secs,
		(SECS(statp->T_stealtime)*100.0)/secs);

		if (COLS > 100) printw (" %8.1f %8.1f", 
				pidp->iostats[IOTOT].compl_cnt / secs, 
				((pidp->iostats[IOTOT].sect_xfrd / 2.0)/1024.0) / secs);
		if (COLS > 120) printw (" %8.1f %8.1f", 
				(pidp->netstats.rd_cnt+pidp->netstats.wr_cnt)/secs, 
				((pidp->netstats.rd_bytes+pidp->netstats.wr_bytes)/(1024*1024))/secs);

		if (pidp->cmd) printw ("  %s", pidp->cmd);
		if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
                if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
		if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
}

int
print_dsk_window()
{
	if (is_alive) {
		calc_io_totals(&globals->iostats[0], NULL);
                foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	mvprintw (lineno++, 0, "*** Global I/O by Device ***");
	lineno++;

	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All       ");
	col=13;
	print_iostats_totals_live(&globals->iostats[0]);
	lineno++;

	if ((LINES_AVAIL>1) && globals->devhash) {
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}

	if ((LINES_AVAIL>2) && globals->mdevhash) {
		lineno++;
		mvprintw (lineno++, 0, "Multipath Devices");
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_hba_window()
{
	if (is_alive) { 
		calc_io_totals(&globals->iostats[0], NULL);
                foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, clear_fc_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, clear_wwn_iostats, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	mvprintw(lineno++, 0, "*** Global I/O by HBA ***");
	lineno++;

	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All       ");
	col=13;
	print_iostats_totals_live(&globals->iostats[0]);
	lineno++;

	if ((LINES_AVAIL>1) && globals->devhash) {
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, print_iostats_fc_live, fc_sort_by_path, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_select_hba_window()
{
	fc_info_t *fcinfop;
	char hba_str[16];

	if (curhba == NO_HBA) return 0;
	if (is_alive) { 
		calc_io_totals(&globals->iostats[0], NULL);
                foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, clear_fc_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, clear_wwn_iostats, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	fcinfop = FIND_FCINFOP(globals->fchash, curhba);
	if (fcinfop == NULL) {
		mvprintw(lineno++, 0, "*** No I/O for HBA %d:%d:%d ***", FCPATH1(curhba), FCPATH2(curhba), FCPATH3(curhba));
		return 0;
	}

	mvprintw(lineno++, 0, "*** I/O for HBA %d:%d:%d ***", FCPATH1(curhba), FCPATH2(curhba), FCPATH3(curhba));
	lineno++;

	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "%d:%d:%d", FCPATH1(curhba), FCPATH2(curhba), FCPATH3(curhba));
	col=13;
	print_iostats_totals_live(&fcinfop->iostats[0]);
	lineno++;

	if ((LINES_AVAIL>1) && fcinfop->fcdevhash) {
		foreach_hash_entry((void **)fcinfop->fcdevhash, DEV_HSIZE, print_iostats_fcdev_live, NULL, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_wwn_window()
{
	if (is_alive) { 
		calc_io_totals(&globals->iostats[0], NULL);
                foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, clear_fc_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, clear_wwn_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	mvprintw(lineno++, 0, "*** Global I/O by Target Path WWN ***");
	lineno++;

	PRINT_IODETAIL_HDR("device            ");
	mvprintw (lineno, 0, "All");
	col=21;
	print_iostats_totals_live(&globals->iostats[0]);
	lineno++;

	if ((LINES_AVAIL>1) && globals->devhash) {
		foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, print_iostats_wwn_live, wwn_sort_by_wwn, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_select_wwn_window()
{
	wwn_info_t *wwninfop;

	if (curwwn == NO_WWN) return 0;
	if (is_alive) { 
		calc_io_totals(&globals->iostats[0], NULL);
                foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, clear_fc_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, clear_wwn_iostats, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	wwninfop = FIND_WWNINFOP(globals->wwnhash, curwwn);
	if (wwninfop == NULL) {
		mvprintw(lineno++, 0, "*** No I/O for Target Path 0x%016llx ***", curwwn);
		return 0;
	}

	mvprintw(lineno++, 0, "*** I/O for Target Path 0x%016llx ***", curwwn);
	lineno++;

	PRINT_IODETAIL_HDR("device            ");
	mvprintw (lineno, 0, "0x%016llx", curwwn);
	col=21;
	print_iostats_totals_live(&wwninfop->iostats[0]);
	lineno++;

	col=21;
	if ((LINES_AVAIL>1) && wwninfop->wwndevhash) {
		foreach_hash_entry((void **)wwninfop->wwndevhash, DEV_HSIZE, print_iostats_wwndev_live, NULL, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_mpath_window()
{
	if (is_alive) {
		calc_io_totals(&globals->iostats[0], NULL);
	}

	print_global_header();	
	lineno++;

	mvprintw (lineno++, 0, "*** Global I/O by Mpath Device ***");
	lineno++;
	
	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All");
	col=13;	
	print_iostats_totals_live(&globals->iostats[0]);
	lineno++;

	if (globals->mdevhash == NULL) {
		mvprintw(lineno++, 0, "*** No Multipath Device Activity Detected ***");
	}

	col=13;	
	if ((LINES_AVAIL>1) && globals->mdevhash) {
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, print_iostats_dev_live, dev_sort_by_count, LINES_AVAIL, NULL);
	}

	return 0;
}

int
print_pid_iosum_live(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        iostats_t *rstatp, *wstatp, *tstatp;

        tstatp = &pidp->iostats[IO_TOTAL];
        if (tstatp->compl_cnt == 0) return 0;

        rstatp = &pidp->iostats[IO_READ];
        wstatp = &pidp->iostats[IO_WRITE];

	if (is_alive) {
		get_command(pidp, NULL);
		if (debug) fprintf (stderr, "pidp: 0x%llx  PID: %d  %s\n", pidp, pidp->PID, pidp->cmd);
		if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
	}

        mvprintw (lineno++, 0, "%8d %8.0f %8.0f %9.1f %9.3f %8d  %s",
                tstatp->compl_cnt,
                rstatp->compl_cnt / secs,
                wstatp->compl_cnt / secs,
                ((rstatp->sect_xfrd + wstatp->sect_xfrd)/2.0) / secs,
                MSECS(tstatp->cum_ioserv / tstatp->compl_cnt),
                MSECS(tstatp->cum_ioserv / tstatp->compl_cnt),
		pidp->PID,
		pidp->cmd ? pidp->cmd : " ");

	if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
        if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);

        return 0;
}

int
print_pid_hc_live(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	hc_info_t *hcinfop;

	if (LINES_AVAIL <= 0) return 0;

	hcinfop = pidp->hcinfop;

	if (hcinfop) {
		if (is_alive) {
			get_command(pidp, NULL);
			if (globals->docker_hash) get_pid_cgroup(pidp, NULL);
		}
		mvprintw (lineno++, col, " %7d %7d %7d %7d %8d  %s",
			hcinfop->total,
			hcinfop->cpustate[HC_USER],
			hcinfop->cpustate[HC_SYS],
			hcinfop->cpustate[HC_INTR],
			pidp->PID,
			pidp->cmd ? pidp->cmd : " ");
		if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
                if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
		if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	}
}

int
print_iotop_window()
{
	struct iostats *iostatsp;
	double avinflt, avserv;

	if (is_alive) {
		calc_io_totals(&globals->iostats[0], NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
	}

	print_global_header();	
	lineno++;

	PRINT_IODETAIL_HDR("device    ");
	mvprintw (lineno, 0, "All       ");
	col=13;
	print_iostats_totals_live(&globals->iostats[0]);
	lineno++;

	if ((LINES_AVAIL>2) && globals->pid_hash) {
		lineno++;
		mvprintw(lineno++, 0, "----------------- Top Tasks Performing I/O ---------------------");
		mvprintw(lineno++, 0, "     Cnt      r/s      w/s    KB/sec    Avserv      %s  Process", tlabel);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_iosum_live,  pid_sort_by_iocnt, LINES_AVAIL, NULL);
	}
}


int 
print_irq_entry_live(void *arg1, void *arg2)
{
        irq_entry_t *irqentryp = (irq_entry_t *)arg1;
        int *irqtypep = (int *)arg2;
        int irq = irqentryp->lle.key;
        irq_name_t *irqname_entry;
	int ncol=col;

	if (LINES_AVAIL < 1) return 0;
        if (*irqtypep == HARDIRQ) {
                irqname_entry = (irq_name_t *)find_entry((lle_t **)globals->irqname_hash, irq, IRQ_HASH(irq));
                if (irqname_entry) {
                        mvprintw (lineno, col, "%4d %-32s", irq, irqname_entry->name);
                } else {
                        mvprintw (lineno, col, "%4d %-32s", irq, " ");
                }
		ncol+=38;
        } else if (IS_WINKI) {
		irqname_entry = (irq_name_t *)find_entry((lle_t **)globals->dpcname_hash, irq, IRQ_HASH(irq));
                if (irqname_entry) {
                        mvprintw (lineno, col, "%4d %-32s", irq, irqname_entry->name);
                } else {
                        mvprintw (lineno, col, "%4d %-32s", irq, " ");
                }
		ncol+=38;

	} else {
                mvprintw (lineno, col, "%4d %-32s", irq, softirq_name[irq]);
		ncol+=38;
        }

        mvprintw(lineno, ncol, "%8d %11.6f %12.3f", irqentryp->count, SECS(irqentryp->total_time),
						(SECS(irqentryp->total_time) / irqentryp->count)*1000000.0);

	lineno++;
}

int
print_select_irq_window()
{
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	uint64 busy_time = 0;
	irq_info_t *cirqinfop, *irqinfop = NULL;
	irq_name_t *irqnamep = NULL;
	irq_entry_t *cirqentryp, *irqentryp = NULL;
	cpu_info_t *cpuinfop;
	int irqtype;
	int header_lineno;
	int cpu, irq;
	char *name = " ";

	if (is_alive) { 
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}

	print_global_header();	

        gschedp = GET_ADD_SCHEDP(&globals->schedp);
        gstatp = &gschedp->sched_stats;
        total_time = gstatp->T_total_time;

	lineno++;
	col = 0;

	if (curhirq > 0) {
		irq = curhirq;
		irqinfop = globals->irqp;
		if (irqnamep = FIND_IRQNAMEP(globals->irqname_hash, irq)) {
			name = irqnamep->name;
		}
		irqtype = HARDIRQ;
	} else if (cursirq > 0) {
		irq = cursirq;
		irqinfop = globals->softirqp;
		if (IS_WINKI) {
			if (irqnamep = FIND_IRQNAMEP(globals->dpcname_hash, irq)) {
				name = irqnamep->name;
			}
		} else {
			if (irq < 10) name = softirq_name[irq];
		}
		irqtype = SOFTIRQ;
	}

	if ((irqinfop == NULL) || 
	    (irqinfop && ((irqentryp = FIND_IRQENTRYP(irqinfop->irq_entry_hash, irq)) == NULL))) {
		mvprintw(lineno++, col, "%s: %d  Unknown", irqtype == HARDIRQ ? "HardIRQ" : "SoftIRQ", irq);
		return 0;
	}

	mvprintw(lineno++, col, "%s: %d %s  Count: %7d  ElpTime: %9.6f  Avg(usecs): %7.3f", irqtype == HARDIRQ ? "HardIRQ" : "SoftIRQ", 
				irq, name, irqentryp->count, SECS(irqentryp->total_time),
				(SECS(irqentryp->total_time) / irqentryp->count)*1000000.0);

	lineno++;
	header_lineno = lineno;
	mvprintw(lineno++, col, "CPU   Count    ElpTime  Avg(usecs)");
	for (cpu = 0; cpu < MAXCPUS; cpu++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, cpu)) {
			if (cirqinfop = (irqtype == HARDIRQ ? cpuinfop->irqp : cpuinfop->softirqp)) {
				if (cirqentryp = FIND_IRQENTRYP(cirqinfop->irq_entry_hash, irq)) {
					if (LINES_AVAIL < 1) {
						col = col+38;
						if (col+25 < COLS) {
							lineno = header_lineno;
							mvprintw(lineno++, col, "CPU   Count    ElpTime  Avg(usecs)");
						} else 
							break;
					}

					mvprintw(lineno++, col, "%3d %7d %10.6f %11.3f", cpu, cirqentryp->count, SECS(cirqentryp->total_time),
											(SECS(cirqentryp->total_time) / cirqentryp->count)*1000000.0);
				}
			}
		}
	}
	
}

int
print_irq_window()
{
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	uint64 busy_time = 0;
	irq_info_t *irqinfop;
	int irqtype;
	int header_lineno;

	if (is_alive) { 
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}

	print_global_header();	

        gschedp = GET_ADD_SCHEDP(&globals->schedp);
        gstatp = &gschedp->sched_stats;
        total_time = gstatp->T_total_time;

	header_lineno = lineno;
	lineno++;
	col = 0;
	mvprintw(lineno++, col, "------------------------------- Hard IRQs -----------------------------");
	mvprintw(lineno++, col, " IRQ Name                                Count     ElpTime   Avg(usecs)");
	irqinfop = globals->irqp;
	if (irqinfop && (LINES_AVAIL > 3)) {
		irqtype = HARDIRQ;
		foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE, 
                                        print_irq_entry_live, irq_sort_by_time, 0, &irqtype);
	}
			
	lineno = header_lineno;
	lineno++;
	col=72;
	if (COLS > 146) {
		mvprintw(lineno++, col, "------------------------------- Soft IRQs -----------------------------");
		mvprintw(lineno++, col, " IRQ Name                                Count     ElpTime   Avg(usecs)");
		irqinfop = globals->softirqp;
		if (irqinfop && (LINES_AVAIL > 3)) {
			irqtype = SOFTIRQ;
			foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
                                        	print_irq_entry_live, irq_sort_by_time, 0, &irqtype);
		}
	}
}

int
print_ldom_window()
{
	ldom_info_t *ldominfop;
	sched_info_t *gschedp;
	sched_stats_t *statp, *gstatp;
	uint64 ldom_total_time, total_time;
	int i;

	if (is_alive) {
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}

	print_global_header();	
	lineno++;

	gschedp = GET_ADD_SCHEDP(&globals->schedp);
	gstatp = &gschedp->sched_stats;
	total_time = gstatp->T_total_time;

	mvprintw (lineno++, 0, "Global CPU usage by NUMA node");
	mvprintw (lineno++, 0, "node  ncpu      Busy     sys     usr     irq    idle   steal");
	for (i=0; i<MAXLDOMS; i++) {
		ldominfop = GET_LDOMP(&globals->ldom_hash, i);
		statp = &ldominfop->sched_stats;
		ldom_total_time = statp->T_total_time;

		if (ldom_total_time && LINES_AVAIL) {
			mvprintw (lineno++, 0, "%4d [%3d] : %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
				i,
                                ldominfop->ncpus,
                                (statp->T_run_time * 100.0) / ldom_total_time,
                                (statp->T_sys_time * 100.0) / ldom_total_time,
                                (statp->T_user_time * 100.0) / ldom_total_time,
                                (statp->T_irq_time * 100.0) / ldom_total_time,
                                (statp->T_idle_time * 100.0) / ldom_total_time,
                                (statp->T_stealtime * 100.0) / ldom_total_time);
		}
	}

	if (LINES_AVAIL) 	
		mvprintw (lineno++, 0, "Total      : %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
                                (gstatp->T_run_time * 100.0) / total_time,
                                (gstatp->T_sys_time * 100.0) / total_time,
                                (gstatp->T_user_time * 100.0) / total_time,
                                (gstatp->T_irq_time * 100.0) / total_time,
                                (gstatp->T_idle_time * 100.0) / total_time,
				(gstatp->T_stealtime * 100.0) / total_time);

	return 0;
}

int
print_select_cpu_window()
{
	cpu_info_t *cpuinfop;
	hc_info_t *hcinfop;
	irq_info_t *irqinfop;
	sched_info_t *cschedp;
	sched_stats_t *cstatp;
	uint64 cpu_total_time;
	print_pc_args_t print_pc_args;
	int nsym=1;
	int irqtype;
	int irqheader_lineno;
	int saved_lineno;

        if (is_alive) {
                update_cpu_times(end_time);
                calc_global_cpu_stats(globals, NULL);
        }

	print_top_line();
	lineno++;

	cpuinfop = FIND_CPUP(globals->cpu_hash, curcpu);
	if (cpuinfop == NULL) {
		mvprintw (lineno++, col, "*** No Activity Found for CPU %d", curcpu);
		return 0;
	}

	mvprintw (lineno++, col, "cpu      Busy     sys     usr     irq    idle   steal");

	cschedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
	cstatp = &cschedp->sched_stats;
	cpu_total_time = cstatp->T_total_time;

	mvprintw (lineno++, col, "%3d:  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
		curcpu,
		(cstatp->T_run_time * 100.0) / cpu_total_time,
		(cstatp->T_sys_time * 100.0) / cpu_total_time,
		(cstatp->T_user_time * 100.0) / cpu_total_time,
                (cstatp->T_irq_time * 100.0) / cpu_total_time,
                (cstatp->T_idle_time * 100.0) / cpu_total_time,
                (cstatp->T_stealtime * 100.0) / cpu_total_time);

	if (cschedp && msr_flag && (LINES_AVAIL > 2))
		live_print_msr_stats(&cschedp->sched_stats, 1);

	lineno++;
	hcinfop = cpuinfop->hcinfop;
	print_pc_args.hcinfop = hcinfop;
	print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = NULL;
	if (hcinfop && hcinfop->pc_hash) {
		mvprintw (lineno++, 0, "------------------------- Top Hardclock Functions ---------------------------");
	        mvprintw (lineno++, 0, "   Count     Pct  State  Function");
        	foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc, pc_sort_by_count, 5, (void *)&print_pc_args);
	}

	if ((LINES_AVAIL > 3) && hcinfop &&  hcinfop->hc_stktrc_hash ) {
		lineno++;
		mvprintw (lineno++, 0, "--------------------- Top System Hardclock Stack Traces ---------------------");
		mvprintw (lineno++, 0, "   count  wait%%  Stack trace");
		foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, print_hc_stktrc_live, stktrc_sort_by_cnt, 5, (void *)hcinfop);
	}

	if (LINES_AVAIL > 3) {
		irqheader_lineno = lineno;
		lineno++;
		col=0;
		mvprintw(lineno++, col, "------------------------------- Hard IRQs -----------------------------");
		mvprintw(lineno++, col, " IRQ Name                                Count     ElpTime    Avg(usec)");
		irqinfop = cpuinfop->irqp;
		if (irqinfop) {
			irqtype = HARDIRQ;
			foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
					print_irq_entry_live, irq_sort_by_time, MIN(LINES_AVAIL, 5), &irqtype);
		}

		saved_lineno = lineno;
		lineno = irqheader_lineno+1;
		col=72;
		if (COLS > 146) {
			mvprintw(lineno++, col, "------------------------------- Soft IRQs -----------------------------");
			mvprintw(lineno++, col, " IRQ Name                                Count     ElpTime    Avg(usec)");
			irqinfop = cpuinfop->softirqp;
			if (irqinfop) {
				irqtype = SOFTIRQ;
				foreach_hash_entry((void **)irqinfop->irq_entry_hash, IRQ_HSIZE,
					print_irq_entry_live, irq_sort_by_time, MIN(LINES_AVAIL, 5), &irqtype);
			}
		}

		lineno = MAX(lineno, saved_lineno);
	}

	col=0;
	/* the following only works for live analysis */
	if (is_alive && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw (lineno++, 0, "----------------------- Top Tasks by Hardclock Count ------------------------");
		mvprintw (lineno++, 0, "   Count    USER     SYS    INTR      %s  Command", tlabel);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           print_pid_hc_live, pid_sort_by_totalhc, LINES_AVAIL, NULL);
	}

	return 0;
}
	
int
print_select_ldom_window()
{
	cpu_info_t *cpuinfop;
	ldom_info_t *ldominfop;
	sched_info_t *cschedp;
	sched_stats_t *cstatp, *gstatp, *lstatp;
	uint64 cpu_total_time, total_time, ldom_total_time;
	int i, lcpu1,lcpu2;
	pcpu_info_t *pcpuinfop;
	cpu_info_t *cpu1infop, *cpu2infop;
	uint64 HT_total_time;

	lineno=0;	
	print_ldom_window();	

	lineno++;
	col=0;

	mvprintw (lineno++, col, "----------------- Node %2d CPU Stats -----------------", curldom);
	mvprintw (lineno++, col, "cpu      Busy     sys     usr     irq    idle   steal");

	for (i=0; i<MAXCPUS; i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			if (LINES_AVAIL == 0) break;
			if (cpuinfop->ldom == curldom) {
				cschedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
				cstatp = &cschedp->sched_stats;
				cpu_total_time = cstatp->T_total_time;

				mvprintw (lineno++, col, "%3d:  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
					i,
                               	 	(cstatp->T_run_time * 100.0) / cpu_total_time,
                               	 	(cstatp->T_sys_time * 100.0) / cpu_total_time,
                                	(cstatp->T_user_time * 100.0) / cpu_total_time,
                                	(cstatp->T_irq_time * 100.0) / cpu_total_time,
                                	(cstatp->T_idle_time * 100.0) / cpu_total_time,
                                	(cstatp->T_stealtime * 100.0) / cpu_total_time);

			}
		}
	}
		
	ldominfop = GET_LDOMP(&globals->ldom_hash, curldom);
	lstatp = &ldominfop->sched_stats;
	ldom_total_time = lstatp->T_total_time;

	if (ldom_total_time && LINES_AVAIL) {
		mvprintw (lineno++, col, "Tot:  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
                       	(lstatp->T_run_time * 100.0) / ldom_total_time,
                       	(lstatp->T_sys_time * 100.0) / ldom_total_time,
			(lstatp->T_user_time * 100.0) / ldom_total_time,
			(lstatp->T_irq_time * 100.0) / ldom_total_time,
                      	(lstatp->T_idle_time * 100.0) / ldom_total_time,
                      	(lstatp->T_stealtime * 100.0) / ldom_total_time);

	}

	if (globals->HT_enabled && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw (lineno++, col, "---------- Node %2d HT Stats ----------", curldom);
		mvprintw (lineno++, col, "   PCPU     didle  busy1  busy2  dbusy");
		for (i = 0; i < MAXCPUS; i++) {
			if (LINES_AVAIL == 0) break;
			if (pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i)) {
				lcpu1 = pcpuinfop->lcpu1;
				lcpu2 = pcpuinfop->lcpu2;
				cpu1infop = FIND_CPUP(globals->cpu_hash, lcpu1);
				cpu2infop = FIND_CPUP(globals->cpu_hash, lcpu2);

				if (cpu1infop->ldom == curldom) {
					HT_total_time = pcpuinfop->idle_time + cpu1infop->lcpu_busy + cpu2infop->lcpu_busy + pcpuinfop->busy_time;

					if (HT_total_time == 0) {
						/* if NO time logged, assume HT pair is idle the entire time */
						HT_total_time = globals->total_secs;
						pcpuinfop->idle_time = globals->total_secs;
					}

					mvprintw (lineno++, col, "[%3d %3d]: %5.1f%% %5.1f%% %5.1f%% %5.1f%%",
							lcpu1, lcpu2,
							(pcpuinfop->idle_time * 100.0) / HT_total_time,
							(cpu1infop->lcpu_busy * 100.0) / HT_total_time,
							(cpu2infop->lcpu_busy * 100.0) / HT_total_time,
							(pcpuinfop->busy_time * 100.0) / HT_total_time);

				}
			}
		}

	}

	return 0;
}
	
int
print_select_dsk_window()
{
	dev_info_t *devinfop; 

	if (is_alive) {
	        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
                foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devname, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
	}

	print_top_line();
	lineno++;
	mvprintw(lineno++, 0, "*** I/O for device 0x%08x ***", curdev);
	lineno++;

	PRINT_IODETAIL_HDR("device    ");
	col=13;
	if (devinfop = FIND_DEVP(DEVHASH(globals, curdev), curdev)) {
		calc_dev_totals(devinfop, NULL);
		print_iostats_dev_live(devinfop, NULL);
	} else { 
		mvprintw(lineno++, col, "*** No Activity Found for device 0x%08x ***", curdev);
		return 0;
	}

	/* we can only print the Top Tasks if we are analyzing live systems */	
        if (is_alive && (LINES_AVAIL>2) && globals->pid_hash) {
                lineno++;
		mvprintw(lineno++, 0, "-------- Top Tasks Performing I/O to device /dev/%s ---------", devinfop->devname);
                mvprintw(lineno++, 0, "     Cnt      r/s      w/s    KB/sec    Avserv      %s  Process", tlabel);
                foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_iosum_live,  pid_sort_by_iocnt, LINES_AVAIL, NULL);
        } else if (!is_alive) {
                lineno++;
		mvprintw(lineno++, 0, "**** Cannot print Top Tasks for this device when analyzing KI dump ****");
	}
}



int
live_dkpid_runtime_summary(void *arg1, void *arg2)
{
        dkpid_info_t *dkpidp = (dkpid_info_t *)arg1;
        live_pid_runtime_summary(dkpidp->pidp, NULL);
}

int
live_dkpid_io_summary(void *arg1, void *arg2)
{
        dkpid_info_t *dkpidp = (dkpid_info_t *)arg1;
	print_pid_iosum_live(dkpidp->pidp, NULL);
}

int
print_select_docker_window()
{
	uint64 dockid;
	docker_info_t *dockerp;

	print_global_header();
	lineno++;

	if (globals->docker_hash == NULL) {
		mvprintw(lineno++, 0, "*** Dockers not in use on this System ***");
		return 0;
	}

	if (is_alive) {
		update_perpid_sched_stats();
		calc_global_cpu_stats(globals, NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_docker_pid_totals, NULL, 0, NULL);
		dockerp = GET_DOCKERP(&globals->docker_hash, 0);
		dockerp->name = "system";
	}

	if ((dockerp = FIND_DOCKERP(globals->docker_hash, curdockid)) == NULL) {
		mvprintw (lineno++, 0, "Container Not Found ***");
	} else {
		mvprintw (lineno++, 0, "Container ID: %012llx  Name: %s", dockerp->ID, dockerp->name);
	}

	npid = (LINES_AVAIL / 2) - 3;
	if (LINES_AVAIL > 3) {
		lineno++;
		mvprintw (lineno++,0,"Top Tasks sorted by CPU time");
		mvprintw (lineno++,0,"    %s  busy%%   sys%%  user%%  runq%%   slp%%   stl%%", tlabel);
		if (COLS > 100) printw ("     IOPS     MB/s");
		if (COLS > 120) printw ("   NetOPS  NetMB/s");
		printw ("  Command");
		foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ, live_dkpid_runtime_summary, dkpid_sort_by_runtime, npid, NULL);
	}

        if (LINES_AVAIL > 3) {
                lineno++;
                mvprintw(lineno++, 0, "Top Tasks sorted by I/O");
                mvprintw(lineno++, 0, "     Cnt      r/s      w/s    KB/sec    Avserv      %s  Process", tlabel);
                foreach_hash_entry((void **)dockerp->dkpid_hash, PID_HASHSZ, live_dkpid_io_summary,  dkpid_sort_by_iocnt, LINES_AVAIL, NULL);
        }
	return 0;
}

int
print_cpu_window()
{
	cpu_info_t *cpuinfop;
	ldom_info_t *ldominfop;
	sched_info_t *gschedp, *cschedp;
	sched_stats_t *cstatp, *gstatp, *lstatp;
	uint64 cpu_total_time, total_time, ldom_total_time;
	int ldoms_columns, lcpus_per_ldom;
	int ldom_lineno[MAXLDOMS] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
	int ldom_colno[MAXLDOMS] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	int i;

	if (is_alive) {
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}
	
	print_global_header();	

	lineno++;
	mvprintw (lineno++, 0, "---------- Global CPU usage by CPU ----------");
	lineno++;

	/* determine the starting lineno and colno for each ldom */
	ldoms_columns = COLS / 26;
	if (globals->nldom == 0) globals->nldom = 1;
	lcpus_per_ldom = globals->nlcpu / globals->nldom;

	for (i = 0; i < globals->nldom; i++) {
		ldom_lineno[i] = lineno + ((4 + lcpus_per_ldom) * (i / ldoms_columns));
		ldom_colno[i] = (i % ldoms_columns ) * 27;
	}

	gschedp = GET_ADD_SCHEDP(&globals->schedp);
	gstatp = &gschedp->sched_stats;
	total_time = gstatp->T_total_time;

	for (i=0; i<globals->nldom; i++) {
		lineno=ldom_lineno[i];
		col=ldom_colno[i];

		if (((col+25) < COLS) && LINES_AVAIL>2) {
			mvprintw (lineno++, col, "-------- Node %2d --------", i);
			mvprintw (lineno++, col, " cpu   sys  usr  irq  idl");
			ldom_lineno[i]= lineno;
		}
	}

	for (i=0; i<MAXCPUS; i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			cschedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
			cstatp = &cschedp->sched_stats;
			cpu_total_time = cstatp->T_total_time;

			lineno=ldom_lineno[cpuinfop->ldom];
			col=ldom_colno[cpuinfop->ldom];

			if (((col+26) < COLS) && LINES_AVAIL) {
				mvprintw (lineno++, col, "%4d: %3.0f%% %3.0f%% %3.0f%% %3.0f%%",
					i,
                               	 	(cstatp->T_sys_time * 100.0) / cpu_total_time,
                                	(cstatp->T_user_time * 100.0) / cpu_total_time,
                                	(cstatp->T_irq_time * 100.0) / cpu_total_time,
                                	(cstatp->T_idle_time * 100.0) / cpu_total_time);

				ldom_lineno[cpuinfop->ldom] = lineno;
			}
		}
	}

	for (i=0; i<globals->nldom; i++) {
		ldominfop = GET_LDOMP(&globals->ldom_hash, i);
		lstatp = &ldominfop->sched_stats;
		ldom_total_time = lstatp->T_total_time;

		if (ldom_total_time) {
			lineno=ldom_lineno[i];
			col=ldom_colno[i];
			if (((col+26) < COLS) && LINES_AVAIL) {
				mvprintw (lineno++, col, " Tot: %3.0f%% %3.0f%% %3.0f%% %3.0f%%",
                               	 	(lstatp->T_sys_time * 100.0) / ldom_total_time,
                                	(lstatp->T_user_time * 100.0) / ldom_total_time,
                                	(lstatp->T_irq_time * 100.0) / ldom_total_time,
                                	(lstatp->T_idle_time * 100.0) / ldom_total_time);

			}
		}
	}
}

int
print_ht_window()
{
	int i, lcpu1,lcpu2, ldom;
	pcpu_info_t *pcpuinfop;
	cpu_info_t *cpu1infop, *cpu2infop;
	uint64 HT_total_time, total_double_idle=0, total_lcpu1_busy=0, total_lcpu2_busy=0, total_double_busy=0;
	int ldoms_columns, pcpus_per_ldom;
	int ldom_lineno[MAXLDOMS] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
	int ldom_colno[MAXLDOMS] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	print_global_header();	
	lineno++;
	mvprintw (lineno++, col, "-------- HyperThread CPU usage -------");

	if (globals->HT_enabled) {
		if (is_alive) calc_global_HT_stats(globals, NULL);
		mvprintw (lineno++, col, "            didle  busy1  busy2  dbusy");
		mvprintw (lineno++, col, "Total:     %5.1f%% %5.1f%% %5.1f%% %5.1f%%",
			globals->ht_total_time ? (globals->ht_double_idle * 100.0) / globals->ht_total_time : 0,
			globals->ht_total_time ? (globals->ht_lcpu1_busy * 100.0) / globals->ht_total_time : 0,
			globals->ht_total_time ? (globals->ht_lcpu2_busy * 100.0) / globals->ht_total_time : 0,
			globals->ht_total_time ? (globals->ht_double_busy * 100.0) / globals->ht_total_time : 0);
		lineno++;

		/* determine the starting lineno and colno for each ldom */
		ldoms_columns = COLS / 26;
		if (globals->nldom == 0) globals->nldom = 1;
		pcpus_per_ldom = globals->ncpu / globals->nldom;

		for (i = 0; i < globals->nldom; i++) {
			ldom_lineno[i] = lineno + ((4 + pcpus_per_ldom) * (i / ldoms_columns));
			ldom_colno[i] = (i % ldoms_columns ) * 40;
		}

		for (i=0; i<globals->nldom; i++) {
			lineno=ldom_lineno[i];
			col=ldom_colno[i];
			
			if (((col+38) < COLS) && LINES_AVAIL >2) {
				mvprintw (lineno++, col, "-------------- Node %2d ---------------", i);
				mvprintw (lineno++, col, "   PCPU     didle  busy1  busy2  dbusy");
				ldom_lineno[i] = lineno;
			}
		}

		for (i = 0; i < MAXCPUS; i++) {
			if (pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i)) {
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

				lineno=ldom_lineno[cpu1infop->ldom];
				col=ldom_colno[cpu1infop->ldom];

				if (((col+38) < COLS) && LINES_AVAIL) {
					mvprintw (lineno++, col, "[%3d %3d]: %5.1f%% %5.1f%% %5.1f%% %5.1f%%",
						lcpu1, lcpu2,
						(pcpuinfop->idle_time * 100.0) / HT_total_time,
						(cpu1infop->lcpu_busy * 100.0) / HT_total_time,
						(cpu2infop->lcpu_busy * 100.0) / HT_total_time,
						(pcpuinfop->busy_time * 100.0) / HT_total_time);

					ldom_lineno[cpu1infop->ldom] = lineno;
				}
			}
		}
	} else {
		mvprintw (lineno++, col, "*** HT is not enabled on this system ***");
	}

	return 0;
}

int
live_print_fobj_physio(void *arg1, void *arg2)
{
	fileobj_t *fobjinfop = (fileobj_t *)arg1;
	iostats_t *iostatsp;
	int rw, col = 0;

	mvprintw (lineno, col, "0x%016llx", fobjinfop->FOBJ);
	col = 20;
	for (rw = IOTOT; rw >= IORD; rw--) {
		iostatsp = &fobjinfop->piostats[rw];
		mvprintw (lineno, col, "%7.0f %7.0f %7d",
			iostatsp->compl_cnt / globals->total_secs*1.0,
			(iostatsp->sect_xfrd/2)/globals->total_secs*1.0,
		iostatsp->sect_xfrd*512 / MAX(iostatsp->compl_cnt, 1));
		col+=25;
		if ((COLS - col) < 75) break;
	}

	mvprintw (lineno++, col, "%s", fobjinfop->filename);
}


int
print_file_window()
{
	int cnt;

	if (is_alive) {
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}
	
	print_global_header();	
	lineno++;

	if (globals->fobj_hash) {
		cnt = (LINES_AVAIL - 8)/2;

		col = 0;
		mvprintw (lineno++, col, "***  Top Files sorted by Logical I/O  ***");
		lineno++;
                mvprintw (lineno, col, "                    -------  Total  -------");
		col+=45;
                if ((COLS - col) > 75) {
			mvprintw (lineno, col, "-------  Write  --------");
			col+=25;
		}
                if ((COLS - col) > 75) {
			mvprintw (lineno, col, "--------  Read  --------");
		}
		lineno++;

		col = 0;
                mvprintw (lineno, col, "Object                 IO/s    KB/s  AvIOsz ");
		col+=45;
	        if ((COLS - col) > 75) {
			mvprintw(lineno, col, "   IO/s    KB/s  AvIOsz");
			col += 25;
		}
	        if ((COLS - col) > 75) {
			mvprintw(lineno, col ,"   IO/s    KB/s  AvIOsz");
		}
		lineno++;
                foreach_hash_entry((void **)globals->fobj_hash, FOBJ_HSIZE, live_print_fobj_logio,
                           (int (*)())fobj_sort_by_logio, cnt, NULL);
		lineno++;

		col = 0;
		mvprintw (lineno++, col, "***  Top Files sorted by Physical I/O  ***");
		lineno++;
                mvprintw (lineno, col, "                    -------  Total  -------");
		col+=45;
                if ((COLS - col) > 75) {
			mvprintw (lineno, col, "-------  Write  --------");
			col+=25;
		}
                if ((COLS - col) > 75) {
			mvprintw (lineno, col, "--------  Read  --------");
		}
		lineno++;

		col = 0;
                mvprintw (lineno, col, "Object                 IO/s    KB/s  AvIOsz ");
		col+=45;
	        if ((COLS - col) > 75) {
			mvprintw(lineno, col, "   IO/s    KB/s  AvIOsz");
			col += 25;
		}
	        if ((COLS - col) > 75) {
			mvprintw(lineno, col ,"   IO/s    KB/s  AvIOsz");
		}
		lineno++;
                foreach_hash_entry((void **)globals->fobj_hash, FOBJ_HSIZE, live_print_fobj_physio,
                           (int (*)())fobj_sort_by_physio, cnt, NULL);

        } else {
		mvprintw(lineno++, 0,"-------------------------- Global File Activity ------------------------------");
		mvprintw (lineno++, 0,"System Call Name                 Count     Rate     ElpTime        Avg        Max    Errs");
        	if (COLS > 95) printw ("    AvSz     KB/s");
		foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, print_fdata_live,
                   	(int (*)())fdata_sort_by_syscalls,
                   	LINES_AVAIL+globals->nlcpu+10, NULL);
		return 0;
	}
}

int
live_file_print_fdev(void *arg1, void *arg2)
{
        filedev_t *fdevinfop = (filedev_t *)arg1;
        char devstr[16];
        iostats_t *statp;

	col=0;
        statp = &fdevinfop->stats[0];

	sprintf(devstr, "0x%08x", fdevinfop->FDEV);
	mvprintw(lineno, col, "%s", devstr);
	col+=13;
	print_iostats_totals_live(statp);
	lineno++;
}


int
print_select_file_window()
{

	fileobj_t *fobjinfop; 
	fstats_t *fstatsp;
	int rw, ndev;

	print_global_header();
	lineno++;

	fobjinfop = FIND_FOBJP(globals->fobj_hash, curfaddr);
	if (fobjinfop == NULL) return 0;

	mvprintw (lineno++, 0, "Fileobj: 0x%016llx  Filename: %s", fobjinfop->FOBJ, fobjinfop->filename);
	lineno++;
	mvprintw (lineno++, 0, "*** Logical I/O ***");
	lineno++;
        mvprintw (lineno++, 0, "-------  Total  ------- -------  Write  -------- --------  Read  --------");
        mvprintw (lineno++, 0, "   IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz");

	col = 0;
	for (rw = IOTOT; rw >= IORD; rw--) {
		fstatsp = &fobjinfop->liostats[rw];
		mvprintw (lineno, col, "%7.0f %7.0f %7d",
			fstatsp->cnt / globals->total_secs*1.0,
			(fstatsp->bytes/1024)/globals->total_secs*1.0,
			fstatsp->bytes / MAX(fstatsp->cnt, 1));
		col+=25;
	}
	lineno++; lineno++;
	mvprintw (lineno++, 0, "*** Physical I/O ***");
	lineno++;
	PRINT_IODETAIL_HDR("disknum   ");
	ndev = LINES_AVAIL-1;
	if (fobjinfop->fdev_hash) {
		foreach_hash_entry((void **)fobjinfop->fdev_hash, FDEV_HSIZE, live_file_print_fdev,
				(int (*)())fdev_sort_by_physio, ndev, NULL);
	}
}

int
futex_print_pids_detail_live(void *arg1, void *arg2)
{
	futex_pids_t    *fpidp = arg1;
	pid_info_t	*pidp, *wpidp;
	int y, x;

	if (LINES_AVAIL && (fpidp->cnt == 0)) return 0;

	pidp = GET_PIDP(&globals->pid_hash, fpidp->lle.key);
	mvprintw (lineno++, col, "    PID=%6lld                %7d %7d %10d   %7.2f %11.3f",
			fpidp->lle.key,
			fpidp->cnt,
			fpidp->n_eagain,
			fpidp->n_etimedout,
			(fpidp->ret_total* 1.0)/fpidp->cnt,
			SECS(fpidp->total_time));
	if (COLS > 102) {
		printw (" %11.6f %11.6f",
			SECS(fpidp->total_time)/fpidp->cnt,
			SECS(fpidp->max_time));
	}

	if (pidp->cmd) printw (" %s", pidp->cmd);
	if (pidp->hcmd) printw (" {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printw (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);


	if (LINES_AVAIL && fpidp->n_othererr) 
		mvprintw(lineno++, col,"    %-27s %7d",tab,"Other Errors", fpidp->n_othererr);
}
			

int
futex_print_ops_detail_live(void *arg1, void *arg2)
{
	futex_op_t	*fopsp = arg1;
	gbl_futex_info_t *gfp = arg2;
	pid_info_t	*wpidp;
	int		pid_cnt = 0, nlines;

	if ((LINES_AVAIL == 0) || (fopsp->cnt == 0)) return 0;

	mvprintw(lineno++, col, "  %-27s %7d %7d %10d   %7.2f %11.3f",
		(fopsp->lle.key & FUTEX_PRIVATE_FLAG) ? futex_privopcode_name[fopsp->lle.key & FUTEX_CMD_MASK] : futex_opcode_name[fopsp->lle.key & FUTEX_CMD_MASK],
		fopsp->cnt,
		fopsp->n_eagain,
		fopsp->n_etimedout,
		(fopsp->ret_total* 1.0)/fopsp->cnt,
		SECS(fopsp->total_time));

	if (COLS > 102) {
		printw(" %11.6f %11.6f",
			SECS(fopsp->total_time)/fopsp->cnt,
			SECS(fopsp->max_time));
	}

	nlines = MIN(LINES_AVAIL,10);
	if (fopsp->pids_hash) {
		foreach_hash_entry((void **)fopsp->pids_hash,FUTEXPID_HSIZE,
                        (int (*)(void *, void *))hash_count_entries,
                        NULL, 0, &pid_cnt);

		if (nlines && pid_cnt) {
			foreach_hash_entry((void **)fopsp->pids_hash,FUTEXPID_HSIZE,
				futex_print_pids_detail_live,
				futex_pidsort_by_time, nlines, NULL);
		}
	} else if (fopsp->max_waker > 0) {
		wpidp = GET_PIDP(&globals->pid_hash, fopsp->max_waker);
		printw ("  %-6d", fopsp->max_waker);
		if (wpidp->cmd) printw (" %s", wpidp->cmd);
		if (wpidp->hcmd) printw (" {%s}", wpidp->hcmd);
		if (wpidp->thread_cmd) printw (" (%s)", wpidp->thread_cmd);
		if (wpidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(wpidp->dockerp))->ID);
	} else if (fopsp->max_waker == -1) {
		printw ("  ICS");
	}

	if (LINES_AVAIL && fopsp->n_othererr) {
		mvprintw(lineno++, col, "Other Errors", fopsp->n_othererr);
	}

	return 0;
}

int
print_futex_info_live(void *arg1, void *arg2)
{
	pid_futex_info_t *pfutexp = arg1;
	pid_info_t       *pidp    = arg2;

	if ((LINES_AVAIL == 0) || (pfutexp->cnt == 0)) return 0;

	mvprintw(lineno++, col, "0x%-27llx %7d   %26s %11.3f",
			pfutexp->addr,
			pfutexp->cnt,
			"-",
			SECS(pfutexp->total_time));

	if (COLS > 102) {
		printw(" %11.6f %11.6f",
			SECS(pfutexp->total_time)/pfutexp->cnt,
			SECS(pfutexp->max_time));
	}

	foreach_hash_entry((void **)pfutexp->ops_hash, FUTEXOP_HSIZE, futex_print_ops_detail_live, futexops_sort_by_op, 0, pidp);
}

int 
print_pidfutex_window()
{
	int futex_cnt = 0;	
	pid_info_t *pidp;
	pidp = GET_PIDP(&globals->pid_hash, curpid);	

	print_top_line();
	lineno++;
	mvprintw (lineno++,0, "PID:  %6d", pidp->PID);

	if (pidp->cmd) printw (" %s", pidp->cmd);
	if (pidp->hcmd) printw ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printw ("  (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printw (" <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);

	foreach_hash_entry((void **)pidp->futex_hash, FUTEX_HSIZE, hash_count_entries, NULL, 0, &futex_cnt);

	if (futex_cnt) {
		mvprintw (lineno++, col, "  TGID: %d", pidp->tgid);
		lineno++;
		mvprintw (lineno++, 0, "Mutex Addr                      Count  EAGAIN  ETIMEDOUT  AvRetVal     ElpTime");
		if (COLS > 102) printw ("         Avg         Max  Max_Waker");
		foreach_hash_entry((void **)pidp->futex_hash, FUTEX_HSIZE, print_futex_info_live, futex_sort_by_time, LINES_AVAIL/2, NULL);
	} else {
		mvprintw (lineno++, 0, "*** No FUTEX activity for this PID detected");
	}
	return 0;
}

int
gbl_futex_print_detail_live(void *arg1, void *arg2)
{
	gbl_futex_info_t        *gfp = arg1;

	if (gfp->cnt == 0) {
		mvprintw(lineno++, col, "*** No Activity Found for Futex 0x%llx ***", gfp->addr);
		return 0;
	} else { 
		mvprintw (lineno++, col, "%-29s %7d %7d %10d   %7.2f %11.3f",
			"ALL",
                        gfp->cnt,
                        gfp->n_eagain,
                        gfp->n_etimedout,
                        (gfp->ret_total* 1.0)/gfp->cnt,
                        SECS(gfp->total_time));

		if (COLS > 102) {
			printw(" %11.6f %11.6f",
				SECS(gfp->total_time)/gfp->cnt,
				SECS(gfp->max_time));
		}

		foreach_hash_entry((void **)gfp->ops_hash, FUTEXOP_HSIZE,
			futex_print_ops_detail_live,
			futexops_sort_by_op, LINES_AVAIL, gfp);
	}
}

int
gbl_futex_print_live(void *arg1, void *arg2)
{
	gbl_futex_info_t        *gfp = arg1;

	if (gfp->cnt == 0) return 0;

	mvprintw (lineno++, col, "0x%-16llx %8d %7d %7d %10d   %7.2f %11.3f",
			gfp->addr,
			FUTEX_TGID(gfp->lle.key),
                        gfp->cnt,
                        gfp->n_eagain,
                        gfp->n_etimedout,
                        (gfp->ret_total* 1.0)/gfp->cnt,
                        SECS(gfp->total_time));

	if (COLS > 102) {
		printw(" %11.6f %11.6f",
			SECS(gfp->total_time)/gfp->cnt,
			SECS(gfp->max_time));
	}
}

int
print_select_futex_window()
{
	uint64 key;
	gbl_futex_info_t *gfp;

	print_global_header();
	lineno++;

	key = FUTEX_KEY(curtgid, curfaddr);
	mvprintw(lineno++, 0, "-------------------- Futex 0x%llx ", curfaddr);
	if (curtgid) printw("  TGID: %d", curtgid);
	printw (" --------------------");
	if (gfp = FIND_GFUTEXP((void **)globals->futex_hash, key)) {
		mvprintw(lineno++, 0, "Operation                       Count  EAGAIN  ETIMEDOUT  AvRetVal     ElpTime");
		if (COLS > 102) {
			printw ("         Avg         Max");
		}
		gbl_futex_print_detail_live(gfp, NULL);
	} else {
		mvprintw(lineno, col, "*** No Activity Found for Futex 0x%llx ***", curfaddr);
	}
	
}

int
print_futex_window()
{
	print_global_header();
	lineno++;
	mvprintw(lineno++, 0, "--------------------------- Global Futex Activity --------------------------------");
	mvprintw(lineno++, 0, "Futex Key              TGID   Count  EAGAIN  ETIMEDOUT  AvRetVal     ElpTime");
	if (COLS > 102) {
		printw ("         Avg         Max");
	}
	foreach_hash_entry((void **)globals->futex_hash ,GFUTEX_HSIZE, gbl_futex_print_live,
                		futex_gblsort_by_cnt, LINES_AVAIL, NULL);
	return 0;
}

int
print_net_window()
{
	int nlines;
	char *hcol1 = "Syscalls";

	if (is_alive) {
		update_cpu_times(end_time);
		calc_global_cpu_stats(globals, NULL);
	}

	if (IS_WINKI) hcol1 = "Requests";
	
	print_global_header();	
	lineno++;

	mvprintw(lineno++, 0,"--------------------------- Top IP->IP dataflows -----------------------------");
        mvprintw(lineno++, 0,"%s      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection", hcol1);
	nlines = LINES_AVAIL / 2;
        foreach_hash_entry2((void **)globals->ipip_hash, IPIP_HASHSZ, print_ipip_live,
                           ipip_sort_by_syscalls, nlines, NULL);
	lineno++;
	
	mvprintw(lineno++, 0,"---------------------------- Top Sockets in Use ------------------------------");
	if (IS_WINKI) {
        	mvprintw(lineno++, 0,"%s      Rd/s      RdKB/s      Wr/s      WrKB/s     LastPid  Connection", hcol1);
	}
        foreach_hash_entry((void **)globals->sdata_hash, FDATA_HASHSZ, print_sdata_live,
                            (int (*)())sdata_sort_by_syscalls,
                            LINES_AVAIL, NULL);

	return 0;
}

int 
print_wait_window()
{ 
	sched_info_t *schedp;
	int nlines; 

	print_global_header();	
	
	if (IS_FTRACE) {
		lineno++;
		mvprintw(lineno++, 0, "*** No Sleep Functions with Ftrace ***");
		return 0;
	}

	schedp = globals->schedp;
	if (globals->slp_hash && schedp) {
		lineno++;
		mvprintw (lineno++, 0, "---------------------------- Top Wait Functions -----------------------------");
		mvprintw (lineno++, 0, "   Count     SlpTime  Msec/Slp  MaxMsecs  Func");
		nlines = LINES_AVAIL / 2;
		foreach_hash_entry_l((void **)globals->slp_hash, SLP_HSIZE, print_slp_info_live, slp_sort_by_time, nlines, &schedp->sched_stats);
	}

	if ((LINES_AVAIL > 3) && globals->stktrc_hash && schedp) {
		lineno++;
		mvprintw (lineno++, 0, "-------------------------- Top Wait Stack Traces ----------------------------");
		mvprintw (lineno++, 0, "   count  wait%%    avwait   Stack trace");
		foreach_hash_entry((void **)globals->stktrc_hash, STKTRC_HSIZE, print_stktrc_info_live, stktrc_sort_by_slptime, LINES_AVAIL, (void *)schedp);
	}
		
}

int
print_hc_window()
{
	int nlines;
	hc_info_t *hcinfop = globals->hcinfop;
	print_pc_args_t print_pc_args;
	print_pc_args.hcinfop = hcinfop;
	print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = NULL;

	print_global_header();	
	lineno++;

	if (IS_FTRACE) {
		lineno++;
		mvprintw(lineno++, 0, "*** No Hardclock Traces with Ftrace ***");
		return 0;
	}

	if ((hcinfop == NULL) || (hcinfop->total == 0)) {
		mvprintw (lineno++, col, "*** No Profiling Activity Found ***");
		return 0;
	}

	mvprintw(lineno++, col, "---------- Global Profiling Activity ----------");
	mvprintw(lineno++, col, "  Count   USER%%    SYS%%   INTR%%   IDLE%%");
	mvprintw(lineno++, col, "%7d %6.2f%% %6.2f%% %6.2f%% %6.2f%%", 
			hcinfop->total,
                        (hcinfop->cpustate[HC_USER]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_SYS]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_INTR]*100.0)/hcinfop->total,
                        (hcinfop->cpustate[HC_IDLE]*100.0)/hcinfop->total);
	
	lineno++;
	nlines = LINES_AVAIL/3;
	if ((hcinfop->pc_hash) && (LINES_AVAIL > 3)) {
		mvprintw(lineno++, col, "------------- Top Kernel Functions -------------");
		mvprintw(lineno++, col, "   Count     Pct  State  Function");
		foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc, pc_sort_by_count, nlines-2, (void *)&print_pc_args);
	}

	nlines = LINES_AVAIL/2;
	if ((hcinfop->hc_stktrc_hash) && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw(lineno++, col, "----------- Top Kernel Stack Traces ------------");
		mvprintw(lineno++, col, "   Count     Pct  Stack trace");
		foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, print_hc_stktrc_live, stktrc_sort_by_cnt, nlines-3, (void *)hcinfop);
	}

	if (!IS_FTRACE && (LINES_AVAIL > 3)) {
		lineno++;
		mvprintw(lineno++, 0, "----------------------- Top Tasks by Hardclock Count ------------------------");
		mvprintw(lineno++, 0, "   Count    USER     SYS    INTR        %s  Command", tlabel);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           print_pid_hc_live, pid_sort_by_totalhc, LINES_AVAIL, NULL);
	}
	
	return 0;
}

int
live_print_docker_totals(void *arg1, void *arg2)
{
	docker_info_t *dockerp = (docker_info_t *)arg1;
	sched_stats_t *statp = &dockerp->sched_stats;

	mvprintw (lineno++, col, "%012llx %12.6f %12.6f %12.6f %12.6f %12.6f", 
		dockerp->ID, 
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time),
		SECS(statp->T_irq_time),
                SECS(statp->T_runq_time));

	if (COLS > 100) printw (" %8.1f %8.1f",
		dockerp->iostats[IOTOT].compl_cnt / secs,
		((dockerp->iostats[IOTOT].sect_xfrd / 2.0)/1024.0) / secs);
	if (COLS > 120) printw (" %8.1f %8.1f",
		(dockerp->netstats.rd_cnt+dockerp->netstats.wr_cnt)/secs,
		((dockerp->netstats.rd_bytes+dockerp->netstats.wr_bytes)/(1024*1024))/secs);	
	if ((COLS > 180) && dockerp && dockerp->name) printw ("  %s", dockerp->name);

	return 0;
}


int
print_docker_window()
{
	docker_info_t *dockerp;

	print_global_header();	
	lineno++;

	if (globals->docker_hash == NULL) {
		mvprintw(lineno++, 0, "*** Dockers not in use on this System ***");
		return 0;
	}

	if (is_alive) {
		update_perpid_sched_stats();
		calc_global_cpu_stats(globals, NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_docker_pid_totals, NULL, 0, NULL);
		dockerp = GET_DOCKERP(&globals->docker_hash, 0);
		dockerp->name = "system";
	}

	mvprintw(lineno++, 0, "Container            busy          sys         user          irq         runq");
	if (COLS > 104) printw ("     IOPS     MB/s");
	if (COLS > 124) printw ("   NetOPS  NetMB/s");
	if (COLS > 180) printw ("  Name");

	foreach_hash_entry((void **)globals->docker_hash, DOCKER_HASHSZ, live_print_docker_totals, docker_sort_by_runtime, 0, NULL);

}

int
print_main_window()
{
	sched_info_t *gschedp;
	sched_stats_t *gstatp;
	uint64 total_time = 0;
	uint64 irq_time = 0;
	uint64 busy_time = 0;
	struct iostats *iostatsp;
	struct sd_stats_t *netstatp;
	double avinflt, avserv;

	if (is_alive) {
		update_cpu_times(end_time);
		update_perpid_sched_stats();
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
		if (globals->docker_hash) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_pid_cgroup, NULL, 0, NULL);
		calc_global_cpu_stats(globals, NULL);
		calc_io_totals(&globals->iostats[0], NULL);
	}

	print_global_header();	
	lineno++;

        gschedp = GET_ADD_SCHEDP(&globals->schedp);
        gstatp = &gschedp->sched_stats;
        total_time = gstatp->T_total_time;

	mvprintw (lineno++,0,"CPU  usr: %6.1f%%  sys: %6.1f%%   irq: %6.1f%%   idle: %6.1f%%  steal: %6.1f%%",
			(gstatp->T_user_time *100.0) / total_time,
			(gstatp->T_sys_time  *100.0) / total_time,
			(gstatp->T_irq_time  *100.0) / total_time,
			(gstatp->T_idle_time *100.0) / total_time,
			(gstatp->T_stealtime*100.0) / total_time);

	iostatsp = &globals->iostats[IOTOT];
	avserv = iostatsp->cum_ioserv/MAX(iostatsp->compl_cnt,1) / 1000000.0;
	avinflt = (iostatsp->cum_async_inflight + iostatsp->cum_sync_inflight) / (MAX(iostatsp->issue_cnt,1) * 1.0);

	mvprintw (lineno++,0,"DSK  ios: %7.1f  MBs: %7.1f  avsz: %7d  inflt: %7.1f  svctm: %7.3f",  
			iostatsp->compl_cnt/secs,
			(iostatsp->sect_xfrd/2048)/secs,
			(iostatsp->sect_xfrd/2)/MAX(iostatsp->compl_cnt,1),
			avinflt,
			avserv);

	mvprintw (lineno++,0, "NET  rds: %7.1f  rKB: %7.1f   wrs: %7.1f    wKB: %7.1f",
		globals->netstats.rd_cnt / secs,
                (globals->netstats.rd_bytes / 1024.0) / secs,
		globals->netstats.wr_cnt / secs,
                (globals->netstats.wr_bytes / 1024.0) / secs);

	if (LINES_AVAIL > 3) {
		lineno++;
		mvprintw (lineno++,0,"Top tasks sorted by CPU time");
		mvprintw (lineno++,0,"    %s  busy%%   sys%%  user%%  runq%%   slp%%   stl%%", tlabel);
		if (COLS > 100) printw ("     IOPS     MB/s");
		if (COLS > 120) printw ("   NetOPS  NetMB/s");
		printw ("  Command");
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, live_pid_runtime_summary, pid_sort_by_runtime, LINES_AVAIL+globals->nlcpu+10, NULL);
	}
	lineno++;
}

typedef struct sysexcl_entry {
	char *name;
	char exclude;
} sysexcl_entry_t;

static sysexcl_entry_t *sysexcl_64 = NULL;
static sysexcl_entry_t *sysexcl_32 = NULL;

int
update_sysexcl_from_sysignore()
{
        FILE *f = NULL;
        int sc32, sc64;
        char *scall;
        int len;

        if ((f = fopen(sysignore,"r")) == NULL) {
                return 0;
        }

        while (scall = fgets((char *)&input_str, 511, f)) {
                len = strlen(scall);
                if (len == 0) continue;

                /* OK to have a comment start with # */
                if (input_str[0] == '#') continue;

                /* Look for newline at end of string */
                if (input_str[len-1] == '\n') input_str[len-1] = 0;

                syscallname_to_syscallno(scall, &sc32, &sc64);
                if (sc64  >= 0)  {
			add_string(&sysexcl_64[sc64].name, scall);
			sysexcl_64[sc64].exclude = 1;
                }
                if (sc32  >= 0)  {
			add_string(&sysexcl_32[sc32].name, scall);
			sysexcl_64[sc64].exclude = 1;
                }
        }

        fclose(f);
}

int
alloc_sysexcl()
{
	if ((sysexcl_64 = calloc(MAX_SYSCALL_IDX, sizeof(sysexcl_entry_t))) == NULL)  {
		FATAL(errno, "Unable to malloc syscall64 exclude table", NULL, 0);
	}
	CALLOC_LOG(sysexcl_64, MAX_SYSCALL_IDX, sizeof(sysexcl_entry_t));

	if ((sysexcl_32 = calloc(MAX_SYSCALL_IDX, sizeof(sysexcl_entry_t))) == NULL)  {
		FATAL(errno, "Unable to malloc syscall32 exclude table", NULL, 0);
	}
	CALLOC_LOG(sysexcl_32, MAX_SYSCALL_IDX, sizeof(sysexcl_entry_t));

	/* check the sysignore file and add syscalls to sysexcl tables */
	if (sysignore) {
		update_sysexcl_from_sysignore();
	}
}

int
print_scall_excl_window()
{
	int lineno_64, lineno_32, i;

	if (sysexcl_64 == NULL) alloc_sysexcl();

	print_top_line();
	lineno++;
	mvprintw (lineno, 0, "--- Excluded 64-bit System Calls ---");
	mvprintw (lineno++, 40, "--- Excluded 32-bit System Calls ---");
	
	lineno_64 = lineno;
	lineno_32 = lineno;
	for (i = 0; i < MAX_SYSCALL_IDX; i++) {
		if ((lineno_64 < LINES-1) && sysexcl_64[i].exclude && sysexcl_64[i].name) {
			mvprintw (lineno_64++, col, "%s [%d]", sysexcl_64[i].name, i);
		}
		if ((lineno_32 < LINES-1) && sysexcl_32[i].exclude && sysexcl_32[i].name) {
			mvprintw (lineno_32++, col+40, "%s [%d]", sysexcl_32[i].name, i);
		}
	}
}

int
print_help_window()
{
	lineno=0; col=0;
	mvprintw (lineno++, 32, "Commands Menu");
	lineno=2;
	mvprintw (lineno++, col, "s - Select Task/CPU/Disk");
 	mvprintw (lineno++, col, "g - Global Task List");
	mvprintw (lineno++, col, "l - Global Node Stats");
	mvprintw (lineno++, col, "c - Global CPU Stats");
	mvprintw (lineno++, col, "p - Global Prof Stats"); 
	mvprintw (lineno++, col, "h - Global HT CPU Stats");
	mvprintw (lineno++, col, "i - Global IRQ Stats");
	mvprintw (lineno++, col, "d - Global Disk Stats");
	mvprintw (lineno++, col, "m - Global Mpath Stats");
	mvprintw (lineno++, col, "y - Global WWN Stats");
	mvprintw (lineno++, col, "z - Global HBA Stats"); 
	mvprintw (lineno++, col, "t - Global IO by PID");
	mvprintw (lineno++, col, "f - Global File Stats"); 
	mvprintw (lineno++, col, "w - Global Wait Stats");
	mvprintw (lineno++, col, "u - Global Futex Stats");
	mvprintw (lineno++, col, "n - Global Socket Stats"); 
	mvprintw (lineno++, col, "k - Global Docker Stats");

	lineno=2; col=26;
	mvprintw (lineno++, col, "G - Task Main Stats");
	mvprintw (lineno++, col, "D - Task Disk Stats");
	mvprintw (lineno++, col, "M - Task Mpath Stats");
	mvprintw (lineno++, col, "L - Task System Calls");
	mvprintw (lineno++, col, "W - Task Wait Stats");
	mvprintw (lineno++, col, "P - Task Profile Stats");
	mvprintw (lineno++, col, "F - Task File Stats");
	mvprintw (lineno++, col, "O - Task Coop Stats");
	mvprintw (lineno++, col, "U - Task Futex Stats");
	lineno++;
	mvprintw (lineno++, col, "C - Select CPU Stats");
	mvprintw (lineno++, col, "T - Select Disk Stats");
	mvprintw (lineno++, col, "I - Select IRQ Stats");
	mvprintw (lineno++, col, "K - Select Docker Stats");
	mvprintw (lineno++, col, "X - Select Futex Stats");

	lineno=2; col=52;
	mvprintw (lineno++, col, "? - Help");
	mvprintw (lineno++, col, "r - Refresh");
	mvprintw (lineno++, col, "b - Prev Screen");
	mvprintw (lineno++, col, "+ - Show Syscall Detail");
	mvprintw (lineno++, col, "- - Hide Syscall Detail");
	if (is_alive) {
		mvprintw (lineno++, col, "a - Set Alarm Interval");
		mvprintw (lineno++, col, "e - Exclude Syscall");
		mvprintw (lineno++, col, "E - Show Excl Syscalls"); 
	} else if (IS_LIKI) {
		mvprintw (lineno++, col, "> - Next Step");
		mvprintw (lineno++, col, "< - Prev Step");
		mvprintw (lineno++, col, "j - Step Time");
		mvprintw (lineno++, col, "J - Jump to Time");
	}
}

static inline int
change_window(int win, int pid, int ldom, int cpu, uint32 dev, uint64 faddr, int tgid, uint64 hba, uint64 wwn, int hirq, int sirq, uint64 dockid) 
{
	int err;
	char msr_flag_save = 0;
	char reset_tracemask = FALSE;

	prevwin = curwin;
	curwin = win;
	lastldom = curldom;
	curldom = ldom;
	lastpid = curpid;
	curpid = pid;
	lastcpu = curcpu;
	curcpu = cpu;
	lastdev = dev;
	curdev = lastdev;
	lastfaddr = curfaddr;
	curfaddr = faddr;
	lasttgid = curtgid;
	curtgid = tgid;
	lasthba = curhba;
	curhba = hba;
	lastwwn = curwwn;
	curwwn = wwn;
	lasthirq = curhirq;
	curhirq = hirq;
	lastsirq = cursirq;
	cursirq = sirq;
	lastdockid = curdockid;
	curdockid = dockid;
	uint64 tracemask;

#if MALLOC_DEBUG
	fprintf (stderr, "change_window - %d -> %d\n", prevwin, curwin);
#endif
	if (is_alive) {
		if (msr_flag) msr_flag_save=1;
		CLEAR_FLAG;
		if (msr_flag_save) SET(MSR_FLAG);
		CLEAR_STATS;
		SET(win_actions[curwin].flags);
		SET_STAT(win_actions[curwin].stats);
	} else {
		return 0;
	}

	SET_EXECUTE_BITS(win_actions[curwin].tracemask);
	SET_TRACEMASK(tracemask);

	if (curwin != prevwin) {
		reset_tracemask = TRUE;
	}
	
	if (curpid != lastpid) {
		if ( lastpid && ((err=liki_disable_tracing_for_task(lastpid)) < 0)) {
			/* this is OK, as the PID may have died */
		}

		if ( curpid && ((err=liki_enable_tracing_for_task(curpid)) < 0)) {
			/* this is OK, as the PID may have died */
		}
		reset_tracemask = TRUE;
	}

	if (curcpu != lastcpu) {
		if ( (lastcpu >= 0) && ((err=liki_disable_tracing_for_cpu(lastcpu)) < 0)) {
			live_cleanup_func(NULL);
			FATAL(-err, "Failed to disable tracing for cpu", "CPU:", lastcpu);
		}

		if ( (curcpu >= 0) && ((err=liki_enable_tracing_for_cpu(curcpu)) < 0)) {
			live_cleanup_func(NULL);
			FATAL(-err, "Failed to enable tracing for cpu", "CPU:", curcpu);
		}
		reset_tracemask = TRUE;
	}

	if (curdev != lastdev) {
		if ( (lastdev >= 0) && ((err=liki_disable_tracing_for_device(lastdev)) < 0)) {
			live_cleanup_func(NULL);
			FATAL(-err, "Failed to disable tracing for dev", "DEV:", lastdev);
		}

		if ( (curdev >= 0) && ((err=liki_enable_tracing_for_device(curdev)) < 0)) {
			live_cleanup_func(NULL);
			FATAL(-err, "Failed to enable tracing for dev", "DEV:", curdev);
		}
		reset_tracemask = TRUE;
	}

	if (reset_tracemask) {
		if ((err=liki_set_tracemask(tracemask)) < 0) {
			live_cleanup_func(NULL);
			FATAL(-err, "Failed to reset traced tracemask", NULL, 0);
		}
	}
}

int
select_task_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[80];
	int pid;
	pid_info_t *pidp;

	if ((prompt==0) && curpid) {
		pid=curpid;
		valid = TRUE;
	} else {
		/* We need to get a valid PID */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Task/PID: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 12);
		noecho();
		if (ret != ERR) {
			pid = strtol(str, NULL, 10);
			if (pid > 0) { 
				valid = TRUE;
			}
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, pid, -1, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		if (is_alive) {
			load_symbols();
		}
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_cpu_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[80];
	int cpu;

	if ((prompt==0) && (curcpu >= 0)) {
		cpu=curcpu;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "CPU: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 12);
		noecho();
		if (ret != ERR) {
			cpu = strtol(str, NULL, 10);
			if ((cpu >= 0) && (cpu < globals->nlcpu)) { 
				valid = TRUE;
			}
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, cpu, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_dsk_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[80];
	uint32 dev;

	if ((prompt==0) && (curdev > 0x0)) {
		dev=curdev;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "DEV: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 80);
		noecho();

		/* need to convert from to a dev_t */
		if ((ret >= 0) && (strlen(str) > 1)) {
			dev = devstr_to_dev(str);
			if (dev > 0x0) { 
				valid = TRUE;
			}
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, dev, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_hba_window(int win, int prompt)
{
	int valid = FALSE;
	char str[80];
	uint32 dev;
	int ret;
	uint64 hba = (uint64)-1;
	int path1, path2, path3;

	if ((prompt==0) && (curhba != (uint64)-1)) {
		hba=curhba;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "HBA: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 80);
		noecho();

		/* need to convert from a str to a HBA path */
		ret = sscanf(str, "%d:%d:%d", &path1, &path2, &path3);
		if (ret == 3) {
			hba = FCPATH(path1, path2, path3, 0);
			valid = TRUE;
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, 0, 0x0ull, -1, hba, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_wwn_window(int win, int prompt)
{
	int valid = FALSE;
	char str[80];
	uint32 dev;
	int ret;
	uint64 wwn = NO_WWN;

	if ((prompt==0) && (curwwn != NO_WWN)) {
		wwn=curwwn;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Target Path WWN: ");
		echo();
		ret = mvgetnstr(LINES-1, 20, str, 80);
		noecho();

		/* need to convert from a str to a HBA path */
		ret = sscanf(str, "0x%llx", &wwn);
		if (ret == 1) {
			valid = TRUE;
		}
		
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, 0, 0x0ull, -1, NO_HBA, wwn, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_ldom_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[12];
	int ldom;

	if ((prompt==0) && (curldom >= 0)) {
		ldom=curldom;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "LDOM: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 12);
		noecho();
		if (ret != ERR) {
			ldom = strtol(str, NULL, 10);
			if ((ldom >= 0) && (ldom < globals->nldom)) { 
				valid = TRUE;
			}
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, ldom, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}

int
select_docker_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[80];
	uint64 dockid;

	if ((prompt==0) && (curdockid != NO_DOCKID)) {
		dockid=curdockid;
		valid = TRUE;
	} else {
		/* We need to get a valid docker */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Container: ");
		echo();
		ret = mvgetnstr(LINES-1, 11, str, 32);
		if ((strlen(str) > 1) && ret != ERR) {
			sscanf (str, "%12llx", &dockid);
			if (dockid != NO_DOCKID) { 
				valid = TRUE;
			}
		}

		noecho();
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, dockid);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}


int
select_irq_window(int win, int prompt)
{
	char irqtype, str[80];
	int valid = FALSE;
	int ret;
	int irqnum = 0;

	/* we need to know hard or soft AND the IRQ number */
	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "HardIRQ or SoftIRQ [h|s]: ");
	echo();
	irqtype=getch();
	if ((irqtype == 'h') || (irqtype == 's')) {
		mvprintw (LINES-1, 34, "IRQ: ");
		ret = mvgetnstr(LINES-1, 40, str, 8);
		if ((strlen(str) > 0) && (ret != ERR)) {
			irqnum = strtol(str, NULL, 10);
			if (irqnum >= 0) {
				if ((irqtype == 's') && (irqnum < 32768)) {
					valid = TRUE;
				} else if ((irqtype == 'h') && (irqnum < 32768 )) {
					valid = TRUE;
				}
			}
		}
	}
	noecho();

	if (valid) {
		input_pending = FALSE;
		if (irqtype == 'h') {
			change_window(win, 0, -1, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, irqnum, -1, NO_DOCKID);
		} else {
			change_window(win, 0, -1, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, irqnum, NO_DOCKID);
		}
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}
}

int
select_futex_window(int win, int prompt)
{
	char str1[80], str2[80];
	int valid = FALSE;
	int ret;
	uint64 faddr;
	int tgid;

	/* we need to get the futex addr AND the TGID */
	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Futex Addr: ");
	echo();
	ret = mvgetnstr(LINES-1, 12, str1, 24);
	if (ret != ERR) {
		faddr = strtoll(str1, NULL, 16);
		if ((faddr > 0) && (faddr < 0xffffffffffffffffull)) {
			mvprintw (LINES-1, 34, "TGID: ");
			ret = mvgetnstr(LINES-1, 40, str2, 8);
			if (ret != ERR) {
				tgid = strtoll(str2, NULL, 10);
				if (tgid >= 0) { 
					valid = TRUE;
				}
			}
		}
	}
	noecho();

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, 0x0, faddr, tgid, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}
}

int
select_file_window(int win, int prompt)
{
	int valid = FALSE;
	int ret;
	char str[80];
	uint64 fileobj;

	if ((prompt==0) && (curfaddr > 0x0)) {
		fileobj=curfaddr;
		valid = TRUE;
	} else {
		/* We need to get a valid LDOM */
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Fileobj: ");
		echo();
		ret = mvgetnstr(LINES-1, 10, str, 24);
		noecho();

		/* need to convert from to a dev_t */
		if ((ret >= 0) && (strlen(str) > 1)) {
			fileobj = strtoull(str, NULL, 16);
			if (fileobj > 0x0) { 
				valid = TRUE;
			}
		}
	}

	if (valid) {
		input_pending = FALSE;
		change_window(win, 0, -1, -1, 0x0, fileobj, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
		live_print_window();
		input_pending = TRUE;
	} else {
		move(LINES-1, 0); clrtoeol();
		mvprintw(LINES-1, 0, "Command: ");
		refresh();
		input_pending = FALSE;
	}

	return 0;
}
int
select_next_step()
{
	/* ignore if past the end of the filter */
	if ((kistep == 0) || (start_filter > end_filter_save)) return 0;
	else {
		/* advance to next interval */ 
		start_filter = end_filter;
		end_filter = start_filter + kistep;
		if (end_filter > end_filter_save) end_filter = end_filter_save;
		next_step = TRUE;
		return 1;
	}
}

int
select_prev_step()
{
	/* ignore if past the end of the filter */
	if ((kistep == 0) || (start_filter < start_filter_save)) return 0;
	else {
		/* advance to prev interval */ 
		end_filter = start_filter;
		start_filter = end_filter - kistep;
		if (start_filter < start_filter_save) start_filter = start_filter_save;
		next_step = TRUE;
		return 1;
	}
}

int 
select_step()
{
	char str[20];
	int ret;
	double float_time;

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Step time: ");
	echo();
	ret = mvgetnstr(LINES-1, 19, str, 7);
	noecho();
	if (ret != ERR) {
		if ((float_time = strtod(str, NULL)) > 0) {
			kistep = float_time*1000000000;
			end_filter = start_filter + kistep;
			if (end_filter > end_filter_save) end_filter = end_filter_save;
			next_step = TRUE;
		}
	}

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Command: ");
	refresh();
	input_pending = FALSE;

}

int 
select_start()
{
	char str[20];
	int ret;
	double float_time;

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Jump to time: ");
	echo();
	ret = mvgetnstr(LINES-1, 19, str, 7);
	noecho();
	if (ret != ERR) {
		if ((float_time = strtod(str, NULL)) >= 0) {
			start_filter = float_time*1000000000;
			end_filter = start_filter + kistep;
			if (start_filter < start_filter_save) start_filter = start_filter_save;
			if (end_filter > end_filter_save) end_filter = end_filter_save;
			next_step = TRUE;
		}
	}

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Command: ");
	refresh();
	input_pending = FALSE;

}



int
select_alarm_secs() 
{
	char str[8];
	int num, ret;

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Seconds (max 120): ");
	echo();
	ret = mvgetnstr(LINES-1, 19, str, 7);
	noecho();
	if (ret != ERR) {
		num = strtol(str, NULL, 10);
		if ((num > 0) && (num <= 120)) { 
			alarm_secs = num;
		}
	}

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "Command: ");
	refresh();
	input_pending = FALSE;

}

int
select_scall_excl()
{
	char scall[48];
	int ret, i;
	int sc32 = -1, sc64 = -1;

	if (sysexcl_64 == NULL) alloc_sysexcl();

	move(LINES-1, 0); clrtoeol();
	mvprintw(LINES-1, 0, "System Call (or 'clear' to reset): ");
	echo();
	ret = mvgetnstr(LINES-1, 36, scall, 47);
	if (ret != ERR) {
		/* if syscall is not found, then simply go back) */
		if (strcmp(scall, "clear") == 0) {
			for (i=0; i < MAX_SYSCALL_IDX; i++) {
				sysexcl_64[i].exclude = 0;
				sysexcl_32[i].exclude = 0;
			}
			liki_ignore_syscall64((long)-1);
			liki_ignore_syscall32((long)-1);
		} else {	
	        	syscallname_to_syscallno(scall, &sc32, &sc64);
                	if (sc64  >= 0)  {
				add_string(&sysexcl_64[sc64].name, scall);
				sysexcl_64[sc64].exclude = 1;
                        	liki_ignore_syscall64((long)sc64);
                	}
                	if (sc32  >= 0)  {
				add_string(&sysexcl_32[sc32].name, scall);
				sysexcl_32[sc32].exclude = 1;
                        	liki_ignore_syscall32((long)sc32);
                	}
		}
	}

	noecho();
        refresh_screen();
}

int
select_window(int prompt)
{
	switch (curwin) {
		case WINLDOM : 
			select_ldom_window(WINLDOM_SEL, 1); break;
		case WINCPU: 
		case WINHT:
		case WINLDOM_SEL: 
		case WINIRQ_SEL:
			select_cpu_window(WINCPU_SEL, 1); break;
		case WINDSK:
		case WINHBA_SEL:
		case WINWWN_SEL:
		case WINFILE_SEL:
			select_dsk_window(WINDSK_SEL, 1); break;
		case WINFUT:
		case WINPID_FUTEX:
			select_futex_window(WINFUT_SEL, 1); break;
		case WINSCALL_EXCL:
			select_scall_excl(WINSCALL_EXCL, 1); break;
		case WINHBA:
			select_hba_window(WINHBA_SEL, 1); break;
		case WINWWN:
			select_wwn_window(WINWWN_SEL, 1); break;
		case WINIRQ:
			select_irq_window(WINIRQ_SEL, 1); break;
		case WINDOCK:
			select_docker_window(WINDOCK_SEL, 1); break;
		case WINFILE:
		case WINPID_FILE:
			if (IS_WINKI) {
				select_file_window(WINFILE_SEL, 1); 
			} else { 
				select_task_window(WINPID, 1); 

			}
			break;
		default: 
			select_task_window(WINPID, 1); break;
	}
	return 0;
}

int
select_global_window(int win)
{
	input_pending = FALSE;
	change_window(win, 0, -1, -1, 0x0, 0x0ull, -1, NO_HBA, NO_WWN, -1, -1, NO_DOCKID);
	live_print_window();
	input_pending = TRUE;
	return 0;
}

int
go_back()
{
	/* go back to previous window */
	input_pending = FALSE;
	change_window(prevwin, lastpid, lastldom, lastcpu, lastdev, lastfaddr, lasttgid, lasthba, lastwwn, lasthirq, lastsirq, lastdockid);
	live_print_window();
	if (is_alive) { 
		load_symbols();
	}
	input_pending = TRUE;
	return 0;
}	

void *
live_termio_thread()
{
	char a;

	while (1) {
		input_pending = FALSE;
		a=getch();
		input_pending = TRUE;

		switch (a) {
			case '?' : select_global_window(WINHELP); break;
			case 'r' : refresh_screen(); break;
			case 'b' : go_back(); break;
			case '+' : SET(SCDETAIL_FLAG); refresh_screen(); break;
			case '-' : CLEAR(SCDETAIL_FLAG); refresh_screen(); break;
			case 'e' : if (is_alive) select_scall_excl(curwin); break;
			case 'E' : if (is_alive) select_global_window(WINSCALL_EXCL); break;
			case 'q' : passes=0; done = TRUE; return(NULL);
			case '>' : if (IS_LIKI && kistep) select_next_step(); break;
			case '<' : if (IS_LIKI && kistep) select_prev_step(); break;
			case 'j' : if (IS_LIKI) select_step(); break; 
			case 'J' : if (IS_LIKI && kistep) select_start(); break; 
			case 'a' : if (is_alive) select_alarm_secs(); break;

			case 's' : select_window(1); break;
			case 'g' : select_global_window(WINMAIN); break;
			case 'c' : select_global_window(WINCPU); break;
			case 'h' : select_global_window(WINHT); break;
			case 'l' : select_global_window(WINLDOM); break;
			case 'i' : select_global_window(WINIRQ); break;
			case 'd' : select_global_window(WINDSK); break;
			case 'm' : select_global_window(WINMPATH); break;
			case 't' : select_global_window(WINIOTOP); break;
			case 'f' : select_global_window(WINFILE); break;
			case 'w' : select_global_window(WINWAIT); break;
			case 'p' : select_global_window(WINHC); break;
			case 'k' : select_global_window(WINDOCK); break;
			case 'u' : select_global_window(WINFUT); break;
			case 'n' : select_global_window(WINNET); break;
			case 'y' : select_global_window(WINWWN); break;
			case 'z' : select_global_window(WINHBA); break;

			case 'G' : select_task_window(WINPID, 0); break;
			case 'D' : select_task_window(WINPID_DSK, 0); break;
			case 'M' : select_task_window(WINPID_MPATH, 0); break;
			case 'L' : select_task_window(WINPID_SCALL, 0); break;
			case 'W' : select_task_window(WINPID_WAIT, 0); break;
			case 'P' : select_task_window(WINPID_HC, 0); break;
			case 'F' : select_task_window(WINPID_FILE, 0); break;
			case 'O' : select_task_window(WINPID_COOP, 0); break;
			case 'U' : select_task_window(WINPID_FUTEX, 0); break;

			case 'C' : select_cpu_window(WINCPU_SEL, 1); break;
			case 'I' : select_irq_window(WINIRQ_SEL, 1); break;
			case 'T' : select_dsk_window(WINDSK_SEL, 1); break;
			case 'K' : select_docker_window(WINDOCK_SEL, 1); break;
			case 'X' : select_futex_window(WINFUT_SEL, 1); break;
			default: ;
		}
	}
}

