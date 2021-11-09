
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <linux/kdev_t.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "block.h"
#include "sched.h"
#include "power.h"
#include "syscalls.h"
#include "irq.h"
#include "hardclock.h"
#include "cache.h"
#include "hash.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include "kprint.h"

#include "Thread.h"
#include "Process.h"
#include "PerfInfo.h"
#include "DiskIo.h"
#include "NetIp.h"
#include "FileIo.h"
#include "winki_util.h"

int kiall_dummy_func(uint64, int, void *);
int kiall_generic_func(void *, void *);
int kiall_print_report(void *);
int kiall_ftrace_print_func(void *, void *);

uint64 last_save_time = 0;
int itimes_fd = -1;

static inline void
kiall_winki_trace_funcs()
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
 ** The initialisation function
 */
void
kiall_init_func(void *v)
{
        int i, ret;
	char piddir[8];

	if (debug) printf ("kiall_init_func()\n");
        process_func = kiall_process_func;
	preprocess_func = NULL;
	if (vis) preprocess_func = kiall_preprocess_func;
        print_func = kiall_print_func;
        report_func = kiall_report_func;
	report_func_arg = filter_func_arg;
	filter_func = info_filter_func;   /* no filter func for kiall, use generic */
	bufmiss_func = pid_bufmiss_func;

	/* kiall is not allowed on live systems!! */
	if (is_alive)  return;

        /* We will disregard the trace records until the Marker is found */
        for (i = 0; i < KI_MAXTRACECALLS; i++) {
                ki_actions[i].execute = 0;
        }

        if (HTML) {
		sprintf (piddir, "%sS", tlabel);
                ret = mkdir(piddir, 0777);
                if (ret && (errno != EEXIST)) {
                        fprintf (stderr, "Unable to make PIDS directory, errno %d\n", errno);
                        fprintf (stderr, "  Continuing...\n");
			CLEAR(PIDTREE_FLAG);
		}
	
		/* for Docker/Contanter kparse data */
               	ret = mkdir("CIDS", 0777);
               	if (ret && (errno != EEXIST)) {
                       	fprintf (stderr, "Unable to make CIDS directory, errno %d\n", errno);
                       	fprintf (stderr, "  Continuing...\n");
			CLEAR(DOCKTREE_FLAG);
		}
        }

        if (IS_WINKI) {
                kiall_winki_trace_funcs();

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
	ki_actions[TRACE_SCHED_MIGRATE_TASK].func = kiall_generic_func;
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
	ki_actions[TRACE_SOFTIRQ_RAISE].func = kiall_generic_func;
	SET_KIACTION_FUNCTION(TRACE_SCSI_DISPATCH_CMD_START, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_SCSI_DISPATCH_CMD_DONE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_INSERTION, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_EXECUTION, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_ENQUEUE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_WORKQUEUE_EXECUTE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_TASKLET_ENQUEUE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_PAGE_FAULT_USER, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_PAGE_FAULT_KERNEL, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_ANON_FAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_FILEMAP_FAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_KERNEL_PAGEFAULT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_ALLOC, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_FREE, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_MM_PAGE_FREE_DIRECT, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_LISTEN_OVERFLOW, kiall_generic_func);
	SET_KIACTION_FUNCTION(TRACE_CACHE_INSERT, cache_insert_func);
	SET_KIACTION_FUNCTION(TRACE_CACHE_EVICT, cache_evict_func);
	SET_KIACTION_FUNCTION(TRACE_WALLTIME, trace_walltime_func);

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
		ki_actions[TRACE_CPU_FREQ].execute = 1;
		ki_actions[TRACE_CPU_IDLE].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_START, 1);
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_DONE, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_INSERTION, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTION, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_ENQUEUE, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTE, 1);
		SET_KIACTION_EXECUTE(TRACE_TASKLET_ENQUEUE, 1);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_USER, 1);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_KERNEL, 1);
		SET_KIACTION_EXECUTE(TRACE_ANON_FAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_FILEMAP_FAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_KERNEL_PAGEFAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_ALLOC, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE_DIRECT, 1);
		SET_KIACTION_EXECUTE(TRACE_LISTEN_OVERFLOW, 1);
		SET_KIACTION_EXECUTE(TRACE_CACHE_INSERT, 1);
		SET_KIACTION_EXECUTE(TRACE_CACHE_EVICT, 1);
	        if (IS_LIKI_V4_PLUS)
       		        ki_actions[TRACE_WALLTIME].func = trace_startup_func;
       		else
                	ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

		SET_KIACTION_EXECUTE(TRACE_WALLTIME, 1);
        	/* bufmiss_func = kparse_bufmiss_func; */
	} else {
		SET_KIACTION_FUNCTION(TRACE_PRINT, kiall_ftrace_print_func);
		SET_KIACTION_EXECUTE(TRACE_PRINT, 1);
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
	parse_mem_info();
	if (is_alive) parse_cpumaps();
	parse_kallsyms();
	parse_devices();

	if (timestamp) {
		parse_mpsched();
		parse_docker_ps();
       		parse_proc_cgroup();
        	parse_lsof();
        	parse_pself();
		parse_maps();
        	parse_edus();
        	parse_ll_R();
        	parse_mpath();
        	parse_jstack();
		if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
	}

	/*
	** For visualization kipid charts we create a VIS/<PID> directory to
	** hold copy (link actually) of the pid_detail.html file and the
	** per-pid json file data.
	**/

	if (vis) vis_kiall_init();
        if (hthr) hash_start_worker_threads();
}

int
kiall_preprocess_func(void *a, void *v)
{
	trace_info_t	*trcinfop = a;
        common_t        tt_rec_ptr;
        common_t        *rec_ptr;

	rec_ptr = conv_common_rec(trcinfop, &tt_rec_ptr);
	if (vis) kiall_interval_processing(rec_ptr->hrtime);
}

void
kiall_interval_processing(uint64 hrtime )
{
	CHECK_VINT_INTERVAL(hrtime);  /* we return here if not time yet */
	vis_interval_processing(hrtime);

/*
**	Other possible interval reporting functions
**
**	cpu_interval_processing(hrtime);
**	diskio_interval_processing(hrtime);
**	network_interval_processing(hrtime);
*/

}

void
save_trcinfo(trace_info_t *t, trace_info_save_t *s, uint64 time_off)
{
	s->time_off = time_off;
	s->header_off = (char *)(t->header) - t->mmap_addr;
	s->cur_event_off = t->cur_event - t->mmap_addr;
	s->cur_time = t->cur_time;

	if (write(itimes_fd, s, sizeof(trace_info_save_t)) <= 0) {
		if (debug) fprintf (stderr, "Unable to write to itimes file (errno %d)\n", errno);
	}
}

int
kiall_process_func(void *v, void *a)
{
        trace_info_t *trcinfop = (trace_info_t *)v;
	common_t *rec_ptr;
	trace_info_save_t save;
	char fname[30];

	if (!IS_LIKI || (nfiles > 1)) return 0;

	rec_ptr = (common_t *)(trcinfop->cur_rec);

	/* first time through */
	if (last_save_time == 0) {
		last_save_time = start_time;
		if (timestamp) {
			sprintf(fname, "itimes.%s", timestamp);
			if ((itimes_fd = open(fname, O_WRONLY | O_CREAT, 0744)) < 0) {
				if (debug) fprintf (stderr, "Unable to open %s (errno %d)\n", fname, errno);
			} else {
				if (ftruncate(itimes_fd, 0ull) == -1) {
					fprintf (stderr, "Unable to truncate itimes file\n");
				}
				save_trcinfo(trcinfop, &save, last_save_time - start_time);
			}
		}

		return 0;
	}

	if ((itimes_fd >= 0) && (rec_ptr->hrtime > (last_save_time + 1000000))) {
		while (rec_ptr->hrtime > (last_save_time + 1000000)) {
			last_save_time += 1000000;
			save_trcinfo(trcinfop, &save, last_save_time - start_time);
		}
	}
	
        return 0;
}

int
kiall_bufmiss_func(void *v, void *a)
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
kiall_dummy_func(uint64 rec_ptr, int cor, void *v)
{
        return 0;
}

int
kiall_generic_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        common_t      tt_rec_ptr;
        common_t      *rec_ptr;

        if (debug) printf ("kiall_generic_func()\n");

        rec_ptr = conv_common_rec(trcinfop, &tt_rec_ptr);
	incr_trc_stats(rec_ptr, NULL);

        return 0;
}

int
kiall_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("pid_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
                ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
                ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 1;
		ki_actions[TRACE_POWER_START].execute = 1;
		ki_actions[TRACE_POWER_END].execute = 1;
		ki_actions[TRACE_POWER_FREQ].execute = 1;
		ki_actions[TRACE_CPU_FREQ].execute = 1;
		ki_actions[TRACE_CPU_IDLE].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_START, 1);
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_DONE, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_INSERTION, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTION, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_ENQUEUE, 1);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTE, 1);
		SET_KIACTION_EXECUTE(TRACE_TASKLET_ENQUEUE, 1);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_USER, 1);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_KERNEL, 1);
		SET_KIACTION_EXECUTE(TRACE_ANON_FAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_FILEMAP_FAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_KERNEL_PAGEFAULT, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_ALLOC, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE, 1);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE_DIRECT, 1);
		SET_KIACTION_EXECUTE(TRACE_LISTEN_OVERFLOW, 1);
		SET_KIACTION_EXECUTE(TRACE_CACHE_INSERT, 1);
		SET_KIACTION_EXECUTE(TRACE_CACHE_EVICT, 1);
                start_time = KD_CUR_TIME;
		/* bufmiss_func = kparse_bufmiss_func; */
        }
        if (strstr(buf, ts_end_marker)) {
                ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 0;
                ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 0;
                ki_actions[TRACE_SYS_EXIT].execute = 0;
                ki_actions[TRACE_SYS_ENTER].execute = 0;
                ki_actions[TRACE_SCHED_SWITCH].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
		ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 0;
		ki_actions[TRACE_POWER_START].execute = 0;
		ki_actions[TRACE_POWER_END].execute = 0;
		ki_actions[TRACE_POWER_FREQ].execute = 0;
		ki_actions[TRACE_CPU_FREQ].execute = 0;
		ki_actions[TRACE_CPU_IDLE].execute = 0;
		ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 0;
		ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 0;
		ki_actions[TRACE_SOFTIRQ_RAISE].execute = 0;
		ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 0;
		ki_actions[TRACE_SOFTIRQ_EXIT].execute = 0;
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_START, 0);
		SET_KIACTION_EXECUTE(TRACE_SCSI_DISPATCH_CMD_DONE, 0);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_INSERTION, 0);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTION, 0);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_ENQUEUE, 0);
		SET_KIACTION_EXECUTE(TRACE_WORKQUEUE_EXECUTE, 0);
		SET_KIACTION_EXECUTE(TRACE_TASKLET_ENQUEUE, 0);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_USER, 0);
		SET_KIACTION_EXECUTE(TRACE_PAGE_FAULT_KERNEL, 0);
		SET_KIACTION_EXECUTE(TRACE_ANON_FAULT, 0);
		SET_KIACTION_EXECUTE(TRACE_FILEMAP_FAULT, 0);
		SET_KIACTION_EXECUTE(TRACE_KERNEL_PAGEFAULT, 0);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_ALLOC, 0);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE, 0);
		SET_KIACTION_EXECUTE(TRACE_MM_PAGE_FREE_DIRECT, 0);
		SET_KIACTION_EXECUTE(TRACE_LISTEN_OVERFLOW, 0);
		SET_KIACTION_EXECUTE(TRACE_CACHE_INSERT, 0);
		SET_KIACTION_EXECUTE(TRACE_CACHE_EVICT, 0);
                ki_actions[TRACE_PRINT].execute = 0;
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
int
kiall_print_report(void *v)
{
	char fname[30];
	char html_flag = HTML;
	int vis_set = 0;
	int hthr_save = hthr;
        parse_cstates();

	hthr = 0;   /* disable multi-threading for now */
	if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
	kparse_print_report(v);
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	HTML = FALSE;
	CLEAR(KPTREE_FLAG);
	CLEAR(KPARSE_FLAG);

	if (oracle) {
		if (vis) {
			vis_set=1;
			CLEAR(VIS_FLAG);
		}
		sprintf(fname, "kipid.oracle.%s.txt", timestamp);
		if (freopen(fname, "w", stdout) == NULL) {
			fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
			return 0;
		}

        	printf("Command line: %s -kipid oracle,nsym=20,npid=10,pidtree,csv -ts %s\n\n", cmdstr, timestamp);
        	printf ("%s (%s)\n\n", tool_name, tool_version);
		parse_uname(1);
		nsym=20;
		npid=10;
		pid_print_report(v);
		printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
		print_cpu_buf_info();
		CLEAR(ORACLE_FLAG);
		if (vis_set) {
                        SET(VIS_FLAG);
                        vis_set = 0;
                }

	}

	CLEAR(ORACLE_FLAG);


	hthr = hthr_save;   /* enable multi-threading  */
	sprintf(fname, "kipid.%s.txt", timestamp);


	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}

        printf("Command line: %s -kipid nsym=20,npid=10,pidtree,csv -ts %s\n\n", cmdstr, timestamp);
        printf("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	nsym=20;
	npid=10;
	pid_csvfile = open_csv_file("kipid", 1);
	if (html_flag) SET(PIDTREE_FLAG);

	pid_print_report(v);

	/* we call pid_print_report a 2nd time if parallel threads are 
	   used, as the kipid.*.txt and kipid.*.csv are not created in
	   the multi-threaded case.   So we turn off the VIS, COOP, and HTML
	   flags to produce just the *.txt file and the csv file.
	*/
	CLEAR(VIS_FLAG);	
	CLEAR(COOP_DETAIL_ENABLED);
	CLEAR_STAT(COOP_STATS);
	HTML = 0;
	if (hthr) {
		hthr = 0; 	/* disable mulithreaded processing */
		pid_print_report(v);
	}

	printf("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(pid_csvfile);
	CLEAR(PIDTREE_FLAG);
	CLEAR_STAT(PERCPU_STATS);

	sprintf(fname, "kidsk.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kidsk npid=20,csv -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	npid=20;
	dsk_csvfile = open_csv_file("kidsk", 1);
	dsk_print_report();
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(dsk_csvfile);
	dsk_csvfile = NULL;
	SET_STAT(PERCPU_STATS);

	if (globals->hcinfop) {
		sprintf(fname, "kiprof.%s.txt", timestamp);
		if (freopen(fname, "w", stdout) == NULL) {
			fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
			return 0;
		}
        	printf("Command line: %s -kiprof nsym=50,npid=20 -ts %s\n\n", cmdstr, timestamp);
        	printf ("%s (%s)\n\n", tool_name, tool_version);
		parse_uname(1);
		nsym=50;
		npid=20;
		prof_print_report(TOTAL);
		printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
		print_cpu_buf_info();
	}

	sprintf(fname, "kirunq.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kirunq npid=20,csv -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	npid=20;
	runq_csvfile = open_csv_file("kirunq", 1);
	runq_print_report(v);
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(runq_csvfile);

	sprintf(fname, "kiwait.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kiwait nsym=50,npid=20,csv -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	nsym=50;
	npid=20;
	wait_csvfile = open_csv_file("kiwait", 1);
	wait_print_report(v);
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(wait_csvfile);

	sprintf(fname, "kisock.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kisock nsock=30, -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	nfile=30;
	socket_csvfile = open_csv_file("kisock", 1);
	socket_print_report(v);
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(socket_csvfile);

	sprintf(fname, "kifile.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kifile nfile=30,csv -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	nfile=30;
	file_csvfile = open_csv_file("kifile", 1);
	file_print_report(v);
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();
	close_csv_file(file_csvfile);
	file_csvfile = NULL;

	/* The rest of the reports are not ready yet */
	if (IS_WINKI) return 0;

	sprintf(fname, "kifutex.%s.txt", timestamp);
	if (freopen(fname, "w", stdout) == NULL) {
		fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
		return 0;
	}
        printf("Command line: %s -kifutex nfutex=50,npid=20 -ts %s\n\n", cmdstr, timestamp);
        printf ("%s (%s)\n\n", tool_name, tool_version);
	parse_uname(1);
	nfutex=50;
	npid=20;
	futex_print_report();
	printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
	print_cpu_buf_info();

	if (globals->docker_hash) {
		sprintf(fname, "kidock.%s.txt", timestamp);
		if (freopen(fname, "w", stdout) == NULL) {
			fprintf (stderr, "Unable to rename stdout to %s (errno: %d)\n", fname, errno);
			return 0;
		}
		npid=10;
        	printf("Command line: %s -kidock npid=%d -ts %s\n\n", cmdstr, npid, timestamp);
        	printf ("%s (%s)\n\n", tool_name, tool_version);
		parse_uname(1);
		if (html_flag) SET(DOCKTREE_FLAG);
		docker_print_report(v);
		CLEAR(DOCKTREE_FLAG);
		printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
		print_cpu_buf_info();
	}

	return 0;
}

int
kiall_print_func(void *v)
{
        int i;
        struct timeval tod;

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                kiall_print_report(v);
                print_flag=0;
        }
        return 0;
}

int
kiall_report_func(void *v)
{

        if (debug) printf ("Entering kiall_report_func %d\n", is_alive);
        if (passes != 0) {
                kiall_print_report(v);
        }

	HR;
	printf ("\n");

        return 0;
}
