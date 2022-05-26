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

#define MAXCPUS 2048
#define TS_SHIFT	27
#define GETNEWBUF  0xffffffffffffffffull
#define TIME_INVAL 0x8000000000000000ull
#define FATAL(err, msg, optmsg, optnum)  fatal(__func__,__LINE__,__FILE__, err, msg, optmsg, optnum)
#define TRACE debug_trace(__func__,__LINE__,__FILE__)

/* #define HEADER_SIZE(ptr)   (IS_LIKI ? sizeof(info_t) : (IS_WINKI ? sizeof(etw_bufhd_t) : sizeof(header_page_t))) */
#define HEADER_SIZE(ptr)   (((ptr->version != 0xffffffff) && (ptr->version & 1)) ? sizeof(info_t) : (((ptr->version != 0xffffffff) && (ptr->version & 0xffff0000)) ? sizeof(etw_bufhd_t) : sizeof(header_page_t)))

enum {
	RINGBUF_TYPE_PADDING            = 29,
	RINGBUF_TYPE_TIME_EXTEND        = 30,
	RINGBUF_TYPE_TIME_STAMP         = 31,
};

typedef struct kd_rec {
	unsigned short		id;
	unsigned char		flags;
	unsigned char		preempt_count;
	int			pid;
/*	int			lock_depth; */
} kd_rec_t;

typedef struct event {
	uint32		type_len_ts;
	uint32		array[0];
} event_t;

typedef struct header_page {
	uint64		time;
	uint32		commit;
	uint32		version;
} header_page_t;

typedef struct trace_info {
	char		*mmap_addr;
	header_page_t	*header;
	char		*next_event;
	char		*cur_event;
	char		*cur_rec;
	uint64		cur_time;
	uint64		next_time;	
	uint64		size;
	uint64		cur_seqno;
	uint64		abs_time;   /* for Windows buffer header time */
	int		cpu;
        int             fd;
        int             save_fd;
        int             pid;
        int             missed_buffers;
        int             buffers;
        int             missed_events;
        int             events;
        int             check_flag;
} trace_info_t;

typedef struct trace_info_save {
	uint64		time_off;
	uint64		header_off;
	uint64		cur_event_off;
	uint64		cur_time;
} trace_info_save_t;

typedef struct hc_cntl { 
        uint64 ki_hc_dump;  /* etiher the ki_spu_info or the hc_dump structure */
        uint64 time;
        int cur_index;
} hc_cntl_t;

typedef struct trace_ids_struct {
        int trace_print;
        int trace_sys_exit;
        int trace_sys_enter;
        int trace_sched_switch;
        int trace_sched_wakeup_new;
        int trace_sched_wakeup;
	int trace_sched_migrate_task;
        int trace_block_rq_issue;
        int trace_block_rq_insert;
        int trace_block_rq_complete;
        int trace_block_rq_requeue;
        int trace_block_rq_abort;
	int trace_hardclock;
	int trace_power_start;
	int trace_power_end;
	int trace_power_freq;
	int trace_irq_handler_entry;
	int trace_irq_handler_exit;
	int trace_softirq_entry;
	int trace_softirq_exit;
	int trace_softirq_raise;
	int trace_scsi_dispatch_cmd_start;
	int trace_scsi_dispatch_cmd_done;
	int trace_listen_overflow;
	int trace_walltime;
	int trace_cpu_freq;
	int trace_cpu_idle;
	int trace_workqueue_insertion;
	int trace_workqueue_execution;
	int trace_workqueue_enqueue;
	int trace_workqueue_execute;
	int trace_tasklet_enqueue;
	int trace_cache_insert;
	int trace_cache_evict;
	int trace_page_fault_user;
	int trace_page_fault_kernel;
	int trace_anon_fault;
	int trace_filemap_fault;
	int trace_kernel_pagefault;
	int trace_mm_page_alloc;
	int trace_mm_page_free;
	int trace_mm_page_free_direct;
	int trace_napi_poll;
	int trace_consume_skb;
	int trace_call_function_entry;
	int trace_call_function_exit;
	int trace_call_function_single_entry;
	int trace_call_function_single_exit;
} trace_ids_t;

typedef struct ki_action {
	int execute;
	int id;
	int rec_size;
	char subsys[16];
	char event[64];
	int (*func)(void *, void *arg);
} ki_action_t;

typedef struct filter_item {
	struct filter_item *fi_next;
	uint64  fi_item;
	char 		*fi_item_str;
} filter_item_t;
 
typedef struct filter_struct {
	filter_item_t *f_P_pid;
	filter_item_t *f_P_tgid;
	filter_item_t *f_P_cpu;
	filter_item_t *f_dev;
	filter_item_t *f_event;
	filter_item_t *f_subsys;
	filter_item_t *f_events;
	filter_item_t *f_uaddr;
	filter_item_t *f_pdb;
} filter_t;

extern trace_info_t trace_files[];
extern trace_info_t trace_file_merged;
extern ki_action_t *ki_actions;
extern ki_action_t *liki_actions;
extern ki_action_t *winki_actions;
extern trace_ids_t trace_ids;
extern uint64 iov_space;
extern filter_t trace_filter;
extern int debug;
extern int print_flag;
extern int break_flag;
extern uint64 ms;
extern uint64 *sort;
extern int sortc;
extern int counts[];
extern int passes;
extern int done;
extern char startup_found;
extern uint32 cur_buf_num;
extern uint64 realtime;
extern double realsecs;
extern double secs;
extern uint64 time_hwm;
extern uint64 time_lwm;
extern uint64 time_mb_lwm;
extern uint64 start_time;
extern uint64 winki_start_time;
extern uint64 end_time;
extern uint64 prev_vint_time;
extern uint64 vis_hostid;
extern uint64 interval_start;
extern uint64 interval_end;
extern int nfiles;
extern struct timespec begin_time;
extern int64 start_filter;
extern int64 end_filter;
extern int64 start_filter_save;
extern int64 end_filter_save;
extern int64 kistep;
extern uint64 interval_start_time;
extern uint64 interval_end_time;
extern uint64 last_time;
extern uint32 winki_bufsz;
extern char vers_str[];
extern char *kernel_trace_name[];
extern char liki_module_loaded;
extern char liki_initialized;

extern void *filter_func_arg;
extern void *process_func_arg;
extern void *print_func_arg;
extern void *report_func_arg;

extern void *(*filter_func)(void *, void *);
extern int (*preprocess_func)(void *, void *);
extern int (*process_func)(void *, void *);
extern int (*sort_func)(const void *, const void *);
extern int (*print_func)(void *);
extern int (*report_func)(void *);
extern int (*bufmiss_func)(void *, void *);
extern int (*bufswtch_func)(void *);
extern int (*alarm_func)(void *);
extern void * generic_filter_func(void *, void *v);
extern int hpux_1131();
extern void fatal(const char *, const int, const char *, int, char *, char *, int);
extern void debug_trace(const char *, const int, const char *);
extern void check_HARDCLOCK_traces();
extern void developers_init();
extern void developers_report();
extern void developers_call();
extern void get_new_buffer(trace_info_t *, int);
extern uint64 get_event_time(trace_info_t *, int);
extern uint32 get_event_len(event_t *);
extern char *get_rec_from_event(event_t *);
extern int check_missed_events(char *);
extern int process_buffer(trace_info_t *);
extern void init_trace_ids();
extern int open_trace_files();
extern int reset_trace_files(int nfiles);
extern void read_fmt_files();
extern void save_and_clear_server_stats(int);
extern char *get_next_event_for_cpu(trace_info_t *);


extern int  setup_percpu_readers();
extern void read_liki_traces();
extern int  load_liki_module();
extern int  unload_liki_module();
extern void init_liki_tracing();
extern int  likidump();
extern int  etldump();
extern void  kitracedump();
extern int  merge();
extern void reset_kgdboc();
extern void clear_kgdboc();





ki_action_t * liki_action();
ki_action_t * winki_action();
