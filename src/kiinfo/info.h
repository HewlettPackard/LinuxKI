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

/* from read_tr.c */
void		set_events_all(int);
void		set_events_default();
int		set_events_options(void *v);

/* from rrt.c */
extern void * run_reader_thread();

extern void   info_init_func(void *);
extern void * info_filter_func(void *, void *);
extern int    info_sort_func(const void *, const void *);
extern int    info_process_func(uint64, void *);
extern int    info_print_func(void *);
extern int    info_report_func(void *);
extern int    info_queuedone_func(uint64, int, void *);
extern int    info_enqueue_func(uint64, int, void *);
extern int    info_bufmiss_func(void *, void *);
extern int    info_bufswtch_func(void *);
extern int    info_alarm_func(void *);
extern int    info_syscall_func(uint64, int, void *);
extern int    info_dummy_func(uint64, int, void *);

extern void  	sched_HT_swtch(uint64);
extern void  	sched_HT_resume(uint64);
extern int  	sched_swtch_func(uint64, int, void*);
extern int 	sched_resume_func(uint64,int, void *);
extern int 	sched_setrq_func(uint64,int, void *);
extern int	sched_bufmiss_adjust(void *, void *);
extern int	sched_perpass_reset();
extern int	sched_adjust_final(void *, void *);
extern int	clear_slp_info(void *, void *);
extern int	clear_setrq_info(void *, void *);
extern void	*find_sched_info(void *);
extern int 	update_pid_sched_stats(void *, void *);
extern void	update_perpid_sched_stats();
extern void	clear_sched_stats(sched_stats_t *);
extern int 	clear_pid_sched_stats(void *, void *);
extern int 	clear_pid_stats(void *, void *);
extern int 	clear_pid_hc_info(void *, void *);
extern int 	clear_syscall_info(void *, void *);

extern int	clean_pid(void *, void *);

extern int	sched_wakeup_func(void *, void *);
extern int	sched_wakeup_new_func(void *, void *);
extern int	sched_switch_thread_names_func(void *, void *);
extern int	sched_switch_func(void *, void *);
extern uint64	update_sched_time(void *, uint64);
extern void	update_sched_prio(void *, int);
extern void 	update_sched_cpu(void *, int);
extern void 	update_sched_state(void *, int, int, uint64);
extern void	update_cpu_times();
extern void 	sleep_report(void *, void *, int (*funct)(const void *, const void *), void *);
extern int      sched_report(void *, void *);
extern void     sched_coop_syscall(void *, void *, uint64);
extern uint64   sched_get_runtime(void *);
extern int      print_wakeup_pids(void *, void *);
extern int      clear_slp_info(void *, void *);
extern int      print_slp_info(void *, void *);
extern int      print_slp_info_csv(void *, void *);
extern int      print_stktrc_info(void *, void *);
extern int      sched_print_kpdata(void *);
extern void	sched_ktc_init();
extern void	sched_merged_wchan_init();
extern int	sched_clear_accumtm(void *);
extern int	sched_print_accumtm(void *);
extern int	sched_print_pertid_accumtm(void *, void *);
extern int	sched_print_tid_accumtm(void *);
extern void	sched_mpschedinfo_init();
extern void	cpu_missed_buffer(void *);
extern void	pid_missed_buffer(void *, void *);
extern int      kp_print_sleep_pids(void *, void *);

extern int	calc_global_cpu_stats(void *, void *);
extern int	print_global_cpu_stats(void*, void *);
extern int	calc_global_HT_stats(void *arg1, void *arg2);
extern void	print_percpu_stats(uint64 *);
extern void	print_perldom_stats(uint64 *);
extern void	print_HT_report();
extern void	print_HT_DBDI_histogram();
extern void     print_global_runq_histogram();
extern void     print_global_setrq_stktraces();
extern void     print_global_swtch_stktraces();
extern void      print_percpu_runq_stats();
extern void	print_percpu_runq_histogram();
extern void	total_cpu_stats(void *, void *);
extern void	print_cstate_stats(uint64 *);

extern int     runq_switch_func(void *, void *);
extern int     runq_wakeup_func(void *, void *);
extern int     runq_wakeup_new_func(void *, void *);
extern int	runq_bufmiss_adjust(void *, void *);
extern int	runq_adjust_final(void *, void *);
extern int	runq_print_func(void *);
extern int	runq_report_func(void *);
extern int	runq_print_report(void *);
extern int    runq_process_func(void *, void *);
extern int    runq_bufmiss_func(void *, void *);
extern int    runq_bufswtch_func(void *);
extern int    runq_alarm_func(void *);
extern void   runq_idle_timing_swtch(void *);
extern int    runq_print_stats(void *, void *);
extern int    print_runq_pids(uint64 *);
extern int    print_runq_stats(void *, void *);
extern int    print_runtime_pids(uint64 *);
extern int    print_systime_pids(uint64 *);
extern int    print_stealtime_pids(uint64 *);
extern int    print_sys_runtime_pids(uint64 *);
extern void   print_futex_summary(uint64 *);

extern void print_percpu_irq_stats(int);
extern void print_global_irq_stats(int);
extern void print_global_hardirq_stats(void *);
extern void print_global_softirq_stats(void *);
extern void clear_irq_stats(void **);

extern void   nfs_init_func(void *);
extern uint64 nfs_filter_func(uint64, void *);
extern int    nfs_process_func(uint64, void *);
extern int    nfs_print_func(void *);
extern int    nfs_report_func(void *);
extern int    nfs_bufmiss_func(void *, void *);
extern int    nfs_bufswtch_func(void *);
extern int    nfs_alarm_func(void *);
extern int    nfs_rfscall_func(uint64, int, void *);
extern int    nfs_rfscall_stats(uint64, void *);
extern int    nfs_rfs_dispatch_stats(uint64, void *);
extern int    nfs_rfs_dispatch_func(uint64, int, void *);
extern int    nfs_print_func_histogram(void *, void *);
extern int    nfs_print_func_summary(void *, void *);
extern int    nfs_print_client_stats(void *, void *);
extern int    nfs_print_server_stats(void *, void *);
extern int    nfs_print_pertid_servers(void *, void *);
extern int    nfs_print_pertid_clients(void *, void *);
extern int    nfs_print_client_global_stats();
extern int    nfs_print_server_global_stats();
extern char * nfs_req_name(int32_t,int32_t);
uint32        nfs_extract_ip(uint64);

/*  External Function definitions */
extern void  kiall_init_func(void *);
extern int   kiall_preprocess_func(void *, void *);
extern void  kiall_interval_processing(uint64);
extern int   kiall_process_func(void *, void *);
extern int   kiall_print_func(void *);
extern int   kiall_report_func(void *);
extern int   kiall_bufmiss_func(void *, void *);
extern int   kiall_generic_func(void *, void *);

extern void  vis_kiall_init();
extern void  vis_clparse_init();
extern void  vis_kipid_init();
extern void  vis_interval_processing(uint64 );
extern void  print_vis_interval_data();

extern void  kparse_init_func(void *);
extern int   kparse_process_func(void *, void *);
extern int   kparse_print_func(void *);
extern int   kparse_report_func(void *);
extern int   kparse_bufmiss_func(void *, void *);
extern int   kparse_print_report(void *);
extern int   kparse_getnewbuf_func(uint64, int, void *);
extern int   kparse_brelse_func(uint64, int, void *);
extern int   kparse_queuedone_func(uint64, int, void *);
extern int   kparse_enqueue_func(uint64, int, void *);
extern int   kparse_rfscall_func(uint64, int, void *);
extern int   kparse_rfs_dispatch_func(uint64, int, void *);
extern int   kparse_block_rq_complete_func(void *, void *);
extern int   kparse_generic_func(void *, void *);
extern int   kparse_ftrace_print_func(void *, void *);

extern void   clparse_init_func(void *);
extern int   clparse_process_func(void *, void *);
extern int   clparse_print_func(void *);
extern int   clparse_report_func(void *);
extern int   clparse_bufmiss_func(void *, void *);

extern int    load_objfile();
extern void   load_objfile_and_shlibs();
extern void   load_perpid_objfile_and_shlibs();
extern int    load_perpid_mapfile(void *, void *);
extern uint64 get_user_pc_name(uint64, uint64, uint64, uint64);
extern void *find_vtext_preg(void *, uint64);

extern void   docker_init_func(void *);
extern void *pid_filter_func(void *, void *);
extern int    docker_print_func(void *);
extern int    docker_print_func(void *);
extern int    docker_report_func(void *);
extern int    docker_print_report(void *);
extern int	calc_docker_pid_totals(void *, void *);
extern uint64 find_docker_by_name(char *);
extern int	docker_print_io_report();
extern int	docker_print_cpu_report();

extern void   pid_init_func(void *);
extern void *pid_filter_func(void *, void *);
extern int    pid_process_func(void *, void *);
extern int    pid_print_func(void *);
extern int    pid_report_func(void *);
extern int    pid_print_report(void *);
extern int    pid_bufmiss_func(void *, void *);
extern void   parse_dmidecode();
extern void   parse_cpuinfo();
extern void   parse_mpsched();
extern void   parse_mpscheds();
extern void   parse_mem_info();
extern void   parse_lsof();
extern void   parse_ll_R();
extern void   parse_maps();
extern void   parse_mpath();
extern void   parse_dmsetup();
extern void   parse_cstates();
extern void   parse_uname(char);
extern void   parse_edus();
extern void   parse_docker_ps();
extern void   parse_proc_cgroup();
extern void   parse_kallsyms();
extern void   parse_pself();
extern void   parse_jstack();
extern void   parse_devices();
extern int    pid_alarm_func(void *);
extern int pid_sched_switch_func(void *, void *);
extern int pid_sched_wakeup_func(void *, void *);
extern int pid_block_rq_issue_func(void *, void *);
extern int pid_block_rq_complete_func(void *, void *);
extern int pid_block_rq_requeue_func(void *, void *);
extern int pid_block_rq_insert_func(void *, void *);
extern int pid_block_rq_abort_func(void *, void *);
extern int pid_cache_insert_func(void *, void *);
extern int pid_cache_evict_func(void *, void *);

extern void   live_init_func(void *);
extern void   live_cleanup_func(void *);
extern void   *live_filter_func(void *, void *);
extern int    live_process_func(void *, void *);
extern int    live_print_func(void *);
extern int    live_report_func(void *);
extern int    live_bufmiss_func(void *, void *);
extern int    live_alarm_func(void *);

extern int    print_syscall_info(void *, void *);
extern int    ki_nosys(void *, void *, uint64);
extern int    ki_read(void *, void *, uint64);
extern int    ki_write(void *, void *, uint64);
extern int    ki_pread(void *, void *, uint64);
extern int    ki_pwrite(void *, void *, uint64);
extern int    ki_open(void *, void *, uint64);
extern int    ki_close(void *, void *, uint64);
extern int    ki_lseek(void *, void *, uint64);
extern int    ki_execve(void *, void *, uint64);
extern int    ki_clone(void *, void *, uint64);
extern int    ki_fork(void *, void *, uint64);
extern int    ki_recvfrom(void *, void *, uint64);
extern int    ki_sendto(void *, void *, uint64);
extern int    ki_readahead(void *, void *, uint64);
extern int    ki_futex(void *, void *, uint64);
extern int    ki_dup(void *, void *, uint64);
extern int    ki_dup2(void *, void *, uint64);
extern int    ki_fcntl(void *, void *, uint64);
extern int    ki_io_submit(void *, void *, uint64);
extern int    ki_io_getevents(void *, void *, uint64);

extern char * get_devstr(uint64, char *);
extern char * get_devstr_short(uint64, char *);
extern uint64 p4_search_unwind_start_addr(uint64, int);

extern void   dsk_init_func(void *);
void *	      dsk_filter_func(void *, void *);
extern int    dsk_sort_func(const void *, const void *);
extern int    dsk_process_func(void *, void *);
extern int    dsk_print_func(void *);
extern int    dsk_report_func(void *);
extern int    dsk_print_report();
extern int    dsk_bufmiss_func(void *, void *);
extern int    dsk_alarm_func(void *);
extern int    dsk_bucket_adjust();
extern int    dsk_print_dev_iostats(void *, void *);
extern int    dsk_print_dev_iostats_total(void *, void *);
extern int    sum_iostat(void *, void *);
extern int    sum_iostats(void *, void *);

extern int    print_pid_swtch_summary(void *, void *);
extern int    print_pid_runtime_summary(void *, void *);
extern int    print_pid_memory(void *, void *);

extern int    calc_dev_totals(void *, void *);
extern void    calc_io_totals(void *, void *);
extern int    calc_fc_totals(void *, void *);
extern int    calc_pid_iototals(void *, void *);
extern int    clear_dev_iostats(void *, void *);
extern int    clear_fc_iostats(void *, void *);
extern int    print_iostats_totals(void *, void *, void *);
extern int    print_iostats_totals_summary(void *, void *, int);
extern int    print_io_histogram(void *, void *);
extern int    clear_pid_iostats(void *, void *);
extern int    print_pid_iostats(void *, void *);
extern int    print_pid_iototals(void *);
extern int    print_pid_iototals_csv(void *);
extern int    print_pid_iosum(void *, void *);
extern int    print_pid_miosum(void *, void *);
extern int    print_fd_info(void *, void *);
extern int    print_clear_histogram(void *, void *);

extern void  *prof_filter_func(void *, void *);
extern int    prof_sort_func(const void *, const void *);
extern int    prof_process_func(void *, void *);
extern int    prof_print_func(void *);
extern int    prof_report_func(void *);
extern int    prof_print_report(int);
extern int    prof_bufmiss_func(void *, void *);
extern int    prof_bufswtch_func(void *);
extern int    prof_alarm_func(void *);
extern int    prof_print_global_cpustates();
extern int    prof_print_summary(void *);
extern int    prof_print_percpu_summary();
extern int    print_pid_symbols (void *, void *);


extern int    hc_print_pc(void *, void *);
extern int    hc_print_pc2(void *, void *);
extern int    hc_clear_pc(void *, void *);
extern int    hc_print_stktrc(void *, void *);
extern int    hc_missed_hc(uint64, uint64, void *);
extern int    need_IDLE();
extern int    print_hc_stktrc(void *, void *); 

extern int    wio_pc(uint64);
extern int    wino_pc(uint64);
extern void   wio_init_func(void *);
extern uint64 wio_filter_func(uint64, void *);
extern int    wio_sort_func(const void *, const void *);
extern int    wio_process_func(uint64, void *);
extern int    wio_print_func(void *);
extern int    wio_report_func(void *);
extern int    wio_bufmiss_func(void *, void *);
extern int    wio_bufswtch_func(void *);
extern int    wio_alarm_func(void *);

extern void   wait_init_func(void *);
extern uint64 wait_filter_func(uint64, void *);
extern int    wait_process_func(void *, void *);
extern int    wait_print_func(void *);
extern int    wait_report_func(void *);
extern int    wait_print_report(void *);
extern int    wait_bufmiss_func(void *, void *);
extern int    wait_bufswtch_func(void *);
extern int    wait_alarm_func(void *);

extern void   sock_init_func(void *);
extern uint64 sock_filter_func(uint64, void *);
extern int    sock_process_func(uint64, void *);
extern int    sock_print_func(void *);
extern int    sock_report_func(void *);
extern int    sock_bufmiss_func(void *, void *);
extern int    sock_bufswtch_func(void *);
extern int    sock_alarm_func(void *);
extern int    sock_pertid_syscall_func(uint64, void *, void *);
extern int    ip_print_info(void *, void *);
extern int    ip_print_ports(void *, void *);

extern void   file_init_func(void *);
extern int    futex_process_func(void *, void *);
extern int    futex_print_func(void *);
extern int    futex_report_func(void *);
extern void   futex_print_report();
extern int    futex_print_detail(void *, void *);
extern int    futex_bufswtch_func(void *);
extern int    futex_alarm_func(void *);
extern int    futex_print_ops_detail(void *, void *);
extern int    futex_clear_ops_detail(void *, void *);
extern int    futex_clear_stats(void *, void *);
extern void   futex_print_report_by_time(int);
extern void   futex_print_report_by_cnt(int);

extern void   file_init_func(void *);
extern int    file_process_func(void *, void *);
extern int    file_print_func(void *);
extern int    file_report_func(void *);
extern int    file_print_report(void *);
extern int    file_bufmiss_func(void *, void *);
extern int    file_bufswtch_func(void *);
extern int    file_alarm_func(void *);
extern int    file_pertid_syscall_func(uint64, void *, void *);
extern int    file_print_fdata(void *, void *);
extern int    file_print_fdata_errs(void *, void *);
extern int    file_global_syscall_stats(uint64);
extern int    file_global_open_stats(uint64);
extern int    file_subtype(uint64);
extern int    file_init_fdinfo(uint64, void *);
extern int    sum_fdata_wait_totals(void *, void *);

extern void   socket_init_func(void *);
extern int    socket_process_func(void *, void *);
extern int    socket_print_func(void *);
extern int    socket_report_func(void *);
extern int    socket_print_report(void *);
extern int    socket_print_ipip(void *, void *);
extern int    socket_print_lip(void *, void *);
extern int    socket_print_rip(void *, void *);
extern int    socket_print_lsock(void *, void *);
extern int    socket_print_rsock(void *, void *);
extern int    socket_print_sdata(void *, void *);



extern int	check_for_missed_buffer(void *, void *, int);
extern void   trace_init_func(void *);
void *	      trace_filter_func(void *, void *);
extern int    trace_process_func(void *, void *);
extern int    trace_print_func(void *);
extern int    trace_report_func(void *);
extern int    trace_bufmiss_func(void *, void *);
extern int    trace_generic_func(void *, void *);
extern int    trace_alarm_func(void *);
int trace_walltime_func(void *, void *);
int trace_startup_func(void *, void *);

extern int	print_anon_fault_rec(void *);
extern int	print_filemap_fault_rec(void *);
extern int	print_kernel_pagefault_rec(void *);
extern int	print_page_fault_kernel_rec(void *);
extern int	print_page_fault_user_rec(void *);
extern int	print_tasklet_enqueue_rec(void *);
extern int	print_listen_overflow_rec(void *);
extern int	print_walltime_rec(void *);
extern int	print_startup_rec(void *);

extern void clear_global_stats();
extern int	clear_pid_info(void *, void *);
extern int	clear_hc_info(void **);
extern int	clear_docker_info(void *, void *);
extern void	clear_all_stats();

extern int add_filter_item(void *, uint64);
extern int add_filter_item_str(void *, char *);
extern void ki_syscall_traces_on();

extern int	pid_printf(const char *, ...); 
extern int	csv_printf(FILE *, const char *, ...); 
extern int	json_printf(FILE *, const char *, ...);
extern void     wtree_build(pid_info_t *);
extern FILE	*open_csv_file(char *, int);
extern void	close_csv_file(FILE *);
extern uint64 convert_pc_to_key(uint64);
extern int	add_warning(void **, int *, int, char *);
extern void	add_command(char **, char *);
extern void	add_string(char **, char *);
extern void	repl_command(char **, char *);
extern void	putstr(char **, char *);
extern int	get_status_int(int, char *);
extern int	get_command(void *, void *);
extern int      get_pid_cgroup(void *, void *);
extern int	get_devname(void *, void *);
extern int	get_pathname(void *, void *);
extern int	get_devinfo(void *, void *);
extern int	get_filename(void *, void *);
extern void	print_ip_port(void *, int);
extern void	print_ip_port_v6(void *, int);
extern void	printstr_ip_port_v6(char *, void *, int);
extern void	cp_sockaddr(void **, void *);
extern void	cp_sockip(void **, void *);
extern uint64	pathname_key(char *);
extern void	syscallname_to_syscallno(char *, int *, int *);
extern void 	bt();
extern int 	for_each_file(char *, char *, char *, uint64);
extern double 	duration(uint64, uint64);
extern int	find_switch_start(uint64 *, uint64);
extern uint64   save_kernel_stack(uint64 *, uint64 *, uint64);
extern uint64   save_entire_stack(uint64 *, uint64 *, uint64);
extern int	is_idle_pc(uint64);
extern int	findsym_idx(uint64);
extern char     *findsym(uint64);
extern char 	*pflag(uint64);
extern char	*pstate(int);
extern char	*ioflags(uint64);
extern uint64   devstr_to_dev(char *);
extern char	*ipc_call_str(uint32);
extern char	*semctl_cmd_str(uint32);
extern char	*futex_op_str(uint32);
extern char	*futex_val3_str(uint32);
extern char 	*open_flags_str(uint32);
extern char	*fcntl_cmd_str(uint32);
extern char	*mmap_flags_str(uint32);
extern char	*mmap_prot_str(uint32);
extern char	*shm_flags_str(uint32);
extern char 	*sock_dom_str(uint32);
extern char	*sock_type_str(uint32);
extern char	*signal_str(uint32);
extern char	*sighow_str(uint32);
extern char	*whence_str(uint32);
extern char	*flt_err_codes(uint32);
extern char 	*ktflag(uint64);
extern char 	*ktstate(uint64);
extern char 	*rtype(uint64);
extern char 	*ftypes(uint64, uint64, uint64);
extern char 	*rflags(uint64);
extern char 	*vfsflags(uint64);
extern char 	*mtype(uint64);
extern char 	*bflags(uint64);
extern char 	*b2flags(uint64);
extern char 	*bptype(uint64);
extern char     *fmt_device(uint64);
extern char     *pregop(uint64);
extern char     *regop(uint64);
extern char     *wr_str(uint64);
extern void	set_ioflags();
extern void	set_gfpflags();
extern char     *gfp_flags_str(unsigned int);
extern char	*reqop_name(uint64);
extern int	reqop(uint64);
extern void	print_cpu_buf_info();


extern int	check_filter(void *, uint64);

extern int 	get_fd_str(int, char *, char);
extern int 	put_fd_str(int, char *, char);
extern int	get_fd_int(int, char); 

extern int 	BOLD(const char *, ...);
extern char 	*SPF(char *, const char *, ...);

extern char ts_begin_marker[];
extern char ts_end_marker[];
extern char *bkfname;
extern char *sysignore;
extern char *edusfname;
extern char *jstackfname;
extern char *objfile;
extern char *openfile;
extern char *cmd_str;
extern FILE *pid_csvfile;
extern FILE *dsk_csvfile;
extern FILE *prof_csvfile;
extern FILE *runq_csvfile;
extern FILE *futex_csvfile;
extern FILE *file_csvfile;
extern FILE *socket_csvfile;
extern FILE *wait_csvfile;
extern FILE *cluster_csvfile;
extern FILE *cluster_network_csvfile;
extern FILE *server_vis_csvfile;
extern FILE *cluster_vis_csvfile;
extern FILE *pidfile;
extern FILE *pid_jsonfile;
extern FILE *pid_wtree_jsonfile;
extern FILE *node_csvfile;
extern FILE *pid_timeline_csvfile;

extern int nsym;
extern int npid;
extern int nfile;
extern int nfutex;
extern int vpct;
extern int vdepth;
extern int vint;
extern int top;

extern char passsword_flag;
extern char *trace_tag;
extern uint32 trace_duration;
extern uint32 trace_bufsize;
extern uint32 trace_segments;
extern char *tag;
extern char *debug_dir;
extern uint64 itime;

extern int runq_detail_time;
extern int rqwait;
extern int sock_detail_time;

extern char * som_syms_str(void *, uint64, uint64 *);
extern int som_syms_update(void *);
extern int load_elf(char *, vtxt_preg_t *);
extern int elf_syms32_update(void *);
extern int elf_syms64_update(void *);
extern char * elf_syms32_str(void *, uint64, uint64 *);
extern char * elf_syms64_str(void *, uint64, uint64 *);
extern int txt_syms_type(char *);
extern char *symlookup(void *,  uint64, uint64 *);
extern char *maplookup(void *,  uint64, uint64 *);
extern int print_user_sym(uint64, uint64, char);
extern void print_kernel_sym(unsigned long, char);
extern void print_stacktrace(unsigned long *, unsigned long, int, uint64);
extern char *dmangle(char *);
extern void objdump();
