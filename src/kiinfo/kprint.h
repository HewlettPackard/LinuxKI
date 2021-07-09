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

extern void  kp_sys_summary();
extern void  kp_toc();
extern void  kp_whats_it_doing();
extern void  kp_global_cpu();
extern void  kp_per_cpu_usage();
extern void  kp_per_ldom_usage();
extern void  kp_per_fsid_usage();
extern void  kp_HT_usage();
extern void  kp_busy_pids();
extern void  kp_top_pids_runtime();
extern void  kp_top_pids_systime();
extern void  kp_trace_types();
extern void  kp_global_trace_types();
extern void  kp_top_pid_trace_counts();
extern void  kp_top_pid_trace_types();
extern void  kp_hardclocks();
extern void  kp_power_report();
extern void  kp_cpustates();
extern void  kp_hc_bycpu();
extern void  kp_hc_kernfuncs();
extern void  kp_hc_stktraces();
extern void  kp_hc_funcbypid();
extern void  kp_hc_bypid();
extern void  kp_th_detection();
extern void  kp_irq();
extern void  kp_hardirqs();
extern void  kp_hardirqs_by_cpu();
extern void  kp_softirqs();
extern void  kp_whats_it_waiting_for();
extern void  kp_swtch_reports();
extern void  kp_freq_swtch_funcs();
extern void  kp_freq_swtch_stktrc();
extern void  kp_top_swtch_pids();
extern void  kp_top_swtch_pid_funcs();
extern void  kp_top_pids_stealtime();
extern void  kp_wait_for_cpu();
extern void  kp_runq_histogram();
extern void  kp_runq_statistics();
extern void  kp_runq_top10();
extern void  kp_top_runq_pids();
extern void  kp_futex();
extern void  kp_futex_summary();
extern void  kp_futex_summary_by_cnt();
extern void  kp_futex_summary_by_time();
extern void  kp_file_activity();
extern void  kp_file_ops();
extern void  kp_file_time();
extern void  kp_file_errs();
extern void  kp_top_files();
extern void  kp_file_logio();		/* for Windows */
extern void  kp_file_physio();		/* for Windows */
extern void  kp_device_report();
extern void  kp_device_globals();
extern void  kp_perdev_reports();
extern void  kp_active_disks();
extern void  kp_highserv1_disks();
extern void  kp_highserv2_disks();
extern void  kp_highwait_disks();
extern void  kp_dsk_histogram();
extern void  kp_perpid_dev_totals();
extern void  kp_dskblk_read();
extern void  kp_dskblk_write();
extern void  kp_io_controllers();
extern void  kp_requeue_disks();
extern void  kp_mapper_report();
extern void  kp_active_mapper_devs();
extern void  kp_hiserv_mapper_devs();
extern void  kp_fc_totals();
extern void  kp_wwn_totals();
extern void  kp_perpid_mdev_totals();
extern void  kp_memory();
extern void  kp_dimm();
extern void  kp_rss();
extern void  kp_vss();
extern void  kp_oracle();
extern void  kp_oracle_sids();
extern void  kp_lgwr_analysis();
extern void  kp_arch_analysis();
extern void  kp_dbw_analysis();
extern void  kp_pquery_analysis();
extern void  kp_ioslave_analysis();
extern void  kp_shared_server_analysis();
extern void  kp_network();
extern void  kp_ipip();
extern void  kp_remoteip();
extern void  kp_localip();
extern void  kp_remoteport();
extern void  kp_localport();
extern void  kp_socket();
extern void  kp_timeo_retrans();
extern void  kp_dockers();
extern void  kp_docker_cpu();
extern void  kp_docker_io();
extern void  kp_docker_ps();
extern void  kp_file_links();
extern void  kp_txt_links();
extern void  kp_csv_links();
extern void  kp_misc_links();
extern void  kp_vis_links();
extern void  kp_warnings_report();
extern int kp_warning (warn_t *, int, char *);

