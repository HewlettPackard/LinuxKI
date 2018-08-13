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
extern int cl_perserver_summary(void *, void *);
extern void cl_toc();
extern void cl_sys_summary();
extern void cl_whats_it_doing();
extern void cl_global_cpu();
extern void cl_global_summary();
extern void cl_global_cpu_by_runtime();
extern void cl_global_cpu_by_systime();
extern void cl_power_report();
extern void cl_HT_usage();
extern void cl_busy_pids();
extern void cl_top_pids_summary();
extern void cl_top_pids_runtime();
extern void cl_top_pids_systime();
extern void cl_top_pids_runqtime();
extern void cl_hardclocks();
extern void cl_hc_states();
extern void cl_hc_funcbypid();
extern void cl_th_detection();
extern void cl_whats_it_waiting_for();
extern void cl_switch_reports();
extern void cl_top_switch_pids();
extern void cl_top_switch_pid_funcs();
extern void cl_wait_for_cpu();
extern void cl_runq_statistics();
extern void cl_futex();
extern void cl_futex_summary_by_cnt();
extern void cl_futex_summary_by_time();
extern void cl_file_activity();
extern void cl_file_ops();
extern void cl_file_time();
extern void cl_file_errs();
extern void cl_device_report();
extern void cl_device_globals();
extern void cl_perdev_reports();
extern void cl_active_disks();
extern void cl_permdev_reports();
extern void cl_active_mdevs();
extern void cl_perpid_mdev_totals();
extern void cl_perpid_dev_totals();
extern void cl_network_report();
extern void cl_network_globals();
extern void cl_network_ipip();
extern void cl_network_local_ip();
extern void cl_network_top_sockets();
extern void cl_warnings_report();
extern void cl_server_csv();
extern void cl_network_csv();
