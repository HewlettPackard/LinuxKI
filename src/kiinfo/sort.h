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

extern int kirec_sort_by_curtime(const void *, const void *);

extern int server_sort_by_busy(const void *, const void *);
extern int server_sort_by_runtime(const void *, const void *);
extern int server_sort_by_systime(const void *, const void *);
extern int server_sort_by_power(const void *, const void *);
extern int server_sort_by_dbusy(const void *, const void *);
extern int server_sort_by_iops(const void *, const void *);
extern int server_sort_by_hc(const void *, const void *);
extern int server_sort_by_avrqtime(const void *, const void *);
extern int server_sort_by_netxfrd(const void *, const void *);
extern int clpid_sort_by_runtime(const void *, const void *);
extern int clpid_sort_by_runqtime(const void *, const void *);
extern int clpid_sort_by_systime(const void *, const void *);
extern int clpid_sort_by_wakeups(const void *, const void *);
extern int clpid_sort_by_switch_cnt(const void *, const void *);
extern int clpid_sort_by_sleep_cnt(const void *, const void *);
extern int clpid_sort_by_hc_sys(const void *, const void *);
extern int clpid_sort_by_hc(const void *, const void *);
extern int clpid_sort_by_iops(const void *, const void *);
extern int clpid_sort_by_miops(const void *, const void *);
extern int clfdata_sort_by_syscalls(const void *, const void *);
extern int clfdata_sort_by_elptime(const void *, const void *);
extern int clfdata_sort_by_errs(const void *, const void *);
extern int clfutex_sort_by_cnt(const void *, const void *);
extern int clfutex_sort_by_time(const void *, const void *);
extern int cldev_sort_by_iops(const void *, const void *);
extern int clipip_sort_by_netxfrd(const void *, const void *);
extern int clip_sort_by_netxfrd(const void *, const void *);
extern int clsdata_sort_by_netxfrd(const void *, const void *);

extern int docker_sort_by_runtime(const void *, const void *);
extern int docker_sort_by_iocnt(const void *, const void *);

extern int dkpid_sort_by_runtime(const void *, const void *);
extern int dkpid_sort_by_systime(const void *, const void *);
extern int dkpid_sort_by_runqtime(const void *, const void *);
extern int dkpid_sort_by_rss(const void *, const void *);
extern int dkpid_sort_by_iocnt(const void *, const void *);

extern int pid_sort_by_trace_recs(const void *, const void *);
extern int pid_sort_by_iocnt(const void *, const void *);
extern int pid_sort_by_miocnt(const void *, const void *);
extern int pid_sort_by_runtime(const void *, const void *);
extern int pid_sort_by_runqtime(const void *, const void *);
extern int pid_sort_by_systime(const void *, const void *);
extern int pid_sort_by_stealtime(const void *, const void *);
extern int pid_sort_by_totalsys(const void *, const void *);
extern int pid_sort_by_totalhc(const void *, const void *);
extern int pid_sort_by_hc(const void *, const void *);
extern int pid_sort_by_wakeups(const void *, const void *);
extern int pid_sort_by_sleep_cnt(const void *, const void *);
extern int pid_sort_by_rss(const void *, const void *);
extern int pid_sort_by_vss(const void *, const void *);
extern int slp_scd_sort_by_time(const void *, const void *);
extern int slp_scd_sort_by_count(const void *, const void *);
extern int slp_sort_by_time(const void *, const void *);
extern int slp_sort_by_count(const void *, const void *);
extern int stktrc_sort_by_cnt(const void *, const void *);
extern int stktrc_sort_by_slptime(const void *, const void *);
extern int mpath_sort_by_cpu(const void *, const void *);
extern int fc_sort_by_path(const void *, const void *);
extern int dev_sort_by_count(const void *, const void *);
extern int dev_sort_by_dev(const void *, const void *);
extern int dev_sort_by_mdev(const void *, const void *);
extern int dev_sort_by_avserv(const void *, const void *);
extern int dev_sort_by_avserv_over5(const void *, const void *);
extern int dev_sort_by_avserv_less5(const void *, const void *);
extern int dev_sort_by_avwait(const void *, const void *);
extern int dev_sort_by_requeue(const void *, const void *);
extern int fd_sort_by_type(const void *, const void *);
extern int fd_sort_by_count(const void *, const void *);
extern int fd_sort_by_time(const void *, const void *);
extern int sock_sort_by_count(const void *, const void *);
extern int ip_sort_by_count(const void *, const void *);
extern int futex_dupsort_by_cnt(const void *, const void *);
extern int futex_reqsort_by_cnt(const void *, const void *);
extern int futex_pidsort_by_time(const void *, const void *);
extern int futex_sort_by_time(const void *, const void *);
extern int futex_gblsort_by_time(const void *, const void *);
extern int futex_gblsort_by_cnt(const void *, const void *);
extern int futexops_sort_by_op(const void *, const void *);
extern int futexops_sort_by_time(const void *, const void *);
extern int futexret_sort_by_time(const void *, const void *);
extern int syscall_sort_by_time(const void *, const void *);
extern int syscall_sort_by_cnt(const void *, const void *);
extern int rfsfunc_sort_by_key(const void *, const void *);
extern int pc_sort_by_count(const void *, const void *);
extern int trc_sort_by_count(const void *, const void *);
extern int irq_sort_by_time(const void *, const void *);
extern int tid_sort_by_pvio(const void *, const void *);
extern int tid_sort_by_ioratio(const void *, const void *);
extern int setrq_sort_by_cnt(const void *, const void *);
extern int fdata_sort_by_syscalls(const void *, const void *);
extern int fdata_sort_by_opens(const void *, const void *);
extern int fdata_sort_by_errs(const void *, const void *);
extern int fdata_sort_by_elptime(const void *, const void *);
extern int fdata_sort_by_pgcache(const void *, const void *);
extern int pgcache_sort_by_cnt(const void *, const void *);
extern int ipip_sort_by_syscalls(const void *, const void *);
extern int ip_sort_by_syscalls(const void *, const void *);
extern int sock_sort_by_syscalls(const void *, const void *);
extern int sdata_sort_by_syscalls(const void *, const void *);
extern int sdata_sort_by_opens(const void *, const void *);
extern int sdata_sort_by_errs(const void *, const void *);
extern int sdata_sort_by_elptime(const void *, const void *);
extern int dskblk_sort_by_rdcnt(const void *, const void *);
extern int dskblk_sort_by_wrcnt(const void *, const void *);
extern int pth_sort_by_wait(const void *, const void *);
extern int pth_sort_by_avwait(const void *, const void *);
extern int pth_sort_by_waitcnt(const void *, const void *);
extern int pth_tid_sort_by_wait(const void *, const void *);
extern int pth_tid_sort_by_wait(const void *, const void *);
extern int      coop_sort_scall_by_sleep_time(const void *, const void *);
extern int      coop_sort_scall_by_cnt(const void *, const void *);
extern int      coop_sort_args_by_sleep_time(const void *, const void *);
extern int      coop_sort_args_by_cnt(const void *, const void *);
extern int      coop_sort_slpfuncs_by_sleep_time(const void *, const void *);
extern int sort_by_sleep_percent;
extern int      coop_sort_slpfuncs_by_cnt(const void *, const void *);
extern int      setrq_sort_by_sleep_time(const void *, const void *);
