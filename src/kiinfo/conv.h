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

extern void *   conv_sys_enter(void *, void *);
extern void *   conv_sys_exit(void *, void *);
extern void *   conv_sched_switch(void *, void *);
extern void *   conv_sched_wakeup(void *, void *);
extern void *   conv_sched_wakeup_new(void *, void *);
extern void *   conv_sched_migrate_task(void *, void *);
extern void *   conv_block_rq_issue(void *, void *);
extern void *   conv_block_rq_insert(void *, void *);
extern void *   conv_block_rq_complete(void *, void *);
extern void *   conv_block_rq_requeue(void *, void *);
extern void *   conv_block_rq_abort(void *, void *);
extern void *   conv_hardclock(void *, void *);
extern void *   conv_power_start(void *, void *);
extern void *   conv_power_end(void *, void *);
extern void *   conv_power_freq(void *, void *);
extern void *   conv_cpu_freq(void *, void *);
extern void *   conv_cpu_idle(void *, void *);
extern void *   conv_irq_handler_entry(void *, void *);
extern void *   conv_irq_handler_exit(void *, void *);
extern void *   conv_softirq_entry(void *, void *);
extern void *   conv_softirq_exit(void *, void *);
extern void *   conv_softirq_raise(void *, void *);
extern void *   conv_scsi_dispatch_cmd_start(void *, void *);
extern void *   conv_scsi_dispatch_cmd_done(void *, void *);
extern void *	conv_workqueue_insertion(void *, void *);
extern void *	conv_workqueue_execution(void *, void *);
extern void *	conv_workqueue_enqueue(void *, void *);
extern void *	conv_workqueue_execute(void *, void *);
extern void *	conv_anon_fault(void *, void *);
extern void *	conv_filemap_fault(void *, void *);
extern void *	conv_kernel_pagefault(void *, void *);
extern void *	conv_page_fault(void *, void *);
extern void *	conv_cache_insert(void *, void *);
extern void *	conv_cache_evict(void *, void *);
extern char *   get_marker_buf(void *);
extern void *   conv_common_rec(void *, void *);
