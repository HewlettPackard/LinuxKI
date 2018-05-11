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

#define KD_ID kdrec.id
#define KD_PID kdrec.pid
#define KD_FLAGS kdrec.flags
#define KD_CUR_TIME trcinfop->cur_time
#define KD_CPU trcinfop->cpu
#define MAXARGS 6
#define TASK_COMM_LEN 16
#define PRINT_COMMON_FIELDS(rec_ptr)  {													\
		if (abstime_flag) {													\
			printf ("%12.09f", rec_ptr->hrtime / 1000000000.0);								\
		} else if ((fmttime_flag || epoch_flag) && (IS_LIKI_V3_PLUS || is_alive)) {							\
			struct timespec curtime, delta_ts;										\
			uint64 delta, dnsecs, dsecs;											\
			char timebuf[30];												\
																	\
			delta = rec_ptr->hrtime - start_time;										\
			dnsecs = delta % 1000000000;											\
			dsecs = delta / 1000000000;											\
			if ((begin_time.tv_nsec + dnsecs) > 1000000000) {								\
				curtime.tv_sec = begin_time.tv_sec + dsecs + 1;								\
				curtime.tv_nsec = begin_time.tv_nsec + dnsecs - 1000000000;						\
			} else {													\
				curtime.tv_nsec = (begin_time.tv_nsec + dnsecs);							\
				curtime.tv_sec = begin_time.tv_sec + dsecs;								\
			}														\
			if (fmttime_flag) {												\
				ctime_r(&curtime.tv_sec, timebuf);									\
				timebuf[19] = 0;											\
				printf ("%s.%06lld", timebuf, curtime.tv_nsec / 1000);							\
			} else {													\
				printf ("%lld.%06lld", curtime.tv_sec, curtime.tv_nsec / 1000);						\
			}														\
		} else {														\
			printf ("%12.06f", (rec_ptr->hrtime - start_time) / 1000000000.0);						\
		}															\
		printf ("%ccpu=%d", fsep, rec_ptr->cpu);										\
		if (seqcnt_flag) printf ("%cseqcnt=%lld ", fsep, rec_ptr->cpu_seqno);							\
		printf ("%cpid=%d%ctgid=%d", fsep, rec_ptr->pid, fsep, rec_ptr->tgid);							\
	}
#define PRINT_KD_REC(rec_ptr)												\
		printf ("%12.06f%ccpu=%d%cpid=%d", 									\
			abstime_flag ? KD_CUR_TIME / 1000000000.0 : (KD_CUR_TIME - start_time) / 1000000000.0,		\
			fsep, KD_CPU,											\
			fsep, rec_ptr->KD_PID)
#define PRINT_EVENT(id) printf ("%c%s", fsep, ki_actions[id].event)
#define PRINT_SYSCALL(pidp, num) if ((pidp->syscall_index == NULL) || (num > MAXSYSCALLS)) {				\
					printf ("[%d]", num);				\
				} else {							\
					printf ("%s", syscall_arg_list[pidp->syscall_index[num]].name);	\
				}

#define KS_ACTION(pidp, syscallno) ks_actions[pidp->syscall_index[syscallno]]

#define	SET_KS_ACTIONS(pidp, is32bit)							\
	/* checking arch_flag is a temp workaruond */					\
	if (IS_LIKI_V1_PLUS) {								\
		/* checking arch_flag is a temp workaruond */				\
		if (is32bit && (arch_flag == X86_64)) {					\
			pidp->syscall_index = globals->syscall_index_32;		\
			pidp->elf = ELF32;						\
		} else {								\
			pidp->syscall_index = globals->syscall_index_64;		\
			pidp->elf = ELF64;						\
		}									\
	} else {									\
		/* if liki v1 or ftrace is used, then we have to rely on the 		\
 		 * lsof parse details.  But if there is no info in the lsof		\
 		 * file, then we have to do some analysis				\
 		 */									\
		if ((pidp->syscall_index == NULL) && (pidp->tgid)) {			\
                	/* Inherit actions from main thread */				\
                	tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);		\
                	pidp->syscall_index = tgidp->syscall_index;			\
			pidp->elf = tgidp->elf;						\
		}									\
	        if (pidp->syscall_index == NULL) {						\
			/* if the syscall_index is still NULL, then assume 64-bit */	\
			pidp->syscall_index = arch_flag ? syscall_index_aarch_64 : syscall_index_x86_64;	\
			pidp->elf = ELF64;						\
		}									\
	}										\

#define IO_READ		0x0			/* used as index into iostats[] array */
#define IO_WRITE	0x1			/* used as index into iostats[] array */
#define IO_TOTAL	0x2			/* used as index into iostats[] array */
#define IO_NONE		0x2

#define TRACE_PRINT		trace_ids.trace_print
#define TRACE_SYS_EXIT		trace_ids.trace_sys_exit
#define TRACE_SYS_ENTER		trace_ids.trace_sys_enter
#define TRACE_SCHED_SWITCH	trace_ids.trace_sched_switch
#define TRACE_SCHED_WAKEUP_NEW  trace_ids.trace_sched_wakeup_new
#define TRACE_SCHED_WAKEUP      trace_ids.trace_sched_wakeup
#define TRACE_SCHED_MIGRATE_TASK	trace_ids.trace_sched_migrate_task
#define TRACE_BLOCK_RQ_ISSUE	trace_ids.trace_block_rq_issue
#define TRACE_BLOCK_RQ_INSERT	trace_ids.trace_block_rq_insert
#define TRACE_BLOCK_RQ_COMPLETE	trace_ids.trace_block_rq_complete
#define TRACE_BLOCK_RQ_REQUEUE	trace_ids.trace_block_rq_requeue
#define TRACE_BLOCK_RQ_ABORT	trace_ids.trace_block_rq_abort
#define TRACE_HARDCLOCK		trace_ids.trace_hardclock
#define TRACE_POWER_START	trace_ids.trace_power_start
#define TRACE_POWER_END		trace_ids.trace_power_end
#define TRACE_POWER_FREQ	trace_ids.trace_power_freq
#define TRACE_IRQ_HANDLER_ENTRY	trace_ids.trace_irq_handler_entry
#define TRACE_IRQ_HANDLER_EXIT	trace_ids.trace_irq_handler_exit
#define TRACE_SOFTIRQ_ENTRY	trace_ids.trace_softirq_entry
#define TRACE_SOFTIRQ_EXIT	trace_ids.trace_softirq_exit
#define TRACE_SOFTIRQ_RAISE	trace_ids.trace_softirq_raise
#define TRACE_SCSI_DISPATCH_CMD_START	trace_ids.trace_scsi_dispatch_cmd_start
#define TRACE_SCSI_DISPATCH_CMD_DONE	trace_ids.trace_scsi_dispatch_cmd_done
#define TRACE_LISTEN_OVERFLOW		trace_ids.trace_listen_overflow
#define TRACE_WALLTIME			trace_ids.trace_walltime
#define TRACE_CPU_FREQ			trace_ids.trace_cpu_freq
#define TRACE_CPU_IDLE			trace_ids.trace_cpu_idle
#define TRACE_WORKQUEUE_INSERTION	trace_ids.trace_workqueue_insertion
#define TRACE_WORKQUEUE_EXECUTION	trace_ids.trace_workqueue_execution
#define TRACE_WORKQUEUE_ENQUEUE		trace_ids.trace_workqueue_enqueue
#define TRACE_WORKQUEUE_EXECUTE		trace_ids.trace_workqueue_execute
#define TRACE_CACHE_INSERT		trace_ids.trace_cache_insert
#define TRACE_CACHE_EVICT		trace_ids.trace_cache_evict
#define TRACE_TASKLET_ENQUEUE		trace_ids.trace_tasklet_enqueue

#define TRACE_PAGE_FAULT_USER		trace_ids.trace_page_fault_user
#define TRACE_PAGE_FAULT_KERNEL		trace_ids.trace_page_fault_kernel
#define TRACE_ANON_FAULT		trace_ids.trace_anon_fault
#define TRACE_FILEMAP_FAULT		trace_ids.trace_filemap_fault
#define TRACE_KERNEL_PAGEFAULT		trace_ids.trace_kernel_pagefault
#define TRACE_MM_PAGE_ALLOC		trace_ids.trace_mm_page_alloc
#define TRACE_MM_PAGE_FREE		trace_ids.trace_mm_page_free
#define TRACE_MM_PAGE_FREE_DIRECT	trace_ids.trace_mm_page_free_direct

typedef struct kd_print {
	kd_rec_t kdrec;
	uint32	filler;
	uint64  ip;
	char	buf[];
} kd_print_t;

typedef struct kdtype_attr {
	char *fieldname;
	short offset;
	short size;
	short sign;
} kdtype_attr_t;

extern kdtype_attr_t block_rq_issue_attr[];
extern kdtype_attr_t block_rq_insert_attr[];
extern kdtype_attr_t block_rq_complete_attr[];
extern kdtype_attr_t block_rq_requeue_attr[];
extern kdtype_attr_t block_rq_abort_attr[];
extern kdtype_attr_t sched_switch_attr[];
extern kdtype_attr_t sched_wakeup_attr[];
extern kdtype_attr_t sched_wakeup_new_attr[];
extern kdtype_attr_t sched_migrate_task_attr[];
extern kdtype_attr_t sys_enter_attr[];
extern kdtype_attr_t sys_exit_attr[];
extern kdtype_attr_t power_start_attr[];
extern kdtype_attr_t power_end_attr[];
extern kdtype_attr_t power_freq_attr[];
extern kdtype_attr_t cpu_freq_attr[];
extern kdtype_attr_t cpu_idle_attr[];
extern kdtype_attr_t irq_handler_entry_attr[];
extern kdtype_attr_t irq_handler_exit_attr[];
extern kdtype_attr_t softirq_entry_attr[];
extern kdtype_attr_t softirq_exit_attr[];
extern kdtype_attr_t softirq_raise_attr[];
extern kdtype_attr_t scsi_dispatch_cmd_start_attr[];
extern kdtype_attr_t scsi_dispatch_cmd_done_attr[];
extern kdtype_attr_t workqueue_insertion_attr[];
extern kdtype_attr_t workqueue_execution_attr[];
extern kdtype_attr_t workqueue_enqueue_attr[];
extern kdtype_attr_t workqueue_execute_attr[];
extern kdtype_attr_t page_fault_attr[];
extern kdtype_attr_t anon_fault_attr[];
extern kdtype_attr_t filemap_fault_attr[];
extern kdtype_attr_t kernel_pagefault_attr[];
extern kdtype_attr_t filemap_pagecache_attr[];
extern kdtype_attr_t mm_page_alloc_attr[];
extern kdtype_attr_t mm_page_free_attr[];
extern kdtype_attr_t listen_overflow[];
extern kdtype_attr_t walltime[];
extern kdtype_attr_t marker_attr[];
