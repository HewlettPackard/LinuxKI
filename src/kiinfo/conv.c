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
#include <time.h>
#include <string.h>
#include <sys/errno.h>
#include "ki_tool.h"
#include "liki.h"
#include "liki_v1.h"
#include "liki_v2.h"
#include "liki_v3.h"
#include "liki_extra.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "info.h"
#include "conv.h"

#define SET_COMMON_FIELDS(trcinfop, p1, p2) 	\
	p1->cpu_seqno = 0;                      \
	p1->id = p2->id;                        \
	p1->pid = p2->pid;                      \
	p1->hrtime = trcinfop->cur_time;        \
	p1->cpu = trcinfop->cpu;		\
	p1->tgid = 0;				\
	p1->spare = 0;

#define SET_COMMON_FIELDS_WINKI(trcinfop, p1, p2)	\
	p1->cpu_seqno = 0;                      \
	p1->id = p2->EventType; 		\
	p1->cpu = trcinfop->cpu;		\
	p1->pid = 0;	                        \
	p1->tgid = 0;				\
	p1->spare = 0;

#define COPY_COMMON_FIELDS(p1, p2)     		\
	memcpy(p1, p2, sizeof(common_t))

#define CONV_COMMON_FIELDS_V1_V2(p1, p2)		\
	memcpy(p1, p2, sizeof(common_v1_t));		\
	p1->tgid = 0;					\
	p1->spare = 0;

#define COPY_NONCOMMON_FIELDS_V1_V2(p1, p2, s2)				\
		memcpy( (char *)p1 + sizeof(common_t),			\
			(char *)p2 + sizeof(common_v1_t),		\
			 sizeof(s2) - sizeof(common_v1_t) );		

#define COPY_VARIABLE_FIELDS(p1, s1, p2, s2)			\
	if (p2->reclen > sizeof(s2) )				\
		memcpy( (char *)p1 + sizeof(s1),		\
			(char *)p2 + sizeof(s2),		\
			p2->reclen - sizeof(s2) );		

#define SYS_ENTER_ID    0
#define SYS_ENTER_ARGS  1
#define SYS_ENTER_ARGS2 2
#define SYS_ENTER_ARGS3 3
#define SYS_EXIT_ID     0
#define SYS_EXIT_RET    1
#define SCHED_SWITCH_PREV_COMM          0
#define SCHED_SWITCH_PREV_PID           1
#define SCHED_SWITCH_PREV_PRIO          2
#define SCHED_SWITCH_PREV_STATE         3
#define SCHED_SWITCH_NEXT_COMM          4
#define SCHED_SWITCH_NEXT_PID           5
#define SCHED_SWITCH_NEXT_PRIO          6
#define SCHED_WAKEUP_COMM               0
#define SCHED_WAKEUP_PID                1
#define SCHED_WAKEUP_PRIO               2
#define SCHED_WAKEUP_SUCCESS            3
#define SCHED_WAKEUP_CPU                4
#define SCHED_MIGRATE_TASK_COMM         0
#define SCHED_MIGRATE_TASK_PID          1
#define SCHED_MIGRATE_TASK_PRIO         2
#define SCHED_MIGRATE_TASK_ORIG_CPU     3
#define SCHED_MIGRATE_TASK_DEST_CPU     4
#define BLOCK_RQ_DEV            0
#define BLOCK_RQ_SECTOR         1
#define BLOCK_RQ_NR_SECTOR      2
#define BLOCK_RQ_RWBS           3
#define BLOCK_RQ_BYTES          4
#define BLOCK_RQ_ERRORS         4
#define BLOCK_RQ_CMD            5
#define BLOCK_RQ_COMM           6
#define POWER_START_TYPE        0
#define POWER_START_STATE       1
#define POWER_START_CPUID       2
#define POWER_END_CPUID         0
#define POWER_FREQ_TYPE         0
#define POWER_FREQ_STATE        1
#define POWER_FREQ_CPUID        2
#define CPU_FREQ_STATE          0
#define CPU_FREQ_CPUID          1
#define CPU_IDLE_STATE          0
#define CPU_IDLE_CPUID          1
#define IRQ_HANDLER_IRQ         0
#define IRQ_HANDLER_NAME        1
#define IRQ_HANDLER_RET         1
#define SOFTIRQ_VEC     0
#define SCSI_CMD_HOST   0
#define SCSI_CMD_CHANNEL        1
#define SCSI_CMD_ID     2
#define SCSI_CMD_LUN    3
#define SCSI_CMD_TYPE   4
#define SCSI_CMD_OPCODE 5
#define SCSI_CMD_CMDLEN 6
#define SCSI_CMD_DATA_SGLEN     7
#define SCSI_CMD_PROT_SGLEN     8
#define SCSI_CMD_CMND   9
#define SCSI_CMD_RET            10

#define WORKQUEUE_INSERTION_FUNC	2
#define WORKQUEUE_EXECUTION_FUNC	2
#define WORKQUEUE_ENQUEUE_FUNC		1
#define WORKQUEUE_ENQUEUE_CPU		4
#define WORKQUEUE_EXECUTE_FUNC		1

#define ANON_FAULT_ADDR			1
#define FILEMAP_FAULT_ADDR		1
#define FILEMAP_FAULT_FLAG		2
#define KERNEL_PAGEFAULT_ADDR		1
#define PAGE_FAULT_ADDR			0
#define PAGE_FAULT_IP			1
#define PAGE_FAULT_ERR			2

#define FILEMAP_PAGECACHE_PAGE		0
#define FILEMAP_PAGECACHE_INO		1
#define FILEMAP_PAGECACHE_IDX		2
#define FILEMAP_PAGECACHE_DEV		3

#define MM_PAGE_ALLOC_PAGE		0
#define MM_PAGE_ALLOC_ORDER		1
#define MM_PAGE_ALLOC_FLAGS		2
#define MM_PAGE_ALLOC_TYPE		3

#define MM_PAGE_FREE_PAGE		0
#define MM_PAGE_FREE_ORDER		1

#define MARKER_IP       0
#define MARKER_BUF      1

static uint32
get_ioflags_from_rwbs (char *rwbs)
{
	uint32 ioflags = 0;
	char f_count = 0;
	int i;


	for (i=0; i < strlen(rwbs); i++) {
		switch(rwbs[i]) {
		case 'F':
			if (f_count) {
				ioflags |= REQ_FUA;
			} else {
				ioflags |= REQ_FLUSH;
				f_count = 1;
			}
			break;
		case 'D':  ioflags |= REQ_DISCARD; break;
		case 'A':  ioflags |= REQ_FAILFAST_DEV; break;
		case 'B':  ioflags |= REQ_SOFTBARRIER; break;
		case 'M':  ioflags |= REQ_META; break;
		case 'W':  ioflags |= REQ_WRITE; break;
		case 'S':  ioflags |= REQ_SYNC; break;
		case 'N':  break;
		case 'R':  break;
		default:
			printf ("Unexpected RWBS character %c in %s\n", rwbs[i], rwbs);
		}
	}

	return ioflags;
}

void *
conv_sys_enter(void *arg1, void *arg2) 
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        syscall_enter_v1_t *v1_rec = (syscall_enter_v1_t *)trcinfop->cur_rec;
        syscall_enter_v2_t *v2_rec = (syscall_enter_v2_t *)trcinfop->cur_rec;
        syscall_enter_t *rec_ptr = (syscall_enter_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, syscall_enter_v2_t);
		COPY_VARIABLE_FIELDS(rec_ptr, syscall_enter_t, v2_rec, syscall_enter_v2_t);
		rec_ptr->reclen = v2_rec->reclen + (sizeof(syscall_enter_t) - sizeof(syscall_enter_v2_t));
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v1_rec, syscall_enter_v1_t);
		COPY_VARIABLE_FIELDS(rec_ptr, syscall_enter_t, v1_rec, syscall_enter_v1_t);
		rec_ptr->is32bit = 0;
		rec_ptr->reclen = v1_rec->reclen + (sizeof(syscall_enter_t) - sizeof(syscall_enter_v1_t));
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(syscall_enter_t);

	memcpy (&rec_ptr->syscallno, (char *)ftrace_rec + sys_enter_attr[SYS_ENTER_ID].offset, sys_enter_attr[SYS_ENTER_ID].size);
	if (sys_enter_attr[SYS_ENTER_ARGS3].offset) {
		memcpy (&rec_ptr->args[0], (char *)ftrace_rec + sys_enter_attr[SYS_ENTER_ARGS3].offset, sys_enter_attr[SYS_ENTER_ARGS3].size);
	} else if (sys_enter_attr[SYS_ENTER_ARGS2].offset) {
		memcpy (&rec_ptr->args[0], (char *)ftrace_rec + sys_enter_attr[SYS_ENTER_ARGS2].offset, sys_enter_attr[SYS_ENTER_ARGS2].size);
	} else {
		memcpy (&rec_ptr->args[0], (char *)ftrace_rec + sys_enter_attr[SYS_ENTER_ARGS].offset, sys_enter_attr[SYS_ENTER_ARGS].size);
	}
	rec_ptr->is32bit = 0;

	return rec_ptr;
}

void *
conv_sys_exit(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        syscall_exit_v1_t *v1_rec = (syscall_exit_v1_t *)trcinfop->cur_rec;
        syscall_exit_v2_t *v2_rec = (syscall_exit_v2_t *)trcinfop->cur_rec;
        syscall_exit_t *rec_ptr = (syscall_exit_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, syscall_exit_v2_t);
		COPY_VARIABLE_FIELDS(rec_ptr, syscall_exit_t, v2_rec, syscall_exit_v2_t);
		rec_ptr->reclen = v2_rec->reclen + (sizeof(syscall_exit_t) - sizeof(syscall_exit_v2_t));
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v1_rec, syscall_exit_v1_t);
		COPY_VARIABLE_FIELDS(rec_ptr, syscall_exit_t, v1_rec, syscall_exit_v1_t);
		rec_ptr->is32bit = 0;
		rec_ptr->reclen = v1_rec->reclen + (sizeof(syscall_exit_t) - sizeof(syscall_exit_v1_t));
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(syscall_exit_t);
	memcpy (&rec_ptr->syscallno, (char *)ftrace_rec + sys_exit_attr[SYS_EXIT_ID].offset, sys_exit_attr[SYS_EXIT_ID].size);
	memcpy (&rec_ptr->ret, (char *)ftrace_rec + sys_exit_attr[SYS_EXIT_RET].offset, sys_exit_attr[SYS_EXIT_RET].size);
	rec_ptr->is32bit = 0;

	return rec_ptr;
}

uint64
conv_stack_trace(uint64 *dest, uint64 *src, uint64 pctype) 
{
	int i;
	uint64 stack_depth = 0;

	if (!VALID_STACK(src[0]))  return 0;
	
	dest[0] = pctype;
	stack_depth = 1;

	for (i=0; i < LEGACY_STACK_DEPTH; i++) {
		if (src[i] == END_STACK) break;	
		dest[i+1] = src[i];
		stack_depth++;
	}

	return stack_depth;
}	
		
		
		


void *
conv_sched_switch(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	sched_switch_v1_t *v1_rec = (sched_switch_v1_t *)trcinfop->cur_rec;
	sched_switch_v2_t *v2_rec = (sched_switch_v2_t *)trcinfop->cur_rec;
	sched_switch_v3_t *v3_rec = (sched_switch_v3_t *)trcinfop->cur_rec;
        sched_switch_t *rec_ptr = (sched_switch_t *)arg2;

	if (IS_LIKI_V4_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V3) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->prev_state = v3_rec->prev_state;
		rec_ptr->prev_prio = v3_rec->prev_prio;
		rec_ptr->next_pid = v3_rec->next_pid;
		rec_ptr->next_tgid = v3_rec->next_tgid;
		rec_ptr->next_policy = v3_rec->next_policy;
		rec_ptr->next_prio = v3_rec->next_prio;
		rec_ptr->syscallno = v3_rec->syscallno;
		rec_ptr->irq_time = v3_rec->irq_time;
		rec_ptr->softirq_time = v3_rec->softirq_time;
		rec_ptr->total_vm = v3_rec->total_vm;
		rec_ptr->total_rss = v3_rec->total_rss;
		memcpy(&rec_ptr->prev_comm[0], &v3_rec->prev_comm[0], TASK_COMM_LEN * sizeof(char));

		rec_ptr->stack_depth = v3_rec->stack_depth;
		if (rec_ptr->stack_depth > 128) rec_ptr->stack_depth = 128;
		memcpy(&rec_ptr->ips[0], &v3_rec->ips[0], rec_ptr->stack_depth * sizeof(uint64));
		rec_ptr->reclen = sizeof(sched_switch_t) + (rec_ptr->stack_depth * sizeof(uint64));

		rec_ptr->stealtime = 0;
		return rec_ptr;
	}

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->prev_state = v2_rec->prev_state;
		rec_ptr->prev_prio = v2_rec->prev_prio;
		rec_ptr->next_pid = v2_rec->next_pid;
		rec_ptr->next_tgid = v2_rec->next_tgid;
		rec_ptr->next_policy = v2_rec->next_policy;
		rec_ptr->next_prio = v2_rec->next_prio;
		rec_ptr->syscallno = v2_rec->syscallno;
		rec_ptr->irq_time = v2_rec->irq_time;
		rec_ptr->softirq_time = v2_rec->softirq_time;
		rec_ptr->total_vm = v2_rec->total_vm;
		rec_ptr->total_rss = v2_rec->total_rss;
		memcpy(&rec_ptr->prev_comm[0], &v2_rec->prev_comm[0], TASK_COMM_LEN * sizeof(char));

		rec_ptr->stack_depth = conv_stack_trace(&rec_ptr->ips[0], &v2_rec->stacktrace[0], STACK_CONTEXT_KERNEL);
		rec_ptr->reclen = sizeof(sched_switch_t) + (rec_ptr->stack_depth * sizeof(uint64));
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->prev_state = v1_rec->prev_state;
		rec_ptr->prev_prio = v1_rec->prev_prio;
		rec_ptr->next_pid = v1_rec->next_pid;
		rec_ptr->next_tgid = v1_rec->next_tgid;
		rec_ptr->next_policy = v1_rec->next_policy;
		rec_ptr->next_prio = v1_rec->next_prio;
		rec_ptr->syscallno = 0;
		rec_ptr->irq_time = 0;
		rec_ptr->softirq_time = 0;
		rec_ptr->total_vm = 0;
		rec_ptr->total_rss = 0;
		memcpy(&rec_ptr->prev_comm[0], &v1_rec->prev_comm[0], TASK_COMM_LEN * sizeof(char));

		rec_ptr->stack_depth = conv_stack_trace(&rec_ptr->ips[0], &v1_rec->stacktrace[0], STACK_CONTEXT_KERNEL);
		rec_ptr->reclen = sizeof(sched_switch_t) + (rec_ptr->stack_depth * sizeof(uint64));
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(sched_switch_t);
	memcpy (&rec_ptr->prev_comm, (char *)ftrace_rec + sched_switch_attr[SCHED_SWITCH_PREV_COMM].offset, sched_switch_attr[SCHED_SWITCH_PREV_COMM].size);
	memcpy (&rec_ptr->prev_state, (char *)ftrace_rec + sched_switch_attr[SCHED_SWITCH_PREV_STATE].offset, sched_switch_attr[SCHED_SWITCH_PREV_STATE].size);
	memcpy (&rec_ptr->prev_prio, (char *)ftrace_rec + sched_switch_attr[SCHED_SWITCH_PREV_PRIO].offset, sched_switch_attr[SCHED_SWITCH_PREV_PRIO].size);
	memcpy (&rec_ptr->next_pid, (char *)ftrace_rec + sched_switch_attr[SCHED_SWITCH_NEXT_PID].offset, sched_switch_attr[SCHED_SWITCH_NEXT_PID].size);
	memcpy (&rec_ptr->next_prio, (char *)ftrace_rec + sched_switch_attr[SCHED_SWITCH_NEXT_PRIO].offset, sched_switch_attr[SCHED_SWITCH_NEXT_PRIO].size);
	rec_ptr->stack_depth=0;
	rec_ptr->next_tgid = 0;
	rec_ptr->irq_time = 0;
	rec_ptr->softirq_time = 0;
	rec_ptr->total_vm = 0;
	rec_ptr->total_rss = 0;

	return rec_ptr;
}

void *
conv_sched_wakeup(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        sched_wakeup_v2_t *v2_rec = (sched_wakeup_v2_t *)trcinfop->cur_rec;
        sched_wakeup_t *rec_ptr = (sched_wakeup_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2 || IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, sched_wakeup_v2_t);
		rec_ptr->reclen = sizeof(sched_wakeup_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(sched_wakeup_t);
	memcpy (&rec_ptr->target_pid, (char *)ftrace_rec + sched_wakeup_attr[SCHED_WAKEUP_PID].offset, sched_wakeup_attr[SCHED_WAKEUP_PID].size);
	memcpy (&rec_ptr->target_pri, (char *)ftrace_rec + sched_wakeup_attr[SCHED_WAKEUP_PRIO].offset, sched_wakeup_attr[SCHED_WAKEUP_PRIO].size);
	memcpy (&rec_ptr->success, (char *)ftrace_rec + sched_wakeup_attr[SCHED_WAKEUP_SUCCESS].offset, sched_wakeup_attr[SCHED_WAKEUP_SUCCESS].size);
	memcpy (&rec_ptr->target_cpu, (char *)ftrace_rec + sched_wakeup_attr[SCHED_WAKEUP_CPU].offset, sched_wakeup_attr[SCHED_WAKEUP_CPU].size);

	return rec_ptr;
}

void *
conv_sched_migrate_task(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        sched_migrate_task_v2_t *v2_rec = (sched_migrate_task_v2_t *)trcinfop->cur_rec;
        sched_migrate_task_t *rec_ptr = (sched_migrate_task_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2 || IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->target_pid = v2_rec->target_pid;
		rec_ptr->target_pri = v2_rec->target_pri;
		rec_ptr->orig_cpu = v2_rec->orig_cpu;
		rec_ptr->dest_cpu = v2_rec->dest_cpu;
		rec_ptr->stack_depth = conv_stack_trace(&rec_ptr->ips[0], &v2_rec->stacktrace[0], STACK_CONTEXT_KERNEL);
		rec_ptr->reclen = sizeof(sched_migrate_task_t) + (rec_ptr->stack_depth * sizeof(uint64));
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	memcpy (&rec_ptr->target_pid, (char *)ftrace_rec + sched_migrate_task_attr[SCHED_MIGRATE_TASK_PID].offset, sched_migrate_task_attr[SCHED_MIGRATE_TASK_PID].size);
	memcpy (&rec_ptr->target_pri, (char *)ftrace_rec + sched_migrate_task_attr[SCHED_MIGRATE_TASK_PRIO].offset, sched_migrate_task_attr[SCHED_MIGRATE_TASK_PRIO].size);
	memcpy (&rec_ptr->orig_cpu, (char *)ftrace_rec + sched_migrate_task_attr[SCHED_MIGRATE_TASK_ORIG_CPU].offset, sched_migrate_task_attr[SCHED_MIGRATE_TASK_ORIG_CPU].size);
	memcpy (&rec_ptr->dest_cpu, (char *)ftrace_rec + sched_migrate_task_attr[SCHED_MIGRATE_TASK_DEST_CPU].offset, sched_migrate_task_attr[SCHED_MIGRATE_TASK_DEST_CPU].size);
	rec_ptr->stack_depth = 0;
	rec_ptr->reclen = sizeof(sched_migrate_task_t);
	return rec_ptr;
}

void *
conv_block_rq_insert(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        block_rq_insert_v1_t *v1_rec = (block_rq_insert_v1_t *)trcinfop->cur_rec;
        block_rq_insert_v2_t *v2_rec = (block_rq_insert_v2_t *)trcinfop->cur_rec;
        block_rq_insert_v3_t *v3_rec = (block_rq_insert_v3_t *)trcinfop->cur_rec;
        block_rq_insert_t *rec_ptr = (block_rq_insert_t *)arg2;
	char *ptr;

	if (IS_LIKI_V5_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V3_PLUS) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->dev = v3_rec->dev;
		rec_ptr->sector = v3_rec->sector;
		rec_ptr->nr_sectors = v3_rec->nr_sectors;
		rec_ptr->bytes = v3_rec->bytes;
		rec_ptr->cmd_type = v3_rec->cmd_type;
		rec_ptr->cmd_flags = v3_rec->cmd_flags;
		rec_ptr->async_in_flight = v3_rec->async_in_flight;
		rec_ptr->sync_in_flight = v3_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_insert_t);
		return rec_ptr;
	}

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->dev = v2_rec->dev;
		rec_ptr->sector = v2_rec->sector;
		rec_ptr->nr_sectors = v2_rec->nr_sectors;
		rec_ptr->bytes = v2_rec->bytes;
		rec_ptr->cmd_type = v2_rec->cmd_type;
		rec_ptr->cmd_flags = v2_rec->cmd_flags;
		rec_ptr->async_in_flight = v2_rec->async_in_flight;
		rec_ptr->sync_in_flight = v2_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_insert_t);
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->dev = v1_rec->dev;
		rec_ptr->sector = v1_rec->sector;
		rec_ptr->nr_sectors = v1_rec->nr_sectors;
		rec_ptr->bytes = v1_rec->bytes;
		rec_ptr->cmd_type = v1_rec->cmd_type;
		rec_ptr->cmd_flags = v1_rec->cmd_flags;
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
		rec_ptr->reclen = sizeof(block_rq_insert_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(block_rq_insert_t);
	ptr = (char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_DEV].offset;
	if (block_rq_insert_attr[BLOCK_RQ_DEV].size == 4) {
		rec_ptr->dev = (uint32)(*ptr);
	} else if (block_rq_insert_attr[BLOCK_RQ_DEV].size == 8) {
		rec_ptr->dev = (uint64)(*ptr);
	} else {
		FATAL(3301, "Unknown device size", "dev size:", block_rq_insert_attr[BLOCK_RQ_DEV].size);
	}
		
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_DEV].offset, block_rq_insert_attr[BLOCK_RQ_DEV].size);
	memcpy (&rec_ptr->sector, (char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_SECTOR].offset, block_rq_insert_attr[BLOCK_RQ_SECTOR].size);
	memcpy (&rec_ptr->nr_sectors, (char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_NR_SECTOR].offset, block_rq_insert_attr[BLOCK_RQ_NR_SECTOR].size);
	memcpy (&rec_ptr->bytes, (char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_BYTES].offset, block_rq_insert_attr[BLOCK_RQ_BYTES].size);
	rec_ptr->cmd_flags = get_ioflags_from_rwbs((char *)ftrace_rec + block_rq_insert_attr[BLOCK_RQ_RWBS].offset);
	rec_ptr->async_in_flight = 0;
	rec_ptr->sync_in_flight = 0;

	return rec_ptr;
}

void *
conv_block_rq_issue(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	block_rq_issue_v1_t *v1_rec = (block_rq_issue_v1_t *)trcinfop->cur_rec;
	block_rq_issue_v2_t *v2_rec = (block_rq_issue_v2_t *)trcinfop->cur_rec;
	block_rq_issue_v3_t *v3_rec = (block_rq_issue_v3_t *)trcinfop->cur_rec;
	DiskIo_Init_t *winki_rec = (DiskIo_Init_t *)trcinfop->cur_rec;
        block_rq_issue_t *rec_ptr = (block_rq_issue_t *)arg2;
	char *ptr;

	if (IS_LIKI_V5_PLUS) {
		return trcinfop->cur_rec;
	} else if (IS_LIKI_V3_PLUS) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->dev = v3_rec->dev;
		rec_ptr->sector = v3_rec->sector;
		rec_ptr->nr_sectors = v3_rec->nr_sectors;
		rec_ptr->bytes = v3_rec->bytes;
		rec_ptr->cmd_type = v3_rec->cmd_type;
		rec_ptr->cmd_flags = v3_rec->cmd_flags;
		rec_ptr->start_time_ns = v3_rec->start_time_ns;
		rec_ptr->async_in_flight = v3_rec->async_in_flight;
		rec_ptr->sync_in_flight = v3_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_issue_t);
		return rec_ptr;
	} else if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->dev = v2_rec->dev;
		rec_ptr->sector = v2_rec->sector;
		rec_ptr->nr_sectors = v2_rec->nr_sectors;
		rec_ptr->bytes = v2_rec->bytes;
		rec_ptr->cmd_type = v2_rec->cmd_type;
		rec_ptr->cmd_flags = v2_rec->cmd_flags;
		rec_ptr->start_time_ns = v2_rec->start_time_ns;
		rec_ptr->async_in_flight = v2_rec->async_in_flight;
		rec_ptr->sync_in_flight = v2_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_issue_t);
		return rec_ptr;
	} else if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->dev = v1_rec->dev;
		rec_ptr->sector = v1_rec->sector;
		rec_ptr->nr_sectors = v1_rec->nr_sectors;
		rec_ptr->bytes = v1_rec->bytes;
		rec_ptr->cmd_type = v1_rec->cmd_type;
		rec_ptr->cmd_flags = v1_rec->cmd_flags;
		rec_ptr->start_time_ns = v1_rec->start_time_ns;
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
		rec_ptr->reclen = sizeof(block_rq_issue_t);
		return rec_ptr;
#if 0
	} else if (IS_WINKI) {
		SET_COMMON_FIELDS_WINKI(trcinfop, rec_ptr, winki_rec, TT_BLOCK_RQ_ISSUE, winki_rec->IssuingThreadId, 0);
		rec_ptr->reclen = sizeof(block_rq_issue_t);
		rec_ptr->irp = winki_rec->irp;
		return rec_ptr;
#endif
	} else {
		SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
		rec_ptr->reclen = sizeof(block_rq_issue_t);
		ptr = (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_DEV].offset;
		if (block_rq_issue_attr[BLOCK_RQ_DEV].size == 4) {
			rec_ptr->dev = (uint32)(*ptr);
		} else if (block_rq_issue_attr[BLOCK_RQ_DEV].size == 8) {
			rec_ptr->dev = (uint64)(*ptr);
		} else {
			FATAL(3302, "Unknown device size", "dev size:", block_rq_issue_attr[BLOCK_RQ_DEV].size);
		}
		
		memcpy (&rec_ptr->dev, (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_DEV].offset, block_rq_issue_attr[BLOCK_RQ_DEV].size);
		memcpy (&rec_ptr->sector, (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_SECTOR].offset, block_rq_issue_attr[BLOCK_RQ_SECTOR].size);
		memcpy (&rec_ptr->nr_sectors, (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_NR_SECTOR].offset, block_rq_issue_attr[BLOCK_RQ_NR_SECTOR].size);
		memcpy (&rec_ptr->bytes, (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_BYTES].offset, block_rq_issue_attr[BLOCK_RQ_BYTES].size);
		/* memcpy (&rec_ptr->comm, (char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_COMM].offset, block_rq_issue_attr[BLOCK_RQ_COMM].size); */
		rec_ptr->cmd_flags = get_ioflags_from_rwbs((char *)ftrace_rec + block_rq_issue_attr[BLOCK_RQ_RWBS].offset);
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
	
		return rec_ptr;
	}
}

void *
conv_block_rq_complete(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        block_rq_complete_v1_t *v1_rec = (block_rq_complete_v1_t *)trcinfop->cur_rec;
        block_rq_complete_v2_t *v2_rec = (block_rq_complete_v2_t *)trcinfop->cur_rec;
        block_rq_complete_v3_t *v3_rec = (block_rq_complete_v3_t *)trcinfop->cur_rec;
        block_rq_complete_t *rec_ptr = (block_rq_complete_t *)arg2;
	char *ptr;

	if (IS_LIKI_V5_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V3_PLUS) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->dev = v3_rec->dev;
		rec_ptr->sector = v3_rec->sector;
		rec_ptr->nr_sectors = v3_rec->nr_sectors;
		rec_ptr->bytes = v3_rec->bytes;
		rec_ptr->cmd_type = v3_rec->cmd_type;
		rec_ptr->cmd_flags = v3_rec->cmd_flags;
		rec_ptr->start_time_ns = v3_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v3_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v3_rec->async_in_flight;
		rec_ptr->sync_in_flight = v3_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_complete_t);
		return rec_ptr;
	}

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->dev = v2_rec->dev;
		rec_ptr->sector = v2_rec->sector;
		rec_ptr->nr_sectors = v2_rec->nr_sectors;
		rec_ptr->bytes = v2_rec->bytes;
		rec_ptr->cmd_type = v2_rec->cmd_type;
		rec_ptr->cmd_flags = v2_rec->cmd_flags;
		rec_ptr->start_time_ns = v2_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v2_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v2_rec->async_in_flight;
		rec_ptr->sync_in_flight = v2_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_complete_t);
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->dev = v1_rec->dev;
		rec_ptr->sector = v1_rec->sector;
		rec_ptr->nr_sectors = v1_rec->nr_sectors;
		rec_ptr->bytes = v1_rec->bytes;
		rec_ptr->cmd_type = v1_rec->cmd_type;
		rec_ptr->cmd_flags = v1_rec->cmd_flags;
		rec_ptr->start_time_ns = v1_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v1_rec->io_start_time_ns;
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
		rec_ptr->reclen = sizeof(block_rq_complete_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(block_rq_complete_t);
	ptr = (char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_DEV].offset;
	if (block_rq_complete_attr[BLOCK_RQ_DEV].size == 4) {
		rec_ptr->dev = (uint32)(*ptr);
	} else if (block_rq_complete_attr[BLOCK_RQ_DEV].size == 8) {
		rec_ptr->dev = (uint64)(*ptr);
	} else {
		FATAL(3303, "Unknown device size", "dev size:", block_rq_complete_attr[BLOCK_RQ_DEV].size);
	}
		
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_DEV].offset, block_rq_complete_attr[BLOCK_RQ_DEV].size);
	memcpy (&rec_ptr->sector, (char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_SECTOR].offset, block_rq_complete_attr[BLOCK_RQ_SECTOR].size);
	memcpy (&rec_ptr->nr_sectors, (char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_NR_SECTOR].offset, block_rq_complete_attr[BLOCK_RQ_NR_SECTOR].size);
	/* memcpy (&rec_ptr->comm, (char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_COMM].offset, block_rq_complete_attr[BLOCK_RQ_COMM].size); */
	rec_ptr->cmd_flags = get_ioflags_from_rwbs((char *)ftrace_rec + block_rq_complete_attr[BLOCK_RQ_RWBS].offset);
	rec_ptr->start_time_ns = 0;
	rec_ptr->io_start_time_ns = 0;
	rec_ptr->async_in_flight = 0;
	rec_ptr->sync_in_flight = 0;
	rec_ptr->bytes = 0;

	return rec_ptr;
}

void *
conv_block_rq_requeue(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        block_rq_requeue_v1_t *v1_rec = (block_rq_requeue_v1_t *)trcinfop->cur_rec;
        block_rq_requeue_v2_t *v2_rec = (block_rq_requeue_v2_t *)trcinfop->cur_rec;
        block_rq_requeue_v3_t *v3_rec = (block_rq_requeue_v3_t *)trcinfop->cur_rec;
        block_rq_requeue_t *rec_ptr = (block_rq_requeue_t *)arg2;

	if (IS_LIKI_V5_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V3_PLUS) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->dev = v3_rec->dev;
		rec_ptr->sector = v3_rec->sector;
		rec_ptr->nr_sectors = v3_rec->nr_sectors;
		rec_ptr->errors = v3_rec->errors;
		rec_ptr->cmd_type = v3_rec->cmd_type;
		rec_ptr->cmd_flags = v3_rec->cmd_flags;
		rec_ptr->start_time_ns = v3_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v3_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v3_rec->async_in_flight;
		rec_ptr->sync_in_flight = v3_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_requeue_t);
		return rec_ptr;
	}

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->dev = v2_rec->dev;
		rec_ptr->sector = v2_rec->sector;
		rec_ptr->nr_sectors = v2_rec->nr_sectors;
		rec_ptr->errors = v2_rec->errors;
		rec_ptr->cmd_type = v2_rec->cmd_type;
		rec_ptr->cmd_flags = v2_rec->cmd_flags;
		rec_ptr->start_time_ns = v2_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v2_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v2_rec->async_in_flight;
		rec_ptr->sync_in_flight = v2_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_requeue_t);
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->dev = v1_rec->dev;
		rec_ptr->sector = v1_rec->sector;
		rec_ptr->nr_sectors = v1_rec->nr_sectors;
		rec_ptr->errors = v1_rec->errors;
		rec_ptr->cmd_type = v1_rec->cmd_type;
		rec_ptr->cmd_flags = v1_rec->cmd_flags;
		rec_ptr->start_time_ns = v1_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v1_rec->io_start_time_ns;
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
		rec_ptr->reclen = sizeof(block_rq_requeue_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(block_rq_requeue_t);
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_DEV].offset, block_rq_requeue_attr[BLOCK_RQ_DEV].size);
	memcpy (&rec_ptr->sector, (char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_SECTOR].offset, block_rq_requeue_attr[BLOCK_RQ_SECTOR].size);
	memcpy (&rec_ptr->nr_sectors, (char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_NR_SECTOR].offset, block_rq_requeue_attr[BLOCK_RQ_NR_SECTOR].size);
	memcpy (&rec_ptr->errors, (char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_ERRORS].offset, block_rq_requeue_attr[BLOCK_RQ_ERRORS].size);
	/* memcpy (&rec_ptr->comm, (char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_COMM].offset, block_rq_requeue_attr[BLOCK_RQ_COMM].size); */
	rec_ptr->cmd_flags = get_ioflags_from_rwbs((char *)ftrace_rec + block_rq_requeue_attr[BLOCK_RQ_RWBS].offset);
	rec_ptr->async_in_flight = 0;
	rec_ptr->sync_in_flight = 0;

	return rec_ptr;
}

void *
conv_block_rq_abort(void *arg1, void *arg2)
{
        trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        block_rq_abort_v1_t *v1_rec = (block_rq_abort_v1_t *)trcinfop->cur_rec;
        block_rq_abort_v2_t *v2_rec = (block_rq_abort_v2_t *)trcinfop->cur_rec;
        block_rq_abort_v3_t *v3_rec = (block_rq_abort_v3_t *)trcinfop->cur_rec;
        block_rq_abort_t *rec_ptr = (block_rq_abort_t *)arg2;

	if (IS_LIKI_V5_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V3_PLUS) {
		COPY_COMMON_FIELDS(rec_ptr, v3_rec);
		rec_ptr->dev = v3_rec->dev;
		rec_ptr->sector = v3_rec->sector;
		rec_ptr->nr_sectors = v3_rec->nr_sectors;
		rec_ptr->errors = v3_rec->errors;
		rec_ptr->cmd_type = v3_rec->cmd_type;
		rec_ptr->cmd_flags = v3_rec->cmd_flags;
		rec_ptr->start_time_ns = v3_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v3_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v3_rec->async_in_flight;
		rec_ptr->sync_in_flight = v3_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_abort_t);
		return rec_ptr;
	}

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->dev = v2_rec->dev;
		rec_ptr->sector = v2_rec->sector;
		rec_ptr->nr_sectors = v2_rec->nr_sectors;
		rec_ptr->errors = v2_rec->errors;
		rec_ptr->cmd_type = v2_rec->cmd_type;
		rec_ptr->cmd_flags = v2_rec->cmd_flags;
		rec_ptr->start_time_ns = v2_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v2_rec->io_start_time_ns;
		rec_ptr->async_in_flight = v2_rec->async_in_flight;
		rec_ptr->sync_in_flight = v2_rec->sync_in_flight;
		rec_ptr->reclen = sizeof(block_rq_abort_t);
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->dev = v1_rec->dev;
		rec_ptr->sector = v1_rec->sector;
		rec_ptr->nr_sectors = v1_rec->nr_sectors;
		rec_ptr->errors = v1_rec->errors;
		rec_ptr->cmd_type = v1_rec->cmd_type;
		rec_ptr->cmd_flags = v1_rec->cmd_flags;
		rec_ptr->start_time_ns = v1_rec->start_time_ns;
		rec_ptr->io_start_time_ns = v1_rec->io_start_time_ns;
		rec_ptr->async_in_flight = 0;
		rec_ptr->sync_in_flight = 0;
		rec_ptr->reclen = sizeof(block_rq_abort_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(block_rq_abort_t);
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_DEV].offset, block_rq_abort_attr[BLOCK_RQ_DEV].size);
	memcpy (&rec_ptr->sector, (char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_SECTOR].offset, block_rq_abort_attr[BLOCK_RQ_SECTOR].size);
	memcpy (&rec_ptr->nr_sectors, (char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_NR_SECTOR].offset, block_rq_abort_attr[BLOCK_RQ_NR_SECTOR].size);
	memcpy (&rec_ptr->errors, (char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_ERRORS].offset, block_rq_abort_attr[BLOCK_RQ_ERRORS].size);
	/* memcpy (&rec_ptr->comm, (char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_COMM].offset, block_rq_abort_attr[BLOCK_RQ_COMM].size); */
	rec_ptr->cmd_flags = get_ioflags_from_rwbs((char *)ftrace_rec + block_rq_abort_attr[BLOCK_RQ_RWBS].offset);
	rec_ptr->async_in_flight = 0;
	rec_ptr->sync_in_flight = 0;

	return rec_ptr;
}

void *
conv_hardclock(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
        kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
        hardclock_v1_t *v1_rec = (hardclock_v1_t *)trcinfop->cur_rec;
        hardclock_v2_t *v2_rec = (hardclock_v2_t *)trcinfop->cur_rec;
	hardclock_t *rec_ptr = (hardclock_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->preempt_count = v2_rec->preempt_count;

		rec_ptr->stack_depth = conv_stack_trace(&rec_ptr->ips[0], &v2_rec->stacktrace[0], rec_ptr->preempt_count == PREEMPT_USER ? STACK_CONTEXT_USER : STACK_CONTEXT_KERNEL);
		rec_ptr->reclen = sizeof(hardclock_t) + (rec_ptr->stack_depth * sizeof(uint64));
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		rec_ptr->preempt_count = v1_rec->preempt_count;

		rec_ptr->stack_depth = conv_stack_trace(&rec_ptr->ips[0], &v2_rec->stacktrace[0], rec_ptr->preempt_count == PREEMPT_USER ? STACK_CONTEXT_USER : STACK_CONTEXT_KERNEL);
		rec_ptr->reclen = sizeof(hardclock_t) + (rec_ptr->stack_depth * sizeof(uint64));
		return rec_ptr;
	}

	/* only liki traces have hardclocks for now */
	FATAL(3304, "Unexected HARDCLOCK trace record found", NULL, -1);
}

void *
conv_power_start(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	power_start_v2_t *v2_rec = (power_start_v2_t *)trcinfop->cur_rec;
	power_start_t *rec_ptr = (power_start_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, power_start_v2_t);
		rec_ptr->reclen = sizeof(power_start_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(power_start_t);
	memcpy (&rec_ptr->state, (char *)ftrace_rec + power_start_attr[POWER_START_STATE].offset, power_start_attr[POWER_START_STATE].size);
	memcpy (&rec_ptr->type, (char *)ftrace_rec + power_start_attr[POWER_START_TYPE].offset, power_start_attr[POWER_START_TYPE].size);
	
	return rec_ptr;
}

void *
conv_power_end(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	power_end_v2_t *v2_rec = (power_end_v2_t *)trcinfop->cur_rec;
	power_end_t *rec_ptr = (power_end_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		rec_ptr->reclen = sizeof(power_end_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(power_end_t);
	
	return rec_ptr;
}

void *
conv_power_freq(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	power_freq_v1_t *v1_rec = (power_freq_v1_t *)trcinfop->cur_rec;
	power_freq_v2_t *v2_rec = (power_freq_v2_t *)trcinfop->cur_rec;
	power_freq_t *rec_ptr = (power_freq_t *)arg2;

	if (IS_LIKI_V3_PLUS) return trcinfop->cur_rec;

	if (IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, power_freq_v2_t);
		rec_ptr->reclen = sizeof(power_freq_t);
		return rec_ptr;
	}

	if (IS_LIKI_V1) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v1_rec, power_freq_v1_t);
		rec_ptr->tgt_cpu = 0;
		rec_ptr->reclen = sizeof(power_freq_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(power_freq_t);
	memcpy (&rec_ptr->freq, (char *)ftrace_rec + power_freq_attr[POWER_FREQ_STATE].offset, power_freq_attr[POWER_FREQ_STATE].size);
	memcpy (&rec_ptr->type, (char *)ftrace_rec + power_freq_attr[POWER_FREQ_TYPE].offset, power_freq_attr[POWER_FREQ_TYPE].size);
	memcpy (&rec_ptr->tgt_cpu, (char *)ftrace_rec + power_freq_attr[POWER_FREQ_CPUID].offset, power_freq_attr[POWER_FREQ_CPUID].size); 
	
	return rec_ptr;
}

void *
conv_cpu_freq(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	power_freq_t *rec_ptr = (power_freq_t *)arg2;
	uint32 freq, tgt_cpu;

	/* this should only exist for ftrace */

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(power_freq_t);
	memcpy (&freq, (char *)ftrace_rec + cpu_freq_attr[CPU_FREQ_STATE].offset, cpu_freq_attr[CPU_FREQ_STATE].size);
	memcpy (&tgt_cpu, (char *)ftrace_rec + cpu_freq_attr[CPU_FREQ_CPUID].offset, cpu_freq_attr[CPU_FREQ_CPUID].size); 

	rec_ptr->freq = freq;
	rec_ptr->tgt_cpu = tgt_cpu;
	
	return rec_ptr;
}


void *
conv_cpu_idle(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	power_start_t *rec_ptr = (power_start_t *)arg2;
	int32 state;

	/* this should only exist for ftrace */

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(power_start_t);
	memcpy (&state, (char *)ftrace_rec + cpu_idle_attr[CPU_IDLE_STATE].offset, cpu_idle_attr[CPU_IDLE_STATE].size);
	rec_ptr->state = state;
	rec_ptr->type = 0;
	
	return rec_ptr;
}


void *
conv_irq_handler_entry(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	irq_handler_entry_v2_t *v2_rec = (irq_handler_entry_v2_t *)trcinfop->cur_rec;
	irq_handler_entry_t *rec_ptr = (irq_handler_entry_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (irq_handler_entry_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, irq_handler_entry_v2_t);
		rec_ptr->reclen = sizeof(irq_handler_entry_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(irq_handler_entry_t);
	memcpy (&rec_ptr->irq, (char *)ftrace_rec + irq_handler_entry_attr[IRQ_HANDLER_IRQ].offset, irq_handler_entry_attr[IRQ_HANDLER_IRQ].size);
	/* must start strcpy 4 bytes from the size of the offset to handle the variable portion such as the str length */
	strncpy (&rec_ptr->name[0], (char *)ftrace_rec + irq_handler_entry_attr[IRQ_HANDLER_NAME].offset + 4, IRQ_NAME_LEN);

	return rec_ptr;
}

void *
conv_irq_handler_exit(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	irq_handler_exit_v2_t *v2_rec = (irq_handler_exit_v2_t *)trcinfop->cur_rec;
	irq_handler_exit_t *rec_ptr = (irq_handler_exit_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (irq_handler_exit_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, irq_handler_exit_v2_t);
		rec_ptr->reclen = sizeof(irq_handler_exit_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(irq_handler_exit_t);
	memcpy (&rec_ptr->irq, (char *)ftrace_rec + irq_handler_exit_attr[IRQ_HANDLER_IRQ].offset, irq_handler_exit_attr[IRQ_HANDLER_IRQ].size);
	memcpy (&rec_ptr->ret, (char *)ftrace_rec + irq_handler_exit_attr[IRQ_HANDLER_RET].offset, irq_handler_exit_attr[IRQ_HANDLER_RET].size);
	
	return rec_ptr;
}

void *
conv_softirq_entry(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	softirq_entry_v2_t *v2_rec = (softirq_entry_v2_t *)trcinfop->cur_rec;
	softirq_entry_t *rec_ptr = (softirq_entry_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (softirq_entry_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, softirq_entry_v2_t);
		rec_ptr->reclen = sizeof(softirq_entry_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(softirq_entry_t);
	memcpy (&rec_ptr->vec, (char *)ftrace_rec + softirq_entry_attr[SOFTIRQ_VEC].offset, softirq_entry_attr[SOFTIRQ_VEC].size);
	
	return rec_ptr;
}

void *
conv_softirq_exit(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	softirq_exit_v2_t *v2_rec = (softirq_exit_v2_t *)trcinfop->cur_rec;
	softirq_exit_t *rec_ptr = (softirq_exit_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (softirq_exit_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, softirq_exit_v2_t);
		rec_ptr->reclen = sizeof(softirq_exit_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(softirq_exit_t);
	memcpy (&rec_ptr->vec, (char *)ftrace_rec + softirq_exit_attr[SOFTIRQ_VEC].offset, softirq_exit_attr[SOFTIRQ_VEC].size);
	
	return rec_ptr;
}

void *
conv_softirq_raise(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	softirq_raise_v2_t *v2_rec = (softirq_raise_v2_t *)trcinfop->cur_rec;
	softirq_raise_t *rec_ptr = (softirq_raise_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (softirq_raise_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, softirq_raise_v2_t);
		rec_ptr->reclen = sizeof(softirq_raise_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(softirq_raise_t);
	memcpy (&rec_ptr->vec, (char *)ftrace_rec + softirq_raise_attr[SOFTIRQ_VEC].offset, softirq_raise_attr[SOFTIRQ_VEC].size);
	
	return rec_ptr;
}

void *
conv_scsi_dispatch_cmd_start(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	scsi_dispatch_cmd_start_v2_t *v2_rec = (scsi_dispatch_cmd_start_v2_t *)trcinfop->cur_rec;
	scsi_dispatch_cmd_start_t *rec_ptr = (scsi_dispatch_cmd_start_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (scsi_dispatch_cmd_start_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, scsi_dispatch_cmd_start_v2_t);
		rec_ptr->reclen = sizeof(scsi_dispatch_cmd_start_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(scsi_dispatch_cmd_start_t);
	memcpy (&rec_ptr->host_no, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_HOST].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_HOST].size);
	memcpy (&rec_ptr->channel, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_CHANNEL].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_CHANNEL].size);
	memcpy (&rec_ptr->cmd_id, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_ID].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_ID].size);
	memcpy (&rec_ptr->lun, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_LUN].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_LUN].size);
	memcpy (&rec_ptr->opcode, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_OPCODE].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_OPCODE].size);
	memcpy (&rec_ptr->cmd_len, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_CMDLEN].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_CMDLEN].size);
	memcpy (&rec_ptr->data_sglen, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_DATA_SGLEN].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_DATA_SGLEN].size);
	memcpy (&rec_ptr->prot_sglen, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_PROT_SGLEN].offset, scsi_dispatch_cmd_start_attr[SCSI_CMD_PROT_SGLEN].size);
	memcpy (&rec_ptr->cmnd, (char *)ftrace_rec + scsi_dispatch_cmd_start_attr[SCSI_CMD_CMND].offset, (rec_ptr->cmd_len > 32) ? 32 : rec_ptr->cmd_len);
	rec_ptr->prot_op = 0;

	/* we will not copy the entire cmnd[] for ftrace since its a variable size */

	return rec_ptr;
}

void *
conv_scsi_dispatch_cmd_done(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	scsi_dispatch_cmd_done_v2_t *v2_rec = (scsi_dispatch_cmd_done_v2_t *)trcinfop->cur_rec;
	scsi_dispatch_cmd_done_t *rec_ptr = (scsi_dispatch_cmd_done_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (scsi_dispatch_cmd_done_t *)trcinfop->cur_rec;

	if (IS_LIKI_V1 || IS_LIKI_V2) {
		CONV_COMMON_FIELDS_V1_V2(rec_ptr, v2_rec);
		COPY_NONCOMMON_FIELDS_V1_V2(rec_ptr, v2_rec, scsi_dispatch_cmd_done_v2_t);
		rec_ptr->reclen = sizeof(scsi_dispatch_cmd_done_t);
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(scsi_dispatch_cmd_done_t);
	memcpy (&rec_ptr->host_no, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_HOST].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_HOST].size);
	memcpy (&rec_ptr->channel, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_CHANNEL].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_CHANNEL].size);
	memcpy (&rec_ptr->cmd_id, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_ID].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_ID].size);
	memcpy (&rec_ptr->lun, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_LUN].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_LUN].size);
	memcpy (&rec_ptr->opcode, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_OPCODE].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_OPCODE].size);
	memcpy (&rec_ptr->result, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_RET].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_RET].size);
	memcpy (&rec_ptr->cmd_len, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_CMDLEN].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_CMDLEN].size);
	memcpy (&rec_ptr->data_sglen, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_DATA_SGLEN].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_DATA_SGLEN].size);
	memcpy (&rec_ptr->prot_sglen, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_PROT_SGLEN].offset, scsi_dispatch_cmd_done_attr[SCSI_CMD_PROT_SGLEN].size);
	memcpy (&rec_ptr->cmnd, (char *)ftrace_rec + scsi_dispatch_cmd_done_attr[SCSI_CMD_CMND].offset, (rec_ptr->cmd_len > 32) ? 32 : rec_ptr->cmd_len);

	/* we will not copy the entire cmnd[] for ftrace since its a variable size */

	return rec_ptr;
}

void *
conv_workqueue_insertion(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	workqueue_enqueue_t *rec_ptr = (workqueue_enqueue_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(workqueue_enqueue_t);
	memcpy (&rec_ptr->funcp, (char *)ftrace_rec + workqueue_insertion_attr[WORKQUEUE_INSERTION_FUNC].offset, workqueue_insertion_attr[WORKQUEUE_INSERTION_FUNC].size);
	rec_ptr->tgt_cpu = -1;

	return rec_ptr;
}

void *
conv_workqueue_execution(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	workqueue_execute_t *rec_ptr = (workqueue_execute_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(workqueue_execute_t);
	memcpy (&rec_ptr->funcp, (char *)ftrace_rec + workqueue_insertion_attr[WORKQUEUE_EXECUTION_FUNC].offset, workqueue_insertion_attr[WORKQUEUE_EXECUTION_FUNC].size);

	return rec_ptr;
}

void *
conv_workqueue_enqueue(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	workqueue_enqueue_t *rec_ptr = (workqueue_enqueue_t *)arg2;

	if (IS_LIKI) return rec_ptr = (workqueue_enqueue_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(workqueue_enqueue_t);
	memcpy (&rec_ptr->funcp, (char *)ftrace_rec + workqueue_enqueue_attr[WORKQUEUE_ENQUEUE_FUNC].offset, workqueue_enqueue_attr[WORKQUEUE_ENQUEUE_FUNC].size);
	memcpy (&rec_ptr->tgt_cpu, (char *)ftrace_rec + workqueue_enqueue_attr[WORKQUEUE_ENQUEUE_CPU].offset, workqueue_enqueue_attr[WORKQUEUE_ENQUEUE_CPU].size);

	return rec_ptr;
}

void *
conv_workqueue_execute(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	workqueue_execute_t *rec_ptr = (workqueue_execute_t *)arg2;

	if (IS_LIKI) return rec_ptr = (workqueue_execute_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(workqueue_execute_t);
	memcpy (&rec_ptr->funcp, (char *)ftrace_rec + workqueue_enqueue_attr[WORKQUEUE_EXECUTE_FUNC].offset, workqueue_enqueue_attr[WORKQUEUE_EXECUTE_FUNC].size);

	return rec_ptr;
}

void *
conv_anon_fault(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	fault_t *rec_ptr = (fault_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(fault_t);
	memcpy (&rec_ptr->addr, (char *)ftrace_rec + anon_fault_attr[ANON_FAULT_ADDR].offset, anon_fault_attr[ANON_FAULT_ADDR].size);
	rec_ptr->error_code = 0;
	rec_ptr->flag = 0;
	rec_ptr->ip = 0;

	return rec_ptr;
}

void *
conv_filemap_fault(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	fault_t *rec_ptr = (fault_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(fault_t);
	memcpy (&rec_ptr->addr, (char *)ftrace_rec + filemap_fault_attr[FILEMAP_FAULT_ADDR].offset, filemap_fault_attr[FILEMAP_FAULT_ADDR].size);
	memcpy (&rec_ptr->flag, (char *)ftrace_rec + filemap_fault_attr[FILEMAP_FAULT_FLAG].offset, filemap_fault_attr[FILEMAP_FAULT_FLAG].size);
	rec_ptr->error_code = 0;
	rec_ptr->ip = 0;

	return rec_ptr;
}
	
void *
conv_kernel_pagefault(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	fault_t *rec_ptr = (fault_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(fault_t);
	memcpy (&rec_ptr->addr, (char *)ftrace_rec + kernel_pagefault_attr[KERNEL_PAGEFAULT_ADDR].offset, kernel_pagefault_attr[KERNEL_PAGEFAULT_ADDR].size);
	rec_ptr->error_code = 0;
	rec_ptr->flag = 0;
	rec_ptr->ip = 0;

	return rec_ptr;
}

void *
conv_page_fault(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	fault_t *rec_ptr = (fault_t *)arg2;

	if (IS_LIKI) return NULL;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(fault_t);
	memcpy (&rec_ptr->addr, (char *)ftrace_rec + page_fault_attr[PAGE_FAULT_ADDR].offset, page_fault_attr[PAGE_FAULT_ADDR].size);
	memcpy (&rec_ptr->ip, (char *)ftrace_rec + page_fault_attr[PAGE_FAULT_IP].offset, page_fault_attr[PAGE_FAULT_IP].size);
	memcpy (&rec_ptr->error_code, (char *)ftrace_rec + page_fault_attr[PAGE_FAULT_ERR].offset, page_fault_attr[PAGE_FAULT_ERR].size);
	rec_ptr->flag = 0;

	return rec_ptr;
}

void *
conv_cache_insert(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	cache_insert_t *rec_ptr = (cache_insert_t *)arg2;

	if (IS_LIKI) return rec_ptr = (cache_insert_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(cache_insert_t);
	memcpy (&rec_ptr->page, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_PAGE].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_PAGE].size);
	memcpy (&rec_ptr->i_ino, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_INO].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_INO].size);
	memcpy (&rec_ptr->index, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_IDX].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_IDX].size);
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_DEV].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_DEV].size);

	return rec_ptr;
}

void *
conv_cache_evict(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	cache_evict_t *rec_ptr = (cache_evict_t *)arg2;

	if (IS_LIKI) return rec_ptr = (cache_evict_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(cache_evict_t);
	memcpy (&rec_ptr->page, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_PAGE].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_PAGE].size);
	memcpy (&rec_ptr->i_ino, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_INO].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_INO].size);
	memcpy (&rec_ptr->index, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_IDX].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_IDX].size);
	memcpy (&rec_ptr->dev, (char *)ftrace_rec + filemap_pagecache_attr[FILEMAP_PAGECACHE_DEV].offset, filemap_pagecache_attr[FILEMAP_PAGECACHE_DEV].size);
	rec_ptr->stack_depth = 0;

	return rec_ptr;
}

void *
conv_mm_page_alloc(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	mm_page_alloc_t *rec_ptr = (mm_page_alloc_t *)arg2;

	if (IS_LIKI) return rec_ptr = (mm_page_alloc_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(mm_page_alloc_t);
	
	memcpy (&rec_ptr->page, (char *)ftrace_rec + mm_page_alloc_attr[MM_PAGE_ALLOC_PAGE].offset, mm_page_alloc_attr[MM_PAGE_ALLOC_PAGE].size);
	memcpy (&rec_ptr->order, (char *)ftrace_rec + mm_page_alloc_attr[MM_PAGE_ALLOC_ORDER].offset, mm_page_alloc_attr[MM_PAGE_ALLOC_ORDER].size);
	memcpy (&rec_ptr->flags, (char *)ftrace_rec + mm_page_alloc_attr[MM_PAGE_ALLOC_FLAGS].offset, mm_page_alloc_attr[MM_PAGE_ALLOC_FLAGS].size);
	memcpy (&rec_ptr->migratetype, (char *)ftrace_rec + mm_page_alloc_attr[MM_PAGE_ALLOC_TYPE].offset, mm_page_alloc_attr[MM_PAGE_ALLOC_TYPE].size);
	rec_ptr->stack_depth = 0;
	return rec_ptr;
}

void *
conv_mm_page_free(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	mm_page_free_t *rec_ptr = (mm_page_free_t *)arg2;

	if (IS_LIKI) return rec_ptr = (mm_page_free_t *)trcinfop->cur_rec;

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	rec_ptr->reclen = sizeof(mm_page_free_t);
	memcpy (&rec_ptr->page, (char *)ftrace_rec + mm_page_free_attr[MM_PAGE_FREE_PAGE].offset, mm_page_free_attr[MM_PAGE_FREE_PAGE].size);
	memcpy (&rec_ptr->order, (char *)ftrace_rec + mm_page_free_attr[MM_PAGE_FREE_ORDER].offset, mm_page_free_attr[MM_PAGE_FREE_ORDER].size);
	rec_ptr->stack_depth = 0;
	return rec_ptr;
}

char *
get_marker_buf(void *arg1)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	char *ftrace_rec = (char *)trcinfop->cur_rec;

	if (IS_LIKI) {
		/* There are no markers in LIKI */
		 return NULL;
	}

	return ftrace_rec + marker_attr[MARKER_BUF].offset;
}

void *
conv_common_rec(void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg1;
	kd_rec_t *ftrace_rec = (kd_rec_t *)trcinfop->cur_rec;
	etw_common_t *winki_rec = (etw_common_t *)trcinfop->cur_rec;
	etw_common_c002_t *c002_rec = (etw_common_c002_t *)trcinfop->cur_rec;
	etw_common_c011_t *c011_rec = (etw_common_c011_t *)trcinfop->cur_rec;
	common_v1_t *v1_rec = (common_v1_t *)trcinfop->cur_rec;
	common_t *rec_ptr = (common_t *)arg2;

	if (IS_LIKI_V3_PLUS) return rec_ptr = (common_t *)trcinfop->cur_rec;

	if ((IS_LIKI_V1 || IS_LIKI_V2)) {
		 CONV_COMMON_FIELDS_V1_V2(rec_ptr, v1_rec);
		 return rec_ptr = (common_t *)trcinfop->cur_rec;
	}

	if (IS_WINKI) {
		SET_COMMON_FIELDS_WINKI(trcinfop, rec_ptr, winki_rec);

		if (winki_rec->ReservedHeaderField == 0xc002 || winki_rec->ReservedHeaderField == 0xc014) {
			rec_ptr->hrtime = c002_rec->TimeStamp;
			rec_ptr->pid = c002_rec->pid;
			rec_ptr->tgid = c002_rec->tid;
			rec_ptr->hrtime = c002_rec->TimeStamp;
		} else if (winki_rec->ReservedHeaderField == 0xc011) {
			rec_ptr->hrtime = c011_rec->TimeStamp;
		} else {
			printf ("*Unknown ReservedHeaderField: 0x%x\n", winki_rec->ReservedHeaderField);
			hex_dump(winki_rec, 1);
			return 0;
		}
		return rec_ptr;
	}

	SET_COMMON_FIELDS(trcinfop, rec_ptr, ftrace_rec);
	
	return rec_ptr;
}

