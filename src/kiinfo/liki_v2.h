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

/* liki_v2.h is used to desceribe old v2 liki record formats */

/* Every trace records starts with a common set of fields */

typedef struct sched_switch_trace_v2 {
	COMMON_FIELDS_V1;
	unsigned long	syscallno;
	char		prev_comm[TASK_COMM_LEN]; /* switching-off task */
	long		prev_state;
	unsigned long 	irq_time;
	unsigned long 	softirq_time;
	int		prev_prio;
	pid_t		next_pid;
	pid_t		next_tgid;
	unsigned int	next_policy;
	int		next_prio;
	unsigned long	stacktrace[LEGACY_STACK_DEPTH];
	unsigned long	total_vm;
	unsigned long	total_rss;
} sched_switch_v2_t;

typedef struct sched_wakeup_trace_v2 {
	COMMON_FIELDS_V1;
	pid_t		target_pid;
	int		target_pri;
	int		target_cpu;
	int		success;
} sched_wakeup_v2_t;
	
typedef struct sched_migrate_task_trace_v2 {
	COMMON_FIELDS_V1;
	pid_t		target_pid;
	int		target_pri;
	int		orig_cpu;;
	int		dest_cpu;
	unsigned long	stacktrace[LEGACY_STACK_DEPTH];
} sched_migrate_task_v2_t;
	

typedef struct block_rq_insert_v2 {
	COMMON_FIELDS_V1;
	dev_t		dev; 
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_insert_v2_t;

typedef struct block_rq_issue_v2 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_issue_v2_t;

typedef struct block_rq_complete_v2 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_complete_v2_t;

typedef struct block_rq_abort_v2 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_abort_v2_t;

typedef struct block_rq_requeue_v2 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_requeue_v2_t;


typedef struct hardclock_v2 {
	COMMON_FIELDS_V1;
	int		preempt_count;
	int		max_cstate;
	unsigned long   stacktrace[LEGACY_STACK_DEPTH];
} hardclock_v2_t;


/* Some system calls have useful data that is pointed to by an argument.
 * The tracing becomes much richer if we go capture that useful data and
 * embed it in the trace. Because this useful data varies by syscll type
 * this is implemented by having a syscall_enter_t record for every call
 * type, plus an optional variable length appendage for those calls for
 * which we want this extra data. The format of the variable length
 * appendage varies by syscall type and is described here:
 *
 * open(), creat(), stat(), lstat(), unlink(), execve()
 *   After the fixed format portion above is the filename passed as a parameter to
 *   the system call. This occupies bytes (sizeof(syscall_enter_t) through (reclen-1)).
 * 
 * select(), pselect()
 *   At end we find:
 *   struct timeval/timespec
 *   fdset  readfds, writefds, exceptfds
 *   The number of bytes in each fdset is given by the nfds parameter to select,
 *   which is in arg[0].
 *
 * poll()
 *   At end we find one or more pollfd structures. The number is given
 *   by the nfds parameter to poll(), found in args[1].
 *
 * ppoll()
 *   At end we find the struct timespec followed by one or more pollfd
 *   structures. The number of pollfd structures is given in args[1].
 */

typedef struct syscall_enter_v2 {
	COMMON_FIELDS_V1;
	int		syscallno;
	int		is32bit;
	long		args[N_SYSCALL_ARGS];
	/* Variable length data goes here. Keep it aligned on a long word boundary. */
} syscall_enter_v2_t;

typedef struct syscall_exit_v2 {
	COMMON_FIELDS_V1;
	int		syscallno;
	int		is32bit;
	long		ret;
} syscall_exit_v2_t;


typedef struct power_start_v2 {
	COMMON_FIELDS_V1;
	unsigned long	type;
	unsigned long	state;
} power_start_v2_t;

typedef struct power_end_v2 {
	COMMON_FIELDS_V1;
} power_end_v2_t;

typedef struct power_freq_v2 {
	COMMON_FIELDS_V1;
	unsigned long	type;
	unsigned long 	freq;
	unsigned long	tgt_cpu;
} power_freq_v2_t;


typedef struct irq_handler_entry_v2 {
	COMMON_FIELDS_V1
	int		irq;
	char		name[IRQ_NAME_LEN];
} irq_handler_entry_v2_t;

typedef struct irq_handler_exit_v2 {
	COMMON_FIELDS_V1;
	int		irq;
	int		ret;
} irq_handler_exit_v2_t;


typedef struct softirq_entry_v2 {
	COMMON_FIELDS_V1;
	int		vec;
} softirq_entry_v2_t;

typedef struct softirq_exit_v2 {
	COMMON_FIELDS_V1;
	int		vec;
} softirq_exit_v2_t;

typedef struct softirq_raise_v2 {
	COMMON_FIELDS_V1;
	int		vec;
	char		name[IRQ_NAME_LEN];
} softirq_raise_v2_t;

typedef struct scsi_dispatch_cmd_start_v2 {
	COMMON_FIELDS_V1;
	unsigned int 	host_no;
	unsigned int	channel;
	unsigned int	cmd_id;
	unsigned int 	lun;
	unsigned int	opcode;
	unsigned int 	cmd_len;
	unsigned int	data_sglen;
	unsigned int 	prot_sglen;
	unsigned char 	prot_op;
	unsigned char	cmnd[];
} scsi_dispatch_cmd_start_v2_t;

typedef struct scsi_dispatch_cmd_done_v2 {
	COMMON_FIELDS_V1;
	unsigned int 	host_no;
	unsigned int 	channel;
	unsigned int 	cmd_id;
	unsigned int 	lun;
	int 		result;
	unsigned int 	opcode;
	unsigned int 	cmd_len;
	unsigned int 	data_sglen;
	unsigned int 	prot_sglen;
	unsigned char 	prot_op;
	unsigned char	cmnd[];
} scsi_dispatch_cmd_done_v2_t;


typedef struct listen_overflow_v2 {
	COMMON_FIELDS_V1;
	unsigned long	sk_flags;
} listen_overflow_v2_t;

