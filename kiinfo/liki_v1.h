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

/* liki_v1.h is used to describe old v1 liki record formats */

/* Every trace records starts with a common set of fields */
#define COMMON_FIELDS_V1                                \
        START_OF_RECORD_MARKER                          \
        unsigned long   hrtime;                         \
        unsigned int    id;     /* trace type */        \
        unsigned int    reclen; /* length of trace */   \
        int             pid;                            \
        int             cpu;                            \
        unsigned long   cpu_seqno;                      

typedef struct common_fields_v1 {
        COMMON_FIELDS_V1;
} common_v1_t;


typedef struct info_trace_v1 {
	unsigned long	hrtime;		/* monotonic absolute time */
	unsigned int	page_length; 	/* CHUNK_SIZE for liki */
	unsigned int	version;
	unsigned long	sync_time;	/* time of sync snapshot */
} info_v1_t;

typedef struct sched_switch_trace_v1 {
	COMMON_FIELDS_V1;
	unsigned long	syscallno;
	char		prev_comm[TASK_COMM_LEN]; /* switching-off task */
	long		prev_state;
	int		prev_prio;
	pid_t		next_pid;
	pid_t		next_tgid;
	unsigned int	next_policy;
	int		next_prio;
	unsigned long	stacktrace[LEGACY_STACK_DEPTH];
} sched_switch_v1_t;

typedef struct sched_wakeup_trace_v1 {
	COMMON_FIELDS_V1;
	pid_t		target_pid;
	int		target_pri;
	int		target_cpu;
	int		success;
} sched_wakeup_v1_t;
	

typedef struct block_rq_insert_v1 {
	COMMON_FIELDS_V1;
	dev_t		dev; 
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
} block_rq_insert_v1_t;

typedef struct block_rq_issue_v1 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
} block_rq_issue_v1_t;

typedef struct block_rq_complete_v1 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
} block_rq_complete_v1_t;

typedef struct block_rq_abort_v1 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
} block_rq_abort_v1_t;

typedef struct block_rq_requeue_v1 {
	COMMON_FIELDS_V1;
	dev_t		dev;
	unsigned long	sector;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	unsigned int	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
} block_rq_requeue_v1_t;

typedef struct hardclock_v1 {
	COMMON_FIELDS_V1;
	int		preempt_count;
	int		unused;
	unsigned long   stacktrace[LEGACY_STACK_DEPTH];
} hardclock_v1_t;

typedef struct syscall_enter_v1 {
	COMMON_FIELDS_V1;
	int		syscallno;
	unsigned int	vldoffset; /* offset from start of trace of any vl data */
	long		args[N_SYSCALL_ARGS];
} syscall_enter_v1_t;

typedef struct syscall_exit_v1 {
	COMMON_FIELDS_V1;
	int		syscallno;
	long		ret;
} syscall_exit_v1_t;

typedef struct power_start_v1 {
	COMMON_FIELDS_V1;
	unsigned long	type;
	unsigned long	state;
} power_start_v1_t;

typedef struct power_end_v1 {
	COMMON_FIELDS_V1;
} power_end_v1_t;

typedef struct power_freq_v1 {
	COMMON_FIELDS_V1;
	unsigned long	type;
	unsigned long 	freq;
} power_freq_v1_t;

typedef struct irq_handler_entry_v1 {
	COMMON_FIELDS_V1;
	int	irq;
	char	name[32];
} irq_handler_entry_v1_t;

typedef struct irq_handler_exit_v1 {
	COMMON_FIELDS_V1;
	int	irq;
	int	ret;
} irq_handler_exit_v1_t;

typedef struct softirq_v1 {
	COMMON_FIELDS_V1;
	int	vec;
} softirq_v1_t;

