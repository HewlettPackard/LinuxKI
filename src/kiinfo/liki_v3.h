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

/* liki_v3.h is used to desceribe old v3 liki record formats */

/* Every trace records starts with a common set of fields */

typedef struct sched_switch_trace_v3 {
	COMMON_FIELDS;
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
	unsigned long	total_vm;
	unsigned long	total_rss;
	unsigned long	stack_depth;
	unsigned long	ips[];
} sched_switch_v3_t;

typedef struct block_rq_insert_trace_v3 {
        COMMON_FIELDS;
        dev_t           dev;
        unsigned long   sector;
        unsigned int    nr_sectors;
        unsigned int    bytes;
        unsigned int    cmd_type;
        unsigned int    cmd_flags;
        int             async_in_flight;
        int             sync_in_flight;
} block_rq_insert_v3_t;

typedef struct block_rq_issue_trace_v3 {
        COMMON_FIELDS;
        dev_t           dev;
        unsigned long   sector;
        unsigned int    nr_sectors;
        unsigned int    bytes;
        unsigned int    cmd_type;
        unsigned int    cmd_flags;
	unsigned long	start_time_ns;
        int             async_in_flight;
        int             sync_in_flight;
} block_rq_issue_v3_t;

typedef struct block_rq_complete_trace_v3 {
        COMMON_FIELDS;
        dev_t           dev;
        unsigned long   sector;
        unsigned int    nr_sectors;
        unsigned int    bytes;
        unsigned int    cmd_type;
        unsigned int    cmd_flags;
        unsigned long   start_time_ns;
        unsigned long   io_start_time_ns;
        int             async_in_flight;
        int             sync_in_flight;
} block_rq_complete_v3_t;

typedef struct block_rq_abort_trace_v3 {
        COMMON_FIELDS;
        dev_t           dev;
        unsigned long   sector;
        unsigned int    nr_sectors;
        unsigned int    errors;
        unsigned int    cmd_type;
        unsigned int    cmd_flags;
        unsigned long   start_time_ns;
        unsigned long   io_start_time_ns;
        int             async_in_flight;
        int             sync_in_flight;
} block_rq_abort_v3_t;


typedef struct block_rq_requeue_trace_v3 {
        COMMON_FIELDS;
        dev_t           dev;
        unsigned long   sector;
        unsigned int    nr_sectors;
        unsigned int    errors;
        unsigned int    cmd_type;
        unsigned int    cmd_flags;
        unsigned long   start_time_ns;
        unsigned long   io_start_time_ns;
        int             async_in_flight;
        int             sync_in_flight;
} block_rq_requeue_v3_t;



