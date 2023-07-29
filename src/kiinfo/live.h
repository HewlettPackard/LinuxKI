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

typedef struct win_action {
 	int (*func)();
	uint64 	flags;
	uint64  stats;
	uint64  tracemask;
} win_action_t;

#define MAX_WIN		36

#define	WINMAIN		0
#define WINPID		1
#define WINPID_FLAGS  (SORT_FLAG | SCHED_FLAG | SCALL_FLAG)
#define WINPID_STATS  (PERPID_STATS | SLEEP_STATS | SCALL_STATS )
#define WINPID_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE) | TT_BIT(TT_HARDCLOCK))

#define WINHELP		2
#define WINHELP_FLAGS	WINMAIN_FLAGS
#define WINHELP_STATS	WINMAIN_STATS 
#define WINHELP_TRACEMASK	WINMAIN_TRACEMASK

#define WINLDOM		3
#define WINLDOM_FLAGS  (SORT_FLAG | SCHED_FLAG)
#define WINLDOM_STATS (GLOBAL_STATS | PERCPU_STATS | HT_STATS )
#define WINLDOM_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT))

#define WINCPU		4
#define WINCPU_FLAGS  (SORT_FLAG | SCHED_FLAG)
#define WINCPU_STATS (GLOBAL_STATS | PERCPU_STATS )
#define WINCPU_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT))

#define WINDSK		5
#define WINDSK_FLAGS  (SORT_FLAG)
#define WINDSK_STATS (GLOBAL_STATS | PERDSK_STATS)
#define WINDSK_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINMPATH	6
#define WINMPATH_FLAGS  (SORT_FLAG)
#define WINMPATH_STATS (GLOBAL_STATS | PERDSK_STATS)
#define WINMPATH_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINIOTOP	7
#define WINIOTOP_FLAGS  (SORT_FLAG)
#define WINIOTOP_STATS (GLOBAL_STATS | PERPID_STATS)
#define WINIOTOP_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))


#define WINIRQ		8
#define WINIRQ_SEL	30
#define WINIRQ_FLAGS  (SORT_FLAG)
#define WINIRQ_STATS (GLOBAL_STATS | PERCPU_STATS | PERIRQ_STATS)
#define WINIRQ_TRACEMASK \
                                (TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT))

#define WINPID_DSK	9
#define WINPID_MPATH	10
#define WINPID_DSK_FLAGS  (SORT_FLAG | SCHED_FLAG | DSK_FLAG)
#define WINPID_DSK_STATS (PERPID_STATS | PERDSK_STATS)
#define WINPID_DSK_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINPID_SCALL	11
#define WINPID_SCALL_FLAGS  (SORT_FLAG | SCHED_FLAG | SCALL_FLAG | SCDETAIL_FLAG)
#define WINPID_SCALL_STATS  (PERPID_STATS | SLEEP_STATS | SCALL_STATS )
#define WINPID_SCALL_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINPID_WAIT	12
#define WINPID_WAIT_FLAGS  (SORT_FLAG | SCHED_FLAG)
#define WINPID_WAIT_STATS  (PERPID_STATS | SLEEP_STATS | STKTRC_STATS )
#define WINPID_WAIT_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINPID_HC	13
#define WINPID_HC_FLAGS  (SORT_FLAG | HC_FLAG)
#define WINPID_HC_STATS  (PERPID_STATS | STKTRC_STATS )
#define WINPID_HC_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
				 TT_BIT(TT_HARDCLOCK))

#define WINPID_FILE	14
#define WINPID_FILE_FLAGS  (SORT_FLAG | SCHED_FLAG | SCALL_FLAG | FILE_FLAG)
#define WINPID_FILE_STATS  (PERPID_STATS | SLEEP_STATS | SCALL_STATS | PERFD_STATS )
#define WINPID_FILE_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))


#define WINFILE		15
#define WINFILE_FLAGS  (SORT_FLAG | SCHED_FLAG | SCALL_FLAG | FILE_FLAG)
#define WINFILE_STATS  (GLOBAL_STATS | SLEEP_STATS | SCALL_STATS | PERFD_STATS | PERPID_STATS)
#define WINFILE_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))


#define WINLDOM_SEL	16
#define WINLDOM_SEL_FLAGS  (SORT_FLAG | SCHED_FLAG)
#define WINLDOM_SEL_STATS (GLOBAL_STATS | PERCPU_STATS )
#define WINLDOM_SEL_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT))

#define WINCPU_SEL	17	
#define WINCPU_SEL_FLAGS  (SORT_FLAG | SCHED_FLAG | HC_FLAG )
#define WINCPU_SEL_STATS (GLOBAL_STATS | PERPID_STATS | PERCPU_STATS | PERIRQ_STATS )
#define WINCPU_SEL_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT) | \
                                 TT_BIT(TT_HARDCLOCK))

#define WINWAIT		18
#define WINWAIT_FLAGS  (SORT_FLAG | SCHED_FLAG)
#define WINWAIT_STATS  (GLOBAL_STATS | SLEEP_STATS | STKTRC_STATS )
#define WINWAIT_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP))

#define WINNET		19
#define WINNET_FLAGS  (SORT_FLAG | SCHED_FLAG | SCALL_FLAG | SOCK_FLAG | SCDETAIL_FLAG)
#define WINNET_STATS  (GLOBAL_STATS | PERPID_STATS | SLEEP_STATS | SCALL_STATS | PERFD_STATS )
#define WINNET_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINDSK_SEL	20
#define WINDSK_SEL_FLAGS  (SORT_FLAG)
#define WINDSK_SEL_STATS (GLOBAL_STATS | PERDSK_STATS | PERPID_STATS)
#define WINDSK_SEL_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINPID_COOP	21
#define WINPID_COOP_FLAGS  (SORT_FLAG | SCHED_FLAG )
#define WINPID_COOP_STATS  (PERPID_STATS | SLEEP_STATS | COOP_STATS )
#define WINPID_COOP_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINFUT		22
#define WINFUT_FLAGS  (SORT_FLAG | SCALL_FLAG )
#define WINFUT_STATS  (GLOBAL_STATS | SCALL_STATS | FUTEX_STATS)
#define WINFUT_TRACEMASK \
                                 (TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINFUT_SEL	23
#define WINFUT_SEL_FLAGS  (SORT_FLAG )
#define WINFUT_SEL_STATS  (GLOBAL_STATS | FUTEX_STATS)
#define WINFUT_SEL_TRACEMASK \
                                 (TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINPID_FUTEX	24
#define WINPID_FUTEX_FLAGS  (SORT_FLAG )
#define WINPID_FUTEX_STATS  (PERPID_STATS | FUTEX_STATS)
#define WINPID_FUTEX_TRACEMASK \
                                 (TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT))

#define WINHC		25	
#define WINHC_FLAGS  (SORT_FLAG | HC_FLAG)
#define WINHC_STATS  (GLOBAL_STATS | PERPID_STATS | STKTRC_STATS)
#define WINHC_TRACEMASK \
				 (TT_BIT(TT_HARDCLOCK))

#define WINHT		26
#define WINHT_FLAGS  ( SCHED_FLAG )
#define WINHT_STATS (GLOBAL_STATS | HT_STATS )
#define WINHT_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH))

#define WINSCALL_EXCL	27
#define WINSCALL_EXCL_FLAGS	WINMAIN_FLAGS
#define WINSCALL_EXCL_STATS	WINMAIN_STATS
#define WINSCALL_EXCL_TRACEMASK	WINMAIN_TRACEMASK

#define WINHBA		28
#define WINHBA_SEL	29
#define WINHBA_FLAGS  (SORT_FLAG)
#define WINHBA_STATS (GLOBAL_STATS | PERDSK_STATS)
#define WINHBA_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINDOCK		31
#define WINDOCK_SEL	32
#define WINMAIN_FLAGS (SORT_FLAG | SCHED_FLAG)
#define WINMAIN_STATS (GLOBAL_STATS | PERPID_STATS | PERCPU_STATS | PERFD_STATS )
#define WINMAIN_TRACEMASK \
                                (TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
                                 TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE) | \
                                 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT) | \
                                 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT))


#define WINWWN		33
#define WINWWN_SEL	34
#define WINWWN_FLAGS  (SORT_FLAG)
#define WINWWN_STATS (GLOBAL_STATS | PERDSK_STATS)
#define WINWWN_TRACEMASK \
                                (TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
                                 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_ABORT) | \
                                 TT_BIT(TT_BLOCK_RQ_REQUEUE))

#define WINFILE_SEL	35
#define WINFILE_SEL_FLAGS  (SORT_FLAG | FILE_FLAG )
#define WINFILE_SEL_STATS  (GLOBAL_STATS | PERFD_STATS)
#define WINFILE_SEL_TRACEMASK 0
