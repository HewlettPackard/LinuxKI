/*
 * (C) Copyright 2015 Hewlett Packard Enterprise Development LP.
 * (C) Copyright 2000-2014 Hewlett-Packard Development Company, L.P.
 * 
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version. 
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software Foundation, 
 * Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301, USA. 
 *
 * likit.c	LInux Kernel Instrumentation
 *
 *		v7.3
 *		colin.honess@gmail.com
 *		mark.ray@hpe.com
 *		pokilfoyle@gmail.com
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/spinlock_types.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/in.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/smp.h>
#include <net/sock.h>
#include <linux/profile.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <asm/syscall.h>
#include <linux/hardirq.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/kernel_stat.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <linux/perf_event.h>
#include <linux/interrupt.h>
#include <linux/tracepoint.h>
#include <linux/aio_abi.h>
#include <asm/page.h>
#include <asm/irq_regs.h>

#if defined CONFIG_X86_64
#include <../arch/x86/include/asm/unistd.h>
#include <../arch/x86/include/asm/stacktrace.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define	IS_32BIT(regs)	test_thread_flag(TIF_IA32)
#else
#define IS_32BIT(regs)  !user_64bit_mode(regs)
#endif

#elif defined CONFIG_ARM64
#include <../arch/arm64/include/asm/unistd.h>
#include <../arch/arm64/include/asm/stacktrace.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define	IS_32BIT(regs)	test_thread_flag(TIF_IA32)
#else
#define IS_32BIT(regs)  !user_64bit_mode(regs)
#endif

#elif defined CONFIG_PPC64
#include <../arch/powerpc/include/asm/unistd.h>
#include <../include/linux/stacktrace.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define	IS_32BIT(regs)	test_thread_flag(TIF_IA32)
#else
#define IS_32BIT(regs)  !user_64bit_mode(regs)
#endif

#else
Confused about platform!
#endif

#ifndef NR_syscalls
#define NR_syscalls __NR_syscalls
#endif

/* liki.h holds definitions of the trace types and a few other
 * things that need to be shared with userspace consumers.
 */
#ifdef __LIKI_DEBUG
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif
#include "liki.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
#define KTIME_GET       ktime_get_real_ts64
#else
#define KTIME_GET       getnstimeofday
#endif

/* Regular spinlocks may sleep in an RT kernel. From a trace 
 * perspective that is bad for a number of reasons. For those
 * spinlocks that might be used in the trace generation path
 * we use raw/arch spinlocks instead.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)

#define	real_spinlock_t			arch_spinlock_t
#define REAL_SPIN_LOCK_UNLOCKED		__ARCH_SPIN_LOCK_UNLOCKED
#define	real_spin_lock			arch_spin_lock
#define real_spin_unlock		arch_spin_unlock
#define real_spin_trylock		arch_spin_trylock

#else

#define	real_spinlock_t			raw_spinlock_t
#define REAL_SPIN_LOCK_UNLOCKED		__RAW_SPIN_LOCK_UNLOCKED
#define	real_spin_lock			__raw_spin_lock
#define real_spin_unlock		__raw_spin_unlock
#define real_spin_trylock		__raw_spin_trylock

#endif	// LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)


/* The following pertain to stack unwinding (see below) */
#define HARDCLOCK_INTERVAL		10	/* profile timer ticks every 1ms, but we
						 * only collect hardclock traces every
						 * this many millieconds. If you don't
						 * want this throttling, do not define
						 * HARDCLOCK_INTERVAL.
						 */


/* Global data declarations
 *
 * I'm going to keep all global data together here so we can easily
 * ensure alignment, and ensure that read-only data is kept away from
 * read-write data. Note that x86 does adjacent line prefetching, so
 * one line can interfere with the next, so in some cases here I've
 * padded data to two cachelines.
 */

/* The tbuf structure is a per-CPU structure that manages a set of
 * per-CPU trace buffers. This is where we keep track of things like
 * where to find the buffer memory, and offsets for read and write.
 * The tbufs pointer itself is global and frequently read in the
 * performance path; it is never updated after initialization.
 * The memory containing the tbuf structures themselves is allocated
 * at run time, is aligned, and includes padding to enaure that no
 * two tbuf structures could collide in cache. 
 */
STATIC struct tbuf {
	/* First line frequently updated by trace generation code */
	char				*buffer;		/* 8 */
	volatile char 			*alloc_chunk;		/* 16 */
	volatile struct task_struct	*waiting_reader;	/* 24 */
	unsigned long			last_hardclock;		/* 32 */
	unsigned long			unused;
	unsigned long			cpu_seqno;		/* 48 */
	unsigned long 			tsc_offset;		/* 56 */
	volatile unsigned int		alloc_offset;		/* 60 */
	char				deferred_wakeup;	/* 61 */
	char				main_man;		/* 62 */
	char				padding_line1[2];	/* 63 */

	/* Second line updated occasionally by trace generation code */
	unsigned long			irq_time_start;		/* 72 */
	unsigned long			softirq_time_start;	/* 80 */
	unsigned long			stealtime_start;	/* 88 */
	unsigned long			prev_tsc_offset;	/* 96 */
	char				padding_line2[32];	/* 128 */

	/* Third line used more by reader */
	volatile char 			*read_chunk;		/* 136 */
	unsigned long			chunk_locks;		/* 144 */
	char				*sync_chunk;		/* 152 */
	struct task_struct	 	*rd_task;		/* 160 */
	struct dentry			*file;			/* 168 */
	real_spinlock_t			chunk_interlock;	/* 172 */
	char 				sync_reader_active;	/* 173 */
	char				buf_mem_type;		/* 174 */
	char 				padding_line3[18];	/* 192 */
} *tbufs ____cacheline_aligned_in_smp;

/*
 * MSR init, start, and stop arrays are read-only so can be shared among all CPUs... although
 * now that I think about it, I wonder if globals references are always a cache-miss?  Hmmm...
 * I'll have to revisit it, but for now let's assume we're Rock Stars. - pk
 */

#ifdef CONFIG_X86_64

struct MsrList msr_init[] = {
        { MSR_WRITE, MSR_PERF_GLBL_CTRL, 0x00, 0x00, 0x00},     // ia32_perf_global_ctrl: disable 4 PMCs & 3 FFCs
        { MSR_WRITE, MSR_PERF_FIXED_CTRL, 0x00, 0x00, 0x00},    // ia32_perf_fixed_ctr_ctrl: clean up FFC ctrls
        { MSR_WRITE, MSR_PMC0, 0x00, 0x00, 0x00},               // ia32_pmc0: zero value (35-5)
        { MSR_WRITE, MSR_PMC1, 0x00, 0x00, 0x00},               // ia32_pmc1: zero value (35-5)
        { MSR_WRITE, MSR_INSTR_RET, 0x00, 0x00, 0x00},          // ia32_fixed_ctr0: zero value (35-17)
        { MSR_WRITE, MSR_CLK_NOHALT_CORE, 0x00, 0x00, 0x00},    // ia32_fixed_ctr1: zero value (35-17)
        { MSR_WRITE, MSR_FIXED_CLKFREQ, 0x00, 0x00, 0x00},      // ia32_MPERF: zero value
        { MSR_WRITE, MSR_ACTUAL_CLKFREQ, 0x00, 0x00, 0x00},     // ia32_APERF: zero value
        { MSR_WRITE, MSR_PERFEVTSEL0, 0x00434f2e, 0x00, 0x00},  // ia32_perfevtsel0, LLC Reference
        { MSR_WRITE, MSR_PERFEVTSEL1, 0x0043412e, 0x00, 0x00},  // ia32_perfevtsel1, LLC Misses
        { MSR_WRITE, MSR_PERF_FIXED_CTRL, 0x333, 0x00, 0x00},   // ia32_perf_fixed_ctr_ctrl: ensure 3 FFCs enabled
        { MSR_WRITE, MSR_PERF_GLBL_CTRL, 0x0f, 0x07, 0x00},     // ia32_perf_global_ctrl: enable 4 PMCs & 3 FFCs
        { MSR_STOP, 0x00, 0x00, 0x00 }
};

struct MsrList msr_stop[] = {
        { MSR_WRITE, MSR_PERF_GLBL_CTRL, 0x00, 0x00, 0x00},     // ia32_perf_global_ctrl: disable 4 PMCs & 3 FFCs
        { MSR_WRITE, MSR_PERF_FIXED_CTRL, 0x00, 0x00, 0x00},    // ia32_perf_fixed_ctr_ctrl: clean up FFC ctrls
        { MSR_STOP, 0x00, 0x00, 0x00}
};

/*
 * The above two structs occupy 6 - 64 byte cachelines. The following aligned
 * pointer will be padded to cacheline boundary because of the aligned ptr
 * that immediately follows.
 */

STATIC struct msr_cpu {
        unsigned long                   cpuid;                  /*  8 */
        unsigned long                   enabled;                /* 16 */
        unsigned long                   init_smi_cnt;           /* 32 */
        char                            padding_line1[32];      /* 64 */
} *msr_cpu_list  ____cacheline_aligned_in_smp;

STATIC void msr_ops(struct MsrList *oplist);

#endif  // CONFIG_X86_64

STATIC struct timer_list *timer_lists ____cacheline_aligned_in_smp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0) || (defined(CONFIG_PPC64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)))
STATIC void hardclock_timer(struct timer_list *t);
#else
STATIC void hardclock_timer(unsigned long cpu);
#endif


/* Ideally we'll allocate buffers from physical memory; but on a system
 * with fragmented memory may fall back to allocating from virtual 
 * memory. We need to remember which so we can free it correctly.
 */
#define BUF_MEM_PC	42
#define BUF_MEM_VC	24

/* Mostly read-only global data */

#define	TRACING_DISABLED	0
#define TRACING_GLOBAL		1
#define	TRACING_RESOURCES	2

STATIC int		tracing_state ____cacheline_aligned_in_smp = TRACING_DISABLED;
STATIC unsigned long	enabled_features = 0;
STATIC char		ignored_syscalls64[NR_syscalls];
STATIC char		ignored_syscalls32[NR_syscalls];

/* Function pointers for unexported functions */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
static struct socket *(*sockfd_lookup_light_fp)(int, int *, int *);
#endif

static int (*vfs_fstat_fp)(int, struct kstat *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
/* Do nothing, we will call stack_trace_save() later */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) && (defined RHEL82)
unsigned int (*stack_trace_save_regs_fp)(struct pt_regs*, unsigned long *, unsigned int, unsigned int);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
static struct stack_trace *(*save_stack_trace_regs_fp)(struct pt_regs*, struct stack_trace*);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
static struct stack_trace *(*save_stack_trace_regs_fp)(struct stack_trace*, struct pt_regs*);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static unsigned long (*copy_from_user_nmi_fp)(void *, const void __user *, unsigned long);
#endif


/* installed_traces is not performance-critical. It defines only which
 * traces are installed, and isn't referenced in every trace.
 */
STATIC volatile unsigned long 	installed_traces = TT_BITMASK_READS_BLOCK;


/* state_mutex is used when manipulating the set of installed traces,
 * when performing a sync, when opening or closing a ringbuf file, 
 * when adding or removing targeted resources, and when shutting down. 
 * These are all fairly infrequent events and not performance critical.
 */
STATIC DEFINE_MUTEX(state_mutex);


/* vldtmp_cache is a set of chunks of temporary space that can be
 * used to build variable length appendages to trace records. Used
 * in the syscall traces. Frequently read, but not updated.
 */
STATIC struct kmem_cache	*vldtmp_cache = NULL;


#ifdef BROKEN_PLATFORM_CLOCKS

/* consecutive_stable_ticks is only read/written by a monarch, and then
 * hopefully only during the first few ticks of tracing.
 */
STATIC int			consecutive_stable_ticks = 0;


/* global_time is performance-critical frequently modified 
 * global data. It should be kept away from anything else that is
 * frequently read or written. 
 */
STATIC volatile unsigned long	global_prev_time ____cacheline_aligned_in_smp = 0;
STATIC real_spinlock_t		global_time_lock = (real_spinlock_t)REAL_SPIN_LOCK_UNLOCKED;
STATIC int			liki_clock_stable = FALSE;

#endif // BROKEN_PLATFORM_CLOCKS


/* Below are globals used mostly by the trace readers. These guys
 * aren't considered so performance-sensitive.
 *
 * reader_cnt is used to track the number of threads currently in
 * read() for a file in our debugfs interface. It is read-write,
 * but infrequently and not performance-critical.
 */
STATIC volatile unsigned long	reader_cnt ____cacheline_aligned_in_smp = 0;
STATIC volatile int	want_shutdown = FALSE;
STATIC volatile int	shutdown_pending = FALSE;


/* dentry is used to maintain a pointer to the root directory of
 * our debugfs interface. It is not frequently used, nor perormance-
 * critical.
 */
STATIC struct  dentry  *debugdir;


/* Forward declaration of tracepoint table needed for kernels newer
 * than 3.14
 */
struct tp_struct {
	struct tracepoint	*tp;
	char 			*name;
	void			*func;
};

struct tp_struct tp_table[];


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)

#define liki_probe_register(TT)         (tp_table[TT].tp ? tracepoint_probe_register(tp_table[TT].tp, tp_table[TT].func, 0) : 0)
#define liki_probe_unregister(TT)       (tp_table[TT].tp ? tracepoint_probe_unregister(tp_table[TT].tp, tp_table[TT].func, 0) : 0)

#define RXUNUSED			void * unused,
#define TXUNUSED			0,

#define LIKI_STACK_SKIP			0

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)

/* Newer kernels introduce a new parameter to probe registration
 * through which you can provide a value that is passed to the
 * probe when it fires. LiKI doesn't need this, so I pass zero in
 * at registration time, and declare "void * unused" in each
 * probe through RXUNUSED.
 */
#define liki_probe_register(TT)		(tp_table[TT].name ? tracepoint_probe_register(tp_table[TT].name, tp_table[TT].func, 0) : 0)
#define liki_probe_unregister(TT)	(tp_table[TT].name ? tracepoint_probe_unregister(tp_table[TT].name, tp_table[TT].func, 0) : 0)

#define RXUNUSED			void * unused,
#define TXUNUSED			0,

#define LIKI_STACK_SKIP			0

#else

#define liki_probe_register(TT)		(tp_table[TT].name ? tracepoint_probe_register(tp_table[TT].name, tp_table[TT].func) : 0)
#define liki_probe_unregister(TT)	(tp_table[TT].name ? tracepoint_probe_unregister(tp_table[TT].name, tp_table[TT].func) : 0)

#define RXUNUSED
#define TXUNUSED

#define LIKI_STACK_SKIP			1

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
#define SYSCALL_GET_ARGUMENTS(a1, a2, a3, a4, a5) syscall_get_arguments(a1, a2, a5)
#define synchronize_sched() synchronize_rcu()
#else

#if (defined RHEL82) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
#define synchronize_sched() synchronize_rcu()
#endif

#define SYSCALL_GET_ARGUMENTS(a1, a2, a3, a4, a5) syscall_get_arguments(a1, a2, a3, a4, a5)
#endif

/* Here we have a few helper macros that save typing in the trace
 * collection code below.
 */

/* Each trace begins with a set of common fields. These are written
 * through a call to the POPULATE_COMMON_FIELDS macro.
 */
#define POPULATE_COMMON_FIELDS(T, TT, LEN, ORDER)		\
	T->hrtime = liki_global_clock(tb, ORDER);		\
	T->id = TT;						\
	T->reclen = LEN;					\
	T->pid = (in_interrupt() ? -1 : current->pid);		\
	T->tgid = (in_interrupt() ? -1 : current->tgid);	\
	T->cpu = mycpu;						\
	T->cpu_seqno = tb->cpu_seqno++;	

/* TRACE_COMMON_DECLS is used at the beginning of every trace function
 * to save typing.
 */
#define TRACE_COMMON_DECLS						\
	unsigned long		flags;					\
	struct tbuf		*tb;					\
	int			mycpu;

#define NEXT_CHUNK(X, T)						\
	((((char *)X + CHUNK_SIZE) < (T->buffer + BUFFER_SIZE))		\
		? ((char *)X+CHUNK_SIZE) : T->buffer)

#define PREV_CHUNK(X, T)						\
	((((char *)X - CHUNK_SIZE) < T->buffer)				\
		? ((char *)(T->buffer) + (BUFFER_SIZE - CHUNK_SIZE)) : 	\
		  ((char *)X - CHUNK_SIZE))
	
#define CHUNK_MASK(TB, PTR)						\
	(1ULL << (((char *)PTR - TB->buffer) / CHUNK_SIZE))

/* Documented by Colin Hones
 * Stack unwinding is the most troublesome thing to get sorted when porting
 * to a new distro/release. V2 kernels passed fewer parameters to dump_trace()
 * so they need to be treated differently to V3. Some platforms can follow 
 * the back-pointer successfully and others cannot; and what works when 
 * unwinding from the current context doesn't necessarily work when unwinding
 * from regs saved earlier (in the hardclock usage). Worst of all, the default
 * unwind (no back-pointer) is little more than a guess, so we see many bogus
 * frames. Then we have SLES11 in which the regular unwind hardly works at all, 
 * and the custom code they replaced it with cripples system performance.
 *
 * Because of all these corner cases and oddities there are more #ifdefs here
 * than I'd like. I'll try to clean it up over time. In the mean time you may 
 * need to tinker here for a while to get good unwinds on a new platform.
 */

/* Documented by Mark Ray - 08/11/2017
 * I have tried to simplify this.   While save_stack_trace_regs() is
 * not exported, we can do a lookup from kallsyms.   This will abstract
 * some of the complexities.
 */

#ifdef CONFIG_X86_64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
struct stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long *entries;
	int skip;	/* input argument: How many entries to skip */
};

void save_stack_trace_regs(struct stack_trace *st, struct pt_regs *regs)
{
	st->nr_entries = stack_trace_save(st->entries, st->max_entries, st->skip);
}

#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs(DATA, NULL);

#elif (defined RHEL82)

void save_stack_trace_regs(struct stack_trace *st, struct pt_regs *regs)
{
	st->nr_entries = stack_trace_save_regs_fp(regs, st->entries, st->max_entries, st->skip);
}

#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs(DATA, NULL);

#elif (defined RHEL8)
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs_fp(NULL, DATA);

#elif (defined SLES15)
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs_fp(NULL, DATA);

#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs_fp(REGS, DATA);

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) && !(defined SLES11 || defined SLES12)
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs_fp(REGS, DATA);

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) && !(defined SLES11 || defined SLES12)
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace_regs_fp(DATA, REGS); 
#else

STATIC int
liki_backtrace_stack(void *data, char *name)
{
        return(0);
}

STATIC void
liki_backtrace_address(void *data, unsigned long addr, int reliable)
{
        struct stack_trace *trace = (struct stack_trace *)data;

        if (trace->skip > 0) {
                trace->skip--;
                return;
        }

        if (trace->nr_entries < trace->max_entries)
                trace->entries[trace->nr_entries++] = addr;

        return;
}

#if (defined SLES11 || defined SLES12)
STATIC struct stacktrace_ops unwind_ops = {
        .stack                  = liki_backtrace_stack,         /* Text header stack type */
        .address                = liki_backtrace_address,       /* Print/record address */
        .walk_stack             = print_context_stack,          /* Traversal function */
};
#define STACK_TRACE(DATA, REGS)						\
	dump_trace(current, REGS, NULL, 0, &unwind_ops, DATA);

#else  // Very old kernels
STATIC void
liki_trace_warning(void *data, char *msg)
{
        return;
}

STATIC void
liki_trace_warning_symbol(void *data, char *msg, unsigned long symbol)
{
        return;
}

STATIC struct stacktrace_ops unwind_ops = {
        .warning                = liki_trace_warning,
        .warning_symbol         = liki_trace_warning_symbol,
        .stack                  = liki_backtrace_stack,         /* Text header stack type */
        .address                = liki_backtrace_address,       /* Print/record address */
        .walk_stack             = print_context_stack_bp,       /* Traversal function */
};

#define STACK_TRACE(DATA, REGS)                                         \
        dump_trace(current, REGS, NULL, &unwind_ops, DATA);
#endif  //  (defined SLES11 || defined SLES12)
#endif  //  LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)

#elif defined CONFIG_PPC64
#if (defined SLES12)
#define STACK_TRACE(DATA, REGS)                                         \
save_stack_trace(DATA);
#else
/* currently supports RHEL 7.3 and later and SLES SP4 and later */
#define STACK_TRACE(DATA, REGS)                                         \
        save_stack_trace_regs(REGS, DATA);
#endif

#elif defined CONFIG_ARM64
#define STACK_TRACE(DATA, REGS)						\
	save_stack_trace(DATA);

#endif // CONFIG_ARM64

struct liki_callchain_entry {
	unsigned long	nr;
	unsigned long	ip[MAX_STACK_DEPTH];
};

DEFINE_PER_CPU(struct liki_callchain_entry, liki_callchains);

#ifdef CONFIG_X86_64

inline void
liki_fetch_kern_caller_regs(struct pt_regs *regs)
{
	/* Derived from perf_arch_fetch_caller_regs() */
	memset(regs, 0, sizeof(struct pt_regs));
       	regs->ip = (unsigned long)__builtin_return_address(0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	asm volatile(_ASM_MOV "%%" _ASM_BP ", %0\n"
			: "=m" ((regs)->bp)
			:: "memory" );
#else
	regs->bp = (unsigned long)caller_frame_pointer();
#endif
       	regs->cs = __KERNEL_CS; 
       	regs->flags = 0;
	asm volatile(_ASM_MOV "%%" _ASM_SP ", %0\n"
			: "=m" ((regs)->sp)
			:: "memory" );
}

/* here we hide the complexity of to copy from user space.  There
 * have been code changes to copy_from_user_nmi() and how the return
 * value is determined.  Originally, it returned the number of bytes
 * copied, but was later changed to return the number of bytes NOT
 * copied.   Ugh!!!
 */
inline unsigned long
liki_copy_from_user(void *to, const void __user *from, unsigned long n)
{
        unsigned long ret = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
        ret = copy_from_user_nmi_fp(to, from, n);
        if (ret != n)
                return n;
        else
                return 0;
#else
        if (__range_not_ok(from, n, TASK_SIZE))
                return n;

        pagefault_disable();
        ret = __copy_from_user_inatomic(to, from, n);
        pagefault_enable();
        return ret;
#endif
}

inline struct liki_callchain_entry *
liki_stack_unwind(struct pt_regs *regs, int skip, int *start)
{
	struct liki_callchain_entry	*callchain;
	struct pt_regs			local_regs;
	const void __user	*fp;
	struct stack_frame	frame;

	/* Switch and migration cases regs will be NULL
	 */
	if (regs == NULL) {
		liki_fetch_kern_caller_regs(&local_regs);
		regs = &local_regs;
	} else {
		/* The register context passed in from the profiling driver
		 * doesn't form the basis of a good unwind for earlier
		 * kernels
		 */
		if (user_mode(regs)) {
			if (current && current->mm) {
				regs = task_pt_regs(current);
			}
		} else {
			liki_fetch_kern_caller_regs(&local_regs);
			regs = &local_regs;
		}
	}

	*start = 0;
	callchain = (struct liki_callchain_entry *)&get_cpu_var(liki_callchains);
	callchain->nr = 0;

	if (regs && !user_mode(regs)) {
		struct stack_trace	st;

		st.entries = (unsigned long *)callchain->ip;
		st.skip = skip;
		st.max_entries = MAX_STACK_DEPTH;

		/* Leave space for kernel marker */
		st.nr_entries = 1;

		STACK_TRACE(&st, regs);

		/* If STACK_TRACE() gives us a useful stack then prepend
		 * the kernel marker
		 */
		if (st.nr_entries > 1) {
			callchain->ip[0] = STACK_CONTEXT_KERNEL;
			callchain->nr = st.nr_entries;
		} else 
			callchain->nr = 0;

		if (current && current->mm)
			regs = task_pt_regs(current);
		else
			regs = NULL;
	}

	if (regs && !IS_32BIT(regs)) {

		callchain->ip[callchain->nr++] = STACK_CONTEXT_USER;
		callchain->ip[callchain->nr++] = regs->ip;

		fp = (void __user *)regs->bp;
		while (callchain->nr < MAX_STACK_DEPTH) {

			frame.next_frame = NULL;
			frame.return_address = 0;

			if (liki_copy_from_user(&frame, fp, sizeof(frame)))
				break;

			if ((unsigned long)fp < regs->sp)
				break;

			callchain->ip[callchain->nr++] = frame.return_address;

			/* break if we have an infinite loop */
			if (fp == frame.next_frame)  break;

			fp = frame.next_frame;
		}
	}

	put_cpu_var(liki_callchains);

	return(callchain);
}

#elif defined CONFIG_PPC64

#define liki_fetch_kern_caller_regs(regs)                 \
	do {                                                    \
		(regs)->result = 0;                             \
		(regs)->nip = (unsigned long)__builtin_return_address(0);                             \
		asm volatile("mr %0,1": "=r" ((regs)->gpr[1]));       \
		asm volatile("mfmsr %0" : "=r" ((regs)->msr));  \
	} while (0)


struct frame_tail {
	struct frame_tail __user *fp;
	unsigned long cr;  /* Condition register save area - not used */
	unsigned long lr;
} __attribute__((packed));


inline struct liki_callchain_entry *
liki_stack_unwind(struct pt_regs *regs, int skip, int *start)
{

	unsigned long err;
	unsigned long lr;
	struct frame_tail __user *fp;
	struct frame_tail buftail;
	struct liki_callchain_entry     *callchain;
	struct pt_regs                  local_regs;

	/* Switch and migration cases regs will be NULL
	 */
	if (regs == NULL) {
		liki_fetch_kern_caller_regs(&local_regs);
		regs = &local_regs;
		} else {
		/* Hardclock case regs will be set */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
		regs = get_irq_regs();
#else
		/* The register context passed in from the profiling driver
		 * doesn't form the basis of a good unwind for earlier
		 * kernels
		 */
		if (user_mode(regs)) {
			if (current && current->mm) {
				regs = task_pt_regs(current);
			}
		} else {
			liki_fetch_kern_caller_regs(&local_regs);
			regs = &local_regs;
		}
#endif
	}

	*start = 0;
	callchain = (struct liki_callchain_entry *)&get_cpu_var(liki_callchains);
	callchain->nr = 0;

	if (!user_mode(regs)) {
		struct stack_trace      st;

		st.entries = (unsigned long *)callchain->ip;
		st.skip = skip;

		st.max_entries = MAX_STACK_DEPTH;

		/* Leave space for kernel marker */
		st.nr_entries = 1;

		STACK_TRACE(&st, regs);

		/* If STACK_TRACE() gives us a useful stack then prepend
		 * the kernel marker
		 */
		if (st.nr_entries > 1) {
			if (callchain->ip[st.nr_entries-1] == END_STACK)
			st.nr_entries--;

			callchain->ip[0] = STACK_CONTEXT_KERNEL;
			callchain->nr = st.nr_entries;
		} else
			callchain->nr = 0;

		if (current && current->mm)
			regs = task_pt_regs(current);
		else
			regs = NULL;
	}

	if (regs) {
		lr = regs->link;
		fp = (struct frame_tail __user *) regs->gpr[1];

		callchain->ip[callchain->nr++] = STACK_CONTEXT_USER;
		callchain->ip[callchain->nr++] = lr;

		while (callchain->nr < MAX_STACK_DEPTH && fp &&
			!((unsigned long)fp & 0xf)) {

			pagefault_disable();
			err = __copy_from_user_inatomic(&buftail, fp, sizeof(buftail));
			pagefault_enable();
			if (err) break;

			callchain->ip[callchain->nr++]=buftail.lr;

			if (fp >= buftail.fp) break;

			fp = buftail.fp;
		}
	}

	put_cpu_var(liki_callchains);

	return(callchain);
}

#elif defined CONFIG_ARM64 
struct frame_tail {
        struct frame_tail __user *fp;
        unsigned long lr;
} __attribute__((packed));

inline struct liki_callchain_entry *
liki_stack_unwind(struct pt_regs *regs, int skip, int *start)
{
	struct liki_callchain_entry	*callchain;
	struct stack_trace		st;
	struct frame_tail __user *fp;
	struct frame_tail buftail;
	unsigned long err;
	
	*start = 0;
	callchain = (struct liki_callchain_entry *)&get_cpu_var(liki_callchains);
	callchain->nr = 0;

	/* if regs == NULL, then this is a sched_switch or similar and we are in kernel mode */
	/* if regs != NULL and not user mode, then its a HARDCLOCK in kernel code */
	if ((regs == NULL) || (regs && !user_mode(regs)))  {
		st.entries = (unsigned long *)callchain->ip;
		st.skip = skip;
		st.max_entries = MAX_STACK_DEPTH;
		st.nr_entries = 1;

		STACK_TRACE (&st, NULL);

		if (st.nr_entries > 1 ) {
			if (callchain->ip[st.nr_entries-1] == END_STACK)
				st.nr_entries--;
			callchain->ip[0] = STACK_CONTEXT_KERNEL;
			callchain->nr = st.nr_entries;
		} else
			callchain->nr = 0;

		/* get regs to perform user stack trace */
		if (current && current->mm)
			regs = task_pt_regs(current);
		else
			regs = NULL;
	}
	

	/* for user stacks, regs must be filled out */
	if (regs && !IS_32BIT(res)) {
		callchain->ip[callchain->nr++] = STACK_CONTEXT_USER;
		callchain->ip[callchain->nr++] = regs->pc;

		fp = (struct frame_tail __user *)regs->regs[29];

		while (callchain->nr < MAX_STACK_DEPTH && fp &&
			!((unsigned long)fp & 0xf)) {
			if (!access_ok(VERIFY_READ, fp, sizeof(buftail)))
				break;

			pagefault_disable();
			err = __copy_from_user_inatomic(&buftail, fp, sizeof(buftail));
			pagefault_enable();

			if (err) break;
		
			callchain->ip[callchain->nr++] = buftail.lr;

			if (fp >= buftail.fp) break;	

			fp = buftail.fp;
		}
	}

	put_cpu_var(liki_callchains);

	return(callchain);
}

#endif


/* The exporting of symbols seems erratic. Most of the kernel functions I want
 * to access are exported in most releases, but not all in all. To work around
 * this I can use kallsyms to figure out function and data addresses and use
 * them anyway, but guess what? Earlier versions didn't export 
 * kallsyms_lookup_name(), so I'll include my own version for those releases. 
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

struct symaddr {
	const char	*name;
	unsigned long	addr;
} sym;

static int kallsyms_callback(struct symaddr *symp, 
			     const char *name, 
			     struct module *mod, 
			     unsigned long addr)
{
	if (name && symp->name && !strcmp(name, symp->name)) {
		symp->addr = addr;
		return(1);
	}

	return(0);
}

unsigned long
kallsyms_lookup_name(const char * name)
{
	sym.name = name;
	sym.addr = 0;

	kallsyms_on_each_symbol((void *)kallsyms_callback, &sym);

	return(sym.addr);
}

#endif // LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)


/* SLES11 SP2 has some unique stack unwinding code that is unique Novell
 * value-add that completely sucks from a performance standpoint; in the
 * context of LiKI or perf it brings the system to its knees. This can
 * be turned off at boot time through the "call_trace" parameter, but we
 * cannot rely on the user to have remembered to do this. We'll check
 * the current status, turn it off if it isn't already off, then restore
 * the entry state when we exit.
 *
 * To understand what is being twiddled here look at 
 * arch/x86/kernel/dumpstack.c in a SLES11 SP2 source tree.
 */
#define	PREFERRED_CALL_TRACE	-1	
#define BOGUS_CALL_TRACE	-42

int	__liki_old_call_trace_state = BOGUS_CALL_TRACE;

static inline void
save_sles11_backtrace_state(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
        unsigned long   addr;

        if ((addr = kallsyms_lookup_name("call_trace")) == 0) {

		/* Presumably a non-SLES distro */
		return;
	}		

	__liki_old_call_trace_state = *((int *)addr);

#ifdef __LIKI_DEBUG
        printk(KERN_WARNING "LiKI: modifying call_trace from %d to %d\n", 
		*((int *)addr), PREFERRED_CALL_TRACE);
#endif

	*((int *)addr) = PREFERRED_CALL_TRACE;
#endif

	return;
}

static inline void
restore_sles11_backtrace_state(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
        unsigned long   addr;

        if ((addr = kallsyms_lookup_name("call_trace")) == 0) {

		/* Again, presumably a non-SLES distro */
		return;
	}

	if (__liki_old_call_trace_state == BOGUS_CALL_TRACE) {

		/* Very unexpected! */
		printk(KERN_WARNING "LiKI: BOGUS_CALL_TRACE found. Please report to HP.\n");
		return;
	}

#ifdef __LIKI_DEBUG
        printk(KERN_WARNING "LiKI: restoring call_trace from %d to %d\n", 
		PREFERRED_CALL_TRACE, __liki_old_call_trace_state);
#endif

	*((int *)addr) = __liki_old_call_trace_state;

#endif
	return;
}


/* We need a means of timestamping events. This needs to provide a 
 * monotonically increasing clock synchronized across all CPUs and 
 * to be as cheap as possible. It should not favor any particular 
 * CPU in accuracy, and should reliably retain order. If the 
 * platform has a strict globally ordered clock then we might use 
 * it, but nearly every time I've tried it on a multi-socket system
 * it's ended in tears.
 *
 * The following implements an appropriate clock on a platform with
 * unsynchronized clocks. It allows time to drift forwards a little, 
 * but over the course of a few second sample this shouldn't be 
 * significant.
 *
 * Note that any use of a spinlock in this code will cause scaling
 * problems on large systems running extreme workloads. Therefore I
 * nominate a "main_man" CPU to periodically check the tsc_offset 
 * of all the others. If it finds things have settled down and the
 * offsets are no longer changing significantly it declares that
 * the clocks are now stable, and the spinlock is avoided.
 *
 * Interrupts should be disabled on entry.
 */

/* Some traces need to have strictly ordered timestamps; these are
 * the traces that may be followed by another trace on a different
 * CPU that is part of the same logical event. For example, wakeup and
 * switch traces must be ordered because we would want the wakeup of
 * a task to always have an earlier timestamp than the switch event 
 * that follows from it - likely on a different CPU. However other
 * trace types, e.g. hardclock, only need to be strictly ordered with
 * respect to other traces on the same CPU; who really cares the
 * precise order of ticks on differrent CPUs? This matters because
 * the timestamp generation code must do more work to order events
 * across CPUs. You'll see shortly...
 */
#define ORDERED		1
#define UNORDERED	2

#ifdef BROKEN_PLATFORM_CLOCKS

/* This is needed when ktime_get() cannot be relied upon */
#define TSC_STABLE_NS_THRESHOLD		500
#define TSC_STABLE_TICKS_THRESHOLD	5

STATIC INLINE unsigned long 
liki_global_clock(struct tbuf * tb, int ordered)
{
        unsigned long 	now, tsc, prev;

	if (likely(liki_clock_stable || ordered==UNORDERED || in_nmi())) 
		return (sched_clock() + tb->tsc_offset);

	real_spin_lock(&global_time_lock);

	prev = global_prev_time;
	tsc = sched_clock();
	now = tsc + tb->tsc_offset;

	if (likely(now > prev))
		global_prev_time = now;

	real_spin_unlock(&global_time_lock);

	if (unlikely(now < prev)) {
		tb->tsc_offset += (prev - now);
		now = prev;
	}

	return (now);
}	

#else

/* NOTE: The following only works on 64-bit platforms, as on
 * these ktime_t is a 64-bit unsigned int.
 */
#define	liki_global_clock(A, B) ktime_to_ns(ktime_get())

#endif	// BROKEN_PLATFORM_CLOCKS


/* Traced resources management.
 *
 * We need to be able to trace just certain tasks, disks, CPUs etc.
 * To do that, we need to keep track of which resources must be traced
 * in an efficient way so that during trace generation we can determine
 * quickly whether or not a trace should be generated.
 *
 * The classic programming data structure for the task would be a hashed
 * table, but from a cache miss perspective they really suck. Performance
 * is all about cache misses, and you get at least two in a hashed lookup,
 * (header plus first entry) plus one more for every entry in a hashed 
 * bucket you have to traverse to find the entry you want.
 *
 * The approach used here is to build the table using cacheline sized
 * structures, where each structure contains one "next" pointer, and an
 * array of entries. The idea is you hash your value to get a pointer to
 * the "head structure" which contains some entries; if your value is in
 * there you only have a single cache miss; if it's not you take another
 * cache miss to retrieve the next batch of entries. We have quite a few 
 * buckets, and fit quite a few entries in each cacheline, so nearly
 * always what you want is in the first cacheline touched.
 *
 * Adding and removing entries is simple enough; try to compact used
 * entries into the first cacheline. In fact I should revisit this 
 * later and add some compaction and free'ing of second and subsequent
 * chain entries during CPU idle times.
 */
STATIC INLINE int resource_is_traced(unsigned long);
STATIC int enable_tracing_for_resource(unsigned long);
STATIC int disable_tracing_for_resource(unsigned long);
STATIC void reset_traced_resources(void);



#define NRIDS	7 /* Sized to fit cacheline */

typedef struct traced_resources {
	struct traced_resources	*next;
	unsigned long		rid[NRIDS];
} traced_resources_t;


#define	TR_HASH_SIZE	1024
#define TR_HASH(RID) 	(((unsigned long)RID) & (TR_HASH_SIZE - 1))
#define DUFF_RID	-1UL

/* A resource id is an unsigned long, and into this we want to put ids for
 * pids, tgids, cpus and devices. So that we know what type of resource we're
 * looking at I provide macros to light up certain high-order bits for each
 * resource type.
 */
#define	PID_RESOURCE(X)		(X)
#define TGID_RESOURCE(X)	(X | 0x8000000000000000ULL)
#define DEVICE_RESOURCE(X)	(X | 0x4000000000000000ULL)
#define CPU_RESOURCE(X)		(X | 0x2000000000000000ULL)

/* The traced_resource_table is accessed in every trace when targetted
 * tracing is enabled, so keep it in different cachelines to all the
 * reader stuff above.
 */
traced_resources_t	traced_resource_table[TR_HASH_SIZE] ____cacheline_aligned_in_smp;

/* The following is used when we manipulate the set of traced resources,
 * so I'll keep these items together.
 */
STATIC real_spinlock_t	traced_resource_lock = (real_spinlock_t)REAL_SPIN_LOCK_UNLOCKED;
struct kmem_cache * 	tr_cache = NULL;
STATIC unsigned long	traced_resource_count = 0;


STATIC void
clear_traced_resource_set(traced_resources_t *tr)
{
	int i;

	for (i=0; i<NRIDS; i++) 
		tr->rid[i] = DUFF_RID;
}


STATIC int
startup_traced_resource_table(void)
{
	int	i;

	if ((tr_cache = kmem_cache_create("LiKI_traced_resource_status", sizeof(traced_resources_t), 0, 
			      SLAB_HWCACHE_ALIGN, NULL)) == NULL)
		return(-ENOMEM);

	for (i=0; i<TR_HASH_SIZE; i++) {
		clear_traced_resource_set(&traced_resource_table[i]);
		traced_resource_table[i].next = NULL;
	}

	return(0);
}


/* Because lookups are used in the performance path, I want to be able to call 
 * this without holding a lock. So long as I am careful not to dereference a
 * NULL pointer this can be done, on the understanding that the trace state
 * or even the thread to which the found trace status applies may change at
 * any time. So we miss a trace, or get a trace or two we don't want; big deal.
 */
STATIC INLINE int
resource_is_traced(unsigned long rid)
{
	traced_resources_t	*trp;
	int			i;

	trp = &traced_resource_table[TR_HASH(rid)];

	while (trp) {
		for (i=0; i<NRIDS; i++)
			if (trp->rid[i]==rid)
				return(TRUE);
		trp = trp->next;
	}
	return(FALSE);
}

STATIC int
enable_tracing_for_resource(unsigned long rid)
{
	traced_resources_t	*trp, *trp_prev = NULL, *free_grp = NULL;
	int			i, free_idx = -1;
	unsigned long		flags;


	/* Likely already traced. We can see that without the lock */
	trp = &traced_resource_table[TR_HASH(rid)];

	while (trp) {

		for (i=0; i<NRIDS; i++) {

			/* If it's already there return */
			if (trp->rid[i]==rid)
				return(-EEXIST); 
		}

		trp = trp->next;
	}


	/* Not there, so likely have to add. Grab lock and do the 
	 * definitive check and add.
	 */
	trp = &traced_resource_table[TR_HASH(rid)];

	local_irq_save(flags);
	real_spin_lock(&traced_resource_lock);

	while (trp) {

		for (i=0; i<NRIDS; i++) {

			/* If it's already there return */
			if (trp->rid[i]==rid) {
				real_spin_unlock(&traced_resource_lock);
				local_irq_restore(flags);
				return(-EEXIST); 
			}

			/* Remember the first free slot */
			if (trp->rid[i]==DUFF_RID && free_idx==-1) {
				free_idx = i; 
				free_grp = trp;
			}
		}

		trp_prev = trp;
		trp = trp->next;
	}

	if (free_idx == -1) {

		/* Didn't find a free slot; allocate more space */
		if ((free_grp = kmem_cache_alloc(tr_cache, GFP_ATOMIC)) == NULL) {
			real_spin_unlock(&traced_resource_lock);
			local_irq_restore(flags);
			return(-ENOMEM);
		}

		clear_traced_resource_set(free_grp);
		free_grp->next = NULL;

		trp_prev->next = free_grp;

		free_idx = 0;
	}

	traced_resource_count++;
	free_grp->rid[free_idx] = rid;

	real_spin_unlock(&traced_resource_lock);
	local_irq_restore(flags);

	return(0);
}
		

STATIC int
disable_tracing_for_resource(unsigned long rid)
{
	traced_resources_t	*trp;
	int			i;
	unsigned long		flags;

	trp = &traced_resource_table[TR_HASH(rid)];

	local_irq_save(flags);
	real_spin_lock(&traced_resource_lock);

	while (trp) {

		for (i=0; i<NRIDS; i++)

			if (trp->rid[i]==rid) {
 
				trp->rid[i]=DUFF_RID;
				traced_resource_count--;

				real_spin_unlock(&traced_resource_lock);
				local_irq_restore(flags);

				return(0);
			}

		trp = trp->next;
	}

	real_spin_unlock(&traced_resource_lock);
	local_irq_restore(flags);
	return(-ENOENT);
}

/* free_traced_resources() shohld be called at shutdown AFTER tracing
 * has stopped as it is incompatible with the lock-free walk of the
 * traced resource buckets
 */
STATIC void
free_traced_resources(void)
{
	int			i;
	traced_resources_t	*trp, *trp_next;;

	for (i=0; i<TR_HASH_SIZE; i++) {

		/* Clear out any overflow resource sets */
		trp = traced_resource_table[i].next;
		while (trp) {
			trp_next = trp->next;
			kmem_cache_free(tr_cache, trp);
			trp = trp_next;
		}
	}
}

STATIC void
reset_traced_resources(void)
{
	traced_resources_t	*trp;
	int			i;
	unsigned long		flags;

	local_irq_save(flags);
	real_spin_lock(&traced_resource_lock);

	for (i=0; i<TR_HASH_SIZE; i++) {

		/* Clear out any overflow resource sets */
		trp = &traced_resource_table[i];
		while (trp) {
			clear_traced_resource_set(trp);
			trp = trp->next;
		}
	}

	traced_resource_count = 0;
	enabled_features &= ~(TASK_FILTERING|DEVICE_FILTERING|CPU_FILTERING|FAMILY_FILTERING);

	real_spin_unlock(&traced_resource_lock);
	local_irq_restore(flags);

	/* Manipulation of exit and fork hooks done under state_mutex 
	 * protection provided by caller
	 */
}

STATIC void
exit_hook(struct task_struct *task)
{
	if (task && resource_is_traced(PID_RESOURCE(task->pid))) {
		disable_tracing_for_resource(PID_RESOURCE(task->pid));
	}
}

STATIC void 
fork_hook(struct task_struct *this, struct task_struct *new)
{
	if (this && resource_is_traced(PID_RESOURCE(this->pid))) {
		enable_tracing_for_resource(PID_RESOURCE(new->pid));
	}
}


/* In-memory ring-buffer management.
 *
 * Each CPU has its own buffer to prevent false-sharing and to allow for
 * lock-free buffer allocation. Each CPUs buffer is managed by a tbuf
 * structure which keeps track of things like where to find the buffer
 * memory, where new data should be placed, where the next read should
 * begin etc.
 *
 * To place an entry in the buffer first allocate space using trace_alloc();
 * this reserves the specified number of bytes in the buffer and returns a
 * pointer to the reserved space. The caller then writes the trace data to 
 * the space, and calls trace_commit() which signifies that the data is in
 * place and is valid to be read by a task reading the buffered data. 
 *
 * While traces are written to the buffers one trace at a time, they are
 * managed and read in units called chunks. To read a chunk first 
 * call buffer_get(), which returns a pointer to the oldest unread chunk.
 * Copy out the data, then release the chunk by calling buffer_release();
 * this makes the chunk available for reuse.
 * 
 * A few details...
 * 
 * If a trace record will not fit entirely in the space remaining in the
 * current alloc(/write) chunk, we move on to the next chunk. Traces are
 * never split between chunks. There may be a few bytes unused at the end
 * of a chunk, but the overhead is small.
 *
 * If the reader fails to keep up with the writer and we run out of
 * unconsumed space, the writer overwrites the oldest chunk - unless the
 * reader is in the process of copying out that chunk, in which case the
 * writer discards the current trace. This requires a bit of locking
 * which will be explained later. It's very cheap.
 *
 * If a reader finds no whole chunk ready for consumption, it blocks.
 * It will be woken once a whole chunk is available.
 *
 * There can be only one reader and one writer. The one reader restriction
 * is enforced during open(), and one writer is enforced by virtue of the
 * buffers being per-CPU. There is the added complication of being partway
 * through logging a trace when an interrupt arrives, and the ISR itself 
 * causes a trace to be logged. This makes things complicated, so I've
 * disabled interrupts while writing a trace.
 */
#define	CHUNKS_PER_BUFFER	16
#define BUFFER_SIZE		(CHUNK_SIZE * CHUNKS_PER_BUFFER)

int
init_trace_state(void)
{
	int 	cpu = 0;
	int	set_main_man = 0;

	/* Walk through all possible CPUs; if that CPU is online then
	 * ensure that it has a buffer allocated.
	 *
	 * Very little consideration is given here to OL* operations.
	 * This function is expected to be called once only, and cannot
	 * as-is be called subsequently to setup/tear down structures
	 * for newly arrived or departed CPUs. However CPUs that are
	 * offline when this function runs will have buffer==NULL, and
	 * the trace code checks for this, so no traces will be logged
	 * for newly online CPUs - but we won't dereference a NULL 
	 * pointer and crash if a CPU goes away.
	 */
	for(; cpu<nr_cpu_ids; cpu++) {

		/* WARNING
 		 * Be careful when logging data to check that a CPU has
		 * a valid buffer pointer before dereferencing it. It
		 * might be that a CPU was offline when the buffers 
		 * were allocated but came online later!
		 */
		if (cpumask_test_cpu(cpu, cpu_online_mask)) {

			info_t *	pinfo;

			/* CPU is online, so allocate a trace buffer.
			 */
			if (tbufs[cpu].buffer == NULL) {

				/* My preferred interface for memory allocation
				 * is kzalloc_node since this allocates node-
				 * local contiguous physical memory. If that
				 * fails because of fragmentation then allocate
				 * virtually contiguous memory instead. We must
				 * remember which type we allocated so as to 
				 * be able to call the right free function.
				 */
				tbufs[cpu].buffer = (char *)kzalloc_node(
					ALIGN(BUFFER_SIZE, cache_line_size()),
					GFP_KERNEL, cpu_to_node(cpu));

				if (tbufs[cpu].buffer != NULL) 

					tbufs[cpu].buf_mem_type = BUF_MEM_PC;

				else {

					printk(KERN_INFO "LiKI: failed to alloc contiguous buffer space"
							 " cpu %d\n", cpu);

					tbufs[cpu].buffer = (char *)vzalloc_node(
						BUFFER_SIZE, cpu_to_node(cpu));

					if (tbufs[cpu].buffer != NULL) 

						tbufs[cpu].buf_mem_type = BUF_MEM_VC;

					else {

						printk(KERN_WARNING "LiKI: failed to alloc any buffer space\n");
						return(-ENOMEM);
					}
				}

				/* The first chunk will be visible to readers
				 * following a sync, so ensure we have a 
				 * valid header to the chunk.
				 */
				pinfo = (info_t *)tbufs[cpu].buffer;
				pinfo->hrtime = liki_global_clock(&tbufs[cpu], ORDERED);
				pinfo->page_length = 0;
				pinfo->version = TRACE_VERSION;
				pinfo->sync_time = 0;
			}

			tbufs[cpu].alloc_chunk = tbufs[cpu].buffer;
			tbufs[cpu].read_chunk = tbufs[cpu].buffer;
			tbufs[cpu].chunk_locks = 1; /* First chunk locked by writer */
			tbufs[cpu].chunk_interlock = (real_spinlock_t)REAL_SPIN_LOCK_UNLOCKED;
			tbufs[cpu].waiting_reader = NULL;
			tbufs[cpu].file = NULL;
			tbufs[cpu].alloc_offset = TRACE_SIZE(info_t);
			tbufs[cpu].rd_task = NULL;
			tbufs[cpu].cpu_seqno = 0;
			tbufs[cpu].tsc_offset = 0;
			tbufs[cpu].sync_chunk = NULL;
			tbufs[cpu].sync_reader_active = FALSE;
			tbufs[cpu].deferred_wakeup = FALSE;
			tbufs[cpu].irq_time_start = 0;
			tbufs[cpu].softirq_time_start = 0;

			if (!set_main_man) {
				tbufs[cpu].main_man = 1;
				set_main_man = 1;
			} else
				tbufs[cpu].main_man = 0;

		} else {

			/* CPU is offline so ensure the buffer pointer is
			 * NULL. The value of other fields is not 
			 * important.
			 */
			tbufs[cpu].buffer = NULL;
		}
	}

	return(0);
}


STATIC int
startup_ring_buffer(void)
{

	/* Each active CPU needs a buffer. I keep track of these through a
	 * dynamically allocated array of struct tbufs. If allocation barfs
	 * then we need to free everything we have allocated so far.
	 */
	tbufs = kzalloc(ALIGN((sizeof(struct tbuf)*nr_cpu_ids), cache_line_size()),
			GFP_KERNEL);

	if (!tbufs) {
		printk(KERN_WARNING "LiKI: failed to allocate space for tbufs\n");
		goto startup_ring_buffer_failed;
	}

	/* We also need a bunch of buffers to use as temporary space when 
	 * constructing traces with variable length data appendages. Unfortunately
	 * those using these buffers may migrate between CPUs in a preemptible
	 * kernel, so I can't do the CPU-local thing.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
	if ((vldtmp_cache = kmem_cache_create("LiKI_vldtmp_cache", MAX_VLDATA_LEN, 0, 
			      SLAB_HWCACHE_ALIGN, NULL)) == NULL) {
#else
	/* on 4.16 kernels, make the slab so it can be copied from user space */
	if ((vldtmp_cache = kmem_cache_create_usercopy("LiKI_vldtmp_cache", MAX_VLDATA_LEN, 0, 
			      SLAB_HWCACHE_ALIGN, 0, MAX_VLDATA_LEN, NULL)) == NULL) {
#endif
		printk(KERN_WARNING "LiKI: failed to allocate vldtmp cache\n");
		goto startup_ring_buffer_failed;
	}

	if (init_trace_state() != 0)
		goto startup_ring_buffer_failed;

	return(0);

startup_ring_buffer_failed:

	/* Allocated memory is free'ed by the next level up
	 * calling the shutdown functions
	 */

	return(ENOMEM);
}

/* if jprobes are not configured in  kernel, then use timers to perform hardclocks */
/* node jprobes are obsolete in 4.15 kernels */
STATIC int
startup_timer_list(void)
{
	int cpu;

	/* Each active CPU needs a buffer. I keep track of these through a
	 * dynamically allocated array of struct tbufs. If allocation barfs
	 * then we need to free everything we have allocated so far.
	 */
	timer_lists = kzalloc(ALIGN((sizeof(struct timer_list)*nr_cpu_ids), cache_line_size()),
			GFP_KERNEL);

	if (!timer_lists) {
		printk(KERN_WARNING "LiKI: failed to allocate space for timer_lists\n");
		goto startup_timer_list_failed;
	}

	/* initialize each per-cpu timer and arm it */
	for (cpu=0; cpu<nr_cpu_ids; cpu++) {
		if (cpumask_test_cpu(cpu, cpu_online_mask)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0) || (defined(CONFIG_PPC64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)))
			timer_setup(&timer_lists[cpu], hardclock_timer, 0);
#else
                        init_timer(&timer_lists[cpu]);
			timer_lists[cpu].function = hardclock_timer;
			timer_lists[cpu].data = cpu;

#endif
			timer_lists[cpu].expires = jiffies + 1;
			add_timer_on(&timer_lists[cpu], cpu);
		}
	}

	return 0;

startup_timer_list_failed:
	/* Allocated memory is free'ed by the next level up
	 * calling the shutdown functions
	 */

        return(ENOMEM);
}

#ifdef CONFIG_X86_64

/*
 *  * MSR processing code...input is an array of MsrList structs
 *   */

STATIC INLINE long read_msr(unsigned int ecx) {
    unsigned int edx = 0, eax = 0;
    unsigned long result = 0;
    __asm__ __volatile__("rdmsr" : "=a"(eax), "=d"(edx) : "c"(ecx));
    result = eax | (unsigned long)edx << 0x20;
    return result;
}

STATIC INLINE void write_msr(int ecx, unsigned int eax, unsigned int edx) {
    __asm__ __volatile__("wrmsr" : : "c"(ecx), "a"(eax), "d"(edx));
}

static void msr_ops(struct MsrList *oplist)
{
    struct MsrList *msrops;
    int i;

    msrops = oplist;
    for (i = 0 ; i <= MSR_VEC_LIMIT ; i++, msrops++) {
        switch (msrops->op) {

        case MSR_STOP:
            goto label_end;
        case MSR_WRITE:
            write_msr(msrops->ecx, msrops->eax, msrops->edx);
            break;
	case MSR_READ:
            msrops->value = read_msr(msrops->ecx);
            break;
        default:
            printk(KERN_WARNING "LIKI: Unknown MSR operater.\n");
            return;
        }
    }
    label_end:
    return;
}

/* its OK for startup_msr() to fail.  If it does, we will
 * just skip the msr processing by leaving msr_cpu_list set to NULL
 */
STATIC int
startup_msr(void)
{
	msr_cpu_list = NULL;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) {
		printk(KERN_WARNING "LiKI: MSR Features disabled, Vendor ID is %d. \n",boot_cpu_data.x86_vendor);
		return(ENOTSUPP);
	}

	/* only allow Advanced CPU statistics on non-VMs */
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		/* printk(KERN_WARNING "LiKI: MSR Features disabled, Vendor ID is %d. \n",boot_cpu_data.x86_vendor); */
		return(ENOTSUPP);
	}

	/* only allow Advanced CPU statistics on known CPUs */
	switch (boot_cpu_data.x86_model) {
		case 26: 	/* INTEL_FAM6_NEHALEM_EP - 45nm Nahalem-EP */
		case 30:	/* INTEL_FAM6_NEHALEM - 45nm Nahalem */
		case 46: 	/* INTEL_FAM6_NAHALEM_EX - 45nm Nahalem-EP */

		case 37:	/* INTEL_FAM6_WESTMERE - 32nm Westmere */
		case 44:	/* INTEL_FAM6_WESTMERE_EP - 32nm Westmere-EP */
		case 45:	/* INTEL_FAM6_WESTMERE - 32nm SandyBridge-E/EN/EP */
		case 47:	/* INTEL_FAM6_WESTMERE_EX - 32nm Westmere-EX */

		case 42:	/* INTEL_FAM6_SANDYBRIDGE - 32nm SandyBridge */
		case 58:	/* INTEL_FAM6_IVYBRIDGE - 22nm IvyBridge */
		case 62:	/* 22nm IvyBridge-EP/EX */

		case 60:	/* 22nm Haswell */
		case 61:	/* 14nm Broadwell Core-M */
		case 63:	
		case 69:
		case 70:
		case 71:	/* 14nm Broadwell +GT3e */
		case 79:	/* 14nm Broadwell Server */
		case 86:	/* 14nm Broadwell Xeon D */

		case 78:	/* 14nm SkyLake Mobile  */
		case 85:	/* 14nm SkyLake (Purley) */
		case 94:	/* 14nm SkyLake Desktop  */		
			break;
		case 87:	/* Knights Landing - needs testing!!! */
		case 133:	/* Knights Mill - needs testing!!! */
		case 142:	/* KabyLake-U/Y - needs testing!!! */
		case 158:	/* KabyLake-H/S - needs testing!!! */
		default:
			printk(KERN_WARNING "LiKI: MSR Features disabled, x86_model is %d. \n",boot_cpu_data.x86_model);
			return(ENOTSUPP);
	}

        msr_cpu_list= kzalloc(ALIGN((sizeof(struct msr_cpu)*nr_cpu_ids), cache_line_size()),
                        GFP_KERNEL);

        if (!msr_cpu_list) {
                printk(KERN_WARNING "LiKI: Could not allocate space for MSR CPU list - skipping\n");
		return(ENOMEM);
        }
        return 0;
}

static void enable_msr(void *data)
{
	int cpuid;
	cpuid = raw_smp_processor_id();

	msr_ops(msr_init);
	msr_cpu_list[cpuid].enabled = 1;
	msr_cpu_list[cpuid].init_smi_cnt = read_msr(MSR_SMI_CNT);
}

static void disable_msr(void *data)
{
	int cpuid;
	cpuid = raw_smp_processor_id();

	if (msr_cpu_list[cpuid].enabled) {
		msr_cpu_list[cpuid].enabled = 0;
		msr_ops(msr_stop);
	}
}


STATIC void
shutdown_msr(void)
{
	/* disable MSR counters on each CPU */
	if (msr_cpu_list) on_each_cpu(disable_msr, NULL, 1);
	
        /* Free the MSR buffer arrays */
        if (msr_cpu_list) kfree(msr_cpu_list);
        return;
}

#endif  // MSR_X86_64

/* Startup and shutdown
 * The simplistic model is:
 * 
 * A. Dump data to disk:
 *	User invokves script
 *	  Script loads likit module into kernel
 *	  Script calls likid to dump the data to disk
 *	    Likid waits until the trace enable file is present in debugfs
 *	    Likid spawns one thread per CPU then enables traces
 *	    Each thread spools data from per-CPU ring buffer file in debugfs to disk
 *	    After some time, likid disables all traces and issues a TRACE_SYNC
 *	    The spooling threads return partial chunks early as a result of the sync
 *          The spooling threads subsequently get "0" from read() - i.e. EOF
 *	    Likid exits
 *	  Script unloads module from kernel
 *
 * B. Realtime merging of data to a single time-ordered stream
 *      Much the same as above, except most of the work is done by threads
 *      created by the interface library likiif.c. The key difference though
 *      is that we will likely see a lot more sync calls as the buffer for 
 *      some CPUs fills up while other (more idle) CPUs do not produce traces
 *      as quickly. The sync in this case is used to "flush out" partially 
 *      filled chunks so the traces in them can be merged with those of the
 *      busy CPUs, and hence allowing the buffers used by the busy CPUs to
 *      be free'd.
 */
#define IN_SHUTDOWN 	(unsigned long)-1ULL

STATIC void
shutdown_timer_lists(void)
{
	int	cpu;

	/* Be sure all timers are deleted */
	for (cpu=0; cpu<nr_cpu_ids; cpu++) {
		del_timer(&timer_lists[cpu]);
	}

	/* Now free the timer_lists array */
	kfree(timer_lists);

	return;
}

STATIC void
shutdown_ring_buffer(void)
{
	int	cpu;
	struct task_struct *tgt;
	unsigned long flags;

	/* Signal a desire to shut down. Readers will see this flag
	 * and not sleep.
	 */
	want_shutdown = TRUE;

	/* Now wake any already sleeping readers */
	for (cpu=0; cpu<nr_cpu_ids; cpu++) {

		/* In several places we disable interrupts as well 
		 * as acquire a raw spinlock for protection. This is
		 * necessary because if interrupts are enabled the
		 * clock may tick and we may find ourselves in the
		 * hardclock trace function trying to lock the same
		 * chunk_interlock we already hold.
		 */
		local_irq_save(flags);
		real_spin_lock(&tbufs[cpu].chunk_interlock);

		if ((tgt = (struct task_struct *)tbufs[cpu].waiting_reader) != NULL) {
			wake_up_process(tgt);
			tbufs[cpu].waiting_reader = NULL;
		}

		real_spin_unlock(&tbufs[cpu].chunk_interlock);
		local_irq_restore(flags);
	}

	/* Finally we must wait until all readers are out of read()
	 * before we tear down the memory they are using. When the
	 * cmpxchg completes newly arriving readers cannot become
	 * readers.
	 */
	while (cmpxchg(&reader_cnt, 0, IN_SHUTDOWN) != 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(10);
	}

	/* Finally it is now safe to tear down the memory
	 */
	for (cpu=0; cpu<nr_cpu_ids; cpu++)
		if (tbufs[cpu].buffer) {
			if (tbufs[cpu].buf_mem_type == BUF_MEM_PC)
				kfree(tbufs[cpu].buffer);
			else if (tbufs[cpu].buf_mem_type == BUF_MEM_VC)
				vfree(tbufs[cpu].buffer);
			else 
				printk(KERN_WARNING "LiKI: Wrong memory type on free"
						    " - THIS IS VERY BAD!!!\n");
		}

	kfree(tbufs);

	return;
}


STATIC char * 
trace_alloc(int size, int wakeup_safe)
{
	char 		*myspace;
	int		mycpu;
	struct tbuf 	*tb;

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];


	/* As mentioned above, a CPU may have been offline when the 
	 * buffers were allocated, but subsequently come online. 
	 * Trying to dereference a NULL buffer pointer would be bad.
	 */
	if (unlikely(tb->buffer == NULL))
		return(NULL);


	/* I don't zero the trailing bytes since the reader knows where
	 * each trace starts and what the data format is, so it should
	 * be pointless. Since the memory should be zero'ed when we
	 * get it there should be no security risk here - at worst the
	 * padding will contain old partial trace data.
	 */


	/* Each trace must fit entirely within a chunk. If this trace
	 * doesn't fit in the space remaining, move on to the next
	 * chunk.
	 */
	if (unlikely(tb->alloc_offset + size > CHUNK_SIZE)) {

		char 		*next_chunk;
		info_t *	pinfo;
		int		deferred_message = FALSE;

		/* This allocation doesn't fit in the current chunk 
		 * so move on to the next chunk. We need to fix up
		 * the old chunk so that the page_length in the info
		 * record at the start of the chunk reflects the
		 * number of used bytes in the chunk.
		 */
		((info_t *)(tb->alloc_chunk))->page_length = 
			(tb->alloc_offset - TRACE_SIZE(info_t));


		/* If the reader isn't keeping 
		 * up, it is possible that it hasn't yet consumed the chunk
		 * we're about to overwrite, or worse still is currently
		 * consuming it. To ensure traces are delivered in-order,
		 * oldest trace first, while still allowing the writer to
		 * continually overwrite old traces requires some locking.
		 *
		 * The approach taken here is to have one lock per chunk,
		 * in the form of a bit in a single per-buffer lockword.
		 * To lock a page I atomically set the corresponding bit in
		 * the lockword. Behavior of reader and writer then is as
		 * follows:
		 *
		 * When the writer wants to move on to the next chunk it
		 * tries to acquire the lock on that chunk. If acquired it
		 * goes ahead and writes to that chunk. It doesn't release
		 * the lock on the chunk until it moves on to the next chunk.
		 * This prevents a reader from reading a partially-written
		 * chunk or partially overwritten chunk. If the writer 
		 * cannot acquire the lock then it discards the trace.
		 *
		 * The reader acquires the lock on a chunk before reading
		 * the chunks contents, and releases it once it's done.
		 *
		 * Only the writer updates the current write location 
		 * (alloc_chunk and alloc_offset), and since there is only
		 * one possible writer no protection is needed. Both the
		 * reader and writer can modify read_chunk - the reader
		 * after it has consumed a chunk, and the writer if it
		 * overwrites a chunk. Protection is provided by having to
		 * hold the chunk lock for chunk N if you want to increment
		 * read_chunk to a value of (N+1).
		 */
		next_chunk = NEXT_CHUNK(tb->alloc_chunk, tb);

		if (!real_spin_trylock(&tb->chunk_interlock)) {
#ifdef __LIKI_DEBUG
			printk(KERN_WARNING "LiKI: Trace lost type 1\n");
#endif
			tb->cpu_seqno++;
			return(NULL);
		}


		if ((tb->sync_chunk == next_chunk && tb->sync_reader_active) ||
		    (tb->chunk_locks & CHUNK_MASK(tb, next_chunk))) {

			/* The next chunk is locked - meaning that there is
			 * a read in progress to the chunk, or the next
			 * chunk is the subject to a sync operation that is
			 * currently underway, so return NULL; the caller
			 * will discard the trace.
			 */
			real_spin_unlock(&tb->chunk_interlock);

			/* Increment the sequence number for this CPU
			 * indicating that a trace was lost.
			 */
#ifdef __LIKI_DEBUG
			printk(KERN_WARNING "LiKI: Trace lost type 2\n");
#endif
			tb->cpu_seqno++;

			return(NULL);

		}

		/* Unset the bit for the current chunk and set the bit
		 * for the next chunk.
		 */
		tb->chunk_locks &= ~CHUNK_MASK(tb, tb->alloc_chunk);
		tb->chunk_locks |= CHUNK_MASK(tb, next_chunk);

		/* If the new write chunk is also the current read
		 * chunk then we're overwriting traces that haven't
		 * yet been consumed. To prevent confusion we bump
		 * the read_chunk up one - the reader has missed its 
		 * chance. The update of read_chunk is protected by
		 * our holding the interlock.
		 */
		if (tb->read_chunk == next_chunk) {
			tb->read_chunk = NEXT_CHUNK(tb->read_chunk, tb);
			deferred_message = TRUE;
		}

		/* We're overwriting the sync chunk; the reader is 
		 * too late, again protected by the interlock.
		 */
		if (tb->sync_chunk == next_chunk) {
			tb->sync_chunk = (char *)NULL;
		}

		/* Before we move alloc_chunk forwards - which would
		 * make the chunk "visible" to readers through a
		 * sync, we need to ensure that a valid chunk
		 * header is in place.
		 */
		pinfo = (info_t *)next_chunk;
		pinfo->hrtime = liki_global_clock(tb, ORDERED);
		pinfo->page_length = 0;
		pinfo->version = TRACE_VERSION;
		pinfo->sync_time = 0;


		/* Everything is ready. Move to the next chunk.
		 */
		tb->alloc_chunk = next_chunk;
		tb->alloc_offset = TRACE_SIZE(info_t);


		/* If the reader is sleeping on the old chunk then 
		 * wake it. With unfortunate timing our reader may 
		 * not yet be properly asleep - so the wakeup may
		 * fail. No problem though - we'll wake him when
		 * we move onto the next chunk.
		 */
		if (tb->waiting_reader != NULL)  {

			/* We cannot wake the reader here because for
			 * the sched_switch trace we hold a run queue
			 * lock, and that might lead to spinlock
			 * deadlock. Rather simply note that the 
			 * wakeup is required and do it later.
			 */
			tb->deferred_wakeup = TRUE;
		}

		real_spin_unlock(&tb->chunk_interlock);

#ifdef __LIKI_DEBUG
		if (deferred_message)
			printk(KERN_WARNING "LiKI: Trace lost type 3\n");
#endif
	}

	if (unlikely(tb->deferred_wakeup && wakeup_safe)) {

		/* Ordinarily we'd need to recheck the condition under
		 * the lock, but here there is only one person who can
		 * change the condition from its current state, and	
		 * that's me - so not needed.
		 */
		struct task_struct *target_task;

		if (real_spin_trylock(&tb->chunk_interlock)) {
			if ((target_task = (struct task_struct *)tb->waiting_reader) != NULL) {
				wake_up_process(target_task);
				tb->waiting_reader = NULL;
			}

			tb->deferred_wakeup = FALSE;

			real_spin_unlock(&tb->chunk_interlock);
		}
	}


	myspace = (char *)tb->alloc_chunk + tb->alloc_offset;

#ifdef __LIKI_DEBUG
	/* This makes locating the start of a record much easier when
	 * examining raw datafiles during debugging.
	 */
	((common_t *)myspace)->marker = START_MARKER_VALUE;
#endif

	return((char *)myspace);
}


STATIC void
trace_commit(void *p)
{
	struct tbuf 	*tb;

#ifdef __LIKI_DEBUG
	((common_t *)p)->marker = END_MARKER_VALUE;
#endif

	tb = &tbufs[raw_smp_processor_id()];

	/* We only increment alloc_offset here so the record becomes
	 * visible to a read following a sync only after it is
	 * completely written.
	 */
	tb->alloc_offset += ((common_t *)p)->reclen;
}


/* buffer_get() returns the next buffer from the ring buffer managed by
 * tb. 
 *
 * Ordinarily the caller will receive a full chunk of data. There are 
 * use cases where we want less than a whole chunk though: when we are
 * woken by a signal, at shutdown time, and when the userspace consumer
 * gives us a "sync" poke. We'll be woken and will return early and 
 * without the lock - but with a pointer to the partially filled chunk.
 */
STATIC char *
buffer_get(struct tbuf *tb, int *sync_case)
{
	char		*tgt_chunk;
	unsigned long 	flags;

	
	/* If we're not still writing in the next chunk to be read
	 * then the reader can take it. Note though that the writer
	 * can bump read_chunk forwards any time we don't hold the
	 * lock on the chunk pointed to by read_chunk, so after
	 * acquiring the lock we need to re-check to ensure we
	 * acquired the right lock and read_lock hasn't been bumped.
	 */
	while (1) {

		local_irq_save(flags);
		real_spin_lock(&tb->chunk_interlock);

		tgt_chunk = (char *)tb->read_chunk;

		/* If the tgt_chunk lock bit is not set, set it and
		 * return - we hold the chunk lock.
		 */
		if (!(tb->chunk_locks & CHUNK_MASK(tb, tgt_chunk))) {

			tb->chunk_locks |= CHUNK_MASK(tb, tgt_chunk);

			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);

			*sync_case = FALSE;
			return(tgt_chunk);
		} 
		

		/* If the target chunk is the sync chunk then we can
		 * proceed to extract what valid traces we can from it
		 * without holding the chunk lock. Indicate this case
		 * to the caller by setting sync_case=TRUE.
		 */
		if (tgt_chunk == tb->sync_chunk) {

			/* While we cannot lock the current chunk, we
			 * are going to rely during the data extract on
			 * the write path not wrapping around and over-
			 * writing the beginning of the chunk. We do 
			 * this by setting sync_reader_active, which 
			 * in conjunction with sync_chunk tells the
			 * writer that we're actively extracting data
			 * from the chunk - so it can append to what 
			 * is already there but not wrap around and
			 * start writing from the start.
			 */
			tb->sync_reader_active = TRUE;
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);
			*sync_case = TRUE;
			return(tgt_chunk);
		}

		if (want_shutdown) {
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);
			*sync_case = FALSE;
			return(NULL);
		}

		/* ... and if tracing is disabled (TT_BITMASK_NO_TRACES, not
		 * TT_BITMASK_READS_BLOCK) then return
		 */
		if (installed_traces == TT_BITMASK_NO_TRACES) {
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);
			return(NULL);
		}

		/* We can't lock the chunk just now. We should wait.
		 */
		tb->waiting_reader = current;
		set_current_state(TASK_INTERRUPTIBLE);

		real_spin_unlock(&tb->chunk_interlock);
		local_irq_restore(flags);

		schedule();

		/* If we are in shutdown, or have been woken by a signal
		 * then return NULL.
		 */
		if (unlikely(signal_pending(current))) {

			/* NULL out the waiting reader pointer. When
			 * woken by a signal there is no waker to do 
			 * it for us.
			 */
			local_irq_save(flags);
			real_spin_lock(&tb->chunk_interlock);
			tb->waiting_reader = NULL;
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);

			*sync_case = FALSE;
			return(NULL);
		}
	}
}


STATIC void
buffer_release(struct tbuf *tb)
{

	tb->chunk_locks &= ~CHUNK_MASK(tb, tb->read_chunk);
	tb->read_chunk = NEXT_CHUNK(tb->read_chunk, tb);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) && LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)

/* One of the constant battles one plays as a module writer is working
 * around the patchy inconsistent exporting of core kernel symbols. The
 * following sadly is missing from SLES11 SP2. Today at least.
 */
unsigned long 
get_mm_counter(struct mm_struct *mm, int member)
{
	long val = 0;

	val = atomic_long_read(&mm->rss_stat.count[member]);

	if (val < 0)
		return 9;

	return (unsigned long)val;
}
#endif

#ifdef CONFIG_X86_64

STATIC INLINE long read_tsc(void)
{
    unsigned eax, edx;
    long long result;
    __asm__ __volatile__("rdtsc" : "=a"(eax), "=d"(edx));
    result = eax | (unsigned long long)edx << 0x20;
    return result;
}

#endif	// CONFIG_X86_64

/* Here finally we have the probes themselves.
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
STATIC void
sched_switch_trace(RXUNUSED bool preempt, struct task_struct *p, struct task_struct *n)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
sched_switch_trace(RXUNUSED struct task_struct *p, struct task_struct *n)
#else
STATIC void
sched_switch_trace(RXUNUSED struct rq *rq, struct task_struct *p, struct task_struct *n)
#endif
{
	sched_switch_t			*t;
	struct pt_regs 			*regs;
	struct mm_struct 		*mm;
	unsigned int			sz, stksz;
#ifdef CONFIG_X86_64
	unsigned int			msr_idx=0;
#endif
	register unsigned long 		irqtmp, softirqtmp, stealtmp;
	struct liki_callchain_entry	*callchain = NULL;
	int				first_entry = 0;
	TRACE_COMMON_DECLS;

	if (unlikely(!p || !n)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to sched_switch_trace()\n");
#endif
		return;
	}

	/* If we aren't doing global tracing, and neither next or 
	 * previous tasks are traced resources, skip trace generation.
	 */
	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(p->pid)) ||
		      resource_is_traced(TGID_RESOURCE(p->tgid)) ||
		      resource_is_traced(PID_RESOURCE(n->pid)) ||
		      resource_is_traced(TGID_RESOURCE(n->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	/* Do the unwind early so I know how much space to allocate in
	 * the trace (based on stack depth)
	 */
	if (current->pid != 0) 
		callchain = liki_stack_unwind(NULL, OTHER_STACK_SKIP, &first_entry);

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

        if (enabled_features & MSR_FEATURE) {
                sz = TRACE_ROUNDUP((sizeof(sched_switch_t) + stksz + MSRSZ));
        } else {
                sz = TRACE_ROUNDUP((sizeof(sched_switch_t) + stksz));
        }

	/* Rules for logging trace data:
	 *
	 * 1. Begin by disabling interrupts so you don't take an
	 *    interrupt and find yourself logging a trace within the
	 *    ISR that was invoked while logging another trace. This
	 *    also prevents process preemption and migration.
	 *
	 * 2. Figure out what CPU you are on, and get a pointer to
	 *    your CPU-specific data. It's important to do this AFTER
	 *    disabling interrupts so you aren't preempted and moved.
	 *
	 * 3. Allocate space for your trace using trace_alloc(). This
	 *    returns NULL if something goes wrong. DO NOT continue
	 *    to write your trace if you get a NULL pointer back!
	 *
	 * 4. Write your trace into the fields of the trace record.
	 *
	 * 5. Call trace_commit() once all your fields have been 
	 *    populated.
	 *
	 * 6. Re-enable interrupts. Don't forget!
	 */

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (sched_switch_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SCHED_SWITCH, sz, ORDERED);

	/* Outgoing thread data first */

	strncpy(t->prev_comm, current->comm, TASK_COMM_LEN);
	regs = task_pt_regs(current);

	/* set syscallno to -1 if regs is NULL */
	if (regs)
		t->syscallno = syscall_get_nr(current, regs);
	else
		t->syscallno = -1; 

	t->prev_prio = p->prio;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
	t->prev_state = p->state;
#else
	t->prev_state = p->__state;
#endif

	/* All the times returned by LiKI are expressed in nanoseconds.
	 * While the IRQ times are currently maintained in kernel in the much 
	 * lower-resoution cputime64 units (= jiffies), we'll convert this
	 * to nanoseconds before passing back to userspace. Maybe one day
	 * Linux-land will make nanosecond accounting available.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	irqtmp = kstat_cpu(mycpu).cpustat.irq;
	softirqtmp = kstat_cpu(mycpu).cpustat.softirq;
	stealtmp = kstat_cpu(mycpu).cpustat.steal;
#else
	irqtmp = kcpustat_this_cpu->cpustat[CPUTIME_IRQ];
	softirqtmp = kcpustat_this_cpu->cpustat[CPUTIME_SOFTIRQ];
	stealtmp = kcpustat_this_cpu->cpustat[CPUTIME_STEAL];
#endif

	if (tb->stealtime_start == 0) {
		t->stealtime = 0;
	} else { 
		t->stealtime = (stealtmp - tb->stealtime_start);
	}
		
	if (tb->irq_time_start == 0) {
		/* if this is the first switch record */
		t->irq_time = 0;
		t->softirq_time = 0;
	} else {
		t->irq_time = (irqtmp - tb->irq_time_start) * (NSEC_PER_SEC/HZ);
		t->softirq_time = (softirqtmp - tb->softirq_time_start) * (NSEC_PER_SEC/HZ);
	} 

	tb->irq_time_start = irqtmp;
	tb->softirq_time_start = softirqtmp;
	tb->stealtime_start = stealtmp;

	/* Get memory consumption */
	if ((mm = current->mm) != NULL) {
		t->total_vm = mm->total_vm;
		t->total_rss = get_mm_rss(mm);
	} else {
		t->total_vm = 0;
		t->total_rss = 0;
	}

	/* Copy in the stack trace if we have one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else 
		t->stack_depth = 0;

	/* Incoming thread data second */

	t->next_pid = n->pid;
	t->next_prio = n->prio;
	t->next_tgid = n->tgid;
	t->next_policy = n->policy;

#ifdef CONFIG_X86_64
	if (enabled_features & MSR_FEATURE) {
		msr_idx = t->stack_depth;
		t->ips[msr_idx++] = read_msr(MSR_PMC0);
		t->ips[msr_idx++] = read_msr(MSR_PMC1);
		t->ips[msr_idx++] = read_msr(MSR_INSTR_RET);
		t->ips[msr_idx++] = read_msr(MSR_CLK_NOHALT_CORE);
		t->ips[msr_idx++] = read_msr(MSR_FIXED_CLKFREQ);
		t->ips[msr_idx++] = read_msr(MSR_ACTUAL_CLKFREQ);
		t->ips[msr_idx++] = read_msr(MSR_SMI_CNT) - msr_cpu_list[mycpu].init_smi_cnt;
	}
#endif	// CONFIG_X86_64

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
STATIC void
sched_wakeup_trace(RXUNUSED struct task_struct *tgt)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
sched_wakeup_trace(RXUNUSED struct task_struct *tgt, int success)
#else
STATIC void
sched_wakeup_trace(RXUNUSED struct rq * __rq,  struct task_struct *tgt, int success)
#endif
{
	sched_wakeup_t		*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(!tgt)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to sched_wakeup_trace()\n");
#endif
		return;
	}

	/* If we aren't doing global tracing, and neither the waker or
	 * wakee tasks are traced resources, skip trace generation.
	 */
	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((!in_interrupt() && resource_is_traced(PID_RESOURCE(current->pid))) ||
		      (!in_interrupt() && resource_is_traced(TGID_RESOURCE(current->tgid))) ||
		      resource_is_traced(PID_RESOURCE(tgt->pid)) ||
		      resource_is_traced(TGID_RESOURCE(tgt->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	/* Note that enable_tracing_for_resource() deals with enabling tracing
	 * for a task for which it is already enabled, and the following code
	 * avoids one traversal to check whetehr a task is traced, then 
	 * another to enable tracing for it
	 */
	if (!in_interrupt() &&
	    (enabled_features & FAMILY_FILTERING) && 
	    resource_is_traced(PID_RESOURCE(tgt->pid)))
		enable_tracing_for_resource(PID_RESOURCE(current->pid));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (sched_wakeup_t *)trace_alloc(TRACE_SIZE(sched_wakeup_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SCHED_WAKEUP, TRACE_SIZE(sched_wakeup_t), ORDERED);

	t->target_pid = tgt->pid;
	t->target_pri = tgt->prio;
	t->target_cpu = task_cpu(tgt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	t->success = 1;
#else
	t->success = success;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
sched_migrate_task_trace(RXUNUSED struct task_struct *p, unsigned int new_cpu)
{
	sched_migrate_task_t		*t;
	unsigned int			sz, stksz;
	unsigned int			first_entry = 0;
	struct liki_callchain_entry	*callchain;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(p == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to sched_migrate_task()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((!in_interrupt() && resource_is_traced(PID_RESOURCE(current->pid))) ||
		      (!in_interrupt() && resource_is_traced(TGID_RESOURCE(current->tgid))) ||
		      resource_is_traced(PID_RESOURCE(p->pid)) ||
		      resource_is_traced(TGID_RESOURCE(p->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	/* Do the unwind early so I know how much space to allocate in
	 * the trace (based on stack depth)
	 */
	callchain = liki_stack_unwind(NULL, OTHER_STACK_SKIP, &first_entry);

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

	sz = TRACE_ROUNDUP((sizeof(sched_migrate_task_t) + stksz));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (sched_migrate_task_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SCHED_MIGRATE_TASK, sz, ORDERED);
	t->target_pid = p->pid;
	t->target_pri = p->prio;
	t->orig_cpu = task_cpu(p);
	t->dest_cpu = new_cpu;

	/* Copy in stack trace if we got one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else 
		t->stack_depth = 0;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)					

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)					
#define POPULATE_COMMON_BLOCK_FIELDS(q, r, T)						\
	T->dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;				\
	T->sector = blk_rq_is_passthrough(r) ? 0 : blk_rq_pos(r);			\
	T->nr_sectors = blk_rq_is_passthrough(r) ? 0 : blk_rq_sectors(r);	 	\
	T->cmd_type = 0;								\
	T->cmd_flags = r->cmd_flags;							\
	T->async_in_flight = q->in_flight[BLK_RW_ASYNC];				\
	T->sync_in_flight = q->in_flight[BLK_RW_SYNC];					
#else
#define POPULATE_COMMON_BLOCK_FIELDS(q, r, T)						\
	T->dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;				\
	T->sector = blk_rq_is_passthrough(r) ? 0 : blk_rq_pos(r);			\
	T->nr_sectors = blk_rq_is_passthrough(r) ? 0 : blk_rq_sectors(r);	 	\
	T->cmd_type = 0;								\
	T->cmd_flags = r->cmd_flags;							\
	T->async_in_flight = 0;								\
	T->sync_in_flight = 0;								
#endif

#else
#define POPULATE_COMMON_BLOCK_FIELDS(q, r, T)						\
	T->dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;				\
	T->sector = (unsigned long)((r->cmd_type == REQ_TYPE_BLOCK_PC) ? 		\
			0 : blk_rq_pos(r));						\
	T->nr_sectors = (r->cmd_type == REQ_TYPE_BLOCK_PC) ? 0 : blk_rq_sectors(r); 	\
	T->cmd_type = r->cmd_type;							\
	T->cmd_flags = r->cmd_flags;							\
	T->async_in_flight = q->in_flight[BLK_RW_ASYNC];				\
	T->sync_in_flight = q->in_flight[BLK_RW_SYNC];				
#endif


STATIC void
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
block_rq_insert_trace(RXUNUSED struct request *r)
#else
block_rq_insert_trace(RXUNUSED struct request_queue *q, struct request *r)
#endif
{
	block_rq_insert_t	*t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	struct request_queue	*q;
#endif
	unsigned int		sz;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(!r)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_insert_trace()\n");
#endif
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		q = r->q;
#endif

	if (unlikely(!q)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_insert_trace()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		dev_t	dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(DEVICE_RESOURCE(dev)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	sz = TRACE_ROUNDUP(sizeof(block_rq_insert_t));

	if (unlikely((t = (block_rq_insert_t *)trace_alloc(sz, TRUE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_BLOCK_RQ_INSERT, sz, ORDERED);
	POPULATE_COMMON_BLOCK_FIELDS(q, r, t);
	t->bytes = blk_rq_bytes(r);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

STATIC void
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
block_rq_issue_trace(RXUNUSED struct request *r)
#else
block_rq_issue_trace(RXUNUSED struct request_queue *q, struct request *r)
#endif

{
	block_rq_issue_t	*t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	struct request_queue	*q;
#endif
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(!r)) {
		printk(KERN_WARNING "LiKI: NULL request pointer passed to block_rq_issue_trace()\n");
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	q = r->q;
#endif

	if (unlikely(!q)) {
		printk(KERN_WARNING "LiKI: NULL request pointer passed to block_rq_issue_trace()\n");
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		dev_t	dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;

		if ((enabled_features & DEVICE_FILTERING) &&
		    !resource_is_traced(DEVICE_RESOURCE(dev)))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (block_rq_issue_t *)trace_alloc(TRACE_SIZE(block_rq_issue_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_BLOCK_RQ_ISSUE, TRACE_SIZE(block_rq_issue_t), ORDERED);
	POPULATE_COMMON_BLOCK_FIELDS(q, r, t);

	t->bytes = blk_rq_bytes(r);
#ifdef CONFIG_BLK_CGROUP
	t->start_time_ns = r->start_time_ns;
#else
	t->start_time_ns = 0;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
STATIC void 
block_rq_complete_trace(RXUNUSED struct request *r, int error, unsigned int nr_bytes)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,5)
STATIC void 
block_rq_complete_trace(RXUNUSED struct request_queue *q, struct request *r, unsigned int nr_bytes)
#else
STATIC void 
block_rq_complete_trace(RXUNUSED struct request_queue *q, struct request *r)
#endif
{
	block_rq_complete_t	*t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	struct request_queue	*q;
#endif

	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(!r)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_complete_trace()\n");
#endif
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	q = r->q;
#endif

	if (unlikely(!q)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_complete_trace()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		dev_t	dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;

		if ((enabled_features & DEVICE_FILTERING) &&
		    !resource_is_traced(DEVICE_RESOURCE(dev)))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (block_rq_complete_t *)trace_alloc(TRACE_SIZE(block_rq_complete_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_BLOCK_RQ_COMPLETE, TRACE_SIZE(block_rq_complete_t), ORDERED);
	POPULATE_COMMON_BLOCK_FIELDS(q, r, t);

	t->bytes = blk_rq_bytes(r);
#ifdef CONFIG_BLK_CGROUP
	t->start_time_ns = r->start_time_ns;
	t->io_start_time_ns = r->io_start_time_ns;
#else
	t->start_time_ns = 0;
	t->io_start_time_ns = 0;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

STATIC void
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
block_rq_requeue_trace(RXUNUSED struct request *r)
#else
block_rq_requeue_trace(RXUNUSED struct request_queue *q, struct request *r)
#endif
{
	block_rq_requeue_t	*t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	struct request_queue	*q;
#endif
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(!r)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_requeue_trace()\n");
#endif
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	q = r->q;
#endif

	if (unlikely(!q)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to block_rq_requeue_trace()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		dev_t	dev = r->rq_disk ? disk_devt(r->rq_disk) : 0;

		if ((enabled_features & DEVICE_FILTERING) &&
		    !resource_is_traced(DEVICE_RESOURCE(dev)))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (block_rq_requeue_t *)trace_alloc(TRACE_SIZE(block_rq_requeue_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_BLOCK_RQ_REQUEUE, TRACE_SIZE(block_rq_requeue_t), ORDERED);
	POPULATE_COMMON_BLOCK_FIELDS(q, r, t);

	t->errors = 0;
#ifdef CONFIG_BLK_CGROUP
	t->start_time_ns = r->start_time_ns;
	t->io_start_time_ns = r->io_start_time_ns;
#else
	t->start_time_ns = 0;
	t->io_start_time_ns = 0;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
STATIC void
mm_filemap_fault_trace(RXUNUSED struct mm_struct *vm_mm, unsigned long virtual_address, unsigned int useless)
{
	filemap_fault_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (!(vm_mm && virtual_address)) {
#ifdef LIKI_DEBUG
		printk(KERN_WARNING "filemap_fault entered with vm_mm==%p and address==%p\n",
			(void *)vm_mm, (void *)virtual_address);
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (filemap_fault_t *)trace_alloc(TRACE_SIZE(filemap_fault_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_FILEMAP_FAULT, TRACE_SIZE(filemap_fault_t), ORDERED);

	t->vm_mm = (unsigned long)vm_mm;
	t->virtual_address = virtual_address;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}
#endif

STATIC void
mm_page_alloc_trace(RXUNUSED struct page *page, unsigned int order, unsigned int gfp_flags, unsigned int migratetype )
{
	mm_page_alloc_t	*t;
	unsigned int			sz, stksz;
	unsigned int			first_entry = 0;
	struct liki_callchain_entry	*callchain;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	/* Do the unwind early so I know how much space to allocate in
	 * the trace (based on stack depth)
	 */
	callchain = liki_stack_unwind(NULL, LIKI_STACK_SKIP, &first_entry);

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

	sz = TRACE_ROUNDUP((sizeof(mm_page_alloc_t) + stksz));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (mm_page_alloc_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_MM_PAGE_ALLOC, sz, ORDERED);

	t->page = page ? page_to_pfn(page) : 0;
	t->order = order;
	t->flags = (unsigned int)gfp_flags;
	t->migratetype = migratetype;

	/* Copy in stack trace if we got one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else
		t->stack_depth = 0;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

STATIC void
mm_page_free_trace(RXUNUSED struct page *page, unsigned int order )
{
	mm_page_free_t	*t;
	unsigned int			sz, stksz;
	unsigned int			first_entry = 0;
	struct liki_callchain_entry	*callchain;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	/* Do the unwind early so I know how much space to allocate in
	 * the trace (based on stack depth)
	 */
	callchain = liki_stack_unwind(NULL, LIKI_STACK_SKIP, &first_entry);

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

	sz = TRACE_ROUNDUP((sizeof(mm_page_free_t) + stksz));
	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (mm_page_free_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_MM_PAGE_FREE, sz, ORDERED);

	t->page = page ? page_to_pfn(page) : 0;
	t->order = order;

	/* Copy in stack trace if we got one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else
		t->stack_depth = 0;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
STATIC void
page_cache_insert_trace(RXUNUSED struct page *page)
{
	cache_insert_t		*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(page == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL page pointer passed to page_cache_insert_trace()");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((current ? resource_is_traced(PID_RESOURCE(current->pid)) : 0) ||
		      (current ? resource_is_traced(TGID_RESOURCE(current->tgid)) : 0) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (cache_insert_t *)trace_alloc(TRACE_SIZE(cache_insert_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_CACHE_INSERT, TRACE_SIZE(cache_insert_t), ORDERED);

	t->page = (unsigned long)page;
	t->i_ino = page->mapping->host->i_ino;
	t->index = page->index;

	if (page->mapping->host->i_sb)
		t->dev = page->mapping->host->i_sb->s_dev;
	else
		t->dev = page->mapping->host->i_rdev;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

/* the cache_evict jprobe is obsolete */
STATIC void
page_cache_evict_trace(RXUNUSED struct page *page)
{
	cache_evict_t			*t;
	unsigned int			sz, stksz;
	struct liki_callchain_entry	*callchain = NULL;
	int				first_entry = 0;
	TRACE_COMMON_DECLS;


	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(page == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL page pointer passed to page_cache_evict_trace()");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((current ? resource_is_traced(PID_RESOURCE(current->pid)) : 0) ||
		      (current ? resource_is_traced(TGID_RESOURCE(current->tgid)) : 0) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	callchain = liki_stack_unwind(NULL, OTHER_STACK_SKIP, &first_entry);

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

	sz = TRACE_ROUNDUP((sizeof(cache_evict_t) + stksz));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (cache_evict_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_CACHE_EVICT, sz, ORDERED);

	t->page = (unsigned long)page;
	t->i_ino = page->mapping->host->i_ino;
	t->index = page->index;

	if (page->mapping->host->i_sb)
		t->dev = page->mapping->host->i_sb->s_dev;
	else
		t->dev = page->mapping->host->i_rdev;

	/* Copy in stack trace if we got one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else 
		t->stack_depth = 0;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}
#endif

STATIC void 
syscall_enter_trace(RXUNUSED struct pt_regs *regs, long syscallno)
{
	syscall_enter_t		*t;
	int			sz;
	long			args_tmp[N_SYSCALL_ARGS];
	void 			*vldtmp;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

#ifdef __LIKI_DEBUG
	if (unlikely(syscallno < 0)) {
		printk(KERN_WARNING "LiKI: duff syscall called\n");
		return;
	}
#endif

	if (unlikely(regs == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to syscall_enter_trace()\n");
#endif
		return;
	}


	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	if (unlikely(IS_32BIT(regs))) {
		if (unlikely(ignored_syscalls32[syscallno])) 
			return;
	} else {
		if (unlikely(ignored_syscalls64[syscallno])) 
			return;
	}

	if (IS_32BIT(regs)) goto scentry_skip_vldata;

	/* Some syscalls get special treatment. These guys have useful data that is 
 	 * pointed to by an argument, so we go follow that pointer and pull the real
 	 * data into the trace. Because the size of this data varies between syscall
 	 * types this is implemeted by adding a variable length appendage to the
 	 * syscall_enter record; this data occupies (sizeof(record type) thru reclen)
	 * bytes.
	 *
	 * To protect ourselves against retarded syscall callers we place a limit on
	 * the amount of variable length data we'll provide. If the caller passes
	 * rediculously long arguments then it'll get truncated data or nothing!
	 *
	 * An added complication comes from the tendency in Linux to bastardize and
	 * change syscalls between releases. For this reason I need to wrap many 
	 * syscall cases in #ifdefs.
	 */

	switch (syscallno) {

#ifdef __NR_open
	case	__NR_open:
#endif
#ifdef __NR_creat
	case	__NR_creat:
#endif
#ifdef __NR_access
	case	__NR_access:
#endif
#ifdef __NR_stat
	case	__NR_stat:
#endif
#ifdef __NR_lstat
	case	__NR_lstat:
#endif
#ifdef __NR_unlink
	case	__NR_unlink:
#endif
	case 	__NR_execve:

	{

		int	fnlen;


		/* Need to read in the args so we can find the filename. Only need
		 * to read in 3 args for read().
		 */
		SYSCALL_GET_ARGUMENTS(current, regs, 0, 3, args_tmp);
		fnlen=strnlen_user((const char __user *)*args_tmp, 32767);

		if (unlikely(fnlen==0))
			goto scentry_skip_vldata;

		if (fnlen > MAX_VLDATA_LEN)
			fnlen = MAX_VLDATA_LEN;

		/* We have an unwelcome complication here. I need to read in the
		 * filename from userspace. I'd like to allocate buffer space for 
		 * the trace, then read it from userspace straight into the trace
		 * memory, however I can't. I must disable interrupts between the
		 * call to trace_alloc() and trace_commit(), and copy_from_user()
		 * may sleep; sleeping with interrupts disabled is very bad! So
		 * instead I copy the filename to some temp space, then disable
		 * interrupts, allocate the trace buffer and copy it in.
		 *
		 * Note I don't use space on the stack to hold the filename. The
		 * maximum filename length recorded is defined by MAX_VLDATA_LEN,
		 * which may be quite big (e.g. 1K). The kernel stack is very 
		 * small, and blowing it is very bad! 
		 * 
		 * I'd like to allocate CPU-local memory for this at startup, but
		 * unfortunately again because of the copy_from_user() I cannot
		 * disable interrupts, so may be preempted on fully preemptive
		 * kernels. So instead I must allocate/free memory each time.
		 * Yawn...
		 */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		/* If copy from userspace fails, skip it */
		if (copy_from_user(vldtmp, (const char __user *)*args_tmp, fnlen) != 0) {
			kmem_cache_free(vldtmp_cache, vldtmp);
			goto scentry_skip_vldata;
		}

		/* Ensure the string is NULL-terminated! */
		memset(vldtmp+MAX_VLDATA_LEN-1, 0, 1);

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + fnlen));

		/* Now we can disable interrupts and allocate the trace buffer */
		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		/* Copy temporary copies of args and filename into the trace buffer */
		memcpy(t->args, args_tmp, sizeof(long) * 3);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, fnlen);

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}

#ifdef __NR_openat
	case	__NR_openat:
#endif
#ifdef __NR_creatat
	case	__NR_creatat:
#endif
#ifdef __NR_statat
	case	__NR_statat:
#endif
#ifdef __NR_lstatat
	case	__NR_lstatat:
#endif
#ifdef __NR_unlinkat
	case	__NR_unlinkat:
#endif

	{
		int	fnlen;

		/* Need to read in the args so we can find the filename. Only need
		 * to read in 4 args for openat().
		 */
		SYSCALL_GET_ARGUMENTS(current, regs, 0, 4, args_tmp);
		fnlen=strnlen_user((const char __user *)args_tmp[1], 32767);

		if (unlikely(fnlen==0))
			goto scentry_skip_vldata;

		if (fnlen > MAX_VLDATA_LEN)
			fnlen = MAX_VLDATA_LEN;

		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		/* If copy from userspace fails, skip it */
		if (copy_from_user(vldtmp, (const char __user *)args_tmp[1], fnlen) != 0) {
			kmem_cache_free(vldtmp_cache, vldtmp);
			goto scentry_skip_vldata;
		}

		/* Ensure the string is NULL-terminated! */
		memset(vldtmp+MAX_VLDATA_LEN-1, 0, 1);

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + fnlen));

		/* Now we can disable interrupts and allocate the trace buffer */
		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		/* Copy temporary copies of args and filename into the trace buffer */
		memcpy(t->args, args_tmp, sizeof(long) * 4);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, fnlen);

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}

	case	__NR_io_submit:

	{

		long		numiocbs;
		struct iocb 	**iocbpp;
		long		i;
		iocbsum_t 	*p;
		int		vldsz;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 3, args_tmp);

		/* We may have many more iocb structures than we have space
		 * for.
		 */
		numiocbs = args_tmp[1];

		vldsz = sizeof(iocbsum_t) * numiocbs;
		if (vldsz > MAX_VLDATA_LEN) {
			numiocbs = MAX_VLDATA_LEN / sizeof(iocbsum_t);
			vldsz = sizeof(iocbsum_t) * numiocbs;
		}

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + vldsz));

		iocbpp = (struct iocb **)args_tmp[2];

		/* Construct the vldata sequence in temp space for the reason
		 * discussed above.
		 */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL) 
			goto scentry_skip_vldata;

		p = vldtmp;

		for (i=0; i<numiocbs; i++, p++) {

			struct iocb		tmp;
			struct iocb __user	*user_iocb;

			if (unlikely(copy_from_user(&user_iocb, iocbpp + i, sizeof(void *)))) {
				kmem_cache_free(vldtmp_cache, vldtmp);
				goto scentry_skip_vldata;
			}

			if (unlikely(copy_from_user(&tmp, user_iocb, sizeof(tmp)))) {

				/* User passed us a bogus pointer! */
				memset(p, 0, sizeof(tmp));

			} else {

				p->aio_lio_opcode = tmp.aio_lio_opcode;
				p->aio_reqprio = tmp.aio_reqprio;
				p->aio_fildes = tmp.aio_fildes;
				p->aio_offset = tmp.aio_offset;
				p->aio_nbytes = tmp.aio_nbytes;

			}

			p->iocbp = user_iocb;
		}

#ifdef __LIKI_DEBUG
		if ((void *)p > (void *)(vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in io_submit() - THIS IS VERY BAD!!!\n");
#endif
		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * 3);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, ((void *)p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}

#ifdef __NR_select
	case	__NR_select:

	{

		int	fds_bytes;
		int	vldsz;
		void	*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 5, args_tmp);

		/* I'm going to implement the vldata thing a little differently
		 * here. Rather than give you the first so many bytes, you'll
		 * get nothing if you have rediculously long arguments. Frankly
		 * it was just too complicated to apportion N bytes across a
		 * TIMESPEC and three bitmasks; mistakes may be made.
		 */

		fds_bytes = (args_tmp[0]/8) + (args_tmp[0] & 07ULL ? 1 : 0);
		vldsz = sizeof(struct TIMESPEC) + (3 * fds_bytes);

		if (vldsz > MAX_VLDATA_LEN)
			goto scentry_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + vldsz));


		/* Construct the vldata sequence in temp space for the reason
		 * discussed above.
		 */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		p = vldtmp;

		/* timeout goes in first. Note that the caller may have specified NULL
  		 * for the timeout pointer; copy_from_user will return non-zero here
  		 * and we'll write zeros into the trace record - we will not barf.
  		 */
		if (copy_from_user(p, (const char __user *)args_tmp[4], sizeof(struct TIMESPEC)) != 0)
			memset(p, 0, sizeof(struct TIMESPEC));

		p += sizeof(struct TIMESPEC);

		/* then each of the variable length fd sets; infds */
		if (copy_from_user(p, (const char __user *)args_tmp[1], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		/* outfds */
		if (copy_from_user(p, (const char __user *)args_tmp[2], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		/* errorfds */
		if (copy_from_user(p, (const char __user *)args_tmp[3], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in select() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * 5);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}
#endif	// __NR_select

#ifdef __NR_pselect6
	case	__NR_pselect6:

	{

		int		fds_bytes;
		int		vldsz;
		void		*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 6, args_tmp);

		fds_bytes = (args_tmp[0]/8) + (args_tmp[0] & 07ULL ? 1 : 0);
		vldsz = sizeof(struct TIMESPEC) + (3 * fds_bytes);

		if (vldsz > MAX_VLDATA_LEN)
			goto scentry_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + vldsz));

		/* You aren't going to get the sigset in vldata; I don't think anyone cares. */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		p = vldtmp;

		if (copy_from_user(p, (const char __user *)args_tmp[4], sizeof(struct TIMESPEC)) != 0)
			memset(p, 0, sizeof(struct TIMESPEC));

		p += sizeof(struct TIMESPEC);

		if (copy_from_user(p, (const char __user *)args_tmp[1], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		if (copy_from_user(p, (const char __user *)args_tmp[2], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		if (copy_from_user(p, (const char __user *)args_tmp[3], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in pselect() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * 6);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}
#endif	// __NR_pselect6

#ifdef __NR_poll
	case	__NR_poll:

	{

		int	fdssz;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 3, args_tmp);

		/* Number of pollfd structures is given in args_tmp[1] */
		fdssz = sizeof(struct pollfd) * args_tmp[1];

		if (fdssz > MAX_VLDATA_LEN)
			goto scentry_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + fdssz));

		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		if (copy_from_user(vldtmp, (const char __user *)args_tmp[0], fdssz) != 0)
			memset(vldtmp, 0, fdssz);

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * 3);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, fdssz);

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	} 
#endif	// __NR_poll

#ifdef __NR_ppoll
	case	__NR_ppoll:

	{

		int	fdssz;
		int	vldsz;
		void 	*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 4, args_tmp);

		fdssz = sizeof(struct pollfd) * args_tmp[1];
		vldsz = fdssz + sizeof(struct TIMESPEC);

		if (vldsz > MAX_VLDATA_LEN)
			goto scentry_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_enter_t) + vldsz));

		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scentry_skip_vldata;

		p = vldtmp;

		/* timeout goes in first */
		if (copy_from_user(p, (const char __user *)args_tmp[2], sizeof(struct TIMESPEC)) != 0)
			memset(p, 0, sizeof(struct TIMESPEC));

		p += sizeof(struct TIMESPEC);

		/* then the fdsets */
		if (copy_from_user(p, (const char __user *)args_tmp[0], fdssz) != 0)
			memset(p, 0, fdssz);

		p += fdssz;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in ppoll() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * 4);
		memcpy(((void *)t + sizeof(syscall_enter_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

 	}
#endif	//__NR_ppoll

	default:

	{

scentry_skip_vldata:
		sz = TRACE_SIZE(syscall_enter_t);

		/* Here I get a fixed number of arguments, since that is what we
		 * did on HP-UX, and the userspace tools filter out the bogus
		 * ones. It would be better if I returned only the used args.
		 */
		SYSCALL_GET_ARGUMENTS(current, regs, 0, N_SYSCALL_ARGS, args_tmp);

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_enter_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		memcpy(t->args, args_tmp, sizeof(long) * N_SYSCALL_ARGS);

		}
	}

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	POPULATE_COMMON_FIELDS(t, TT_SYSCALL_ENTER, sz, UNORDERED);

	t->syscallno = syscallno;

	if (IS_32BIT(regs))
		t->is32bit = TRUE;
	else
		t->is32bit = FALSE;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
syscall_exit_trace(RXUNUSED struct pt_regs *regs, long ret)
{
	syscall_exit_t		*t;
	long			syscallno;
	long			args_tmp[N_SYSCALL_ARGS];
	void 			*vldtmp;
	int			sz;
	struct sockaddr_storage	remote;
	struct sockaddr_storage	local;
	struct socket		*sock;
	int			loclen = 0, remlen = 0;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(regs == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to syscall_exit_trace()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	syscallno = syscall_get_nr(current, regs);

	if (unlikely(IS_32BIT(regs))) {
		if (unlikely(ignored_syscalls32[syscallno])) 
			return;
	} else {
		if (unlikely(ignored_syscalls64[syscallno])) 
			return;
	}

	if (IS_32BIT(regs)) goto scexit_skip_vldata;

	switch (syscallno) {

#ifdef __NR_select
	case	__NR_select:

	{

		int	fds_bytes;
		int	vldsz;
		void	*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 5, args_tmp);

		fds_bytes = (args_tmp[0]/8) + (args_tmp[0] & 07ULL ? 1 : 0);
		vldsz = (3 * fds_bytes);

		if (vldsz > MAX_VLDATA_LEN)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + vldsz));


		/* Construct the vldata sequence in temp space for the reason
		 * discussed above.
		 */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scexit_skip_vldata;

		p = vldtmp;

		/* then each of the variable length fd sets; infds */
		if (copy_from_user(p, (const char __user *)args_tmp[1], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		/* outfds */
		if (copy_from_user(p, (const char __user *)args_tmp[2], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		/* errorfds */
		if (copy_from_user(p, (const char __user *)args_tmp[3], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in select() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(((void *)t + sizeof(syscall_exit_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}
#endif	// __NR_select

#ifdef __NR_pselect6
	case	__NR_pselect6:

	{

		int		fds_bytes;
		int		vldsz;
		void		*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 6, args_tmp);

		fds_bytes = (args_tmp[0]/8) + (args_tmp[0] & 07ULL ? 1 : 0);
		vldsz = (3 * fds_bytes);

		if (vldsz > MAX_VLDATA_LEN)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + vldsz));

		/* You aren't going to get the sigset in vldata; I don't think anyone cares. */
		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scexit_skip_vldata;

		p = vldtmp;

		if (copy_from_user(p, (const char __user *)args_tmp[1], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		if (copy_from_user(p, (const char __user *)args_tmp[2], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

		if (copy_from_user(p, (const char __user *)args_tmp[3], fds_bytes) != 0)
			memset(p, 0, fds_bytes);

		p += fds_bytes;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in pselect() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(((void *)t + sizeof(syscall_exit_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	}
#endif	// __NR_pselect6

#ifdef __NR_poll
	case	__NR_poll:

	{

		int	fdssz;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 3, args_tmp);

		/* Number of pollfd structures is given in args_tmp[1] */
		fdssz = sizeof(struct pollfd) * args_tmp[1];

		if (fdssz > MAX_VLDATA_LEN)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + fdssz));

		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scexit_skip_vldata;

		if (copy_from_user(vldtmp, (const char __user *)args_tmp[0], fdssz) != 0)
			memset(vldtmp, 0, fdssz);

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(((void *)t + sizeof(syscall_exit_t)), vldtmp, fdssz);

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

	} 
#endif	// __NR_poll

#ifdef __NR_ppoll
	case	__NR_ppoll:

	{

		int	vldsz;
		void 	*p;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 4, args_tmp);

		vldsz = sizeof(struct pollfd) * args_tmp[1];

		if (vldsz > MAX_VLDATA_LEN)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + vldsz));

		if ((vldtmp = kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scexit_skip_vldata;

		p = vldtmp;

		/* then the fdsets */
		if (copy_from_user(p, (const char __user *)args_tmp[0], vldsz) != 0)
			memset(p, 0, vldsz);

		p += vldsz;

#ifdef __LIKI_DEBUG
		if (p > (vldtmp + MAX_VLDATA_LEN))
			printk(KERN_WARNING "LiKI: Over-ran vldtmp in ppoll() - THIS IS VERY BAD!!!\n");
#endif

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldtmp);
			return;
		}

		memcpy(((void *)t + sizeof(syscall_exit_t)), vldtmp, (p - vldtmp));

		kmem_cache_free(vldtmp_cache, vldtmp);

		break;

 	}
#endif	//__NR_ppoll


	/* For the networking syscalls we capture the local and remote socket 
	 * addresses so we can reliably piece together connections across a cluster.
	 */
	case __NR_recvfrom:
	case __NR_sendto:

		{
		int			fd;
		int			err;
		int			fput_needed;
		short			sock_type = 0;

		if (ret <= 0) 
			goto scexit_skip_vldata;

		local.ss_family = 0;
		sock = NULL;

		SYSCALL_GET_ARGUMENTS(current, regs, 0, 6, args_tmp);

		/* Get the LOCAL address from the socket. Get this first so
		 * we can check whether it is AF_INET. If it isn't we don't
		 * care about it.
		 */
		fd = (int)args_tmp[0];

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		if ((sock = sockfd_lookup_light_fp(fd, &err, &fput_needed)) == NULL) 
#else
		fput_needed = 1;
		if ((sock = sockfd_lookup(fd, &err)) == NULL) 
#endif
			goto scexit_skip_vldata;

		sock_type = sock->type;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
		if ((loclen = sock->ops->getname(sock, (struct sockaddr *)&local, 0)) <= 0) {
#else
		if (sock->ops->getname(sock, (struct sockaddr *)&local, &loclen, 0)) {
#endif
			fput_light(sock->file, fput_needed);
			goto scexit_skip_vldata;
		}

		/* Pointer to buffer for address is in args[4], and size of this buffer
		 * is in args[5]. If either of these was zero and we still got data 
		 * then this must be a connection-based socket.
		 */
		if (args_tmp[4] == 0 || args_tmp[5] == 0) {

			/* Get remote socket addresses */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
			if ((remlen = sock->ops->getname(sock, (struct sockaddr *)&remote, 1)) <= 0) {
#else
			if (sock->ops->getname(sock, (struct sockaddr *)&remote, &remlen, 1)) {
#endif
				fput_light(sock->file, fput_needed);
				goto scexit_skip_vldata;
			}

		} else {

			/* Copy the remote address from the user buffer. We'll copy at most 
			 * either the number of bytes for which we have storage, or the
		 	 * number of bytes the kernel returned to the user buffer.
		 	 */
			if (args_tmp[5] < sizeof(struct sockaddr_storage))
				remlen = (int)args_tmp[5];
			else
				remlen = (int)sizeof(struct sockaddr_storage);
	
			if (copy_from_user((void *)&remote, (const char __user *)args_tmp[4], remlen) != 0)
				memset((void *)&remote, 0, sizeof(struct sockaddr_storage));
		}

		fput_light(sock->file, fput_needed);

		if (remlen <= 0 || loclen <= 0)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + loclen + remlen + sizeof(short)));

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		memcpy((void *)t + sizeof(syscall_exit_t), &local, loclen);
		memcpy((void *)t + sizeof(syscall_exit_t) + loclen, 
			&remote, remlen);
		memcpy((void *)t + sizeof(syscall_exit_t) + loclen + remlen, &sock_type, sizeof(short));

		break;

		}

	case __NR_recvmsg:
	case __NR_read:
	case __NR_readv:
	case __NR_pread64:
	case __NR_write:
	case __NR_writev:
	case __NR_pwrite64:
#ifdef __NR_sendmsg
	case __NR_sendmsg:
#endif
#ifdef __NR_send
	case __NR_send:
#endif
#ifdef __NR_recv
	case __NR_recv:
#endif

		{

 		struct kstat		stat_struct;
 		fileaddr_t		*fileaddr;
		int			fd;
		int			err;
		int			fput_needed;
	        short			sock_type = 0;


		/* Only care about socket addresses if we transferred data */
		if (ret <= 0) goto scexit_skip_vldata;

		/* Conveniently all these syscalls have the file descriptor as the
		 * first argument
		 */
		SYSCALL_GET_ARGUMENTS(current, regs, 0, 6, args_tmp);
		remote.ss_family = 0;
		sock = NULL;

		/* Get local and remote socket addresses, similar to getsockname()
		 * and getpeername()
		 */
		fd = (int)args_tmp[0];

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		if ((sock = sockfd_lookup_light_fp(fd, &err, &fput_needed)) != NULL)  {
#else
		fput_needed = 1;
		if ((sock = sockfd_lookup(fd, &err)) != NULL) {
#endif
			memset(&remote, 0, sizeof(struct sockaddr_storage));
			memset(&local, 0, sizeof(struct sockaddr_storage));
			sock_type = sock->type;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
			if ((remlen = sock->ops->getname(sock, (struct sockaddr *)&remote, 1)) <= 0) {
#else
			if (sock->ops->getname(sock, (struct sockaddr *)&remote, &remlen, 1)) {
#endif
				fput_light(sock->file, fput_needed);
				goto scexit_skip_vldata;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
			if ((loclen = sock->ops->getname(sock, (struct sockaddr *)&local, 0)) <= 0) {
#else
			if (sock->ops->getname(sock, (struct sockaddr *)&local, &loclen, 0)) {
#endif
				fput_light(sock->file, fput_needed);
				goto scexit_skip_vldata;
			}

			fput_light(sock->file, fput_needed);
	
			if (loclen <= 0 || remlen <= 0) {
				goto scexit_skip_vldata;
			}

		} else {

 			if (vfs_fstat_fp(fd, &stat_struct) != 0) 
 				goto scexit_skip_vldata;

 			fileaddr = (fileaddr_t *)&local;
 			fileaddr->ss_family = AF_REGFILE;
 			fileaddr->i_ino = stat_struct.ino;
			if (stat_struct.rdev) {
				fileaddr->dev = stat_struct.rdev;
			} else {
 				fileaddr->dev = stat_struct.dev;
			}

 			loclen = sizeof(fileaddr_t);
 			remlen = 0;
		}

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + loclen + remlen + sizeof(short)));

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		memcpy((void *)t + sizeof(syscall_exit_t), &local, loclen);
		memcpy((void *)t + sizeof(syscall_exit_t) + loclen, &remote, remlen);
		memcpy((void *)t + sizeof(syscall_exit_t) + loclen + remlen, &sock_type, sizeof(short));

		break;

		}

	case __NR_recvmmsg:
#ifdef __NR_sendmmsg
	case __NR_sendmmsg:
#endif

		{

		/* for the mmsg variants we additionally need to figure out
		 * how much data was actually sent by adding up all the
		 * msg_len fields.
		 */

		int			fd;
		int			err;
		int			fput_needed;
		unsigned int		vlen;
		void 			*vldata;
		unsigned long		bytes_xfer;


		loclen = remlen = 0;

		/* Only care about socket addresses if we transferred data */
		if (ret <= 0) goto scexit_skip_vldata;

		SYSCALL_GET_ARGUMENTS(current, regs, 0, 6, args_tmp);


		/* Figure out how much data was actually sent/received.
		 * Going to need space for the struct mmsghdr stuff to be
		 * copied in from userspace. Our vldata space is 1K so 
		 * should be plenty big enough. If not, skip vldata.
		 */
		vlen = (unsigned int)(args_tmp[2]);

		/* The following should be redundant, since ret should be <= 0
		 * if there are no messages, but belt and braces...
		 */
		if (vlen == 0)
			goto scexit_skip_vldata;

		if (vlen * sizeof(struct mmsghdr) > MAX_VLDATA_LEN)
			goto scexit_skip_vldata;

		if ((vldata = (void *)kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL)
			goto scexit_skip_vldata;

		if (unlikely(copy_from_user(vldata, (void *)args_tmp[1], vlen * sizeof(struct mmsghdr)))) {
			kmem_cache_free(vldtmp_cache, vldata);
			goto scexit_skip_vldata;
		}

		for (bytes_xfer=0; vlen>0; vlen--)
			bytes_xfer += ((struct mmsghdr *)vldata)[vlen-1].msg_len;

		kmem_cache_free(vldtmp_cache, vldata);


		/* Now on with the address stuff...
		 */
		remote.ss_family = 0;
		sock = NULL;

		/* Get local and remote socket addresses, similar to getsockname()
		 * and getpeername()
		 */
		fd = (int)args_tmp[0];

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		if ((sock = sockfd_lookup_light_fp(fd, &err, &fput_needed)) == NULL) 
#else
		fput_needed = 1;
		if ((sock = sockfd_lookup(fd, &err)) == NULL) 
#endif
			goto mmsgexit_skip_addresses;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
		if ((remlen = sock->ops->getname(sock, (struct sockaddr *)&remote, 1)) <= 0) {
#else
		if (sock->ops->getname(sock, (struct sockaddr *)&remote, &remlen, 1)) {
#endif
			fput_light(sock->file, fput_needed);
			goto scexit_skip_vldata;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
			if ((loclen = sock->ops->getname(sock, (struct sockaddr *)&local, 0)) <= 0) {
#else
			if (sock->ops->getname(sock, (struct sockaddr *)&local, &loclen, 0)) {
#endif
			fput_light(sock->file, fput_needed);
			goto scexit_skip_vldata;
		}

		fput_light(sock->file, fput_needed);

		if (loclen <= 0 || remlen <= 0)
			loclen = remlen = 0;

mmsgexit_skip_addresses:

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + sizeof(unsigned long) + 
				loclen + remlen));

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		*((unsigned long *)((void *)t + sizeof(syscall_exit_t))) = bytes_xfer;

		if (loclen) {
			memcpy((void *)t + sizeof(syscall_exit_t) + sizeof(unsigned long), 
			&local, loclen);
			memcpy((void *)t + sizeof(syscall_exit_t) + sizeof(unsigned long) + loclen,
			&remote, remlen);
		}

		break;

		}

#ifdef __NR_sendfile
	case __NR_sendfile:
#endif
		{

		int			out_fd;
		int			err;
		int			fput_needed;


		/* Only care about socket addresses if we transferred data */
		if (ret <= 0) goto scexit_skip_vldata;

		/* Get args for the out_fd */
		SYSCALL_GET_ARGUMENTS(current, regs, 0, 4, args_tmp);
		remote.ss_family = 0;
		sock = NULL;

		/* Get local and remote socket addresses, similar to getsockname()
		 * and getpeername()
		 */
		out_fd = (int)args_tmp[1];
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
		if ((sock = sockfd_lookup_light_fp(out_fd, &err, &fput_needed)) == NULL) 
#else
		fput_needed = 1;
		if ((sock = sockfd_lookup(out_fd, &err)) == NULL) 
#endif
			goto scexit_skip_vldata;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
		if ((remlen = sock->ops->getname(sock, (struct sockaddr *)&remote, 1)) <= 0) {
#else
		if (sock->ops->getname(sock, (struct sockaddr *)&remote, &remlen, 1)) {
#endif
			fput_light(sock->file, fput_needed);
			goto scexit_skip_vldata;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
		if ((loclen = sock->ops->getname(sock, (struct sockaddr *)&local, 0)) <= 0) {
#else
		if (sock->ops->getname(sock, (struct sockaddr *)&local, &loclen, 0)) {
#endif
			fput_light(sock->file, fput_needed);
			goto scexit_skip_vldata;
		}

		fput_light(sock->file, fput_needed);

		if (loclen <= 0 || remlen <= 0)
			goto scexit_skip_vldata;

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + loclen + remlen));

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		memcpy((void *)t + sizeof(syscall_exit_t), &local, loclen);
		memcpy((void *)t + sizeof(syscall_exit_t) + loclen, &remote, remlen);

		break;

		}

	case __NR_io_getevents:
		{

		int		vldsz;
		int		numioev;
		int		i;
		struct io_event	*ioevp, *vldp;


		if (ret <= 0) goto scexit_skip_vldata;


		SYSCALL_GET_ARGUMENTS(current, regs, 0, 4, args_tmp);

		/* We may have many more io_event structures than we have space
		 * for.
		 */
		numioev = ret;
		vldsz = sizeof(struct io_event) * numioev;
		if (vldsz > MAX_VLDATA_LEN) {
			numioev = MAX_VLDATA_LEN / sizeof(struct io_event);
			vldsz = sizeof(struct io_event) * numioev;
		}

		sz = TRACE_ROUNDUP((sizeof(syscall_exit_t) + vldsz));

		ioevp = (struct io_event *)args_tmp[3];

		/* Copy data from userspace to vldtmp space
		 */
		if ((vldp = (struct io_event *)kmem_cache_alloc(vldtmp_cache, GFP_KERNEL)) == NULL) 
			goto scexit_skip_vldata;

		for (i=0; i<numioev; i++) {
			if (unlikely(copy_from_user(&vldp[i], ioevp + i, sizeof(struct io_event))))
				memset(&vldp[i], 0, sizeof(struct io_event));
		}

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			kmem_cache_free(vldtmp_cache, vldp);
			return;
		}

		memcpy(((void *)t + sizeof(syscall_exit_t)), vldp, vldsz);

		kmem_cache_free(vldtmp_cache, vldp);

		break;

		}

	default:

		{

scexit_skip_vldata:
		sz = TRACE_SIZE(syscall_exit_t);

		raw_local_irq_save(flags);

		if (unlikely((t = (syscall_exit_t *)trace_alloc(sz, TRUE)) == NULL)) {
			raw_local_irq_restore(flags);
			return;
		}

		}

	}

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	POPULATE_COMMON_FIELDS(t, TT_SYSCALL_EXIT, sz, UNORDERED);
	t->syscallno = syscallno;
	if (IS_32BIT(regs))
		t->is32bit = TRUE;
	else
		t->is32bit = FALSE;

	t->ret = ret;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


/* The following is the expected preempt_count when not executing in driver/interrupt */
#define HARDCLOCK_COUNT		0x10000

STATIC void
hardclock_trace(struct pt_regs *regs)
{
	hardclock_t			*t;
	unsigned long			time;
	unsigned int			sz, stksz;
	int				first_entry = 0;
	struct liki_callchain_entry	*callchain = NULL;
	int				preempt_cnt;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))) {
			return;
		}
	}

	/* Do the unwind early so I know how much space to allocate in
	 * the trace (based on stack depth)
	 */

	/* if we are using timers and SOFTIRQ_VAL is set to 1, then that is due to the timer.
	 * So clear it, but if we are using jprobes, then the HARDIRQ_VAL is set to 1 and we
	 * will clear that as well
	 */
	preempt_cnt = preempt_count();
	if (timer_lists && (SOFTIRQ_VAL(preempt_cnt) == 1))
	        preempt_cnt &= ~SOFTIRQ_MASK;
	else if (HARDIRQ_VAL(preempt_cnt) == 1)
	        preempt_cnt &= ~HARDIRQ_MASK;

	/* If we're idle we don't want any stacktrace. 
	 */
	if (!(current->pid == 0 && (preempt_cnt == 0)))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
		/* I don't know if this is always true, but it was for Ubuntu with 5.8.12 kernel */
		callchain = liki_stack_unwind(regs, HARDCLOCK_STACK_SKIP+2, &first_entry);
#else
		callchain = liki_stack_unwind(regs, HARDCLOCK_STACK_SKIP, &first_entry);
#endif

	if (callchain)
		stksz = sizeof(unsigned long) * (callchain->nr - first_entry);
	else
		stksz = 0;

	sz = TRACE_ROUNDUP((sizeof(hardclock_t) + stksz));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

#ifdef HARDCLOCK_INTERVAL
	/* Throttle the rate of hardclock records to less than the resolution
	 * of the profile tick. It would be nice to do this by creating a
	 * unique timer (i.e. not use the profile timer), but since we want 
	 * hardclocks to stop when the CPU is idle this would be more involved
	 * and require more hooks into the kernel than it's worth.
	 */
	time = liki_global_clock(tb, UNORDERED);

	if (time < (tb->last_hardclock + (HARDCLOCK_INTERVAL * 1000000))) {
		raw_local_irq_restore(flags);
		return;
	}

	tb->last_hardclock = time;
#endif

	if (unlikely((t = (hardclock_t *)trace_alloc(sz, TRUE)) == NULL)) {
		raw_local_irq_restore(flags);
		printk(KERN_WARNING "LiKI: hardclock_trace() - trace_alloc failed\n");
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_HARDCLOCK, sz, UNORDERED);

	/* The common fields in the hardclock trace are a little different.
	 * Ordinarily we want the pid and cmd to indicate that we are in 
	 * an ISR, but in this case we know we're in an ISR and we want to
	 * know about the interrupted task.
	 */
	t->pid = current->pid;
	t->tgid = current->tgid;

	/* Copy in stack trace if we got one */
	if (callchain) {
		t->stack_depth = callchain->nr - first_entry;
		memcpy(t->ips, &callchain->ip[first_entry], stksz);
	} else 
		t->stack_depth = 0;

	if (callchain && (callchain->nr && (callchain->ip[0] == STACK_CONTEXT_USER))) {
		t->preempt_count = USER_MODE;
	} else {
		t->preempt_count = preempt_cnt;
	}

	trace_commit(t);

	raw_local_irq_restore(flags);


#ifdef BROKEN_PLATFORM_CLOCKS

	/* If this CPU is the main man and the clock is still considered unstable,
	 * consider whether we should now consider it stable. This may take a while
	 * so do it after interrupts are re-enabled.
	 *
	 * If the kernel has found the TSCs to be unstable, we shouldn't guess 
	 * otherwise - else something like not having constant_tsc and an active 
	 * frequency driver could screw us up!
	 */
#ifdef CONFIG_X86_64
#define KERNEL_THINKS_CLOCK_UNSTABLE check_tsc_unstable()
#else
#define KERNEL_THINKS_CLOCK_UNSTABLE 0
#endif

	if (unlikely(!liki_clock_stable && tb->main_man && !KERNEL_THINKS_CLOCK_UNSTABLE)) {

		int 	cpu;
		int	unstable_this_tick = 0;

		/* Look through all CPUs, comparing their tsc_offset to the value
		 * it had during the last tick. If tha value of any CPU's offset
		 * has increased more than TSC_STABLE_NS_THRESHOLD then the clocks
		 * aren't yet stable.
		 */
		for (cpu=0; cpu<nr_cpu_ids; cpu++) {

			if (tbufs[cpu].tsc_offset - tbufs[cpu].prev_tsc_offset	> TSC_STABLE_NS_THRESHOLD)
				unstable_this_tick++;

			tbufs[cpu].prev_tsc_offset = tbufs[cpu].tsc_offset;
		}

		/* If the clocks aren't stable then reset the count of ticks for
		 * which the clocks were stable, otherwise increment the count
		 * and consider pronouncing the clocks finally stable.
		 */
		if (unstable_this_tick) 
			consecutive_stable_ticks = 0;
		else
			consecutive_stable_ticks++;

		if (consecutive_stable_ticks >= TSC_STABLE_TICKS_THRESHOLD)
			liki_clock_stable = 1;

#ifdef __LIKI_DEBUG
		printk("consecutive_stable_ticks: %d\n", consecutive_stable_ticks);
#endif

	}

#endif // BROKEN_PLATFORM_CLOCKS

	return;
}


/* Kernel 3.10 has a bug. Some fool removed register_timer_hook() because they
 * couldn't immediately see any code that used it. LiKI uses it, as does SystemTAP,
 * so both tools became broken. The SystemTAP folks complained, so code is being
 * inserted that introduces a new profile-tick tracepoint. When this is in, LiKI
 * should use it. However in the mean time we can hook ourselves back into the
 * profile_tick mechanism using jprobes.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0) 

STATIC void
hardclock_jprobe(int type)
{
	struct pt_regs *regs = get_irq_regs();

	hardclock_trace(regs);

	jprobe_return();
}

STATIC struct jprobe jphc = {
	.entry = (kprobe_opcode_t *)hardclock_jprobe,
	.kp = {
		.symbol_name = "profile_tick",
	},
};

#endif

long unsigned int kln_addr = 0;
unsigned long (*kallsyms_lookup_name_fp)(const char *name) = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) 
/* This code is derived from https://github.com/zizzu0/LinuxKernelModules/blob/main/FindKallsymsLookupName.c
* kallsyms_lookup_name undefined and finding not exported functions in the linux kernel
*
* zizzu 2020
*
* On kernels 5.7+ kallsyms_lookup_name is not exported anymore, so it is not usable in kernel modules.
* The address of this function is visible via /proc/kallsyms
* but since the address is randomized on reboot, hardcoding a value is not possible.
* A kprobe replaces the first instruction of a kernel function
* and saves cpu registers into a struct pt_regs *regs and then a handler
* function is executed with that struct as parameter.
* The saved value of the instruction pointer in regs->ip, is the address of probed function + 1.
* A kprobe on kallsyms_lookup_name can read the address in the handler function.
* Internally register_kprobe calls kallsyms_lookup_name, which is visible for this code, so,
* planting a second kprobe, allow us to get the address of kallsyms_lookup_name without waiting
* and then we can call this address via a function pointer, to use kallsyms_lookup_name in our module.
*
* example for _x86_64.
*/

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (--regs->ip);

  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;

  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;

  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
    return ret;
  }

#ifdef __LIKI_DEBUG
  pr_info("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);
#endif

  return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0) || (defined(CONFIG_PPC64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)))
STATIC void
hardclock_timer(struct timer_list *t)
{
#else
STATIC void
hardclock_timer(unsigned long data)
{
#endif
	int cpu = raw_smp_processor_id();
	unsigned long target_jiffy = jiffies + 1;
	struct pt_regs *regs;

	regs = get_irq_regs();

	hardclock_trace(regs);

	if (!shutdown_pending && !(tracing_state == TRACING_DISABLED)) {
		mod_timer(&timer_lists[cpu], target_jiffy);
	}
}

STATIC void
power_start_trace(RXUNUSED unsigned int type, unsigned int state, unsigned int cpu)
{
	power_start_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (power_start_t *)trace_alloc(TRACE_SIZE(power_start_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_POWER_START, TRACE_SIZE(power_start_t), UNORDERED);
	t->type = (unsigned long)type;
	t->state = (unsigned long)state;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
power_end_trace(RXUNUSED unsigned int cpu)
{
	power_end_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (power_end_t *)trace_alloc(TRACE_SIZE(power_end_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_POWER_END, TRACE_SIZE(power_end_t), UNORDERED);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
cpu_idle_trace(RXUNUSED unsigned int state, unsigned int cpu)
{

	if ((int)state == -1)
		power_end_trace(TXUNUSED cpu);
	else
		power_start_trace(TXUNUSED 0, state, cpu);
}
#endif


STATIC INLINE void
freq_trace_common(unsigned long type, unsigned long freq, unsigned long cpu)
{
	power_freq_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))
			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (power_freq_t *)trace_alloc(TRACE_SIZE(power_freq_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_POWER_FREQ, TRACE_SIZE(power_freq_t), UNORDERED);
	t->type = type; /* Retire this in v7 */
	t->freq = freq;
	t->tgt_cpu = cpu;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
cpu_freq_trace(RXUNUSED unsigned long freq, unsigned long cpu)
{
	freq_trace_common(0, freq, cpu);
}

#else
STATIC void
power_freq_trace(RXUNUSED unsigned long type, unsigned long freq, unsigned long cpu)
{
	freq_trace_common(type, freq, cpu);
}
#endif


STATIC void
irq_handler_entry_trace(RXUNUSED int irq, struct irqaction *action)
{
	irq_handler_entry_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(action == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to irq_handler_entry_trace()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (irq_handler_entry_t *)trace_alloc(TRACE_SIZE(irq_handler_entry_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_IRQ_HANDLER_ENTRY, TRACE_SIZE(irq_handler_entry_t), UNORDERED);
	
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->pid = current->pid;
	t->tgid = current->tgid;

	t->irq = irq;

	if (action->name != NULL)
		strncpy(t->name, action->name, IRQ_NAME_LEN);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
irq_handler_exit_trace(RXUNUSED int irq, struct irqaction *action, int ret)
{
	irq_handler_exit_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (irq_handler_exit_t *)trace_alloc(TRACE_SIZE(irq_handler_exit_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_IRQ_HANDLER_EXIT, TRACE_SIZE(irq_handler_exit_t), UNORDERED);
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->pid = current->pid;
	t->tgid = current->tgid;
	t->irq = irq;
	t->ret = ret;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


/* I'm not at all happy about the following being here. It isn't exported for
 * use by modules, so if I wanted a name I had to put it here. Thankfully the
 * community STRONGLY discourages the addition of new softirqs, so hopefully
 * it will be stable. If not, the vector in the trace will be correct but the 
 * name will not.
 */
#define NR_SOFTIRQS     10

char *softirq_names[NR_SOFTIRQS] = {
        "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "BLOCK_IOPOLL",
        "TASKLET", "SCHED", "HRTIMER",  "RCU"
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
softirq_entry_trace(RXUNUSED unsigned int vec_nr)
#else
STATIC void
softirq_entry_trace(RXUNUSED struct softirq_action *h, struct softirq_action *vec)
#endif
{
	softirq_entry_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (softirq_entry_t *)trace_alloc(TRACE_SIZE(softirq_entry_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SOFTIRQ_ENTRY, TRACE_SIZE(softirq_entry_t), UNORDERED);
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->pid = current->pid;
	t->tgid = current->tgid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	t->vec = vec_nr;
#else
	if (vec)
		t->vec = (int)(h - vec);
	else
		t->vec = (int)(long)h;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
softirq_exit_trace(RXUNUSED unsigned int vec_nr)
#else
STATIC void
softirq_exit_trace(RXUNUSED struct softirq_action *h, struct softirq_action *vec)
#endif
{
	softirq_exit_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (softirq_exit_t *)trace_alloc(TRACE_SIZE(softirq_exit_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SOFTIRQ_EXIT, TRACE_SIZE(softirq_exit_t), UNORDERED);
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->pid = current->pid;
	t->tgid = current->tgid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	t->vec = vec_nr;
#else
	if (vec)
		t->vec = (int)(h - vec);
	else
		t->vec = (int)(long)h;
#endif

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
STATIC void
softirq_raise_trace(RXUNUSED unsigned int vec_nr)
#else
STATIC void
softirq_raise_trace(RXUNUSED struct softirq_action *h, struct softirq_action *vec)
#endif
{
	softirq_raise_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!(resource_is_traced(PID_RESOURCE(current->pid)) ||
		      resource_is_traced(TGID_RESOURCE(current->tgid)) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (softirq_raise_t *)trace_alloc(TRACE_SIZE(softirq_raise_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SOFTIRQ_RAISE, TRACE_SIZE(softirq_raise_t), UNORDERED);
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->pid = current->pid;
	t->tgid = current->tgid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	t->vec = vec_nr;
#else
	if (vec)
		t->vec = (int)(h - vec);
	else
		t->vec = (int)(long)h;
#endif

	if (t->vec >= 0 && t->vec < NR_SOFTIRQS)
		strncpy(t->name, softirq_names[t->vec], IRQ_NAME_LEN);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
__workqueue_enqueue_trace_common(int cpu, struct work_struct *work)
{
	workqueue_enqueue_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(work == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to workqueue_enqueue()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((!in_interrupt() && current ? resource_is_traced(PID_RESOURCE(current->pid)) : 0) ||
		      (!in_interrupt() && current ? resource_is_traced(TGID_RESOURCE(current->tgid)) : 0) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (workqueue_enqueue_t *)trace_alloc(TRACE_SIZE(workqueue_enqueue_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_WORKQUEUE_ENQUEUE, TRACE_SIZE(workqueue_enqueue_t), ORDERED);
	
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	if (cpu == NR_CPUS)
		t->tgt_cpu = UINT_MAX;
	else
		t->tgt_cpu = cpu;
	t->funcp = work->func;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
STATIC void
workqueue_enqueue_trace(struct task_struct *task, struct work_struct *work)
{
	__workqueue_enqueue_trace_common(task_cpu(task), work);
}

#else
STATIC void
workqueue_enqueue_trace(RXUNUSED int cpu, void *wq, struct work_struct *work)
{
	__workqueue_enqueue_trace_common(cpu, work);
}
#endif


STATIC void
__workqueue_execute_trace_common(struct work_struct *work)
{
	workqueue_execute_t	*t;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(work == NULL)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to workqueue_execute()\n");
#endif
		return;
	}

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!((!in_interrupt() && current ? resource_is_traced(PID_RESOURCE(current->pid)) : 0) ||
		      (!in_interrupt() && current ? resource_is_traced(TGID_RESOURCE(current->tgid)) : 0) ||
		      resource_is_traced(CPU_RESOURCE(raw_smp_processor_id()))))

			return;
	}

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (workqueue_execute_t *)trace_alloc(TRACE_SIZE(workqueue_execute_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_WORKQUEUE_EXECUTE, TRACE_SIZE(workqueue_execute_t), ORDERED);
	
	/* Set the PID of the process that was running when the IRQ occured, similar to ftrace */
	t->funcp = work->func;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
STATIC void
workqueue_execute_trace(struct task_struct *task, struct work_struct *work)
{
	__workqueue_execute_trace_common(work);
}

#else
STATIC void
workqueue_execute_trace(RXUNUSED struct work_struct *work)
{
	__workqueue_execute_trace_common(work);
}
#endif


STATIC void
scsi_dispatch_cmd_start_trace(RXUNUSED struct scsi_cmnd *cmd)
{
	scsi_dispatch_cmd_start_t	*t;
	register int	sz;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))
			return;
	}

	if (unlikely(!cmd)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to scsi_dispatch_cmd_start_trace()\n");
#endif
		return;
	}

	/* The cmd->cmnd field is a variable length field. */
	sz = TRACE_ROUNDUP((cmd->cmd_len + sizeof(scsi_dispatch_cmd_start_t)));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (scsi_dispatch_cmd_start_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SCSI_DISPATCH_CMD_START, sz, ORDERED);

	t->host_no = cmd->device->host->host_no;
	t->channel = cmd->device->channel;
	t->cmd_id = cmd->device->id;
	t->lun = cmd->device->lun;
	t->opcode = cmd->cmnd[0];
	t->cmd_len = cmd->cmd_len;
	t->data_sglen = scsi_sg_count(cmd);
	t->prot_sglen = scsi_prot_sg_count(cmd);
	t->prot_op = scsi_get_prot_op(cmd);
	memcpy(&(t->cmnd), cmd->cmnd, cmd->cmd_len);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
scsi_dispatch_cmd_done_trace(RXUNUSED struct scsi_cmnd *cmd)
{
	scsi_dispatch_cmd_done_t	*t;
	register int			sz;
	TRACE_COMMON_DECLS;

	if (unlikely(tracing_state == TRACING_DISABLED))
		return;

	if (unlikely(tracing_state == TRACING_RESOURCES)) {

		if (!resource_is_traced(CPU_RESOURCE(raw_smp_processor_id())))
			return;
	}

	if (unlikely(!cmd)) {
#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: NULL pointer passed to scsi_dispatch_cmd_done_trace()\n");
#endif
		return;
	}

	/* The cmd->cmnd field is a variable length field. */
	sz = TRACE_ROUNDUP((cmd->cmd_len + sizeof(scsi_dispatch_cmd_done_t)));

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (scsi_dispatch_cmd_done_t *)trace_alloc(sz, FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_SCSI_DISPATCH_CMD_DONE, sz, ORDERED);

	t->host_no = cmd->device->host->host_no;
	t->channel = cmd->device->channel;
	t->cmd_id = cmd->device->id;
	t->lun = cmd->device->lun;
	t->result = cmd->result;
	t->opcode = cmd->cmnd[0];
	t->cmd_len = cmd->cmd_len;
	t->data_sglen = scsi_sg_count(cmd);
	t->prot_sglen = scsi_prot_sg_count(cmd);
	t->prot_op = scsi_get_prot_op(cmd);
        memcpy(&(t->cmnd), cmd->cmnd, cmd->cmd_len);

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}


STATIC void
startup_trace(void)
{
	startup_t	*t;
	unsigned long	before, after;
	TRACE_COMMON_DECLS;

	raw_local_irq_save(flags);

	mycpu = raw_smp_processor_id();
	tb = &tbufs[mycpu];

	if (unlikely((t = (startup_t *)trace_alloc(TRACE_SIZE(startup_t), FALSE)) == NULL)) {
		raw_local_irq_restore(flags);
		return;
	}

	POPULATE_COMMON_FIELDS(t, TT_STARTUP, TRACE_SIZE(startup_t), UNORDERED);

	before = liki_global_clock(tb, ORDERED);
	KTIME_GET(&(t->walltime));
	after = liki_global_clock(tb, ORDERED);
	t->hrtime = ((after - before)/2) + before;

	t->tracemask = installed_traces;
	t->enabled_features = enabled_features;

	trace_commit(t);

	raw_local_irq_restore(flags);

	return;
}

/* debugfs dummy open
 * This is to work around a bug in RHEL 8 where the 
 * access to debugfs files fails with EPERM if there is
 * not an .open definition in the file ops.
 */
STATIC int
liki_dummy_open(struct inode *ino, struct file *f)
{
        return 0;
}

/* debugfs interface to the ring buffer
 * 
 * cpu_buf_open() is the function invoked when userspace calls open() on a
 * ring buffer file.
 */
STATIC int 
cpu_buf_open(struct inode *inode, struct file *file)
{
	struct tbuf 		*tb;
	struct task_struct	*reader;

	/* Only one task can open each trace file for reading
	 * at once. We also need to ensure there is no active
	 * in-kernel reader when we tear down the data at
	 * module unload time
	 */
	mutex_lock(&state_mutex);

	if ((tb = (struct tbuf *)inode->i_private) == NULL) {
		mutex_unlock(&state_mutex);
		printk(KERN_WARNING "LiKI: i_private == NULL in cpu_buf_open()\n");
		return(-EINVAL);
	}

	if ((reader = tb->rd_task) != NULL) {

		/* We have a recorded read task for this file already.
		 */
		mutex_unlock(&state_mutex);
		return(-EAGAIN);
	}

	/* Either there is no current reader, or the there was but it died.
	 * Either way we're free to go ahead and become the reader.
	 */
	tb->rd_task = current;

	file->private_data = tb;

	mutex_unlock(&state_mutex);

	return(nonseekable_open(inode, file));
}


/* cpu_buf_release() is called when userspace calls close() on a ring 
 * buffer file, or a task with the ring buffer file open terminates.
 */
STATIC int
cpu_buf_release(struct inode * inode, struct file * file)
{
	struct tbuf	*tb;

	mutex_lock(&state_mutex);

	if ((tb = (struct tbuf *)file->private_data) == NULL) {
		mutex_unlock(&state_mutex);
		printk(KERN_WARNING "LiKI: i_private == NULL in cpu_buf_release()\n");
		return(-ENODEV);
	}

	/* If there is no registered reader, then the file isn't
	 * currently open
	 */
	if (tb->rd_task == NULL) {

		mutex_unlock(&state_mutex);
		printk(KERN_WARNING "LiKI: rd_task == NULL in cpu_buf_release()\n");
		return(-EINVAL);
	}
	
	tb->rd_task = NULL;
	file->private_data = NULL;

	mutex_unlock(&state_mutex);

	return(0);
}


#define DECREMENT_READER_CNT		\
	do {				\
		oval = reader_cnt;	\
		nval = oval - 1;	\
	} while (cmpxchg(&reader_cnt, oval, nval) != oval);


STATIC ssize_t 
cpu_buf_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	struct tbuf	*tb;
	char		*tdata;
	unsigned long	oval, nval;
	int		sync_case;
	unsigned int	valid_bytes;
	unsigned int	page_length;
	unsigned long 	flags;


	/* Caller must request at least CHUNK_SIZE bytes */
	if (count < CHUNK_SIZE)
		return(-EINVAL);


	/* We need to coordinate with the shutdown code. The challenge is
	 * that the shutdown code frees the memory used for tbuf and the
	 * buffers, and we need to be sure that we don't access them here
	 * after they are free'ed. (The broader problem of the module being
	 * unloaded while someone has one of our files open is thankfully
	 * protected against by the filesystem - the module unload will
	 * wait until there are no references to our files.)
	 *
	 * The approach taken is to keep a reader count. The shutdown
	 * code must atomically set the reader count from 0 to IN_SHUTDOWN,
	 * and the reader code must atomically increment the count from any
	 * value other than IN_SHUTDOWN.
	 */
	do {
		oval = reader_cnt;

		if (oval == IN_SHUTDOWN) 
			return(-EIO);

		if (want_shutdown)
			return(-EIO);
		
		nval = oval + 1;

	} while (cmpxchg(&reader_cnt, oval, nval) != oval);


	/* From here on down, there MUST be no way out of this function that 
	 * doesn't decrement the reader count before exiting!
	 */


	/* Note that private_data provides a place in which we can squirrel
	 * away something relevant to a file when the file is created. In
	 * this case I use this as a place to store a pointer to the tbuf
	 * structure pertaining to the CPU to which the file refers.
	 * If there is no buffer for this CPU (presumably because it was
	 * offline when the buffers were allocated) then be sure to
	 * return a failure - and NOT dereference a null buffer pointer.
	 */
	if ((tb = (struct tbuf *)file->private_data) == NULL) {
		DECREMENT_READER_CNT;
		return(-ENODEV);
	}

restart_buffer_get:

	if ((tdata = buffer_get(tb, &sync_case)) == NULL) {

		/* We didn't get a buffer. That means either we
		 * were woken from sleep by a signal, or are 
		 * shutting down.
		 */
		DECREMENT_READER_CNT;

		if (signal_pending(current)) {
			return(-EINTR);
		} else
			return(0);
	}

	if (sync_case) {

		unsigned long	sync_time;
		struct tbuf	*mytb;
		int		mycpu;

		/* We're going to copy out the valid bytes in the chunk even
		 * though we don't hold the lock on the chunk; we have set
		 * sync_reader_active however, and this in combination with
		 * sync_chunk will tell the writer not to completely over-
		 * write the chunk. (It's ok for the writer to continue 
		 * appending data, but not to wrap around and overwrite
		 * the piece of the chunk we are taking as valid.)
		 *
		 * We know the bytes in the range (0 thru alloc_offset)
		 * are valid, so we'll return these. Other traces may get
		 * appended while we copy, but we'll ignore those.
		 *
		 * We'll make a note in the header of the current time so
		 * that when merging we can know that we have all traces
		 * up to this time and can merge to this point even if no
		 * traces have been produced by this CPU for a while. We
		 * must turn off interrupts while getting the time, else
		 * we might migrate between determining our CPU and using
		 * the offset correction for that CPU.
		 */
		local_irq_save(flags);
		mycpu = raw_smp_processor_id();	
		mytb = &tbufs[mycpu];
		sync_time = liki_global_clock(mytb, UNORDERED);
		local_irq_restore(flags);

		valid_bytes = tb->alloc_offset;

		/* If "the writer" spilled over into the next chunk while
		 * we were getting here then the alloc_offset we copied
		 * may apply to the new chunk rather than the old. However
		 * the chunk we want is now free so restart.
		 */
		if (tb->alloc_chunk != tdata) {

			/* We have set sync_reader_active in buffer_get()
			 * so unset it here.
			 */
			local_irq_save(flags);
			real_spin_lock(&tb->chunk_interlock);
			tb->sync_reader_active = FALSE;
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);

			goto restart_buffer_get;
		}

		page_length = valid_bytes - TRACE_SIZE(info_t);

		/* The first copy_to_user() copies out the trace record as
		 * it stands, then the second fixes up the page_size field
		 * to reflect that we're returning a partial page. Note that
		 * the page may be modified while we're copying it out, but
		 * we know that at least valid_bytes will be valid. We are
		 * protected from the writer wrapping around and overwriting
		 * the page by sync_reader_active. The third copy writes 
		 * out the sync time into the chunk header; this both tells
		 * userspace that this chunk is a sync chunk, and the time
		 * up to which it represents (this may be different from the
		 * time of last trace if the CPU is idle and in powersave).
		 *
		 * Some trivia: Not all memcpy implementations copy in the
		 * obvious low-to-high order; if you want to know why think
		 * about the case of copying overlapping regions of memory.
		 * This is why I don't just rely on copying the chunk to
		 * write an appropriate page_length value to the target.
		 */
		if (copy_to_user(ubuf, tdata, valid_bytes) ||
		    copy_to_user(&((info_t *)ubuf)->page_length, &page_length, sizeof(int)) ||
		    copy_to_user(&((info_t *)ubuf)->sync_time, &sync_time, sizeof(unsigned long))) {

			/* No need to buffer_release() since we don't hold lock
			 */
			local_irq_save(flags);
			real_spin_lock(&tb->chunk_interlock);
			tb->sync_reader_active = FALSE;
			real_spin_unlock(&tb->chunk_interlock);
			local_irq_restore(flags);

			DECREMENT_READER_CNT;

			printk(KERN_WARNING "LiKI: copy to userspace failed\n");
			return(-EIO);
		}

		/* We've copied out data that extends to or beyond the
		 * sync point so the sync is complete for this CPU.
		 */
		local_irq_save(flags);
		real_spin_lock(&tb->chunk_interlock);

		/* It is possible that a later sync came in and 
		 * changed sync_chunk while we were working. We
		 * must leave this new sync in place, and only 
		 * clear sync_chunk if it is the sync that we're
		 * responding to.
		 * Is it possible that a later sync came in and
		 * set sync_chunk to this same chunk? Absolutely,
		 * but we're servicing that later sync right now,
		 * so we still get to clear sync_chunk.
		 */
		if (tb->sync_chunk == tdata)
			tb->sync_chunk = NULL;
		tb->sync_reader_active = FALSE;

		real_spin_unlock(&tb->chunk_interlock);
		local_irq_restore(flags);

		DECREMENT_READER_CNT;

		return(valid_bytes);
	}

	/* Could copy out the exact size, but it's likely to be 
	 * close, and that would take a second copy_to_user() to
	 * patch up the page_length.
	 */
	if (copy_to_user(ubuf, tdata, CHUNK_SIZE)) {

		/* Don't do the full buffer_release() as we didn't
		 * successfully read this chnk.
		 */
		local_irq_save(flags);
		real_spin_lock(&tb->chunk_interlock);
		tb->chunk_locks &= ~CHUNK_MASK(tb, tdata);
		real_spin_unlock(&tb->chunk_interlock);
		local_irq_restore(flags);

		DECREMENT_READER_CNT;

		printk(KERN_WARNING "LiKI: copy to userspace failed\n");
		return(-EIO);
	}

	valid_bytes = ((info_t *)tdata)->page_length + TRACE_SIZE(info_t);

	/* If the chunk is the sync chunk then clear the sync_chunk
	 * field as we've returned the data up to the sync point.
	 * How do we know that sync_chunk isn't being set to the 
	 * current chunk from a later sync call? Because for that
	 * to happen, the tdata chunk would have to be the current
	 * write chunk, and that can't be the case because we hold
	 * the chunk lock.
	 */
	local_irq_save(flags);
	real_spin_lock(&tb->chunk_interlock);

	if (tb->sync_chunk == tdata) 
		tb->sync_chunk = NULL;

	buffer_release(tb);

	real_spin_unlock(&tb->chunk_interlock);
	local_irq_restore(flags);

	DECREMENT_READER_CNT;

	/* The page_length in the full chunk case is fixed up when
	 * the trace path switches to a new chunk, so nothing
	 * special needed here.
	 */

	return(valid_bytes);
	
}

STATIC const struct file_operations cpu_buf_fops = {
	.read = cpu_buf_read,
	.open = cpu_buf_open,
	.release = cpu_buf_release,
	.owner = THIS_MODULE,
};


/* debugfs interface to the sync mechanism
 *
 * The sync mechanism here is an approximation.  It is needed because
 * it may take a long time on lesser active CPUs to fill a whole chunk,
 * and some userspace apps are impatient to receive whatever data we
 * have as of right now. This mechanism makes a best-effort attempt at
 * providing that.
 *
 * Following a sync we will return data that includes (and maybe 
 * exceeds) the trace data available up to the point in time the sync
 * was executed.
 * 
 * There are two usage models for this: either issues a sync for CPU_ALL
 * in which case every CPU returns with data up to (and possibly beyond)
 * the point in time at which the sync occurred, or just for a specific
 * CPU. It is anticipated that the former will be used after disabling
 * tracing at the end of a collection run to flush out data in partially
 * filled chunks, while the former will be used by realtime merging
 * when the merge process needs data from a lesser active CPU in order
 * to proceed with the merge.
 */
STATIC ssize_t 
liki_sync_write(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *off)
{
	struct task_struct	*tgt;
	int			target_cpu;
	int			cpu;
	unsigned long 		flags;

	if (count != sizeof(target_cpu))
		return (-EINVAL);

	if (copy_from_user(&target_cpu, ubuf, sizeof(target_cpu)))
		return (-EFAULT);

	if (target_cpu != ALL_CPUS && target_cpu != OTHER_CPUS &&
	    (target_cpu >= nr_cpu_ids || tbufs[target_cpu].buffer == NULL))
		return (-EINVAL);


	/* The sync works by recording the current write chunk in
	 * the tbuf as the "sync_chunk" and then prodding the
	 * reader if it is asleep. The reader will see the 
	 * sync_chunk and ignore that the writer hasn't yet 
	 * finished writing this chunk, and return what data is
	 * available in the chunk right away.
	 *
	 * Note that I don't check that there isn't already a sync
	 * underway - I just update sync_chunk to reflect the most
	 * recently asked for sync location.
	 */
	if (target_cpu == ALL_CPUS || target_cpu == OTHER_CPUS) {

		for (cpu=0; cpu<nr_cpu_ids; cpu++) {

			/* Only do this for online CPUs! */
			if (tbufs[cpu].buffer) {

				if (target_cpu == OTHER_CPUS && 
			            cpu == raw_smp_processor_id())
					continue;

				local_irq_save(flags);
				real_spin_lock(&tbufs[cpu].chunk_interlock);
	
				tbufs[cpu].sync_chunk = (char *)tbufs[cpu].alloc_chunk;
	
				if ((tgt = (struct task_struct *)tbufs[cpu].waiting_reader) != NULL) {
					tbufs[cpu].waiting_reader = NULL;
					wake_up_process(tgt);
				}
	
				real_spin_unlock(&tbufs[cpu].chunk_interlock);
				local_irq_restore(flags);
			}
		}

	} else {

		local_irq_save(flags);
		real_spin_lock(&tbufs[target_cpu].chunk_interlock);

		tbufs[target_cpu].sync_chunk = (char *)tbufs[target_cpu].alloc_chunk;

		if ((tgt = (struct task_struct *)tbufs[target_cpu].waiting_reader) != NULL) {
			tbufs[target_cpu].waiting_reader = NULL;
			wake_up_process(tgt);
		}

		real_spin_unlock(&tbufs[target_cpu].chunk_interlock);
		local_irq_restore(flags);
	}

	return (sizeof(target_cpu));
}


STATIC const struct file_operations liki_sync_fops = {
	.open = liki_dummy_open,
	.write = liki_sync_write,
	.owner = THIS_MODULE,
};


STATIC ssize_t 
liki_ignored_syscalls32_write(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *off)
{
	long	syscallno;

	if (count != sizeof(long))
		return (-EINVAL);

	if (copy_from_user(&syscallno, ubuf, sizeof(long)))
		return (-EFAULT);

	if (syscallno > NR_syscalls)
		return(-EINVAL);

	if (syscallno < -1)
		return(-EINVAL);

	mutex_lock(&state_mutex);

	if (syscallno == -1) {
		memset(ignored_syscalls32, 0, NR_syscalls);
		enabled_features &= ~SYSCALL32_FILTERING;
		mutex_unlock(&state_mutex);
		return(sizeof(long));
	}

	ignored_syscalls32[syscallno] = 1;
	enabled_features |= SYSCALL32_FILTERING;
	mutex_unlock(&state_mutex);

	return(sizeof(long));
}


STATIC const struct file_operations liki_ignored_syscalls32_fops = {
	.open = liki_dummy_open,
	.write = liki_ignored_syscalls32_write,
	.owner = THIS_MODULE,
};


STATIC ssize_t 
liki_ignored_syscalls64_write(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *off)
{
	long	syscallno;

	if (count != sizeof(long))
		return (-EINVAL);

	if (copy_from_user(&syscallno, ubuf, sizeof(long)))
		return (-EFAULT);

	if (syscallno > NR_syscalls)
		return(-EINVAL);

	if (syscallno < -1)
		return(-EINVAL);

	mutex_lock(&state_mutex);

	if (syscallno == -1) {
		memset(ignored_syscalls64, 0, NR_syscalls);
		mutex_unlock(&state_mutex);
		enabled_features &= ~SYSCALL64_FILTERING;
		return(sizeof(long));
	}

	ignored_syscalls64[syscallno] = 1;
	enabled_features |= SYSCALL64_FILTERING;
	mutex_unlock(&state_mutex);

	return(sizeof(long));
}


STATIC const struct file_operations liki_ignored_syscalls64_fops = {
	.open = liki_dummy_open,
	.write = liki_ignored_syscalls64_write,
	.owner = THIS_MODULE,
};



/* Table to keep track of the tracepoints. Fields are:
 * 	tp	Pointer to kernel tracepoint structure for this tracepoint
 * 	name	Tracepoint symbolic name
 * 	func	Pointer to the LiKI probe function
 *
 * The NULLs exist because not every LiKI trace type is implemented as a 
 * linux tracepoint.
 */
struct tp_struct tp_table[TT_NUM_PROBES] = {
	{NULL, NULL, NULL},
	{NULL, "sched_switch", sched_switch_trace},
	{NULL, "sched_wakeup", sched_wakeup_trace},
	{NULL, "block_rq_insert", block_rq_insert_trace},
	{NULL, "block_rq_issue", block_rq_issue_trace},
	{NULL, "block_rq_complete", block_rq_complete_trace},
	{NULL, NULL, NULL},
	{NULL, "block_rq_requeue", block_rq_requeue_trace},
	{NULL, NULL, NULL},
	{NULL, "sys_enter", syscall_enter_trace},
	{NULL, "sys_exit", syscall_exit_trace},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	{NULL, "cpu_idle", cpu_idle_trace},
	{NULL, NULL, NULL},
	{NULL, "cpu_frequency", cpu_freq_trace},
#else
	{NULL, "power_start", power_start_trace},
	{NULL, "power_end", power_end_trace},
	{NULL, "power_frequency", power_freq_trace},
#endif
	{NULL, "sched_migrate_task", sched_migrate_task_trace},
	{NULL, "irq_handler_entry", irq_handler_entry_trace},
	{NULL, "irq_handler_exit", irq_handler_exit_trace},
	{NULL, "softirq_entry", softirq_entry_trace},
	{NULL, "softirq_exit", softirq_exit_trace},
	{NULL, "softirq_raise", softirq_raise_trace},
	{NULL, "scsi_dispatch_cmd_start", scsi_dispatch_cmd_start_trace},
	{NULL, "scsi_dispatch_cmd_done", scsi_dispatch_cmd_done_trace},
	{NULL, NULL, NULL},
	{NULL, NULL, NULL},
	{NULL, NULL, NULL},
	{NULL, NULL, NULL},
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	{NULL, "mm_filemap_fault", mm_filemap_fault_trace},
#else
	{NULL, NULL, NULL},
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	{NULL, "workqueue_insertion", workqueue_enqueue_trace},
	{NULL, "workqueue_execution", workqueue_execute_trace},
#else
	{NULL, "workqueue_queue_work", workqueue_enqueue_trace},
	{NULL, "workqueue_execute_start", workqueue_execute_trace},
#endif
	{NULL, NULL, NULL},	/* tasklet is done with probes */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	{NULL, "mm_filemap_add_to_page_cache", page_cache_insert_trace},
	{NULL, "mm_filemap_delete_from_page_cache", page_cache_evict_trace},
#else
	{NULL, NULL, NULL},	/* inserts and evicts used to be done with probes */
	{NULL, NULL, NULL},
#endif
	{NULL, "mm_page_alloc", mm_page_alloc_trace},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
	{NULL, "mm_page_free", mm_page_free_trace},
#else 
	{NULL, "mm_page_free_direct", mm_page_free_trace},
#endif
	{NULL, "sched_process_exit", exit_hook},
	{NULL, "sched_process_fork", fork_hook}
};


/* debugfs interface to read and modify the set of installed traces
 */
STATIC int
change_installed_traces(unsigned long requested_traces)
{
	unsigned long	new_installed_traces = 0;
	int 		i, err;

	/* Turn off tracing while we adjust the installed traces. Don't want odd
	 * selections of traces dribbling in at the start and end of the trace.
	 */
	tracing_state = TRACING_DISABLED;	/* REVISIT: Memory fence here? */


	/* De-install ALL traces; start with a clean slate. The tracepoints are 
	 * quite strightforward and neat, but things get a little less elegant
	 * when we come to probes implemented using jprobes and timer hooks.
	 */
	for (i = 1; i < TT_NUM_USER_PROBES; i++) {
		if (TRACE_ENABLED_IN(i, installed_traces))
			liki_probe_unregister(i);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0) 

/* jprobes are obsolete in 4.15 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	if (TRACE_ENABLED_IN(TT_HARDCLOCK, installed_traces))
		unregister_jprobe(&jphc);
#else
	if (TRACE_ENABLED_IN(TT_HARDCLOCK, installed_traces))
		unregister_timer_hook((int (*)(struct pt_regs *))hardclock_trace);
#endif

#endif


	/* Have readers block while we change the set of installed traces */
	installed_traces = TT_BITMASK_READS_BLOCK;


	/* Now one-by-one run through and install the selected 
	 * traces.
	 */
	for (i = 1; i < TT_NUM_USER_PROBES; i++) {
		if (TRACE_ENABLED_IN(i, requested_traces)) {
			if (liki_probe_register(i)) {
       				printk(KERN_WARNING "LiKI: could not enable %s trace\n", tp_table[i].name);
			} else
				new_installed_traces |= (TT_BIT(i));
		}
	}

	if (TRACE_ENABLED_IN(TT_HARDCLOCK, requested_traces)) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) 
/* jprobes are obsolet in 4.15.   So use the timer list instead */

		if (startup_timer_list() != 0) {
			printk(KERN_WARNING "LiKI: failed to create timer_list entries. Hardclock traces disabled\n");
		}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)

		memset(&jphc, 0, sizeof(struct jprobe));
	        jphc.entry = (kprobe_opcode_t *)hardclock_jprobe;
		jphc.kp.symbol_name = "profile_tick";

		if (register_jprobe(&jphc) < 0) {
			printk(KERN_WARNING "LiKI: could not enable hardclock jprobe - Attempting Kernel Timers\n");
			if (startup_timer_list() != 0) {
				printk(KERN_WARNING "LiKI: failed to create timer_list entries. Hardclock traces disabled\n");
			}
		} else
			new_installed_traces |= (TT_BIT(TT_HARDCLOCK));
#else
		if (register_timer_hook((int (*)(struct pt_regs *))hardclock_trace) != 0) {
			printk(KERN_WARNING "LiKI: could not enable hardclock trace - Attempting Kernel Timers\n");
			if (startup_timer_list() != 0) {
				printk(KERN_WARNING "LiKI: failed to create timer_list entries\n");
			}
		} else
			new_installed_traces |= (TT_BIT(TT_HARDCLOCK));
#endif
	}

	if (requested_traces & TT_BITMASK_READS_BLOCK)
		new_installed_traces |= (TT_BITMASK_READS_BLOCK);

	installed_traces = new_installed_traces;


	/* If the new set of installed traces is not TT_NO_TRACES then
	 * enable tracing.
	 */
	if ((new_installed_traces != TT_BITMASK_NO_TRACES) && 
	    (new_installed_traces != TT_BITMASK_READS_BLOCK)) {

		/* Before tracing is turned on write out a
		 * wall time record.
		 */
		startup_trace();

		if (traced_resource_count > 0) 
			tracing_state = TRACING_RESOURCES;
		else 
			tracing_state = TRACING_GLOBAL;

	}

	for (i=1, err=0; i<TT_NUM_USER_PROBES; i++)
		if (TRACE_ENABLED_IN(i, requested_traces) && 
		    !TRACE_ENABLED_IN(i, new_installed_traces)) {
			printk(KERN_WARNING "LiKI: Couldn't enable trace number %d\n", i);
			err++;
		}

	if (err) {

#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: tracemask wanted: %lx tracemask achieved: %lx\n",
			requested_traces, new_installed_traces);
#endif
		return (-EIO);

	} else
		return (0);
}


STATIC ssize_t 
liki_get_et(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{

	if (count < sizeof(unsigned long))
		return (-EINVAL);

	if (copy_to_user(ubuf, (const void *)&installed_traces, sizeof(unsigned long)))
		return (-EFAULT);

	return (sizeof(unsigned long));
}


STATIC ssize_t 
liki_set_et(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *off)
{
	unsigned long		new_et;
	int			ret;

	if (count != sizeof(unsigned long))
		return(-EINVAL);

	if (copy_from_user(&new_et, ubuf, sizeof(unsigned long)))
		return(-EFAULT);

	/* Need to ensure we don't have two folks fiddling with enabled
	 * traces at the same time, or someone in shutdown while we're
	 * fiddling with enabled traces etc.
	 */
	mutex_lock(&state_mutex);
	ret = change_installed_traces(new_et);
	mutex_unlock(&state_mutex);

	if (ret == 0)
        	return (sizeof(long long));
	else
		return (ret);
}


STATIC const struct file_operations liki_et_fops = {
	.open = liki_dummy_open,
	.read = liki_get_et,
	.write = liki_set_et,
	.owner = THIS_MODULE,
};


STATIC int
task_tracing_op(unsigned long id, int op)
{
	int	ret;

	switch (op) {

	case ADD_RESOURCE:
	
		if ((ret=enable_tracing_for_resource((unsigned long)id)) < 0)
			return(ret);

#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: added %p to traced resources\n", (void *)id);
#endif
		return(0);

	case REMOVE_RESOURCE:

		if ((ret=disable_tracing_for_resource((unsigned long)id)) < 0)
			return(ret);

#ifdef __LIKI_DEBUG
		printk(KERN_WARNING "LiKI: removed %p from traced resources\n", (void *)id);
#endif
		return(0);

	}

	return(-EINVAL);
}


STATIC ssize_t 
liki_modify_traced_resources(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *off)
{
	resource_op_t		rop;
	int			ret=0;

	if (count != sizeof(resource_op_t))
		return(-EINVAL);

	if (copy_from_user(&rop, ubuf, count)) 
		return(-EFAULT);

	if ((rop.op & VALID_ROP) == 0)
		return(-EINVAL);

	mutex_lock(&state_mutex);

	/* The RESET_RESOURCES and REENABLE_GLOBAL cases are special... */
	if (rop.op == RESET_RESOURCES) {

		reset_traced_resources();
		mutex_unlock(&state_mutex);
		return(count);
	}

	if (rop.op == REENABLE_GLOBAL) {

		tracing_state = TRACING_GLOBAL;
		reset_traced_resources();
		mutex_unlock(&state_mutex);

		return(count);
	}

	switch(rop.type) {

#ifdef CONFIG_X86_64
	case MSR_DATA:

        {
		if (msr_cpu_list) { 
                	if ( rop.op == ADD_RESOURCE ) {
                        	enabled_features |= MSR_FEATURE;
				on_each_cpu(enable_msr, NULL, 1);
                	} else {
                        	enabled_features &= ~MSR_FEATURE;
				on_each_cpu(disable_msr, NULL, 1);
                	}
		}
                break;
        }
#endif

	case TASKID:

	{ 
		ret = task_tracing_op(PID_RESOURCE(rop.id), rop.op);

		if (ret == 0) {
			enabled_features |= TASK_FILTERING;
			tracing_state = TRACING_RESOURCES;
		}

		break;
	}

	case TASKGID:

	{
		ret = task_tracing_op(TGID_RESOURCE(rop.id), rop.op);

		if (ret == 0) {
			enabled_features |= TASKGROUP_FILTERING;
			tracing_state = TRACING_RESOURCES;
		}

		break;
	}

	case CPUID:

	{
		ret = task_tracing_op(CPU_RESOURCE(rop.id), rop.op);

		if (ret == 0) {
			enabled_features |= CPU_FILTERING;
			tracing_state = TRACING_RESOURCES;
		}

		break;
	}

	case DEVICEID:

	{
		ret = task_tracing_op(DEVICE_RESOURCE(rop.id), rop.op);

		if (ret == 0) {
			enabled_features |= DEVICE_FILTERING;
			tracing_state = TRACING_RESOURCES;
		}

		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&state_mutex);

	return(ret==0 ? count : ret);
}


STATIC const struct file_operations liki_traced_resources_fops = {
	.open = liki_dummy_open,
	.write = liki_modify_traced_resources,
	.owner = THIS_MODULE,
};


STATIC int
create_debugfs_files(void)
{
	int 	cpu;
	char	fname[128];


	/*
	 * All our files will be in our own directory below the debugfs 
	 * root. Create that directory here.
	 */
	if ((debugdir = debugfs_create_dir(DEBUGFS_DIR_NAME, NULL)) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create debugfs directory\n");
		return(ENODEV);
	}

	/*
	 * Each active CPU needs a file. If allocation barfs then we need to 
	 * free everything we have allocated so far, and tear down any debugfs 
	 * files/dirs.
	 */
	for(cpu=0; cpu<nr_cpu_ids; cpu++) {

		if (tbufs[cpu].buffer) {

			sprintf(fname, "%s%d", DEBUGFS_BUFPREFIX_NAME, cpu);

			tbufs[cpu].file = debugfs_create_file(fname, 0400, debugdir, 
				&tbufs[cpu], &cpu_buf_fops);

			if (!tbufs[cpu].file) {
				printk(KERN_WARNING "LiKI: failed to create ringbuf file\n");
				goto create_debugfs_files_failed;
			}
		} 
	}


	/* Create the sync control file
	 */
 	if (debugfs_create_file(SYNC_FILE, 0200, debugdir, 0, &liki_sync_fops) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create sync file\n");
		goto create_debugfs_files_failed;
	}


	/* Create the file through which to tell LiKI which resources we
 	 * want to trace
 	 */
	if (debugfs_create_file(TRACED_RESOURCES_FILE, 0600, debugdir, 0, &liki_traced_resources_fops) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create traced_resources file\n");
		goto create_debugfs_files_failed;
	}


	/* Create the files through which to tell LiKI which syscalls we
 	 * want to ignore
 	 */
	if (debugfs_create_file(IGNORED_SYSCALLS32_FILE, 0600, debugdir, 0, &liki_ignored_syscalls32_fops) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create ignored_syscalls32 file\n");
		goto create_debugfs_files_failed;
	}

	if (debugfs_create_file(IGNORED_SYSCALLS64_FILE, 0600, debugdir, 0, &liki_ignored_syscalls64_fops) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create ignored_syscalls64 file\n");
		goto create_debugfs_files_failed;
	}


	/* Create a file that can be used by userspace tools to control 
	 * the set of running traces.
	 */
 	if (debugfs_create_file(TRACE_ENABLE_FILE, 0600, debugdir, 0, &liki_et_fops) == NULL) {
		printk(KERN_WARNING "LiKI: failed to create trace enable  file\n");
		goto create_debugfs_files_failed;
	}

	return(0);

create_debugfs_files_failed:


	/* Files will de deleted by caller */

	return(ENODEV);
}


/*
 * startup()
 * Allocate buffers for performance data, and setup access via debugfs.
 */

STATIC long
startup(void)
{

	if (startup_ring_buffer() != 0) {
		printk(KERN_WARNING "LiKI: failed to create ring buffers\n");
		return(1);
	}

	if (startup_traced_resource_table() != 0) {
		printk(KERN_WARNING "LiKI: failed to create traced resouce status slab\n");
		return(2);
	}
		
	memset(ignored_syscalls32, 0, NR_syscalls);
	memset(ignored_syscalls64, 0, NR_syscalls);

	if (create_debugfs_files() != 0) {
		printk(KERN_WARNING "LiKI: failed to create debugfs interface\n");
		return(3);
	}

#ifdef CONFIG_X86_64
	startup_msr();
#endif
	return(0);
}


STATIC void
shutdown(void)
{

	printk(KERN_INFO "LiKI: tracing shutting down...\n");

	mutex_lock(&state_mutex);
	shutdown_pending=TRUE;

	change_installed_traces(TT_BITMASK_NO_TRACES);
	synchronize_sched();

	if (timer_lists)
		shutdown_timer_lists();

	if (tbufs) 
		shutdown_ring_buffer();

#ifdef CONFIG_X86_64
	if (msr_cpu_list)
		shutdown_msr();
#endif
	if (vldtmp_cache)
		kmem_cache_destroy(vldtmp_cache);

	if (tr_cache) {
		free_traced_resources();
		kmem_cache_destroy(tr_cache);
	}

	if (debugdir)
		debugfs_remove_recursive(debugdir);

	restore_sles11_backtrace_state();

	/* Not going to release state_mutex here because the module is
	 * about to be unloaded, and I don't want anyone sneaking
	 * in and re-enabling traces.
	 */
	printk(KERN_INFO "LiKI: shut down successfully\n");
	mutex_unlock(&state_mutex);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
STATIC void
init_tp_entry(struct tracepoint *tp, void *priv) 
{
	int i;

	for (i=1; i<TT_NUM_PROBES; i++) {
		if (tp->name && tp_table[i].name && (strcmp(tp->name, tp_table[i].name) == 0)) { 
			tp_table[i].tp = tp;
			/* printk(KERN_INFO "LiKI: event %d - %s initialized\n", i, tp->name); */
		}
	}

	return;
} 
#endif

STATIC int
liki_initialize(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	int ret = 0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	int	i;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	printk(KERN_INFO "LiKI: unsupported kernel version\n");
	return(-EINVAL);
#else
	printk(KERN_INFO "LiKI: tracing starting up...\n");
#endif



/* REVISIT: state_mutex ? */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	for_each_kernel_tracepoint(init_tp_entry, NULL);

	for (i=1; i<TT_NUM_PROBES; i++) 
		if (tp_table[i].name && tp_table[i].tp==NULL)
			printk(KERN_WARNING "LiKI: event %s could not be initialized\n", tp_table[i].name);
#endif

	save_sles11_backtrace_state();

	/* I'm tired of having to re-code kernel functions that are not exported
	 * for module use, so instead I'll go find the address of those 
	 * un-exported functions and call them anyway.
	 */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
	if (ret < 0) return ret;

	ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
	if (ret < 0) { 
		unregister_kprobe(&kp0);
		return ret;
	}

	unregister_kprobe(&kp0);
	unregister_kprobe(&kp1);
#ifdef __LIKI_DEBUG
	printk(KERN_INFO "kallsyms_lookup_name address = 0x%lx\n", kln_addr);
#endif

	kallsyms_lookup_name_fp = (unsigned long (*)(const char *name)) kln_addr;

#ifdef __LIKI_DEBUG
  	printk(KERN_INFO "kallsyms_lookup_name address = 0x%lx\n", kallsyms_lookup_name_fp("kallsyms_lookup_name"));
#endif

#else
	kallsyms_lookup_name_fp = (unsigned long (*)(const char *name))kallsyms_lookup_name;
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	/* Nothing to do here as we will use sockfd_lookup() */
#elif defined CONFIG_PPC64
	if ((sockfd_lookup_light_fp = (void *)kallsyms_lookup_name_fp("sockfd_lookup")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find sockfd_lookup()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#else

        if ((sockfd_lookup_light_fp = (void *)kallsyms_lookup_name_fp("sockfd_lookup_light")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find sockfd_lookup_light()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	/* Nothing to do here as we will use stack_trace_save() */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) && (defined RHEL82)
	if ((stack_trace_save_regs_fp = (void *)kallsyms_lookup_name_fp("stack_trace_save_regs")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find stack_trace_save_regs()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
        if ((save_stack_trace_regs_fp = (void *)kallsyms_lookup_name_fp("save_stack_trace_regs")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find save_stack_trace_regs()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
	if ((copy_from_user_nmi_fp = (void *)kallsyms_lookup_name_fp("copy_from_user_nmi")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find copy_from_user_nmi()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	if ((vfs_fstat_fp = (void *)kallsyms_lookup_name_fp("vfs_fstat")) == 0) {
		printk(KERN_WARNING "LiKI: cannot find copy_from_user_nmi()\n");
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		return(-EINVAL);
	}
#else
	vfs_fstat_fp = (int (*)(int, struct kstat *))vfs_fstat;
#endif

	if (startup() != 0) {
		printk(KERN_WARNING "LiKI: tracing initialization failed\n");
		shutdown();
		return(-EINVAL);
	}

	printk(KERN_INFO "LiKI: tracing was set up successfully\n");
	return(0);
}


STATIC void
liki_exit(void)
{
	shutdown();
}

module_init(liki_initialize);
module_exit(liki_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("colin.honess@gmail.com");
MODULE_DESCRIPTION("LInux Kernel Instrumentation. Intended for use only under the guidance of HP.");
