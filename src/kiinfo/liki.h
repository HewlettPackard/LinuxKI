/* (C) Copyright 2015 Hewlett Packard Enterprise Development LP.
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
 */

#include <linux/perf_event.h>
#ifdef __KERNEL__
	#include <linux/socket.h>
#else
	#include <sys/socket.h>
#endif

#if __KERNEL__ 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
#define TIMESPEC timespec64
#else
#define TIMESPEC timespec
#endif
#else
#define TIMESPEC timespec
#endif

/* TRACE_VERSION should always be odd in LiKI. kiinfo uses the lowest order
 * bit to determine whether the trace data comes from LiKI or ftrace.
 */
#define TRACE_VERSION		9


/* Filenames */
#define DEBUGFS_DIR_NAME	"liki"
#define DEBUGFS_BUFPREFIX_NAME  "cpu"
#define BACKTRACE_THROTTLE_FILE	"backtrace_throttle"
#define IGNORED_SYSCALLS32_FILE	"ignored_syscalls32"
#define IGNORED_SYSCALLS64_FILE	"ignored_syscalls64"
#define TRACE_ENABLE_FILE	"enabled_traces"
#define	TRACED_RESOURCES_FILE	"traced_resources"
#define	SYNC_FILE		"sync"
#define DEFAULT_DATAFILE_NAME   "ki.bin"
#define FP_FILE_SUFFIX		"fp"


/* Some limits */
#define MAX_STACK_DEPTH		PERF_MAX_STACK_DEPTH
#define	LEGACY_STACK_DEPTH	16 /* V1 and 2 of LiKI */
#define END_STACK 		0xffffffffffffffffull
#define	MAX_VLDATA_LEN		1024
#define CHUNK_SIZE      	262144
#define TASK_COMM_LEN		16
#define IRQ_NAME_LEN		16
#define N_SYSCALL_ARGS		6
#define MAXCPUS 		2048
#define	MAX_FNAME_LEN		256

#define STACK_CONTEXT_USER	((unsigned long)(-512))
#define STACK_CONTEXT_KERNEL	((unsigned long)(-128))


/* Trace type signifiers. Each trace is represented by a bit in a
 * bitmask.
 */
#define TT_UNUSED			0
#define TT_SCHED_SWITCH			1
#define TT_SCHED_WAKEUP			2
#define TT_BLOCK_RQ_INSERT		3
#define TT_BLOCK_RQ_ISSUE		4
#define TT_BLOCK_RQ_COMPLETE		5
#define TT_BLOCK_RQ_ABORT		6		/* OBSOLETE */
#define TT_BLOCK_RQ_REQUEUE		7
#define TT_HARDCLOCK			8
#define TT_SYSCALL_ENTER		9		
#define TT_SYSCALL_EXIT			10
#define TT_POWER_START			11
#define TT_POWER_END			12
#define	TT_POWER_FREQ			13
#define	TT_SCHED_MIGRATE_TASK		14
#define TT_IRQ_HANDLER_ENTRY		15
#define TT_IRQ_HANDLER_EXIT		16
#define TT_SOFTIRQ_ENTRY		17
#define TT_SOFTIRQ_EXIT			18
#define TT_SOFTIRQ_RAISE		19
#define TT_SCSI_DISPATCH_CMD_START	20
#define TT_SCSI_DISPATCH_CMD_DONE	21
#define TT_LISTEN_OVERFLOW		22
#define	TT_WALLTIME			23
#define	TT_STARTUP			23	/* Enhances and replaces walltime */
#define	UNUSED1				24
#define	UNUSED2				25
#define TT_FILEMAP_FAULT		26
#define TT_WORKQUEUE_ENQUEUE		27
#define TT_WORKQUEUE_EXECUTE		28
#define TT_TASKLET_ENQUEUE		29
#define TT_CACHE_INSERT			30
#define TT_CACHE_EVICT			31
#define TT_MM_PAGE_ALLOC                32
#define TT_MM_PAGE_FREE			33

/* These aren't real probes. They are used internally to clean up
 * some traced resource related data etc. They should never be 
 * enabled as per a regular trace, and should always be last
 * in the list.
 */
#define TT_SCHED_PROCESS_EXIT		34
#define TT_SCHED_PROCESS_FORK		35

#define TT_NUM_PROBES			36
#define TT_NUM_USER_PROBES		34



/* Macros pertaining to which traces are enabled */
#define	TT_BIT(TYPE)			(1ULL << TYPE)
#define TRACE_ENABLED_IN(TYPE, SET)	(SET & TT_BIT(TYPE))

/* Pseudo trace type signifiers. These don't relate to an actual
 * trace, but do control some aspect of enabling/disabling traces.
 */
#define	TT_BITMASK_READS_BLOCK	0x8000000000000000ULL

/* Groups of trace signifiers for convenience  */
#define TT_BITMASK_NO_TRACES	0x0000000000000000ULL

#define	TT_BITMASK_DEFAULT_TRACES \
				(TT_BIT(TT_SCHED_SWITCH) | TT_BIT(TT_SCHED_WAKEUP) | \
				 TT_BIT(TT_BLOCK_RQ_INSERT) | TT_BIT(TT_BLOCK_RQ_ISSUE) | \
				 TT_BIT(TT_BLOCK_RQ_COMPLETE) | TT_BIT(TT_BLOCK_RQ_REQUEUE) | \
				 TT_BIT(TT_SYSCALL_ENTER) | TT_BIT(TT_SYSCALL_EXIT) | \
				 TT_BIT(TT_HARDCLOCK) | TT_BIT(TT_POWER_FREQ) | \
				 TT_BIT(TT_SOFTIRQ_ENTRY) | TT_BIT(TT_SOFTIRQ_EXIT) | \
				 TT_BIT(TT_IRQ_HANDLER_ENTRY) | TT_BIT(TT_IRQ_HANDLER_EXIT))


/* The listen overflow trace is expensive and can be called VERY 
 * frequently. You're going to have to specifically ask for that one!
 */
#define TT_BITMASK_ALL_TRACES	(0x0fffffffffffffffULL & ~(TT_BIT(TT_LISTEN_OVERFLOW)) & \
				 ~(TT_BIT(TT_SCHED_PROCESS_EXIT)) & ~(TT_BIT(TT_SCHED_PROCESS_FORK)))

/* Mode identifiers */
#define	USER_MODE		-1
#define PREEMPT_VAL(val)        (val & PREEMPT_MASK)
#define SOFTIRQ_VAL(val)        ((val & SOFTIRQ_MASK) >> SOFTIRQ_SHIFT)
#define HARDIRQ_VAL(val)        ((val & HARDIRQ_MASK) >> HARDIRQ_SHIFT)
#define NMI_BIT(val)            ((val & NMI_MASK) >> NMI_SHIFT)


/* When debugging it is really helpful to have easily recognisable
 * values embedded in the start of each trace record. These are
 * not wanted in production trace data.
 */
#ifdef __LIKI_DEBUG
#define START_OF_RECORD_MARKER 	unsigned long marker;
#define	START_MARKER_VALUE		0xccccccccccccccccULL
#define	END_MARKER_VALUE		0x2222222222222222ULL
#else
#define START_OF_RECORD_MARKER
#endif


/* Every trace records starts with a common set of fields */
#define COMMON_FIELDS					\
	START_OF_RECORD_MARKER				\
	unsigned long	hrtime;				\
	unsigned int	id;	/* trace type */	\
	unsigned int	reclen;	/* length of trace */ 	\
	int		pid;				\
	int		cpu;				\
	unsigned long	cpu_seqno;			\
	int		tgid;				\
	int		spare;


typedef struct common_fields {
	COMMON_FIELDS;
} common_t;


/* info_trace is a special trace that appears at the start of each 
 * chunk. Think of it as a chunk header.
 */
typedef struct info_trace {
	unsigned long	hrtime;		/* monotonic absolute time */
	unsigned int	page_length; 	/* CHUNK_SIZE for liki */
	unsigned int	version;
	unsigned long	sync_time;	/* time of sync snapshot */
} info_t;


/* wall time trace is provided exactly once whenever tracing is
 * enabled - meaning when the tracemask changes from "no traces"
 * to "some traces". In the context of streaming to disk this 
 * will result in one record at the start of one of the per-CPU
 * trace files that occurs earlier than any other trace. In the
 * context of real-time tracing it will result in a record each
 * time tracing is re-enabled.
 */

typedef struct walltime_trace {
	COMMON_FIELDS;
	struct TIMESPEC	walltime;
} walltime_t;

/* The startup_trace record supercedes the walltime trace, extending
 * it to provide information about the parameters of the collection.
 *
 * Feature flags denoting which (if any) filtering is applied
 * at collection time.
 */
#define	TASK_FILTERING			0x1UL
#define	TASKGROUP_FILTERING		0x2UL
#define	DEVICE_FILTERING		0x4UL
#define	CPU_FILTERING			0x8UL
#define FAMILY_FILTERING		0x10UL
#define	SYSCALL32_FILTERING		0x20UL
#define	SYSCALL64_FILTERING		0x40UL
#define MSR_FEATURE			0x80UL

#define NUM_MSR_STATS 7 

#define MSRSZ  sizeof(unsigned long)*NUM_MSR_STATS

typedef struct startup_trace {
	COMMON_FIELDS;
	struct TIMESPEC	walltime;
	unsigned long	tracemask;
	unsigned long	enabled_features;
} startup_t;

	
/* Now the real traces... */

typedef struct sched_switch_trace {
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
	unsigned long	stealtime;
	unsigned long	stack_depth;
	unsigned long	ips[];
} sched_switch_t;


typedef struct sched_wakeup_trace {
	COMMON_FIELDS;
	pid_t		target_pid;
	int		target_pri;
	int		target_cpu;
	int		success;
} sched_wakeup_t;

typedef struct sched_migrate_task_trace {
	COMMON_FIELDS;
	pid_t		target_pid;
	int		target_pri;
	int		orig_cpu;;
	int		dest_cpu;
	unsigned long	stack_depth;
	unsigned long	ips[];
} sched_migrate_task_t;
	

typedef struct block_rq_insert_trace {
	COMMON_FIELDS;
	dev_t		dev; 
	unsigned long	sector;
	unsigned long	cmd_flags;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_insert_t;


typedef struct block_rq_issue_trace {
	COMMON_FIELDS;
	dev_t		dev;
	unsigned long	sector;
	unsigned long	cmd_flags;
	unsigned long	start_time_ns;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_issue_t;


typedef struct block_rq_complete_trace {
	COMMON_FIELDS;
	dev_t		dev;
	unsigned long	sector;
	unsigned long 	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	unsigned int	nr_sectors;
	unsigned int	bytes;
	unsigned int	cmd_type;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_complete_t;


/* this is obsolete, but keeping for now */
typedef struct block_rq_abort_trace {
	COMMON_FIELDS;
	dev_t		dev;
	unsigned long	sector;
	unsigned long	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_abort_t;


typedef struct block_rq_requeue_trace {
	COMMON_FIELDS;
	dev_t		dev;
	unsigned long	sector;
	unsigned long 	cmd_flags;
	unsigned long	start_time_ns;
	unsigned long	io_start_time_ns;
	unsigned int	nr_sectors;
	unsigned int	errors;
	unsigned int	cmd_type;
	int		async_in_flight;
	int		sync_in_flight;
} block_rq_requeue_t;


typedef struct cache_insert_trace {
	COMMON_FIELDS;
	unsigned long	page;
	dev_t		dev;
	unsigned long	i_ino;
	unsigned long	index;
} cache_insert_t;


typedef struct cache_evict_trace {
	COMMON_FIELDS;
	unsigned long	page;
	dev_t		dev;
	unsigned long	i_ino;
	unsigned long	index;
	unsigned long	stack_depth;
	unsigned long	ips[];
} cache_evict_t;


typedef struct filemap_fault_trace {
	COMMON_FIELDS;
	unsigned long	vm_mm;
	unsigned long	virtual_address;
} filemap_fault_t;


typedef struct hardclock_trace {
	COMMON_FIELDS;
	int		preempt_count;
	int		filler;
	unsigned long	stack_depth;
	unsigned long	ips[];
} hardclock_t;

typedef struct power_start_trace {
	COMMON_FIELDS;
	unsigned long	type;
	unsigned long	state;
} power_start_t;


typedef struct power_end_trace {
	COMMON_FIELDS;
} power_end_t;


typedef struct power_freq_trace {
	COMMON_FIELDS;
	unsigned long	type;
	unsigned long 	freq;
	unsigned long	tgt_cpu;
} power_freq_t;


typedef struct irq_handler_entry_trace {
	COMMON_FIELDS;
	int		irq;
	char		name[IRQ_NAME_LEN];
} irq_handler_entry_t;


typedef struct irq_handler_exit_trace {
	COMMON_FIELDS;
	int		irq;
	int		ret;
} irq_handler_exit_t;


typedef struct softirq_entry_trace {
	COMMON_FIELDS;
	int		vec;
} softirq_entry_t;


typedef struct softirq_exit_trace {
	COMMON_FIELDS;
	int		vec;
} softirq_exit_t;


typedef struct softirq_raise_trace {
	COMMON_FIELDS;
	int		vec;
	char		name[IRQ_NAME_LEN];
} softirq_raise_t;


typedef struct tasklet_enqueue_trace {
	COMMON_FIELDS;
	unsigned long	hi;
	void *		funcp;
	unsigned long	arg;
} tasklet_enqueue_t;


#ifndef WQ_NAM_LEN
#define WQ_NAM_LEN	24
#endif

typedef struct workqueue_enqueue_trace {
	COMMON_FIELDS;
	void *		funcp;
	int		tgt_cpu;
} workqueue_enqueue_t;


typedef struct workqueue_execute_trace {
	COMMON_FIELDS;
	void *		funcp;
} workqueue_execute_t;


typedef struct scsi_dispatch_cmd_start_trace {
	COMMON_FIELDS;
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
} scsi_dispatch_cmd_start_t;


typedef struct scsi_dispatch_cmd_done_trace {
	COMMON_FIELDS;
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
} scsi_dispatch_cmd_done_t;


typedef struct listen_overflow_trace {
	COMMON_FIELDS;
	unsigned long	sock_flags;
} listen_overflow_t;


/* Some system calls have useful data that is pointed to by an argument.
 * The tracing becomes much richer if we go capture that useful data and
 * embed it in the trace. Because this useful data varies by syscall type
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
 *
 * io_submit()
 *   Here we want info about the IOs submitted. The iocbs structure
 *   passed in from usersace is a bit of an overkill, therefore we
 *   pull out just the interesting fields into a struct iocbsum.
 *   There may be many of these following the syscall)enter record;
 *   use the reclen to figure out how many (I don't promise you'll
 *   get the number specified in the second syscall parameter).
 */

typedef struct iocbsum {
	struct iocb 	*iocbp;
	short unsigned 	aio_lio_opcode; /* see IOCB_CMD_ above */
	short		aio_reqprio;
	unsigned int	aio_fildes;
	long int	aio_offset;
	unsigned long	aio_nbytes;
} iocbsum_t;

typedef struct syscall_enter_trace {
	COMMON_FIELDS;
	int		syscallno;
	int		is32bit;
	long		args[N_SYSCALL_ARGS];
	/* Variable length data goes here. Keep it aligned on a long word boundary. */
} syscall_enter_t;


/* Much as we want some data passed into a syscall to be recorded
 * in the trace data, sometimes we want data returned from a 
 * syscall to be recorded. This is appended after the syscall_exit
 * record as above.
 *
 * The syscall_exit appendages we have are:
 *
 * io_getevents()
 *   The struct io_event structures returned by io_getevents() are
 *   appended.
 */

typedef struct syscall_exit_trace {
	COMMON_FIELDS;
	int		syscallno;
	int		is32bit;
	long		ret;
} syscall_exit_t;

/* for KMEM events */

typedef struct mm_page_alloc_trace {
	COMMON_FIELDS;
	unsigned long	page;
	unsigned int	order;
	unsigned int	flags;
	unsigned int	migratetype;
	int		filler;
	unsigned long	stack_depth;
	unsigned long	ips[];
} mm_page_alloc_t;

typedef struct mm_page_free_trace {
	COMMON_FIELDS;
	unsigned long	page;
	unsigned int	order; 
	int		filler;
	unsigned long	stack_depth;
	unsigned long	ips[];
} mm_page_free_t;


/* For socket-related data-moving system calls we place the endpoint 
 * addresses into an appendage of type sockaddr_storage_t. For reads
 * and writes of regular files we append the following type which
 * mimicks the format of the socket address in that the first entry
 * denotes the type of address, and define a new address type for
 * regular files.
 */
#define	AF_REGFILE	(65535) 	/* was USHRT_MAX, but that did not compile on RHEL 6.1 */

typedef struct  {
	sa_family_t 	ss_family;
	unsigned long 	i_ino;
	dev_t		dev;
} fileaddr_t;


/* Workload fingerprinting trace types */
typedef struct fp_switch_trace {
	COMMON_FIELDS;
#ifdef INCLUDE_SYSCALLS
	int		syscallno;
	int		is32bit;
	long		args[N_SYSCALL_ARGS];
#endif
	pid_t		next_pid;
	long		prev_state;
	unsigned long	stack_depth;
	unsigned long	ips[];
} fp_switch_t;


typedef struct fp_hardclock_trace {
	COMMON_FIELDS;
	int		preempt_count;
	int		syscallno;
	int		is32bit;
	long		args[N_SYSCALL_ARGS];
	unsigned long	stack_depth;
	unsigned long	ips[];
} fp_hardclock_t;


/* Traces must be aligned on an 8-byte boundary so we can put two 
 * longs at the beginning. Rather than aligining the trace within 
 * an unaligned space the caller always rounds up the allocated 
 * size to be a multiple of the align size, so the next record is 
 * always correctly aligned.
 */
#define ALIGN_SIZE		8ULL
#define	ALIGN_MASK		(ALIGN_SIZE - 1)
#define	TRACE_ROUNDUP(X)	((X & ALIGN_MASK) ? ((X + ALIGN_SIZE) & ~ALIGN_MASK) : X)
#define TRACE_SIZE(TYPE) 	TRACE_ROUNDUP(sizeof(TYPE))


/* The timestamp in each trace is in the first word regardless of
 * trace type.
 */
#define TIMESTAMP(F)    	(((common_t *)F)->hrtime)


/* Some useful defines */
#define END_OF_DATA(X) 		(X + ((info_t *)X)->page_length + TRACE_SIZE(info_t))
#define IS_INFO_REC(X)  	(X->next_r == X->read_chunk)
#define IS_SYNC_CHUNK(X)	(((info_t *)(X))->sync_time)
#define	BYTES_IN_CHUNK(X)	(((info_t *)(X))->page_length + TRACE_SIZE(info_t))
#define	TRUE			1
#define FALSE			0
#define	ALL_CPUS		(-1)
#define OTHER_CPUS		(-2)


/* Operation types for the op field below for task-based tracing. Note these are
 * bits, permitting a quick single-op check for a valid operation type
 */
#define	ADD_RESOURCE		1
#define	REMOVE_RESOURCE		2
#define REENABLE_GLOBAL		3
#define RESET_RESOURCES		4
#define VALID_ROP		(ADD_RESOURCE | REMOVE_RESOURCE | RESET_RESOURCES)

enum resource_type {
	TASKID,
	TASKGID,
	CPUID,
	DEVICEID,
	TASKFAMILY,
	MSR_DATA
};

typedef struct {
	unsigned long		id;
	enum resource_type	type;
	int			op;
} resource_op_t;


/* Merge parameters passed in by the application to likiif
 * merge functions
 */
typedef struct {
	ssize_t 	(*read_func)(int, void *);
	int		num_sources;
	int		*src_data;
} merge_params_t;


/* Function prototypes for likiif.c
 */
int 		liki_init(char *);
int 		liki_open_ringbuf(int *);
int 		liki_close_ringbuf(int);
int 		liki_set_backtrace_throttling(unsigned long);
int 		liki_set_tracemask(unsigned long);
unsigned long 	liki_get_tracemask(void);
int 		liki_sync(int);
int 		liki_ignore_syscall32(long);
int 		liki_ignore_syscall64(long);
int 		liki_enable_tracing_for_task(pid_t);
int 		liki_disable_tracing_for_task(pid_t);
int 		liki_enable_tracing_for_task_group(pid_t);
int 		liki_disable_tracing_for_task_group(pid_t);
/* There is no disable_tracing for task_family. Use 
 * liki_reset_traced_resources() or
 * liki_reenable_global_tracing()
 */
int 		liki_enable_tracing_for_device(dev_t);
int 		liki_disable_tracing_for_device(dev_t);
int 		liki_enable_tracing_for_cpu(int);
int 		liki_disable_tracing_for_cpu(int);
int 		liki_reenable_global_tracing(void);
int 		liki_reset_traced_resources(void);
int 		liki_begin_merge(merge_params_t *);
void 		liki_end_merge(void);
int 		liki_next_merged_chunk(char *);
int		liki_trace_count(int, unsigned long *, unsigned long *, unsigned long *);
int		liki_validate_chunk(char *, char *, unsigned long *, unsigned long *, unsigned long *, unsigned long *);

#ifdef __LIKI_RTMERGE
#define 	LIKI_SYNC_INTERVAL	200000000UL	/* ns */

int 		liki_open_live_stream(void);
void 		liki_close_live_stream(void);
void 		liki_set_end_of_sample(unsigned long interval);
int 		liki_next_live_chunk(char *);
#endif

/* MSR register access allows us to grab PMU counters
 * to determine real-time turbo-boost clock speeds, say
 * every hardclock tick.
 * It also allows us to grab other cache miss, CPI
 * metrics at every sched_switch record.
 */

#define MSR_VEC_LIMIT 32

/*
 * Reference for MSR register definition and opcodes come from:
 * Intel 64 and IA-32 Architectures
 * Software Developer.s Manual
 * Combined Volumes: 1, 2A, 2B, 2C, 3A, 3B, 3C and 3D
 *
 * http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-325462.pdf
 *
 * See Volume 3B sections 18.2.1 - 18.2.4  "Architectual Performance Monitoring", and section 19.1
 */


/*
 * MSR register addresses
 */

#define MSR_PERF_GLBL_CTRL      0x38f
#define MSR_PERF_FIXED_CTRL     0x38d

#define MSR_PERFEVTSEL0         0x186
#define MSR_PERFEVTSEL1         0x187
#define MSR_PERFEVTSEL2         0x188
#define MSR_PERFEVTSEL3         0x189

#define MSR_PMC0                0xc1 // Register addrs for the 4 gen. purpose progamable registers
#define MSR_PMC1                0xc2
#define MSR_PMC2                0xc3
#define MSR_PMC3                0xc4
#define MSR_INSTR_RET           0x309
#define MSR_CLK_NOHALT_CORE     0x30a
#define MSR_FIXED_CLKFREQ       0xe7
#define MSR_ACTUAL_CLKFREQ      0xe8
#define MSR_SMI_CNT             0x34

enum MsrOperation {
    MSR_NOP   = 0,
    MSR_READ  = 1,
    MSR_WRITE = 2,
    MSR_STOP  = 3,
    MSR_RDTSC = 4
};

struct MsrList {
    unsigned int op;              // MsrOperation
    unsigned int ecx;             // msr identifier
    unsigned int eax;             // low double word
    unsigned int edx;             // high double word
    unsigned long value;          // quad word
};
