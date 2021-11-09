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

/*   MACRO definitions	*/

#define IS_FTRACE (globals->kiversion == 0)
#define IS_LIKI	((globals->kiversion != 0xffffffff) && (globals->kiversion & 1))  /* if last bit is set, then trace is from liki module */
#define IS_LIKI_V1 (globals->kiversion==1)
#define IS_LIKI_V2 (globals->kiversion==3)
#define IS_LIKI_V3 (globals->kiversion==5)
#define IS_LIKI_V4 (globals->kiversion==7)
#define IS_LIKI_V5 (globals->kiversion==9)
#define IS_LIKI_V1_PLUS (IS_LIKI && globals->kiversion >= 1)
#define IS_LIKI_V2_PLUS (IS_LIKI && globals->kiversion >= 3)
#define IS_LIKI_V3_PLUS (IS_LIKI && globals->kiversion >= 5)
#define IS_LIKI_V4_PLUS (IS_LIKI && globals->kiversion >= 7)
#define IS_LIKI_V5_PLUS (IS_LIKI && globals->kiversion >= 9)

#define WINKI_V1 0x10000
#define WINKI_V2 0x20000
#define IS_WINKI ((globals->kiversion != 0xffffffff) && (globals->kiversion & 0xffff0000))  /* if last bit is set, then trace is from liki module */
#define IS_WINKI_V1  (globals->kiversion == WINKI_V1 )
#define IS_WINKI_V2  (globals->kiversion == WINKI_V2 )
#define IS_WINKI_V1_PLUS (IS_WINKI && globals->kiversion >= WINKI_V1)
#define IS_WINKI_V2_PLUS (IS_WINKI && globals->kiversion >= WINKI_V2)

#define STEAL_ON (IS_LIKI_V4_PLUS && globals->VM_guest)

#define SET_TRACEMASK						\
{								\
	int i;							\
        tracemask = 0;						\
        for (i = 1; i < LIKI_MAXTRACECALLS; i++) {		\
                if (ki_actions[i].execute) {			\
                        tracemask |= TT_BIT(i);			\
                }						\
        }							\
}

#define SET_EXECUTE_BITS(tracemask)				\
{								\
	int i;							\
	for (i = 1; i < LIKI_MAXTRACECALLS; i++) {		\
		if (tracemask & TT_BIT(i)) {			\
			ki_actions[i].execute = 1;		\
		} else { 					\
			ki_actions[i].execute = 0;		\
		}						\
	}							\
}

#define SET_KIACTION_EXECUTE(index, value)				\
	if (index) ki_actions[index].execute = value;

#define SET_KIACTION_FUNCTION(index, value)				\
	if (index) ki_actions[index].func = value;

#ifdef MALLOC_DEBUG
#define FREE(ptr) 						\
	if (ptr) {						\
		fprintf (stderr, "%s():%d [%s] - %p free\n",   \
			__func__,__LINE__,__FILE__, ptr);	\
		fflush(stderr);				\
		free(ptr);					\
	}
#else
#define FREE(ptr) 						\
	if (ptr) {						\
		free(ptr);					\
	}
#endif

#ifdef MALLOC_DEBUG						
#define CALLOC_LOG(ptr, nmemb, size)				\
	fprintf (stderr, "%s():%d [%s] - %p calloc(%d,%d)\n",   \
			__func__,__LINE__,__FILE__, ptr, 	\
			nmemb, size);				
#else
#define CALLOC_LOG(ptr,nmemb,size)
#endif
	
#ifdef MALLOC_DEBUG						
#define MALLOC_LOG(ptr, size)					\
	fprintf (stderr, "%s():%d [%s] - %p malloc(%d)\n",	\
			__func__,__LINE__,__FILE__, ptr, 	\
			size);					
#else
#define MALLOC_LOG(ptr,size)
#endif

#define MAX_REC_LEN (MAX_VLDATA_LEN + 2048) 

/* used for global flags */
#define SET(flag) (kiinfo_flags |= flag)
#define CLEAR(flag) (kiinfo_flags &= ~flag)
#define ISSET(flag) (kiinfo_flags & flag)
#define CLEAR_FLAG 	(kiinfo_flags = 0);
#define INIT_FLAG() (kiinfo_flags = 0ull);

/* flags used by kipid reporting */
#define SCHED_FLAG		0x1ull
#define DSK_FLAG		0x2ull
#define SCALL_FLAG		0x4ull
#define SORT_FLAG		0x8ull
#define FILE_FLAG		0x10ull
#define HC_FLAG			0x20ull
#define MEMORY_FLAG		0x40ull
#define SCDETAIL_FLAG		0x80ull
#define	FUTEX_FLAG		0x100ull
#define SOCK_FLAG		0x200ull

/* other flags passed to kiinfo subtools */
/* #define SYMLOOKUP_FLAG		0x400ull */
#define SYMDETAIL_FLAG 		0x800ull
#define ITIME_FLAG		0x1000ull
#define CSV_FLAG		0x2000ull
#define PIDTREE_FLAG		0x4000ull
#define KPTREE_FLAG		0x8000ull
#define VIS_FLAG		0x10000ull
#define KPARSE_FLAG		0x20000ull
#define SYSARGS_FLAG            0x40000ull
#define SYSENTER_FLAG		0x80000ull
#define ABSTIME_FLAG		0x100000ull
#define SEQCNT_FLAG		0x200000ull
#define NOMAPPER_FLAG		0x400000ull
#define NOMARKER_FLAG		0x800000ull
#define PRINTCMD_FLAG		0x1000000ull
#define PRINTMB_FLAG            0x2000000ull
#define DSK_DETAIL_FLAG		0x4000000ull
#define KPARSE_FULL_FLAG	0x8000000ull
#define ORACLE_FLAG		0x10000000ull
#define DSK_NODEV_FLAG		0x20000000ull
#define DSK_MPATH_FLAG		0x40000000ull
#define KITRACEDUMP_FLAG	0x80000000ull
#define LIKIDUMP_FLAG		0x100000000ull
#define LIKIMERGE_FLAG		0x200000000ull
#define AVAILABLE_FLAG		0x400000000ull
#define OBJDUMP_FLAG		0x800000000ull
#define CLUSTER_FLAG		0x1000000000ull
#define CLTREE_FLAG		0x2000000000ull
#define KIALL_FLAG		0x4000000000ull
#define FMTTIME_FLAG		0x8000000000ull
#define CACHE_FLAG		0x10000000000ull
#define MANGLE_FLAG		0x20000000000ull
#define INFO_FLAG               0x40000000000ull
#define KITRACE_FLAG            0x80000000000ull
#define FILTER_FLAG		0x100000000000ull
#define EPOCH_FLAG		0x200000000000ull
#define RUNQ_HISTOGRAM		0x400000000000ull
#define HT_DBDI_HISTOGRAM	0x800000000000ull
#define COOP_DETAIL_ENABLED	0x1000000000000ull
#define MSR_FLAG		0x2000000000000ull
#define DOCKTREE_FLAG		0x4000000000000ull
#define ETLDUMP_FLAG		0x8000000000000ull

#define SET_STAT(flag) (kiinfo_stats |= flag)
#define CLEAR_STAT(flag) (kiinfo_stats &= ~flag)
#define ISSET_STAT(flag) (kiinfo_stats & flag)
#define CLEAR_STATS	(kiinfo_stats = 0);
#define INIT_STATS() (kiinfo_stats = 0ull);

#define GLOBAL_STATS		0x1ull
#define PERPID_STATS		0x2ull
#define PERCPU_STATS		0x4ull
#define PERIRQ_STATS		0x8ull
#define PERTRC_STATS		0x10ull
#define STKTRC_STATS		0x20ull
#define PERDSK_STATS		0x40ull
#define SCALL_STATS		0x80ull
#define HT_STATS		0x100ull
#define COOP_STATS		0x200ull
#define DSKBLK_STATS		0x400ull
#define PERFD_STATS		0x800ull
#define POWER_STATS		0x1000ull
#define SLEEP_STATS		0x2000ull
#define FUTEX_STATS		0x4000ull
#define IDLE_STATS		0x8000ull

#define sort_flag		(ISSET(SORT_FLAG))
#define sched_flag		(ISSET(SCHED_FLAG))
#define dsk_flag		(ISSET(DSK_FLAG))
#define scall_flag		(ISSET(SCALL_FLAG))
#define scdetail_flag		(ISSET(SCDETAIL_FLAG))
#define futex_flag		(ISSET(FUTEX_FLAG))
#define hc_flag			(ISSET(HC_FLAG))
#define memory_flag		(ISSET(MEMORY_FLAG))
#define file_flag		(ISSET(FILE_FLAG))
#define pgcache_flag		(ISSET(CACHE_FLAG))
#define sock_flag		(ISSET(SOCK_FLAG))
#define symdetail_flag		(ISSET(SYMDETAIL_FLAG))
#define csv_flag		(ISSET(CSV_FLAG))
#define vis			(ISSET(VIS_FLAG))
#define kptree			(ISSET(KPTREE_FLAG))
#define pidtree			(ISSET(PIDTREE_FLAG))
#define docktree		(ISSET(DOCKTREE_FLAG))
#define itime_flag		(ISSET(ITIME_FLAG))
#define sysenter_flag		(ISSET(SYSENTER_FLAG))
#define sysargs_flag		(ISSET(SYSARGS_FLAG))
#define abstime_flag		(ISSET(ABSTIME_FLAG))
#define fmttime_flag		(ISSET(FMTTIME_FLAG))
#define epoch_flag		(ISSET(EPOCH_FLAG))
#define seqcnt_flag		(ISSET(SEQCNT_FLAG))
#define nomapper_flag		(ISSET(NOMAPPER_FLAG))
#define nomarker_flag		(ISSET(NOMARKER_FLAG))
#define printcmd_flag		(ISSET(PRINTCMD_FLAG))
#define printmb_flag		(ISSET(PRINTMB_FLAG))
#define kparse_flag		(ISSET(KPARSE_FLAG))
#define kitracedump_flag	(ISSET(KITRACEDUMP_FLAG))
#define etldump_flag		(ISSET(ETLDUMP_FLAG))
#define likidump_flag		(ISSET(LIKIDUMP_FLAG))
#define likimerge_flag		(ISSET(LIKIMERGE_FLAG))
#define objdump_flag		(ISSET(OBJDUMP_FLAG))
#define dsk_detail_flag		(ISSET(DSK_DETAIL_FLAG))
#define dsk_nodev_flag		(ISSET(DSK_NODEV_FLAG))
#define dsk_mpath_flag		(ISSET(DSK_MPATH_FLAG))
#define kparse_full		(ISSET(KPARSE_FULL_FLAG))
#define oracle			(ISSET(ORACLE_FLAG))
#define runq_histogram		(ISSET(RUNQ_HISTOGRAM))
#define HT_DBDI_histogram	(ISSET(HT_DBDI_HISTOGRAM))
#define coop_detail_enabled	(ISSET(COOP_DETAIL_ENABLED))
#define cluster_flag		(ISSET(CLUSTER_FLAG))
#define cltree			(ISSET(CLTREE_FLAG))
#define	kiall_flag		(ISSET(KIALL_FLAG))
#define mangle_flag		(ISSET(MANGLE_FLAG))
#define info_flag		(ISSET(INFO_FLAG))
#define kitrace_flag		(ISSET(KITRACE_FLAG))
#define filter_flag		(ISSET(FILTER_FLAG))
#define msr_flag		(ISSET(MSR_FLAG))

#define global_stats		(ISSET_STAT(GLOBAL_STATS))
#define perpid_stats		(ISSET_STAT(PERPID_STATS))
#define percpu_stats		(ISSET_STAT(PERCPU_STATS))
#define perdsk_stats		(ISSET_STAT(PERDSK_STATS))
#define perirq_stats		(ISSET_STAT(PERIRQ_STATS))
#define pertrc_stats		(ISSET_STAT(PERTRC_STATS))
#define perfd_stats		(ISSET_STAT(PERFD_STATS))
#define scall_stats		(ISSET_STAT(SCALL_STATS))
#define stktrc_stats		(ISSET_STAT(STKTRC_STATS))
#define ht_stats		(ISSET_STAT(HT_STATS))
#define coop_stats		(ISSET_STAT(COOP_STATS))
#define dskblk_stats		(ISSET_STAT(DSKBLK_STATS))
#define power_stats		(ISSET_STAT(POWER_STATS))
#define sleep_stats		(ISSET_STAT(SLEEP_STATS))
#define futex_stats		(ISSET_STAT(FUTEX_STATS))
#define idle_stats		(ISSET_STAT(IDLE_STATS))

#define MAX_SERVERS 1024
#define MAXCPUS 2048
#define MAXLDOMS 128
#define MAXARGS 6
#define MAX_SAVE_STACK_DEPTH 16

#define KB 1024ull
#define MB 1024*1024ull
#define GB 1024*1024*1024ull
#define TB 1024*1024*1024*1024ull

#define MAXSYSCALLS 656
#define MAX_SYSCALL_IDX 1080
#define TMP_SASIZE 50
#define PID_SASIZE 1000
#define IS_ERR_VALUE(x)  ((signed long)x >= -4095 && (signed long)x < 0)
#define UNKNOWN_SYMIDX 0xffffffffffffffffull
#define DUMMY_SYSCALL 9999

#define MAX_MAJORS      256
#define MAX_INSTANCES   256
#define MAX_TARGETS     16
#define MAX_LUNS        16
#define LPSORT_SIZE     1024
#define MAX_SCSI_OPCODE 256

#define MAPPER_MAJOR    mapper_major
#define NODEV_MAJOR	0xffull
#define NO_DEV		(dev_t)-13
#define NO_HBA		((uint64)-1)
#define NO_WWN		((uint64)0)
#define NO_DOCKID	((uint64)-1)

#define MP_ROUND_ROBIN	1
#define MP_QUEUE_LENGTH	2
#define MP_SERVICE_TIME	3

#define PREEMPT_USER    0xffffffff
#define PREEMPT_MASK	0x000000ff
#define SOFTIRQ_MASK    0x0000ff00
#define HARDIRQ_MASK    0x03ff0000
#define NMI_MASK	0x04000000

#define SOFTIRQ_SHIFT   8
#define HARDIRQ_SHIFT 	16
#define NMI_SHIFT	26

#define TASKID_NODE	1
#define SOCKET_NODE	2
#define RUNQ_NODE	4
#define ICS_TIMER_NODE	8
#define DISK_NODE	16
#define LOCK_NODE	32

#define PREEMPT_VAL(val)	(val & PREEMPT_MASK)
#define SOFTIRQ_VAL(val)	((val & SOFTIRQ_MASK) >> SOFTIRQ_SHIFT)
#define HARDIRQ_VAL(val)	((val & HARDIRQ_MASK) >> HARDIRQ_SHIFT)
#define NMI_BIT(val)		((val & NMI_MASK) >> NMI_SHIFT)
#define NCSTATES	11	/* number of cstates */
#define CSTATE_BUSY	10

#define HC_USER		0
#define HC_SYS		1
#define HC_IDLE		2
#define HC_INTR		3
#define HC_STATES	4

#define SCA_UNKNOWN	0
#define SCA_MITIGATED	1
#define SCA_VULNERABLE	2

#define STACK_CONTEXT(pc)   ((pc == STACK_CONTEXT_USER) || (pc == STACK_CONTEXT_KERNEL))
#define WINKERN_ADDR(pc)    ((pc & 0xfffff80000000000) == 0xfffff80000000000)

#define END_STACK 0xffffffffffffffffull
#define NULL_STACK 0ull
#define USER_STACK(sym)	(sym == END_STACK)
#define VALID_STACK(sym)	(sym != END_STACK &&			\
            			 sym != NULL_STACK)

#define MAJOR_MASK      0xfff00000ull
#define LUN_MASK	0x000fffffull
#define MAJOR_SHIFT     20

#define RELTIME 0		/* calulate time relative to the start of trace */
#define ABSTIME 1		/* calculate time relative to the start of the syscall */
#define CHECK_TIME_FILTER(hrtime) if (((hrtime - start_time) < start_filter) || ((hrtime - start_time) > end_filter)) return NULL;
#define FILTER_START_TIME ( is_alive ? (interval_start_time + start_filter) : (start_time + start_filter))

#define CHECK_VINT_INTERVAL(hrtime)     if (((hrtime - interval_end)/1000000.0) >= (vint * 1.0) ) { \
						interval_start =  interval_end;			\
						interval_end += (1000000 * vint);		\
					} else {						\
						return;						\
					}

#define PER_PASS 0              /* 1st dimension into stats[][] array */
#define TOTAL 1

#define ALL 0x7fffffff
#define NONE 0

#define X86_64		0
#define AARCH64		1
#define PPC64LE		2
#define MAXARCH		3

#define ELF32		0		
#define ELF64		1

#define IORD            0
#define IOWR            1       /* 2nd dimension into iostats[] array */
#define IOTOT           2

#define NBUCKETS	10
#define RUNQ_NBUCKETS   11
#define IDLE_TIME_NBUCKETS 16
#define RQLIST_SIZE 50

#define BIND_NONE	0 	/* pidp->binding */
#define BIND_LDOM	1

#define PCPU		0	/* cpuinfop->cpu_attr */
#define LCPU		1       

#define LCPU_UNKNOWN		0x0
#define LCPU_BUSY		0x1
#define LCPU_IDLE		0x2

#define ITIME_UNKNOWN         0       /* cpuinfo->state */
#define ITIME_IDLE            1       /* state for idle timiing analysis */
#define ITIME_BUSY            2
#define ITIME_BUFF_MISS       3

#define N_PTH_CLASS	4
#define PTH_CLASS_MUTEX		0
#define PTH_CLASS_CONDVAR	1
#define PTH_CLASS_SPINLOCK	2
#define PTH_CLASS_OTHER		3

/* ftypes */
#define F_UKN		0
#define F_REG		1
#define F_CHR		2
#define F_BLK		3
#define F_FIFO		4
#define F_DIR		5
#define F_sock		6
#define F_unix		7
#define F_IPv4		8
#define F_IPv6		9
#define F_netlink	10
#define F_anon		11
#define F_TYPES		12

/* ioflags array - for old 2.6.32 kernels and ftrace */
#define REQ_WRITE               0x00000001
#define REQ_FAILFAST_DEV        (1 << 1)
#define REQ_DISCARD             (1 << 4)
#define REQ_SOFTBARRIER         (1 << 6)
#define REQ_HARDBARRIER         (1 << 7)
#define REQ_FUA                 (1 << 8)
#define REQ_SYNC                (1 << 18)
#define REQ_META                (1 << 20)
#define REQ_FLUSH               (1 << 26)

#define REQ_NRBIT	32  /* should be 35, but need to expand the cmd_flags */
#define GFP_NRBIT	32  
#define IRQ_NRBIT	16

/* special node numbers for sockets */
#define TCP_NODE	1
#define UDP_NODE	2
#define UNKNOWN_NODE	7


/* winki thread wait reasons */
#define Executive		0
#define FreePage		1
#define PageIn			2
#define	PoolAllocation		3
#define DelayAllocation		4
#define Suspended		5
#define UserRequest		6
#define WrExecutive		7
#define WrFreePage		8
#define WrPageIn		9
#define WrPoolAllocation	10
#define WrDelayExecution	11
#define WrSuspended		12
#define WrUserRequest		13
#define WrEventPair		14
#define WrQueue			15
#define WrLpcReceive		16
#define WrLpcReply		17
#define WrVirtualMemory		18
#define WrPageOut		19
#define	WrRendezvous		20
#define WrKeyedEvent		21 
#define WrTerminated		22
#define WrProcessInSwap		23
#define WrCpuRateControl	24
#define WrCalloutStack		25
#define WrKernel		26
#define WrResource		27
#define WrPushLock		28
#define WrMutex			29
#define WrQuantumEnd		30
#define WrDispatchInt		31
#define WrPreempted		32
#define WrYieldExecution	33
#define WrFastMutex		34
#define WrGuardedMutex		35
#define WrRundown		36
#define WrAlertThreadId		37
#define WrDeferredPreempt	38
#define MaxThreadWaitReasons	39

/* Thread States */
#define Initialized		0
#define Ready			1
#define Running			2
#define Standby			3
#define Terminated		4
#define Waiting			5
#define Transition		6
#define DeferredReady		7
#define MaxThreadStates		10

#define MaxThreadWaitMode	2

#define dev_major(num)  ((num & MAJOR_MASK) >> MAJOR_SHIFT)
#define lun(num)        (num & LUN_MASK)
#define mkdev(major,minor)  ((major << MAJOR_SHIFT) | minor)

#define VG_INDEX(num)   ((num & VG_INDEX_MASK) >> VG_INDEX_SHIFT)
#define LV_INDEX(num)   ((num & LV_INDEX_MASK))

#define GET_SERVER(ptr)  (server_info_t *)find_add_info((void **)&ptr, sizeof(server_info_t))
#define GET_POWERP(ptr)  (power_info_t *)find_add_info((void **)&ptr, sizeof(power_info_t))
#define GET_HCINFOP(ptr)  (hc_info_t *)find_add_info((void **)&ptr, sizeof(hc_info_t))
#define GET_ADD_SCHEDP(addr)  (sched_info_t *)find_add_info((void **)addr, sizeof(sched_info_t))
#define GET_ADD_RQINFOP(addr)  (runq_info_t *)find_add_info((void **)addr, sizeof(runq_info_t))
#define GET_ADD_IRQINFOP(addr)  (irq_info_t *)find_add_info((void **)addr, sizeof(irq_info_t))
#define GET_ADD_SCALL_STATSP(addr) (syscall_stats_t *)find_add_info((void **)addr, sizeof(syscall_stats_t))
#define GET_IOV_STATSP(addr)	(iov_stats_t *)find_add_info((void **)addr, sizeof(iov_stats_t))

#define GET_DOCKERP(hashp, key) (docker_info_t *)find_add_hash_entry((lle_t ***)hashp, DOCKER_HASHSZ, key, DOCKER_HASH(key), sizeof(docker_info_t))
#define GET_DKPIDP(hashp, key)	(dkpid_info_t *)find_add_hash_entry((lle_t ***)hashp, PID_HASHSZ, key, PID_HASH(key), sizeof(dkpid_info_t))
#define GET_PIDP(hashp, key)	(pid_info_t *)find_add_hash_entry((lle_t ***)hashp, PID_HASHSZ, key, PID_HASH(key), sizeof(pid_info_t))
#define GET_CPUP(hashp, key)   (cpu_info_t *)find_add_hash_entry((lle_t ***)hashp, CPU_HASHSZ, key, CPU_HASH(key), sizeof(cpu_info_t))
#define GET_PCPUP(hashp, key)   (pcpu_info_t *)find_add_hash_entry((lle_t ***)hashp, CPU_HASHSZ, key, CPU_HASH(key), sizeof(pcpu_info_t))
#define GET_LDOMP(hashp, key)   (ldom_info_t *)find_add_hash_entry((lle_t ***)hashp, LDOM_HASHSZ, key, LDOM_HASH(key), sizeof(ldom_info_t))
#define GET_PCINFOP(hashp, key)  (pc_info_t *)find_add_hash_entry((lle_t ***)hashp, PC_HSIZE, key, PC_HASH(key), sizeof(pc_info_t))
#define GET_DEVP(hashp, key)  (dev_info_t *)find_add_hash_entry((lle_t ***)hashp, DEV_HSIZE, key, DEV_HASH(key), sizeof(dev_info_t))
#define GET_FCINFOP(hashp, key)  (fc_info_t *)find_add_hash_entry((lle_t ***)hashp, FC_HSIZE, key, FC_HASH(key), sizeof(fc_info_t))
#define GET_FCDEVP(hashp, key)  (fc_dev_t *)find_add_hash_entry((lle_t ***)hashp, DEV_HSIZE, key, DEV_HASH(key), sizeof(fc_dev_t))
#define GET_WWNINFOP(hashp, key)  (wwn_info_t *)find_add_hash_entry((lle_t ***)hashp, WWN_HSIZE, key, WWN_HASH(key), sizeof(wwn_info_t))
#define GET_WWNDEVP(hashp, key)  (wwn_dev_t *)find_add_hash_entry((lle_t ***)hashp, DEV_HSIZE, key, DEV_HASH(key), sizeof(wwn_dev_t))
#define GET_FDINFOP(hashp, key)  (fd_info_t *)find_add_hash_entry((lle_t ***)hashp, FD_HSIZE, key, FD_HASH(key), sizeof(fd_info_t))
#define GET_FDEVP(hashp, key)  (filedev_t *)find_add_hash_entry((lle_t ***)hashp, FDEV_HSIZE, key, FDEV_HASH(key), sizeof(filedev_t))
#define GET_FOBJP(hashp, key)  (fileobj_t *)find_add_hash_entry((lle_t ***)hashp, FOBJ_HSIZE, key, FOBJ_HASH(key), sizeof(fileobj_t))
#define GET_SYSCALLP(hashp, key)  (syscall_info_t *)find_add_hash_entry((lle_t ***)hashp, SYSCALL_HASHSZ, key, SYSCALL_HASH(key), sizeof(syscall_info_t))
#define GET_ADDR_TO_IDX_HASH_ENTRYP(hashp, key)  (addr_to_idx_hash_entry_t *)find_add_hash_entry((lle_t ***)hashp, ADDR_TO_IDX_HASHSZ, key, ADDR_TO_IDX_HASH(key), sizeof(addr_to_idx_hash_entry_t))
#define GET_SCDWINFOP(hashp, key)  (scd_waker_info_t *)find_add_hash_entry((lle_t ***)hashp, WPID_HSIZE, key, WPID_HASH(key), sizeof(scd_waker_info_t))
#define GET_SLPINFOP(hashp, key)  (slp_info_t *)find_add_hash_entry((lle_t ***)hashp, SLP_HSIZE, key, SLP_HASH(key), sizeof(slp_info_t))
#define GET_RQINFOP(hashp, key)  (runq_info_t *)find_add_hash_entry((lle_t ***)hashp, CPU_HASHSZ, key, CPU_HASH(key), sizeof(runq_info_t))
#define GET_SETRQP(hashp, key)  (setrq_info_t *)find_add_hash_entry((lle_t ***)hashp, WPID_HSIZE, key, WPID_HASH(key), sizeof(setrq_info_t))
#define GET_PGCACHEP(hashp, dev, node) (pgcache_t *)find_add_hash_entry((lle_t ***)hashp, PGCACHE_HASHSZ, PGCACHE_KEY(dev,node),		\
								PGCACHE_HASH(dev, node), sizeof(pgcache_t))
#define GET_FDATAP(hashp, dev, node) (fdata_info_t *)find_add_hash_entry((lle_t ***)hashp, 							\
								FDATA_HASHSZ, FDATA_KEY(dev,node), 						\
								FDATA_HASH(dev,node), sizeof(fdata_info_t))
#define GET_SDATAP(hashp, ip1, port1, ip2, port2) (sdata_info_t *)find_add_hash_entry2((lle2_t ***)hashp, 					\
								SDATA_HASHSZ, SOCK_KEY(ip1, port1), SOCK_KEY(ip2, port2),			\
								SDATA_HASH(ip1, port1, ip2, port2), sizeof(sdata_info_t))
#define GET_IPIPP(hashp, ip1, ip2) (ipip_info_t *)find_add_hash_entry2((lle2_t ***)hashp, 							\
								IPIP_HASHSZ, ip1, ip2,					\
								IPIP_HASH(ip1, ip2), sizeof(ipip_info_t))
#define GET_IPP(hashp, ip) (ip_info_t *)find_add_hash_entry((lle_t ***)hashp, 									\
								IP_HASHSZ, ip,									\
								IP_HASH(ip), sizeof(ip_info_t))
#define GET_SOCKP(hashp, ip, port) (sock_info_t *)find_add_hash_entry((lle_t ***)hashp, 							\
								SOCK_HASHSZ, SOCK_KEY(ip, port),						\
								SOCK_HASH(ip, port), sizeof(sock_info_t))
#define GET_TRCP(hashp, key) (trc_info_t *)find_add_hash_entry((lle_t ***)hashp, TRC_HASHSZ, key, TRC_HASH(key), sizeof(trc_info_t))
#define GET_IOREQP(hashp, key) (io_req_t *)find_add_hash_entry((lle_t ***)hashp, IOQ_HSIZE, key, IOQ_HASH(key), sizeof(io_req_t))
#define GET_CTX(hashp, key) (ctx_info_t *)find_add_hash_entry((lle_t ***)hashp, CTX_HSIZE, key, CTX_HASH(key), sizeof(ctx_info_t))
#define GET_IOCB(hashp, key) (iocb_info_t *)find_add_hash_entry((lle_t ***)hashp, IOCB_HSIZE, key, IOCB_HASH(key), sizeof(iocb_info_t))
#define GET_MPATHP(hashp, key) (mpath_info_t *)find_add_hash_entry((lle_t ***)hashp, MPATH_HSIZE, key, MPATH_HASH(key), sizeof(mpath_info_t))
#define GET_IRQENTRYP(hashp, key) (irq_entry_t *)find_add_hash_entry((lle_t ***)hashp, IRQ_HSIZE, key, IRQ_HASH(key), sizeof(irq_entry_t))	
#define GET_IRQNAMEP(hashp, key) (irq_name_t *)find_add_hash_entry((lle_t ***)hashp, IRQ_HSIZE, key, IRQ_HASH(key), sizeof(irq_name_t))
#define GET_ELFMAPP(hashp, key) (elfmap_info_t *)find_add_hash_entry((lle_t ***)hashp, ELFMAP_HSIZE, key, ELFMAP_HASH(key), sizeof(elfmap_info_t))
#define GET_COOP_SCALLP(hashp, key)  (coop_scall_t *)find_add_hash_entry((lle_t ***)hashp, SYSCALL_HASHSZ, key, SYSCALL_HASH(key), sizeof(coop_scall_t))
#define GET_COOP_SCALL_ARGSP(hashp, key)  (coop_scall_arg_t *)find_add_hash_entry((lle_t ***)hashp, ARGS_HSIZE, key, ARGS_HASH(key), sizeof(coop_scall_arg_t))
#define GET_COOP_SLPFUNCP(hashp, key) (coop_slpfunc_t *)find_add_hash_entry((lle_t ***)hashp, PC_HSIZE, key, PC_HASH(key), sizeof(coop_slpfunc_t))

#define GET_WTREEP(hashp, key) (wait_tree_nodes_t *)find_add_hash_entry((lle_t ***)hashp, WTREE_HSIZE, key, WTREE_HASH(key), sizeof(wait_tree_nodes_t))
#define GET_FUTEXP(hashp, key)   (pid_futex_info_t *)find_add_hash_entry((lle_t ***)hashp, FUTEX_HSIZE, key, FUTEX_HASH(key), sizeof(pid_futex_info_t))
#define GET_GFUTEXP(hashp, key)   (gbl_futex_info_t *)find_add_hash_entry((lle_t ***)hashp, GFUTEX_HSIZE, key, GFUTEX_HASH(key), sizeof(gbl_futex_info_t))
#define GET_FOPSP(hashp, key)  (futex_op_t *)find_add_hash_entry((lle_t ***)hashp, FUTEXOP_HSIZE, key, FUTEXOP_HASH(key), sizeof(futex_op_t))
#define GET_RQFUTEXP(hashp, key)  (futex_reque_t *)find_add_hash_entry((lle_t ***)hashp, FUTEX_HSIZE, key, FUTEX_HASH(key), sizeof(futex_reque_t))
#define GET_FUDUPP(hashp, key)  (futex_dup_t *)find_add_hash_entry((lle_t ***)hashp, FUTEX_HSIZE, key, FUTEX_HASH(key), sizeof(futex_dup_t))
#define GET_FPIDP(hashp, key) (futex_pids_t *)find_add_hash_entry((lle_t ***)hashp, FUTEXPID_HSIZE, key, FUTEXPID_HASH(key), sizeof(futex_pids_t))
#define GET_FRETP(hashp, key)  (futex_ret_t *)find_add_hash_entry((lle_t ***)hashp, FUTEXRET_HSIZE, key, FUTEXRET_HASH(key), sizeof(futex_ret_t))
#define GET_CLPIDP(hashp, server, pid)	(clpid_info_t *)find_add_hash_entry((lle_t ***)hashp, CLPID_HASHSZ, CLPID_KEY(server, pid), CLPID_HASH(server, pid), sizeof(clpid_info_t))
#define GET_CLFDATAP(hashp, server, dev, node) (clfdata_info_t *)find_add_hash_entry((lle_t ***)hashp, CLFDATA_HASHSZ, CLFDATA_KEY(server, dev, node), CLFDATA_HASH(server, dev, node), sizeof(clfdata_info_t))
#define GET_CLDEVP(hashp, server, dev)	(cldev_info_t *)find_add_hash_entry((lle_t ***)hashp, CLDEV_HSIZE, CLDEV_KEY(server, dev), CLDEV_HASH(server, dev), sizeof(cldev_info_t))
#define GET_CLFUTEXP(hashp, server, addr)   (clfutex_info_t *)find_add_hash_entry((lle_t ***)hashp, CLFUTEX_HASHSZ, CLFUTEX_KEY(server, addr), CLFUTEX_HASH(server, addr), sizeof(clfutex_info_t))
#define GET_CLIPIPP(hashp, ip1, ip2) (clipip_info_t *)find_add_hash_entry2((lle2_t ***)hashp, IPIP_HASHSZ, ip1, ip2, IPIP_HASH(ip1, ip2), sizeof(clipip_info_t))
#define GET_CLIPP(hashp, ip) (clip_info_t *)find_add_hash_entry((lle_t ***)hashp, IP_HASHSZ, ip, IP_HASH(ip), sizeof(clip_info_t))
#define GET_CLSDATAP(hashp, ip1, port1, ip2, port2) (clsdata_info_t *)find_add_hash_entry2((lle2_t ***)hashp, 					\
								SDATA_HASHSZ, SOCK_KEY(ip1, port1), SOCK_KEY(ip2, port2), 			\
								SDATA_HASH(ip1, port1, ip2, port2), sizeof(clsdata_info_t))

#define FIND_DOCKERP(hash, key) (docker_info_t *)find_entry((lle_t **)hash, key, DOCKER_HASH(key))
#define FIND_PIDP(hash, key)  (pid_info_t *)find_entry((lle_t **)hash, key, PID_HASH(key))
#define FIND_CPUP(hash, key)  (cpu_info_t *)find_entry((lle_t **)hash, key, CPU_HASH(key))
#define FIND_PCPUP(hash, key)  (pcpu_info_t *)find_entry((lle_t **)hash, key, CPU_HASH(key))
#define FIND_LDOMP(hash, key)  (ldom_info_t *)find_entry((lle_t **)hash, key, LDOM_HASH(key))
#define FIND_DEVP(hash, key)  (dev_info_t *)find_entry((lle_t **)hash, key, DEV_HASH(key))
#define FIND_FCINFOP(hash, key)  (fc_info_t *)find_entry((lle_t **)hash, key, FC_HASH(key))
#define FIND_WWNINFOP(hash, key)  (wwn_info_t *)find_entry((lle_t **)hash, key, WWN_HASH(key))
#define FIND_IOREQP(hash, key)  (io_req_t *)find_entry((lle_t **)hash, key, IOQ_HASH(key))
#define FIND_CTX(hashp, key) (ctx_info_t *)find_entry((lle_t **)hashp, key, CTX_HASH(key))
#define FIND_IOCB(hashp, key) (iocb_info_t *)find_entry((lle_t **)hashp, key, IOCB_HASH(key))
#define FIND_FDINFOP(hash, key)  (fd_info_t *)find_entry(lle_t **)hash, key, FD_HASH(key))
#define FIND_FDATAP(hash, dev, node)  (fdata_info_t *)find_entry((lle_t **)hash, FDATA_KEY(dev,node), FDATA_HASH(dev, node))
#define FIND_SDATAP(hash, ip1, port1, ip2, port2)  (sdata_info_t *)find_entry2((lle2_t **)hash, SOCK_KEY(ip1, port1), SOCK_KEY(ip2, port2), SDATA_HASH(ip1, port1, ip2, port2))
#define FIND_IRQENTRYP(hash, key) (irq_entry_t *)find_entry((lle_t **)hash, key, IRQ_HASH(key))
#define FIND_IRQNAMEP(hash, key)  (irq_name_t *)find_entry((lle_t **)hash, key, IRQ_HASH(key))
#define FIND_RQINFOP(hash, key)  (rq_info_t *)find_entry((lle_t **)hash, key, key)
#define FIND_ELFMAPP(hash, key) (elfmap_info_t *)find_entry((lle_t **)hash, key, ELFMAP_HASH(key))
#define FIND_CLIPP(hashp, ip) (clip_info_t *)find_entry((lle_t **)hashp, ip, IP_HASH(ip))
#define FIND_GFUTEXP(hashp, key)  (gbl_futex_info_t *)find_entry((lle_t **)hashp, key, GFUTEX_HASH(key))
#define FIND_FOBJP(hashp, key)  (fileobj_t *)find_entry((lle_t **)hashp, key, FOBJ_HASH(key))

#define FIND_AND_REMOVE_IOREQP(hashp, key)  (io_req_t *)find_remove_hash_entry((lle_t ***)hashp, IOQ_HSIZE, key, IOQ_HASH(key), sizeof(io_req_t))
#define FIND_AND_REMOVE_IOCB(hashp, key)  (iocb_info_t *)find_remove_hash_entry((lle_t ***)hashp, IOCB_HSIZE, key, IOCB_HASH(key), sizeof(iocb_info_t))
#define GET_ADD_VTXT(hashp, key)	(vtxt_preg_t *)add_entry_head((lle_t **)hashp, key, sizeof(vtxt_preg_t))

#define PRINT_DEVNAME(devinfop) 					\
		if (devinfop->devname) {				\
			printf ("%-10s", devinfop->devname);		\
		} else {						\
			printf ("0x%08x", devinfop->lle.key);		\
		}

#define PID lle.key
#define SYSCALLNO lle.key
#define TID lle.key
#define WAIT_PC lle.key
#define ID lle.key
#define THREAD_CNT cpu
#define F_TYPE(a) (a & 0xffff)
#define DEV(dev) (dev & 0xffffffff)

#define FSTYPE_HSIZE 0x10
#define FSTYPE_HASH(fstype) (int)(fstype & (FSTYPE_HSIZE-1))

#define FIND_REQP(hash, key) (futex_reque_t *)find_entry((lle_t **)hash, key, FUTEX_HASH(key))
#define FUTEX_KEY(tgid, uaddr) ((uaddr & 0xffffffffff) | ((uint64)tgid << 40))
#define FUTEX_TGID(key) ((key & 0xffffff0000000000) >> 40)
#define FUTEX_HSIZE 0x400
#define FUTEX_HASH(key)  ((key & (key >> 32)) % FUTEX_HSIZE)
#define GFUTEX_HSIZE 0x4000
#define GFUTEX_HASH(key)  ((key & (key >> 32)) % GFUTEX_HSIZE)
#define FUTEXOP_HSIZE 0x8
#define FUTEXOP_HASH(key) (key %  FUTEXOP_HSIZE)
#define FUTEXPID_HSIZE 0x40
#define FUTEXPID_HASH(key) (int)(key & (FUTEXPID_HSIZE-1))
#define FUTEXRET_HSIZE 0x10 
#define FUTEXRET_HASH(key) ((key & 0xff) %  FUTEXRET_HSIZE)

#define CLFUTEX_HASHSZ 0x100
#define CLFUTEX_HASH(server, addr)  ((server+addr) % CLFUTEX_HASHSZ)
#define CLFUTEX_KEY(server, addr)  ((uint64) server << 48 | addr & 0xffffffffffffull)
#define CLFUTEX_ADDR(key) (key & 0xffffffffffffull)
#define CLFUTEX_SERVER(key) (key >> 48)

#define IS_REQUEUE(op)  (((op & 0xf) == FUTEX_REQUEUE) || ((op & 0xf) == FUTEX_CMP_REQUEUE) || \
                         ((op & 0xf) == FUTEX_WAIT_REQUEUE_PI) || ((op & 0xf) == FUTEX_CMP_REQUEUE_PI))

#define WPID_HSIZE 0x20
#define WPID_HASH(key) (int)(key & (WPID_HSIZE-1))

#define WTREE_HSIZE 0x20
#define WTREE_HASH(key) (int)0
/* #define WTREE_HASH(key) (int)(key & (WTREE_HSIZE-1))  */


/*
**  How to enable stacktrace? Use obsolete bits in kc_kernelenable
**      KI_SWTCH_STK    : KI_RESUME_NCS         13 was obsolete
**      KI_SETRQ_STK    : KI_HARDCLOCK_IDLE     15 was obsolete
*/

#define NO_FD 0xffffffff

#define ELFMAP_HSIZE 0x100
#define ELFMAP_KEY(str) pathname_key(str)
#define ELFMAP_HASH(key) (key & (ELFMAP_HSIZE-1))

#define SYSERR_HSIZE 0x40
#define SYSERR_KEY(errno, syscallno)  (errno << 16 | syscallno)
#define SYSERR_SYSCALLNO(key) (key & 0xffff)
#define SYSERR_ERRNO(key) ((key >> 16) & 0xffff)
#define SYSERR_HASH(key)  ((SYSERR_SYSCALLNO(key) + SYSERR_ERRNO(key)) % SYSERR_HSIZE)

#define SLP_HSIZE 0x20
#define SLP_HASH(key)  ((key >> 9) & (SLP_HSIZE-1))

#define PDB_HSIZE 0x400
#define PDB_HASH(key) (key & (PDB_HSIZE-1))

#define STKTRC_HSIZE 0x1000
#define STKTRC_HASH(key)  (key & (STKTRC_HSIZE -1))

#define FD lle.key
#define FD_HSIZE 0x80
#define FD_HASH(fd) (fd & (FD_HSIZE-1))

#define FOBJ lle.key
#define FOBJ_HSIZE 0x1000
#define FOBJ_HASH(fobj) ((fobj << 10) & (FOBJ_HSIZE-1))

#define FDEV lle.key
#define FDEV_HSIZE 0x20
#define FDEV_HASH(fdev) ((fdev << 10) & (FDEV_HSIZE-1))

#define REG_HSIZE 0x20
#define REG_HMASK (REG_HSIZE - 1)
#define REG_HASH(key) ((key >> 17) & (REG_HSIZE-1))

/* used for devhash */
#define DEV_HSIZE 0x100
#define DEV_HASH(key)   (key % DEV_HSIZE)
#define DEVHASHP(PTR, DEV) (dev_major(DEV) == MAPPER_MAJOR ? &(PTR)->mdevhash : &(PTR)->devhash)
#define DEVHASH(PTR, DEV) (dev_major(DEV) == MAPPER_MAJOR ? (PTR)->mdevhash : (PTR)->devhash)
#define IOSTATSP(PTR, DEV, RW) (dev_major(DEV) == MAPPER_MAJOR ? &((PTR)->miostats[RW]) : &((PTR)->iostats[RW]))
#define IOSTATS(PTR, DEV, RW) (dev_major(DEV) == MAPPER_MAJOR ? ((PTR)->miostats[RW]) : ((PTR)->iostats[RW]))

/* used for cluster-wide devhash */
#define CLDEV_HSIZE	0x100
#define CLDEV_HASH(server, dev)  ((dev + server) % CLDEV_HSIZE)
#define CLDEV_KEY(server, dev)  ((uint64) server << 32 | dev & 0x7fffffff)
#define CLDEV_DEV(key) (dev & 0xffffffff)
#define CLDEV_SERVER(key) (dev >> 32)

#define CLDEVHASHP(DEV) (dev_major(DEV) == MAPPER_MAJOR ? &clmdev_hash : &cldev_hash)
#define CLDEVHASH(DEV) (dev_major(DEV) == MAPPER_MAJOR ? clmdev_hash : cldev_hash)

/* used for io request hash */
#define IOQ_HSIZE 0x80
#define IOQ_HASH(key)   ((key >> 2) % IOQ_HSIZE)

/* used for pvhash and insthash */
#define MPATH_HSIZE 0x8
#define MPATH_HASH(key)  (key % MPATH_HSIZE)

#define DSKBLK_HSIZE 65536
#define DSKBLK_KEY(device, blkno) ((dev << 32) | (blkno & 0xffffffff))
#define DSKBLK_DEV(key) (key >> 32)
#define DSKBLK_BLKNO(key) (key & 0xffffffff)
#define DSKBLK_HASH(key) ((key >> 1) % DSKBLK_HSIZE)

/* used for fchash */
#define FC_HSIZE 0x20
#define FCPATH(path1, path2, path3, path4)  (((path1+0ull) << 48) | ((path2+0ull) << 32) | ((path3+0ull) << 16) | path4)
#define FCPATH1(key) ((key >> 48) & 0xffff)
#define FCPATH2(key) ((key >> 32) & 0xffff)
#define FCPATH3(key) ((key >> 16) & 0xffff)
#define FCPATH4(key) (key & 0xffff)
#define DEVPATH_TO_FCPATH(path) (path != NO_HBA ? path & 0xffffffffffff0000ull : path)
#define FC_HASH(key)  (FCPATH1(key) % MPATH_HSIZE)

#define WWN_HSIZE 0x40
#define WWN_HASH(key)	((((key >> 48) & 0xffff) + ((key >> 32) & 0xffff) + ((key >> 16) & 0xffff) + (key & 0xffff)) % WWN_HSIZE)

#define PC_HSIZE 0x40
#define PC_HASH(key)  (((key >> 9) + (key & 0x3f)) % PC_HSIZE)

#define PTH_KEY(pid, pth_addr) ((pth_addr & 0xffffffff) | ((uint64)pid << 32))
#define PTH_PID(key) ((key & 0xffffffff00000000) >> 32)
#define PTH_HASHSZ 0x20
#define PTH_HASH(key)  (((key >> 9) & (key >> 32)) % PTH_HASHSZ)
#define PTHG_HASHSZ 0x100
#define PTHG_HASH(key)  (((key >> 9) & (key >> 32)) % PTHG_HASHSZ)

#define PID_HASHSZ 0x4000
#define PID_HASH(pid) ((((pid+1) + ((pid+1) << 10)) & 0x7fffffff) % PID_HASHSZ)

#define DOCKER_HASHSZ 0x100
#define DOCKER_HASH(id)  (id % DOCKER_HASHSZ)

/* for use with the cluster-wide pid_hash */
#define CLPID_HASHSZ 0x4000
#define CLPID_HASH(server, pid)  ((pid + server) % CLPID_HASHSZ)
#define CLPID_KEY(server, pid)  ((uint64) server << 32 | pid & 0x7fffffff)
#define CLPID_PID(key) (key & 0x7fffffff)
#define CLPID_SERVER(key) (key >> 32)

#define CPU_HASHSZ 0x200
#define CPU_HASH(cpu) ((cpu) % CPU_HASHSZ)

#define LDOM_HASHSZ 0x10
#define LDOM_HASH(ldom) ((ldom) % LDOM_HASHSZ)
 
#define RFSFUNC_HSIZE	0x40
#define RFSFUNC_MASK	(RFSFUNC_HSIZE - 1)
#define RFSFUNC_KEY(version,procnum)	((version << 8) | procnum)
#define RFSFUNC_HASH(key) 		(key & RFSFUNC_MASK)
#define RFSFUNC_VERSION(key)  (key >> 8)
#define RFSFUNC_PROCNUM(key)  (key & 0xff)

#define SID_TBLSZ 128 

#define FDATA_HASHSZ 0x400 
#define FDATA_KEY(dev,node) ((dev << 32) | node & 0xffffffff)
#define FDATA_HASH(dev,node) ((dev + node) % FDATA_HASHSZ)

#define PGCACHE_HASHSZ 0x40
#define PGCACHE_KEY(dev,node) ((dev << 32) | node & 0xffffffff)
#define PGCACHE_HASH(dev,node) ((dev + node) % PGCACHE_HASHSZ)

#define SIN_ADDR(sock) (sock->sin6_addr.s6_addr32[3]) 
#define SIN_PORT(sock) (sock->sin6_port)
#define SOCK_KEY(ip, port) (((0ull + ip) << 32) + port)
#define SOCK_IP(key)  (key >> 32) 
#define SOCK_IP4(key)	((key >> 56) & 0xff)
#define SOCK_IP3(key)	((key >> 48) & 0xff)
#define SOCK_IP2(key)	((key >> 40) & 0xff)
#define SOCK_IP1(key)	((key >> 32) & 0xff)
#define SOCK_PORT(key)  (key & 0xffffffff)
#define BE2LE(port)    ((port >> 8) + ((port & 0xff) << 8))

#define IP4(key)	((key >> 24) & 0xff)
#define IP3(key)	((key >> 16) & 0xff)
#define IP2(key)	((key >> 8) & 0xff)
#define IP1(key)	(key & 0xff)

#define SDATA_HASHSZ 0x400
#define SDATA_HASH(ip1, port1, ip2, port2)  ((ip1+port1+ip2+port2) % SDATA_HASHSZ)

#define IPIP_HASHSZ 0x100
#define IPIP_HASH(ip1, ip2) ((ip1+ip2) % IPIP_HASHSZ)

#define IP_HASHSZ	0x40
#define IP_HASH(key)	(key % IP_HASHSZ)

#define SOCK_HASHSZ	0x400
#define SOCK_HASH(ip, port) 	((IP1(ip) + IP2(ip) + IP3(ip) + IP4(ip) + port) % SOCK_HASHSZ) 

/* we may need to revisit this as it only supports..
 * 65536 servers, 256 major numbers, 4096 minor numbers, and inode numbers less than 16m 
 * There can at time be collisions, which could lead showing the wrong file.   But its all
 * I have at the moment.  
 */
#define CLFDATA_HASHSZ 0x1000
#define CLFDATA_KEY(server, dev, node)  ((uint64)server << 48 | ((uint64)dev_major(dev) & 0xff) << 40 | (uint64)(lun(dev) & 0xffff) << 24 | (uint64)node & 0xffffff)
#define CLFDATA_HASH(server, dev, node)  ((server+dev+node) % CLFDATA_HASHSZ)

#define VOLNAME_HASHSZ 0x400 
#define VOLNAME_HASH(dev) ((((dev & 0xff000000) >> 24) + ((dev & 0xff0000) >> 8) + (dev & 0xffff)) & (VOLNAME_HASHSZ - 1))

#define TRC_HASHSZ	MAXSYSCALLS
#define TRC_HASH(key)   ((TRC_SYSCALLNO(key) + TRC_FSTYPE(key) + TRC_ID(key) + (TRC_MODE(key) << 4)) % TRC_HASHSZ)
#define TRC_KEY(mode, fstype, id, syscallno)  (((uint64)mode << 60) | ((uint64)fstype << 52) | ((uint64)id << 16)  | syscallno) 
#define TRC_SYSCALLNO(key) (key & 0xffff)
#define TRC_ID(key) ((key >> 16) & 0xffff)
#define TRC_MODE(key) ((key >> 60) & 0xf) 
#define TRC_FSTYPE(key) ((key >> 52) & 0xf)

#define SYSCALL_HASHSZ	0x20
#define SYSCALL_HASH(key)  (key % SYSCALL_HASHSZ)
#define SYSCALL_KEY(mode, fstype, syscallno)  (((uint64)mode << 60) | ((uint64)fstype << 56) | syscallno) 
#define SYSCALL_NO(key) (key & 0xffff)
#define SYSCALL_MODE(key) ((key >> 60) & 0xf) 
#define SYSCALL_FSTYPE(key) ((key << 56) & 0xf)

#define ADDR_TO_IDX_HASHSZ 0x20
#define ADDR_TO_IDX_HASH(key)  ((key > 8) % ADDR_TO_IDX_HASHSZ)

#define NOSYS   0
#define OTHERFD 1
#define JFS     2
#define SOCKET  3
#define FIFO    4

#define DEVSTR_LEN      128

#define WAKER          0x0001
#define WOKEN          0x0002
#define SLEEPER        0x0002

#define MAX_THREAD_LIST 128 /* max number of woken threads we'll follow up within a single syscall by the waker */
#define SETRQ_HSIZE 0x40
#define ARGS_HSIZE  0x20
#define SEC_ARGS_HSIZE  0x20
#define ARGS_HMASK (ARGS_HSIZE - 1)
#define SEC_ARGS_HMASK (SEC_ARGS_HSIZE - 1)
#define ARGS_HASH(key)  (((key >> 8) ^ key) & ARGS_HMASK)
#define SEC_ARGS_HASH(key)  (((key >> 8) ^ key) & SEC_ARGS_HMASK)
#define WCH_HSIZE 0x40
#define WCH_HMASK (WCH_HSIZE - 1)
#define WCH_HASH(key) ((key >> 9) & WCH_HMASK)

#define IRQ_HSIZE 0x200
#define IRQ_HMASK (IRQ_HSIZE - 1)
#define IRQ_HASH(vec) (vec & IRQ_HMASK)

#define CTX_HSIZE 0x80
#define CTX_HMASK (CTX_HSIZE - 1)
#define CTX_HASH(key) ((key >> 13) & CTX_HMASK)

#define IOCB_HSIZE 0x40
#define IOCB_HMASK (IOCB_HSIZE - 1)
#define IOCB_HASH(key) ((key >> 4 ) & IOCB_HMASK)

#define PER_SYSCALL	1
#define UNKNOWN_SCALL MAXSYSCALLS  /* real syscalls are 0 thru MAXSYSCALLS-1, we used the next for unknown */
#define UNKNOWN_PID  0xfffffffdull    /* we need to use -3 to distinguish from -1 = ICS. */
#define ICS 0xfffffffffffffffful   /* With LIKI ICS = -1.  With ftrace it is 0 */

/* sched_stats.state */
/* for PID and CPU */
#define UNKNOWN	0x0
#define USER	0x01
#define SYS	0x02
#define RUNNING	0x4
#define RUNQ	0x08
#define IDLE	0x10
#define SWTCH	0x20
#define NEW	0x40
#define ZOMBIE	0x80
#define SOFTIRQ 0x100
#define HARDIRQ 0x200

#define RUNQ_IDLE  (RUNQ | IDLE)  

/* task states */
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_STOPPED		4
#define TASK_TRACED		8
#define EXIT_ZOMBIE		16
#define EXIT_DEAD               32
#define TASK_DEAD		64
#define TASK_WAKEKILL		128
#define TASK_WAKING		256

/* will be used to format arguments.   These are also indexs into the arg_actions
 * array.
 */
#define DECIMAL		0
#define HEX		1
#define OCTAL		2
#define SKIP		3
#define FUTEX_OP_ARG	4	
#define FCNTL_CMD	5	
#define MMAP_PROT	6	
#define MMAP_FLAGS	7
#define OFLAGS		8	
#define SOCK_DOM	9
#define SOCK_TYPE	10
#define SIGNAL		11
#define SIGHOW		12
#define WHENCE		13
#define IPC_CALL	14
#define FUTEX_VAL3	15
#define SEMCTL_CMD	16
#define MAXARG_ACTIONS 	17

#define NUM_RQHIST_BUCKETS 10
#define MAX_RQHIST_PROCS   256

/* macros for managing the Notes and Warnings messages and links.  */
/* update with warnmsg[] definitions in globals.c */
#define MAXWARNMSG		33	
#define MAXNOTEMSG		0
#define MAXNOTEWARN		MAXWARNMSG+MAXNOTEMSG
#define WARN_CPU_BOTTLENECK		0		
#define WARN_REREADS			1
#define WARN_BARRIER			2
#define WARN_SEMGET			3
#define WARN_REQUEUES			4
#define WARN_HIGH_AVSERV		5
#define WARN_HAS_JOURNAL		6
#define WARN_MIGRATE_PAGES		7
#define WARN_IXGBE_READ			8
#define WARN_NUMA_OFF			9
#define WARN_SEMLOCK			10
#define WARN_STEALTIME			11
#define WARN_IO_DELAYS			12
#define WARN_XFS_DIO_ALIGN		13
#define WARN_XFS_DIOREAD		14
#define WARN_TASKLET			15
#define WARN_POWER			16
#define WARN_MULTIPATH_BUG		17
#define WARN_SK_BUSY			18
#define WARN_ADD_RANDOM			19
#define WARN_MD_FLUSH			20
#define WARN_HUGETLB_FAULT		21
#define WARN_KSTAT_IRQS			22
#define WARN_ORACLE_POLL		23
#define WARN_PCC_CPUFREQ		24
#define WARN_SCA_VULN			25
#define WARN_TCP_TIMEOUTS		26
#define WARN_KVM_PAGEFAULT		27
#define WARN_SQL_STATS			28
#define WARN_ORACLE_COLSTATS		29
#define WARN_CACHE_BYPASS		30
#define WARN_MEM_IMBALANCE		31
#define WARN_NODE_LOWMEM		32
#define NOTE_NUM1		MAXWARNMSG+0

/* warn flags passed to "foreach" functions for detection */
#define WARNF_RETRIES			0x01ull 
#define WARNF_AVSERV			0x02ull
#define WARNF_BARRIER			0x04ull
#define WARNF_SEMGET			0x08ull
#define WARNF_REQUEUES			0x10ull
#define WARNF_HAS_JOURNAL		0x20ull
#define WARNF_MIGRATE_PAGES		0x40ull
#define WARNF_IXGBE_READ		0x80ull
#define WARNF_REREADS			0x100ull
#define WARNF_CPU_BOTTLENECK		0x200ull
#define WARNF_STEALTIME			0x400ull
#define WARNF_IO_DELAYS			0x800ull
#define WARNF_XFS_DIO_ALIGN		0x1000ull
#define WARNF_XFS_DIOREAD		0x2000ull
#define WARNF_TASKLET			0x4000ull
#define WARNF_POWER			0x8000ull
#define WARNF_MULTIPATH_BUG		0x10000ull
#define WARNF_ADD_RANDOM		0x20000ull
#define WARNF_MD_FLUSH			0x40000ull
#define WARNF_ORACLE_POLL		0x80000ull
#define WARNF_CACHE_BYPASS		0x100000ull
#define WARNF_MEM_IMBALANCE		0x200000ull
#define WARNF_NODE_LOWMEM		0x400000ull

/* warn flags specific to hardclocks warnflag */ 
#define WARNF_SEMLOCK			0x1ull
#define WARNF_SK_BUSY			0x2ull
#define WARNF_HUGETLB_FAULT		0x4ull
#define WARNF_KSTAT_IRQS		0x8ull
#define WARNF_PCC_CPUFREQ		0x10ull
#define WARNF_KVM_PAGEFAULT		0x20ull
#define WARNF_ORACLE_COLSTATS		0x40ull

/* warn flags specific to Windows */
#define WARNF_TCPTIMEOUTS		0x01ull 
#define WARNF_SQL_STATS			0x02ull 


typedef struct var_arg_struct {
        void *arg1;
        void *arg2;
	void *arg3;
} var_arg_t;

typedef struct warnmsg_entry{
	char *msg;
	char *url;
	char *lnk;
} warnmsg_t;

#define WARN			0
#define NOTE			1
#define MAX_WARNINGS		256
typedef struct warn {
	int	type;		/* WARN or NOTE */
	int	idx;  		/* index into msgwarn[] array */
	char    *lnk;		/* Link to top of secion */
} warn_t;

typedef struct lle_entry {
        struct lle_entry *next;
        uint64 key;
} lle_t;

typedef struct lle2_entry {
	struct lle2_entry *next;
	uint64 key1;
	uint64 key2;
} lle2_t;

/*
** Futex tracking data structures -
**
** A good FUTEX reference: http://locklessinc.com/articles/futex_cheat_sheet/
**
** Process-private, no requeue:
**      (waker_tgid+vaddr == sleeper_tgid+vaddr)
**      warn if FUTEX_PRIVATE_FLAG not set.
** Process-private, requeues:
**      (waker_tgid == sleeper_tgid) && (waker_vaddr != sleeper_vaddr)
**      warn if FUTEX_PRIVATE_FLAG not set.
** Process-shared, no requeue:
**      (waker_tgid != sleeper_tgid) && (waker_vaddr == sleeper_vaddr)
** Process-shared, requeues:
**      (waker_tgid != sleeper_tgid) && (waker_vaddr != sleeper_vaddr)
*/

typedef struct futex_ret {
        lle_t           lle;            /* key is the return value of the syscall (which also encodes the errno) */
        uint32          cnt;
        uint64          total_time;
        uint64          max_time;
        uint32          max_waker;      /* waker associated with our max wait time */
} futex_ret_t;

typedef struct futex_pids {
        lle_t           lle;            /* the pid operating on the futex */
        uint32          cnt;
        uint64          total_time;
        uint64          max_time;
        uint32          max_waker;
        uint32          ret_total;
        uint32          n_eagain;
        uint32          n_etimedout;
        uint32          n_othererr;
} futex_pids_t;

typedef struct futex_op {
        lle_t           lle;            /* key is the OP type */
        uint32          cnt;
        futex_ret_t     **retval_hash;
	futex_pids_t    **pids_hash;
        uint64          total_time;
        uint64          max_time;
        uint32          max_waker;      /* waker associated with our max wait time */
        uint32          ret_total;
        uint32          n_eagain;
        uint32          n_etimedout;
        uint32          n_othererr;
} futex_op_t;

typedef struct futex_dup {
        lle_t           lle;            /* the uaddr1 value passed in */
        uint64          addr;
        uint32          cnt;
} futex_dup_t ;

typedef struct futex_reque {
        lle_t           lle;            /* the uaddr2 value passed in as the requeueu addr */
        uint64          addr;
        uint32          cnt;
} futex_reque_t;

typedef struct gbl_futex_info {
        lle_t           lle;            /* lle.key is the futex vaddr passed in as arg0 */
        uint64          addr;
        futex_op_t      **ops_hash;	/* list of pids using futex hangs off the ops list */
        futex_reque_t   **uaddr2_hash;  /* list of requeued addrs */
        futex_dup_t     **dup_hash;     /* list of possible addrs pointing to the same futex */
                                        /* only those addrs not in the requeue list are true dups */
                                        /* only added if not in uaddr2_hash (requeue hash) */
        futex_pids_t    **pids_hash;
	uint64          total_time;
        uint64          max_time;
        uint32          max_waker;      /* waker associated with our max wait time */
        uint32          cnt;
        uint32          ret_total;
        uint32          n_eagain;
        uint32          n_etimedout;
        uint32          n_othererr;
} gbl_futex_info_t;

typedef struct pid_futex_info {
        lle_t           lle;            /* lle.key is the futex vaddr passed in as arg0 or arg4 */
        uint64          addr;
        futex_op_t      **ops_hash;
        futex_reque_t   **uaddr2_hash;  /* the list of requeued addrs */
        uint64          total_time;
        uint64          max_time;
        uint32          last_waker;
        uint64          last_waker_uaddr1;
        uint32          max_waker;      /* waker associated with our max wait time */
        uint32          cnt;
} pid_futex_info_t;

typedef struct symidx {
	uint64		st_value;
	uint32		idx;
} symidx_t;

typedef struct elfmap_info {
	lle_t		lle;
	char		*fnameptr;
	void  		*elfp;
	symidx_t	*symtab;
	int		nsym;
} elfmap_info_t;

#define MAPCLASS	127
#define DLL		126
typedef struct vtxt_preg {
	lle_t           lle;
	uint64          p_vaddr;
	uint64          p_endaddr;
	uint64          p_off;
	uint64 		elf_vaddr;
	char            *elfp;	 	
	elfmap_info_t	*elfmapp;
	void            *symbols;
	char            *strings;
	char            *filename;
	int             nsyms;
	short           p_type;
} vtxt_preg_t;

#define MAX_STR_LEN	64
typedef struct str_lle_entry {
	struct str_lle_entry *next;
	char key[MAX_STR_LEN];
} strlle_t;

typedef struct pdb_symidx {
	uint64		symaddr;
	char		*symptr;
} pdb_symidx_t;

typedef struct pdb_info {
	strlle_t	strlle;
	void 		*mapptr;
	pdb_symidx_t	*symtab;
	char 		*filename;
	void 		*ControlImagePtr;
	int		size;
	int		nsyms;
} pdb_info_t;

typedef struct stktrc_lle_entry {
        struct stktrc_lle_entry *next;
        uint64 key[LEGACY_STACK_DEPTH];
} stklle_t;

typedef struct stktrc_info {
        stklle_t           stklle;
	void		*pidp;
        uint64          slptime;        /* cumulative time sleeping in this stack */
        int             stklen;         /* length in uint64 units */
        int             cnt;
	int 		state;
} stktrc_info_t;

typedef struct print_pc_info_args {
	FILE 		*pidfile;
	struct hc_info	*hcinfop;
	uint64		*warnflagp;
} print_pc_args_t;

typedef struct pc_info {
	lle_t		lle;
	vtxt_preg_t	*pregp;
	int		state;
	int		count;
} pc_info_t;

typedef struct hc_info {
	uint64 warnflag;
	pc_info_t	**pc_hash;
	stktrc_info_t	**hc_stktrc_hash;
	uint32		total;
	uint32		cpustate[HC_STATES];
} hc_info_t;

typedef struct syscall_arg {
	char *label;
	int	format;
} syscall_arg_t;

typedef struct syscall_arg_list{
                        char *name;
			syscall_arg_t retval;
			syscall_arg_t args[MAXARGS];
                } syscall_arg_list_t;

#define FILEOP  0x1
#define FUTEXOP 0x2

typedef struct ks_action {
                        char execute;
                        char logio;
                        int scallop;
                        int (*func)(void *, void *, uint64);
                } ks_action_t;

typedef struct arg_action {
                        char *(*func)(unsigned int);
		} arg_action_t;

typedef struct iostats {
	uint64        sect_xfrd;
	uint64        max_ioserv;
	uint64        max_iowait;
	uint64        cum_ioserv;            
	uint64        cum_iowait;             
	uint32		qlen;
	uint32		qops;
	uint64		next_sector;		/* valid only pertid, gathered during INSERT */
	uint32          insert_cnt;		/* gathered during INSERT */
	uint32          issue_cnt;		/* gathered during ISSUE */
	uint32		requeue_cnt;		/* increment on requeue */
	uint32		abort_cnt;		/* increment on abort */
	uint32		barrier_cnt;		/* increment for barrier I/O */
	uint32		cum_qlen;		/* gathered during INSERT */
	uint32		max_qlen;		/* gathered during INSERT */
	uint32		cum_async_inflight;	/* gathered during ISSUED */
	uint32		cum_sync_inflight;	/* gathered during ISSUED */
	uint32          random_ios;		/* valid only pertid, gathered during ISSUE */
	uint32          seq_ios;		/* valid only pertid, gathered during ISSUE */
	uint32	        compl_cnt;
	uint32		error_cnt;
} iostats_t;

typedef struct win_service {
	lle_t		lle;
} win_service_t;

struct arg_info {
	uint64            arg0;
	uint64            arg1;
	uint64            arg2;
	uint64            arg3;
} ;

typedef struct pth_tid_list {
        lle_t                   lle;                    /* key = tid */
        uint64                total_wait;             /* total wait time for obj */
        uint64                max_wait;               /* max wait time observed */
        uint32                pid;                    /* PID       */
        uint32                acq_cnt;                /* cnt acquired by this tid */
} pth_tid_list_t;


typedef struct pth_obj_stats {
        lle_t                   lle;                    /* key = pid/obj_addr */
	uint64		obj_addr;		/* object address */
        uint64                obj_type;               /* object flags passed in */
        uint64                acq_time;               /* time when last acquired */
        uint64                total_wait;             /* total wait time for obj */
        uint64                avg_wait;               /* avg wait time per attempt */
        uint64                total_hold;             /* total hold time for obj */
        uint64                avg_hold;               /* avg obj hold time */
        uint64                max_wait;               /* max wait time observed */
        uint64                max_hold;               /* max wait time observed */
        void                    *gl_objp;               /* ptr to global obj stats */
        struct hc_info          *hcinfop;               /* hardclock seen while held */
        pth_tid_list_t          **ktid_hash;            /* hash to tids acquiring obj */
        uint32                acq_cnt;                /* number of time acquired */
/*      uint32                nest_cnt;                  nesting count for multiple obj's */
/*      uint32                wake_cnt;                  total wait count for this obj_addr */
} pth_obj_stats_t;

typedef struct pth_obj_info {
        pth_obj_stats_t *last_pth_objp;         /* lastobj we slept on...used to check nesting */
        void            *pth_statsp_hash;       /* hash table with obj_addr as key */
/*      uint32        nesting_cnt;               per tid global cnt of lock/obj acquire count */
/*      uint32        wake_cnt;                  count of the number times we've woken for this abj_add */
/*      uint32        max_nested;                highest nesting count seen by this tid */
} pth_obj_info_t;

typedef struct pth_class_entry {
	pth_obj_stats_t 	**pth_obj_stats_hash;
} pth_class_entry_t;

typedef struct lviostats { 
	uint32		cnt;
	uint32		errs;
	uint64          bytes;
	uint64		total_time;
	uint64		max_time;
} lviostats_t;

typedef struct wait_info {
	uint64 		sleep_time;
	uint64		max_time;
	uint32     		count;
} wait_info_t;

/* the first part of fd_stats must the the same as sd_stats */
struct fd_stats {
	uint64          total_time;
	uint64		max_time;
	uint64		rd_bytes;
	uint64		wr_bytes;
	uint32		errors;
	uint32		syscall_cnt;		
	uint32		rd_cnt;
	uint32		wr_cnt;
	uint32		last_pid;
	uint32		lseek_cnt;
	uint32 		open_cnt;
	uint32		seqios;
	uint32		rndios;
};

struct sd_stats {
	uint64          total_time;
	uint64		max_time;
	uint64		rd_bytes;
	uint64		wr_bytes;	
	uint32		errors;
	uint32		syscall_cnt;		/* packets on Windows */
	uint32		rd_cnt;
	uint32		wr_cnt;
	uint32		last_pid;
};

/* used for .map files */
typedef struct map_entry {
	uint64		addr;
	uint64		nameptr;
} map_entry_t;

typedef struct pid_info {
	lle_t		lle;
	char		*cmd;
	char 		*thread_cmd;
	char		*hcmd;		/* Hadoop proc name or SQL Instance name*/
	void		*dockerp;	/* docker pointer */
	void *schedp;			/* struct sched_info */
	hc_info_t *hcinfop;		/* struct hc_info */
	void **devhash;			/* struct dev_info */
	void **mdevhash;		/* struct dev_info */
	void **scallhash;		/* struct syscallinfo */
	void **fdhash;			/* struct fdinfo */
	void **fobj_hash;		/* struct fileobj_info WINDOWS ONLY */
	void **sdata_hash;		/* struct sdata_info WINDOWS ONLY */
	void **trc_hash;		/* struct trc_info */
	void **slp_hash;		/* struct slp_info */
	void **user_slp_hash;		/* struct slp_info */
	void **stktrc_hash;		/* struct stktrc_info */
	void **runq_stktrc_hash;	/* struct stktrc_info */
	void **futex_hash;              /* struct pid_futex_info */
	void *vtxt_pregp;		/* struct vtxt_preg */
	void *mapinfop;			/* struct vtxt_preg */	
	void **pgcache_hash;		/* struct pgcache */
	void *win_services;		/* struct win_service */

	/* information saved on sys_enter */
	short 		*syscall_index;
	char 		*last_open_fname;
	char 		*last_exec_fname;
	uint64		last_syscall_time;
	uint64 		last_syscall_args[MAXARGS];
	uint64		last_syscall_id;

	/* needed for Windows as system calls can be "nested" */
	void		*win_active_syscalls;

	/* used for filemap cache stats */
	uint32		cache_insert_cnt;
	uint32		cache_evict_cnt;

	/* information saved on sched_switch when going to SLEEP */
	uint64		last_stack_depth;
	uint64		last_stktrc[LEGACY_STACK_DEPTH];	
	uint64 		last_sleep_delta;		/* needed for WinKI */

	/* global pid information */
	uint32		syscall_cnt;
	int		num_tr_recs;
	int		clean_cnt;  	/* use to cleanup memory for PID */
	int		missed_buffers;
	int		tgid;
	int		ppid;
	int 		nlwp;
	int		ora_sid;	/* Index into the sid_table */
	int		ora_proc;       /* Index into the sid_table[].sid_pid[] array */
	short		binding;  	 /* BIND_NONE = 0; BIND_LDOM=1 */
	short		binding_num;
	uint64 		rss;
	uint64 		vss;
	char		elf; 		/* ELF32 = 0; ELF64 = 1 */
	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
	struct iostats	miostats[3];    /* TOTAL=0/READ=1/WRITE=2 */
	struct fd_stats  fdstats; 	/* pointer to an array of fdstats */
	struct sd_stats  netstats;
} pid_info_t;

typedef struct print_stktrc_info_args {
	struct sched_info *schedp;
	struct pid_info *pidp;
	uint64		warnflag;
} print_stktrc_args_t;

typedef struct args_info {
	lle_t                   lle;                    /* key = arg value */
	struct args_info        **sec_args_hash;
	uint64                sleep_time;
	uint32                  cnt;
} args_info_t;

typedef struct w_scall {
	lle_t			lle;			/* key = syscall no */
	struct args_info	**args_hash;
	uint64		sleep_time;
	uint32			cnt;
} w_scall_t;

typedef struct w_tid {                                  /* key = tid number of waker */
	lle_t                   lle;
	w_scall_t               **w_scall_hash;
	stktrc_info_t           **w_stktrc_hash;        /* hash  of setrq stack traces  */
	uint64                sleep_time;             /* to be added at syscall completion by waker */
	uint32                  cnt;
	int			pid;
} w_tid_t;

typedef struct w_tlist {
	w_tid_t                 *wtidp;                 /* waking tid w_tid_t to update with syscall info */
	uint64                sleep_time;
	} w_tlist_t;

typedef struct rq_wait_cnt {
	uint64		time;
	uint64		seq_cnt;
	uint64		sleep_caller;
	int			cpu;
	int			pid;
	int			tid;
	int			scall;
	int			sched_policy;
	int			pri;
	int			state;
	int			invol;
} rq_wait_cnt_t;

typedef struct runq_info {
	lle_t			lle;			/* key = wchan address */
	uint64		total_time;
	uint64		max_time;
	uint64		max_time_int;
	uint32		cnt;
	uint32		migrations;
	uint32		ldom_migrations_in;
	uint32		ldom_migrations_out;
	uint32		idle_handoff;
        uint32                rqhist[RUNQ_NBUCKETS];
} runq_info_t;

typedef struct slp_info {
	lle_t   		lle;			/* key = base addr of kernel function  */
	uint64 			sleep_time;
	uint64			max_time;
        void                    **scd_wpid_hash;    /* hashed list of tids waking us up from this kernel func.  Used in the scdetail kipid option */
	int     		count;
} slp_info_t;

#define LLC_REF		0
#define LLC_MISSES	1
#define RET_INSTR	2
#define CYC_NOHALT_CORE	3
#define REF_CLK_FREQ	4
#define ACT_CLK_FREQ	5
#define SMI_CNT		6
#define MSR_NREGS	7

#define TOTAL_TIME		0
#define IDLE_TIME		1
#define RUN_TIME		2
#define USER_TIME		3
#define	SYS_TIME		4
#define STEAL_TIME		5
#define STEAL_TIME_IDLE		6
#define IRQ_TIME		7		
#define IRQ_BEGIN		8
#define HARDIRQ_SYS_TIME	8 
#define HARDIRQ_USER_TIME	9
#define HARDIRQ_IDLE_TIME	10
#define SOFTIRQ_SYS_TIME	11
#define SOFTIRQ_USER_TIME	12
#define SOFTIRQ_IDLE_TIME	13
#define IRQ_END			13   
/* per-pid stats */
#define SLEEP_TIME		14
#define	RUNQ_TIME		15
#define	RUNQ_IDLE_TIME		16
#define RUNQ_PRI_TIME		17
#define RUNQ_USRPRI_TIME	18
#define TOTAL_WAITED4_TIME	19
#define UFLT_SLEEP_TIME		20
#define N_TIME_STATS		21

#define T_total_time		time[TOTAL_TIME]
#define T_idle_time		time[IDLE_TIME]
#define T_run_time		time[RUN_TIME]
#define T_user_time		time[USER_TIME]
#define T_sys_time		time[SYS_TIME]
#define T_stealtime		time[STEAL_TIME]
#define T_stealtime_idle	time[STEAL_TIME_IDLE]
#define T_irq_time     		time[IRQ_TIME]
#define T_softirq_user_time    	time[SOFTIRQ_USER_TIME]
#define T_softirq_sys_time     	time[SOFTIRQ_SYS_TIME]
#define T_softirq_idle_time  	time[SOFTIRQ_IDLE_TIME]
#define T_hardirq_user_time    	time[HARDIRQ_USER_TIME]
#define T_hardirq_sys_time     	time[HARDIRQ_SYS_TIME]
#define T_hardirq_idle_time    	time[HARDIRQ_IDLE_TIME]
#define T_sleep_time		time[SLEEP_TIME]
#define T_runq_time		time[RUNQ_TIME]
#define T_runq_idle_time	time[RUNQ_IDLE_TIME]
#define T_runq_pri_time		time[RUNQ_PRI_TIME]
#define T_runq_usrpri_time	time[RUNQ_USRPRI_TIME]
#define T_total_waited4_time   	time[TOTAL_WAITED4_TIME]
#define T_uflt_sleep_time       time[UFLT_SLEEP_TIME]

#define SOFTIRQ_CNT		0
#define HARDIRQ_CNT		1
#define IRQ_CNT_END		1
#define SWITCH_CNT		2
#define PREEMPT_CNT		3
#define SLEEP_CNT		4
#define SETRQ_CNT		5	/* incremented on source pid of wakeup */
#define WAKEUP_CNT		6	/* incremented on target pid of wakeup */
#define RUNQ_CNT		7
#define RUNQ_IDLE_CNT		8
#define RUNQ_PRI_CNT		9
#define RUNQ_USRPRI_CNT		10
#define UFLT_SLEEP_CNT		11
#define N_CNT_STATS		12

#define C_softirq_cnt		cnt[SOFTIRQ_CNT]
#define C_hardirq_cnt		cnt[HARDIRQ_CNT]
#define C_switch_cnt		cnt[SWITCH_CNT]
#define C_preempt_cnt		cnt[PREEMPT_CNT]
#define C_sleep_cnt		cnt[SLEEP_CNT]
#define C_setrq_cnt		cnt[SETRQ_CNT]
#define C_wakeup_cnt		cnt[WAKEUP_CNT]
#define C_runq_cnt		cnt[RUNQ_CNT]
#define C_runq_idle_cnt		cnt[RUNQ_IDLE_CNT]
#define C_runq_pri_cnt		cnt[RUNQ_PRI_CNT]
#define C_runq_usrpri_cnt	cnt[RUNQ_USRPRI_CNT]
#define C_uflt_sleep_cnt	cnt[UFLT_SLEEP_CNT]

typedef struct sched_stats {
	uint64  	last_cur_time;  
	uint64 		time[N_TIME_STATS];
	unsigned long	msr_last[MSR_NREGS];
	unsigned long	msr_total[MSR_NREGS];
	int		cnt[N_CNT_STATS];
	int     	state;   		/* UNKNOWN, RUNNING, ON_RUNQ, SLEEPING */
} sched_stats_t;

/* For coop tracking we map the interaction using:
* Tasks that WOKE ME
*      setrq_src_has
*        coop_waker_scall_hash
*          coop waker_args_hash
*            coop_sleeper_scall_hash
*              coop_sleeper_arg_hash
*                coop_slpfunc_hash (liki only, NA in ftrace version)
*
*
* Tasks that I WOKE UP
*      setrq_tgt_hash
*        coop_scall_hash
*          coop_sleep_arg_hash
*            coop_slpfunc_hash (liki only, NA in ftrace version)
*              coop_waker_scall_hash
*                coop_waker_arg_hash
*/

typedef struct coop_waker_scall {
        lle_t   lle;                    /*key is syscall number */
        int     cnt;
        uint64  sleep_time;
        struct coop_scall_arg    **coop_waker_arg_hash;
} coop_waker_scall_t;

typedef struct coop_slpfunc {
        lle_t   lle;                    /* key is PC of blocking function */
        int     cnt;
        uint64  sleep_time;
        struct coop_waker_scall **coop_waker_sc_hash;
} coop_slpfunc_t;

typedef struct coop_scall_arg {
        lle_t   lle;                    /* key is hex value of arg cast as uint64 */
        int     cnt;
        uint64  sleep_time;
        struct coop_slpfunc **coop_slpfunc_hash;
        struct coop_scall   **coop_sleeper_scall_hash;
} coop_scall_arg_t;


typedef struct coop_scall {
        lle_t   lle;                    /*key is syscall no */
        int     cnt;
        uint64  sleep_time;
        struct coop_scall_arg    **coop_args_hash;
} coop_scall_t;

typedef struct wtree_node {
	lle_t   lle;                    /* the key varies... it's the pid for "taskID" type nodes in our tree */
	char	*name;
	int	index;
	int	type;
	void    *infop;			/* varies... points to the sched_stat_t of the pid in the"taskID" node type */
} wtree_node_t;

typedef struct setrq_info {
        lle_t           lle;            /* key is pid */
        struct coop_scall    **coop_scall_hash;   /* syscalls waker/sleeper were in when woken */
        uint64          sleep_time;
        uint64          unknown_time;
        int             cnt;
} setrq_info_t;


typedef struct scd_waker_info {
        lle_t           lle;            /* key is pid */
        int             count;
        uint64          sleep_time;
        uint64          max_time;
} scd_waker_info_t;


typedef struct coop_info{
        struct pid_info *pidp;
	struct pid_info *rep_pidp;
	uint64 waker_is_ICS;
        uint64 waker_scall;
        uint64 waker_arg0;
        uint64 sleeper_scall;
        uint64 sleeper_arg0;
        uint64 slpfunc;
        uint64 cnt;
        uint64 scall_cnt;
        uint64 scall_slptime;
        uint64 sleep_time;
        uint64 total_cnt; /* copied in from the tgt setrq_info->cnt field */
        uint64 total_slp_time; /* copied in from the schedp->stats.sleep_time for the sleeping thread/task/pid */
        uint64 which;   /*  is this for a sleeper task or a waker task list we are processing  */
        char elf;
} coop_info_t;

typedef struct sched_info {
	struct sched_stats      sched_stats;
	setrq_info_t  		**setrq_src_hash;   /* tids that woke this thread up */
	setrq_info_t  		**setrq_tgt_hash;   /* tids that this thread woke up */
	struct wait_tree_nodes  **wtree_hash;       /* a list of the pids to include in visualization maps */
	runq_info_t		*rqinfop;
	runq_info_t		**rqh;
	uint64			warnflag;
	int	policy;
	int     pri_high;
	int     pri_low;
	int     cpu;
	int     cpu_migrations;
	int	ldom_migrations;
	int	last_swtch_forced;
	int     next_index;
	int cur_sleep_cnt;
	int cur_wakeup_cnt;
	int max_wakeup_cnt;
	int max_wakeup_cnt_hit;
	uint32 last_target_pid;
	uint64 max_wakeup_time;
} sched_info_t;

typedef struct wait_tree_ptrs {
        struct pid_info   *root_pidp;
        struct pid_info   *curr_pidp;
        struct pid_info   *prev_pidp;
        int          depth;
        int          pad;
} wait_tree_ptrs_t;

typedef struct wait_tree_nodes {
        lle_t   lle;                    /* the key varies... it's the pid for "taskID" type nodes in our tree */
        char    *name;
        char    *thr_name;
        int     index;
        int     type;
        int     Ddepth;                 /* depth, or level of recursion we first Discovered this node  */
        void    *infop;                 /* varies... points to the sched_stat_t of the pid in the"taskID" node type */
} wait_tree_nodes_t;

/*  The following structure is used to create JSON formatted output.
**  See http://www.json.org  for details on JSON format.
**  JavaScript Object Notation  = JSON
*/

 typedef struct  json_s {
       char    *name;          /* JSON object 'string' */
       float   time;           /* JSON object 'value'  */
       int     count;          /* JSON object 'value'  */
       int     type;           /* kiinfo use only */
       char    *detail;        /* JSON object 'value' */
       int     flags;          /* kiinfo use only */
} json_t;

typedef struct idle_info {
	uint64 time_period;
	uint32 total_cnt;
	uint32 idle_cnt;
	uint32 prev_resume_cnt;
	uint32 prev_time;
} idle_info_t;

typedef struct pcpu_info {
	lle_t		lle;
	int	lcpu1;
	int	lcpu2;
	uint64 last_time;
	uint64 busy_time;			/* accum time when both CPUs are busy */
	uint64 idle_time;			/* accum time when both CPUs are idle */
	uint64 unknown_idle; 			/* accum time when CPU is idle, but sibling is Unknown */
	uint64 unknown_busy;			/* accum time when CPU is busy, but sibling is Unknown */
	uint64 last_db_time; 			/* last time when HT pair became double busy */
	uint64 last_di_time;			/* last time when HT pair became double idle */
	uint64 sys_DBDI_hist[IDLE_TIME_NBUCKETS]; /*sys-wide DI hist while I'm DB */
	uint64 pset_DBDI_hist[IDLE_TIME_NBUCKETS];
	uint64 ldom_DBDI_hist[IDLE_TIME_NBUCKETS];
} pcpu_info_t;

typedef struct power_info {
	uint64	freq_hi;
	uint64	freq_low;
	uint64  cstate_times[NCSTATES];
	uint64 	last_cstate_time;
	int	cur_cstate;
	int     power_freq_cnt;
	int  	power_start_cnt;
	int  	power_end_cnt;
} power_info_t;

typedef struct cpu_info {
	lle_t		lle;
	hc_info_t    *hcinfop;
	struct sched_info *schedp;
	struct power_info *powerp;
	struct irq_info	*irqp;
	struct irq_info	*softirqp;

	int cpu;
	int physid;			/*  from cpuinfo file, used to find HT cpus */
	int ldom;
	int pcpu_idx;			/* index into Physical cpuinfo array if this CPU is an LCPU */
	int pid;			/* Currently executing PID.  Updated in sched_switch_func */

	/* These fields are used for HT accounting */
	short cpu_attr;
	short lcpu_sibling;
	uint32 lcpu_state;		
	uint64 lcpu_busy;			/* time when CPU is busy, but sibling is idle */

	uint64		total_traces;
	uint64 idle_time;
	uint64	last_swtch_time;
	int 	runq_len;
	int	max_runq_len;
	int	last_softirq_vec;
	uint64	last_softirq_time;

	/* These fields are use for IDLE accounting  */
        uint64 idle_hist[IDLE_TIME_NBUCKETS];
        int state_post_itime;
	idle_info_t idle[8];	        /* array of idle period counters, 0.1ms, 1ms, 5ms, 10ms,  */
					/* 50ms, 100ms, 500ms, 1000ms */
	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
	struct iostats	miostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
	
} cpu_info_t;

typedef struct ldom_info {
	lle_t		lle;
	struct sched_stats sched_stats;
	uint64 memkb;
	uint64 freekb;
	uint64 usedkb;
	int ncpus;
	int bind_cnt;
	int oracle_bind_cnt;
} ldom_info_t ;
			
typedef struct trc_info {		/* includes syscalls */
	lle_t		lle;
	struct syscall_stats *syscall_statsp;
	uint32		count;
} trc_info_t;

#define SCHED_POLICY_MASK 0xffff
#if 0
typedef enum sched_policy {
	SCHED_NORMAL =   0,     /* Strict First-In/First-Out policy */
	SCHED_FIFO =     1,     /* Strict First-In/First-Out policy */
	SCHED_RR =       2,     /* FIFO, with a Round-Robin interval */   
	SCHED_BATCH =    3,    
	SCHED_ISO =      4,     /* reserved but not yet implemented */
	SCHED_IDLE =     5
} sched_policy_t;
#endif

#define MAXSKIPLIST 5

typedef struct iotimes {
	uint32 time[2][NBUCKETS];
} iotimes_t;

typedef struct iocb_info {
	lle_t		lle;		/* key = iocbp */
	uint64		hrtime;
	uint64		pid;
	uint64		offset;
	uint64		bytes;
	uint32		fd;
	uint32		op;
} iocb_info_t;

typedef struct ctx_info {
	lle_t		lle;		/* key =  ctx_id */
	uint64		pid;
	uint64		syscallno;
	void 		*iocb_hash;
} ctx_info_t;

typedef struct fd_info {
	lle_t		lle;			/*  key = FD */
	void		**syscallp;			/* syscall_info_t */
	char 		*fnamep;
	uint64		next_byteno;
	uint64		dev;
	struct sockaddr_in6	*lsock;
	struct sockaddr_in6	*rsock;
	uint32		node;
	int		ftype;
	int 		rndio_flag;
	int		multiple_fnames;
	int 		closed;
	struct fd_stats	stats;
} fd_info_t;


typedef struct filedev_info {
	lle_t		lle;			/* key = devnum */
	struct iostats	stats[3];
	uint64		last_offset;
} filedev_t;

typedef struct fstats {
	uint64		next_offset;
	uint64          bytes;
	uint32		cnt;		
	uint32		seqios;
	uint32		rndios;
} fstats_t;

typedef struct fileobj_info {			/* Windows File Object */
	lle_t		lle;			/* key = object ptr */
	char 		*filename;
	void		**fdev_hash;
	struct fstats	liostats[3];
	struct iostats	piostats[3];
	uint32		last_tid;
} fileobj_t;

typedef struct io_req {
	lle_t		lle;
	uint64  	insert_time;
	uint64  	issue_time;
	uint32		insert_pid;
	uint32		issue_pid;
	uint64		sector;
	uint32		nr_sector;
	uint32		requeue_cnt;
	char		seq_flag;
} io_req_t;

typedef struct dev_info {
	lle_t		lle;
	struct io_req	**ioq_hash;
	void 		**mpath_hash; 	/* mpath_info */
	char 		*devname;
	/* for devices in a mapper device */
	uint64		devpath;	/* x:x:x:x path of device from multipath -l or scsi events */
	uint64		wwn;		/* WWN of path from ll -R */
	char		*pathname;      /* target path from ll -R */
	void		*mdevinfop;	/* pointer to mapper device */
	void		*wsysconfigp;	/* pointer wo windows physdisk SysConfig rec */
	void		*siblingp;	/* points to sibling device */
	void		*fcinfop;	/* points to FC HBA info */

	/* for mapper devices */
	char		*mapname;	/* /dev/mapper device name */
	void		*devlist;	/* hash of devices belonging to the this mapper devices */
	int		mp_policy;	/* 1=MP_ROUND_ROBIN, 2=MP_QUEUE_LENGTH, 3=MP_SERVICE_TIME */

	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
} dev_info_t;

typedef struct mpath_info {
	lle_t		lle;
	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
} mpath_info_t;

typedef struct dskblk_info {		/* key = 32 bits for dev, 32 bits for blkno */
	lle_t		lle;
	uint64		sector;
	int		rd_cnt;
	int		wr_cnt;
} dskblk_info_t;

typedef struct fc_dev {
	lle_t		lle;
	void		*devinfop;
} fc_dev_t;

typedef struct fc_info {
	lle_t 		lle;
	struct fc_dev **fcdevhash;	/* key is the dev, used to find devinfop quickly */
	struct iostats	iostats[3];
} fc_info_t;

typedef struct wwn_dev {
	lle_t		lle;
	void		*devinfop;
} wwn_dev_t;

typedef struct wwn_info {
	lle_t		lle;
	struct wwn_dev **wwndevhash;	/* key is the dev, used to find devinfop quickly */
	struct iostats iostats[3];
} wwn_info_t;

typedef struct iov_stats {
	uint64		rd_time;
	uint64		rd_max_time;
	uint64		rd_bytes;
	uint64		wr_time;
	uint64		wr_max_time;
	uint64		wr_bytes;
	uint32		rd_cnt;
	uint32		wr_cnt;
} iov_stats_t;

typedef struct syscall_stats {
	uint64		total_time;
	uint64		max_time;
	uint64		bytes;		/* only for syscalls doing logical I/O */
	uint32		count;
	uint32		errors;
} syscall_stats_t;

struct logio_stats {
	uint64		bytes;
	uint64		total_time;
	uint64		max_time;
	uint32		errors;
	uint32		cnt;
};

struct logio_info {
	lle_t		lle;		/* lle.net = unique v_fstype/v_type/f_type */    
	struct logio_stats 	stats;
};

struct syscall_info {
	lle_t			lle;
	struct syscall_stats	stats;
	struct sched_stats	sched_stats;
	void			**slp_hash;
	struct iov_stats	*iov_stats;
};

struct win_syscall_save_entry {
	void *	next;
	uint64  starttime;
	uint64  addr;
	int	nested;
};

typedef struct addr_to_idx_hash_entry {
	lle_t			lle;
	uint64			idx;
} addr_to_idx_hash_entry_t;

#define MAX_FLT_TYPES	10
#define FLT_READ	0
#define FLT_WRITE 1
#define FLT_TOTAL 2
typedef struct flt_stats {
	uint32		total;
	uint32		vflt_cnt;
	uint32		pflt_cnt;
	uint32		flt_cnt[3][MAX_FLT_TYPES];	/* 1st element - wrt; 2nd element - pcause */
} flt_stats_t;

typedef struct reg_info {
	lle_t		lle;
	uint64	p_space;
	uint64	p_vaddr;
	uint32	p_count;
	uint32		p_type;
	struct flt_stats	fltstats;
} reg_info_t;

typedef struct flt_info {
	struct flt_stats	fltstats;
	struct reg_info		**reg_hash;
} flt_info_t;

typedef struct pgcache_info {
	lle_t		lle;			/* key dev/inode */
	uint32		cache_insert_cnt;
	uint32		cache_evict_cnt;
} pgcache_t;
	
typedef struct fdata_info {
	lle_t		lle;			/*  key = FD */
	char		*fnameptr;
	void		**syscallp;			/* syscall_info_t */
	uint32		cache_insert_cnt;
	uint32		cache_evict_cnt;
	struct fd_stats	stats;
	uint64		dev;
	uint32		node;
	int		ftype;
} fdata_info_t;

typedef struct sdata_info {
	lle2_t		lle;
	char		*fnameptr;
	void		**syscallp;		/* syscall_info_t */
	void		*rsockp;		/* quick ptr to Remote sock_info_t */
	void		*lsockp;		/* quick ptr to Local sock_info_t */
	void		*ripp;			/* quick ptr to Remote ip_info_t */
	void		*lipp;			/* quick ptr to Local ip_info_t */
	void		*ipipp;			/* quick ptr to IP->IP info_t */
	void 		*laddr;			/* ptr to sockaddr_in6 */
	void 		*raddr;			/* ptr to sockaddr_in6 */
	uint32		node;
	uint32		type;
	struct sd_stats	stats;
} sdata_info_t;

typedef struct sock_info {
	lle_t		lle;
	void		*syscallp;
	void 		*saddr;			/* ptr to sockaddr_in6 */
	struct sd_stats	stats;
} sock_info_t ;

typedef struct ip_info {
	lle_t		lle;
	void		*syscallp;
	void 		*saddr;			/* ptr to sockaddr_in6 */
	struct sd_stats	stats;
} ip_info_t;

typedef struct ipip_info {
	lle2_t		lle;
	void		*syscallp;
	void 		*laddr;			/* ptr to sockaddr_in6 */
	void 		*raddr;			/* ptr to sockaddr_in6 */
	struct sd_stats	stats;
} ipip_info_t;

struct sid_pid {
	lle_t		lle;
	pid_t		pid;
	struct pid_info	*pidinfop;
};

struct ora_stats {
	uint64		run_time;
	uint64		runq_time;
	int		pid_cnt;
	int		sched_policy;
	struct iostats  iostats[3];
};

struct sid_info {
	char		sid_name[20];
	struct sid_pid	*sid_pid[16];
	struct ora_stats stats;
	int		phys_cnt;
};

typedef struct symtable_struct {
	uint64		addr;
	char 		*nameptr;
	char 		*module;
} symtable_t;

typedef struct irq_name {
	lle_t		lle;
	char		*name;
} irq_name_t;
	
typedef struct irq_entry {
        lle_t           lle;                    /* key = irq vector */
	uint64		total_time;
	int		count;
} irq_entry_t;
	
struct irq_info {
	int		count;
	uint64		total_time;
	void 		**irq_entry_hash;  
};

typedef struct docker_info {
	lle_t lle;
	char *name;
	void **dkpid_hash;		/* perpid information */
	sched_stats_t sched_stats;
	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
	struct sd_stats  netstats;	
} docker_info_t;

	
typedef struct server_info {
	char *subdir;
	char *hostname;
	char *os_vers;
	char *model;
	pid_info_t **pid_hash;		/* perpid information */
	cpu_info_t **cpu_hash;		/* per-lcpu information */
	pcpu_info_t **pcpu_hash;	/* per-pcpu information */
	ldom_info_t **ldom_hash;	/* per-ldom information */
	docker_info_t **docker_hash;    /* per-docker information */
	hc_info_t *hcinfop;		/* struct hc_info */
	sched_info_t *schedp;		/* struct sched_info */
	power_info_t *powerp;		/* struct power_info */
	void **trc_hash;  
	void **slp_hash;		/* struct slp_info */
	void **stktrc_hash;		/* struct stktrc_info */
	void **syscall_hash;		/* struct syscall_info */
	void **fdata_hash;		/* struct fdata_info_t */
	void **fobj_hash;		/* struct fileobj_t   WINDOWS only */
	void **sdata_hash;		/* struct sdata_info_t */
	void **ipip_hash;		/* struct ipip_info_t */
	void **rip_hash;		/* struct ip_info_t */
	void **lip_hash;		/* struct ip_info_t */
	void **rsock_hash;		/* struct sock_info_t */
	void **lsock_hash;		/* struct sock_info_t */
	void **futex_hash;              /* struct gbl_futex_info_t */
	/* IO related structures */
	void **dskblk_hash;		/* struct dskblk_info */
	void **devhash;			/* struct dev_info */
	void *iotimes;			/* struct iotimes */
	void **elfmap_hash;		/* struct elfmap_info_t */
	void **pdbmap_hash;   		/* Windows PDB Hash Table */
	void *vtxt_pregp;
	struct iostats	iostats[3];     /* TOTAL=0/READ=1/WRITE=2 */
	struct sd_stats netstats;	/* network stats */
	void **mdevhash;		/* struct dev_info */
	void **fchash;
	void **wwnhash;			/* struct dev_info */
	void **ctx_hash;		/* struct ctx_info_t */
	void **win_syscall_hash;	/* struct addr_to_idx_hash_entry_t */
	void **win_dpc_hash;		/* struct addr_to_idx_hash_entry_t */
	short *syscall_index_32;
	short *syscall_index_64;
	/* for optional irq processing */
	struct irq_info	*irqp;
	struct irq_info	*softirqp;
	void **irqname_hash;		
	void **dpcname_hash;		
	symtable_t *symtable;

	/* for block_rq cmd_flags interpretation.  */
	char **io_flags;		/* based off os_vers */
	char **req_op;
	uint64 req_op_mask;
	uint64	cmd_flag_mask;
	int	req_op_shift;
	int	cmd_flag_shift;
	uint64 sync_bit;		/* varies based on os_vers, used for Barrier I/O detection */
	
	char **gfp_flags;		/* based off os_vers */

	/* for global HT stats */
	uint64 ht_total_time;
	uint64 ht_double_idle;
	uint64 ht_lcpu1_busy;
	uint64 ht_lcpu2_busy;
	uint64 ht_double_busy;

	uint64 memkb;
	struct iostats	miostats[3];    /* TOTAL=0/READ=1/WRITE=2 */
	warn_t *warnings;		/* array of warnings and notes found */
	int next_warning;		/* to use with the array of warnings */
	int server_id;			/* index into server_table array */
	double total_secs;
	unsigned int kiversion;
	int	nsyms;
	int total_buffers;
	int total_events;
	int missed_buffers;
	int missed_events;
	int next_sid;
	int total_traces;
	int nldom;
	int ncpu;
	int nlcpu;	
	int ndevs;
	int futex_cnt;
	uint32 cache_insert_cnt;
	uint32 cache_evict_cnt;
	char HT_enabled;
	char SNC_enabled;
	char VM_guest;
	char MSR_enabled;
	float clk_mhz;

	/* Kernel Side Channel Attacks (Spectre/Meltdown) fixes */
	int scavuln;

	/* network info */
	int num_tcp_timeouts;
	uint64 tcp_timeout_time;
} server_info_t;

/* hash of pids belonging to same docker container */
typedef struct dkpid_info {
	lle_t			lle;
	pid_info_t		*pidp;
	docker_info_t		*dockerp;
} dkpid_info_t;

typedef struct clpid_info {
	lle_t			lle;
	pid_info_t		*pidp;
	server_info_t		*globals;
} clpid_info_t;

typedef struct clfdata_info {
	lle_t			lle;
	uint64			dev;
	uint32			node;
	fdata_info_t		*fdatap;
	server_info_t		*globals;
} clfdata_info_t;

typedef struct cldev_info {
	lle_t			lle;
	dev_info_t		*devinfop;
	server_info_t		*globals;
} cldev_info_t;

typedef struct clfutex_info {
	lle_t			lle;
	gbl_futex_info_t	*futexp;
	server_info_t		*globals;
} clfutex_info_t; 

typedef struct clipip_info {
	lle2_t			lle;
	ipip_info_t		*ipipp;
	server_info_t		*globals;
} clipip_info_t;

typedef struct clip_info {
	lle_t			lle;
	ip_info_t		*ipp;
	server_info_t		*globals;
} clip_info_t;

typedef struct clsdata_info {
	lle2_t			lle;
	sdata_info_t		*sdatap;
	server_info_t		*globals;
} clsdata_info_t;

/* Type definitions */

typedef struct sid_info sid_info_t;
typedef struct sid_pid	sid_pid_t;
typedef struct syscall_info syscall_info_t;
typedef struct fd_stats fd_stats_t;
typedef struct sd_stats sd_stats_t;
typedef struct logio_info logio_info_t;
typedef struct logio_stats logio_stats_t;
typedef struct ora_stats ora_stats_t;
typedef struct arg_info arg_info_t;
typedef struct irq_info irq_info_t;
typedef struct win_syscall_save_entry win_syscall_save_t;

/* Global Varibles */

extern uint64 kiinfo_flags;
extern uint64 kiinfo_stats;
extern char arch_flag;
extern char html_flag;
extern char	*cwd;
extern char *warnurl_dir;
extern struct ki_config ki_cf;
extern server_info_t *server[];
extern clpid_info_t **clpid_hash;
extern clfdata_info_t **clfdata_hash;
extern cldev_info_t **cldev_hash;
extern cldev_info_t **clmdev_hash;
extern clfutex_info_t **clfutex_hash;
extern clipip_info_t **clipip_hash;
extern clip_info_t **cllip_hash;
extern clsdata_info_t **clsdata_hash;
extern int 	nservers;
extern int	max_cstate;
extern char	collapse_on;
extern uint64   gbl_irq_time;
extern int 	mapper_major;
extern uint64 idle_time_buckets[];
extern pth_class_entry_t gl_pth_class_tbl[];
extern server_info_t *globals;
extern server_info_t   *prev_int_serverp;
extern server_info_t   *curr_int_serverp;
extern runq_info_t ldrq[];
extern runq_info_t     prev_int_ldrq[];        /* Two runq_info_t's to track delta stats */
extern runq_info_t     curr_int_ldrq[];        /* for 100ms interval CPU summary.  See   */

extern sid_info_t sid_table[];
extern uint64 dsk_io_sizes[];
extern vtxt_preg_t objfile_preg;
extern int next_sid;
extern char fsep;		/* field separator */
extern char *tab;
extern char *tab0;
extern char *tab4;
extern char *tab8;
extern char *tab12;
extern char *tab16;
extern char line[];		/* used for HTML processing */
extern int  lineno;		/* used for GREY line processing (HTML) and cursors */
extern int  col;		/* used for cursors */
extern uint64 warn0;
extern char *tlabel;
extern char *plabel;

extern uint64 idle_pc;
extern uint64 ogetblk_pc;
extern uint64 biowait_pc;
extern uint64 waitforpageio_pc;
extern uint64 physio1_pc;
extern uint64 physio2_pc;
extern uint64 vx_fbiowait_pc;
extern uint64 pfn_cache_pc;
extern uint64 fcache_iowait_pc;
extern uint64 vx_recsmp_rangelock_pc;
extern uint64 vx_recsmp_lock_pc;
extern uint64 vx_rwsleep_rec_lock_pc;
extern uint64 busywait_pc;
extern uint64 btree_prune_chunks_pc;
extern uint64 chunk_is_invalid_pc;
extern uint64 bcvalloc_pc;
extern uint64 setfclrange_pc;
extern uint64 vx_dnlc_purge_ip_pc;
extern uint64 vx_dnlc_purge_iplist_pc;
extern uint64 vx_cbdnlc_purge_ip_pc;
extern uint64 vx_cbdnlc_purge_iplist_pc;
extern uint64 vx_cbdnlc_purge_chklist_pc;
extern uint64 vx_ifree_scan_list_pc;
extern uint64 vx_inode_free_list_pc;
extern uint64 vx_inode_free_pc;
extern uint64 vx_inactive_list_pc;
extern uint64 vx_worklist_process_pc;
extern uint64 vx_vnode_flush_pc;
extern uint64 vasusage_pc;
extern uint64 vasusage_vmtotal_pc;
extern uint64 kalloc_contiguous_memory_pc;
extern uint64 vx_extsearchanyodd_pc;
extern uint64 vx_dirscan_pc;
extern uint64 vx_dirbread_pc;
extern uint64 wire_pages_pc;
extern uint64 cold_bring_in_pages_pc;

extern char *ftype_name_index[];
extern char *ioflags_name_2[];
extern char *ioflags_name_2_6_36[];
extern char *ioflags_name_2_6_37[];
extern char *ioflags_name_2_6_39[];
extern char *ioflags_name_3_0[];
extern char *ioflags_name_3_2[];
extern char *ioflags_name_3_6[];
extern char *ioflags_name_4[];
extern char *ioflags_name_4_8[];
extern char *ioflags_name_4_10[];
extern char *ioflags_name_4_15[];
extern char *req_op_name_2[];
extern char *req_op_name_4_8[];
extern char *req_op_name_4_10[];
extern char *gfp_name_3_0[];
extern char *gfp_name_4_0[];
extern char *gfp_name_4_4[];
extern char *gfp_name_4_10[];
extern char *gfp_name_4_13[];
extern char *sotype_name_index[];
extern char *fstype_name_index[];
extern char *cpustate_name_index[];
extern char *sched_policy_name[];
extern char *futex_privopcode_name[];
extern char *futex_opcode_name[];
extern char *fcntl_cmd_name[];
extern char *subtype_name_index[];
extern char *softirq_name[];
extern char *scsi_opcode_name[];
extern char *kr_name_index[];
extern char *kpdata_name_index[];
extern char *socktype_name_index[];
extern warnmsg_t warnmsg[];
extern syscall_arg_list_t *syscall_arg_list;
extern syscall_arg_list_t linux_syscall_arg_list[];
extern syscall_arg_list_t win_syscall_arg_list[];
extern ks_action_t ks_actions[];
extern arg_action_t arg_actions[];
extern short syscall_index_x86_64[];
extern short syscall_index_x86_32[];
extern short syscall_index_aarch_64[];
extern short syscall_index_ppc64le[];
extern short syscall_index_win[];
extern int cpu2ldom[MAXCPUS*2][2];
extern char *win_thread_state[];
extern char *win_thread_mode[];
extern char *win_thread_wait_reason[];
extern char *win_irq_flags[];

extern void hex_dump(void *, int);
extern int incr_trc_stats(void *, void *);

extern char input_str[];
extern char util_str[];

#define __NUM_access 21
#define __NUM_creat 85
#define __NUM_execve 59
#define __NUM_io_getevents 208
#define __NUM_io_submit 209
#define __NUM_lstat 6
#define __NUM_open 2
#define __NUM_openat 257
#define __NUM_poll 7
#define __NUM_ppoll 271
#define __NUM_pread64 17
#define __NUM_pselect6 270
#define __NUM_pwrite64 18
#define __NUM_read 0
#define __NUM_readv 19
#define __NUM_recvfrom 45
#define __NUM_recvmmsg 299
#define __NUM_recvmsg 47
#define __NUM_select 23
#define __NUM_sendmmsg 307
#define __NUM_sendmsg 46
#define __NUM_sendto 44
#define __NUM_splice 275
#define __NUM_stat 4
#define __NUM_unlink 87
#define __NUM_unlinkat 263
#define __NUM_vmsplice 278
#define __NUM_write 1
#define __NUM_writev 20
