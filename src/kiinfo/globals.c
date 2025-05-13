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

#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "info.h"
#include "developers.h"
#include "kd_types.h"
#include "msgcat.h"

#define UKN (KI_MAXSYSCALLS-1)

server_info_t *server[MAX_SERVERS];
int		nservers = 0;
server_info_t	*globals;		/* The current server_info that KI is working on  */
server_info_t	*prev_int_serverp;	/* Two time server_info_t's to perform 100ms	*/
server_info_t	*curr_int_serverp;	/* interval stats delta calculations with. See	*/
					/* kiall_interval_processing() for details.	*/

runq_info_t	ldrq[MAXLDOMS];
runq_info_t	prev_int_ldrq[MAXLDOMS];	/* Two runq_info_t's to track delta stats */
runq_info_t	curr_int_ldrq[MAXLDOMS];	/* for 100ms interval CPU summary.  See   */

cstate_info_t  	cstates[NCSTATES];


uint64		gbl_irq_time = 0;
int		max_cstate = 0;
int		cstate_names = 0;

/* globals hash tables for cluster collections */
clpid_info_t	**clpid_hash;		/* this is the globals pid hash table.  The PID and Server ID is needed to hash into this pid. */
clfdata_info_t	**clfdata_hash;
cldev_info_t	**cldev_hash;
cldev_info_t	**clmdev_hash;
clfutex_info_t  **clfutex_hash;
clipip_info_t	**clipip_hash;
clip_info_t	**cllip_hash;
clsdata_info_t	**clsdata_hash;

ntstatus_info_t **ntstatus_hash;

char 	collapse_on = FALSE;		/* Used in COLLASPE_ macros */
int	mapper_major = 253;		/* default */

sid_info_t sid_table[SID_TBLSZ];
vtxt_preg_t 	objfile_preg;		/* special pregion for objfile= option */

int next_sid = 1;
uint64 idle_time_buckets[IDLE_TIME_NBUCKETS-1]={
        10, 20, 50, 100, 250, 500, 750, 1000, 1250, 1500, 2000, 3000, 5000, 10000, 20000};
char input_str[4096];
char util_str[4096];
char *warnurl_dir = "http://htmlpreview.github.io/?https://github.com/HewlettPackard/LinuxKI/blob/master/documentation";
char *tab = "\0";    /* report indentation variable; */
char *tab0 = "\0";    /* report indentation variable; */
char *tab4 = "    ";
char fsep = ' ';	/* field separator */
int lineno=0;
int col=0;
char line[2048];
int font_color;

uint64 dsk_io_sizes[NBUCKETS-1]={ 2, 5, 10, 15, 30, 50, 100, 150, 200};

char *socktype_name_index[11] = {
	"0-ukn",
	"TCP",
	"UDP",
	"IP",
	"RDM",
	"SEQPACKET",
	"DCCP",
	"7-ukn",
	"8-ukn",
	"9-ukn",
	"PACKET"
};

char *ftype_name_index[F_TYPES] = {
	"0-ukn",
	"REG",
	"CHR",
	"BLK",
	"FIFO",
	"DIR",
	"sock",
	"unix",
	"IPv4",
	"IPv6",
	"netlink",
	"0000"
};

/* for 2.x kernels */
char *ioflags_name_2[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"DISCARD",
	"SORTED",
	"SOFTBARRIER",
	"HARDBARRIER",
	"FUA",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ORDERED_COLOR",
	"SYNC",
	"ALLOCED",
	"META",
	"COPY_USER",
	"INTEGRITY",
	"NOIDLE",
	 NULL, 		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"FLUSH",
	"FLUSH_SEQ",
	NULL,	
	NULL,
	NULL,
	NULL,
	NULL	
};

/* for 2.6.36 kernels */
char *ioflags_name_2_6_36[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"HARDBARRIER",
	"SYNC",
	"META",
	"DISCARD",
	"NOIDLE",
	"UNPLUG",
	"FUA",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ORDERED_COLOR",
	"ALLOCED",
	"COPY_USER",
	"INTEGRITY",
	"FLUSH",
	 NULL, 		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"SECURE",
	NULL,	
	NULL,
	NULL,
	NULL,
	NULL,
	NULL	
};

/* for 2.6.37 kernels */
char *ioflags_name_2_6_37[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"DISCARD",
	"NOIDLE",
	"UNPLUG",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"FUA",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH",
	 NULL, 		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"SECURE",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL	
};

/* for 2.6.39 kernels */
char *ioflags_name_2_6_39[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"DISCARD",
	"NOIDLE",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"FUA",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH",
	"FLUSH_SEQ",
	 NULL, 		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"SECURE",
	"ON_PLUG",
	NULL,
	NULL,
	NULL,
	NULL	
};

/* for 3.0 kernels */
char *ioflags_name_3_0[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"DISCARD",
	"NOIDLE",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"FUA",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH",
	"FLUSH_SEQ",
	 NULL,     		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"SECURE",
	"KERNEL",
	NULL,
	NULL,
	NULL,
	NULL
};

/* for 3.2 - 3.5 kernels */
char *ioflags_name_3_2[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"DISCARD",
	"SECURE",
	"NOIDLE",
	"FUA",
	"FLUSH",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH_SEQ",
	 NULL,     		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"KERNEL",
	NULL,
	NULL,
	NULL
};

/* for 3.8 - 3.17 */
char *ioflags_name_3_6[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"DISCARD",
	"SECURE",
	"WRITE_SAME",
	"NOIDLE",
	"FUA",
	"FLUSH",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH_SEQ",
	 NULL,     		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"KERNEL",
	"PM",			/* added in 3.10 kernels */
	"END"		     	/* added in 3.10 kernels */
	/* NRBITS is only 32 bits for now */
	/* , "HASHED" */     	/* added in 3.15 */
	/* , "MQ_INFLIGHT" */   /* addind in 3.16 */
};

/* for 3.18 -  4.7 */
char *ioflags_name_4[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"DISCARD",
	"SECURE",
	"WRITE_SAME",
	"NOIDLE",
	"INTEGRITY",		/* added in 3.18 */
	"FUA",
	"FLUSH",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH_SEQ",
	 NULL,     		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"PM"
	"HASHED",
  	/* NRBITS is only 32 bits for now, so skip the rest!  
 	 * "MQ_INFLIGHT",									
	 * "MQ_NOTIMEOUT"        * added in 3.19, removed in 4.5
	 */
};

/* for 4.8 -  4.9 */
char *ioflags_name_4_8[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"NOIDLE",
	"INTEGRITY",		/* added in 3.18 */
	"FUA",
	"PREFLUSH",
	"RAHEAD",
	"THROTTLED",
	"SORTED",
	"SOFTBARRIER",
	"NOMERGE",
	"STARTED",
	"DONTPREP",
	"QUEUED",
	"ELVPRIV",
	"FAILED",
	"QUIET",
	"PREEMPT",
	"ALLOCED",
	"COPY_USER",
	"FLUSH_SEQ",
	 NULL,     		/* Do not print "IO_STAT" */
	"MIXED_MERGE",
	"PM",
	"HASHED",  	
 	"MQ_INFLIGHT",									
	NULL,
	NULL
};

char *ioflags_name_4_10[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"NOMERGE",
	"IDLE",
	"INTEGRITY",
	"FUA",
	"PREFLUSH",
	"RAHEAD",
	"BACKGROUND",
	"NOUNMAP",  	/* introduced in 4.12 */
	"NOWAIT",       /* introduced in 4.13 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *ioflags_name_4_15[REQ_NRBIT] = {
	"FAILFAST_DEV",
	"FAILFAST_TRANSPORT",
	"FAILFAST_DRIVER",
	"SYNC",
	"META",
	"PRIO",
	"NOMERGE",
	"IDLE",
	"INTEGRITY",
	"FUA",
	"PREFLUSH",
	"RAHEAD",
	"BACKGROUND",
	"NOWAIT",
	"NOUNMAP",
	"DRV",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *gfp_name_3_0[GFP_NRBIT] = {
	NULL,
	"DMA",
	"HIGHMEM",
	"DMA32",
	"MOVABLE",
	"WAIT",
	"HIGH",
	"IO",
	"FS",
	"COLD",
	"NOWARN",
	"REPEAT",
	"NOFAIL",
	"NORETRY",
	"MEMALLOC",
	"COMP",
	"ZERO",
	"NOMEMALLOC",
	"HARDWALL",
	"THISNODE",
	"RECLAIMABLE",
	"KMEMCG",
	"NOTRACK",
	"NO_KSWAPD",
	"OTHER_NODE"
	"WRITE",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *gfp_name_4_0[GFP_NRBIT] = {
	NULL,
	"DMA",
	"HIGHMEM",
	"DMA32",
	"MOVABLE",
	"WAIT",
	"HIGH",
	"IO",
	"FS",
	"COLD",
	"NOWARN",
	"REPEAT",
	"NOFAIL",
	"NORETRY",
	"MEMALLOC",
	"COMP",
	"ZERO",
	"NOMEMALLOC",
	"HARDWALL",
	"THISNODE",
	"ATOMIC",
	"NOACCOUNT",
	"NOTRACK",
	"NO_KSWAPD",
	"OTHER_NODE"
	"WRITE",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *gfp_name_4_4[GFP_NRBIT] = {
	NULL,
	"DMA",
	"HIGHMEM",
	"DMA32",
	"MOVABLE",
	"RECLAIMABLE",
	"HIGH",
	"IO",
	"FS",
	"COLD",
	"NOWARN",
	"REPEAT",
	"NOFAIL",
	"NORETRY",
	"MEMALLOC",
	"COMP",
	"ZERO",
	"NOMEMALLOC",
	"HARDWALL",
	"THISNODE",
	"ATOMIC",
	"ACCOUNT",
	"NOTRACK",
	"DIRECT_RECLAIM",
	"OTHER_NODE",
	"WRITE",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *gfp_name_4_10[GFP_NRBIT] = {
	NULL,
	"DMA",
	"HIGHMEM",
	"DMA32",
	"MOVABLE",
	"RECLAIMABLE",
	"HIGH",
	"IO",
	"FS",
	"COLD",
	"NOWARN",
	"REPEAT",
	"NOFAIL",
	"NORETRY",
	"MEMALLOC",
	"COMP",
	"ZERO",
	"NOMEMALLOC",
	"HARDWALL",
	"THISNODE",
	"ATOMIC",
	"ACCOUNT",
	"NOTRACK",
	"DIRECT_RECLAIM",
	"WRITE",
	"KSWAPD_RECLAIM",
	"NOLOCKDEP",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

char *gfp_name_4_13[GFP_NRBIT] = {
	NULL,
	"DMA",
	"HIGHMEM",
	"DMA32",
	"MOVABLE",
	"RECLAIMABLE",
	"HIGH",
	"IO",
	"FS",
	"COLD",		/* removed in 4.15 */
	"NOWARN",
	"RETRY_MAYFAIL",
	"NOFAIL",
	"NORETRY",
	"MEMALLOC",
	"COMP",
	"ZERO",
	"NOMEMALLOC",
	"HARDWALL",
	"THISNODE",
	"ATOMIC",
	"ACCOUNT",
	"GFP_NOTRACK",	/* removed in 4.15 */
	"DIRECT_RECLAIM",
	"WRITE",
	"KSWAPD_RECLAIM",
	"NOLOCKDEP",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};





char *req_op_name_2[36] = {
	"read",
	"write",
	"ukn-2",
	"ukn-3",
	"ukn-4",
	"ukn-5",
	"ukn-6",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"ukn-10",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15",
	"ukn-16",
	"ukn-17",
	"ukn-18",
	"ukn-19",
	"ukn-20",
	"ukn-21",
	"ukn-22",
	"ukn-23",
	"ukn-24",
	"ukn-25",
	"ukn-26",
	"ukn-27",
	"ukn-28",
	"ukn-29",
	"ukn-30",
	"ukn-31",
	"ukn-32",
	"ukn-33",
	"ukn-34",
	"ukn-35"
};

char *req_op_name_4_8[36] = {
	"read",
	"write",
	"discard",
	"secure_erase",
	"write_same",
	"flush", 
	"ukn-6",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"ukn-10",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15",
	"ukn-16",
	"ukn-17",
	"ukn-18",
	"ukn-19",
	"ukn-20",
	"ukn-21",
	"ukn-22",
	"ukn-23",
	"ukn-24",
	"ukn-25",
	"ukn-26",
	"ukn-27",
	"ukn-28",
	"ukn-29",
	"ukn-30",
	"ukn-31",
	"ukn-32",
	"ukn-33",
	"ukn-34",
	"ukn-35"
};

char *req_op_name_4_10[36] = {
	"read",
	"write",
	"flush",
	"discard",
	"zone_report",
	"secure_erase",
	"zone_reset",
	"write_same",
	"write_zero",	
	"write_zero",		/* in 4.12, REQ_OP_WRITE_ZEROES was changed from 8 to 9, but 8 is currently unused */
	"ukn-10",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15",
	"ukn-16",
	"ukn-17",
	"ukn-18",
	"ukn-19",
	"ukn-20",
	"ukn-21",
	"ukn-22",
	"ukn-23",
	"ukn-24",
	"ukn-25",
	"ukn-26",
	"ukn-27",
	"ukn-28",
	"ukn-29",
	"ukn-30",
	"ukn-31",
	/* introduced in 4.11 */
	"scsi_in",
	"scsi_out",
	"dvr_in",
	"dvr_out"
};

char *cpustate_name_index[5] = {
        "USER",
        "SYS",
        "IDLE",
        "INTR",
        "FLT"
};

char *sched_policy_name[10] = {
	"SCHED_NORMAL",
	"SCHED_FIFO",
	"SCHED_RR",
	"SCHED_BATCH",
	"SCHED_ISO",
	"SCHED_IDLE"
};

char *futex_opcode_name[13] = {
        "FUTEX_WAIT",
        "FUTEX_WAKE",
        "FUTEX_FD",
        "FUTEX_REQUEUE",
        "FUTEX_CMP_REQUEUE",
        "FUTEX_WAKE_OP",
        "FUTEX_LOCK_PI",
        "FUTEX_UNLOCK_PI",
        "FUTEX_TRYLOCK_PI",
        "FUTEX_WAIT_BITSET",
        "FUTEX_WAKE_BITSET",
        "FUTEX_WAIT_REQUEUE_PI",
        "FUTEX_CMP_REQUEUE_PI"
};

char *futex_privopcode_name[13] = {
        "FUTEX_WAIT_PRIVATE",
        "FUTEX_WAKE_PRIVATE",
        "FUTEX_FD_PRIVATE",
        "FUTEX_REQUEUE_PRIVATE",
        "FUTEX_CMP_REQUEUE_PRIVATE",
        "FUTEX_WAKE_OP_PRIVATE",
        "FUTEX_LOCK_PI_PRIVATE",
        "FUTEX_UNLOCK_PI_PRIVATE",
        "FUTEX_TRYLOCK_PI_PRIVATE",
        "FUTEX_WAIT_BITSET_PRIVATE",
        "FUTEX_WAKE_BITSET_PRIVATE",
        "FUTEX_WAIT_REQUEUE_PI_PRIVATE",
        "FUTEX_CMP_REQUEUE_PI_PRIVATE"
};

char *fcntl_cmd_name[17] = {
	"F_DUPFD",
	"F_GETFD",
	"F_SETFD",
	"F_GETFL",
	"F_SETFL",
	"F_GETLK",
	"F_SETLK",
	"F_SETLKW",
	"F_SETOWN",
	"F_GETOWN",
	"F_SETSIG",
	"F_GETSIG"
	"F_GETLK64",
	"F_SETLK64",
	"F_SETLKW64",
	"F_SETOWN_EX",
	"F_GETOWN_EX"
};

char *softirq_name[10] = {
	"HI",
	"TIMER",
	"NET_TX",
	"NET_RX",
	"BLOCK",
	"BLOCK_IOPOLL",
	"TASKLET",
	"SCHED",
	"HRTIMER",
	"RCU"
};

/* see plugin_scsi.c */
char *scsi_opcode_name[MAX_SCSI_OPCODE] = {
	"TEST_UNIT_READY",
	"REZERO_UNIT",		/* 0x1 */
	"0x2",
	"REQUEST_SENSE",	/* 0x3 */
	"FORMAT_UNIT",		/* 0x4 */
	"READ_BLOCK_LIMITS",	/* 0x5 */
	"0x6",
	"REASSIGN_BLOCKS",	/* 0x7 */
	"READ_6",		/* 0x8 */
	"0x9",
	"WRITE_6",		/* 0xa */
	"SEEK_6",		/* 0xb */
	"0xc",			/* 0xc */
	"0xd",			/* 0xd */
	"0xe",			/* 0xe */
	"READ_REVERSE", 	/* 0xf */
	"WRITE_FILEMARKS",	/* 0x10 */
	"SPACE",		/* 0x11 */
	"INQUIRY",		/* 0x12 */
	"0x13",			/* 0x13 */
	"RECOVER_BUFFERED_DATA", /* 0x14 */
	"MODE_SELECT",		/* 0x15 */
	"RESERVE",		/* 0x16 */
	"RELEASE",		/* 0x17 */
	"COPY",
	"ERASE",
	"MODE_SENSE",
	"START_STOP",
	"RECEIVE_DIAGNOSTIC",
	"SEND_DIAGNOSTIC",
	"ALLOW_MEDIUM_REMOVAL",
	"0x1f",
	"0x20",
	"0x21",
	"0x22",
	"0x23",
	"SET_WINDOW",
	"READ_CAPACITY",
	"0x26",
	"0x27",
	"READ_10",
	"0x29",
	"WRITE_10",
	"SEEK_10",
	"0x2c",
	"0x2d",
	"WRITE_VERIFY",
	"VERIFY",
	"SEARCH_HIGH",
	"SEARCH_EQUAL",
	"SEARCH_LOW",
	"SET_LIMITS",
	"READ_POSITION",
	"SYNCHRONIZE_CACHE",		/* 0x35 */
	"LOCK_UNLOCK_CACHE",		/* 0x36 */
	"READ_DEFECT_DATA",		/* 0x37 */
	"MEDIUM_SCAN",			/* 0x38 */
	"COMPARE",			/* 0x39 */
	"COPY_VERIFY",			/* 0x3a */
	"WRTE_BUFFER",			/* 0x3b */
	"READ_BUFFER",			/* 0x3c */
	"UPDATE_BLOCK",			/* 0x3d */
	"READ_LONG",			/* 0x3e */
	"WRITE_LONG",			/* 0x3f */
	"CHANE_DEFINITION",		/* 0x40 */
	"WRITE_SAME",			/* 0x41 */
	"0x42",
	"READ_TOC",
	"0x44",
	"0x45",
	"0x46",
	"0x47",
	"0x48",
	"0x49",
	"GET_EVENT_STATUS_NOTIFICATION",
	"0x4b",
	"LOG_SELECT",
	"LOG_SENSE",
	"0x4e",
	"0x4f",
	"0x50",
	"0x51",
	"0x52",
	"0x53",
	"0x54", 
	"MODE_SELECT_10",
	"RESERVE_10",
	"RELEASE_10",
	"0x58",
	"0x59",
	"MODE_SENSE_10",
	"0x5b",
	"0x5c",
	"0x5d",
	"PERSISTENT_RESERVE_IN",
	"PERSISTENT_RESERVE_OUT",
	"0x60",
	"0x61",
	"0x62",
	"0x63",
	"0x64",
	"0x65",
	"0x66",
	"0x67",
	"0x68",
	"0x69",
	"0x6a",
	"0x6b",
	"0x6c",
	"0x6d",
	"0x6e",
	"0x6f",
	"0x70",
	"0x71",
	"0x72",
	"0x73",
	"0x74",
	"0x75",
	"0x76",
	"0x77",
	"0x78",
	"0x79",
	"0x7a",
	"0x7b",
	"0x7c",
	"0x7d",
	"0x7e",
	"0x7f",
	"0x80",
	"0x81",
	"0x82",
	"0x83",
	"0x84",
	"0x85",
	"ACCESS_CONTROL_IN",
	"ACCESS_CONTROL_OUT",
	"READ16",
	"COMPARE_AND_WRITE",
	"WRITE16",
	"ORWRITE",		/* 0x8b */
	"0x8c",
	"0x8d",
	"0x8e",
	"0x8f",
	"0x90",
	"SYNCHRONIZE_CACHE16",
	"0x92",
	"0x93",
	"0x94",
	"0x95",
	"0x96",
	"0x97",
	"0x98",
	"0x99",
	"0x9a",
	"0x9b",
	"0x9c",
	"0x9d",
	"0x9e",
	"0x9f",
	"0xa0",
	"0xa1",
	"0xa2",
	"MAINTENANCE_IN",
	"MAINTENANCE_OUT",
	"MOVE_MEDIUM",
	"EXCHANGE_MEDIUM",
	"0xa7",
	"READ_12",
	"SERVICE_ACTION_OUT_12",
	"WRITE_12",
	"SERVICE_ACTION_IN_12",
	"0xac",
	"0xad",
	"WRITE_VERIFY",
	"0xaf",
	"SEARCH_HIGH_12",
	"SEACH_EQUAL_12",
	"SEARCH_LOW_12",
	"0xb3",
	"0xb4",
	"0xb5",
	"SEND_VOLUME_TAG",
	"0xb7",
	"READ_ELEMENT_STATUS",
	"0xb9",
	"0xba",
	"0xbb",
	"0xbc",
	"0xbd",
	"0xbe",
	"0xbf",
	"0xc0",
	"0xc1",
	"0xc2",
	"0xc3",
	"0xc4",
	"0xc5",
	"0xc6",
	"0xc7",
	"0xc8",
	"0xc9",
	"0xra",
	"0xcb",
	"0xcc",
	"0xcd",
	"0xce",
	"0xcf",
	"0xd0",
	"0xd1",
	"0xd2",
	"0xd3",
	"0xd4",
	"0xd5",
	"0xd6",
	"0xd7",
	"0xd8",
	"0xd9",
	"0xda",
	"0xdb",
	"0xdc",
	"0xdd",
	"0xde",
	"0xdf",
	"0xe0",
	"0xe1",
	"0xe2",
	"0xe3",
	"0xe4",
	"0xe5",
	"0xe6",
	"0xe7",
	"0xe8",
	"0xe9",
	"WRITE_LONG_2",
	"0xeb",
	"0xec",
	"0xed",
	"0xee",
	"0xef",
	"0xf0",
	"0xf1",
	"0xf2",
	"0xf3",
	"0xf4",
	"0xf5",
	"0xf6",
	"0xf7",
	"0xf8",
	"0xf9",
	"0xfa",
	"0xfb",
	"0xfc",
	"0xfd",
	"0xfe",
	"0xff"
};


kdtype_attr_t block_rq_abort_attr[] = {
	{"dev_t dev", 12, 4, 0},
	{"sector_t sector", 16, 8, 0},
	{"int nr_sector", 24, 4, 0},
	{"char rwbs", 32, 8, 0},
	{"int errors", 28, 4, 0},
	{"char[] cmd", 40, 4, 0}, 
	{NULL, 0, 0, 0}
};

kdtype_attr_t block_rq_requeue_attr[] = {
	{"dev_t dev", 12, 4, 0},
	{"sector_t sector", 16, 8, 0},
	{"int nr_sector", 24, 4, 0},
	{"char rwbs", 32, 8, 0},
	{"int errors", 28, 4, 0},
	{"char[] cmd", 40, 4, 0}, 
	{NULL, 0, 0, 0}
};

kdtype_attr_t block_rq_insert_attr[] = {
	{"dev_t dev", 12, 4, 0},
	{"sector_t sector", 16, 8, 0},
	{"int nr_sector", 24, 4, 0},
	{"char rwbs", 32, 8, 0},
	{"int bytes", 28, 4, 0},
	{"char[] cmd", 56, 4, 0}, 
	{"char comm[", 40, 16, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t block_rq_issue_attr[] = {
	{"dev_t dev", 12, 4, 0},
	{"sector_t sector", 16, 8, 0},
	{"int nr_sector", 24, 4, 0},
	{"char rwbs", 32, 8, 0},
	{"int bytes", 28, 4, 0},
	{"char[] cmd", 56, 4, 0}, 
	{"char comm[", 40, 16, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t block_rq_complete_attr[] = {
	{"dev_t dev", 12, 4, 0},
	{"sector_t sector", 16, 8, 0},
	{"int nr_sector", 24, 4, 0},
	{"char rwbs", 32, 8, 0},
	{"int errors", 28, 4, 0},
	{"char[] cmd", 40, 4, 0}, 
	{NULL, 0, 0, 0}
};

kdtype_attr_t sys_enter_attr[] = {
	{"long id", 16, 8, 0},
	{"long args", 24, 48, 0},
	{"u8 args", 0, 0, 0},
	{"char args", 0, 0, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t sys_exit_attr[] = {
	{"long id", 16, 8, 0},
	{"long ret", 24, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t sched_switch_attr[] = {
	{" prev_comm[", 12, 16, 0},
	{"pid_t prev_pid", 28, 4, 0},
	{"int prev_prio", 32, 4, 0},
	{"long prev_state", 40, 8, 0},
	{" next_comm[", 48, 16, 0},
	{"pid_t next_pid", 64, 4, 0},
	{"int next_prio", 68, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t sched_wakeup_attr[] = {
	{" comm[", 12, 16, 0},
	{"pid_t pid;", 28, 4, 0},
	{"int prio", 32, 4, 0},
	{"int success", 36, 4, 0},
	{"cpu;", 40, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t sched_wakeup_new_attr[] = {
	{" comm[", 12, 16, 0},
	{"pid_t pid;", 28, 4, 0},
	{"int prio", 32, 4, 0},
	{"int success", 36, 4, 0},
	{"int cpu;", 40, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t sched_migrate_task_attr[] = {
	{" comm[", 12, 16, 0},
	{"pid_t pid;", 28, 4, 0},
	{"int prio", 32, 4, 0},
	{"orig_cpu", 36, 4, 0},
	{"dest_cpu", 40, 4, 0},
	{NULL, 0, 0, 0}
};
	

kdtype_attr_t power_start_attr[] = {
	{"u64 type", 16, 8, 0},
	{"u64 state", 24, 8, 0},
	{"u64 cpu_id;", 32, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t power_end_attr[] = {
	{"u64 cpu_id;", 16, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t power_freq_attr[] = {
	{"u64 type", 16, 8, 0},
	{"u64 state", 24, 8, 0},
	{"u64 cpu_id", 32, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t cpu_freq_attr[] = {
	{"u32 state", 8, 4, 0},
	{"u32 cpu_id", 12, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t cpu_idle_attr[] = {
	{"u32 state", 8, 4, 0},
	{"u32 cpu_id", 12, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t irq_handler_entry_attr[] = {
	{"int irq", 12, 4, 0},
	{"char[] name", 16, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t irq_handler_exit_attr[] = {
	{"int irq", 12, 4, 0},
	{"int ret", 16, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t softirq_entry_attr[] = {
	{"int vec", 12, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t softirq_exit_attr[] = {
	{"int vec", 12, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t softirq_raise_attr[] = {
	{"int vec", 12, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t scsi_dispatch_cmd_start_attr[] = {
	{"int hostno", 12, 4, 0},
	{"int channel", 16, 4, 0},
	{"int id", 20, 4, 0},
	{"int lun", 24, 4, 0},
	{"int type", 28, 4, 0},
	{"int opcode", 32, 4, 0},
	{"int cmd_len", 36, 4, 0},
	{"int data_sglen", 40, 4, 0},
	{"int prot_sglen", 44, 4, 0},
	{"cmnd; ", 48, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t scsi_dispatch_cmd_done_attr[] = {
	{"int hostno", 12, 4, 0},
	{"int channel", 16, 4, 0},
	{"int id", 20, 4, 0},
	{"int lun", 24, 4, 0},
	{"int type", 28, 4, 0},
	{"int opcode", 36, 4, 0},
	{"int cmd_len", 40, 4, 0},
	{"int data_sglen", 44, 4, 0},
	{"int prot_sglen", 48, 4, 0},
	{"cmnd; ", 52, 4, 0},
	{"int result", 32, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t workqueue_insertion_attr[] = {
	{"char thread_comm[", 12, 16, 0},
	{"thread_pid;", 28, 4, 0},
	{"work_func_t func", 32, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t workqueue_execution_attr[] = {
	{"char thread_comm[", 12, 16, 0},
	{"thread_pid;", 28, 4, 0},
	{"work_func_t func", 32, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t workqueue_enqueue_attr[] = {
	{" * work;", 8, 8, 0},
	{" * function;", 16, 8, 0},
	{" * workqueue;", 24, 8, 0},
	{"int req_cpu;", 32, 4, 0},
	{"int cpu;", 36, 4, 0},
	{NULL, 0, 0, 0},
};

kdtype_attr_t workqueue_execute_attr[] = {
	{" * work;", 8, 8, 0},
	{" * function;", 16, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t page_fault_attr[] = {
	{"long address;", 8, 8, 0},
	{"long ip;", 16, 8, 0},
	{"long error_code;", 24, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t anon_fault_attr[] = {
	{"mm_struct * mm;", 16, 8, 0},
	{"long address;", 24, 8, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t filemap_fault_attr[] = {
	{"mm_struct * mm;", 16, 8, 0},
	{"long address;", 24, 8, 0},
	{"int flag;", 32, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t kernel_pagefault_attr[] = {
	{"task_struct * task;", 16, 8, 0},
	{"long address;", 24, 8, 0},
	{"pt_regs * regs;", 32, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t filemap_pagecache_attr[] = {
	{"struct page * page;", 8, 8, 0},
	{"long i_ino;", 16, 8, 0},
 	{"long index;", 24, 8, 0},
	{"dev_t s_dev;", 32, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t mm_page_alloc_attr[] = {
	{" * page;", 8, 8, 0},
	{"int order;", 16, 4, 0},
 	{"gfp_t gfp_flags;", 20, 4, 0},
	{"int migratetype;", 24, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t mm_page_free_attr[] = {
	{" * page;", 8, 8, 0},
	{"int order;", 16, 4, 0},
	{NULL, 0, 0, 0}
};

kdtype_attr_t marker_attr[] = {
	{"long ip", 16, 8, 0},
	{"char buf", 24, 0, 0},
	{NULL, 0, 0, 0}
};

ks_action_t ks_actions[KI_MAXSYSCALLS] = {
	{ 1, 1, 1, ki_read},		/*read*/
	{ 1, 1, 1, ki_write},		/*write*/
	{ 1, 0, 0, ki_open},		/*open*/
	{ 1, 0, 1, ki_close},		/*close*/
	{ 0, 0, 0, ki_nosys},		/*stat*/
	{ 0, 0, 1, ki_nosys},		/*fstat*/
	{ 0, 0, 0, ki_nosys},		/*lstat*/
	{ 0, 0, 0, ki_nosys},		/*poll*/
	{ 1, 0, 1, ki_lseek},		/*lseek*/
	{ 0, 0, 0, ki_nosys},		/*mmap*/
	{ 0, 0, 0, ki_nosys},		/*mprotect*/
	{ 0, 0, 0, ki_nosys},		/*munmap*/
	{ 0, 0, 0, ki_nosys},		/*brk*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigaction*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigprocmask*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigreturn*/
	{ 1, 0, 1, ki_ioctl},		/*ioctl*/
	{ 1, 1, 1, ki_read},		/*pread64*/
	{ 1, 1, 1, ki_write},		/*pwrite64*/
	{ 1, 1, 1, ki_read},		/*readv*/
	{ 1, 1, 1, ki_write},		/*writev*/
	{ 0, 0, 0, ki_nosys},		/*access*/
	{ 0, 0, 0, ki_nosys},		/*pipe*/
	{ 0, 0, 0, ki_nosys},		/*select*/
	{ 0, 0, 0, ki_nosys},		/*sched_yield*/
	{ 0, 0, 0, ki_nosys},		/*mremap*/
	{ 0, 0, 0, ki_nosys},		/*msync*/
	{ 0, 0, 0, ki_nosys},		/*mincore*/
	{ 0, 0, 0, ki_nosys},		/*madvise*/
	{ 0, 0, 0, ki_nosys},		/*shmget*/
	{ 0, 0, 0, ki_nosys},		/*shmat*/
	{ 0, 0, 0, ki_nosys},		/*shmctl*/
	{ 1, 0, 1, ki_dup},		/*dup*/
	{ 1, 0, 1, ki_dup2},		/*dup2*/
	{ 0, 0, 0, ki_nosys},		/*pause*/
	{ 0, 0, 0, ki_nosys},		/*nanosleep*/
	{ 0, 0, 0, ki_nosys},		/*getitimer*/
	{ 0, 0, 0, ki_nosys},		/*alarm*/
	{ 0, 0, 0, ki_nosys},		/*setitimer*/
	{ 0, 0, 0, ki_nosys},		/*getpid*/
	{ 0, 0, 1, ki_nosys}, 		/*sendfile*/
	{ 0, 0, 0, ki_nosys}, 		/*socket*/
	{ 0, 0, 1, ki_nosys}, 		/*connect*/
	{ 0, 0, 1, ki_nosys}, 		/*accept*/
	{ 1, 1, 1, ki_nosys}, 		/*sendto*/
	{ 1, 1, 1, ki_nosys}, 		/*recvfrom*/
	{ 0, 1, 1, ki_nosys}, 		/*sendmsg*/
	{ 0, 1, 1, ki_nosys}, 		/*recvmsg*/
	{ 0, 0, 1, ki_nosys},		/*shutdown */
	{ 0, 0, 1, ki_nosys},		/*bind*/
	{ 0, 0, 1, ki_nosys},		/*listen*/
	{ 0, 0, 1, ki_nosys},		/*getsockname*/
	{ 0, 0, 1, ki_nosys},           /*getpeername*/
	{ 0, 0, 0, ki_nosys},		/*socketpair*/
	{ 0, 0, 0, ki_nosys},		/*setsockopt*/
	{ 0, 0, 0, ki_nosys},		/*getsockopt*/
	{ 1, 0, 0, ki_clone},		/*clone*/
	{ 1, 0, 0, ki_fork},		/*fork*/
	{ 1, 0, 0, ki_fork},		/*vfork*/
	{ 1, 0, 0, ki_execve},		/*execve*/
	{ 0, 0, 0, ki_nosys},		/*exit*/
	{ 0, 0, 0, ki_nosys},		/*wait4*/
	{ 0, 0, 0, ki_nosys}, 		/*kill*/
	{ 0, 0, 0, ki_nosys},		/*uname*/
	{ 0, 0, 0, ki_nosys},		/*semget*/
	{ 0, 0, 0, ki_nosys},		/*semop*/
	{ 0, 0, 0, ki_nosys},		/*semctl*/
	{ 0, 0, 0, ki_nosys},		/*shmdt*/
	{ 0, 0, 0, ki_nosys},		/*msgget*/
	{ 0, 0, 0, ki_nosys},		/*msgsnd*/
	{ 0, 0, 0, ki_nosys},		/*msgrcv*/
	{ 0, 0, 0, ki_nosys},		/*msgctl*/
	{ 1, 0, 1, ki_fcntl}, 		/*fcntl*/
	{ 0, 0, 1, ki_nosys}, 		/*flock*/
	{ 0, 0, 1, ki_nosys},		/*fsync*/
	{ 0, 0, 1, ki_nosys}, 		/*fdatasync*/
	{ 0, 0, 0, ki_nosys}, 		/*truncate*/
	{ 0, 0, 1, ki_nosys},		/*ftruncate*/
	{ 0, 0, 1, ki_nosys},		/*getdents*/
	{ 0, 0, 0, ki_nosys},		/*getcwd*/
	{ 0, 0, 0, ki_nosys},		/*chdir*/
	{ 0, 0, 1, ki_nosys},		/*fchdir*/
	{ 0, 0, 0, ki_nosys},		/*rename*/
	{ 0, 0, 0, ki_nosys},		/*mkdir*/
	{ 0, 0, 0, ki_nosys},		/*rmdir*/
	{ 0, 0, 0, ki_nosys},		/*creat*/
	{ 0, 0, 0, ki_nosys},		/*link*/
	{ 0, 0, 0, ki_nosys},		/*unlink*/
	{ 0, 0, 0, ki_nosys},		/*symlink*/
	{ 0, 0, 0, ki_nosys},		/*readlink*/
	{ 0, 0, 0, ki_nosys},		/*chmod*/
	{ 0, 0, 1, ki_nosys},		/*fchmod*/
	{ 0, 0, 0, ki_nosys},		/*chown*/
	{ 0, 0, 1, ki_nosys},		/*fchown*/
	{ 0, 0, 0, ki_nosys},		/*lchown*/
	{ 0, 0, 0, ki_nosys},		/*umask*/
	{ 0, 0, 0, ki_nosys},		/*gettimeofday*/
	{ 0, 0, 0, ki_nosys},		/*getrlimit*/
	{ 0, 0, 0, ki_nosys},		/*getrusage*/
	{ 0, 0, 0, ki_nosys},		/*sysinfo*/
	{ 0, 0, 0, ki_nosys},		/*times*/
	{ 0, 0, 0, ki_nosys},		/*ptrace*/
	{ 0, 0, 0, ki_nosys},		/*getuid*/
	{ 0, 0, 0, ki_nosys},		/*syslog*/
	{ 0, 0, 0, ki_nosys},		/*getgid*/
	{ 0, 0, 0, ki_nosys},		/*setuid*/
	{ 0, 0, 0, ki_nosys},		/*setgid*/
	{ 0, 0, 0, ki_nosys},		/*geteuid*/
	{ 0, 0, 0, ki_nosys},		/*getegid*/
	{ 0, 0, 0, ki_nosys},		/*setpgid*/
	{ 0, 0, 0, ki_nosys},		/*getppid*/
	{ 0, 0, 0, ki_nosys},		/*getpgrp*/
	{ 0, 0, 0, ki_nosys},		/*setsid*/
	{ 0, 0, 0, ki_nosys},		/*setreuid*/
	{ 0, 0, 0, ki_nosys},		/*setregid*/
	{ 0, 0, 0, ki_nosys},		/*getgroups*/
	{ 0, 0, 0, ki_nosys},		/*setgorups*/
	{ 0, 0, 0, ki_nosys},		/*setresuid*/
	{ 0, 0, 0, ki_nosys},		/*getresuid*/
	{ 0, 0, 0, ki_nosys},		/*setresgid*/
	{ 0, 0, 0, ki_nosys},		/*getresgid*/
	{ 0, 0, 0, ki_nosys},		/*getpgid*/ 
	{ 0, 0, 0, ki_nosys},		/*setfsuid*/
	{ 0, 0, 0, ki_nosys},		/*setfsgid*/
	{ 0, 0, 0, ki_nosys},		/*getsid*/
	{ 0, 0, 0, ki_nosys},		/*capget*/
	{ 0, 0, 0, ki_nosys},		/*capset*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigpending*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigtimedwait*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigqueueinfo*/
	{ 0, 0, 0, ki_nosys},		/*rt_sigsuspend*/
	{ 0, 0, 0, ki_nosys},		/*sigaltstack*/
	{ 0, 0, 0, ki_nosys},		/*utime*/
	{ 0, 0, 0, ki_nosys},		/*mknod*/
	{ 0, 0, 0, ki_nosys},		/*uselib*/
	{ 0, 0, 0, ki_nosys},		/*personality*/
	{ 0, 0, 0, ki_nosys},		/*ustat*/
	{ 0, 0, 0, ki_nosys},		/*statfs*/
	{ 0, 0, 0, ki_nosys},		/*fstatfs*/
	{ 0, 0, 1, ki_nosys}, 		/*sysfs*/
	{ 0, 0, 0, ki_nosys},		/*getpriority*/
	{ 0, 0, 0, ki_nosys},		/*setpriority*/
	{ 0, 0, 0, ki_nosys},		/*sched_setparam*/
	{ 0, 0, 0, ki_nosys},		/*sched_getparam*/
	{ 0, 0, 0, ki_nosys},		/*sched_setscheduler*/
	{ 0, 0, 0, ki_nosys},		/*sched_getscheduler*/
	{ 0, 0, 0, ki_nosys},		/*sched_get_priority_max*/
	{ 0, 0, 0, ki_nosys},		/*sched_get_priority_min*/
	{ 0, 0, 0, ki_nosys},		/*sched_rr_get_interval*/
	{ 0, 0, 0, ki_nosys},		/*mlock*/
	{ 0, 0, 0, ki_nosys},		/*munlock*/
	{ 0, 0, 0, ki_nosys},		/*mlockall*/
	{ 0, 0, 0, ki_nosys},		/*munlockall*/
	{ 0, 0, 0, ki_nosys},		/*vhangup*/
	{ 0, 0, 0, ki_nosys},		/*modify_ldt*/
	{ 0, 0, 0, ki_nosys},		/*pivot_root*/
	{ 0, 0, 0, ki_nosys},		/*_sysctl*/
	{ 0, 0, 0, ki_nosys},		/*prctl*/
	{ 0, 0, 0, ki_nosys},		/*arch_prctl*/
	{ 0, 0, 0, ki_nosys},		/*adjtimex*/
	{ 0, 0, 0, ki_nosys},		/*setrlimit*/
	{ 0, 0, 0, ki_nosys},		/*chroot*/
	{ 0, 0, 0, ki_nosys},		/*sync*/
	{ 0, 0, 0, ki_nosys},		/*acct*/
	{ 0, 0, 0, ki_nosys},		/*settimeofday*/
	{ 0, 0, 0, ki_nosys},		/*mount*/
	{ 0, 0, 0, ki_nosys},		/*umount2*/
	{ 0, 0, 0, ki_nosys},		/*swapon*/
	{ 0, 0, 0, ki_nosys},		/*swapoff*/
	{ 0, 0, 0, ki_nosys},		/*reboot*/
	{ 0, 0, 0, ki_nosys},		/*sethostname*/
	{ 0, 0, 0, ki_nosys},		/*setdomainname*/
	{ 0, 0, 0, ki_nosys},		/*iopl*/
	{ 0, 0, 0, ki_nosys},		/*ioperm*/
	{ 0, 0, 0, ki_nosys},		/*create_module*/
	{ 0, 0, 0, ki_nosys},		/*init_module*/
	{ 0, 0, 0, ki_nosys},		/*delete_module*/
	{ 0, 0, 0, ki_nosys},		/*get_kernel_syms*/
	{ 0, 0, 0, ki_nosys},		/*query_module*/
	{ 0, 0, 0, ki_nosys},		/*quotactl*/
	{ 0, 0, 0, ki_nosys},		/*nfsservctl*/
	{ 0, 0, 0, ki_nosys},		/*getpmsg*/
	{ 0, 0, 0, ki_nosys},		/*putpmsg*/
	{ 0, 0, 0, ki_nosys},		/*afs_syscall*/
	{ 0, 0, 0, ki_nosys},		/*tuxcall*/
	{ 0, 0, 0, ki_nosys},		/*security*/
	{ 0, 0, 0, ki_nosys},		/*gettid*/
	{ 0, 0, 1, ki_readahead},     /* execute bit disabled now */
	{ 0, 0, 0, ki_nosys},		/*setxattr*/
	{ 0, 0, 0, ki_nosys},		/*lsetxattr*/
	{ 0, 0, 0, ki_nosys},		/*fsetxattr*/
	{ 0, 0, 0, ki_nosys},		/*getxattr*/
	{ 0, 0, 0, ki_nosys},		/*lgetxattr*/
	{ 0, 0, 0, ki_nosys},		/*fgetxattr*/
	{ 0, 0, 0, ki_nosys},		/*listxattr*/
	{ 0, 0, 0, ki_nosys},		/*llistxattr*/
	{ 0, 0, 0, ki_nosys},		/*flistxattr*/
	{ 0, 0, 0, ki_nosys},		/*removexattr*/
	{ 0, 0, 0, ki_nosys},		/*lremovexattr*/
	{ 0, 0, 0, ki_nosys},		/*fremovexattr*/
	{ 0, 0, 0, ki_nosys},		/*tkill*/
	{ 0, 0, 0, ki_nosys},		/*time*/
	{ 1, 0, 2, ki_futex},		/*futex*/
	{ 0, 0, 0, ki_nosys},		/*sched_setaffinity*/
	{ 0, 0, 0, ki_nosys},		/*sched_getaffinity*/
	{ 0, 0, 0, ki_nosys},		/*set_thread_area*/
	{ 0, 0, 0, ki_nosys},		/*io_setup*/
	{ 0, 0, 0, ki_nosys},		/*io_destroy*/
	{ 1, 0, 0, ki_io_getevents},	/*io_getevents*/
	{ 1, 0, 0, ki_io_submit},	/*io_submit*/
	{ 0, 0, 0, ki_nosys},		/*io_cancel*/
	{ 0, 0, 0, ki_nosys},		/*get_thread_area*/
	{ 0, 0, 0, ki_nosys},		/*lookup_dcookie*/
	{ 0, 0, 0, ki_nosys},		/*epoll_create*/
	{ 0, 0, 0, ki_nosys},		/*epoll_ctl_old*/
	{ 0, 0, 0, ki_nosys},		/*epoll_wait_old*/
	{ 0, 0, 0, ki_nosys},		/*remap_file_pages*/
	{ 0, 0, 1, ki_nosys},		/*getdents64*/
	{ 0, 0, 0, ki_nosys},		/*set_tid_address*/
	{ 0, 0, 0, ki_nosys},		/*restart_syscall*/
	{ 0, 0, 0, ki_nosys},		/*semtimedop*/
	{ 0, 0, 0, ki_nosys},		/*fadvise64*/
	{ 0, 0, 0, ki_nosys},		/*timer_create*/
	{ 0, 0, 0, ki_nosys},		/*timer_settime*/
	{ 0, 0, 0, ki_nosys},		/*timer_gettime*/
	{ 0, 0, 0, ki_nosys},		/*timer_getoverrun*/
	{ 0, 0, 0, ki_nosys},		/*timer_delete*/
	{ 0, 0, 0, ki_nosys},		/*clock_settime*/
	{ 0, 0, 0, ki_nosys},		/*clock_gettime*/
	{ 0, 0, 0, ki_nosys},		/*clock_getres*/
	{ 0, 0, 0, ki_nosys},		/*clock_nanosleep*/
	{ 0, 0, 0, ki_nosys},		/*exit_group*/
	{ 0, 0, 0, ki_nosys},		/*epoll_wait*/
	{ 0, 0, 0, ki_nosys},		/*epoll_ctl_old*/
	{ 0, 0, 0, ki_nosys},		/*tgkill*/
	{ 0, 0, 0, ki_nosys},		/*utimes*/
	{ 0, 0, 0, ki_nosys},		/*vserver*/
	{ 0, 0, 0, ki_nosys},		/*mbind*/
	{ 0, 0, 0, ki_nosys},		/*set_mempolicy*/
	{ 0, 0, 0, ki_nosys},		/*get_mempolicy*/
	{ 0, 0, 0, ki_nosys},		/*mq_open*/
	{ 0, 0, 0, ki_nosys},		/*mq_unlock*/
	{ 0, 0, 0, ki_nosys},		/*mq_timedsend*/
	{ 0, 0, 0, ki_nosys},		/*mq_timedreceive*/
	{ 0, 0, 0, ki_nosys},		/*mq_notify*/
	{ 0, 0, 0, ki_nosys},		/*mq_getsetattr*/
	{ 0, 0, 0, ki_nosys},		/*kexec_load*/
	{ 0, 0, 0, ki_nosys},		/*waitid*/
	{ 0, 0, 0, ki_nosys},		/*add_key*/
	{ 0, 0, 0, ki_nosys},		/*request_key*/
	{ 0, 0, 0, ki_nosys},		/*keyctl*/
	{ 0, 0, 0, ki_nosys},		/*ioprio_set*/
	{ 0, 0, 0, ki_nosys},		/*ioprio_get*/
	{ 0, 0, 0, ki_nosys},		/*ionotify_init*/
	{ 0, 0, 0, ki_nosys},		/*ionotify_add_watch*/
	{ 0, 0, 0, ki_nosys},		/*ionotify_rm_watch*/
	{ 0, 0, 0, ki_nosys},		/*migrate_pages*/
	{ 1, 0, 0, ki_open},		/*openat*/
	{ 0, 0, 0, ki_nosys},		/*mkdirat*/
	{ 0, 0, 0, ki_nosys},		/*mknodat*/
	{ 0, 0, 1, ki_nosys},		/*fchownat*/
	{ 0, 0, 1, ki_nosys},		/*futimesat*/
	{ 0, 0, 0, ki_nosys},		/*fstatat*/
	{ 0, 0, 1, ki_nosys},		/*unlinkat*/
	{ 0, 0, 1, ki_nosys},		/*renameat*/
	{ 0, 0, 1, ki_nosys},		/*linkat*/
	{ 0, 0, 0, ki_nosys},		/*symlinkat*/
	{ 0, 0, 1, ki_nosys},		/*readlinkat*/
	{ 0, 0, 1, ki_nosys},		/*fchmodat*/
	{ 0, 0, 1, ki_nosys},		/*faccessat*/
	{ 0, 0, 0, ki_nosys},		/*pselect6*/
	{ 0, 0, 0, ki_nosys},		/*ppoll*/
	{ 0, 0, 0, ki_nosys},		/*unshare*/
	{ 0, 0, 0, ki_nosys},		/*set_robust_list*/
	{ 0, 0, 0, ki_nosys},		/*get_robust_list*/
	{ 1, 1, 1, ki_splice},		/*splice*/
	{ 0, 0, 1, ki_nosys},		/*tee*/
	{ 0, 0, 1, ki_nosys},		/*sync_file_range*/
	{ 1, 1, 1, ki_write},		/*vmsplice*/
	{ 0, 0, 0, ki_nosys},		/*move_pages*/
	{ 0, 0, 1, ki_nosys},		/*utimensat*/
	{ 0, 0, 0, ki_nosys},		/*epoll_pwait*/
	{ 0, 0, 1, ki_nosys},		/*signalfd*/
	{ 0, 0, 0, ki_nosys},		/*timerfd_create*/
	{ 0, 0, 0, ki_nosys},		/*eventfd*/
	{ 0, 0, 1, ki_nosys},		/*fallocate*/
	{ 0, 0, 1, ki_nosys},		/*timerfd_settime*/
	{ 0, 0, 1, ki_nosys},		/*timerfd_gettime*/
	{ 0, 0, 1, ki_nosys},		/*accept4*/
	{ 0, 0, 1, ki_nosys},		/*signalfd4*/
	{ 0, 0, 0, ki_nosys},		/*eventfd2*/
	{ 0, 0, 0, ki_nosys},		/*epoll_create1*/
	{ 0, 0, 1, ki_nosys},		/*dup3*/
	{ 0, 0, 0, ki_nosys},		/*pipe2*/
	{ 0, 0, 0, ki_nosys},		/*inotify_init1*/
	{ 1, 1, 1, ki_read},		/*preadv*/
	{ 1, 1, 1, ki_write},		/*pwritev*/
	{ 0, 0, 0, ki_nosys},		/*rt_tsigqueueinfo*/
	{ 0, 0, 0, ki_nosys},		/*perf_event_open*/
	{ 0, 1, 1, ki_nosys},		/*recvmmsg*/
	{ 0, 0, 0, ki_nosys},		/*fanotify_init*/
	{ 0, 0, 0, ki_nosys},		/*fanotify_mark*/
	{ 0, 0, 0, ki_nosys},		/*prlimit64*/
	{ 0, 0, 0, ki_nosys},		/*name_to_handle_at*/
	{ 0, 0, 0, ki_nosys},		/*open_by_handle_at*/
	{ 0, 0, 0, ki_nosys},		/*clock_adj_time*/
	{ 0, 0, 0, ki_nosys},		/*syncfs*/
	{ 0, 1, 1, ki_nosys},		/*sendmmsg*/
	{ 0, 0, 0, ki_nosys},		/*set_ns*/
	{ 0, 0, 0, ki_nosys},		/*get_cpu*/
	{ 0, 0, 0, ki_nosys},		/*process_vm_readv*/
	{ 0, 0, 0, ki_nosys},		/*process_vm_writev*/
	{ 0, 0, 0, ki_nosys},		/*kcmp*/
	{ 0, 0, 0, ki_nosys},		/*finit_module*/
	{ 0, 0, 0, ki_nosys},		/*sched_setattr*/
	{ 0, 0, 0, ki_nosys},		/*sched_getattr*/
	{ 0, 0, 0, ki_nosys},		/*renameat2*/
	{ 0, 0, 0, ki_nosys},		/*ukn-317*/
	{ 0, 0, 0, ki_nosys},		/*get_random*/
	{ 0, 0, 0, ki_nosys},		/*memfd_create*/
	{ 0, 0, 0, ki_nosys},		/*kexec_file_load*/
	{ 0, 0, 0, ki_nosys},		/*ukn-321*/
	{ 0, 0, 0, ki_nosys},		/*ukn-322*/
	{ 0, 0, 0, ki_nosys},		/*userfaultfd*/
	{ 0, 0, 0, ki_nosys},		/*ukn-324*/
	{ 0, 0, 0, ki_nosys},		/*ukn-325*/
	{ 0, 0, 0, ki_nosys},		/*copy_file_range*/
	{ 0, 0, 0, ki_nosys},		/*ukn-327*/
	{ 0, 0, 0, ki_nosys},		/*ukn-328*/
	{ 0, 0, 0, ki_nosys},		/*ukn-329*/
	{ 0, 0, 0, ki_nosys},		/*ukn-330*/
	{ 0, 0, 0, ki_nosys},		/*ukn-331*/
	{ 0, 0, 0, ki_nosys},		/*ukn-332*/
	{ 0, 0, 0, ki_nosys},		/*ukn-333*/
	{ 0, 0, 0, ki_nosys},		/*ukn-334*/
	{ 0, 0, 0, ki_nosys},		/*ukn-335*/
	{ 0, 0, 0, ki_nosys},		/*ukn-336*/
	{ 0, 0, 0, ki_nosys},		/*ukn-337*/
	{ 0, 0, 0, ki_nosys},		/*ukn-338*/
	{ 0, 0, 0, ki_nosys},		/*ukn-339*/
	{ 0, 0, 0, ki_nosys},		/*ukn-340*/
	{ 0, 0, 0, ki_nosys},		/*ukn-341*/
	{ 0, 0, 0, ki_nosys},		/*ukn-342*/
	{ 0, 0, 0, ki_nosys},		/*ukn-343*/
	{ 0, 0, 0, ki_nosys},		/*ukn-344*/
	{ 0, 0, 0, ki_nosys},		/*ukn-345*/
	{ 0, 0, 0, ki_nosys},		/*ukn-346*/
	{ 0, 0, 0, ki_nosys},		/*ukn-347*/
	{ 0, 0, 0, ki_nosys},		/*ukn-348*/
	{ 0, 0, 0, ki_nosys},		/*ukn-349*/
	{ 0, 0, 0, ki_nosys},		/*ukn-350*/
	{ 0, 0, 0, ki_nosys},		/*ukn-351*/
	{ 0, 0, 0, ki_nosys},		/*ukn-352*/
	{ 0, 0, 0, ki_nosys},		/*ukn-353*/
	{ 0, 0, 0, ki_nosys},		/*ukn-354*/
	{ 0, 0, 0, ki_nosys},		/*ukn-355*/
	{ 0, 0, 0, ki_nosys},		/*ukn-356*/
	{ 0, 0, 0, ki_nosys},		/*ukn-357*/
	{ 0, 0, 0, ki_nosys},		/*ukn-358*/
	{ 0, 0, 0, ki_nosys},		/*ukn-359*/
	{ 0, 0, 0, ki_nosys},		/*ukn-360*/
	{ 0, 0, 0, ki_nosys},		/*ukn-361*/
	{ 0, 0, 0, ki_nosys},		/*ukn-362*/
	{ 0, 0, 0, ki_nosys},		/*ukn-363*/
	{ 0, 0, 0, ki_nosys},		/*ukn-364*/
	{ 0, 0, 0, ki_nosys},		/*ukn-365*/
	{ 0, 0, 0, ki_nosys},		/*ukn-366*/
	{ 0, 0, 0, ki_nosys},		/*ukn-367*/
	{ 0, 0, 0, ki_nosys},		/*ukn-368*/
	{ 0, 0, 0, ki_nosys},		/*ukn-369*/
	{ 0, 0, 0, ki_nosys},		/*ukn-370*/
	{ 0, 0, 0, ki_nosys},		/*ukn-371*/
	{ 0, 0, 0, ki_nosys},		/*ukn-372*/
	{ 0, 0, 0, ki_nosys},		/*ukn-373*/
	{ 0, 0, 0, ki_nosys},		/*ukn-374*/
	{ 0, 0, 0, ki_nosys},		/*ukn-375*/
	{ 0, 0, 0, ki_nosys},		/*ukn-376*/
	{ 0, 0, 0, ki_nosys},		/*ukn-377*/
	{ 0, 0, 0, ki_nosys},		/*ukn-378*/
	{ 0, 0, 0, ki_nosys},		/*ukn-379*/
	{ 0, 0, 0, ki_nosys},		/*ukn-380*/
	{ 0, 0, 0, ki_nosys},		/*ukn-381*/
	{ 0, 0, 0, ki_nosys},		/*ukn-382*/
	{ 0, 0, 0, ki_nosys},		/*ukn-383*/
	{ 0, 0, 0, ki_nosys},		/*ukn-384*/
	{ 0, 0, 0, ki_nosys},		/*ukn-385*/
	{ 0, 0, 0, ki_nosys},		/*ukn-386*/
	{ 0, 0, 0, ki_nosys},		/*ukn-387*/
	{ 0, 0, 0, ki_nosys},		/*ukn-388*/
	{ 0, 0, 0, ki_nosys},		/*ukn-389*/
	{ 0, 0, 0, ki_nosys},		/*ukn-390*/
	{ 0, 0, 0, ki_nosys},		/*ukn-391*/
	{ 0, 0, 0, ki_nosys},		/*ukn-392*/
	{ 0, 0, 0, ki_nosys},		/*ukn-393*/
	{ 0, 0, 0, ki_nosys},		/*ukn-394*/
	{ 0, 0, 0, ki_nosys},		/*ukn-395*/
	{ 0, 0, 0, ki_nosys},		/*ukn-396*/
	{ 0, 0, 0, ki_nosys},		/*ukn-397*/
	{ 0, 0, 0, ki_nosys},		/*ukn-398*/
	{ 0, 0, 0, ki_nosys},		/*ukn-399*/
	{ 0, 0, 0, ki_nosys},		/*waitpid*/
	{ 0, 0, 0, ki_nosys},		/*break*/
	{ 0, 0, 0, ki_nosys},		/*oldstat*/
	{ 0, 0, 0, ki_nosys},		/*umount*/
	{ 0, 0, 0, ki_nosys},		/*stime*/
	{ 0, 0, 1, ki_nosys},		/*oldfstat*/
	{ 0, 0, 0, ki_nosys},		/*stty*/
	{ 0, 0, 0, ki_nosys},		/*gtty*/
	{ 0, 0, 0, ki_nosys},		/*nice*/
	{ 0, 0, 0, ki_nosys},		/*ftime*/
	{ 0, 0, 0, ki_nosys},		/*prof*/
	{ 0, 0, 0, ki_nosys},		/*signal*/
	{ 0, 0, 0, ki_nosys},		/*lock*/
	{ 0, 0, 0, ki_nosys},		/*mpx*/
	{ 0, 0, 0, ki_nosys},		/*ulimit*/
	{ 0, 0, 0, ki_nosys},		/*oldolduname*/
	{ 0, 0, 0, ki_nosys},		/*sigaction*/
	{ 0, 0, 0, ki_nosys},		/*sgetmask*/
	{ 0, 0, 0, ki_nosys},		/*ssetmask*/
	{ 0, 0, 0, ki_nosys},		/*sigsuspend*/
	{ 0, 0, 0, ki_nosys},		/*oldlstat*/
	{ 0, 0, 1, ki_nosys},		/*readdir*/	
	{ 0, 0, 0, ki_nosys},		/*profil*/
	{ 0, 0, 0, ki_nosys},		/*socketcall*/
	{ 0, 0, 0, ki_nosys},		/*olduname*/
	{ 0, 0, 0, ki_nosys},		/*idle*/
	{ 0, 0, 0, ki_nosys},		/*vm86old*/
	{ 0, 0, 0, ki_nosys},		/*ipc*/
	{ 0, 0, 0, ki_nosys},		/*sigreturn*/
	{ 0, 0, 0, ki_nosys},		/*sigprocmask*/
	{ 0, 0, 0, ki_nosys},		/*bdflush*/
	{ 1, 0, 1, ki_lseek},		/*_llseek*/
	{ 0, 0, 0, ki_nosys},		/*_newselect*/
	{ 0, 0, 0, ki_nosys},		/*vm86*/
	{ 0, 0, 0, ki_nosys},		/*ugetrlimit*/
	{ 0, 0, 0, ki_nosys},		/*mmap2*/
	{ 0, 0, 0, ki_nosys},		/*truncate64*/
	{ 0, 0, 0, ki_nosys},		/*ftruncate64*/
	{ 0, 0, 0, ki_nosys},		/*stat64*/
	{ 0, 0, 0, ki_nosys},		/*lstat64*/
	{ 0, 0, 1, ki_nosys},		/*fstat64*/
	{ 0, 0, 0, ki_nosys},		/*lchown32*/
	{ 0, 0, 0, ki_nosys},		/*getuid32*/
	{ 0, 0, 0, ki_nosys},		/*getgid32*/
	{ 0, 0, 0, ki_nosys},		/*geteuid32*/
	{ 0, 0, 0, ki_nosys},		/*getegid32*/
	{ 0, 0, 0, ki_nosys},		/*setreuid32*/
	{ 0, 0, 0, ki_nosys},		/*setregid32*/
	{ 0, 0, 0, ki_nosys},		/*getgroups32*/
	{ 0, 0, 0, ki_nosys},		/*setgroups32*/
	{ 0, 0, 1, ki_nosys},		/*fchown32*/
	{ 0, 0, 0, ki_nosys},		/*setresuid32*/
	{ 0, 0, 0, ki_nosys},		/*getresuid32*/
	{ 0, 0, 0, ki_nosys},		/*setresgid32*/
	{ 0, 0, 0, ki_nosys},		/*getresgid32*/
	{ 0, 0, 0, ki_nosys},		/*chown32*/
	{ 0, 0, 0, ki_nosys},		/*setuid32*/
	{ 0, 0, 0, ki_nosys},		/*setgid32*/
	{ 0, 0, 0, ki_nosys},		/*setfsuid32*/
	{ 0, 0, 0, ki_nosys},		/*setfsgid32*/
	{ 1, 0, 1, ki_fcntl},		/*fcntl64*/
	{ 0, 0, 0, ki_nosys},		/*ukn-461*/
	{ 0, 0, 0, ki_nosys},		/*ukn-462*/
	{ 0, 0, 1, ki_nosys},		/*sendfile64*/
	{ 0, 0, 0, ki_nosys},		/*sys_set_zone_reclaim*/
	{ 0, 0, 0, ki_nosys},		/*statfs64*/
	{ 0, 0, 1, ki_nosys},		/*fstatfs64*/
	{ 0, 0, 1, ki_nosys},		/*fadvise64_64*/
	{ 0, 0, 0, ki_nosys},		/*sys_setaltroot*/
	{ 0, 0, 1, ki_nosys},		/*fstat64*/
	{ 0, 0, 0, ki_nosys},		/*getcpu*/
	{ 0, 0, 0, ki_nosys},		/*send*/
	{ 0, 0, 0, ki_nosys},		/*recv*/
	{ 0, 0, 0, ki_nosys},		/*ukn-474*/
	{ 0, 0, 0, ki_nosys},		/*ukn-475*/
	{ 0, 0, 0, ki_nosys},		/*ukn-476*/
	{ 0, 0, 0, ki_nosys},		/*ukn-477*/
	{ 0, 0, 0, ki_nosys},		/*ukn-478*/
	{ 0, 0, 0, ki_nosys},		/*ukn-479*/
	{ 0, 0, 0, ki_nosys},		/*ukn-480*/
	{ 0, 0, 0, ki_nosys},		/*ukn-481*/
	{ 0, 0, 0, ki_nosys},		/*ukn-482*/
	{ 0, 0, 0, ki_nosys},		/*ukn-483*/
	{ 0, 0, 0, ki_nosys},		/*ukn-484*/
	{ 0, 0, 0, ki_nosys},		/*ukn-485*/
	{ 0, 0, 0, ki_nosys},		/*ukn-486*/
	{ 0, 0, 0, ki_nosys},		/*ukn-487*/
	{ 0, 0, 0, ki_nosys},		/*ukn-488*/
	{ 0, 0, 0, ki_nosys},		/*ukn-489*/
	{ 0, 0, 0, ki_nosys},		/*ukn-490*/
	{ 0, 0, 0, ki_nosys},		/*ukn-491*/
	{ 0, 0, 0, ki_nosys},		/*ukn-492*/
	{ 0, 0, 0, ki_nosys},		/*ukn-493*/
	{ 0, 0, 0, ki_nosys},		/*ukn-494*/
	{ 0, 0, 0, ki_nosys},		/*ukn-495*/
	{ 0, 0, 0, ki_nosys},		/*ukn-496*/
	{ 0, 0, 0, ki_nosys},		/*ukn-497*/
	{ 0, 0, 0, ki_nosys},		/*ukn-498*/
	{ 0, 0, 0, ki_nosys} 		/*ukn-499*/
};

arg_action_t arg_actions[MAXARG_ACTIONS] = {
	NULL,	
	NULL,
	NULL,
	NULL,
	futex_op_str,
	fcntl_cmd_str,
	mmap_prot_str,
	mmap_flags_str,
	open_flags_str,
	sock_dom_str,
	sock_type_str,
	signal_str,
	sighow_str,
	whence_str,
	ipc_call_str,
	futex_val3_str,
	semctl_cmd_str
};

short syscall_index_win[MAX_SYSCALL_IDX];
	
short syscall_index_x86_64[MAX_SYSCALL_IDX] = {
	/* read */			0,
	/* write */			1,	
	/* open */			2,
	/* close */			3,
	/* stat */			4,
	/* fstat */			5,
	/* lstat */			6,
	/* poll */			7,
	/* lseek */			8,
	/* mmap */			9,
	/* mprotect */			10,
	/* munmap */			11,
	/* brk */			12,
	/* rt_sigaction */		13,
	/* rt_sigprocmask */		14,
	/* rt_sigreturn */		15,
	/* ioctl */			16,
	/* pread64 */			17,
	/* pwrite64 */			18,
	/* readv */			19,
	/* writev */			20,
	/* access */			21,
	/* pipe */			22,
	/* select */			23,
	/* sched_yield */		24,
	/* mremap */			25,
	/* msync */			26,
	/* mincore */			27,
	/* madvise */			28,
	/* shmget */			29,
	/* shmat */			30,
	/* shmctl */			31,
	/* dup */			32,
	/* dup2 */			33,
	/* pause */			34,
	/* nanosleep */			35,
	/* getitimer */			36,
	/* alarm */			37,
	/* setitimer */			38,
	/* getid */			39,
	/* sendfile */			40,
	/* socket */			41,
	/* connect */			42,
	/* accept */			43,
	/* sendto */			44,
	/* recvfrom */			45,
	/* sendmsg */			46,
	/* recvmsg */			47,
	/* shutdown */			48,
	/* bind */			49,
	/* listen */			50,
	/* getsockname */		51,
	/* getpeername */		52,
	/* socketpair */		53,
	/* setsockopt */		54,
	/* getsockopt */		55,
	/* clone */			56,
	/* fork */			57,
	/* vfork */			58,
	/* execve */			59,
	/* exit */			60,
	/* wait4 */			61,
	/* kill */			62,
	/* uname */			63,
	/* semget */			64,
	/* semop */			65,
	/* semctl */			66,
	/* shmdt */			67,
	/* msgget */			68,
	/* msgsnd */			69,
	/* msgrcv */			70,
	/* msgctl */			71,
	/* fcntl */			72,
	/* flock */			73,
	/* fsync */ 			74,
	/* fdatasync */			75,
	/* truncate */			76,
	/* ftruncate */			77,
	/* getdents */			78,
	/* getcwd */			79,
	/* chdir */			80,
	/* fchdir */			81,
	/* rename */			82,
	/* mkdir */ 			83,
	/* rmdir */			84,
	/* creat */			85,
	/* link */			86,
	/* unlink */			87,	
	/* symlink */			88,
	/* readlink */			89,
	/* chmod */			90,
	/* fchmod */			91,
	/* chown */			92,
	/* fchown */			93,
	/* lchown */			94,
	/* umask */			95,
	/* gettimeofday */		96,
	/* getrlimit */			97,
	/* getrusage */			98,
	/* sysinfo */			99,
	/* times */			100,
	/* ptrace */			101,
	/* getuid */			102,
	/* syslog */			103,
	/* getgid */			104,
	/* setuid */			105,
	/* setgid */			106,
	/* geteuid */			107,
	/* getegid */			108, 
	/* setpgid */			109,
	/* getppid */			110,
	/* getpgrp */			111,
	/* setsid */			112,
	/* setreuid */			113,
	/* setregid */			114,
	/* getgroups */			115,
	/* setgroups */			116,
	/* setresuid */			117,
	/* getresuid */			118,
	/* setresgid */			119,
	/* getresgid */			120,
	/* getpgid */			121,
	/* setfsuid */			122,
	/* setfsgid */			123,
	/* getsid */			124,
	/* capget */			125,
	/* capset */			126,
	/* rt_sigpending */		127,
	/* rt_sigtimedwait */		128,
	/* rt_sigqueueinfo */		129,
	/* rt_sigsuspend */		130,
	/* sigaltstack */		131,
	/* utime */			132,
	/* mknod */			133,
	/* uselib */			134,
	/* personality */		135,
	/* ustat */			136,
	/* statfs */			137,
	/* fstatfs */			138,
	/* sysfs */			139,
	/* getpriority */		140,
	/* setpriority */		141,
	/* sched_setparam */		142,
	/* sched_getparam */		143,
	/* sched_setscheduler */	144,
	/* sched_getscheduler */	145,
	/* sched_get_priority_max */	146,
	/* sched_get_priority_min */	147,
	/* sched_rr_get_interval */	148,
	/* mlock */			149,
	/* munlock */			150,
	/* mlockall */			151,
	/* munlockall */		152,
	/* vhangup */			153,
	/* modify_ldt */		154,
	/* pivot_root */		155,
	/* _sysctl */			156,
	/* prctl */			157,
	/* arch_prctl */		158,
	/* adjtimex */			159,
	/* setrlimit */			160,
	/* chroot */			161,
	/* sync */			162,
	/* acct */			163,
	/* settimeofday */		164,
	/* mount */			165,
	/* umount2 */			166,
	/* swapon */			167,
	/* swapoff */			168,
	/* reboot */			169,
	/* sethostname */		170,
	/* setdomainname */		171,
	/* iopl */			172,
	/* ioperm */			173,
	/* create_module */		174,
	/* init_module */		175,
	/* delete_module */		176,
	/* get_kernel_syms */		177,
	/* query_module */		178,
	/* quotactl */			179,
	/* nfsservctl */		180,
	/* getpmsg */ 			181,
	/* putpmsg */			182,
	/* afs_syscall */		183,
	/* tuxcall */			184,
	/* security */			185,
	/* gettid */			186,
	/* readahead */			187,
	/* setxattr */			188,
	/* lsetxattr */			189,
	/* fsetxattr */			190,
	/* getxattr */			191,
	/* lgetxattr */			192,
	/* fgetxattr */			193,
	/* listxattr */			194,
	/* llistxattr */		195,
	/* flistxattr */		196,
	/* removexattr */		197,
	/* lremovexattr */		198,
	/* fremovexattr */		199,
	/* tkill */			200,
	/* time */			201,
	/* futex */			202,
	/* sched_setaffinity */		203,
	/* sched_getaffinity */		204,
	/* set_thread_area */		205,
	/* io_setup */			206,
	/* io_destroy */		207,
	/* io_getevents */		208,
	/* io_submit */			209,
	/* io_cancel */			210,
	/* get_thread_area */		211,
	/* lookup_dcookie */		212,
	/* epoll_create */		213,
	/* epoll_ctl_old */		214,
	/* epoll_wait_old */		215,
	/* remap_file_pages */		216,
	/* getdents64 */		217,
	/* set_tid_address */		218,
	/* restart_syscall */		219,
	/* semtimedop */		220,
	/* fadvise64 */			221,
	/* timer_create */		222,
	/* timer_settime */		223,
	/* timer_gettime */		224,
	/* timer_getoverrun */		225,
	/* timer_delete */		226,
	/* clock_settime */		227,
	/* clock_gettime */		228,
	/* clock_getres */		229,
	/* clock_nanosleep */		230,
	/* exit_group */		231,
	/* epoll_wait */		232,
	/* epoll_ctl */			233,
	/* tgkill */			234,
	/* utimes */			235,
	/* vserver */			236,
	/* mbind */			237,
	/* set_mempolicy */		238,
	/* get_mempolicy */		239,
	/* mq_open */			240,
	/* mq_unlink */			241,
	/* mq_timedsend */		242,
	/* mq_timedreceive */		243,
	/* mq_notify */			244,
	/* mq_getsetattr */		245,
	/* kexec_load */		246,
	/* waitid */			247,
	/* add_key */			248,
	/* request_key */		249,
	/* keyctl */			250,
	/* ioprio_set */		251,
	/* ioprio_get */		252,
	/* inotify_init */		253,
	/* inotify_add_watch */		254,
	/* inotify_rm_watch */		255,
	/* migrate_pages */		256,
	/* openat */			257,
	/* mkdirat */			258,
	/* mknodat */			259,
	/* fchownat */ 			260,
	/* futimesat */			261,
	/* fstatat */			262,
	/* unlinkat */			263,
	/* renameat */			264,
	/* linkat */			265,
	/* symlinkat */			266,
	/* readlinkat */		267,
	/* fchmodat */			268,
	/* faccessat */			269,
	/* pselect6 */			270,
	/* ppoll */			271,
	/* unshare */			272,
	/* set_robust_list */		273,
	/* get_robust_list */		274,
	/* splice */			275,
	/* tee */			276,
	/* sync_file_range */		277,
	/* vmsplice */			278,
	/* move_pages */		279,
	/* utimensat */			280,
	/* epoll_pwait */		281,
	/* signalfd */			282,
	/* timerfd_create */		283,
	/* eventfd */			284,
	/* fallocate */			285,
	/* timerfd_settime */		286,
	/* timerfd_gettime */		287,
	/* accept4 */			288,
	/* signalfd4 */			289,
	/* eventfd2 */			290,
	/* epoll_create1 */		291,
	/* dup3 */			292,
	/* pipe2 */			293,
	/* inotify_init1 */		294,
	/* preadv */			295,
	/* pwritev */			296,
	/* rt_tsigqueueinfo */		297,
	/* perf_event_open */		298,
	/* recvmmsg */			299,
	/* fanotify_init */		300,
	/* fanotify_mark */		301,
	/* prlimit64 */			302,
	/* name_to_handle_at */		303,
	/* open_by_handle_at */		304,
	/* clock_adj_time */		305,
	/* syncfs */			306,
	/* sendmmsg */			307,
	/* set_ns */			308,
	/* get_cpu */			309,
	/* process_vm_readv */		310,
	/* process_vm_writev */		311,
	/* kcmp */			312,	
	/* finit_module */		313,	
	/* sched_set_attr */		314,	
	/* sched_get_attr */		315,	
	/* renameat2 */			316,	
	/* seccomp */			317,	
	/* getrandom */			318,	
	/* memfd_create */		319,	
	/* kexec_file_load */		320,	
	/* bpf */			321,	
	/* execveat */			322,	
	/* userfaultfd */		323,	
	/* membarrier */		324,	
	/* mlock2 */			325,	
	/* copy_file_range */		326,	
	/* preadv2 */			327,	
	/* pwritev2 */			328,	
	/* pkey_mprotect */		329,	
	/* pkey_alloc */   	 	330,	
	/* pkey_free */			331,	
	/* statx */			332,	
	/* io_pgetevents */		333,	
	/* rseq */			334,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-340 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-350 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-360 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-370 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-380 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-390 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-400 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-410 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-420 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* pidfd_send_signal */		424,	
	/* io_uring_register */		425,	
	/* io_uring_register */		426,	
	/* io_uring_register */		427,	
	/* open_tree */			428,	
	/* move_mount */		429,	
	/* fsopen */ 	  	 	430,	
	/* fsconfig */			431,	
	/* fsmount */			432,	
	/* fspick */			433,	
	/* pidfd_open */		434,	
	/* clone3 */			435,	
	/* close_range */		436,	
	/* openat2 */			437,	
	/* pidfd_getfd */		438,	
	/* faccessat2 */		439,	
	/* process_madvise */    	440,	
	/* epoll_pwait2 */		441,	
	/* mount_setattr */		442,	
	/* quotactl_fd */		443,	
	/* landlock_create_ruleset */	444,	
	/* landlock_add_rule */		445,	
	/* landlock_restrict_self */	446,	
	/* memfd_secret */		447,	
	/* process_mrelease */		448,	
	/* futex_waitv */		449,	
	/* set_mempolicy_home_node */  	450,	
	/* cachestat */			451,	
	/* fchmodat2 */			452,	
	/* map_shadow_stack */		453,	
	/* futex_wake */		454,	
	/* futex_wait */		455,	
	/* futex_requeue */		456,	
	/* statmount */			457,	
	/* listmount */			458,	
	/* lsm_get_self_attr */		459,	
	/* lsm_set_self_attr */    	460,	
	/* lsm_list_modules */		461,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-470 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-480 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-490 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-510 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-520 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-530 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-540 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-550 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-560 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-570 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-580 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-590 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-600 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-610 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-620 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-630 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-640 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-650 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-660 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-670 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-680 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-690 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-700 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-710 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-720 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-730 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-740 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-750 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-760 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-770 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-780 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-790 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-800 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-810 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-820 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-830 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-840 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-850 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-860 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-870 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-880 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-890 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-900 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-910 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-920 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-930 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-940 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-950 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-960 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-970 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-980 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-990 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1000 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1010 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1020 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1030 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1040 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1050 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1060 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1070 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
};

#define SYSCALL32	500	
short syscall_index_x86_32[MAX_SYSCALL_IDX] = {
	/* restart_syscall */		219,
	/* exit */			60,
	/* fork */			57,
	/* read */			0,
	/* write */			1,	
	/* open */			2,
	/* close */			3,
	/* waitpid */			SYSCALL32+0,
	/* creat */			85,
	/* link */			86,
	/* 10 unlink */			87,	
	/* execve */			59,
	/* chdir */			80,
	/* time */			201,
	/* mknod */			133,
	/* chmod */			90,
	/* lchown */			94,
	/* break */			SYSCALL32+1,
	/* oldstat */			SYSCALL32+2,
	/* lseek */			8,
	/* 20 getpid */			39,
	/* mount */			165,
	/* umount */			SYSCALL32+3,
	/* setuid */			105,
	/* getuid */			102,
	/* stime */			SYSCALL32+4,
	/* ptrace */			101,
	/* alarm */			37,
	/* oldfstat */			SYSCALL32+5,
	/* pause */			34,
	/* 30 utime */			132,
	/* stty */			SYSCALL32+6,
	/* gtty */			SYSCALL32+7,
	/* access */			21,
	/* nice */			SYSCALL32+8,
	/* ftime */			SYSCALL32+9,
	/* sync */			162,
	/* kill */			62,
	/* rename */			82,
	/* mkdir */ 			83,
	/* 40 rmdir */			84,
	/* dup */			32,
	/* pipe */			22,
	/* times */			100,
	/* prof */			SYSCALL32+10,
	/* brk */			12,
	/* setgid */			106,
	/* getgid */			104,
	/* signal */			SYSCALL32+11,
	/* geteuid */			107,
	/* 50 getegid */		108, 
	/* acct */			163,
	/* umount2 */			166,
	/* lock */			SYSCALL32+12,
	/* ioctl */			16,
	/* fcntl */			72,
	/* mpx */			SYSCALL32+13,
	/* setpgid */			109,
	/* ulimit */			SYSCALL32+14,
	/* oldolduname */		SYSCALL32+15,
	/* 60 umask */			95,
	/* chroot */			161,
	/* ustat */			136,
	/* dup2 */			33,
	/* getppid */			110,
	/* getpgrp */			111,
	/* setsid */			112,
	/* sigaction */			SYSCALL32+16,
	/* sgetmask */			SYSCALL32+17,
	/* ssetmask */			SYSCALL32+18,
	/* 70 setreuid */		113,
	/* setregid */			114,
	/* sigsuspend */		SYSCALL32+19,
	/* sigpending */		SYSCALL32+20,
	/* sethostname */		170,
	/* setrlimit */			160,
	/* getrlimit */			97,
	/* getrusage */			98,
	/* gettimeofday */		96,
	/* settimeofday */		164,
	/* 80 getgroups */		115,
	/* setgroups */			116,
	/* select */			23,
	/* symlink */			88,
	/* oldlstat */			SYSCALL32+21,
	/* readlink */			89,
	/* uselib */			134,
	/* swapon */			167,
	/* reboot */			169,
	/* readdir */			SYSCALL32+22,
	/* 90 mmap */			9,
	/* munmap */			11,
	/* truncate */			76,
	/* ftruncate */			77,
	/* fchmod */			91,
	/* fchown */			93,
	/* getpriority */		140,
	/* setpriority */		141,
	/* profil */			SYSCALL32+23,
	/* statfs */			137,
	/* 100 fstatfs */		138,
	/* ioperm */			173,
	/* socketcall */		SYSCALL32+24,
	/* syslog */			103,
	/* setitimer */			38,
	/* getitimer */			36,
	/* stat */			4,
	/* lstat */			6,
	/* fstat */			5,
	/* olduname */			SYSCALL32+25,
	/* 110 iopl */			172,
	/* vhangup */			153,
	/* idle */			SYSCALL32+26,
	/* vm86old */			SYSCALL32+27,
	/* wait4 */			61,
	/* swapoff */			168,
	/* sysinfo */			99,
	/* ipc */			SYSCALL32+28,
	/* fsync */ 			74,
	/* sigreturn */			SYSCALL32+29,
	/* 120 clone */			56,
	/* setdomainname */		171,
	/* uname */			63,
	/* modify_ldt */		154,
	/* adjtimex */			159,
	/* mprotect */			10,
	/* sigprocmask */		SYSCALL32+30,
	/* create_module */		174,
	/* init_module */		175,
	/* delete_module */		176,
	/* 130 get_kernel_syms */	177,
	/* quotactl */			179,
	/* getpgid */			121,
	/* fchdir */			81,
	/* bdflush */			SYSCALL32+31,
	/* sysfs */			139,
	/* personality */		135,
	/* afs_syscall */		183,
	/* setfsuid */			122,
	/* setfsgid */			123,	
	/* 140 _llseek */		SYSCALL32+32,
	/* getdents */			78,
	/* _newselect */		SYSCALL32+33,
	/* flock */			73,
	/* msync */			26,
	/* readv */			19,
	/* writev */			20,
	/* getsid */			124,
	/* fdatasync */			75,
	/* _sysctl */			156,
	/* 150 mlock */			149,
	/* munlock */			150,
	/* mlockall */			151,
	/* munlockall */		152,
	/* sched_setparam */		142,
	/* sched_getparam */		143,
	/* sched_setscheduler */	144,
	/* sched_getscheduler */	145,
	/* sched_yield */		24,
	/* sched_get_priority_max */	146,
	/* 160 sched_get_priority_min */147,
	/* sched_rr_get_interval */	148,
	/* nanosleep */			35,
	/* mremap */			25,
	/* setresuid */			117,
	/* getresuid */			118,
	/* vm86 */			SYSCALL32+34,
	/* query_module */		178,
	/* poll */			7,
	/* nfsservctl */		180,
	/* 170 setresgid */		119,
	/* getresgid */			120,
	/* prctl */			157,
	/* rt_sigreturn */		15,
	/* rt_sigaction */		13,
	/* rt_sigprocmask */		14,
	/* rt_sigpending */		127,
	/* rt_sigtimedwait */		128,
	/* rt_sigqueueinfo */		129,
	/* rt_sigsuspend */		130,
	/* 180 pread64 */		17,
	/* pwrite64 */			18,
	/* chown */			92,
	/* getcwd */			79,
	/* capget */			125,
	/* capset */			126,
	/* sigaltstack */		131,
	/* sendfile */			40,
	/* getpmsg */ 			181,
	/* putpmsg */			182,
	/* 190 vfork */			58,
	/* ugetrlimit */		SYSCALL32+35,
	/* mmap2 */			SYSCALL32+36,
	/* truncate64 */		SYSCALL32+37,
	/* ftruncate64 */		SYSCALL32+38,
	/* stat64 */			SYSCALL32+39,
	/* lstat64 */			SYSCALL32+40,
	/* fstat64 */			SYSCALL32+41,
	/* lchown32 */			SYSCALL32+42,
	/* getuid32 */			SYSCALL32+43,
	/* 200 getgid32 */		SYSCALL32+44,
	/* geteuid32 */			SYSCALL32+45,
	/* getegid32 */			SYSCALL32+46,
	/* setreuid32 */		SYSCALL32+47,
	/* setregid32 */		SYSCALL32+48,
	/* getgroups32 */		SYSCALL32+49,
	/* setgroups32 */		SYSCALL32+50,
	/* fchown32 */			SYSCALL32+51,
	/* setresuid32 */		SYSCALL32+52,
	/* getresuid32 */		SYSCALL32+53,
	/* 210 setresgid32 */		SYSCALL32+54,
	/* getresgid32 */		SYSCALL32+55,
	/* chown32 */			SYSCALL32+56,
	/* setuid32 */			SYSCALL32+57,
	/* setgid32 */			SYSCALL32+58,
	/* setfsuid32 */		SYSCALL32+59,
	/* setfsgid32 */		SYSCALL32+60,
	/* pivot_root */		155,
	/* mincore */			27,
	/* madvise */			28,
	/* 220 getdents64 */		217,
	/* fcntl64 */			SYSCALL32+61,
	/* ukn-222 */			UKN,
	/* ukn-223 */			UKN,
	/* gettid */			186,
	/* readahead */			187,
	/* setxattr */			188,
	/* lsetxattr */			189,
	/* fsetxattr */			190,
	/* getxattr */			191,
	/* 230 lgetxattr */		192,
	/* fgetxattr */			193,
	/* listxattr */			194,
	/* llistxattr */		195,
	/* flistxattr */		196,
	/* removexattr */		197,
	/* lremovexattr */		198,
	/* fremovexattr */		199,
	/* tkill */			200,
	/* sendfile64 */		SYSCALL32+64,
	/* 240 futex */			202,
	/* sched_setaffinity */		203,
	/* sched_getaffinity */		204,
	/* set_thread_area */		205,
	/* get_thread_area */		211,
	/* io_setup */			206,
	/* io_destroy */		207,
	/* io_getevents */		208,
	/* io_submit */			209,
	/* io_cancel */			210,
	/* 250 fadvise64 */		221,
	/* sys_set_zone_reclaim */	SYSCALL32+65,
	/* exit_group */		231,
	/* lookup_dcookie */		212,
	/* epoll_create */		213,
	/* epoll_ctl */			233,
	/* epoll_wait */		232,
	/* remap_file_pages */		216,
	/* set_tid_address */		218,
	/* timer_create */		222,
	/* 260 timer_settime */		223,
	/* timer_gettime */		224,
	/* timer_getoverrun */		225,
	/* timer_delete */		226,
	/* clock_settime */		227,
	/* clock_gettime */		228,
	/* clock_getres */		229,
	/* clock_nanosleep */		230,
	/* statfs64 */			SYSCALL32+66,
	/* fstatfs64 */			SYSCALL32+67,
	/* 270 tgkill */		234,
	/* utimes */			235,
	/* fadvise64_64 */		SYSCALL32+68,
	/* vserver */			236,
	/* mbind */			237,
	/* get_mempolicy */		239,
	/* set_mempolicy */		238,
	/* mq_open */			240,
	/* mq_unlink */			241,
	/* mq_timedsend */		242,
	/* 280 mq_timedreceive */	243,
	/* mq_notify */			244,
	/* mq_getsetattr */		245,
	/* kexec_load */		246,
	/* waitid */			247,
	/* sys_setaltroot */		SYSCALL32+69,
	/* add_key */			248,
	/* request_key */		249,
	/* keyctl */			250,
	/* ioprio_set */		251,
	/* 290 ioprio_get */		252,
	/* inotify_init */		253,
	/* inotify_add_watch */		254,
	/* inotify_rm_watch */		255,
	/* migrate_pages */		256,
	/* openat */			257,
	/* mkdirat */			258,
	/* mknodat */			259,
	/* fchownat */ 			260,
	/* futimesat */			261,
	/* 300 fstatat64 */		SYSCALL32+70,
	/* unlinkat */			263,
	/* renameat */			264,
	/* linkat */			265,
	/* symlinkat */			266,
	/* readlinkat */		267,
	/* fchmodat */			268,
	/* faccessat */			269,
	/* pselect6 */			270,
	/* ppoll */			271,
	/* 310 unshare */		272,
	/* set_robust_list */		273,
	/* get_robust_list */		274,
	/* splice */			275,
	/* sync_file_range */		277,
	/* tee */			276,
	/* vmsplice */			278,
	/* move_pages */		279,
	/* getcpu */			SYSCALL32+71,
	/* epoll_pwait */		281,
	/* 320 utimensat */		280,
	/* signalfd */			282,
	/* timerfd_create */		283,
	/* eventfd */			284,
	/* fallocate */			285,
	/* timerfd_settime */		286,
	/* timerfd_gettime */		287,
	/* signalfd4 */			289,
	/* eventfd2 */			290,
	/* epoll_create1 */		291,
	/* 330 dup3 */			292,
	/* pipe2 */			293,
	/* inotify_init1 */		294,
	/* preadv */			295,
	/* pwritev */			296,
	/* rt_tsigqueueinfo */		297,
	/* perf_event_open */		298,
	/* recvmmsg */			299,
	/* fanotify_init */		300,
	/* fanotify_mark */		301,
	/* 340 prlimit64 */		302,
	/* name_to_handle_at */		303,
	/* open_by_handle_at */		304,
	/* clock_adj_time */		305,
	/* syncfs */			306,
	/* sendmmsg */			307,
	/* set_ns */			308,
	/* process_vm_readv */		310,
	/* process_vm_writev */		311,
	/* kcmp */			312,
	/* 350 finit_module */   	313,	
	/* sched_setattr */		314,	
	/* sched_getattr */		315,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* getrandom */			318,	
	/* memfd_create */		319,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-360 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-370 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* userfaultfd */		323,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* copy_file_range */		326,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-380 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-390 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-400 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-410 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-420 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-430 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* process_madvise */  	 	440,	
	/* epoll_pwait2 */		441,	
	/* mount_setattr */		442,	
	/* quotactl_fd */		443,	
	/* landlock_create_ruleset */	444,	
	/* landlock_add_rule */		445,	
	/* landlock_restrict_self */	446,	
	/* memfd_secret */		447,	
	/* process_mrelease */		448,	
	/* futex_waitv */		449,	
	/* set_mempolicy_home_node */  	450,	
	/* cachestat */			451,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-460 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-470 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-480 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-490 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-500 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-510 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-520 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-530 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-540 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-550 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-560 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-570 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-580 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-590 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-600 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-610 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-620 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-630 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-640 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-650 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-660 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-670 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-680 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-690 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-700 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-710 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-720 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-730 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-740 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-750 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-760 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-770 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-780 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-790 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-800 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-810 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-820 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-830 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-840 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-850 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-860 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-870 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-880 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-890 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-900 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-910 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-920 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-930 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-940 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-950 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-960 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-970 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-980 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-990 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1000 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1010 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1020 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1030 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1040 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1050 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1060 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1070 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
};

short syscall_index_aarch_64[MAX_SYSCALL_IDX] = {
	/* 0 io_setup */			206,
	/* io_destroy */		207,
	/* io_submit */			209,
	/* io_cancel */			210,
	/* io_getevents */		208,
	/* setxattr */			188,
	/* lsetxattr */			189,
	/* fsetxattr */			190,
	/* getxattr */			191,
	/* lgetxattr */			192,
	/* 10 fgetxattr */			193,
	/* listxattr */			194,
	/* llistxattr */		195,
	/* flistxattr */		196,
	/* removexattr */		197,
	/* lremovexattr */		198,
	/* fremovexattr */		199,
	/* getcwd */			79,
	/* lookup_dcookie */		212,
	/* eventfd2 */			290,
	/* 20 epoll_create1 */		291,
	/* epoll_ctl */			233,
	/* epoll_pwait */		281,
	/* dup */			32,
	/* dup3 */			292,
	/* fcntl */			72,
	/* inotify_init1 */		294,
	/* inotify_add_watch */		254,
	/* inotify_rm_watch */		255,
	/* ioctl */			16,
	/* 30 ioprio_set */		251,
	/* ioprio_get */		252,
	/* flock */			73,
	/* mknodat */			259,
	/* mkdirat */			258,
	/* unlinkat */			263,
	/* symlinkat */			266,
	/* linkat */			265,
	/* renameat */			264,
	/* umount2 */			166,
	/* 40 mount */			165,
	/* pivot_root */		155,
	/* nfsservctl */		180,
	/* statfs */			137,
	/* fstatfs */			138,
	/* truncate */			76,
	/* ftruncate */			77,
	/* fallocate */			285,
	/* faccessat */			269,
	/* chdir */			80,
	/* 50 fchdir */			81,
	/* chroot */			161,
	/* fchmod */			91,
	/* fchmodat */			268,
	/* fchownat */ 			260,
	/* fchown */			93,
	/* openat */			257,
	/* close */			3,
	/* vhangup */			153,
	/* pipe2 */			293,
	/* 60 quotactl */			179,
	/* getdents64 */		217,
	/* lseek */			8,
	/* read */			0,
	/* write */			1,	
	/* readv */			19,
	/* writev */			20,
	/* pread64 */			17,
	/* pwrite64 */			18,
	/* preadv */			295,
	/* 70 pwritev */			296,
	/* sendfile */			40,
	/* pselect6 */			270,
	/* ppoll */			271,
	/* signalfd4 */			289,
	/* vmsplice */			278,
	/* splice */			275,
	/* tee */			276,
	/* readlinkat */		267,
	/* fstatat */			262,
	/* 80 fstat64 */			SYSCALL32+41,
	/* sync */			162,
	/* fsync */ 			74,
	/* fdatasync */			75,
	/* sync_file_range */		277,
	/* timerfd_create */		283,
	/* timerfd_settime */		286,
	/* timerfd_gettime */		287,
	/* utimensat */			280,
	/* acct */			163,
	/* 90 capget */			125,
	/* capset */			126,
	/* personality */		135,
	/* exit */			60,
	/* exit_group */		231,
	/* waitid */			247,
	/* set_tid_address */		218,
	/* unshare */			272,
	/* futex */			202,
	/* set_robust_list */		273,
	/* 100 get_robust_list */		274,
	/* nanosleep */			35,
	/* getitimer */			36,
	/* setitimer */			38,
	/* kexec_load */		246,
	/* init_module */		175,
	/* delete_module */		176,
	/* timer_create */		222,
	/* timer_gettime */		224,
	/* timer_getoverrun */		225,
	/* 110 timer_settime */		223,
	/* timer_delete */		226,
	/* clock_settime */		227,
	/* clock_gettime */		228,
	/* clock_getres */		229,
	/* clock_nanosleep */		230,
	/* syslog */			103,
	/* ptrace */			101,
	/* sched_setparam */		142,
	/* sched_setscheduler */	144,
	/* 120 sched_getscheduler */	145,
	/* sched_getparam */		143,
	/* sched_setaffinity */		203,
	/* sched_getaffinity */		204,
	/* sched_yield */		24,
	/* sched_get_priority_max */	146,
	/* sched_get_priority_min */	147,
	/* sched_rr_get_interval */	148,
	/* restart_syscall */		219,
	/* kill */			62,
	/* 130 tkill */			200,
	/* tgkill */			234,
	/* sigaltstack */		131,
	/* rt_sigsuspend */		130,
	/* rt_sigaction */		13,
	/* rt_sigprocmask */		14,
	/* rt_sigpending */		127,
	/* rt_sigtimedwait */		128,
	/* rt_sigqueueinfo */		129,
	/* rt_sigreturn */		15,
	/* 140 setpriority */		141,
	/* getpriority */		140,
	/* reboot */			169,
	/* setregid */			114,
	/* setgid */			106,
	/* setreuid */			113,
	/* setuid */			105,
	/* setresuid */			117,
	/* getresuid */			118,
	/* setresgid */			119,
	/* 150 getresgid */			120,
	/* setfsuid */			122,
	/* setfsgid */			123,
	/* times */			100,
	/* setpgid */			109,
	/* getpgid */			121,
	/* getsid */			124,
	/* setsid */			112,
	/* getgroups */			115,
	/* setgroups */			116,
	/* 160 uname */			63,
	/* sethostname */		170,
	/* setdomainname */		171,
	/* getrlimit */			97,
	/* setrlimit */			160,
	/* getrusage */			98,
	/* umask */			95,
	/* prctl */			157,
	/* getcpu */			SYSCALL32+71,
	/* gettimeofday */		96,
	/* 170 settimeofday */		164,
	/* adjtimex */			159,
	/* getpid */			39,
	/* getppid */			110,
	/* getuid */			102,
	/* geteuid */			107,
	/* getgid */			104,
	/* getegid */			108, 
	/* gettid */			186,
	/* sysinfo */			99,
	/* 180 mq_open */			240,
	/* mq_unlink */			241,
	/* mq_timedsend */		242,
	/* mq_timedreceive */		243,
	/* mq_notify */			244,
	/* mq_getsetattr */		245,
	/* msgget */			68,
	/* msgctl */			71,
	/* msgrcv */			70,
	/* msgsnd */			69,
	/* 190 semget */			64,
	/* semctl */			66,
	/* semtimedop */		220,
	/* semop */			65,
	/* shmget */			29,
	/* shmctl */			31,
	/* shmat */			30,
	/* shmdt */			67,
	/* socket */			41,
	/* socketpair */		53,
	/* 200 bind */			49,
	/* listen */			50,
	/* accept */			43,
	/* connect */			42,
	/* getsockname */		51,
	/* getpeername */		52,
	/* sendto */			44,
	/* recvfrom */			45,
	/* setsockopt */		54,
	/* getsockopt */		55,
	/* 210 shutdown */			48,
	/* sendmsg */			46,
	/* recvmsg */			47,
	/* readahead */			187,
	/* brk */			12,
	/* munmap */			11,
	/* mremap */			25,
	/* add_key */			248,
	/* request_key */		249,
	/* keyctl */			250,
	/* 220 clone */			56,
	/* execve */			59,
	/* mmap */			9,
	/* fadvise64 */			221,
	/* swapon */			167,
	/* swapoff */			168,
	/* mprotect */			10,
	/* msync */			26,
	/* mlock */			149,
	/* mlockall */			151,
	/* 230 munlock */			150,
	/* munlockall */		152,
	/* mincore */			27,
	/* madvise */			28,
	/* remap_file_pages */		216,
	/* mbind */			237,
	/* get_mempolicy */		239,
	/* set_mempolicy */		238,
	/* migrate_pages */		256,
	/* move_pages */		279,
	/* 240 rt_tsigqueueinfo */		297,
	/* perf_event_open */		298,
	/* accept4 */			288,
	/* recvmmsg */			299,
	/* arch_specific_call */	UKN,
	/* ukn-245 */			UKN,
	/* ukn-246 */			UKN,
	/* ukn-247 */			UKN,
	/* ukn-248 */			UKN,
	/* ukn-249 */			UKN,
	/* ukn-250 */			UKN,
	/* ukn-251 */			UKN,
	/* ukn-252 */			UKN,
	/* ukn-253 */			UKN,
	/* ukn-254 */			UKN,
	/* ukn-255 */			UKN,
	/* ukn-256 */			UKN,
	/* ukn-257 */			UKN,
	/* ukn-258 */			UKN,
	/* ukn-259 */			UKN,
	/* wait4 */			61,
	/* prlimit64 */			302,
	/* fanotify_init */		300,
	/* fanotify_mark */		301,
	/* name_to_handle_at */		303,
	/* open_by_handle_at */		304,
	/* clock_adj_time */		305,
	/* syncfs */			306,
	/* set_ns */			308,
	/* ukn-269 */			UKN,
	/* ukn-269 */			UKN,
	/* ukn-312 */  			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-320 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-330 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-340 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-350 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-360 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-370 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-380 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-390 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-400 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-410 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-420 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-430 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-440 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-450 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-460 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-470 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-480 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-490 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-500 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-510 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-520 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-530 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-540 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-550 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-560 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-570 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-580 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-590 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-600 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-610 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-620 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-630 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-640 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-650 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-660 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-670 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-680 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-690 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-700 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-710 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-720 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-730 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-740 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-750 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-760 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-770 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-780 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-790 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-800 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-810 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-820 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-830 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-840 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-850 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-860 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-870 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-880 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-890 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-900 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-910 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-920 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-930 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-940 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-950 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-960 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-970 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-980 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-990 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1000 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1010 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* ukn-1020 */   	 	UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* undefined */			UKN,	
	/* open */			2,
	/* link */			86,
	/* unlink */			87,	
	/* mknod */			133,
	/* chmod */			90,
	/* chown */			92,
	/* 1030 mkdir */ 			83,
	/* rmdir */			84,
	/* lchown */			94,
	/* access */			21,
	/* rename */			82,
	/* readlink */			89,
	/* symlink */			88,
	/* utimes */			235,
	/* stat */			4,
	/* lstat */			6,
	/* 1040 pipe */			22,
	/* dup2 */			33,
	/* epoll_create */		213,
	/* inotify_init */		253,
	/* eventfd */			284,
	/* signalfd */			282,
	/* sendfile */			40,
	/* ftruncate */			77,
	/* truncate */			76,
	/* stat */			4,
	/* 1050 lstat */			6,
	/* fstat */			5,
	/* fcntl */			72,
	/* fadvise64 */			221,
	/* fstatat */			262,
	/* fstatfs */			138,
	/* statfs */			137,
	/* lseek */			8,
	/* mmap */			9,
	/* alarm */			37,
	/* 1060 getpgrp */			111,
	/* pause */			34,
	/* time */			201,
	/* utime */			132,
	/* creat */			85,
	/* getdents */			78,
	/* futimesat */			261,
	/* select */			23,
	/* poll */			7,
	/* epoll_wait */		232,
	/* 1070 ustat */			136,
	/* vfork */			58,
	/* wait4 */			61,
	/* recv */			SYSCALL32+73,	
	/* send */			SYSCALL32+72,
	/* bdflush */			SYSCALL32+31,
	/* umount */			SYSCALL32+3,
	/* uselib */			134,
	/* _sysctl */			156,
	/* fork */			57
};

short syscall_index_ppc64le[MAX_SYSCALL_IDX] = {
       /* 0 restart_syscall */         219,
       /* exit */                      60,
       /* fork */                      57,
       /* read */                      0,
       /* write */                     1,
       /* open */                      2,
       /* close */                     3,
       /* waitpid */                   UKN,
       /* creat */                     85,
       /* link */                      86,
       /* 10 nlink */                  87,
       /*  execve */                   59,
       /*  chdir */                    80,
       /*  time */                     201,
       /*  mknod */                    133,
       /*  chmod */                    90,
       /*  lchown */                   94,
       /*  break */                    UKN,
       /*  oldstat */                  UKN,
       /*  lseek */                    8,
       /* 20 getpid */                 39,
       /* mount */                     165,
       /* umount */                    UKN,
       /* setuid */                    105,
       /* getuid */                    102,
       /* stime */                     UKN,
       /* ptrace */                    101,
       /* alarm */                     37,
       /* oldfstat */                  UKN,
       /* pause */                     34,
       /* 30 utime */                  132,
       /* stty */                      UKN,
       /* gtty */                      UKN,
       /* access */                    21,
       /* nice */                      UKN,
       /* ftime */                     UKN,
       /* sync */                      162,
       /* kill */                      62,
       /* rename */                    82,
       /* mkdir */                     83,
       /* 40 rmdir */                  84,
       /* dup */                       32,
       /* pipe */                      22,
       /* times */                     100,
       /* prof */                      UKN,
       /* brk */                       12,
       /* setgid */                    106,
       /* getgid */                    104,
       /* signal */                    UKN,
       /* geteuid */                   107,
       /* 50 getegid */                108,
       /* acct */                      163,
       /* umount2 */                   166,
       /* lock */                      UKN,
       /* ioctl */                     16,
       /* fcntl */                     72,
       /* mpx */                       UKN,
       /* setpgid */                   109,
       /* ulimit */                    UKN,
       /* oldolduname */               UKN,
       /* 60 umask */                  95,
       /* chroot */                    161,
       /* ustat */                     136,
       /* dup2 */                      33,
       /* getppid */                   110,
       /* getpgrp */                   111,
       /* setsid */                    112,
       /* sigaction */                 UKN,
       /* sgetmask */                  UKN,
       /* ssetmask */                  UKN,
       /* 70 setreuid */               113,
       /* setregid */                  114,
       /* sigsuspend */                UKN,
       /* sigpending */                UKN,
       /* sethostname */               170,
       /* setrlimit */                 160,
       /* getrlimit */                 97,
       /* getrusage */                 98,
       /* gettimeofday */              96,
       /* settimeofday */              164,
       /* 80 getgroups */              115,
       /* setgroups */                 116,
       /* select */                    23,
       /* symlink */                   88,
       /* oldlstat */                  UKN,
       /* readlink */                  89,
       /* uselib */                    134,
       /* swapon */                    167,
       /* reboot */                    169,
       /* readdir */                   UKN,
       /* 90 mmap */                   9,
       /* munmap */                    11,
       /* truncate */                  76,
       /* ftruncate */                 77,
       /* fchmod */                    91,
       /* fchown */                    93,
       /* getpriority */               140,
       /* setpriority */               141,
       /* profil */                    UKN,
       /* statfs */                    137,
       /* 100 fstatfs */               138,
       /* ioperm */                    173,
       /* socketcall */                UKN,
       /* syslog */                    103,
       /* setitimer */                 38,
       /* getitimer */                 36,
       /* stat */                      4,
       /* lstat */                     6,
       /* fstat */                     5,
       /* olduname */                  UKN,
       /* 110 iopl */                  172,
       /* vhangup */                   153,
       /* idle */                      UKN,
       /* vm86 */                      UKN,
       /* wait4 */                     61,
       /* swapoff */                   168,
       /* sysinfo */                   99,
       /* ipc */                       UKN,
       /* fsync */                     74,
       /* sigreturn */                 UKN,
       /* 120 clone */                 56,
       /* setdomainname */             171,
       /* uname */                     63,
       /* modify_ldt */                154,
       /* adjtimex */                  159,
       /* mprotect */                  10,
       /* sigprocmask */               UKN,
       /* create_module */             174,
       /* init_module */               175,
       /* delete_module */             176,
       /* 130 get_kernel_syms */       177,
       /* quotactl */                  179,
       /* getpgid */                   121,
       /* fchdir */                    81,
       /* bdflush */                   UKN,
       /* sysfs */                     139,
       /* personality */               135,
       /* afs_syscall */               183,
       /* setfsuid */                  122,
       /* setfsgid */                  123,
       /* 140 _llseek */               UKN,
       /* getdents */                  78,
       /* _newselect */                UKN,
       /* flock */                     73,
       /* msync */                     26,
       /* readv */                     19,
       /* writev */                    20,
       /* getsid */                    124,
       /* fdatasync */                 75,
       /* _sysctl */                   156,
       /* 150 mlock */                 149,
       /* munlock */                   150,
       /* mlockall */                  151,
       /* munlockall */                152,
       /* sched_setparam */            142,
       /* sched_getparam */            143,
       /* sched_setscheduler */        144,
       /* sched_getscheduler */        145,
       /* sched_yield */               24,
       /* sched_get_priority_max */    146,
       /* 160 sched_get_priority_min */ 147,
       /* sched_rr_get_interval */     148,
       /* nanosleep */                 35,
       /* mremap */                    25,
       /* setresuid */                 117,
       /* getresuid */                 118,
       /* query_module */              178,
       /* poll */                      7,
       /* nfsservctl */                180,
       /* setresgid */                 119,
       /* 170 getresgid */             120,
       /* prctl */                     157,
       /* rt_sigreturn */              15,
       /* rt_sigaction */              13,
       /* rt_sigprocmask */            14,
       /* rt_sigpending */             127,
       /* rt_sigtimedwait */           128,
       /* rt_sigqueueinfo */           129,
       /* rt_sigsuspend */             130,
       /* pread64 */                   17,
       /* 180 pwrite64 */              18,
       /* chown */                     92,
       /* getcwd */                    79,
       /* capget */                    125,
       /* capset */                    126,
       /* sigaltstack */               131,
       /* sendfile */                  40,
       /* getpmsg */                   181,
       /* putpmsg */                   182,
       /* vfork */                     58,
       /* 190 ugetrlimit */            UKN,
       /* readahead */                 187,
       /* mmap2 */                     UKN,
       /* truncate64 */                UKN,
       /* ftruncate64 */               UKN,
       /* stat64 */                    UKN,
       /* lstat64 */                   UKN,
       /* fstat64 */                   UKN,
       /* pciconfig_read */            UKN,
       /* pciconfig_write */           UKN,
       /* 200 pciconfig_iobase */      UKN,
       /* multiplexer */               UKN,
       /* getdents64 */                217,
       /* pivot_root */                155,
       /* fcntl64 */                   UKN,
       /* madvise */                   28,
       /* mincore */                   27,
       /* gettid */                    186,
       /* tkill */                     200,
       /* setxattr */                  188,
       /* 210 lsetxattr */             189,
       /* fsetxattr */                 190,
       /* getxattr */                  191,
       /* lgetxattr */                 192,
       /* fgetxattr */                 193,
       /* listxattr */                 194,
       /* llistxattr */                195,
       /* flistxattr */                196,
       /* removexattr */               197,
       /* lremovexattr */              198,
       /* 220 fremovexattr */          199,
       /* futex */                     202,
       /* sched_setaffinity */         203,
       /* sched_getaffinity */         204,
       /* undefined */                 UKN,
       /* tuxcall */                   184,
       /* sendfile64 */                UKN,
       /* io_setup */                  206,
       /* io_destroy */                207,
       /* io_getevents */              208,
       /* 230 io_submit */             209,
       /* io_cancel */                 210,
       /* set_tid_address */           218,
       /* fadvise64 */                 221,
       /* exit_group */                231,
       /* lookup_dcookie */            212,
       /* epoll_create */              213,
       /* epoll_ctl */                 233,
       /* epoll_wait */                232,
       /* remap_file_pages */          216,
       /* 240 timer_create */          222,
       /* timer_settime */             223,
       /* timer_gettime */             224,
       /* timer_getoverrun */          225,
       /* timer_delete */              226,
       /* clock_settime */             227,
       /* clock_gettime */             228,
       /* clock_getres */              229,
       /* clock_nanosleep */           230,
       /* swapcontext */               UKN,
       /* 250 tgkill */                234,
       /* utimes */                    235,
       /* statfs64 */                  UKN,
       /* fstatfs64 */                 UKN,
       /* fadvise64_64 */              UKN,
       /* rtas */                      UKN,
       /* sys_debug_setcontext */      UKN,
       /* undefined */                 UKN,
       /* migrate_pages */             256,
       /* mbind */                     237,
       /* 260 get_mempolicy */         239,
       /* set_mempolicy */             238,
       /* mq_open */                   240,
       /* mq_unlink */                 241,
       /* mq_timedsend */              242,
       /* mq_timedreceive */           243,
       /* mq_notify */                 244,
       /* mq_getsetattr */             245,
       /* kexec_load */                246,
       /* add_key */                   248,
       /* 270 request_key */           249,
       /* keyctl */                    250,
       /* waitid */                    247,
       /* ioprio_set */                251,
       /* ioprio_get */                252,
       /* inotify_init */              253,
       /* inotify_add_watch */         254,
       /* inotify_rm_watch */          255,
       /* spu_run */                   UKN,
       /* spu_create */                UKN,
       /* 280 pselect6 */              270,
       /* ppoll */                     271,
       /* unshare */                   272,
       /* splice */                    275,
       /* tee */                       276,
       /* vmsplice */                  278,
       /* openat */                    257,
       /* mkdirat */                   258,
       /* mknodat */                   259,
       /* fchownat */                  260,
       /* 290 futimesat */             261,
       /* newfstatat */                262,
       /* unlinkat */                  263,
       /* renameat */                  264,
       /* linkat */                    265,
       /* symlinkat */                 266,
       /* readlinkat */                267,
       /* fchmodat */                  268,
       /* faccessat */                 269,
       /* get_robust_list */           274,
       /* 300 set_robust_list */       273,
       /* move_pages */                279,
       /* getcpu */                    309,
       /* epoll_pwait */               281,
       /* utimensat */                 280,
       /* signalfd */                  282,
       /* timerfd_create */            283,
       /* eventfd */                   284,
       /* sync_file_range2 */          UKN,
       /* fallocate */                 285,
       /* 310 subpage_prot */          UKN,
       /* timerfd_settime */           286,
       /* timerfd_gettime */           287,
       /* signalfd4 */                 289,
       /* eventfd2 */                  290,
       /* epoll_create1 */             291,
       /* dup3 */                      292,
       /* pipe2 */                     293,
       /* inotify_init1 */             294,
       /* perf_event_open */           298,
       /* 320 preadv */                295,
       /* pwritev */                   296,
       /* rt_tgsigqueueinfo */         297,
       /* fanotify_init */             300,
       /* fanotify_mark */             301,
       /* prlimit64 */                 302,
       /* socket */                    41,
       /* bind */                      49,
       /* connect */                   42,
       /* listen */                    50,
       /* 330 accept */                43,
       /* getsockname */               51,
       /* getpeername */               52,
       /* socketpair */                53,
       /* send */                      SYSCALL32+72,
       /* sendto */                    44,
       /* recv */                      SYSCALL32+73,
       /* recvfrom */                  45,
       /* shutdown */                  48,
       /* setsockopt */                54,
       /* 340 getsockopt */            55,
       /* sendmsg */                   46,
       /* recvmsg */                   47,
       /* recvmmsg */                  299,
       /* accept4 */                   288,
       /* name_to_handle_at */         303,
       /* open_by_handle_at */         304,
       /* clock_adjtime */             305,
       /* syncfs */                    306,
       /* sendmmsg */                  307,
       /* 350 setns */                 308,
       /* process_vm_readv */          310,
       /* process_vm_writev */         311,
       /* finit_module */              313,
       /* kcmp */                      312,
       /* sched_setattr */             314,
       /* sched_getattr */             315,
       /* renameat2 */                 316,
       /* seccomp */                   317,
       /* getrandom */                 318,
       /* 360 memfd_create */          319,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* switch_endian */             UKN,
       /* userfaultfd */               323,
       /* membarrier */                324,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* 370-undefined */             UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* mlock2 */                    325,
       /* copy_file_range */           326,
       /* 380 preadv2 */               327,
       /* pwritev2 */                  328,
       /* kexec_file_load */           320,
       /* statx */                     332,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-390 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-400 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-410 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-420 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-430 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-440 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-450 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-460 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-470 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-480 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-490 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-500 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-510 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-520 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-530 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-540 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-550 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-560 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-570 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-580 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-590 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-600 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-610 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-620 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-630 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-640 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-650 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-660 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-670 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-680 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-690 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-700 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-710 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-720 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-730 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-740 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-750 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-760 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-770 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-780 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-790 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-800 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-810 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-820 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-830 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-840 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-850 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-860 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-870 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-880 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-890 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-900 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-910 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-920 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-930 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-940 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-950 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-960 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-970 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-980 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-990 */                   UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1000 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1010 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1020 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1030 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1040 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1050 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1060 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* ukn-1070 */                  UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,
       /* undefined */                 UKN,

};


/* global pointer to OS specific syscall_arg_list */
syscall_arg_list_t *syscall_arg_list;

/* Windows will be allocated dynamically */
syscall_arg_list_t win_syscall_arg_list[KI_MAXSYSCALLS] = {
{"unknown", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}
};

/* Linux will be statically allocated */
syscall_arg_list_t linux_syscall_arg_list[KI_MAXSYSCALLS] = {
{"read", "ret", HEX, "fd", DECIMAL, "*buf", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"write", "ret", HEX, "fd", DECIMAL, "*buf", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"open", "ret", DECIMAL, "*pathname", HEX, "flags", OFLAGS, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"close", "ret", HEX, "fd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"stat", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstat", "ret", HEX, "fd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lstat", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"poll", "ret", HEX, "*fds", HEX, "nfds", DECIMAL, "timeout", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lseek", "ret", HEX, "fd", DECIMAL, "offset", HEX, "whence", WHENCE, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mmap", "ret", HEX, "*addr", HEX, "length", HEX, "prot", MMAP_PROT, "flags", MMAP_FLAGS, "fd", DECIMAL, "offset", HEX},
{"mprotect", "ret", HEX, "*addr", HEX, "len", HEX, "prot", MMAP_PROT, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"munmap", "ret", HEX, "*addr", HEX, "length", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"brk", "ret", HEX, "*addr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rt_sigaction", "ret", HEX, "sig", SIGNAL, "*act", HEX, "*oact", HEX, "sigsetsize", DECIMAL, NULL, SKIP, NULL, SKIP},
{"rt_sigprocmask", "ret", HEX, "how", SIGHOW, "*set", HEX, "*oset", HEX, "sigsetsize", DECIMAL, NULL, SKIP, NULL, SKIP},
{"rt_sigreturn", "ret", HEX, "arg0", HEX, "arg1", HEX, "arg2", HEX, "arg3", HEX, NULL, SKIP, NULL, SKIP},
{"ioctl", "ret", HEX, "fd", DECIMAL, "request", IOCTL_REQ, "arg2", HEX, "arg3", HEX, NULL, SKIP, NULL, SKIP},
{"pread64", "ret", HEX, "fd", DECIMAL, "*buf", HEX, "count", DECIMAL, "offset", HEX, NULL, SKIP, NULL, SKIP},
{"pwrite64", "ret", HEX, "fd", DECIMAL, "*buf", HEX, "count", DECIMAL, "offset", HEX, NULL, SKIP, NULL, SKIP},
{"readv", "ret", DECIMAL, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"writev", "ret", DECIMAL, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"access", "ret", HEX, "*pathname", HEX, "mode", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pipe", "ret", HEX, "pipefd[2]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"select", "ret", HEX, "nfds", DECIMAL, "*readfds", HEX, "*writefds", HEX, "*exceptfds", HEX, "*timeout", HEX, NULL, SKIP},
{"sched_yield", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mremap", "ret", HEX, "*old_address", HEX, "old_size", HEX, "new_size", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"msync", "ret", HEX, "*addr", HEX, "length", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mincore", "ret", HEX, "*addr", HEX, "length", DECIMAL, "*vec", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"madvise", "ret", HEX, "*addr", HEX, "length", HEX, "advise", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"shmget", "ret", HEX, "key", HEX, "size", HEX, "shmflag", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"shmat", "ret", HEX, "shmid", DECIMAL, "*shmaddr", HEX, "shmflag", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"shmctl", "ret", HEX, "shmid", DECIMAL, "command", DECIMAL, "*buf", HEX,  NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"dup", "ret", HEX, "oldfd", DECIMAL, NULL, SKIP, NULL, SKIP,  NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"dup2", "ret", HEX, "oldfd", DECIMAL, "newfd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pause", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"nanosleep", "ret", HEX, "*req", HEX, "*rem", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getitimer", "ret", HEX, "which", HEX, "*curr_value", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"alarm", "ret", HEX, "seconds", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setitimer", "ret", HEX, "which", HEX, "*new_value", HEX, "*old_value", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpid", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sendfile", "ret", DECIMAL, "out_fd", DECIMAL, "in_fd", DECIMAL, "*offset", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP},
{"socket", "ret", DECIMAL, "domain", SOCK_DOM, "type", SOCK_TYPE, "protocol", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"connect", "ret", HEX, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"accept", "ret", DECIMAL, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sendto", "ret", DECIMAL, "sockfd", DECIMAL, "*buf", HEX, "len", DECIMAL, "flags", HEX, "*dest_addr", HEX, "addrlen", DECIMAL},
{"recvfrom", "ret", DECIMAL, "sockfd", DECIMAL, "*buf", HEX, "len", DECIMAL, "flags", HEX, "*src_addr", HEX, "*addrlen", HEX},
{"sendmsg", "ret", DECIMAL, "sockfd", DECIMAL, "*msg", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"recvmsg", "ret", DECIMAL, "sockfd", DECIMAL, "*msg", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"shutdown", "ret", HEX, "sockfd", DECIMAL, "how", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"bind", "ret", HEX, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"listen", "ret", HEX, "sockfd", DECIMAL, "backlog", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getsockname", "ret", HEX, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpeername", "ret", HEX, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"socketpair", "ret", HEX, "domain", DECIMAL, "type", HEX, "protocol", DECIMAL, "sv[2]", HEX, NULL, SKIP, NULL, SKIP},
{"setsockopt", "ret", HEX, "sockfd", DECIMAL, "level", DECIMAL, "optname", DECIMAL, "*optval", HEX, "optlen", DECIMAL, NULL, SKIP},
{"getsockopt", "ret", HEX, "sockfd", DECIMAL, "level", DECIMAL, "optname", DECIMAL, "*optval", HEX, "*optlen", HEX, NULL, SKIP},
{"sys_clone", "ret", DECIMAL, "clone_flags", HEX, "newsp", HEX, "*parent_tid", HEX, "*child_tid", HEX, "*regs", HEX, NULL, SKIP},
{"fork", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"vfork", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"execve", "ret", HEX, "*filename", HEX, "*argv[]", HEX, "*envp[]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"exit", "ret", HEX, "status", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"wait4", "ret", HEX, "pid", DECIMAL, "*status", HEX, "options", HEX, "*rusage", HEX, NULL, SKIP, NULL, SKIP},
{"kill", "ret", HEX, "pid", DECIMAL, "sig", SIGNAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"uname", "ret", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"semget", "ret", HEX, "key", HEX, "nsems", DECIMAL, "semflag", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"semop", "ret", HEX, "semid", DECIMAL, "*sops", HEX, "nsops", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"semctl", "ret", HEX, "semid", DECIMAL, "semnum", DECIMAL, "command", SEMCTL_CMD, "arg3", HEX, NULL, SKIP, NULL, SKIP},
{"shmdt", "ret", HEX, "*shmaddr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"msgget", "ret", HEX, "key", HEX, "msgflag", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"msgsnd", "ret", HEX, "msgid", DECIMAL, "*msgp", HEX, "msgsz", DECIMAL, "msgflg", HEX, NULL, SKIP, NULL, SKIP},
{"msgrcv", "ret", HEX, "msgid", DECIMAL, "*msgp", HEX, "msgsz", DECIMAL, "msgtyp", DECIMAL, "msgflg", HEX, NULL, SKIP},
{"msgctl", "ret", HEX, "msgid", DECIMAL, "cmd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"fcntl", "ret", HEX, "fd", DECIMAL, "cmd", FCNTL_CMD, "arg2", HEX, "arg3", HEX, NULL, SKIP, NULL, SKIP},
{"flock", "ret", HEX, "fd", DECIMAL, "operaton", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"fsync", "ret", HEX, "fd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"fdatasync", "ret", HEX, "fd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"truncate", "ret", HEX, "*path", HEX, "length", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"ftruncate", "ret", HEX, "fd", DECIMAL, "length", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"getdents", "ret", HEX, "fd", DECIMAL, "*dirp", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getcwd", "ret", HEX, "*buf", HEX, "size", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"chdir", "ret", HEX, "*path", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fchdir", "ret", HEX, "fd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rename", "ret", HEX, "*oldpath", HEX, "*newpath", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mkdir", "ret", HEX, "*pathname", HEX, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rmdir", "ret", HEX, "*pathname", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"creat", "ret", DECIMAL, "*pathname", HEX, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"link", "ret", HEX, "*oldpath", HEX, "*newpath", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"unlink", "ret", HEX, "*pathname", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"symlink", "ret", HEX, "*oldpath", HEX, "*newpath", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"readlink", "ret", HEX, "*path", HEX, "*buf", HEX, "bufsize", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"chmod", "ret", HEX, "*path", HEX, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fchmod", "ret", HEX, "fd", DECIMAL, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"chown", "ret", HEX, "*path", HEX, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fchown", "ret", HEX, "fd", DECIMAL, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lchown", "ret", HEX, "*path", HEX, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"umask", "ret", HEX, "mask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"gettimeofday", "ret", HEX, "*tv", HEX, "*tz", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getrlimit", "ret", HEX, "resource", DECIMAL, "*rlim", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getrusage", "ret", HEX, "who", DECIMAL, "*usage", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sysinfo", "ret", HEX, "*info", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"times", "ret", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ptrace", "ret", HEX, "request", DECIMAL, "pid", DECIMAL, "*addr", HEX, "*data", HEX, NULL, SKIP, NULL, SKIP},
{"getuid", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"syslog", "ret", HEX, "type", DECIMAL, "*bufp", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getgid", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setuid", "ret", HEX, "uid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setgid", "ret", HEX, "gid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"geteuid","ret", HEX,  NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getegid", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setpgid", "ret", HEX, "pid", DECIMAL, "pgid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getppid", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpgrp", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setsid", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setreuid", "ret", HEX, "ruid", DECIMAL, "euid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setregid", "ret", HEX, "rgid", DECIMAL, "egid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getgroups", "ret", HEX, "size", DECIMAL, "list[]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setgroups", "ret", HEX, "size", DECIMAL, "*list[]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setresuid", "ret", HEX, "ruid", DECIMAL, "euid", DECIMAL, "suid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getresuid", "ret", HEX, "*ruid", HEX, "*euid", HEX, "*suid", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setresgid", "ret", HEX, "rgid", DECIMAL, "egid", DECIMAL, "sgid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getresgid", "ret", HEX, "*rgid", HEX, "*egid", HEX, "*sgid", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpgid", "ret", HEX, "pid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setfsuid", "ret", HEX, "fsuid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setfsgid", "ret", HEX, "fsgid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getsid", "ret", HEX, "pid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"capget", "ret", HEX, "hdrp", HEX, "datap", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"capset", "ret", HEX, "hdrp", HEX, "datap", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rt_sigpending", "ret", HEX, "*set", HEX, "sigsetsize", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rt_sigtimedwait", "ret", HEX, "*uthese", HEX, "*uinfo", HEX, "*uts", HEX, "sigsetsize", DECIMAL, NULL, SKIP, NULL, SKIP},
{"rt_sigqueueinfo", "ret", HEX, "pid", DECIMAL, "sig", SIGNAL, "*uinfo", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rt_sigsuspend", "ret", HEX, "*unewset", HEX, "sigsetsize", DECIMAL, "regs", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sigaltstack", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"utime", "ret", HEX, "*filename", HEX, "*times", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mknod", "ret", HEX, "*pathname", HEX, "mode", OCTAL, "dev", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"uselib", "ret", HEX, "*library", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"personality", "ret", HEX, "persona", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ustat", "ret", HEX, "dev", HEX, "*ubuf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"statfs", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstatfs", "ret", HEX, "fd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sysfs", "ret", HEX, "option", DECIMAL, "arg1", HEX, "arg2", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpriority", "ret", HEX, "which", DECIMAL, "who", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setpriority", "ret", HEX, "which", DECIMAL, "who", DECIMAL, "prio", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_setparam", "ret", HEX, "pid", DECIMAL, "*param", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_getparam", "ret", HEX, "pid", DECIMAL, "*param", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_setscheduler", "ret", HEX, "pid", DECIMAL, "policy", DECIMAL, "*param", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"sched_getscheduler", "ret", HEX, "pid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_get_priority_max", "ret", HEX, "policy", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_get_priority_min", "ret", HEX, "policy", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_rr_get_interval", "ret", HEX, "pid", DECIMAL, "*tp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mlock", "ret", DECIMAL, "*addr", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"munlock", "ret", DECIMAL, "*addr", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mlockall", "ret", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"munlockall", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"vhangup", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"modify_ldt", "ret", HEX, "func", HEX, "*ptr", HEX, "bytecount", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pivot_root", "ret", HEX, "*new_root", HEX, "*put_old", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"_sysctl", "ret", HEX, "*args", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"prctl", "ret", HEX, "option", DECIMAL, "arg2", HEX, "arg3", HEX, "arg4", HEX, "arg5", HEX, NULL, SKIP},
{"arch_prctl", "ret", HEX, "code", DECIMAL, "*addr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"adjtimex", "ret", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setrlimit", "ret", HEX, "resource", DECIMAL, "*rlim", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"chroot", "ret", HEX, "*path", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sync", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"acct", "ret", HEX, "*filename", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"settimeofday", "ret", HEX, "*tv", HEX, "*tz", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mount", "ret", HEX, "source", HEX, "*target", HEX, "*filesystemtype", HEX, "mountflags", HEX, "*data", HEX, NULL, SKIP},
{"umount2", "ret", HEX, "*target", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"swapon", "ret", HEX, "*path", HEX, "swapflags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"swapoff", "ret", HEX, "*path", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"reboot", "ret", HEX, "magic", DECIMAL, "magic2", DECIMAL, "cmd", DECIMAL, "*arg", HEX, NULL, SKIP, NULL, SKIP},
{"sethostname", "ret", HEX, "*name", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setdomainname", "ret", HEX, "*name", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"iopl", "ret", HEX, "level", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ioperm", "ret", HEX, "from", DECIMAL, "num", DECIMAL, "turn_on", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"create_module", "ret", HEX, "*name", HEX, "size", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"init_module", "ret", HEX, "*umod", HEX, "len", DECIMAL, "*uargs", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"delete_module", "ret", HEX, "*name_user", HEX, "flags", HEX, "*rqtp", HEX, "*tmtp", HEX, NULL, SKIP, NULL, SKIP}, 
{"get_kernel_syms", "ret", HEX, "*table", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"query_module", "ret", HEX, "*name", HEX, "which", DECIMAL, "*buf", HEX, "bufsize", DECIMAL, "*ret", HEX, NULL, SKIP},
{"quotactl", "ret", HEX, "cmd", DECIMAL, "*special", HEX, "id", DECIMAL, "addr", HEX, NULL, SKIP, NULL, SKIP},
{"nfsservctl", "ret", HEX, "cmd", DECIMAL, "*argp", HEX, "*resp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getpmsg", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"putpmsg", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"afs_syscall", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"tuxcall", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"security", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"gettid", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"readahead", "ret", HEX, "fd", DECIMAL, "offset", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lsetxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fsetxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lgetxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fgetxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"listxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"llistxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"flistxattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"removexattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lremovexattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fremovexattr", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"tkill", "ret", HEX, "tid", DECIMAL, "sig", SIGNAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"time", "ret", HEX, "*t", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"futex", "ret", HEX, "*uaddr", HEX, "op", FUTEX_OP_ARG, "val", HEX, "*timeout", HEX, "*uaddr2", HEX, "val3", FUTEX_VAL3},
{"sched_setaffinity", "ret", HEX, "pid", DECIMAL, "cpusetsize", HEX, "*mask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"sched_getaffinity", "ret", HEX, "pid", DECIMAL, "cpusetsize", HEX, "*mask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"set_thread_area", "ret", HEX, "*u_info", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"io_setup", "ret", HEX, "nr_events", DECIMAL, "*ctxp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"io_destroy", "ret", HEX, "ctx", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"io_getevents", "ret", HEX, "ctx_id", HEX, "min_nr", DECIMAL, "nr", DECIMAL, "*events", HEX, "*timeout", HEX, NULL, SKIP},
{"io_submit", "ret", HEX, "ctx_id", HEX, "nr", DECIMAL, "**iocbpp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"io_cancel", "ret", HEX, "ctx_id", HEX, "*iocb", HEX, "*result", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"get_thread_area", "ret", HEX, "*u_info", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lookup_dcookie", "ret", HEX, "cookie", HEX, "*buffer", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"epoll_create", "ret", HEX, "size", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"epoll_ctl_old", "ret", HEX, "epfd", DECIMAL, "op", DECIMAL, "fd", DECIMAL, "*event", HEX, NULL, SKIP, NULL, SKIP},
{"epoll_wait_old", "ret", HEX, "epfd", DECIMAL, "*events", HEX, "maxevents", DECIMAL, "timeout", DECIMAL, NULL, SKIP, NULL, SKIP},
{"remap_file_pages", "ret", HEX, "*addr", HEX, "size", DECIMAL, "prot", HEX, "pgoff", HEX, "flags", HEX, NULL, SKIP},
{"getdents64", "ret", HEX, "fd", DECIMAL, "*dirp", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"set_tid_address", "ret", HEX, "*tidptr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"restart_sycsall", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"semtimedop", "ret", HEX, "semid", DECIMAL, "*sops", HEX, "nsops", DECIMAL, "*timeout", HEX, NULL, SKIP, NULL, SKIP},
{"fadvise64", "ret", HEX, "fs", DECIMAL, "offset", HEX, "len", DECIMAL, "advise", DECIMAL, NULL, SKIP, NULL, SKIP}, 
{"timer_create", "ret", HEX, "which_clock", DECIMAL, "*time_event_spec", HEX, "*created_time_id", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"timer_settime", "ret", HEX, "timer_id", DECIMAL, "flags", HEX, "*new_setting", HEX, "*old_setting", HEX, NULL, SKIP, NULL, SKIP},
{"timer_gettime", "ret", HEX, "timer_id", DECIMAL, "*setting", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"timer_getoverrun", "ret", HEX, "timer_id", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"timer_delete", "ret", HEX, "timer_id", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clock_settime", "ret", HEX, "which_clock", DECIMAL, "*tp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clock_gettime", "ret", HEX, "which_clock", DECIMAL, "*tp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clock_getres", "ret", HEX, "which_clock", DECIMAL, "*tp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clock_nanosleep", "ret", HEX, "which_clock", DECIMAL, "flags", HEX, "*rqtp", HEX, "*rmtp", HEX, NULL, SKIP, NULL, SKIP},
{"exit_group", "ret", HEX, "status", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"epoll_wait", "ret", HEX, "epfd", DECIMAL, "*events", HEX, "maxevents", DECIMAL, "timeout", DECIMAL, NULL, SKIP, NULL, SKIP},
{"epoll_ctl_old", "ret", HEX, "epfd", DECIMAL, "op", DECIMAL, "fd", DECIMAL, "*event", HEX, NULL, SKIP, NULL, SKIP},
{"tgkill", "ret", HEX, "tgid", DECIMAL, "pid", DECIMAL, "sig", SIGNAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"utimes", "ret", HEX, "*filename", HEX, "times[2]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"vserver", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mbind", "ret", HEX, "*addr", HEX, "len", HEX, "mode", HEX, "*nodemask", HEX, "maxnode", DECIMAL, "flags", HEX},
{"set_mempolicy", "ret", HEX, "mode", HEX, "*nodemask", HEX, "maxnode", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"get_mempolicy", "ret", HEX, "mode", HEX, "*nodemask", HEX, "maxnode", DECIMAL, "addr", HEX, "flags", HEX, NULL, SKIP},
{"mq_open", "ret", HEX, "*name", HEX, "oflag", HEX, "mode", HEX, "*attr", HEX, NULL, SKIP, NULL, SKIP},
{"mq_unlink", "ret", HEX, "name", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mq_timedsend", "ret", HEX, "mqdes", DECIMAL, "*msg_ptr", HEX, "msg_len", DECIMAL, "msg_prio", DECIMAL, "*abs_timeout", HEX, NULL, SKIP},
{"mq_timedreceive", "ret", HEX, "mqdes", DECIMAL, "*msg_ptr", HEX, "msg_len", DECIMAL, "*msg_prio", HEX, "*abs_timeout", HEX, NULL, SKIP},
{"mq_notify", "ret", HEX, "mqdes", DECIMAL, "*notification", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mq_getsetattr", "ret", HEX, "mqdes", DECIMAL, "*newattr", HEX, "*oldattr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"kexec_load", "ret", HEX, "entry", DECIMAL, "nr_segments", DECIMAL, "*segments", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"waitid", "ret", HEX, "idtype", DECIMAL, "id", DECIMAL, "*infop", HEX, "options", HEX, NULL, SKIP, NULL, SKIP},
{"add_key", "ret", HEX, "*type", HEX, "*description", HEX, "*payload", HEX, "plen", DECIMAL, "keyring", HEX, NULL, SKIP}, 
{"request_key", "ret", HEX, "*type", HEX, "*description", HEX, "*callout_info", HEX, "keyring", HEX, NULL, SKIP, NULL, SKIP},
{"keyctl", "ret", HEX, "cmd", DECIMAL, "arg1", HEX, "arg2", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ioprio_set", "ret", HEX, "which", DECIMAL, "who", DECIMAL, "ioprio", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ioprio_get", "ret", HEX, "which", DECIMAL, "who", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"inotify_init", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"inotify_add_watch", "ret", HEX, "fd", DECIMAL, "*pathname", HEX, "mask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"inotify_rm_watch", "ret", HEX, "fd", DECIMAL, "wd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"migrate_pages", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"openat", "ret", DECIMAL, "dirfd", DECIMAL, "*pathname", HEX, "flags", OFLAGS, "mode", OCTAL, NULL, SKIP, NULL, SKIP},
{"mkdirat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "mode", OCTAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mknodat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "mode", OCTAL, "dev", HEX, NULL, SKIP, NULL, SKIP},
{"fchownat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "owner", DECIMAL, "group", DECIMAL, "flags", HEX, NULL, SKIP},
{"futimesat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "times[2]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstatat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "*buf", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"unlinkat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"renameat", "ret", HEX, "olddirfd", DECIMAL, "*oldpath", HEX, "newdirfd", DECIMAL, "*newpath", HEX, NULL, SKIP, NULL, SKIP},
{"linkat", "ret", HEX, "olddirfd", DECIMAL, "*oldpath", HEX, "newdirfd", DECIMAL, "*newpath", HEX, "flags", HEX, NULL, SKIP},
{"symlinkat", "ret", HEX, "*oldpath", HEX, "newdirfd", DECIMAL, "*newpath", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"readlinkat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "*buf", HEX, "bufsize", DECIMAL, NULL, SKIP, NULL, SKIP},
{"fchmodat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "mode", OCTAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"faccessat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "mode", OCTAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"pselect6", "ret", HEX, "nfds", DECIMAL, "*readfds", HEX, "*writefds", HEX, "*exceptfds", HEX, "*timeout", HEX, "*sigmask", HEX},
{"ppoll", "ret", HEX, "*fds", HEX, "nfds", DECIMAL, "*timeout", HEX, "*sigmask", HEX, NULL, SKIP, NULL, SKIP},
{"unshare", "ret", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"set_robust_list", "ret", HEX, "*head", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"get_robust_list", "ret", HEX, "pid", DECIMAL, "**head_ptr", HEX, "*len_ptr", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"splice", "ret", HEX, "fd_in", DECIMAL, "*off_in", HEX, "fd_out", DECIMAL, "*off_out", HEX, "len", DECIMAL, "flags", HEX},
{"tee", "ret", HEX, "fd_in", DECIMAL, "fd_out", DECIMAL, "len", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"sync_file_range", "ret", HEX, "fd", DECIMAL, "offset", HEX, "nbytes", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP}, 
{"vmsplice", "ret", HEX, "fd", DECIMAL, "*iov", HEX, "nr_segs", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP}, 
{"move_pages", "ret", HEX, "pid", DECIMAL, "nr_pages", DECIMAL, "**address", HEX, "*nodes", HEX, "*status", HEX, "flags", HEX},
{"utimensat", "ret", HEX, "dirfd", DECIMAL, "*pathname", HEX, "times[2]", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP}, 
{"epoll_pwait", "ret", HEX, "epfd", DECIMAL, "*events", HEX, "maxevents", DECIMAL, "timeout", DECIMAL, "*sigmask", HEX, NULL, SKIP},
{"signalfd", "ret", HEX, "fd", DECIMAL, "*mask", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"timerfd_create", "ret", HEX, "clockid", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"eventfd", "ret", HEX, "initval", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"fallocate", "ret", HEX, "fd", DECIMAL, "mode", HEX, "offset", HEX, "len", DECIMAL, NULL, SKIP, NULL, SKIP},
{"timerfd_settime", "ret", HEX, "fd", DECIMAL, "flags", HEX, "*new_value", HEX, "*old_value", HEX, NULL, SKIP, NULL, SKIP},
{"timerfd_gettime", "ret", HEX, "fd", DECIMAL, "*curr_value", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"accept4", "ret", HEX, "sockfd", DECIMAL, "*addr", HEX, "addrlen", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"signalfd4", "ret", HEX, "fd", DECIMAL, "*mask", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"eventfd2", "ret", HEX, "initval", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"epoll_create1", "ret", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"dup3", "ret", HEX, "oldfd", DECIMAL, "newfd", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pipe2", "ret", HEX, "pipefd[2]", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"inotify_init1", "ret", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"preadv", "ret", HEX, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, "offset", HEX, NULL, SKIP, NULL, SKIP},
{"pwritev", "ret", HEX, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, "offset", HEX, NULL, SKIP, NULL, SKIP},
{"rt_tgsigqueueinfo", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"perf_event_open", "ret", HEX, "arg0", HEX, "arg1", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"recvmmsg", "ret", HEX, "sockfd", DECIMAL, "*msgvec", HEX, "vlen", DECIMAL, "flags", HEX, "*timeout", HEX, NULL, SKIP},
{"fanotify_init", "ret", DECIMAL, "flags", HEX, "event_f_flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fanotify_mark", "ret", DECIMAL, "fanotify_fd", DECIMAL, "flags", HEX, "mask", HEX, "dirfd", DECIMAL, "*pathname", HEX, NULL, SKIP},
{"prlimit64", "ret", DECIMAL, "pid", DECIMAL, "resouce", DECIMAL, "*new_limit", HEX, "*old_limit", HEX, NULL, SKIP, NULL, SKIP},
{"name_to_handle_at", "ret", DECIMAL, "dirfd", DECIMAL, "*pathname", HEX, "*handle", HEX, "*mount_id", HEX, "flags", HEX, NULL, SKIP},
{"open_by_handle_at", "ret", DECIMAL, "mount_fd", DECIMAL, "*handle", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clock_adj_time", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"syncfs", "ret", DECIMAL, "fd", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sendmmsg", "ret", HEX, "sockfd", DECIMAL, "*msgvec", HEX, "vlen", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"set_ns", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"get_cpu", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"process_vm_readv", "ret", DECIMAL, "pid", DECIMAL, "*local_iov", HEX, "liovcnt", DECIMAL, "*remote_iov", HEX, "riovcnt", DECIMAL, "flags", HEX},
{"process_vm_writev", "ret", DECIMAL, "pid", DECIMAL, "*local_iov", HEX, "liovcnt", DECIMAL, "*remote_iov", HEX, "riovcnt", DECIMAL, "flags", HEX},
{"kcmp", "ret", DECIMAL, "pid1", DECIMAL, "pid2", DECIMAL, "type", DECIMAL, "idx1", DECIMAL, "idx2", DECIMAL, NULL, SKIP},
{"finit_module", "ret", DECIMAL, "fd", DECIMAL, "*param_values", HEX, "flags", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_setattr", "ret", DECIMAL, "pid", DECIMAL, "*attr", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sched_getattr", "ret", DECIMAL, "pid", DECIMAL, "*attr", HEX, "size", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"renameat2", "ret", HEX, "olddirfd", DECIMAL, "*oldpath", HEX, "newdirfd", DECIMAL, "*newpath", HEX, "flags", HEX, NULL, SKIP},
{"seccomp", "ret", DECIMAL, "operation", DECIMAL, "flags", HEX, "*args", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getrandom", "ret", DECIMAL, "buf", HEX, "buflen", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"memfd_create", "ret", DECIMAL, "*name", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"kexec_file_load", "ret", DECIMAL, "entry", HEX, "nr_segments", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"bpf", "ret", DECIMAL, "cmd", DECIMAL, "*attr", HEX, "size", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"execveat", "ret", DECIMAL, "dirfd", DECIMAL, "*pathname", HEX, "*argv", HEX, "*envp", HEX, "flags", HEX, NULL, SKIP},
{"userfaultfd", "ret", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"membarrier", "ret", DECIMAL, "cmd", DECIMAL, "flags", HEX, "cpu_id", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mlock2", "ret", DECIMAL, "*addr", HEX, "len", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"copy_file_range", "ret", HEX, "fd_in", DECIMAL, "*off_in", HEX, "fd_out", DECIMAL, "*off_out", HEX, "len", HEX, "flags", DECIMAL},
{"preadv2", "ret", HEX, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, "offset", HEX, "flags", HEX, NULL, SKIP},
{"pwritev2", "ret", HEX, "fd", DECIMAL, "*iov", HEX, "iovcnt", DECIMAL, "offset", HEX, "flags", HEX, NULL, SKIP},
{"pkey_mprotect", "ret", DECIMAL, "addr", HEX, "len", HEX, "prot", HEX, "pkey", DECIMAL, NULL, SKIP, NULL, SKIP},
{"pkey_alloc", "ret", DECIMAL, "flags", HEX, "access_rights", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pkey_free", "ret", DECIMAL, "key", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"statx", "ret", DECIMAL, "dirfd", DECIMAL, "*pathname", HEX, "flags", HEX, "mask", HEX, "*restrict", HEX, NULL, SKIP},
{"io_pgetevents", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"rseq", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-335", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-336", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-337", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-338", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-339", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-340", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-341", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-342", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-343", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-344", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-345", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-346", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-347", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-348", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-349", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-350", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-351", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-352", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-353", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-354", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-355", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-356", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-357", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-358", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-359", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-360", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-361", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-362", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-363", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-364", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-365", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-366", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-367", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-368", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-369", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-370", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-371", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-372", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-373", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-374", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-375", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-376", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-377", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-378", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-379", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-380", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-381", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-382", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-383", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-384", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-385", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-386", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-387", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-388", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-389", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-390", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-391", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-392", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-393", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-394", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-395", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-396", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-397", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-398", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-399", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-400", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-401", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-402", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-403", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-404", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-405", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-406", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-407", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-408", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-409", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-410", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-411", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-412", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-413", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-414", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-415", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-416", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-417", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-418", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-419", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-420", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-421", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-422", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-423", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pidfd_send_signal", "ret", DECIMAL, "pidfd", DECIMAL, "sig", DECIMAL, "*info", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"io_uring_setup", "ret", DECIMAL, "entries", DECIMAL, "*p", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"io_uring_enter", "ret", DECIMAL, "fd", DECIMAL, "to_submit", DECIMAL, "min_complete", DECIMAL, "flags", HEX, "*sig", HEX, NULL, SKIP},
{"io_uring_register", "ret", DECIMAL, "fd", DECIMAL, "opcode", DECIMAL, "*arg", HEX, "nr_args", DECIMAL, "*sig", HEX, NULL, SKIP},
{"open_tree", "ret", DECIMAL, "dfd", DECIMAL, "*path", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"move_mount", "ret", DECIMAL, "from_dfd", DECIMAL, "*from_path", HEX, "to_dfd", DECIMAL, "*to_path", HEX, "ms_flags", HEX, NULL, SKIP},
{"fsopen", "ret", DECIMAL, "*fs_name", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fsconfig", "ret", DECIMAL, "fs_fd", DECIMAL, "cmd", DECIMAL, "*key", HEX, "*value", HEX, "aux", DECIMAL, NULL, SKIP},
{"fsmount", "ret", DECIMAL, "fs_fd", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fspick", "ret", DECIMAL, "dfd", DECIMAL, "*path", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pidfd_open", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"clone3", "ret", DECIMAL, "*cl_args", HEX, "size", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"close_range", "ret", DECIMAL, "first", DECIMAL, "last", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"openat2", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"pidfd_getfd", "ret", DECIMAL, "pidfd", DECIMAL, "fd", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"faccessat2", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"proc_madvise", "ret", DECIMAL,  NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"epoll_pwait2", "ret", DECIMAL, "epfd", DECIMAL, "*events", HEX, "maxevents", DECIMAL, "*timeout", HEX, "*sigmask", HEX, NULL, SKIP},
{"mount_setattr", "ret", DECIMAL, "dirfd", DECIMAL, "*pathname", HEX, "flags", HEX, "*attr", HEX, "size", HEX, NULL, SKIP},
{"sys_quotactl_fd", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"landlock_create_ruleset", "ret", DECIMAL, "*attr", HEX, "size", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"landlock_add_rule", "ret", DECIMAL, "ruleset_fd", DECIMAL, "rule_type", DECIMAL, "*rule_attr", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP},
{"landlock_restrict_self", "ret", DECIMAL, "ruleset_fd", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"memfd_secret", "ret", DECIMAL, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"process_mrelease", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"futex_waitv", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"set_mempolicy_home_node", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"cachestat", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fchmodat2", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"map_shadow_stack", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"futex_wake", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"futex_wait", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"futex_requeue", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"statmount", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"listmount", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lsm_get_self_attr", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lsm_set_self_attr", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lsm_list_modules", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-462", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-463", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-464", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-465", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-466", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-467", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-468", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-469", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-470", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-471", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-472", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-473", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-474", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-475", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-476", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-477", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-478", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-479", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-480", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-481", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-482", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-483", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-484", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-485", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-486", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-487", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-488", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-489", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-490", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-491", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-492", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-493", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-494", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-495", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-496", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-497", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-498", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-499", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
/* system call definitions below are for 32-bit system calls.  See SYSCALL32 */
{"waitpid", "ret", HEX, "pid", DECIMAL, "*status", HEX, "options", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"break", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"oldstat", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"umount", "ret", HEX, "*target", HEX, "flags", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"stime", "ret", HEX, "*t", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"oldfstat", "ret", HEX, "fd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"stty", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"gtty", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"nice", "ret", HEX, "inc", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ftime", "ret", HEX, "*tp", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"prof", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"signal", "ret", HEX, "signum", DECIMAL, "handler", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lock", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mpx", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ulimit", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"oldolduname", "ret", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sigaction", "ret", HEX, "sig", SIGNAL, "*act", HEX, "*oact", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sgetmask", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ssetmask", "ret", HEX, "newmask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sigsuspend", "ret", HEX, "*mask", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sigpending", "ret", HEX, "*set", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"oldlstat", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"readdir", "ret", HEX, "fd", DECIMAL, "*dirp", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"profil", "ret", HEX, "*buf", HEX, "bufsiz", DECIMAL, "offset", HEX, "scale", DECIMAL, NULL, SKIP, NULL, SKIP},
{"socketcall", "ret", HEX, "call", DECIMAL, "*args", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"olduname", "ret", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"idle", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"vm86old", "ret", HEX, "*info", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ipc", "ret", HEX, "call", IPC_CALL, "first", HEX, "second", HEX, "third", HEX, "*ptr", HEX, "fifth", HEX},
{"sigreturn", "ret", HEX, "__unused", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sigprocmask", "ret", HEX, "how", SIGHOW, "*set", HEX, "*oset", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"bdflush", "ret", HEX, "func", HEX, "*address", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"_llseek", "ret", HEX, "fd", DECIMAL, "offset_hi", HEX, "offset_lo", HEX, "*result", HEX, "whence", WHENCE, NULL, SKIP},
{"_newselect", "ret", HEX, "nfds", DECIMAL, "*readfds", HEX, "*writefds", HEX, "*exceptfds", HEX, "*timeout", HEX, NULL, SKIP},
{"vm86", "ret", HEX, "fn", HEX, "*v86", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ugetrlimit", "ret", HEX, "resource", DECIMAL, "*rlim", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"mmap2", "ret", HEX, "*addr", HEX, "length", HEX, "prot", HEX, "flags", HEX, "fd", DECIMAL, "pgoffset", HEX},
{"truncate64", "ret", HEX, "*path", HEX, "length", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"ftruncate64", "ret", HEX, "fd", DECIMAL, "length", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}, 
{"stat64", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lstat64", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstat64", "ret", HEX, "fd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"lchown32", "ret", HEX, "*path", HEX, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getuid32", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getgid32", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"geteuid32", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getegid32", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setreuid32", "ret", HEX, "ruid", DECIMAL, "euid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setregid32", "ret", HEX, "rgid", DECIMAL, "egid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getgroups32", "ret", HEX, "size", DECIMAL, "list[]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setgroups32", "ret", HEX, "size", DECIMAL, "*list[]", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fchown32", "ret", HEX, "fd", DECIMAL, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setresuid32", "ret", HEX, "ruid", DECIMAL, "euid", DECIMAL, "suid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getresuid32", "ret", HEX, "*ruid", HEX, "*euid", HEX, "*suid", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setresgid32", "ret", HEX, "rgid", DECIMAL, "egid", DECIMAL, "sgid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getresgid32", "ret", HEX, "*rgid", HEX, "*egid", HEX, "*sgid", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"chown32", "ret", HEX, "*path", HEX, "owner", DECIMAL, "group", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setuid32", "ret", HEX, "uid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setgid32", "ret", HEX, "gid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setfsuid32", "ret", HEX, "fsuid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"setfsgid32", "ret", HEX, "fsgid", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fcntl64", "ret", HEX, "fd", DECIMAL, "cmd", DECIMAL, "arg2", HEX, "arg3", HEX, NULL, SKIP, NULL, SKIP},
{"ukn-222", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-223", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"sendfile64", "ret", DECIMAL, "out_fd", DECIMAL, "in_fd", DECIMAL, "*offset", HEX, "count", DECIMAL, NULL, SKIP, NULL, SKIP},
{"sys_set_zone_reclaim", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"statfs64", "ret", HEX, "*path", HEX, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstatfs64", "ret", HEX, "fd", DECIMAL, "*buf", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fadvise64_64", "ret", HEX, "fs", DECIMAL, "offset", HEX, "len", DECIMAL, "advise", DECIMAL, NULL, SKIP, NULL, SKIP}, 
{"sys_setaltroot", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"fstatat64", "ret", HEX, "arg0=", HEX, "arg1=", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"getcpu", "ret", HEX, "*cpu", HEX, "*node", HEX, "*tcache", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"send", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"recv", "ret", DECIMAL, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-474", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-475", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-476", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-477", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-478", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-479", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-480", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-481", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-482", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-483", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-484", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-485", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-486", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-487", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-488", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-489", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-490", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-491", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-492", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-493", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-494", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-495", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-496", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-497", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"ukn-498", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP},
{"unknown", "ret", HEX, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP, NULL, SKIP}
};

warnmsg_t warnmsg[MAXNOTEWARN] = {
	{ "Warning: CPU Bottleneck (Idle < 10%)", NULL, NULL },
	{ "Warning: Excessive Disk Block re-reads detected (Freq > 20)", NULL, NULL },
	{ "Warning: Barrier Writes detected (Freq > 20)", _HTTP_BARRIERS, NULL },
	{ "Warning: Suspect SAP worker task with many semget() errors (Freq > 100)", _HTTP_SEMGET, NULL },
	{ "Warning: Excessive Block I/O requeues detected", NULL },
	{ "Warning: Average Service Times > 30 msecs", NULL },
	{ "Warning: Spinlock contention detected in ext4 journal due to writes by kiinfo", NULL},
	{ "Warning: Performance impact due to excessive page migrations", _HTTP_NUMA_BALANCING},
	{ "Warning: Check for un-terminated lans on IXGBE network interface cards", _HTTP_UNTERMINATED_IXGBE},
	{ "Warning: System booted with NUMA features disabled.", _HTTP_NUMA_OFF},
	{ "Warning: Suspect large SEMMSL value causing high System CPU usage", _HTTP_SEMLOCK},
	{ "Warning: CPU Stealtime > 10%", NULL},
	{ "Warning: Delayed I/Os detected", NULL},
	{ "Warning: Suspect Unaligned XFS Direct I/O", _HTTP_XFS_DIO_UNALIGNED},
	{ "Warning: Suspect XFS Direct I/O with cached pages", _HTTP_XFS_DIOREAD},
	{ "Warning: Excessive Tasklet SoftIRQs", _HTTP_TASKLET},
	{ "Warning: System enabled for power savings", _HTTP_POWER},
	{ "Warning: RHEL 7.3 and SLES 12 SP2 Multipath bug may impact I/O performance", _HTTP_MULTIPATH_BUG},
	{ "Warning: Suspect network-latency tuned profile used", _HTTP_SK_BUSY},
	{ "Warning: High BLOCK SotIRQ times, consider setting add_random to 0 for all /dev/sd* devices", _HTTP_ADD_RANDOM},
	{ "Warning: High wait time in md_flush(), suspect barrier writes to MD device", _HTTP_MD_FLUSH},
	{ "Warning: Spinlock contention during hugetlb_fault", _HTTP_HUGETLB_FAULT},
	{ "Warning: High CPU time or Contention on /proc/stats due to high CPU and IRQ count", _HTTP_KSTAT_IRQS}, 
	{ "Warning: Excessive poll() calls by Oracle", _HTTP_ORACLE_POLL},
	{ "Warning: Excessive CPU time in pcc_cpufreq driver", _HTTP_PCC_CPUFREQ},
	{ "Warning: Security mitigations present", _HTTP_SSA_VULN},
	{ "Warning: TCP Timeouts Detected", _HTTP_TCP_TIMEOUTS},
	{ "Warning: Excessive page faults on KVM host, consider using Huge Pages", _HTTP_KVM_PAGEFAULT},
	{ "Warning: Excessive CPU time in SQL stats code. Consider disabling stats", _HTTP_SQL_STATS},
	{ "Warning: Excessive CPU time in Oracle column stats code. Consider disabling column stats", _HTTP_ORACLE_COLSTATS},
	{ "Warning: Large I/Os (>1MB)  may degradge performance on PCIe Smart Array Controllers", _HTTP_CACHE_BYPASS},
	{ "Warning: Memory is not balanced across NUMA nodes, check for missing/unconfigured memory DIMMS", NULL},
	{ "Warning: Memory on one or more NUMA nodes is below 100 MB", NULL},
	{ "Warning: Threads delayed on RunQ with max wait time more than 100 msecs", _HTTP_RUNQ_DELAYS},
	{ "Warning: High System CPU utilization during memory allocations, deallocations, and page faults", _HTTP_LARGE_NUMA_NODE},
        { "Warning: System is using clocksource other than tsc", _HTTP_CLOCKSOURCE},
        { "Warning: Spinlock contention caused by systemd --user and high number of user logins/logoffs", _HTTP_SYSTEMD_USER},
	{ "Warning: Suspect SOS_BLOCKALLOCPARTIALLIST spinlock contention", _HTTP_MEMBLOCK_ALLOC}
};


char *win_thread_state[MaxThreadStates] = {
	"Initialized",
	"Ready",
	"Running",
	"Standby",
	"Terminated",
	"Waiting",
	"Transistion",
	"DeferredReady",
	"Unknown-8",
	"Unknown-9"

};

char *win_thread_mode[MaxThreadWaitMode] = {
	"Kernel",
	"User"
};

char *win_thread_wait_reason[MaxThreadWaitReasons] = {
	"Executive",
	"FreePage",
	"PageIn",
	"PoolAllocation",
	"DelayAllocation",
	"Suspended",
	"UserRequest",
	"WrExecutive",
	"WrFreePage",
	"WrPageIn",
	"WrPoolAllocation",
	"WrDelayExecution",
	"WrSuspended",
	"WrUserRequest",
	"WrEventPair",
	"WrQueue",
	"WrLpcReceive",
	"WrLpcReply",
	"WrVirtualMemory",
	"WrPageOut",
	"WrRendezvious",
	"WrKeyedEvent",
	"WrTerminated",
	"WrProcessInSwap",
	"WrCpuRateControl",
	"WrCalloutStack",
	"WrKernel",
	"WrResource",
	"WrPushLock",
	"WrMutex",
	"WrQuantumEnd",
	"WrDispatchInt",
	"WrPreempted",
	"WrYieldExecution",
	"WrFastMutex",
	"WrGuardedMutex",
	"WrRundown",
	"WrAlertThreadId",
	"WrDeferredPreempt",
	"Unknown"
};

char *win_irq_flags[IRQ_NRBIT] = {
	"Nocache",
	"MountCompletion",
	"SynchronousApi",
	"AssociatedIrp",
	"BufferedIo",
	"DeallocateBuffer",
	"SynchronousPagingIo",
	"CreateOperation",
	"ReadOperation",
	"WriteOperation",
	"CloseOperation",
	"DeferIoCompletion",
	"ObQueryName",
	"HoldDeviceQueue",
	"RetryIoCOmpletion",
	"ClassCacheOperation"
};

char *nvidiactl_ioctl[NVIDIA_NRCTLS] = {
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x10 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x20 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_CREATE_VSPACE",   	/* 0x27 */
	"NVIDIA_IOCTL_CREATE_SIMPLE",   	/* 0x28 */
	"NVIDIA_IOCTL_DESTROY",		   	/* 0x29 */
	"NVIDIA_IOCTL_CALL",		   	/* 0x2a */
	"NVIDIA_IOCTL_CREATE",		   	/* 0x2b */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x30 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_GET_PARAM", 	  	/* 0x32 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_QUERY",           	/* 0x37 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x40 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_MEMORY",			/* 0x4a */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x4d */
	"NVIDIA_IOCTL_HOST_MAP",		/* 0x4e */
	"NVIDIA_IOCTL_HOST_UNMAP",		/* 0x4f */
	"NVIDIA_IOCTL_?",			/* 0x50 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_CREATE_DMA",		/* 0x54 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_VSPACE_MAP",		/* 0x57 */
	"NVIDIA_IOCTL_VSPACE_UNMAP",		/* 0x58 */
	"NVIDIA_IOCTL_BIND",			/* 0x59 */
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",
	"NVIDIA_IOCTL_?",			/* 0x5e */
	"NVIDIA_IOCTL_?",			/* 0x5f */
	"NVIDIA_IOCTL_?",			/* 0x60 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0x70 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0x80 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0x90 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0xa0 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0xb0 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			/* 0xc0 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_CARD_INFO",			/* 0xc8 */
	"NVIDIA_IOCTL_?",					
	"NVIDIA_IOCTL_ENV_INFO",			/* 0xca */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_CREATE_OS_EVENT", 		/* 0xce */
	"NVIDIA_IOCTL_DESTROY_OS_EVENT", 		/* 0xcf */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_CHECK_VERSION_STR",		/* 0xd2 */
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?",			
	"NVIDIA_IOCTL_?"
};

char *uvm_ioctl[UVM_NRCTLS] = {
        "UVM_IOCTL?",
	"UVM_RESERVE_VA",
	"UVM_RELEASE_VA",
	"UVM_REGION_COMMIT",
	"UVM_REGION_DECOMMIT",
	"UVM_REGION_SET_STREAM",
	"UVM_SET_STREAM_RUNNING",
	"UVM_SET_STREAM_STOPPED",
	"UVM_IOCTL?",
	"UVM_RUN_TEST",
	"UVM_ADD_SESSION",
	"UVM_REMOVE_SESSION",
	"UVM_ENABLE_COUNTERS",
	"UVM_MAP_COUNTER",
	"UVM_CREATE_EVENT_QUEUE",
	"UVM_REMOVE_EVENT_QUEUE",
	"UVM_MAP_EVENT_QUEUE",
	"UVM_EVENT_CTRL",
	"UVM_REGISTER_MPS_SERVER",
	"UVM_REGISTER_MPS_CLIENT",
	"UVM_GET_GPU_UUID_TABLE",
	"UVM_REGION_SET_BACKING",
	"UVM_REGION_UNSET_BACKING",
	"UVM_CREATE_RANGE_GROUP",
	"UVM_DESTROY_RANGE_GROUP",
	"UVM_REGISTER_GPU_VASPACE",
	"UVM_UNREGISTER_GPU_VASPACE",
	"UVM_REGISTER_CHANNEL",
	"UVM_UNREGISTER_CHANNEL",
	"UVM_ENABLE_PEER_ACCESS",
	"UVM_DISABLE_PEER_ACCESS",
	"UVM_SET_RANGE_GROUP"
	"UVM_IOCTL?",
	"UVM_MAP_EXTERNAL_ALLOCATION",
	"UVM_FREE",
	"UVM_MEM_MAP",
	"UVM_DEBUG_ACCESS_MEMORY",
	"UVM_REGISTER_GPU",
	"UVM_UNREGISTER_GPU",
	"PAGEABLE_MEM_ACCESS",
	"UVM_PREVENT_MIGRATION_RANGE_GROUPS",
	"UVM_ALLOW_MIGRATION_RANGE_GROUPS",
	"UVM_SET_PREFERRED_LOCATION",
	"UVM_UNSET_PREFERRED_LOCATION",
	"UVM_ENABLE_READ_DUPLICATION",
	"UVM_DISABLE_READ_DUPLICATION",
	"UVM_SET_ACCESSED_BY",
	"UVM_UNSET_ACCESSED_BY",
	"UVM_IOCTL?",
	"UVM_IOCTL?",
	"UVM_IOCTL?",
	"UVM_MIGRATE",
	"UVM_IOCTL?",
	"UVM_MIGRATE_RANGE_GROUP",
	"UVM_ENABLE_SYSTEM_WIDE_ATOMICS",
	"UVM_DISABLE_SYSTEM_WIDE_ATOMICS",
	"UVM_TOOLS_INIT_EVENT_TRACKER",
	"UVM_TOOLS_SET_NOTIFICATION_THRESHOLD",
	"UVM_TOOLS_EVENT_QUEUE_ENABLE_EVENTS",
	"UVM_TOOLS_EVENT_QUEUE_DISABLE_EVENTS",
	"UVM_TOOLS_ENABLE_COUNTERS",
	"UVM_TOOLS_DISABLE_COUNTERS",
	"UVM_TOOLS_READ_PROCESS_MEMORY",
	"UVM_TOOLS_WRITE_PROCESS_MEMORY",
	"UVM_TOOLS_GET_PROCESSOR_UUID_TABLE",
	"UVM_MAP_DYNAMIC_PARALLELISM_REGION",
	"UVM_UNMAP_EXTERNAL",
	"UVM_TOOLS_FLUSH_EVENTS",
	"UVM_ALLOC_SEMAPHORE_POOL",
	"UVM_CLEAN_UP_ZOMBIE_RESOURCES",
	"UVM_PAGEABLE_MEM_ACCESS_ON_GPU",
	"UVM_POPULATE_PAGEABLE",
	"UVM_VALIDATE_VA_RANGE",
	"UVM_CREATE_EXTERNAL_RANGE",
	"UVM_MAP_EXTERNAL_SPARSE",
	"UVM_MM_INITIALIZE",
	"UVM_IOCTL?",
	"UVM_IOCTL?",
	"UVM_IOCTL?",
	"UVM_IOCTL?"
};


char *drm_ioctl[DRM_NRCTLS] = {
	"DRM_IOCTL_VERSION",
	"DRM_IOCTL_GET_UNIQUE",
	"DRM_IOCTL_GET_MAGIC",
	"DRM_IOCTL_IRQ_BUSID",
	"DRM_IOCTL_GET_MAP", 
	"DRM_IOCTL_GET_CLIENT",
	"DRM_IOCTL_GET_STATS",
	"DRM_IOCTL_SET_VERSION",
	"DRM_IOCTL_MODESET_CTL",
	"DRM_IOCTL_GEM_CLOSE",
	"DRM_IOCTL_GEM_FLINK",
	"DRM_IOCTL_GEM_OPEN",
	"DRM_IOCTL_GET_CAP",
	"DRM_IOCTL_SET_CLIENT_CAP",
	"DRM_IOCTL_?",				
	"DRM_IOCTL_?",
	"DRM_IOCTL_SET_UNIQUE",			/* 0x10 */
	"DRM_IOCTL_AUTH_MAGIC",
	"DRM_IOCTL_BLOCK",
	"DRM_IOCTL_UNBLOCK",
	"DRM_IOCTL_CONTROL",
	"DRM_IOCTL_ADD_MAP",
	"DRM_IOCTL_ADD_BUFS",
	"DRM_IOCTL_MARK_BUFS",
	"DRM_IOCTL_INFO_BUFS",
	"DRM_IOCTL_MAP_BUFS",
	"DRM_IOCTL_FREE_BUFS",
	"DRM_IOCTL_RM_MAP",
	"DRM_IOCTL_SET_SAREA_CTX",
	"DRM_IOCTL_GET_SAREA_CTX",
	"DRM_IOCTL_SET_MASTER",
	"DRM_IOCTL_DROP_MASTER",
	"DRM_IOCTL_ADD_CTX",			/* 0x20 */
	"DRM_IOCTL_RM_CTX",
	"DRM_IOCTL_MOD_CTX",
	"DRM_IOCTL_GET_CTX",
	"DRM_IOCTL_SWITCH_CTX",
	"DRM_IOCTL_NEW_CTX",
	"DRM_IOCTL_RES_CTX",
	"DRM_IOCTL_ADD_DRAW",
	"DRM_IOCTL_RM_DRAW",
	"DRM_IOCTL_DMA",				
	"DRM_IOCTL_LOCK",
	"DRM_IOCTL_UNLOCK",
	"DRM_IOCTL_FINISH",
	"DRM_IOCTL_PRIME_HANDLE_TO_FD",	
	"DRM_IOCTL_PRIMT_FD_TO_HANDLE",
	"DRM_IOCTL_?",
	"DRM_IOCTL_AGP_ACQUIRE",		/* 0x30 */
	"DRM_IOCTL_AGP_RELEASE",
	"DRM_IOCTL_AGP_ENABLE",
	"DRM_IOCTL_AGP_INFO",
	"DRM_IOCTL_AGP_ALLOC",
	"DRM_IOCTL_AGP_FREE",
	"DRM_IOCTL_AGP_BIND",
	"DRM_IOCTL_AGP_UNBIND",
	"DRM_IOCTL_SG_ALLOC",
	"DRM_IOCTL_SG_FREE",
	"DRM_IOCTL_WAIT_VBLANK",	
	"DRM_IOCTL_CRTC_GET_SEQUENCE",
	"DRM_IOCTL_CRTC_QUEUE_SEQUENCE",
	"DRM_IOCTL_?",
	"DRM_IOCTL_?",
	"DRM_IOCTL_UPDATE_DRAW",
	"DRM_NVIDIA_GET_CRTC_CRC32",				/* DRM_COMMAND_BASE 0x40 */
	"DRM_NVIDIA_GEM_IMPORT_NVKMS_MEMORY",
	"DRM_NVIDIA_GEM_IMPORT_USERSPACE_MEMORY",
	"DRM_NVIDIA_GET_DEV_INFO",
	"DRM_NVIDIA_FENCE_SUPPORTED",
	"DRM_NVIDIA_PRIME_FENCE_CONTEXT_CREATE",
	"DRM_NVIDIA_GEM_PRIME_FENCE_ATTACH",
	"DRM_NVIDIA_GET_CLIENT_CAPABILITY",
	"DRM_NVIDIA_GEM_EXPORT_NVKMS_MEMORY",
	"DRM_NVIDIA_GEM_MAP_OFFSET",
	"DRM_NVIDIA_GEM_ALLOC_NVKMS_MEMORY",
	"DRM_NVIDIA_GET_CRTC_CRC32_V2",
	"DRM_NVIDIA_GEM_EXPORT_DMABUF_MEMORY",
	"DRM_NVIDIA_GEM_IDENTIFY_OBJECT",
	"DRM_NVIDIA_DMABUF_SUPPORTED",
	"DRM_NVIDIA_GET_DPY_ID_FOR_CONNECTOR_ID",
	"DRM_NVIDIA_GET_CONNECTOR_ID_FOR_DPY_ID",	/* +0x10 */
	"DRM_NVIDIA_GRANT_PERMISSIONS",
	"DRM_NVIDIA_REVOKE_PERMISSIONS",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",					/* +0x20 */
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",					/* +0x30 */
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",					/* +0x40 */
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",					/* +0x50 */
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_NVIDIA_?",
	"DRM_IOCTL_MODE_GETRESOURCES",			/* 0xa0 */
	"DRM_IOCTL_MODE_GETCRTC",
	"DRM_IOCTL_MODE_SETCRTC",
	"DRM_IOCTL_MODE_CURSOR",
	"DRM_IOCTL_MODE_GETGAMMA",
	"DRM_IOCTL_MODE_SETGAMMA",
	"DRM_IOCTL_MODE_GETENCODER",
	"DRM_IOCTL_MODE_GETCONNECTOR",
	"DRM_IOCTL_MODE_ATTACHMODE",
	"DRM_IOCTL_MODE_DETACHMODE",
	"DRM_IOCTL_MODE_GETPROPERTY",
	"DRM_IOCTL_MODE_SETPROPERTY",	
	"DRM_IOCTL_MODE_GETPROPBLOB",
	"DRM_IOCTL_MODE_GETFB",
	"DRM_IOCTL_MODE_ADDFB",
	"DRM_IOCTL_MODE_RMFB",
	"DRM_IOCTL_MODE_PAGE_FLIP",			/* 0xb0 */
	"DRM_IOCTL_MODE_DIRTYFB",
	"DRM_IOCTL_MODE_CREATE_DUMB",
	"DRM_IOCTL_MODE_MAP_DUMB",
	"DRM_IOCTL_MODE_DESTROY_DUMB",
	"DRM_IOCTL_MODE_GETPLANERESOURCES",
	"DRM_IOCTL_MODE_GETPLANE",
	"DRM_IOCTL_MODE_SETPLANE",
	"DRM_IOCTL_MODE_ADDFB2",
	"DRM_IOCTL_MODE_OBJ_GETPROPERTIES",
	"DRM_IOCTL_MODE_OBJ_SETPROPERTY",
	"DRM_IOCTL_MODE_CURSOR2",
	"DRM_IOCTL_MODE_ATOMIC",
	"DRM_IOCTL_MODE_CREATEPROPBLOB",
	"DRM_IOCTL_MODE_DESTROYPROPBLOB",
	"DRM_IOCTL_SYNCOBJ_CREATE",
	"DRM_IOCTL_SYNCOBJ_DESTROY",			/* 0xc0 */
	"DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD",
	"DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE",
	"DRM_IOCTL_SYNCOBJ_WAIT",
	"DRM_IOCTL_SYNCOBJ_RESET",
	"DRM_IOCTL_SYNCOBJ_SIGNAL",
	"DRM_IOCTL_MODE_CREATE_LEASE",
	"DRM_IOCTL_MODE_LIST_LESSEES",
	"DRM_IOCTL_MODE_GET_LEASE",
	"DRM_IOCTL_MODE_REVOKE_LEASE",
	"DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT",		
	"DRM_IOCTL_SYNCOBJ_QUERY",
	"DRM_IOCTL_SYNCOBJ_TRANSFER",
	"DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL",
	"DRM_IOCTL_MODE_GETFB2",
	"DRM_IOCTL_?",
};

char *dm_ioctl[DM_NRCTLS] = {
       /* Top level cmds */
       "DM_VERSION",               /* 0x0 */
       "DM_REMOVE_ALL",               /* 0x1 */
       "DM_LIST_DEVICES",               /* 0x2 */

       /* device level cmds */
       "DM_DEV_CREATE",               /* 0x3 */
       "DM_DEV_REMOVE",               /* 0x4 */
       "DM_DEV_RENAME",               /* 0x5 */
       "DM_DEV_SUSPEND",               /* 0x6 */
       "DM_DEV_STATUS",               /* 0x7 */
       "DM_DEV_WAIT",               /* 0x8 */

       /* Table level cmds */
       "DM_TABLE_LOAD",               /* 0x9 */
       "DM_TABLE_CLEAR",               /* 0xa */
       "DM_TABLE_DEPS",               /* 0xb */
       "DM_TABLE_STATUS",               /* 0xc */

       /* Added later */
       "DM_LIST_VERSIONS",               /* 0xd */
       "DM_TARGET_MSG",               /* 0xe */
       "DM_DEV_SET_GEOMETRY",               /* 0xf */
       "DM_DEV_ARM_POLL",               /* 0x10 */
       "DM_GET_TARGET_VERSION"               /* 0x11 */
};

/* KVM ioctls have some duplicates.   For now, we will print just the first one listed in the
 * following URL:
 *
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/kvm.h
 */

char *kvm_ioctl[KVM_NRCTLS] = {
/*
 *  * ioctls for /dev/kvm fds:
 *   */
       "KVM_GET_API_VERSION",               /* 0x00 */
       "KVM_CREATE_VM",               /* 0x01 */
       "KVM_GET_MSR_INDEX_LIST",               /* 0x02 */
       "KVM_CHECK_EXTENSION",               /* 0x03 */
       "KVM_GET_VCPU_MMAP_SIZE",               /* 0x04 */
       "KVM_GET_SUPPORTED_CPUID",               /* 0x05 */	   
       "KVM_S390_ENABLE_SIE",               /* 0x06 */
	   "KVM_?",								/* 0x07 */
	   "KVM_?",								/* 0x08 */	   
       "KVM_GET_EMULATED_CPUID",               /* 0x09 */
       "KVM_GET_MSR_FEATURE_INDEX_LIST",       /* 0x0a */
	   "KVM_?",								/* 0x0b */
	   "KVM_?",								/* 0x0c */
	   "KVM_?",								/* 0x0d */
	   "KVM_?",								/* 0x0e */
	   "KVM_?",								/* 0x0f */
	   "KVM_?",								/* 0x10 */
	   "KVM_?",								/* 0x11 */
	   "KVM_?",								/* 0x12 */
	   "KVM_?",								/* 0x13 */
	   "KVM_?",								/* 0x14 */
	   "KVM_?",								/* 0x15 */
	   "KVM_?",								/* 0x16 */
	   "KVM_?",								/* 0x17 */
	   "KVM_?",								/* 0x18 */
	   "KVM_?",								/* 0x19 */
	   "KVM_?",								/* 0x1a */
	   "KVM_?",								/* 0x1b */
	   "KVM_?",								/* 0x1c */
	   "KVM_?",								/* 0x1d */
	   "KVM_?",								/* 0x1e */
	   "KVM_?",								/* 0x1f */
	   "KVM_?",								/* 0x20 */
	   "KVM_?",								/* 0x21 */
	   "KVM_?",								/* 0x22 */
	   "KVM_?",								/* 0x23 */
	   "KVM_?",								/* 0x24 */
	   "KVM_?",								/* 0x25 */
	   "KVM_?",								/* 0x26 */
	   "KVM_?",								/* 0x27 */
	   "KVM_?",								/* 0x28 */
	   "KVM_?",								/* 0x29 */
	   "KVM_?",								/* 0x2a */
	   "KVM_?",								/* 0x2b */
	   "KVM_?",								/* 0x2c */
	   "KVM_?",								/* 0x2d */
	   "KVM_?",								/* 0x2e */
	   "KVM_?",								/* 0x2f */
	   "KVM_?",								/* 0x30 */
	   "KVM_?",								/* 0x31 */
	   "KVM_?",								/* 0x32 */
	   "KVM_?",								/* 0x33 */
	   "KVM_?",								/* 0x34 */
	   "KVM_?",								/* 0x35 */
	   "KVM_?",								/* 0x36 */
	   "KVM_?",								/* 0x37 */
	   "KVM_?",								/* 0x38 */
	   "KVM_?",								/* 0x39 */
	   "KVM_?",								/* 0x3a */
	   "KVM_?",								/* 0x3b */
	   "KVM_?",								/* 0x3c */
	   "KVM_?",								/* 0x3d */
	   "KVM_?",								/* 0x3e */
	   "KVM_?",								/* 0x3f */ 
	   "KVM_?",								/* 0x40 */
       "KVM_CREATE_VCPU",               /* 0x41 */
       "KVM_GET_DIRTY_LOG",               /* 0x42 */
	   "KVM_?",								/* 0x43 */
       "KVM_SET_NR_MMU_PAGES",               /* 0x44 */
       "KVM_GET_NR_MMU_PAGES",               /* 0x45 */
       "KVM_SET_USER_MEMORY_REGION",               /* 0x46 */
       "KVM_SET_TSS_ADDR",               /* 0x47 */
       "KVM_SET_IDENTITY_MAP_ADDR",               /* 0x48 */
       "KVM_SET_USER_MEMORY_REGION2",               /* 0x49 */
	   "KVM_?",								/* 0x4a */
	   "KVM_?",								/* 0x4b */
	   "KVM_?",								/* 0x4c */
	   "KVM_?",								/* 0x4d */
	   "KVM_?",								/* 0x4e */
	   "KVM_?",								/* 0x4f */
       "KVM_S390_UCAS_MAP",               /* 0x50 */
       "KVM_S390_UCAS_UNMAP",               /* 0x51 */
       "KVM_S390_VCPU_FAULT",               /* 0x52 */
	   "KVM_?",               /* 0x53 */
	   "KVM_?",               /* 0x54 */
	   "KVM_?",               /* 0x55 */
	   "KVM_?",               /* 0x56 */
	   "KVM_?",               /* 0x57 */
	   "KVM_?",               /* 0x58 */
	   "KVM_?",               /* 0x59 */
	   "KVM_?",               /* 0x5a */
	   "KVM_?",               /* 0x5b */
	   "KVM_?",               /* 0x5c */
	   "KVM_?",               /* 0x5d */
	   "KVM_?",               /* 0x5e */
	   "KVM_?",               /* 0x5f */
       "KVM_CREATE_IRQCHIP",               /* 0x60 */
       "KVM_IRQ_LINE",               /* 0x61 */
       "KVM_GET_IRQCHIP",               /* 0x62 */
       "KVM_SET_IRQCHIP",               /* 0x63 */
       "KVM_CREATE_PIT",               /* 0x64 */
       "KVM_GET_PIT",               /* 0x65 */
       "KVM_SET_PIT",               /* 0x66 */
       "KVM_IRQ_LINE_STATUSIO",               /* 0x67 */
       "KVM_UNREGISTER_COALESCED_MMIO",               /* 0x68 */
	   "KVM_?",               /* 0x69 */	   
       "KVM_SET_GSI_ROUTING",               /* 0x6a */
	   "KVM_?",               /* 0x6b */
	   "KVM_?",               /* 0x6c */
	   "KVM_?",               /* 0x6d */
	   "KVM_?",               /* 0x6e */
	   "KVM_?",               /* 0x6f */
	   "KVM_?",               /* 0x70 */
       "KVM_REINJECT_CONTROL",               /* 0x71 */
	   "KVM_?",               /* 0x72 */
	   "KVM_?",               /* 0x73 */
	   "KVM_?",               /* 0x74 */
	   "KVM_?",               /* 0x75 */
       "KVM_IRQFD",               /* 0x76 */
       "KVM_CREATE_PIT2",               /* 0x77 */
       "KVM_SET_BOOT_CPU_ID",               /* 0x78 */
       "KVM_IOEVENTFD",               /* 0x79 */
       "KVM_XEN_HVM_CONFIG",               /* 0x7a */
       "KVM_SET_CLOCK",               /* 0x7b */
       "KVM_GET_CLOCK",               /* 0x7c */
	   "KVM_?",               /* 0x7d */
	   "KVM_?",               /* 0x7e */
	   "KVM_?",               /* 0x7f */
       "KVM_RUN",               /* 0x80 */
       "KVM_GET_REGS",               /* 0x81 */
       "KVM_SET_REGS",               /* 0x82 */
       "KVM_GET_SREGS",               /* 0x83 */
       "KVM_SET_SREGS",               /* 0x84 */
       "KVM_TRANSLATE",               /* 0x85 */
       "KVM_INTERRUPT",               /* 0x86 */
	   "KVM_?",               /* 0x87 */
       "KVM_GET_MSRS",               /* 0x88 */
       "KVM_SET_MSRS",               /* 0x89 */
       "KVM_SET_CPUID",               /* 0x8a */
       "KVM_SET_SIGNAL_MASK",               /* 0x8b */
       "KVM_GET_FPU",               /* 0x8c */
       "KVM_SET_FPU",               /* 0x8d */
       "KVM_GET_LAPIC",               /* 0x8e */
       "KVM_SET_LAPIC",               /* 0x8f */
       "KVM_SET_CPUID2",               /* 0x90 */
       "KVM_GET_CPUID2",               /* 0x91 */
       "KVM_TPR_ACCESS_REPORTING",               /* 0x92 */
       "KVM_SET_VAPIC_ADDR",               /* 0x93 */
       "KVM_S390_INTERRUPT",               /* 0x94 */
       "KVM_S390_STORE_STATUS",               /* 0x95 */
       "KVM_S390_SET_INITIAL_PSW",               /* 0x96 */
       "KVM_S390_INITIAL_RESET",               /* 0x97 */
       "KVM_GET_MP_STATE",               /* 0x98 */
       "KVM_SET_MP_STATE",               /* 0x99 */
       "KVM_NMI",               /* 0x9a */
       "KVM_SET_GUEST_DEBUG",               /* 0x9b */
       "KVM_X86_SETUP_MCE",               /* 0x9c */
       "KVM_X86_GET_MCE_CAP_SUPPORTED",   /* 0x9d */
       "KVM_X86_SET_MCE",               /* 0x9e */
       "KVM_GET_PIT2",               /* 0x9f */
       "KVM_SET_PIT2",               /* 0xa0 */
       "KVM_PPC_GET_PVINFO",               /* 0xa1 */
       "KVM_SET_TSC_KHZ",               /* 0xa2 */
       "KVM_GET_TSC_KHZ",               /* 0xa3 */
       "KVM_GET_XSAVE",               /* 0xa4 */
       "KVM_SIGNAL_MSI",               /* 0xa5 */
       "KVM_PPC_GET_SMMU_INFO",               /* 0xa6 */
       "KVM_PPC_ALLOCATE_HTAB",               /* 0xa7 */
       "KVM_CREATE_SPAPR_TCE",               /* 0xa8 */
       "KVM_ALLOCATE_RMA",               /* 0xa9 */
       "KVM_PPC_GET_HTAB_FD",               /* 0xaa */
       "KVM_ARM_SET_DEVICE_ADDR",               /* 0xab */
       "KVM_PPC_RTAS_DEFINE_TOKEN",               /* 0xac */
       "KVM_PPC_RESIZE_HPT_PREPARE",               /* 0xad */
       "KVM_PPC_RESIZE_HPT_COMMIT",               /* 0xae */
       "KVM_PPC_CONFIGURE_V3_MMU",               /* 0xaf */
       "KVM_PPC_GET_RMMU_INFO",               /* 0xb0 */
       "KVM_PPC_GET_CPU_CHAR",               /* 0xb1 */
       "KVM_SET_PMU_EVENT_FILTER",               /* 0xb2 */
       "KVM_PPC_SVM_OFF",               /* 0xb3 */
       "KVM_ARM_MTE_COPY_TAGS",               /* 0xb4 */
       "KVM_ARM_SET_COUNTER_OFFSET",               /* 0xb5 */
       "KVM_ARM_GET_REG_WRITABLE_MASKS",               /* 0xb6 */
       "KVM_SMI",               /* 0xb7 */
       "KVM_S390_GET_CMMA_BITS",               /* 0xb8 */
       "KVM_S390_SET_CMMA_BITS",               /* 0xb9 */
       "KVM_MEMORY_ENCRYPT_OP",               /* 0xba */
       "KVM_MEMORY_ENCRYPT_REG_REGION",               /* 0xbb */
       "KVM_MEMORY_ENCRYPT_UNREG_REGION",               /* 0xbc */
       "KVM_HYPERV_EVENTFD",               /* 0xbd */
       "KVM_GET_NESTED_STATE",               /* 0xbe */
       "KVM_SET_NESTED_STATE",               /* 0xbf */
       "KVM_CLEAR_DIRTY_LOG",               /* 0xc0 */
       "KVM_GET_SUPPORTED_HV_CPUID",               /* 0xc1 */
       "KVM_ARM_VCPU_FINALIZE",               /* 0xc2 */
       "KVM_S390_NORMAL_RESET",               /* 0xc3 */
       "KVM_S390_CLEAR_RESET",               /* 0xc4 */
       "KVM_S390_PV_COMMAND",               /* 0xc5 */
       "KVM_X86_SET_MSR_FILTER",               /* 0xc6 */
       "KVM_RESET_DIRTY_RINGS",               /* 0xc7 */
       "KVM_XEN_HVM_GET_ATTR",               /* 0xc8 */
       "KVM_XEN_HVM_SET_ATTR",               /* 0xc9 */
       "KVM_XEN_VCPU_GET_ATTR",               /* 0xca */
       "KVM_XEN_VCPU_SET_ATTR",               /* 0xcb */
	   "KVM_GET_SREGS2",               /* 0xcc */
       "KVM_SET_SREGS2",               /* 0xcd */
       "KVM_GET_STATS_FD",               /* 0xce */
       "KVM_GET_XSAVE2",               /* 0xcf */
       "KVM_XEN_HVM_EVTCHN_SEND",               /* 0xd0 */
       "KVM_S390_ZPCI_OP",               /* 0xd1 */
       "KVM_SET_MEMORY_ATTRIBUTES",               /* 0xd2 */
	   "KVM_?",               /* 0xd3 */
       "KVM_CREATE_GUEST_MEMFD"               /* 0xd4 */
       "KVM_?"               /* 0xd5 */	   
	   "KVM_?"               /* 0xd6 */
	   "KVM_?"               /* 0xd7 */
	   "KVM_?"               /* 0xd8 */
	   "KVM_?"               /* 0xd9 */
	   "KVM_?"               /* 0xda */
	   "KVM_?"               /* 0xdb */
	   "KVM_?"               /* 0xdc */
	   "KVM_?"               /* 0xdd */
	   "KVM_?"               /* 0xde */
	   "KVM_?"               /* 0xdf */
       "KVM_CREATE_DEVICE",               /* 0xe0 */
       "KVM_SET_DEVICE_ATTR",               /* 0xe1 */
       "KVM_GET_DEVICE_ATTR",               /* 0xe2 */
       "KVM_HAS_DEVICE_ATTR",               /* 0xe3 */
	   "KVM_?",               /* 0xe4 */
	   "KVM_?",               /* 0xe5 */
	   "KVM_?",               /* 0xe6 */
	   "KVM_?",               /* 0xe7 */
	   "KVM_?",               /* 0xe8 */
	   "KVM_?",               /* 0xe9 */
	   "KVM_?",               /* 0xea */
	   "KVM_?",               /* 0xeb */
	   "KVM_?",               /* 0xec */
	   "KVM_?",               /* 0xed */
	   "KVM_?",               /* 0xee */
	   "KVM_?"               /* 0xef */
};

#if 0
char *kvm_ioctl[KVM_NRCTLS] = {
/*
 *  * ioctls for /dev/kvm fds:
 *   */
       "KVM_GET_API_VERSION",               /* 0x00 */
       "KVM_CREATE_VM",               /* 0x01 */
       "KVM_GET_MSR_INDEX_LIST",               /* 0x02 */
       "KVM_CHECK_EXTENSION",               /* 0x03 */
       "KVM_GET_VCPU_MMAP_SIZE",               /* 0x04 */
       "KVM_GET_SUPPORTED_CPUID",               /* 0x05 */	   
       "KVM_S390_ENABLE_SIE",               /* 0x06 */
	   "KVM_?",								/* 0x07 */
	   "KVM_?",								/* 0x08 */	   
       "KVM_GET_EMULATED_CPUID",               /* 0x09 */
       "KVM_GET_MSR_FEATURE_INDEX_LIST",       /* 0x0a */
	   "KVM_?",								/* 0x0b */
	   "KVM_?",								/* 0x0c */
	   "KVM_?",								/* 0x0d */
	   "KVM_?",								/* 0x0e */
	   "KVM_?",								/* 0x0f */
	   "KVM_?",								/* 0x10 */
	   "KVM_?",								/* 0x11 */
	   "KVM_?",								/* 0x12 */
	   "KVM_?",								/* 0x13 */
	   "KVM_?",								/* 0x14 */
	   "KVM_?",								/* 0x15 */
	   "KVM_?",								/* 0x16 */
	   "KVM_?",								/* 0x17 */
	   "KVM_?",								/* 0x18 */
	   "KVM_?",								/* 0x19 */
	   "KVM_?",								/* 0x1a */
	   "KVM_?",								/* 0x1b */
	   "KVM_?",								/* 0x1c */
	   "KVM_?",								/* 0x1d */
	   "KVM_?",								/* 0x1e */
	   "KVM_?",								/* 0x1f */
	   "KVM_?",								/* 0x20 */
	   "KVM_?",								/* 0x21 */
	   "KVM_?",								/* 0x22 */
	   "KVM_?",								/* 0x23 */
	   "KVM_?",								/* 0x24 */
	   "KVM_?",								/* 0x25 */
	   "KVM_?",								/* 0x26 */
	   "KVM_?",								/* 0x27 */
	   "KVM_?",								/* 0x28 */
	   "KVM_?",								/* 0x29 */
	   "KVM_?",								/* 0x2a */
	   "KVM_?",								/* 0x2b */
	   "KVM_?",								/* 0x2c */
	   "KVM_?",								/* 0x2d */
	   "KVM_?",								/* 0x2e */
	   "KVM_?",								/* 0x2f */
	   "KVM_?",								/* 0x30 */
	   "KVM_?",								/* 0x31 */
	   "KVM_?",								/* 0x32 */
	   "KVM_?",								/* 0x33 */
	   "KVM_?",								/* 0x34 */
	   "KVM_?",								/* 0x35 */
	   "KVM_?",								/* 0x36 */
	   "KVM_?",								/* 0x37 */
	   "KVM_?",								/* 0x38 */
	   "KVM_?",								/* 0x39 */
	   "KVM_?",								/* 0x3a */
	   "KVM_?",								/* 0x3b */
	   "KVM_?",								/* 0x3c */
	   "KVM_?",								/* 0x3d */
	   "KVM_?",								/* 0x3e */
	   "KVM_?",								/* 0x3f */ 
	   "KVM_?",								/* 0x40 */
       "KVM_CREATE_VCPU",               /* 0x41 */
       "KVM_GET_DIRTY_LOG",               /* 0x42 */
	   "KVM_?",								/* 0x43 */
       "KVM_SET_NR_MMU_PAGES",               /* 0x44 */
       "KVM_GET_NR_MMU_PAGES",               /* 0x45 */
       "KVM_SET_USER_MEMORY_REGION",               /* 0x46 */
       "KVM_SET_TSS_ADDR",               /* 0x47 */
       "KVM_SET_IDENTITY_MAP_ADDR",               /* 0x48 */
       "KVM_SET_USER_MEMORY_REGION2",               /* 0x49 */
	   "KVM_?",								/* 0x4a */
	   "KVM_?",								/* 0x4b */
	   "KVM_?",								/* 0x4c */
	   "KVM_?",								/* 0x4d */
	   "KVM_?",								/* 0x4e */
	   "KVM_?",								/* 0x4f */
       "KVM_S390_UCAS_MAP",               /* 0x50 */
       "KVM_S390_UCAS_UNMAP",               /* 0x51 */
       "KVM_S390_VCPU_FAULT",               /* 0x52 */
	   "KVM_?",               /* 0x53 */
	   "KVM_?",               /* 0x54 */
	   "KVM_?",               /* 0x55 */
	   "KVM_?",               /* 0x56 */
	   "KVM_?",               /* 0x57 */
	   "KVM_?",               /* 0x58 */
	   "KVM_?",               /* 0x59 */
	   "KVM_?",               /* 0x5a */
	   "KVM_?",               /* 0x5b */
	   "KVM_?",               /* 0x5c */
	   "KVM_?",               /* 0x5d */
	   "KVM_?",               /* 0x5e */
	   "KVM_?",               /* 0x5f */
       "KVM_CREATE_IRQCHIP",               /* 0x60 */
       "KVM_IRQ_LINE",               /* 0x61 */
       "KVM_GET_IRQCHIP",               /* 0x62 */
       "KVM_SET_IRQCHIP",               /* 0x63 */
       "KVM_CREATE_PIT",               /* 0x64 */
       "KVM_GET_PIT",               /* 0x65 */
       "KVM_SET_PIT",               /* 0x66 */
       "KVM_IRQ_LINE_STATUS/KVM_REGISTER_COALESCED_MMIO",               /* 0x67 */
       "KVM_UNREGISTER_COALESCED_MMIO",               /* 0x68 */
	   "KVM_?",               /* 0x69 */	   
       "KVM_SET_GSI_ROUTING",               /* 0x6a */
	   "KVM_?",               /* 0x6b */
	   "KVM_?",               /* 0x6c */
	   "KVM_?",               /* 0x6d */
	   "KVM_?",               /* 0x6e */
	   "KVM_?",               /* 0x6f */
	   "KVM_?",               /* 0x70 */
       "KVM_REINJECT_CONTROL",               /* 0x71 */
	   "KVM_?",               /* 0x72 */
	   "KVM_?",               /* 0x73 */
	   "KVM_?",               /* 0x74 */
	   "KVM_?",               /* 0x75 */
       "KVM_IRQFD",               /* 0x76 */
       "KVM_CREATE_PIT2",               /* 0x77 */
       "KVM_SET_BOOT_CPU_ID",               /* 0x78 */
       "KVM_IOEVENTFD",               /* 0x79 */
       "KVM_XEN_HVM_CONFIG",               /* 0x7a */
       "KVM_SET_CLOCK",               /* 0x7b */
       "KVM_GET_CLOCK",               /* 0x7c */
	   "KVM_?",               /* 0x7d */
	   "KVM_?",               /* 0x7e */
	   "KVM_?",               /* 0x7f */
       "KVM_RUN",               /* 0x80 */
       "KVM_GET_REGS",               /* 0x81 */
       "KVM_SET_REGS",               /* 0x82 */
       "KVM_GET_SREGS",               /* 0x83 */
       "KVM_SET_SREGS",               /* 0x84 */
       "KVM_TRANSLATE",               /* 0x85 */
       "KVM_INTERRUPT",               /* 0x86 */
	   "KVM_?",               /* 0x87 */
       "KVM_GET_MSRS",               /* 0x88 */
       "KVM_SET_MSRS",               /* 0x89 */
       "KVM_SET_CPUID",               /* 0x8a */
       "KVM_SET_SIGNAL_MASK",               /* 0x8b */
       "KVM_GET_FPU",               /* 0x8c */
       "KVM_SET_FPU",               /* 0x8d */
       "KVM_GET_LAPIC",               /* 0x8e */
       "KVM_SET_LAPIC",               /* 0x8f */
       "KVM_SET_CPUID2",               /* 0x90 */
       "KVM_GET_CPUID2",               /* 0x91 */
       "KVM_TPR_ACCESS_REPORTING",               /* 0x92 */
       "KVM_SET_VAPIC_ADDR",               /* 0x93 */
       "KVM_S390_INTERRUPT",               /* 0x94 */
       "KVM_S390_STORE_STATUS",               /* 0x95 */
       "KVM_S390_SET_INITIAL_PSW",               /* 0x96 */
       "KVM_S390_INITIAL_RESET",               /* 0x97 */
       "KVM_GET_MP_STATE",               /* 0x98 */
       "KVM_SET_MP_STATE",               /* 0x99 */
       "KVM_NMI",               /* 0x9a */
       "KVM_SET_GUEST_DEBUG",               /* 0x9b */
       "KVM_X86_SETUP_MCE",               /* 0x9c */
       "KVM_X86_GET_MCE_CAP_SUPPORTED",   /* 0x9d */
       "KVM_X86_SET_MCE",               /* 0x9e */
       "KVM_GET_VCPU_EVENTS",               /* 0x9f */
       "KVM_SET_VCPU_EVENTS/KVM_SET_PIT2",               /* 0xa0 */
       "KVM_GET_DEBUGREGS/KVM_PPC_GET_PVINFO",               /* 0xa1 */
       "KVM_SET_DEBUGREGS/KVM_SET_TSC_KHZ",               /* 0xa2 */
       "KVM_ENABLE_CAP/KVM_GET_TSC_KHZ",               /* 0xa3 */
       "KVM_GET_XSAVE/KVM_?",               /* 0xa4 */
       "KVM_SET_XSAVE/KVM_SIGNAL_MSI",               /* 0xa5 */
       "KVM_GET_XCRS/KVM_PPC_GET_SMMU_INFO",               /* 0xa6 */
       "KVM_SET_XCRS/KVM_PPC_ALLOCATE_HTAB",               /* 0xa7 */
	   "KVM_?/KVM_CREATE_SPAPR_TCE",               /* 0xa8 */
	   "KVM_?/KVM_ALLOCATE_RMA",               /* 0xa9 */
       "KVM_DIRTY_TLB/KVM_PPC_GET_HTAB_FD",               /* 0xaa */
       "KVM_GET_ONE_REG/KVM_ARM_SET_DEVICE_ADDR",               /* 0xab */
       "KVM_SET_ONE_REG/KVM_PPC_RTAS_DEFINE_TOKEN",               /* 0xac */
       "KVM_KVMCLOCK_CTRL/KVM_PPC_RESIZE_HPT_PREPARE",               /* 0xad */
       "KVM_ARM_VCPU_INIT/KVM_PPC_RESIZE_HPT_COMMIT",               /* 0xae */
       "KVM_ARM_PREFERRED_TARGET/KVM_PPC_CONFIGURE_V3_MMU",               /* 0xaf */
       "KVM_PPC_GET_RMMU_INFO/KVM_GET_REG_LIST",               /* 0xb0 */
       "KVM_PPC_GET_CPU_CHAR/KVM_S390_MEM_OP",               /* 0xb1 */
       "KVM_SET_PMU_EVENT_FILTER/KVM_S390_GET_SKEYS",               /* 0xb2 */
       "KVM_PPC_SVM_OFF/KVM_S390_SET_SKEYS",               /* 0xb3 */
       "KVM_ARM_MTE_COPY_TAGS/KVM_S390_IRQ",               /* 0xb4 */
       "KVM_ARM_SET_COUNTER_OFFSET/KVM_S390_SET_IRQ_STATE",               /* 0xb5 */
       "KVM_ARM_GET_REG_WRITABLE_MASKS/KVM_S390_GET_IRQ_STATE",               /* 0xb6 */
       "KVM_SMI",               /* 0xb7 */
       "KVM_S390_GET_CMMA_BITS",               /* 0xb8 */
       "KVM_S390_SET_CMMA_BITS",               /* 0xb9 */
       "KVM_MEMORY_ENCRYPT_OP",               /* 0xba */
       "KVM_MEMORY_ENCRYPT_REG_REGION",               /* 0xbb */
       "KVM_MEMORY_ENCRYPT_UNREG_REGION",               /* 0xbc */
       "KVM_HYPERV_EVENTFD",               /* 0xbd */
       "KVM_GET_NESTED_STATE",               /* 0xbe */
       "KVM_SET_NESTED_STATE",               /* 0xbf */
       "KVM_CLEAR_DIRTY_LOG",               /* 0xc0 */
       "KVM_GET_SUPPORTED_HV_CPUID",               /* 0xc1 */
       "KVM_ARM_VCPU_FINALIZE",               /* 0xc2 */
       "KVM_S390_NORMAL_RESET",               /* 0xc3 */
       "KVM_S390_CLEAR_RESET",               /* 0xc4 */
       "KVM_S390_PV_COMMAND",               /* 0xc5 */
       "KVM_X86_SET_MSR_FILTER",               /* 0xc6 */
       "KVM_RESET_DIRTY_RINGS",               /* 0xc7 */
       "KVM_XEN_HVM_GET_ATTR",               /* 0xc8 */
       "KVM_XEN_HVM_SET_ATTR",               /* 0xc9 */
       "KVM_XEN_VCPU_GET_ATTR",               /* 0xca */
       "KVM_XEN_VCPU_SET_ATTR",               /* 0xcb */
	   "KVM_GET_SREGS2",               /* 0xcc */
       "KVM_SET_SREGS2",               /* 0xcd */
       "KVM_GET_STATS_FD",               /* 0xce */
       "KVM_GET_XSAVE2",               /* 0xcf */
       "KVM_S390_PV_CPU_COMMAND/KVM_XEN_HVM_EVTCHN_SEND",               /* 0xd0 */
       "KVM_S390_ZPCI_OP",               /* 0xd1 */
       "KVM_SET_MEMORY_ATTRIBUTES",               /* 0xd2 */
	   "KVM_?",               /* 0xd3 */
       "KVM_CREATE_GUEST_MEMFD"               /* 0xd4 */
       "KVM_?"               /* 0xd5 */	   
	   "KVM_?"               /* 0xd6 */
	   "KVM_?"               /* 0xd7 */
	   "KVM_?"               /* 0xd8 */
	   "KVM_?"               /* 0xd9 */
	   "KVM_?"               /* 0xda */
	   "KVM_?"               /* 0xdb */
	   "KVM_?"               /* 0xdc */
	   "KVM_?"               /* 0xdd */
	   "KVM_?"               /* 0xde */
	   "KVM_?"               /* 0xdf */
       "KVM_CREATE_DEVICE",               /* 0xe0 */
       "KVM_SET_DEVICE_ATTR",               /* 0xe1 */
       "KVM_GET_DEVICE_ATTR",               /* 0xe2 */
       "KVM_HAS_DEVICE_ATTR",               /* 0xe3 */
	   "KVM_?",               /* 0xe4 */
	   "KVM_?",               /* 0xe5 */
	   "KVM_?",               /* 0xe6 */
	   "KVM_?",               /* 0xe7 */
	   "KVM_?",               /* 0xe8 */
	   "KVM_?",               /* 0xe9 */
	   "KVM_?",               /* 0xea */
	   "KVM_?",               /* 0xeb */
	   "KVM_?",               /* 0xec */
	   "KVM_?",               /* 0xed */
	   "KVM_?",               /* 0xee */
	   "KVM_?"               /* 0xef */
};

#endif

char *sg_ioctl[SG_NRCTLS] = {
          "SG_?",               /* 0x0 */
       "SG_SET_TIMEOUT",               /* 0x01 */
       "SG_GET_TIMEOUT",               /* 0x02 */	   
       "SG_EMULATED_HOST",         /* 0x03 */
       "SG_SET_TRANSFORM",          /* 0x04 */
       "SG_GET_TRANSFORM",               /* 0x05 */
	   "SG_?",               /* 0x06 */
	   "SG_?",               /* 0x07 */
	   "SG_?",               /* 0x08 */
	   "SG_?",               /* 0x09 */
	   "SG_?",               /* 0x0a */
	   "SG_?",               /* 0x0b */
	   "SG_?",               /* 0x0c */
	   "SG_?",               /* 0x0d */
	   "SG_?",               /* 0x0e */
	   "SG_?",               /* 0x0f */
	   "SG_?",               /* 0x10 */
	   "SG_?",               /* 0x11 */
	   "SG_?",               /* 0x12 */
	   "SG_?",               /* 0x13 */
	   "SG_?",               /* 0x14 */
	   "SG_?",               /* 0x15 */
	   "SG_?",               /* 0x16 */
	   "SG_?",               /* 0x17 */
	   "SG_?",               /* 0x18 */
	   "SG_?",               /* 0x19 */
	   "SG_?",               /* 0x1a */
	   "SG_?",               /* 0x1b */
	   "SG_?",               /* 0x1c */
	   "SG_?",               /* 0x1d */
	   "SG_?",               /* 0x1e */
	   "SG_?",               /* 0x1f */
	   "SG_?",               /* 0x20 */
	   "SG_?",               /* 0x21 */
	   "SG_?",               /* 0x22 */
	   "SG_?",               /* 0x23 */
	   "SG_?",               /* 0x24 */
	   "SG_?",               /* 0x25 */
	   "SG_?",               /* 0x26 */
	   "SG_?",               /* 0x27 */
	   "SG_?",               /* 0x28 */
	   "SG_?",               /* 0x29 */
	   "SG_?",               /* 0x2a */
	   "SG_?",               /* 0x2b */
	   "SG_?",               /* 0x2c */
	   "SG_?",               /* 0x2d */
	   "SG_?",               /* 0x2e */
	   "SG_?",               /* 0x2f */
	   "SG_?",               /* 0x30 */
	   "SG_?",               /* 0x31 */
	   "SG_?",               /* 0x32 */
	   "SG_?",               /* 0x33 */
	   "SG_?",               /* 0x34 */
	   "SG_?",               /* 0x35 */
	   "SG_?",               /* 0x36 */
	   "SG_?",               /* 0x37 */
	   "SG_?",               /* 0x38 */
	   "SG_?",               /* 0x39 */
	   "SG_?",               /* 0x3a */
	   "SG_?",               /* 0x3b */
	   "SG_?",               /* 0x3c */
	   "SG_?",               /* 0x3d */
	   "SG_?",               /* 0x3e */
	   "SG_?",               /* 0x3f */
	   "SG_?",               /* 0x40 */
	   "SG_?",               /* 0x41 */
	   "SG_?",               /* 0x42 */
	   "SG_?",               /* 0x43 */
	   "SG_?",               /* 0x44 */
	   "SG_?",               /* 0x45 */
	   "SG_?",               /* 0x46 */
	   "SG_?",               /* 0x47 */
	   "SG_?",               /* 0x48 */
	   "SG_?",               /* 0x49 */
	   "SG_?",               /* 0x4a */
	   "SG_?",               /* 0x4b */
	   "SG_?",               /* 0x4c */
	   "SG_?",               /* 0x4d */
	   "SG_?",               /* 0x4e */
	   "SG_?",               /* 0x4f */
	   "SG_?",               /* 0x50 */
	   "SG_?",               /* 0x51 */
	   "SG_?",               /* 0x52 */
	   "SG_?",               /* 0x53 */
	   "SG_?",               /* 0x54 */
	   "SG_?",               /* 0x55 */
	   "SG_?",               /* 0x56 */
	   "SG_?",               /* 0x57 */
	   "SG_?",               /* 0x58 */
	   "SG_?",               /* 0x59 */
	   "SG_?",               /* 0x5a */
	   "SG_?",               /* 0x5b */
	   "SG_?",               /* 0x5c */
	   "SG_?",               /* 0x5d */
	   "SG_?",               /* 0x5e */
	   "SG_?",               /* 0x5f */
	   "SG_?",               /* 0x60 */
	   "SG_?",               /* 0x61 */
	   "SG_?",               /* 0x62 */
	   "SG_?",               /* 0x63 */
	   "SG_?",               /* 0x64 */
	   "SG_?",               /* 0x65 */
	   "SG_?",               /* 0x66 */
	   "SG_?",               /* 0x67 */
	   "SG_?",               /* 0x68 */
	   "SG_?",               /* 0x69 */
	   "SG_?",               /* 0x6a */
	   "SG_?",               /* 0x6b */
	   "SG_?",               /* 0x6c */
	   "SG_?",               /* 0x6d */
	   "SG_?",               /* 0x6e */
	   "SG_?",               /* 0x6f */	     
       "SG_GET_COMMAND_Q",               /* 0x70 */
       "SG_SET_COMMAND_Q",               /* 0x71 */
       "SG_GET_RESERVED_SIZE",               /* 0x72 */
	   "SG_?",               /* 0x73 */
	   "SG_?",               /* 0x74 */
       "SG_SET_RESERVED_SIZE",               /* 0x75 */
       "SG_GET_SCSI_ID",                   /* 0x76  */
	   "SG_?",               /* 0x77 */
	   "SG_?",               /* 0x78 */
       "SG_SET_FORCE_LOW_DMA",               /* 0x79 */
       "SG_GET_LOW_DMA",               /* 0x7a */
       "SG_SET_FORCE_PACK_ID",               /* 0x7b */
       "SG_GET_PACK_ID",               /* 0x7c */
       "SG_GET_NUM_WAITING",               /* 0x7d */
	   "SG_SET_DEBUG",               /* 0x7e */
       "SG_GET_SG_TABLESIZE",               /* 0x7F */
	   "SG_?",               /* 0x80 */
	   "SG_?",               /* 0x81 */
       "SG_GET_VERSION_NUM",               /* 0x82 */
       "SG_NEXT_CMD_LEN",               /* 0x83 */
       "SG_SCSI_RESET",               /* 0x84 */
       "SG_IO",               /* 0x85 */
       "SG_GET_REQUEST_TABLE",               /* 0x86 */
       "SG_SET_KEEP_ORPHAN",               /* 0x87 */
       "SG_GET_KEEP_ORPHAN",               /* 0x88 */
       "SG_GET_ACCESS_COUNT",               /* 0x89 */
	   "SG_?",               /* 0x8a */
	   "SG_?",               /* 0x8b */
	   "SG_?",               /* 0x8c */
	   "SG_?",               /* 0x8d */
	   "SG_?",               /* 0x8e */
	   "SG_?"               /* 0x8f */   
};


char *errnostr[NERRNO] = {
	"ENOERR",
	"EPERM",
	"ENOENT",
	"ESRCH",
	"EINTR",
	"EIO",
	"ENXIO",
	"E2BIG",
	"ENOEXEC",
	"EBADF",
	"ECHILD",
	"EAGAIN",
	"ENOMEM",
	"EACCESS",
	"EFAULT",
	"ENOTBLK",
	"EBUSY",
	"EEXIST",
	"EXDEV",
	"ENODEV",
	"ENOTDIR",
	"EISDIR",
	"EINVAL",
	"ENFILE",
	"EMFILE",
	"ENOTTY",
	"ETXTBSY",
	"EFBIG",
	"ENOSPC",
	"ESPIPE",
	"EROFS",
	"EMLINK",
	"EPIPE",
	"EDOM",
	"ERANGE",
	"EDEADLK",
	"ENAMETOOLONG",
	"ENOLCK",
	"ENOSYS",
	"ENOTEMPTY",
	"EWOULDBLOCK",
	"ENOMSG",
	"EIDRM",
	"ECHRNG",
	"EL2NSYNC",
	"EL3HLT",
	"EL3RST",
	"ELNRNG",
	"EUNATCH",
	"ENOSCI",
	"EL2HLT",
	"EBADE",
	"EBADR",
	"EXFULL",
	"ENOANO",
	"EBADRQC",
	"EBADSLT",
	"EDEADLOCK",
	"EBFONT",
	"ENOSTR",
	"ENODATA",
	"ETIME",
	"ENOSR",
	"ENONET",
	"ENOPKG",
	"EREMOTE",
	"ENOLINK",
	"EADV",
	"ESRMNT",
	"ECOMM",
	"EPROTO",
	"EMULTIHOP",
	"EDOTDOT",
	"EBADMSG",
	"EOVERFLOW",
	"ENOTUNIQ",
	"EBADFD",
	"EREMCHG",
	"ELIBACC",
	"ELIBBAD",
	"ELIBSCN",
	"ELIBMAX",
	"ELIBEXEC",
	"EILSEQ",
	"ERESTART",
	"ERESTART",
	"ESTRPIPE",
	"EUSERS",
	"ENOTSOCK",
	"EDESTADDRREQ",
	"EMSGSIZE",
	"EPROTOTYPE",
	"ENOPROTOOPT",
	"EPROTONOSUPPORT",
	"ESOCKTNOSUPPORT",
	"EOPNOTSUPP",
	"EPFNOSUPPORT",
	"EAFNOSUPPORT",
	"EADDRINUSE",
	"EADDRNOTAVAIL",
	"ENETDOWN",
	"ENETUNREACH",
	"ENETRESET",
	"ECONNABORTED",
	"ECONNRESET",
	"ENOBUFS",
	"EISCONN",
	"ENOTCONN",
	"ESHUTDOWN",
	"ETOOMANYREFS",
	"ETIMEDOUT",
	"ECONNREFUSED",
	"EHOSTDOWN",
	"EHOSTUNREACH",
	"EALREADY",
	"EINPROGRESS",
	"ESTALE",
	"EUCLEAN",
	"ENOTNAM",
	"ENAVAIL",
	"EISNAM",
	"EREMOTEIO",
	"EDQUOT",
	"ENOMEDIUM",
	"EMEDIUMTYPE",
	"ECANCELED",
	"ENOKEY",
	"EKEYEXPIRED",
	"EKEYREVOKED",
	"EKEYREJECTED",
	"EOWNERDEAD",
	"ENOTRECOVERABLE",
	"ERFKILL",
	"EHWPOISON" 
};
