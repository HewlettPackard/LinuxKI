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

/* likiif
 * LiKI InterFace Library
 *
 * A couple of #defines affect this file:
 * __LIKI_RTMERGE 	define this if you want to do realtime streaming
 * __LIKI_DEBUG		define this for debugging messages to stdout
 *
 * NOTE: This file requires _GNU_SOURCE to be defined so as to provide
 * access to some of the CPU_SET stuff
 */
#include <unistd.h>
#include <asm-generic/unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <curses.h>
#include "liki.h"

#define PATHLEN	256

static int		liki_enabled = FALSE;
static char		liki_debug_mountpoint[PATHLEN];
static DIR		*liki_dir = NULL;
int			liki_tef = -1;
int			liki_sf = -1;
int			liki_isf32 = -1;
int			liki_isf64 = -1;
int			liki_trf = -1;
static unsigned long	end_of_sample_period = 0;
static unsigned long	new_sample_period = 0;

static inline int
trace_len(char *t)
{
	common_t *cp = (common_t *)t;

#ifdef __LIKI_DEBUG
	if (cp->marker != END_MARKER_VALUE) {
		fprintf(stderr, "LiKI: trace_len() could not find marker!\n");
		exit(99);
	}

	switch(cp->id) {

		case TT_SCHED_SWITCH :
		case TT_SCHED_WAKEUP :
		case TT_SCHED_MIGRATE_TASK :
		case TT_BLOCK_RQ_INSERT :
		case TT_BLOCK_RQ_ISSUE :
		case TT_BLOCK_RQ_COMPLETE :
		case TT_BLOCK_RQ_ABORT :
		case TT_BLOCK_RQ_REQUEUE :
		case TT_HARDCLOCK :
		case TT_SYSCALL_ENTER :
		case TT_SYSCALL_EXIT :
		case TT_POWER_START :
		case TT_POWER_END :
		case TT_POWER_FREQ :
		case TT_IRQ_HANDLER_ENTRY :
		case TT_IRQ_HANDLER_EXIT :
		case TT_SOFTIRQ_ENTRY :
		case TT_SOFTIRQ_EXIT :
		case TT_SOFTIRQ_RAISE :
		case TT_SCSI_DISPATCH_CMD_START :
		case TT_SCSI_DISPATCH_CMD_DONE :
		case TT_LISTEN_OVERFLOW :
		case TT_STARTUP :
		case TT_FP_SWITCH:
		case TT_FP_HARDCLOCK:
		case TT_FILEMAP_FAULT:
		case TT_TASKLET_ENQUEUE:
		case TT_WORKQUEUE_ENQUEUE:
		case TT_WORKQUEUE_EXECUTE:
		case TT_MM_PAGE_ALLOC;
		case TT_MM_PAGE_FREE;
		case TT_CACHE_INSERT:
		case TT_CACHE_EVICT:
			return(cp->reclen);
		default:
			fprintf(stderr, "LiKI: trace_len() passed an invalid trace! (id = %d)\n", cp->id);
			exit(99);
	}
#endif
	return(cp->reclen);
}

int
init_debug_mountpoint(char * user_debug_dir) 
{
	char		debug_mountpoint[PATHLEN];
	char		dirname[PATHLEN];

	/* If this is the first time through we need to wait until the kernel has
	 * set up the debugfs interface, and everything is ready to go, then open
	 * up important files and directories.
	 */
	if (liki_dir != NULL || liki_enabled)
		return -EINVAL;

	if (user_debug_dir == NULL) {

		/* We will only check the default location /sys/kernel/debug, then /debug */
		strcpy(debug_mountpoint, "/sys/kernel/debug");
		sprintf(dirname, "%s/%s", debug_mountpoint, DEBUGFS_DIR_NAME);

		if ((liki_dir = opendir(dirname)) == NULL) {

			/* Then try /debug */
			strcpy(debug_mountpoint, "/debug");
			sprintf(dirname, "%s/%s", debug_mountpoint, DEBUGFS_DIR_NAME);
			liki_dir = opendir(dirname);
		}

	} else {

		strcpy(debug_mountpoint, user_debug_dir);
		sprintf(dirname, "%s/%s", debug_mountpoint, DEBUGFS_DIR_NAME);
		liki_dir = opendir(dirname);
	}

	if (liki_dir == NULL) {
		fprintf(stderr, "Failed to open liki directory in debugfs.\n");
		fprintf(stderr, "Make sure debugfs is mounted or use debug_dir\n"); 
		fprintf(stderr, "option to specify the correct location.\n\n");
		fprintf(stderr, "  $ mount -t debugfs debugfs /sys/kernel/debug\n"); 
		_exit(-ENOENT);
	}

	/* We found the debugfs mountpoint. Stuff the name in the global */
	strcpy(liki_debug_mountpoint, debug_mountpoint);

	/* when we exit here, the globals liki_dir and liki_debug_mountpoint are set */
	
	return 0;
}



int
liki_init(char *user_debug_dir)
{
	char		name[PATHLEN];
	int		res;

	if (liki_enabled) return -EINVAL;

	if (liki_dir == NULL) init_debug_mountpoint(user_debug_dir) ;

	/* Open the sync file */
	sprintf(name, "%s/%s/%s", liki_debug_mountpoint, DEBUGFS_DIR_NAME, SYNC_FILE);
	if ((liki_sf = open(name, O_RDWR)) < 0) {
		fprintf (stderr, "Cannot open %s\n", name);
		return -ENOENT;
	}

	/* Open the traced resources file */
	sprintf(name, "%s/%s/%s", liki_debug_mountpoint, DEBUGFS_DIR_NAME, TRACED_RESOURCES_FILE);
	if ((liki_trf = open(name, O_RDWR)) < 0) {
		fprintf (stderr, "Cannot open %s\n", name); 
		return -ENOENT;
	}

	/* Open the ignored_syscalls files */
	sprintf(name, "%s/%s/%s", liki_debug_mountpoint, DEBUGFS_DIR_NAME, IGNORED_SYSCALLS32_FILE);
	if ((liki_isf32 = open(name, O_WRONLY)) < 0) {
		fprintf (stderr, "Cannot open %s\n", name); 
		return -ENOENT;
	}

	sprintf(name, "%s/%s/%s", liki_debug_mountpoint, DEBUGFS_DIR_NAME, IGNORED_SYSCALLS64_FILE);
	if ((liki_isf64 = open(name, O_WRONLY)) < 0) {
		fprintf (stderr, "Cannot open %s\n", name); 
		return -ENOENT;
	}

	/* Open trace enable file */
	sprintf(name, "%s/%s/%s", liki_debug_mountpoint, DEBUGFS_DIR_NAME, TRACE_ENABLE_FILE);
	if ((liki_tef = open(name, O_RDWR)) < 0) {
		fprintf (stderr, "Cannot open %s\n", name); 
		return(-ENOENT);
	}

	if ((res = liki_set_tracemask(TT_BITMASK_READS_BLOCK)) != sizeof(long))
		return(res);

	liki_enabled = TRUE;

	return(0);
}


int
liki_open_ringbuf(int *cpu)
{
	char		fname[PATHLEN];
	struct dirent	*dep;
	char 		*cpunumstr;
	int		cpunum;

	if (liki_dir == NULL)
		return(-EINVAL);

	/* Open the next per-CPU ring buffer file. We have no idea how may CPUs
	 * the kernel module decided to produce traces for; it may be for example
	 * that some CPUs were offline when tracing was loaded. However we know
	 * the format of the filenames used, so just open the next file that has
	 * this format. The kernel module is the only guy that creates files in
	 * the directory, so this should be just fine.
	 */
	while ((dep = readdir(liki_dir)) != NULL) {

		if (dep == NULL)
			return(-EINVAL);

		/* If the current file matches the pattern expected for a ring buffer
	 	 * file then open it and return the file descriptor.
		 */
		if (strncmp(dep->d_name, DEBUGFS_BUFPREFIX_NAME, strlen(DEBUGFS_BUFPREFIX_NAME)) == 0) {

			/* Extract the CPU-number component of the filename 
			 */
			cpunumstr = dep->d_name + strlen(DEBUGFS_BUFPREFIX_NAME);
			cpunum = atoi(cpunumstr);

			/* Open the ring-buffer file
			 */
			sprintf(fname, "%s/%s/%s%d", liki_debug_mountpoint, 
				DEBUGFS_DIR_NAME, DEBUGFS_BUFPREFIX_NAME, cpunum);

			*cpu = cpunum;
			return(open(fname, O_RDONLY));

		}
	}

	return(-ENOENT);
}


int
liki_close_ringbuf(int fd)
{

	/* If the caller is closing a ringbuf file then they are likely closing
	 * down and we should close the debugfs directory while we're at it. If
	 * we're wrong we'll just open it again later.
	 */
	if (liki_dir != NULL) {
		closedir(liki_dir);
		liki_dir = NULL;
	}

	return(close(fd));
}


int
liki_set_tracemask(unsigned long mask)
{
	return (write(liki_tef, &mask, sizeof(long)));
}


unsigned long
liki_get_tracemask()
{
	unsigned long	mask;

	if (read(liki_tef, &mask, sizeof(long)) != sizeof(long))  {
		return(-1);
	}

	return(mask);
}

int
liki_sync(int cpu)
{
	if (liki_sf == -1)
		return -EINVAL;

	if (cpu != ALL_CPUS && cpu != OTHER_CPUS && (cpu < 0 || cpu > MAXCPUS))
		return -EINVAL;

	return(write(liki_sf, &cpu, sizeof(int)));
}

int
liki_ignore_syscall32(long syscallno)
{
	if (syscallno < -1 || syscallno >= __NR_syscalls)
		return -EINVAL;

	return(write(liki_isf32, &syscallno, sizeof(long)));
}

int
liki_ignore_syscall64(long syscallno)
{
	if (syscallno < -1 || syscallno >= __NR_syscalls)
		return -EINVAL;

	return(write(liki_isf64, &syscallno, sizeof(long)));
}

int 
liki_enable_msr_data()
{
	resource_op_t	rop;
	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = 0;
	rop.type = MSR_DATA;
		
	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int 
liki_disable_msr_data()
{
	resource_op_t	rop;
	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REMOVE_RESOURCE;
	rop.id = 0;
	rop.type = MSR_DATA;
	
	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_enable_tracing_for_task(pid_t task)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = task;
	rop.type = TASKID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_disable_tracing_for_task(pid_t task)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REMOVE_RESOURCE;
	rop.id = task;
	rop.type = TASKID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_enable_tracing_for_task_group(pid_t task)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = task;
	rop.type = TASKGID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_disable_tracing_for_task_group(pid_t task)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REMOVE_RESOURCE;
	rop.id = task;
	rop.type = TASKGID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_enable_tracing_for_task_family(pid_t task)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = task;
	rop.type = TASKFAMILY;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_enable_tracing_for_cpu(int cpu)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = cpu;
	rop.type = CPUID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_disable_tracing_for_cpu(int cpu)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REMOVE_RESOURCE;
	rop.id = cpu;
	rop.type = CPUID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_enable_tracing_for_device(dev_t dev)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = ADD_RESOURCE;
	rop.id = dev;
	rop.type = DEVICEID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_disable_tracing_for_device(dev_t dev)
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REMOVE_RESOURCE;
	rop.id = dev;
	rop.type = DEVICEID;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_reset_traced_resources()
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = RESET_RESOURCES;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_reenable_global_tracing()
{
	resource_op_t	rop;

	if (liki_trf == -1)
		return -EINVAL;

	rop.op = REENABLE_GLOBAL;

	return(write(liki_trf, &rop, sizeof(resource_op_t)));
}

int
liki_validate_chunk(char *str, char *buf, unsigned long *prevts, unsigned long *prevseq, 
		    unsigned long *traces, unsigned long *lost_traces)
{

	char			*p;
	int 			n;
	unsigned long		ts;
	int			sz;
	static int		prevcpu;
	int			ret = 0;

	n = ((info_t *)(buf))->page_length + TRACE_SIZE(info_t);

	/* Check the header version number */
	if (((info_t *)buf)->version != TRACE_VERSION) {
		fprintf(stderr, "%s: version number wrong in header, want %d got %d\n",
			str, TRACE_VERSION, ((info_t *)buf)->version);
		ret = -1;
	}

	if (prevts && *prevts != -1UL && ((info_t *)(buf))->hrtime < *prevts) {
		fprintf(stderr, "%s: time in header (%lu) earlier than earliest possible time (%lu)!\n", 
		        str, ((info_t *)(buf))->hrtime, *prevts);
		ret = -1;
	}

	/* If the caller turned on CPU seqno checking and this is the first call
	 * then make note of the cpu # in the first trace. As we go through we'll
	 * check that every trace has this same CPU number, and if not (presumably
	 * because its a merged tracefile) we'll disable seqno checking.
	 */
	if (prevseq && *prevseq == -1UL)
		prevcpu = ((common_t *)(buf+TRACE_SIZE(info_t)))->cpu;

	/* Don't count the info_t records. */

	for (p=buf+TRACE_SIZE(info_t); p<(buf+n); p+=sz) {

		common_t *ct = (common_t *)p;

		if (traces)
			(*traces)++;

		sz = trace_len(p);

		if (sz <= 0) {
			fprintf(stderr, "%s: trace size problem\n", str);
			fprintf(stderr, "%s: trace type is %d\n", str, *(unsigned int *)p);
			ret = -1;
		}

		ts = ct->hrtime;

		if (prevts && *prevts != -1UL) {
			if (ts < *prevts) {
				fprintf(stderr, "%s: time went backwards!\n", str);
				fprintf(stderr, "%s: ts: %lu prevts: %lu\n", str, ts, *prevts);
				ret = -1;
			}
		}

		/* if seqno checking not disabled by caller or by me... */
		if (prevseq && *prevseq != -2UL) {

			/* If we have a trace for a different cpu than last time */
			if (ct->cpu != prevcpu)
				*prevseq = -2; /* disable seqno checking */
			else {
				if (*prevseq != -1UL && ct->cpu_seqno != (*prevseq + 1)) {
					if (lost_traces)
						*lost_traces += (ct->cpu_seqno - *prevseq);
					fprintf(stderr, "%s: lost trace range %lu to %lu\n", str, *prevseq, ct->cpu_seqno);
				}
				*prevseq = ct->cpu_seqno;
			}
		}

		if (prevts) *prevts = ts;
	}

	return ret;
}

void
print_chunk(char *buf)
{
	char			*p;
	int 			n;
	int			sz;

	fprintf(stderr, "%s chunk at %lx\n", (((info_t *)(buf))->sync_time == 0 ? "FULL":"PARTIAL"), 
		(unsigned long)buf);

	n = ((info_t *)(buf))->page_length + TRACE_SIZE(info_t);

	for (p=buf+TRACE_SIZE(info_t); p<(buf+n); p+=sz) {

		common_t *ct = (common_t *)p;

		fprintf(stderr,"%lu\n", ct->cpu_seqno);

		sz = trace_len(p);
	}

}

	
int
liki_trace_count(int fd, unsigned long *chunks, unsigned long *traces, unsigned long *lost_traces)
{
	int		ret;
	char		buf[CHUNK_SIZE];
	unsigned long	prevts, prevseq;

	if (lseek(fd, 0, SEEK_SET) != 0)
		return(-EINVAL);

	*chunks = *traces = *lost_traces = 0;
	prevseq = prevts = -1;

	while ((ret = read(fd, buf, CHUNK_SIZE)) > 0) {

		if ((ret = liki_validate_chunk("trace count", buf, &prevts, &prevseq, traces, lost_traces)) < 0) 
			return(ret);

		(*chunks)++;
	}

	/* If sequance number == -2 then we disabled sequence number
	 * checking. Reflect this to caller in lost_traces.
	 */
	if (prevseq == -2UL)
		*lost_traces = -1ULL;

	if (ret < 0)
		return(ret);

	return(0);
}


/* Internal data structure that describes one merge input */
typedef struct {
        int             src_data;
        int             n;
        char            *buf;
        char            *p;
} mip_t;

/* Internal data structure that describes the current active merge */
static struct {
	ssize_t 	(*read_func)(int, void *);
	int		num_sources;
	int		num_sources_active;
	mip_t		*mips;
	unsigned long	*cached_ts;
} am;

int
liki_begin_merge(merge_params_t	*mp)
{
	int 	i;

	if (am.num_sources_active != 0)
		return(-EBUSY);

	if (mp->read_func == NULL)
		return(-EINVAL);

/*
	if (mp->num_sources < 2)
		return(-EINVAL);
*/

	if (mp->src_data == NULL)
		return(-EINVAL);

	am.read_func = mp->read_func;
	am.num_sources = mp->num_sources;
	am.num_sources_active = am.num_sources;

	if ((am.mips = (mip_t *)malloc(sizeof(mip_t) * am.num_sources)) == NULL) {
		am.num_sources_active = 0;
		return(-ENOMEM);
	}

	if ((am.cached_ts = (unsigned long *)malloc(sizeof(unsigned long) * am.num_sources)) == NULL) {
		am.num_sources_active = 0;
		return(-ENOMEM);
	}

	for (i=0; i<am.num_sources; i++) {

		am.mips[i].src_data = mp->src_data[i];
		am.mips[i].n = 0;
	
		/* Allocate an in-memory buffer to hold data from this 
		 * file as it is read in.
		 */
		if ((am.mips[i].buf = (char *)malloc(CHUNK_SIZE)) == NULL) {
			am.num_sources_active = 0;
			return(-ENOMEM);
		}
	
		/* p is our current pointer/offset into the buffer as 
		 * we process its records.
		 */
		am.mips[i].p = am.mips[i].buf;

		/* Here we prime the pump. To be clear, when likit creates 
		 * the ringbuf it is initialized with a header record, so we
		 * should always be able to read at least that.
		 */
		if (am.read_func(am.mips[i].src_data, am.mips[i].buf) < 0) {

			/* Error condition reading this ringbuf. Invalidate
			 * cached_ts for the file to denote that it isn't 
			 * going to produce any more data, and set p to -1
			 * so we'll barf if I get confused below.
			 */
			am.mips[i].p = (char *)-1;
			am.cached_ts[i] = ULONG_MAX;
			am.num_sources_active--;

		} else {

			/* Make note of the number of bytes of useful data
			 * in the chunk we just read.
			 */
			am.mips[i].n = ((info_t *)(am.mips[i].buf))->page_length + TRACE_SIZE(info_t);

			/* We don't transcribe the info_t records from the
			 * inputs (we make up new ones), so pass over the
			 * initial info_t in our newly-read chunk.
			 */
			am.mips[i].p += TRACE_SIZE(info_t);

			/* Prime cached_ts. I use this little cache to avoid 
			 * having to access the next record from every input
			 * every time around the merge loop, since this would
			 * increase the cache footprint dramatically.
			 */
			if (am.mips[i].p >= (am.mips[i].buf + am.mips[i].n) &&
			    IS_SYNC_CHUNK(am.mips[i].buf)) 
				am.cached_ts[i] = ((info_t *)(am.mips[i].buf))->sync_time;
			else
				am.cached_ts[i] = TIMESTAMP(am.mips[i].p);

			/* If the application has just declared a new sample
			 * period, figure out the trace time of the end
			 */
			if (new_sample_period) {
				end_of_sample_period = ((info_t *)(am.mips[i].buf))->hrtime + new_sample_period;
				new_sample_period = 0;
			}
		}
	}

	return(0);
}

void
liki_end_merge()
{
	am.num_sources_active = 0;
}

int
liki_next_merged_chunk(char *buf)
{
	static info_t		ttinfo;
	char			*bp;
	int			earliest = -1;
	static unsigned long	earliest_time = -1;
	int			i;
	int			sz;
	int 			ret;

	bp = buf;

	while (am.num_sources_active > 0) {

		earliest_time = -1;

		for (i=0; i<am.num_sources; i++) {
			
			/* If we're done with this file, pass over it
			 */
			if (am.cached_ts[i] == ULONG_MAX) 
				continue;

			/* If this input is out of records but is a sync chunk
			 * then pass over it for now; we may still be ok to 
			 * continue the merge if the sync_time in the header
			 * is beyond the earliest time we come up with - since
			 * that means that there were no records produced by
			 * this CPU up until sync_time.
			 */
	
			if (am.cached_ts[i] < earliest_time) {
				earliest_time = am.cached_ts[i];
				earliest = i;
			}
		}

		/* If we are string a new chunk then start the
		 * chunk with an info_t record made up on the spot. Note we
		 * don't yet know the number of bytes of useful trace data
		 * that will be in this chunk, so initialize to zero and 
		 * update just before we pass the chunk back to the caller.
		 */
		if (bp == buf) {
			ttinfo.hrtime = earliest_time;
			ttinfo.page_length = 0;
			ttinfo.sync_time = 0;
			ttinfo.version = (((info_t *)(am.mips[earliest].buf))->version);

			memcpy(bp, &ttinfo, sizeof(info_t));
			bp += TRACE_SIZE(info_t);

		}

		/* In the live streaming case, if the earliest record available
 		 * is timestamped after the end of the current sample period,
 		 * then return what we have so far in a partial chunk.
 		 */
		if (end_of_sample_period &&
		    earliest_time > end_of_sample_period) {

			/* Fix-up the page_length in the initial info_t record */
			((info_t *)buf)->page_length = (bp - buf) - TRACE_SIZE(info_t);

			/* Mark this as a sync chunk */
			((info_t *)buf)->sync_time = end_of_sample_period;

			/* Reset end_of_sample_period since we've reached the
 			 * end and done our duty by returning the partial/sync
 			 * chunk.
 			 */
			end_of_sample_period = 0;

#ifdef __LIKI_DEBUG
			liki_validate_chunk("merge output full chunk", buf, NULL, NULL, NULL, NULL);
#endif
			return(bp - buf);
		}

		/* If the earliest record available was the pseudo record of
		 * the timestamp on one inputs sync chunk (meaning not only
		 * has that input run out of traces, but we're now trying to
		 * merge beyond the time of the last sync for this input).
		 * Time to go get more data.
		 */
		if (am.mips[earliest].p >= (am.mips[earliest].buf + am.mips[earliest].n))
			goto need_more_data;
	
		/* Validate that we're looking at a real trace record */
		if ((sz = trace_len(am.mips[earliest].p)) == -1) {
			fprintf(stderr, "found duff trace in input file\n");
			return(-EMEDIUMTYPE);
		}

		if ((sz = trace_len(am.mips[earliest].p)) == 0) {
			fprintf(stderr, "found zero-length trace in input file (earliest=%d)\n", earliest);
			return(-EMEDIUMTYPE);
		}

		/* The output records must not cross a chunk boundary, so
		 * if this record won't fit in the remaining space fix-up
		 * the page_length at the start of the chunk and return
		 * it - we're done for this iteration.
		 */
		if ((bp - buf) + sz > CHUNK_SIZE) {

			/* Fix-up the page_length in the initial info_t record */
			((info_t *)buf)->page_length = (bp - buf) - TRACE_SIZE(info_t);
#ifdef __LIKI_DEBUG
			liki_validate_chunk("merge output full chunk", buf, NULL, NULL, NULL, NULL);
#endif
			return(bp - buf);
		}

		/* Write the earliest record to the outgoing buffer, and move
		 * forwards our pointer into the outgoing buffer.
		 */
        	memcpy(bp, am.mips[earliest].p, sz);
        	bp += sz;

		/* Move forward our pointer for this input.
		 */
		am.mips[earliest].p += sz;


		/* We can merge until one or more inputs run dry. At
		 * that point we need to go and get more data.
		 */
need_more_data:
		if ((am.mips[earliest].p >= (am.mips[earliest].buf + am.mips[earliest].n)) &&
		    (((info_t *)(am.mips[earliest].buf))->sync_time <= earliest_time)) {

			int		old_is_partial;
			unsigned long	old_timestamp;

			old_is_partial = IS_SYNC_CHUNK(am.mips[earliest].buf);
			old_timestamp = ((info_t*)(am.mips[earliest].buf))->hrtime;

			/* Read will always return > 0 if there is a chance of more data.
			 * Note that even when there are no traces in a chunk for a CPU 
			 * we still return the chunk header. We only return 0 when
			 * shutdown is occurring or tracing is disabled (NO_TRACES).
			 */
			if ((ret=am.read_func(am.mips[earliest].src_data, am.mips[earliest].buf)) <= 0) {

				/* Read failed or EOF (tracing shutdown). */
				am.mips[earliest].p = (char *)-1;
				am.cached_ts[earliest] = ULONG_MAX;
				am.num_sources_active--;
#ifdef DEBUG
				fprintf(stderr, "read ringbuf returned %d\n", ret);
#endif

			} else {

				/* In assigning p, remember to skip over the
				 * info_t record as it isn't transcribed into
				 * the output.
				 */
				am.mips[earliest].n = ((info_t *)(am.mips[earliest].buf))->page_length + TRACE_SIZE(info_t);

				/* Don't reset the pointer to beginning of chunk if the prior chunk
				 * was a partial (following sync) and this read returns more data
				 * in the same chunk.
				 */
				if (!(old_is_partial && (((info_t*)(am.mips[earliest].buf))->hrtime == old_timestamp)))
					am.mips[earliest].p = am.mips[earliest].buf + TRACE_SIZE(info_t);
			}
		}

		/* Read the timestamp from the next record into the cached_ts
		 * entry corresponding to the input from which we just 
		 * consumed a trace.
		 * 
		 * Note that am.cached_ts[earliest] will be set to ULONG_MAX
		 * in the code immediately above if there is no more data
		 * for this input.
		 */
		if (am.cached_ts[earliest] != ULONG_MAX) {
			if (am.mips[earliest].p >= (am.mips[earliest].buf + am.mips[earliest].n) &&
		    	    IS_SYNC_CHUNK(am.mips[earliest].buf)) {
				am.cached_ts[earliest] = ((info_t *)(am.mips[earliest].buf))->sync_time;
#ifdef DEBUG
				if (am.cached_ts[earliest] > (unsigned long)0xff00000000000000)
					fprintf(stderr, "shit #1\n");
#endif
			} else if (am.mips[earliest].p < (am.mips[earliest].buf + am.mips[earliest].n)) {
				am.cached_ts[earliest] = TIMESTAMP(am.mips[earliest].p);
#ifdef DEBUG
				if (am.cached_ts[earliest] > (unsigned long)0xff00000000000000) {
					fprintf(stderr, "shit #1\n");
				}
#endif
			}
		}

		/* If the application has just declared a new sample
		 * period, figure out the trace time of the end
		 */
		if (new_sample_period) {
			end_of_sample_period = ((info_t *)(buf))->hrtime + new_sample_period;
			new_sample_period = 0;
		}
	}

	/* We've run out of data from our input files.
	 */
	if (bp == buf) 
		return(0);
	else {
		/* Patch up the number of valid trace bytes in chunk, and 
		 * indicate this is the last chunk by making it a "sync"
		 * chunk
		 */
		((info_t *)buf)->page_length = (bp - buf) - TRACE_SIZE(info_t);
		((info_t *)buf)->sync_time = earliest_time + 1;

		return(bp - buf);
	}
}


/* The following code produces a real-time ordered stream of traces. It purposly
 * requires that you define __LIKI_RTMERGE before including this file if you 
 * want to use this code; the reason being that it brings with it calls into
 * libpthread that single-threaded apps may want to be without.
 */

#ifdef __LIKI_RTMERGE

#include <pthread.h>

#define BUF_SIZE		(CHUNK_SIZE * 4) 
#define	BYTES_IN_BUF(RP, WP)	(RP <= WP ? (WP - RP) : (BUF_SIZE - (RP - WP)))
#define NEXT_CHUNK(B, P) 	(((P+CHUNK_SIZE)>=(B+BUF_SIZE)) ? B : (P+CHUNK_SIZE))
#define	SOFT_SYNC_THRESHOLD	30
#define	HARD_SYNC_THRESHOLD	50


/* The per-cpu structure contains management info for the per-cpu buffers. Slave
 * threads (one per cpu) stream data from the per-cpu in-kernel ring buffer into
 * the corresponding in-process per-cpu buffer. The merge thread reads from these
 * per-cpu buffers and merges the traces in time order into the merged buffer.
 * The app reads the merged traces from the merged buffer.
 */
typedef struct {
	int		cpu;		/* CPU # to which this buffer pertains	*/
	int		rbfd;		/* ring buffer file desriptor */
	char		*buf;		/* pointer to in-process buffer for this cpu */
	volatile char	*read_chunk;	/* the chunk from which we're currently reading */
	char		*next_r;	/* the exact location of the next read */
	volatile char	*write_chunk;	/* the chunk being written by the pcpu thread */
	volatile int	need_wakeup;
	pthread_mutex_t	mtx;
	pthread_cond_t	cond;
} pcpu_t;

static	pcpu_t		pcpu[MAXCPUS];
static	volatile int	waiting_for_cpu = -1;
static 	volatile int	terminate_live_stream = FALSE;
static  pthread_t       stids[MAXCPUS];
static  pthread_t       mtid;
static  pthread_t       synctid;
static  int             cpucnt;
unsigned long 		liki_sync_interval = LIKI_SYNC_INTERVAL;

int delme = 0;
int setsched_errs = 0;

void *
liki_pcpu_thread(void * vp_pcpu)
{
	int			ret;
	pcpu_t			*pp = (pcpu_t *)vp_pcpu;
	int			util;
	int			tgtcpu;
	int			affin_cpu;
        cpu_set_t       	*cpusetp;
        size_t          	cpusetsz;
	struct sched_param 	sp;
#ifdef __LIKI_DEBUG_VERBOSE
	unsigned long		prevts = -1;
	unsigned long		prevseq = -1;
	unsigned long		traces = 0;
	unsigned long		lost_traces = 0;
#endif

	sp.sched_priority = sched_get_priority_min(SCHED_RR);
	/* If sched_setscheduler fails, then skip this for the rest of the CPUs */
	if ((sched_setscheduler(0, SCHED_RR, &sp) == -1) && (setsched_errs == 0)) {
		perror("sched_setscheduler()");
		fprintf(stderr, "failed to make per-CPU threads realtime (possible due to selinux being enabled)\n");
		setsched_errs = 1;
	}

	/* Affinitize the per-CPU thread to a set that includes the CPU it 
	 * is streaming from, and the "adjacent" CPU. See likid.c for the
	 * reasoning.
	 */
	if ((cpusetp = CPU_ALLOC(MAXCPUS)) != NULL) {

		cpusetsz = CPU_ALLOC_SIZE(MAXCPUS);

		CPU_ZERO_S(cpusetsz, cpusetp);

		affin_cpu = (pp->cpu & 1UL ? (pp->cpu - 1) : (pp->cpu + 1));

		CPU_SET_S(pp->cpu, cpusetsz, cpusetp);
		CPU_SET_S(affin_cpu, cpusetsz, cpusetp);

		if ((ret=pthread_setaffinity_np(pthread_self(), cpusetsz, cpusetp)) != 0) {
			fprintf(stderr, "failed to affinitize per-CPU thread, error=%d\n", ret);
		}

		CPU_FREE(cpusetp);
	}

	/* The pcpu threads read traces from the kernel into in-process
	 * per-cpu buffers. They do this until a read from the ring buffer 
	 * fails (unlikely) or tracing is disabled; when the latter occurs
	 * read() returns 0.
	 * 
	 * The buffering here is a little different to the in-kernel buffering.
	 * In kernel when a sync occurs we continue extending the same chunk,
	 * i.e. we don't start a new chunk. In userspace we don't want the
	 * merge thread to be reading a sync chunk at the same time a read()
	 * from kernel completes and overwrites it, and there is no way of
	 * "getting inside the read" to protect the update of the buffer from
	 * concurrent read. So we use a new buffer chunk for each partial read
	 * of a block.
	 */
	while (!terminate_live_stream &&
	       ((ret=read(pp->rbfd, (void *)pp->write_chunk, CHUNK_SIZE)) > 0)) {

#ifdef __LIKI_DEBUG_VERBOSE
		if (IS_SYNC_CHUNK(pp->write_chunk))
			fprintf(stderr, "%lu sync %llu bytes completed by cpu %d\n", 
			  ((info_t *)(pp->write_chunk))->sync_time,
			  ((info_t *)(pp->write_chunk))->page_length + TRACE_SIZE(info_t), pp->cpu);
		else
			fprintf(stderr, "whole chunk read by cpu %d\n", pp->cpu);
#endif

		pthread_mutex_lock(&pp->mtx);

		/* Technically the following is incorrect as it doesn't factor in
		 * the latest chunk, but the thresholds are a guess anyway, so
		 * who cares?
		 */
		util = (BYTES_IN_BUF(pp->read_chunk, pp->write_chunk) * 100)/BUF_SIZE;

#ifdef __LIKI_DEBUG_VERBOSE
		if (!IS_SYNC_CHUNK(pp->write_chunk)) {
			liki_validate_chunk("read from ringbuf", (char *)pp->write_chunk, 
				&prevts, &prevseq, &traces, &lost_traces);
			fprintf(stderr, "validate in pcpu: traces: %lu lost: %lu\n", traces, lost_traces);
		}
#endif

		/* The thinking here is to avoid the buffer of busy CPUs
		 * filling by prodding less busy CPUs to sync. So if our
		 * buffer utilization is over a lower threshold we prod
		 * just the most laggard CPU, but if it's above a higher
		 * threshold we prod every other CPU. The issue with just
		 * syncing the slowest CPU is that others may be almost
		 * as slow, and it will take the fastest CPU completing
		 * one whole chunk read to prod each one.
		 */
#ifdef __LIKI_DEBUG
		if (util > 90)
			fprintf(stderr, "pcpu buffer cpu %d at %d pct\n", pp->cpu, util);
#endif

		if ((tgtcpu = waiting_for_cpu) != -1) {

			if (util > HARD_SYNC_THRESHOLD) {
#ifdef __LIKI_DEBUG
				fprintf(stderr, "cpu %d hit hard threshold, syncing all...\n", pp->cpu);
#endif
				if (liki_sync(OTHER_CPUS) < 0) {
					fprintf(stderr, "failed to initiate sync(ALL_CPUS)\n");
					exit(99);
				}

			} else if (util > SOFT_SYNC_THRESHOLD) {

				if (tgtcpu != pp->cpu) {

					if (liki_sync(tgtcpu) < 0) {
						fprintf(stderr, "failed to initiate sync(laggard)\n");
						exit(99);
					}
				}
			}
		}

		if (pp->need_wakeup) {

			pp->need_wakeup = FALSE;
			pthread_cond_signal(&pp->cond);

			if (waiting_for_cpu == pp->cpu)
				waiting_for_cpu = -1;
		}

		/* Move the write chunk forwards, but don't overtake
		 * the reader
		 */
		while (NEXT_CHUNK(pp->buf, pp->write_chunk) == pp->read_chunk) {

			/* While we're waiting here the in-kernel ring buffer
			 * could be overflowing and we could be losing buffers.
			 * This will be detectable by missing per-CPU sequence
			 * numbers in the trace data.
			 */
			if (terminate_live_stream) {
				pthread_mutex_unlock(&pp->mtx);
#ifdef DEBUG
				fprintf(stderr, "liki_pcpu_thread: terminate_live_stream\n");
#endif
				pthread_exit(NULL);
			}

			pp->need_wakeup = TRUE;
			pthread_cond_wait(&pp->cond, &pp->mtx); 

			if (terminate_live_stream) {
				pthread_mutex_unlock(&pp->mtx);
#ifdef DEBUG
				fprintf(stderr, "liki_pcpu_thread: terminate_live_stream2\n");
#endif
				pthread_exit(NULL);
			}
		}

		pp->write_chunk = NEXT_CHUNK(pp->buf, pp->write_chunk);

		pthread_mutex_unlock(&pp->mtx);
	}

#ifdef DEBUG
	fprintf(stderr, "liki_pcpu_thread: return\n");
#endif
	return(NULL);
}

ssize_t
read_from_pcpu_buffer(int cpu, void *buf)
{
	pcpu_t		*pcpup;

	pcpup = &pcpu[cpu];

	pthread_mutex_lock(&pcpup->mtx);

	/* Wait until more data is available from the pcpu thread. */

	while (pcpup->read_chunk == pcpup->write_chunk) {

		if (terminate_live_stream) {
			pthread_mutex_unlock(&pcpup->mtx);
			pthread_exit(NULL);
		}

		pcpup->need_wakeup = TRUE;
		waiting_for_cpu = pcpup->cpu;
		pthread_cond_wait(&pcpup->cond, &pcpup->mtx);

		if (terminate_live_stream) {
			pthread_mutex_unlock(&pcpup->mtx);
			pthread_exit(NULL);
		}
	}

	/* REVISIT: Got to figure out how to remove the memcpy here! */
	memcpy(buf, (const void *)pcpup->read_chunk, ((info_t *)(pcpup->read_chunk))->page_length + TRACE_SIZE(info_t));
#ifdef __LIKI_DEBUG
	memset((void *)pcpup->read_chunk, 0, CHUNK_SIZE);
#endif
	/* Move on to the next chunk. 
	 */
	pcpup->read_chunk = NEXT_CHUNK(pcpup->buf, pcpup->read_chunk);

	/* If pcpu thread was waiting for more space then wake it up. */
	if (pcpup->need_wakeup) {
		pcpup->need_wakeup = FALSE;
		pthread_cond_signal(&pcpup->cond);
	}

	pthread_mutex_unlock(&pcpup->mtx);

#ifdef __LIKI_DEBUG
	liki_validate_chunk("merge read_from_pcpu_buffer()", buf, NULL, NULL, NULL, NULL);
#endif
	return(((info_t *)(buf))->page_length + TRACE_SIZE(info_t));
}


/* The merge thread constantly merges available traces from the per-CPU
 * buffers and stores these in a merge_traces buffer from which they
 * can be read by the application.
 */
char		*mt_buf;		/* pointer to merged traces buffer */
char		*mt_read_chunk;		/* the chunk from which we're currently reading */
char		*mt_write_chunk;	/* the chunk being written by the pcpu thread */
int		mt_need_wakeup = FALSE;
pthread_mutex_t	mt_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t	mt_cond = PTHREAD_COND_INITIALIZER;

void *
liki_merge_thread(void * mpv)
{
	merge_params_t	*mp = (merge_params_t *)mpv;
	int		err;
#ifdef LIKI_REALTIME_PCPU_THREADS
	struct sched_param sp;
#endif
#ifdef __LIKI_DEBUG
	unsigned long	lmt_prevts = -1;
	unsigned long traces = 0;
	unsigned long lost_traces = 0;
#endif
	
#ifdef	LIKI_REALTIME_PCPU_THREADS
	sp.sched_priority = sched_get_priority_min(SCHED_RR) + 1;
	if (sched_setscheduler(0, SCHED_RR, &sp) == -1) {
		perror("sched_setscheduler()");
		fprintf(stderr, "failed to make per-CPU threads realtime\n");
	}
#endif

	if ((mt_buf = (char *)malloc(BUF_SIZE)) == NULL) {
		terminate_live_stream = TRUE;
		pthread_exit(NULL);
	}

	mt_read_chunk = mt_write_chunk = mt_buf;

	liki_begin_merge(mp);

	while (!terminate_live_stream) {

	       if ((err=liki_next_merged_chunk(mt_write_chunk)) < 0) {
			fprintf(stderr, "liki_next_merged_chunk() returned error=%d\n", err);
			exit(99);
		}

#ifdef __LIKI_DEBUG
		liki_validate_chunk("validate merged", mt_write_chunk, &lmt_prevts, NULL, &traces, &lost_traces);
#endif

		pthread_mutex_lock(&mt_mtx);

		/* If app hasn't consumed the oldest write chunk then wait.
 		 * Note we must do it this way otherwise we may end up
 		 * overwriting a sync chunk, and the app would then become
 		 * confused.
 		 */
		while (NEXT_CHUNK(mt_buf, mt_write_chunk) == mt_read_chunk) {

			if (terminate_live_stream) {
				pthread_mutex_unlock(&mt_mtx);
				return(NULL);
			}

			mt_need_wakeup = TRUE;
			pthread_cond_wait(&mt_cond, &mt_mtx);

			if (terminate_live_stream) {
				pthread_mutex_unlock(&mt_mtx);
				return(NULL);
			}
		}

		mt_write_chunk = NEXT_CHUNK(mt_buf, mt_write_chunk);

		if (mt_need_wakeup) {
			mt_need_wakeup = FALSE;
			pthread_cond_signal(&mt_cond);
		}

		pthread_mutex_unlock(&mt_mtx);
	}


	return(NULL);
}

pthread_cond_t	sync_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t	sync_mtx = PTHREAD_MUTEX_INITIALIZER;

void *
liki_sync_thread()
{
	struct timespec 	ts;

	while (!terminate_live_stream) {

		clock_gettime(CLOCK_REALTIME, &ts);

		ts.tv_nsec += liki_sync_interval;

		while (ts.tv_nsec >= 1000000000) {
			ts.tv_nsec-=1000000000;
			ts.tv_sec++;
		}

		/* Sleep for a duration, but use a condvar so that at the
		 * termination we can be easily kicked
		 */
		pthread_mutex_lock(&sync_mtx);
		pthread_cond_timedwait(&sync_cond, &sync_mtx, &ts);
		pthread_mutex_unlock(&sync_mtx);

		liki_sync(ALL_CPUS);
	}

	return(0);
}

int
liki_open_live_stream()
{
	static merge_params_t	mp;
	int		err;
	int		cpu;
	int		i;

	cpucnt = 0;

	while ((pcpu[cpucnt].rbfd = liki_open_ringbuf(&cpu)) >= 0) {

		pcpu[cpucnt].cpu = cpu;
		pcpu[cpucnt].buf = malloc(BUF_SIZE);
		memset(pcpu[cpucnt].buf, 0, BUF_SIZE);
		pcpu[cpucnt].read_chunk = pcpu[cpucnt].buf;
		pcpu[cpucnt].next_r = pcpu[cpucnt].buf;
		pcpu[cpucnt].write_chunk = pcpu[cpucnt].buf;
		pcpu[cpucnt].need_wakeup = FALSE;
		pthread_mutex_init(&pcpu[cpucnt].mtx, NULL);
		pthread_cond_init(&pcpu[cpucnt].cond, NULL);

		if ((err = pthread_create(&stids[cpucnt], NULL, liki_pcpu_thread, (void *)&pcpu[cpucnt])) != 0) {
			fprintf(stderr, "failed to spawn thread for cpu %d, err = %d\n", cpucnt, err);
			goto kill_streaming_threads;
		}

		cpucnt++;
	}

	mp.read_func = read_from_pcpu_buffer;
	mp.num_sources = cpucnt;
	if ((mp.src_data = malloc(sizeof(int) * cpucnt)) == NULL) {
		fprintf(stderr, "failed to malloc memory\n");
		goto kill_streaming_threads;
	}
	for(i=0; i<cpucnt; i++) mp.src_data[i] = i;

	if ((err = pthread_create(&mtid, NULL, liki_merge_thread, &mp)) != 0) {
		fprintf(stderr, "failed to spawn merge master thread, err = %d\n", err);
		goto kill_streaming_threads;
	}

	if ((err = pthread_create(&synctid, NULL, liki_sync_thread, (void *)NULL)) != 0) {
		fprintf(stderr, "failed to spawn sync thread, err = %d\n", err);
		goto kill_merge_threads;
	}

	return(0);

kill_merge_threads:
#ifdef DEBUG
	fprintf(stderr, "open_live_stream():kill_merge_threads\n");
#endif
	pthread_cancel(mtid);

kill_streaming_threads:
#ifdef DEBUG
	fprintf(stderr, "open_live_stream():kill_streaming_threads\n");
#endif
	for (; cpucnt>-0; cpucnt--)
		pthread_cancel(stids[cpucnt]);

	return(-1);
}

void
liki_close_live_stream()
{
	int	i;

	/* Lock down the whole pipeline to prevent wakeups being
	 * lost and threads hanging
	 */
	pthread_mutex_lock(&sync_mtx);
	pthread_mutex_lock(&mt_mtx);
	for (i=0; i<cpucnt; i++)
		pthread_mutex_lock(&pcpu[i].mtx);

	/* Set the "we're done flag for all to see */
	terminate_live_stream = TRUE;

	/* Kick any of the per-CPU threads out of kernel if that's
	 * where they be
	 */
	liki_sync(ALL_CPUS);

	/* Kick the merge thread */
	pthread_cond_signal(&mt_cond);

	/* Kick the sync thread */
	pthread_cond_signal(&sync_cond);

	/* Give all waiting per-CPU threads a prod */
	for (i=0; i<cpucnt; i++)
		pthread_cond_broadcast(&pcpu[i].cond);

	/* Release the locks */
	pthread_mutex_unlock(&sync_mtx);
	pthread_mutex_unlock(&mt_mtx);
	for (i=0; i<cpucnt; i++)
		pthread_mutex_unlock(&pcpu[i].mtx);

	/* Wait for all threads to terminate */
	for (i=0; i<cpucnt; i++) 
		pthread_join(stids[i], NULL);

	pthread_join(mtid, NULL);
	pthread_join(synctid, NULL);

	/* Close files... */
	for (i=0; i<cpucnt; i++)
		liki_close_ringbuf(pcpu[i].rbfd);

	close(liki_sf);
	close(liki_trf);
	close(liki_tef);
	close(liki_isf32);
	close(liki_isf64);
} 


int
liki_next_live_chunk(char *buf)
{
	int		ret;
#ifdef __LIKI_DEBUG
	unsigned long	lmt_prevts = -1;
	unsigned long	traces = 0;
	unsigned long	lost_traces = 0;
#endif
	pthread_mutex_lock(&mt_mtx);

	/* If we've already consumed all available merged data
 	 * then sleep.
 	 */
	while (mt_read_chunk == mt_write_chunk) {

		mt_need_wakeup = TRUE;

		if (terminate_live_stream) {
			pthread_mutex_unlock(&mt_mtx);
			return(-EIO);
		}
	
		if ((ret=pthread_cond_wait(&mt_cond, &mt_mtx)) != 0) {
			pthread_mutex_unlock(&mt_mtx);
			return(-ret);
		}

		if (terminate_live_stream) {
			pthread_mutex_unlock(&mt_mtx);
			return(-EIO);
		}
	}

	memcpy(buf, mt_read_chunk, CHUNK_SIZE);

	mt_read_chunk = NEXT_CHUNK(mt_buf, mt_read_chunk);

	/* We free'ed up some space. If need be, wake the merge thread. */
	if (mt_need_wakeup) {

		mt_need_wakeup = FALSE;
		pthread_cond_signal(&mt_cond);
	}

#ifdef __LIKI_DEBUG
	liki_validate_chunk("validate merged", mt_read_chunk, &lmt_prevts, NULL, &traces, &lost_traces);
#endif

	pthread_mutex_unlock(&mt_mtx);
	
	return(BYTES_IN_CHUNK(buf));
}

void
liki_set_end_of_sample(unsigned long interval)
{
	new_sample_period = interval;
}

#endif
