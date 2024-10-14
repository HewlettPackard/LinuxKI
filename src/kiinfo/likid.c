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

/* likid
 *
 * Dumps liki data from interface files in debugfs to real files in the
 * current working directory. 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>
#include <sched.h>
#include <signal.h>

#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"

extern int liki_enable_msr_data();
extern int likiend_init();

struct	trace_stream {
	int		rb_file;
	int		fs_file;
	int		cpu;
	unsigned long   fp;
} trace_streams[MAXCPUS];

int		cpucnt;

pthread_mutex_t	printf_mutex = PTHREAD_MUTEX_INITIALIZER;

static void likid_sighandler(int sig);
static struct sigaction LIKID_HANDLER = {likid_sighandler, 0, 0, 0, 0};

static void likid_sighandler(int sig)
{
	FATAL(0, "Signal caught", "signal:", sig);
}

void
ignore_syscalls(char *fname)
{
	FILE *f = NULL;
	int syscallno32, syscallno64;
	char *rtnptr;
	int len;

	if ((f = fopen(fname,"r")) == NULL) {
		fprintf (stderr, "\nUnable to open sysignore file (%s), errno %d\n", f, errno);
		fprintf (stderr, "Continuing without ignored system calls\n");
		return;
	}

	while (rtnptr = fgets((char *)&input_str, 511, f)) {
		len = strlen(rtnptr);
		if (len == 0) continue;

		/* OK to have a comment start with # */
		if (input_str[0] == '#') continue;

		/* Look for newline at end of string */
		if (input_str[len-1] == '\n') input_str[len-1] = 0;

		syscallname_to_syscallno(rtnptr, &syscallno32, &syscallno64);
		if (syscallno64  >= 0)  {
			if (!kilive) fprintf (stderr, "ignoring %s [%d] system call (64-bit)\n", rtnptr, syscallno64); 
			liki_ignore_syscall64((long)syscallno64);
		}
		if (syscallno32  >= 0)  {
			if (!kilive) fprintf (stderr, "ignoring %s [%d] system call (32-bit)\n", rtnptr, syscallno32); 			 
			liki_ignore_syscall32((long)syscallno32);
		}
	}

	fclose(f);
	return;
}
 
void *
run_dumper_thread(void * mystream)
{
	struct trace_stream *msp;
	int		cpu;
	int		affin_cpu;
	char		buf[CHUNK_SIZE];
	int		ret;
	int		sz;
	unsigned long	mask;
	cpu_set_t	*cpusetp;
	size_t		cpusetsz;
#ifdef __LIKI_REALTIME_PCPU_THREADS
	struct 		sched_param sp;
#endif

	msp = (struct trace_stream *)mystream;
	cpu = msp->cpu;

#ifdef __LIKI_REALTIME_PCPU_THREADS
	/* Make dumper thread low priority realtime */
	sp.sched_priority = sched_get_priority_min(SCHED_RR);
	if (sched_setscheduler(0, SCHED_RR, &sp) == -1) {
		perror("sched_setscheduler()");
		fprintf(stderr, "failed to make per-CPU threads realtime.  Continuing without realtime priority\n");
                fprintf(stderr, "See https://access.redhat.com/articles/3696121 or try to disable selinux\n");

	}
#endif

	/* Affinitize the dumper thread appropriately. Ideally I'd
	 ** affinitize to the node of the target CPU, but there is
	 ** no straightforward way of doing this in linux without
	 ** using libnuma - and that's a piece of shirt. So..
	 **
	 ** I don't want to affinitize threads to the CPU for which
	 ** they are collecting traces because then I'd be piling
	 ** more work on the busiest CPU. So I affinitize each
	 ** thread also to the "adjacent" CPU, exploiting the fact
	 ** that sockets always seem to have an even number of cores
	 ** to keep the trace data on the same socket.
	 **/
        if ((cpusetp = CPU_ALLOC(MAXCPUS)) != NULL) {
		cpusetsz = CPU_ALLOC_SIZE(MAXCPUS);

		CPU_ZERO_S(cpusetsz, cpusetp);

		affin_cpu = (cpu & 1UL ? (cpu - 1) : (cpu + 1));

		CPU_SET_S(cpu, cpusetsz, cpusetp);
		CPU_SET_S(affin_cpu, cpusetsz, cpusetp);

		if ((ret=pthread_setaffinity_np(pthread_self(), cpusetsz, cpusetp)) != 0) {
			fprintf(stderr, "failed to affinitize per-CPU thread, error=%d\n", ret);
		}

		CPU_FREE(cpusetp);
	} 

	if (likistart_flag) {
		/* loop until tracing has been stopped */
		while (1) {
			sleep(1);
        		mask = liki_get_tracemask();
			if (mask == TT_BITMASK_NO_TRACES) break;
		}
	}

	while ((ret = read(msp->rb_file, buf, CHUNK_SIZE)) != 0) { /* ! EOF */

		if (ret < 0) {
			perror("read()");
			fprintf(stderr, "%s: error reading data from trace file\n", tool_name);
			pthread_exit(NULL);
		}

		/* On the whole we want to write the whole chunk despite it likely 
		 * having some unused bytes at the end, to maintain alignment and 
		 * "whole block" behavior. The exception to this is the very last
		 * chunk (which we can identify because it will be a "sync" chunk).
		 */
		sz = (IS_SYNC_CHUNK(buf) ? ret : CHUNK_SIZE);

		if (write(msp->fs_file, buf, sz) != sz) {
			perror("write()");
			fprintf(stderr, "%s: error writing data to disk\n", tool_name);
			pthread_exit(NULL);
		}
	}

	pthread_exit(NULL);
}

int
likidump()
{
	pthread_t	tids[MAXCPUS];
	int		i;
	char		fname[MAX_FNAME_LEN];
	char		*spooldir = NULL;
	char 		*fname_ext = NULL;
	int		error;
	struct stat	sbuf;
	int		fd;
	int		opt;
	pid_t		tgt_pid = (pid_t)-1;
	pid_t		tgt_pgid = (pid_t)-1;
	uint64		tracemask;
	filter_item_t	*fi;

	if ((sigaction(SIGINT, &LIKID_HANDLER, NULL) == -1) || 
            (sigaction(SIGTERM, &LIKID_HANDLER, NULL) == -1) ||
            (sigaction(SIGHUP, &LIKID_HANDLER, NULL) == -1) ||
            (sigaction(SIGQUIT, &LIKID_HANDLER, NULL) == -1)) {
		perror ("FAILED to set SIGINT handler");
		return 1;
	}

	/* Initialize tracing
	 */
	if (error = liki_init(debug_dir)) {
		FATAL(-error, "Failed to initialize liki tracing module", NULL, -1);
	}
	liki_initialized = 1;

	/* Set up to trace just a single task if specified 
	*/

	fi = trace_filter.f_P_pid;
	while (fi) {
		if (fi->fi_item > 0) {
			fprintf (stderr, "Enabling tracing for PID %d\n", fi->fi_item);
			if ((error=liki_enable_tracing_for_task(fi->fi_item)) < 0) {
					FATAL(-error, "Failed to target task", "PID:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* Set up to trace just a task group if specified 
	*/
	fi = trace_filter.f_P_tgid;
	while (fi) {
		if (fi->fi_item > 0) {
			fprintf (stderr, "Enabling tracing for TGID %d\n", fi->fi_item);
			if ((error=liki_enable_tracing_for_task_group(fi->fi_item)) < 0) {
				FATAL(-error, "Failed to target task group", "TGID:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	fi = trace_filter.f_dev;
	while (fi) {
		if ((int)fi->fi_item >= 0) {
			fprintf (stderr, "Enabling tracing for DEV 0x%x\n", fi->fi_item);
			if ((error=liki_enable_tracing_for_device(fi->fi_item)) < 0) {
				FATAL(-error, "Failed to target task device", "DEV:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	fi = trace_filter.f_P_cpu;
	while (fi) {
		if ((int)fi->fi_item >= 0) {
			fprintf (stderr, "Enabling tracing for CPU %d\n", fi->fi_item);
			if ((error=liki_enable_tracing_for_cpu(fi->fi_item)) < 0) {
				FATAL(-error, "Failed to target cpu ", "CPU:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* filter out ignored system calls */
	if (sysignore) ignore_syscalls(sysignore);

	/* Open all the ring buffer files and the associated disk files, and
	 * create a thread per file pair to stream the buffers to disk
	 */
	cpucnt = 0;

	while ((fd = liki_open_ringbuf(&trace_streams[cpucnt].cpu)) >= 0) {

		trace_streams[cpucnt].rb_file = fd;

		/* Open the corresponding disk file to which traces from this per-CPU
		 * ring buffer will be streamed
		 */
		sprintf(fname, "%s.%03d.%s", DEFAULT_DATAFILE_NAME, trace_streams[cpucnt].cpu, timestamp);

		if ((trace_streams[cpucnt].fs_file = open(fname, O_WRONLY|O_CREAT|O_TRUNC, (S_IWUSR|S_IRUSR))) < 0) {
			perror("open()");
			fprintf(stderr, "%s: failed to open trace dump file\n", tool_name);
			liki_close_ringbuf(trace_streams[cpucnt].rb_file);
			continue;
		}

		/* Finally create the dedicated streaming thread for this file
		 */
		if ((error = pthread_create(&tids[cpucnt], NULL, run_dumper_thread, (void *)&trace_streams[cpucnt]))) {
			fprintf(stderr, "%s: failed to spawn thread for cpu %lu\n", tool_name, trace_streams[cpucnt].cpu);
			liki_close_ringbuf(trace_streams[cpucnt].rb_file);
			close(trace_streams[cpucnt].fs_file);
			continue;
		}

		cpucnt++;
	}

	if (cpucnt == 0) {
		FATAL(1450, "Found no ring buffers", NULL, -1);
	}

#ifdef NOTDEF
	/* Throttle backtracing so as not to kill performance */
	if ((error = liki_set_backtrace_throttling(150000)) < 0) {
		FATAL(-error, "Failed to set backtrace throttling", NULL, -1);
	}
#endif

	/* All streaming threads are in place, so enable tracing
	 */
	ki_actions = liki_action();
	init_trace_ids();

	if (msr_flag) liki_enable_msr_data();	

	if (set_events_options(filter_func_arg) == 0) set_events_default();
	SET_TRACEMASK(tracemask);
        if ((error = liki_set_tracemask(tracemask)) < 0) {
                FATAL(-error, "Failed to enable traces", NULL, -1);
        }

	printf("%s: spooling trace data to disk...\n", tool_name);

	if (likidump_flag) {
		/* Sleep while traces are collected 
	 	*/
		sleep(trace_duration);

		/* Disable tracing, and cause trailing trace data to be flushed
	 	*/
		if ((error = liki_set_tracemask(TT_BITMASK_NO_TRACES)) < 0) {
                	FATAL(-error, "Failed to halt tracing", NULL, -1);
		}

		/* Flush out trailing traces in partial chunks */
		if ((error = liki_sync(ALL_CPUS)) < 0) {
                	FATAL(-error, "Failed to sync trace files", NULL, -1);
		}
	
		/* Remove our target task from the traced tasks list
	 	*/
		if (tgt_pid != (pid_t)-1) {
			if (liki_disable_tracing_for_task(tgt_pid) < 0) {
                		FATAL(-error, "Failed to remove target_ task", "PID:", tgt_pid);
			}
		}

		/* Remove our target task group from the traced tasks list
	 	*/
		if (tgt_pgid != (pid_t)-1) {
			if (liki_disable_tracing_for_task_group(tgt_pgid) < 0) {
                		FATAL(-error, "Failed to remove target task group", "TGID:", tgt_pgid);
			}
		}
	}

	/* The streamer threads will notice the end of the trace data stream
	 * and exit. Wait for that to happen.
	 */
	for (i=0; i<cpucnt; i++)  
		pthread_join(tids[i], NULL);

	/* Leave tracing in the state in which we wish to find it
	 */
	if ((error = liki_set_tracemask(TT_BITMASK_READS_BLOCK)) < 0) {
		FATAL(-error, "failed to reset tracing", NULL, -1);
	}

	/* For each opened ring buffer files and the disk files, close them. */
	for (i=0; i<cpucnt; i++) {

		liki_close_ringbuf(trace_streams[i].rb_file);
		close(trace_streams[i].fs_file);


		/* Remind ourselves of the name of the trace file...
		 */
		sprintf(fname, "%s.%03d.%s", DEFAULT_DATAFILE_NAME, trace_streams[cpucnt].cpu, timestamp);

	}

	printf("%s: Tracing complete\n", tool_name);

	return(0);
}

int
likiend()
{
	int error;

	/* open liki trace files */
	if (error = likiend_init(debug_dir)) {
		FATAL(-error, "Failed to initialize liki tracing module", NULL, -1);
	}

	/* Disable tracing, and cause trailing trace data to be flushed
 	*/
	if ((error = liki_set_tracemask(TT_BITMASK_NO_TRACES)) < 0) {
               	FATAL(-error, "Failed to halt tracing", NULL, -1);
	}

	/* Flush out trailing traces in partial chunks */
	if ((error = liki_sync(ALL_CPUS)) < 0) {
               	FATAL(-error, "Failed to sync trace files", NULL, -1);
	}
}
