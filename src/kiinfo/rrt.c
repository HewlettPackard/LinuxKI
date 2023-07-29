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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/times.h>
#include <malloc.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"

#define BUFFER_SIZE 4096
#define BUFFER_SET_SIZE trace_segments   /* 1 MB */

#define MAXTHREADS 2048
#define MAXCPUS 2048

cpu_set_t *mask;
pthread_t tid[MAXTHREADS];
char	 terminate = FALSE;


typedef struct {
	pthread_t tid;
	char srcfile[133];
	char destfile[133];
	int  srcfd;
        int  destfd;
	char *buffer_set[1024];
} rrt_cntl_t;


/* 
** One array entry per CPU possible, up to 512 CPUs for now 
** the 1MB buffer is not allocated unless the CPU exists 
*/

rrt_cntl_t trc_cntl[MAXCPUS];

void read_raw_trace();
int  setup_percpu_readers();
void * run_reader_thread();
void alloc_thread_this_cpu();

void alloc_thread_this_cpu(uint64 mycpu)
{
   
    int i,error;

    if ((error=pthread_create(&trc_cntl[mycpu].tid, NULL, run_reader_thread, (void *)mycpu)) != 0) {
                FATAL(error, "failed to reate reader thread", "CPU:", mycpu);
    }
}

__thread uint64 cpu;
__thread int curr_buf;
__thread int prev_buf;
__thread int flush_buf;

void *
run_reader_thread(void * vcpuno)
{
        int             affin_cpu;
	int		ret;
        cpu_set_t       *cpusetp;
        size_t          cpusetsz;
#ifdef __LIKI_REALTIME_PCPU_THREADS
        struct          sched_param sp;
#endif

        cpu= (uint64)vcpuno;
        if (debug) printf(" run_reader-thread for cpu %d \n",cpu);

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

    sprintf (trc_cntl[cpu].srcfile, "%s/tracing/per_cpu/cpu%d/trace_pipe_raw", debug_dir, cpu);

    if (timestamp) {
	sprintf (trc_cntl[cpu].destfile, "ki.bin.%03d.%s", cpu, timestamp);
    } else {
	sprintf (trc_cntl[cpu].destfile, "ki.bin.%03d", cpu);
    }

    if (debug) printf ("copying %s -> %s\n", trc_cntl[cpu].srcfile, trc_cntl[cpu].destfile); 

    /*
    **  Open per-cpu Source file 
    */
    if (debug) printf("opening srcfile %s  dest file %s  \n",trc_cntl[cpu].srcfile, trc_cntl[cpu].destfile);

    if((trc_cntl[cpu].srcfd = open64(trc_cntl[cpu].srcfile, O_RDONLY)) < 0) {
            FATAL(errno,"Unable to open trace_pipe_raw file", "CPU:", cpu); 
    }

    /*
    **  Open per-cpu binary file
    */
    if((trc_cntl[cpu].destfd = open64(trc_cntl[cpu].destfile, O_WRONLY | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH)) < 0) {
	FATAL(errno, "Unable to open file or write", trc_cntl[cpu].destfile, -1);
    }

    read_raw_trace();

    close(trc_cntl[cpu].srcfd);
    close(trc_cntl[cpu].destfd);
    return NULL;
}




int
flush_buffers (int cnt)
{
	int fbuf, pbuf;
	int total_cnt = cnt;
	int page_len;
	int i;
	char *bufptr;
	header_page_t *ptr;
	
	if (debug) printf ("flush_buffers: flush_buf=%d prev_buf=%d curr_buf=%d\n",flush_buf, prev_buf, curr_buf);
	if (flush_buf == prev_buf) {
		/* we only flush up to the prev_buf */
		return 0;
	}

	/* lets normalize the prev_buf index to compare against the flush_buf */
	pbuf = prev_buf;
	if (pbuf < flush_buf) pbuf = pbuf + BUFFER_SET_SIZE;

	/* only flush up to the prev_buf */	
	if (flush_buf + cnt > pbuf) 
		total_cnt = (pbuf - flush_buf);

	for (i=0; i < total_cnt; i++) {
		ptr = (header_page_t *)trc_cntl[cpu].buffer_set[flush_buf];
		/* kiversion = ptr->version; */
		ptr->version = 0;
		page_len = ptr->commit + HEADER_SIZE(ptr);
                if (debug) printf("TID %d flushing buffer %d  for CPU %d to fd %d \n",trc_cntl[cpu].tid, flush_buf, cpu, trc_cntl[cpu].destfd); 
		if (write(trc_cntl[cpu].destfd, trc_cntl[cpu].buffer_set[flush_buf], page_len) < 0) {
			FATAL(errno, "Unable to flush buffer to file", trc_cntl[cpu].destfile, page_len);
		}
		flush_buf++;
		if (flush_buf >= BUFFER_SET_SIZE)  {
			flush_buf = 0;
		}
	}

	if (debug) printf ("flushed %d pages\n", total_cnt);
	return total_cnt;
}
				

void
read_raw_trace()
{
    int i;
    header_page_t *ptr, *prevptr;
    ssize_t ret;
    struct timespec tm;
    double event_time;
    int flush_on_empty;
    int flushed_cnt;
    int page_len;
    char *mem_rval;
    int once = 1;
    struct pollfd fds;
   
    if (debug && once) {
       printf("read_raw_trace for CPU %d \n",cpu);
       once=0;
    }
 
    tm.tv_sec = 0;
    tm.tv_nsec = 10000000;		/* 10 msecs */


    /*
    **  Initialise buffers
    */
    mem_rval = memalign(4096, (sizeof(char) * BUFFER_SIZE * BUFFER_SET_SIZE));
    if (debug) printf("memalign for cpu %d rval = 0x%llx \n",cpu,mem_rval);
    if ( (trc_cntl[cpu].buffer_set[0] = mem_rval) == NULL) {
	FATAL(errno, "Unable to CPU trace buffer", "Size", BUFFER_SIZE);
    }


    memset(trc_cntl[cpu].buffer_set[0], 0 , BUFFER_SIZE * BUFFER_SET_SIZE);

    for (i = 1; i < BUFFER_SET_SIZE; i++) {
        trc_cntl[cpu].buffer_set[i] = trc_cntl[cpu].buffer_set[i-1] + 4096;
    }


    curr_buf = 0;
    prev_buf = BUFFER_SET_SIZE - 1;   /* previous buffer written to */ 
    flush_buf = 0; 		/* next buffer to flush */
    fds.fd = trc_cntl[cpu].srcfd;
    fds.events = POLLIN;

    while (1) {

    	if((ret = read(trc_cntl[cpu].srcfd, trc_cntl[cpu].buffer_set[curr_buf], sizeof(char)*BUFFER_SIZE)) < 0) {
		FATAL(errno, "Unable to read trace_pipe_raw", "CPU: ", cpu);
	}
        if (debug) printf("read_raw_trace():  CPU %d, ret=%d \n",cpu, ret);

	ptr = (header_page_t *)trc_cntl[cpu].buffer_set[curr_buf];
	prevptr = (header_page_t *)trc_cntl[cpu].buffer_set[prev_buf];
	event_time = SECS(ptr->time);
	ptr->commit = ptr->commit & 0xffffff; 		   /* overwrite bits may be set in newer ftrace records */
	/* kiversion = ptr->version; */
	page_len = ptr->commit + HEADER_SIZE(ptr);

	if ((ret && (ptr->time > prevptr->time)) || terminate) {
    		if (debug) printf ("ret=%lld fbuf=%d pbuf=%d cbuf=%d time: 0x%llx %5.6f len: 0x%llx version=0x%x\n", ret, flush_buf, prev_buf, curr_buf, ptr->time, event_time, ptr->commit, ptr->version);
		
		/* advance buffer */
		prev_buf = curr_buf;
		curr_buf++;
		if (curr_buf == BUFFER_SET_SIZE) curr_buf = 0;

		if (terminate) {
			flush_buffers(BUFFER_SET_SIZE);
			return;
		} else {
			if (curr_buf == flush_buf) {
				/* Our buffer of cached pages is full, we must start to flush */
				/* Since we need some pages, we will only flush 4 pages for now */
				flushed_cnt = flush_buffers(4);
			}
	
			flush_on_empty = 1;
	
			if (page_len < BUFFER_SIZE / 2) {
				/* we are digesting pages too fast, throttle it some */
				nanosleep(&tm, NULL);
			}
		}
	} else if (flush_on_empty) {
		flushed_cnt = flush_buffers(16);
		if (flushed_cnt < 16) flush_on_empty = 0;
	} else {
		/* we sleep for 10 msec while we wait for data */
		nanosleep(&tm, NULL); 
		flush_on_empty = 0;
	}

    }
}



int setup_percpu_readers(void)
{
        uint64 i;
        int nrcpus = MAXCPUS;
	char percpu_file[40];
	char trace_pipe_file[128];
	struct stat statbuf;

        for ( i = 0; i < nrcpus; i++ ) {
		sprintf (percpu_file, "/sys/devices/system/cpu/cpu%d", i);
		sprintf (trace_pipe_file, "%s/tracing/per_cpu/cpu%d/trace_pipe_raw", debug_dir, i);
		if ((stat(percpu_file, &statbuf) == 0) &&
		    (stat(trace_pipe_file, &statbuf) == 0)) {
			alloc_thread_this_cpu(i); 
			if (debug) printf("CPU %d found \n",i);
                }
        }

        return 0;
}

