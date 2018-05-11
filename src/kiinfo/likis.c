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

/* likis
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
#include <sys/utsname.h>

#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"

extern int      liki_open_live_stream();
extern void	ignore_syscalls(char *);
extern struct utsname  utsname;
extern int	done;

static void likis_sighandler(int sig);
static void alarm_sighandler(int sig);
static struct sigaction LIKIS_HANDLER = {likis_sighandler, 0, 0, 0, 0};
static struct sigaction ALARM_HANDLER = {alarm_sighandler, 0, 0, SA_RESTART, 0};
int unload_liki_module();

static void likis_sighandler(int sig)
{
	FATAL(1000, "Signal Caught", "signal:", sig);
}

static void alarm_sighandler(int sig)
{
	if (debug) fprintf (stderr, "kiinfo caught Signal %d\n", sig);     
	liki_sync(ALL_CPUS);
	alarm_func(NULL);
	alarm(alarm_secs);
}

int 
unload_liki_module() 
{
	char *module;
	int ret;
	char command[255];

	module =  "likit";
	sprintf (command,  "rmmod %s >/dev/null 2>&1", module);
	if ((ret = system(command)) != 0) {
		return(-1);
	}
	liki_module_loaded = 0;

	return 0;
}	

int 
load_liki_module() 
{
	char fname[80];
	int ret;
	char command[255];
	

	if ((sigaction(SIGINT, &LIKIS_HANDLER, NULL) == -1) || 
            (sigaction(SIGTERM, &LIKIS_HANDLER, NULL) == -1) ||
            (sigaction(SIGHUP, &LIKIS_HANDLER, NULL) == -1) ||
            (sigaction(SIGQUIT, &LIKIS_HANDLER, NULL) == -1)) {
		FATAL(errno, "FAILED to set SIGINT handler", NULL, -1);
	}

	unload_liki_module(); 
	sprintf (command,"insmod /lib/modules/%s/misc/likit.ko 2>/dev/null", utsname.release);
	if ((ret = system(command)) != 0) {
		/* if the insmod fails, then we need to check the /opt/linuxki/modules
		 * directory for the appropriate module.  We will first check
		 * using the uname */

		sprintf (command,  "insmod /opt/linuxki/likit.ko 2>/dev/null");
		if ((ret = system(command)) != 0) {
			FATAL(1001, "Unable to load likit.ko module", NULL, -1);
		}
	}

	liki_module_loaded = 1;

	return 0;
}	



trace_info_t *
get_likis_event()
{
	trace_info_t	*trcinfop = &trace_file_merged;
	event_t		*eventp;
	char		*rec_ptr;

	trcinfop->cur_event = trcinfop->next_event;
	eventp = (event_t *)trcinfop->cur_event;

	if ((char *)eventp >= ((char *)trcinfop->header + HEADER_SIZE(trcinfop->header) + trcinfop->header->commit)) {
		return NULL;
	} else if (get_event_len(eventp) == 0) {
		return NULL;
	}

	rec_ptr = (char *)get_rec_from_event(eventp);
	if (rec_ptr == NULL) return NULL;

	trcinfop->cur_time = ((common_t *)rec_ptr)->hrtime;
	trcinfop->cur_rec = rec_ptr;
	trcinfop->next_event = (char *)eventp + get_event_len(eventp);

	if (debug) printf ("header time: 0x%llx %6.6f pagelen: %lld header: 0x%llx curevent: 0x%llx nextevent: 0x%llx elen: %d\n",
	        trcinfop->header->time,
	        SECS(trcinfop->header->time),
	        trcinfop->header->commit,
	        trcinfop->header,
	        trcinfop->cur_event,
	        trcinfop->next_event,
		get_event_len(eventp));

	return (trcinfop);	
}	
	

void
init_liki_tracing()
{
	int 		err;
	pid_t           tgt_pid = (pid_t)-1;
        pid_t           tgt_pgid = (pid_t)-1;
        struct timeval tod;
	uint64 		tracemask;
	int		i;

        filter_item_t *fi;
	filter_t *f = (filter_t *)filter_func_arg;
	int filter_cnt=0;

	if (debug) printf ("init_liki_tracing\n");

	/* Initialize tracing
	 */
	if (err = liki_init(debug_dir)) {
		FATAL(-err, "Failed to initialize liki tracing module", NULL, -1);
	}
	liki_initialized = 1;

	/* Set up to trace specific tasks
	*/
	fi = trace_filter.f_P_pid;
	while (fi) {
		if (fi->fi_item > 0) {
			if ((err=liki_enable_tracing_for_task(fi->fi_item)) < 0) {
				FATAL(-err, "Failed to target task", "PID:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* Set up to trace specific task groups
	*/
	fi = trace_filter.f_P_tgid;
	while (fi) {
		if (fi->fi_item > 0) {
			if ((err=liki_enable_tracing_for_task_group(fi->fi_item)) < 0) {
				FATAL(-err, "Failed to target task group", "TGID:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* Set up to trace for specified CPUs
	*/
	fi = trace_filter.f_P_cpu;
	while (fi) {
		if (fi->fi_item > 0) {
			if ((err=liki_enable_tracing_for_cpu(fi->fi_item)) < 0) {
				FATAL(-err, "Failed to target cpu", "CPU:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* Set up to trace just a task group if specified 
	*/
	fi = trace_filter.f_dev;
	while (fi) {
		if (fi->fi_item > 0) {
			if ((err=liki_enable_tracing_for_device(fi->fi_item)) < 0) {
				FATAL(-err, "Failed to target device", "DEV:", fi->fi_item);
			}
		}
		fi = fi->fi_next;
	}

	/* filter out ignored system calls */
	if (sysignore && strlen(sysignore)) ignore_syscalls(sysignore);

	/* Open all the ring buffer files and the associated disk files, and
	 * create a thread per file pair to stream the buffers to disk
	 */
        if ((err = liki_open_live_stream()) < 0) {
		FATAL(-err, "Unable to open live liki stream", NULL, -1);
        }

	if (msr_flag) liki_enable_msr_data();

	SET_TRACEMASK(tracemask);
        if ((err = liki_set_tracemask(tracemask)) < 0) {
		FATAL(-err, "Failed to set tracemask", NULL, -1);
        }

}

void 
read_liki_traces()
{
	char 		buf[CHUNK_SIZE];
	info_t		*hdr;
	int 	err=0;
	trace_info_t	*trcinfop;
	uint64		rel_time;
        struct timeval tod;
	int pass = 1;
	uint64 elapsed_time;

	done = FALSE;
	/* the time is now printed with the walltime record */
        gettimeofday(&tod, NULL);
	begin_time.tv_sec = tod.tv_sec;
	begin_time.tv_nsec = tod.tv_usec*1000;
	if ((IS_LIKI_V1 || IS_LIKI_V2) && (!kilive)) {
        	printf ("%s", ctime(&tod.tv_sec));
	}

	while (!done) {
		liki_set_end_of_sample(1000000000);

       		while (!done && ((err=liki_next_live_chunk(buf)) >= 0)) {
			/* Now we have a merged chunck, what do we do with it!!! */
			trcinfop = &trace_file_merged;
			hdr = (info_t *)buf;
			globals->kiversion = hdr->version;
			if (debug) 
				printf ("%12.9f Size: %d Version: %d sync_time %12.9f\n", 
						SECS(hdr->hrtime -  start_time), hdr->page_length, hdr->version, 
						hdr->sync_time ? SECS(hdr->sync_time - start_time): 0.0); 

			trcinfop->mmap_addr = buf;
			trcinfop->header = (header_page_t *)buf;
			if (trcinfop->header->commit) {
				trcinfop->next_event = (char *)trcinfop->header + HEADER_SIZE(trcinfop->header);
				trcinfop->buffers++;
				trcinfop->fd = 0;

				while (!done && (trcinfop = get_likis_event())) {
					trcinfop->events++;
					if (start_time == 0) {
						start_time = trcinfop->cur_time;
						interval_start_time = trcinfop->cur_time;
					}
					rel_time = trcinfop->cur_time - start_time;

					if (rel_time > (pass * alarm_secs * 1000000000ull)) {
						end_time = start_time + (pass * alarm_secs *1000000000ull);
						globals->total_secs = alarm_secs * pass * 1.0;
						secs = alarm_secs * 1.0;
						developers_report();
						tod.tv_sec += alarm_secs;
						if (pass >= passes) {
							done = TRUE;
							break;
						} else {
        						if (!kilive) printf ("%s", ctime(&tod.tv_sec));
							interval_start_time = end_time;
							pass++;
							/* alarm(alarm_secs); */
						}
					}

					check_missed_events(trcinfop->cur_rec);

					if (filter_func) {
						if (filter_func(trcinfop, filter_func_arg)) {
							process_buffer(trcinfop);
                        			}
                        			/* else go back to while loop and try again */
                        			/* we loop until we return a trcinfop,      */
                        			/* or NULL when we reach the end of the file */
                			} else {
						process_buffer(trcinfop); 
                			}

        				end_time = trcinfop->cur_time;
					secs = SECS(end_time - interval_start_time);
					elapsed_time = end_time - start_time;
        				elapsed_time = (elapsed_time > start_filter) ? elapsed_time -= start_filter : 0;
					globals->total_secs = SECS(elapsed_time);
				}
			}
			if (!done && IS_SYNC_CHUNK(buf))  {
				/* check to see if we exceeded the alarm time */
				rel_time = hdr->sync_time - start_time;
				if (rel_time > (pass * alarm_secs * 1000000000ull)) {
					end_time = start_time + (pass * alarm_secs *1000000000ull);
					globals->total_secs = alarm_secs * pass * 1.0;
					secs = alarm_secs * 1.0;
					developers_report();
					tod.tv_sec += alarm_secs;
					if (pass >= passes) {
						done = TRUE;
						break;
					} else  {
        					if (!kilive) printf ("%s", ctime(&tod.tv_sec));
						interval_start_time = SECS(end_time);
						pass++;
						/* alarm(alarm_secs); */
					}
				}

				break; 
			}
		} /* end while */

       		if (err < 0) {
			FATAL(-err, "Failed to get next trace chunk", NULL, -1);	
		}

	} /* end while */
}
