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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"
#include "kd_types.h"
#include "conv.h"
#include "hash.h"

void *filter_func_arg;
void *process_func_arg;
void *print_func_arg;
void *report_func_arg;
void *bufmiss_func_arg;
void *bufswtch_func_arg;
void *alarm_func_arg;

void * (*filter_func)(void *, void *);
int (*preprocess_func)(void *, void *);
int (*process_func)(void *, void *);
int (*sort_func)(const void *, const void *);
int (*print_func)(void *);
int (*report_func)(void *);
int (*bufmiss_func)(void *, void *);
int (*bufswtch_func)(void *);
int (*alarm_func)(void *);

filter_t trace_filter;
int print_flag;
double secs;
uint64 interval_start_time = 0;
uint64 last_time = 0;

ki_action_t *ki_actions;
trace_ids_t trace_ids;

/*
** Adds a filter item onto the supplied linked list of items
*/
int
add_filter_item(void *a, uint64 item)
{
	filter_item_t *f = (filter_item_t *)a;
	filter_item_t *ft;

        if (ft = malloc(sizeof(filter_item_t))) {
                ft->fi_next = f->fi_next;
                ft->fi_item = item;
                f->fi_next = ft;
		SET(FILTER_FLAG);
                return 0;
        }

        return -1;

}

/*
** Adds a filter item onto the supplied linked list of items
*/
int
add_filter_item_str(void *a, char *item_str)
{
	filter_item_t *f = (filter_item_t *)a;
	filter_item_t *ft;

        if (ft = malloc(sizeof(filter_item_t))) {
                ft->fi_next = f->fi_next;
                ft->fi_item_str = item_str;
                f->fi_next = ft;
                return 0;
        }

        return -1;

}

inline int rb_len_time_stamp()
{
        if (atoi(globals->os_vers) >= 5) {
                return 8;
        } else {
                return 16;
        }
}

char *
get_rec_from_event(event_t *eventp) 
{
	uint32 type_len_ts, type_len;
	uint32 event_header_length;

	if (IS_WINKI || IS_LIKI) return (char *)eventp;

	type_len_ts = eventp->type_len_ts;
	type_len = type_len_ts & 0x1f;

	switch (type_len) { 
	case RINGBUF_TYPE_PADDING:
	case RINGBUF_TYPE_TIME_EXTEND:
		return NULL;
		break;
	case 0:
		event_header_length = 8;
		break;
	case RINGBUF_TYPE_TIME_STAMP:
		event_header_length = rb_len_time_stamp();
		break;
	default: 
		event_header_length = 4;
		break;
	}

	return (char *)eventp + event_header_length;
}
	
int
process_buffer(trace_info_t *trcinfop)
{
	common_t tt_rec_ptr;
	common_t *rec_ptr;

	if (debug) fprintf (stderr, "process_buffer()\n");

	rec_ptr = conv_common_rec(trcinfop, &tt_rec_ptr);

	if (preprocess_func) {
		preprocess_func((void *)trcinfop, NULL);
	}

	/* action specific function */
	if (ki_actions[rec_ptr->id].execute && ki_actions[rec_ptr->id].func) {
		if (IS_WINKI && (winki_start_time == 0)) winki_start_time = trcinfop->cur_time;
		ki_actions[rec_ptr->id].func((void *)trcinfop, filter_func_arg);
	}

	/* for generic post processing */
	if (process_func) {
		process_func((void *)trcinfop, NULL);
	}
}

void
developers_init()
{
	uint64		key;
	int		i;

	if (debug) fprintf (stderr, "developers_init()\n");

	if (is_alive) {
		init_liki_tracing();
		/* set signal handling here if needed */
	}
}

int
check_missed_events(char *rec_ptr) 
{
	common_t *liki_rec = (common_t *)rec_ptr;
	trace_info_t *mytrcp;
	int cpu, missed_events;
	unsigned long seqno;

	if (IS_LIKI) {
		/* we cannot use trcinfp here as the ki.bin files may be merged into a single file *
		 * instead, we use the cpu found in the liki event records and index back into the *
 		 * trace_files[] array 								   */
		cpu = liki_rec->cpu;
		mytrcp = &trace_files[cpu];
		seqno =  liki_rec->cpu_seqno;
		mytrcp->cur_time = liki_rec->hrtime;

		if (mytrcp->cur_seqno == 0) {
			/* skip the first missed event sequence */
			missed_events = 0; 
		} else {
			missed_events = seqno ? seqno - (mytrcp->cur_seqno + 1) : 0;
		}

		if (missed_events) {
			if (!kilive) {
				printf ("---------- CPU[%d] Missed %d events (prev_seqno: %lld  seqno: %lld) ----------\n", 
					cpu, missed_events, mytrcp->cur_seqno, seqno);
			}
			mytrcp->missed_events += missed_events;
			if (is_alive) trace_file_merged.missed_events += missed_events;
		}

		mytrcp->cur_seqno = seqno;
		return missed_events;
	} else {
		return 0;
	}
}

inline uint32
_get_event_len(event_t *eventp) 
{
	uint32 type_len_ts, type_len;
	uint32 length;
	common_t *rec_ptr;
	etw_common_t *etw_rec_ptr;
	etw_common_c014_t *etw_c014_rec_ptr;
	
	if (IS_LIKI) {
		rec_ptr = (common_t *)eventp;
		return rec_ptr->reclen;
	}
	
	if (IS_WINKI) {
		/* be sure we are 64-bit aligned */
		etw_rec_ptr = (etw_common_t *)eventp;
		if (etw_rec_ptr->ReservedHeaderField == 0xc014) {
			etw_c014_rec_ptr = (etw_common_c014_t *)etw_rec_ptr;
			return ((etw_c014_rec_ptr->EventSize+7) & ~0x7);
		} else {
			return ((etw_rec_ptr->EventSize+7) & ~0x7);
		}
	}
		

	type_len_ts = eventp->type_len_ts;
	type_len = type_len_ts & 0x1f;

	switch (type_len) { 
	case RINGBUF_TYPE_PADDING:
		length = eventp->array[0] * 4;
		length += 8;
		break;
	case RINGBUF_TYPE_TIME_EXTEND:
		length = 8;
		break;
	case RINGBUF_TYPE_TIME_STAMP:
		length = rb_len_time_stamp();
		break;
	case 0:
		length = eventp->array[0] + 4;
		break;
	default: 
		length = (type_len * 4) + 4;
		break;
	}

	return length;
}

uint32
get_event_len(event_t *eventp) 
{
	return _get_event_len(eventp);
}
	
uint64
get_event_time(trace_info_t *trcinfop, int how)
{
	uint32 type_len_ts, type_len;
	uint64 time_delta, ts, event_time;
	uint32 length;
	event_t *eventp = (event_t*)trcinfop->next_event;
	common_t *rec_ptr = (common_t *)eventp;
	etw_common_t *etw_rec_ptr = (etw_common_t *)eventp;
	etw_common_c002_t *etw_rec_c002_ptr = (etw_common_c002_t *)eventp;
	etw_common_c011_t *etw_rec_c011_ptr = (etw_common_c011_t *)eventp;
	etw_common_c014_t *etw_rec_c014_ptr = (etw_common_c014_t *)eventp;

	/* printf ("get_event_time: header 0x%llx   how: %d version %d\n", trcinfop->header, how, globals->kiversion); */

	if (IS_LIKI) return rec_ptr->hrtime;

	if (IS_WINKI) {
		if (etw_rec_ptr->ReservedHeaderField == 0xc002) {
			return etw_rec_c002_ptr->TimeStamp;
		} else if (etw_rec_ptr->ReservedHeaderField == 0xc011) {
			return etw_rec_c011_ptr->TimeStamp;
		} else if (etw_rec_ptr->ReservedHeaderField == 0xc014) {
			return etw_rec_c014_ptr->TimeStamp;
		} else {
			printf ("Unknown ReservedHeaderField: 0x%x\n", etw_rec_ptr->ReservedHeaderField);
			hex_dump(etw_rec_ptr, 1);
			return 0;
		}
	}
			
	type_len_ts = eventp->type_len_ts;
	type_len = type_len_ts & 0x1f;
	ts = (type_len_ts >> 5) & 0x7ffffff;

	switch (type_len) { 
	case RINGBUF_TYPE_PADDING:
	 	time_delta = ts;		
		break;
	case RINGBUF_TYPE_TIME_EXTEND:
		time_delta =  ((uint64)eventp->array[0] << TS_SHIFT) + ts;
		break;
	case RINGBUF_TYPE_TIME_STAMP:
		if (how) trcinfop->next_time = ts;

		time_delta = 0;
		break;
	case 0:
		time_delta = 0;
		break;
	default: 
		time_delta =  ts;
		break;
	}

	if (how) {
		return (trcinfop->next_time + time_delta);
	} else {
		return (trcinfop->header->time + time_delta);
	}
}
		

void
get_new_buffer(trace_info_t *trcinfop, int cpu)
{
	event_t *eventp;
	int retry=1;
	header_page_t *old_header;
	kd_rec_t *rec_ptr;

	if (debug) fprintf (stderr, "get_new_buffer() cpu: %d\n", cpu); 

	while (retry) {
		retry=0;

		old_header = trcinfop->header;
		if (IS_LIKI) {
			trcinfop->header = (header_page_t *)((char *)trcinfop->header+CHUNK_SIZE);
		} else if (IS_WINKI) {
			trcinfop->header = (header_page_t *)((char *)trcinfop->header+winki_bufsz);
		} else {
			trcinfop->header = (header_page_t *)((char *)trcinfop->header + trcinfop->header->commit + HEADER_SIZE(trcinfop->header));
		}

		/* check for end of file or a bad timestamp */
		if (    ((char *)trcinfop->header >= (trcinfop->mmap_addr + trcinfop->size))		||
			(old_header->time > trcinfop->header->time) 					||
			(!(old_header->time & TIME_INVAL) && (trcinfop->header->time & TIME_INVAL))	) {
               		close(trcinfop->fd);
               		trcinfop->fd = 0;
             	  	trcinfop->header = 0;
			trcinfop->next_time = 0;
		} else if (trcinfop->header->commit) {
			trcinfop->next_event = (char *)trcinfop->header + HEADER_SIZE(trcinfop->header);
			trcinfop->next_time = get_event_time(trcinfop, 0);
			trcinfop->buffers++;

			if (debug) 
				fprintf (stderr, "CPU[%d] start time: 0x%llx %6.6f  len: %lld hdr: 0x%llx next_event: 0x%llx next_time: 0x%llx\n",
				cpu,
				trcinfop->header->time,
				SECS(trcinfop->header->time),
				trcinfop->header->commit,
				trcinfop->header,
				trcinfop->next_event,
				trcinfop->next_time);
			
			/* check for bad timestamp and treat as a missed buffer */
			if (trcinfop->header->time && 
		    	    (old_header->time > trcinfop->header->time)) {
				printf ("CPU[%d]: Old Time %9.6f (0x%llx)   New Time %9.6f\n", 
					cpu, SECS(old_header->time), old_header->time, SECS(trcinfop->header->time));
			}
		} else {
			retry=1;
		}
	}
}

char *
get_next_event_for_cpu(trace_info_t *trcinfop)
{
	event_t *eventp;
	int elen;

	if (trcinfop->fd == 0) return NULL;

	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	if (trcinfop->next_time) {
		trcinfop->cur_event = trcinfop->next_event;
		trcinfop->cur_time = trcinfop->next_time;
		eventp = (event_t *)trcinfop->cur_event;
		elen = _get_event_len(eventp);
		trcinfop->next_event = (char *)eventp + elen;

		if (trcinfop->next_event >= ((char *)trcinfop->header + (IS_WINKI ? 0 : HEADER_SIZE(trcinfop->header)) + trcinfop->header->commit)) {
			trcinfop->next_event = (char *)GETNEWBUF;
		} else if (_get_event_len((event_t *)trcinfop->next_event) == 0) {
			trcinfop->next_event = (char *)GETNEWBUF;
		} else {
			trcinfop->next_time = get_event_time(trcinfop, 1);
		}	
		return trcinfop->cur_event;
	} else {
		return NULL;
	}
}

static inline trace_info_t *
get_next_event(int count) 
{
	int cntl_indx, low_indx;
	uint64 low_time=0ull;
	int found;
	trace_info_t *trcinfop;
	event_t *eventp;
	uint32 length;
	uint64 cur_time;
	char *rec_ptr;
	int	missed_events=0;
	common_t  *liki_rec;
	uint32	elen;

    while (1) {
	found = 0;
	low_indx = 0;
	low_time = 0ull;
	/* find trace info with lowest timestamp */
	for (cntl_indx=0; cntl_indx<count; cntl_indx++) {
		trcinfop = &trace_files[cntl_indx];
		if (trcinfop->fd == 0) continue;

		if (trcinfop->next_event == (char *)GETNEWBUF) {
			if (debug) fprintf (stderr, "CPU[%d] map_addr: 0x%llx size: %d - cur header: 0x%llx commit: %d next_event: 0x%llx \n", 
				trcinfop->cpu,
				trcinfop->mmap_addr,
				trcinfop->size,
				trcinfop->header,
				trcinfop->header->commit,
				trcinfop->next_event); 
			get_new_buffer(trcinfop, cntl_indx);
			if (debug) fprintf (stderr, "CPU[%d] header: 0x%llx next_event: 0x%llx \n", 
				trcinfop->cpu,
				trcinfop->header,
				trcinfop->next_event); 
		}	

		if (trcinfop->next_time) {
			found = 1;	
			if ((low_time == 0) || (trcinfop->next_time < low_time)) {
				low_time = trcinfop->next_time;
				low_indx = cntl_indx;
			}
		}
	}

	if (found) {
		/* We found the trace info rec with the lowest time */
		/* return the event and advance the next_event */

		trcinfop = &trace_files[low_indx];
		trcinfop->cur_event = trcinfop->next_event;
		trcinfop->cur_time = trcinfop->next_time;
		trcinfop->cpu = low_indx;
		eventp = (event_t *)trcinfop->cur_event;
		elen = _get_event_len(eventp);
		trcinfop->next_event = (char *)eventp + elen;
		if (debug) { 
				fprintf (stderr, "cur event - CPU %d, map_addr 0x%llx, header 0x%llx (0x%llx), cur_event 0x%llx (0x%llx) cur_time 0x%llx elen 0x%x  next_event 0x%llx (0x%llx)\n",
					trcinfop->cpu, trcinfop->mmap_addr, 
					trcinfop->header, 
					(char *)trcinfop->header - trcinfop->mmap_addr, 
					trcinfop->cur_event,
					(char *)trcinfop->cur_event - trcinfop->mmap_addr,
					trcinfop->cur_time, 
					elen,
					trcinfop->next_event, 
					(char *)trcinfop->next_event - trcinfop->mmap_addr);
		}

		if (trcinfop->next_event >= ((char *)trcinfop->header + (IS_WINKI ? 0 : HEADER_SIZE(trcinfop->header)) + trcinfop->header->commit)) {
			trcinfop->next_event = (char *)GETNEWBUF;
		} else if (_get_event_len((event_t *)trcinfop->next_event) == 0) {
			trcinfop->next_event = (char *)GETNEWBUF;
		} else {
			trcinfop->next_time = get_event_time(trcinfop, 1);
			length = _get_event_len((event_t *)trcinfop->next_event);
			if (debug) {
				fprintf (stderr, "next event - CPU[%d] curevent: 0x%llx nextevent: 0x%llx elen: %d  next_time: 0x%llx *\n", 
					trcinfop->cpu,
					trcinfop->cur_event,
					trcinfop->next_event,
					length,
					trcinfop->next_time);
			}
		}	
		if (start_time == 0) {
			start_time = trcinfop->cur_time; 	/* set on first event found */
			interval_start = interval_end = FILTER_START_TIME;	/* for VIS */
		}

		rec_ptr = get_rec_from_event(eventp);
		if (rec_ptr == NULL) continue;

		trcinfop->cur_rec = rec_ptr;

		missed_events = check_missed_events(rec_ptr);
		if (missed_events && bufmiss_func) {
			/* if an event has been missed, do any special processing */
			/* for now, this is only reliable for LIKI tracing */
			bufmiss_func(trcinfop, rec_ptr);
		}

		/* this is a bit of a kludge to skip records until the startup record is found.
		 ** This should not occur, but we have seen it once. */
                if ((start_filter == 0) && IS_LIKI_V4_PLUS) {
                        liki_rec = (common_t *)rec_ptr;

                        if (liki_rec->id == TT_STARTUP) {
                                startup_found = 1;
                        }
                        if (!startup_found) { 
				continue;
			}
                }
			
		if (filter_func) { 
			if (filter_func(trcinfop, filter_func_arg)) {
				return trcinfop;
			}
			/* else go back to while loop and try again */
			/* we loop until we return a trcinfop,      */
			/* or NULL when we reach the end of the file */
		} else {
				return trcinfop;
		}
	} else {
		return NULL;
	}
    }

}

/* Calls the report func if we set one */
void
print(int count, int(*f)(void *), void *v)
{
	int i;

	if (f) {
		f(v);
	}
}

/* in order to jump to the start time, a few things must have occured before
 *
 *     1.   likimerge is done
 *     2.   kiinfo -kiall has already been executed 
 *     3.   the itimes file is successfully generated, which is only done on kiall
 */
int
find_start_event() {
	trace_info_t *t = &trace_files[0];
	trace_info_save_t *itimesp = NULL, *s;
	uint64 idx, nentries;
	int itimes_fd;
	char fname[30];
	struct stat statbuf;

	sprintf (fname, "itimes.%s", timestamp);
	if ((itimes_fd = open(fname, O_RDONLY)) < 0) {
		printf ("Unable to open %s (errno %d)\n", fname, errno);
		return 0;
	}

	if (fstat(itimes_fd, &statbuf) != 0) {
		printf ("Unable to fstat %s (errno %d)\n", fname, errno);
		close(itimes_fd);
		return 0;
	}

	if (statbuf.st_size == 0) {
		printf ("%s has a length of zero\n", fname);
		close(itimes_fd);
		return 0;
	}

	if ((itimesp = (trace_info_save_t *)mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, itimes_fd, 0)) == MAP_FAILED) {
		printf ("Unable to mmap %s (errno %d)\n", fname, errno);
		close (itimes_fd);
		return 0;
	}

	/* set the start time.  It should be in the first itimes rec */
	s = &itimesp[0];
	start_time = s->cur_time;
	interval_start = interval_end = FILTER_START_TIME;	/* for VIS */

	/* Hopefully, we find the correct itimes save info by doing a quick index */
	idx = start_filter / 1000000;
	nentries = statbuf.st_size / sizeof(trace_info_save_t);
	s = &itimesp[idx];

	/* just in case the quick index found the wrong one, we will use it
	 * as a starting place and search either forward or backward to find the 
	 * correct one
	 */
	if (idx != (s->time_off/1000000)) {
		while ((idx < nentries) && (idx < (s->time_off/1000000))) {
			idx ++;
			s = &itimesp[idx];
		}
		while ((idx > 0) && (idx > (s->time_off/1000000))) {
			idx--;
			s = &itimesp[idx];
		}
	}

	t->header = (header_page_t *)(t->mmap_addr + s->header_off);
	t->next_event = t->mmap_addr + s->cur_event_off;
	t->next_time = s->cur_time;

	if (debug) fprintf (stderr, "[%d] 0x%llx 0x%llx 0x%llx %9.6f\n", idx, t->header, t->cur_event, t->cur_rec, t->cur_time);

	munmap(itimesp, statbuf.st_size);
	close(itimes_fd);
}

void 
developers_call(int ncpus) 
{
	trace_info_t *trcinfop;
	event_t		*eventp;
	int		num=0;
	char 		*cur_rec;
	common_t	tt_rec_ptr;
	common_t	*rec_ptr;
	uint64		elapsed_time;

	if (debug) fprintf (stderr, "developers_call() - ncpus = %d\n", ncpus);

	if (IS_LIKI && (ncpus == 1)) find_start_event();
	
	winki_start_time = 0;

	while (trcinfop = get_next_event(ncpus)) {
		eventp = (event_t *)trcinfop->cur_event;
		rec_ptr = conv_common_rec(trcinfop, &tt_rec_ptr);

		trcinfop->events++;
		last_time = trcinfop->cur_time;
		if (end_filter && (last_time - start_time > end_filter)) break;
		process_buffer(trcinfop); 
	}

	if (IS_WINKI) {
		/* convert start and stop times to be compatible with Linux times */
		start_time = CONVERT_WIN_TIME(winki_start_time);
		last_time = CONVERT_WIN_TIME(last_time);
	}

	if (end_time == 0) end_time = last_time;
	elapsed_time = end_time - start_time;
	elapsed_time = (elapsed_time > start_filter) ? elapsed_time -= start_filter : 0;

	secs = globals->total_secs = SECS(elapsed_time);

	/* print(num, print_func, print_func_arg); */
}

/*
 * ** Called after we have finshed tracing
 * */
void
developers_report()
{

#ifdef DEBUG
        if (debug) fprintf (stderr, "Entering developers_report()\n");
#endif
        if (report_func) {
                report_func(report_func_arg);
        }
#ifdef DEBUG
        if (debug) fprintf (stderr, "Exitng developers_report()\n");
#endif
}
