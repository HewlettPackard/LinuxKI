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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"
#include "kd_types.h"
#include "hash.h"

extern int break_flag;
extern int debug;
extern char *cmd_str;
extern char terminate;
extern char *kgdboc_str;

int bufsize_fd = 0;
int marker_fd = 0;
int trace_fd = 0;
int traceon_fd = 0;
int enable_fd = 0;
int curtracer_fd = 0;
int id_fd = 0;

int bufsize_value = 2048;
int enable_value = 0;
int traceon_value = 0;
char curtracer_value[32];
char ki_enable[KI_MAXTRACECALLS];

#define MAX_FIELDS 100
#define TRACEID_LOW 15


void fatal(const char *func, const int lineno, const char *file, int err, char *errmsg, char *optmsg, int optnum);
static void traced_sighandler(int sig);
static struct sigaction TRACED_HANDLER = {traced_sighandler, 0, 0, 0, 0};

static void traced_sighandler(int sig)
{
	FATAL(1999, "Signal Caught", "signal:", sig);
}

ki_action_t *
liki_action()
{
	ki_action_t *liki_actions;

	liki_actions = calloc(KI_MAXTRACECALLS, sizeof(ki_action_t));
	if (liki_actions == NULL) {
		FATAL(errno,"Cannot allocate memory for ki_actions array", NULL, -1);
	}

	/* ID 0 is not used with liki, so we will use it to add a dummy
 	 * entry for print, which is not used by liki
 	 */
 
	liki_actions[0].id = 0;
	strcpy(&liki_actions[0].subsys[0], "ftrace");
	strcpy(&liki_actions[0].event[0], "print");

	liki_actions[TT_SCHED_SWITCH].id = TT_SCHED_SWITCH;
	strcpy(&liki_actions[TT_SCHED_SWITCH].subsys[0], "sched");
	strcpy(&liki_actions[TT_SCHED_SWITCH].event[0], "sched_switch");

	liki_actions[TT_SCHED_WAKEUP].id = TT_SCHED_WAKEUP;
	strcpy(&liki_actions[TT_SCHED_WAKEUP].subsys[0], "sched");
	strcpy(&liki_actions[TT_SCHED_WAKEUP].event[0], "sched_wakeup");

	liki_actions[TT_SCHED_MIGRATE_TASK].id = TT_SCHED_MIGRATE_TASK;
	strcpy(&liki_actions[TT_SCHED_MIGRATE_TASK].subsys[0], "sched");
	strcpy(&liki_actions[TT_SCHED_MIGRATE_TASK].event[0], "sched_migrate_task");

	liki_actions[TT_BLOCK_RQ_INSERT].id = TT_BLOCK_RQ_INSERT;
	strcpy(&liki_actions[TT_BLOCK_RQ_INSERT].subsys[0], "block");
	strcpy(&liki_actions[TT_BLOCK_RQ_INSERT].event[0], "block_rq_insert");

	liki_actions[TT_BLOCK_RQ_ISSUE].id = TT_BLOCK_RQ_ISSUE;
	strcpy(&liki_actions[TT_BLOCK_RQ_ISSUE].subsys[0], "block");
	strcpy(&liki_actions[TT_BLOCK_RQ_ISSUE].event[0], "block_rq_issue");

	liki_actions[TT_BLOCK_RQ_COMPLETE].id = TT_BLOCK_RQ_COMPLETE;
	strcpy(&liki_actions[TT_BLOCK_RQ_COMPLETE].subsys[0], "block");
	strcpy(&liki_actions[TT_BLOCK_RQ_COMPLETE].event[0], "block_rq_complete");

	liki_actions[TT_BLOCK_RQ_ABORT].id = TT_BLOCK_RQ_ABORT;
	strcpy(&liki_actions[TT_BLOCK_RQ_ABORT].subsys[0], "block");
	strcpy(&liki_actions[TT_BLOCK_RQ_ABORT].event[0], "block_rq_abort");

	liki_actions[TT_BLOCK_RQ_REQUEUE].id = TT_BLOCK_RQ_REQUEUE;
	strcpy(&liki_actions[TT_BLOCK_RQ_REQUEUE].subsys[0], "block");
	strcpy(&liki_actions[TT_BLOCK_RQ_REQUEUE].event[0], "block_rq_requeue");

	liki_actions[TT_HARDCLOCK].id = TT_HARDCLOCK;
	strcpy(&liki_actions[TT_HARDCLOCK].subsys[0], "prof");
	strcpy(&liki_actions[TT_HARDCLOCK].event[0], "hardclock");

	liki_actions[TT_POWER_START].id = TT_POWER_START;
	strcpy(&liki_actions[TT_POWER_START].subsys[0], "power");
	strcpy(&liki_actions[TT_POWER_START].event[0], "power_start");

	liki_actions[TT_POWER_END].id = TT_POWER_END;
	strcpy(&liki_actions[TT_POWER_END].subsys[0], "power");
	strcpy(&liki_actions[TT_POWER_END].event[0], "power_end");

	liki_actions[TT_POWER_FREQ].id = TT_POWER_FREQ;
	strcpy(&liki_actions[TT_POWER_FREQ].subsys[0], "power");
	strcpy(&liki_actions[TT_POWER_FREQ].event[0], "power_frequency");

	liki_actions[TT_SYSCALL_ENTER].id = TT_SYSCALL_ENTER;
	strcpy(&liki_actions[TT_SYSCALL_ENTER].subsys[0], "syscalls");
	strcpy(&liki_actions[TT_SYSCALL_ENTER].event[0], "sys_enter");

	liki_actions[TT_SYSCALL_EXIT].id = TT_SYSCALL_EXIT;
	strcpy(&liki_actions[TT_SYSCALL_EXIT].subsys[0], "syscalls");
	strcpy(&liki_actions[TT_SYSCALL_EXIT].event[0], "sys_exit");

	liki_actions[TT_IRQ_HANDLER_ENTRY].id = TT_IRQ_HANDLER_ENTRY;
	strcpy(&liki_actions[TT_IRQ_HANDLER_ENTRY].subsys[0], "irq");
	strcpy(&liki_actions[TT_IRQ_HANDLER_ENTRY].event[0], "irq_handler_entry");

	liki_actions[TT_IRQ_HANDLER_EXIT].id = TT_IRQ_HANDLER_EXIT;
	strcpy(&liki_actions[TT_IRQ_HANDLER_EXIT].subsys[0], "irq");
	strcpy(&liki_actions[TT_IRQ_HANDLER_EXIT].event[0], "irq_handler_exit");

	liki_actions[TT_SOFTIRQ_ENTRY].id = TT_SOFTIRQ_ENTRY;
	strcpy(&liki_actions[TT_SOFTIRQ_ENTRY].subsys[0], "irq");
	strcpy(&liki_actions[TT_SOFTIRQ_ENTRY].event[0], "softirq_entry");

	liki_actions[TT_SOFTIRQ_EXIT].id = TT_SOFTIRQ_EXIT;
	strcpy(&liki_actions[TT_SOFTIRQ_EXIT].subsys[0], "irq");
	strcpy(&liki_actions[TT_SOFTIRQ_EXIT].event[0], "softirq_exit");

	liki_actions[TT_SOFTIRQ_RAISE].id = TT_SOFTIRQ_RAISE;
	strcpy(&liki_actions[TT_SOFTIRQ_RAISE].subsys[0], "irq");
	strcpy(&liki_actions[TT_SOFTIRQ_RAISE].event[0], "softirq_raise");

	liki_actions[TT_SCSI_DISPATCH_CMD_START].id = TT_SCSI_DISPATCH_CMD_START;
	strcpy(&liki_actions[TT_SCSI_DISPATCH_CMD_START].subsys[0], "scsi");
	strcpy(&liki_actions[TT_SCSI_DISPATCH_CMD_START].event[0], "scsi_dispatch_cmd_start");

	liki_actions[TT_SCSI_DISPATCH_CMD_DONE].id = TT_SCSI_DISPATCH_CMD_DONE;
	strcpy(&liki_actions[TT_SCSI_DISPATCH_CMD_DONE].subsys[0], "scsi");
	strcpy(&liki_actions[TT_SCSI_DISPATCH_CMD_DONE].event[0], "scsi_dispatch_cmd_done");

	liki_actions[TT_LISTEN_OVERFLOW].id = TT_LISTEN_OVERFLOW;
	strcpy(&liki_actions[TT_LISTEN_OVERFLOW].subsys[0], "");
	strcpy(&liki_actions[TT_LISTEN_OVERFLOW].event[0], "listen_overflow");

	liki_actions[TT_WALLTIME].id = TT_WALLTIME;
	strcpy(&liki_actions[TT_WALLTIME].subsys[0], "");
	strcpy(&liki_actions[TT_WALLTIME].event[0], "walltime");

	liki_actions[TT_WORKQUEUE_ENQUEUE].id = TT_WORKQUEUE_ENQUEUE;
	strcpy(&liki_actions[TT_WORKQUEUE_ENQUEUE].subsys[0], "workqueue");
	strcpy(&liki_actions[TT_WORKQUEUE_ENQUEUE].event[0], "workqueue_queue_work");

	liki_actions[TT_WORKQUEUE_EXECUTE].id = TT_WORKQUEUE_EXECUTE;
	strcpy(&liki_actions[TT_WORKQUEUE_EXECUTE].subsys[0], "workqueue");
	strcpy(&liki_actions[TT_WORKQUEUE_EXECUTE].event[0], "workqueue_execute_start");

	liki_actions[TT_TASKLET_ENQUEUE].id = TT_TASKLET_ENQUEUE;
	strcpy(&liki_actions[TT_TASKLET_ENQUEUE].subsys[0], "tasklet");
	strcpy(&liki_actions[TT_TASKLET_ENQUEUE].event[0], "tasklet_enqueue");

	liki_actions[TT_CACHE_INSERT].id = TT_CACHE_INSERT;
	strcpy(&liki_actions[TT_CACHE_INSERT].subsys[0], "filemap");
	strcpy(&liki_actions[TT_CACHE_INSERT].event[0], "mm_filemap_add_to_page_cache");

	liki_actions[TT_CACHE_EVICT].id = TT_CACHE_EVICT;
	strcpy(&liki_actions[TT_CACHE_EVICT].subsys[0], "filemap");
	strcpy(&liki_actions[TT_CACHE_EVICT].event[0], "mm_filemap_delete_from_page_cache");

	liki_actions[TT_MM_PAGE_ALLOC].id = TT_MM_PAGE_ALLOC;
	strcpy(&liki_actions[TT_MM_PAGE_ALLOC].subsys[0], "kmem");
	strcpy(&liki_actions[TT_MM_PAGE_ALLOC].event[0], "mm_page_alloc");

	liki_actions[TT_MM_PAGE_FREE].id = TT_MM_PAGE_FREE;
	strcpy(&liki_actions[TT_MM_PAGE_FREE].subsys[0], "kmem");
	strcpy(&liki_actions[TT_MM_PAGE_FREE].event[0], "mm_page_free");

	return liki_actions;
}


ki_action_t *
winki_action()
{
	ki_action_t *winki_actions;
	int i;

	winki_actions = calloc(65536, sizeof(ki_action_t));
	if (winki_actions == NULL) {
		FATAL(errno,"Cannot allocate memory for ki_actions array", NULL, -1);
	}

	for (i = 0; i < 65536; i++) {
		winki_actions[i].id = i;
		strcpy(&winki_actions[i].subsys[0], "unknown");
		strcpy(&winki_actions[i].event[0], "unknown");
	}

return winki_actions;
}


int
put_fd_int(int fd, int value, char ignore_err)
{
	char buf[20];
	int size;

	if (fd <= 0) return 0;
	sprintf (buf, "%d\n", value);
	lseek(fd, 0, SEEK_SET);
	if (size = write(fd, &buf, strlen(buf)) == 0) {
		if (!ignore_err) {
			fprintf (stderr, "put_fd_int(): write failed (errno=%d)\n", errno);
			return -1;
		}
	}

	return 0;
}

int
get_fd_int(int fd, char ignore_err)
{
	char buf[20];
	int size;

	if (fd <= 0) return 0;
	lseek(fd, 0, SEEK_SET);
	if (size = read(fd, &buf, 20) == 0) {
		if (!ignore_err) {
			fprintf (stderr, "get_fd_int(): write failed (errno=%d)\n", errno);
		}
		return -1;
	}

	buf[size] = 0;
	return atoi(buf);
	return 0;
}

int
put_file_char(char *fname, char value, char ignore_err)
{
	int fd;

	if ((fd = open(fname, O_WRONLY)) < 0) {
	 	/* if we fail, its OK, we just skip this one.  Let's just print a message if debug is on */
		if (debug) {
			perror ("open() failed");
			fprintf (stderr, "Unable to open %s (errno %d)\n", fname, errno);
		}
		return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &value, 1) < 1) {
		if (!ignore_err) {
			fprintf (stderr, "put_fd_int(): write failed (errno=%d)\n", errno);
		}
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

char
get_file_char(char *fname, char ignore_err)
{
	char value;
	int fd;

	if ((fd = open(fname, O_RDONLY)) < 0) {
	 	/* if we fail, its OK, we just skip this one.  Let's just print a message if debug is on */
		if (debug) {
			perror ("open() failed");
			fprintf (stderr, "Unable to open %s (errno %d)\n", fname, errno);
		}
		return 0;
	}

	lseek(fd, 0, SEEK_SET);
	if (read(fd, &value, 1) < 1) {
		if (!ignore_err) {
			fprintf (stderr, "get_file_char(): write failed (errno=%d)\n", errno);
		}
		close(fd);
		return 0;
	}
	close(fd);
	return value;
}

int
put_fd_str(int fd, char *str, char ignore_err)
{
	int size;

	lseek(fd, 0, SEEK_SET);
	if (size = write(fd, str, strlen(str)) == 0) {
		if (!ignore_err) {
			fprintf (stderr, "put_fd_str(): write failed (errno=%d)\n", errno);
		}
		return -1;
	}

	return 0;
}

int 
get_fd_str(int fd, char *str, char ignore_err)
{
	int size; 

	lseek(fd, 0, SEEK_SET);
	if ((size = read(fd, str, 1024)) == 0) {
		if (!ignore_err) {
			fprintf (stderr, "put_fd_str(): write failed (errno=%d)\n", errno);
		}
		return -1;
	}

	str[size] = 0;
	return strlen(str);
}

		

/* once the ids file is opened, we need to initialize the trace_ids array so we can access the ki_actions array
 * easily. Its a lot of compares.
 */ 

void 
init_trace_ids()
{
	int i;
	TRACE_CPU_FREQ = 0;
	TRACE_CPU_IDLE = 0;
	TRACE_POWER_START = 0;
	TRACE_POWER_END = 0;
	TRACE_POWER_FREQ = 0;

	for (i = 0; i < KI_MAXTRACECALLS; i++) {
		if (strcmp(ki_actions[i].event, "print") == 0) TRACE_PRINT = i;
		else if (strcmp(ki_actions[i].event, "sys_exit") == 0) TRACE_SYS_EXIT = i;
		else if (strcmp(ki_actions[i].event, "sys_enter") == 0) TRACE_SYS_ENTER = i;
		else if (strcmp(ki_actions[i].event, "sched_switch") == 0) TRACE_SCHED_SWITCH = i;
		else if (strcmp(ki_actions[i].event, "sched_wakeup_new") == 0) TRACE_SCHED_WAKEUP_NEW = i;
		else if (strcmp(ki_actions[i].event, "sched_wakeup") == 0) TRACE_SCHED_WAKEUP = i;
		else if (strcmp(ki_actions[i].event, "sched_migrate_task") == 0) TRACE_SCHED_MIGRATE_TASK = i;
		else if (strcmp(ki_actions[i].event, "block_rq_issue") == 0) TRACE_BLOCK_RQ_ISSUE = i;
		else if (strcmp(ki_actions[i].event, "block_rq_insert") == 0) TRACE_BLOCK_RQ_INSERT = i;
		else if (strcmp(ki_actions[i].event, "block_rq_complete") == 0) TRACE_BLOCK_RQ_COMPLETE = i;
		else if (strcmp(ki_actions[i].event, "block_rq_requeue") == 0) TRACE_BLOCK_RQ_REQUEUE = i;
		else if (strcmp(ki_actions[i].event, "block_rq_abort") == 0) TRACE_BLOCK_RQ_ABORT = i;
		else if (strcmp(ki_actions[i].event, "hardclock") == 0) TRACE_HARDCLOCK = i;
		else if (strcmp(ki_actions[i].event, "power_start") == 0) TRACE_POWER_START = i;
		else if (strcmp(ki_actions[i].event, "power_end") == 0) TRACE_POWER_END = i;
		else if (strcmp(ki_actions[i].event, "power_frequency") == 0) TRACE_POWER_FREQ = i;
		else if (strcmp(ki_actions[i].event, "cpu_frequency") == 0) TRACE_CPU_FREQ = i;
		else if (strcmp(ki_actions[i].event, "cpu_idle") == 0) TRACE_CPU_IDLE = i;
		else if (strcmp(ki_actions[i].event, "irq_handler_entry") == 0) TRACE_IRQ_HANDLER_ENTRY = i;
		else if (strcmp(ki_actions[i].event, "irq_handler_exit") == 0) TRACE_IRQ_HANDLER_EXIT = i;
		else if (strcmp(ki_actions[i].event, "softirq_entry") == 0) TRACE_SOFTIRQ_ENTRY = i;
		else if (strcmp(ki_actions[i].event, "softirq_exit") == 0) TRACE_SOFTIRQ_EXIT = i;
		else if (strcmp(ki_actions[i].event, "softirq_raise") == 0) TRACE_SOFTIRQ_RAISE = i;
		else if (strcmp(ki_actions[i].event, "scsi_dispatch_cmd_start") == 0) TRACE_SCSI_DISPATCH_CMD_START = i;
		else if (strcmp(ki_actions[i].event, "scsi_dispatch_cmd_done") == 0) TRACE_SCSI_DISPATCH_CMD_DONE = i;
		else if (strcmp(ki_actions[i].event, "listen_overflow") == 0) TRACE_LISTEN_OVERFLOW = i;
		else if (strcmp(ki_actions[i].event, "workqueue_insertion") == 0) TRACE_WORKQUEUE_INSERTION = i;
		else if (strcmp(ki_actions[i].event, "workqueue_execution") == 0) TRACE_WORKQUEUE_EXECUTION = i;
		else if (strcmp(ki_actions[i].event, "workqueue_queue_work") == 0) TRACE_WORKQUEUE_ENQUEUE = i;
		else if (strcmp(ki_actions[i].event, "workqueue_execute_start") == 0) TRACE_WORKQUEUE_EXECUTE = i;
		else if (strcmp(ki_actions[i].event, "mm_filemap_add_to_page_cache") == 0) TRACE_CACHE_INSERT = i;
		else if (strcmp(ki_actions[i].event, "mm_filemap_delete_from_page_cache") == 0) TRACE_CACHE_EVICT = i;
		else if (strcmp(ki_actions[i].event, "cache_insert") == 0) TRACE_CACHE_INSERT = i;
		else if (strcmp(ki_actions[i].event, "cache_evict") == 0) TRACE_CACHE_EVICT = i;
		else if (strcmp(ki_actions[i].event, "tasklet_enqueue") == 0) TRACE_TASKLET_ENQUEUE = i;
#if 0
THese events cause panics on SLES 15, so removing them!!
		else if (strcmp(ki_actions[i].event, "page_fault_kernel") == 0) TRACE_PAGE_FAULT_KERNEL = i;
		else if (strcmp(ki_actions[i].event, "page_fault_user") == 0) TRACE_PAGE_FAULT_USER = i;
#endif
		else if (strcmp(ki_actions[i].event, "mm_filemap_fault") == 0) TRACE_FILEMAP_FAULT = i;
		else if (strcmp(ki_actions[i].event, "mm_anon_fault") == 0) TRACE_ANON_FAULT = i;
		else if (strcmp(ki_actions[i].event, "mm_kernel_pagefault") == 0) TRACE_KERNEL_PAGEFAULT = i;
		else if (strcmp(ki_actions[i].event, "mm_page_alloc") == 0) TRACE_MM_PAGE_ALLOC = i;
		else if (strcmp(ki_actions[i].event, "mm_page_free_direct") == 0) TRACE_MM_PAGE_FREE_DIRECT = i;
		else if (strcmp(ki_actions[i].event, "mm_page_free") == 0) TRACE_MM_PAGE_FREE = i;
		else if (strcmp(ki_actions[i].event, "walltime") == 0) TRACE_WALLTIME = i;
	}
}
	
void open_misc_trace_files()
{
	DIR *dir;
	char fname[256];
	int errnum;

	sprintf (fname, "%s/%s", debug_dir, "tracing");
	if ((dir = opendir(fname)) == NULL) {
		perror ("open of debugfs failed");
		FATAL(errno, "Unable to open debugfs.  Please be sure debugfs is mounted", debug_dir, -1);
	}

	sprintf(fname, "%s/tracing/trace_marker", debug_dir);
	if ((marker_fd = open(fname, O_RDWR)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}

	sprintf(fname, "%s/tracing/buffer_size_kb", debug_dir);
	if ((bufsize_fd = open(fname, O_RDWR)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}

	sprintf(fname, "%s/tracing/trace", debug_dir);
	if ((trace_fd = open(fname, O_RDWR)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}
	sprintf(fname, "%s/tracing/tracing_enabled", debug_dir);
	if ((enable_fd = open(fname, O_RDWR)) < 0) {
		/* if the file does not exist, then do nothing) */
	}

	sprintf(fname, "%s/tracing/tracing_on", debug_dir);
	if ((traceon_fd = open(fname, O_RDWR)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}

	sprintf(fname, "%s/tracing/current_tracer", debug_dir);
	if ((curtracer_fd = open(fname, O_RDWR)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}

	/* closedir(dir); */
	return;
}

void save_misc_trace_values()
{
        enable_value = get_fd_int(enable_fd, 1);
        traceon_value = get_fd_int(traceon_fd, 0);
        bufsize_value = get_fd_int(traceon_fd, 0);
	get_fd_str(curtracer_fd, curtracer_value, 0);
}

void restore_misc_trace_values()
{
        put_fd_int(enable_fd, enable_value, 1);
        put_fd_int(traceon_fd, traceon_value, 0);
        put_fd_int(traceon_fd, bufsize_value, 0);
	put_fd_str(curtracer_fd, curtracer_value, 0);
}

void
traverse_dir(DIR *dir, char *dirname, char *parent, char *subsys)
{
	char fname[256];
	struct dirent *dent;
	DIR *subdir;
	FILE *event_file, *id_file;
	int id;
	char *rtnptr;
	
	while (dent = readdir(dir)) {
		sprintf (fname, "%s/%s", dirname, dent->d_name);
		if (strncmp(dent->d_name, ".", 1) == 0) continue;

		if (strcmp(dent->d_name, "format") == 0) { 

			if ((event_file = fopen(fname, "r")) == NULL) {
				FATAL(errno, "Unable to open file", fname, -1);
			}

			rtnptr = fgets((char *)&input_str, 1024, event_file);

			if (strstr(input_str, "FORMAT TOO BIG")) {
				sprintf (fname, "%s/%s", dirname, "id");
				if ((id_file = fopen(fname, "r")) == NULL) {
					FATAL(errno, "Unable to open file", fname, -1);
				}
				rtnptr = fgets((char *)&input_str, 1024, id_file);
				sscanf (&input_str[0], "%d", &id);

				fclose(event_file);
				fclose(id_file);
			
			} else { 
				rtnptr = fgets((char *)&input_str, 511, event_file);

				sscanf (&input_str[4], "%d", &id);

				fclose(event_file);
			}

			if (id < KI_MAXTRACECALLS) {
				ki_actions[id].id = id;
				strncpy(&ki_actions[id].subsys[0], subsys, 15); ki_actions[id].subsys[15] = 0;
				strncpy(&ki_actions[id].event[0], parent, 31); ki_actions[id].event[31] = 0;
			} else {
				printf ("subsys: %s  event: %s  ID: %d  << ID larger than %d, skipping\n", ki_actions[id].subsys, ki_actions[id].event, id, KI_MAXTRACECALLS);
			}
			if (debug) printf ("subsys: %s  event: %s  ID: %d\n", ki_actions[id].subsys, ki_actions[id].event, id);
			/* if I find the format file, then no need to traverse this subdir more */
			return;
		} else if (subdir = opendir(fname)) {
			traverse_dir(subdir, fname, dent->d_name, subsys);
			closedir(subdir);
		} 
	}
}	


void
build_id_table()
{
	DIR *events_dir;
	char events_dirname[128];
	char fname[256];
	struct dirent *dent;
	DIR *subdir;
	int i, ret;
	char *addr;
	ki_action_t ki_item;

	if (debug) printf ("build_id_table()\n");
	sprintf (events_dirname, "%s/tracing/events", debug_dir);
	if ((events_dir = opendir(events_dirname)) == NULL) {
		FATAL(errno, "Cannot open %s", events_dirname, 0);
	}

	sprintf(fname, "ids.%s", timestamp);
	if ((id_fd = open(fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0) {
			FATAL(errno, "Unable to open file", fname, -1);
	}

	/* initialize the ki_actions mmap array */
	bzero (&ki_item, sizeof(ki_action_t));
	for (i = 0; i < KI_MAXTRACECALLS; i++) {
		ki_item.id = i;
		if (ret=write (id_fd, &ki_item, sizeof(ki_action_t)) <= 0) {
			FATAL(errno, "Cannot write to file", fname, i);
		}
	}
	
	addr = mmap(NULL, sizeof(ki_action_t)*KI_MAXTRACECALLS, PROT_READ | PROT_WRITE, MAP_SHARED, id_fd, 0);
	if (addr == MAP_FAILED) {
		FATAL(errno, "Cannot mmap file", fname, -1);
	}
	
	ki_actions = (ki_action_t *)addr;

	while (dent = readdir(events_dir)) {
		sprintf (fname, "%s/%s", events_dirname, dent->d_name);
		if (strncmp(dent->d_name, ".", 1) == 0) continue;

		if (subdir = opendir(fname)) {
			traverse_dir(subdir, fname, dent->d_name, dent->d_name);
			closedir(subdir);
		} 
	}

	closedir(events_dir);
}

int
save_all_events()
{
	char 	fname[256];
	int 	i;

	if (debug) printf("save_all_events\n");
	for (i = TRACEID_LOW; i < KI_MAXTRACECALLS; i++) {
		if (strlen(ki_actions[i].subsys) ==  0) continue;
		sprintf(fname, "%s/tracing/events/%s/%s/enable", debug_dir, ki_actions[i].subsys, ki_actions[i].event);

		ki_enable[i] = get_file_char(fname, 0);
	}
	return 0;
}

int
restore_all_events()
{
	char 	fname[256];
	int 	i;

	if (debug) printf("restore_all_events\n");
	for (i = TRACEID_LOW; i < KI_MAXTRACECALLS; i++) {
		if (strlen(ki_actions[i].subsys) ==  0) continue;
		sprintf(fname, "%s/tracing/events/%s/%s/enable", debug_dir, ki_actions[i].subsys, ki_actions[i].event);

		if (ki_enable[i]) {
			put_file_char(fname, ki_enable[i], 1);
			if (debug) printf ("%s = %c\n", fname, ki_enable[i]);
		}
	}
	return 0;
}



int
clear_all_events()
{
	char	fname[256];
	int	i;

	if (debug) printf ("clear_all_events\n");
	for (i = TRACEID_LOW; i < KI_MAXTRACECALLS; i++) {
		if (strlen(ki_actions[i].subsys) ==  0) continue;
		sprintf(fname, "%s/tracing/events/%s/%s/enable", debug_dir, ki_actions[i].subsys, ki_actions[i].event);
		put_file_char(fname, '0', 1);
	}
	return 0;
}

void
set_ftrace_events(char value)
{
	char	fname[256];
	int	i;

	for (i = TRACEID_LOW; i < KI_MAXTRACECALLS; i++) {
		if (ki_actions[i].execute) {
			sprintf(fname, "%s/tracing/events/%s/%s/enable", debug_dir, ki_actions[i].subsys, ki_actions[i].event);
			if (debug) printf ("Enable trace id: %d\n", i);
			put_file_char(fname, value, 0);
		}
	}
}

void
set_events_all(int value)
{
	int i;

	for (i = 0; i < (IS_WINKI ? 65536 : KI_MAXTRACECALLS); i++) {
		ki_actions[i].execute = value;
	}
}

void 
set_events_default()
{
	ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
	ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
	ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
	ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
	ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
	ki_actions[TRACE_SYS_EXIT].execute = 1;
	ki_actions[TRACE_SYS_ENTER].execute = 1;
	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;	
	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;	
	if (TRACE_POWER_FREQ) ki_actions[TRACE_POWER_FREQ].execute = 1;	
	if (TRACE_CPU_FREQ) ki_actions[TRACE_CPU_FREQ].execute = 1;	
	ki_actions[TRACE_HARDCLOCK].execute = 1;
	ki_actions[TRACE_WALLTIME].execute = 1;
	ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;	
	ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;	
	ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;	
	ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;	
}

int 
set_events_options(void *v)
{
	filter_t *f=v;
	filter_item_t *fi;
	char	filter_found = FALSE;
	int	filter_cnt = 0;
	int 	i;

	if (debug) fprintf (stderr, "set_events_options()\n");
	if (fi = f->f_events) {
		filter_found = TRUE;
		while (fi) {
			if ((strcmp(fi->fi_item_str,"default") == 0) || 
			    (strcmp(fi->fi_item_str,"kipid") == 0) ||  
			    (strcmp(fi->fi_item_str,"kparse") == 0) ||  
			    (strcmp(fi->fi_item_str,"kitrace") == 0)) {
				filter_cnt++;
				set_events_default();
			} else if (strcmp(fi->fi_item_str,"all") == 0) {
				filter_cnt++;
				/*  Only match the trace records from liki  */
				ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;	
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;	
				ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 1;	
				if (TRACE_POWER_START) ki_actions[TRACE_POWER_START].execute = 1;
				if (TRACE_POWER_END) ki_actions[TRACE_POWER_END].execute = 1;
				if (TRACE_POWER_FREQ) ki_actions[TRACE_POWER_FREQ].execute = 1;	
				if (TRACE_CPU_FREQ) ki_actions[TRACE_CPU_FREQ].execute = 1;	
				if (TRACE_CPU_IDLE) ki_actions[TRACE_CPU_IDLE].execute = 1;	
				ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;	
				ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;	
				ki_actions[TRACE_SCSI_DISPATCH_CMD_START].execute = 1;	
				ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].execute = 1;	
				if (TRACE_HARDCLOCK) ki_actions[TRACE_HARDCLOCK].execute = 1;
				ki_actions[TRACE_WALLTIME].execute = 1;
				if (TRACE_WORKQUEUE_INSERTION) ki_actions[TRACE_WORKQUEUE_INSERTION].execute = 1;
				if (TRACE_WORKQUEUE_EXECUTION) ki_actions[TRACE_WORKQUEUE_EXECUTION].execute = 1;
				if (TRACE_WORKQUEUE_ENQUEUE) ki_actions[TRACE_WORKQUEUE_ENQUEUE].execute = 1;
				if (TRACE_WORKQUEUE_EXECUTE) ki_actions[TRACE_WORKQUEUE_EXECUTE].execute = 1;
			} else if (strcmp(fi->fi_item_str, "kidsk") == 0) {
				filter_cnt++;
				ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
				ki_actions[TRACE_WALLTIME].execute = 1;
			} else if (strcmp(fi->fi_item_str, "kiprof") == 0) {
				filter_cnt++;
				ki_actions[TRACE_HARDCLOCK].execute = 1;
				ki_actions[TRACE_WALLTIME].execute = 1;
			} else if (strcmp(fi->fi_item_str, "kifile") == 0) {
				filter_cnt++;
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;	
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;	
				ki_actions[TRACE_WALLTIME].execute = 1;
			} else if (strcmp(fi->fi_item_str, "kiwait") == 0) {
				filter_cnt++;
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;	
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;	
				ki_actions[TRACE_WALLTIME].execute = 1;
			} else if (strcmp(fi->fi_item_str,"hidden") == 0) {
				filter_cnt++;
				/*  Only match the trace records from liki  */
				ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
				ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;	
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;	
				ki_actions[TRACE_SCHED_MIGRATE_TASK].execute = 1;	
				if (TRACE_POWER_START) ki_actions[TRACE_POWER_START].execute = 1;
				if (TRACE_POWER_END) ki_actions[TRACE_POWER_END].execute = 1;
				if (TRACE_POWER_FREQ) ki_actions[TRACE_POWER_FREQ].execute = 1;	
				if (TRACE_CPU_FREQ) ki_actions[TRACE_CPU_FREQ].execute = 1;	
				if (TRACE_CPU_IDLE) ki_actions[TRACE_CPU_IDLE].execute = 1;	
				ki_actions[TRACE_IRQ_HANDLER_ENTRY].execute = 1;	
				ki_actions[TRACE_IRQ_HANDLER_EXIT].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_ENTRY].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_EXIT].execute = 1;	
				ki_actions[TRACE_SOFTIRQ_RAISE].execute = 1;	
				ki_actions[TRACE_SCSI_DISPATCH_CMD_START].execute = 1;	
				ki_actions[TRACE_SCSI_DISPATCH_CMD_DONE].execute = 1;	
				if (TRACE_HARDCLOCK) ki_actions[TRACE_HARDCLOCK].execute = 1;
				if (TRACE_LISTEN_OVERFLOW) ki_actions[TRACE_LISTEN_OVERFLOW].execute = 1;
				ki_actions[TRACE_WALLTIME].execute = 1;
				if (TRACE_WORKQUEUE_INSERTION) ki_actions[TRACE_WORKQUEUE_INSERTION].execute = 1;
				if (TRACE_WORKQUEUE_EXECUTION) ki_actions[TRACE_WORKQUEUE_EXECUTION].execute = 1;
				if (TRACE_WORKQUEUE_ENQUEUE) ki_actions[TRACE_WORKQUEUE_ENQUEUE].execute = 1;
				if (TRACE_WORKQUEUE_EXECUTE) ki_actions[TRACE_WORKQUEUE_EXECUTE].execute = 1;
				if (TRACE_TASKLET_ENQUEUE) ki_actions[TRACE_TASKLET_ENQUEUE].execute = 1;
				if (TRACE_CACHE_INSERT) ki_actions[TRACE_CACHE_INSERT].execute = 1;
				if (TRACE_CACHE_EVICT) ki_actions[TRACE_CACHE_EVICT].execute = 1;
				if (TRACE_ANON_FAULT) ki_actions[TRACE_ANON_FAULT].execute = 1;
				if (TRACE_FILEMAP_FAULT) ki_actions[TRACE_FILEMAP_FAULT].execute = 1;
#if 0
These events cause panics on SLES 15
				if (TRACE_KERNEL_PAGEFAULT) ki_actions[TRACE_KERNEL_PAGEFAULT].execute = 0;
				if (TRACE_PAGE_FAULT_USER) ki_actions[TRACE_PAGE_FAULT_USER].execute = 0;
				if (TRACE_PAGE_FAULT_KERNEL) ki_actions[TRACE_PAGE_FAULT_KERNEL].execute = 1;
#endif
				if (TRACE_MM_PAGE_ALLOC) ki_actions[TRACE_MM_PAGE_ALLOC].execute = 1;
				if (TRACE_MM_PAGE_FREE)ki_actions[TRACE_MM_PAGE_FREE].execute = 1;
				if (TRACE_MM_PAGE_FREE_DIRECT)ki_actions[TRACE_MM_PAGE_FREE_DIRECT].execute = 1;
			} else { 
				for (i = 1; i < KI_MAXTRACECALLS; i++) {
					if (strcmp(fi->fi_item_str, ki_actions[i].event) == 0) {
						filter_cnt++;
						ki_actions[i].execute = 1;
						i = KI_MAXTRACECALLS;
					}	
				}
			}	
			fi = fi->fi_next;
		}
	}

	if (fi = f->f_subsys) {
		filter_found = TRUE;
		while (fi) {
			for (i = 1; i < KI_MAXTRACECALLS; i++) {
				if (strcmp(fi->fi_item_str, "default") == 0) {
					filter_cnt++;
					set_events_default();
				} else if (strcmp(fi->fi_item_str, ki_actions[i].subsys) == 0) {
					filter_cnt++;
					ki_actions[i].execute = 1;
				}	
			}
			fi = fi->fi_next;
		}
	}

	if (filter_found && (filter_cnt == 0)) {
		fprintf (stderr, "No events found to be traced\nExiting\n");
		FATAL(1025, "No events found to be traces\nExiting", NULL, -1);
	}
	
	return (filter_cnt);
}

void 
debug_trace(const char *func, const int lineno, const char *file) 
{
	fprintf (stderr, "DEBUG: %s():%d [%s]\n", tool_name, func, lineno, file);
}

void 
fatal(const char *func, const int lineno, const char *file, int err, char *errmsg, char *optmsg, int optnum)
{
	if (kilive) {
		live_cleanup_func(NULL);
	}

	if (cwd) {
		if (chdir(cwd) == -1) 
			fprintf (stderr, "Unable to chdir to original directory (errno %d)\n", errno);
	}
	fprintf (stderr, "%s error: %s():%d [%s]: ", tool_name, func, lineno, file);
	if (errmsg) fprintf(stderr, "%s", errmsg);
	if (optmsg) fprintf (stderr, " - %s", optmsg);
	if (optnum != -1) fprintf (stderr, " %d", optnum);
	if (err < 1000) {
			fprintf (stderr, ": errno %d - ", err);
			errno=err;
			perror("");
	} else {
		fprintf (stderr, "\n");
	}

        if (kitracedump_flag) {
		sleep(1);
		fprintf (stderr, "Restoring Tracing events\n");
		restore_all_events();
		restore_misc_trace_values();
        }

	if (kgdboc_str) reset_kgdboc();

	if (liki_initialized) {
		fprintf (stderr, "  resetting trace mask...\n");
        	liki_set_tracemask(TT_BITMASK_NO_TRACES);
		fprintf (stderr, "  closing liki ring buffers...\n");
        	liki_close_live_stream();
	}

	if (liki_module_loaded) {
		fprintf (stderr, "  Unloading likit.ko...\n");
		unload_liki_module();
	}

        _exit(err);
}

void 
kitracedump()
{
	int old_bufsize;
	char begin_marker[80];
	char end_marker[80];
	char version[20];
    	struct timespec tm;

	if (debug) printf ("kitracedump()\n");

	if (timestamp) {
		sprintf(begin_marker, "kitrace_marker_BEGIN_%s", timestamp);
		sprintf(end_marker, "kitrace_marker_END_%s", timestamp);
	} else {
		sprintf(begin_marker, "kitrace_marker_BEGIN");
		sprintf(end_marker, "kitrace_marker_END");
	}
	sprintf(version, "%s (%s)", tool_name, tool_version);

	build_id_table();
	init_trace_ids();
	open_misc_trace_files();

	save_misc_trace_values();
	save_all_events();

	/* after saving the tracing data, we can enable the trap code */

        if ((sigaction(SIGINT, &TRACED_HANDLER, NULL) == -1) ||
            (sigaction(SIGTERM, &TRACED_HANDLER, NULL) == -1) ||
            (sigaction(SIGHUP, &TRACED_HANDLER, NULL) == -1) ||
            (sigaction(SIGQUIT, &TRACED_HANDLER, NULL) == -1)) {
                perror ("FAILED to set SIGINT handler");
                return;
        }

	put_fd_int(trace_fd, 0, 0);
	close(trace_fd);
	put_fd_str(curtracer_fd, "nop", 0);
	/* put_fd_int(enable_fd, 0, 1); */
	put_fd_int(traceon_fd, 0, 0);
	clear_all_events();
	if (trace_bufsize) old_bufsize = put_fd_int(bufsize_fd, trace_bufsize, 1);
	if (set_events_options(filter_func_arg) == 0) set_events_default();
	set_ftrace_events('1');

	put_fd_int(traceon_fd, 1, 0);
	if ((enable_fd >= 0) && !enable_value) put_fd_int(enable_fd, 1, 1);

	printf ("Pausing 10 seconds to sync CPU clocks, please wait...\n");
	sleep(10);

	/* startup percpu read thread */
    	if (setup_percpu_readers()) {
		FATAL(1275, "setup_percpu_readers failed", NULL, -1);
    	}

	tm.tv_sec = 1; tm.tv_nsec = 0;		/* 1 sec */
	nanosleep(&tm, NULL);
	tm.tv_sec = 0;	
	printf ("Collecting trace data for %d seconds, please wait...\n", trace_duration);
	put_fd_str(marker_fd, version, 0);
	put_fd_str(marker_fd, begin_marker, 0); 

    	/* sleep for duration seconds, then call exit which will stop all threads*/
    	sleep(trace_duration);

	put_fd_str(marker_fd, end_marker, 0);
	tm.tv_sec = 1; tm.tv_nsec = 0;		/*  1 sec */
	nanosleep(&tm, NULL);
	/* put_fd_int(enable_fd, 0, 1); */
	put_fd_int(traceon_fd, 0, 0);

	terminate=TRUE;
	sleep(1);

	set_ftrace_events('0');
	
	/* Stop per-cpu reader threads */
	/* terminate_percpu_readers(); */

	restore_all_events();
	restore_misc_trace_values();
	printf ("Trace collection complete\n");
    	sleep(1);
}

int
get_field_attributes(char *s, kdtype_attr_t *attr) {

	char *cptr;	

	if (cptr = strstr(s, "offset:")) { 
		cptr+=7;
		sscanf(cptr, "%d", &attr->offset);
	} else {
		return 0;
	}

	if (cptr = strstr(s, "size:")) { 
		cptr+=5;
		sscanf(cptr, "%d", &attr->size);
	} else {
		return 0;
	} 

	if (cptr = strstr(s, "signed:")) { 
		cptr+=7;
		sscanf(cptr, "%d", &attr->sign);
	} else {
		attr->sign = 0;	
	} 

	return 1;
}

void
parse_fmt_file(char *fname, kdtype_attr_t *attr_array) {

	FILE *f = NULL;
	char *rtnptr;
	kdtype_attr_t tmp_attr;
	int i;

	if (debug) printf ("parse_fmt_file\n");

	if ((f = fopen(fname, "r")) == NULL) {	
		if (debug) { 
			perror ("open() failed");
                	fprintf (stderr, "Unable to fopen %s (errno %d)\n", fname, errno);
			fprintf (stderr, "Continuing with RHEL6 defaults...\n");
		}
                return;
        }
	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			break;
		}

		if (get_field_attributes(rtnptr, &tmp_attr) == 0) {
			continue;
		}
		
		for (i = 0; i < MAX_FIELDS; i++) {
			if (attr_array[i].fieldname == NULL) {
				break;
			}

			if (strstr(rtnptr, attr_array[i].fieldname)) {
				attr_array[i].offset = tmp_attr.offset;
				attr_array[i].size = tmp_attr.size;
				attr_array[i].sign = tmp_attr.sign;

				if (debug) printf ("field: %s  offset:%d  size:%d  signed:%d\n", attr_array[i].fieldname, attr_array[i].offset, attr_array[i].size, attr_array[i].sign);
				break;
			}
		}
	}
}
			
void
read_fmt_files() 
{
	char fname[256];
	char prefix[80];
	char postfix[80];

	prefix[0]=0;
	sprintf(postfix, ".fmt.%s", timestamp);

        sprintf(fname, "%ssched_switch%s", prefix, postfix);
	parse_fmt_file(fname, sched_switch_attr);
        sprintf(fname, "%ssched_wakeup%s", prefix, postfix);
	parse_fmt_file(fname, sched_wakeup_attr);
        sprintf(fname, "%ssched_wakeup_new%s", prefix, postfix);
	parse_fmt_file(fname, sched_wakeup_new_attr);
        sprintf(fname, "%ssched_migrate_task%s", prefix, postfix);
	parse_fmt_file(fname, sched_migrate_task_attr);

        sprintf(fname, "%ssys_enter%s", prefix, postfix);
	parse_fmt_file(fname, sys_enter_attr);
        sprintf(fname, "%ssys_exit%s", prefix, postfix);
	parse_fmt_file(fname, sys_exit_attr);

        sprintf(fname, "%sblock_rq_insert%s", prefix, postfix);
	parse_fmt_file(fname, block_rq_insert_attr);
        sprintf(fname, "%sblock_rq_issue%s", prefix, postfix);
	parse_fmt_file(fname, block_rq_issue_attr);
        sprintf(fname, "%sblock_rq_complete%s", prefix, postfix);
	parse_fmt_file(fname, block_rq_complete_attr);
        sprintf(fname, "%sblock_rq_abort%s", prefix, postfix);
	parse_fmt_file(fname, block_rq_abort_attr);
        sprintf(fname, "%sblock_rq_requeue%s", prefix, postfix);
	parse_fmt_file(fname, block_rq_requeue_attr);

        sprintf(fname, "%spower_start%s", prefix, postfix);
	parse_fmt_file(fname, power_start_attr);
        sprintf(fname, "%spower_end%s", prefix, postfix);
	parse_fmt_file(fname, power_end_attr);
        sprintf(fname, "%spower_frequency%s", prefix, postfix);
	parse_fmt_file(fname, power_freq_attr);

        sprintf(fname, "%scpu_frequency%s", prefix, postfix);
	parse_fmt_file(fname, cpu_freq_attr);
        sprintf(fname, "%scpu_idle%s", prefix, postfix);
	parse_fmt_file(fname, cpu_idle_attr);

        sprintf(fname, "%sirq_handler_entry%s", prefix, postfix);
	parse_fmt_file(fname, irq_handler_entry_attr);
        sprintf(fname, "%sirq_handler_exit%s", prefix, postfix);
	parse_fmt_file(fname, irq_handler_exit_attr);
        sprintf(fname, "%ssoftirq_entry%s", prefix, postfix);
	parse_fmt_file(fname, softirq_entry_attr);
        sprintf(fname, "%ssoftirq_exit%s", prefix, postfix);
	parse_fmt_file(fname, softirq_exit_attr);
        sprintf(fname, "%ssoftirq_raise%s", prefix, postfix);
	parse_fmt_file(fname, softirq_raise_attr);

        sprintf(fname, "%sscsi_dispatch_cmd_start%s", prefix, postfix);
	parse_fmt_file(fname, scsi_dispatch_cmd_start_attr);
        sprintf(fname, "%sscsi_dispatch_cmd_done%s", prefix, postfix);
	parse_fmt_file(fname, scsi_dispatch_cmd_done_attr);

	sprintf(fname, "%sworkqueue_insertion%s", prefix, postfix);
	parse_fmt_file(fname, workqueue_insertion_attr);
	sprintf(fname, "%sworkqueue_execution%s", prefix, postfix);
	parse_fmt_file(fname, workqueue_execution_attr);
	sprintf(fname, "%sworkqueue_queue_work%s", prefix, postfix);
	parse_fmt_file(fname, workqueue_enqueue_attr);
	sprintf(fname, "%sworkqueue_execute_start%s", prefix, postfix);
	parse_fmt_file(fname, workqueue_execute_attr);

	/* 3.0 kernels*/
	sprintf(fname, "%spage_fault_user%s", prefix, postfix);
	parse_fmt_file(fname, page_fault_attr);
	sprintf(fname, "%spage_fault_kernel%s", prefix, postfix);
	parse_fmt_file(fname, page_fault_attr);
	
	/* 2.6.32 kernels */
	sprintf(fname, "%smm_anon_fault%s", prefix, postfix);
	parse_fmt_file(fname, anon_fault_attr);
	sprintf(fname, "%smm_filemap_fault%s", prefix, postfix);
	parse_fmt_file(fname, filemap_fault_attr);
	sprintf(fname, "%smm_kernel_pagefault%s", prefix, postfix);
	parse_fmt_file(fname, kernel_pagefault_attr);

	/* 3.0 kernels */
	sprintf(fname, "%smm_filemap_add_to_page_cache%s", prefix, postfix);
	parse_fmt_file(fname, filemap_pagecache_attr);
	sprintf(fname, "%smm_filemap_delete_from_page_cache%s", prefix, postfix);
	parse_fmt_file(fname, filemap_pagecache_attr);

	sprintf(fname, "%smm_page_alloc%s", prefix, postfix);
	parse_fmt_file(fname, mm_page_alloc_attr);
	sprintf(fname, "%smm_page_free%s", prefix, postfix);
	parse_fmt_file(fname, mm_page_free_attr);
	/* 2.6 kernels */
	sprintf(fname, "%smm_page_free_direct%s", prefix, postfix);
	parse_fmt_file(fname, mm_page_free_attr);
	

        sprintf(fname, "%sprint%s", prefix, postfix);
	parse_fmt_file(fname, marker_attr);
}	

int
open_merged_file() 
{
	int i, ncpus = 0;
	char fname[256];
	struct stat statbuf;
	char *addr, *id_addr, *anon_addr;
	header_page_t *header;

	if (debug) printf ("open_merged_files %s\n", timestamp);
	if (timestamp==NULL) return 0;

	i = 0;
	trace_files[i].cpu = -1;
	trace_files[i].cur_seqno = 0;
	sprintf(fname, "ki.bin.%s", timestamp);
	if (debug) printf ("Opening trace file %s\n", fname);
	
	if ((trace_files[i].fd = open(fname, O_RDONLY)) < 0) {
		if (debug) perror ("open() failed");
		trace_files[i].fd = 0;
		return 0;
	}

	if (fstat(trace_files[i].fd, &statbuf) != 0) {
		if (debug) perror ("fstat() failed");
		trace_files[i].fd = 0;
		close(trace_files[i].fd);
		return 0;
	}

	if (statbuf.st_size == 0) {
		trace_files[i].fd = 0;
		trace_files[i].size = 0;
		close(trace_files[i].fd);
		return 0;
	}

	trace_files[i].size = statbuf.st_size;

	addr = mmap(NULL, trace_files[i].size, PROT_READ, MAP_PRIVATE, trace_files[i].fd, 0);
	if (addr == MAP_FAILED) {
		fprintf (stderr, "Cannot mmap file %s - Errno %d\n", fname, errno);
		trace_files[i].fd = 0;
		trace_files[i].size = 0;
		close(trace_files[i].fd);
		return 0;
	} else {
		trace_files[i].header = (header_page_t *)addr;
		trace_files[i].mmap_addr = addr;
	}
			
	ncpus = i+1;	

	globals->kiversion = 0;
	if (addr) {
		header = (header_page_t *)addr;
		globals->kiversion = header->version;
	}

	if (IS_LIKI) { 
		ki_actions = liki_action();
	} else if (IS_WINKI) {
		ki_actions = winki_action();
	} else {
		/* we shouldn't get here */
        	sprintf(fname, "ids.%s", timestamp);
        	if ((id_fd = open(fname, O_RDONLY)) < 0) {
			FATAL(errno, "Unable to ids.<timestamp> file.   Check timestamp used and permissions", fname, -1);
        	}

        	id_addr = mmap(NULL, sizeof(ki_action_t)*KI_MAXTRACECALLS, PROT_READ, MAP_PRIVATE, id_fd, 0);
        	if (id_addr == MAP_FAILED) {
                	FATAL(errno, "Cannot mmap file", fname, -1);
        	}

		anon_addr = mmap(NULL, sizeof(ki_action_t)*KI_MAXTRACECALLS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        	if (anon_addr == MAP_FAILED) {
                	FATAL(errno, "Cannot create anon ids mmap file", NULL, -1);
        	}

		munmap (id_addr,  sizeof(ki_action_t)*KI_MAXTRACECALLS);
		close (id_fd);

		memcpy(anon_addr, id_addr, sizeof(ki_action_t)*KI_MAXTRACECALLS);
		ki_actions = (ki_action_t *)anon_addr;

	}

	trace_files[i].save_fd = trace_files[i].fd;
	return ncpus;
}

int
reset_trace_files(int nfiles) 
{
	int i;
	trace_info_t *trcinfop;

	for (i = 0; i < MAXCPUS; i++) {
		trcinfop = &trace_files[i];
		trcinfop->fd = trcinfop->save_fd;
		trcinfop->header = (header_page_t *)trcinfop->mmap_addr;
		trcinfop->next_event = NULL;
		trcinfop->cur_event = NULL;
		trcinfop->cur_rec = NULL;
		trcinfop->cur_time = trcinfop->next_time = trcinfop->cur_seqno = 0ull;
		trcinfop->cpu = trcinfop->pid = trcinfop->check_flag = 0;
	}
}

int
close_trace_files(int nfiles) 
{
	int i;
	trace_info_t *trcinfop;

	for (i = 0; i < MAXCPUS; i++) {
		trcinfop = &trace_files[i];
		if (trcinfop->fd) close(trcinfop->fd);
		if (trcinfop->mmap_addr) munmap (trcinfop->mmap_addr, 0);
		trcinfop->mmap_addr = NULL;
		trcinfop->header = NULL;
		trcinfop->next_event = NULL;
		trcinfop->cur_event = NULL;
		trcinfop->cur_rec = NULL;
		trcinfop->cur_time = trcinfop->next_time = trcinfop->size = trcinfop->cur_seqno = 0ull;
		trcinfop->cpu = trcinfop->fd = trcinfop->pid = trcinfop->check_flag = 0;
	}
}

char *
open_trace_file(char *fname, int cpu, int flags, mode_t mode)
{
	char *addr = NULL;
	struct stat statbuf;

	trace_files[cpu].cpu = cpu;
	if (debug) printf ("Opening trace file %s\n", fname);
	
	if ((trace_files[cpu].fd = open(fname, flags, mode)) < 0) {
		if (debug) { 
			printf ("open of file %s failed - errno %d\n", fname, errno); 
		}
		trace_files[cpu].fd = 0;
		return NULL;
	}

	if (fstat(trace_files[cpu].fd, &statbuf) != 0) {
		if (debug) perror ("fstat() failed");
		close(trace_files[cpu].fd);
		trace_files[cpu].fd = 0;
		return NULL;
	}

	if (statbuf.st_size == 0) {
		if (flags == O_RDONLY) {
			close(trace_files[cpu].fd);
			trace_files[cpu].fd = 0;
		}
		trace_files[cpu].size = 0;
		return NULL;
	}

	trace_files[cpu].size = statbuf.st_size;

	addr = mmap(NULL, trace_files[cpu].size, PROT_READ, MAP_PRIVATE, trace_files[cpu].fd, 0);
	if (addr == MAP_FAILED) {
		printf ("Cannot mmap file %s - Errno %d\n", fname, errno);
		close(trace_files[cpu].fd);
		trace_files[cpu].fd = 0;
		trace_files[cpu].size = 0;
		return addr;
	} else {
		trace_files[cpu].header = (header_page_t *)addr;
		trace_files[cpu].mmap_addr = addr;
	}
		
	trace_files[cpu].save_fd = trace_files[cpu].fd;
	
	return addr;
}



int
open_trace_files()
{

	int i, ncpus=0;
	char fname[256];
	struct stat statbuf;
	char *addr, *id_addr, *anon_addr, *first_addr = NULL;
	uint64 size;
	header_page_t *header;

	if (debug) printf ("open_trace_files %s\n", timestamp);
	if (timestamp==NULL) return 0;

	for (i = 0; i < MAXCPUS; i++) {
		sprintf(fname, "ki.bin.%03d.%s", i, timestamp);
		if ((addr = open_trace_file(fname, i, O_RDONLY, 0666)) == NULL) {
			/* unable to open or mmap file */
			continue;
		}

		if (first_addr == NULL) first_addr = addr;
		ncpus = i+1;	
        }

	globals->kiversion = 0;
	if (first_addr) {
		header = (header_page_t *)first_addr;
		if (debug) printf ("KI Binary Version %d\n", header->version);
		globals->kiversion = header->version;
	}

	if (IS_LIKI) { 
		ki_actions = liki_action();
	} else if (IS_WINKI) {
		ki_actions = winki_action();
	} else {
        	sprintf(fname, "ids.%s", timestamp);
        	if ((id_fd = open(fname, O_RDONLY)) < 0) {
			FATAL(errno, "Unable to open ids.<timestamp> file.   Check timestamp used and permissions", fname, -1);
        	}

	        if (fstat(id_fd, &statbuf) != 0) {
			if (debug) perror ("fstat() failed");
			size = 0;
		} else {
			size = MIN(sizeof(ki_action_t)*KI_MAXTRACECALLS, statbuf.st_size);
		}

        	id_addr = mmap(NULL, sizeof(ki_action_t)*KI_MAXTRACECALLS, PROT_READ, MAP_PRIVATE, id_fd, 0);
        	if (id_addr == MAP_FAILED) {
                	FATAL(errno, "Cannot mmap file", fname, -1);
        	}

		anon_addr = mmap(NULL, sizeof(ki_action_t)*KI_MAXTRACECALLS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        	if (anon_addr == MAP_FAILED) {
                	FATAL(errno, "Cannot create anon ids mmap file", NULL, -1);
        	}

		memcpy(anon_addr, id_addr, size);
		ki_actions = (ki_action_t *)anon_addr;

		munmap (id_addr,  size);
		close (id_fd);
	}

	printf ("NCPUS=%d\n", ncpus);
	return ncpus;
}

/* perform initial read on each per-cpu file to 
 * populate the trace_files[] array 
 */
void
init_trace_files(int ncpus)
{
	int i, retry;
	trace_info_t *trcinfop;
	uint64	hdrtime;

	if (debug) printf ("init_trace_files() ncpus=%d\n", ncpus);
	for (i = 0; i < ncpus; i++) {
		/* printf ("CPU[%d] fd: %d\n", i, trace_files[i].fd); */
	    	if (trace_files[i].fd == 0) continue;

		/* perform initial read on each per-cpu file */
	
		trcinfop = &trace_files[i];
                trcinfop->header = (header_page_t *)trcinfop->mmap_addr;
		retry=1;
        	while (retry) {
                	retry=0;
                	if ((char *)trcinfop->header >= (trcinfop->mmap_addr + trcinfop->size)) {
                        	/* end of file */
                        	close(trcinfop->fd);
                        	trcinfop->fd = 0;
                        	trcinfop->header = 0;
                        	trcinfop->next_time = 0;
                	} else if (trcinfop->header->commit) {
                        	trcinfop->next_event = (char *)trcinfop->header + HEADER_SIZE(trcinfop->header);
				trcinfop->next_time = get_event_time(trcinfop, 0);
				trcinfop->buffers++;

				if (debug) printf ("  CPU[%d] start time: 0x%llx %9.9f  len: %d vers: %d  hdr: 0x%llx next_event: 0x%llx next_time: 0x%llx\n", i,
                                	trcinfop->header->time,
                                	SECS(trcinfop->header->time),
                                	trcinfop->header->commit,
					trcinfop->header->version,
                                	trcinfop->header,
					trcinfop->next_event,
					trcinfop->next_time);

				if (IS_WINKI) {
					etw_header_page_t *etw_headerp = (etw_header_page_t *)trcinfop->header;
					if ((i==0) && (etw_headerp->time == 0ull)) {
						winki_bufsz = etw_headerp->bufsz;
					}
				}
					
                	} else {
			 	/* if there is no commit value, then skip to the next chunk */
                		trcinfop->header = (header_page_t *)((char *)trcinfop->header + trcinfop->header->commit + HEADER_SIZE(trcinfop->header));
                        	retry=1;
			}
		}
	}
}
