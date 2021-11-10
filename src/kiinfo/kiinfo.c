/***************************************************************************
 * Copyright 2017 Hewlett Packard Enterprise Development LP.  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details. You
 * should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * ***************************************************************************/

#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include "ki_tool.h"
#include "option_iface.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"
#include "hash.h"
#include "vers.h"
#include "html.h"

extern void (*init_func)(void *);
extern void firstpass_init_func(void *);
extern int open_trace_files();
extern int close_trace_files(int);
extern int init_trace_files(int);
extern int open_merged_file();
extern int init_debug_mountpoint(char *);

int debug=0;            /* debug code is off by default */
int is_alive=0;         /* live analyze can be done with liki kernel module only */
int VM_guest=0;         /* for live analysis, is this system a VM Guest */

char arch_flag = X86_64;
struct tm gmt;
char *cmdstr;
char *timestamp;
int do_detail_help;
int alarm_secs=5;               
char HTML	= 0;
int passes=1;
int done=FALSE;
init_t Init;
char startup_found = 0;
double realsecs = 0;
uint64 realtime = 0;
uint64 start_time = 0;				/* absolute times of first event */
uint64 winki_start_time = 0;			/* absolute times of first traced event */
uint64 end_time= 0;
uint64 prev_vint_time = 0;
uint64 vis_hostid = 0;
uint64 interval_start = 0;			/* VIS csv interval reporting */
uint64 interval_end = 0;			/* VIS csv interval reporting */
struct timespec begin_time;			
int64 start_filter = 0;			/* relative times */
int64 start_filter_save;
int64 end_filter= 0xfffffffffffffffull;
int64 end_filter_save;
int64 kistep = 0ull;
uint32 winki_bufsz = 0;
char	liki_module_loaded = 0;
char	liki_initialized = 0;
char *cwd = NULL;
int nfiles = 0;
struct utsname utsname;
char *kgdboc_str = NULL;
char *tlabel;		/* Thread label for reporting Threads ID */
char *plabel;		/* Process/Task Group label for reporting Process ID */
EventTraceHdr_t *winki_hdr = NULL;

trace_info_t  trace_files[MAXCPUS];
trace_info_t  trace_file_merged;
char ts_begin_marker[64];
char ts_end_marker[64];

FILE *dockfile = NULL;
FILE *kipid_file = NULL;
FILE *node_csvfile = NULL;
FILE *pid_csvfile = NULL;
FILE *dsk_csvfile = NULL;
FILE *futex_csvfile = NULL;
FILE *file_csvfile = NULL;
FILE *socket_csvfile = NULL;
FILE *runq_csvfile = NULL;
FILE *wait_csvfile = NULL;
FILE *cluster_csvfile = NULL;
FILE *cluster_network_csvfile = NULL;
FILE *server_vis_csvfile = NULL;
FILE *cluster_vis_csvfile = NULL;

#include "custom_options.h"


static void catch_int(int sig)
{
	fprintf (stderr, "kiinfo caught Signal %d\n", sig);
}

int
main(int argc, char *argv[])
{
	char	command[4096];
	int i, n, ret;
	char line[256];
	char kp[30];
	FILE *trcfile = NULL;	

	Init.i_argc = argc;
	Init.i_argv = argv;
	Init.i_options = otab;
	cmdstr = argv[0];

	/* output toolname and arguments */
	sprintf (command, "Command line: %s ", argv[0]);
	for (i=1; i<argc; i++) {
		n = strlen(command);
		sprintf(&command[n], "%s ", argv[i]);
	}

	option_decode(&Init);  
	if (timestamp == NULL) is_alive = TRUE;

	if (kiall_flag) {
		if (timestamp == NULL) {
			option_usage(&Init, "Timestamp (-ts <timestamp>) required to for kiall tool", "kiall");
			_exit(1);
		} else if (HTML) {
			sprintf(kp, "kp.%s.html", timestamp);
		} else {
			sprintf(kp, "kp.%s.txt", timestamp);
		}
        	if (freopen(kp, "w", stdout) == NULL) {
			fprintf (stderr, "Unable to reopen stdout as %s (errno %d)\n", kp, errno);
			_exit(1);
		}
	}

	if (!kilive) {
		DOC_START(tool_name);
	}

	sprintf (line, "%s %s ", tool_name, timestamp); TITLE(line);
	if (!kilive) {
		STYLE;
		printf("%s\n\n", command);
		BR;
	}

	sprintf (line, "%s (%s)\n", tool_name, tool_version); H1(line); 
	TEXTx("\n");
	HR; BR;
	PRE;

	if (likidump_flag) {
		if (geteuid() != 0) { 
			fprintf (stderr, "You must run kinfo as root to collect a trace dump\n");
			_exit(-1);
		}

		if (uname(&utsname) == 0) {
			if (strstr(utsname.machine, "aarch64")) arch_flag = AARCH64;
			else if (strstr(utsname.machine, "ppc64le")) arch_flag = PPC64LE;
		}
		clear_kgdboc();
		syscall_arg_list = linux_syscall_arg_list;

		likidump();
		if (kgdboc_str) reset_kgdboc();
		_exit(0);
	} else if (kitracedump_flag) {
		if (geteuid() != 0) { 
			fprintf (stderr, "You must run kinfo as root to collect a trace dump\n");
			_exit(-1);
		}
		kitracedump();
		_exit(0);
	} else if (objdump_flag) {
		objdump();
		_exit(0);
	} else if (etldump_flag) {
		etldump();
		_exit(0);
	}

	if (likimerge_flag) {
		if (timestamp == NULL) {
			option_usage(&Init, "Timestamp (-ts <timestamp>) required to merge KI binary files", "likimerge");
			_exit(1);
		}
		globals = GET_SERVER(server[0]);
		globals->server_id = nservers;
		nfiles = open_trace_files();
        	if (nfiles == 0) {
			FATAL(1008, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
        	}

		init_trace_files(nfiles);		
		close_trace_files(nfiles);		
		merge();
	}

	if (kitracedump_flag || likimerge_flag) {
		_exit(0);
	}

	if (tool_init_func == NULL) _exit(0);

	if (is_alive) CLEAR(COOP_DETAIL_ENABLED);
	if (is_alive && kparse_flag) {
		fprintf(stderr, "Live tracing not allowed with kiinfo -kparse\n");
		_exit(1);
	}

	if (csv_flag) fsep = ',';               /* change field separator for CSV output */ 
	if (is_alive) {
		if (geteuid() != 0) { 
			fprintf (stderr, "You must run kinfo as root to perform online tracing\n");
			_exit(-1);
		}
		/* clear kgdboc file to avoid failure due to jprobe */
		clear_kgdboc();
		/* Disable time filters for live KI */
		start_filter = 0;
		end_filter = 0xfffffffffffffffull;


		if (uname(&utsname) == 0) {
			if (strstr(utsname.machine, "aarch64")) arch_flag = AARCH64;
			else if (strstr(utsname.machine, "ppc64le")) arch_flag = PPC64LE;
		}

		globals = GET_SERVER(server[0]);
		globals->server_id = nservers;
		globals->VM_guest = VM_guest;
		parse_uname(0);
		nservers++;

		syscall_arg_list = linux_syscall_arg_list;

		if (arch_flag == AARCH64) {
			globals->syscall_index_32 = syscall_index_aarch_64;
			globals->syscall_index_64 = syscall_index_aarch_64;
		} else if (arch_flag == PPC64LE) {
			globals->syscall_index_32 = syscall_index_ppc64le;
			globals->syscall_index_64 = syscall_index_ppc64le;
		} else if (IS_WINKI) {
			globals->syscall_index_32 = syscall_index_win;
			globals->syscall_index_64 = syscall_index_win;
		} else {
			globals->syscall_index_32 = syscall_index_x86_32;
			globals->syscall_index_64 = syscall_index_x86_64;
		}

		ki_actions = liki_action();
		start_time = 0;
		end_time= 0;
		globals->kiversion = TRACE_VERSION;		/* initialize this to 1 for now until we actually read data */
		init_trace_ids();
		load_liki_module();

		/* open debugfs directory needef or LiKI */
		init_debug_mountpoint(debug_dir);

		tlabel="PID";
		plabel="TGID";

		init_func(NULL);
		developers_init();		/* calls liki_init_tracing */ 

		set_ioflags(); 	/* needs to be called after setting IS_LIKI */
		set_gfpflags();
	 
		read_liki_traces();		/* call instead of developers_call() */
		liki_close_live_stream();
		unload_liki_module();

		if (kgdboc_str) reset_kgdboc();

		if (!kilive) {
			save_and_clear_server_stats(nfiles);
			printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
        		print_cpu_buf_info();
		} else {
			live_cleanup_func(NULL);
		}
	} else if (timestamp && kilive) {
		cwd = get_current_dir_name();
		for_each_file(".", "ki.bin.", timestamp, cluster_flag);
		if (nservers == 0) {
			FATAL(1009, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
		}

		sprintf (ts_begin_marker, "kitrace_marker_BEGIN_%s", timestamp);
		sprintf (ts_end_marker, "kitrace_marker_END_%s", timestamp);
		
		globals = server[0];
		start_time = 0;
		end_time= 0;

		nfiles = open_merged_file();
        	if (nfiles == 0) {
			nfiles = open_trace_files();
		}

		if (nfiles == 0) FATAL(1010, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);

		if (IS_WINKI) {
			tlabel="TID";
			plabel="PID";
		} else {
			tlabel="PID";
			plabel="TGID";
		}

		init_trace_files(nfiles); 
		if (!IS_LIKI) kistep = 0;
		if (IS_FTRACE) read_fmt_files(); 
		if (!IS_WINKI) init_trace_ids(); /* skip this for now */

		parse_uname(1);
		set_ioflags();
		set_gfpflags();
		printf ("KI Binary Version %d\n", globals->kiversion);

		if (IS_WINKI) {
			syscall_arg_list = win_syscall_arg_list;
		} else {
			syscall_arg_list = linux_syscall_arg_list;
                }

		if (arch_flag == AARCH64) {
			globals->syscall_index_32 = syscall_index_aarch_64;
			globals->syscall_index_64 = syscall_index_aarch_64;
		} else if (arch_flag == PPC64LE) {
			globals->syscall_index_32 = syscall_index_ppc64le;
			globals->syscall_index_64 = syscall_index_ppc64le;
		} else if (IS_WINKI) {
			globals->syscall_index_32 = syscall_index_win;
			globals->syscall_index_64 = syscall_index_win;
		} else {
			globals->syscall_index_32 = syscall_index_x86_32;
			globals->syscall_index_64 = syscall_index_x86_64;
		}

		if (IS_WINKI) {
			int reset_kitrace_flag = 0;
			
			firstpass_init_func(NULL);
			developers_call(nfiles);
			close_trace_files(nfiles);

			nfiles = open_trace_files();
			if (nfiles == 0)  FATAL(1010, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
			init_trace_files(nfiles);

			start_time = 0;
		} else {
			end_filter_save = end_filter;
			start_filter_save = start_filter;
			if (kistep) end_filter = start_filter + kistep;
		}

		if (IS_WINKI) {
			tlabel="TID";
			plabel="PID";
		} else {
			tlabel="PID";
			plabel="TGID";
		}

		init_func(NULL);

		while (!done) {
			developers_call(nfiles);
			developers_report();
			clear_all_stats();
			reset_trace_files(nfiles);		
			start_time = 0;
			end_time= 0;
			init_trace_files(nfiles); 
			globals->missed_events = globals->total_events = 0;
                        parse_pself();
                        parse_proc_cgroup();
		}

		close_trace_files(nfiles);		
		live_cleanup_func(NULL);
		
	} else if (timestamp) {
		/* Ignoring system calls is applied during data collection only */
		if (sysignore) { 
			fprintf (stderr, "Warning: sysignore file is only applied at the time the trace is collected.  Ignoring sysignore option.\n");
		}

		cwd = get_current_dir_name();
		for_each_file(".", "ki.bin.", timestamp, cluster_flag);

		if (nservers == 0) {
			FATAL(1009, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
		}

		sprintf (ts_begin_marker, "kitrace_marker_BEGIN_%s", timestamp);
		sprintf (ts_end_marker, "kitrace_marker_END_%s", timestamp);
		if (cluster_flag)  
			fprintf (stderr, "Number of Servers to analyze: %d\n", nservers);

		for (i=0; i < nservers; i++) {
			globals = server[i];
			start_time = 0;
			end_time= 0;
			ret = chdir(globals->subdir);
			if (cluster_flag) fprintf (stderr, "Processing KI files in %s\n", globals->subdir);
			nfiles = open_merged_file();
       			if (nfiles == 0) {
				nfiles = open_trace_files();
			}

			if (nfiles == 0)  FATAL(1010, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
			init_trace_files(nfiles); 


			if (IS_FTRACE) read_fmt_files(); 
			if (!IS_WINKI) init_trace_ids();  /* skip for now */

			parse_uname(1);
			set_ioflags();
			set_gfpflags();
			printf ("KI Binary Version %d\n", globals->kiversion);

			if (IS_WINKI) {
				syscall_arg_list = win_syscall_arg_list;
			} else {
				syscall_arg_list = linux_syscall_arg_list;
               		}
			if (arch_flag == AARCH64) {
				globals->syscall_index_32 = syscall_index_aarch_64;
				globals->syscall_index_64 = syscall_index_aarch_64;
			} else if (arch_flag == PPC64LE) {
				globals->syscall_index_32 = syscall_index_ppc64le;
				globals->syscall_index_64 = syscall_index_ppc64le;
			} else if (IS_WINKI) {
				globals->syscall_index_32 = syscall_index_win;
				globals->syscall_index_64 = syscall_index_win;;
			} else {
				globals->syscall_index_32 = syscall_index_x86_32;
				globals->syscall_index_64 = syscall_index_x86_64;
			}

			if (IS_WINKI) {
				int reset_kitrace_flag = 0;
			
				if (kitrace_flag) {
					CLEAR(KITRACE_FLAG);
					reset_kitrace_flag=1;
				}
				firstpass_init_func(NULL);
				developers_call(nfiles);
				close_trace_files(nfiles);

				nfiles = open_trace_files();
				if (nfiles == 0)  FATAL(1010, "Cannot open file of the form ki.bin*.<timestamp>", timestamp, -1);
				init_trace_files(nfiles);
				if (reset_kitrace_flag) {
					SET(KITRACE_FLAG);
				}
			}

			start_time = 0;

			if (IS_WINKI) {
				tlabel="TID";
				plabel="PID";
			} else {
				tlabel="PID";
				plabel="TGID";
			}

			init_func(NULL);

			developers_init();
			developers_call(nfiles);
			close_trace_files(nfiles);		
			save_and_clear_server_stats(nfiles);
			ret = chdir(cwd);
		}

		developers_report();

		if ((!cluster_flag) && (!kiall_flag) && (!kilive)) {
			printf ("\nTotal time captured (secs): %3.2f\n", globals->total_secs);
        		print_cpu_buf_info();
		}

		if (kilive) {
			live_cleanup_func(NULL);
		}
	}

	exit(0);
}
