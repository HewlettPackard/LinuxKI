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
#include <strings.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <linux/kdev_t.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "kd_types.h"
#include "hash.h"
#include "info.h"
#include "syscalls.h"
#include "sched.h"
#include "cache.h"
#include "sort.h"
#include "html.h"
#include "msgcat.h"
#include "conv.h"

#include "FileIo.h"
#include "DiskIo.h"
#include "SysConfig.h"
#include "Process.h"
#include "Image.h"
#include "winki_util.h"

int file_ftrace_print_func(void *, void *);
/*
 ** The initialisation function
 */

static inline void
file_win_trace_funcs()
{
	int i;
	
	for (i = 0; i < 65536; i++) {
		ki_actions[i].id = i;
		ki_actions[i].func = NULL;
		ki_actions[i].execute = 0;
	}

        strcpy(&ki_actions[0].subsys[0], "EventTrace");
        strcpy(&ki_actions[0].event[0], "Header");
        ki_actions[0].func = winki_header_func;
        ki_actions[0].execute = 1;

        strcpy(&ki_actions[0x400].subsys[0], "FileIo");
        strcpy(&ki_actions[0x400].event[0], "FileName");
        ki_actions[0x400].func=print_fileio_name_func; 
        strcpy(&ki_actions[0x420].subsys[0], "FileIo");
        strcpy(&ki_actions[0x420].event[0], "FileCreate");
        ki_actions[0x420].func=print_fileio_name_func;

        strcpy(&ki_actions[0x423].subsys[0], "FileIo");
        strcpy(&ki_actions[0x423].event[0], "FileDelete");
        ki_actions[0x423].func=print_fileio_name_func;

        strcpy(&ki_actions[0x424].subsys[0], "FileIo");
        strcpy(&ki_actions[0x424].event[0], "FileRundown");
        ki_actions[0x424].func=print_fileio_name_func;

        strcpy(&ki_actions[0x440].subsys[0], "FileIo");
        strcpy(&ki_actions[0x440].event[0], "Create");
        ki_actions[0x440].func=print_fileio_create_func;

        strcpy(&ki_actions[0x441].subsys[0], "FileIo");
        strcpy(&ki_actions[0x441].event[0], "Cleanup");
        ki_actions[0x441].func=print_fileio_simpleop_func;

        strcpy(&ki_actions[0x442].subsys[0], "FileIo");
        strcpy(&ki_actions[0x442].event[0], "Close");
        ki_actions[0x442].func=print_fileio_simpleop_func;

        strcpy(&ki_actions[0x443].subsys[0], "FileIo");
        strcpy(&ki_actions[0x443].event[0], "Read");
        ki_actions[0x443].func=print_fileio_readwrite_func;

        strcpy(&ki_actions[0x444].subsys[0], "FileIo");
        strcpy(&ki_actions[0x444].event[0], "Write");
        ki_actions[0x444].func=print_fileio_readwrite_func;

        strcpy(&ki_actions[0x445].subsys[0], "FileIo");
        strcpy(&ki_actions[0x445].event[0], "SetInfo");
        ki_actions[0x445].func=print_fileio_info_func;

        strcpy(&ki_actions[0x446].subsys[0], "FileIo");
        strcpy(&ki_actions[0x446].event[0], "Delete");
        ki_actions[0x446].func=print_fileio_info_func;

        strcpy(&ki_actions[0x447].subsys[0], "FileIo");
        strcpy(&ki_actions[0x447].event[0], "Rename");
        ki_actions[0x447].func=print_fileio_info_func;

        strcpy(&ki_actions[0x448].subsys[0], "FileIo");
        strcpy(&ki_actions[0x448].event[0], "DirEnum");
        ki_actions[0x448].func=print_fileio_direnum_func;

        strcpy(&ki_actions[0x449].subsys[0], "FileIo");
        strcpy(&ki_actions[0x449].event[0], "Flush");
        ki_actions[0x449].func=print_fileio_simpleop_func;

        strcpy(&ki_actions[0x44a].subsys[0], "FileIo");
        strcpy(&ki_actions[0x44a].event[0], "QueryInfo");
        ki_actions[0x44a].func=print_fileio_info_func;

        strcpy(&ki_actions[0x44b].subsys[0], "FileIo");
        strcpy(&ki_actions[0x44b].event[0], "FSControl");
        ki_actions[0x44b].func=print_fileio_info_func;

        strcpy(&ki_actions[0x44c].subsys[0], "FileIo");
        strcpy(&ki_actions[0x44c].event[0], "OperationEnd");
        ki_actions[0x44c].func=print_fileio_opend_func;

        strcpy(&ki_actions[0x44d].subsys[0], "FileIo");
        strcpy(&ki_actions[0x44d].event[0], "DirNotify");
        ki_actions[0x44d].func=print_fileio_direnum_func;

        strcpy(&ki_actions[0x44f].subsys[0], "FileIo");
        strcpy(&ki_actions[0x44f].event[0], "DeletePath");
        ki_actions[0x44f].func=print_fileio_name_func;

        strcpy(&ki_actions[0x450].subsys[0], "FileIo");
        strcpy(&ki_actions[0x450].event[0], "RenamePath");
        ki_actions[0x450].func=print_fileio_name_func;

        strcpy(&ki_actions[0xb0f].subsys[0], "SysConfig");
        strcpy(&ki_actions[0xb0f].event[0], "Services");
        ki_actions[0xb0f].func=sysconfig_services_func;
        ki_actions[0xb0f].execute = 1;

        strcpy(&ki_actions[0x30a].subsys[0], "Process");
        strcpy(&ki_actions[0x30a].event[0], "Load");
        ki_actions[0x30a].func=process_load_func;
        ki_actions[0x30a].execute = 1;

        strcpy(&ki_actions[0x1403].subsys[0], "Image");
        strcpy(&ki_actions[0x1403].event[0], "DCStart");
        ki_actions[0x1403].func=image_dcstart_func;
        ki_actions[0x1403].execute = 1;

        strcpy(&ki_actions[0x1404].subsys[0], "Image");
        strcpy(&ki_actions[0x1404].event[0], "DCEnd");
        ki_actions[0x1404].func=image_dcstart_func;
        ki_actions[0x1404].execute = 1;
}


void
file_init_func(void *v)
{
	if (debug) printf ("file_init_func()\n");
        process_func = NULL;
        print_func = file_print_func;
        report_func = file_report_func;
	filter_func = info_filter_func;   /* no filter func for kifile, use generic */
        bufmiss_func = pid_bufmiss_func;

	if (IS_WINKI) {
		file_win_trace_funcs();
	} else {
	        /* go ahead and initialize the trace functions, but do not set the execute field */
		ki_actions[TRACE_SYS_EXIT].func = sys_exit_func;
		ki_actions[TRACE_SYS_ENTER].func = sys_enter_func;
		ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_func;
		ki_actions[TRACE_SCHED_WAKEUP_NEW].func = sched_wakeup_func;
		ki_actions[TRACE_SCHED_WAKEUP].func = sched_wakeup_func;
		ki_actions[TRACE_CACHE_INSERT].func = cache_insert_func;
		ki_actions[TRACE_CACHE_EVICT].func = cache_evict_func;
		if (IS_LIKI_V4_PLUS)
			ki_actions[TRACE_WALLTIME].func = trace_startup_func;
		else
			ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

		if (is_alive) {
			if (set_events_options(filter_func_arg) == 0) {
				/* if no filters, set up default tracing */
				ki_actions[TRACE_SYS_EXIT].execute = 1;
				ki_actions[TRACE_SYS_ENTER].execute = 1;
				ki_actions[TRACE_WALLTIME].execute = 1;
				if (scdetail_flag) {
					ki_actions[TRACE_SCHED_SWITCH].execute = 1;
					ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
					ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
				}
			}
		} else if (IS_LIKI) {
			ki_actions[TRACE_SYS_EXIT].execute = 1;
			ki_actions[TRACE_SYS_ENTER].execute = 1;
			ki_actions[TRACE_WALLTIME].execute = 1;
			if (scdetail_flag) {
				ki_actions[TRACE_SCHED_SWITCH].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
				ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
			}
			ki_actions[TRACE_CACHE_INSERT].execute = 1;
			ki_actions[TRACE_CACHE_EVICT].execute = 1;
		} else {
			set_events_all(0);
	       	 	ki_actions[TRACE_PRINT].func = file_ftrace_print_func;
			ki_actions[TRACE_PRINT].execute = 1;
		}

	        parse_kallsyms();
		if (timestamp) {
			parse_lsof();
			parse_pself();
			parse_edus();
			parse_jstack();
		}
	}
	if (timestamp) {
			file_csvfile = open_csv_file("kifile", 1);
	}
}

int
file_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int file_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("file_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_SYS_EXIT].execute = 1;
                ki_actions[TRACE_SYS_ENTER].execute = 1;
		if (scdetail_flag) {
                	ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 1;
                	ki_actions[TRACE_SCHED_WAKEUP].execute = 1;
		}
		ki_actions[TRACE_CACHE_INSERT].execute = 1;
		ki_actions[TRACE_CACHE_EVICT].execute = 1;
                start_time = KD_CUR_TIME;
        }
        if (strstr(buf, ts_end_marker)) {
                ki_actions[TRACE_SYS_EXIT].execute = 0;
                ki_actions[TRACE_SYS_ENTER].execute = 0;
                ki_actions[TRACE_SCHED_SWITCH].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP_NEW].execute = 0;
                ki_actions[TRACE_SCHED_WAKEUP].execute = 0;
		ki_actions[TRACE_CACHE_INSERT].execute = 0;
		ki_actions[TRACE_CACHE_EVICT].execute = 0;
                ki_actions[TRACE_PRINT].execute = 0;
                end_time = KD_CUR_TIME;
                bufmiss_func =  NULL;
        }

        if (debug)  {
                PRINT_KD_REC(rec_ptr);
                PRINT_EVENT(rec_ptr->KD_ID);
                printf (" %s\n", buf);
        }
}

int file_print_pgcache(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = (fdata_info_t *)arg1;
	if ((fdatap->cache_evict_cnt + fdatap->cache_insert_cnt) == 0) return 0;

	printf ("%8d %8d  0x%08llx %10u %8s  %s\n", 
			fdatap->cache_insert_cnt, 
			fdatap->cache_evict_cnt,
			fdatap->dev & 0xffffffff,
			fdatap->node,
                        ftype_name_index[fdatap->ftype],
        		fdatap->fnameptr ? fdatap->fnameptr : "???");
}

int file_print_fdata(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = (fdata_info_t *)arg1;
        uint64 *scallflagp = (uint64 *)arg2;
        char    typebuf[40];
	var_arg_t vararg;

        if (fdatap->stats.syscall_cnt == 0) return 0;

        SPAN_GREY;

	if (scallflagp && *scallflagp) {
                printf ("\ndevice: 0x%08llx node: %7u fstype: %8s  filename:",
			fdatap->dev,
			fdatap->node,
                        ftype_name_index[fdatap->ftype]);
        } else {
                printf ("%8d %10.4f %7d %7d %7d %7d 0x%016llx %10u %8s",
                        fdatap->stats.syscall_cnt,
                        SECS(fdatap->stats.total_time),
                        fdatap->stats.lseek_cnt,
                        fdatap->stats.rd_cnt,
                        fdatap->stats.wr_cnt,
                        fdatap->stats.errors,
			fdatap->dev,
			fdatap->node,
                        ftype_name_index[fdatap->ftype]);
        }

        printf ("  %s", fdatap->fnameptr ? fdatap->fnameptr : "???");
	if (cluster_flag) {
		printf ("  [");
		SERVER_URL_FIELD_SECTION(globals, _LNK_3_0);
		printf ("]");
	}
	
	printf ("\n");	
        if ((lineno & 0x1) == 0) _SPAN;
        lineno++;

        if (scallflagp && *scallflagp) {
                printf("%sSystem Call Name                 Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s\n", tab);
			vararg.arg1 = NULL;
			vararg.arg2 = NULL;
                        foreach_hash_entry((void **)fdatap->syscallp, SYSCALL_HASHSZ,
                                        (int (*)(void *, void *))print_syscall_info,
                                        (int (*)()) syscall_sort_by_time,
                                        0, &vararg);
        }

        return 0;
}

int 
clear_fdata_stats(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = (fdata_info_t *)arg1;

        if (fdatap->stats.syscall_cnt == 0) return 0;
	bzero(&fdatap->stats, sizeof(fd_stats_t));

        foreach_hash_entry(fdatap->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&fdatap->syscallp, SYSCALL_HASHSZ);
}

int 
file_print_fdata_errs(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = (fdata_info_t *)arg1;

        if (fdatap->stats.errors == 0) return 0;

        file_print_fdata((void *)fdatap, arg2);

        return 0;
}

int
print_file_csv(void *arg1, void *arg2)
{
	syscall_info_t *syscallp = (syscall_info_t *)arg1;
	syscall_stats_t *sysstatp = &syscallp->stats;
	struct arg_info *workarg = (struct arg_info *)arg2;
	pid_info_t *pidp = (pid_info_t *)workarg->arg0;
	pid_info_t *tgidp;
	fd_info_t *fdinfop = (fd_info_t *)workarg->arg1;
	fd_info_t *tfdinfop;
	fdata_info_t *fdatap;
	char *fnameptr, *cmdstr;
	uint64 key, fdtype, syscallno;

        if (sysstatp->count == 0) return 0;
	if ((fdinfop->lsock) && (fdinfop->rsock)) return 0;

	syscallno = SYSCALL_NO(syscallp->lle.key);

	if ((fdinfop->ftype == 0) && (pidp->tgid)) { 
		/* inherit filenames from primary thread */
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
		if (tfdinfop) fdinfop = tfdinfop;  /* set fdinfop to point to main tasks fdinfop */
	}

	fdatap = (fdata_info_t *)find_entry((lle_t **)globals->fdata_hash,
		FDATA_KEY(fdinfop->dev, fdinfop->node),
		FDATA_HASH(fdinfop->dev, fdinfop->node));

	if (fdatap && fdatap->fnameptr) {
		fnameptr = fdatap->fnameptr;
		fdtype = fdinfop->ftype;
	} else if (fdinfop->fnamep) {
		fnameptr = fdinfop->fnamep;
		fdtype = fdinfop->ftype;
	} else {
		fnameptr = "(unknown)";
		fdtype = 0;
	}

	csv_printf (file_csvfile,"%lld,%s,%s,%d,%s,%s,%s,%d,%d,%3.2f,%7.6f,%7.6f,%7.6f,%d",
		pidp->PID,
		pidp->cmd,
		pidp->thread_cmd,
		fdinfop->FD,
		fnameptr,
		ftype_name_index[fdtype],
		syscall_arg_list[pidp->syscall_index[syscallno]].name,
		syscallno,
		sysstatp->count,
		sysstatp->count / secs,
		SECS(sysstatp->total_time),
		SECS(sysstatp->total_time / sysstatp->count),
		SECS(sysstatp->max_time),
		sysstatp->errors);

        if (sysstatp->bytes)  {
                csv_printf (file_csvfile, ",%d,%2.1f",
                        (sysstatp->bytes) / sysstatp->count,
                        (sysstatp->bytes) / (secs * 1024.0));
        } else {
		csv_printf (file_csvfile, ",0,0.0");
	}

	csv_printf (file_csvfile, "\n");

	return 0;
}

int
file_fd_csv(void *arg1, void *arg2)
{
        fd_info_t *fdinfop = (fd_info_t *)arg1;
        pid_info_t *pidp = (pid_info_t *)arg2;
        struct arg_info  workarg;

        workarg.arg0 = (uint64)pidp;
        workarg.arg1 = (uint64)fdinfop;

        foreach_hash_entry((void **)fdinfop->syscallp, SYSCALL_HASHSZ,
                                (int (*)(void *, void *))print_file_csv,
                                NULL, 0,  &workarg);

}

int
file_pid_csv(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
        foreach_hash_entry((void **)pidp->fdhash, FD_HSIZE,
                                (int (*)(void *, void *))file_fd_csv,
                                NULL, 0, pidp);
}

void
file_print_csv()
{
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                                        (int (*)(void *, void *))file_pid_csv,
                                        NULL, 0, NULL);
}

int
file_print_report(void *v)
{
	uint64 scallflag=1;
	tab=tab0;

	printf ("\n%s******** GLOBAL FILE ACTIVITY REPORT ********\n", tab);

        printf ("\n%s---  Top Files sorted by System Call Count  ---\n", tab);
        printf("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata,
                           (int (*)())fdata_sort_by_syscalls,
                           nfile, NULL);

        printf ("\n%s---  Top Files sorted by System Call Count (Detailed)  ---\n", tab);
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata,
                           (int (*)())fdata_sort_by_syscalls,
                           nfile, &scallflag);

        printf ("\n%s---  Top Files sorted by Errors  ---\n", tab);
        printf("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata_errs,
                           (int (*)())fdata_sort_by_errs,
                           nfile, NULL);

        printf ("\n%s---  Top Files sorted by Elapsed Time  ---\n", tab);
        printf("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename\n", tab);
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata,
                            (int (*)())fdata_sort_by_elptime,
                            nfile, NULL);

	if (globals->cache_insert_cnt + globals->cache_evict_cnt) {
		printf ("\n%s--- Top Files sorted by Page Cache Activity ---\n", tab);
        	printf("%s Inserts   Evicts         dev       node     type  Filename\n", tab);
        	foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_pgcache,
                            (int (*)())fdata_sort_by_pgcache,
                            nfile, NULL);
	}

	if (file_csvfile) {
		csv_printf(file_csvfile, "PID,Command,ThreadName,FD,Filename,type,System Call,syscallno,Count,Rate,ElpTime,AvTime,MaxTime,errors,AvSz,KB/s\n");
		file_print_csv();
	}

	foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, clear_fdata_stats, NULL, 0, NULL);

	printf ("\n");
}

int
file_print_func(void *v)
{
        struct timeval tod;

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                file_print_report(v);
                print_flag=0;
        }
        return 0;
}

int
file_report_func(void *v)
{

        if (debug) printf ("Entering file_report_func %d\n", is_alive);
        if (passes != 0) {
                file_print_report(v);
        }

        return 0;
}
