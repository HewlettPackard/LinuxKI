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
#include "info.h"
#include "hardclock.h"
#include "sched.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include "hash.h"
#include "msgcat.h"
#include "kprint.h"
#include <ncurses.h>
#include <curses.h>

#include "winki.h"
#include "Image.h"
#include "Pdb.h"
#include "PerfInfo.h"
#include "Process.h"
#include "Thread.h"
#include "winki_util.h"

extern int pc_hugetlb_fault;
extern int pc_huge_pmd_share;
extern int pc_queued_spin_lock_slowpath;
extern int pc_SYSC_semtimedop;
extern int pc_semtimedop;
extern int pc_semctl;
extern int pc_rwsem_down_write_failed;
extern int pc_kstat_irqs_usr;
extern int pc_pcc_cpufreq_target;
extern int pc_kvm_mmu_page_fault;
extern int pc_do_numa_page;
extern int pc_migrate_pages;
extern int pc_pagevec_lru_move_fn;
extern int pc_release_pages;
extern int pc_alloc_pages_nodemask;

int prof_dummy_func(void *, void *);
int prof_ftrace_print_func(void *, void *);

static inline void
prof_winki_trace_funcs()
{
	winki_init_actions(NULL);
	winki_enable_event(0x30a, process_load_func);
	winki_enable_event(0x529, thread_spinlock_func);
	winki_enable_event(0x548, thread_setname_func);
	winki_enable_event(0xf2e, perfinfo_profile_func);
}


/*
 ** The initialisation function
 */
void
prof_init_func(void *v)
{
        int i;

	if (debug) printf ("prof_init_func()\n");

	if (!IS_LIKI && !IS_WINKI) { 
		printf ("No Hardclock Entries Captured\n\n");
		_exit(0);
	}

        process_func = NULL;
        print_func = prof_print_func;
        report_func = prof_report_func;
        /* bufmiss_func = prof_bufmiss_func; */
        bufmiss_func =  NULL;
	filter_func = trace_filter_func;
	report_func_arg = filter_func_arg;

	if (IS_WINKI) {
		parse_SQLThreadList();
		prof_winki_trace_funcs();
		return;
	}

        /* go ahead and initialize the trace functions, but do not set the execute field */
        ki_actions[TRACE_HARDCLOCK].func = hardclock_func;
        ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_thread_names_func;
        if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (IS_LIKI || is_alive) {
		ki_actions[TRACE_HARDCLOCK].execute = 1;
		ki_actions[TRACE_WALLTIME].execute = 1;
		if (!is_alive) ki_actions[TRACE_SCHED_SWITCH].execute = 1;
	} else {
		set_events_all(0);
        	ki_actions[TRACE_PRINT].func = prof_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

	parse_cpuinfo();
	parse_mpsched();
	parse_kallsyms();
	if (is_alive) load_objfile_and_shlibs();

	if (timestamp) {
		parse_maps();
		parse_pself();
		parse_edus();
		parse_jstack();
		if (objfile) load_elf(objfile, &objfile_preg);
		if (IS_LIKI) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);

	}
}

int
prof_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int
prof_bufmiss_func(void *v, void *a)
{
        trace_info_t *trcinfop = v;
	char tt_rec_ptr[MAX_REC_LEN];
        sched_switch_t *rec_ptr;
        int old_pid, next_pid;

	/* we cannot detect missed buffers with just HARDCLOCK traces */
}

void *
prof_filter_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	common_t tt_rec_ptr;
	common_t *rec_ptr;
	filter_t *f = v;
	filter_item_t *fi;
	void *ret1;

	rec_ptr = conv_common_rec(a, &tt_rec_ptr);

	if (!ki_actions[rec_ptr->id].execute) {
		return NULL;
	}

        if (rec_ptr->id == TRACE_PRINT) return rec_ptr;
	CHECK_TIME_FILTER(rec_ptr->hrtime);

        if ((rec_ptr->id >= TRACE_SCHED_SWITCH) && (rec_ptr->id <= TRACE_SCHED_WAKEUP)) return rec_ptr;
        if ((rec_ptr->id >= TRACE_BLOCK_RQ_COMPLETE) && (rec_ptr ->id <= TRACE_BLOCK_RQ_ABORT)) return rec_ptr;

	ret1 = rec_ptr;

	if (fi = f->f_P_pid) {
		ret1 = NULL;
		while (fi) {
			if (rec_ptr->pid == fi->fi_item) {
				return rec_ptr;
			}
			fi = fi->fi_next;
		}
	}

	if (fi = f->f_P_cpu) {
		ret1 = NULL;
		while (fi) {
			if (rec_ptr->cpu == fi->fi_item) {
				return rec_ptr;
			}
			fi = fi->fi_next;
		}
	}

	return ret1;
}

/*
 **
 */
int
prof_dummy_func(void *rec_ptr, void *v)
{
        return 0;
}

int prof_ftrace_print_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);
        if (debug) printf ("pid_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
                ki_actions[TRACE_HARDCLOCK].execute = 1;
                ki_actions[TRACE_SCHED_SWITCH].execute = 1;
                start_time = KD_CUR_TIME;
		bufmiss_func = NULL;
        }
        if (strstr(buf, ts_end_marker)) {
                ki_actions[TRACE_HARDCLOCK].execute = 0;
                ki_actions[TRACE_SCHED_SWITCH].execute = 0;
                ki_actions[TRACE_PRINT].execute = 0;
                end_time = KD_CUR_TIME;
                bufmiss_func =  NULL;
        }

        if (debug)  {
                PRINT_KD_REC(rec_ptr);
                PRINT_EVENT(rec_ptr->KD_ID);
                printf (" %s", buf);

	NL;
        }
}

int
hc_print_pc(void *arg1, void *arg2)
{
	pc_info_t *pcinfop = (pc_info_t *)arg1;
	print_pc_args_t *print_pc_args = (print_pc_args_t *)arg2;
	FILE *pidfile = print_pc_args->pidfile;
	hc_info_t *hcinfop = print_pc_args->hcinfop;
	vtxt_preg_t *pregp;

	uint64 key;
	char *sym = NULL; 
	char *symfile = NULL;
	uint64 offset, symaddr;

	if (pcinfop->count == 0) return 0;
	key = pcinfop->lle.key;
	pregp = pcinfop->pregp;

	SPAN_GREY;

	if (IS_WINKI) {
                if (pregp) {
                        sym = win_symlookup(pregp, key, &symaddr);
			symfile = pregp->filename;
                }
	} else if (!UNKNOWN_SYMIDX(key)) {
		if (key < globals->nsyms-1)  {
			sym = globals->symtable[key].nameptr;
		} else {
			if (objfile_preg.elfp && (key < 0x10000000)) {
				sym = symlookup(&objfile_preg, key, &offset);
				symfile = objfile;
			} else if (pregp) {
				if (pregp->p_type == MAPCLASS) {
					sym = maplookup(pregp, key, &offset); 
				} else { 
					sym = symlookup(pregp, key, &offset);
				}
				symfile = pregp->filename;
			}
		}
	} else {
		sym="UNKNOWN";
	}

	if (kilive) {
		mvprintw (lineno, 0, "%8d %6.2f%%  %-6s %s", 
				pcinfop->count, 
				(pcinfop->count*100.0) / hcinfop->total, 
				cpustate_name_index[pcinfop->state],
				sym ? dmangle(sym) : "UNKNOWN");
		if (symfile) printw (" [%s]", symfile);
	} else {
		pid_printf (pidfile, "%s%8d %6.2f%%  %-6s %s", tab, 
				pcinfop->count, 
				(pcinfop->count*100.0) / hcinfop->total, 
				cpustate_name_index[pcinfop->state],
				sym ? dmangle(sym) : "UNKNOWN");
		if (symfile) pid_printf (pidfile, " [%s]", symfile);
		PNL;
	}

	BLACK_FONT;

	if ((lineno & 0x1) == 0) _SPAN;
	lineno++;
}

int
print_spin_stats(void *arg1, char *name, FILE *pidfile)
{
	spin_stats_t *statp = (spin_stats_t *)arg1;

	if (kilive) {
		mvprintw (lineno, 0, "%10d %10.1f %12d %10.1f %12d %10.1f %12d %10.1f  %s", 
				statp->count, 
				statp->count / globals->total_secs,
				statp->waitcycles,
				statp->waitcycles / (statp->count * 1.0),
				statp->heldcycles,
				statp->heldcycles / (statp->count * 1.0),
				statp->spincnt,
				statp->spincnt / (statp->count * 1.0),
				name);
	} else {
		pid_printf (pidfile, "%s%10d %10.1f %12d %10.1f %12d %10.1f %12d %10.1f  %s", tab, 
				statp->count, 
				statp->count / globals->total_secs,
				statp->waitcycles,
				statp->waitcycles / (statp->count * 1.0),
				statp->heldcycles,
				statp->heldcycles / (statp->count * 1.0),
				statp->spincnt,
				statp->spincnt / (statp->count * 1.0),
				name);
		PNL;
	}
}


int
print_spin_info(void *arg1, void *arg2)
{
	spin_info_t *spininfop = (spin_info_t *)arg1;
	FILE *pidfile = (FILE *)arg2;
	uint64 addr;
	char caller_str[256];
	
	/* if (spininfop->count == 0) return 0; */
	addr = spininfop->CALLER_ADDR;
	sprint_win_sym(caller_str, addr, NULL);

	print_spin_stats(&spininfop->stats, caller_str, pidfile);
	lineno++;
}

int print_pid_spinlock_summary(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	spinlock_info_t *spinlockp;

	if ((spinlockp = pidp->spinlockp) == NULL) return 0;

	PID_URL_FIELD8(pidp->PID);
	print_spin_stats(&spinlockp->stats, pidp->cmd, NULL);
}


int
hc_print_pc2(void *arg1, void *arg2)
{
	pc_info_t *pcinfop = (pc_info_t *)arg1;
	print_pc_args_t *print_pc_args = (print_pc_args_t *)arg2;
	hc_info_t *hcinfop = print_pc_args->hcinfop;
	FILE *pidfile = print_pc_args->pidfile;
	vtxt_preg_t *pregp = pcinfop->pregp;
	uint64 key;
	char *sym = NULL; 
	char *symfile = NULL;
	uint64 offset;
	uint64 symaddr;

	if (pcinfop->count == 0) return 0;
	key = pcinfop->lle.key;

	SPAN_GREY;

	if (IS_WINKI) {
                if (pregp) {
                        sym = win_symlookup(pregp, key, &symaddr);
			symfile = pregp->filename;
                }
        } else if ((pcinfop->state != HC_USER) && ((key > globals->nsyms) || UNKNOWN_SYMIDX(key)))  {
                /* fall through */
	} else if (!UNKNOWN_SYMIDX(key)) {
		if (pcinfop->state == HC_USER) {
			if (objfile_preg.elfp && (key < 0x10000000)) {
				sym = symlookup(&objfile_preg, key, &offset);
				symfile = objfile;
			} else if (pcinfop->pregp) {
				if (pcinfop->pregp->p_type == MAPCLASS) {
					sym = maplookup(pcinfop->pregp, key, &offset); 
				} else { 
					sym = symlookup(pcinfop->pregp, key, &offset);
				}
				symfile = pcinfop->pregp->filename;
			}
		} else if (key < globals->nsyms-1)  {
			sym = globals->symtable[key].nameptr;
		}
	}
	
	if (sym && print_pc_args->warnflagp) {
		if ((pcinfop->count > 100) && (strstr(sym, "jbd2_journal_start") )) {
			RED_FONT;
			(*print_pc_args->warnflagp) |= WARNF_HAS_JOURNAL;
		} else if ((((pcinfop->count*100.0) / hcinfop->total) > 2.0) &&
			     (strstr(sym, "semtimedop") || strstr(sym, "semctl"))) {
			RED_FONT;
			(*print_pc_args->warnflagp) |= WARNF_SEMLOCK;
		} else if ((((pcinfop->count*100.0) / hcinfop->total) > 0.5) &&
			     (strstr(sym, "sk_busy_loop") )) {
			RED_FONT;
			(*print_pc_args->warnflagp) |= WARNF_SK_BUSY;
		} else if ((((pcinfop->count*100.0) / hcinfop->total) > 2.0) &&
			     (strstr(sym, "qosdUpdExprExecStatsRws") )) {
			RED_FONT;
			(*print_pc_args->warnflagp) |= WARNF_ORACLE_COLSTATS;
		} else if ((((pcinfop->count*100.0) / hcinfop->total) > 2.0) &&
			     (strstr(dmangle(sym), "LatchBase::AcquireInternal") ||
			      strstr(dmangle(sym), "LatchBase::ReleaseInternal") )) {
			(*print_pc_args->warnflagp) |= WARNF_SQL_STATS;
			RED_FONT;
		} else if ((((pcinfop->count*100.0) / hcinfop->total) > 1.0) &&
			((key == pc_pagevec_lru_move_fn) || (key == pc_alloc_pages_nodemask) || (key == pc_release_pages))) {
			*print_pc_args->warnflagp |= WARNF_LARGE_NUMA_NODE;
			RED_FONT;
		}
	}
		
	if (sym == NULL) {
		if (UNKNOWN_SYMIDX(key)) {
			printf ("%s%8d %6.2f%%  %-6s %s", tab,
				pcinfop->count,
				(pcinfop->count*100.0) / hcinfop->total,
				cpustate_name_index[pcinfop->state],
				"unknown");
		} else {
			printf ("%s%8d %6.2f%%  %-6s 0x%llx", tab,
				pcinfop->count, 
				(pcinfop->count*100.0) / hcinfop->total, 
				cpustate_name_index[pcinfop->state],
				key);
		}
	} else {
		printf ("%s%8d %6.2f%%  %-6s %s", tab, 
				pcinfop->count, 
				(pcinfop->count*100.0) / hcinfop->total, 
				cpustate_name_index[pcinfop->state],
				dmangle(sym));
	}
	BLACK_FONT;

	if (symfile) printf (" [%s]", symfile);
	NL;

	if ((lineno & 0x1) == 0) _SPAN;
	lineno++;
}

int
hc_clear_pc(void *arg1, void *arg2)
{
	pc_info_t *pcinfop = (pc_info_t *)arg1;

	pcinfop->count = 0;
}

int
hc_print_pc_sys(void *arg1, void *arg2)
{
	pc_info_t *pcinfop = (pc_info_t *)arg1;
	print_pc_args_t *print_pc_args = (print_pc_args_t *)arg2;
	FILE *pidfile = print_pc_args->pidfile;
	hc_info_t *hcinfop = print_pc_args->hcinfop;
	uint64 idx, symaddr;
	char *symptr = "UNKNOWN";
	pid_info_t *pidp;
	vtxt_preg_t *pregp;

	idx = pcinfop->lle.key;

	SPAN_GREY;
	if (IS_WINKI) {
		if (pregp = get_win_pregp(idx, NULL)) {
			symptr = win_symlookup(pregp, idx, &symaddr);
		} 
	} else if ((pcinfop->state == HC_USER) || (idx > globals->nsyms) || (UNKNOWN_SYMIDX(idx)))  {
		/* fall through */
	} else {
		symptr = globals->symtable[idx].nameptr;
	}

	pid_printf (pidfile, "%s%8d %6.2f%%  %-6s", tab, 
				pcinfop->count, 
				(pcinfop->count*100.0) / hcinfop->total, 
				cpustate_name_index[pcinfop->state]);

	if (symptr) { 
		pid_printf (pidfile, " %s", symptr);
	} else { 
		pid_printf (pidfile, " 0x%0llx", idx); 
	}

	if (IS_WINKI && pregp && pregp->filename) {
		pid_printf (pidfile, " [%s]", pregp->filename);
	}

	NL;
}

int
hc_print_stktrc(void *p1, void *p2)
{
	stktrc_info_t *stktrcp = (stktrc_info_t *)p1;
	print_pc_args_t *print_pc_args = (print_pc_args_t *)p2;
	hc_info_t *hcinfop = print_pc_args->hcinfop;
	FILE *pidfile = print_pc_args->pidfile;
	pid_info_t *pidp;
	vtxt_preg_t *pregp;
        float avg, wpct;
	uint64 key, symaddr;
	char *sym;
	uint64 offset;
        int i;
	int hugetlb_fault_warn_cnt = 0;
	int semlock_warn_cnt = 0;
	int kstat_irqs_warn_cnt = 0;
	int queued_spin_lock_slowpath_cnt = 0;
	int rwsem_down_write_failed_cnt = 0;
	int kvm_pagefault_warn_cnt = 0;
	int cpufreq_warn_cnt = 0;
        int migrate_pages_warn_cnt = 0;

	if (stktrcp->cnt == 0) return 0;

	wpct = ((float)stktrcp->cnt *100.0)/(hcinfop->total);
        pid_printf (pidfile, "%s%8d %6.2f%%",tab, stktrcp->cnt, wpct);
        for (i=0;i<stktrcp->stklen; i++) {
                key = stktrcp->stklle.key[i];

		if (IS_WINKI) {
			pidp = stktrcp->pidp;
			pregp = get_win_pregp(key, pidp);
			if (pregp) {
				sym = win_symlookup(pregp, key, &symaddr);
			} 

			if (sym) { 
				pid_printf (pidfile, "  %s", sym);
			} else if (pregp) {
				pid_printf (pidfile, "  [%s]", pregp->filename);
			} else {
				pid_printf (pidfile, "  0x%llx", key);
			}
		} else if (key == STACK_CONTEXT_KERNEL) {
			continue;
		} else if (key == STACK_CONTEXT_USER) {
			pid_printf (pidfile, "  |");
		} else if (UNKNOWN_SYMIDX(key)) {
			pid_printf (pidfile, "  unknown");
		} else if ((globals->symtable) && (key < globals->nsyms-1)) {
			if (kparse_flag && print_pc_args->warnflagp) {
				if (stktrcp->cnt >= 200) { 
					/* cannot use the pc key as there can be more than one queued_spin_lock_slowpath function in kallsyms */
				 	if (strcmp(globals->symtable[key].nameptr, "queued_spin_lock_slowpath") == 0) queued_spin_lock_slowpath_cnt++;
				 	if (key == pc_rwsem_down_write_failed) rwsem_down_write_failed_cnt++;
					if (rwsem_down_write_failed_cnt && ((key == pc_hugetlb_fault) || (key == pc_huge_pmd_share))) 
						hugetlb_fault_warn_cnt=2;
					else if (queued_spin_lock_slowpath_cnt && ((key == pc_semctl) || (key == pc_SYSC_semtimedop) || (key == pc_semtimedop)))
						semlock_warn_cnt=2;
					else if (key == pc_kstat_irqs_usr) kstat_irqs_warn_cnt=2;
					else if (key == pc_pcc_cpufreq_target) cpufreq_warn_cnt=2;
					else if (key == pc_kvm_mmu_page_fault) kvm_pagefault_warn_cnt=2;
					else if ((key == pc_do_numa_page) || (key == pc_migrate_pages)) migrate_pages_warn_cnt++;
				}

				if (hugetlb_fault_warn_cnt >= 2) {
					RED_FONT;
					*print_pc_args->warnflagp |= WARNF_HUGETLB_FAULT;
					hugetlb_fault_warn_cnt = 1;
				} else if (semlock_warn_cnt >= 2) {
					RED_FONT;
					*print_pc_args->warnflagp |= WARNF_SEMLOCK;
					semlock_warn_cnt = 1;
				} else if (kstat_irqs_warn_cnt >= 2) {
					RED_FONT;
					*print_pc_args->warnflagp |= WARNF_KSTAT_IRQS;
					kstat_irqs_warn_cnt = 0;
				} else if (cpufreq_warn_cnt >= 2) {
					RED_FONT;
					cpufreq_warn_cnt = 0;
					*print_pc_args->warnflagp |= WARNF_PCC_CPUFREQ;
				} else if (kvm_pagefault_warn_cnt >= 2) {
					RED_FONT;
					kvm_pagefault_warn_cnt = 0;
					*print_pc_args->warnflagp |= WARNF_KVM_PAGEFAULT;
                                } else if (migrate_pages_warn_cnt >= 2) {
                                        RED_FONT;
                                        migrate_pages_warn_cnt = 0;
                                        *print_pc_args->warnflagp |= WARNF_MIGRATE_PAGES;

				}
			}
			pid_printf (pidfile, "  %s", globals->symtable[key].nameptr);
			BLACK_FONT;
		} else if (stktrcp->pidp) {
			pidp = stktrcp->pidp;
			if (pidp->PID != pidp->tgid) {
				pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
			}

			if (pregp = find_vtext_preg(pidp->vtxt_pregp, key)) {
				if (sym = symlookup(pregp, key, &offset)) {
					pid_printf (pidfile, "  %s", dmangle(sym));
				} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
					pid_printf (pidfile, "  %s", dmangle(sym));
				} else {
					pid_printf (pidfile, "  0x%llx", key);
				}
			} else if (sym = maplookup(pidp->mapinfop, key, &offset)) {
				pid_printf (pidfile, "  %s", dmangle(sym));
			} else {
				pid_printf (pidfile, "  0x%llx", key);
			}
		} else {
			pid_printf (pidfile, "  0x%llx", key);
		}
        }
        PNL;

}

int
prof_print_summary(void *arg1)
{
	hc_info_t *hcinfop = (hc_info_t *)arg1;

	if (hcinfop->total) {
		printf ("%7d %6.2f%% %6.2f%% %6.2f%% %6.2f%%", hcinfop->total, 
			(hcinfop->cpustate[HC_USER]*100.0)/hcinfop->total, 
			(hcinfop->cpustate[HC_SYS]*100.0)/hcinfop->total, 
			(hcinfop->cpustate[HC_INTR]*100.0)/hcinfop->total, 
			(hcinfop->cpustate[HC_IDLE]*100.0)/hcinfop->total);
	} else {
		printf ("%7d %6.2f%% %6.2f%% %6.2f%% %6.2f%%", 0, 0.0, 0.0, 0.0, 0.0);
	}

	return 0;
}

int
prof_print_percpu_summary() 
{
	cpu_info_t *cpuinfop;
	hc_info_t *hcinfop;
	int i;

	lineno=0;
	
	for (i = 0; i < MAXCPUS; i++) {
        	if ((cpuinfop = FIND_CPUP(globals->cpu_hash, i)) && cpuinfop->hcinfop) {
			hcinfop = cpuinfop->hcinfop;	
			if (hcinfop->total == 0) continue;

			SPAN_GREY;
			printf ("%7d ", i);
			prof_print_summary(hcinfop);
			_SPAN;
			NL;
			lineno++;
		}
	}
}
 
int 
prof_print_percpu_symbols(uint32 count)
{
        int i;
        cpu_info_t *cpuinfop;
        hc_info_t *ghcinfop, *hcinfop;
        uint64  total;
	print_pc_args_t print_pc_args;

        ghcinfop = (hc_info_t *)globals->hcinfop;
        if (ghcinfop->total == 0) return 0;

        total = ghcinfop->total;

        for (i = 0; i < MAXCPUS; i++) {
            if ((cpuinfop = FIND_CPUP(globals->cpu_hash, i)) && cpuinfop->hcinfop) {
		hcinfop = cpuinfop->hcinfop;
                if ((hcinfop->cpustate[HC_SYS] == 0) && (hcinfop->cpustate[HC_INTR] == 0)) continue;
                if (hcinfop->pc_hash == NULL) continue;

		print_pc_args.hcinfop = hcinfop;
		print_pc_args.warnflagp = NULL;
		print_pc_args.pidfile = NULL;

                printf("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                printf("Kernel Functions for CPU  %d \n",i);
                printf("Sample count is %lld/%lld -- Percent for this CPU is %7.2f\n",
                        hcinfop->total, total, hcinfop->total*100.0/total);
		printf("   Count     Pct  State  Function\n");
                printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");

                lineno=0;
                foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc_sys, pc_sort_by_count, nsym, (void *)&print_pc_args);

                printf("\nnon-idle CPU %d  HARDCLOCK STACK TRACES (sort by count):\n\n",i);
                printf("   Count     Pct  Stack trace\n");
                printf("============================================================\n");
                foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, hc_print_stktrc, stktrc_sort_by_cnt, nsym, (void *)&print_pc_args);
            }
        }

	return 0;
}

int print_pid_symbols(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        uint64  total = *(uint64 *)arg2;
        hc_info_t *hcinfop = (hc_info_t *)pidp->hcinfop;
	print_pc_args_t print_pc_args;
	uint64 warnflag = 0;
	int warn_indx;

        if (hcinfop==NULL) return 0;
        if (hcinfop->cpustate[HC_SYS] == 0)   return 0;

	print_pc_args.warnflagp = NULL;

	NL;
        CAPTION_GREY;
        BOLD("Pid: ");
        PID_URL_FIELD8(pidp->PID);
        BOLD ("Sys/Count: ");
	printf ("%d/%d (%4.2f%%)  ", hcinfop->cpustate[HC_SYS], total, hcinfop->cpustate[HC_SYS]*100.0/total);
	BOLD ("Command: ");
        if (pidp->cmd) {
		printf("%s ", pidp->cmd);
		if (strstr(pidp->cmd, "kiinfo") == NULL) {
			print_pc_args.warnflagp = &warnflag;
		}
	}
	if (pidp->hcmd) printf ("{%s} ", pidp->hcmd);
        if (pidp->thread_cmd) printf("(%s) ", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	if (cluster_flag) {SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_1_4_5); }
	
	_CAPTION;

        TEXT("-----------------------------------------------------------------\n");
	lineno=0;
        SPAN_GREY;
        BOLD ("%s   Count    USER     SYS    INTR", tab); NL;
	_SPAN;
	
        printf ("%s %7d %7d %7d %7d", tab, 
				hcinfop->total, 
				hcinfop->cpustate[HC_USER], 
				hcinfop->cpustate[HC_SYS], 
				hcinfop->cpustate[HC_INTR]);
	NL;
        TEXT("-----------------------------------------------------------------\n");
	SPAN_GREY;
        BOLD("   Count    %%Pid  State  Function"); NL;
	_SPAN;

        lineno++;
	print_pc_args.hcinfop = hcinfop;
	print_pc_args.pidfile = NULL;
        foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc2, pc_sort_by_count, 5, &print_pc_args);

	if (print_pc_args.warnflagp && ((*print_pc_args.warnflagp) & WARNF_HAS_JOURNAL)) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_HAS_JOURNAL, _LNK_1_4_5);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_5); NL;
	}

	if (print_pc_args.warnflagp && ((*print_pc_args.warnflagp) & WARNF_SQL_STATS)) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SQL_STATS, _LNK_1_4_5);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_5); NL;
	}

	if (print_pc_args.warnflagp && ((*print_pc_args.warnflagp) & WARNF_ORACLE_COLSTATS)) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_ORACLE_COLSTATS, _LNK_1_4_5);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_5); NL;
	}


	return 0;
}

int
prof_print_perpid_symbols()
{
        int i;
        hc_info_t       *hcinfop;
        uint64  total;

        if (npid == 0) return 0;

        hcinfop = (hc_info_t *)globals->hcinfop;
        if (hcinfop->total == 0) return 0;

        total = hcinfop->cpustate[HC_SYS];

        printf("\n******** PER-PROCESS HARDCLOCK REPORT ********\n");
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_symbols,
                                   pid_sort_by_totalsys,
                                   npid, (void *)&total);

        return 0;
}

void
clear_percpu_hc_info()
{
	cpu_info_t *cpuinfop;
	hc_info_t *hcinfop;
	int i;

	for (i = 0; i < MAXCPUS; i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			clear_hc_info((void **)&cpuinfop->hcinfop);
		}
	}
}

int
prof_print_report(int ptype)
{
	hc_info_t *hcinfop = (hc_info_t *)globals->hcinfop;
	print_pc_args_t print_pc_args;

	if (hcinfop == NULL || hcinfop->total == 0) {
		printf ("%sNo HARDCLOCK entries found\n", tab);
		return 0;
	}

	print_pc_args.hcinfop = hcinfop;
	print_pc_args.warnflagp = NULL;
	print_pc_args.pidfile = NULL;

	tab=tab0;
	lineno = 1;
	if (is_alive) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_command, NULL, 0, NULL);
	if (IS_LIKI && !kiall_flag) foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, load_perpid_mapfile, NULL, 0, NULL);
        printf("NOTE: idle hardclock traces are not always logged.\n\n");

	printf ("\n******** GLOBAL HARDCLOCK REPORT ********\n");
 	BOLD ("  Count   USER%%    SYS%%   INTR%%   IDLE%%\n");	
	prof_print_summary(hcinfop);
	printf ("\n");

        printf("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        printf("Kernel Functions executed during profile \n");
        printf("   Count     Pct  State  Function\n");
        printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc_sys, pc_sort_by_count, nsym, (void *)&print_pc_args);

        printf("\nnon-idle GLOBAL HARDCLOCK STACK TRACES (sort by count):\n\n");
        printf("   Count     Pct  Stack trace\n");
        printf("============================================================\n");
        foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, hc_print_stktrc, stktrc_sort_by_cnt, nsym, (void *)&print_pc_args);


	printf ("\n******** PERCPU HARDCLOCK REPORT ********\n");
	BOLD("    CPU   Count   USER%%    SYS%%   INTR%%   IDLE%%\n");
        TEXT("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	prof_print_percpu_summary();

	if (nsym) prof_print_percpu_symbols(nsym);
	if (npid && nsym) prof_print_perpid_symbols();

	if (is_alive) {
		clear_all_stats();
		clear_percpu_hc_info();
	}

	return 0;
}

int
prof_print_func(void *v)
{
        int i;
        struct timeval tod;

        if ((print_flag) && (is_alive)) {
                gettimeofday(&tod, NULL);
                printf ("\n%s\n", ctime(&tod.tv_sec));
                prof_print_report(PER_PASS);
                print_flag=0;
        }
        return 0;
}

int
prof_report_func(void *v)
{

        if (debug) printf ("Entering prof_report_func %d\n", is_alive);
        if (passes != 0) {
                prof_print_report(TOTAL);
        }

        return 0;
}
