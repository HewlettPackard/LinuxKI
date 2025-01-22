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

uint64 kiinfo_flags = 0ull; 
uint64 kiinfo_stats = 0ull;
int   tools_cnt = 0;

char *openfile = NULL;
char *objfile = NULL;
char *bkfname = NULL;
char *sysignore = NULL;
char *pdbfiles = NULL;


/* kitracedump globals and defaults */
char *debug_dir = "/sys/kernel/debug";
char *etl_filename = NULL;
uint32 trace_duration = 20;
uint32 trace_bufsize = 0;
uint32 trace_segments = 256;

int   top = (uint32)0x7fffffff;
int   npid = (uint32)0x7fffffff;
int   nsym = (uint32)0x7fffffff;
int   nfile = (uint32)0x7fffffff;
int   nfutex = (uint32)0x7fffffff;
uint64 itime = 0;
int   vpct = (uint32)0x3;
int   vdepth = (uint32)0x1;
int   vint =   (uint32)100;
int   hthr =   (uint32)0;
int   kilive = 0;
char *edusfname=NULL;
char *jstackfname=NULL;

/* kipid options */
int   runq_detail_time = 0x7fffffff;
int   sock_detail_time = 0x7fffffff;

/* kirunq options */
int rqpid = -1;       /* if set and triggers rqcnt or rqwait are set, we report the primadonna's */
int rqwait = 0x7fffffff;
int rqcnt  = 0x7fffffff;     /* a runq wait of 1000 threads triggers one-liner RESUME delay! output */
uint64 rqpid_pri = 0;  /* at SWTCH time we set this for the target pid */

void     (*tool_init_func)(void *) = NULL;
extern void   wait_init_func(void *);
extern void   prof_init_func(void *);
extern void   wio_init_func(void *);
extern void   dsk_init_func(void *);
extern void   kparse_init_func(void *);
extern void   trace_init_func(void *);
extern void   pid_init_func(void *);
extern void   live_init_func(void *);
extern void   runq_init_func(void *);
extern void   socket_init_func(void *);
extern void   file_init_func(void *);
extern void   futex_init_func(void *);
extern void   docker_init_func(void *);
extern void   clparse_init_func(void *);
extern void   kiall_init_func(void *);
extern int    add_filter_item(void *, uint64);
extern int    ki_turn_on_select_syscall_traces();

void
pw_option_usage(init_t *init, char *msg, char *name)
{
	option_usage(init, msg, name);
}

static void
Likimerge(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(LIKIMERGE_FLAG);

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
		if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "likimerge");
		}
	    }
	}

	filter_func_arg = &trace_filter;
}

static void
Objdump(init_t *init, arg_t *arg)
{
	prop_t *prop;
	SET(OBJDUMP_FLAG);
}


static void
Kitracedump(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(KITRACEDUMP_FLAG);
	is_alive = 0;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("debug_dir", prop->p_name) == 0) {
                        debug_dir = prop->p_value.s;
                } else if (strcmp("dur", prop->p_name) == 0) {
        		trace_duration = (uint32)prop->p_value.i;
                } else if (strcmp("bufsize", prop->p_name) == 0) {
        		trace_bufsize = (uint32)prop->p_value.i;
                } else if (strcmp("segments", prop->p_name) == 0) {
        		trace_segments = (uint32)prop->p_value.i;
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
		} else if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "kitracedump");
		}
	    }
	}

	filter_func_arg = &trace_filter;

}

static void
Etldump(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(ETLDUMP_FLAG);
	is_alive = 0;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("file", prop->p_name) == 0) {
                        etl_filename = prop->p_value.s;
		} else if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "kitracedump");
		}
	    }
	}

	filter_func_arg = NULL;
}

static void
Likidump(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(LIKIDUMP_FLAG);
	is_alive = 0;
	debug_dir = NULL;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("debug_dir", prop->p_name) == 0) {
                        debug_dir = prop->p_value.s;
                } else if (strcmp("dur", prop->p_name) == 0) {
        		trace_duration = (uint32)prop->p_value.i;
                } else if (strcmp("pid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
                } else if (strcmp("tgid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
                } else if (strcmp("dev", prop->p_name) == 0) {
                        if (prop->p_value.i >= 0) add_filter_item(&trace_filter.f_dev, (int)prop->p_value.i);
                } else if (strcmp("cpu", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_cpu, (int)prop->p_value.i);
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
		} else if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "likidump");
		}
	    }
	}

	filter_func_arg = &trace_filter;
}

static void
Likistart(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(LIKISTART_FLAG);
	is_alive = 0;
	debug_dir = NULL;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("debug_dir", prop->p_name) == 0) {
                        debug_dir = prop->p_value.s;
                } else if (strcmp("dur", prop->p_name) == 0) {
        		trace_duration = (uint32)prop->p_value.i;
                } else if (strcmp("pid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
                } else if (strcmp("tgid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
                } else if (strcmp("dev", prop->p_name) == 0) {
                        if (prop->p_value.i >= 0) add_filter_item(&trace_filter.f_dev, (int)prop->p_value.i);
                } else if (strcmp("cpu", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_cpu, (int)prop->p_value.i);
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
		} else if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "likistart");
		}
	    }
	}

	filter_func_arg = &trace_filter;
}

static void
Likiend(init_t *init, arg_t *arg)
{
	prop_t *prop;

	SET(LIKIEND_FLAG);
	is_alive = 0;
	debug_dir = NULL;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("debug_dir", prop->p_name) == 0) {
                        debug_dir = prop->p_value.s;
		} else if (strcmp("help", prop->p_name) == 0) {
			option_usage(init, NULL, "likiend");
		}
	    }
	}
}


static void
Kparse(init_t *init, arg_t *arg)
{
	prop_t *prop;

	tool_init_func = kparse_init_func; 

	SET(KPARSE_FULL_FLAG | ORACLE_FLAG | SCHED_FLAG | RUNQ_HISTOGRAM | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERCPU_STATS | PERPID_STATS | PERIRQ_STATS | PERTRC_STATS | COOP_STATS |
		SLEEP_STATS | STKTRC_STATS | PERDSK_STATS | HT_STATS | DSKBLK_STATS | POWER_STATS | 
		IDLE_STATS | PERFD_STATS ); 

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
		if (strcmp("nooracle", prop->p_name) == 0) {
			CLEAR(ORACLE_FLAG);
		} else if (strcmp("kptree", prop->p_name) == 0) {
			SET(KPTREE_FLAG);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
		} else if (strcmp("nofutex", prop->p_name) == 0) {
			CLEAR_STAT(FUTEX_STATS);
                } else if (strcmp("mangle", prop->p_name) == 0) {
                        SET(MANGLE_FLAG);
		} else if (strcmp("vis", prop->p_name) == 0) {
			SET(VIS_FLAG);
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
		} else if (strcmp("lite", prop->p_name) == 0) {
			CLEAR(KPARSE_FULL_FLAG);
		} else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kparse");
		}
	    }
	}

	rqwait = 0x7fffffff; 
	rqcnt  = 0x7fffffff;  
	nfutex=10;
	filter_func_arg = &trace_filter;
}

static void
Kidsk(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;
	tool_init_func = dsk_init_func;
	npid = 20;

	SET(DSK_DETAIL_FLAG | SYSARGS_FLAG | SYSENTER_FLAG | SORT_FLAG );
	SET_STAT(PERDSK_STATS | PERPID_STATS | GLOBAL_STATS);
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("dev", prop->p_name) == 0) {
                        if (prop->p_value.i >= 0) add_filter_item(&trace_filter.f_dev, (int)prop->p_value.i);
                } else if (strcmp("pid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
                } else if (strcmp("tgid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
		} else if (strcmp("nomapper", prop->p_name) == 0) {
			SET(NOMAPPER_FLAG);
                } else if (strcmp("bkfname", prop->p_name) == 0) {
                        bkfname = prop->p_value.s;
		} else if (strcmp("percpu", prop->p_name) == 0) {
			SET_STAT(PERCPU_STATS);
                } else if (strcmp("nodev", prop->p_name) == 0) {
                        SET(DSK_NODEV_FLAG);
                } else if (strcmp("detail", prop->p_name) == 0) {
                        (int)prop->p_value.i ? SET(DSK_DETAIL_FLAG) : CLEAR(DSK_DETAIL_FLAG);
		} else if (strcmp("mpath_detail", prop->p_name) == 0) {
                        SET(DSK_MPATH_FLAG);
                } else if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
			npid ? SET_STAT(PERPID_STATS) : CLEAR_STAT(PERPID_STATS);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kidsk");
                }
	    }
        }

	filter_func_arg = &trace_filter;
	if (npid == 0) CLEAR(PERPID_STATS);  
}

/* Kipid option processing */

static void
Report(init_t *init, prop_t *prop)
{
	char	*report_str;
	char	value;
	int	i;
	int	bad;

	report_str = (char *)prop->p_value.s;
	bad = 0;

	for (i = 0; i < strlen(report_str); i++) {
		value = report_str[i];
		if (strchr("-asxhfcopnm", value) == 0) 
			bad++;
	}

	if (bad)
		pw_option_usage(init, "Invalid report (-r) option", "kipid");

	if (strstr(report_str, "-")) {
		value = 0;
	} else {
		CLEAR(SCHED_FLAG | DSK_FLAG | FUTEX_FLAG | MEMORY_FLAG | FILE_FLAG | CACHE_FLAG | SOCK_FLAG | HC_FLAG | SCALL_FLAG);
		value = 1;
	}

	if (strstr(report_str, "a")) value ? SET(SCHED_FLAG) : CLEAR(SCHED_FLAG);
	if (strstr(report_str, "s")) value ? SET(SCALL_FLAG) : CLEAR(SCALL_FLAG);
	if (strstr(report_str, "x")) value ? SET(FUTEX_FLAG) : CLEAR(FUTEX_FLAG);
	if (strstr(report_str, "h")) value ? SET(HC_FLAG) : CLEAR(HC_FLAG);
	if (strstr(report_str, "f")) value ? SET(FILE_FLAG) : CLEAR(FILE_FLAG);
	if (strstr(report_str, "c")) value ? SET(CACHE_FLAG) : CLEAR(CACHE_FLAG);
	if (strstr(report_str, "o")) value ? SET(SOCK_FLAG) : CLEAR(SOCK_FLAG); 
	if (strstr(report_str, "p")) value ? SET(DSK_FLAG) : CLEAR(DSK_FLAG); 
	if (strstr(report_str, "m")) value ? SET(MEMORY_FLAG) : CLEAR(MEMORY_FLAG);
 
	if (coop_detail_enabled) {
		SET(SCHED_FLAG | SCALL_FLAG);
	}

}

static void
Kipid(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int pid_cnt=0;
	int ret;

	tools_cnt++;
	SET(SCHED_FLAG | SCALL_FLAG | FILE_FLAG | SOCK_FLAG | SORT_FLAG | DSK_FLAG | 
	    FUTEX_FLAG | HC_FLAG | MEMORY_FLAG | CACHE_FLAG | SYSARGS_FLAG | SYSENTER_FLAG | SCDETAIL_FLAG);
	SET_STAT(PERPID_STATS | SLEEP_STATS | STKTRC_STATS | COOP_STATS | SCALL_STATS | 
	    PERDSK_STATS | PERFD_STATS | FUTEX_STATS | PERTRC_STATS );
	tool_init_func = pid_init_func;
	nsym=10;
	npid=10;
	nfutex=10;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("pid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) {
				add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("tgid", prop->p_name) == 0) {
			if ((int)prop->p_value.i >= 0) {
                        	add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("oracle", prop->p_name) == 0) {
                        SET(ORACLE_FLAG);
			pid_cnt++;
                } else if (strcmp("nsym", prop->p_name) == 0) {
        		nsym = (uint32)prop->p_value.i;
		} else if (strcmp("nfutex", prop->p_name) == 0) {
                        nfutex = (uint32)prop->p_value.i;
                } else if (strcmp("scdetail", prop->p_name) == 0) {
			SET(SCDETAIL_FLAG);
                } else if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
                } else if (strcmp("rqdetail", prop->p_name) == 0) {
			runq_detail_time = (int)prop->p_value.i;
                } else if (strcmp("coop", prop->p_name) == 0) {
			SET(SCHED_FLAG | SCALL_FLAG | COOP_DETAIL_ENABLED);
		} else if (strcmp("pidtree", prop->p_name) == 0) {
			SET(PIDTREE_FLAG);
		} else if (strcmp("nofutex", prop->p_name) == 0) {
			CLEAR_STAT(FUTEX_STATS);
                } else if (strcmp("mangle", prop->p_name) == 0) {
                        SET(MANGLE_FLAG);
		} else if (strcmp("vis", prop->p_name) == 0) {
			SET(VIS_FLAG);
		} else if (strcmp("vpct", prop->p_name) == 0) {
                        vpct = (uint32)prop->p_value.i;
                } else if (strcmp("vdepth", prop->p_name) == 0) {
                        vdepth = (uint32)prop->p_value.i;
                } else if (strcmp("rqhist", prop->p_name) == 0) {
        		SET(RUNQ_HISTOGRAM); 
                } else if (strcmp("rqdetail", prop->p_name) == 0) {
			runq_detail_time = (int)prop->p_value.i;
                } else if (strcmp("report", prop->p_name) == 0) {
                	Report(init, prop);
		} else if (strcmp("objfile", prop->p_name) == 0) {
			if (pid_cnt && (objfile==NULL)) objfile = prop->p_value.s;
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strncmp("nosysenter", prop->p_name, 10) == 0) {
			CLEAR(SYSENTER_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kipid");
                } else {
			pw_option_usage(init, NULL, "kipid");
		}
	    }
        }

	rqwait = 0x7fffffff; 
	rqcnt  = 0x7fffffff;  
	filter_func_arg = &trace_filter;
}

static void
Kidock(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int pid_cnt=0;
	int ret;

	tools_cnt++;
	SET(SCHED_FLAG | SCALL_FLAG | FILE_FLAG | SOCK_FLAG | SORT_FLAG | DSK_FLAG | 
	    FUTEX_FLAG | HC_FLAG | MEMORY_FLAG | CACHE_FLAG | SYSARGS_FLAG | SYSENTER_FLAG );
	SET_STAT(PERPID_STATS | SLEEP_STATS | STKTRC_STATS | COOP_STATS | SCALL_STATS | PERDSK_STATS | PERFD_STATS | FUTEX_STATS );
	tool_init_func = docker_init_func;
	npid=10;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
		} else if (strcmp("docktree", prop->p_name) == 0) {
			SET(DOCKTREE_FLAG);
                } else {
			pw_option_usage(init, NULL, "kidock");
		}
	    }
	}

	filter_func_arg = &trace_filter;
}


static void
Kilive(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int pid_cnt=0;
	int ret;

	tools_cnt++;
	tool_init_func = live_init_func;
	kilive = 1;
	npid=10;
	SET_STAT(FUTEX_STATS);
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
		} else if (strcmp("nofutex", prop->p_name) == 0) {
			CLEAR_STAT(FUTEX_STATS);
                } else if (strcmp("mangle", prop->p_name) == 0) {
                        SET(MANGLE_FLAG);
		} else if (strcmp("step", prop->p_name) == 0) {
			double float_time;
			if ((float_time = strtod(prop->p_value.s, NULL)) > 0.0) {
				kistep = float_time*1000000000;
			}
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kilive");
                } else {
			pw_option_usage(init, NULL, "kilive");
		}
	    }
	}

	rqwait = 0x7fffffff; 
	rqcnt  = 0x7fffffff;  
	passes = 0x7fffffff;
	filter_func_arg = &trace_filter;

}

static void
Kitrace(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;

	tools_cnt++;
	tool_init_func = trace_init_func;
	SET(PRINTMB_FLAG | SYSARGS_FLAG | SYSENTER_FLAG | KITRACE_FLAG);
	CLEAR_STATS;
	int pid_cnt = 0;

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("pid", prop->p_name) == 0) {
			if ((int)prop->p_value.i >= 0) {
                        	add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("tgid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) {
				add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("cpu", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_cpu, (int)prop->p_value.i);
                } else if (strcmp("dev", prop->p_name) == 0) {
                        if (prop->p_value.i >= 0) add_filter_item(&trace_filter.f_dev, (int)prop->p_value.i);
		} else if (strncmp("nosysenter", prop->p_name, 10) == 0) {
			CLEAR(SYSENTER_FLAG);
		} else if (strncmp("sysenter", prop->p_name, 8) == 0) {
			SET(SYSENTER_FLAG);
		} else if (strcmp("nosysargs", prop->p_name) == 0) {
			CLEAR(SYSARGS_FLAG);
		} else if (strncmp("sysargs", prop->p_name, 7) == 0) {
			SET(SYSARGS_FLAG);
		} else if (strcmp("printcmd", prop->p_name) == 0) {
			SET(PRINTCMD_FLAG);
		} else if (strcmp("nomapper", prop->p_name) == 0) {
			SET(NOMAPPER_FLAG);
		} else if (strcmp("nomarker", prop->p_name) == 0) {
			SET(NOMARKER_FLAG);
                } else if (strcmp("mangle", prop->p_name) == 0) {
                        SET(MANGLE_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
		} else if (strcmp("objfile", prop->p_name) == 0) {
			if (pid_cnt && (objfile==NULL)) objfile = prop->p_value.s;
		} else if (strcmp("seqcnt", prop->p_name) == 0) {
			SET(SEQCNT_FLAG);
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
		} else if (strcmp("info", prop->p_name) == 0) {
			SET(INFO_FLAG);
		} else if (strcmp("sysconfig", prop->p_name) == 0) {
			SET(SYSCONFIG_FLAG);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("pdbfiles", prop->p_name) == 0) {
                        pdbfiles = prop->p_value.s;
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kitrace");
                } else {
			pw_option_usage(init, NULL, "kitrace");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kiprof(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	int pid_cnt = 0;

	tools_cnt++;
	tool_init_func = prof_init_func;

	SET(HC_FLAG | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERCPU_STATS | STKTRC_STATS | PERPID_STATS);
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("cpu", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_cpu, (int)prop->p_value.i);
                } else if (strcmp("pid", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) {
				add_filter_item(&trace_filter.f_P_pid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("tgid", prop->p_name) == 0) {
			if ((int)prop->p_value.i >= 0) {
                        	add_filter_item(&trace_filter.f_P_tgid, (int)prop->p_value.i);
				pid_cnt++;
			}
                } else if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
			npid ? SET(PERPID_STATS) : CLEAR(PERPID_STATS);
                } else if (strcmp("nsym", prop->p_name) == 0) {
        		nsym = (uint32)prop->p_value.i;
		} else if (strcmp("objfile", prop->p_name) == 0) {
			if (pid_cnt && (objfile==NULL)) objfile = prop->p_value.s;
		} else if (strcmp("seqcnt", prop->p_name) == 0) {
			SET(SEQCNT_FLAG);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kiprof");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kiwait(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;
	tool_init_func = wait_init_func; 

	SET(SYSARGS_FLAG | SYSENTER_FLAG | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERCPU_STATS | SLEEP_STATS | STKTRC_STATS | PERPID_STATS);
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
			npid ? SET_STAT(PERPID_STATS) : CLEAR_STAT(PERPID_STATS);
                } else if (strcmp("nsym", prop->p_name) == 0) {
        		nsym = (uint32)prop->p_value.i;
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kiwait");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kirunq(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;

	tool_init_func = runq_init_func;
	npid=10;	
	SET(SCHED_FLAG | SYSARGS_FLAG | SYSENTER_FLAG | RUNQ_HISTOGRAM | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERCPU_STATS | PERPID_STATS | HT_STATS | PERIRQ_STATS | IDLE_STATS);

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("cpu", prop->p_name) == 0) {
                        if ((int)prop->p_value.i >= 0) add_filter_item(&trace_filter.f_P_cpu, (int)prop->p_value.i);
                } else if (strcmp("rqdetail", prop->p_name) == 0) {
			runq_detail_time = (int)prop->p_value.i;
                } else if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
			if (npid == 0) CLEAR_STAT(PERPID_STATS);
		} else if (strcmp("itime", prop->p_name) == 0) {
                        itime = prop->p_value.i;
                        SET(ITIME_FLAG);
		} else if (strcmp("rqpid", prop->p_name) == 0) {
                        rqpid = prop->p_value.i;
			/* printf("rqpid set to %d\n",rqpid); */
		} else if (strcmp("rqwait", prop->p_name) == 0) {
                        rqwait = prop->p_value.i;
		} else if (strcmp("rqcnt", prop->p_name) == 0) {
                        rqcnt = prop->p_value.i;
		} else if (strcmp("HThist", prop->p_name) ==0 ) {
			SET(HT_DBDI_HISTOGRAM);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("msr", prop->p_name) == 0) {
                        SET(MSR_FLAG);
                } else if (strcmp("events", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_events, prop->p_value.s);
                } else if (strcmp("subsys", prop->p_name) == 0) {
                        add_filter_item_str(&trace_filter.f_subsys, prop->p_value.s);
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kirunq");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kifile(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;

	tool_init_func = file_init_func; 

	SET(SYSARGS_FLAG | SCALL_FLAG | SORT_FLAG );
	SET_STAT(GLOBAL_STATS | PERPID_STATS | PERFD_STATS | SCALL_STATS);
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("nfile", prop->p_name) == 0) {
        		nfile = (uint32)prop->p_value.i;
                } else if (strcmp("scdetail", prop->p_name) == 0) {
			SET(SCDETAIL_FLAG);
			SET_STAT(SLEEP_STATS);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strncmp("nosysenter", prop->p_name, 10) == 0) {
			CLEAR(SYSENTER_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kifile");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kisock(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;

	SET(SOCK_FLAG | SCDETAIL_FLAG | SYSARGS_FLAG | SYSENTER_FLAG | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERFD_STATS | SCALL_STATS);

	tool_init_func = socket_init_func; 

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("nsock", prop->p_name) == 0) {
        		nfile = (uint32)prop->p_value.i;
                } else if (strcmp("scdetail", prop->p_name) == 0) {
			SET(SCDETAIL_FLAG);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strncmp("nosysenter", prop->p_name, 10) == 0) {
			CLEAR(SYSENTER_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kisock");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Kifutex(init_t *init, arg_t *arg)
{
	prop_t *prop;
	int ret;
	tools_cnt++;

	tool_init_func = futex_init_func; 

	SET(SYSARGS_FLAG | SYSENTER_FLAG | SORT_FLAG);
	SET_STAT(GLOBAL_STATS | PERPID_STATS | FUTEX_STATS );
	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("uaddr", prop->p_name) == 0) {
                        add_filter_item(&trace_filter.f_uaddr, prop->p_value.i);
                } else if (strcmp("nfutex", prop->p_name) == 0) {
        		nfutex = (uint32)prop->p_value.i;
                } else if (strcmp("npid", prop->p_name) == 0) {
        		npid = (uint32)prop->p_value.i;
			npid ? SET_STAT(PERPID_STATS) : CLEAR_STAT(PERPID_STATS);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
                } else if (strcmp("kitrace", prop->p_name) == 0) {
                        SET(KITRACE_FLAG);
		} else if (strncmp("nosysenter", prop->p_name, 10) == 0) {
			CLEAR(SYSENTER_FLAG);
		} else if (strcmp("abstime", prop->p_name) == 0) {
			SET(ABSTIME_FLAG);
		} else if (strcmp("fmttime", prop->p_name) == 0) {
			SET(FMTTIME_FLAG);
		} else if (strcmp("epochtime", prop->p_name) == 0) {
			SET(EPOCH_FLAG);
                } else if (strcmp("sysignore", prop->p_name) == 0) {
                        sysignore = prop->p_value.s;
                } else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kifutex");
		}
	    }
        }

	filter_func_arg = &trace_filter;
}

static void
Clparse(init_t *init, arg_t *arg)
{
	prop_t *prop;

	tool_init_func = clparse_init_func; 
	top=20;

	SET(CLUSTER_FLAG | SCHED_FLAG | KPARSE_FULL_FLAG | ORACLE_FLAG | RUNQ_HISTOGRAM | SOCK_FLAG | SORT_FLAG );
	SET_STAT(GLOBAL_STATS | PERPID_STATS | PERCPU_STATS | PERIRQ_STATS | PERTRC_STATS | SCALL_STATS |
	          SLEEP_STATS | STKTRC_STATS | PERDSK_STATS | FUTEX_STATS | PERFD_STATS | POWER_STATS);

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("top", prop->p_name) == 0) {
        		top = (uint32)prop->p_value.i;
		} else if (strcmp("nooracle", prop->p_name) == 0) {
			CLEAR(ORACLE_FLAG);
		} else if (strcmp("cltree", prop->p_name) == 0) {
			SET(CLTREE_FLAG);
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
		} else if (strcmp("nofutex", prop->p_name) == 0) {
			CLEAR_STAT(FUTEX_STATS);
		} else if (strcmp("mangle", prop->p_name) == 0) {
			SET(MANGLE_FLAG);
                } else if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
		} else if (strcmp("vis", prop->p_name) == 0) {
			SET(VIS_FLAG);
		} else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "clparse");
		}
	    }
	}

	rqwait = 0x7fffffff; 
	rqcnt  = 0x7fffffff;  
	nfutex=10;
	filter_func_arg = &trace_filter;
}


static void
Kiall(init_t *init, arg_t *arg)
{
	prop_t *prop;

	tools_cnt++;
	tool_init_func = kiall_init_func; 
	npid=20;
	top=20;
	hthr=0;
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	SET(SCHED_FLAG | KPARSE_FLAG | KPARSE_FULL_FLAG | SYSENTER_FLAG | SYSARGS_FLAG |
	    SCDETAIL_FLAG | SCALL_FLAG | KPTREE_FLAG | FUTEX_FLAG | FILE_FLAG | CACHE_FLAG |
	    HC_FLAG | MEMORY_FLAG | SOCK_FLAG | DSK_FLAG | SORT_FLAG | 
	    HT_DBDI_HISTOGRAM | RUNQ_HISTOGRAM | KIALL_FLAG); 

	SET_STAT(GLOBAL_STATS | PERPID_STATS | PERCPU_STATS | PERIRQ_STATS | PERTRC_STATS | COOP_STATS | SCALL_STATS |
		SLEEP_STATS | STKTRC_STATS | PERDSK_STATS | POWER_STATS | DSKBLK_STATS | PERFD_STATS | HT_STATS | 
		IDLE_STATS | FUTEX_STATS);

	if (arg) {
            for (prop = arg->a_props; prop; prop = prop->p_nextp) {
                if (strcmp("csv", prop->p_name) == 0) {
                        SET(CSV_FLAG);
                } else if (strcmp("oracle", prop->p_name) == 0) {
                        SET(ORACLE_FLAG);
		} else if (strcmp("nofutex", prop->p_name) == 0) {
			CLEAR_STAT(FUTEX_STATS);
		} else if (strcmp("mangle", prop->p_name) == 0) {
			SET(MANGLE_FLAG);
                } else if (strcmp("vis", prop->p_name) == 0) {
                        SET(VIS_FLAG);
		} else if (strcmp("vpct", prop->p_name) == 0) {
			vpct = (uint32)prop->p_value.i;
		} else if (strcmp("vdepth", prop->p_name) == 0) {
			vdepth = (uint32)prop->p_value.i;
		} else if (strcmp("vint", prop->p_name) == 0) {
			vint = (uint32)prop->p_value.i;
		} else if (strcmp("hthr", prop->p_name) == 0) {
			if ((prop->p_value.i == 0) || (prop->p_value.i > ncpus)) {
				hthr = ncpus;
			} else {
				hthr = prop->p_value.i;
			}
		} else if (strcmp("edus", prop->p_name) == 0) {
			edusfname = prop->p_value.s;
		} else if (strcmp("jstack", prop->p_name) == 0) {
			jstackfname = prop->p_value.s;
		} else if (strcmp("help", prop->p_name) == 0) {
			pw_option_usage(init, NULL, "kiall");
		}
	    }
	}

	/* limit number of threads to the number of CPU cores */
	rqwait = 0x7fffffff; 
	rqcnt  = 0x7fffffff;  
	nfutex=10;
	npid=10;
	nsym=20;
	filter_func_arg = &trace_filter;
}

/* general options processing */

/*
**  -h | help option
*/
static void
Usage(init_t *init, arg_t *arg)
{

	if (arg) {
		do_detail_help = prop_lookup(arg->a_props, "detail") ? 1 : 0;
	}
	option_usage(init, NULL, NULL);

}

static void
Html(init_t *init, arg_t *arg)
{
	HTML = TRUE;
}

/*
** Sets the alarm in seconds
*/
static void
Alarm(init_t *init, arg_t *arg)
{

	if (arg->a_valid) {
		alarm_secs = (int)arg->a_value.i;
	} else {
		alarm_secs = 5;
	}
	is_alive = 1;
}

/*
** Sets the debug flag
*/
static void
Debug(init_t *init, arg_t *arg)
{
	debug=1;
}

static void
Timestamp(init_t *init, arg_t *arg)
{
	timestamp = arg->a_value.s;
	is_alive = 0;
}

static void
Starttime(init_t *init, arg_t *arg)
{
	double float_time;

	if ((float_time = strtod(arg->a_value.s, NULL)) > 0.0) {
		start_filter = float_time*1000000000;
	}
}

static void
Endtime(init_t *init, arg_t *arg)
{
	double float_time;

	if ((float_time = strtod(arg->a_value.s, NULL)) > 0.0) {
		end_filter = float_time*1000000000;
	}
}


static void
Passes(init_t *init, arg_t *arg)
{
	if (arg->a_valid) {
		passes = arg->a_value.i;
	} else { 
		passes = 1;
	}
	is_alive = 1;
}	

static void
Nosort(init_t *init, arg_t *arg)
{
	CLEAR(SORT_FLAG);
}

extern filter_t filter;
/*
** Flag arrays.
*/
flag_t help_flags[] = {
  { "detail",      NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t dump_flags[] = {
  { "debug_dir",	"path", FA_ALL, FT_REG, "s"},
  { "dur",              "duration", FA_ALL, FT_REG, "i"},
  { "bufsize",		"kb", FA_ALL, FT_REG | FT_HIDDEN, "i"},
  { "segments",         "segments", FA_ALL, FT_REG | FT_HIDDEN, "i"},
  { "events",		"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 		"subsys", FA_ALL, FT_REG, "s"},
  { "nop",		NULL,      FA_ALL, FT_OPT | FT_HIDDEN, NULL },    /* ignore this option */
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t etldump_flags[] = {
  { "file",	"etlfile", FA_ALL, FT_REG | FT_HIDDEN, "s"},
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};


flag_t likid_flags[] = {
  { "debug_dir",	"path", FA_ALL, FT_REG, "s"},
  { "pid",		"pid",   FA_ALL, FT_REG , "i"},
  { "tgid",		"tgid",  FA_ALL, FT_REG , "i"},
  { "dev",		"dev",     FA_ALL, FT_REG,  "i" },
  { "cpu",		"cpu",     FA_ALL, FT_REG,  "i" },
  { "msr",		NULL,      FA_ALL, FT_OPT, NULL },
  { "nop",		NULL,      FA_ALL, FT_OPT | FT_HIDDEN, NULL },    /* ignore this option */
  { "dur",              "duration", FA_ALL, FT_REG, "i"},
  { "events",		"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 		"subsys", FA_ALL, FT_REG, "s"},
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "help",        	NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t likiend_flags[] = {
  { "debug_dir",	"path", FA_ALL, FT_REG, "s"},
  { "help",        	NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t likim_flags[] = {
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};


flag_t kparse_flags[] = {
  { "nooracle",    NULL,   FA_ALL, FT_OPT, NULL },
  { "kptree",      NULL,   FA_ALL, FT_OPT, NULL },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "nofutex",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",   "mangle", FA_ALL, FT_OPT, NULL},
  { "vis",         NULL,   FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "events",	"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 	"subsys", FA_ALL, FT_REG, "s"},
  { "lite",        NULL,   FA_ALL, FT_OPT, NULL },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t pid_flags[] = {
  { "help",        NULL,    FA_ALL, FT_OPT, NULL},
  { "pid",         "pid",   FA_ALL, FT_REG, "i"},
  { "tgid",        "tgid",  FA_ALL, FT_REG, "i"},
  { "scdetail",    NULL,    FA_ALL, FT_OPT, NULL},
  { "nsym",   "nsym",    FA_ALL, FT_REG, "i" },
  { "nfutex",   "nfutex",    FA_ALL, FT_REG, "i" },
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "pidtree",     NULL,    FA_ALL, FT_OPT, NULL},
  { "nofutex",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",   "mangle", FA_ALL, FT_OPT, NULL},
  { "vis",         NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL},
  { "vpct",        "vpct",  FA_ALL, FT_REG | FT_HIDDEN, "i" },
  { "vdepth",      "vdepth",  FA_ALL, FT_REG | FT_HIDDEN, "i" },
  { "rqhist",      NULL,    FA_ALL, FT_OPT, NULL },
  { "oracle",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "coop",        NULL,    FA_ALL, FT_OPT, NULL },
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "msr",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "nosysenter",  NULL,    FA_ALL, FT_OPT, NULL },
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "objfile",     "filename",    FA_ALL, FT_REG, "s" },
  { "events",		"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 		"subsys", FA_ALL, FT_REG, "s"},
  { "report",	   "[-]asxhfopnm\n\t\t\t\t- - Omit Reports\n\t\t\t\ta - Scheduler Activity Report\n\t\t\t\ts - System Call Report\n\t\t\t\tx - Futex Report\n\t\t\t\th - CPU Activity Report\n\t\t\t\tf - File Activity Report\n\t\t\t\to - Network/Socket Activity Report\n\t\t\t\tp - Physical Volume Report\n\t\t\t\tm - Memory Report", FA_ALL, FT_REG, "s"},
/*
  { "rqdetail",    "usecs",    FA_ALL, FT_OPT, "i" },
*/
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { 0,0,0,0,0 }
};

flag_t dock_flags[] = {
  { "help",        NULL,    FA_ALL, FT_OPT, NULL},
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "docktree",     NULL,    FA_ALL, FT_OPT, NULL},
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { 0,0,0,0,0 }
};

flag_t live_flags[] = {
  { "help",         NULL,   FA_ALL, FT_OPT, NULL },
  { "sysignore",   "filename", FA_ALL, FT_REG, "s" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},  
  { "msr",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "nofutex",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",   "mangle", FA_ALL, FT_OPT, NULL},
  { "step",	   "<time_in_secs>",  FA_ALL, FT_OPT, "s" },
  { 0,0,0,0,0 }
};

flag_t dsk_flags[] = {
  { "help",         NULL,   FA_ALL, FT_OPT, NULL },
  { "dev",    "dev",     FA_ALL, FT_REG,  "i" },
  { "pid",    "pid",     FA_ALL, FT_REG,  "i" },
  { "tgid",    "tgid",     FA_ALL, FT_REG,  "i" },
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "percpu",  	  NULL,  FA_ALL, FT_OPT, NULL },
  { "nodev",      NULL,  FA_ALL, FT_OPT, NULL },
  { "nomapper",   NULL,  FA_ALL, FT_OPT, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mpath_detail", NULL, FA_ALL, FT_OPT, NULL },
  { "bkfname",     "filename",   FA_ALL, FT_REG, "s" },
  { "detail",   "detail (default 1)",    FA_ALL, FT_REG, "i" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "vis",         NULL,   FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t prof_flags[] = {
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { "pid",    "pid",     FA_ALL, FT_REG,  "i" },
  { "tgid",    "tgid",     FA_ALL, FT_REG,  "i" },
  { "cpu",    "cpu",     FA_ALL, FT_REG,  "i" },
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "nsym",   "nsym",    FA_ALL, FT_REG, "i" },
  { "objfile",     "filename",    FA_ALL, FT_REG, "s" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t wait_flags[] = {
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "nsym",   "nsym",    FA_ALL, FT_REG, "i" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t file_flags[] = {
  { "nfile",   "nfile",    FA_ALL, FT_REG, "i" },
  { "scdetail",    NULL,    FA_ALL, FT_OPT, NULL},
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "nosysenter",  NULL,    FA_ALL, FT_OPT, NULL },
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t sock_flags[] = {
  { "nsock",   "nsock",    FA_ALL, FT_REG, "i" },
  { "scdetail",    NULL,    FA_ALL, FT_OPT, NULL},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "nosysenter",  NULL,    FA_ALL, FT_OPT, NULL },
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t futex_flags[] = {
  { "uaddr",     "uaddr",  FA_ALL, FT_REG, "i" },
  { "nfutex",   "nfutex",    FA_ALL, FT_REG, "i" },
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "nosysenter",  NULL,    FA_ALL, FT_OPT, NULL },
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t trace_flags[] = {
  { "pid",    "pid",     FA_ALL, FT_REG,  "i" },
  { "tgid",    "tgid",     FA_ALL, FT_REG,  "i" },
  { "cpu",    "cpu",     FA_ALL, FT_REG,  "i" },
  { "dev",    "dev",     FA_ALL, FT_REG,  "i" },
  { "sysenter",    NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nosysenter",  NULL,    FA_ALL, FT_OPT, NULL },
  { "sysargs",     NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nosysargs",   NULL,    FA_ALL, FT_OPT, NULL },
  { "printcmd",    NULL,    FA_ALL, FT_OPT, NULL },
  { "objfile",     "filename",    FA_ALL, FT_REG, "s" },
  { "nomapper", NULL, FA_ALL, FT_OPT, NULL },
  { "nomarker", NULL, FA_ALL, FT_OPT, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",   "mangle", FA_ALL, FT_OPT, NULL},
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "seqcnt", NULL, FA_ALL, FT_OPT, NULL },
  { "events",		"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 		"subsys", FA_ALL, FT_REG, "s"},
  { "sysignore",        "filename",   FA_ALL, FT_REG, "s" },
  { "pdbfiles",        "filename",   FA_ALL, FT_REG, "s" },
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "msr",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "info",	NULL,     FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "sysconfig",	NULL,     FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t runq_flags[] = {
  { "npid",   "npid",    FA_ALL, FT_REG, "i" },
  { "itime",   "itime",    FA_ALL, FT_REG | FT_HIDDEN, "i" },
  { "rqpid",   "rqpid",    FA_ALL, FT_REG, "i" },
  { "rqwait",   "rqwait",    FA_ALL, FT_REG, "i" },
  { "events",		"default | all | tool | event", FA_ALL, FT_REG, "s"},
  { "subsys", 		"subsys", FA_ALL, FT_REG, "s"},
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "kitrace", 	   NULL,    FA_ALL, FT_OPT, NULL},
  { "abstime", NULL, FA_ALL, FT_OPT, NULL },
  { "fmttime", NULL, FA_ALL, FT_OPT, NULL },
  { "epochtime", NULL, FA_ALL, FT_OPT, NULL },
  { "msr",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t clparse_flags[] = {
  { "top",   "num",    FA_ALL, FT_REG, "i" },
  { "nooracle",    NULL,   FA_ALL, FT_OPT, NULL },
  { "cltree",      NULL,   FA_ALL, FT_OPT, NULL },
  { "csv",         NULL,   FA_ALL, FT_OPT, NULL },
  { "vis",         NULL,   FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nofutex",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",   "mangle", FA_ALL, FT_OPT, NULL},
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

flag_t kiall_flags[] = {
  { "oracle",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "nofutex",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "mangle",  	   NULL,    FA_ALL, FT_OPT, NULL},
  { "csv",	   NULL,    FA_ALL, FT_OPT, NULL },
  { "vis",	   NULL,    FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "vpct",        "vpct",    FA_ALL, FT_OPT | FT_HIDDEN, "i"},
  { "vdepth",      "vdepth",  FA_ALL, FT_OPT | FT_HIDDEN, "i"},
  { "vint",        "vint",    FA_ALL, FT_OPT | FT_HIDDEN, "i"},
  { "hthr",  "num_threads",    FA_ALL, FT_OPT | FT_HIDDEN, "i"},
  { "edus",        "filename", FA_ALL, FT_REG, "s"},
  { "jstack",      "filename", FA_ALL, FT_REG, "s"},
  { "nomerge", NULL, FA_ALL, FT_OPT | FT_HIDDEN, NULL },
  { "nop",		NULL,      FA_ALL, FT_OPT | FT_HIDDEN, NULL },    /* ignore this option */
  { "help",        NULL,   FA_ALL, FT_OPT, NULL },
  { 0,0,0,0,0 }
};

/*
** Option array
*/
option_t otab[] =
{
  { "kitracedump", "dump",  NULL,    dump_flags, OT_CONF,    0, NULL, Kitracedump    },
  { "etldump", "etl",  NULL,    etldump_flags, OT_CONF,    0, NULL, Etldump    },
  { "likidump", "likid",  NULL,    likid_flags, OT_CONF,    0, NULL, Likidump    },
  { "likistart", NULL,  NULL,    likid_flags, OT_CONF,    0, NULL, Likistart    },
  { "likiend", NULL,  NULL,    likiend_flags, OT_CONF,    0, NULL, Likiend    },
  { "likimerge", "likim", NULL,   likim_flags, OT_CONF, 0, NULL, Likimerge },
  { "kparse",    "kp",  NULL,    kparse_flags, OT_CONF,    0, NULL, Kparse    }, 
  { "kitrace",   NULL,  NULL,   trace_flags, OT_CONF,    0, NULL, Kitrace     },
  { "kipid",     NULL,  NULL,    pid_flags , OT_CONF,    0, NULL, Kipid     },
  { "kidsk",     NULL,  NULL,    dsk_flags , OT_CONF,    0, NULL, Kidsk     },
  { "kirunq",    NULL,  NULL,   runq_flags,  OT_CONF,    0, NULL, Kirunq     },
  { "kifile",	 NULL,  NULL,   file_flags, OT_CONF,     0, NULL, Kifile     }, 
  { "kisock",	 NULL,  NULL,   sock_flags, OT_CONF,     0, NULL, Kisock     }, 
  { "kifutex",	 NULL,  NULL,   futex_flags, OT_CONF,     0, NULL, Kifutex    }, 
  { "kiprof",    NULL,  NULL,    prof_flags , OT_CONF,   0, NULL, Kiprof    },
  { "kiwait",    NULL,  NULL,    wait_flags , OT_CONF,   0, NULL, Kiwait    },
  { "kidock",     NULL,  NULL,    dock_flags , OT_CONF,    0, NULL, Kidock     },
  { "kiall",     NULL,  NULL,    kiall_flags, OT_CONF, 0, NULL, Kiall },
  { "kilive",     "live",  NULL,    live_flags , OT_CONF,    0, NULL, Kilive     },
  { "clparse",    "cl",  NULL,    clparse_flags, OT_CONF,    0, NULL, Clparse    }, 
  { "help",      "h",  NULL,    help_flags, OT_CONF,     0, NULL, Usage      },
  { "html",     NULL,  NULL,          NULL, OT_CONF,     0, NULL, Html       },   
  { "timestamp", "ts", " <timestamp>", NULL, OT_CONF | OT_MANARG,   0, "s",  Timestamp  },
  { "starttime", "start", " <time_in_secs>", NULL, OT_CONF | OT_MANARG, 0, "s", Starttime },
  { "endtime", "end", " <time_in_secs>", NULL, OT_CONF | OT_MANARG, 0, "s", Endtime },
  { "alarm",     "a",  " [sec]",      NULL, OT_CONF | OT_OPTARG,   0, "i",  Alarm      },
  { "passes",    "p",  " <count>",    NULL, OT_CONF | OT_MANARG,   0, "i",  Passes     },
  { "nosort",     "ns", NULL, NULL,         OT_CONF | OT_HIDDEN,     0, NULL, Nosort     },
  { "objdump", "sd", NULL,   NULL, OT_CONF | OT_HIDDEN, 0, NULL, Objdump },
  { "Debug",	 "D",  NULL,	NULL,	    OT_CONF | OT_HIDDEN | OT_OPTARG,   0, "i",  Debug      },
  { 0, 0, 0, 0, 0, 0, 0, 0 }  /* End of option list */
};
