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
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "kprint.h"
#include "sort.h"
#include "html.h"
#include "kpmsgcat.h"
#include "msgcat.h"
#include "hash.h"
#include "oracle.h"
#include "FileIo.h"

typedef struct kp_trc_type_args {
        uint64          warnflag;
        int             total_recs;
} kp_trc_type_args_t;

int
kp_warning(warn_t *warning, int indx, char *top)
{
        int msg_idx = warning[indx].idx;

        ANM(SPF(line, "%s%d", _LNK_WARN, indx));
        if (warning[indx].type == WARN) {
                RED_FONT;
                T(warnmsg[msg_idx].msg);
                T(" ");
                if (warnmsg[msg_idx].url) {
                        AERx(warnmsg[msg_idx].url, T("[INFO]"));
                }
                ARFx(SPF(line,"%s%d", _LNK_WARN, indx+1), _MSG_NEXT_NOTE);
                BLACK_FONT;
        } else {
                BOLD(warnmsg[msg_idx].msg);
                T(" ");
                if (top) {
                        ARFx(top, "[Sect]");
                }
                if (warnmsg[msg_idx].url) {
                        AERx(warnmsg[msg_idx].url, T("[INFO]"));
                }
                ARFx(SPF(line,"%s%d", _LNK_WARN, indx+1), _MSG_NEXT_NOTE);
        }

        return 0;
}

void
print_cmdline()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	int warn_indx;

	sprintf (fname, "cmdline.%s", timestamp);
        if ( (f = fopen(fname, "r")) == NULL) {
                return;
        }

	ANM(_LNK_0_1_0);
        rtnptr = fgets((char *)&input_str, 511, f);
        while (rtnptr != NULL) {
		printf ("%s", input_str); 

		if (strstr(input_str, "numa=off")) {
                	warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_NUMA_OFF, _LNK_0_1_0);
                	kp_warning(globals->warnings, warn_indx, _LNK_0_1_0); NL;
		}

                rtnptr = fgets((char *)&input_str, 511, f);
        }

	fclose(f);
}

void
print_mem_info()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	int i;
	char  varname[30];
	int	hp_anon_kb, hp_total, hp_free, hp_used, hp_pagesize;

	if (is_alive) {
		sprintf (fname, "/proc/meminfo");
	} else {
		sprintf(fname, "mem_info.%s", timestamp);
	}
	
        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname,  errno);
                fprintf (stderr, "Continuing without memory info.\n");
                return;
        }

	i = 0;
        rtnptr = fgets((char *)&input_str, 127, f);
        while (rtnptr != NULL) {
		/* print 1st 4 lines */
		if (i < 4) printf ("%s", input_str); 
	
		if (strncmp(input_str, "AnonHugePages", 13) == 0) {
			sscanf (input_str, "%s %d", varname, &hp_anon_kb);
		} else if (strncmp(input_str, "HugePages_Total", 15) == 0) { 
			sscanf (input_str, "%s %d", varname, &hp_total);
		} else if (strncmp(input_str, "HugePages_Free", 14) == 0) { 
			sscanf (input_str, "%s %d", varname, &hp_free);
		} else if (strncmp(input_str, "Hugepagesize", 12) == 0) { 
			sscanf (input_str, "%s %d", varname, &hp_pagesize);
		}
		
		i++;
                rtnptr = fgets((char *)&input_str, 127, f);
        }

	printf ("HugePages: %7d  %9d  %9d",
		hp_total, hp_total - hp_free, hp_free); NL;
	printf ("Hugepagesize : %7d kb", hp_pagesize); NL;
	printf ("AnonHugePages: %7d kb", hp_anon_kb); NL;

	fclose (f);
}

void 
kp_sys_summary ()
{
	int warn_indx;

	if (debug) printf ("kp_sys_summary\n");
	
	HR;
	ITALIC_U("basic system info"); NL;
	if (globals->hostname) { BOLD("Hostname        : %s", globals->hostname); NL; }
	if (globals->os_vers) { BOLD("OS version      : %s", globals->os_vers); NL; }
	if (globals->model) { BOLD("Model           : %s", globals->model); NL; }

	if (globals->VM_guest) { BOLD("Virtual Machine Guest"); NL; }

	BOLD("Physical cores  : %d", globals->ncpu); NL;
	if (globals->HT_enabled) { BOLD("Logical cores   : %d", globals->nlcpu); NL; }
	if (globals->nldom > 0) { BOLD("Sockets         : %d", globals->nldom); NL; }

	if (globals->memkb) { BOLD("Memory (GB)     : %d", globals->memkb / (1024*1024)); NL; }

	if (globals->SNC_enabled) { BOLD("Sub-NUMA Cluster enabled"); NL; }

	if (!IS_WINKI) {
		NL;
		print_cmdline(); NL;
		print_mem_info(); NL;

		ANM(_LNK_0_2_0);
		BOLD("Side-Channel Attack (Spectre/Meltdown) Mitigations:"); NL;
		parse_scavuln(1);

		if (globals->scavuln == SCA_MITIGATED) {
                	warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SCA_VULN, _LNK_0_2_0);
                	kp_warning(globals->warnings, warn_indx, _LNK_0_2_0); T("\n");
        	}
	}
}

void kp_toc()
{	
	hc_info_t *hcinfop = globals->hcinfop;
	HR;
	BLUE_TABLE;
	ANM(_LNK_TOC);
	HEAD3(_MSG_TOC);
	_TABLE;

	NLt;
 	UL; LI; RED_FONT; T(_MSG_LINK); T(" "); ARFx(SPF(line,"%s%d", _LNK_WARN, 0), _MSG_NEXT_NOTE); BLACK_FONT; _UL; NLt;
	T(_MSG_LINK_INFO); NLt;

	UL;
	  LI; ARF(_LNK_1_0, _MSG_1_0); NLt;
	  UL;
	    LI; ARF(_LNK_1_1, _MSG_1_1); NLt;
 	    UL;
	      LI; ARF(_LNK_1_1_1, _MSG_1_1_1); NLt;
	      if (globals->nldom) { LI; ARF(_LNK_1_1_2, _MSG_1_1_2); NLt }
	      if (globals->powerp) {LI; ARF(_LNK_1_1_3, _MSG_1_1_3); NLt }
	      if (globals->HT_enabled) { LI; ARF(_LNK_1_1_4, _MSG_1_1_4); NLt }
 	    _UL;
	    LI; ARF(_LNK_1_2, _MSG_1_2); NLt;
	    UL;
              LI; ARF(_LNK_1_2_1, _MSG_1_2_1); NLt;
              LI; ARF(_LNK_1_2_2, _MSG_1_2_2); NLt;
	      if (STEAL_ON) { LI; ARF(_LNK_1_2_3, _MSG_1_2_3); NLt; }
            _UL;
	    LI; ARF(_LNK_1_3, _MSG_1_3); NLt;
	    UL;
              LI; ARF(_LNK_1_3_1, _MSG_1_3_1); NLt;
              LI; ARF(_LNK_1_3_2, _MSG_1_3_2); NLt;
              if (kparse_full) LI; ARF(_LNK_1_3_3, _MSG_1_3_3); NLt;
	    _UL;
	    LI; ARF(_LNK_1_4, _MSG_1_4); NLt;
            if (hcinfop && hcinfop->total) {
	    UL;
              LI; ARF(_LNK_1_4_1, _MSG_1_4_1); NLt;
              LI; ARF(_LNK_1_4_2, _MSG_1_4_2); NLt;
              LI; ARF(_LNK_1_4_3, _MSG_1_4_3); NLt;
              if (kparse_full) { LI; ARF(_LNK_1_4_4, _MSG_1_4_4); NLt; } 
              if (kparse_full) { LI; ARF(_LNK_1_4_5, _MSG_1_4_5); NLt; } 
	    _UL;
	    }
	    LI; ARF(_LNK_1_5, _MSG_1_5); NLt;
	    if (globals->irqp || globals->softirqp) {
	      LI; ARF(_LNK_1_6, _MSG_1_6); NLt;
	      UL;
                LI; ARF(_LNK_1_6_1, _MSG_1_6_1); NLt;
                LI; ARF(_LNK_1_6_2, _MSG_1_6_2); NLt;
                LI; ARF(_LNK_1_6_3, _MSG_1_6_3); NLt;
	      _UL;
	    }
	  _UL;

	  LI; ARF(_LNK_2_0, _MSG_2_0); NLt;
	  UL;
            LI; ARF(_LNK_2_1, _MSG_2_1); NLt;
	    UL;
              LI; ARF(_LNK_2_1_1, _MSG_2_1_1); NLt;
              LI; ARF(_LNK_2_1_2, _MSG_2_1_2); NLt;
              LI; ARF(_LNK_2_1_3, _MSG_2_1_3); NLt;
	      if (kparse_full)  { LI; ARF(_LNK_2_1_4, _MSG_2_1_4); NLt; }
            _UL;
            LI; ARF(_LNK_2_2, _MSG_2_2); NLt;
	    UL;
              LI; ARF(_LNK_2_2_1, _MSG_2_2_1); NLt;
              LI; ARF(_LNK_2_2_2, _MSG_2_2_2); NLt;
            _UL;
	    if (!IS_WINKI) {
	    	LI; ARF(_LNK_2_3, _MSG_2_3); NLt;
            	UL;
              	LI; ARF(_LNK_2_3_1, _MSG_2_3_1); NLt;
              	LI; ARF(_LNK_2_3_2, _MSG_2_3_2); NLt;
            	_UL;
	    }
	  _UL;

	  LI; ARF(_LNK_3_0, _MSG_3_0); NLt;
	  UL;
	    if (IS_WINKI) {
              LI; ARF(_LNK_3_1, _MSG_3_1_WIN); NLt;
              LI; ARF(_LNK_3_2, _MSG_3_2_WIN); NLt;
	    } else {
              LI; ARF(_LNK_3_1, _MSG_3_1); NLt;
              LI; ARF(_LNK_3_2, _MSG_3_2); NLt;
              LI; ARF(_LNK_3_3, _MSG_3_3); NLt;
              if (kparse_full) LI; ARF(_LNK_3_4, _MSG_3_4); NLt;
	    }
	  _UL;
	  
	  LI; ARF(_LNK_4_0, _MSG_4_0); NLt;
	  UL;
	    LI; ARF(_LNK_4_1, _MSG_4_1); NLt;
	    LI; ARF(_LNK_4_2, _MSG_4_2); NLt;
	    UL;
              LI; ARF(_LNK_4_2_1, _MSG_4_2_1); NLt;
              LI; ARF(_LNK_4_2_2, _MSG_4_2_2); NLt;
              LI; ARF(_LNK_4_2_3, _MSG_4_2_3); NLt;
              LI; ARF(_LNK_4_2_4, _MSG_4_2_4); NLt;
              LI; ARF(_LNK_4_2_5, _MSG_4_2_5); NLt;
              LI; ARF(_LNK_4_2_6, _MSG_4_2_6); NLt;
            _UL;
	    if (!IS_WINKI) {
	    	LI; ARF(_LNK_4_3, _MSG_4_3); NLt;
	    	  UL;
              	  LI; ARF(_LNK_4_3_1, _MSG_4_3_1); NLt;
              	  LI; ARF(_LNK_4_3_2, _MSG_4_3_2); NLt;
	    	  _UL;
	    	LI; ARF(_LNK_4_4, _MSG_4_4); NLt;
	    	LI; ARF(_LNK_4_5, _MSG_4_5); NLt;
	    	LI; ARF(_LNK_4_6, _MSG_4_6); NLt;
	    }
	    LI; ARF(_LNK_4_7, _MSG_4_7); NLt;
	    if (!IS_WINKI) {
	    	if (dskblk_stats) {
			LI; ARF(_LNK_4_8, _MSG_4_8); NLt;
			LI; ARF(_LNK_4_9, _MSG_4_9); NLt;
		}
		LI; ARF(_LNK_4_10, _MSG_4_10); NLt;
	    }
	  _UL;

	  LI; ARF(_LNK_5_0, _MSG_5_0); NLt;
	  UL;
	    LI; ARF(_LNK_5_1, _MSG_5_1); NLt;
	    LI; ARF(_LNK_5_2, _MSG_5_2); NLt;
	    LI; ARF(_LNK_5_3, _MSG_5_3); NLt;
	    LI; ARF(_LNK_5_4, _MSG_5_4); NLt;
	    LI; ARF(_LNK_5_5, _MSG_5_5); NLt;
	    LI; ARF(_LNK_5_6, _MSG_5_6); NLt;
	    if (IS_WINKI) {
		    LI; ARF(_LNK_5_7, _MSG_5_7); NLt; 
	    }
	  _UL;

	  if (!IS_WINKI) {
	    LI; ARF(_LNK_6_0, _MSG_6_0); NLt;
	    UL;
	      LI; ARF(_LNK_6_1, _MSG_6_1); NLt;
	      if (IS_LIKI_V2_PLUS) {
	        LI; ARF(_LNK_6_2, _MSG_6_2); NLt;
	        LI; ARF(_LNK_6_3, _MSG_6_3); NLt;
	      }
	    _UL;

	    if (next_sid > 1) {
              LI; ARF(_LNK_7_0, _MSG_7_0); NLt;
	      UL;	
                LI; ARF(_LNK_7_1, _MSG_7_1); NLt;
                LI; ARF(_LNK_7_2, _MSG_7_2); NLt;
                LI; ARF(_LNK_7_3, _MSG_7_3); NLt;
                LI; ARF(_LNK_7_4, _MSG_7_4); NLt;
                LI; ARF(_LNK_7_5, _MSG_7_5); NLt;
                LI; ARF(_LNK_7_6, _MSG_7_6); NLt;
                LI; ARF(_LNK_7_7, _MSG_7_7); NLt;
	      _UL;
	    }

	    if (globals->docker_hash) {
  	      LI; ARF(_LNK_8_0, _MSG_8_0); NLt;
	      UL;	
                LI; ARF(_LNK_8_1, _MSG_8_1); NLt;
                LI; ARF(_LNK_8_2, _MSG_8_2); NLt;
                LI; ARF(_LNK_8_3, _MSG_8_3); NLt;
	      _UL;
	    }
	  }

  	  LI; ARF(_LNK_9_0, _MSG_9_0); NLt;
	  if (HTML) {
	    UL;	
              LI; ARF(_LNK_9_1, _MSG_9_1); NLt;
              LI; ARF(_LNK_9_2, _MSG_9_2); NLt;
              LI; ARF(_LNK_9_3, _MSG_9_3); NLt;
              if (vis) { LI; ARF(_LNK_9_4, _MSG_9_4); NLt; }
	    _UL;
	  }

          LI; ARF(_LNK_10_0, _MSG_10_0); NLt;
	_UL;
}

void
kp_whats_it_doing()			/* Section 1.0 */
{
	HR; 
	BLUE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_0);
        HEAD2(_MSG_1_0); 
        FONT_SIZE(-1);
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	PRE;

	return;
}
	
void
kp_global_cpu()				/* Section 1.1 */
{
        uint64  warnflag = 0;
        int warn_indx;

        GREEN_TABLE;
        TEXT("\n");
        ANM(_LNK_1_1);
        HEAD3(_MSG_1_1); 
        FONT_SIZE(-1);
        ARFx(_LNK_1_1_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (cluster_flag) BOLD("Server           ");
	BOLD("    nCPU          sys%%        user%%        idle%%");
	if (gbl_irq_time) BOLD("  hardirq_sys hardirq_user hardirq idle  softirq_sys softirq_user softirq_idle");
	if (STEAL_ON) BOLD("   stealbusy%%   stealidle%%");
	if (msr_flag) BOLD ("  LLC_hit%%    CPI   Avg_MHz  SMI_cnt");
	NL;

	print_global_cpu_stats(globals, &warnflag);
        if (warnflag & WARNF_CPU_BOTTLENECK) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_CPU_BOTTLENECK, _LNK_1_1);
                kp_warning(globals->warnings, warn_indx, _LNK_1_1); NL;
        }

	return;
}

void
kp_per_cpu_usage()			/* Section 1.1.1 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        TEXT("\n");
        ANM(_LNK_1_1_1);
        HEAD3(_MSG_1_1_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_1,"[Prev Subsection]");

        if (globals->nldom) {
                ARFx(_LNK_1_1_2,"[Next Subsection]");
	} else if (globals->powerp) {
                ARFx(_LNK_1_1_3,"[Next Subsection]");
	} else if (globals->HT_enabled) {
                ARFx(_LNK_1_1_4,"[Next Subsection]");
        } else {
                ARFx(_LNK_1_2,"[Next Subsection]");
        }

        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        print_percpu_stats(&warnflag);
	CSV_FIELD("kirunq", "[CSV]");

	if (warnflag & WARNF_STEALTIME) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_STEALTIME, _LNK_1_1_1);
                kp_warning(globals->warnings, warn_indx, _LNK_1_1_1); NL;
        }
		
	return;
}

void
kp_per_ldom_usage()			/* Section 1.1.2 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_1_2);
        HEAD3(_MSG_1_1_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_1_1,"[Prev Subsection]");
	if (globals->powerp) {
                ARFx(_LNK_1_1_3,"[Next Subsection]");
        } else if (globals->HT_enabled) {
                ARFx(_LNK_1_1_4,"[Next Subsection]");
        } else {
                ARFx(_LNK_1_2,"[Next Subsection]");
        }
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	print_perldom_stats(NULL);
	CSV_FIELD("kirunq", "[CSV]");
}

void kp_power_report()			/* Section 1.1.3 */
{
        uint64 warnflag = 0ull;
        int warn_indx=0;

        ORANGE_TABLE;
        ANM(_LNK_1_1_3);
        HEAD3(_MSG_1_1_3);
        FONT_SIZE(-1);
        if (globals->nldom) {
                ARFx(_LNK_1_1_2,"[Prev Subsection]");
        } else {
                ARFx(_LNK_1_1_1,"[Prev Subsection]");
	}
        if (globals->HT_enabled) {
                ARFx(_LNK_1_1_4,"[Next Subsection]");
        } else {
                ARFx(_LNK_1_2,"[Next Subsection]");
        }
        ARFx(_LNK_1_0,"---[Prev Section]"); 
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	if (globals->powerp) {
		print_cstate_stats(&warnflag);
		CSV_FIELD("kirunq", "[CSV]");

		if (warnflag & WARNF_POWER) {
                	warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_POWER, _LNK_1_1_3);
                	kp_warning(globals->warnings, warn_indx, _LNK_1_1_3); NL;
		}
	} else { 
		BOLD("No Power Events Captured"); NL;
	}
}

void
kp_HT_usage()				/* Section 1.1.4 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_1_4);
        HEAD3(_MSG_1_1_4);
        FONT_SIZE(-1);
	if (globals->powerp) {
                ARFx(_LNK_1_1_3,"[Prev Subsection]");
        } else if (globals->nldom) {
                ARFx(_LNK_1_1_2,"[Prev Subsection]");
        } else {
                ARFx(_LNK_1_1_1,"[Prev Subsection]");
        }

        ARFx(_LNK_1_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        print_HT_report(NULL); 
}

void
kp_busy_pids()				/* Section 1.2 */
{

        GREEN_TABLE;
        ANM(_LNK_1_2);
        HEAD3(_MSG_1_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_1,"[Prev Subsection]");
        ARFx(_LNK_1_2_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_top_pids_runtime()			/* Section 1.2.1 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_2_1);
        HEAD3(_MSG_1_2_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_2,"[Prev Subsection]");
        ARFx(_LNK_1_2_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	npid=10;
        print_runtime_pids(&warnflag);
	CSV_FIELD("kipid", "[CSV]");

	return;
}

void
kp_top_pids_systime()			/* Section 1.2.2 */
{
        ORANGE_TABLE;
        ANM(_LNK_1_2_2);
        HEAD3(_MSG_1_2_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_2_1,"[Prev Subsection]");
	if (STEAL_ON) { ARFx(_LNK_1_2_3,"[Next Subsection]"); }
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	npid=10;
        print_systime_pids(NULL);
	CSV_FIELD("kipid", "[CSV]");

	return;
}

void
kp_top_pids_stealtime()			/* Section 1.2.3 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_2_3);
        HEAD3(_MSG_1_2_3);
        FONT_SIZE(-1);
        ARFx(_LNK_1_2_2,"[Prev Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	npid=10;
        print_stealtime_pids(NULL);
	CSV_FIELD("kipid", "[CSV]");

	return;
}

void
kp_trace_types()			/* Section 1.3 */
{
        kp_trc_type_args_t trctyp_arg;
        int warn_indx;

        GREEN_TABLE;
        ANM(_LNK_1_3);
        HEAD3(_MSG_1_3); 
        FONT_SIZE(-1);
        ARFx(_LNK_1_2,"[Prev Subsection]");
        ARFx(_LNK_1_3_1,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
kp_trc_type (void *arg1, void *arg2)
{
        trc_info_t *trcp = (trc_info_t *)arg1;
        kp_trc_type_args_t *trctyp_argp = (kp_trc_type_args_t *)arg2;
        syscall_stats_t *syscall_statsp = trcp->syscall_statsp;
        uint64  key, syscallno, mode, id, ftype;
        int i, total_traces;
	char ftypestr[80];
	short *syscall_index;

        total_traces = trctyp_argp->total_recs;

        if (trcp == NULL) {
                BOLD("No Trace Types Logged"); BR;
                return 0;
        }
        key = trcp->lle.key;
        id = TRC_ID(key);
	ftype = TRC_FSTYPE(key);
        syscallno = TRC_SYSCALLNO(key);
        mode = TRC_MODE(key);

        SPAN_GREY;

	syscall_index = (mode == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64;

        if (syscall_statsp) {
		if ((trctyp_argp->warnflag == 0) && strstr("semget", syscall_arg_list[syscall_index[syscallno]].name) && (syscall_statsp->errors > 100)) {
			RED_FONT;
			trctyp_argp->warnflag |= WARNF_SEMGET;
		}

		if ((trctyp_argp->warnflag == 0) && strstr("poll", syscall_arg_list[syscall_index[syscallno]].name) && 
		    (syscall_statsp->count > 10000) && ((syscall_statsp->total_time / syscall_statsp->count) < 2000)) {
			RED_FONT;
			trctyp_argp->warnflag |= WARNF_ORACLE_POLL;
		}

                if (ftype) 
                        sprintf (ftypestr, "%s (%s)", syscall_arg_list[syscall_index[syscallno]].name, ftype_name_index[ftype]);
                else 
                        sprintf (ftypestr, "%s", syscall_arg_list[syscall_index[syscallno]].name);

                printf("%-8d %6.2f%%  %-30s %4d %11.3f %9.4f %9.6f %9d",
                trcp->count,
                (trcp->count*100.0) / (total_traces*1.0), 
                ftypestr,
		mode,
                SECS(syscall_statsp->total_time),
                SECS(syscall_statsp->max_time),
                SECS(syscall_statsp->total_time) / (trcp->count*1.0), syscall_statsp->errors);
		BLACK_FONT;
        } else {
                printf("%-8d %6.2f%%  %-77s",
                        trcp->count,
                        (trcp->count*100.0) / (total_traces*1.0),
		        ki_actions[id].event);

        }
        if ((lineno & 0x1) == 0) _SPAN;
	NL;

        lineno++;

        return 0;

}

void
kp_global_trace_types()			/* Section 1.3.1 */
{
        kp_trc_type_args_t trctyp_arg;
	int		warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_3_1);
        HEAD3(_MSG_1_3_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_3,"[Prev Subsection]");
        ARFx(_LNK_1_3_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("Freq     Percent  Trace_type                    64bit    ElapsedT       Max       Ave    Errors"); NL;

        trctyp_arg.total_recs = globals->total_traces;
        trctyp_arg.warnflag = 0ull;
        foreach_hash_entry((void **)globals->trc_hash, TRC_HASHSZ, kp_trc_type, trc_sort_by_count, 30, &trctyp_arg);
        printf ("Total Traces %d", globals->total_traces); NL;

	/* Warn if processes do excessive SEMGET calls */
	if (trctyp_arg.warnflag & WARNF_SEMGET) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SEMGET, _LNK_1_3_1);
		kp_warning(globals->warnings, warn_indx, _LNK_1_3_1); NL;
	}

}

int
kp_pid_freq(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        uint64 *warnflagp = (uint64 *)arg2;

        SPAN_GREY;

        PID_URL_FIELD8(pidp->PID);
        printf ("    %9d     %-48s",
                pidp->num_tr_recs,
                pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	NL;

        if ((lineno & 0x1) == 0) _SPAN;
        lineno++;

	return 0;
}

void
kp_top_pid_trace_counts()		/* Section 1.3.2 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_3_2);
        HEAD3(_MSG_1_3_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_3_1,"[Prev Subsection]");
        if (kparse_full) {
                ARFx(_LNK_1_3_3,"[Next Subsection]");
        } else {
                ARFx(_LNK_1_4,"[Next Subsection]");
        }
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("%s         Frequency     Command", tlabel); NL;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, kp_pid_freq, pid_sort_by_trace_recs, 20, &warnflag);

}

int
kp_pid_traces(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        kp_trc_type_args_t *trctyp_arg = arg2;
        kp_trc_type_args_t local_trctyp_arg;
        uint64  warnflag = 0;
        int warn_indx;

        CAPTION_GREY;
        BOLD("Analyzing Pid: ");
        PID_URL_FIELD8(pidp->PID);
	BOLD ("Trace Records: ");
	printf ("%-8d ", pidp->num_tr_recs); 
        BOLD("cmd: ");
        printf("%s ", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
        _CAPTION;

        BOLD("Freq     Percent  Trace_type                    64bit    ElapsedT       Max       Ave    Errors"); NL;

        lineno=0;

        local_trctyp_arg.total_recs = pidp->num_tr_recs;
        local_trctyp_arg.warnflag = 0ull;
        foreach_hash_entry((void **)pidp->trc_hash, TRC_HASHSZ, kp_trc_type, trc_sort_by_count, 15, &local_trctyp_arg);
        if ((local_trctyp_arg.warnflag & WARNF_SEMGET) && (strstr(pidp->cmd, "dw.") || strstr(pidp->cmd, "work"))) {
		trctyp_arg->warnflag |= WARNF_SEMGET;
	}
        if ((local_trctyp_arg.warnflag & WARNF_ORACLE_POLL) && ((strncmp(pidp->cmd, "oracle", 6) == 0))) {
		trctyp_arg->warnflag |= WARNF_ORACLE_POLL;
	}

        return 0;
}

void
kp_top_pid_trace_types()		/* Section 1.3.3 */
{
        kp_trc_type_args_t trctyp_arg;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_3_3);
        HEAD3(_MSG_1_3_3);
        FONT_SIZE(-1);
        ARFx(_LNK_1_3_2,"[Prev Subsection]");
        ARFx(_LNK_1_4,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	trctyp_arg.warnflag = 0;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, kp_pid_traces, pid_sort_by_trace_recs, 10, &trctyp_arg);
	/* Warn if SAP disp+work processes do excessive SEMGET calls */
	if (trctyp_arg.warnflag & WARNF_SEMGET) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SEMGET, _LNK_1_3_3);
		kp_warning(globals->warnings, warn_indx, _LNK_1_3_3); NL;
	}

	/* Warn if oracle processes do excessive poll() calls */
	if (trctyp_arg.warnflag & WARNF_ORACLE_POLL) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_ORACLE_POLL, _LNK_1_3_3);
		kp_warning(globals->warnings, warn_indx, _LNK_1_3_3); NL;
	}


}

void
kp_hardclocks()				/* Section 1.4 */
{
	hc_info_t *hcinfop = globals->hcinfop;

        GREEN_TABLE;
        ANM(_LNK_1_4);
        HEAD3(_MSG_1_4);
        FONT_SIZE(-1);
        if (hcinfop && hcinfop->total) {
        	ARFx(_LNK_1_3,"[Prev Subsection]");
        	ARFx(_LNK_1_4_1,"[Next Subsection]");
        	ARFx(_LNK_1_0,"---[Prev Section]");
        	ARFx(_LNK_2_0,"[Next Section]");
        	ARFx(_LNK_TOC,"[Table of Contents]");
	} else {
        	ARFx(_LNK_1_3,"[Prev Subsection]");
        	ARFx(_LNK_1_5,"[Next Subsection]");
        	ARFx(_LNK_1_0,"---[Prev Section]");
        	ARFx(_LNK_2_0,"[Next Section]");
        	ARFx(_LNK_TOC,"[Table of Contents]");
	}
        _TABLE;
        TEXTx("\n");

        if (hcinfop && hcinfop->total) {
        	printf("%s", _MSG_1_4_INFO); NL;
	} else {
		BOLD ("No Hardclock Entries Found"); NL;
	}
}

void
kp_cpustates()				/* Section 1.4.1 */
{
        hc_info_t *hcinfop;

        ORANGE_TABLE;
        ANM(_LNK_1_4_1);
        HEAD3(_MSG_1_4_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_3_3,"[Prev Subsection]");
        ARFx(_LNK_1_4_2,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        hcinfop = globals->hcinfop;

	if (hcinfop && hcinfop->total && hcinfop->pc_hash) {
		BOLD ("  Count   USER%%    SYS%%   INTR%%   IDLE%%"); NL;
		prof_print_summary(hcinfop);
		NL;
	} else {
                BOLD("No Hardclock Entries Found"); NL;
        }
}

void
kp_hc_bycpu()		   		/* Section 1.4.2 */
{

        int i;
        cpu_info_t *cpuinfop;
        hc_info_t *hcinfop;
        uint64 total;

        ORANGE_TABLE;
        ANM(_LNK_1_4_2);
        HEAD3(_MSG_1_4_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4_1,"[Prev Subsection]");
        ARFx(_LNK_1_4_3,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        hcinfop = globals->hcinfop;
	if (hcinfop && hcinfop->total && hcinfop->pc_hash) {
		lineno=0;
		BOLD ("    CPU   Count   USER%%    SYS%%   INTR%%   IDLE%%"); NL;
        	prof_print_percpu_summary(hcinfop);
	} else {
                BOLD("No Hardclock Entries Found"); NL;
        }
}

void
kp_hc_kernfuncs()			/* Section 1.4.3 */
{
        hc_info_t *hcinfop;
	print_pc_args_t print_pc_args;
	int warn_indx;
	uint64 warnflag = 0;

        ORANGE_TABLE;
        ANM(_LNK_1_4_3);
        HEAD3(_MSG_1_4_3);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4_2,"[Prev Subsection]");
        if (kparse_full) {
                ARFx(_LNK_1_4_4,"[Next Subsection]");
        } else {
                ARFx(_LNK_1_5,"[Next Subsection]");
        }
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        hcinfop = globals->hcinfop;
        print_pc_args.hcinfop = hcinfop;
        print_pc_args.warnflagp = &warnflag;
	print_pc_args.pidfile = NULL;

	if (hcinfop && hcinfop->total && hcinfop->pc_hash) {
        	BOLD("   Count     Pct  State  Function "); NL;
		lineno=0;
        	foreach_hash_entry((void **)hcinfop->pc_hash, PC_HSIZE, hc_print_pc2, pc_sort_by_count, 40, (void *)&print_pc_args);
	} else {
                BOLD("No Hardclock Entries Found"); NL;
        }

	if ((*print_pc_args.warnflagp) & WARNF_SEMLOCK) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SEMLOCK, _LNK_1_4_3);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_3); NL;
	}

	if ((*print_pc_args.warnflagp) & WARNF_SK_BUSY) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SK_BUSY, _LNK_1_4_3);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_3); NL;
	}
}

extern int pc_queued_spin_lock_slowpath;
extern int pc_semctl;
extern int pc_rwsem_down_write_failed;

void
kp_hc_stktraces()			/* Section 1.4.4 */
{
        hc_info_t *hcinfop;
	print_pc_args_t print_pc_args;
        int warn_indx;
	uint64 warnflag = 0;

        ORANGE_TABLE;
        ANM(_LNK_1_4_4);
        HEAD3(_MSG_1_4_4);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4_3,"[Prev Subsection]");
        ARFx(_LNK_1_4_5,"[Next Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        hcinfop = globals->hcinfop;
        print_pc_args.hcinfop = hcinfop;
        print_pc_args.warnflagp = &warnflag;
	print_pc_args.pidfile = NULL;
	if (hcinfop && hcinfop->total && hcinfop->pc_hash) {
        	BOLD("   Count     Pct  Stack trace"); NL;
        	foreach_hash_entry((void **)hcinfop->hc_stktrc_hash, STKTRC_HSIZE, hc_print_stktrc, stktrc_sort_by_cnt, 50, (void *)&print_pc_args);
	} else {
                BOLD("No Hardclock Entries Found"); NL;
        }

	if ((*print_pc_args.warnflagp) & WARNF_SEMLOCK) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_SEMLOCK, _LNK_1_4_4);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_4); NL;
	}

	if ((*print_pc_args.warnflagp) & WARNF_HUGETLB_FAULT) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_HUGETLB_FAULT, _LNK_1_4_4);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_4); NL;
	}

	if ((*print_pc_args.warnflagp) & WARNF_KSTAT_IRQS) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_KSTAT_IRQS, _LNK_1_4_4);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_4); NL;
	}

	if ((*print_pc_args.warnflagp) & WARNF_PCC_CPUFREQ) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_PCC_CPUFREQ, _LNK_1_4_4);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_4); NL;
	}

	if ((*print_pc_args.warnflagp) & WARNF_KVM_PAGEFAULT) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_KVM_PAGEFAULT, _LNK_1_4_4);
		kp_warning(globals->warnings, warn_indx, _LNK_1_4_4); NL;
	}
}

void
kp_hc_funcbypid()			/* Section 1.4.5 */
{
        hc_info_t *hcinfop;
        uint64  total;

        ORANGE_TABLE;
        ANM(_LNK_1_4_5);
        HEAD3(_MSG_1_4_5);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4_4,"[Prev Subsection]");
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        hcinfop = globals->hcinfop;
	if (hcinfop && hcinfop->total && hcinfop->pc_hash) {
	        total = hcinfop->total;
	        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ,
                           (int (*)(void *, void *))print_pid_symbols,
                                   pid_sort_by_hc,
                                   5, (void *)&total);
	} else {
                BOLD("No Hardclock Entries Found"); NL;
        }
}

void 
kp_th_detection()			/* Section 1.5 */
{
        uint64 warnflag = 0ull;
        int warn_indx=0;

        GREEN_TABLE;
        ANM(_LNK_1_5);
        HEAD3(_MSG_1_5);
        FONT_SIZE(-1);
        ARFx(_LNK_1_4,"[Prev Subsection]"); 
	if (globals->irqp || globals->softirqp) {
        	ARFx(_LNK_1_6,"[Next Subsection]"); 
	}
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

        BOLD("%s       Wakeups MaxWakeups    Count     TimeStamp  cmd", tlabel); NL;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_wakeup_pids, pid_sort_by_wakeups, 10, NULL);
}

void 
kp_irq()				/* Section 1.6 */
{
        GREEN_TABLE;
        ANM(_LNK_1_6);
        HEAD3(_MSG_1_6);
        FONT_SIZE(-1);
        ARFx(_LNK_1_5,"[Prev Subsection]"); 
        ARFx(_LNK_1_6_1,"[Next Subsection]"); 
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
}

void 
kp_hardirqs()				/* Section 1.6.1 */
{
        ORANGE_TABLE;
        ANM(_LNK_1_6_1);
        HEAD3(_MSG_1_6_1);
        FONT_SIZE(-1);
        ARFx(_LNK_1_6,"[Prev Subsection]"); 
        ARFx(_LNK_1_6_2,"[Next Subsection]"); 
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	print_global_hardirq_stats(NULL);
}

void 
kp_hardirqs_by_cpu()			/* Section 1.6.2 */
{
        ORANGE_TABLE;
        ANM(_LNK_1_6_2);
        HEAD3(_MSG_1_6_2);
        FONT_SIZE(-1);
        ARFx(_LNK_1_6_1,"[Prev Subsection]"); 
        ARFx(_LNK_1_6_3,"[Next Subsection]"); 
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	print_percpu_irq_stats(HARDIRQ);
}

void 
kp_softirqs()				/* Section 1.6.3 */
{
        uint64  warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_1_6_3);
        HEAD3(_MSG_1_6_3);
        FONT_SIZE(-1);
        ARFx(_LNK_1_6_2,"[Prev Subsection]"); 
        ARFx(_LNK_1_0,"---[Prev Section]");
        ARFx(_LNK_2_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	print_global_softirq_stats(&warnflag);
        if (warnflag & WARNF_TASKLET) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_TASKLET, _LNK_1_6_3);
                kp_warning(globals->warnings, warn_indx, _LNK_1_6_3); NL;
	}

        if (warnflag & WARNF_ADD_RANDOM) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_ADD_RANDOM, _LNK_1_6_3);
                kp_warning(globals->warnings, warn_indx, _LNK_1_6_3); NL;
	}
}

void
kp_whats_it_waiting_for()      		/* Section 2.0 */
{

        HR;
        BLUE_TABLE;
        ANM(_LNK_2_0);
        HEAD2(_MSG_2_0);
        FONT_SIZE(-1);
        ARFx(_LNK_1_0,"[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_swtch_reports()          		/* Section 2.1 */
{
        GREEN_TABLE;
        ANM(_LNK_2_1);
        HEAD3(_MSG_2_1);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_freq_swtch_funcs()          		/* Section 2.1.1 */
{
        uint64  warnflag = 0;
        int warn_indx;
        sched_info_t *schedp = globals->schedp;
	var_arg_t vararg;

        ORANGE_TABLE;
        ANM(_LNK_2_1_1);
        HEAD3(_MSG_2_1_1);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1,"[Prev Subsection]");
        ARFx(_LNK_2_1_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (schedp == NULL) return ;
        if (globals->slp_hash == NULL) return;

        lineno=1;
        BOLD("   Count     Pct    SlpTime  SlpPct   Msec/Slp   MaxMsecs  Func"); NL;
	vararg.arg1 = NULL;
	vararg.arg2 = &schedp->sched_stats;
	foreach_hash_entry_l((void **)globals->slp_hash, SLP_HSIZE, print_slp_info, slp_sort_by_count, 30, &vararg);
}

void
kp_freq_swtch_stktrc()          	/* Section 2.1.2 */
{
        int warn_indx;
	print_stktrc_args_t print_stktrc_args;
	var_arg_t vararg;

        ORANGE_TABLE;
        ANM(_LNK_2_1_2);
        HEAD3(_MSG_2_1_2);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1_1,"[Prev Subsection]");
        ARFx(_LNK_2_1_3,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (globals->schedp == NULL) return ;
        if (globals->stktrc_hash == NULL) return;

        print_stktrc_args.schedp = globals->schedp;
	print_stktrc_args.warnflag = 0;
	
	vararg.arg1 = NULL;
	vararg.arg2 = &print_stktrc_args;

        lineno=1;

        BOLD("   count   wpct       avg   Stack trace"); NL;
        BOLD("              %%     msecs              "); NL;
        BOLD("============================================================\n");
        foreach_hash_entry((void **)globals->stktrc_hash, STKTRC_HSIZE, print_stktrc_info, stktrc_sort_by_cnt, 30, (void *)&vararg);

	if (print_stktrc_args.warnflag & WARNF_MIGRATE_PAGES) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_MIGRATE_PAGES, _LNK_2_1_2);
		kp_warning(globals->warnings, warn_indx, _LNK_2_1_2); NL;
	}

	if (print_stktrc_args.warnflag & WARNF_IXGBE_READ) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_IXGBE_READ, _LNK_2_1_2);
		kp_warning(globals->warnings, warn_indx, _LNK_2_1_2); NL;
	}

	if (print_stktrc_args.warnflag & WARNF_XFS_DIOREAD) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_XFS_DIOREAD, _LNK_2_1_2);
		kp_warning(globals->warnings, warn_indx, _LNK_2_1_2); NL;
	}

	if (print_stktrc_args.warnflag & WARNF_XFS_DIO_ALIGN) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_XFS_DIO_ALIGN, _LNK_2_1_2);
		kp_warning(globals->warnings, warn_indx, _LNK_2_1_2); NL;
	}

	if (print_stktrc_args.warnflag & WARNF_MD_FLUSH) {
		warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_MD_FLUSH, _LNK_2_1_2);
		kp_warning(globals->warnings, warn_indx, _LNK_2_1_2); NL;
	}

}

void
kp_top_swtch_pids()           		/* Section 2.1.2 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_1_3);
        HEAD3(_MSG_2_1_3);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1_2,"[Prev Subsection]");
        if (kparse_full) {
                ARFx(_LNK_2_1_4,"[Next Subsection]");
        } else {
                ARFx(_LNK_2_2,"[Next Subsection]");
        }

        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("%s        VolSlp ForceSlp  MigrCnt    SlpTime     AvMsec  Command", tlabel); NL;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_swtch_summary, pid_sort_by_sleep_cnt, 20, NULL); 
	CSV_FIELD("kipid", "[CSV]");
}

int
kp_print_sleep_pids(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;

        if (pidp->schedp == NULL) return 0;
        if (pidp->slp_hash == NULL) return 0;

        CAPTION_GREY;
        BOLD("Pid: ");
        PID_URL_FIELD8(pidp->PID);
        BOLD("Cmd: ");
        printf("%s", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	if (cluster_flag) {DSPACE; SERVER_URL_FIELD_SECTION_BRACKETS(globals, _LNK_2_1_3); }
        _CAPTION;

        nsym=5;

        sleep_report((void *)pidp->slp_hash, pidp->schedp, slp_sort_by_time, NULL);
	NL;

        return 0;
}

void
kp_top_swtch_pid_funcs()           	/* Section 2.1.4 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_1_4);
        HEAD3(_MSG_2_1_4);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1_3,"[Prev Subsection]");
        ARFx(_LNK_2_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, kp_print_sleep_pids, pid_sort_by_sleep_cnt, 10, NULL); 
	CSV_FIELD("kiwait", "[CSV]");
}

void
kp_wait_for_cpu()              		/* Section 2.2 */
{
        GREEN_TABLE;
        ANM(_LNK_2_2);
        HEAD3(_MSG_2_2);

        FONT_SIZE(-1);
        ARFx(_LNK_2_1,"[Prev Subsection]");
        ARFx(_LNK_2_2_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}


void
kp_runq_histogram()			/* Section 2.2.1 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_2_1);
        HEAD3(_MSG_2_2_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_2,"[Prev Subsection]");
        ARFx(_LNK_2_2_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        print_percpu_runq_histogram();
}

void
kp_runq_statistics()			/* Section 2.2.1 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_2_1);
        HEAD3(_MSG_2_2_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_2,"[Prev Subsection]");
        ARFx(_LNK_2_2_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        print_percpu_runq_stats();
}

void
kp_top_runq_pids()				/* Section 2.2.2 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_2_2);
        HEAD3(_MSG_2_2_2);
        FONT_SIZE(-1);
        ARFx(_LNK_2_2_1,"[Prev Subsection]");
	if (!IS_WINKI) ARFx(_LNK_2_3,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        npid=10;
        print_runq_pids(NULL);
	CSV_FIELD("kipid", "[CSV]");
}

void
kp_futex()				/* Section 2.3 */
{
        GREEN_TABLE;
        ANM(_LNK_2_3);
        HEAD3(_MSG_2_3);

        FONT_SIZE(-1);
        ARFx(_LNK_2_2_2,"[Prev Subsection]");
        ARFx(_LNK_2_3_1,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

}

void
kp_futex_summary_by_cnt()                              /* Section 2.3.1 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_3_1);
        HEAD3(_MSG_2_3_1);
        FONT_SIZE(-1);
        ARFx(_LNK_2_3,"[Prev Subsection]");
        ARFx(_LNK_2_3_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        foreach_hash_entry((void **)globals->futex_hash,GFUTEX_HSIZE,
                        (int (*)(void *, void *))hash_count_entries,
                        NULL, 0, &globals->futex_cnt);
	BOLD("%sTotal Futex count = %d (Top %d listed)", tab, globals->futex_cnt, MIN(globals->futex_cnt, nfutex)); NL;
	futex_print_report_by_cnt(globals->futex_cnt);
}

void
kp_futex_summary_by_time()                              /* Section 2.3.2 */
{
        ORANGE_TABLE;
        ANM(_LNK_2_3_2);
        HEAD3(_MSG_2_3_2);
        FONT_SIZE(-1);
        ARFx(_LNK_2_3_1,"[Prev Subsection]");
        ARFx(_LNK_3_0,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_3_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("%sTotal Futex count = %d (Top %d listed)", tab, globals->futex_cnt, MIN(globals->futex_cnt, nfutex)); NL;
	futex_print_report_by_time(globals->futex_cnt);
}

void
kp_file_activity()			/* Section 3.0 */
{
        HR;
        BLUE_TABLE;
        ANM(_LNK_3_0);
        HEAD2(_MSG_3_0);
        FONT_SIZE(-1);
        ARFx(_LNK_2_0,"[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_file_ops()				/* Section 3.1 */
{
        GREEN_TABLE;
        ANM(_LNK_3_1);
        HEAD3(_MSG_3_1);

        FONT_SIZE(-1);
        ARFx(_LNK_3_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        lineno = 1;
        tab=tab0;

        BOLD("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename", tab); NL;
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata,
                           (int (*)())fdata_sort_by_syscalls,
                           20, NULL);

	CSV_FIELD("kifile", "[CSV]");
}

void
kp_file_logio()
{
        GREEN_TABLE;
        ANM(_LNK_3_1);
        HEAD3(_MSG_3_1);

        FONT_SIZE(-1);
        ARFx(_LNK_3_2,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        lineno = 1;
        tab=tab0;

	BOLD ("                    -------  Total  ------- -------  Write  -------- --------  Read  --------"); NL;
	BOLD ("Object                 IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz     IO/s    KB/s  AvIOsz  filename"); NL;

	foreach_hash_entry((void **)globals->fobj_hash, FOBJ_HSIZE, file_print_fobj_logio,
			   (int (*)())fobj_sort_by_logio, 20, NULL);

}

void
kp_file_time()				/* Section 3.2 */
{
        uint64 warnflag = 0ull;
        int warn_indx;

        GREEN_TABLE;
        ANM(_LNK_3_2);
        HEAD3(_MSG_3_2);

        FONT_SIZE(-1);
        ARFx(_LNK_3_1,"[Prev Subsection]");
        ARFx(_LNK_3_3,"[Next Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        lineno = 0;
        tab=tab0;

        BOLD("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename", tab); NL;
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata,
                            (int (*)())fdata_sort_by_elptime,
                            20, NULL);
	CSV_FIELD("kifile", "[CSV]");
}

void
kp_file_physio()
{
        GREEN_TABLE;
        ANM(_LNK_3_2);
        HEAD3(_MSG_3_2);

        FONT_SIZE(-1);
        ARFx(_LNK_3_1,"[Prev Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        lineno = 1;
        tab=tab0;

	foreach_hash_entry((void **)globals->fobj_hash, FOBJ_HSIZE, file_print_fobj_physio,
			   (int (*)())fobj_sort_by_physio, 10, NULL);

}

void
kp_file_errs()				/* Section 3.3 */
{

        GREEN_TABLE;
        ANM(_LNK_3_3);
        HEAD3(_MSG_3_3);

        FONT_SIZE(-1);
        ARFx(_LNK_3_2,"[Prev Subsection]");
        if (kparse_full) {
                ARFx(_LNK_3_4,"[Next Subsection]");
        } 
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        lineno = 1;
        tab=tab0;

        BOLD("%sSyscalls    ElpTime  Lseeks   Reads  Writes    Errs         dev/fdatap       node     type  Filename", tab); NL;
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, file_print_fdata_errs,
                           (int (*)())fdata_sort_by_errs,
                           20, NULL);
	CSV_FIELD("kifile", "[CSV]");

}

int
kp_fdata_syscalls(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = (fdata_info_t *)arg1;
	var_arg_t vararg;

        if (fdatap->stats.syscall_cnt == 0)
                return 0;

        CAPTION_GREY;
        BOLD("Device: ");
        printf("0x%llx ", fdatap->dev);
        BOLD("Node: ");
        printf("%d ", fdatap->node);
	BOLD("Syscalls: ");
	printf("%d ", fdatap->stats.syscall_cnt);
        BOLD("Fname: ");
        printf("%-60s ", fdatap->fnameptr);

        _CAPTION;

        BOLD("System Call Name                 Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s"); NL;

	vararg.arg1 = NULL;
	vararg.arg2 = NULL;
        foreach_hash_entry((void **)fdatap->syscallp, SYSCALL_HASHSZ,
                                (int (*)(void *, void *))print_syscall_info,
                                (int (*)())syscall_sort_by_cnt, 10, &vararg);

        return 0;
}

void
kp_top_files()				/* Section 3.4 */
{

        GREEN_TABLE;
        ANM(_LNK_3_4);
        HEAD3(_MSG_3_4);

        FONT_SIZE(-1);
        ARFx(_LNK_3_3,"[Prev Subsection]");
        ARFx(_LNK_2_0,"---[Prev Section]");
        ARFx(_LNK_4_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, kp_fdata_syscalls, fdata_sort_by_syscalls, 10, NULL);
	CSV_FIELD("kifile", "[CSV]");

}

void
kp_device_report()			/* Section 4.0 */
{
        HR;
        BLUE_TABLE;
        ANM(_LNK_4_0);
        HEAD2(_MSG_4_0);
        FONT_SIZE(-1);
        ARFx(_LNK_3_0,"[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");

        _TABLE;
}

int
kp_dev_entries(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	uint64 *warnflagp = (uint64 *)arg2;
	struct iostats *statsp = &devinfop->iostats[0];
	uint32 dev;

	if (devinfop->iostats[IOTOT].compl_cnt == 0) return 0;

	if (warnflagp && (devinfop->mp_policy == MP_ROUND_ROBIN)) {
        	/* check  for RHEL 7.3 round-robin bug 1422567 */
        	if (strstr(globals->os_vers, "3.10.0-514.el7") ||
            	    strstr(globals->os_vers, "3.10.0-514.2.2") ||
            	    strstr(globals->os_vers, "3.10.0-514.6.1") ||
            	    strstr(globals->os_vers, "3.10.0-514.6.2") ||
            	    strstr(globals->os_vers, "3.10.0-514.10.2") ||
		    /* Snd check for SLES 12 SP2 */
            	    strstr(globals->os_vers, "4.4.21-69") ||
            	    strstr(globals->os_vers, "4.4.21-81") ||
            	    strstr(globals->os_vers, "4.4.21-84") ||
            	    strstr(globals->os_vers, "4.4.21-90") ||
            	    strstr(globals->os_vers, "4.4.38-93") ||
            	    strstr(globals->os_vers, "4.4.49-92.11") ||
            	    strstr(globals->os_vers, "4.4.49-92.14") ||
            	    strstr(globals->os_vers, "4.4.59-92.17") ||
            	    strstr(globals->os_vers, "4.4.59-92.20") ||
            	    strstr(globals->os_vers, "4.4.59-92.24") ||
            	    strstr(globals->os_vers, "4.4.74-92.29") ||
            	    strstr(globals->os_vers, "4.4.74-92.32") ||
            	    strstr(globals->os_vers, "4.4.74-92.35") ||
            	    strstr(globals->os_vers, "4.4.74-92.38") ||
            	    strstr(globals->os_vers, "4.4.90-92.45") ||
            	    strstr(globals->os_vers, "4.4.90-92.50") ||
            	    strstr(globals->os_vers, "4.4.103-92.53") ||
            	    strstr(globals->os_vers, "4.4.103-92.56") ||
            	    strstr(globals->os_vers, "4.4.114-92.64") ||
            	    strstr(globals->os_vers, "4.4.114-92.67") ||
            	    strstr(globals->os_vers, "4.4.120-92.70")) {
                	(*warnflagp) |= WARNF_MULTIPATH_BUG;
			RED_FONT;
        	}
	}

        dev = devinfop->lle.key;
	PRINT_DEVNAME(devinfop); 
	BLACK_FONT;
	DSPACE;
	print_iostats_totals(globals, &devinfop->iostats[0], arg2);

	if (statsp[IOTOT].barrier_cnt) {
               	printf (" barriers: ");
               	RED_FONT;
               	printf ("%d", statsp[IOTOT].barrier_cnt);
               	BLACK_FONT;
	}

	if (statsp[IOTOT].requeue_cnt) {
                printf (" requeue: ");
                RED_FONT;
                printf ("%d", statsp[IOTOT].requeue_cnt);
                BLACK_FONT;
        }

	NL;

        if ((statsp[IOTOT].barrier_cnt > 20) && (warnflagp != NULL)) {
                (*warnflagp) |= WARNF_BARRIER;
        }


}

void
kp_device_globals()			/* Section 4.1 */
{
	struct iostats *tiostatsp, *riostatsp, *wiostatsp;

        GREEN_TABLE;
        ANM(_LNK_4_1);
        HEAD3(_MSG_4_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2,"[Next Subsection]");
        ARFx(_LNK_3_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("         --------------------  Total  -------------------- --------------------  Write  -------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Devices     IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        printf ("%7d  ", globals->ndevs);
	print_iostats_totals(globals, &globals->iostats[0], NULL);
	return;
}

void
kp_perdev_reports()			/* Section 4.2.0 */
{ 
	GREEN_TABLE;
	ANM(_LNK_4_2);
	HEAD3(_MSG_4_2);

        FONT_SIZE(-1);
        ARFx(_LNK_4_1,"[Prev Subsection]");
        ARFx(_LNK_4_2_1,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

int
kp_dev_entries_over5(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;

	if ((devinfop->iostats[IOTOT].compl_cnt / secs) < 5) return 0;

	kp_dev_entries(arg1, arg2);
	return 0;
}

int
kp_dev_entries_less5(void *arg1, void *arg2)
{
        dev_info_t *devinfop = (dev_info_t *)arg1;
        uint64 *warnflagp = (uint64 *)arg2;
        if (devinfop->iostats[IOTOT].compl_cnt == 0) return 0;
        if ((devinfop->iostats[IOTOT].compl_cnt / secs) > 5) return 0;

	kp_dev_entries(arg1, arg2);
	return 0;
}

int
kp_dev_requeue_entries(void *arg1, void *arg2)
{
        dev_info_t *devinfop = (dev_info_t *)arg1;

        if (devinfop->iostats[IOTOT].requeue_cnt == 0) return 0;

        kp_dev_entries(arg1, arg2);
        return 0;
}

void
kp_active_disks()			/* Section 4.2.1 */
{
        uint64 warnflag = 0ull;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_2_1);
        HEAD3(_MSG_4_2_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2,"[Prev Subsection]");
        ARFx(_LNK_4_2_2,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;

	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, kp_dev_entries, dev_sort_by_count, 10, &warnflag);
	CSV_FIELD("kidsk", "[CSV]");

        if (warnflag & WARNF_BARRIER) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_BARRIER, _LNK_4_2_1);
                kp_warning(globals->warnings, warn_indx, _LNK_4_2_1);  NL;
	}
}

void
kp_highserv1_disks()			/* Section 4.2.2 */
{
        uint64 warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_2_2);
        HEAD3(_MSG_4_2_2);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_1,"[Prev Subsection]");
        ARFx(_LNK_4_2_3,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, kp_dev_entries_over5, dev_sort_by_avserv_over5, 10, &warnflag);
	CSV_FIELD("kidsk", "[CSV]");

        if (warnflag & WARNF_AVSERV) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_HIGH_AVSERV, _LNK_4_2_2);
                kp_warning(globals->warnings, warn_indx, _LNK_4_2_2); NL;
	}
}

void 
kp_highserv2_disks()			/* Section 4.2.3 */
{
        uint64 warnflag = 0;
        int warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_2_3);
        HEAD3(_MSG_4_2_3);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_2,"[Prev Subsection]");
        ARFx(_LNK_4_2_4,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, kp_dev_entries_less5, dev_sort_by_avserv_less5, 10, &warnflag);
	CSV_FIELD("kidsk", "[CSV]");
}

void
kp_highwait_disks()			/* Section 4.2.4 */
{
        ORANGE_TABLE;
        ANM(_LNK_4_2_4);
        HEAD3(_MSG_4_2_4);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_3,"[Prev Subsection]");
        ARFx(_LNK_4_2_5,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, kp_dev_entries, dev_sort_by_avwait, 10, NULL);
	CSV_FIELD("kidsk", "[CSV]");
}

void
kp_requeue_disks()			/* Section 4.2.5 */
{
        uint64 warnflag=0;
        int64 warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_2_5);
        HEAD3(_MSG_4_2_5);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_4,"[Prev Subsection]");
        ARFx(_LNK_4_2_6,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, kp_dev_requeue_entries, dev_sort_by_requeue, 0, &warnflag);
        if (warnflag & WARNF_REQUEUES) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_REQUEUES, _LNK_4_2_5);
                kp_warning(globals->warnings, warn_indx, _LNK_4_2_5); NL;
	}
}

void
kp_dsk_histogram()			/* Section 4.2.6 */
{
        uint64 warnflag=0;
        int64 warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_2_6);
        HEAD3(_MSG_4_2_6);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2_5,"[Prev Subsection]");
	if (IS_WINKI) {
        	ARFx(_LNK_4_7,"[Next Subsection]");
	} else {
        	ARFx(_LNK_4_3,"[Next Subsection]");
	}
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
        print_io_histogram(globals->iotimes, &warnflag);
        if (warnflag & WARNF_IO_DELAYS) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_IO_DELAYS, _LNK_4_2_6);
                kp_warning(globals->warnings, warn_indx, _LNK_4_2_6); NL;
        }
}

void
kp_mapper_report()			/* Section 4.3.0 */
{
        GREEN_TABLE;
        ANM(_LNK_4_3);
        HEAD3(_MSG_4_3);

        FONT_SIZE(-1);
        ARFx(_LNK_4_2,"[Prev Subsection]");
        ARFx(_LNK_4_3_1,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_active_mapper_devs()			/* Section 4.3.1 */
{
        uint64 warnflag=0;
        int64 warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_3_1);
        HEAD3(_MSG_4_3_1);

        FONT_SIZE(-1);
        ARFx(_LNK_4_3,"[Prev Subsection]");
        ARFx(_LNK_4_3_2,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, kp_dev_entries, dev_sort_by_count, 10, &warnflag);

        if (warnflag & WARNF_MULTIPATH_BUG) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_MULTIPATH_BUG, _LNK_4_3_1);
                kp_warning(globals->warnings, warn_indx, _LNK_4_3_1); NL;
        }

	CSV_FIELD("kidsk", "[CSV]");
}

void
kp_hiserv_mapper_devs()			/* Section 4.3.2 */
{
        uint64 warnflag=0;
        int64 warn_indx;

        ORANGE_TABLE;
        ANM(_LNK_4_3_2);
        HEAD3(_MSG_4_3_2);

        FONT_SIZE(-1);
        ARFx(_LNK_4_3_1,"[Prev Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, kp_dev_entries_over5, dev_sort_by_avserv_over5, 10, NULL);
	CSV_FIELD("kidsk", "[CSV]");
}

int
kp_fc_entries(void *arg1, void *arg2)
{
	fc_info_t *fcinfop = (fc_info_t *)arg1;
	struct iostats *statsp = &fcinfop->iostats[0];
	uint64 fcpath = fcinfop->lle.key;
	char path_str[16];

	if (fcpath == NO_HBA) {
		sprintf (path_str, "ukn");
	} else {
		sprintf (path_str, "%d:%d:%d", FCPATH1(fcpath), FCPATH2(fcpath), FCPATH3(fcpath));
	}
	printf ("%-10s", path_str);
	DSPACE;
	print_iostats_totals(globals, &fcinfop->iostats[0], arg2);

	if (statsp[IOTOT].barrier_cnt) {
               	printf (" barriers: ");
               	RED_FONT;
               	printf ("%d", statsp[IOTOT].barrier_cnt);
               	BLACK_FONT;
	}

	if (statsp[IOTOT].requeue_cnt) {
                printf (" requeue: ");
                RED_FONT;
                printf ("%d", statsp[IOTOT].requeue_cnt);
                BLACK_FONT;
        }

	NL;

}

void
kp_fc_totals()				/* Section 4.4 */
{
        GREEN_TABLE;
        ANM(_LNK_4_4);
        HEAD3(_MSG_4_4);

        FONT_SIZE(-1);
        ARFx(_LNK_4_3_2,"[Prev Subsection]");
        ARFx(_LNK_4_5,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("            --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Device         IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->fchash, FC_HSIZE, kp_fc_entries, NULL, 0, NULL);
}


int
kp_wwn_entries(void *arg1, void *arg2)
{
	wwn_info_t *wwninfop = (wwn_info_t *)arg1;
	struct iostats *statsp = &wwninfop->iostats[0];
	uint64 wwn = wwninfop->lle.key;
	char wwn_str[20];

	if (wwn) {
		sprintf (wwn_str, "0x%016llx", wwn);
	} else {
		sprintf (wwn_str, "%18s", "none");
	}
	printf ("%-18s", wwn_str);
	DSPACE;
	print_iostats_totals(globals, &wwninfop->iostats[0], arg2);

	if (statsp[IOTOT].barrier_cnt) {
               	printf (" barriers: ");
               	RED_FONT;
               	printf ("%d", statsp[IOTOT].barrier_cnt);
               	BLACK_FONT;
	}

	if (statsp[IOTOT].requeue_cnt) {
                printf (" requeue: ");
                RED_FONT;
                printf ("%d", statsp[IOTOT].requeue_cnt);
                BLACK_FONT;
        }

	NL;
}

void
kp_wwn_totals()				/* Section 4.5 */
{
        GREEN_TABLE;
        ANM(_LNK_4_5);
        HEAD3(_MSG_4_5);

        FONT_SIZE(-1);
        ARFx(_LNK_4_4,"[Prev Subsection]");
        ARFx(_LNK_4_6,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        tab=tab0;
        lineno=1;
	BOLD("                    --------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD("Target WWN             IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv"); NL;
        foreach_hash_entry((void **)globals->wwnhash, WWN_HSIZE, kp_wwn_entries, wwn_sort_by_wwn, 0, NULL);
}


void
kp_perpid_mdev_totals()			/* Section 4.6 */
{
        GREEN_TABLE;
        ANM(_LNK_4_6);
        HEAD3(_MSG_4_6);

        FONT_SIZE(-1);
        ARFx(_LNK_4_6,"[Prev Subsection]");
        ARFx(_LNK_4_7,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("--------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD ("   IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv      %s  Process", tlabel); NL;

        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_miosum,  pid_sort_by_miocnt, 10, NULL);
	CSV_FIELD("kipid", "[CSV]");
}

void
kp_perpid_dev_totals()			/* Section 4.7 */
{
        GREEN_TABLE;
        ANM(_LNK_4_7);
        HEAD3(_MSG_4_7);

        FONT_SIZE(-1);
	if (IS_WINKI) {
        	ARFx(_LNK_4_2,"[Prev Subsection]");
	} else {
        	ARFx(_LNK_4_6,"[Prev Subsection]");
	}
	if (!IS_WINKI) ARFx(_LNK_4_8,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	BOLD ("--------------------  Total  -------------------- ---------------------  Write  ------------------- ---------------------  Read  --------------------"); NL;
	BOLD ("   IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv      %s  Process", tlabel); NL;

        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_iosum,  pid_sort_by_iocnt, 10, NULL);
	CSV_FIELD("kipid", "[CSV]");
}

int
kp_blk_read_entry(void *arg1, void *arg2)
{
        dskblk_info_t *dskblkp = (dskblk_info_t *)arg1;
        uint64 *warnflagp = (uint64 *)arg2;
	dev_info_t *devinfop;
        uint64 dev;

        if (dskblkp->rd_cnt < 3) return 0;

        dev = DSKBLK_DEV(dskblkp->lle.key);
        if (dskblkp->rd_cnt > 50)  {
                RED_FONT;
                if (warnflagp) (*warnflagp) |= WARNF_REREADS;
        }
	devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);

        printf("%-7d 0x%08llx      0x%-8llx     ",
                dskblkp->rd_cnt,
                dev,
                dskblkp->sector);

	if (devinfop->devname) printf ("/dev/%s", devinfop->devname);
        if (devinfop->mapname) printf ("    (/dev/mapper/%s)", devinfop->mapname);
	
	NL;
        BLACK_FONT;

        return 0;
}

void
kp_dskblk_read()			/* Section 4.7 */
{

        uint64  warnflag = 0;
        int     warn_indx;

        GREEN_TABLE;
        ANM(_LNK_4_8);
        HEAD3(_MSG_4_8);

        FONT_SIZE(-1);
        ARFx(_LNK_4_7,"[Prev Subsection]");
        ARFx(_LNK_4_9,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
        T(_MSG_4_8_INFO);

        BOLD("Freq    Dev             Block"); NL;
        foreach_hash_entry((void **)globals->dskblk_hash, DSKBLK_HSIZE, kp_blk_read_entry, dskblk_sort_by_rdcnt, 10, &warnflag);

        if (warnflag & WARNF_REREADS) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_REREADS, _LNK_4_5);
                kp_warning(globals->warnings, warn_indx, _LNK_4_5); T("\n");
        }

}

int
kp_blk_write_entry(void *arg1, void *arg2)
{
        dskblk_info_t *dskblkp = (dskblk_info_t *)arg1;
        char device[12];
        uint64 dev;
	dev_info_t *devinfop;

        if (dskblkp->wr_cnt < 2) return 0;

        dev = DSKBLK_DEV(dskblkp->lle.key);
        devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);

        printf("%-7d 0x%08llx      0x%-8llx     ",
                dskblkp->wr_cnt,
                dev,
                dskblkp->sector);

	if (devinfop->devname)  
                printf ("/dev/%s", devinfop->devname);
       	if (devinfop->mapname) 
               	printf ("    (/dev/mapper/%s)", devinfop->mapname);
	
	printf ("\n");

        return 0;
}

void
kp_dskblk_write()			/* Section 4.9 */
{
        GREEN_TABLE;
        ANM(_LNK_4_9);
        HEAD3(_MSG_4_9);

        FONT_SIZE(-1);
        ARFx(_LNK_4_8,"[Prev Subsection]");
        ARFx(_LNK_4_10,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("Freq    Dev             Block"); NL;
        foreach_hash_entry((void **)globals->dskblk_hash, DSKBLK_HSIZE, kp_blk_write_entry, dskblk_sort_by_wrcnt, 10, NULL);

}

void
kp_io_controllers()			/* Section 4.10 */
{
	uint64 warnflag = 0ull;
	int warn_indx;

        GREEN_TABLE;
        ANM(_LNK_4_10);
        HEAD3(_MSG_4_10);

        FONT_SIZE(-1);
        ARFx(_LNK_4_9,"[Prev Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
        ARFx(_LNK_5_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	NL;

	io_controllers(&warnflag, 1);
        if (warnflag & WARNF_CACHE_BYPASS) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_CACHE_BYPASS, _LNK_4_10);
                kp_warning(globals->warnings, warn_indx, _LNK_4_10);  NL;
	}
}

void 
kp_network()
{
        HR;
        BLUE_TABLE;
        ANM(_LNK_5_0);
        HEAD2(_MSG_5_0);
        FONT_SIZE(-1);
        ARFx(_LNK_4_0,"[Prev Section]"); 
	if (!IS_WINKI) {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_ipip()
{
	char *hdr1="Syscalls";

        GREEN_TABLE;
        ANM(_LNK_5_1);
        HEAD2(_MSG_5_1);
        FONT_SIZE(-1);
        ARFx(_LNK_5_2,"[Next Subsection]"); 
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI) {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (IS_WINKI) hdr1="Requests";
	BOLD ("%s      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection", hdr1); NL;
	foreach_hash_entry2((void **)globals->ipip_hash, IPIP_HASHSZ, socket_print_ipip,
			    (int (*)())ipip_sort_by_syscalls, 10, NULL);
	CSV_FIELD("kisock", "[CSV]");
}

void
kp_remoteip()
{
	uint64 scallflag=1;
       	int nentries=5;

        GREEN_TABLE;
        ANM(_LNK_5_2);
        HEAD2(_MSG_5_2);
        FONT_SIZE(-1);
        ARFx(_LNK_5_1,"[Prev Subsection]"); 
        ARFx(_LNK_5_3,"[Next Subsection]"); 
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI) {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (IS_WINKI) {
		scallflag=0;
		nentries=10;
		BOLD("Requests      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection"); NL;
	}
        
	foreach_hash_entry((void **)globals->rip_hash, IP_HASHSZ, socket_print_rip,
			   (int (*)())ip_sort_by_syscalls, nentries, &scallflag);
	CSV_FIELD("kisock", "[CSV]");
}

void
kp_remoteport()
{
	uint64 scallflag=1;
	int nentries=5;

        GREEN_TABLE;
        ANM(_LNK_5_3);
        HEAD2(_MSG_5_3);
        FONT_SIZE(-1);
        ARFx(_LNK_5_2,"[Prev Subsection]"); 
        ARFx(_LNK_5_4,"[Next Subsection]"); 
        ARFx(_LNK_4_0,"---[Prev Section]"); 
	if (!IS_WINKI)  {
                ARFx(_LNK_6_0,"[Next Section]");
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (IS_WINKI) {
		scallflag=0;
		nentries=10;
		BOLD("Requests      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection"); NL;
	}

        foreach_hash_entry((void **)globals->rsock_hash, SOCK_HASHSZ, socket_print_rsock,
			   (int (*)())sock_sort_by_syscalls, nentries, &scallflag);
	CSV_FIELD("kisock", "[CSV]");
}

void
kp_localip()
{
	uint64	scallflag=1;
	int	nentries=5;

        GREEN_TABLE;
        ANM(_LNK_5_4);
        HEAD2(_MSG_5_4);
        FONT_SIZE(-1);
        ARFx(_LNK_5_3,"[Prev Subsection]");
        ARFx(_LNK_5_5,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI) {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (IS_WINKI) {
		scallflag=0;
		nentries=10;
		BOLD("Requests      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection"); NL;
	} 
	
	foreach_hash_entry((void **)globals->lip_hash, IP_HASHSZ, socket_print_lip,
			   (int (*)())ip_sort_by_syscalls, nentries, &scallflag);

	CSV_FIELD("kisock", "[CSV]");
}

void
kp_localport()
{
	uint64 scallflag=1;
	int nentries=5;

        GREEN_TABLE;
        ANM(_LNK_5_5);
        HEAD2(_MSG_5_5);
        FONT_SIZE(-1);
        ARFx(_LNK_5_4,"[Prev Subsection]");
        ARFx(_LNK_5_6,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI)  {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
	
	if (IS_WINKI) {
		scallflag=0;
		nentries=10;
		BOLD("Requests      Rd/s      RdKB/s      Wr/s      WrKB/s  Connection"); NL;
	}
		
	foreach_hash_entry((void **)globals->lsock_hash, SOCK_HASHSZ, socket_print_lsock,
			   (int (*)())sock_sort_by_syscalls, nentries, &scallflag);

	CSV_FIELD("kisock", "[CSV]");
}

void
kp_socket()
{
	char *hdr1="Syscalls";

        GREEN_TABLE;
        ANM(_LNK_5_6);
        HEAD2(_MSG_5_6);
        FONT_SIZE(-1);
        ARFx(_LNK_5_5,"[Prev Subsection]");
	if (IS_WINKI) ARFx(_LNK_5_5,"[Next Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI)  {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (IS_WINKI) hdr1="Requests";

	BOLD("%s      Rd/s      RdKB/s      Wr/s      WrKB/s   LastPid  Connection", hdr1); NL;
        foreach_hash_entry2((void **)globals->sdata_hash, SDATA_HASHSZ, socket_print_sdata,
                           (int (*)())sdata_sort_by_syscalls, 10, NULL);
	CSV_FIELD("kisock", "[CSV]");
}

void
kp_timeo_retrans()
{
	int warn_indx;

        GREEN_TABLE;
        ANM(_LNK_5_7);
        HEAD2(_MSG_5_7);
        FONT_SIZE(-1);
        ARFx(_LNK_5_6,"[Prev Subsection]");
        ARFx(_LNK_4_0,"---[Prev Section]");
	if (!IS_WINKI) {
                ARFx(_LNK_6_0,"[Next Section]");
	} else {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (globals->num_tcp_timeouts) { 
		RED_FONT;
		printf ("%d TCP Timeouts Detected - Avg delay (secs) = %7.6f\n", 
				globals->num_tcp_timeouts, 
				SECS((globals->tcp_timeout_time * 1.0) / globals->num_tcp_timeouts));
		BLACK_FONT;

                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_TCP_TIMEOUTS, _LNK_5_7);
                kp_warning(globals->warnings, warn_indx, _LNK_5_7); NL;
	} else {
		BOLD ("No TCP Timeouts Detected\n");
	}
}


void
kp_memory()				/* Section 6.0 */
{
        HR;
        BLUE_TABLE;
        ANM(_LNK_6_0);
        HEAD2(_MSG_6_0);
        FONT_SIZE(-1);
        ARFx(_LNK_5_0,"[Prev Section]"); 
        if (next_sid > 1)  {
                ARFx(_LNK_7_0,"[Next Section]");
        } else if (globals->docker_hash) { 
                ARFx(_LNK_8_0,"[Next Section]"); 
	} else  {
                ARFx(_LNK_9_0,"[Next Section]"); 
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_dimm(void *arg1, void *arg2)		/* Section 6.1 */
{
        uint64 warnflag = 0ull;
        int i, warn_indx=0, nldom;
	ldom_info_t *ldominfop;
	uint64 maxmem = 0, minmem = 0;

        GREEN_TABLE;
        ANM(_LNK_6_1);
        HEAD3(_MSG_6_1);
        FONT_SIZE(-1);
        ARFx(_LNK_6_2,"[Next Subsection]"); 
        ARFx(_LNK_6_0,"---[Prev Section]"); 
        if (next_sid > 1)  {
                ARFx(_LNK_7_0,"[Next Section]");
        } else if (globals->docker_hash) { 
                ARFx(_LNK_8_0,"[Next Section]"); 
	} else {
		ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (arch_flag == PPC64LE) {
		TEXT("DIMM information not available for PowerPC servers\n");
		return;
	}

	parse_dmidecode();

	BOLD("\n-- NUMA Node Memory--\n");
	BOLD("\nNode   TotalMB   UsedMB   FreeMB\n");

	nldom = MAX(globals->nldom, 1);
	for (i = 0; i < globals->nldom; i++) {
		if (ldominfop = FIND_LDOMP(globals->ldom_hash, i)) {
			if (minmem == 0) 
				minmem = ldominfop->memkb;
			else  
				minmem = MIN(ldominfop->memkb, minmem);
			maxmem = MAX(ldominfop->memkb, maxmem);

			if ((ldominfop->memkb * 100.0 / maxmem) < 95.0) {
				warnflag |= WARNF_MEM_IMBALANCE;
				RED_FONT; 
			}

			if (ldominfop->freekb < 100 * 1024) {
				warnflag |= WARNF_NODE_LOWMEM;
				if (font_color == 0) RED_FONT; 
			}

			printf ("%4d  %8lld %8lld %8lld\n", i,
				ldominfop->memkb/1024,
				ldominfop->usedkb/1024,
				ldominfop->freekb/1024);

			BLACK_FONT;
		}
	}

	if (warnflag & WARNF_MEM_IMBALANCE) {
        	warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_MEM_IMBALANCE, _LNK_6_1);
               	kp_warning(globals->warnings, warn_indx, _LNK_6_1); NL;
	}

	if (warnflag & WARNF_NODE_LOWMEM) {
                warn_indx = add_warning((void **)&globals->warnings, &globals->next_warning, WARN_NODE_LOWMEM, _LNK_6_1);
               	kp_warning(globals->warnings, warn_indx, _LNK_6_1); NL;
	}
}


int
kp_pid_memory(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
	sched_info_t *schedp;
        uint64 *warnflagp = (uint64 *)arg2;

        printf ("%9d %9d ",
                pidp->vss,
                pidp->rss);
        PID_URL_FIELD8_R(pidp->PID);
        printf (" %s", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%012llx&gt;" : " <%012llx>", ((docker_info_t *)(pidp->dockerp))->ID);
	NL;

        return 0;
}

void
kp_rss()				/* Section 6.2 */
{
        uint64 warnflag = 0ull;
        int warn_indx=0;

        GREEN_TABLE;
        ANM(_LNK_6_2);
        HEAD3(_MSG_6_2);
        FONT_SIZE(-1);
        ARFx(_LNK_6_1,"[Prev Subsection]"); 
        ARFx(_LNK_6_3,"[Next Subsection]"); 
        ARFx(_LNK_6_0,"---[Prev Section]"); 
        if (next_sid > 1)  {
                ARFx(_LNK_7_0,"[Next Section]");
        } else if (globals->docker_hash) { 
                ARFx(_LNK_8_0,"[Next Section]"); 
	} else {
		ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("      vss       rss      %s Command", tlabel); NL;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, kp_pid_memory, pid_sort_by_rss, 10, &warnflag);
	CSV_FIELD("kipid", "[CSV]");
}

void
kp_vss()				/* Section 6.3 */
{
        uint64 warnflag = 0ull;
        int warn_indx=0;

        GREEN_TABLE;
        ANM(_LNK_6_3);
        HEAD3(_MSG_6_3);
        FONT_SIZE(-1);
        ARFx(_LNK_6_2,"[Prev Subsection]"); 
        ARFx(_LNK_6_0,"---[Prev Section]");
        if (next_sid > 1)  {
                ARFx(_LNK_7_0,"[Next Section]");
        } else if (globals->docker_hash) { 
                ARFx(_LNK_8_0,"[Next Section]"); 
        } else  { 
                ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

        BOLD("      vss       rss      %s Command", tlabel); NL;
        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, kp_pid_memory, pid_sort_by_vss, 10, &warnflag);
	CSV_FIELD("kipid", "[CSV]");
}


void
kp_oracle()				/* Section 7.0 */
{
        HR;
        BLUE_TABLE;
        ANM(_LNK_7_0);
        HEAD2(_MSG_7_0);
        FONT_SIZE(-1);
        ARFx(_LNK_6_0,"[Prev Section]");
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_print_orastats (int type)
{
	int i;
        ora_stats_t orastats;
	int count, indx;

	if (type == NORACLE)  {
		/* usually, we only won't one hash chain for the specific Oracle process type 
		 * so count=1 is normal.   But we have a special cause to look at all the
		 * hash chains to analyze every Oracle process.  So so if NORACLE is passed, we
		 * alter the count to NO_ORACLE and start at bucket 0 so we can look at every
		 * hash chain 
		 */
		count=NORACLE;
		indx=0;
	} else {
		count=1;
		indx = type;
	}

	if (IS_LIKI && ((type == LGWR) || (type == DBWRITER))) {
        	BOLD("                                --- CPU STATS ---   ---------- PHYSICAL READS --------   --------- PHYSICAL WRITES --------"); NL;
        	BOLD("Instance    Procs  SchedPolicy  RunTime  RunQTime   IO/sec   AvSize   KB/sec    AvServ   IO/sec   AvSize   KB/sec    AvServ"); NL;
	} else {
        	BOLD("                   --- CPU STATS ---   ---------- PHYSICAL READS --------   --------- PHYSICAL WRITES --------"); NL;
        	BOLD("Instance    Procs  RunTime  RunQTime   IO/sec   AvSize   KB/sec    AvServ   IO/sec   AvSize   KB/sec    AvServ"); NL;
	}

        for (i = 1; i < next_sid; i++) {
                bzero(&orastats, sizeof(ora_stats_t));
                foreach_hash_entry((void **)&sid_table[i].sid_pid[indx], count, oracle_pid_stats, NULL, 0, &orastats);

                printf("%-9s %6d",
                        sid_table[i].sid_name, 
			 orastats.pid_cnt);

		if (IS_LIKI && ((type == LGWR) || (type == DBWRITER))) {
        		printf (" %12s", sched_policy_name[orastats.sched_policy]);
		}

                printf(" %9.3f %9.3f %8.0f %8lld %8.0f %9.6f %8.0f %8lld %8.0f %9.6f",
                        SECS(orastats.run_time),
                        SECS(orastats.runq_time),
                        orastats.iostats[IORD].compl_cnt / secs,
                        (orastats.iostats[IORD].sect_xfrd/2) / MAX(orastats.iostats[IORD].compl_cnt,1 ),
                        (orastats.iostats[IORD].sect_xfrd/2) / secs,
			SECS(orastats.iostats[IORD].cum_ioserv / MAX(orastats.iostats[IORD].compl_cnt,1)),
                        orastats.iostats[IOWR].compl_cnt / secs,
                        (orastats.iostats[IOWR].sect_xfrd/2) / MAX(orastats.iostats[IOWR].compl_cnt, 1),
                        (orastats.iostats[IOWR].sect_xfrd/2) / secs,
			SECS(orastats.iostats[IOWR].cum_ioserv / MAX(orastats.iostats[IOWR].compl_cnt, 1)));

		if (orastats.iostats[IOTOT].barrier_cnt) {
                	printf (" barriers: ");
                	RED_FONT;
                	printf ("%d", orastats.iostats[IOTOT].barrier_cnt);
                	BLACK_FONT;
		}

		NL;
        }
}

void
kp_oracle_sids()			/* Section 7.1 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_1);
        HEAD3(_MSG_7_1);
        FONT_SIZE(-1);
        ARFx(_LNK_7_2,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(NORACLE);
}

void
kp_lgwr_analysis()			/* Section 7.2 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_2);
        HEAD3(_MSG_7_2);
        FONT_SIZE(-1);
        ARFx(_LNK_7_1,"[Prev Subsection]"); 
        ARFx(_LNK_7_3,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(LGWR);
}

void
kp_arch_analysis()			/* Section 7.3 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_3);
        HEAD3(_MSG_7_3);
        FONT_SIZE(-1);
        ARFx(_LNK_7_2,"[Prev Subsection]"); 
        ARFx(_LNK_7_4,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(ARCHIVE);
}

void
kp_dbw_analysis()			/* Section 7.4 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_4);
        HEAD3(_MSG_7_4);
        FONT_SIZE(-1);
        ARFx(_LNK_7_3,"[Prev Subsection]"); 
        ARFx(_LNK_7_5,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(DBWRITER);
}

void
kp_pquery_analysis()			/* Section 7.5 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_5);
        HEAD3(_MSG_7_5);
        FONT_SIZE(-1);
        ARFx(_LNK_7_4,"[Prev Subsection]"); 
        ARFx(_LNK_7_6,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(PQUERY);
}

void
kp_shared_server_analysis()		/* Section 7.6 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_6);
        HEAD3(_MSG_7_6);
        FONT_SIZE(-1);
        ARFx(_LNK_7_5,"[Prev Subsection]"); 
        ARFx(_LNK_7_7,"[Next Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;


	kp_print_orastats(ORACLE);
}

void
kp_ioslave_analysis()			/* Section 7.7 */
{
        int warn_indx=0;
        uint64 warnflag = 0ull;

        GREEN_TABLE;
        ANM(_LNK_7_7);
        HEAD3(_MSG_7_7);
        FONT_SIZE(-1);
        ARFx(_LNK_7_6,"[Prev Subsection]"); 
        ARFx(_LNK_7_0,"---[Prev Section]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Next Section]");
	} else {
        	ARFx(_LNK_9_0,"[Next Section]");
	}
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
        NL;

	kp_print_orastats(SLAVE);
}

void
kp_dockers()			/* Section 8.0 */
{
	HR;
        BLUE_TABLE;
        ANM(_LNK_8_0);
        HEAD2(_MSG_8_0);
        FONT_SIZE(-1);
	
	if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"[Prev Section]"); 
	} else if (IS_LIKI_V2_PLUS)  { 
        	ARFx(_LNK_6_0,"[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"[Prev Section]");
	}

        ARFx(_LNK_9_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_docker_ps()				/* Section 8.1 */
{
        GREEN_TABLE;
        ANM(_LNK_8_1);
        HEAD3(_MSG_8_1);
        FONT_SIZE(-1);
        ARFx(_LNK_8_2,"[Next Subsection]"); 
	if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (IS_LIKI_V2_PLUS)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_9_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	print_docker_ps();
}
	

void
kp_docker_cpu()				/* Section 8.1 */
{
        GREEN_TABLE;
        ANM(_LNK_8_2);
        HEAD3(_MSG_8_2);
        FONT_SIZE(-1);
        ARFx(_LNK_8_2,"[Next Subsection]"); 
	if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (IS_LIKI_V2_PLUS)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_9_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	docker_print_cpu_report();

}

void
kp_docker_io()				/* Section 8.3 */
{
        GREEN_TABLE;
        ANM(_LNK_8_3);
        HEAD3(_MSG_8_3);
        FONT_SIZE(-1);
        ARFx(_LNK_8_2,"[Prev Subsection]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"---[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (IS_LIKI_V2_PLUS)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_9_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;

	docker_print_io_report();
}

void
kp_file_links()			/* Section 9.0 */
{
        int i, msg_idx;
        warn_t *warnp;

	HR;
        BLUE_TABLE;
        ANM(_LNK_9_0);
        HEAD2(_MSG_9_0);
        FONT_SIZE(-1);
	
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"[Prev Section]"); 
	} else if (!IS_WINKI)  { 
        	ARFx(_LNK_6_0,"[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"[Prev Section]");
	}

        ARFx(_LNK_10_0,"[Next Section]");
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;
}

void
kp_txt_links()				/* Section 9.1 */
{
        GREEN_TABLE;
        ANM(_LNK_9_1);
        HEAD3(_MSG_9_1);
        FONT_SIZE(-1);
        ARFx(_LNK_9_2,"[Next Subsection]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"---[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (!IS_WINKI)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_10_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
	TXT_FIELD("kipid", "PID Analysis Report");
	TXT_FIELD("kidsk", "Disk Analysis Report");
	TXT_FIELD("kirunq", "CPU/RunQ Analysis Report");
	if (globals->hcinfop) TXT_FIELD("kiprof", "CPU Profiling Report");
	TXT_FIELD("kiwait", "Wait/Sleep Analysis Report");
	TXT_FIELD("kifile", "File Activity Report");
	TXT_FIELD("kifutex", "Futex Report");
	if (globals->docker_hash) TXT_FIELD("kisock", "Docker Container Report");
}

void
kp_csv_links()				/* Section 9.2 */
{
        GREEN_TABLE;
        ANM(_LNK_9_2);
        HEAD3(_MSG_9_2);
        FONT_SIZE(-1);
        ARFx(_LNK_9_1,"[Prev Subsection]"); 
        ARFx(_LNK_9_3,"[Next Subsection]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"---[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (!IS_WINKI)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_10_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
	CSV_FIELD("kipid", "kipid CSV file");
	CSV_FIELD("kidsk", "kidsk CSV file");
	CSV_FIELD("kirunq", "kirunq CSV file");
	CSV_FIELD("kiwait", "kiwait CSV file");
	CSV_FIELD("kifile", "kifile CSV file");
	CSV_FIELD("kisock", "kisock CSV file");
}

void
kp_misc_links()				/* Section 9.3 */
{
        GREEN_TABLE;
        ANM(_LNK_9_3);
        HEAD3(_MSG_9_3);
        FONT_SIZE(-1);
        ARFx(_LNK_9_2,"[Prev Subsection]");  
        if (vis) { ARFx(_LNK_9_4,"[Next Subsection]");  }
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"---[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (!IS_WINKI)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_10_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
	BOLD("General"); NL;
	if (IS_WINKI) {
		FILE_FIELD("systeminfo", "systeminfo");
		FILE_FIELD("cpulist", "wmic cpu list brief");
		FILE_FIELD("corelist", "wmic cpu get SocketDesignation, NumberOfCores, NumberOfLogicalProcessors");
		FILE_FIELD("tasklist", "tasklist");

	} else {
		FILE_FIELD("uname-a", "uname -a");
		FILE_FIELD("release", "/etc/*release");
		FILE_FIELD("uptime", "uptime");
		FILE_FIELD("cmdline", "/proc/cmdline");
		FILE_FIELD("grub.conf", "/boot/grub/grub.conf");
		BOLD("Configuration"); NL;
		FILE_FIELD("cpuinfo", "/proc/cpuinfo");
		FILE_FIELD("mem_info", "free; /proc/meminfo");
		FILE_FIELD("lspci", "lspci");
		FILE_FIELD("dmidecode", "dmidecode");
		FILE_FIELD("getconf-a", "getconf -a");
		FILE_FIELD("sysctl-a", "sysctl -a");
		FILE_FIELD("sysctl.conf", "/etc/sysctl.conf");
		FILE_FIELD("sched_features", "<debugfs>/sched_features");
		FILE_FIELD("ipcs-m", "ipcs -m");
		BOLD("NUMA Information"); NL;
		FILE_FIELD("numa_info", "numactl --hardware / numastat");
		FILE_FIELD("mpsched", "mpsched");
		BOLD("Processes"); NL;
		FILE_FIELD("ps-eLf", "ps -eLf");
		FILE_FIELD("ps-aux", "ps aus");
		FILE_FIELD("pstree", "pstree");
		FILE_FIELD("stacks", "/proc/*/stacks/*");
		BOLD("File Systems and I/O"); NL;
		FILE_FIELD("mount-v", "mount -v");
		FILE_FIELD("fstab", "/etc/fstab");
		FILE_FIELD("extfs", "extfs inforamation");
		FILE_FIELD("lvm", "LVM info");
		FILE_FIELD("dmsetup_ls", "dmsetup ls --tree");
		FILE_FIELD("multipath-l", "multipath -ll");
		FILE_FIELD("multipath.conf", "/etc/multipath.conf");
		FILE_FIELD("block_params", "Block Device parameters");
		FILE_FIELD("interrupts", "/proc/interrupts");
		FILE_FIELD("fc_linkspeed", "/sys/devices/pci*/*/*/host*/fc_host/host*/speed");
		BOLD("Network"); NL;
		FILE_FIELD("ifconfig", "ifconfig");
		FILE_FIELD("ethtool", "ethtool");
		FILE_FIELD("route-n", "route -n");
		FILE_FIELD("bonds", "/proc/net/bonding/bond*");
		FILE_FIELD("netstat-s", "netstat -s");
		FILE_FIELD("netstat-neopa", "netstat -neopa");
	}
}

void
kp_vis_links()				/* Section 9.4 */
{
        GREEN_TABLE;
        ANM(_LNK_9_4);
        HEAD3(_MSG_9_4);
        FONT_SIZE(-1);
        ARFx(_LNK_9_3,"[Prev Subsection]"); 
	if (globals->docker_hash) {
        	ARFx(_LNK_8_0,"---[Prev Section]"); 
	} else if (next_sid > 1)  {
        	ARFx(_LNK_7_0,"---[Prev Section]"); 
	} else if (IS_LIKI_V2_PLUS)  { 
        	ARFx(_LNK_6_0,"---[Prev Section]");
	} else { 
        	ARFx(_LNK_5_0,"---[Prev Section]");
	}
        ARFx(_LNK_10_0,"[Next Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]"); 
        _TABLE;
	VISFILE_FIELD("timeline", "Server Activity Timeline");
	VISFILE_FIELD("kidsk_scatter", "Disk Device I/Os");
	VISFILE_FIELD("futex_scatter", "Global Futex Usage");
	VISFILE_FIELD("network", "Top 50 Network Traffice Flows");
	VISFILE_FIELD("socket", "Server Network Traffice Flow by IP+Port (UDP or TCP)");
	VISFILE_FIELD("kidsk", "Disk Statistics");
	VISFILE_FIELD("kirunq", "CPU/RunQ Statistics");
	VISFILE_FIELD("kifile", "File Statistics");
	VISFILE_FIELD("kipid_io", "Per-Task I/O Statistics");
	VISFILE_FIELD("kipid_sched", "Per-Task Scheduler Statistics");
}

void
kp_warnings_report()			/* Section 9.0 */
{
        int i, msg_idx;
        warn_t *warnp;

	HR;
        BLUE_TABLE;
        ANM(_LNK_10_0);
        ANM(SPF(line,"%s%d", _LNK_WARN, globals->next_warning));
        HEAD2(_MSG_10_0);
        FONT_SIZE(-1);
	
        ARFx(_LNK_9_0,"[Prev Section]"); 
        ARFx(_LNK_TOC,"[Table of Contents]");
        _TABLE;

	if (globals->next_warning == 0) {
		BOLD("No Warnings Found"); NL;
		return;
	}

        RED_FONT;
        UL;
        for (i = 0; i < globals->next_warning; i++) {
                warnp = globals->warnings;
                if (warnp[i].type == NOTE) continue;

                msg_idx = warnp[i].idx;

                if (HTML) {
                    if (warnp[i].lnk)  {
                            LI; ARFx(SPF(line, "%s", warnp[i].lnk), warnmsg[msg_idx].msg); 
                    } else {
                            LI; ARFx(SPF(line,"%s%d", _LNK_WARN, i), warnmsg[msg_idx].msg); 
                    }
                } else {
                        printf ("%s", warnmsg[msg_idx].msg); NL;
                }

        }
        _UL;
        BLACK_FONT;
}

