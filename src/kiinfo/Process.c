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
#include <time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "scsi.h"

int
print_process_load_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	ProcessLoad_t *p = (ProcessLoad_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 

	printf (" pid=%d ", p->ProcessID);
	PRINT_WIN_FILENAME(&p->Name[0]);
	printf ("\n");

	if (debug) hex_dump(p, 2);
}

int
process_load_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	ProcessLoad_t *p = (ProcessLoad_t *)trcinfop->cur_event;
	uint16 *chr;
	pid_info_t *pidp, *tgidp;

	pidp = GET_PIDP(&globals->pid_hash, p->tid);
	tgidp = GET_PIDP(&globals->pid_hash, p->ProcessID);

	if (kitrace_flag) {
		print_process_load_func (a, v);
	} else {
		update_pid_ids(p->tid, p->pid);
		trcinfop->pid = p->tid; 
	}

	chr = &p->Name[0];
	/* printf ("pid=%d ", tgidp->PID); PRINT_WIN_NAME2(chr);  printf ("\n"); */
	PRINT_WIN_NAME2_STR(util_str, chr);
	if (strstr(util_str, ".exe")) {
		add_command (&tgidp->cmd, strrchr(util_str, '\\')+1);
		add_command (&pidp->cmd, strrchr(util_str, '\\')+1);
	}
}
