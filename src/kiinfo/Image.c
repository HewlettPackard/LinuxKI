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
print_image_c002_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        Image_Load_c002_t *p = (Image_Load_c002_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C002(p);
        update_pid_ids(p->tid, p->pid);

        printf (" base=0x%llx size=0x%llx pid=%d cksum=%d",
                p->ImageBase,
                p->ImageSize,
                p->ProcessId,
                p->ImageCheckSum);

        printf (" filename=\"");
        PRINT_WIN_FILENAME(&p->FileName[0]);
        printf ("\"");

        printf ("\n");

        if (debug) hex_dump(p, 4);
}


int
print_image_c011_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        Image_Load_c011_t *p = (Image_Load_c011_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, 0, 0);

        printf (" base=0x%llx size=0x%llx pid=%d cksum=%d default_base=0x%llx",
                p->ImageBase,
                p->ImageSize,
                p->ProcessId,
                p->ImageCheckSum,
                p->DefaultBase);

        printf (" filename=\"");
        PRINT_WIN_FILENAME(&p->FileName[0]);
        printf ("\"");

        printf ("\n");

        if (debug) hex_dump(p, 4);
}


int
print_image_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	etw_common_t *p = (etw_common_t *)trcinfop->cur_event;

	if (p->ReservedHeaderField == 0xc002) {
		print_image_c002_func(trcinfop, v);
	} else if (p->ReservedHeaderField == 0xc011) {
	        print_image_c011_func(trcinfop, v);
	} else {
	        printf ("Unknown Reserved Header Field\n");
	        hex_dump(p, 4);
	}
}

int
image_dcstart_func (void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        Image_Load_c011_t *p = (Image_Load_c011_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	uint16 *chr;

	pidp=GET_PIDP(&globals->pid_hash, p->ProcessId);

	if (kitrace_flag) {
		print_image_c011_func(trcinfop, v);
	}

        chr = &p->FileName[0];
        PRINT_WIN_NAME2_STR(util_str, chr);
        if (strstr(util_str, ".exe")) {
                add_command (&pidp->cmd, strrchr(util_str, '\\')+1);
        }
}

int
image_dcend_func (void *a, void *v)
{

}
