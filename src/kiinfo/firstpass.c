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
#include <unistd.h>
#include "ki_tool.h"
#include "winki.h"
#include "liki.h"
#include "liki_extra.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "info.h"
#include "kd_types.h"

#include "Image.h"
#include "Provider.h"
#include "SysConfig.h"
#include "winki_util.h"

int firstpass_image_func(void *, void *);
int firstpass_header_func(void *, void *);
int firstpass_generic_func(void *, void *);
int firstpass_provider_func(void *, void *);

static inline void
win_set_firstpass_funcs()
{
	int i;

	winki_init_actions(NULL);

	winki_enable_event(0, winki_header_func);
	for (i = 1; i < 10; i++) {
		winki_enable_event(i, firstpass_generic_func);
	}

	winki_enable_event(0x24, firstpass_header_func);
	winki_enable_event(0x1402, firstpass_image_func);
	winki_enable_event(0x1403, firstpass_image_func);
	winki_enable_event(0x1404, firstpass_image_func);
	winki_enable_event(0x140a, firstpass_image_func);
	winki_enable_event(0x1421, firstpass_image_func);
	winki_enable_event(0xb0f, sysconfig_services_func);
}

/*
 ** The initialization function
 */
void
firstpass_init_func(void *v)
{
	int i;
	pid_info_t *pidp;

	if (debug) printf ("firstpass_init_func()\n");
        process_func = NULL;
        print_func = NULL;
        report_func = NULL;
        filter_func  = NULL;
	alarm_func = NULL;
        bufmiss_func = NULL;

	if (IS_WINKI) { 
		win_set_firstpass_funcs();

		/* Init the System process - PID 4 */
		pidp = GET_PIDP(&globals->pid_hash, 4);
		add_command(&pidp->cmd, "System");
	} else {
		/* only for Windows for now */
	}

}

int
save_image_c002_func(Image_Load_c002_t *p)
{
	int pid;
	uint16 *chr;
	char *ptr;
	pid_info_t *pidp;
	vtxt_preg_t *vtxt_pregp;

	update_pid_ids(p->tid, p->pid);

	pidp = GET_PIDP(&globals->pid_hash, p->pid);

	if (WINKERN_ADDR(p->ImageBase)) { 
		vtxt_pregp = GET_ADD_VTXT(&globals->vtxt_pregp, p->ImageBase);
	} else {
		vtxt_pregp = GET_ADD_VTXT(&pidp->vtxt_pregp, p->ImageBase);
	}

	if (vtxt_pregp->p_vaddr == 0ull) {
		vtxt_pregp->p_vaddr = p->ImageBase;
		vtxt_pregp->p_endaddr = p->ImageBase + p->ImageSize;
		vtxt_pregp->p_off = 0;

		/* we only want the last part of the pathname here */
		chr = &p->FileName[0];
		PRINT_WIN_NAME2_STR(util_str, chr);
		if ((ptr = strrchr(util_str, '\\')) == NULL) {
			ptr = util_str;
		}

		/* skip leading '\' */
		ptr++;

		vtxt_pregp->filename = malloc(strlen(ptr)+1);
		if (vtxt_pregp->filename) {
			MALLOC_LOG(vtxt_pregp->filename, strlen(ptr)+1);
			strcpy(vtxt_pregp->filename, ptr);	
		}

		if (debug) printf ("PID: %d  Start: 0x%llx  End: 0x%llx Filename: %s\n", 
			p->pid, 
			vtxt_pregp->p_vaddr,
			vtxt_pregp->p_endaddr, 
			vtxt_pregp->filename);
	}
}


int
save_image_c011_func(Image_Load_c011_t *p)
{
	int pid;
	uint16 *chr;
	char *ptr;
	pid_info_t *pidp;
	vtxt_preg_t *vtxt_pregp;

	pidp = GET_PIDP(&globals->pid_hash, p->ProcessId);

	if (WINKERN_ADDR(p->ImageBase)) { 
		vtxt_pregp = GET_ADD_VTXT(&globals->vtxt_pregp, p->ImageBase);
	} else {
		vtxt_pregp = GET_ADD_VTXT(&pidp->vtxt_pregp, p->ImageBase);
	}

	if (vtxt_pregp->p_vaddr == 0ull) {
		vtxt_pregp->p_vaddr = p->ImageBase;
		vtxt_pregp->p_endaddr = p->ImageBase + p->ImageSize;
		vtxt_pregp->p_off = 0;
	}

	/* we only want the last part of the pathname here */
	chr = &p->FileName[0];
	PRINT_WIN_NAME2_STR(util_str, chr);
	if ((ptr = strrchr(util_str, '\\')) == NULL) {
		ptr = util_str;
	}

	/* skip leading '\' */
	ptr++;

	if (strstr(ptr, ".exe") && (pidp->cmd == NULL)) {
		add_command(&pidp->cmd, ptr);
	}

	add_command (&vtxt_pregp->filename, ptr);
	if (debug) printf ("PID: %d  Start: 0x%llx  End: 0x%llx Filename: %s\n", 
		p->ProcessId, 
		vtxt_pregp->p_vaddr,
		vtxt_pregp->p_endaddr, 
		vtxt_pregp->filename);
}

int
firstpass_image_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	etw_common_t *p = (etw_common_t *)trcinfop->cur_event;
        if (p->ReservedHeaderField == 0xc002) {
                save_image_c002_func((Image_Load_c002_t *)p);
        } else if (p->ReservedHeaderField == 0xc011) {
                save_image_c011_func((Image_Load_c011_t *)p);
        }
}

/* These traces are very tricky */
int
firstpass_provider_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	Provider_t *p = (Provider_t *)trcinfop->cur_event;
	int i;

	if ((p->guid[0] == 0xb3e675d7) && (p->guid[1] == 0x4f182554) && (p->guid[2] == 0x62270b83) && (p->guid[3] == 0xde602573)) {	
		if (p->EventType == 64) {
			file_version_func((FileVersion_t *)p);
                } else if (p->EventType == 36) {
                        pdb_image_func((PdbImage_t *)p);
                }
	}

}

int
firstpass_generic_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        etw_common_t *p = (etw_common_t *)trcinfop->cur_event;
        etw_common_c002_t *p2 = (etw_common_c002_t *)trcinfop->cur_event;;
        etw_common_c011_t *p11 = (etw_common_c011_t *)trcinfop->cur_event;;

        if (p->ReservedHeaderField == 0xc014) {
                firstpass_provider_func(trcinfop, v);
                return 0;
        }
}

int
firstpass_header_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	EventTraceHdr_t *p = (EventTraceHdr_t *)trcinfop->cur_event;
	etw_common_c014_t *p014 = (etw_common_c014_t *)trcinfop->cur_event;

	/* this is a special case */
	if (p->ReservedHeaderField == 0xc014) {
		firstpass_provider_func(trcinfop, v);
		return 0;
	}

	/* PRINT_TIME(p->TimeStamp); */
	if (winki_hdr == NULL) winki_hdr = p;
}
