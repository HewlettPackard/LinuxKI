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

#include "Pdb.h"

int
print_fileio_create_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_Create_t *p = (FileIo_Create_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	winki_stack_info_t stkinfo, *stkinfop;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	stkinfop = &stkinfo;
	stkinfop->depth = 0;
	winki_save_stktrc(trcinfop, trcinfop->next_event, stkinfop);

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 

	pidp = GET_PIDP(&globals->pid_hash, p->pid);

	printf (" irp=0x%llx obj=0x%llx options=0x%x attr=%d access=%d",
	p->IrpPtr,
	p->FileObject,
	p->CreateOptions,
	p->FileAttributes,
	p->ShareAccess);

	printf (" filename=\"");
	PRINT_WIN_FILENAME(&p->OpenPath[0]);
	printf ("\"");

	PRINT_WIN_STKTRC2(pidp, stkinfop);

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

int
print_fileio_readwrite_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_ReadWrite_t *p = (FileIo_ReadWrite_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	winki_stack_info_t stkinfo, *stkinfop;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	stkinfop = &stkinfo;
	stkinfop->depth = 0;
	winki_save_stktrc(trcinfop, trcinfop->next_event, stkinfop);

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 
	pidp = GET_PIDP(&globals->pid_hash, p->pid);

	printf (" offset=0x%llx irp=0x%llx ttid=0x%llx obj=0x%llx size=%d flags=0x%x",
		p->Offset,
		p->IrpPtr,
		p->TTID,
		p->FileObject,
		p->IoSize,
		p->IoFlags);

	PRINT_WIN_STKTRC2(pidp, stkinfop);

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

int
print_fileio_opend_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_OpEnd_t *p = (FileIo_OpEnd_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 

	printf (" irp=0x%llx extra=0x%x status=%d",
		p->IrpPtr,
		p->ExtraInfo,
		p->NtStatus);

	printf ("\n");

	if (debug) hex_dump(p, 4);
}

int
print_fileio_name_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_FileName_t *p = (FileIo_FileName_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" obj=0x%llx", p->FileObject);

	printf (" \"");
	PRINT_WIN_FILENAME(&p->FileName[0]);
	printf ("\"");
	printf ("\n");

	if (debug) hex_dump(p, 3);
}

int
print_fileio_info_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_Info_t *p = (FileIo_Info_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C002(p);

	printf (" irp=0x%llx ttid=0x%llx obj=0x%llx class=%d\n",
		p->IrpPtr,
		p->TTID,
		p->FileObject,
		p->InfoClass);	
}		

int
print_fileio_direnum_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_DirEnum_t *p = (FileIo_DirEnum_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	winki_stack_info_t stkinfo, *stkinfop;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	stkinfop = &stkinfo;
	stkinfop->depth = 0;
	winki_save_stktrc(trcinfop, trcinfop->next_event, stkinfop);

	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 
	pidp = GET_PIDP(&globals->pid_hash, p->pid);

	printf (" irp=0x%llx ttid=0x%llx obj=0x%llx len=%d class=%d index=%d",
		p->IrpPtr,
		p->TTID,
		p->FileObject,
		p->Length,
		p->InfoClass,
		p->FileIndex);

	printf (" filename=\"");
	PRINT_WIN_FILENAME(&p->FileName[0]);
	printf ("\"");

	PRINT_WIN_STKTRC2(pidp, stkinfop);

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

int
print_fileio_simpleop_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_SimpleOp_t *p = (FileIo_SimpleOp_t *)trcinfop->cur_event;
	pid_info_t *pidp;
	winki_stack_info_t stkinfo, *stkinfop;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
		get_new_buffer(trcinfop, trcinfop->cpu);
	}

	stkinfop = &stkinfo;
	stkinfop->depth = 0;
	winki_save_stktrc(trcinfop, trcinfop->next_event, stkinfop);


	PRINT_COMMON_FIELDS_C002(p);
	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 
	pidp = GET_PIDP(&globals->pid_hash, p->pid);

	printf (" irp=0x%llx ttid=0x%llx obj=0x%llx",
		p->IrpPtr,
		p->TTID,
		p->FileObject);

	PRINT_WIN_STKTRC2(pidp, stkinfop);

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

