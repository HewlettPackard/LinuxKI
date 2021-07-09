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
calc_fdev_totals(void *arg1, void *arg2) 
{
        filedev_t *fdevinfop = (filedev_t *)arg1;

        calc_io_totals(&fdevinfop->stats[0], NULL);

        return 0;
}

int
calc_fobj_totals(void *arg1, void *arg2) 
{
        fileobj_t *fobjinfop = (fileobj_t *)arg1;
	fstats_t *fstats;

        if (fobjinfop == NULL) return 0;

	fstats = &fobjinfop->liostats[0];
	fstats[IOTOT].bytes = fstats[IORD].bytes + fstats[IOWR].bytes;
	fstats[IOTOT].cnt = fstats[IORD].cnt + fstats[IOWR].cnt;
	fstats[IOTOT].seqios = fstats[IORD].seqios + fstats[IOWR].seqios;
	fstats[IOTOT].rndios = fstats[IORD].rndios + fstats[IOWR].rndios;

        calc_io_totals(&fobjinfop->piostats[0], NULL);

	if (fobjinfop->fdev_hash) {
		foreach_hash_entry((void **)fobjinfop->fdev_hash, FDEV_HSIZE, calc_fdev_totals, NULL, 0, 0);
	}

        return 0;
}

static inline int
fileio_incr_fileobj_stats(FileIo_ReadWrite_t *p, fstats_t *statp)
{

	if (p->Offset == statp->next_offset) {
		statp->seqios++;
	} else {
		statp->rndios++;
	}

	statp->cnt++;
	statp->bytes += p->IoSize;
	statp->next_offset += p->Offset + p->IoSize;
}

static inline void
fileio_perfile_stats(FileIo_ReadWrite_t *p) 
{
	fileobj_t *fobjinfop;
	uint32 rw;
	uint64 obj = p->FileObject;

	rw = filereq_type(p->EventType);

	fobjinfop = GET_FOBJP(&globals->fobj_hash, obj);

	fileio_incr_fileobj_stats(p, &fobjinfop->liostats[rw]);
	fobjinfop->last_tid = p->tid;
}

static inline void
fileio_perpid_file_stats(FileIo_ReadWrite_t *p) 
{
	fileobj_t *fobjinfop;
	uint32 rw;
	uint64 obj = p->FileObject;
	pid_info_t *pidp;

	pidp = GET_PIDP(&globals->pid_hash, p->tid);

	rw = filereq_type(p->EventType);

	fobjinfop = GET_FOBJP(&pidp->fobj_hash, obj);
	
	fileio_incr_fileobj_stats(p, &fobjinfop->liostats[rw]);
	fobjinfop->last_tid = p->tid;
}

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

	/*
	printf (" Stacktrace: ");
	PRINT_WIN_STKTRC2(pidp, stkinfop);
	*/

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

int
fileio_create_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_Create_t *p = (FileIo_Create_t *)trcinfop->cur_event;
	fileobj_t *fobjinfop;
	uint16 *chr;

	chr = &p->OpenPath[0];
	PRINT_WIN_NAME2_STR(util_str, chr)

	fobjinfop = GET_FOBJP(&globals->fobj_hash, p->FileObject);
	add_command(&fobjinfop->filename, util_str);

	if (kitrace_flag) 
		print_fileio_create_func(a, v);
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

	/* 
	printf (" Stacktrace: ");
	PRINT_WIN_STKTRC2(pidp, stkinfop);
	*/

	printf ("\n");

	if (debug) hex_dump(p, 6);
}


int 
fileio_readwrite_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_ReadWrite_t *p = (FileIo_ReadWrite_t *)trcinfop->cur_event;

	if (global_stats && perfd_stats) fileio_perfile_stats(p);
	if (perpid_stats && perfd_stats) fileio_perpid_file_stats(p);

	if (kitrace_flag)
		print_fileio_readwrite_func(a, v);
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


int fileio_name_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	FileIo_FileName_t *p = (FileIo_FileName_t *)trcinfop->cur_event;
	fileobj_t *fobjinfop;
	uint16 *chr;

	chr = &p->FileName[0];
	PRINT_WIN_NAME2_STR(util_str, chr)

	fobjinfop = GET_FOBJP(&globals->fobj_hash, p->FileObject);
	add_command(&fobjinfop->filename, util_str);

	if (kitrace_flag) 
		print_fileio_name_func(a, v);
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

       	/* printf (" Stacktrace: ");	
	PRINT_WIN_STKTRC2(pidp, stkinfop);
	*/

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

	/* printf (" Stacktrace: ");
	PRINT_WIN_STKTRC2(pidp, stkinfop);
	*/

	printf ("\n");

	if (debug) hex_dump(p, 6);
}

