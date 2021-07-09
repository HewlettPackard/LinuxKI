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
print_diskio_init_func (trace_info_t *trcinfop, DiskIo_Init_t *p, pid_info_t *pidp, winki_stack_info_t *stkinfop)
{
	PRINT_COMMON_FIELDS_C002(p);

	printf (" tid=%d irp=0x%llx",
	        p->IssuingThreadId,
	        p->Irp);

	if (stkinfop->depth) {
		printf (" Stacktrace: ");
		PRINT_WIN_STKTRC2(pidp, stkinfop);
	}

	printf ("\n");

	if (debug) hex_dump(p, 6);
}


int diskio_init_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_Init_t *p = (DiskIo_Init_t *)trcinfop->cur_event;
	filter_t *f = v;
	pid_info_t *pidp;
	winki_stack_info_t stkinfo;

	/* we have to peak to see if the next event for the buffer it a StackWalk event */
	/* However, if we are at the end of the buffer, we need to move to the next one */
	if (trcinfop->next_event == (char *)GETNEWBUF) {
	        get_new_buffer(trcinfop, trcinfop->cpu);
	}

	update_pid_ids(p->tid, p->pid);
	trcinfop->pid = p->tid; 
	pidp = GET_PIDP(&globals->pid_hash, p->tid);

	stkinfo.depth = 0;
	winki_save_stktrc(trcinfop, trcinfop->next_event, &stkinfo);

	if (kitrace_flag) {
		print_diskio_init_func(trcinfop, p, pidp, &stkinfo);
	}
}

static inline int
diskio_incr_compl_iostats(DiskIo_ReadWrite_t *p, iostats_t *statp, uint64 qtm, uint64 svtm)
{
	statp->compl_cnt++;
	statp->sect_xfrd += p->TransferSize / 512;
	statp->cum_ioserv += svtm;
	statp->cum_iowait += qtm;
	statp->max_ioserv = MAX(statp->max_ioserv, svtm);
	statp->max_iowait = MAX(statp->max_iowait, qtm);

	if (statp->next_sector == p->ByteOffset/512) {
		statp->seq_ios++;
	} else {
		statp->random_ios++;
	}

	statp->next_sector = p->ByteOffset/512 + p->TransferSize/512;

	return 0;
}

static inline void
diskio_dev_complete_stats(DiskIo_ReadWrite_t *p, uint64 qtm, uint64 svtm) 
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev;

	rw = ioreq_type(p->EventType);
	dev = p->DiskNumber;

	devinfop = GET_DEVP(&globals->devhash, dev);
	diskio_incr_compl_iostats(p, &devinfop->iostats[rw], qtm, svtm);
}

static inline void
diskio_perfile_complete_stats(DiskIo_ReadWrite_t *p, uint64 qtm, uint64 svtm)
{
	fileobj_t *fobjinfop;
	filedev_t *fdevinfop;
	uint32 rw;
	uint32 dev = p->DiskNumber;
	uint64 obj = p->FileObject;

	rw = ioreq_type(p->EventType);

	fobjinfop = GET_FOBJP(&globals->fobj_hash, obj);
	diskio_incr_compl_iostats(p, &fobjinfop->piostats[rw], qtm, svtm);

	fdevinfop = GET_FDEVP(&fobjinfop->fdev_hash, dev);
	diskio_incr_compl_iostats(p, &fdevinfop->stats[rw], qtm, svtm);
}

static inline void
diskio_perpid_complete_stats(DiskIo_ReadWrite_t *p, pid_info_t *pidp, uint64 qtm, uint64 svtm)
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev;

	rw = ioreq_type(p->EventType);
	dev = p->DiskNumber;

	diskio_incr_compl_iostats(p, IOSTATSP(pidp, dev, rw), qtm, svtm);

	devinfop = GET_DEVP(&pidp->devhash, dev);
	diskio_incr_compl_iostats(p, &devinfop->iostats[rw], qtm, svtm);
}	

static inline void
diskio_global_complete_stats(DiskIo_ReadWrite_t *p, uint64 qtm, uint64 svtm)
{
	iotimes_t *timesp;
	uint32 rw;
	uint64 dev;

	rw = ioreq_type(p->EventType);

	diskio_incr_compl_iostats(p, IOSTATSP(globals, dev, rw), qtm, svtm);

	timesp = find_add_info (&globals->iotimes, sizeof (iotimes_t));
	incr_io_histogram(&timesp->time[rw][0], rw, svtm);
} 

int print_diskio_readwrite_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_ReadWrite_t *p = (DiskIo_ReadWrite_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	pidp = GET_PIDP(&globals->pid_hash, p->IssuingThreadId);

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" disk=%d offset=0x%llx size=0x%x irp=0x%llx flags=%s fileobj=0x%llx",
		p->DiskNumber,
		p->ByteOffset,
		p->TransferSize,
		p->Irp,
		irqflags(p->IrpFlags & 0xffff),
		p->FileObject);

	printf (" tid=%d pid=%d svtm=",
		p->IssuingThreadId,
		pidp->tgid);
	PRINT_TIME_DIFF(0, p->HighResResponseTime);

	printf ("\n");

	if (debug) hex_dump(p, 3);
}

int diskio_readwrite_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_ReadWrite_t *p = (DiskIo_ReadWrite_t *)trcinfop->cur_event;
	filter_t *f = v;
	pid_info_t *pidp;
	uint64 svtm;

	if (kitrace_flag) {
		print_diskio_readwrite_func(trcinfop, f);
	}

	pidp = GET_PIDP(&globals->pid_hash, p->IssuingThreadId);
	svtm = (p->HighResResponseTime * 1000000000) / winki_hdr->PerfFreq;

	if (svtm > 0) {
		if (perdsk_stats) diskio_dev_complete_stats(p, 0, svtm);
		if (perpid_stats) diskio_perpid_complete_stats(p, pidp, 0, svtm);
		if (global_stats && perfd_stats) diskio_perfile_complete_stats(p, 0, svtm); 
		if (global_stats) diskio_global_complete_stats(p, 0, svtm);
	}
}

int
print_diskio_flush_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	DiskIo_Flush_t *p = (DiskIo_Flush_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	pidp = GET_PIDP(&globals->pid_hash, p->IssuingThreadId);

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" disk=%d flags=%s irp=0x%llx tid=%d pid=%d svtm=",
		p->DiskNumber,
		irqflags(p->IrpFlags & 0xffff),
		p->Irp,
		p->IssuingThreadId,
		pidp->tgid);
	PRINT_TIME_DIFF(0, p->HighResResponseTime);

	printf ("\n");

	if (debug) hex_dump(p, 3);
}

int diskio_flush_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;

	if (kitrace_flag) {
		print_diskio_flush_func(trcinfop, f);
	}
}
