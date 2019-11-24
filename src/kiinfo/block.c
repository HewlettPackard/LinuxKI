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
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "conv.h"
#include "scsi.h"

#define BLOCK_RQ_CMD	5
#define INVALID_SECTOR(sector)  ((sector == 0) || (sector == 0xffffffffffffffff) || (sector == 0x7ffffffffff) || (sector == 0x7fff00000000))
/*  The BARRIER_IO macros is bad since the cmd_flags are ever changing, need to revisit */
/*  This is the bad Barrier IO below 
#define BARRIER_IO(ptr) (((ptr->sector == 0) || (ptr->sector == 0xffffffffffffffff)) && (ptr->nr_sectors == 0) && 	\
			((ptr->cmd_flags & globals->sync_bit) || (reqop(ptr->cmd_flags) == IO_WRITE)))
*/
#define BARRIER_IO(ptr) (INVALID_SECTOR(ptr->sector) && flush_flag(ptr->cmd_flags))




static inline int
incr_insert_iostats (block_rq_insert_t *rec_ptr, iostats_t *statp, int *rndio_flagp)
{

	if (BARRIER_IO(rec_ptr)) {
		statp->barrier_cnt++;
		return 0;
	} else if (INVALID_SECTOR(rec_ptr->sector)) {
		return 0;
	}

	statp->insert_cnt++;
	statp->qlen++;
	statp->qops++;
	statp->cum_qlen+=statp->qlen;
	statp->max_qlen = MAX(statp->max_qlen, statp->qlen);

	if (rndio_flagp) {
		if (*rndio_flagp == -1) {
			/* calculate random I/Os as usual and set *rndio_flags */
			if (statp->next_sector == rec_ptr->sector) {
				statp->seq_ios++;
				*rndio_flagp = 0;
			} else {
				statp->random_ios++;
				*rndio_flagp = 1;
			}
		} else if (*rndio_flagp == 1) {
			statp->random_ios++;
		} else {
			statp->seq_ios++;
		}
	}

	statp->next_sector = rec_ptr->sector + rec_ptr->nr_sectors;

	return 0;
}

static inline int
incr_issue_iostats (block_rq_issue_t *rec_ptr, iostats_t *statp, int *rndio_flagp)
{
	if (statp->qlen > 0) {
		statp->issue_cnt++;
		if (statp->qlen > 0) { 
			statp->qlen--;
			statp->cum_qlen+=statp->qlen;
			statp->qops++;
		}
	}

	statp->cum_async_inflight += rec_ptr->async_in_flight;
	statp->cum_sync_inflight += rec_ptr->sync_in_flight;

	return 0;
}

static inline int
incr_compl_iostats(block_rq_complete_t *rec_ptr, iostats_t *statp, uint64 qtm, uint64 svtm)
{
	statp->compl_cnt++;
	statp->sect_xfrd += rec_ptr->nr_sectors;
	statp->cum_ioserv += svtm;
	statp->cum_iowait += qtm;
	statp->max_ioserv = MAX(statp->max_ioserv, svtm);
	statp->max_iowait = MAX(statp->max_iowait, qtm);

	return 0;
}

static inline int
incr_io_histogram(uint32 *io_times, int rw, uint64 svtm)
{
	uint64 elapsed_time = svtm / 1000000;		/* elapsed time is in msecs */
	int i;

        for (i=0; i < (NBUCKETS-1); i++) {
                if (elapsed_time < dsk_io_sizes[i]) {
                        io_times[i]++;
                        break;
                } else {
                        continue;
                }
        }

        if (elapsed_time >= dsk_io_sizes[NBUCKETS-2]) {
                io_times[i]++;
        }

	return 0;
}

static inline void *
track_inserted_ios(void *a)
{
        block_rq_insert_t *rec_ptr = (block_rq_insert_t *)a;
        uint64 sector = rec_ptr->sector;
	uint64 dev = DEV(rec_ptr->dev);
        io_req_t *ioreqp;
        dev_info_t *devinfop;

        /* don't track these special sectors */
        if (INVALID_SECTOR(sector)) return NULL;

	/* fprintf (stderr, "track_inserted_ios() - dev 0x%x, sector %lld, nr_sectors, %d\n", dev, sector, rec_ptr->nr_sectors); */
        devinfop = GET_DEVP(DEVHASHP(globals,dev),dev);
        ioreqp = GET_IOREQP(&devinfop->ioq_hash, sector);
        ioreqp->insert_time = rec_ptr->hrtime;
	ioreqp->insert_pid = rec_ptr->pid;
	ioreqp->sector = sector;
	ioreqp->nr_sector = rec_ptr->nr_sectors;

	return ioreqp;
}

static inline void *
find_overlapping_ioreq(void **arg, uint64 sector, uint32 len)
{
	lle_t **hashptr = (lle_t **)arg;
	io_req_t *ioreqp, *pioreqp;
	int i;
	uint64 end = sector + len;
	uint64 msector, mend;

	if (hashptr == NULL) return NULL;

	/* fprintf (stderr, "find_overlapping_ioreq():  sector=%lld end=%lld len=%d\n",  sector, sector+len, len);  */
	for (i = 0; i < IOQ_HSIZE; i++) {
		pioreqp = (io_req_t *)&hashptr[i];
		ioreqp = (io_req_t *)hashptr[i];
		while (ioreqp != NULL) {
			msector = ioreqp->sector;
			mend = ioreqp->sector + ioreqp->nr_sector;
			if ((sector <= msector) &&  (mend <= end)) {
				pioreqp->lle.next = ioreqp->lle.next;
				/* fprintf (stderr, "found overlapping ioreq() msector: %lld, mend: %lld\n", msector, mend ); */
				return (void *)ioreqp;
			}
		
			pioreqp = ioreqp;	
			ioreqp = (io_req_t *)ioreqp->lle.next;
		}
	}

	return NULL;
}

static inline void *
track_issued_ios(void *a)
{
        block_rq_issue_t *rec_ptr = (block_rq_issue_t *)a;
        uint64 sector = rec_ptr->sector;
	uint64 dev = DEV(rec_ptr->dev);
        io_req_t *ioreqp, *mioreqp;
        dev_info_t *devinfop;
	if (debug) printf ("track_issued_ios()\n");

        /* don't track these special sectors */
        if (INVALID_SECTOR(sector)) return NULL;

	/* fprintf (stderr, "track_issued_ios() - dev 0x%x, sector %d, nr_sectors %d\n", dev, sector, rec_ptr->nr_sectors); */
        devinfop = GET_DEVP(DEVHASHP(globals,dev),dev);
        ioreqp = FIND_IOREQP(devinfop->ioq_hash, sector);
	if (ioreqp) {
        	ioreqp->issue_time = rec_ptr->hrtime;
		ioreqp->issue_pid = rec_ptr->pid;
		ioreqp->nr_sector = rec_ptr->nr_sectors;
		return ioreqp;
	} else if (ioreqp = find_overlapping_ioreq((void **)devinfop->ioq_hash, sector, rec_ptr->nr_sectors)) {
		/* if no ioreq found, then check for overlapping request
 		 * in case we have merged requests 
 		 */
		mioreqp = GET_IOREQP(&devinfop->ioq_hash, sector);
		mioreqp->insert_pid = ioreqp->insert_pid;
		mioreqp->insert_time = ioreqp->insert_time;
		mioreqp->issue_pid = rec_ptr->pid;
		mioreqp->issue_time = rec_ptr->hrtime;
		mioreqp->sector = sector;
		mioreqp->nr_sector = rec_ptr->nr_sectors;
		FREE(ioreqp);
		return mioreqp;
	} else {	
		/* add new entry */
		ioreqp = GET_IOREQP(&devinfop->ioq_hash, sector);
        	ioreqp->issue_time = rec_ptr->hrtime;
		ioreqp->issue_pid = rec_ptr->pid;
		ioreqp->insert_time = rec_ptr->hrtime;
		ioreqp->insert_pid = rec_ptr->pid;   /* indicates that insert is missing */
		ioreqp->sector = sector;
		ioreqp->nr_sector = rec_ptr->nr_sectors;
		return ioreqp;
	}
}

static inline void *
find_issued_io(uint32 dev, uint64 sector)
{
        io_req_t *ioreqp; 
        dev_info_t *devinfop;

	if (debug) printf ("find_issued_io()\n");
        
        /* don't track these special sectors */
        if (INVALID_SECTOR(sector)) return NULL;

	if ((dev_major(dev) == MAPPER_MAJOR) &&  (globals->mdevhash == NULL)) return NULL;
	if ((dev_major(dev) != MAPPER_MAJOR) &&  (globals->devhash == NULL)) return NULL;
        
        devinfop = FIND_DEVP(DEVHASH(globals, dev), (uint64)dev);
	if (devinfop == NULL) return NULL;

        ioreqp = FIND_AND_REMOVE_IOREQP(&devinfop->ioq_hash, sector);
	return ioreqp;
}

static inline void
block_global_insert_stats(block_rq_insert_t *rec_ptr)
{
	uint32 rw;
	rw = reqop(rec_ptr->cmd_flags); 
	if (rw > IO_WRITE) return;

	incr_insert_iostats (rec_ptr, &globals->iostats[rw], NULL);
}

static inline void
block_dev_insert_stats(block_rq_insert_t *rec_ptr)
{
	dev_info_t *devinfop;
	uint64 dev = DEV(rec_ptr->dev);
	uint32 rw;
	int rndio_flag=-1;
	
	if (debug) printf ("block_dev_insert_stats\n");
	rw = reqop(rec_ptr->cmd_flags); 
	if (rw > IO_WRITE) return;
	
        devinfop = GET_DEVP(DEVHASHP(globals,dev),dev);
	incr_insert_iostats (rec_ptr, &devinfop->iostats[rw], &rndio_flag);	

}

static inline void
block_perpid_insert_stats(block_rq_insert_t *rec_ptr, pid_info_t *pidp) 
{
	dev_info_t *devinfop;
	iostats_t *iostatsp;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);
	int rndio_flag=-1;

	if (pidp == NULL) return;
	rw = reqop(rec_ptr->cmd_flags); 
	if (rw > IO_WRITE) return;

	incr_insert_iostats(rec_ptr, IOSTATSP(pidp, dev, rw), NULL);

	devinfop = GET_DEVP(DEVHASHP(pidp, dev),dev); 
	incr_insert_iostats (rec_ptr, &devinfop->iostats[rw], &rndio_flag);	
}

static inline void
block_dev_complete_stats(block_rq_complete_t *rec_ptr, uint64 qtm, uint64 svtm) 
{
	dev_info_t *devinfop;
	mpath_info_t *mpath_infop;
	uint32 rw;
	uint64 dev;
	int	cpu;

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	dev = DEV(rec_ptr->dev);
        devinfop = GET_DEVP(DEVHASHP(globals,dev),DEV(dev));
	
	incr_compl_iostats(rec_ptr, &devinfop->iostats[rw], qtm, svtm);

	if (dsk_mpath_flag) {
	        /* collect multipath stats on a per-cpu basis */
		cpu = rec_ptr->cpu;
                mpath_infop = GET_MPATHP(&devinfop->mpath_hash, cpu);
		incr_compl_iostats(rec_ptr, &mpath_infop->iostats[rw], qtm, svtm);
	}
	
}

static inline void
block_perpid_abort_stats(block_rq_abort_t *rec_ptr,  pid_info_t *pidp)
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

        if (INVALID_SECTOR(rec_ptr->sector)) return;
	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	IOSTATSP(pidp, dev, rw)->abort_cnt++;

	devinfop = GET_DEVP(DEVHASHP(pidp, dev),dev); 
	devinfop->iostats[rw].abort_cnt++;
}

static inline void
block_dev_abort_stats(block_rq_abort_t *rec_ptr)
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	devinfop = GET_DEVP(DEVHASHP(globals,dev),dev); 
	devinfop->iostats[rw].abort_cnt++;
}

static inline void
block_perpid_requeue_stats(block_rq_requeue_t *rec_ptr, pid_info_t *pidp)
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	IOSTATSP(pidp, dev, rw)->requeue_cnt++;

	devinfop = GET_DEVP(DEVHASHP(pidp, dev),dev); 
	devinfop->iostats[rw].requeue_cnt++;
}

static inline void
block_dev_requeue_stats(block_rq_requeue_t *rec_ptr)
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	devinfop = GET_DEVP(DEVHASHP(globals,dev),dev); 
	devinfop->iostats[rw].requeue_cnt++;
}

static inline void
block_perpid_complete_stats(block_rq_complete_t *rec_ptr, pid_info_t *pidp, uint64 qtm, uint64 svtm) 
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	incr_compl_iostats(rec_ptr, IOSTATSP(pidp, dev, rw), qtm, svtm);

	devinfop = GET_DEVP(DEVHASHP(pidp, dev),dev);
	incr_compl_iostats(rec_ptr, &devinfop->iostats[rw], qtm, svtm);
}

static inline void
block_percpu_complete_stats(block_rq_complete_t *rec_ptr, int pid, uint64 qtm, uint64 svtm) 
{
	cpu_info_t *cpuinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);
	int cpu = rec_ptr->cpu;

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
	incr_compl_iostats(rec_ptr, IOSTATSP(cpuinfop, dev, rw), qtm, svtm);
}

static inline void
block_global_complete_stats(block_rq_complete_t *rec_ptr, int pid, uint64 qtm, uint64 svtm) 
{
	iotimes_t *timesp;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	if (dev_major(dev) != MAPPER_MAJOR) {
		incr_compl_iostats(rec_ptr, IOSTATSP(globals, dev, rw), qtm, svtm);

		timesp = find_add_info (&globals->iotimes, sizeof (iotimes_t));
		incr_io_histogram(&timesp->time[rw][0], rw, svtm);
	}
}

static inline void
block_dskblk_complete_stats(block_rq_complete_t *rec_ptr)
{
	
	dskblk_info_t *dskblkp;
	uint32 rw;
	uint64 sector, dev;
	
	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	dev = rec_ptr->dev;
        sector = rec_ptr->sector;

	dskblkp = (dskblk_info_t *)find_add_hash_entry((lle_t ***)&globals->dskblk_hash,
					DSKBLK_HSIZE,
					DSKBLK_KEY(dev, sector),
					DSKBLK_HASH(DSKBLK_KEY(dev,sector)),
					sizeof(dskblk_info_t));

	dskblkp->sector = sector;
	if (rw == IO_WRITE)
		dskblkp->wr_cnt++;
	else
		dskblkp->rd_cnt++;

}

static inline void
block_dev_issue_stats(block_rq_issue_t *rec_ptr) 
{
	dev_info_t *devinfop;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	devinfop = GET_DEVP(DEVHASHP(globals, dev),dev);
	incr_issue_iostats (rec_ptr, &devinfop->iostats[rw], NULL);		
}

static inline void
block_global_issue_stats(block_rq_issue_t *rec_ptr)
{
	uint32 rw;
	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	incr_issue_iostats (rec_ptr, &globals->iostats[rw], NULL);
}

static inline void
block_perpid_issue_stats(block_rq_issue_t *rec_ptr, pid_info_t *pidp) 
{
	dev_info_t *devinfop;
	iostats_t *iostatsp;
	io_req_t *ioreqp;
	uint32 rw;
	uint64 dev = DEV(rec_ptr->dev);

	if (pidp == NULL) return;
        if ((nomapper_flag) && (dev_major(dev) == MAPPER_MAJOR)) return;

	rw = reqop(rec_ptr->cmd_flags); 
	if ((rw > IO_WRITE) || INVALID_SECTOR(rec_ptr->sector)) return;

	devinfop = GET_DEVP(DEVHASHP(globals, dev),dev);
	if (devinfop == NULL) return;

        ioreqp = FIND_IOREQP(devinfop->ioq_hash, rec_ptr->sector);
	if (ioreqp && ioreqp->insert_pid) {
		incr_issue_iostats(rec_ptr, IOSTATSP(pidp, dev, rw), NULL);

		devinfop = GET_DEVP(DEVHASHP(pidp, dev), dev);
		incr_issue_iostats (rec_ptr, &devinfop->iostats[rw], NULL);	
	}
}


static inline int
print_block_rq_insert_rec(void *a, char *scsi_cmd_addr)
{
	block_rq_insert_t *rec_ptr = (block_rq_insert_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);  
	PRINT_EVENT(rec_ptr->id); 

	printf ("%cdev_t=0x%08llx%cwr=%s%cflags=%s%csector=0x%llx%clen=%d",
		fsep, DEV(rec_ptr->dev),
		fsep, reqop_name(rec_ptr->cmd_flags),
		fsep, ioflags(rec_ptr->cmd_flags), 
		fsep, rec_ptr->sector,
		fsep, rec_ptr->nr_sectors * 512);

	if (IS_LIKI_V2_PLUS) {
		printf ("%casync=%d%csync=%d", 
			fsep, rec_ptr->async_in_flight, 
			fsep, rec_ptr->sync_in_flight);
	}
	/* printf ("%cflags: 0x%016llx", fsep, rec_ptr->cmd_flags);  */
	printf ("\n");
	return 0;
}

static inline int
print_block_rq_issue_rec(void *a, char *scsi_cmd_addr)
{
	block_rq_issue_t *rec_ptr = (block_rq_issue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr); 
	PRINT_EVENT(rec_ptr->id);

	printf ("%cdev_t=0x%08llx%cwr=%s%cflags=%s%csector=0x%llx%clen=%d",
		fsep, DEV(rec_ptr->dev),
		fsep, reqop_name(rec_ptr->cmd_flags),
		fsep, ioflags(rec_ptr->cmd_flags),
		fsep, rec_ptr->sector,
		fsep, rec_ptr->nr_sectors * 512);

	if (IS_LIKI_V2_PLUS) {
		printf ("%casync=%d%csync=%d", 
			fsep, rec_ptr->async_in_flight,
			fsep, rec_ptr->sync_in_flight);
	}

	/* printf ("%cflags: 0x%016llx", fsep, rec_ptr->cmd_flags); */
	printf ("\n");
	return 0;
}

static inline int
print_block_rq_complete_rec(void *a, int issue_pid, int insert_pid, uint64 qtm, uint64 svtm, char *scsi_cmd_addr)
{
	block_rq_complete_t *rec_ptr = (block_rq_complete_t *)a;

	if (kilive) return 0;
	
	PRINT_COMMON_FIELDS(rec_ptr);  
	PRINT_EVENT(rec_ptr->id); 

	printf ("%cdev_t=0x%08llx%cwr=%s%cflags=%s%csector=0x%llx%clen=%d",
		fsep, DEV(rec_ptr->dev),
		fsep, reqop_name(rec_ptr->cmd_flags),
		fsep, ioflags(rec_ptr->cmd_flags),
		fsep, rec_ptr->sector,
		fsep, rec_ptr->nr_sectors * 512);

	if (IS_LIKI_V2_PLUS) {
		printf ("%casync=%d%csync=%d", 
			fsep, rec_ptr->async_in_flight,
			fsep, rec_ptr->sync_in_flight);
	}

	printf ("%cqpid=%d%cspid=%d%cqtm= %9.06f%csvtm= %9.06f", 
		fsep, insert_pid, 
		fsep, issue_pid,
		fsep, SECS(qtm),
		fsep, SECS(svtm));

	/* printf ("%cflags: 0x%016llx", fsep, rec_ptr->cmd_flags); */
	printf ("\n");

	return 0;
}

static inline int
print_block_rq_requeue_rec(void *a, int issue_pid, int insert_pid, uint64 svtm, uint64 qtm)
{
	block_rq_requeue_t *rec_ptr = (block_rq_requeue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr); 
	PRINT_EVENT(rec_ptr->id);

	printf ("%cdev_t=0x%08llx%cwr=%s%cflags=%s%csector=0x%llx%clen=%d%cerr=%d",
		fsep, DEV(rec_ptr->dev),
		fsep, reqop_name(rec_ptr->cmd_flags),
		fsep, ioflags(rec_ptr->cmd_flags),
		fsep, rec_ptr->sector,
		fsep, rec_ptr->nr_sectors * 512,
		fsep, rec_ptr->errors);

	printf ("%cqpid=%d%cspid=%d%cqtm= %9.06f%creqtm= %9.06f", 
		fsep, insert_pid,
		fsep, issue_pid,
		fsep, SECS(qtm),
		fsep, SECS(svtm));
	printf ("\n");
}

static inline int
print_block_rq_abort_rec(void *a, int issue_pid, int insert_pid, uint64 svtm, uint64 qtm)
{
	block_rq_requeue_t *rec_ptr = (block_rq_requeue_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr); 
	PRINT_EVENT(rec_ptr->id);

	printf ("%cdev_t=0x%08x%cwr=%s%cflags=%s%csector=0x%llx%clen=%d%cerr=%d\n",
		fsep, DEV(rec_ptr->dev),
		fsep, reqop_name(rec_ptr->cmd_flags),
		fsep, ioflags(rec_ptr->cmd_flags),
		fsep, rec_ptr->sector,
		fsep, rec_ptr->nr_sectors * 512,
		fsep, rec_ptr->errors);

	printf ("%cqpid=%d%cspid=%d%cqtm= %9.06f%creqtm= %9.06f", 
		fsep, insert_pid,
		fsep, issue_pid,
		fsep, SECS(qtm),
		fsep, SECS(svtm));
	printf ("\n");
	return 0;
}

int
block_rq_insert_func(void *a, void *v)
{
        trace_info_t *trcinfop = a;
	filter_t *f = v;
	block_rq_insert_t tt_rec_ptr;
        block_rq_insert_t *rec_ptr;
	pid_info_t *pidp = NULL;
	char barrier_io=FALSE;
	char *scsi_cmd_addr = NULL;

	rec_ptr = conv_block_rq_insert(trcinfop, &tt_rec_ptr);

        if ((nomapper_flag) && (dev_major(DEV(rec_ptr->dev)) == MAPPER_MAJOR)) return 0;
        if (!check_filter(f->f_P_tgid, rec_ptr->tgid) &&
            !check_filter(f->f_P_pid, (uint64)rec_ptr->pid) &&
            !check_filter(f->f_dev, DEV(rec_ptr->dev)) &&
            !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu))
                return 0;

	if (perpid_stats) pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);

	track_inserted_ios(rec_ptr);

	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);
	if (perdsk_stats) block_dev_insert_stats(rec_ptr);
	if (perpid_stats) block_perpid_insert_stats(rec_ptr, pidp);
	if (global_stats) block_global_insert_stats(rec_ptr);

	if (kitrace_flag) {
		if ( rec_ptr->bytes && !IS_LIKI) {
			scsi_cmd_addr = (char *)trcinfop->cur_rec + block_rq_insert_attr[BLOCK_RQ_CMD].offset;
        	}
		print_block_rq_insert_rec(rec_ptr, scsi_cmd_addr);
	}

	return 0;
}

int 
block_rq_issue_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
        block_rq_issue_t tt_rec_ptr;
        block_rq_issue_t *rec_ptr;
	pid_info_t *pidp = NULL;
	char *scsi_cmd_addr = NULL;
	io_req_t *ioreqp;
	int issue_pid = 0, insert_pid = 0;
	pid_info_t *insert_pidp = NULL;

	rec_ptr = conv_block_rq_issue(trcinfop, &tt_rec_ptr);

        if ((nomapper_flag) && (dev_major(DEV(rec_ptr->dev)) == MAPPER_MAJOR)) return 0;
	if (perpid_stats) pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);

	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);
	if (ioreqp = track_issued_ios(rec_ptr)) {
		issue_pid = ioreqp->issue_pid;
		insert_pid = ioreqp->insert_pid;
		insert_pidp = GET_PIDP(&globals->pid_hash, insert_pid);

                if (!check_filter(f->f_P_tgid, insert_pidp->tgid) &&
                    !check_filter(f->f_P_pid, insert_pid) &&
                    !check_filter(f->f_dev, DEV(rec_ptr->dev)) &&
                    !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu)) {
                        return 0;
                }

		if (perdsk_stats) block_dev_issue_stats(rec_ptr); 
		if (perpid_stats) block_perpid_issue_stats(rec_ptr, pidp);
		if (global_stats) block_global_issue_stats(rec_ptr);
	} else if (filter_flag) {
		/* if there are filters but no ioreqp, then just return */
		return 0;
	}

	if (kitrace_flag) {
		if ( rec_ptr->bytes && !IS_LIKI) {
                       	scsi_cmd_addr = (char *)trcinfop->cur_rec + block_rq_insert_attr[BLOCK_RQ_CMD].offset;
               	}
		print_block_rq_issue_rec(rec_ptr, NULL);
	}
	return 0;
}

int
block_rq_complete_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
        block_rq_complete_t tt_rec_ptr;
        block_rq_complete_t *rec_ptr;
	io_req_t *ioreqp;
	uint64 svtm = 0, qtm = 0;
	int issue_pid = 0, insert_pid = 0;
	int insert_tgid = 0;
	pid_info_t *pidp = NULL;
	pid_info_t *insert_pidp = NULL;
	char *scsi_cmd_addr = NULL;

	rec_ptr = conv_block_rq_complete(trcinfop, &tt_rec_ptr);

        if ((nomapper_flag) && (dev_major(DEV(rec_ptr->dev)) == MAPPER_MAJOR)) return 0;

	if (pertrc_stats) {
		if (perpid_stats) pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		incr_trc_stats(rec_ptr, pidp);
	}

        if ((kitrace_flag && !filter_flag) &&  (INVALID_SECTOR(rec_ptr->sector) && !BARRIER_IO(rec_ptr))) { 
		if ((rec_ptr->nr_sectors==0) && rec_ptr->bytes && !IS_LIKI) {
                	scsi_cmd_addr = (char *)trcinfop->cur_rec + block_rq_complete_attr[BLOCK_RQ_CMD].offset;
        	}
        	print_block_rq_complete_rec(rec_ptr, 0, 0, 0, 0, scsi_cmd_addr);
		return 0;
	}

	ioreqp = find_issued_io(DEV(rec_ptr->dev), rec_ptr->sector);
	if (ioreqp) {
		issue_pid = ioreqp->issue_pid;
		insert_pid = ioreqp->insert_pid;
		insert_pidp = GET_PIDP(&globals->pid_hash, insert_pid);

                if (!check_filter(f->f_P_tgid, insert_pidp->tgid) &&
                    !check_filter(f->f_P_pid, insert_pid) &&
                    !check_filter(f->f_dev, DEV(rec_ptr->dev)) &&
                    !check_filter(f->f_P_cpu, (uint64)rec_ptr->cpu)) {
                        FREE(ioreqp);
                        return 0;
                }

                if (ioreqp->insert_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                } else if (ioreqp->issue_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->insert_time;
                } else if (ioreqp->insert_time > ioreqp->issue_time) {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                } else {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                        qtm = ioreqp->issue_time - ioreqp->insert_time;
                }
		FREE(ioreqp);
	} else if (filter_flag) {
		/* if there are filters but no ioreqp, then just return */
		return 0;
	}

	if (svtm > 0) {
		if (perdsk_stats) block_dev_complete_stats(rec_ptr, qtm, svtm); 
		if (perpid_stats && insert_pidp && (insert_pid > 0)) block_perpid_complete_stats(rec_ptr, insert_pidp, qtm, svtm);
		if (percpu_stats) block_percpu_complete_stats(rec_ptr, insert_pid, qtm, svtm);
		if (global_stats) block_global_complete_stats(rec_ptr, insert_pid, qtm, svtm);
		if (dskblk_stats) block_dskblk_complete_stats(rec_ptr);
	}

	if (kitrace_flag || (dsk_detail_flag && ((svtm/1000000) >= dsk_io_sizes[NBUCKETS-2]))) {
		print_block_rq_complete_rec(rec_ptr, insert_pid, issue_pid, qtm, svtm, NULL);
	}

	return 0;
}

int 
block_rq_abort_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
        block_rq_abort_t tt_rec_ptr;
        block_rq_abort_t *rec_ptr;
	io_req_t *ioreqp;
	pid_info_t *pidp = NULL;
	pid_info_t *insert_pidp = NULL;
	uint64 svtm = 0, qtm = 0;
	int issue_pid = 0, insert_pid = 0;

	rec_ptr = conv_block_rq_abort(trcinfop, &tt_rec_ptr);

        if ((nomapper_flag) && (dev_major(DEV(rec_ptr->dev)) == MAPPER_MAJOR)) return 0;

	if (pertrc_stats) { 
		if (perpid_stats) pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		incr_trc_stats(rec_ptr, pidp);
	}

	if (ioreqp) {
                issue_pid = ioreqp->issue_pid;
                insert_pid = ioreqp->insert_pid;
        } else {
                if (f->f_P_pid || f->f_P_tgid || f->f_P_cpu || f->f_dev) return 0;
        }
	
	if (ioreqp) {
                if (ioreqp->insert_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                        qtm = 0;
                } else if (ioreqp->issue_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->insert_time;
                        qtm =  0;
                } else {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                        qtm = ioreqp->issue_time - ioreqp->insert_time;
                }
	} else if (f->f_P_pid || f->f_P_tgid || f->f_P_cpu || f->f_dev) {
		return 0;
	}

	if (perdsk_stats) block_dev_abort_stats(rec_ptr);
	if (perpid_stats && ioreqp && (ioreqp->insert_pid > 0)) {
		insert_pidp = GET_PIDP(&globals->pid_hash, ioreqp->insert_pid);
		block_perpid_abort_stats(rec_ptr, insert_pidp);
	}

	if (kitrace_flag) print_block_rq_abort_rec(rec_ptr, insert_pid, issue_pid, svtm, qtm);
	FREE(ioreqp);

	return 0;
}

int 
block_rq_requeue_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	block_rq_requeue_t	tt_rec_ptr;
	block_rq_requeue_t	*rec_ptr;
	io_req_t *ioreqp;
	pid_info_t *pidp = NULL;
	pid_info_t *insert_pidp = NULL;
	int64 svtm = 0, qtm = 0;
        int issue_pid = 0, insert_pid = 0;

	rec_ptr = conv_block_rq_requeue(trcinfop, &tt_rec_ptr);
        if ((nomapper_flag) && (dev_major(DEV(rec_ptr->dev)) == MAPPER_MAJOR)) return 0;

	if (pertrc_stats) {
		if (perpid_stats) pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		incr_trc_stats(rec_ptr, pidp);
	}

	ioreqp = find_issued_io(DEV(rec_ptr->dev), rec_ptr->sector);
        if (ioreqp) {
                issue_pid = ioreqp->issue_pid;
                insert_pid = ioreqp->insert_pid;
        } else if (f->f_P_pid || f->f_P_tgid || f->f_P_cpu || f->f_dev) {
                return 0;
        }

	if (ioreqp) {
                if (ioreqp->insert_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                        qtm = 0;
                } else if (ioreqp->issue_time == 0) {
                        svtm = rec_ptr->hrtime - ioreqp->insert_time;
                        qtm =  0;
                } else {
                        svtm = rec_ptr->hrtime - ioreqp->issue_time;
                        qtm = ioreqp->issue_time - ioreqp->insert_time;
                }
	} else if (f->f_P_pid || f->f_P_tgid || f->f_P_cpu || f->f_dev) {
		return 0;
	}

	if (perdsk_stats) block_dev_requeue_stats(rec_ptr);
	if (perpid_stats && ioreqp && (ioreqp->insert_pid > 0)) {
		insert_pidp = GET_PIDP(&globals->pid_hash, ioreqp->insert_pid);
		block_perpid_requeue_stats(rec_ptr, insert_pidp);
	}
	if (kitrace_flag) print_block_rq_requeue_rec(rec_ptr, insert_pid, issue_pid, svtm, qtm); 

	FREE(ioreqp);
	return 0;
}
