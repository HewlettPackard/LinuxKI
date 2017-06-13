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
#include "block.h"
#include "sched.h"
#include "hash.h"
#include "sort.h"
#include "html.h"
#include "conv.h"
#include <ncurses.h>
#include <curses.h>

int dsk_ftrace_print_func(void *, void *);

char print_csv_header = TRUE;

uint64
devstr_to_dev(char *str)
{
        FILE *f;
        char fname[80];
        char *rtnptr;
	dev_info_t *devinfop;
        uint32 major, minor;
        uint64 dev = 0ull;
	int i;
	

        if (strncmp(str,"0x", 2) == 0) {
                dev = strtoll(str, NULL, 16);
                if (dev == 0xffffffffffffffff) dev = 0;
        } else if (is_alive) {
                sprintf (fname, "/sys/block/%s/dev", str);
                if ((f = fopen(fname, "r")) == NULL) {
                        return 0;
                }

                rtnptr = fgets((char *)&input_str, 127, f);
                sscanf (rtnptr, "%d:%d", &major, &minor);

                dev = mkdev(major, minor);
                fclose(f);
        } else {
                /* search the device table */
		for (i=0; i < DEV_HSIZE; i++) {
			devinfop = globals->devhash[i]; 
			while (devinfop && devinfop->devname) {
				if (strcmp(str, devinfop->devname) == 0) {
					dev = devinfop->lle.key;
					break;
				}
				devinfop = (dev_info_t *)devinfop->lle.next;
			}
		}

		if (dev == 0ull) {
			/* next, search the multipath table */
			for (i=0; i < DEV_HSIZE; i++) {
				devinfop = globals->mdevhash[i]; 
				while (devinfop && devinfop->devname) {
					if (strcmp(str, devinfop->devname) == 0) {
						dev = devinfop->lle.key;
						break;
					}
					devinfop = (dev_info_t *)devinfop->lle.next;
				}
			}
		}
        }

        return dev;
}

int
sum_iostats(void *arg1, void *arg2)
{
	iostats_t *iostat = (iostats_t *)arg1;
	iostats_t *tiostat = (iostats_t *)arg2;
	iostats_t *iostatp, *tiostatp;
	int rw;

	for (rw = IORD; rw <= IOTOT; rw++) {
		iostatp = (iostats_t *)&iostat[rw];
		tiostatp = (iostats_t *)&tiostat[rw];

		tiostatp->sect_xfrd += iostatp->sect_xfrd;
		tiostatp->max_ioserv = MAX(iostatp->max_ioserv, tiostatp->max_ioserv);
		tiostatp->max_iowait = MAX(iostatp->max_ioserv, tiostatp->max_iowait);
		tiostatp->cum_ioserv += iostatp->cum_ioserv;
		tiostatp->cum_iowait += iostatp->cum_iowait;
		tiostatp->qlen = MAX(iostatp->qlen, tiostatp->qlen);
		tiostatp->max_qlen = MAX(iostatp->max_qlen, tiostatp->max_qlen);
		tiostatp->cum_qlen += iostatp->cum_qlen;
		tiostatp->cum_async_inflight += iostatp->cum_async_inflight;
		tiostatp->cum_sync_inflight += iostatp->cum_sync_inflight;
		tiostatp->insert_cnt += iostatp->insert_cnt;
		tiostatp->issue_cnt += iostatp->issue_cnt;
		tiostatp->requeue_cnt += iostatp->requeue_cnt;
		tiostatp->abort_cnt += iostatp->abort_cnt;
		tiostatp->barrier_cnt += iostatp->barrier_cnt;
		tiostatp->random_ios += iostatp->random_ios;
		tiostatp->seq_ios += iostatp->seq_ios;
		tiostatp->compl_cnt += iostatp->compl_cnt;
		tiostatp->error_cnt += iostatp->error_cnt;
	
	}
}


void
calc_io_totals(void *arg1, void *arg2)
{
	iostats_t *iostats = (iostats_t *) arg1;
	iostats_t *rstatp, *wstatp, *tstatp;

	rstatp = &iostats[IO_READ];
	wstatp = &iostats[IO_WRITE];
	tstatp = &iostats[IO_TOTAL];

	tstatp->sect_xfrd = rstatp->sect_xfrd + wstatp->sect_xfrd;
	tstatp->max_ioserv = MAX(rstatp->max_ioserv, wstatp->max_ioserv);
	tstatp->max_iowait = MAX(rstatp->max_iowait, wstatp->max_iowait);
	tstatp->max_qlen = MAX(rstatp->max_qlen, wstatp->max_qlen);
	tstatp->cum_ioserv = rstatp->cum_ioserv + wstatp->cum_ioserv;
	tstatp->cum_iowait = rstatp->cum_iowait + wstatp->cum_iowait;
	tstatp->cum_qlen = rstatp->cum_qlen + wstatp->cum_qlen;
	tstatp->cum_async_inflight = rstatp->cum_async_inflight + wstatp->cum_async_inflight;
	tstatp->cum_sync_inflight = rstatp->cum_sync_inflight + wstatp->cum_sync_inflight;
	tstatp->qlen = rstatp->qlen + wstatp->qlen;
	tstatp->qops = rstatp->qops + wstatp->qops;
	tstatp->insert_cnt = rstatp->insert_cnt + wstatp->insert_cnt;
	tstatp->issue_cnt = rstatp->issue_cnt + wstatp->issue_cnt;
	tstatp->compl_cnt = rstatp->compl_cnt + wstatp->compl_cnt;
	tstatp->random_ios = rstatp->random_ios + wstatp->random_ios;
	tstatp->seq_ios = rstatp->seq_ios + wstatp->seq_ios;
	tstatp->requeue_cnt = rstatp->requeue_cnt + wstatp->requeue_cnt;
	tstatp->barrier_cnt = rstatp->barrier_cnt + wstatp->barrier_cnt;
}

int
calc_dev_totals(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	uint64 count_devs = (uint64)arg2;
	
	if (devinfop == NULL) return 0;

	calc_io_totals(&devinfop->iostats[0], NULL);
	if (count_devs) globals->ndevs++;
	return 0;
}

int
calc_fc_totals(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	dev_info_t *mdevinfop ;
	fc_info_t *fcinfop;
	fc_dev_t *fcdevp;
	iostats_t *devstatp, *fcstatp;
	int i;

	if (devinfop == NULL) return 0;

	fcinfop = GET_FCINFOP(&globals->fchash, DEVPATH_TO_FCPATH(devinfop->devpath));
	fcdevp = GET_FCDEVP(&fcinfop->fcdevhash, devinfop->lle.key);
	fcdevp->devinfop = devinfop;

	for (i = IO_READ; i <= IO_TOTAL; i++) {
		devstatp = &devinfop->iostats[i];
		fcstatp = &fcinfop->iostats[i];

		fcstatp->sect_xfrd += devstatp->sect_xfrd;
		fcstatp->max_ioserv = MAX(fcstatp->max_ioserv, devstatp->max_ioserv);
		fcstatp->max_iowait = MAX(fcstatp->max_iowait, devstatp->max_iowait);
		fcstatp->cum_ioserv += devstatp->cum_ioserv;
		fcstatp->cum_iowait += devstatp->cum_iowait;
		fcstatp->qlen += devstatp->qlen;
		fcstatp->qops += fcstatp->qops;
		fcstatp->insert_cnt += devstatp->insert_cnt;
		fcstatp->issue_cnt += devstatp->issue_cnt;
		fcstatp->requeue_cnt += devstatp->requeue_cnt;
		fcstatp->abort_cnt += devstatp->abort_cnt;
		fcstatp->barrier_cnt += devstatp->barrier_cnt;
		fcstatp->cum_qlen += devstatp->cum_qlen;
		fcstatp->max_qlen = MAX(fcstatp->max_qlen, devstatp->max_qlen);
		fcstatp->cum_async_inflight += devstatp->cum_async_inflight;
		fcstatp->cum_sync_inflight += devstatp->cum_sync_inflight;
		fcstatp->random_ios += devstatp->random_ios;
		fcstatp->seq_ios += devstatp->seq_ios;
		fcstatp->compl_cnt += devstatp->compl_cnt;
		fcstatp->error_cnt += devstatp->error_cnt;
	}
	
	return 0;
}


int
clear_dev_iostats(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	
	if (devinfop == NULL) return 0;
	
	free_hash_table((lle_t ***)&devinfop->ioq_hash, IOQ_HSIZE);
	bzero(&devinfop->iostats[0], sizeof(iostats_t)*3);
	return 0;
}

int
clear_fc_iostats(void *arg1, void *arg2)
{
	fc_info_t *fcinfop = (fc_info_t *)arg1;

	bzero(&fcinfop->iostats[0], sizeof(iostats_t)*3);
	return 0;
}

int
print_dev_iostats(void *arg1, char *devstr, char *devname, char *devpath, char *mapname) 
{
	iostats_t *statp = (iostats_t *)arg1;

	uint64 aviosz;
	double avwait, avserv, avqlen, avinflt;
	int rw;
	
	for (rw = IO_READ; rw <= IO_TOTAL; rw++) {
		pid_printf ("%s  %10s", tab, devstr);
		csv_printf(dsk_csvfile,"%-10s,%10s", devname, devstr ? devstr : " ");
		csv_printf(dsk_csvfile,",%-16s", devpath ? devpath : " ");
		csv_printf(dsk_csvfile,",%-16s", mapname ? mapname : " ");
	
		aviosz = 0;
		avwait = avserv = avqlen = avinflt = avqlen = 0.0;
		if (statp[rw].compl_cnt) {
			aviosz = (statp[rw].sect_xfrd /2) / statp[rw].compl_cnt ;	/* convert to KB */
			avwait =  MSECS(statp[rw].cum_iowait / statp[rw].compl_cnt); 	/* convert to msecs */
			avserv = MSECS(statp[rw].cum_ioserv / statp[rw].compl_cnt);
		}

		if (statp[rw].issue_cnt) {
			avinflt = (statp[rw].cum_async_inflight + statp[rw].cum_sync_inflight) / (statp[rw].issue_cnt * 1.0);
		}

		if (statp[rw].qops) {
			avqlen = statp[rw].cum_qlen  / (statp[rw].qops * 1.0);
		}

		switch(rw) {
		case IO_READ: pid_printf("%3s", "r"); csv_printf(dsk_csvfile,",Read "); break;
		case IO_WRITE: pid_printf("%3s", "w"); csv_printf(dsk_csvfile,",Write"); break;
		case IO_TOTAL: pid_printf("%3s", "t"); csv_printf(dsk_csvfile,",Total"); break;
		}			

		pid_printf (" %6.2f %7.2f %6.0f %6.0f %5ld %8.2f %8.2f %6d %6d %6d %6d %6d %7.1f %7.1f",
			avqlen,
			avinflt,
			statp[rw].compl_cnt / secs,
			(statp[rw].sect_xfrd / 2) / secs,
			aviosz,
			avwait,
			avserv,
			statp[rw].compl_cnt,
			statp[rw].seq_ios,
			statp[rw].random_ios,
			statp[rw].requeue_cnt,
			statp[rw].barrier_cnt,
			MSECS(statp[rw].max_iowait),
			MSECS(statp[rw].max_ioserv));
		if (statp[rw].abort_cnt) 
			pid_printf ("  Aborted: %5d",statp[rw].abort_cnt);
		pid_printf("\n");

		csv_printf (dsk_csvfile, ",%7.2f,%7.2f,%6.0f,%6.0f,%5ld,%9.3f,%9.3f,%6d,%6d,%6d,%6d,%6d,%6d,%8.2f,%8.2f\n",
			avqlen,
			avinflt,
			statp[rw].compl_cnt / secs,
			(statp[rw].sect_xfrd / 2) / secs,
			aviosz,
			avwait,
			avserv,
			statp[rw].compl_cnt,
			statp[rw].seq_ios,
			statp[rw].random_ios,
			statp[rw].requeue_cnt,
			statp[rw].abort_cnt,
			statp[rw].barrier_cnt,
			MSECS(statp[rw].max_iowait),
			MSECS(statp[rw].max_ioserv));
	}

	return 0;	
}

/* this is used to print an I/O summary on one line.  It does not include a nl character */
int
print_iostats_totals(void *arg1, void *arg2, void *arg3)
{
	server_info_t *serverp = (server_info_t *)arg1;
	struct iostats *iostats = (iostats_t *)arg2;
	uint64 *warnflagp = (uint64*)arg3;
	struct iostats *iostatsp;
	int i = IOTOT;
	uint64 aviosz;
	double avserv, avinflt;

	while (i >= IORD) {
		iostatsp = &iostats[i];
        	avserv = iostatsp->cum_ioserv/MAX(iostatsp->compl_cnt,1) / 1000000.0;
		avinflt = (iostatsp->cum_async_inflight + iostatsp->cum_sync_inflight) / (MAX(iostatsp->issue_cnt,1) * 1.0);

		printf ("%7.0f %7.0f %7d %7.2f %8.2f ",
                        iostatsp->compl_cnt/serverp->total_secs,
                        (iostatsp->sect_xfrd/2048)/serverp->total_secs,
                        (iostatsp->sect_xfrd/2)/MAX(iostatsp->compl_cnt,1),
			avinflt,
                        (iostatsp->cum_iowait/MAX(iostatsp->compl_cnt,1) / 1000000.0));

        	if (warnflagp && (avserv > 30.0)) {
                	RED_FONT;
			(*warnflagp) |= WARNF_AVSERV;
		}	

                pid_printf ("%8.2f ", avserv);
		BLACK_FONT;

                i--;
        }
}

int
print_mpath_iostats(void *arg1, void *arg2)
{
	mpath_info_t *mpath_infop = (mpath_info_t *)arg1;
	iostats_t *statp;
	char devstr[16];
	int cpu;

	cpu = mpath_infop->lle.key;
	statp = &mpath_infop->iostats[0];
	if (statp[IOTOT].compl_cnt == 0) return 0;

	sprintf (devstr, "cpu%lld  \0", cpu);
	print_dev_iostats(statp, devstr, NULL, NULL, NULL);
	return 0;
}

int
calc_pid_iototals(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	
	if (pidp == NULL) return 0;

	calc_io_totals(&pidp->iostats[0], NULL);
	return 0;
}

int
calc_mpath_iototals(void *arg1, void *arg2)
{
	mpath_info_t *mpath_infop = (mpath_info_t *)arg1;

	if (mpath_infop == NULL) return 0;
	
	calc_io_totals(&mpath_infop->iostats[0], NULL);
	return 0;
}

int
print_pid_iosum(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	iostats_t *rstatp, *wstatp, *tstatp;
	docker_info_t *dockerp;
	
	if (pidp == NULL) return 0;
	
	tstatp = &pidp->iostats[IO_TOTAL];
	if (tstatp->compl_cnt == 0) return 0;

	rstatp = &pidp->iostats[IO_READ];
	wstatp = &pidp->iostats[IO_WRITE];

	SPAN_GREY;
	printf ("%8d %8.0f %8.0f %9.1f %9.3f ",
		tstatp->compl_cnt,
		rstatp->compl_cnt / secs,
		wstatp->compl_cnt / secs,
		((rstatp->sect_xfrd + wstatp->sect_xfrd)/2.0) / secs,
		MSECS(tstatp->cum_ioserv / tstatp->compl_cnt),
		MSECS(tstatp->cum_ioserv / tstatp->compl_cnt));

	PID_URL_FIELD8_R(pidp->PID);
	if (pidp->cmd) printf ("  %s", pidp->cmd);
	if (pidp->hcmd) printf ("  {%s}", pidp->hcmd);
	if (pidp->thread_cmd) printf (" (%s)", pidp->thread_cmd);
	if (pidp->dockerp) printf (HTML ? " &lt;%s&gt;" : " <%s>", ((docker_info_t *)(pidp->dockerp))->name);

	printf ("\n");
			
	_SPAN;	

	return 0;
}

void
print_iosum_detail(iostats_t *statsp)
{
	pid_printf ("        Cnt   : %6d   Total KB: %9.1f    ElpTime: %9.5f\n",
		statsp->compl_cnt,
		statsp->sect_xfrd / 2.0,
		SECS(statsp->cum_ioserv + statsp->cum_iowait));
	pid_printf ("        Rate  : %6.1f   KB/sec  : %9.1f    AvServ : %9.5f\n",
		(statsp->compl_cnt * 1.0) / secs,
		(statsp->sect_xfrd / 2.0) / secs,
		SECS(statsp->cum_ioserv / (statsp->compl_cnt * 1.0)));
	pid_printf ("        Errs:   %6d   AvgSz   : %9.1f    AvWait : %9.5f\n", 
		statsp->error_cnt,
		(statsp->sect_xfrd / 2.0) / (statsp->compl_cnt * 1.0),
		SECS(statsp->cum_iowait / (statsp->compl_cnt * 1.0)));
	pid_printf ("        Requeue :     %5d   MaxQlen :     %5d\n",
		statsp->requeue_cnt,
		statsp->max_qlen);
	if (statsp->abort_cnt) 
		pid_printf ("        Aborted :     %5d\n", statsp->abort_cnt);
}


int
print_pid_iototals(void *arg1)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	iostats_t *rstatp, *wstatp, *tstatp;
	
	if (pidp == NULL) return 0;
	
	tstatp = &pidp->iostats[IO_TOTAL];
	if (tstatp->compl_cnt == 0) return 0;

	rstatp = &pidp->iostats[IO_READ];
	wstatp = &pidp->iostats[IO_WRITE];

	pid_printf ("\n    Totals:\n", tab);

	if (rstatp->compl_cnt !=0) {
		pid_printf ("      Physical Reads:\n");
		print_iosum_detail(rstatp);
	}

	if (wstatp->compl_cnt !=0) {
		pid_printf ("      Physical Writes:\n");
		print_iosum_detail(wstatp);
	}

	pid_printf ("\n");
			

	return 0;
}
int
print_pid_iototals_csv(void *arg1)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	iostats_t *statsp;
	int i;
	double avserv, avwait, avsz;
	
	if (pidp == NULL) return 0;

	for (i = IORD; i <= IOWR; i++) {
		statsp = &pidp->iostats[i];
		if (statsp->compl_cnt) {
			avserv = SECS(statsp->cum_ioserv / (statsp->compl_cnt * 1.0));
			avwait = SECS(statsp->cum_iowait / (statsp->compl_cnt * 1.0));
			avsz = (statsp->sect_xfrd / 2.0) / (statsp->compl_cnt * 1.0);
		} else {
			avserv = avwait = avsz = 0.0;
		}

		csv_printf (pid_csvfile, ",%d,%1.0f,%7.6f,%2.1f,%2.1f,%1.0f,%7.6f,%7.6f,%d,%d,%d,%7.6f,%7.6f",
			statsp->compl_cnt,
			statsp->sect_xfrd / 2.0,
			SECS(statsp->cum_ioserv + statsp->cum_iowait),
			(statsp->compl_cnt * 1.0) / secs,
			(statsp->sect_xfrd / 2.0) /secs,
			avsz,
			avwait,
			avserv,
			statsp->requeue_cnt,
			statsp->abort_cnt,
			statsp->barrier_cnt,
			SECS(statsp->max_iowait),
			SECS(statsp->max_ioserv));	
	}	
	
}

int
clear_pid_iostats(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	
	if (pidp == NULL) return 0;

	bzero(&pidp->iostats[0], sizeof(iostats_t)*3);
	return 0;
}

int
dsk_print_dev_iostats(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	dev_info_t *gdevinfop, *mdevinfop;
	iostats_t *statp;
	uint64 dev;
	uint64 devpath;
	char devstr[16];
	char devpath_str[16];
	char *devname;

	if (devinfop->iostats[IOTOT].compl_cnt == 0) return 0;

	dev = devinfop->lle.key;
	statp = &devinfop->iostats[0];
        gdevinfop = GET_DEVP(DEVHASHP(globals,dev),dev);

	pid_printf ("%s0x%08llx", tab, dev);
	if (devinfop->mapname) { 
		pid_printf ("   /dev/mapper/%s  ->", devinfop->mapname);
	} else if (gdevinfop->mapname) {
		pid_printf ("   /dev/mapper/%s  ->", gdevinfop->mapname);
	} 

	devname = "unkn";
	if (devinfop->devname) {
		devname = devinfop->devname;
	} else if (gdevinfop->devname) {
		devname = gdevinfop->devname;
	} 

	pid_printf ("  /dev/%s", devname);

	if (gdevinfop->devpath != NO_HBA) {
		devpath = gdevinfop->devpath;
		sprintf (devpath_str, "%d:%d:%d:%d", FCPATH1(devpath), FCPATH2(devpath), FCPATH3(devpath), FCPATH4(devpath));
	} else {
		sprintf (devpath_str, "unknown");
	}
	pid_printf ("  (HW path: %s)", devpath_str);
		
	mdevinfop = gdevinfop->mdevinfop;
	if (mdevinfop && mdevinfop->devname) {
		pid_printf ("   (mpath device: /dev/mapper/%s)", mdevinfop->mapname);
	} else {
		devpath_str[0] = 0;
	}
	pid_printf ("\n");

	sprintf(devstr, "0x%08x", dev);
	print_dev_iostats(statp, devstr, devname, &devpath_str[0], mdevinfop ? mdevinfop->mapname : NULL);

	if (dsk_mpath_flag) {
		foreach_hash_entry((void **)devinfop->mpath_hash, MPATH_HSIZE, calc_mpath_iototals, NULL, 0, NULL);
		foreach_hash_entry((void **)devinfop->mpath_hash, MPATH_HSIZE, print_mpath_iostats, mpath_sort_by_cpu, 0, NULL);
	}

	return 0;
}

int
dsk_print_fc_iostats(void *arg1, void *arg2)
{
	fc_info_t *fcinfop = (fc_info_t *)arg1;
	iostats_t *statp;
	uint64 devpath;
	char devpath_str[16];

	if (fcinfop->iostats[IOTOT].compl_cnt == 0) return 0;

	devpath = fcinfop->lle.key;
	statp = &fcinfop->iostats[0];
	if (devpath != NO_HBA) {
		sprintf (devpath_str, "%d:%d:%d", FCPATH1(devpath), FCPATH2(devpath), FCPATH3(devpath));
	} else {
		sprintf (devpath_str, "unkn");
	}

	printf ("%s%-8s\n", tab, devpath_str);

	print_dev_iostats(statp, devpath_str, NULL, NULL, NULL);

	return 0;
}

int
print_dev_iostats_total(void *arg1, void *arg2)
{
	iostats_t *statp =  (iostats_t *)arg1;
	dev_info_t *devinfop = (dev_info_t *)arg2;
	uint64 dev;
        uint32  aviosz = 0;
        double  avwait, avserv, avqlen, avinflt;
	
	if (statp[IOTOT].compl_cnt == 0)  {
		return;
	}

	dev = devinfop->lle.key;
        if (devinfop->devname) {
		pid_printf ("%s%10s", tab, devinfop->devname);
	} else {
		pid_printf ("%s0x%08x", tab, dev);
	}

	avwait = avserv = avqlen = 0.0;
	aviosz =  ((statp[IOTOT].sect_xfrd+1)/2) / statp[IOTOT].compl_cnt;
        avwait =  MSECS(statp[IOTOT].cum_iowait / statp[IOTOT].compl_cnt);
        avserv = MSECS(statp[IOTOT].cum_ioserv / statp[IOTOT].compl_cnt);
        avqlen = (statp[IOTOT].cum_qlen/2.0) / (statp[IOTOT].qops * 1.0);
	if (statp[IOTOT].issue_cnt) {
		avinflt = (statp[IOTOT].cum_async_inflight + statp[IOTOT].cum_sync_inflight) / (statp[IOTOT].issue_cnt * 1.0);
	} else {
		avinflt = 0.0;
	}
        printf (" %6.2f %7.2f %6.0f %6.0f %8.0f %5ld %7.2f",
                        avqlen,
			avinflt,
                        statp[IORD].compl_cnt / secs,
                        statp[IOWR].compl_cnt / secs,
                        (statp[IOTOT].sect_xfrd/2) / secs,
                        aviosz,
                        avwait);

        if (avserv > 30.0) {
                RED_FONT;
                pid_printf (" %7.2f", avserv);
                BLACK_FONT;
        } else {
                pid_printf (" %7.2f", avserv);
        }

        if (statp[IOTOT].requeue_cnt) {
                pid_printf (" requeue: ");
                RED_FONT;
                pid_printf ("%d", statp[IOTOT].requeue_cnt);
                BLACK_FONT;
        }

	if (statp[IOTOT].barrier_cnt) {
		pid_printf (" barriers: ");
		RED_FONT;
		pid_printf ("%d", statp[IOTOT].barrier_cnt);
		BLACK_FONT;
	}

	if (statp[IOTOT].abort_cnt) {
		pid_printf (" Aborted: ");
		RED_FONT;
		pid_printf ("%d", statp[IOTOT].abort_cnt);
		BLACK_FONT;
	}

        pid_printf ("\n");
        return 0;
}

int 
print_io_histogram(void *arg1, void *arg2)
{
	iotimes_t *timesp = (iotimes_t *)arg1;
	uint64 *warnflagp = (uint64*)arg2;
	int rw;
	int i;

	if (timesp == NULL) return 0;

        printf ("     msecs ");
        for (i=0; i< NBUCKETS-1; i++) {
                if ((i == 0) || ((i!=0) && (dsk_io_sizes[i] != dsk_io_sizes[i-1]))) {
                        printf ("<%-6lld", dsk_io_sizes[i]);
                }
        }

        printf (">%lld\n", dsk_io_sizes[NBUCKETS-2]);

        for (rw=IO_READ; rw <= IO_WRITE; rw++) {
                if (rw==IO_WRITE) {
                        printf ("    Write: ");
                } else {
                        printf ("    Read:  ");
                }
                for (i=0; i<NBUCKETS; i++) {
                        if ((i == 0) || ((i!=0) && (dsk_io_sizes[i] != dsk_io_sizes[i-1]))) {
	/*
                                if (warnflagp && (dsk_io_sizes[i] > 200) && (timesp->time[rw][i])) {
                                        RED_FONT;
                                        (*warnflagp) |= WARNF_IO_DELAYS;
                                }
	*/
                                printf ("%-6d ", timesp->time[rw][i]);
                        }
                }
                printf("\n");
        }	
	return 0;
}

/*
 *
 */
int
dsk_bucket_adjust()
{
        FILE *bkfile = NULL;
        int value;
        char ign_chars[256];
        int n=0, i=0, last;

        if ( (bkfile = fopen(bkfname,"r")) == NULL) {
                printf ("Unable to open Time Bucket file %s, errno %d\n", bkfname, errno);
                printf ("Using default Time Bucket config\n");
                return 0;
        }

        while (n != -1) {
                n = fscanf (bkfile, "%d", &value);
                if (n==-1)
                        /* stop if at the end of the file */
                        break;
                if (n==0) {
                        /* skip non-decimal values */
                        n = fscanf (bkfile, "%s", (char *)&ign_chars);
                } else {
                        /* we have a decimal value */
                        /* printf ("i= %d, n = %d, value = %d \n", i, n, value);  */
                        if (i==0) {
                                dsk_io_sizes[i] = value;
                                i++;
                        } else if (dsk_io_sizes[i-1] < value) {
                                /* Note, if the value is descenting, its ignored */
                                dsk_io_sizes[i] = value;
                                i++;
                        }
                        if (i >= (NBUCKETS-1))
                                break;
                }
        }

        last = i - 1;
        if (last) {
                while (i < (NBUCKETS-1)) {
                        dsk_io_sizes[i] = dsk_io_sizes[last];
                        i++;
                }
        }

        fclose(bkfile);
        return 0;
}

	

/*
 ** The initialization function
 */
void
dsk_init_func(void *v)
{
	int i;

	if (debug) printf ("dsk_init_func\n");
	process_func = dsk_process_func;
	print_func = dsk_print_func;
	report_func = dsk_report_func;
	/* bufmiss_func = dsk_bufmiss_func; */
	alarm_func = dsk_alarm_func;
	filter_func = trace_filter_func;

        /* We will disgard the trace records until the Marker is found */
        for (i = 0; i < KI_MAXTRACECALLS; i++) {
                ki_actions[i].execute = 0;
        }

	ki_actions[TRACE_BLOCK_RQ_ISSUE].func = block_rq_issue_func;
	ki_actions[TRACE_BLOCK_RQ_INSERT].func = block_rq_insert_func;
	ki_actions[TRACE_BLOCK_RQ_COMPLETE].func = block_rq_complete_func;
	ki_actions[TRACE_BLOCK_RQ_REQUEUE].func = block_rq_requeue_func;
	ki_actions[TRACE_BLOCK_RQ_ABORT].func = block_rq_abort_func;
	ki_actions[TRACE_SCHED_SWITCH].func = sched_switch_thread_names_func;
	if (IS_LIKI_V4_PLUS)
                ki_actions[TRACE_WALLTIME].func = trace_startup_func;
        else
                ki_actions[TRACE_WALLTIME].func = trace_walltime_func;

	if (IS_LIKI)	 {
		ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1; 
		ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
		ki_actions[TRACE_WALLTIME].execute = 1;
		if (!is_alive) ki_actions[TRACE_SCHED_SWITCH].execute = 1;
	} else {
        	/* We will disgard the trace records until the Marker is found */
        	ki_actions[TRACE_PRINT].func = dsk_ftrace_print_func;
        	ki_actions[TRACE_PRINT].execute = 1;
	}

        dsk_io_sizes[0]= 5ull;
        dsk_io_sizes[1]= 10;
        dsk_io_sizes[2]= 20;
        dsk_io_sizes[3]= 50;
        dsk_io_sizes[4]= 100;
        dsk_io_sizes[5]= 200;
        dsk_io_sizes[6]= 300;
        dsk_io_sizes[7]= 500;
        dsk_io_sizes[8]= 1000;
	if (bkfname) {
		dsk_bucket_adjust();
	}

	parse_devices();
	parse_docker_ps();

	if (timestamp) {
		parse_proc_cgroup();
		parse_pself();
		parse_edus();
		parse_ll_R();
		parse_mpath();
		parse_jstack();

		dsk_csvfile = open_csv_file("kidsk", 1);
	}
}

int
dsk_process_func(void *a, void *arg)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        return 0;
}

int
dsk_report_func(void *v)
{
	dsk_print_report();

	return 0;
}

int
dsk_bufmiss_func(void *v, void *a)
{
	return 0;	
}

int
dsk_print_report()
{
	cpu_info_t *cpuinfop;
	char cpustr[16];
	int i;
	FILE *tmp;

	tab=tab0;
	csv_printf(dsk_csvfile,"devname   ,device    ,h/w path        ,Mapper Device   ,rwt  ,  avque,avinflt,  io/s,  KB/s, avsz,   avwait,   avserv,   tot,   seq,   rnd, reque, abort, flush, maxwait, maxserv\n");

	if (is_alive) {
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, get_command, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, get_devinfo, NULL, 0, NULL);
	} else {
		/* do mpath summary */
	}

        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_dev_totals, NULL, 0, (void *)1);
        foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, calc_dev_totals, NULL, 0, NULL);
	if (!dsk_nodev_flag) {
		printf ("\nPhysical Device Statistics\n");
		printf ("\n%s      device rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
		foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, dsk_print_dev_iostats, dev_sort_by_mdev, 0, NULL);

		printf ("\nMapper Device Statistics\n");
		printf ("\n%s      device rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
		foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, dsk_print_dev_iostats, dev_sort_by_dev, 0, NULL);
	}

	/* We do this to omit the CSV printing for the HBA devices and per-CPU stats */
	tmp = dsk_csvfile; dsk_csvfile=NULL;
	
	/* print multipath FC totals */
	if (!kiall_flag) foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, calc_fc_totals, NULL, 0, NULL);
	if (globals->fchash) {
		printf ("\nMultipath FC HBA Statistics\n");
		printf ("\n%s      HBA    rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
		
		foreach_hash_entry((void **)globals->fchash, FC_HSIZE, dsk_print_fc_iostats, fc_sort_by_path, 0, NULL); 
	}
	
	if (percpu_stats) {
            printf ("\nPer-CPU Statistics (for possible per-HBA statistics\n");
	    printf ("\n%s      device rw  avque avinflt   io/s   KB/s  avsz   avwait   avserv    tot    seq    rnd  reque  flush maxwait maxserv\n", tab);
            for (i = 0; i < MAXCPUS; i++) {
                if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
                        sprintf(cpustr, "cpu=%d", i);
                        calc_io_totals(&cpuinfop->iostats[0], NULL);
                        print_dev_iostats(&cpuinfop->iostats[0], cpustr, NULL, NULL, NULL);
                        bzero(&cpuinfop->iostats[0], sizeof(iostats_t)*3);
                }
            }
        }

        printf ("\nPhysical I/O Histogram\n");
	print_io_histogram(globals->iotimes, NULL);

	if (npid) {
		if (npid==ALL) {
			printf ("\nAll tasks sorted by physical I/O\n\n");
		} else {
			printf ("\nTop %d Tasks sorted by physical I/O\n\n", npid);
		}

	        BOLD ("     Cnt      r/s      w/s    KB/sec    Avserv      PID  Process\n");
		BOLD ("==============================================================================\n");

		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, calc_pid_iototals, NULL, 0, NULL);
		foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, print_pid_iosum,  pid_sort_by_iocnt, npid, NULL);
	}
	printf ("\n");
	dsk_csvfile = tmp; 

	/* clear stats */
	if (is_alive) {
		clear_all_stats();
	}
}

int
dsk_print_func(void *v)
{
	struct timeval tod;
	if (debug) printf ("dsk_print_func\n");
	
	dsk_print_report();
	return 0;	
}

int 
dsk_ftrace_print_func(void *a, void *arg)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	kd_print_t *rec_ptr = (kd_print_t *)trcinfop->cur_rec;
	char *buf = get_marker_buf(trcinfop);

	if (debug) printf ("trace_ftrace_print_func()\n");

        if (strstr(buf, ts_begin_marker)) {
		ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 1; 
		ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 1;
		ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 1;
		ki_actions[TRACE_SCHED_SWITCH].execute = 1;
		
		start_time = KD_CUR_TIME;
        }

        if (strstr(buf, ts_end_marker)) {
		ki_actions[TRACE_BLOCK_RQ_ISSUE].execute = 0;
		ki_actions[TRACE_BLOCK_RQ_INSERT].execute = 0; 
		ki_actions[TRACE_BLOCK_RQ_COMPLETE].execute = 0;
		ki_actions[TRACE_BLOCK_RQ_REQUEUE].execute = 0;
		ki_actions[TRACE_BLOCK_RQ_ABORT].execute = 0;
		ki_actions[TRACE_SCHED_SWITCH].execute = 0;
		ki_actions[TRACE_PRINT].execute = 0;

		end_time = KD_CUR_TIME;
        }

        if (debug)  {
		PRINT_KD_REC(rec_ptr);
        	PRINT_EVENT(rec_ptr->KD_ID);
        	printf (" %s", buf);

	        printf ("\n");
	}
}

/* alarm_func() should contain any 
 * extra code to handle the alarm
 */

int dsk_alarm_func(void *v)
{
	return 0;
}
