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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <unistd.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "info.h"


void
clear_global_stats()
{
	sched_info_t *schedp;

	globals->ndevs=0;
	bzero(&globals->iostats[0], sizeof(struct iostats)*3);	
	bzero(&globals->miostats[0], sizeof(struct iostats)*3);	

	if (schedp = globals->schedp)  {
		bzero(&schedp->sched_stats, sizeof(sched_stats_t));
	}
}
	


void
clear_irq_stats(void **arg1)
{
        irq_info_t *irqinfop = *arg1;

        if (irqinfop == NULL) return;

        free_hash_table((lle_t ***)&irqinfop->irq_entry_hash, IRQ_HSIZE);
        FREE(irqinfop);
        *arg1 = NULL;

        return;
}

int
clear_ctx_info(void *arg1, void *arg2)
{
        ctx_info_t *ctxp = arg1;

	free_hash_table((lle_t ***)&ctxp->iocb_hash, IOCB_HSIZE);
	return 0;
}

int
clear_syscall_info(void *arg1, void *arg2)
{
        syscall_info_t *syscallp = arg1;

	FREE(syscallp->iov_stats);
	free_hash_table((lle_t ***)&syscallp->slp_hash, SLP_HSIZE);
	return 0;
}

int
clear_fd_info(void *arg1, void *arg2)
{
        fd_info_t *fdinfop = arg1;

	FREE(fdinfop->fnamep);
	FREE(fdinfop->lsock);
	FREE(fdinfop->rsock);
	foreach_hash_entry((void **)fdinfop->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&fdinfop->syscallp, SYSCALL_HASHSZ);
}

int
clear_fdata_info(void *arg1, void *arg2)
{
        fdata_info_t *fdatap = arg1;

	FREE(fdatap->fnameptr);
	foreach_hash_entry((void **)fdatap->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&fdatap->syscallp, SYSCALL_HASHSZ);
}

int
clear_sdata_info(void *arg1, void *arg2)
{
        sdata_info_t *sdatap = arg1;

	FREE(sdatap->fnameptr);
	FREE(sdatap->laddr);
	FREE(sdatap->raddr);
	foreach_hash_entry((void **)sdatap->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&sdatap->syscallp, SYSCALL_HASHSZ);
}

int
clear_ipip_info(void *arg1, void *arg2)
{
	ipip_info_t *ipipp = arg1;

	FREE(ipipp->laddr);
	FREE(ipipp->raddr);
	foreach_hash_entry((void **)ipipp->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&ipipp->syscallp, SYSCALL_HASHSZ);
}

int
clear_ip_info(void *arg1, void *arg2)
{
	ip_info_t *ipp = arg1;
	FREE(ipp->saddr);
	foreach_hash_entry((void **)ipp->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&ipp->syscallp, SYSCALL_HASHSZ);
}

int
clear_sock_info(void *arg1, void *arg2)
{
	sock_info_t *sockp = arg1;
	FREE(sockp->saddr);
	foreach_hash_entry((void **)sockp->syscallp, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&sockp->syscallp, SYSCALL_HASHSZ);
}

int
clear_hc_info(void **arg1)
{
        hc_info_t *hcinfop = *arg1;

        if (hcinfop == NULL) return 0;
        free_hash_table((lle_t ***)&hcinfop->pc_hash, PC_HSIZE);
        free_hash_table((lle_t ***)&hcinfop->hc_stktrc_hash, STKTRC_HSIZE);
        FREE(hcinfop);
        *arg1 = NULL;
}

int
clear_docker_info(void *arg1, void *arg2)
{
	docker_info_t *dockerp = arg1;

	bzero(&dockerp->sched_stats, sizeof(sched_stats_t));
        bzero(&dockerp->iostats[0], sizeof(iostats_t)*3);
        bzero(&dockerp->netstats, sizeof(sd_stats_t));

	free_hash_table((lle_t ***)&dockerp->dkpid_hash, PID_HASHSZ);
	FREE(dockerp->dkpid_hash);
}

int
clear_pid_devinfo(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
        if (devinfop == NULL) return 0;

        free_hash_table((lle_t ***)&devinfop->ioq_hash, IOQ_HSIZE);
	free_hash_table((lle_t ***)&devinfop->mpath_hash, MPATH_HSIZE);
	FREE(devinfop->devname);
	FREE(devinfop->mapname);

	return 0;
}

int
clear_global_devinfo(void *arg1, void *arg2)
{
        dev_info_t *devinfop = (dev_info_t *)arg1;

        if (devinfop == NULL) return 0;
        free_hash_table((lle_t ***)&devinfop->ioq_hash, IOQ_HSIZE);
	free_hash_table((lle_t ***)&devinfop->mpath_hash, MPATH_HSIZE);
        bzero(&devinfop->iostats[0], sizeof(iostats_t)*3);
        return 0;
}

int 
clear_setrq_info(void *arg1, void *arg2)
{
	setrq_info_t *setrqp = (setrq_info_t *)arg1;

	setrqp->cnt = 0;
	setrqp->sleep_time = 0;
	setrqp->unknown_time = 0;
	return 0;
}

int 
clear_sched_info(void **arg1)
{
	sched_info_t *schedp = *arg1;

	if (schedp == NULL) return 0;

	free_hash_table((lle_t ***)&schedp->setrq_src_hash, WPID_HSIZE);
	free_hash_table((lle_t ***)&schedp->setrq_tgt_hash, WPID_HSIZE);

	FREE(schedp->rqinfop); 
	free_hash_table((lle_t ***)&schedp->rqh, CPU_HASHSZ);	

	FREE(schedp);
	*arg1 = NULL;
}

int
clear_percpu_sched_info(void *arg1)
{
	sched_info_t *schedp = (sched_info_t *)arg1;
	sched_stats_t *statp;
	uint64 last_cur_time;
	unsigned long last_smi_cnt, total_smi_cnt;
	int state; 

	if (schedp == NULL) return 0;
	statp = &schedp->sched_stats;
	
	free_hash_table((lle_t ***)&schedp->setrq_src_hash, WPID_HSIZE);
	free_hash_table((lle_t ***)&schedp->setrq_tgt_hash, WPID_HSIZE);
	free_hash_table((lle_t ***)&schedp->rqh, CPU_HASHSZ);	

	FREE(schedp->rqinfop); 
	schedp->rqinfop = NULL;
	
	state = statp->state;
	last_cur_time = statp->last_cur_time;
	bzero(statp, sizeof(sched_stats_t));
	statp->state = state;
	statp->last_cur_time = last_cur_time;
}	

int
clear_trc_info(void *arg1, void *arg2)
{
        trc_info_t *trcinfop = (trc_info_t *)arg1;

        if (trcinfop == NULL) return 0;
	FREE(trcinfop->syscall_statsp);
	trcinfop->syscall_statsp = NULL;
}

int
clear_futex_op(void *arg1, void *arg2)
{
	futex_op_t *fopsp = (futex_op_t *)arg1;

	free_hash_table((lle_t ***)&fopsp->retval_hash, FUTEXRET_HSIZE);
	free_hash_table((lle_t ***)&fopsp->pids_hash, FUTEXPID_HSIZE);
}

int
clear_pid_futex_info(void *arg1, void *arg2)
{
	pid_futex_info_t *futexp = (pid_futex_info_t *)arg1;

	foreach_hash_entry((void **)futexp->ops_hash, FUTEXOP_HSIZE, clear_futex_op, NULL, 0, NULL);
	free_hash_table((lle_t ***)&futexp->ops_hash, FUTEXOP_HSIZE);
	free_hash_table((lle_t ***)&futexp->uaddr2_hash, FUTEXOP_HSIZE);
}

int
clear_gbl_futex_info(void *arg1, void *arg2)
{
	gbl_futex_info_t *futexp = (gbl_futex_info_t *)arg1;

	foreach_hash_entry((void **)futexp->ops_hash, FUTEXOP_HSIZE, clear_futex_op, NULL, 0, NULL);
	free_hash_table((lle_t ***)&futexp->ops_hash, FUTEXOP_HSIZE);
	free_hash_table((lle_t ***)&futexp->uaddr2_hash, FUTEXOP_HSIZE);
	free_hash_table((lle_t ***)&futexp->pids_hash, FUTEXPID_HSIZE);
	free_hash_table((lle_t ***)&futexp->dup_hash, FUTEX_HSIZE);
}

int
clear_mapinfo(pid_info_t *pidp)
{
	vtxt_preg_t *pregp = pidp->mapinfop;

	if (pregp) {
		FREE(pregp->symbols);
		FREE(pregp);
	}
}

int
clear_vtxt_preg(pid_info_t *pidp)
{
	vtxt_preg_t *pregp = pidp->vtxt_pregp;
	vtxt_preg_t *next;

	while (pregp) {
		next = (vtxt_preg_t *)(pregp->lle.next);	
		
	 	FREE(pregp->filename);	
		FREE(pregp);
		pregp = next;
	}
	
	pidp->vtxt_pregp = NULL;
}

int 
clear_pid_info(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;

	clear_sched_info((void **)&pidp->schedp);
	clear_hc_info((void **)&pidp->hcinfop);

        foreach_hash_entry((void **)pidp->devhash, DEV_HSIZE, clear_pid_devinfo, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->devhash, DEV_HSIZE);

        foreach_hash_entry((void **)pidp->mdevhash, DEV_HSIZE, clear_pid_devinfo, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->mdevhash, DEV_HSIZE);

	foreach_hash_entry((void **)pidp->scallhash, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->scallhash, SYSCALL_HASHSZ);

	foreach_hash_entry((void **)pidp->fdhash, FD_HSIZE, clear_fd_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->fdhash, FD_HSIZE);

	foreach_hash_entry((void **)pidp->trc_hash, TRC_HASHSZ, clear_trc_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->trc_hash, TRC_HASHSZ);

	free_hash_table((lle_t ***)&pidp->slp_hash, SLP_HSIZE);
	free_hash_table((lle_t ***)&pidp->user_slp_hash, SLP_HSIZE);
	free_hash_table((lle_t ***)&pidp->stktrc_hash, STKTRC_HSIZE);

	foreach_hash_entry((void **)pidp->futex_hash, FUTEX_HSIZE, clear_pid_futex_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&pidp->futex_hash, FUTEX_HSIZE);

	clear_vtxt_preg(pidp);
	clear_mapinfo(pidp);

	free_hash_table((lle_t ***)&pidp->pgcache_hash, PGCACHE_HASHSZ);

	FREE(pidp->last_open_fname); 
	FREE(pidp->last_exec_fname); 
	FREE(pidp->cmd);
	FREE(pidp->thread_cmd);
	FREE(pidp->hcmd);
	pidp->dockerp == NULL;
	return 0;
}

void
clear_percpu_stats()
{
	int i;
	cpu_info_t *cpuinfop;

	for (i=0; i<MAXCPUS; i++) {
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, i)) {
			/* it would be nice just to call clear_sched_info(), however
			 * I would like to maintain some stats in the schedp record
			 * so we call clear_percpu_sched_info.
			 * I cannot do this for kilive since the stats can get out
			 * of date
			 */
			if (kilive)
				clear_sched_info((void **)&cpuinfop->schedp);
			else
				clear_percpu_sched_info((void *)cpuinfop->schedp);

        		clear_hc_info((void **)&cpuinfop->hcinfop);
        		clear_irq_stats((void **)&cpuinfop->irqp);
        		clear_irq_stats((void **)&cpuinfop->softirqp);
			FREE(cpuinfop->powerp);
			cpuinfop->powerp = NULL;

			cpuinfop->total_traces = 0;
			cpuinfop->idle_time = 0;
			bzero(&cpuinfop->iostats[0], sizeof(struct iostats) * 3);
			bzero(&cpuinfop->miostats[0], sizeof(struct iostats) * 3);
			
			if (idle_stats) {
				bzero (&cpuinfop->idle[0], sizeof(idle_info_t) *8);
				bzero (&cpuinfop->idle_hist[0], sizeof(uint64)*IDLE_TIME_NBUCKETS);
			}
		}
	}
}

void
clear_HT_stats()
{
	int i;
	pcpu_info_t *pcpuinfop;
	cpu_info_t *cpu1infop, *cpu2infop;
	
	for (i = 0; i < MAXCPUS; i++) {
		if (pcpuinfop = FIND_PCPUP(globals->pcpu_hash, i)) {
			cpu1infop = FIND_CPUP(globals->cpu_hash, pcpuinfop->lcpu1);
			cpu2infop = FIND_CPUP(globals->cpu_hash, pcpuinfop->lcpu2);
			pcpuinfop->busy_time = 0;
			pcpuinfop->idle_time = 0;
			pcpuinfop->unknown_idle = 0;
			pcpuinfop->unknown_busy = 0;
			bzero(pcpuinfop->sys_DBDI_hist, sizeof(uint64)*IDLE_TIME_NBUCKETS);
			bzero(pcpuinfop->pset_DBDI_hist, sizeof(uint64)*IDLE_TIME_NBUCKETS);
			bzero(pcpuinfop->ldom_DBDI_hist, sizeof(uint64)*IDLE_TIME_NBUCKETS);

			cpu1infop->lcpu_state = LCPU_UNKNOWN;
			cpu2infop->lcpu_state = LCPU_UNKNOWN;
			cpu1infop->lcpu_busy = 0;
			cpu2infop->lcpu_busy = 0;
		}
	}
}

void
clear_all_stats()
{
	int i;
#if MALLOC_DEBUG
	fprintf (stderr, "clear_all_stats\n");
#endif 
        free_hash_table((lle_t ***)&globals->slp_hash, SLP_HSIZE);
        free_hash_table((lle_t ***)&globals->stktrc_hash, STKTRC_HSIZE);
        clear_hc_info((void **)&globals->hcinfop);
        clear_irq_stats((void **)&globals->irqp);
        clear_irq_stats((void **)&globals->softirqp);
	clear_sched_info((void **)&globals->schedp);
	foreach_hash_entry((void **)globals->syscall_hash, SYSCALL_HASHSZ, clear_syscall_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->syscall_hash, SYSCALL_HASHSZ);
	foreach_hash_entry((void **)globals->trc_hash, TRC_HASHSZ, clear_trc_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->trc_hash, TRC_HASHSZ);
	foreach_hash_entry((void **)globals->futex_hash, FUTEX_HSIZE, clear_gbl_futex_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->futex_hash, FUTEX_HSIZE);
	free_hash_table((lle_t ***)&globals->dskblk_hash, DSKBLK_HSIZE);

	foreach_hash_entry((void **)globals->ctx_hash, CTX_HSIZE, clear_ctx_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->ctx_hash, CTX_HSIZE);

        foreach_hash_entry((void **)globals->devhash, DEV_HSIZE, clear_global_devinfo, NULL, 0, NULL);
        foreach_hash_entry((void **)globals->mdevhash, DEV_HSIZE, clear_global_devinfo, NULL, 0, NULL);

        foreach_hash_entry((void **)globals->fdata_hash, FDATA_HASHSZ, clear_fdata_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->fdata_hash, FDATA_HASHSZ);

        foreach_hash_entry((void **)globals->sdata_hash, SDATA_HASHSZ, clear_sdata_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->sdata_hash, SDATA_HASHSZ);

        foreach_hash_entry((void **)globals->pid_hash, PID_HASHSZ, clear_pid_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->pid_hash, PID_HASHSZ);

	foreach_hash_entry((void **)globals->ipip_hash, IPIP_HASHSZ, clear_ipip_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->ipip_hash, IPIP_HASHSZ);

	foreach_hash_entry((void **)globals->rip_hash, IP_HASHSZ, clear_ip_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->rip_hash, IP_HASHSZ);

	foreach_hash_entry((void **)globals->lip_hash, IP_HASHSZ, clear_ip_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->lip_hash, IP_HASHSZ);

	foreach_hash_entry((void **)globals->rsock_hash, SOCK_HASHSZ, clear_ip_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->rsock_hash, SOCK_HASHSZ);

	foreach_hash_entry((void **)globals->lsock_hash, SOCK_HASHSZ, clear_ip_info, NULL, 0, NULL);
	free_hash_table((lle_t ***)&globals->lsock_hash, SOCK_HASHSZ);

        foreach_hash_entry((void **)globals->fchash, FC_HSIZE, clear_fc_iostats, NULL, 0, NULL);

	foreach_hash_entry((void **)globals->docker_hash, DOCKER_HASHSZ, clear_docker_info, NULL, 0, NULL);

	free_hash_table((lle_t ***)&globals->ldom_hash, LDOM_HASHSZ);


	FREE(globals->powerp);
	globals->powerp = NULL;
	FREE(globals->iotimes);
	globals->iotimes = NULL;

        clear_percpu_stats();
        clear_HT_stats(NULL);
	clear_global_stats();

	bzero((char *)ldrq, MAXLDOMS * sizeof(runq_info_t) );
        bzero(&globals->iostats, sizeof(struct iostats)*3);
        bzero(&globals->netstats, sizeof(struct sd_stats));

	if (oracle) {
		for (i = 1; i < next_sid; i++) {
			bzero (&sid_table[i].stats, sizeof(ora_stats_t));
		}
	}

        return;
}
