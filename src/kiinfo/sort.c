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
#include <sys/errno.h>
#include <sys/types.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "hash.h"
#include "info.h"

/*
 *    sorts per-process information by total trace records
 */
int
pid_sort_by_trace_recs(const void *v1, void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
	int32 num1, num2;
	int32 diff;

	if (a1->cmd) {
		if (strstr(a1->cmd, "kiinfo")) { 
			num1 = 0;	
		}
	}

	if (a2->cmd) {
		if (strstr(a2->cmd, "kiinfo")) {
			num2 = 0;
		}
	}

	num1 = a1->num_tr_recs;
	num2 = a2->num_tr_recs;
	diff = num1 - num2;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

/*
 *    sorts per-process information by wakeups
 */
int
pid_sort_by_wakeups(const void *v1, void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
	sched_info_t *schedp1 = a1->schedp;
	sched_info_t *schedp2 = a2->schedp;
	int32 num1, num2;
	int32 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

	num1 = schedp1->max_wakeup_cnt;
	num2 = schedp2->max_wakeup_cnt;
	diff = num1 - num2;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

/*
 *    sorts per-process information by wakeups
 */
int
pid_sort_by_sleep_cnt(const void *v1, void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
	sched_info_t *schedp1 = a1->schedp;
	sched_info_t *schedp2 = a2->schedp;
	int32 num1, num2;
	int32 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
	num1 = schedp1->sched_stats.C_sleep_cnt;
	num2 = schedp2->sched_stats.C_sleep_cnt;
	diff = num1 - num2;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
pid_sort_by_iocnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
	int64 diff;

	return (int)(a2->iostats[IOTOT].compl_cnt - a1->iostats[IOTOT].compl_cnt);
}

int
pid_sort_by_miocnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
	int64 diff;

	return (int)(a2->miostats[IOTOT].compl_cnt - a1->miostats[IOTOT].compl_cnt);
}

int
pid_sort_by_runqtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_runq_time - schedp2->sched_stats.T_runq_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_runtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = schedp1->sched_stats.T_run_time - schedp2->sched_stats.T_run_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_systime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = schedp1->sched_stats.T_sys_time - schedp2->sched_stats.T_sys_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_stealtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pid_info_t *a1 = (pid_info_t *)*p1;
	pid_info_t *a2 = (pid_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = schedp1->sched_stats.T_stealtime - schedp2->sched_stats.T_stealtime;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_totalsys(const void *v1, void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_info_t *a1 = (pid_info_t *)*p1;
        pid_info_t *a2 = (pid_info_t *)*p2;
        hc_info_t *h1 = (hc_info_t *)a1->hcinfop;
        hc_info_t *h2 = (hc_info_t *)a2->hcinfop;
        int diff;

	if (h1 == NULL && h2 == NULL) return 0;
	if (h1 == NULL) return 1;
	if (h2 == NULL) return -1;

        diff = h1->cpustate[HC_SYS] - h2->cpustate[HC_SYS];

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_totalhc(const void *v1, void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_info_t *a1 = (pid_info_t *)*p1;
        pid_info_t *a2 = (pid_info_t *)*p2;
        hc_info_t *h1 = (hc_info_t *)a1->hcinfop;
        hc_info_t *h2 = (hc_info_t *)a2->hcinfop;
	int total1, total2;
        int diff;

	if (h1 == NULL && h2 == NULL) return 0;
	if (h1 == NULL) return 1;
	if (h2 == NULL) return -1;

        diff = h1->total - h2->total;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pid_sort_by_hc(const void *v1, void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_info_t *a1 = (pid_info_t *)*p1;
        pid_info_t *a2 = (pid_info_t *)*p2;
        hc_info_t *h1 = (hc_info_t *)a1->hcinfop;
        hc_info_t *h2 = (hc_info_t *)a2->hcinfop;
        int diff;

	if (h1 == NULL && h2 == NULL) return 0;
	if (h1 == NULL) return 1;
	if (h2 == NULL) return -1;

        diff = h1->total - h2->total;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

/*
 **    sorts per-process information by RSS
 **/
int
pid_sort_by_rss(const void *v1, void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_info_t *a1 = (pid_info_t *)*p1;
        pid_info_t *a2 = (pid_info_t *)*p2;
        int64 num1, num2;
        int64 diff;
        num1 = a1->rss;
        num2 = a2->rss;
        diff = num1 - num2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

/*
 **    sorts per-process information by VSS
 **/
int
pid_sort_by_vss(const void *v1, void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_info_t *a1 = (pid_info_t *)*p1;
        pid_info_t *a2 = (pid_info_t *)*p2;
        int64 num1, num2;
        int64 diff;
        num1 = a1->vss;
        num2 = a2->vss;
        diff = num1 - num2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
docker_sort_by_runtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	docker_info_t *dockerp1 = (docker_info_t *)*p1;
	docker_info_t *dockerp2 = (docker_info_t *)*p2;
	int64 diff;

        diff = dockerp1->sched_stats.T_run_time - dockerp2->sched_stats.T_run_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
docker_sort_by_iocnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	docker_info_t *dockerp1 = (docker_info_t *)*p1;
	docker_info_t *dockerp2 = (docker_info_t *)*p2;
	int64 diff;

	return (int)(dockerp2->iostats[IOTOT].compl_cnt - dockerp1->iostats[IOTOT].compl_cnt);
}

int
dkpid_sort_by_runtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dkpid_info_t *b1 = (dkpid_info_t *)*p1;
	dkpid_info_t *b2 = (dkpid_info_t *)*p2;
	pid_info_t *a1 = (pid_info_t *)b1->pidp;
	pid_info_t *a2 = (pid_info_t *)b2->pidp;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_run_time - schedp2->sched_stats.T_run_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
dkpid_sort_by_runqtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dkpid_info_t *b1 = (dkpid_info_t *)*p1;
	dkpid_info_t *b2 = (dkpid_info_t *)*p2;
	pid_info_t *a1 = (pid_info_t *)b1->pidp;
	pid_info_t *a2 = (pid_info_t *)b2->pidp;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_runq_time - schedp2->sched_stats.T_runq_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
dkpid_sort_by_systime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dkpid_info_t *b1 = (dkpid_info_t *)*p1;
	dkpid_info_t *b2 = (dkpid_info_t *)*p2;
	pid_info_t *a1 = (pid_info_t *)b1->pidp;
	pid_info_t *a2 = (pid_info_t *)b2->pidp;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_sys_time - schedp2->sched_stats.T_sys_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
dkpid_sort_by_rss(const void *v1, void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dkpid_info_t *b1 = (dkpid_info_t *)*p1;
	dkpid_info_t *b2 = (dkpid_info_t *)*p2;
	pid_info_t *a1 = (pid_info_t *)b1->pidp;
	pid_info_t *a2 = (pid_info_t *)b2->pidp;
        int64 num1, num2;
        int64 diff;
        num1 = a1->rss;
        num2 = a2->rss;
        diff = num1 - num2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
dkpid_sort_by_iocnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dkpid_info_t *b1 = (dkpid_info_t *)*p1;
	dkpid_info_t *b2 = (dkpid_info_t *)*p2;
	pid_info_t *a1 = (pid_info_t *)b1->pidp;
	pid_info_t *a2 = (pid_info_t *)b2->pidp;
	int64 diff;

	return (int)(a2->iostats[IOTOT].compl_cnt - a1->iostats[IOTOT].compl_cnt);
}

int
fc_sort_by_path(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fc_info_t *a1 = (fc_info_t *)*p1;
	fc_info_t *a2 = (fc_info_t *)*p2;
	int64 diff;

	diff = a2->lle.key - a1->lle.key;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_dev(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	int64 diff;

	diff = a2->lle.key - a1->lle.key;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_mdev(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	int64 diff1, diff2, diff3;

	diff1 = (uint64)a2->mdevinfop - (uint64)a1->mdevinfop;
	diff2 = a2->devpath - a1->devpath;
	diff3 = a2->lle.key - a1->lle.key;

	if (diff1 < 0) {
		return 1;
	} else if (diff1 > 0) {
		return -1;
	} else {
		if (diff2 < 0) {
			return 1;
		} else if (diff2 > 0) {
			return -1;
		} else {
			if (diff3 < 0) {
				return 1;
			} else if (diff3 > 0) {
				return -1;
			} else {
				return 0;
			}
		}
	}
}

int
irq_sort_by_time(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	irq_entry_t *a1 = (irq_entry_t *)*p1;
	irq_entry_t *a2 = (irq_entry_t *)*p2;
	int64 diff;

	diff = a1->total_time - a2->total_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
slp_scd_sort_by_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        scd_waker_info_t *a1 = (scd_waker_info_t *)*p1;
        scd_waker_info_t *a2 = (scd_waker_info_t *)*p2;
        int64 diff;

        diff = a1->sleep_time - a2->sleep_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
slp_scd_sort_by_count(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        scd_waker_info_t *a1 = (scd_waker_info_t *)*p1;
        scd_waker_info_t *a2 = (scd_waker_info_t *)*p2;

        int64 diff;

        diff = a1->count - a2->count;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
slp_sort_by_time(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	slp_info_t *a1 = (slp_info_t *)*p1;
	slp_info_t *a2 = (slp_info_t *)*p2;
	int64 diff;

	diff = a1->sleep_time - a2->sleep_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
slp_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	slp_info_t *a1 = (slp_info_t *)*p1;
	slp_info_t *a2 = (slp_info_t *)*p2;
	int64 diff;

	diff = a1->count - a2->count;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
fd_sort_by_type(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fd_info_t *a1 = (fd_info_t *)*p1;
	fd_info_t *a2 = (fd_info_t *)*p2;
	int64 diff1, diff2;

	diff1 = a2->ftype - a1->ftype;
	diff2 = a1->stats.syscall_cnt - a2->stats.syscall_cnt;

	if (diff1 < 0) {
		return 1;
	} else if (diff1 > 0) {
		return -1;
	} else {
		if (diff2 < 0) {
			return 1;
		} else if (diff2 > 0) {
			return -1;
		} else {
			return 0;
		}
	}
}

int
fd_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fd_info_t *a1 = (fd_info_t *)*p1;
	fd_info_t *a2 = (fd_info_t *)*p2;
	int64 diff;

	diff = a1->stats.syscall_cnt - a2->stats.syscall_cnt;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}


int
fd_sort_by_time(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fd_info_t *a1 = (fd_info_t *)*p1;
	fd_info_t *a2 = (fd_info_t *)*p2;
	int64 diff;

	diff = a1->stats.total_time - a2->stats.total_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}


int
pth_tid_sort_by_wait(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pth_tid_list_t  *a1 = (pth_tid_list_t *)*p1;
        pth_tid_list_t  *a2 = (pth_tid_list_t *)*p2;
        int64 diff;

        diff = a1->total_wait - a2->total_wait;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
pth_sort_by_wait(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pth_obj_stats_t *a1 = (pth_obj_stats_t *)*p1;
        pth_obj_stats_t *a2 = (pth_obj_stats_t *)*p2;
        int64 diff;

        diff = a1->total_wait - a2->total_wait;

	if (((a1->acq_cnt <= 1) && (a2->acq_cnt <= 1)) ||
	    ((a1->acq_cnt > 1) && (a2->acq_cnt > 1))) {
        	if (diff < 0) {
                	return 1;
        	} else if (diff > 0) {
                	return -1;
        	} else {
                	return 0;
        	}
	}

	if (a1->acq_cnt <=1) {
		return 1;
	} else {
		return -1;
	}
}

int
pth_sort_by_avwait(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pth_obj_stats_t *a1 = (pth_obj_stats_t *)*p1;
        pth_obj_stats_t *a2 = (pth_obj_stats_t *)*p2;
        int64 diff;

        diff = (a1->total_wait/a1->acq_cnt) - (a2->total_wait/a2->acq_cnt);

	if (((a1->acq_cnt <= 1) && (a2->acq_cnt <= 1)) ||
	    ((a1->acq_cnt > 1) && (a2->acq_cnt > 1))) {
        	if (diff < 0) {
                	return 1;
        	} else if (diff > 0) {
                	return -1;
        	} else {
                	return 0;
        	}
	}

	if (a1->acq_cnt <=1) {
		return 1;
	} else {
		return -1;
	}
}

int
pth_sort_by_waitcnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pth_obj_stats_t *a1 = (pth_obj_stats_t *)*p1;
        pth_obj_stats_t *a2 = (pth_obj_stats_t *)*p2;
        int64 diff;

        diff = a1->acq_cnt - a2->acq_cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
sock_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sock_info_t *a1 = (sock_info_t *)*p1;
	sock_info_t *a2 = (sock_info_t *)*p2;
	int64 diff;

	diff = a1->stats.syscall_cnt - a2->stats.syscall_cnt;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
ip_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	ip_info_t *a1 = (ip_info_t *)*p1;
	ip_info_t *a2 = (ip_info_t *)*p2;
	int64 diff;

	diff = a1->stats.syscall_cnt - a2->stats.syscall_cnt;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
futex_dupsort_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        futex_dup_t *a1 = (futex_dup_t *)*p1;
        futex_dup_t *a2 = (futex_dup_t *)*p2;
        int64 diff;

        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futex_reqsort_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        futex_reque_t *a1 = (futex_reque_t *)*p1;
        futex_reque_t *a2 = (futex_reque_t *)*p2;
        int64 diff;

        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
futex_pidsort_by_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        futex_pids_t *a1 = (futex_pids_t *)*p1;
        futex_pids_t *a2 = (futex_pids_t *)*p2;
        int64 diff;

        diff = a1->total_time - a2->total_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futexops_sort_by_op(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        futex_op_t *a1 = (futex_op_t *)*p1;
        futex_op_t *a2 = (futex_op_t *)*p2;
        int64 diff;

        diff = a2->lle.key - a1->lle.key;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futexops_sort_by_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        futex_op_t *a1 = (futex_op_t *)*p1;
        futex_op_t *a2 = (futex_op_t *)*p2;
        int64 diff;

        diff = a1->total_time - a2->total_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futex_sort_by_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        pid_futex_info_t *a1 = (pid_futex_info_t *)*p1;
        pid_futex_info_t *a2 = (pid_futex_info_t *)*p2;
        int64 diff;

        diff = a1->total_time - a2->total_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futex_gblsort_by_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        gbl_futex_info_t *a1 = (gbl_futex_info_t *)*p1;
        gbl_futex_info_t *a2 = (gbl_futex_info_t *)*p2;
        int64 diff;

        diff = a1->total_time - a2->total_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
futex_gblsort_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        gbl_futex_info_t *a1 = (gbl_futex_info_t *)*p1;
        gbl_futex_info_t *a2 = (gbl_futex_info_t *)*p2;
        int32 diff;

        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
syscall_sort_by_time(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	syscall_info_t *a1 = (syscall_info_t *)*p1;
	syscall_info_t *a2 = (syscall_info_t *)*p2;
	int64 diff;

	diff = a1->stats.total_time - a2->stats.total_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
syscall_sort_by_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	syscall_info_t *a1 = (syscall_info_t *)*p1;
	syscall_info_t *a2 = (syscall_info_t *)*p2;
	int64 diff;

	return  (int)(a2->stats.count - a1->stats.count);

}

int
pc_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pc_info_t *a1 = (pc_info_t *)*p1;
	pc_info_t *a2 = (pc_info_t *)*p2;
	int64 diff;

	diff = a1->count - a2->count;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
trc_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	trc_info_t *a1 = (trc_info_t *)*p1;
	trc_info_t *a2 = (trc_info_t *)*p2;
	int32 diff;

	diff = a1->count - a2->count;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_count(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	int64 diff;

	return (int)(a2->iostats[IOTOT].compl_cnt - a1->iostats[IOTOT].compl_cnt);
}

int
mpath_sort_by_cpu(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	mpath_info_t *a1 = (mpath_info_t *)*p1;
	mpath_info_t *a2 = (mpath_info_t *)*p2;
	int64 diff;

	diff = a2->lle.key - a1->lle.key;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_avserv(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	uint64 avserv1, avserv2;
	int64 diff;

	if (a1->iostats[IOTOT].compl_cnt) {
		avserv1 = a1->iostats[IOTOT].cum_ioserv / a1->iostats[IOTOT].compl_cnt;
	} else {
		avserv1 = 0;
	}

	if (a2->iostats[IOTOT].compl_cnt) {
	avserv2 = a2->iostats[IOTOT].cum_ioserv / a2->iostats[IOTOT].compl_cnt;
	} else {
		avserv2 = 0;
	}

	diff = avserv1 - avserv2;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else { 
		return 0;
	}
}

int
dev_sort_by_avserv_over5(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	uint64 avserv1, avserv2;
	uint64 ios1, ios2;
	int64 diff;

	if (a1->iostats[IOTOT].compl_cnt) {
		avserv1 = a1->iostats[IOTOT].cum_ioserv / a1->iostats[IOTOT].compl_cnt;
	} else {
		avserv1 = 0;
	}

	if (a2->iostats[IOTOT].compl_cnt) {
		avserv2 = a2->iostats[IOTOT].cum_ioserv / a2->iostats[IOTOT].compl_cnt;
	} else {
		avserv2 = 0;
	}
	ios1 = a1->iostats[IOTOT].compl_cnt / secs;
	ios2 = a2->iostats[IOTOT].compl_cnt / secs;

	diff = avserv1 - avserv2;
	if ((ios1 > 5) && (ios2 < 5)) 
		return -1;
	if ((ios1 < 5) && (ios2 > 5)) 
		return 1;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_avserv_less5(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	uint64 avserv1, avserv2;
	uint64 ios1, ios2;
	int64 diff;

	if(a1->iostats[IOTOT].compl_cnt) {
		avserv1 = a1->iostats[IOTOT].cum_ioserv / a1->iostats[IOTOT].compl_cnt;
	} else {
		avserv1 = 0;
	}

	if(a2->iostats[IOTOT].compl_cnt) {
		avserv2 = a2->iostats[IOTOT].cum_ioserv / a2->iostats[IOTOT].compl_cnt;
	} else {
		avserv2 = 0;
	}

	ios1 = a1->iostats[IOTOT].compl_cnt / secs;
	ios2 = a2->iostats[IOTOT].compl_cnt / secs;

	diff = avserv1 - avserv2;
	if ((ios1 > 5) && (ios2 < 5)) 
		return 1;
	if ((ios1 < 5) && (ios2 > 5)) 
		return -1;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dev_sort_by_avwait(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	uint64 avwait1, avwait2;
	int64 diff;

	if(a1->iostats[IOTOT].compl_cnt) {
		avwait1 = a1->iostats[IOTOT].cum_iowait / a1->iostats[IOTOT].compl_cnt;
	} else {
		avwait1 = 0;
	}


	if(a2->iostats[IOTOT].compl_cnt) {
		avwait2 = a2->iostats[IOTOT].cum_iowait / a2->iostats[IOTOT].compl_cnt;
	} else {
		avwait2 = 0;
	}

	diff = avwait1 - avwait2;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}


int
dev_sort_by_requeue(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dev_info_t *a1 = (dev_info_t *)*p1;
	dev_info_t *a2 = (dev_info_t *)*p2;
	uint64 avwait1, avwait2;
	int64 diff;

	diff = a1->iostats[IOTOT].requeue_cnt - a2->iostats[IOTOT].requeue_cnt;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

/* note the sleep cnt is used as a secondary sort key */
int
setrq_sort_by_sleep_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        setrq_info_t *a1 = (setrq_info_t *)*p1;
        setrq_info_t *a2 = (setrq_info_t *)*p2;
        int64 diff1, diff2;

        diff1 = a1->sleep_time - a2->sleep_time;
	diff2= a1->cnt - a2->cnt;

        if (diff1 < 0) {
                return 1;
        } else if (diff1 > 0) {
                return -1;
        } else if (diff2 < 0) {
		return 1;
	} else if (diff2 > 0) {
		return -1;
	} else {
                return 0;
        }
}



int
setrq_sort_by_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	setrq_info_t *a1 = (setrq_info_t *)*p1;
	setrq_info_t *a2 = (setrq_info_t *)*p2;
	int64 diff;

	diff = a1->cnt - a2->cnt;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
wtid_sort_by_slptime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	w_tid_t *a1 = (w_tid_t *)*p1;
	w_tid_t *a2 = (w_tid_t *)*p2;
	int64 diff;

	diff = a1->sleep_time - a2->sleep_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
fdata_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fdata_info_t *a1 = (fdata_info_t *)*p1;
	fdata_info_t *a2 = (fdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.syscall_cnt - a1->stats.syscall_cnt);
}

/*
int
fdata_sort_by_opens(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fdata_info_t *a1 = (fdata_info_t *)*p1;
	fdata_info_t *a2 = (fdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.open_cnt - a1->stats.open_cnt);
}
*/

int
fdata_sort_by_errs(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fdata_info_t *a1 = (fdata_info_t *)*p1;
	fdata_info_t *a2 = (fdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.errors - a1->stats.errors);
}

int
fdata_sort_by_elptime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fdata_info_t *a1 = (fdata_info_t *)*p1;
	fdata_info_t *a2 = (fdata_info_t *)*p2;
	int64 diff;

	diff = a1->stats.total_time - a2->stats.total_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
fdata_sort_by_pgcache(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	fdata_info_t *a1 = (fdata_info_t *)*p1;
	fdata_info_t *a2 = (fdata_info_t *)*p2;
	int32 diff;

	diff = (a1->cache_insert_cnt + a1->cache_evict_cnt) - 
	       (a2->cache_insert_cnt + a2->cache_evict_cnt);

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
pgcache_sort_by_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	pgcache_t *a1 = (pgcache_t *)*p1;
	pgcache_t *a2 = (pgcache_t *)*p2;
	int32 diff;

	diff = (a1->cache_insert_cnt + a1->cache_evict_cnt) - 
	       (a2->cache_insert_cnt + a2->cache_evict_cnt);

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
ipip_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	ipip_info_t *a1 = (ipip_info_t *)*p1;
	ipip_info_t *a2 = (ipip_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.syscall_cnt - a1->stats.syscall_cnt);
}

int
ip_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	ip_info_t *a1 = (ip_info_t *)*p1;
	ip_info_t *a2 = (ip_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.syscall_cnt - a1->stats.syscall_cnt);
}

int
sock_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sock_info_t *a1 = (sock_info_t *)*p1;
	sock_info_t *a2 = (sock_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.syscall_cnt - a1->stats.syscall_cnt);
}

int
sdata_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sdata_info_t *a1 = (sdata_info_t *)*p1;
	sdata_info_t *a2 = (sdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.syscall_cnt - a1->stats.syscall_cnt);
}

/*
int
sdata_sort_by_opens(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sdata_info_t *a1 = (sdata_info_t *)*p1;
	sdata_info_t *a2 = (sdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.open_cnt - a1->stats.open_cnt);
}
*/

int
sdata_sort_by_errs(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sdata_info_t *a1 = (sdata_info_t *)*p1;
	sdata_info_t *a2 = (sdata_info_t *)*p2;
	int64 diff;

	return (int)(a2->stats.errors - a1->stats.errors);
}

int
sdata_sort_by_elptime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	sdata_info_t *a1 = (sdata_info_t *)*p1;
	sdata_info_t *a2 = (sdata_info_t *)*p2;
	int64 diff;

	diff = a1->stats.total_time - a2->stats.total_time;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
dskblk_sort_by_rdcnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dskblk_info_t *a1 = (dskblk_info_t *)*p1;
	dskblk_info_t *a2 = (dskblk_info_t *)*p2;
	int64 diff;

	return (int)(a2->rd_cnt - a1->rd_cnt);
}

int
dskblk_sort_by_wrcnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	dskblk_info_t *a1 = (dskblk_info_t *)*p1;
	dskblk_info_t *a2 = (dskblk_info_t *)*p2;
	int64 diff;

	return (int)(a2->wr_cnt - a1->wr_cnt);
}

int
stktrc_sort_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        stktrc_info_t *a1;
        stktrc_info_t *a2;
        int32 diff;

        a1 = (stktrc_info_t *)*p1;
        a2 = (stktrc_info_t *)*p2;
        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}

int
stktrc_sort_by_slptime(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        stktrc_info_t *a1;
        stktrc_info_t *a2;
        int64 diff;

        a1 = (stktrc_info_t *)*p1;
        a2 = (stktrc_info_t *)*p2;
        diff = a1->slptime - a2->slptime;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}

/* coop related sort funcs */

int
coop_sort_scall_by_sleep_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_scall_t *a1;
        coop_scall_t *a2;
        int64 diff;

        a1 = (coop_scall_t *)*p1;
        a2 = (coop_scall_t *)*p2;
        diff = a1->sleep_time - a2->sleep_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}


int
coop_sort_scall_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_scall_t *a1;
        coop_scall_t *a2;
        int64 diff;

        a1 = (coop_scall_t *)*p1;
        a2 = (coop_scall_t *)*p2;
        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}


int
coop_sort_args_by_sleep_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_scall_arg_t *a1;
        coop_scall_arg_t *a2;
        int64 diff;

        a1 = (coop_scall_arg_t *)*p1;
        a2 = (coop_scall_arg_t *)*p2;
        diff = a1->sleep_time - a2->sleep_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}


int
coop_sort_args_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_scall_arg_t *a1;
        coop_scall_arg_t *a2;
        int64 diff;

        a1 = (coop_scall_arg_t *)*p1;
        a2 = (coop_scall_arg_t *)*p2;
        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}


int
coop_sort_slpfuncs_by_sleep_time(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_slpfunc_t *a1;
        coop_slpfunc_t *a2;
        int64 diff;

        a1 = (coop_slpfunc_t *)*p1;
        a2 = (coop_slpfunc_t *)*p2;
        diff = a1->sleep_time - a2->sleep_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }

}


int
coop_sort_slpfuncs_by_cnt(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        coop_slpfunc_t *a1;
        coop_slpfunc_t *a2;
        int64 diff;

        a1 = (coop_slpfunc_t *)*p1;
        a2 = (coop_slpfunc_t *)*p2;
        diff = a1->cnt - a2->cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_busy(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;	
	double diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = ((schedp1->sched_stats.T_run_time * 100.0) / (schedp1->sched_stats.T_run_time + schedp1->sched_stats.T_idle_time)) -
               ((schedp2->sched_stats.T_run_time * 100.0) / (schedp2->sched_stats.T_run_time + schedp2->sched_stats.T_idle_time));

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
server_sort_by_runtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;	
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = schedp1->sched_stats.T_run_time - schedp2->sched_stats.T_run_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_systime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;	
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

        diff = schedp1->sched_stats.T_sys_time - schedp2->sched_stats.T_sys_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_power(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        power_info_t *powerp1 = a1->powerp;
        power_info_t *powerp2 = a2->powerp;	
	int64 diff, events1, events2;

	if (powerp1 == NULL && powerp2 == NULL) return 0;
	if (powerp1 == NULL) return 1;
	if (powerp2 == NULL) return -1;

	events1 = powerp1->power_freq_cnt + powerp1->power_start_cnt + powerp1->power_end_cnt;
	events2 = powerp2->power_freq_cnt + powerp2->power_start_cnt + powerp2->power_end_cnt;
        diff = events1 - events2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_dbusy(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
	int64 diff;

        diff = a1->ht_double_busy - a2->ht_double_busy;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_iops(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
	double diff;

        diff = (a1->iostats[IOTOT].compl_cnt / a1->total_secs) - (a2->iostats[IOTOT].compl_cnt / a2->total_secs);

        if (diff < 0.0) {
                return 1;
        } else if (diff > 0.0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_hc(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
	hc_info_t *hc1 = a1->hcinfop;
	hc_info_t *hc2 = a2->hcinfop;
	int diff;

	if (hc1 == NULL && hc2 == NULL) return 0;
	if (hc1 == NULL) return 1;
	if (hc2 == NULL) return -1;

        diff = hc1->total - hc2->total;
	
        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_avrqtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        sched_info_t *schedp1 = a1->schedp;
        sched_info_t *schedp2 = a2->schedp;	
	runq_info_t *rq1, *rq2;
	double diff, av1, av2;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;

	rq1 = schedp1->rqinfop;
	rq2 = schedp2->rqinfop;

	if (rq1 == NULL && rq2 == NULL) return 0;
	if (rq1 == NULL) return 1;
	if (rq2 == NULL) return -1;

	av1 = ((rq1->total_time * 1.0) /MAX(rq1->cnt, 1));
	av2 = ((rq2->total_time * 1.0) /MAX(rq2->cnt, 1));
        diff = av1 - av2;

        if (diff < 0.0) {
                return 1;
        } else if (diff > 0.0) {
                return -1;
        } else {
                return 0;
        }
}

int
server_sort_by_netxfrd(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	server_info_t *a1 = (server_info_t *)*p1;
	server_info_t *a2 = (server_info_t *)*p2;
        sd_stats_t *stats1p = &a1->netstats;
        sd_stats_t *stats2p = &a2->netstats;	
	uint64  xfrd1, xfrd2;
	int64 diff;

	xfrd1 =  stats1p->rd_bytes + stats1p->wr_bytes;
	xfrd2 =  stats2p->rd_bytes + stats2p->wr_bytes;
        diff = xfrd1 - xfrd2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_runtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_run_time - schedp2->sched_stats.T_run_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_systime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_sys_time - schedp2->sched_stats.T_sys_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_hc_sys(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        hc_info_t *hc1 = b1->hcinfop;
        hc_info_t *hc2 = b2->hcinfop;
	int diff;

	if (hc1 == NULL && hc2 == NULL) return 0;
	if (hc1 == NULL) return 1;
	if (hc2 == NULL) return -1;
        diff = hc1->cpustate[HC_SYS] - hc2->cpustate[HC_SYS];

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
clpid_sort_by_hc(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        hc_info_t *hc1 = b1->hcinfop;
        hc_info_t *hc2 = b2->hcinfop;
	int diff;

	if (hc1 == NULL && hc2 == NULL) return 0;
	if (hc1 == NULL) return 1;
	if (hc2 == NULL) return -1;
        diff = hc1->total - hc2->total;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_runqtime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int64 diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.T_runq_time - schedp2->sched_stats.T_runq_time;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_wakeups(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.C_wakeup_cnt - schedp2->sched_stats.C_wakeup_cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_switch_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.C_switch_cnt - schedp2->sched_stats.C_switch_cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_sleep_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
        sched_info_t *schedp1 = b1->schedp;
        sched_info_t *schedp2 = b2->schedp;
	int diff;

	if (schedp1 == NULL && schedp2 == NULL) return 0;
	if (schedp1 == NULL) return 1;
	if (schedp2 == NULL) return -1;
        diff = schedp1->sched_stats.C_sleep_cnt - schedp2->sched_stats.C_sleep_cnt;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_miops(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
	server_info_t *g1 = a1->globals;
	server_info_t *g2 = a2->globals;
	double diff;

        diff = ((b1->miostats[IOTOT].compl_cnt * 1.0)/ g1->total_secs) - ((b2->miostats[IOTOT].compl_cnt * 1.0) / g2->total_secs);

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int
clpid_sort_by_iops(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clpid_info_t *a1 = (clpid_info_t *)*p1;
	clpid_info_t *a2 = (clpid_info_t *)*p2;
	pid_info_t *b1 = a1->pidp;
	pid_info_t *b2 = a2->pidp;
	server_info_t *g1 = a1->globals;
	server_info_t *g2 = a2->globals;
	double diff;

        diff = ((b1->iostats[IOTOT].compl_cnt * 1.0)/ g1->total_secs) - ((b2->iostats[IOTOT].compl_cnt * 1.0) / g2->total_secs);

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}


int
cldev_sort_by_iops(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	cldev_info_t *a1 = (cldev_info_t *)*p1;
	cldev_info_t *a2 = (cldev_info_t *)*p2;
	dev_info_t *b1 = a1->devinfop;
	dev_info_t *b2 = a2->devinfop;
	server_info_t *g1 = a1->globals;
	server_info_t *g2 = a2->globals;
	double diff;

        diff = ((b1->iostats[IOTOT].compl_cnt * 1.0)/ g1->total_secs) - ((b2->iostats[IOTOT].compl_cnt * 1.0) / g2->total_secs);

        if (diff < 0.0) {
                return 1;
        } else if (diff > 0.0) {
                return -1;
        } else {
                return 0.0;
        }
}

int
clfdata_sort_by_syscalls(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clfdata_info_t *a1 = (clfdata_info_t *)*p1;
	clfdata_info_t *a2 = (clfdata_info_t *)*p2;
	fdata_info_t *b1 = a1->fdatap;
	fdata_info_t *b2 = a2->fdatap;

	return (int)(b2->stats.syscall_cnt - b1->stats.syscall_cnt);
}

int
clfdata_sort_by_elptime(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clfdata_info_t *a1 = (clfdata_info_t *)*p1;
	clfdata_info_t *a2 = (clfdata_info_t *)*p2;
	fdata_info_t *b1 = a1->fdatap;
	fdata_info_t *b2 = a2->fdatap;
	int64 diff;

	diff = b1->stats.total_time - b2->stats.total_time;
	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int
clfdata_sort_by_errs(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clfdata_info_t *a1 = (clfdata_info_t *)*p1;
	clfdata_info_t *a2 = (clfdata_info_t *)*p2;
	fdata_info_t *b1 = a1->fdatap;
	fdata_info_t *b2 = a2->fdatap;

	return (int)(b2->stats.errors - b1->stats.errors);
}

int
clfutex_sort_by_cnt(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clfutex_info_t *a1 = (clfutex_info_t *)*p1;
	clfutex_info_t *a2 = (clfutex_info_t *)*p2;
	gbl_futex_info_t *f1 = a1->futexp;
	gbl_futex_info_t *f2 = a2->futexp;

	return (int)(f2->cnt - f1->cnt);
}

int
clfutex_sort_by_time(const void *v1, const void *v2)
{
	const uint64 *p1=v1;
	const uint64 *p2=v2;
	clfutex_info_t *a1 = (clfutex_info_t *)*p1;
	clfutex_info_t *a2 = (clfutex_info_t *)*p2;
	gbl_futex_info_t *f1 = a1->futexp;
	gbl_futex_info_t *f2 = a2->futexp;
	int64 diff;

	diff = f1->total_time - f2->total_time;
	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

int 
clipip_sort_by_netxfrd(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        clipip_info_t *a1 = (clipip_info_t *)*p1;
        clipip_info_t *a2 = (clipip_info_t *)*p2;
	ipip_info_t *b1 = a1->ipipp;
	ipip_info_t *b2 = a2->ipipp;
        sd_stats_t *stats1p = &b1->stats;
        sd_stats_t *stats2p = &b2->stats;	
	uint64  xfrd1, xfrd2;
	int64 diff;

	xfrd1 =  stats1p->rd_bytes + stats1p->wr_bytes;
	xfrd2 =  stats2p->rd_bytes + stats2p->wr_bytes;
        diff = xfrd1 - xfrd2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int 
clip_sort_by_netxfrd(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        clip_info_t *a1 = (clip_info_t *)*p1;
        clip_info_t *a2 = (clip_info_t *)*p2;
	ip_info_t *b1 = a1->ipp;
	ip_info_t *b2 = a2->ipp;
        sd_stats_t *stats1p = &b1->stats;
        sd_stats_t *stats2p = &b2->stats;	
	uint64  xfrd1, xfrd2;
	int64 diff;

	xfrd1 =  stats1p->rd_bytes + stats1p->wr_bytes;
	xfrd2 =  stats2p->rd_bytes + stats2p->wr_bytes;
        diff = xfrd1 - xfrd2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

int 
clsdata_sort_by_netxfrd(const void *v1, const void *v2)
{
        const uint64 *p1=v1;
        const uint64 *p2=v2;
        clsdata_info_t *a1 = (clsdata_info_t *)*p1;
        clsdata_info_t *a2 = (clsdata_info_t *)*p2;
	sdata_info_t *b1 = a1->sdatap;
	sdata_info_t *b2 = a2->sdatap;
        sd_stats_t *stats1p = &b1->stats;
        sd_stats_t *stats2p = &b2->stats;	
	uint64  xfrd1, xfrd2;
	int64 diff;

	xfrd1 =  stats1p->rd_bytes + stats1p->wr_bytes;
	xfrd2 =  stats2p->rd_bytes + stats2p->wr_bytes;
        diff = xfrd1 - xfrd2;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}
