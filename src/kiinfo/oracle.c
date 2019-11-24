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
#include <linux/kdev_t.h>
#include <err.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "globals.h"
#include "kd_types.h"
#include "info.h"

int oracle_pid_stats(void *arg1, void *arg2)
{
        sid_pid_t *sidpidp = (sid_pid_t *)arg1;
        ora_stats_t *orastatsp = (ora_stats_t *)arg2;
        pid_info_t *pidp = sidpidp->pidinfop;
	sched_info_t *schedp;

	if (pidp == NULL) return 0;
	schedp = (sched_info_t *)pidp->schedp;

        orastatsp->pid_cnt++;
	if (pidp->schedp) {
		orastatsp->run_time += schedp->sched_stats.T_run_time;
		orastatsp->runq_time += schedp->sched_stats.T_runq_time;
		orastatsp->sched_policy = schedp->policy;
	}

	sum_iostats(&pidp->iostats, &orastatsp->iostats);

        return 0;
}
