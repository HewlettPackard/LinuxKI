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

#define LGWR            0
#define ARCHIVE         1
#define DBWRITER        2
#define SLAVE           3
#define PQUERY          4
#define SHSERV          5
#define JOBQ            6
#define DISPATCHER      7
#define CHECKPT         8
#define PMON            9
#define SMON            10
#define RECOV           11
#define OTHER           14
#define ORACLE          15
#define NORACLE         16

extern int oracle_pid_stats(void *, void *);

static char *oracle_proc[NORACLE] = {
   "ora_lg",
   "ora_arc",
   "ora_dbw",
   "ora_i",
   "ora_p",
   "ora_s",
   "ora_j",
   "ora_d0",
   "ora_ckpt",
   "ora_pmon",
   "ora_smon",
   "ora_reco",
   "ora_ukn",
   "ora_ukn",
   "other",
   "oracle"
};

static char *oracle_procname[NORACLE] = {
    "Oracle Log Writer",
    "Oracle Archive Processes",
    "Oracle DB Writers",
    "Oracle Parallel Writers",
    "Oracle Parallel Query Processes",
    "Oracle Shared Server Processes",
    "Oracle Job Queue Processes",
    "Oracle Dispatcher Processes",
    "Oracle Checkpoint Process",
    "Oracle Process Monitor Process",
    "Oracle System Monitor Process",
    "Oracle Recoverer Process",
    "Oracle Unknown Processes",
    "Oracle Unknown Processes",
    "Other Oracle Processes",
    "Oracle Shadow Processes"
};

