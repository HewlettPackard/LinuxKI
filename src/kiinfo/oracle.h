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

extern int oracle_pid_stats(void *, void *);
extern int get_oracle_wait_event(void *, unsigned long *, unsigned int);
extern void update_oracle_wait_event(void *, uint64);
extern void ora_wait_report(void *, void *);
extern void sid_wait_report(void *, void *);

extern char *oracle_proc[];
extern char *oracle_procname[];
extern char *oracle_wait_event[];

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

#define ORA_NONE			0
#define ORA_DB_FILE_SEQ_READ		1
#define ORA_LOG_FILE_SYNC_PWWAIT 	2
#define ORA_LOG_FILE_SYNC_POLLING 	3
#define ORA_CURSOR_PIN_S 		4
#define ORA_NET_FROM_CLIENT  		5
#define ORA_NET_FROM_DBLINK		6
#define ORA_ENQ_TX_ROW_LOCK		7
#define ORA_DB_ASYNC_IO			8
#define ORA_LOG_FILE_SWITCH		9
#define ORA_BUFFER_BUSY_WAIT		10
#define ORA_GC_CUR_READ			11
#define ORA_GC_CUR_MB_READ		12
#define ORA_LATCH_CACHE_BUF		13
#define ORA_NEVENTS			14	
