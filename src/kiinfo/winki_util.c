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

#include "Pdb.h"
#include "Image.h"
#include "SysConfig.h"
#include "DiskIo.h"
#include "FileIo.h"
#include "Process.h"
#include "Thread.h"
#include "PerfInfo.h"
#include "Provider.h"
#include "NetIp.h"

extern int trace_winki_header_func(void *, void *);

void
winki_enable_event(int id, int func(void *, void*))
{
	ki_actions[id].func = func;
	ki_actions[id].execute = 1;
}

int
winki_init_actions(int func(void *, void*))
{
	int i;

	for (i = 0; i < 65536; i++) {
		ki_actions[i].id = i;
		ki_actions[i].func = func;
		ki_actions[i].execute = 0;
	}

	strcpy(&ki_actions[0].subsys[0], "EventTrace"); strcpy(&ki_actions[0].event[0], "Header");
	strcpy(&ki_actions[0x5].subsys[0], "EventTrace"); strcpy(&ki_actions[0x5].event[0], "Extension");
	strcpy(&ki_actions[0x8].subsys[0], "EventTrace"); strcpy(&ki_actions[0x8].event[0], "RDComplete");
	strcpy(&ki_actions[0x20].subsys[0], "EventTrace"); strcpy(&ki_actions[0x20].event[0], "EndExtension");
	strcpy(&ki_actions[0x50].subsys[0], "EventTrace"); strcpy(&ki_actions[0x50].event[0], "PartitionInfoExtension");
	strcpy(&ki_actions[0x10a].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10a].event[0], "Read"); 
	strcpy(&ki_actions[0x10b].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10b].event[0], "Write");
	strcpy(&ki_actions[0x10c].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10c].event[0], "ReadInit");
	strcpy(&ki_actions[0x10d].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10d].event[0], "WriteInit");
	strcpy(&ki_actions[0x10e].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10e].event[0], "FlushBuffers"); 
	strcpy(&ki_actions[0x10f].subsys[0], "DiskIo"); strcpy(&ki_actions[0x10f].event[0], "FlushInit");
	strcpy(&ki_actions[0x122].subsys[0], "DiskIo"); strcpy(&ki_actions[0x122].event[0], "DrvMjFnCall");
	strcpy(&ki_actions[0x123].subsys[0], "DiskIo"); strcpy(&ki_actions[0x123].event[0], "DrvMjFnRet");
	strcpy(&ki_actions[0x125].subsys[0], "DiskIo"); strcpy(&ki_actions[0x125].event[0], "DrvComplRout");
	strcpy(&ki_actions[0x134].subsys[0], "DiskIo"); strcpy(&ki_actions[0x134].event[0], "DiskComplReq");
	strcpy(&ki_actions[0x135].subsys[0], "DiskIo"); strcpy(&ki_actions[0x135].event[0], "DrvComplReqRet");
	strcpy(&ki_actions[0x220].subsys[0], "PageFault"); strcpy(&ki_actions[0x220].event[0], "HardFault");
	strcpy(&ki_actions[0x301].subsys[0], "Process"); strcpy(&ki_actions[0x301].event[0], "Start");
	strcpy(&ki_actions[0x302].subsys[0], "Process"); strcpy(&ki_actions[0x302].event[0], "End");
	strcpy(&ki_actions[0x303].subsys[0], "Process"); strcpy(&ki_actions[0x303].event[0], "DCStart");
	strcpy(&ki_actions[0x304].subsys[0], "Process"); strcpy(&ki_actions[0x304].event[0], "DCEnd");
	strcpy(&ki_actions[0x30a].subsys[0], "Process"); strcpy(&ki_actions[0x30a].event[0], "Load");
	strcpy(&ki_actions[0x30b].subsys[0], "Process"); strcpy(&ki_actions[0x30b].event[0], "Terminate");
	strcpy(&ki_actions[0x327].subsys[0], "Process"); strcpy(&ki_actions[0x327].event[0], "Defunct");
	strcpy(&ki_actions[0x400].subsys[0], "FileIo"); strcpy(&ki_actions[0x400].event[0], "FileName");
	strcpy(&ki_actions[0x420].subsys[0], "FileIo"); strcpy(&ki_actions[0x420].event[0], "FileCreate");
	strcpy(&ki_actions[0x423].subsys[0], "FileIo"); strcpy(&ki_actions[0x423].event[0], "FileDelete");
	strcpy(&ki_actions[0x424].subsys[0], "FileIo"); strcpy(&ki_actions[0x424].event[0], "FileRundown");
	strcpy(&ki_actions[0x440].subsys[0], "FileIo"); strcpy(&ki_actions[0x440].event[0], "Create");
	strcpy(&ki_actions[0x441].subsys[0], "FileIo"); strcpy(&ki_actions[0x441].event[0], "Cleanup");
	strcpy(&ki_actions[0x442].subsys[0], "FileIo"); strcpy(&ki_actions[0x442].event[0], "Close");
	strcpy(&ki_actions[0x443].subsys[0], "FileIo"); strcpy(&ki_actions[0x443].event[0], "Read");
	strcpy(&ki_actions[0x444].subsys[0], "FileIo"); strcpy(&ki_actions[0x444].event[0], "Write");
	strcpy(&ki_actions[0x445].subsys[0], "FileIo"); strcpy(&ki_actions[0x445].event[0], "SetInfo");
	strcpy(&ki_actions[0x446].subsys[0], "FileIo"); strcpy(&ki_actions[0x446].event[0], "Delete");
	strcpy(&ki_actions[0x447].subsys[0], "FileIo"); strcpy(&ki_actions[0x447].event[0], "Rename");
	strcpy(&ki_actions[0x448].subsys[0], "FileIo"); strcpy(&ki_actions[0x448].event[0], "DirEnum");
	strcpy(&ki_actions[0x449].subsys[0], "FileIo"); strcpy(&ki_actions[0x449].event[0], "Flush");
	strcpy(&ki_actions[0x44a].subsys[0], "FileIo"); strcpy(&ki_actions[0x44a].event[0], "QueryInfo");
	strcpy(&ki_actions[0x44b].subsys[0], "FileIo"); strcpy(&ki_actions[0x44b].event[0], "FSControl");
	strcpy(&ki_actions[0x44c].subsys[0], "FileIo"); strcpy(&ki_actions[0x44c].event[0], "OperationEnd");
	strcpy(&ki_actions[0x44d].subsys[0], "FileIo"); strcpy(&ki_actions[0x44d].event[0], "DirNotify");
	strcpy(&ki_actions[0x44f].subsys[0], "FileIo"); strcpy(&ki_actions[0x44f].event[0], "DeletePath");
	strcpy(&ki_actions[0x450].subsys[0], "FileIo"); strcpy(&ki_actions[0x450].event[0], "RenamePath");
	strcpy(&ki_actions[0x501].subsys[0], "Thread"); strcpy(&ki_actions[0x501].event[0], "Start");
	strcpy(&ki_actions[0x502].subsys[0], "Thread"); strcpy(&ki_actions[0x502].event[0], "End");
	strcpy(&ki_actions[0x503].subsys[0], "Thread"); strcpy(&ki_actions[0x503].event[0], "DCStart");
	strcpy(&ki_actions[0x504].subsys[0], "Thread"); strcpy(&ki_actions[0x504].event[0], "DCEnd");
	strcpy(&ki_actions[0x524].subsys[0], "Thread"); strcpy(&ki_actions[0x524].event[0], "Cswitch");
	strcpy(&ki_actions[0x532].subsys[0], "Thread"); strcpy(&ki_actions[0x532].event[0], "ReadyThread");
	strcpy(&ki_actions[0x542].subsys[0], "Thread"); strcpy(&ki_actions[0x542].event[0], "AutoBoostSetFloor");
	strcpy(&ki_actions[0x543].subsys[0], "Thread"); strcpy(&ki_actions[0x543].event[0], "AutoBoostClearFloor");
	strcpy(&ki_actions[0x544].subsys[0], "Thread"); strcpy(&ki_actions[0x544].event[0], "AutoBoostEntryExhaustion");
	strcpy(&ki_actions[0x548].subsys[0], "Thread"); strcpy(&ki_actions[0x548].event[0], "SetName");
	strcpy(&ki_actions[0x60a].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60a].event[0], "SendIPV4");
	strcpy(&ki_actions[0x60b].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60b].event[0], "RecvIPV4");
	strcpy(&ki_actions[0x60c].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60c].event[0], "ConnectIPV4");
	strcpy(&ki_actions[0x60d].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60d].event[0], "DisconnectIPV4");
	strcpy(&ki_actions[0x60e].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60e].event[0], "RetransmitIPV4");
	strcpy(&ki_actions[0x60e].subsys[0], "TcpIp"); strcpy(&ki_actions[0x60e].event[0], "AcceptIPV4");
	strcpy(&ki_actions[0x610].subsys[0], "TcpIp"); strcpy(&ki_actions[0x610].event[0], "ReconnectIPV4");
	strcpy(&ki_actions[0x611].subsys[0], "TcpIp"); strcpy(&ki_actions[0x611].event[0], "Fail");
	strcpy(&ki_actions[0x612].subsys[0], "TcpIp"); strcpy(&ki_actions[0x612].event[0], "TCPCopyIPV4");
	strcpy(&ki_actions[0x61a].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61a].event[0], "SendIPV6");
	strcpy(&ki_actions[0x61b].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61b].event[0], "RecvIPV6");
	strcpy(&ki_actions[0x61c].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61c].event[0], "ConnectIPV6");
	strcpy(&ki_actions[0x61d].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61d].event[0], "DisconnectIPV6");
	strcpy(&ki_actions[0x61e].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61e].event[0], "RetransmitIPV6");
	strcpy(&ki_actions[0x61f].subsys[0], "TcpIp"); strcpy(&ki_actions[0x61f].event[0], "AcceptIPV6");
	strcpy(&ki_actions[0x620].subsys[0], "TcpIp"); strcpy(&ki_actions[0x620].event[0], "ReconnectIPV6");
	strcpy(&ki_actions[0x622].subsys[0], "TcpIp"); strcpy(&ki_actions[0x622].event[0], "TCPCopyIPV6");
	strcpy(&ki_actions[0x80a].subsys[0], "UdpIp"); strcpy(&ki_actions[0x80a].event[0], "SendIPV4");
	strcpy(&ki_actions[0x80b].subsys[0], "UdpIp"); strcpy(&ki_actions[0x80b].event[0], "RecvIPV4");
	strcpy(&ki_actions[0x811].subsys[0], "UdpIp"); strcpy(&ki_actions[0x11b].event[0], "Fail");
	strcpy(&ki_actions[0x81a].subsys[0], "UdpIp"); strcpy(&ki_actions[0x81a].event[0], "SendIPV6");
	strcpy(&ki_actions[0x81b].subsys[0], "UdpIp"); strcpy(&ki_actions[0x81b].event[0], "RecvIPV6");
	strcpy(&ki_actions[0xb0a].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0a].event[0], "CPU");
	strcpy(&ki_actions[0xb0b].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0b].event[0], "PhysDisk");
	strcpy(&ki_actions[0xb0c].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0c].event[0], "LogDisk");
	strcpy(&ki_actions[0xb0d].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0d].event[0], "NIC");
	strcpy(&ki_actions[0xb0e].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0e].event[0], "Video");
	strcpy(&ki_actions[0xb0f].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb0f].event[0], "Services");
	strcpy(&ki_actions[0xb10].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb10].event[0], "Power");
	strcpy(&ki_actions[0xb12].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb12].event[0], "OpticalDisk");
	strcpy(&ki_actions[0xb15].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb15].event[0], "IRQ");
	strcpy(&ki_actions[0xb16].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb16].event[0], "PnP");
	strcpy(&ki_actions[0xb18].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb18].event[0], "NumaNode");
	strcpy(&ki_actions[0xb19].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb19].event[0], "Platform");
	strcpy(&ki_actions[0xb1a].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1a].event[0], "ProcessorGroup");
	strcpy(&ki_actions[0xb1b].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1b].event[0], "ProcessorGroup");
	strcpy(&ki_actions[0xb1c].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1c].event[0], "DPI");
	strcpy(&ki_actions[0xb1d].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1d].event[0], "CodeIntegrity");
	strcpy(&ki_actions[0xb1e].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1e].event[0], "TelemetryConfig");
	strcpy(&ki_actions[0xb1f].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb1f].event[0], "Defragmentation");
	strcpy(&ki_actions[0xb21].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb21].event[0], "DeviceFamily");
	strcpy(&ki_actions[0xb22].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb22].event[0], "FlightIds");
	strcpy(&ki_actions[0xb23].subsys[0], "SysConfig"); strcpy(&ki_actions[0xb23].event[0], "FlightIds");
	strcpy(&ki_actions[0xf2e].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf2e].event[0], "SampleProfile");
	strcpy(&ki_actions[0xf32].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf32].event[0], "ISR-MSI");
	strcpy(&ki_actions[0xf33].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf33].event[0], "SysClEnter");
	strcpy(&ki_actions[0xf34].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf34].event[0], "SysClExit");
	strcpy(&ki_actions[0xf42].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf42].event[0], "ThreadedDPC");
	strcpy(&ki_actions[0xf43].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf43].event[0], "ISR");
	strcpy(&ki_actions[0xf44].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf44].event[0], "DPC");
	strcpy(&ki_actions[0xf45].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf45].event[0], "TimeDPC");
	strcpy(&ki_actions[0xf48].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf48].event[0], "SetInterval");
	strcpy(&ki_actions[0xf49].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf49].event[0], "CollectionStart");
	strcpy(&ki_actions[0xf4a].subsys[0], "PerfInfo"); strcpy(&ki_actions[0xf4a].event[0], "CollectionEnd");
	strcpy(&ki_actions[0x1235].subsys[0], "Power"); strcpy(&ki_actions[0x1235].event[0], "Cstate");
	strcpy(&ki_actions[0x1402].subsys[0], "Image"); strcpy(&ki_actions[0x1402].event[0], "UnLoad");
	strcpy(&ki_actions[0x1403].subsys[0], "Image"); strcpy(&ki_actions[0x1403].event[0], "DCStart");
	strcpy(&ki_actions[0x1404].subsys[0], "Image"); strcpy(&ki_actions[0x1404].event[0], "DCEnd");
	strcpy(&ki_actions[0x140a].subsys[0], "Image"); strcpy(&ki_actions[0x140a].event[0], "Load");
	strcpy(&ki_actions[0x1421].subsys[0], "Image"); strcpy(&ki_actions[0x1421].event[0], "KernelBase");
	strcpy(&ki_actions[0x1820].subsys[0], "StackWalk"); strcpy(&ki_actions[0x1820].event[0], "Stack");
}

int
winki_header_func (void *a, void *v)
{
        trace_winki_header_func(a, v);

        ki_actions[0].execute = 0;
}

void
winki_update_sched_state(void *arg, int old_state, int new_state, uint64 delta)
{
        sched_stats_t *statp = arg;

	if (debug) printf ("statp: 0x%llx old_state: 0x%x new_state: 0x%x delta: %lld  ", statp, old_state, new_state, delta); 
	if (debug) printf ("RunTime: %12.6f  UserTime: %12.6f  SysTime: %12.6f  IdleTime: %12.6f \n",
			SECS(statp->T_run_time), SECS(statp->T_user_time), SECS(statp->T_sys_time), SECS(statp->T_idle_time));

        if (old_state & RUNNING) {
                statp->T_run_time += delta;
                if ((old_state & USER) && (old_state & HARDIRQ)) {
                        statp->T_hardirq_user_time += delta;
                } else if ((old_state & USER) && (old_state & SOFTIRQ)) {
                        statp->T_softirq_user_time += delta;
                } else if (old_state & USER) {
                        statp->T_user_time += delta;
                } else if ((old_state & SYS) && (old_state & HARDIRQ)) {
                        statp->T_hardirq_sys_time += delta;
                } else if ((old_state & SYS) && (old_state & SOFTIRQ)) {
                        statp->T_softirq_sys_time += delta;
                } else if (old_state & SYS) {
                        statp->T_sys_time += delta;
                } else if (old_state & HARDIRQ) {
                        /* assume process was running in the kernel? */
                        statp->T_hardirq_sys_time += delta;
                } else if (old_state & SOFTIRQ) {
                        /* assume process was running in the kernel? */
                        statp->T_softirq_user_time += delta;
                } else {
                        /* assume process was running in the kernel? */
                        statp->T_sys_time += delta;
                }
        } else if (old_state & RUNQ) {
                statp->T_runq_time += delta;
                statp->C_runq_cnt++;
                if (old_state & IDLE) {
                        statp->C_runq_idle_cnt++;
                        statp->T_runq_idle_time += delta;
                } else {
                        if (old_state & USER) {
                                statp->C_runq_usrpri_cnt++;
                                statp->T_runq_usrpri_time += delta;
                        }
                        statp->C_runq_pri_cnt++;
                        statp->T_runq_pri_time += delta;
                }
        } else if (old_state & SWTCH) {
                statp->T_sleep_time += delta;
        } else if (old_state & IDLE) {
                if (old_state & HARDIRQ) {
                        statp->T_hardirq_idle_time += delta;
                } else if (old_state & SOFTIRQ) {
                        statp->T_softirq_idle_time += delta;
                } else {
                        statp->T_idle_time += delta;
                }
	} else if (new_state & RUNQ) {
		/* assume thread was sleeping if it is being woken up */
                statp->T_sleep_time += delta;
		statp->LastWaitReason = UnknownReason;
		if (old_state & UNKNOWN) {
			statp->C_sleep_cnt++;
			statp->C_switch_cnt++;
		}
        } else {
                /* if the oldstate is UNKNOWN, we just dont account for it */
        } 


        statp->state = new_state;
	if (debug) printf ("\n");
}

static int last_syscall_idx = 0;

short 
syscall_addr_to_id(uint64 ip)
{
	addr_to_idx_hash_entry_t *syscall_hash_entryp;
	pid_info_t *syspidp;
	short idx;
	int i;
	char *name;

	if (ip == 0ull) return 0;

	syscall_hash_entryp = (addr_to_idx_hash_entry_t *)GET_ADDR_TO_IDX_HASH_ENTRYP(&globals->win_syscall_hash, ip);
	if (syscall_hash_entryp->idx == 0) {
		syspidp = GET_PIDP(&globals->pid_hash, 0);
		name = get_win_sym(ip, syspidp);
		if (name == NULL) return 0;

		idx = ++last_syscall_idx;
		syscall_hash_entryp->idx = idx;
		globals->syscall_index_64[idx] = idx;
		win_syscall_arg_list[idx].name = name;
		win_syscall_arg_list[idx].retval.label = "ret";
		win_syscall_arg_list[idx].retval.format = HEX;
		for (i = 0; i < MAXARGS; i++) {
			win_syscall_arg_list[idx].args[i].label=NULL;
			win_syscall_arg_list[idx].args[i].format=SKIP;
		}

		/* printf ("syscall_addr_to_id():   ip: 0x%llx  name %s   id: %d\n",
			ip, win_syscall_arg_list[idx].name, idx);
		*/
	}

	return syscall_hash_entryp->idx;
}

static int last_dpc_idx = 0;

int 
dpc_addr_to_idx(uint64 ip)
{
	addr_to_idx_hash_entry_t *dpc_hash_entryp;
	pid_info_t *syspidp;
	short idx;
	int i;
	char *name;

	if (ip == 0ull) return 0;

	dpc_hash_entryp = (addr_to_idx_hash_entry_t *)GET_ADDR_TO_IDX_HASH_ENTRYP(&globals->win_dpc_hash, ip);
	if (dpc_hash_entryp->idx == 0) {
		idx = (last_dpc_idx++);
		dpc_hash_entryp->idx = idx;
	}

	return dpc_hash_entryp->idx;
}
