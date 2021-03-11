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

int
print_sysconfig_services_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_Services_t *p = (SysConfig_Services_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);

	printf (" pid=%d state=0x%x tag=0x%x",
		p->ProcessId,
		p->ServiceState,
		p->SubProcessTag);

	chr = &p->Name[0];
	printf (" Service=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" Display=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" Process=\"");
	PRINT_WIN_NAME2(chr);

	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int
sysconfig_services_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_Services_t *p = (SysConfig_Services_t *)trcinfop->cur_event;
	uint16 *chr;
	pid_info_t *pidp;
	win_service_t *servicep;

	if (kitrace_flag) {
		print_sysconfig_services_func (trcinfop, p);
	}

	if (p->ProcessId == 0) return 0;
	
	pidp = GET_PIDP(&globals->pid_hash, p->ProcessId);

	servicep = (win_service_t *)add_entry_head ((lle_t **)&pidp->win_services, (uint64)p, sizeof (lle_t));

	chr = &p->Name[0];
	PRINT_WIN_NAME2_STR(util_str, chr);
	add_command (&pidp->hcmd, util_str);
	PRINT_WIN_NAME2_STR(NULL, chr);
	PRINT_WIN_NAME2_STR(util_str, chr);
	add_command (&pidp->cmd, util_str);
}
	

int 
print_sysconfig_physdisk_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_PhysDisk_t *p = (SysConfig_PhysDisk_t *)trcinfop->cur_event;
	uint16 *chr;

	PRINT_COMMON_FIELDS_C002(p);

	printf (" disknum=%d bps=%d port=%d path=%d target=%d lun=%d partcnt=%d dwc=%d",
		p->DiskNumber,
		p->BytesPerSector,
		p->SCSIPort,
		p->SCSIPath,
		p->SCSITarget,
		p->SCSILun,
		p->PartitionCount,
		p->WriteCacheEnabled);

	chr = &p->Manufacturer[0];
	printf (" Manufacturer=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\"\n");

	if (debug) hex_dump(p, 3);
}

int 
sysconfig_physdisk_func (void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	SysConfig_PhysDisk_t *p = (SysConfig_PhysDisk_t *)trcinfop->cur_event;
	dev_info_t *devinfop;

	if (kitrace_flag) {
		print_sysconfig_physdisk_func (trcinfop, p);
	}

	devinfop = GET_DEVP(&globals->devhash, p->DiskNumber);	
	devinfop->wsysconfigp = (void *)p;
}
