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
#include <sys/socket.h>
#include <linux/kdev_t.h>
#include <unistd.h>
#include "ki_tool.h"
#include "liki.h"
#include "liki_extra.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "kd_types.h"
#include "conv.h"

/* following are needed for ftrace.  The buf is
   extra space for the command buffer on the conversion
*/
typedef struct scsi_dispatch_cmd_start_plus { 
	scsi_dispatch_cmd_start_t	data;
	char				buf[32];
} scsi_dispatch_cmd_start_plus_t;

typedef struct scsi_dispatch_cmd_done_plus { 
	scsi_dispatch_cmd_start_t	data;
	char				buf[32];
} scsi_dispatch_cmd_done_plus_t;

void
print_scsi_cmd(int cmd_len, char *ptr)
{
        int i;
        char *cmd_ptr;

        /* cmd_ptr = ptr+4;   skip over dynamic description fields */
        if (cmd_len) {
                printf ("%ccmd=[", fsep);
                int first_time=1;
                for (i=0; i < cmd_len; i++) {
                        if (i)  printf(" %02hhx", *ptr);
                        else
                                printf("%02hhx", *ptr);

                        ptr++;
                }
                printf ("]");
        }
        /* printf (" cmd=[ %s ]", cmd_ptr); */
}

static inline int 
print_scsi_dispatch_cmd_start_rec(void *a)
{
	scsi_dispatch_cmd_start_t *rec_ptr = (scsi_dispatch_cmd_start_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	
	printf ("%cpath=%d:%d:%d:%d%copcode=%s%ccmd_len=%d%cdata_sglen=%d%cprot_sglen=%d", 
		fsep, rec_ptr->host_no, rec_ptr->channel, rec_ptr->cmd_id, rec_ptr->lun,
		fsep, scsi_opcode_name[rec_ptr->opcode],
		fsep, rec_ptr->cmd_len,
		fsep, rec_ptr->data_sglen,
		fsep, rec_ptr->prot_sglen);

	if (rec_ptr->cmd_len) {
		printf ("%cprot_op=%d", fsep, rec_ptr->prot_op);
		print_scsi_cmd (rec_ptr->cmd_len, &rec_ptr->cmnd[0]);
	}

	printf ("\n");

	return 0;
}

int
scsi_dispatch_cmd_start_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	scsi_dispatch_cmd_start_plus_t tt_rec_ptr;
	scsi_dispatch_cmd_start_t *rec_ptr;

	if (debug) printf ("trace_scsi_dispatch_cmd_start_func()\n");

	rec_ptr = conv_scsi_dispatch_cmd_start(trcinfop, &tt_rec_ptr);
	print_scsi_dispatch_cmd_start_rec(rec_ptr);

	return 0;
}

static inline int
print_scsi_dispatch_cmd_done_rec(void *a)
{
	scsi_dispatch_cmd_done_t *rec_ptr = (scsi_dispatch_cmd_done_t *)a;

	PRINT_COMMON_FIELDS(rec_ptr);
	PRINT_EVENT(rec_ptr->id);
	
	printf ("%cpath=%d:%d:%d:%d%copcode=%s%ccmd_len=%d%cdata_sglen=%d%cprot_sglen=%d",
		fsep, rec_ptr->host_no, rec_ptr->channel, rec_ptr->cmd_id, rec_ptr->lun,
		fsep, scsi_opcode_name[rec_ptr->opcode],
		fsep, rec_ptr->cmd_len,
		fsep, rec_ptr->data_sglen,
		fsep, rec_ptr->prot_sglen);

	if (rec_ptr->cmd_len) {
		printf ("%cprot_op=%d", fsep, rec_ptr->prot_op);
		print_scsi_cmd (rec_ptr->cmd_len, &rec_ptr->cmnd[0]);
	}

	printf ("%cresult=%d\n", fsep, rec_ptr->result);

	return 0;
}

int
scsi_dispatch_cmd_done_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	filter_t *f = v;
	scsi_dispatch_cmd_done_plus_t tt_rec_ptr;
	scsi_dispatch_cmd_done_t *rec_ptr;

	if (debug) printf ("trace_scsi_dispatch_cmd_done_func()\n");

	rec_ptr = conv_scsi_dispatch_cmd_done(trcinfop, &tt_rec_ptr);
	print_scsi_dispatch_cmd_done_rec(rec_ptr);

	return 0;
}
