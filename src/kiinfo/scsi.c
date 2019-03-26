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

#define status_byte(result) (((result) >> 1) & 0x7f)
#define msg_byte(result)    (((result) >> 8) & 0xff)
#define host_byte(result)   (((result) >> 16) & 0xff)
#define driver_byte(result) (((result) >> 24) & 0xff)

static const char * const hostbyte_table[]={
"DID_OK", "DID_NO_CONNECT", "DID_BUS_BUSY", "DID_TIME_OUT", "DID_BAD_TARGET",
"DID_ABORT", "DID_PARITY", "DID_ERROR", "DID_RESET", "DID_BAD_INTR",
"DID_PASSTHROUGH", "DID_SOFT_ERROR", "DID_IMM_RETRY", "DID_REQUEUE",
"DID_TRANSPORT_DISRUPTED", "DID_TRANSPORT_FAILFAST", "DID_TARGET_FAILURE",
"DID_NEXUS_FAILURE" };

static const char * const driverbyte_table[]={
"DRIVER_OK", "DRIVER_BUSY", "DRIVER_SOFT",  "DRIVER_MEDIA", "DRIVER_ERROR",
"DRIVER_INVALID", "DRIVER_TIMEOUT", "DRIVER_HARD", "DRIVER_SENSE"};

static const char * const msgbyte_table[]={
"COMMAND_COMPLETE","EXTENDED_MSG","SAVE_POINTERS","RESTORE_POINTERS","DISCONNECT",
"INITIATOR_ERROR","ABORT_TASK_SET","MESSAGE_REJECT","NOP","MSG_PARITY_ERROR",
"LINKED_CMD_COMPLETE","LINKED_FLG_CMD_COMPLETE","TARGET_RESET","ABORT_TASK",
"CLEAR_TASK_SET","INITIATE_RECOVER","RELEASE_RECOVERY","0x11","0x12","0x13",
"0x14","0x15","CLEAR_ACA","LOGICAL_UNIT_RESET","0x18","0x19","0x1a","0x1b",
"0x1c","0x1d","0x1e","0x1f","SIMPLE_QUEUE_TAG","HEAD_OF_QUEUE_TAG",
"ORDERED_QUEUE_TAG","IGNORE_WIDE_RESIDUE","ACA"};

static const char * const statusbyte_table[]={
"GOOD","CHECK_CONDITION","0x3","BUSY","0x5","0x6","0x7","INTERMEDIATE_GOOD",
"0x9", "INTERMEDIATE_C_GOOD","0xb","RESERVATION_CONFLICT","0xd","0xe","0xf",
"0x10","COMMAND_TERMINATED","0x12","0x13","QUEUE_FULL","0x15","0x16","0x17",
"ACA_ACTIVE","0x19","0x1a","0x1b","0x1c","0x1d","0x1e","0x1f","TASK_ABORTED"};

static inline int
print_result(unsigned int result)
{
	printf ("%cresult=0x%x", fsep, result);
	if (result) {
		printf ("%c%s/%s/%s/%s", fsep, 
			driverbyte_table[driver_byte(result)],
			hostbyte_table[host_byte(result)],
			msg_byte(result) < 0x25 ? msgbyte_table[msg_byte(result)] : "?",
			status_byte(result) < 0x21 ? statusbyte_table[status_byte(result)] : "?");
	}
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

	print_result(rec_ptr->result);
	printf ("\n");

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
