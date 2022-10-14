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
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long uint64;

typedef signed char int8;
typedef signed short int16;
typedef signed int int32;
typedef signed long int64;

#define TRUE 1
#define FALSE 0
#define TRACEMEM_FAIL -1
#define ALL_KERNELTRACES_FAIL -2
#define ALL_SYSCALLTRACES_FAIL -3
#define CLR_SYSCALL_FAIL -4
#define FREE_TRACEMEM_FAIL -5
#define SECS(value) ((value) / 1000000000.0)	/* nanoseconds to seconds */
#define MSECS(value) ((value) / 1000000.0)	/* microseconds to seconds */
#define MiSECS(value) ((value) / 1000.0) 	/* milliseconds to seconds */
#define JiSECS(value) ((value) / 100.0)		/* Jiffy/centiseconds to seconds */
#define NSECS(value) ((value))
#define KI_MAXTRACECALLS 2600
#define LIKI_MAXTRACECALLS 64 
#define KI_MAXSYSCALLS	 500

#define MIN(X,Y) ((X) < (Y) ?  (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ?  (X) : (Y))

/* function prototypes */
void read_traces (FILE *trcfile);


/*globals*/
extern int debug;
extern struct tm gmt;
extern uint32 _buffer_size;
extern int is_alive;
extern int kilive;
extern int VM_guest;
extern int alarm_secs;
extern FILE *output;
extern char release[];
extern char hostname[];
extern char HTML;
extern char update_flag;
extern char *timestamp;
extern char *cmdstr;
extern int  Txtfile;
extern char *tool_name;
extern char *tool_version;
