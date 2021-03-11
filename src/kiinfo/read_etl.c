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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "globals.h"
#include "developers.h"
#include "info.h"
#include "kd_types.h"

extern char *open_trace_file(char *, int, int, mode_t);
extern int close_trace_files(int);

int 
etldump()
{
	char fname[128];
	char version[20];
	char errmsg[256];
	char *etl_fname, *addr, *ptr;
	int  etl_fd;
	struct stat statbuf;
	etw_bufhd_t *bufhdp;
	uint32 bufsz = 0;
	int i=0, cpu, ncpus=0;
	EventTraceHdr_t *eventp;
	char first_file = FALSE;
	uint32 buffer[4];
	etw_header_page_t header;
	off_t offset;

	if (debug) printf ("etldump()\n");

	if (timestamp == NULL) {
		fprintf (stderr, "kiinfo -etldump option requires timestamp (-ts)\n");
		exit(-1);
	}

	if (etl_filename) { 
		etl_fname = etl_filename;
	} else {
		sprintf(fname, "ki.%s.etl", timestamp);
		etl_fname = fname;
	}

	sprintf(version, "%s (%s)", tool_name, tool_version);

	if ((etl_fd = open(etl_fname, O_RDONLY)) < 0) {
		FATAL(errno, "Cannot open file", etl_fname, -1);
	}

        if (fstat(etl_fd, &statbuf) != 0) {
		FATAL(errno, "Cannot fstat file", etl_fname, -1);
        }

        if (statbuf.st_size == 0) {
		FATAL(0, "File is empty", etl_fname, -1);
        }

        addr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, etl_fd, 0);
        if (addr == MAP_FAILED) {
		FATAL(errno, "Cannot mmap file", etl_filename, -1);
	}

	printf ("ETL File %s opened succesfully!   Size = 0x%llx\n", etl_fname, statbuf.st_size);
	ptr = addr;

	while (ptr < addr+statbuf.st_size) { 
		bufhdp = (etw_bufhd_t *)ptr;
		cpu = bufhdp->cpu;
		bufsz = bufhdp->bufsz;

		if (cpu < 0) {
			printf ("CPU value less than 0\n");
			printf ("[%d] 0x%llx  -- Buffer CPU %d --\n", i, ptr-addr, cpu);
			printf ("     Bufsz: %d\n", bufhdp->bufsz);
			exit(-10);
		}
	
/*
		Buffers may be different sizes!!
		if (bufsz == 0) bufsz = bufhdp->bufsz;
		if (bufhdp->bufsz != bufsz) {
			printf ("[%d] 0x%llx  -- Buffer CPU %d --\n", i, ptr-addr, cpu);
			hex_dump(bufhdp, 2);
			FATAL(1510, "Invalid Buffer header found", "bufsz:", bufhdp->bufsz);
		}
*/

		sprintf(fname, "ki.bin.%03d.%s", cpu, timestamp);

		uint64 PerfFreq = 2648433;
		time_t tv_sec;
		uint64 tv_nsec;
		
		if (trace_files[cpu].fd == 0) {
			open_trace_file(fname, cpu, O_CREAT | O_WRONLY, 0666);
			if (trace_files[cpu].fd <= 0) {
				i++;
				ptr+= bufhdp->bufsz;
				continue;
			}
	
			if ((cpu+1) > ncpus) ncpus = cpu+1;

			if (debug) {
				tv_sec = (bufhdp->timestamp - UNIX_TIME_START) / TICKS_PER_SECOND;
				tv_nsec = (bufhdp->timestamp - UNIX_TIME_START) % TICKS_PER_SECOND*100;

				printf ("Bin Trace file %s opened \n", fname);
				printf ("[%d] 0x%llx  -- Buffer CPU %d --\n", i, ptr-addr, cpu);
				printf ("     Bufsz: %d\n", bufhdp->bufsz);
				printf ("     Datasz: %d\n", bufhdp->datasz);
				printf ("     timestamp: %s\n", ctime(&tv_sec));
				printf ("     cpu: %d\n", cpu);
			}


			if (cpu == 0) {
			/* Let's print first record */
			eventp = (EventTraceHdr_t *)(ptr + sizeof(etw_bufhd_t));
			printf ("  Event 0\n");
			printf ("    TraceVers:   %d\n", eventp->TraceVersion);
			printf ("    Reserved:    0x%x\n", eventp->ReservedHeaderField);
			printf ("    EventType:   %d\n", eventp->EventType);
			printf ("    EventSize:   %d\n", eventp->EventSize);
			printf ("    Pid:         %d\n", eventp->pid);
			printf ("    Tid:         %d\n", eventp->tid);
			printf ("    TimeStamp:   0x%llx\n", eventp->TimeStamp);
			tv_sec = (eventp->EndTime - UNIX_TIME_START) / TICKS_PER_SECOND;
			tv_nsec = (eventp->EndTime - UNIX_TIME_START) % TICKS_PER_SECOND*100;
			printf ("    EndTime:     %s 0x%llx\n", ctime(&tv_sec), eventp->EndTime);
			tv_sec = (eventp->StartTime - UNIX_TIME_START) / TICKS_PER_SECOND;
			tv_nsec = (eventp->StartTime - UNIX_TIME_START) % TICKS_PER_SECOND*100;
			printf ("    StartTime:   %s 0x%llx\n", ctime(&tv_sec), eventp->StartTime);
			tv_sec = (eventp->BootTime - UNIX_TIME_START) / TICKS_PER_SECOND;
			tv_nsec = (eventp->BootTime - UNIX_TIME_START) % TICKS_PER_SECOND*100;
			printf ("    BootTime:    %s 0x%llx\n", ctime(&tv_sec), eventp->EndTime);

			printf ("    KernelTime:  %d\n", eventp->KernelTime);
			printf ("    UserTime:    %d\n", eventp->UserTime);
			printf ("    BufferSize:  %d\n", eventp->BufferSize);
			printf ("    Version:     %d\n", eventp->Version);
			printf ("    NumCPUs:	  %d\n", eventp->NumberOfProcessors);
			printf ("    CPUSpeed:    %d MHZ\n", eventp->CPUSpeed);
			printf ("    TimerRes:   %d\n", eventp->TimerResolution);
			printf ("    PerfFreq:    %lld\n", eventp->PerfFreq);

			printf ("    TIME:        0x%llx\n", eventp->TimeStamp * eventp->TimerResolution);
			
			}	
		}

		/* Write Buffer to per-CPU file */
		offset = lseek(trace_files[cpu].fd, 0, SEEK_CUR);
		if (write(trace_files[cpu].fd, ptr, bufsz) != bufsz) { 
			FATAL(errno, "Failed to write to file", fname, -1);
		}

		/* Here, we will convert each WINKI header, to a FTRACE header.  */
		header.time = bufhdp->timestamp;
		header.commit = bufhdp->datasz;
		header.version = WINKI_V1;
		/* In the special case, we will save the winki "CHUNK_SIZE"      */

		header.bufsz = bufhdp->bufsz;
		header.cpu = cpu;

		lseek (trace_files[cpu].fd, offset, SEEK_SET);
		if (write(trace_files[cpu].fd, &header, sizeof(etw_header_page_t)) <= 0) { 
			FATAL(errno, "Failed to write version to file", fname, -1);
		}
		lseek (trace_files[cpu].fd, offset+bufsz, SEEK_SET);
		i++;
		ptr+= bufhdp->bufsz;
	}


	close_trace_files(ncpus);
}


