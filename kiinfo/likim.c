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

/* likim - LInux KI Merge
 *
 * Merge multiple time-ordered data files into a single time-ordered
 * data faile. Used to merge the per-CPU data into system-wide data.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include "liki.h"
#include "ki_tool.h"
#include "developers.h"
#include "globals.h"
#include "info.h"

ssize_t read_chunk(int fd, void * buf)
{
	return(read(fd, buf, CHUNK_SIZE));
}

int
merge()
{
	char 		*dirname;
	char		outputfile[80];
	char		fname[MAX_FNAME_LEN];
	char		*fname_ext = "";
	char		buf[CHUNK_SIZE];
	int		infds[MAXCPUS];
	int		incnt;
	int		outfd;
	DIR		*dp;
	struct dirent	*dep;
	unsigned int	sz;
	int		ret;
	int		i, j;
	merge_params_t	mp;

	if (debug) printf ("merge()\n");
	printf ("%s: Merging KI Binary Files\n", tool_name);


	/* Open all the input files found in the target directory that
	 * look like they contain trace data (denoted by their name
	 * being based on DEFAULT_DATAFILE_NAME).
	 */
	incnt = open_trace_files();
	if (incnt == 0) {
		fprintf (stderr, "No Active trace files to Merge\n");
		_exit(1);
	}

        if (debug) printf("open_trace_files(): returned %d\n", incnt);
        sprintf (outputfile, "%s.%s", DEFAULT_DATAFILE_NAME, timestamp);

        /* Open the output file */
        if ((outfd = open(outputfile, O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR)) == -1) {
		FATAL(errno, "Unable to open file", outputfile, -1);
        }

        if (debug) printf ("merge(): outputfile %s opened\n", outputfile);

	if (IS_LIKI) {
		/* Sort and merge the records, writing them to output */
		for (j=0, i=0; i < MAXCPUS; i++) {
			if (trace_files[i].fd > 0) {
				infds[j] = trace_files[i].fd;
				j++;
			}
		}
		incnt = j;
		for (i=j; i < MAXCPUS; i++) {
			infds[i] = 0;
		}

		mp.read_func = read_chunk;
		mp.num_sources = incnt;
		mp.src_data = infds;

		if (debug) printf ("calling liki_begin_merge()\n");
		liki_begin_merge(&mp);

		while ((ret = liki_next_merged_chunk(buf)) > 0) { /* ! EOF */

			/* Write out whole chunks despite there likely being unused bytes
			 * at the end to maintain alignment and whole block behavior. The
		 	 * exception is the final chunk, which we can identify because
		 	 * it will be a "sync" chunk.
		 	 */
			sz = (IS_SYNC_CHUNK(buf) ? ret : CHUNK_SIZE);

			if (write(outfd, buf, sz) != sz) {
				FATAL(errno, "Unable to write to file", outputfile, -1);
			}
		}

		if (ret < 0) {
			FATAL(1401, "Unable to merge next chunk", NULL, -1);
		}
	} else {
		fprintf (stderr, "kitracemerge cannot merge ki.bin files.   Suspect default tracing (ftrace) used\n");
		_exit(1);
	}

	close(outfd);

	for (i=0; i<incnt; i++)
		close(infds[i]);

	return 0;
}
