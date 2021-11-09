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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sem.h>
#include <sys/sysmacros.h>
/*
#include <linux/in.h>
#include <linux/in6.h>
*/
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <netdb.h>
#include <execinfo.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "hash.h"
#include "developers.h"
#include "info.h"
#include "futex.h"
#include "winki.h"
#include "Pdb.h"

void 
save_and_clear_server_stats(int nfiles) 
{
	int i;
	trace_info_t *trcinfop;

	if (is_alive) {
		if (kilive) {
			globals->total_buffers = 0;
			globals->total_events = 0;
			globals->missed_events = 0;
		}

		trcinfop = &trace_file_merged;
		globals->total_buffers += trcinfop->buffers;
		globals->total_events += trcinfop->events;
		globals->missed_events += trcinfop->missed_events;

		trcinfop->buffers = 0;
		trcinfop->events = 0;
		trcinfop->missed_buffers = 0;
		trcinfop->missed_events = 0;
/*
	        for (i=0; i < MAXCPUS; i++) {
			trcinfop = &trace_files[i];
			globals->missed_buffers += trcinfop->missed_buffers;
			globals->missed_events += trcinfop->missed_events;

			trcinfop->buffers = 0;
			trcinfop->events = 0;
			trcinfop->missed_buffers = 0;
			trcinfop->missed_events = 0;
	    	}
*/
	} else {
	    for (i=0; i < MAXCPUS; i++) {
		trcinfop = &trace_files[i];
		globals->total_buffers += trcinfop->buffers;
		globals->total_events += trcinfop->events;
		globals->missed_buffers += trcinfop->missed_buffers;
		globals->missed_events += trcinfop->missed_events;

		trcinfop->buffers = 0;
		trcinfop->events = 0;
		trcinfop->missed_buffers = 0;
		trcinfop->missed_events = 0;
	    }
	}
}

void 
print_cpu_buf_info() 
{
	int i;
	trace_info_t *trcinfop;

	if (IS_LIKI) {	
		printf ("Total Buffers: %d  Total Events processed: %d  Missed Events %d (%4.2f%%)\n", 
			globals->total_buffers, 
			globals->total_events,
			globals->missed_events,
			(globals->missed_events / ((globals->total_events + globals->missed_events) * 1.0)) * 100);
	} else {
		printf ("Total Buffers: %d  Total Events processed: %d  Missed Events %d (%4.2f%%)\n", 
			globals->total_buffers, 
			globals->total_events,
			globals->missed_buffers,
			(globals->missed_buffers / ((globals->missed_buffers + globals->total_buffers) * 1.0)) * 100);
	}
}

void
putstr(char **destp, char *strarg)
{
	FREE(*destp);
	if ((*destp = malloc((strlen(strarg)+5) & 0xfffffffc)) == NULL) {
		FATAL(errno, "malloc failure", NULL, -1);
	}
	MALLOC_LOG(*destp, (strlen(strarg)+5) & 0xfffffffc);
	
	strcpy (*destp, strarg);
}

void
repl_command(char **destp, char *cmd) 
{
	char *destcmd;

	if (*destp == NULL) {
		if ((*destp = malloc((strlen(cmd)+5) & 0xfffffffc)) == NULL) {
			FATAL(errno, "malloc failure", NULL, -1);
		}
		MALLOC_LOG(*destp, (strlen(cmd)+5) & 0xfffffffc);
		
		strcpy (*destp, cmd);
	} else if (strcmp (*destp, cmd)) {
		FREE(*destp);
		if ((*destp = malloc((strlen(cmd)+5) & 0xfffffffc)) == NULL) {
			FATAL(errno, "malloc failure", NULL, -1);
		}
		MALLOC_LOG(*destp, (strlen(cmd)+5) & 0xfffffffc);
               	strcpy (*destp, cmd);
	}
}

void
add_command(char **destp, char *cmd) 
{
	char *destcmd;
	char *ptr = cmd;

	if (*destp == NULL) {
		if (strlen(cmd) > 32) {
			/* for long command names, search for the last / */
			if (ptr = strrchr(cmd, '/')) {
				cmd = ptr + 1;
			}
		}

		if ((*destp = malloc((strlen(cmd)+5) & 0xfffffffc)) == NULL) {
			FATAL(errno, "malloc failure", NULL, -1);
		}
		MALLOC_LOG(*destp, (strlen(cmd)+5) & 0xfffffffc);
		strcpy (*destp, cmd);
	}
}

void
add_string(char **destp, char *src) 
{
	char *destcmd;

	if (*destp == NULL) {
		if ((*destp = malloc(strlen(src)+1)) == NULL) {
			FATAL(errno, "malloc failure", NULL, -1);
		}
		
		MALLOC_LOG(*destp, strlen(src)+1);
		strcpy (*destp, src);
	}
}

int
get_status_int(int pid, char *str)
{
	char	fname[80];
	FILE	*f;
	int	intval = 0;
	char 	*rtnptr;

	sprintf(fname, "/proc/%d/status", pid);
        if ((f = fopen(fname, "r")) == NULL) {
		return 0;
        }	

	rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		if ((strncmp(input_str, str, strlen(str))) == 0) {
			rtnptr += strlen(str);
			sscanf (rtnptr, "%d", &intval);
			break;
		}
		rtnptr = fgets((char *)&input_str, 127, f);
	}
	fclose(f);
	return intval;
}

int
get_pid_cgroup(void *arg1, void *arg2)
{
        pid_info_t *pidp = (pid_info_t *)arg1;
        FILE *f = NULL;
        char fname[30];
        uint64 id = 0;
        char *rtnptr;
        char *pos;
        dkpid_info_t *dkpidp = NULL;
        docker_info_t *dockerp = NULL;

	if (!is_alive || (pidp->PID <= 0)) return 0;

	if (pidp->tgid == 0) pidp->tgid = get_status_int(pidp->PID, "Tgid:");

	if (pidp->tgid == pidp->PID) {
        	sprintf(fname, "/proc/%d/cgroup", pidp->tgid);
	} else {
        	sprintf(fname, "/proc/%d/task/%d/cgroup", pidp->tgid, pidp->PID);
	}

        if ((f = fopen(fname, "r")) == NULL) {
                return 0;
        }

        rtnptr = fgets((char *)&input_str, 511, f);
        while (rtnptr != NULL) {

                /* so we need to see if the containerID is embedded in the string.
                 * The format may vary, however, so we need to be flexible with the search
                 *
                 * we will only look at the long strings and assume they are
                 * related to a containerID
                 */

                if ((id == 0) && (strlen(rtnptr) > 64)) {
                        /* for each container from docker ps output,
                         * let's see if there's a match.
                         */
                        if (id = get_container_id(rtnptr)) {
                                pidp = GET_PIDP(&globals->pid_hash, pidp->PID);
                                dockerp = GET_DOCKERP(&globals->docker_hash, id);
                                pidp->dockerp = dockerp;

                                dkpidp = GET_DKPIDP(&dockerp->dkpid_hash, pidp->PID);
                                dkpidp->dockerp = dockerp;
                                dkpidp->pidp = pidp;
                                /* fprintf (stderr, "PID: %d   id: %12llx name: %s\n", pid, id, dockerp->name); */
				break;
                        }
                }

                rtnptr = fgets((char *)&input_str, 511, f);
        }

        fclose(f);
        return 0;
}

int 
inherit_command(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	pid_info_t *tgidp;

	if ((pidp->cmd == NULL) && pidp->tgid && (pidp->tgid != pidp->PID)) {
		tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		if (tgidp->cmd) repl_command (&pidp->cmd, tgidp->cmd);
	}

	return 0;
}	
	

	
	

int 
get_command(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	int	fd;
	char	fname[80];
	char 	*start = NULL, *end = NULL;

	if (pidp->tgid == 0) pidp->tgid = get_status_int(pidp->PID, "Tgid:");

	sprintf(fname, "/proc/%ld/cmdline", pidp->tgid);
        if ((fd = open(fname, O_RDONLY)) <= 0) {
		return 0;
        }	
	if (get_fd_str(fd, input_str, 1) > 0 ) {
		add_command (&pidp->cmd, input_str);
	} else {
		/* process is likely a daemon, so read the stat file */
		close(fd);
		sprintf(fname, "/proc/%ld/stat", pidp->tgid);
        	if ((fd = open(fname, O_RDONLY)) <= 0) {
			return 0;
        	}	
		
		if (get_fd_str(fd, input_str, 1) > 0 ) {
			start = strchr(input_str, '(');
			end = strchr(input_str, ')');
	
			if (start && (start < end)) {	
				*start = '[';
				*end = ']';		
				*(end+1) = 0;
				add_command (&pidp->cmd, start);
			}
		}
	}	

	close(fd);
}


int
get_filename(void *arg1, void *arg2)
{
	fd_info_t *fdinfop = (fd_info_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	fdata_info_t *fdatap;
	char	fname[80];
	char	namestr[1024];
	int	ret;
	struct stat buf;

	if (!is_alive || fdinfop->fnamep) return 0;

	if (pidp->tgid == 0) pidp->tgid = get_status_int(pidp->PID, "Tgid:");

	/* fprintf (stderr, "get_filename: pidp: %p   fdinfop: %p\n", pidp, fdinfop); */
	sprintf(fname, "/proc/%ld/fd/%ld", pidp->tgid, fdinfop->FD);
	if ((ret=readlink(fname, namestr, 1024)) > 0) {
		namestr[ret] = 0;
		add_command(&fdinfop->fnamep, namestr);

	}

	if (fdinfop->fnamep && fdinfop->dev==0 && fdinfop->node==0) {
		if (stat(fdinfop->fnamep, &buf) == 0) {
			fdinfop->dev = mkdev(major(buf.st_dev), minor(buf.st_dev));
			fdinfop->node = buf.st_ino;

			fdatap = GET_FDATAP(&globals->fdata_hash, fdinfop->dev, fdinfop->node);
			if (fdatap->fnameptr == NULL) {
				fdatap->fnameptr = malloc(strlen(fdinfop->fnamep)+1);
				MALLOC_LOG(fdatap->fnameptr, strlen(fdinfop->fnamep)+1);
				if (fdatap->fnameptr) strcpy(fdatap->fnameptr, fdinfop->fnamep);
				fdatap->dev = fdinfop->dev;
				fdatap->node = fdinfop->node;
			}
		}
	}

	return 0;
}

int
get_pathname(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	int fd;
	char	path[80];
	char	linkstr[80];
	uint64	dev;
	ssize_t sz;
	char    *pos;
	int 	path1, path2, path3, path4;

	if (!is_alive)  return 0;
	
	dev = devinfop->lle.key;
	sprintf(path, "/sys/dev/block/%lld:%lld/device", dev_major(dev), lun(dev));
	sz = readlink(path, linkstr, 80);
	if (sz <= 0) return 0;
	if (sz > 79) return 0;

	linkstr[sz] = 0;
	pos = strrchr(linkstr, '/');
	pos++;
	
	sscanf (pos, "%d:%d:%d:%d", &path1, &path2, &path3, &path4);
	devinfop->devpath = FCPATH(path1, path2, path3, path4);
}
		
	

int
get_devname(void *arg1, void *arg2)
{
	dev_info_t *devinfop = (dev_info_t *)arg1;
	int	fd;
	char	fname[80];
	char 	*start = NULL, *end = NULL;
	uint64	dev;

	if (!is_alive)  return 0;
	
	dev = devinfop->lle.key;
	sprintf(fname, "/sys/dev/block/%lld:%lld/uevent", dev_major(dev), lun(dev));
        if ((fd = open(fname, O_RDONLY)) <= 0) {
		return 0;
        }	
		
	if (get_fd_str(fd, input_str, 1) > 0 ) {
		start = strstr(input_str, "DEVNAME=");
		if (start) { 
			start = start + 8;
			end = strstr(start, "\n");
		}
		if (start &&  (start < end)) {
			*end = 0;
			add_command(&devinfop->devname, start);

			/* if we have a mapper device, determine the mapper name */
			if (devinfop->devname == strstr(devinfop->devname, "dm-")) {
				close(fd);		
				sprintf(fname, "/sys/block/%s/dm/name", devinfop->devname);
        			if ((fd = open(fname, O_RDONLY)) <= 0) {
					return 0;
        			}	

				if (get_fd_str(fd, input_str, 1) > 0 ) {
					if (end = strstr(input_str, "\n")) *end = 0;
					add_command(&devinfop->mapname, input_str);
				}
			}
		}
	}
	close(fd);
}

uint64
get_devnum(char *devname)
{
	FILE *f = NULL;
	char	fname[80];
	uint64	dev = 0ull;
	char *rtnptr;
	int major, minor;

	if (!is_alive)  return 0;
	sprintf(fname, "/sys/block/%s/uevent", devname);
        if ((f = fopen(fname, "r")) == NULL) {
		return 0;
        }	

	rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		if (strstr(input_str, "MAJOR=")) {
			sscanf(input_str+6, "%d", &major);
		} else if (strstr(input_str, "MINOR=")) {
			sscanf(input_str+6, "%d", &minor);
		} else {
			break;
		}
	
		rtnptr = fgets((char *)&input_str, 127, f);
	}

	fclose(f);

	dev = mkdev(major, minor);
	return dev;
}

int
get_mpinfo(void *arg1, void *arg2)
{
	dev_info_t *mdevinfop = (dev_info_t *)arg1;
	dev_info_t *devinfop;
	uint64	mdev, dev;
	DIR *curdir;
	struct dirent *dent;
	char dirname[80];

	if (!is_alive)  return 0;

	mdev = mdevinfop->lle.key;
	sprintf(dirname, "/sys/dev/block/%lld:%lld/slaves", dev_major(mdev), lun(mdev));

	if ((curdir = opendir(dirname)) == NULL) {
		/* not a multipath device */
		return 0;
	}

	while (dent = readdir(curdir)) {
		if (strncmp(dent->d_name, ".", 1) == 0) continue;

		/* we just want the slave links */
		if (dent->d_type == DT_LNK) { 
			if (dev = get_devnum(dent->d_name)) {
				devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
				devinfop->mdevinfop = mdevinfop;
				devinfop->siblingp = mdevinfop->devlist;
				mdevinfop->devlist = devinfop;
			}
		} 
	}
	closedir(curdir);
}
		
int
get_devinfo(void *arg1, void *arg2)
{
	if (!is_alive) return 0;

	dev_info_t *devinfop = (dev_info_t *)arg1;
	get_devname(devinfop, arg2);
	get_pathname(devinfop, arg2);
	get_mpinfo(devinfop, arg2);
}

char kgdboc_value[128];
extern char *kgdboc_str;

void
clear_kgdboc() 
{
	int fd;

	kgdboc_str = NULL;
	/* first, save old value */
        if ((fd = open("/sys/module/kgdboc/parameters/kgdboc",  O_RDONLY)) <= 0) {
		return;
        }	

	/* if the file was not empty, then close it for read, then re-open and clear it */
	if (get_fd_str(fd, kgdboc_value, 1) > 0 ) {
		close(fd);
        	if ((fd = open("/sys/module/kgdboc/parameters/kgdboc",  O_WRONLY)) <= 0) {
			/* if we cannot clear the file, we must bail */
			perror ("Cannot open /sys/module/kgdboc/parameters/kgdoc");
			fprintf (stderr, "Exiting to avoid conflict with KGDB\n");
			_exit(101);
        	}	

		/* clear the kgdboc value and save the old value */
		if (put_fd_str(fd, " ", 0) < 0 ) {
			/* if we cannot clear the file, we must bail */
			perror ("Cannot clear /sys/module/kgdboc/parameters/kgdoc");
			fprintf (stderr, "Exiting to avoid conflict with KGDB\n");
			_exit(102);
		}
		kgdboc_str = &kgdboc_value[0];
	}

	close(fd);
}

void
reset_kgdboc()
{
	int fd;

	if (kgdboc_str == NULL) return;
       	if ((fd = open("/sys/module/kgdboc/parameters/kgdboc",  O_WRONLY)) <= 0) {
		/* if we cannot clear the file, we must bail */
		perror ("Cannot open /sys/module/kgdboc/parameters/kgdoc");
		fprintf (stderr, "KGDB will remain disabled\n");
		close(fd);
		return;
       	}	

	/* reset the kgdboc value to the old value */
	if (put_fd_str(fd, kgdboc_str, 0) < 0 ) {
		/* if we cannot clear the file, we must bail */
		perror ("Cannot write /sys/module/kgdboc/parameters/kgdoc");
		fprintf (stderr, "KGDB will remain disabled\n");
	}

	close(fd);
}

int 
add_warning(void **warnarray_addr, int *next_warningp, int warn_num, char *lnk) 
{
	warn_t *warnp;
	int current_warning = *next_warningp;

	warnp = (warn_t *)find_add_info((void **)warnarray_addr, sizeof(warn_t)*MAX_WARNINGS);

	warnp[current_warning].idx = warn_num;

	if (warn_num < MAXWARNMSG) {
		warnp[current_warning].type = WARN;
		warnp[current_warning].lnk = lnk;
	} else {
		warnp[current_warning].type = NOTE;
	}

	(*next_warningp)++;

	return current_warning;
}

char *
fmt_device(uint64 d)
{
   static char str[320];
   dev_t devno;

	devno = (dev_t)d;
	switch(devno) {
	case NO_DEV: return("NO_DEV");
	default:
  	    {
		sprintf(str,"%d/%#.6llx", (char)dev_major(d), lun(d));
		return(str);
	    }
	}
}

int check_filter(void *list, uint64 value)
{
	filter_item_t *fi;

	/* return TRUE if there is no filter */
	if (!filter_flag) return 1;

	/* if the value is in the specified filter list
	 * then return 1, and also return 1 if this filter
	 * list is empty 
	 *
	 * Only return 0 if there is a filter, but the 
	 * value is not found.
	 */
	if (fi = list) {
		while (fi) {
			if (fi->fi_item == value) {
				return 1;
			}
			fi = fi->fi_next;
		}
	}

	return 0;
}

char *
pstate(int f)
{
	static char str[320];

	str[0]=0;

	if (f & TASK_WAKING)  (void)strcat(str,"WAKING|"); 
	if (f & TASK_WAKEKILL)  (void)strcat(str,"WAKEKILL|"); 
	if (f & TASK_DEAD)  (void)strcat(str,"DEAD|"); 
	if (f & TASK_DEAD) (void)strcat(str,"DEAD|");
	if (f & EXIT_DEAD) (void)strcat(str,"EXIT|");
	if (f & EXIT_ZOMBIE) (void)strcat(str,"ZOMB|");
	if (f & TASK_TRACED) (void)strcat(str,"TRACED|");
	if (f & TASK_STOPPED) (void)strcat(str,"STOP|");
	if (f & TASK_UNINTERRUPTIBLE) (void)strcat(str,"SSLEEP");
	if (f & TASK_INTERRUPTIBLE) (void)strcat(str,"SLEEP");
	if (f == 0) (void)strcat(str,"RUN");
	
	return(str);
}	

#define MAX_IPC_CALLS	32 
#define IPC_CALL_MASK	(MAX_IPC_CALLS-1)
char *ipc_call_name[MAX_IPC_CALLS] = {
	"ukn-0",
	"SEMOP",
	"SEMGET",
	"SEMCTL",
	"SEMTIMEDOP",
	"ukn-5",
	"ukn-6",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"ukn-10",
	"MSGSND",
	"MSGRCV",
	"MSGGET",
	"MSGCTL",
	"ukn-15",
	"ukn-16",
	"ukn-17",
	"ukn-18",
	"ukn-19",
	"ukn-20",
	"SHMAT",
	"SHMDT",
	"SHMGET",
	"SHMCTL",
	"ukn-25",
	"ukn-26",
	"ukn-27",
	"ukn-28",
	"ukn-29",
	"ukn-30",
	"ukn-31"
};

char *
ipc_call_str(unsigned int f)
{
	unsigned int call_no = f & IPC_CALL_MASK;
	return ipc_call_name[call_no];
}

char *
semctl_cmd_str(unsigned int f)
{
	char *p;
	switch (f) {
		case(SETVAL) : p = "SETVAL"; break;
		case(SETALL) : p = "SETALL"; break;
		case(GETPID) : p = "GETPID"; break;
		case(GETVAL) : p = "GETVAL"; break;
		case(GETALL) : p = "GETALL"; break;
		case(GETNCNT) : p = "GETNCNT"; break;
		case(GETZCNT) : p = "GETZCNT"; break;
		default : p = NULL;
	}

	return p;
}


char *
futex_op_str(unsigned int f)
{
	static char str[10];
	unsigned int cmd = f & FUTEX_CMD_MASK;

	if (cmd > 12) {
		sprintf (str, "0x%llxd", f);
		return(str);
	}
	if (f & FUTEX_PRIVATE_FLAG) 
		return futex_privopcode_name[cmd];
	else
		return futex_opcode_name[cmd];
}

char *futex_wake_op[16] = {
	"FUTEX_OP_SET",
	"FUTEX_OP_ADD",
	"FUTEX_OP_OR",
	"FUTEX_OP_ANDN",
	"FUTEX_OP_XOR",
	"ukn-5",
	"ukn-6",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"ukn-10",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15"
};

char *futex_wake_cmp[16] = {
	"FUTEX_OP_CMP_EQ",
	"FUTEX_OP_CMP_NE",
	"FUTEX_OP_CMP_LT",
	"FUTEX_OP_CMP_LE",
	"FUTEX_OP_CMP_GT",
	"FUTEX_OP_CMP_GE",
	"ukn-6",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"ukn-10",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15"
};

char *
futex_val3_str(unsigned int f)
{
	unsigned int op = f >> 28;
	unsigned int cmp = (f >> 24) & 0xf;
	unsigned int oparg = (f >> 12) & 0xfff;
	unsigned int cmparg = f & 0xfff;

	printf (" op=%s cmp=%s oparg=%d cmparg=%d", futex_wake_op[op], futex_wake_cmp[cmp], oparg, cmparg);

	return NULL;
}

char *
fcntl_cmd_str(unsigned int f)
{
	char *str = util_str;
	str[0] = 0;

	if (f > 16) {
		sprintf (str, "%d", f);
		return(str);
	}
	return fcntl_cmd_name[f];
}

char *
mmap_prot_str(unsigned int f)
{
	char *str = util_str;
	str[0] = 0;

	if (f == 0) strcat(str, "NONE|");
	if (f & PROT_READ) strcat (str,"READ|");
	if (f & PROT_WRITE) strcat (str,"WRITE|");
	if (f & PROT_EXEC) strcat (str,"EXEC|");

	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf (str, "0x%llx", f);
	}
	return(str);
}

#ifndef MAP_32BIT
#define	MAP_32BIT 0x40  
#endif

char *
mmap_flags_str(unsigned int f)
{
	char *str = util_str;
	str[0] = 0;

	if (f & MAP_SHARED) strcat (str, "SHARED|");
	if (f & MAP_PRIVATE) strcat (str, "PRIVATE|");
	if (f & MAP_32BIT) strcat (str, "32BIT|");
	if (f & MAP_ANONYMOUS) strcat (str, "ANON|");
	if (f & MAP_DENYWRITE) strcat (str, "DENYWRITE|");
	if (f & MAP_EXECUTABLE) strcat (str, "EXEC|");
	if (f & MAP_FILE) strcat (str, "FILE|");
	if (f & MAP_FIXED) strcat (str, "FIXED|");
	if (f & MAP_GROWSDOWN) strcat (str, "GROWSDOWN|");
#ifdef MAP_HUGETLB
	if (f & MAP_HUGETLB) strcat (str, "HUGETLB|");
#endif
	if (f & MAP_LOCKED) strcat (str, "LOCKED|");
	if (f & MAP_NONBLOCK) strcat (str, "NONBLOCK|");
	if (f & MAP_NORESERVE) strcat (str, "NORESERVE|");
	if (f & MAP_POPULATE) strcat (str, "POPULATE|");
	if (f & MAP_STACK) strcat (str, "STACK|");

	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf (str, "0x%llx", f);
	}
	return(str);
}	

char *
shm_flags_str(unsigned int f)
{
	char *str = util_str;
	str[0] = 0;
	unsigned int  mode = f & 0x1ff;
	

	if (f & IPC_CREAT) strcat (str, "CREAT|");
	if (f & IPC_EXCL) strcat (str, "EXCL|");
	if (f & SHM_HUGETLB) strcat (str, "HUGETLB|");
	if (f & SHM_NORESERVE) strcat (str, "NORESERVE|");

	if (mode & S_IRUSR) strcat (str, "r"); else strcat (str, "-");
	if (mode & S_IWUSR) strcat (str, "w"); else strcat (str, "-");
	if (mode & S_IXUSR) strcat (str, "x"); else strcat (str, "-");
	if (mode & S_IRGRP) strcat (str, "r"); else strcat (str, "-");
	if (mode & S_IWGRP) strcat (str, "w"); else strcat (str, "-");
	if (mode & S_IXGRP) strcat (str, "x"); else strcat (str, "-");
	if (mode & S_IROTH) strcat (str, "r"); else strcat (str, "-");
	if (mode & S_IWOTH) strcat (str, "w"); else strcat (str, "-");
	if (mode & S_IXOTH) strcat (str, "x"); else strcat (str, "-");
	
	return(str);
}	

char *
open_flags_str(unsigned int f)
{
	char *str = util_str;
	str[0] = 0;

	if ((f & O_ACCMODE) == O_RDONLY) strcat(str, "RDONLY|");
	if ((f & O_ACCMODE) ==  O_WRONLY) strcat (str, "WRONLY|");
	if ((f & O_ACCMODE) == O_RDWR) strcat (str, "RDWR|");
	if (f & O_CREAT) strcat (str, "CREAT|");
	if (f & O_APPEND) strcat (str, "APPEND|");
	if (f & O_TRUNC) strcat (str, "TRUNC|");
	if (f & O_ASYNC) strcat (str, "ASYNC|");
	if (f & O_DSYNC) strcat (str, "DSYNC|");
	if (f & O_SYNC) strcat (str, "SYNC|");
	if (f & O_DIRECT) strcat (str, "DIRECT|");
	if (f & O_LARGEFILE) strcat (str, "LARGEFILE|");
	if (f & O_EXCL) strcat (str, "EXCL|");
	if (f & O_CLOEXEC) strcat (str, "CLOEXEC|");
	if (f & O_NOATIME) strcat (str, "NOATIME|");
	if (f & O_DIRECTORY) strcat (str, "DIRECTORY|");
	if (f & O_NOFOLLOW) strcat (str, "NOFOLLOW|");
	if (f & O_NOCTTY) strcat (str, "NOCTTY|");
	if (f & O_NONBLOCK) strcat (str, "NONBLOCK|");

	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf (str, "0x%llx", f);
	}
	return(str);
}	

void
set_ioflags()
{

	/* the rq_flag_bits changed all the time, so this is a bit of a pain.   So after calling
 	 * parse_uname, we need to set the io_flags and such
  	 */
	globals->req_op_mask = 0x1;
	globals->req_op_shift = 0;
	globals->cmd_flag_mask = 0xfffffffffffffffe;
	globals->cmd_flag_shift = 1;
	globals->req_op = req_op_name_2;

	if (IS_WINKI) return;
	if (!IS_LIKI || (globals->os_vers[0] == '2')) {
		/* For Ftrace, just use the version 2.6.32 flags */
		if (strncmp(globals->os_vers, "2.6.36", 6) == 0) {
			globals->io_flags = ioflags_name_2_6_36;
			globals->sync_bit = 1 << 5;
		} else if ((strncmp(globals->os_vers, "2.6.37", 6) == 0) ||
		         (strncmp(globals->os_vers, "2.6.38", 6) == 0)) {
			globals->io_flags = ioflags_name_2_6_37;
			globals->sync_bit = 1 << 4;
		} else if (strncmp(globals->os_vers, "2.6.39", 6) == 0) {
			globals->io_flags = ioflags_name_2_6_39;
			globals->sync_bit = 1 << 4;
		} else {
			globals->io_flags = ioflags_name_2;
			globals->sync_bit = 1 << 18;
		}
	} else if ((strncmp(globals->os_vers, "3.0.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.1.", 4) == 0)) {
		globals->io_flags = ioflags_name_3_0;
		globals->sync_bit = 1 << 4;
	} else if ((strncmp(globals->os_vers, "3.2.", 4) == 0) || 
		  (strncmp(globals->os_vers, "3.3.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.4.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.5.", 4) == 0)) {
		globals->io_flags = ioflags_name_3_2;
		globals->sync_bit = 1 << 4;
	} else if ((strncmp(globals->os_vers, "3.6.", 4) == 0) || 
		  (strncmp(globals->os_vers, "3.7.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.8.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.9.", 4) == 0) ||
		  (strncmp(globals->os_vers, "3.10.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.11.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.12.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.13.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.14.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.15.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.16.", 5) == 0) ||
		  (strncmp(globals->os_vers, "3.17.", 5) == 0)) {
		globals->io_flags = ioflags_name_3_6;
		globals->sync_bit = 1 << 4;
	} else if ((strncmp(globals->os_vers, "3.18.", 5) == 0) || 
		  (strncmp(globals->os_vers, "3.19.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.0.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.1.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.2.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.3.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.4.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.5.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.6.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.7.", 4) == 0)) {
		globals->io_flags = ioflags_name_4;
		globals->sync_bit = 1 << 4;
	} else if ((strncmp(globals->os_vers, "4.8.", 4) == 0) || 
		  (strncmp(globals->os_vers, "4.9.", 4) == 0)) {
		globals->io_flags = ioflags_name_4_8;
		globals->sync_bit = 1 << 3;
		globals->req_op_mask = 0xe000000000000000;
		globals->req_op_shift = 61;
		globals->cmd_flag_mask = 0x1fffffffffffffff;
		globals->cmd_flag_shift = 0;
		globals->req_op = req_op_name_4_8;
	} else if ((strncmp(globals->os_vers, "4.10.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.11.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.12.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.13.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.14.", 5) == 0)) {
		globals->io_flags = ioflags_name_4_10;
		globals->req_op = req_op_name_4_10;
		globals->sync_bit = 1 << 11;
		globals->req_op_mask = 0xff;
		globals->req_op_shift = 0;
		globals->cmd_flag_mask = 0xffffffffffffff00;
		globals->cmd_flag_shift = 8;
	} else { 
		/* 4.13 through 4.16 as of 04/20/2018 */
		globals->io_flags = ioflags_name_4_15;
		globals->req_op = req_op_name_4_10;
		globals->sync_bit = 1 << 11;
		globals->req_op_mask = 0xff;
		globals->req_op_shift = 0;
		globals->cmd_flag_mask = 0xffffffffffffff00;
		globals->cmd_flag_shift = 8;
	}
}


int
reqop(uint64 f)
{
	char *str = util_str;
	int op;

	op = (f & globals->req_op_mask) >> globals->req_op_shift;
	return op;
}

char *
reqop_name(uint64 f)
{
	char *str = util_str;
	int op;

	op = (f & globals->req_op_mask) >> globals->req_op_shift;
	if (op < 36) return globals->req_op[op];
	return "ukn";
}
	
char *
ioflags(uint64 f) 
{
	char *str = util_str;
	str[0] = 0;
	int i;
	int op;
	uint64 cmd_flags;

	cmd_flags = (f & globals->cmd_flag_mask) >> globals->cmd_flag_shift;

	for (i = 0; i < REQ_NRBIT; i++) {   	
		if ((cmd_flags & (1 << i)) && globals->io_flags[i]) {
			strcat(str, globals->io_flags[i]);
			strcat(str, "|");
		}
	}

	/* take off the last "|" character */
	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf(str, "0x%x", cmd_flags);
	}

	return(str);
}

int
flush_flag(uint64 f) 
{
	int i;
	uint64 cmd_flags;

	cmd_flags = (f & globals->cmd_flag_mask) >> globals->cmd_flag_shift;

	for (i = 0; i < REQ_NRBIT; i++) {   	
		if (globals->io_flags[i] == NULL) continue;
		if ((cmd_flags & (1 << i)) && 
		    ((strcmp(globals->io_flags[i],"FLUSH") == 0) ||
		    (strcmp(globals->io_flags[i],"SYNC") == 0))) {
			 return 1;
		}
	}

	return 0;
}





void
set_gfpflags()
{
	if (IS_WINKI) return;
	if ((globals->os_vers[0] == '2') || (globals->os_vers[0] == '3')) {
		globals->gfp_flags = gfp_name_3_0;
	} else if ((strncmp(globals->os_vers, "4.0.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.1.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.2.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.3.", 4) == 0)) {
		globals->gfp_flags = gfp_name_4_0;
	} else if ((strncmp(globals->os_vers, "4.4.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.5.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.6.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.7.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.8.", 4) == 0) ||
		  (strncmp(globals->os_vers, "4.9.", 4) == 0)) {
		globals->gfp_flags = gfp_name_4_4;
	} else if ((strncmp(globals->os_vers, "4.10.", 5) == 0) || 
		  (strncmp(globals->os_vers, "4.11.", 5) == 0) ||
		  (strncmp(globals->os_vers, "4.12.", 5) == 0)) {
		globals->gfp_flags = gfp_name_4_10;
	} else {
		/* 4.13 through 4.16 as of 04/20/2018 */
		globals->gfp_flags = gfp_name_4_13;
	}

}

char *
gfp_flags_str(unsigned int f)
{
	char *str = util_str;
	int i;
	str[0] = 0;

	for (i = 0; i < GFP_NRBIT; i++) {   	
		if ((f & (1 << i)) && globals->gfp_flags[i]) {
			strcat(str, globals->gfp_flags[i]);
			strcat(str, "|");
		}
	}

	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf (str, "0x%llx", f);
	}
	return(str);
}	

#define SOCK_DOM_MASK 0x3f
#define SOCK_DOM_MAX 64
char *sock_domains[SOCK_DOM_MAX] = {
	"AF_UNSPEC",
	"AF_UNIX",
	"AF_INET",
	"AF_AX25",
	"AF_IPX",
	"AF_APPLETALK",
	"AF_NETROM",
	"AF_BRIDGE",
	"AF_ATMPVC",
	"AF_X25",
	"AF_INET6",
	"AF_ROSE",
	"AF_DECnet",
	"AF_NETBEUI",
	"AF_SECURITY",
	"AF_KEY",
	"AF_NETLINK",
	"AF_PACKET",
	"AF_ASH",
	"AF_ECONET",
	"AF_ATMSVC",
	"AF_RDS",
	"AF_SNA",
	"AF_IRDA",
	"AF_PPPOX",
	"AF_WANPIPE",
	"AF_LLC",
	"ukn-27",
	"ukn-28",
	"AF_CAN",
	"AF_TIPC",
	"AF_BLUETOOTH",
	"AF_IUCV",
	"AF_RXRPC",
	"AF_ISDN",
	"AF_PHONET",
	"AF_IEEE802154",
	"AF_CAIF",
	"AF_ALG",
	"ukn-40",
	"ukn-41",
	"ukn-42",
	"ukn-43",
	"ukn-44",
	"ukn-45",
	"ukn-46",
	"ukn-47",
	"ukn-48",
	"ukn-49",
	"ukn-50",
	"ukn-51",
	"ukn-52",
	"ukn-53",
	"ukn-54",
	"ukn-55",
	"ukn-56",
	"ukn-57",
	"ukn-58",
	"ukn-59",
	"ukn-60",
	"ukn-61",
	"ukn-62",
	"ukn-63"
};

char *
sock_dom_str(unsigned int f)
{
	unsigned int domain = f & SOCK_DOM_MASK;
	return sock_domains[domain];
}

#define SOCK_TYPE_MASK 0xf
#define SOCK_MAX 16
char *sock_types[SOCK_MAX] = {
	"ukn-0",
	"STREAM",
	"DGRAM",
	"RAW",
	"RDM",
	"SEQPACKET",
	"DCCP",
	"ukn-7",
	"ukn-8",
	"ukn-9",
	"SOCK_PACKET",
	"ukn-11",
	"ukn-12",
	"ukn-13",
	"ukn-14",
	"ukn-15"
};

char *
sock_type_str(unsigned int f)
{
	unsigned int flags = f & SOCK_TYPE_MASK;
	return sock_types[flags];
}

#define SIGNUM_MAX	64
#define SIGNUM_MASK	(SIGNUM_MAX -1)
char *signal_name[SIGNUM_MAX] = {
	"unk-0",
	"SIGHUP",
	"SIGINT",
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT",
	"SIGBUS",
	"SIGFPE",
	"SIGKILL",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGSTKFLT",
	"SIGCHLD",
	"SIGCONT",
	"SIGSTOP",
	"SIGTSTP",
	"SIGTTIN",
	"SIGTTOU",
	"SIGURG",
	"SIGXCPU",
	"SIGXRSZ",
	"SIGVTALRM",
	"SIGPROF",
	"SIGWINCH",
	"SIGIO",
	"SIGPWR",
	"SIGSYS",
	"ukn-32",
	"ukn-33"
	"ukn-34",
	"ukn-35",
	"ukn-36",
	"ukn-37",
	"ukn-38",
	"ukn-39",
	"ukn-40",
	"ukn-41",
	"ukn-42",
	"ukn-43",
	"ukn-44"
	"ukn-45",
	"ukn-46",
	"ukn-47",
	"ukn-48",
	"ukn-49",
	"ukn-50",
	"ukn-51",
	"ukn-52",
	"ukn-53",
	"ukn-54"
	"ukn-55",
	"ukn-56",
	"ukn-57",
	"ukn-58",
	"ukn-59",
	"ukn-60",
	"ukn-61",
	"ukn-62",
	"ukn-63"
};

char *
signal_str(unsigned int f)
{
	unsigned int signo = f & SIGNUM_MASK;
	return signal_name[signo];
}

#define SIGHOW_MAX	4
#define SIGHOW_MASK	(SIGHOW_MAX - 1)
char *sighow_name[SIGHOW_MAX] = {
	"BLOCK",
	"UNBLOCK",
	"SETMASK",
	"ukn-3"
};

char *
sighow_str(unsigned int f)
{
	unsigned int sighow = f & SIGHOW_MASK;
	return sighow_name[sighow];
}

#define WHENCE_MAX	4
#define WHENCE_MASK	(WHENCE_MAX - 1)
char *whence_name[WHENCE_MAX] = {
	"SEEK_SET",
	"SEEK_CUR",
	"SEEK_END",
	"ukn-3"
};

char *
whence_str(unsigned int f)
{
	unsigned int whence = f & WHENCE_MASK;
	return whence_name[whence];
}

enum x86_pf_error_code {
        PF_PROT         =               1 << 0,
        PF_WRITE        =               1 << 1,
        PF_USER         =               1 << 2,
        PF_RSVD         =               1 << 3,
        PF_INSTR        =               1 << 4,
};

char *
flt_err_codes(unsigned int f)
{
	static char str[40];
	str[0] = 0;

	if (f & PF_PROT) strcat(str,"PFAULT|"); else strcat(str,"VFAULT|");
	if (f & PF_WRITE) strcat(str,"WRITE|");  else strcat(str,"READ|");
	if (f & PF_USER) strcat(str,"USER|"); else strcat(str,"KERNEL|");
	if (f & PF_RSVD) strcat(str,"RSVD|");
	if (f & PF_INSTR) strcat(str,"INSTR|"); else strcat(str,"DATA|");
	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		strcat(str, "n/a");
	}
	
	return(str);
}

int
csv_printf(FILE *file, const char *format, ...)
{
	va_list ap;

	if ((hthr == 0) && file)  {
		va_start(ap, format);
		vfprintf(file, format, ap);
	}
	
	return 0;
}


int
pid_printf(FILE *pidfile, const char *format, ...)
{
	va_list ap;

	if (hthr == 0) {	
		va_start(ap, format);
		vprintf(format, ap);
	}
	if (pidfile)  {
		va_start(ap, format);
		vfprintf(pidfile, format, ap);
	}
	
	return 0;
}

int
dock_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	if (dockfile)  {
		va_start(ap, format);
		vfprintf(dockfile, format, ap);
	}
	
	return 0;
}

int
json_printf(FILE *file, const char *format, ...)
{
        va_list ap;

        if (file)  {
                va_start(ap, format);
                vfprintf(file, format, ap);
        }

        return 0;
}



/* 
 * findsym_idx
 * searches symtable to find symbol name
 * This search is a modified b-tree search
 */

int
findsym_idx(uint64 addr) {
	int low = 0;
	int high = globals->nsyms;
	int mid; 

	if (globals->nsyms == 0) return 0;

	while (1) {
		/* for now, use a binary search algorithm */
		if ((high - low) <= 1) {
			return low;
		}

		mid = (high + low) / 2; 
		if (addr < globals->symtable[mid].addr) {
			high = mid;
		} else {
			low = mid;
		}
	}
}	
/* 
 * findsym
 * searches symtable to find symbol name
 * This search is a modified b-tree search
 */

char *
findsym(uint64 addr) {
	int low = 0;
	int high = globals->nsyms;
	int mid;

	/* printf ("findsym() - nsym: %d   addr: 0x%llx\n", globals->nsyms, addr); */
	if (globals->nsyms == 0) return NULL;
	while (1) {
		/* for now, use a binary search algorithm */
		if ((high - low) <= 1) {
			return globals->symtable[low].nameptr;	
		}

		mid = (high + low) / 2; 
		if (addr < globals->symtable[mid].addr) {
			high = mid;
		} else {
			low = mid;
		}
	}
}	

void
print_sym_offset(uint64 addr) {
        int idx;
        uint64 offset;

        idx = findsym_idx(addr);
        offset = addr - globals->symtable[idx].addr;
        if ((idx > 0) && (idx < globals->nsyms-1) && (offset < 0x10000)) {
                printf (" %s+0x%lx",  globals->symtable[idx].nameptr, addr - globals->symtable[idx].addr);
         } else {
                printf (" 0x%lx", addr);
         }
}


void
print_kernel_sym(unsigned long addr, char print_offset)
{
	int idx = 0;
	uint64 offset = 0ull;

	if (globals->nsyms) {
		idx = findsym_idx(addr);
		offset = addr - globals->symtable[idx].addr;
	}

	if ((idx > 0) && (idx < globals->nsyms-1)) {
		if (print_offset) {
        		printf ("%s%s+0x%llx",  globals->symtable[idx].nameptr,
				globals->symtable[idx].module ? globals->symtable[idx].module : "",
				addr - globals->symtable[idx].addr);
		} else {
			printf ("%s%s", globals->symtable[idx].nameptr,
				globals->symtable[idx].module ? globals->symtable[idx].module : ""); 
		}
	} else {
		printf ("%p", addr);
	}
	return;
}

char *
dmangle(char *sym)
{
	int i;
	int len_pos, name_pos, util_pos;
	int len;
	int ret;

	if (mangle_flag || (strncmp(sym, "_Z", 2))) {
		/* doesn't need to be demangled */
		return sym;
	} else {
		i = 2;	
	}

	/* Locate the first "N" after the _Z */
	while (i < strlen(sym)) { 
		if (sym[i] == 'N') {
			i++;
			break;
		} else {
			i++;
		}
	}

	/* if we didn't find the first "N", then reset i to 2 */
        if (i >= strlen(sym)) i = 2;

	/* we need to find the first number after _Z and the first character after 
	 * the number.
	 */

	util_str[0] = 0;
	util_pos = 0;
	/* we will allow _nested_ symbols, so we loop here */
	while (sym[i] != 0) {
		len_pos = 0;
		name_pos = 0;
		len = 0;
		/* skip ofter any alpha characters to find the function length */
		while (sym[i] != 0) {
			if (isalpha(sym[i]) || (sym[i] == '_')) { 
				i++;
				continue;
			} else if (isdigit(sym[i])) { 
				len_pos = i;
				break;
			} else {
				/* unexpected symbol,  return original sym */
				return sym;
			}
		}

		while (sym[i] != 0) {
			if (isdigit(sym[i])) {
				i++;
				continue;
			} else if (isalpha(sym[i]) || (sym[i] == '_')) {
				name_pos = i;
				break;
			} else {
				/* unexpected symbol,  return original sym */
				return sym;
			}
		}

		if ((name_pos == 0) || (len_pos == 0)) return sym;	

		if (sscanf (&sym[len_pos], "%d", &len))  {
			strncpy (&util_str[util_pos], &sym[name_pos], len);
			i= i+len;
			if (isdigit(sym[i])) {
				util_str[util_pos+len] = ':';
				util_str[util_pos+len+1] = ':';
				util_pos = util_pos+len+2;
				continue;
			} else {
				util_str[util_pos+len] = 0;
				break;
			}
		} else {
			return sym;
		}
	}

	if ((name_pos == 0) || (len_pos == 0)) 
		return sym;	
	else 
		return (util_str);
	
	/* we should not get here, but if we do just return what was passed in */

}	

/* we only return a value of 1 if maplookup is called
 * the .map stacks don't follow normal procedure calling
 * conventions, so we want to signal to the upper layers to
 * stop the stacktrace */
int
print_user_sym(unsigned long ip, uint64 pid, char print_objfile)
{
	uint64 offset;
	char *sym, *fptr, *old_fptr = NULL;
	vtxt_preg_t *pregp;
	pid_info_t *pidp;

	if (ip == 0x0) return 0;

	if (objfile_preg.elfp && (ip < 0x10000000)) { 
		if (sym = symlookup(&objfile_preg, ip, &offset)) {
			if (print_objfile) {
				printf ("%s+0x%llx [%s]", dmangle(sym), offset, objfile);
			} else {
				printf ("%s+0x%llx", dmangle(sym), offset);
			}
		} else if (sym = maplookup(pidp->mapinfop, ip, &offset)) {
			printf ("%s+0x%llx", dmangle(sym), offset);
			return 1;
		} else {
			printf ("0x%llx", ip);
		}
	} else {
		pidp = GET_PIDP(&globals->pid_hash, pid);

		/* if mulithreaded, then we must use the tgid pid */
		if (pidp->tgid && (pidp->PID != pidp->tgid)) {
			pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		}

		if (pregp = find_vtext_preg(pidp->vtxt_pregp, ip)) {
			if ((pregp->filename) && print_objfile) {
				fptr = strrchr (pregp->filename, '/');
				if (fptr)  {
					fptr = fptr+1;
				} else  {
					fptr = pregp->filename;
				}
				if (fptr != old_fptr) printf (" [%s]:", fptr);
				old_fptr = fptr;
			}

			if (sym = symlookup(pregp, ip, &offset)) {
				printf ("%s+0x%llx", dmangle(sym), offset);
			} else if (sym = maplookup(pidp->mapinfop, ip, &offset)) {
				printf ("%s+0x%llx", dmangle(sym), offset);
				return 1;
			} else {
				printf ("0x%llx", ip);
			}
		} else if (sym = maplookup(pidp->mapinfop, ip, &offset)) {
			printf ("%s+0x%llx", dmangle(sym), offset);
			return 1;
		} else {
			printf ("0x%llx", ip);
		}
	}
	return 0;
}

void
print_stacktrace_hex(unsigned long *stktrc, uint64 depth)
{
        int i;
	uint64 argval;
	int idx;
	uint64 offset;

        printf (" HEXTRACE:");
        for (i=0; i < depth; i++) {
		printf (" 0x%llx", stktrc[i]);
	}

        return;
}


void
print_stacktrace(unsigned long *stktrc, unsigned long depth, int start, uint64 pid)
{
        int i;
	uint64 argval;
	int idx;
	int is_user = 0;

	/* print_stacktrace_hex (stktrc, depth); */

	if (depth == 0) return;

       	for (i=0; i < depth; i++) {
		switch (stktrc[i]) {
			case END_STACK: continue;
			case STACK_CONTEXT_KERNEL:     is_user = 0; continue;
			case STACK_CONTEXT_USER:      
				if (i > 0) printf ("%c|", fsep);
				is_user = 1; 
				continue;
		}

		if (i < start) continue;

		printf ("%c", fsep);
		if (is_user) {
			if (print_user_sym(stktrc[i], pid, 1))
				break;
		} else {
			print_kernel_sym(stktrc[i], 1);	
		}
	}

        return;
}


int stack_switch_start = 0;

int 
find_switch_start(uint64 *stack, uint64 depth)
{
	int i;
	char *symptr;
	int retval=1;


	if (globals->nsyms==0) return 0;
	if (depth == 0) return 0;
	if (stack[0] != STACK_CONTEXT_KERNEL) {
		/* we should find the KERNEL CONTEXT marker for a switch record */
		return 0;
	}
	
	for (i=1; i < depth; i++) { 
		if (STACK_CONTEXT(stack[i])) {
			/* stop at next CONTEXT marker, if we get this far
			 * then we did not find a switch overhead func 
			 */
			break;
		}
	
		symptr = findsym(stack[i]);
		
		if (symptr)  {
			if (strncmp(symptr, "thread_return", 13) == 0)  retval=i+1;				/* for RHEL 6 */
                	else if ((strlen(symptr) == 10) && (strncmp(symptr, "__schedule", 10) == 0))  retval= i+1;   /* for SUSE 11 */
                	else if ((strlen(symptr) == 8) && (strncmp(symptr, "schedule", 8) == 0))  retval= i+1;       /* for RHEL 7 */
                	/* else if ((strlen(symptr) == 11) && (strncmp(symptr, "io_schedule", 11) == 0))  retval= i+1;        for RHEL 7 */
                	else if (strncmp(symptr, "wait_for_common", 15) == 0)  retval= i+1; 
                	else if (strncmp(symptr, "schedule_timeout", 16) == 0)  retval= i+1;
                	else if (strncmp(symptr, "schedule_hrtimeout", 18) == 0)  retval= i+1;
                	else if (strncmp(symptr, "schedule_preempt_disabled", 25) == 0)  retval= i+1;		/* for Ubuntu 12.10 */
                	else if (strncmp(symptr, "_cond_resched", 13) == 0)  retval= i+1;		/* for Ubuntu 12.10 */
                	else if (strncmp(symptr, "__cond_resched", 14) == 0)  retval= i+1;		/* for Ubuntu 12.10 */
			else if (strncmp(symptr, "sched_switch_trace", 18) == 0) retval= i+1;
			else if (strncmp(symptr, "pick_next_task_fair", 19) == 0) retval= i+1;
			else if (strncmp(symptr, "__sched_text_start", 18) == 0) retval= i+1;		/* ARM64, l4tm */
			else continue;
		}
        }
        return retval;
}

/* Save just the kernel portion of the stack */
uint64 
save_kernel_stack(uint64 *dest, uint64 *src, uint64 depth) 
{
	uint64 i;

	for (i = 0; i < depth && i < LEGACY_STACK_DEPTH; i++) { 
		if (STACK_CONTEXT(src[i])) {
			/* stop at next CONTEXT marker */
			break;
		}

		dest[i] = src[i];
	}

	return i;	
}

/* Save entire stack */
uint64 
save_entire_stack(uint64 *dest, uint64 *src, uint64 depth)
{
	uint64 i, j;

	for (i = 0, j=0; i < depth && j < LEGACY_STACK_DEPTH; i++) { 
		dest[j] = src[i];
		j++;
	}

	return j;	
}

int
is_idle_pc(uint64 pc)
{
	char *symptr;

	if (STACK_CONTEXT(pc)) return 0;

	symptr = findsym(pc);
	if (symptr == NULL) return 0;

	if (strstr(symptr, "_idle"))  return 1;
	if (strstr(symptr, "native_safe_halt")) return 1;
	if (strstr(symptr, "tick_nohz_"))  return 1;
	return 0;
}
	

/*
 * convert_pc_to_key()
 */
uint64 convert_pc_to_key(uint64 pc)
{
        uint64 key=0, offset=0;
	int idx;

	/* do not convert the CONTEXT markers */	
	if (STACK_CONTEXT(pc)) return pc;

	if (globals->symtable == NULL) return UNKNOWN_SYMIDX;
	idx = findsym_idx(pc);	
        offset = pc - globals->symtable[idx].addr;
        if ((idx > 0) && (idx < globals->nsyms-1) && (offset < 0x10000)) {
                return idx;
        } else {	
		return pc;
        }
}


void
hex_dump(void *arg, int lines)
{
        unsigned int *ptr = (unsigned int *)arg;
        int i, j;

        for (j=0; j<lines; j++) {
                printf ("0x%lx: ", (uint64)ptr);
                for (i=0; i<8; i++) {
                        printf ("0x%08x ", *ptr);
                        ptr++;
                }
                printf ("\n");
        }
}

void
hex_dump_stderr(void *p, int len)
{
        unsigned int *ptr, *end;
        int i;

        ptr = (unsigned int *)p;
        end = (unsigned int *)((char *)p + len);
        while (ptr < end) {
                fprintf (stderr, "0x%llx: ", ptr);
                for (i = 0; i<8; i++) {
                        fprintf (stderr, "0x%08x ", *ptr);
                        ptr++;
                }
                fprintf (stderr, "\n");
        }
}


int
incr_trc_stats(void *arg1, void *arg2)
{
        common_t *rec_ptr = (common_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	trc_info_t *trcp;
        cpu_info_t      *cpuinfop;
        uint64          pid, id, cpu;
        uint64          key;

        pid = rec_ptr->pid;
        id = rec_ptr->id;
        cpu = rec_ptr->cpu;

        key = TRC_KEY(0ul, 0ul, id, 0ul);

        if (kparse_flag) {
                trcp = GET_TRCP(&globals->trc_hash, key);
                trcp->count++;
                globals->total_traces++;
        }

        /* now log per-pid trc info */
        if (perpid_stats && pidp) {
                pidp->num_tr_recs++;

                trcp = GET_TRCP(&pidp->trc_hash, key);
                trcp->count++;
        }
	return 0;
}

FILE *
open_csv_file(char *subtool, int addtimestamp) 
{
	FILE *csvfile = NULL;
	char fname[30];

	/* if they are using the kitrace flag, then don't create a CSV report 
	/* however, if the csv flag is used, the KI ASCII data will be printed as 
	/* a csv 
 	*/
	/* if (kitrace_flag) return NULL; */

        if (csv_flag) {
                if (timestamp && addtimestamp) {
                        sprintf (fname, "%s.%s.csv", subtool, timestamp);
                } else {
                        sprintf (fname, "%s.csv", subtool);
                }
                if ((csvfile = fopen(fname, "w")) == NULL) {
                        fprintf (stderr, "Unable to open CSV file %s, errno %d\n", fname, errno);
                        fprintf (stderr, "  Continuing without CSV output\n");
			return NULL;
                }
        }

	return csvfile;
}


void
close_csv_file(FILE *csvfile)
{
        if (csv_flag) {
		if (csvfile) fclose(csvfile);
	}
	csvfile = NULL;

	return;
}

void
bt()
{
#define SIZE	40
	int j, nptrs;
	void *buffer[SIZE];
	char **strings;

	nptrs = backtrace(buffer, SIZE);
	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

        for (j = 0; j < nptrs; j++)
               printf("%s\n", strings[j]);

        FREE(strings);
}

int
for_each_file(char *dir, char *expr1, char *expr2, uint64 traverse)
{
	DIR *curdir;
	struct dirent *dent;
	server_info_t *servinfop;
	char fname[256];

	if (debug) printf ("for_each_file(): %s %s traverse %d\n", expr1, expr2, traverse);

	if ((curdir = opendir(dir)) == NULL) {
		if (traverse == 0) {
			perror ("opendir() failed");
			fprintf (stderr, "Unable to open cwd %s (errno %d)\n", dir, errno);
		}
		return 0;
	}

	while (dent = readdir(curdir)) {
		if (strncmp(dent->d_name, ".", 1) == 0) continue;

		if ((dent->d_type == DT_REG) || (dent->d_type == DT_UNKNOWN) || (dent->d_type == DT_LNK)) { 
			if (strstr(dent->d_name, expr1) && strstr(dent->d_name, expr2)) {
				/* check for match first */
				servinfop = GET_SERVER(server[nservers]);
				servinfop->server_id = nservers;
				putstr(&servinfop->subdir, dir);
				nservers++;
				/* if we find one ki.bin file, we stop looking in this subdir */
				return 0;
			}
		} 

		if ((dent->d_type == DT_DIR) || (dent->d_type == DT_UNKNOWN)) {
			sprintf (fname, "%s/%s", dir, dent->d_name);
			if (traverse) for_each_file(fname, expr1, expr2, traverse);
		}
	}
	closedir(curdir);

	return 0; 
}

void 
print_ip_port (void *arg1, int be2le, FILE *pidfile)
{
	struct sockaddr_in *sock = (struct sockaddr_in *)arg1;
	uint64 key;
	uint32 port;
	char host[64], serv[64];
	int i;

	/*
	if (getnameinfo((struct sockaddr *)sock, sizeof(struct sockaddr_in), 
	    host, 64, serv, 64, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		pid_printf (pidfile, "%s:%s", host, serv);
		return;
	}
	*/

	port = be2le ? BE2LE(sock->sin_port) : sock->sin_port;
	key = SOCK_KEY(sock->sin_addr.s_addr, port);
	pid_printf (pidfile, "%u.%u.%u.%u",
		SOCK_IP1(key),
		SOCK_IP2(key),
		SOCK_IP3(key),
		SOCK_IP4(key));
	if (port) pid_printf (pidfile, ":%d", SOCK_PORT(key));
}

void
print_ip_v6 (void *arg1, FILE *pidfile)
{
	unsigned char *s6addr8 = (char *)arg1;
	uint16 *s6addr16 = (uint16 *)arg1;
	int i;
	char skip = TRUE;

	i = 0;
	while (i < 8) {
		/* skip leading zeros */
		if (s6addr16[i] == 0) skip=FALSE;
		if (s6addr16[i]) break;
		i++;
	}

	if (i == 8) {
		/* if addr is empty, then just print the port num and return */
		pid_printf (pidfile, "[::]");
		return;
	}

	if ((i == 6) || ((i == 5) && (s6addr16[i] == 0xffff))) {
		/* if first 5 elements are zero, and 6th is 0xffff, assume an IPv4 addr */
		pid_printf (pidfile, "%u.%u.%u.%u", 
			s6addr8[12],
			s6addr8[13],
			s6addr8[14],
			s6addr8[15]);
		return;
	}

	pid_printf (pidfile, "[");
	if (skip == FALSE) pid_printf (pidfile, "::");
	/* print the first element */
	pid_printf (pidfile, "%x", s6addr16[i]);
	i++;

	while (i < 8) {
	  	if (skip && s6addr16[i] == 0) {
			while (i < 8) {
				if (s6addr16[i] == 0) {
					i++;
				} else {
					pid_printf (pidfile, ":");
					skip = FALSE;
					break;
				}
			}
		}	
		
		if (i < 8) {
			pid_printf (pidfile, ":%x", s6addr16[i]);
			i++;
		}
	}
	pid_printf (pidfile, "]");
}

void 
print_ip_port_v6 (void *arg1, int be2le, FILE *pidfile)
{
	struct sockaddr_in6 *sock = (struct sockaddr_in6 *)arg1;
	uint32 port;
	int i;
	char skip = TRUE;  	/* can we skip any values */
	char host[64], serv[64];

	/* for debugging 
  		for (i=0; i < 16; i++) {
		printf ("%2hhu ", sock->sin6_addr.s6_addr[i]);
	}
	*/

#if 0
	/* this does not work like I hoped it would!
	if (getnameinfo((struct sockaddr *)sock, sizeof(struct sockaddr_in6), 
	    host, 64, serv, 64, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		pid_printf (pidfile, "%s:%s", host, serv);
		return;
	}
	*/
#endif

	port = be2le ? BE2LE(sock->sin6_port) : sock->sin6_port;

	print_ip_v6((void *)&sock->sin6_addr.s6_addr16[0], pidfile);

	if (port) pid_printf (pidfile, ":%d", port);
}

void 
printstr_ip_port_v6 (char *ipstr, void *arg1, int be2le)
{
	struct sockaddr_in6 *sock = (struct sockaddr_in6 *)arg1;
	uint32 port;
	int i;
	char skip = TRUE;  	/* can we skip any values */
	char tmpstr[80];
	char host[64], serv[64];

/*
	if (getnameinfo((struct sockaddr *)sock, sizeof(struct sockaddr_in6), 
	    host, 64, serv, 64, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		sprintf(tmpstr, "%s:%s", host, serv);
		return;
	}	
*/

	ipstr[0] = 0;
	port = be2le ? BE2LE(sock->sin6_port) : sock->sin6_port;
	i = 0;
	while (i < 8) {
		/* skip leading zeros */
		if (sock->sin6_addr.s6_addr16[i] == 0) skip=FALSE;
		if (sock->sin6_addr.s6_addr16[i]) break;
		i++;
	}
	
	if (i == 8) {
		/* if addr is empty, then just print the port num and return */
		strcat(ipstr, "[::]");
		if (port) {
			sprintf(tmpstr, ":%d", port);
			strcat(ipstr, tmpstr);
		}
		return;
	}

	if ((i == 6) || ((i == 5) && (sock->sin6_addr.s6_addr16[i] == 0xffff))) {
		/* if first 5 elements are zero, and 6th is 0xffff, assume an IPv4 addr */
		sprintf(tmpstr, "%u.%u.%u.%u", 
			sock->sin6_addr.s6_addr[12],
			sock->sin6_addr.s6_addr[13],
			sock->sin6_addr.s6_addr[14],
			sock->sin6_addr.s6_addr[15]);
		strcat(ipstr, tmpstr);
		if (port) {
			sprintf(tmpstr, ":%d", port);
			strcat(ipstr, tmpstr); 
		}
		return;
	}

	strcat(ipstr, "["); 
	if (skip == FALSE) strcat (ipstr, "::");
	/* print the first element */
	sprintf(tmpstr, "%x", BE2LE(sock->sin6_addr.s6_addr16[i]));
	strcat(ipstr, tmpstr); 
	i++;

	while (i < 8) {
	  	if (skip && sock->sin6_addr.s6_addr16[i] == 0) {
			while (i < 8) {
				if (sock->sin6_addr.s6_addr16[i] == 0) {
					i++;
				} else {
					strcat(ipstr, ":");
					skip = FALSE;
					break;
				}
			}
		}	
		
		if (i < 8) {
			sprintf(tmpstr, ":%x", BE2LE(sock->sin6_addr.s6_addr16[i]));
			strcat(ipstr, tmpstr); 
			i++;
		}
	}
	strcat(ipstr, "]");
	if (port) {
		sprintf(tmpstr, ":%d", port);
		strcat(ipstr, tmpstr);
	}
}

void
cp_sockaddr (void **ptraddr, void *srcptr)
{
	struct sockaddr_in6 *dstptr = (struct sockaddr_in6 *)*ptraddr;
	/* if the socket address is non-zero, skip it and return */
	if (srcptr == NULL) return;
	if (dstptr) return;

	/* Now allocate it and copy the data from the srcptr */
	if (dstptr == NULL) {
		if (dstptr = calloc(1, sizeof(struct sockaddr_in6))) {
			CALLOC_LOG(lsock, 1, sizeof(struct sockaddr_in6));
		} else {
			return;
		}
	}

	memcpy(dstptr, srcptr, sizeof(struct sockaddr_in6));
	*ptraddr = dstptr;
	return;
}
		
void
cp_sockip (void **ptraddr, void *srcptr)
{
	struct sockaddr_in6 *dstptr = (struct sockaddr_in6 *)*ptraddr;
	/* if the socket address is non-zero, skip it and return */
	if (srcptr == NULL) return;
	if (dstptr) return;

	/* Now allocate it and copy the data from the srcptr */
	if (dstptr == NULL) {
		if (dstptr = calloc(1, sizeof(struct sockaddr_in6))) {
			CALLOC_LOG(lsock, 1, sizeof(struct sockaddr_in6));
		} else {
			return;
		}
	}

	memcpy(dstptr, srcptr, sizeof(struct sockaddr_in6));
	dstptr->sin6_port = 0;
	*ptraddr = dstptr;
	return;
}



uint64
pathname_key(char *str)
{
	int i;
	uint64 key=0, len=0;
	uint64 cksum1=0, cksum2=0, cksum3=0, cksum4=0;

	len=strlen(str);
	
	for (i=0; i<len; i++) {
		cksum1 += str[i];
	}
	cksum1 += len;

	for (i=0; i<len-3; i+=3) {
		cksum2 += str[i];
		cksum3 += str[i+1];
		cksum4 += str[i+2];
	}
	
	key = cksum1 | (cksum2 & 0xffff) <<16 | (cksum3 & 0xffff)  << 32 | (cksum4 & 0xffff) << 48;

	return key;
}

void
syscallname_to_syscallno(char *name, int *syscallno32, int *syscallno64)
{
	int i, j;

	*syscallno32 = -2;
	*syscallno64 = -2;

	for (i = 0; i < KI_MAXSYSCALLS; i++) {
		if (strcmp(syscall_arg_list[i].name, name) == 0) {
			if (arch_flag == AARCH64) {
				for (j = 0; j < MAX_SYSCALL_IDX; j++) {
					if (i == syscall_index_aarch_64[j]) {
						*syscallno32 = j;
						*syscallno64 = j;
						break;
					}
				}
			} else {
				for (j = 0; j < MAX_SYSCALL_IDX; j++) {
					if (i == syscall_index_x86_32[j]) {
						*syscallno32 = j;
						break;
					}
				}
			
				for (j = 0; j < MAX_SYSCALL_IDX; j++) {
					if (i == syscall_index_x86_64[j]) {
						*syscallno64 = j;
						break;
					}
				}
			}

			break;
		}
	}
}

int
push_win_syscall(void *arg1, uint64 addr, uint64 hrtime)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	win_syscall_save_t *entry, *next; 

	next = pidp->win_active_syscalls;

	if ((entry = (win_syscall_save_t *)malloc(sizeof(win_syscall_save_t))) == NULL) {
		FATAL(errno, "malloc failure", NULL, -1);
	}

	entry->addr = addr;
	entry->starttime = hrtime;
	entry->next = next;

	pidp->win_active_syscalls = entry;

	return 1;
}

int 
pop_win_syscall(void *arg1, uint64 *addr, uint64 *hrtime)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	win_syscall_save_t *entry;

	if ((entry = (win_syscall_save_t *)pidp->win_active_syscalls) == NULL) {
		*addr = 0;
		*hrtime = 0;
		return 0;
	}

	*addr = entry->addr;
	*hrtime = entry->starttime;
	pidp->win_active_syscalls = entry->next;

	FREE(entry);

	/* I have had problams with the nested system calls.   So here, let's drain the pipe
	 * and make sure that the syscall stack is empty 
	 */

	while ((entry = (win_syscall_save_t *)pidp->win_active_syscalls) != NULL) {
		pidp->win_active_syscalls = entry->next;
		FREE(entry);
	}

	return 1;
}

void
winki_save_stktrc (void *arg0, void *arg1, void *arg2)
{
	trace_info_t *trcinfop = (trace_info_t *)arg0;
	StackWalk_t *stk = (StackWalk_t *)arg1;
	winki_stack_info_t *stkinfop = (winki_stack_info_t *)arg2;
	int i=0, j=0;
	trace_info_t trcinfop_save;

	/* first, we have to save the current contents of the trcinfop so it can be 
	   restored after grabbing the stack */
	memcpy(&trcinfop_save, trcinfop, sizeof(trace_info_t));

	while (stk && (stk != (StackWalk_t *)GETNEWBUF) && (stk->EventType == 0x1820) && (j < WINKI_MAX_DEPTH)) {
		get_next_event_for_cpu(trcinfop);
		i = 0;
		while (&stk->Stack[i] < (uint64 *)((uint64)trcinfop->cur_event + get_event_len((event_t *)trcinfop->cur_event)) && (j < WINKI_MAX_DEPTH)) {
			stkinfop->Stack[j] = stk->Stack[i];
			j++;
			i++;
		}

		if (trcinfop->next_event == (char *)GETNEWBUF) {
			get_new_buffer(trcinfop, trcinfop->cpu);
		}
		stk = (StackWalk_t *)trcinfop->next_event;
	}

	stkinfop->depth = j;

	/* now restore the contents of the trcinfop */
	memcpy(trcinfop, &trcinfop_save, sizeof(trace_info_t));

}

void
update_pid_ids(int tid, int pid)
{
	pid_info_t *pidp;
	pid_info_t *tgidp;

	if (pid) tgidp = GET_PIDP(&globals->pid_hash, pid);
	if (tid) {
		pidp = GET_PIDP(&globals->pid_hash, tid);
	pidp->tgid = pid;
	}
}

char *
irqflags(uint32 f) 
{
	char *str = util_str;
	str[0] = 0;
	int i;
	int op;

	for (i = 0; i < IRQ_NRBIT; i++) {   	
		if (f & (1 << i)) {
			strcat(str, win_irq_flags[i]);
			strcat(str, "|");
		}
	}

	/* take off the last "|" character */
	if (strlen(str)) {
		str[strlen(str)-1] = 0;
	} else {
		sprintf(str, "0x%x", f);
	}

	return(str);
}

