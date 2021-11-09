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
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <linux/kdev_t.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "globals.h"
#include "info.h"
#include "html.h"
#include "oracle.h"
#include "hash.h"
#include "kd_types.h"

extern struct utsname  utsname;

int pc_sleep_on_page = -1;
int pc_migration_entry_wait = -1;
int pc_msleep = -1;
int pc_ixgbe_read_i2c_byte_generic = -1;
int pc_semctl = -1;
int pc_semtimedop = -1;
int pc_mutex_lock = -1;
int pc_xfs_file_aio_read = -1;
int pc_xfs_file_read_iter = -1;
int pc_inode_dio_wait = -1;
int pc_xfs_file_dio_aio_write = -1;
int pc_md_flush_request = -1;
int pc_blkdev_issue_flush = -1;
int pc_hugetlb_fault = -1;
int pc_huge_pmd_share = -1;
int pc_SYSC_semtimedop = -1;
int pc_queued_spin_lock_slowpath = -1;
int pc_rwsem_down_write_failed = -1;
int pc_mutex_lock_slowpath = -1;
int pc_kstat_irqs_usr = -1;
int pc_pcc_cpufreq_target = -1;
int pc_kvm_mmu_page_fault = -1;


void
parse_uname(char print_flag)
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	char *tmpptr;
	char os[32], hostname[128], vers[128];

	if (is_alive) {
		globals->os_vers = utsname.release;
		if (tmpptr = strstr(utsname.nodename, ".")) *tmpptr = 0;
		globals->hostname = utsname.nodename;
        } else {
		sprintf (fname, "uname-a.%s", timestamp);
                if ((f = fopen(fname, "r")) == NULL) { 
			if (debug) fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                        return;
                }

                while (rtnptr = fgets((char*)&input_str, 511, f)) {
                        if (print_flag) { BOLD("%s\n", input_str); }
			
			sscanf(input_str, "%s %s %s\n", 
			os,
			hostname, 
			vers);

			if (tmpptr = strstr(hostname, ".")) *tmpptr = 0;
			putstr (&globals->hostname, hostname);
			putstr (&globals->os_vers, vers);

			if (strstr(input_str, "aarch64")) {
				arch_flag = AARCH64;
			} else if (strstr(input_str, "ppc64le")) {
				arch_flag = PPC64LE;
			}
                }

		fclose(f);
        }

}

void 
parse_mem_info()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	char varname[30];
	int node;
	ldom_info_t *ldominfop;
	uint64 node_mem, node_free, node_used, node_shmem, node_thp, node_hp, node_hp_free;
	char kb1[16], kb2[16], kb3[16], kb4[16], kb5[16], kb6[16];


	if (is_alive) {
		sprintf(fname, "/proc/meminfo");
	} else {
		sprintf(fname, "mem_info.%s", timestamp);
	}

	if ( (f = fopen(fname,"r")) == NULL) {
		fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
		fprintf (stderr, "Continuing without memory info.\n");
		return;
	}

	rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		node = -1;
		if ((strncmp(input_str, "Mem:", 4) == 0) || (strncmp(input_str, "MemTotal:", 9) == 0)) {
			sscanf (input_str,"%s %lld", varname, &globals->memkb);
		}

		if (strncmp(input_str, "Node_", 5) == 0) {
			sscanf(input_str+5, "%d %lld%s %lld%s %11d%s", 
				&node, &node_mem, kb1, 
				&node_free, kb2, 
				&node_used, kb3);

			if (node >= 0) {
				ldominfop = GET_LDOMP(&globals->ldom_hash, node);
				ldominfop->memkb = node_mem;
				ldominfop->freekb = node_free;
				ldominfop->usedkb = node_used;
			}
		}

		rtnptr = fgets((char *)&input_str, 127, f);
	}
}

/* parse_lsof */
void
parse_lsof()
{
	FILE *lsof = NULL;
	char fname[30];
	char *rtnptr;
	int i, ret, nitems;
	int pid, fd, major, minor, node, type, family;
	uint64 device;
	pid_info_t *pidp;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	fd_info_t *fdinfop;
	char arg1[32], arg3[128], arg4[128], arg5[128], arg6[128], arg7[128], arg8[128], arg9[256], arg10[256];
	char *userstr, *fdstr, *typestr, *devstr, *sizestr, *nodestr, *namestr;
	int words;
	char *tmp;
	long int tid;
	struct sockaddr_in6 *lsock = NULL, *rsock = NULL;

	if (debug) fprintf (stderr, "parse_lsof()\n");

	if (timestamp == NULL) return;

	sprintf (fname, "lsof.%s", timestamp);
        if ( (lsof = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "  Continuing without file names\n");
                return;
        }

	/* skip the first line */
	rtnptr = fgets((char *)&input_str, 511, lsof);
	while (rtnptr != NULL) {
		lsock = NULL;
		rsock = NULL;
		rtnptr = fgets((char *)&input_str, 511, lsof);
		if (rtnptr == NULL) 
			/* stop if at the end of the file */
			break;

		if (strstr(input_str, " unknown ")) continue;

		sscanf(input_str, "%s %d %s %s %s %s %s %s %s %s\n", 
			arg1,
			&pid,
			arg3,
			arg4,
			arg5, 
			arg6,
			arg7,
			arg8,
			arg9, 
			arg10);

		pidp = GET_PIDP(&globals->pid_hash, pid);

		tid = 0; 
		if (isdigit(arg3[0]))  {
			tid = strtol(arg3, NULL, 10);
			fdstr = arg5;
			typestr = arg6;
			devstr = arg7;
			sizestr = arg8;
			nodestr = arg9;
			namestr = arg10;
		} else {
			fdstr = arg4;
			typestr = arg5;
			devstr = arg6;
			sizestr = arg7;
			nodestr = arg8;
			namestr = arg9;
		}

		if (tid) {
			pidp = GET_PIDP(&globals->pid_hash, tid);
		}	

		/* the arch_flag is a temporary workaround du to lsof changes */
		if ((pidp->syscall_index == NULL) && arch_flag) {
			pidp->syscall_index = globals->syscall_index_64;
			pidp->elf = ELF64;
		}

		if (pidp->syscall_index == NULL) {
				pidp->syscall_index = globals->syscall_index_32;
				pidp->elf = ELF32;
		}

		if (strstr(fdstr, "DEL")) continue;
		if (strstr(fdstr, "unknown")) continue;

		if (strstr(fdstr, "mem")) { 
			if (strstr(input_str, "/lib64/") || strstr(input_str, "/lib/x86_64")) {
				pidp->syscall_index = globals->syscall_index_64;
				pidp->elf = ELF64;
			}
			continue;
		}

		if (sscanf(fdstr, "%d", &fd) == 0) continue;
	
		type =0;
		for (i=0; i < F_TYPES; i++) {
			if (strcmp(typestr, ftype_name_index[i]) == 0) {
				type = i;
				break;
			}
		}

		if (type == F_unix) {
			sscanf (devstr, "%0llx", &device);
			major = minor = 0;
		} else if ((type==F_IPv4) || (type==F_IPv6)) {
			sscanf (devstr, "%lld", &device);
		} else if (type==F_netlink) {
			device = 0;
			if (tid) {
				sizestr = arg7;
				nodestr = arg8;
				namestr = arg9;
			} else {
				sizestr = arg6;
				nodestr = arg7;
				namestr = arg8;
			}
		} else {
			sscanf (devstr, "%d,%d", &major, &minor);
			device = mkdev(major,minor);
		}

		if ((type == F_IPv6) || (type==F_IPv4)) {
			node = 0;
			if (type == F_IPv4) family=AF_INET;
			else family=AF_INET6;

			if (strstr(nodestr, "TCP")) {
				node = TCP_NODE;	
				if (tmp = strstr(input_str, " TCP ")) {
					namestr = tmp+5;
					if (tmp = strchr (namestr, '\n')) tmp[0] = 0;
				}
			} else if (strstr(nodestr, "UDP")) {
				node = UDP_NODE;
				if (tmp = strstr(input_str, " UDP ")) {
					namestr = tmp+5;
					if (tmp = strchr (namestr, '\n')) tmp[0] = 0;
				}
			} else {
				node = UNKNOWN_NODE;
			}
		} else {
			sscanf (nodestr, "%d", &node);
		}

		if (strstr(namestr, "(ESTABLISHED)")) { 
			int l1, l2, l3, l4, r1, r2, r3, r4;
			int lp, rp;
			
			nitems = sscanf(namestr, "%d.%d.%d.%d:%d->%d.%d.%d.%d:%d\n", 
				&l1, &l2, &l3, &l4, &lp, &r1, &r2, &r3, &r4, &rp);
	
			if (nitems == 10) {
				/* printf ("%s L=%d.%d.%d.%d:%d R=%d.%d.%d.%d:%d\n", namestr, 
					l1, l2, l3, l4, lp, r1, r2, r3, r4, rp); */

				if (rsock = calloc(1, sizeof(struct sockaddr_in6))) {
					CALLOC_LOG(rsock, 1, sizeof(struct sockaddr_in6));
					if (lsock = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(lsock, 1, sizeof(struct sockaddr_in6));
						char *raddr, *laddr;
						rsock->sin6_port = rp;	
						rsock->sin6_family=family;
						lsock->sin6_addr.s6_addr16[5] = 0xffff;
						raddr = (char *)&rsock->sin6_addr.s6_addr[12];
						raddr[0] = r1;
						raddr[1] = r2;
						raddr[2] = r3;
						raddr[3] = r4;
						lsock->sin6_port=lp;
						lsock->sin6_family=family;
						lsock->sin6_addr.s6_addr16[5] = 0xffff;
						laddr = (char *)&lsock->sin6_addr.s6_addr[12];
						laddr[0] = l1;
						laddr[1] = l2;
						laddr[2] = l3;
						laddr[3] = l4;
					} else {
						FREE(rsock);
						rsock=NULL;
						lsock=NULL;
					}
				}
			}
		} else if (node == UDP_NODE) {
			/* for UDP, there is only a single IP address */
			int l1, l2, l3, l4, lp;
			
			nitems = sscanf(namestr, "%d.%d.%d.%d:%d\n", 
				&l1, &l2, &l3, &l4, &lp);

			if (nitems == 5) {
				if (lsock = calloc(1, sizeof(struct sockaddr_in6))) {
					CALLOC_LOG(lsock, 1, sizeof(struct sockaddr_in6));
					if (rsock = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(rsock, 1, sizeof(struct sockaddr_in6));
						char *raddr, *laddr;
						lsock->sin6_port=lp;
						lsock->sin6_addr.s6_addr16[5] = 0xffff;
						laddr = (char *)&lsock->sin6_addr.s6_addr[12];
						laddr[0] = l1;
						laddr[1] = l2;
						laddr[2] = l3;
						laddr[3] = l4;
						rsock->sin6_port = 0;	
						rsock->sin6_family=0;
						rsock->sin6_addr.s6_addr16[5] = 0;
						raddr = (char *)&rsock->sin6_addr.s6_addr[12];
						raddr[0] = 0;
						raddr[1] = 0;
						raddr[2] = 0;
						raddr[3] = 0;
					} else {
						FREE(lsock);
						lsock=NULL;
						rsock=NULL;
					}
				}
			}
		}

		if (lsock && rsock) {
			sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(lsock), SIN_PORT(lsock), SIN_ADDR(rsock), SIN_PORT(rsock)); 
			sdatap->node = node;
			sdatap->type = type;
			cp_sockaddr (&sdatap->laddr, lsock);
			cp_sockaddr (&sdatap->raddr, rsock);
			if (sdatap->fnameptr == NULL) {
				if ((sdatap->fnameptr = malloc(strlen(namestr)+1)) == NULL) {
					FATAL(errno, "malloc() of fname failed", NULL, -1);
				}
				MALLOC_LOG(sdatap->fnameptr, strlen(namestr)+1);
				strcpy ((char *)sdatap->fnameptr, namestr);
			}
		} else {
			fdatap = GET_FDATAP(&globals->fdata_hash, device, node);
			if (fdatap->ftype == 0) {
				fdatap->dev = device;
				fdatap->ftype = type;
				fdatap->node = node;
				if (fdatap->fnameptr == NULL) {
					if ((fdatap->fnameptr = malloc(strlen(namestr)+1)) == NULL) {
						FATAL(errno, "malloc() of fname failed", NULL, -1);
					}
					MALLOC_LOG(fdatap->fnameptr, strlen(namestr)+1);
					strcpy ((char *)fdatap->fnameptr, namestr);
				}
			}
		}

		fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
		fdinfop->dev = device;
		fdinfop->ftype = type;
		fdinfop->node = node;
		fdinfop->rsock=rsock;
		fdinfop->lsock=lsock;
		if (fdinfop->fnamep == NULL) {
			if ((fdinfop->fnamep = malloc(strlen(namestr)+1)) == NULL) {
				FATAL(errno, "malloc() of fname failed", NULL, -1);
			}
			MALLOC_LOG(fdinfop->fnamep, strlen(namestr)+1);
			strcpy ((char *)fdinfop->fnamep, namestr);
		}

		/* if (debug)fprintf (stderr, "PID: %d  FD: %d Type: %s  device: 0x%llx  [%d,%d] node: %d name:%s lsock:0x%llx rsock:0x%llx\n", 
  				pid, fd, ftype_name_index[type], fdinfop->dev, major, minor, fdinfop->node, namestr, lsock, rsock);  
		*/

	}
	fclose(lsof);
}

int 
parse_cpulist()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr, *p, *pos;
	int 	MHz;

	if (is_alive) {
		return 0;
	} else {
		sprintf (fname, "cpulist.%s", timestamp);
	}

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without NODE reporting (all CPUs will be considered to be in NODE 0)\n");
                return 0;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL)  {
			/* stop if at the end of the file */
			break;
		}
		if (p = strstr(input_str, "GenuineIntel")) {
			pos = p+13;
			sscanf (pos, "%d\n", &MHz);

			globals->clk_mhz = MHz * 1.0;
		}
	}



}


/* parse_cpuinfo */
void
parse_cpuinfo()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr, *pos;
	int i, j;
	cpu_info_t *cpuinfop, *cpu1infop, *cpu2infop;
	pcpu_info_t *pcpuinfop;
	int	cpu, node, physid = -1;
	int	prev_node = -1;
	float   ghz;

	if (is_alive) {
		sprintf (fname, "/proc/cpuinfo");
	} else {
		sprintf (fname, "cpuinfo.%s", timestamp);
	}

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without NODE reporting (all CPUs will be considered to be in NODE 0)\n");
                return;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL)  {
			/* stop if at the end of the file */
			break;
		}

		if (strncmp(input_str, "processor", 9) == 0) {
			pos = strchr(input_str, ':') + 1;
			sscanf (pos, "%d\n", &cpu);

			cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
			cpuinfop->cpu = cpu;
			globals->nlcpu++;
		}

		if (strncmp(input_str, "core id", 7) == 0) {
			if (cpuinfop == NULL)  {
				printf ("NULL cpuinfop in parse_cpuinfo()\n");
				exit (1);
			}
			pos = strchr(input_str, ':') + 1;
			sscanf (pos, "%d\n", &physid);

			cpuinfop->physid = physid;
		}

		if (strncmp(input_str, "physical id", 11) == 0) { 
			if (cpuinfop == NULL)  {
				printf ("NULL cpuinfop in parse_cpuinfo()\n");
				exit (1);
			}
			pos = strchr(input_str, ':') + 1;
			sscanf (pos, "%d\n", &node);
			if (debug) fprintf (stderr, "processor: %3d    physical_id: %3d    core_id: %3d\n", cpu, physid, node);

			/* override node assignment if VM_guest */
			if (globals->VM_guest) node=0;

			cpuinfop->ldom = node;
			if (node > prev_node) {  
				/* this assume node1 will come before node1 in the cpuinfo file */
				globals->nldom++;
				prev_node = node;
			}
		}

		/* while this isn't set for the first CPU, it should be OK as the first CPU
		 * should have a node of 0 
		 */
		if (strncmp(input_str, "flags", 5) == 0) { 
			if (strstr(input_str, "hypervisor")) {
				globals->VM_guest=TRUE;
			}
		}

		if (strstr(input_str, "model name")) { 
			pos = strrchr(input_str, ' ');
			if (pos && strstr(pos, "GHz")) {
				 sscanf (pos+1, "%f\n", &ghz);
				 globals->clk_mhz = ghz*1000.0;
			}
		}

	}
	fclose(f);

	/* now check to see if we have any HT CPUs, which should have matching physical IDs and nodes */
	/* if physid == -1, then we have a Virtual machine, so not HT */
	if (!globals->VM_guest && (physid != -1)) {
	    for (i=1; i < MAXCPUS; i++) {
	        if (cpu2infop = FIND_CPUP(globals->cpu_hash, i)) { 
		    /* now scan entries backworks looking for a match */
		    for (j=i-1; j >=0; j--) {
	    	        if (cpu1infop = FIND_CPUP(globals->cpu_hash, j)) { 
			    if ((cpu2infop->ldom == cpu1infop->ldom) && (cpu2infop->physid == cpu1infop->physid)) {
				/* we have a match! Note that cpu J will be the lowest numbered CPU */
				globals->ncpu++;
				globals->HT_enabled = TRUE;

				cpu2infop->lcpu_sibling = j;
				cpu2infop->cpu_attr = LCPU;
				cpu2infop->pcpu_idx = j;
				cpu2infop->lcpu_state = LCPU_UNKNOWN;

				cpu1infop->lcpu_sibling = i;
				cpu1infop->cpu_attr = LCPU;
				cpu1infop->pcpu_idx = j;
				cpu1infop->lcpu_state = LCPU_UNKNOWN;
			
				pcpuinfop = GET_PCPUP(&globals->pcpu_hash, j);
				pcpuinfop->lcpu1 = j;
				pcpuinfop->lcpu2 = i;
				pcpuinfop->last_time = 0;	
			    }
			}
		    }
		}
	    }
	} else {
	    globals->VM_guest = TRUE;
	}

	if (globals->ncpu == 0) globals->ncpu = globals->nlcpu;
	if (globals->nldom == 1) globals->nldom = 0;              /* only one node? Then no nodes */
}
	

/* parse_cpumaps */
void
parse_cpumaps()
{
	FILE *f = NULL;
	char fname[64];
	char *rtnptr, *pos;
	int i, n, lcpu, ldom, nldom, nlcpu, nitems;
	unsigned int cpumask;
	cpu_info_t *cpuinfop;
	int item[64];

	if (!is_alive) {
		return;
	}
	
	if (debug) printf ("parse_cpumaps()\n");

	for (ldom=0; ldom < MAXLDOMS; ldom++) {
		sprintf (fname, "/sys/devices/system/node/node%d/cpumap", ldom);
        	if ( (f = fopen(fname,"r")) == NULL) {
                	break;
        	}

		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) break;

		nitems = sscanf (rtnptr, "%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", 
			&item[0], &item[1], &item[2], &item[3], &item[4], &item[5], &item[6], &item[7],
			&item[8], &item[9], &item[10], &item[11], &item[12], &item[13], &item[14], &item[15],
			&item[16], &item[17], &item[18], &item[19], &item[20], &item[21], &item[22], &item[23],
			&item[24], &item[25], &item[26], &item[27], &item[28], &item[29], &item[30], &item[31],
			&item[32], &item[33], &item[34], &item[35], &item[36], &item[37], &item[38], &item[39],
			&item[40], &item[41], &item[42], &item[43], &item[44], &item[45], &item[46], &item[47],
			&item[48], &item[49], &item[50], &item[51], &item[52], &item[53], &item[54], &item[55],
			&item[56], &item[57], &item[58], &item[59], &item[60], &item[61], &item[62], &item[63]);
			
		lcpu=0;
		for (n = nitems-1; n >= 0; n--) {
			cpumask=item[n];
			for (i = 0; i < 32; i++, lcpu++) {
				if (lcpu >= globals->nlcpu) break;
				if (cpumask & (1<<i)) {
					/* CPU is enabled for this node */
					cpuinfop = GET_CPUP(&globals->cpu_hash, lcpu);
					cpuinfop->ldom = ldom;
					cpuinfop->cpu = lcpu;
				}
			}
		}

		
	}

	if ((ldom > 0) && (ldom != globals->nldom)) {
		globals->nldom = ldom;
		globals->SNC_enabled = TRUE;
	}
}




/* parse_mpsched */
/* Normally, we use cpuinfo for ldom assignments, but this is for Sub-Numa Clustering (SNC) */
/* This should be called after parse_cpuinfo() */
void
parse_mpsched()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	int i, ret;
	cpu_info_t *cpuinfop;
	int cpu[96], ldom, nlcpu;
	short nitems, nldom;
	char parse_start = FALSE;

	if (is_alive) return;

	sprintf (fname, "mpsched.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without NODE reporting (all CPUs will be considered to be in NODE 0)\n");
                return;
        }

	nldom=0;
	nlcpu=0;
	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL)  {
			/* stop if at the end of the file */
			break;
		}
		
		
		if (strstr(input_str, "----")) { 
			parse_start = TRUE;
			continue;
		}

		if (!parse_start) continue;
		
		nitems = sscanf (input_str, "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d", 
			&ldom, 
			&cpu[0], &cpu[1], &cpu[2], &cpu[3], &cpu[4], &cpu[5], &cpu[6], &cpu[7],
			&cpu[8], &cpu[9], &cpu[10], &cpu[11], &cpu[12], &cpu[13], &cpu[14], &cpu[15],
			&cpu[16], &cpu[17], &cpu[18], &cpu[19], &cpu[20], &cpu[21], &cpu[22], &cpu[23],
			&cpu[24], &cpu[25], &cpu[26], &cpu[27], &cpu[28], &cpu[29], &cpu[30], &cpu[31],
			&cpu[32], &cpu[33], &cpu[34], &cpu[35], &cpu[36], &cpu[37], &cpu[38], &cpu[39],
			&cpu[40], &cpu[41], &cpu[42], &cpu[43], &cpu[44], &cpu[45], &cpu[46], &cpu[47],
			&cpu[48], &cpu[49], &cpu[50], &cpu[51], &cpu[52], &cpu[53], &cpu[54], &cpu[55],
			&cpu[56], &cpu[57], &cpu[58], &cpu[59], &cpu[60], &cpu[61], &cpu[62], &cpu[63],
			&cpu[64], &cpu[65], &cpu[66], &cpu[67], &cpu[68], &cpu[69], &cpu[70], &cpu[71],
			&cpu[72], &cpu[73], &cpu[74], &cpu[75], &cpu[76], &cpu[77], &cpu[78], &cpu[79],
			&cpu[80], &cpu[81], &cpu[82], &cpu[83], &cpu[84], &cpu[85], &cpu[86], &cpu[87],
			&cpu[88], &cpu[89], &cpu[90], &cpu[91], &cpu[92], &cpu[93], &cpu[94], &cpu[95]);

		if (nitems > 1) {
			nldom++;
			
			for (i = 0; i < (nitems - 1); i++) {
				cpuinfop = GET_CPUP(&globals->cpu_hash, cpu[i]);
				cpuinfop->ldom = ldom;
				cpuinfop->cpu = cpu[i];
				nlcpu++;
			}
		}
	}

	if ((nldom > 1) && (nldom != globals->nldom)) {
		globals->nldom = nldom;
		globals->nlcpu = nlcpu;
		globals->SNC_enabled = TRUE;
	}
	fclose(f);
}

/* parse_mpscheds */
void
parse_mpscheds()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr, *cptr;
	int cpu1 = -1;
	int cpu2 = -1;
	int i, ret1;
	cpu_info_t *cpuinfop;
	pcpu_info_t *pcpuinfop;
	int found = 0;

	sprintf (fname, "mpscheds.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without HT reporting\n");
                return;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL)  {
			/* stop if at the end of the file */
			break;
		}
		
		cptr = strchr(input_str, '[');
		while (cptr) {
			cptr += 1;
			ret1 = sscanf (cptr, "%d %d", &cpu1, &cpu2);
	
			if (ret1==2) {
				if (!found) {
					found = 1;
					globals->HT_enabled = TRUE;
				}
				globals->ncpu++;
			        /* Check for HT CPUs siblings and record */
                                if (debug) fprintf (stderr, "HT cpus -  %d / %d\n", cpu1, cpu2);

				cpuinfop = GET_CPUP(&globals->cpu_hash, cpu1);
                                cpuinfop->cpu = cpu1;
                                cpuinfop->cpu_attr = LCPU;
                                cpuinfop->lcpu_sibling = cpu2;
                                cpuinfop->pcpu_idx = cpu1;
                                cpuinfop->lcpu_state = LCPU_UNKNOWN;

				cpuinfop = GET_CPUP(&globals->cpu_hash, cpu2);
                                cpuinfop->cpu = cpu2;
                                cpuinfop->cpu_attr = LCPU;
                                cpuinfop->lcpu_sibling = cpu1;
                                cpuinfop->pcpu_idx = cpu1;
                                cpuinfop->lcpu_state = LCPU_UNKNOWN;

                                pcpuinfop = GET_PCPUP(&globals->pcpu_hash, cpu1);
                                pcpuinfop->lcpu1 = cpu1;
                                pcpuinfop->lcpu2 = cpu2;
                                pcpuinfop->last_time = 0;
                        }

			cptr = strchr(cptr, '[');
			
		}
	}

	if (globals->ncpu == 0) globals->ncpu = globals->nlcpu;
	fclose(f);
}

void
add_oracle_sid(pid_info_t *pidp)
{
        char sid_name[20];
        int  i, len;
        int  oraproc_idx=0;
        char *startp, *endp;
        sid_pid_t *sidpidp;

	if (debug) fprintf (stderr, "add_oracle_sid_1() sid: %d %s\n", pidp->ora_sid, pidp->cmd);
        if (pidp->ora_sid) {
                /* Already recorded in sid_pid table */
                return;
	}

        if (strlen((char *)pidp->cmd) == 0) {
                /* we do not have command names */
                return;
	}

        if ((strncmp((char *)pidp->cmd, "ora", 3) != 0) || 
            (strncmp((char *)pidp->cmd, "oraagent", 8) == 0) ||
            (strncmp((char *)pidp->cmd, "orarootagent", 12) == 0)) {
                pidp->ora_sid = -1;
                pidp->ora_proc = -1;
                return;
        }

        len = 0;
        bzero (sid_name,20);
        for (i = ORACLE; i >= LGWR; i--) {
                len = strlen((char *)oracle_proc[i]);
                if (strncmp((char *)pidp->cmd, (char *)oracle_proc[i], len) == 0) {
                        oraproc_idx = i;
                        break;
                }
        }

        if (debug) fprintf (stderr, "add_oracle_sid_2(): %s %d\n", pidp->cmd, oraproc_idx);

        if (i == -1)  {
                oraproc_idx = OTHER;
        }

        if (oraproc_idx == ORACLE)  {
                len = 6;
                startp = (char *)&pidp->cmd[len];
                if (strstr(startp, ".") || strstr(startp,"+")) {
                        /* this is likely a oracle.sh or oracle+ASM process */
                        return;
		}
                strcpy(sid_name, startp);
        } else {
                len = 9;
                strncpy(sid_name, (char *)&pidp->cmd[len], MIN(strlen(&pidp->cmd[len]), 20));
        }

        for (i = 1; i < next_sid; i++) {
                if (strcmp(sid_table[i].sid_name, sid_name) == 0) {
                        /* we have a match */
                        break;
                }
        }

        if (i == next_sid) {
                if (next_sid >= SID_TBLSZ) {
                        printf ("Sid Table Overflow: number of Oracle Instances exceeds %d\n", SID_TBLSZ);
                        return ;
                }
                /* no match.  Need new SID entry */
		sprintf (sid_table[next_sid].sid_name, "%-19s", sid_name);
		len = strlen(sid_name);
		if (len > 19) len = 19;
		sid_table[next_sid].sid_name[len] = 0;
                next_sid++;
        }

        pidp->ora_sid = i;
        pidp->ora_proc = oraproc_idx;
        sidpidp = (sid_pid_t *)add_entry_head((lle_t **)&sid_table[i].sid_pid[oraproc_idx], pidp->PID, sizeof(sid_pid_t));
        sidpidp->pidinfop = pidp;

        if (debug) fprintf (stderr, "PID %lld / %s / %s / %s / %s\n", pidp->PID, (char *)pidp->cmd,
                sid_name, (char *)oracle_proc[oraproc_idx], (char *)oracle_procname[oraproc_idx]);
}


int 
print_pidp_addr(void *arg1, void *arg2) 
{
	pid_info_t *pidp = arg1;

	printf ("pidp 0x%llx %d %s \n", pidp, pidp->PID, pidp->cmd);
}

/* parse_pself */
void
parse_pself()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	char *lineptr;
	size_t n, retval;
	int i, ret;
	pid_info_t *pidp;
	char uid[20], stime[20], tty[20], time[20], cmd[80];
	int pid, ppid, tgid;
	int crit, nlwp;

	if (is_alive) return;

	if (debug) fprintf (stderr, "parse_pself()\n");

	sprintf(fname, "ps-eLf.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without process names.\n");
                return;
        }

	/* skip the first line */
	n = 0;
	lineptr = malloc(4096);
	if (lineptr == NULL) {
		fprintf (stderr, "parse_pself() - unable to malloc buffer - skipping...\n");
		return;
	}
	MALLOC_LOG(lineptr, 4096);
	retval = getline(&lineptr, &n, f);

	while (1) {
		retval = getline(&lineptr, &n, f);
		if (retval == -1ull ) {
			/* stop if at the end of the file */
			break;
		}

		sscanf (lineptr, "%s %lld %lld %lld %d %d %s %s %s %78s", uid, &tgid, &ppid, &pid, &crit, &nlwp, stime, tty, time, cmd);

		pidp = GET_PIDP(&globals->pid_hash, pid);
		pidp->ppid = ppid;
		pidp->tgid = tgid;
		pidp->nlwp = nlwp;

		add_command(&pidp->cmd, cmd);

		if (oracle) 
			add_oracle_sid(pidp);
	
		/* check for Hadoop Java processes */	
		if ((rtnptr = strstr(lineptr, "Dproc_")) != NULL) {
			rtnptr = rtnptr+6;
			sscanf (rtnptr, "%s", cmd);
			add_command(&pidp->hcmd, cmd);
		} else if (strstr(lineptr, "mapreduce")) {
			add_command(&pidp->hcmd, "mapreduce");
		}
	}

	FREE(lineptr);	
}

void
parse_edus()
{
	FILE *f = NULL;
	char fname[256];
	char *rtnptr;
	uint64 pid=0;
	pid_info_t *pidp;
	uint64 tgid, edu_id, utid;
	char thrname[32];

	if (edusfname) {
		sprintf(fname, "%s", edusfname);
	} else {
		sprintf(fname, "edus.%s", timestamp);
	}

	if ((f = fopen(fname,"r")) == NULL) {
		if (edusfname && !kilive) {
			fprintf (stderr,"Unable to open file %s, errno %d\n", fname, errno);
			fprintf (stderr,"Continuing without DB2 thread names.\n");
		}
		return;
	}

        /* skip the first line */
        rtnptr = fgets((char *)&input_str, 256, f);

        while (rtnptr != NULL) {
                rtnptr = fgets((char *)&input_str, 256, f);
                if (rtnptr == NULL)
                        /* stop if at the end of the file */
                        break;

		if (strstr(input_str, "==========")) break;

                if (strstr(input_str, "db2") == 0) continue;
                if (strstr(input_str, "db2wdog PID")) continue;
                if (strstr(input_str, "db2acd  PID")) continue;

                if (strstr(input_str, "db2sysc PID:")) {
                        sscanf (input_str+13, "%lld", &tgid);
                        pidp = GET_PIDP(&globals->pid_hash, tgid);
			add_command(&pidp->cmd, "db2sysc");
                        continue;
                }

                if (tgid == 0) continue;


	}

        while (rtnptr != NULL) {
                rtnptr = fgets((char *)&input_str, 256, f);
                if (rtnptr == NULL)
                        /* stop if at the end of the file */
                        break;
                sscanf (input_str, "%lld %lld %lld %s", &edu_id, &utid, &pid, thrname);
                pidp = GET_PIDP(&globals->pid_hash, pid);
		repl_command(&pidp->thread_cmd, thrname);

                if (debug) fprintf (stderr, "PID: %lld TGID: %lld  %s (%s)\n", pidp->PID, pidp->tgid, pidp->cmd, pidp->thread_cmd);
	}
}

void
parse_jstack()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	uint64 pid=0;
	pid_info_t *pidp;
	char thrname[128];
	char *nidptr, *thrptr, *qptr, *cptr;
	
	if (jstackfname) {
		sprintf(fname, "%s", jstackfname);
	} else {
		sprintf(fname, "jstack.%s", timestamp);
	}

	if ((f = fopen(fname,"r")) == NULL) {
		return;
	}

        rtnptr = fgets((char *)&input_str, 256, f);
        while (rtnptr != NULL) {
		if (nidptr = strstr(input_str, "nid=")) {
			/* 1st char should be a quote */
			thrptr = input_str+1;
			/* find 2nd quote and terminate string */
			if (qptr = strchr(thrptr, '"')) *qptr = 0;
			/* scan thread cmd and replace comma w/ space if needed */
			while (cptr = strchr(thrptr,',')) {
				*cptr = ' ';
			}
	
			sscanf (nidptr+4, "0x%llx", &pid);
                	pidp = GET_PIDP(&globals->pid_hash, pid);
			repl_command(&pidp->thread_cmd, thrptr);
	
       	         	if (debug) fprintf (stderr, "PID: %lld TGID: %lld %s (%s)\n", pidp->PID, pidp->tgid, pidp->cmd, pidp->thread_cmd);
		}
                rtnptr = fgets((char *)&input_str, 256, f);
	}
}

dev_info_t *find_devp(char *devname) 
{
	int i;
	dev_info_t *devinfop;

	if (globals->devhash == 0) return NULL;
	for (i=0; i < DEV_HSIZE; i++) {
		devinfop = (dev_info_t *)&globals->devhash[i];
		while (devinfop != NULL) {
			if (devinfop->devname && (strcmp(devinfop->devname, devname) == 0)) {
				return devinfop;
			}
			devinfop = (dev_info_t *)devinfop->lle.next;
		}
	}

	return NULL;
}


/* parse_ll_R */
/* this must be called BEFORE parse_mpath() */
void
parse_ll_R()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr, *ptr;
	char mode[12], user[20], group[20], month[4], day[4], time[8], mapname[30], 
             devname[30], pathname[60], dummy[6];
	int  nlink, size, major, minor;
	uint64 wwn;
	unsigned int dev;
	dev_info_t *devinfop;
	int ret;

        if (debug) fprintf (stderr, "parse_ll_R\n"); 
        if (is_alive) {
		/* only need the by-path info here */
                ret = system("ls -lR /dev >/tmp/.ll_R  2>/dev/null");
                sprintf (fname, "/tmp/.ll_R");
        } else {
                sprintf (fname, "ll_R_dev_all.%s", timestamp);
        }

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr,"Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr,"Continuing without device names.\n");
                return;
        }

	rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		if ((strncmp(input_str, "/dev:", 5) == 0) || (strncmp(input_str, "/dev/cciss:", 11) == 0)) {
			while (rtnptr != NULL) {
				if (strlen(input_str) == 1) break;
				if (input_str[0] == 'b') { 
					sscanf (input_str, "%s %d %s %s %d, %d %s %s %s %s", mode, &nlink, user, group, &major, &minor, month, day, time, devname);
					dev = mkdev(major,minor);
					devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
					devinfop->devpath = -1;
					add_string(&devinfop->devname, devname);
				}
	
				rtnptr = fgets((char *)&input_str, 127, f);
			}
		} else if (strncmp(input_str, "/dev/mapper:", 12) == 0) {
			while (rtnptr != NULL) {
				if (strlen(input_str) == 1) break;
				if (input_str[0] == 'l') { 
					sscanf (input_str, "%s %d %s %s %d %s %s %s %s %s %s", mode, &nlink, user, group, &size, month, day, time, mapname, dummy, devname);
					sscanf (&devname[6], "%d", &minor);
					dev = mkdev (MAPPER_MAJOR, minor);
					devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
					add_string(&devinfop->mapname, mapname);
				}
				rtnptr = fgets((char *)&input_str, 127, f);
			}
		} else if (strncmp(input_str, "/dev/disk/by-path:", 18) == 0) {
			while (rtnptr != NULL) {
				if (strlen(input_str) == 1) break;
				if (input_str[0] == 'l') { 
					sscanf (input_str, "%s %d %s %s %d %s %s %s %s %s %s", mode, &nlink, user, group, &size, month, day, time, pathname, dummy, devname);
					if ((ptr = strstr(pathname, "-fc-")) && (devinfop = find_devp(&devname[6]))) {
						sscanf(&ptr[4], "0x%llx", &devinfop->wwn);
						add_string(&devinfop->pathname, pathname);
					}
				}
				rtnptr = fgets((char *)&input_str, 127, f);
			}

		} else {
			rtnptr = fgets((char *)&input_str, 127, f);
		}
	}
	fclose(f);
/*
	if (is_alive) {
		unlink(fname);	
	}
*/
}

/* parse_mpath */
void
parse_mpath()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	char arg0[40], arg1[40], arg2[40], arg3[40];
	char *mpathname, *wwid, *array_type, devname[30];
	int mpathnum;
	int path1, path2, path3, path4;
	int major, minor;
	uint32 dev;
	dev_info_t *devinfop, *mdevinfop = NULL;
	int nargs = 0, mp_policy=0;


	if (debug) fprintf (stderr, "parse mpath");	
	sprintf(fname,"multipath-l.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without multipath names.\n");
                return;
        }

        rtnptr = fgets((char *)&input_str, 127, f);
        while (rtnptr != NULL) {
		if (strstr(input_str, "dm-")) {
			nargs = sscanf(input_str, "%s %s dm-%s %s", arg0, arg1, arg2, arg3);
			/* sscanf(input_str, "%s %s dm-%d %s", mpathname, wwid, &minor, array_type); */

			if (nargs == 4) {
				mpathname = arg0;
				wwid = arg1;
				minor = atoi(arg2);
				array_type = arg3;
			} else {
				mpathname = " ";
				wwid = arg0;
				minor = atoi(arg1);
				array_type = arg3;
			}
			if (debug) fprintf (stderr, "> %s %s dm-%d %s\n", mpathname, wwid, minor, array_type);
		
			dev = mkdev(mapper_major, minor);
			mdevinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
			add_string(&mdevinfop->mapname, mpathname);
			mdevinfop->devlist = NULL;
		}

		if (strstr(input_str, "round-robin")) {
			mp_policy = MP_ROUND_ROBIN;
		} else if (strstr(input_str, "queue-length")) {
			mp_policy = MP_QUEUE_LENGTH;
		} else if (strstr(input_str, "service-time")) {
			mp_policy = MP_SERVICE_TIME;
		}
			

		if ((strncmp(input_str, "  |- ", 5) == 0) || 
		    (strncmp(input_str, "  `- ", 5) == 0) || 
		    (strncmp(input_str, "| `- ", 5) == 0) || 
		    (strncmp(input_str, "| |- ", 5) == 0)) {
			sscanf(&input_str[5], "%d:%d:%d:%d %s %d:%d", 
				&path1, &path2, &path3, &path4, devname, &major, &minor);
			if (debug) fprintf (stderr, "  %s: %d:%d:%d:%d %s %d:%d\n", mpathname, path1, path2, path3, path4, devname, major, minor);

			dev = mkdev(major, minor);
			devinfop = GET_DEVP(DEVHASHP(globals,dev), dev);
			add_string(&devinfop->devname, devname);
			devinfop->devpath = FCPATH(path1, path2, path3, path4);

			if (mdevinfop) {	
				/* add the device to the mapper devices devlist */	
				devinfop->mdevinfop = mdevinfop;
				devinfop->siblingp = mdevinfop->devlist;	
				mdevinfop->devlist = devinfop;	
				mdevinfop->mp_policy = mp_policy;
			}
		}

                rtnptr = fgets((char *)&input_str, 127, f);

        }
	fclose(f);
}

/* parse_dmsetup */
void
parse_dmsetup()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
        char devname[128];
        int  major, minor;
	int ret;

	if (is_alive) return;	

	sprintf(fname,"dmsetup.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                return;
        }

	/* first line here should be good.  We just need the Major number */
        rtnptr = fgets((char *)&input_str, 127, f);
	if (sscanf (input_str, "%s (%d:%d)\n", &devname[0], &major, &minor)) {
		mapper_major = major;
		if (debug) fprintf (stderr, "%d %s\n", mapper_major, devname);
	}

	fclose(f);
}
	
/* parse_devices */
void
parse_devices()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
        char devname[128];
        int  major, minor;

	if (is_alive) {
		sprintf (fname, "/proc/devices");
	} else {
		sprintf (fname, "devices.%s", timestamp);
	}

        if ( (f = fopen(fname,"r")) == NULL) {
		parse_dmsetup();
                return;
        }

	/* first line here should be good.  We just need the Major number */
        rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		if (sscanf (input_str, "%d %s\n", &major, devname)) {
			if (strcmp(devname, "device-mapper") == 0) {
				mapper_major = major;
				if (debug) fprintf (stderr, "%d %s\n", mapper_major, devname);
				break;
			}
		}
                rtnptr = fgets((char *)&input_str, 127, f);
	}

	fclose(f);
}
	
/* parse_cstates */
void
parse_cstates()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	uint64 cstate_times[NCSTATES];
        cpu_info_t *cpuinfop;
	power_info_t *powerp, *gpowerp;
	int cpu, i;
	int nscan, ncstates;

	gpowerp = GET_POWERP(globals->powerp);
	if (gpowerp->power_start_cnt + gpowerp->power_end_cnt) return;

	if (is_alive) return;

	sprintf (fname, "cstates.%s", timestamp);
        if ( (f = fopen(fname,"r")) == NULL) {
                return;
        }

	/* skip first line */
        rtnptr = fgets((char *)&input_str, 127, f);
	while (rtnptr != NULL) {
		if (strstr(input_str, " CPU ")) break;
        	rtnptr = fgets((char *)&input_str, 127, f);
	}

        rtnptr = fgets((char *)&input_str, 127, f);
        while (rtnptr != NULL) {

		for (i=0; i < NCSTATES; i++) {
			cstate_times[i] = 0;
		}
                /* printf ("%s", input_str);  */
		nscan = sscanf (input_str, "%d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", &cpu, 
			&cstate_times[0], &cstate_times[1], &cstate_times[2], &cstate_times[3], &cstate_times[4], 
			&cstate_times[5], &cstate_times[6], &cstate_times[7], &cstate_times[8], &cstate_times[9]);

		ncstates = nscan - 2;
		if (ncstates < 0) continue;

		for (i=ncstates; i > 0; i--) {
			if (cstate_times[i]) {
				max_cstate = MAX(max_cstate,i);
				break;
			}
		}
		
		if (cpuinfop = FIND_CPUP(globals->cpu_hash, cpu)) {
			powerp = GET_POWERP(cpuinfop->powerp);
			bcopy(&cstate_times[1], &powerp->cstate_times[1], sizeof(uint64)*(NCSTATES-1));
			powerp->cstate_times[CSTATE_BUSY] = cstate_times[0];
			if (debug) {
				fprintf (stderr, "CPU: %d", cpu);
				for (i = 0; i <= max_cstate; i++) {
					fprintf (stderr, " %9lld", powerp->cstate_times[i]);
				}
				fprintf (stderr, "\n");
			}
			if (global_stats) {
				for (i=0; i < NCSTATES; i++) {
					gpowerp->cstate_times[i] += cstate_times[i];
				}
			}
		}
	
                rtnptr = fgets((char *)&input_str, 127, f);
	}
	fclose(f);
}

int
sym_sort_by_addr(const void *v1, const void *v2)
{
        const symtable_t *p1=v1;
        const symtable_t *p2=v2;
        int64 diff;

        diff = p2->addr - p1->addr;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}

/* parse_kallsyms */
void
parse_kallsyms()
{
	FILE *kallsyms = NULL;
	char fname[30];
	int i;
	uint64 addr;
	char type;
	char *symstr;
	struct stat statbuf;
	char *start, *newline, *rtnptr;
	int nitems;
	char symbol[255];
	char module[255];
	size_t len;
	char *space;
	int nsyms = 0;

	globals->nsyms = 0;
	if (debug) fprintf (stderr, "parse_kallsyms()\n");

	if (timestamp) {
		sprintf (fname, "kallsyms.%s", timestamp);
	} else {
		sprintf (fname, "/proc/kallsyms");
	}

	/* first, count the number of symbols to store */
        if ( (kallsyms = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "  Continuing without file names\n");
                return;
        }

	rtnptr = fgets((char *)&input_str, 511, kallsyms);
	while (rtnptr != NULL) {
		if ((rtnptr[17] == 't') || (rtnptr[17] == 'T')) { 
			nsyms++;
		}
		rtnptr = fgets((char *)&input_str, 511, kallsyms);
	}

	fclose (kallsyms);

	if (debug) fprintf (stderr, "nsyms = %d\n", nsyms); 
	globals->symtable = calloc(sizeof(symtable_t), nsyms);
	if (globals->symtable == NULL) {
		fprintf (stderr, "parse_kallsyms():  malloc() failed\n");
		return;
	}
	MALLOC_LOG(globals->symtable, nsyms * sizeof(symtable_t));
	
        if ( (kallsyms = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "  Continuing without file names\n");
                return;
        }

	rtnptr = fgets((char *)&input_str, 511, kallsyms);
	i = 0;
	while (rtnptr != NULL) {
		if ((rtnptr[17] == 't') || (rtnptr[17] == 'T')) { 
			module[0] = 0;
			sscanf(rtnptr, "%llx %c %s %s\n", &globals->symtable[i].addr, &type, symbol, module);

			if (strlen(symbol)) {
				/* Need to roundup to word aligned to prevent coredumps on SLES */
				globals->symtable[i].nameptr = malloc((strlen(symbol)+4) & 0xfffffffc);
				if (globals->symtable[i].nameptr) {
					MALLOC_LOG(globals->symtable[i].nameptr, strlen(symbol)+4);
					strcpy(globals->symtable[i].nameptr, symbol);
				}
			}

			if (strlen(module)) {
				/* Need to roundup to word aligned to prevent coredumps on SLES */
				globals->symtable[i].module = malloc((strlen(module)+4) & 0xfffffffc);
				if (globals->symtable[i].module) {
					MALLOC_LOG(globals->symtable[i].module, strlen(module)+4);
					strcpy(globals->symtable[i].module, module);
				}
			}
			
			i++;
		}
		rtnptr = fgets((char *)&input_str, 511, kallsyms);
	}
	fclose (kallsyms);

	/* now sort the table */
	qsort (globals->symtable, nsyms, sizeof(symtable_t), sym_sort_by_addr);

#if 0
	for (i=0; i < nsyms; i++) {
		fprintf (stderr, "[%d] 0x%llx %s %s\n", i, globals->symtable[i].addr, globals->symtable[i].nameptr, globals->symtable[i].module ? globals->symtable[i].module : "");
	} 
#endif

	/* now, make a final pass looking for specifc symbol names and saving the index for quick lookups later */
	for (i=0; i < nsyms; i++) {
		if (strcmp(globals->symtable[i].nameptr, "sleep_on_page") == 0)  pc_sleep_on_page = i; 
		else if (strcmp(globals->symtable[i].nameptr, "migration_entry_wait") == 0)  pc_migration_entry_wait = i; 
		else if (strcmp(globals->symtable[i].nameptr, "msleep") == 0)  pc_msleep = i; 
		else if (strcmp(globals->symtable[i].nameptr, "ixgbe_read_i2c_byte_generic") == 0)  pc_ixgbe_read_i2c_byte_generic = i; 
		else if (strcmp(globals->symtable[i].nameptr, "sys_semtimedop") == 0) pc_semtimedop = i;
		else if (strcmp(globals->symtable[i].nameptr, "sys_semctl") == 0) pc_semctl = i;
		else if (strcmp(globals->symtable[i].nameptr, "inode_dio_wait") == 0) pc_inode_dio_wait = i;
		else if (strcmp(globals->symtable[i].nameptr, "xfs_file_dio_aio_write") == 0) pc_xfs_file_dio_aio_write = i;
		else if (strcmp(globals->symtable[i].nameptr, "mutex_lock") == 0) pc_mutex_lock = i;
		else if (strcmp(globals->symtable[i].nameptr, "xfs_file_aio_read") == 0) pc_xfs_file_aio_read = i;
		else if (strcmp(globals->symtable[i].nameptr, "xfs_file_read_iter") == 0) pc_xfs_file_read_iter = i;
		else if (strcmp(globals->symtable[i].nameptr, "sleep_on_page") == 0)  pc_sleep_on_page = i; 
		else if (strcmp(globals->symtable[i].nameptr, "md_flush_request") == 0)  pc_md_flush_request = i; 
		else if (strcmp(globals->symtable[i].nameptr, "blkdev_issue_flush") == 0)  pc_blkdev_issue_flush = i; 
		else if (strcmp(globals->symtable[i].nameptr, "queued_spin_lock_slowpath") == 0) pc_queued_spin_lock_slowpath = i;
		else if (strcmp(globals->symtable[i].nameptr, "rwsem_down_write_failed") == 0)  pc_rwsem_down_write_failed = i; 
		else if (strcmp(globals->symtable[i].nameptr, "hugetlb_fault") == 0)  pc_hugetlb_fault = i; 
		else if (strcmp(globals->symtable[i].nameptr, "huge_pmd_share") == 0)  pc_huge_pmd_share = i; 
		else if (strcmp(globals->symtable[i].nameptr, "SYSC_semtimedop") == 0)  pc_SYSC_semtimedop = i; 
		else if (strcmp(globals->symtable[i].nameptr, "kstat_irqs_usr") == 0)  pc_kstat_irqs_usr = i; 
		else if (strcmp(globals->symtable[i].nameptr, "__mutex_lock_slowpath") == 0)  pc_mutex_lock_slowpath = i; 
		else if (strcmp(globals->symtable[i].nameptr, "pcc_cpufreq_target") == 0)  pc_pcc_cpufreq_target = i; 
		else if (strcmp(globals->symtable[i].nameptr, "kvm_mmu_page_fault") == 0) pc_kvm_mmu_page_fault = i;
	}

	globals->nsyms = nsyms;
}

/* parse maps file */
void
parse_maps()
{
	FILE *f = NULL;
	char fname[30];
	char dname[30];
	int pid;
	char *rtnptr;
	pid_info_t *pidp = NULL;
	char *objnamep = NULL;
	uint64 start, end, offset, inode;
	char perm[12], fdstr[12], objname[512];
	char *pathname, *hitp, *sptr;
	vtxt_preg_t *vtxt_pregp;
	struct stat buf;

	if (is_alive) return;

	sprintf(fname, "maps.%s", timestamp);
	sprintf(dname, "objdump.%s", timestamp);
	if ((f = fopen(fname, "r")) == NULL) {
		if (debug) fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
		return;
	}

	rtnptr = fgets((char *)&input_str, 511, f);
	while (rtnptr != NULL) {
		if (strncmp(input_str, "/proc/self", 10) == 0) break;
		if (input_str[0] == '/') {
			/* we found a new PID */
			if (strncmp(input_str, "/proc/", 6) != 0)  {
				/* not sure what this line is */
				break;
			}

			sscanf(&input_str[6], "%d\n", &pid);
			pidp = NULL;
		}

		sscanf(input_str, "%llx-%llx %s %llx %s %lld %s\n", &start, &end, perm, &offset, fdstr, &inode, objname);
		if ((perm[2] == 'x') && (inode > 0)) {

			if (debug) fprintf (stderr, "%d %llx-%llx %s %08x %s %lld %s\n", pid, start, end, perm, offset, fdstr, inode, objname);
			if (pidp == NULL) pidp = GET_PIDP(&globals->pid_hash, pid);

			vtxt_pregp = GET_ADD_VTXT(&pidp->vtxt_pregp,start);
			vtxt_pregp->p_vaddr = start;
			vtxt_pregp->p_endaddr =  end;
			vtxt_pregp->p_off = offset;
			vtxt_pregp->filename = malloc(strlen(objname)+1);
			if (vtxt_pregp->filename) {
				MALLOC_LOG(vtxt_pregp->filename, strlen(objname)+1);
				strcpy(vtxt_pregp->filename, &objname[0]);	
			}

			/* if the file has been (deleted), then don't try to load the elf */
			if (strstr(input_str, "(deleted)") == NULL) {
			    /* check to see if the pathname exists, otherwise, no need to load elf data */
			    if (pathname = malloc(strlen(dname) + 1 + strlen(objname)+1)) {
				MALLOC_LOG(pathname, strlen(dname) + 1 + strlen(objname)+1);
				sprintf (pathname, "%s/%s", dname, objname);

				/* next, check the objname in pathaname for "/" and replace with "?" */
				sptr = pathname + strlen(dname) + 1;
		        	while (hitp = strchr(sptr, '/')) {
       			       		hitp[0] = '?';
               				sptr = hitp + 1;
       				}

				if (stat(pathname, &buf) == 0) {	
					load_elf(pathname,  pidp->vtxt_pregp);
				}

				FREE(pathname);
				pathname = NULL;
			    }
			}
		}

		rtnptr = fgets((char *)&input_str, 511, f);
	}
}
			
int
load_perpid_mapfile(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	FILE *f = NULL;
	int fd;
	vtxt_preg_t *mapinfop;
	map_entry_t *maptab;
	struct stat statbuf;
	char fname[20];
	char *startptr, *rtnptr, *tmp1, *tmp2, *mmapptr;
	int nsyms=0, i=0, ret;
	uint64 offset = 0, addr, size;
	uint64 len = 0;

	/* if mulithreaded, then we must use the tgid pid */
        if (pidp->tgid && (pidp->PID != pidp->tgid)) {
                pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
        }

	/* return if map info is already initialized */
	if (pidp->mapinfop) return 0;

	sprintf (fname, "%d.map", pidp->PID);

	/* first pass to count the number of symbols */
        if ( (f = fopen(fname,"r")) == NULL) {
		/* silently return */
                return 0;
        }

	rtnptr = fgets((char *)&input_str, 511, f);
	while (rtnptr != NULL) {
		nsyms++;
		rtnptr = fgets((char *)&input_str, 511, f);
	}

	printf ("Number of Symbols: %d\n", nsyms);
	fclose(f);

	/* 2nd pass, build maptable, also open file for mmap access for later */
        if ( (f = fopen(fname,"r")) == NULL) {
		/* silently return */
                return 0;
        }

	if ((fd = open(fname, O_RDONLY)) < 0) {
		return 0;
	}

	if ((ret = fstat(fd, &statbuf)) < 0) {
		close(fd);
		return 0;
	}

	if ((size = statbuf.st_size) == 0) {
		close(fd);
		return 0;
	}

	mmapptr = mmap(NULL, statbuf.st_size, PROT_READ , MAP_SHARED, fd, 0);
	if (mmapptr == MAP_FAILED) {
		close(fd);
		return 0;
	}

	/* we can close the file here now that its mmaped */
	close(fd);

	mapinfop = find_add_info((void **)&pidp->mapinfop, sizeof(vtxt_preg_t));
	if (mapinfop == NULL) {
		munmap(mmapptr, size);
		return 0;
	}

	maptab = find_add_info((void **)&mapinfop->symbols, nsyms * sizeof(map_entry_t));
	if (maptab == NULL) {
		FREE(mapinfop);
		munmap(mmapptr, size);
		return 0;
	}

	rtnptr = fgets((char *)&input_str, 4096, f);
	input_str[4095] = 0;
	while (rtnptr != NULL) {
		len = strlen(rtnptr);
		if ((tmp1 = strchr(rtnptr, ' ')+1) > 0) { 
			if ((tmp2 = strchr (tmp1, ' ') + 1) > 0) { 
				if (sscanf (rtnptr, "%llx", &addr)) {
					/* printf ("[%d] 0x%llx - 0x%016llx %0x%llx\n", i, (tmp2-rtnptr)+offset, addr, tmp2); */
					/* printf ("[%d] 0x%llx - 0x%016llx %s\n", i, (tmp2-rtnptr)+offset, addr, tmp2);  */
					maptab[i].addr = addr;
					maptab[i].nameptr = (tmp2-rtnptr)+offset;
					i++;
				}
			}
		}

		offset += len;
		rtnptr = fgets((char *)&input_str, 4096, f);
		input_str[4095] = 0;
	}

	fclose(f);

	mapinfop->nsyms = i;
	mapinfop->elfp = mmapptr;
	mapinfop->p_type = MAPCLASS;

	return 0;
}

void
load_perpid_objfile_and_shlibs(pid_info_t *pidp)
{
	FILE *f = NULL;
	char fname[80];
	char *objnamep;
	char *rtnptr;
	uint64 start, end, offset, inode;
	char perm[12], fdstr[12], objname[512];
	vtxt_preg_t *vtxt_pregp;

	if (debug) fprintf (stderr, "load_perpid_objfile_and_shlibs - PID: %d\n", pidp->PID);
	if (pidp->vtxt_pregp) return;

	sprintf (fname, "/proc/%ld/maps", pidp->PID);
	if ((f = fopen(fname, "r")) == NULL) {
		if (debug) fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
		return;
	}

	while (rtnptr = fgets((char*)&input_str, 511, f)) {
		sscanf(input_str, "%llx-%llx %s %llx %s %lld %s\n", &start, &end, perm, &offset, fdstr, &inode, objname);
		if ((perm[2] == 'x') && (inode > 0)) {
			if (debug) fprintf (stderr, "%llx-%llx %s %08x %s %lld %s\n", start, end, perm, offset, fdstr, inode, objname);

			vtxt_pregp = GET_ADD_VTXT(&pidp->vtxt_pregp,start);
			vtxt_pregp->p_vaddr = start;
			vtxt_pregp->p_endaddr =  end;
			vtxt_pregp->p_off = offset;

			if (strstr(input_str, "(deleted)") == NULL) {
				if (objnamep = malloc(strlen(objname)+1)) {
					MALLOC_LOG(objnamep, strlen(objname)+1);
					strcpy(objnamep, objname);
					load_elf(objnamep,  pidp->vtxt_pregp);
				}
			}
		}
	}

	fclose(f);
	return;
}

static void
set_pidinfo_live(uint64 pid)
{
	pid_info_t *pidp;

	pidp = GET_PIDP(&globals->pid_hash, pid);
	get_command(pidp, NULL);
	load_perpid_objfile_and_shlibs(pidp);
	load_perpid_mapfile(pidp, NULL);
}

void load_objfile_and_shlibs()
{
	filter_item_t *fi;
	pid_info_t *pidp;
	DIR *procfs_dir;
	struct dirent *dent;
	uint64 pid;

	if (debug) fprintf (stderr, "load_objfile_and_shlibs()\n");

	/* if there is no filter, then get info on all PIDS */
	if ((((filter_t *)filter_func_arg)->f_P_pid == NULL) &&
	    (((filter_t *)filter_func_arg)->f_P_tgid == NULL)) {

		if ((procfs_dir = opendir("/proc")) == NULL) {
			return;
		}
	
		while (dent = readdir(procfs_dir)) {
			if (sscanf (dent->d_name, "%d", &pid)) {
				set_pidinfo_live(pid);
			}
		}

		closedir(procfs_dir);
	}


	if (fi = ((filter_t *)filter_func_arg)->f_P_pid) {
		while (fi) { 
			set_pidinfo_live(fi->fi_item);
			fi = fi->fi_next;
		}
	}

	if (fi = ((filter_t *)filter_func_arg)->f_P_tgid) {
		while (fi) { 
			set_pidinfo_live(fi->fi_item);
			fi = fi->fi_next;
		}
	}
}

void
print_docker_ps()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	int ret;
	uint64 id;

	/* if (debug) fprintf (stderr, "print_docker_ps\n"); */
	if (is_alive) {
		ret = system("docker ps >/tmp/.docker_ps  2>/dev/null");
		sprintf (fname, "/tmp/.docker_ps");
	} else {
		sprintf (fname, "docker_ps.%s", timestamp);
	}

        if ( (f = fopen(fname,"r")) == NULL) {
                return;
        }
	
	/* first line here should be the header */
        rtnptr = fgets((char *)&input_str, 1024, f);
	if (rtnptr) BOLD ("%s", rtnptr);
	
	while (rtnptr = fgets((char *)&input_str, 1024, f)) {
                if (sscanf(rtnptr, "%12llx", &id)) {
			DOCKER_URL_FIELD(id);
			printf ("%s", &rtnptr[12]);
		} else {
			printf ("%s", rtnptr);
		}

                rtnptr = fgets((char *)&input_str, 1024, f);
	}

	if (!HTML) printf ("\n");
	fclose(f);
	if (is_alive) {
		unlink(fname);	
	}
}

void
parse_docker_ps()
{
        FILE *f = NULL;
	char fname[30];
        char *rtnptr;
	char *strptr;
	uint64 offset;
	uint64 id;
        char name[512];
	docker_info_t *dockerp;
	int ret;


	/* if (debug) fprintf (stderr, "parse_docker_ps\n"); */
	if (is_alive) {
		ret = system("docker ps >/tmp/.docker_ps  2>/dev/null");
		sprintf (fname, "/tmp/.docker_ps");
	} else {
		sprintf (fname, "docker_ps.%s", timestamp);
	}

        if ( (f = fopen(fname,"r")) == NULL) {
                return;
        }
	
	/* first line here should be the header */
        rtnptr = fgets((char *)&input_str, 1024, f);
	while (rtnptr != NULL) {
		if (strncmp(input_str, "CONTAINER ID", 12 ) == 0) {
                        if ((strptr = strstr(input_str, "NAMES")) == NULL) {
                                fprintf (stderr, "Cannot find NAMES in docker ps output\n");
                                return;
                        }

                        offset = strptr - rtnptr;

                        rtnptr = fgets((char *)&input_str, 1024, f);
                        continue;
                }

                if (sscanf(rtnptr, "%llx", &id) && sscanf(rtnptr+offset, "%s\n", name)) {
			dockerp = GET_DOCKERP(&globals->docker_hash, id);
			add_command(&dockerp->name, name);
                }

                rtnptr = fgets((char *)&input_str, 1024, f);
	}

	fclose(f);
	if (is_alive) {
		unlink(fname);	
	}

	return;
}

uint64 get_container_id(char *str) {
	int i;
	uint64 id = 0ull;
	docker_info_t *dockerp;
	char id_str[16];
	
	if (globals->docker_hash == NULL) return 0ull;

	for (i = 0; i < DOCKER_HASHSZ; i++) {
		dockerp = globals->docker_hash[i];
	
		while (dockerp != NULL) {
			sprintf (&id_str[0], "%012llx", dockerp->lle.key);
			id_str[12] = 0;
				
			if (strstr(str, id_str)) { 
				/* We have a match! */
				id = dockerp->lle.key;
				goto found;
			}
			
			dockerp = (docker_info_t *)dockerp->lle.next;
		}
	}

found:	
	return id;
}

void
parse_proc_cgroup()
{

	FILE *f = NULL;
	char fname[30];
	int pid;
	uint64 id = 0;
	char *rtnptr;
	char *pos;
	pid_info_t *pidp = NULL;
	dkpid_info_t *dkpidp = NULL;
	docker_info_t *dockerp = NULL;

	if (debug) fprintf (stderr, "parse_proc_cgroup\n");
	if (is_alive) return;

	sprintf(fname, "proc_cgroup.%s", timestamp);
	if ((f = fopen(fname, "r")) == NULL) {
		if (debug) fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
		return;
	}

	rtnptr = fgets((char *)&input_str, 511, f);
	while (rtnptr != NULL) {
		if (strncmp(input_str, "/proc/self", 10) == 0) break;
		if (input_str[0] == '/') {
			/* we found a new PID */
			if (strncmp(input_str, "/proc/", 6) != 0)  {
				/* not sure what this line is */
				break;
			}

			sscanf(&input_str[6], "%d\n", &pid);
			pidp = NULL;
			dockerp = NULL;
			id = 0;
	
			rtnptr = fgets((char *)&input_str, 511, f);
			continue;
		}

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
				pidp = GET_PIDP(&globals->pid_hash, pid);
				dockerp = GET_DOCKERP(&globals->docker_hash, id);
				pidp->dockerp = dockerp;

				dkpidp = GET_DKPIDP(&dockerp->dkpid_hash, pid);
				dkpidp->dockerp = dockerp;
				dkpidp->pidp = pidp;
				/* fprintf (stderr, "PID: %d   id: %012llx name: %s\n", pid, id, dockerp->name); */
			}
		}

		rtnptr = fgets((char *)&input_str, 511, f);
	}

	fclose(f);
}

void 
parse_scavuln(char print_flag)
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	char varname[30];

	globals->scavuln = SCA_UNKNOWN;
	if (is_alive) {
		return;
	} else {
		sprintf(fname, "scavuln.%s", timestamp);
	}

	if ( (f = fopen(fname,"r")) == NULL) {
		/* 
		fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
		fprintf (stderr, "Continuing without memory info.\n");
		*/
		if (print_flag) printf ("runki from LinuxKI version 5.8 needed to capture Side-Channel Attack Mitigation information\n");
		return;
	}

	globals->scavuln = SCA_VULNERABLE;
	rtnptr = fgets((char *)&input_str, 127, f);
	if (rtnptr == NULL ) {
		if (print_flag) printf ("Kernel does not support Side-Channel Attack Mitigations\n");
	} else {
	    	while (rtnptr != NULL) {
			if (print_flag) printf("%s", rtnptr);
			if (strstr(input_str, "Mitigat")) {
				globals->scavuln = SCA_MITIGATED;
			}

			rtnptr = fgets((char *)&input_str, 127, f);
		}
	}
}

int
parse_corelist() 
{
	int fd, ret, i = 0;
	struct stat statbuf;
	uint64 offset = 0, addr, size, len=0;
	char *mapptr, *chr, *pos;
	char fname[32];
	cpu_info_t *cpuinfop, *scpuinfop;
	pcpu_info_t *pcpuinfop;
	int	cpu, ncores, nlcores;
	int 	nlcpu = 0, ncpu = 0, nldom = 0;

	globals->nldom = 1;

        sprintf(fname, "corelist.%s", timestamp);

	if ((fd = open(fname, O_RDONLY)) < 0)  {
		fprintf(stderr, "Unable to open file %s for processing, continuing without core attributes\n", fname);
		perror("open error");
		return 0;
	}

	if ((ret = fstat(fd, &statbuf)) < 0) {
		fprintf(stderr, "Unable to stat file %s for processing, continuing\n", fname);
		perror("fstat error");
		close(fd);
		return 0;
	}

	if ((size = statbuf.st_size) == 0) {
		fprintf(stderr, "PDB TXT file %s is empty\n", fname);
		close(fd);
		return 0;
	}

	size = statbuf.st_size;
	mapptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapptr == MAP_FAILED) {
                fprintf(stderr, "Unable to mmap file %s for processing\n", fname);
                close(fd);
                return 0;
        }

        close (fd);

        if ((mapptr[0] != (char)0xff) || (mapptr[1] != (char)0xfe)) {
                fprintf (stderr, "Invalid corelist file %s, skipping\n", fname);
                return 0;
        }

        /* First pass is to count symbols */
        chr = mapptr+2;
        while (chr < mapptr + (size-20)) {
                GET_WIN_LINE(util_str, chr);
		/* printf ("util_str: %s\n", util_str); */

		if (strncmp(util_str, "NumberOfCores=", 14) == 0) {
			pos = strchr(util_str, '=') + 1;
			sscanf (pos, "%d\n", &ncores);
		} else if (strncmp(util_str, "NumberOfLogicalProcessors=", 26) == 0) {
			pos = strchr(util_str, '=') + 1;
			sscanf (pos, "%d\n", &nlcores);
		} else if (strncmp(util_str, "SocketDesignation=", 18) == 0) {
			nldom++;
			globals->nldom = nldom;
			if (nlcores > ncores) globals->HT_enabled = TRUE;

			for (i = 0; i < ncores; i++) {
				cpu = nlcpu;
				nlcpu++;
				ncpu++;

				cpuinfop = GET_CPUP(&globals->cpu_hash, cpu);
				cpuinfop->ldom = nldom - 1;
				cpuinfop->cpu = cpu;
				cpuinfop->pcpu_idx = cpu;

				/* printf ("CPU: %d  Node: %d  Sibling: %d\n", cpuinfop->cpu, cpuinfop->ldom, cpu+1); */

				/* in Windows HT pairs are adjacent */
				if (globals->HT_enabled) {
					cpuinfop->lcpu_sibling = cpu+1;
		
					pcpuinfop = GET_PCPUP(&globals->pcpu_hash, cpu);
					pcpuinfop->lcpu1 = cpu;
					pcpuinfop->lcpu2 = cpu+1;
					pcpuinfop->last_time = 0;	

					scpuinfop = GET_CPUP(&globals->cpu_hash, cpu+1);
					scpuinfop->ldom = nldom - 1;
					scpuinfop->cpu = cpu+1;
					scpuinfop->lcpu_sibling = cpu;
					scpuinfop->pcpu_idx = cpu;
					/* printf ("CPU: %d  Node: %d  Sibling: %d\n", scpuinfop->cpu, scpuinfop->ldom, scpuinfop->lcpu_sibling); */
					cpu++;
					nlcpu++;
				}
			}
		}
        }

	globals->nlcpu = nlcpu;
	globals->ncpu = ncpu;

	munmap(mapptr, size);
	return 0;
}

int
parse_SQLThreadList() 
{
	int fd, ret, i = 0;
	struct stat statbuf;
	uint64 offset = 0, addr, size, len=0;
	char *mapptr, *chr, *pos;
	char fname[32];
	int pid, tid;
	pid_info_t *pidp, *tgidp;
	char instance[32], thrname[64];

        sprintf(fname, "SQLThreadList.%s", timestamp);

	if ((fd = open(fname, O_RDONLY)) < 0)  {
		if (debug) {
			fprintf(stderr, "Unable to open file %s for processing, continuing without SQL Thread List\n", fname);
			perror("open error");
		}
		return -1;
	}

	if ((ret = fstat(fd, &statbuf)) < 0) {
		if (debug) {
			fprintf(stderr, "Unable to stat file %s for processing, continuing\n", fname);
			perror("fstat error");
		}
		close(fd);
		return 0;
	}

	if ((size = statbuf.st_size) == 0) {
		if (debug) {
			fprintf(stderr, "SQL Thread List file %s is empty, continuing\n", fname);
		}
		close(fd);
		return 0;
	}

	size = statbuf.st_size;
	mapptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapptr == MAP_FAILED) {
                fprintf(stderr, "Unable to mmap file %s for processing\n", fname);
                close(fd);
                return 0;
        }

        close (fd);

        if ((mapptr[0] != (char)0xff) || (mapptr[1] != (char)0xfe)) {
                fprintf (stderr, "Invalid SQL Thread List file %s, skipping\n", fname);
                return 0;
        }

        chr = mapptr+2;
        while (chr < mapptr + (size-4)) {
                GET_WIN_LINE(util_str, chr);

		if (strncmp(util_str, "PID,INSTANCE", 12) == 0) continue;

		sscanf(util_str, "%d,%[^,],%d,%[^\r]", &pid, instance, &tid, thrname); 
		/* printf ("%d <%s> %d <%s>\n", pid, instance, tid, thrname); */

		if (tid) {
			pidp = GET_PIDP(&globals->pid_hash, tid);
			add_command(&pidp->thread_cmd, thrname);
			if (pid) {
				tgidp = GET_PIDP(&globals->pid_hash, pid);
				pidp->tgid = pid;
				add_command (&tgidp->hcmd, instance);
			}
		}
	}

	munmap(mapptr, size);
}


long
get_memkb(char *str) 
{
	char *p, *s;
	p = s = str;
	long size = 0;

	while (*s != ' ') {
		if (*s != ',') {
			*p++ = *s;
		}
		s++;
	}
	*p = 0;
	size = atol(str) * 1024;
	return (size);
}

void 
parse_systeminfo()
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr, *pos, *end;
	int i, j;
	int	cpu, ncores, nlcores;
	float   ghz;

	sprintf (fname, "systeminfo.%s", timestamp);

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without NODE reporting (all CPUs will be considered to be in NODE 0)\n");
                return;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			/* stop if at the end of the file */
			break;
		}

		if (strncmp(input_str, "Host Name:", 10) == 0) {
			pos=&input_str[10];
			while (isspace(*pos)) pos++;
			end = pos;
			while (end && (*end != 0xa) && (*end != 0xd)) end++;
			*end=0;
			add_command(&globals->hostname, pos);
		} else if (strncmp(input_str, "OS Version:", 11) == 0) {
			pos=&input_str[11];
			while (isspace(*pos)) pos++;
			end = pos;
			while (end && (*end != 0xa) && (*end != 0xd)) end++;
			*end=0;
			add_command(&globals->os_vers, pos);
		} else if (strncmp(input_str, "System Model:", 13) == 0) {
			pos=&input_str[13];
			while (isspace(*pos)) pos++;
			end = pos;
			while (end && (*end != 0xa) && (*end != 0xd)) end++;
			*end=0;
			add_command(&globals->model, pos);
		} else if (strncmp(input_str, "Total Physical Memory:", 22) == 0) {
			pos=&input_str[22];
			while (isspace(*pos)) pos++;
			globals->memkb = get_memkb(pos);
			return;
		}
	}
	
	fclose(f);
}

int get_max_sectors_kb()
{
	FILE *f = NULL; 
	char fname[32];
	char *rtnptr, *pos, *end;
	int max_max_sectors_kb = 0, max_sectors_kb;

	sprintf (fname, "block_params.%s", timestamp);

	if ( (f = fopen(fname,"r")) == NULL) {
                return 0;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			/* stop if at the end of the file */
			break;
		}
		if ((strncmp(input_str, "/sys/block/sd", 13) == 0) && 
		     strstr(input_str, "max_sectors_kb")) {
			/* get the max_sector_kb */
			pos = strchr(input_str, ':');
			pos++;
			sscanf (pos, "%d", &max_sectors_kb);
			max_max_sectors_kb = MAX(max_max_sectors_kb, max_sectors_kb);
		}
	}

	fclose(f);
	return max_max_sectors_kb;
}

int show_fc_linkspeeds()
{
	FILE *f = NULL; 
	char fname[30];
	char *rtnptr;

	sprintf (fname, "fc_linkspeed.%s", timestamp);

	if ( (f = fopen(fname,"r")) == NULL) {
                return 0;
        }

	BOLD ("\n** Fibre Channel Link Speeds **\n");
	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			/* stop if at the end of the file */
			break;
		}

		printf("%s", input_str);
	}
	fclose(f);
}

void 
io_controllers(uint64 *warnflagp, char print_flag)
{
	FILE *f = NULL;
	char fname[32];
	char *rtnptr;
	int max_sectors_kb;

	if (IS_WINKI) return;

	max_sectors_kb = get_max_sectors_kb();

	sprintf (fname, "lspci-v.%s", timestamp);

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without checking RAID controllers\n");
                return;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			/* stop if at the end of the file */
			break;
		}
		if (strstr(input_str, " Fibre Channel: ") ||
		    strstr(input_str, " RAID bus controller: ") || 
		    strstr(input_str, " Attached SCSI controller: ")) {
			if (print_flag)  printf("%s", input_str);

			/* Read next line to get subsystem */  
			rtnptr = fgets((char *)&input_str, 511, f);
			if (rtnptr == NULL) {
				/* stop if at the end of the file */
				break;
			}

			if ((max_sectors_kb > 1024) && 
			    (strstr(input_str, " P4") || strstr(input_str, " P8"))) {
				(*warnflagp) |= WARNF_CACHE_BYPASS;
				RED_FONT;
			}

			if (print_flag)  printf("%s", input_str);
			BLACK_FONT;
		}
	}

	fclose(f);

	show_fc_linkspeeds();
}

void
parse_dmidecode() 
{
	FILE *f = NULL;
	char fname[30];
	char *rtnptr;
	int size, speed, cfg_speed, hdr = 1;
	char type[8];
	char locator[25];
	char mfg[16];
	char unit[16];

	if (IS_WINKI) return;

	sprintf (fname, "dmidecode.%s", timestamp);

        if ( (f = fopen(fname,"r")) == NULL) {
                fprintf (stderr, "Unable to open file %s, errno %d\n", fname, errno);
                fprintf (stderr, "Continuing without getting memory details\n");
                return;
        }

	while (1) {
		rtnptr = fgets((char *)&input_str, 511, f);
		if (rtnptr == NULL) {
			/* stop if at the end of the file */
			break;
		}

		if (strstr(input_str, "Memory Device")) {
			if (hdr) BOLD ("Location              Type    Size    Speed CfgSpeed  Mfg\n");
			hdr = speed = size = cfg_speed = 0;
			while (1) {
				rtnptr = fgets((char *)&input_str, 511, f);
				if (rtnptr == NULL) {
					/* stop if at the end of the file */
					if (size) {
						printf ("%24s  %6s %4d GB  %4d MT/s  %4d MT/s\n",
							locator, type, size, speed, cfg_speed);
					}
					break;
				}

				if (strncmp(input_str, "Handle", 6) == 0) {
					if (size) {
						printf ("%-20s %5s %4d GB   %6d   %6d  %s\n",
							locator, type, size, speed, cfg_speed, mfg);
					}
					break;
				}

				if (strncmp(input_str+1, "Size:", 5) == 0) {
					sscanf (input_str+7, "%d %2s", &size, unit);
					if (unit[0] == 'M') size = size / 1024;
				} else if (strncmp(input_str+1, "Speed:", 6) == 0) {
					sscanf (input_str+8, "%d", &speed);
				} else if (strncmp(input_str+1, "Configured Memory Speed:", 24) == 0) {
					sscanf (input_str+26, "%d", &cfg_speed);
				} else if (strncmp(input_str+1, "Type:", 5) == 0) {
					sscanf (input_str+7, "%16s", type);
				} else if (strncmp(input_str+1, "Manufacturer:", 13) == 0) {
					sscanf (input_str+15, "%s", mfg);
				} else if (strncmp(input_str+1, "Locator:", 8) == 0) {
					strncpy (locator, input_str+10, 24);
					locator[strlen(locator)-1] = 0;
				}
				
			}
		}

	}
}

