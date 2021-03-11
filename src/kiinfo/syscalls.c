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
#include <linux/aio_abi.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kdev_t.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>

/* have to jump through some hoop for ARM processors */
#if __aarch64__
#define __ARCH_WANT_SYSCALL_DEPRECATED
#define __ARCH_WANT_SYSCALL_NO_AT
#include <asm-generic/unistd.h>
#undef __ARCH_WANT_SYSCALL_NO_AT
#undef __ARCH_WANT_SYSCALL_DEPRECATED

#elif __PPC__
#include <asm/unistd.h>
#else
#include <asm/unistd_64.h>
#endif

#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"

#include "kd_types.h"
#include "globals.h"
#include "conv.h"
#include "hash.h"
#include "info.h"
#include "futex.h"

void
incr_syscall_stats(void *arg1, uint64 ret, uint64 syscalltm, int logio) 
{
	syscall_stats_t *statp = (syscall_stats_t *)arg1;
	statp->count++;
	statp->total_time += syscalltm;
	statp->max_time = MAX(syscalltm, statp->max_time);
	if (IS_ERR_VALUE(ret)) statp->errors++;

	if (logio && (signed long)ret > 0 ) {
		statp->bytes += ret;
	}
}

static inline void
incr_fd_syscall_stats(fd_info_t *fdinfop, uint64 syscallbegtm)
{
	        fdinfop->stats.syscall_cnt++;
                fdinfop->stats.total_time += syscallbegtm;
                fdinfop->stats.max_time = MAX(syscallbegtm, fdinfop->stats.max_time);
}

static inline void
incr_socket_stats(void *arg1, void *arg2, uint64 syscalltm, int elf, int logio)
{
	sd_stats_t *statp = (sd_stats_t *)arg1;
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg2;
	short *syscall_index;
	uint64 bytes;

	syscall_index = ((elf == ELF32) ? globals->syscall_index_32 : globals->syscall_index_64);

	statp->syscall_cnt++;
	statp->total_time += syscalltm;
	statp->max_time = MAX(syscalltm, statp->max_time);
	statp->last_pid = rec_ptr->pid;
 	if (IS_ERR_VALUE(rec_ptr->ret) || (logio==0))  { 
		statp->errors++;
		return;
	}

	bytes = rec_ptr->ret;

	switch (rec_ptr->syscallno) {
                case __NR_recvfrom:
                case __NR_recvmsg:
                case __NR_read:
                case __NR_readv:
			statp->rd_bytes += bytes;
			statp->rd_cnt++;
			break;
		case __NR_vmsplice:
                case __NR_sendto:
                case __NR_sendmsg:
                case __NR_write :
                case __NR_writev :	
			statp->wr_bytes += bytes;
			statp->wr_cnt++;
			break;
                case __NR_splice:
			if (logio == 1) {
				statp->rd_bytes += bytes;
				statp->rd_cnt++;
			} else if (logio == 2) {
				statp->wr_bytes += bytes;
				statp->wr_cnt++;
			}
			break;
		default:
		;
	}
}

static inline void
pid_update_fdinfo(void *arg1, void *arg2)
{
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	fd_info_t *fdinfop = (fd_info_t *)arg2;
	char *		varptr;
	struct sockaddr_in *laddr, *raddr;
	struct sockaddr_in6 *ldest, *rdest;
	struct sockaddr_in6 *lsock_src6;
	struct sockaddr_in6 *rsock_src6;
	fileaddr_t	*faddr;
	unsigned int	dev;

	/* if the file was previously closed, let's cleanup the fdinfop.  We will keep the syscall stats 
	if (fdinfop->closed) {
		fdinfop->dev=0;
		fdinfop->node=0;
		fdinfop->ftype=0;
		if (fdinfop->lsock) {
			FREE(fdinfop->lsock);
			fdinfop->lsock = NULL;
		}
		if (fdinfop->rsock) {
			FREE(fdinfop->rsock);
			fdinfop->rsock = NULL;
		}
		 if (fdinfop->fnamep) {
			FREE(fdinfop->fnamep);
			fdinfop->fnamep = NULL;
		}
		fdinfop->multiple_fnames++;
		fdinfop->closed=0;
	}
	*/
		

	/* printf ("pid_update_fdinfo() rec_ptr: 0x%llx  reclen: %d %d\n", rec_ptr, rec_ptr->reclen, sizeof(syscall_exit_t));  */
	if (rec_ptr->reclen <= sizeof(syscall_exit_t)) return;

	varptr = (char *)rec_ptr + sizeof(syscall_exit_t);
	switch (rec_ptr->syscallno) {
#ifndef __NR_sendmmsg
#define __NR_sendmmsg 307
#define __NR_recvmmsg 299
#endif
		case __NR_recvmmsg :
		case __NR_sendmmsg :
			varptr += sizeof(unsigned long);
		case __NR_recvfrom:
                case __NR_sendto:
                case __NR_recvmsg:
                case __NR_sendmsg:
                case __NR_vmsplice:
                case __NR_splice:
                case __NR_read:
                case __NR_readv:
                case __NR_write :
                case __NR_writev :
			laddr = (struct sockaddr_in *)varptr;
			if (laddr->sin_family == AF_INET) {
				raddr = (struct sockaddr_in *)(varptr+sizeof(struct sockaddr_in));
				if (fdinfop->lsock && fdinfop->rsock) {
					ldest = fdinfop->lsock;
					rdest = fdinfop->rsock;
				} else if (ldest = calloc(1, sizeof(struct sockaddr_in6))) {
					CALLOC_LOG(ldest, 1, sizeof(struct sockaddr_in6));
					if (rdest = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(rdest, 1, sizeof(struct sockaddr_in6));
						fdinfop->lsock = ldest;
						fdinfop->rsock = rdest;
					}
				}

				/* munge the IPv4 data into the IPv6 struct for now */
				/* update the socket information in the fd_info_t structure */
				memcpy(&ldest->sin6_addr.s6_addr[12], &laddr->sin_addr.s_addr, 4);
				memcpy(&rdest->sin6_addr.s6_addr[12], &raddr->sin_addr.s_addr, 4);
				ldest->sin6_addr.s6_addr16[5] = 0xffff;
				rdest->sin6_addr.s6_addr16[5] = 0xffff;
				ldest->sin6_port = BE2LE(laddr->sin_port);
				rdest->sin6_port = BE2LE(raddr->sin_port);
				ldest->sin6_family = laddr->sin_family;
				rdest->sin6_family = raddr->sin_family;
				fdinfop->ftype = F_IPv4;
				fdinfop->node = TCP_NODE;
				fdinfop->dev = 0;
			} else if (laddr->sin_family == AF_REGFILE) {
				faddr = (fileaddr_t *)varptr;
				fdinfop->node = faddr->i_ino;
				fdinfop->dev = faddr->dev;
				fdinfop->ftype = F_REG;
				if (fdinfop->lsock) {
					FREE(fdinfop->lsock);
					fdinfop->lsock = NULL;
				}
				if (fdinfop->rsock) {
					FREE(fdinfop->rsock);
					fdinfop->rsock = NULL;
				}
			} else if (laddr->sin_family == AF_INET6) {
				lsock_src6 = (struct sockaddr_in6 *)laddr;
                        	rsock_src6 = (struct sockaddr_in6 *)(varptr+sizeof(struct sockaddr_in6));

				if (fdinfop->lsock && fdinfop->rsock) {
					ldest = fdinfop->lsock;
					rdest = fdinfop->rsock;
				} else {
					if (ldest = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(ldest, 1, sizeof(struct sockaddr_in6));
						if (rdest = calloc(1, sizeof(struct sockaddr_in6))) {
							CALLOC_LOG(rdest, 1, sizeof(struct sockaddr_in6));
							fdinfop->lsock = ldest;
							fdinfop->rsock = rdest;
						}
					}
				}

				/* update the socket information in the fd_info_t structure */
				memcpy(&ldest->sin6_addr.s6_addr[0], &lsock_src6->sin6_addr.s6_addr[0], 16);
				memcpy(&rdest->sin6_addr.s6_addr[0], &rsock_src6->sin6_addr.s6_addr[0], 16);
				ldest->sin6_port = BE2LE(lsock_src6->sin6_port);
				rdest->sin6_port = BE2LE(rsock_src6->sin6_port);
				ldest->sin6_family = lsock_src6->sin6_family;
				rdest->sin6_family = rsock_src6->sin6_family;
				fdinfop->ftype = F_IPv6;
				fdinfop->node = TCP_NODE;
				fdinfop->dev = 0;

			}
			break;
		default:
		;
	}
}

static inline int
socket_global_syscall_stats(void *arg1, void *arg2, void *arg3, int logio, uint64 syscallbegtm)
{
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	sdata_info_t *sdatap = (sdata_info_t *)arg2;
	pid_info_t *pidp = (pid_info_t *)arg3;

	sock_info_t *rsockp, *lsockp;
	ip_info_t *ripp, *lipp;
	ipip_info_t *ipipp;
	syscall_info_t *syscallp;
	uint64 syscallno;
	uint64 ip1, ip2;
	struct socket_in6 *laddr, *raddr;

	if (!global_stats) return 0;
	if (!sock_flag) return 0;

	syscallno = rec_ptr->syscallno;

	ipipp = (ipip_info_t *)sdatap->ipipp;
	if (ipipp == NULL) {
		ipipp = GET_IPIPP(&globals->ipip_hash, SOCK_IP(sdatap->lle.key1), SOCK_IP(sdatap->lle.key2));
		cp_sockip(&ipipp->laddr, sdatap->laddr);
		cp_sockip(&ipipp->raddr, sdatap->raddr);
		sdatap->ipipp = ipipp;
	}

	incr_socket_stats(&ipipp->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
	syscallp = GET_SYSCALLP(&ipipp->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
	incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);

	lipp = (ip_info_t *)sdatap->lipp;
	if (lipp == NULL) {
		lipp = GET_IPP(&globals->lip_hash, SOCK_IP(sdatap->lle.key1));
		cp_sockip(&lipp->saddr, sdatap->laddr);
		sdatap->lipp = lipp;
	}
	incr_socket_stats(&lipp->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
	syscallp = GET_SYSCALLP(&lipp->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
	incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);

	ripp = (ip_info_t *)sdatap->ripp;
	if (ripp == NULL) {
		ripp = GET_IPP(&globals->rip_hash, SOCK_IP(sdatap->lle.key2));
		cp_sockip(&ripp->saddr, sdatap->raddr);
		sdatap->ripp = ripp;
	}
	incr_socket_stats(&ripp->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
	syscallp = GET_SYSCALLP(&ripp->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
	incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);

	lsockp = (sock_info_t *)sdatap->lsockp;
	if (lsockp == NULL) {
		lsockp = GET_SOCKP(&globals->lsock_hash, SOCK_IP(sdatap->lle.key1), SOCK_PORT(sdatap->lle.key1));
		cp_sockaddr(&lsockp->saddr, sdatap->laddr);
		sdatap->lsockp = lsockp;
	}
	incr_socket_stats(&lsockp->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
	syscallp = GET_SYSCALLP(&lsockp->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
	incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);
	
	rsockp = (sock_info_t *)sdatap->rsockp;
	if (rsockp == NULL) {
		rsockp = GET_SOCKP(&globals->rsock_hash, SOCK_IP(sdatap->lle.key2), SOCK_PORT(sdatap->lle.key2));
		cp_sockaddr(&rsockp->saddr, sdatap->raddr);
		sdatap->rsockp = rsockp;
	}
	incr_socket_stats(&rsockp->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
	syscallp = GET_SYSCALLP(&rsockp->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
	incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);
}

static inline void
update_file_stats(void *a, pid_info_t *pidp, int fd, uint64 syscallbegtm, int old_state, int new_state, int logio) {
	syscall_exit_t *rec_ptr =  (syscall_exit_t *)a;
	syscall_info_t *syscallp;
        pid_info_t *tgidp;
	cpu_info_t *cpuinfop;
	sched_info_t *schedp, *gschedp;
	sched_stats_t *statp, *sstatp;
	fd_info_t *fdinfop, *tfdinfop, *ofdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	uint64 delta;
	uint32 syscallno;
	uint64 key, device=0;
	uint64 node=0, ftype=0;
	trc_info_t *trcp;
	syscall_stats_t *syscall_statsp;
	struct sockaddr_in6 *lsock = NULL, *rsock = NULL;

	syscallno = rec_ptr->syscallno;
    	if ((fd < 65536) && (fd >= 0))  {
		fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
		if (perpid_stats && perfd_stats) {
			incr_fd_syscall_stats(fdinfop, syscallbegtm);
			if (scall_stats) {
				syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
				delta = update_sched_time(&syscallp->sched_stats, rec_ptr->hrtime);
				update_sched_state(&syscallp->sched_stats, old_state, new_state, delta);
				incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);
			}
		}

		/* if needed, update the fdinfo from the TGID fdinfo */
		ofdinfop = fdinfop;
		if (pidp->tgid && (fdinfop->node == 0) && (fdinfop->ftype == 0)) {
			/* inherit fdinfop from primary thread */
			tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
			tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
			if (tfdinfop) fdinfop = tfdinfop;
		}
		pid_update_fdinfo(rec_ptr, fdinfop);
		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;
		lsock = fdinfop->lsock;
		rsock = fdinfop->rsock;

		if (is_alive) get_filename(fdinfop, pidp);

		if (perfd_stats && lsock && rsock) {
			incr_socket_stats(&pidp->netstats, rec_ptr, syscallbegtm, pidp->elf, logio);
			incr_socket_stats((struct fd_stats_t *)&ofdinfop->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
		}

		/* Global File Stats */
    		if (global_stats && lsock && rsock) {
               		sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(lsock), SIN_PORT(lsock), 
                                                                 	SIN_ADDR(rsock), SIN_PORT(rsock));
			cp_sockaddr (&sdatap->laddr, lsock);
			cp_sockaddr (&sdatap->raddr, rsock);
			incr_socket_stats(&sdatap->stats, rec_ptr, syscallbegtm, pidp->elf, logio);
			syscallp = GET_SYSCALLP(&sdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
			update_sched_state(&syscallp->sched_stats, old_state, new_state, delta);
			incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);
			incr_socket_stats(&globals->netstats, rec_ptr, syscallbegtm, pidp->elf, logio);
			socket_global_syscall_stats(rec_ptr, sdatap, pidp, logio, syscallbegtm);
		} else if (global_stats && device && node) {
			fdatap = GET_FDATAP(&globals->fdata_hash, device, node);
			fdatap->stats.syscall_cnt++;
			fdatap->stats.total_time += syscallbegtm;
			fdatap->stats.last_pid = rec_ptr->pid;
			fdatap->dev = device;
			fdatap->node = node;
			fdatap->ftype = ftype;
			if ((fdatap->fnameptr == NULL) && fdinfop->fnamep) {
	                        if ((fdatap->fnameptr = malloc(strlen(fdinfop->fnamep)+1)) == NULL) {
                                        FATAL(errno, "malloc() of fname failed", NULL, -1);
                                }
                                MALLOC_LOG(fdatap->fnameptr, strlen(fdinfop->fnamep)+1);
                                strcpy ((char *)fdatap->fnameptr, fdinfop->fnamep);
			}
				
			if (IS_ERR_VALUE(rec_ptr->ret)) fdatap->stats.errors++;
			/* logical I/Os here */

			syscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
			update_sched_state(&syscallp->sched_stats, old_state, new_state, delta);
			incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, logio);
		}
	}
}

static inline void 
track_submit_ios(syscall_enter_t *rec_ptr, pid_info_t *pidp)
{
	pid_info_t *tgidp;
	ctx_info_t *ctxp;
	iocb_info_t *iocbp;
	uint64 ctx_id = rec_ptr->args[0];
	uint64 nr     = rec_ptr->args[1];
	uint64 iocbpp = rec_ptr->args[2];
	char *varptr = (char *)rec_ptr + sizeof(syscall_enter_t);
	iocbsum_t *iocb = (iocbsum_t *)varptr;
	syscall_info_t *syscallp, *gsyscallp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	int i = 0;
	int fd, oldfd = -1;

	ctxp = GET_CTX(&globals->ctx_hash, ctx_id);
	ctxp->pid = rec_ptr->pid;
	ctxp->syscallno = rec_ptr->syscallno;
	while ((char *)iocb < ((char *)rec_ptr + rec_ptr->reclen)) {
		iocbp =  GET_IOCB(&ctxp->iocb_hash, (uint64)iocb->iocbp);
		iocbp->hrtime = rec_ptr->hrtime;
		iocbp->op = iocb->aio_lio_opcode;
		iocbp->offset = iocb->aio_offset;
		iocbp->fd = iocb->aio_fildes;
		iocbp->bytes = iocb->aio_nbytes;
		iocb++;

		/* We also want to track the io_submit() system calls per fd */
		pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
		fd = iocbp->fd;
		if (perfd_stats && (fd < 65536) && (fd >= 0)) {
			fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
			syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
			if (fd != oldfd) {
				fdinfop->stats.syscall_cnt++;
	 			syscallp->stats.count++;
				if (pidp->tgid && (fdinfop->node == 0) && (fdinfop->ftype == 0)) {
					/* inherit fdinfop from primary thread */
					tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
					if (tfdinfop) fdinfop = tfdinfop;
				}

				if (global_stats && fdinfop->dev && fdinfop->node) {
					fdatap = GET_FDATAP(&globals->fdata_hash, fdinfop->dev, fdinfop->node);
					fdatap->stats.syscall_cnt++;
					fdatap->stats.last_pid = rec_ptr->pid;
					gsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
					gsyscallp->stats.count++;
				}
				oldfd = fd;
			}
		}
	}


	return;
}

int
ki_read(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *tgidp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	uint64 bytes;
	uint64 device=0;
	uint64 node=0, ftype=0;
	uint64 fd;
	int rndio_flag = 0;

	bytes = rec_ptr->ret;
	fd = pidp->last_syscall_args[0];

        if (perfd_stats && (fd < 65536) && (fd >= 0))  {
		fdinfop = GET_FDINFOP(&pidp->fdhash, fd);

                /* this calculate is not necessarily accurate, since we don't
                 * always know which byte we are starting on.  However, we assume
                 * sequential unless we see lseek() system calls.  The lseek will
                 * compare the address to the next_byteno as well as reset the
                 * next_byteno;
                 */

                fdinfop->stats.rd_cnt++;
		if (!IS_ERR_VALUE(rec_ptr->ret)) {
                	fdinfop->next_byteno = fdinfop->next_byteno + bytes;
                	if (fdinfop->rndio_flag)
                        	fdinfop->stats.rndios++;
                	else
                        	fdinfop->stats.seqios++;

                	rndio_flag = fdinfop->rndio_flag;
                	fdinfop->rndio_flag = 0;
		}

		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;

                if (pidp->tgid && node == 0) {
                        /* inherit fdinfop from primary thread */
                        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                        if (tfdinfop) {
                                device = tfdinfop->dev;
                                node = tfdinfop->node;
                                ftype = tfdinfop->ftype;
                        }
                }
	
                /* global per-file stats */
		if (global_stats && fdinfop->lsock) {
                	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(fdinfop->lsock), SIN_PORT(fdinfop->lsock), 
                                                                  SIN_ADDR(fdinfop->rsock), SIN_PORT(fdinfop->rsock));
			cp_sockaddr (&sdatap->laddr, fdinfop->lsock);
			cp_sockaddr (&sdatap->raddr, fdinfop->rsock);
			/* the following is updated in socket_global_syscall_stats */
                	/* sdatap->stats.rd_cnt++; */
        	} else if (global_stats && device && node) {
                	fdatap = GET_FDATAP(&globals->fdata_hash, device, node);
                	fdatap->stats.rd_cnt++;

			if (!IS_ERR_VALUE(rec_ptr->ret)) {
                		if (rndio_flag)
        	                	fdatap->stats.rndios++;
                		else
                        		fdatap->stats.seqios++;
			}
        	}
	}
}

int
ki_pread(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
ki_write(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *tgidp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	uint64 bytes;
	uint64 device=0;
	uint64 node=0, ftype=0;
	uint64 fd;
	int rndio_flag = 0;

	bytes = rec_ptr->ret;
	fd = pidp->last_syscall_args[0];

        if (perfd_stats && (fd < 65536) && (fd >= 0))  {
        	fdinfop = GET_FDINFOP(&pidp->fdhash, fd);

                /* this calculate is not necessarily accurate, since we don't
                 * always know which byte we are starting on.  However, we assume
                 * sequential unless we see lseek() system calls.  The lseek will
                 * compare the address to the next_byteno as well as reset the
                 * next_byteno;
                 */

                fdinfop->stats.wr_cnt++;
		if (!IS_ERR_VALUE(rec_ptr->ret)) {
                	fdinfop->next_byteno = fdinfop->next_byteno + bytes;
                	if (fdinfop->rndio_flag)
                        	fdinfop->stats.rndios++;
                	else
                        	fdinfop->stats.seqios++;

                	rndio_flag = fdinfop->rndio_flag;
                	fdinfop->rndio_flag = 0;
		}

		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;
                if (pidp->tgid && node == 0) {
                        /* inherit fdinfop from primary thread */
                        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                        if (tfdinfop) {
                                device = tfdinfop->dev;
                                node = tfdinfop->node;
                                ftype = tfdinfop->ftype;
                        }
                }
 
                /* global per-file stats */
		if (global_stats && fdinfop->lsock) {
                	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(fdinfop->lsock), SIN_PORT(fdinfop->lsock), 
                                                                  SIN_ADDR(fdinfop->rsock), SIN_PORT(fdinfop->rsock));
			cp_sockaddr (&sdatap->laddr, fdinfop->lsock);
			cp_sockaddr (&sdatap->raddr, fdinfop->rsock);
			/* the following is updated in socket_global_syscall_stats */
                	/* sdatap->stats.wr_cnt++; */
        	} else if (global_stats && device && node) {
                	fdatap = GET_FDATAP(&globals->fdata_hash,device,node);
                	fdatap->stats.wr_cnt++;

			if (!IS_ERR_VALUE(rec_ptr->ret)) {
                		if (rndio_flag)
        	                	fdatap->stats.rndios++;
                		else
                        		fdatap->stats.seqios++;
			}
        	}
	}
}

int
ki_pwrite(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
ki_splice(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *tgidp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	uint64 bytes;
	uint64 device=0;
	uint64 node=0, ftype=0;
	uint64 fd, fd_in, fd_out;
	int rndio_flag = 0;

	bytes = rec_ptr->ret;
	fd_in = pidp->last_syscall_args[0];
	fd_out = pidp->last_syscall_args[2];

	fd = fd_in;
        if (perfd_stats && (fd < 65536) && (fd >= 0))  {
		fdinfop = GET_FDINFOP(&pidp->fdhash, fd);

                /* this calculate is not necessarily accurate, since we don't
                 * always know which byte we are starting on.  However, we assume
                 * sequential unless we see lseek() system calls.  The lseek will
                 * compare the address to the next_byteno as well as reset the
                 * next_byteno;
                 */

                fdinfop->stats.rd_cnt++;
		if (!IS_ERR_VALUE(rec_ptr->ret)) {
                	fdinfop->next_byteno = fdinfop->next_byteno + bytes;
                	if (fdinfop->rndio_flag)
                        	fdinfop->stats.rndios++;
                	else
                        	fdinfop->stats.seqios++;

                	rndio_flag = fdinfop->rndio_flag;
                	fdinfop->rndio_flag = 0;
		}

		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;

                if (pidp->tgid && node == 0) {
                        /* inherit fdinfop from primary thread */
                        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                        if (tfdinfop) {
                                device = tfdinfop->dev;
                                node = tfdinfop->node;
                                ftype = tfdinfop->ftype;
                        }
                }
	
                /* global per-file stats */
		if (global_stats && fdinfop->lsock) {
                	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(fdinfop->lsock), SIN_PORT(fdinfop->lsock), 
                                                                  SIN_ADDR(fdinfop->rsock), SIN_PORT(fdinfop->rsock));
			cp_sockaddr (&sdatap->laddr, fdinfop->lsock);
			cp_sockaddr (&sdatap->raddr, fdinfop->rsock);
                	/* sdatap->stats.rd_cnt++; */
        	} else if (global_stats && device && node) {
                	fdatap = GET_FDATAP(&globals->fdata_hash, device, node);
                	fdatap->stats.rd_cnt++;

			if (!IS_ERR_VALUE(rec_ptr->ret)) {
                		if (rndio_flag)
        	                	fdatap->stats.rndios++;
                		else
                        		fdatap->stats.seqios++;
			}
        	}
	}

	fd = fd_out;
        if (perfd_stats && (fd < 65536) && (fd >= 0))  {

		/* only need this for fd_out, as this is done is sys_exit_func2() for fd_in */
		update_file_stats(rec_ptr, pidp, fd, scalltime, 0, 0, 2);

        	fdinfop = GET_FDINFOP(&pidp->fdhash, fd);

                /* this calculate is not necessarily accurate, since we don't
                 * always know which byte we are starting on.  However, we assume
                 * sequential unless we see lseek() system calls.  The lseek will
                 * compare the address to the next_byteno as well as reset the
                 * next_byteno;
                 */

                fdinfop->stats.wr_cnt++;
		if (!IS_ERR_VALUE(rec_ptr->ret)) {
                	fdinfop->next_byteno = fdinfop->next_byteno + bytes;
                	if (fdinfop->rndio_flag)
                        	fdinfop->stats.rndios++;
                	else
                        	fdinfop->stats.seqios++;

                	rndio_flag = fdinfop->rndio_flag;
                	fdinfop->rndio_flag = 0;
		}

		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;
                if (pidp->tgid && node == 0) {
                        /* inherit fdinfop from primary thread */
                        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                        if (tfdinfop) {
                                device = tfdinfop->dev;
                                node = tfdinfop->node;
                                ftype = tfdinfop->ftype;
                        }
                }
 
                /* global per-file stats */
		if (global_stats && fdinfop->lsock) {
                	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(fdinfop->lsock), SIN_PORT(fdinfop->lsock), 
                                                                  SIN_ADDR(fdinfop->rsock), SIN_PORT(fdinfop->rsock));
			cp_sockaddr (&sdatap->laddr, fdinfop->lsock);
			cp_sockaddr (&sdatap->raddr, fdinfop->rsock);
                	sdatap->stats.wr_cnt++;
        	} else if (global_stats && device && node) {
                	fdatap = GET_FDATAP(&globals->fdata_hash,device,node);
                	fdatap->stats.wr_cnt++;

			if (!IS_ERR_VALUE(rec_ptr->ret)) {
                		if (rndio_flag)
        	                	fdatap->stats.rndios++;
                		else
                        		fdatap->stats.seqios++;
			}
        	}
	}
}

int
ki_lseek(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *tgidp;
	fd_info_t *fdinfop, *tfdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
	uint64 byte_no;
	uint64 device=0;
	uint64 node=0, ftype=0;
	uint64 fd, whence;

	if (IS_ERR_VALUE(rec_ptr->ret)) return 0;

	fd = pidp->last_syscall_args[0];
	byte_no = pidp->last_syscall_args[1];
	whence = pidp->last_syscall_args[2];

        if (perfd_stats && (fd < 65536) && (fd >= 0))  {
        	fdinfop = GET_FDINFOP(&pidp->fdhash, fd);

                fdinfop->stats.lseek_cnt++;
		if (!IS_ERR_VALUE(rec_ptr->ret)) {
		    if (whence == SEEK_SET) {
			if (byte_no != fdinfop->next_byteno) {
				fdinfop->next_byteno = byte_no;
				fdinfop->rndio_flag = 1;
			}
		    } else if (whence == SEEK_CUR) {
			if (byte_no != 0) {
				fdinfop->next_byteno = fdinfop->next_byteno + byte_no;
				fdinfop->rndio_flag = 1;
			}
		   } else if (whence == SEEK_END) {
			/* we cannot tell if this is random or sequential or 
			 * nor can we tell the next_byteno
			 * so we just default to random 
			 */
			fdinfop->next_byteno = 0;
			fdinfop->rndio_flag = 1;
		    }
		}

		device = fdinfop->dev;
		node = fdinfop->node;
		ftype = fdinfop->ftype;

                if (pidp->tgid && node == 0) {
                        /* inherit fdinfop from primary thread */
                        tgidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
                        tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
                        if (tfdinfop) {
                                device = tfdinfop->dev;
                                node = tfdinfop->node;
                                ftype = tfdinfop->ftype;
                        }
                }
 
                /* global per-file stats */
		if (global_stats && fdinfop->lsock) {
                	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(fdinfop->lsock), SIN_PORT(fdinfop->lsock), 
                                                                  SIN_ADDR(fdinfop->rsock), SIN_PORT(fdinfop->rsock));
			cp_sockaddr (&sdatap->laddr, fdinfop->lsock);
			cp_sockaddr (&sdatap->raddr, fdinfop->rsock);
                	/* sdatap->stats.lseek_cnt++; */
		} else if (global_stats && device && node) {
                	fdatap = GET_FDATAP(&globals->fdata_hash,device,node);
                	fdatap->stats.lseek_cnt++;
        	}
	}
}

int
ki_open(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	fd_info_t *fdinfop;
	syscall_info_t *syscallp;
	uint64 fd, pid, syscallno;
	sched_stats_t *sstatp;
	int old_state, new_state;
	uint64 delta;
	ks_action_t *ks_action;

	if (IS_ERR_VALUE(rec_ptr->ret)) return 0;

	fd = rec_ptr->ret;
	syscallno = rec_ptr->syscallno;

        if (perfd_stats && (fd < 65536) && (fd >= 0))  {
		ks_action = &(KS_ACTION(pidp, syscallno));

        	fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
                fdinfop->stats.open_cnt++;
		fdinfop->stats.syscall_cnt++;
		fdinfop->stats.total_time += scalltime;
		fdinfop->stats.max_time = MAX(fdinfop->stats.max_time, scalltime);
		fdinfop->closed = 0;
	
		syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
		incr_syscall_stats(&syscallp->stats, rec_ptr->ret, scalltime, ks_action->logio);

		/* if multi-threaded, we need to change the master threads filename */
		if (pidp->tgid && (pidp->PID != pidp->tgid)) pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);

		if ((fdinfop->fnamep == NULL) && (pidp->last_open_fname)) {
			fdinfop->fnamep = pidp->last_open_fname;
			pidp->last_open_fname = NULL;
		} else if (fdinfop->fnamep && pidp->last_open_fname) {
			if (strcmp(fdinfop->fnamep, pidp->last_open_fname)) {
				FREE(fdinfop->fnamep);
				fdinfop->fnamep = pidp->last_open_fname;
				fdinfop->multiple_fnames++;
				pidp->last_open_fname=NULL;
			}

		}

		FREE(fdinfop->lsock); fdinfop->lsock = NULL;
		FREE(fdinfop->rsock); fdinfop->rsock = NULL;
	}
}

int
ki_close(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	fd_info_t *fdinfop;
	int fd;

	fd = pidp->last_syscall_args[0];
	if ((fd < 65536) && (fd >= 0)) { 
        	fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
		fdinfop->closed = 1;
	}
}

int
ki_io_submit(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}
int
ki_io_getevents(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	char *varptr = (char *)rec_ptr + sizeof(syscall_exit_t);
	pid_info_t *tpidp, *tgidp;
	fd_info_t *fdinfop, *tfdinfop;
	fd_stats_t *fdstatsp, *fdata_statsp;
	fdata_info_t *fdatap;
	syscall_info_t *syscallp, *fsyscallp, *gsyscallp;
	iov_stats_t *iovstatp, *fiovstatp, *giovstatp;
	struct io_event *ioevp = (struct io_event *)varptr;
	ctx_info_t *ctxp;
	iocb_info_t *iocbp;
	uint64 ctx_id;
	uint64 numioev = rec_ptr->ret;
	int i = 0, fd;
	uint64 elp_time;

	if (numioev == 0) return 0;

	ctx_id = pidp->last_syscall_args[0];
	ctxp = FIND_CTX(globals->ctx_hash, ctx_id);
	if (ctxp == NULL) return 0;

	while ((char *)ioevp < ((char *)rec_ptr + rec_ptr->reclen)) {
		iocbp = FIND_IOCB(ctxp->iocb_hash, (uint64)ioevp->obj);
		if (iocbp) {

			/* since we only log 32 IOCB, we can miss some, especially with the ORACLE
			 * DB writer that can submit 100s of IOs.   So if the IO size doesn't match
			 * then lets tjust skip it.  This is only true for PWRITE and PREAD operations.
			 * However, if PWRITEV and PREADV operations, bytes on the io_submit() represent
			 * the size of the iov array, but res is the number of bytes transferred, so they
			 * will never be equal.   
			 */
			if (((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PREAD)) && 
			    (ioevp->res != iocbp->bytes)) { 
				/*
				PRINT_COMMON_FIELDS(rec_ptr);
				printf (" ** Incomplete AIO - ctx_id: 0x%llx IOEV[%d] iocbp=0x%llx bytes: %lld res=%lld\n", 
					ctx_id, i, ioevp->obj, iocbp->bytes, ioevp->res);
				*/

					FIND_AND_REMOVE_IOCB(&ctxp->iocb_hash, (uint64)(ioevp->obj));
					continue;
			}	

			/* we need to increment the process FD stats and syscall stats.
			 * we also need to increment the global file stats
			 */
			elp_time = rec_ptr->hrtime - iocbp->hrtime;
			tpidp = GET_PIDP(&globals->pid_hash, ctxp->pid);
			syscallp = GET_SYSCALLP(&tpidp->scallhash, SYSCALL_KEY(tpidp->elf, 0ul, ctxp->syscallno));
			iovstatp = GET_IOV_STATSP(&syscallp->iov_stats);
			if ((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PWRITEV)) {
				iovstatp->wr_bytes += ioevp->res;
				iovstatp->wr_cnt++;
				iovstatp->wr_time += elp_time;
				iovstatp->wr_max_time = MAX(iovstatp->wr_max_time, elp_time);
			} else if ((iocbp->op==IOCB_CMD_PREAD) || (iocbp->op==IOCB_CMD_PREADV)) {
				iovstatp->rd_bytes += ioevp->res;
				iovstatp->rd_cnt++;
				iovstatp->rd_time += elp_time;
				iovstatp->rd_max_time = MAX(iovstatp->rd_max_time, elp_time);
			} 

			fd = iocbp->fd;
			if (perfd_stats && (fd < 65536) && (fd >= 0)) {
				fdinfop = GET_FDINFOP(&tpidp->fdhash, fd);
				fdstatsp = &fdinfop->stats;
				if ((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PWRITEV)) {
					fdstatsp->wr_bytes += ioevp->res;
					fdstatsp->wr_cnt++;
					fdstatsp->total_time += elp_time;
					fdstatsp->max_time = MAX(fdstatsp->max_time, elp_time);
				} else if ((iocbp->op==IOCB_CMD_PREAD) || (iocbp->op==IOCB_CMD_PREADV)) {
					fdstatsp->rd_bytes += ioevp->res;
					fdstatsp->rd_cnt++;
					fdstatsp->total_time += elp_time;
					fdstatsp->max_time = MAX(fdstatsp->max_time, elp_time);
				}
				fdstatsp->total_time += elp_time;
				fdstatsp->max_time = MAX(fdstatsp->max_time,  elp_time);

				fsyscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, ctxp->syscallno));
				fiovstatp = GET_IOV_STATSP(&fsyscallp->iov_stats);
				if ((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PWRITEV)) {
					fiovstatp->wr_bytes += ioevp->res;
					fiovstatp->wr_cnt++;
					fiovstatp->wr_time += elp_time;
					fiovstatp->wr_max_time = MAX(iovstatp->wr_max_time, elp_time);
				} else if ((iocbp->op==IOCB_CMD_PREAD) || (iocbp->op==IOCB_CMD_PREADV)) {
					fiovstatp->rd_bytes += ioevp->res;
					fiovstatp->rd_cnt++;
					fiovstatp->rd_time += elp_time;
					fiovstatp->rd_max_time = MAX(iovstatp->rd_max_time, elp_time);
				} 

				if (tpidp->tgid && (fdinfop->node == 0) && (fdinfop->ftype == 0)) {
					/* inherit fdinfop from primary thread */
					tgidp = GET_PIDP(&globals->pid_hash, tpidp->tgid);
					tfdinfop = (fd_info_t *)find_entry((lle_t **)tgidp->fdhash, fdinfop->FD, FD_HASH(fdinfop->FD));
					if (tfdinfop) fdinfop = tfdinfop;
				}

				if (global_stats && fdinfop->dev && fdinfop->node) {
					fdatap = GET_FDATAP(&globals->fdata_hash, fdinfop->dev, fdinfop->node);
					fdata_statsp = &fdatap->stats;
					if ((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PWRITEV)) {
						fdata_statsp->wr_bytes += ioevp->res;
						fdata_statsp->wr_cnt++;
						fdata_statsp->total_time += elp_time;
						fdata_statsp->max_time = MAX(fdata_statsp->max_time, elp_time);
					} else if ((iocbp->op==IOCB_CMD_PREAD) || (iocbp->op==IOCB_CMD_PREADV)) {
						fdata_statsp->rd_bytes += ioevp->res;
						fdata_statsp->rd_cnt++;
						fdata_statsp->total_time += elp_time;
						fdata_statsp->max_time = MAX(fdata_statsp->max_time, elp_time);
					} 
					
					gsyscallp = GET_SYSCALLP(&fdatap->syscallp, SYSCALL_KEY(tpidp->elf, 0ul, ctxp->syscallno));					
					giovstatp = GET_IOV_STATSP(&gsyscallp->iov_stats);
					if ((iocbp->op==IOCB_CMD_PWRITE) || (iocbp->op==IOCB_CMD_PWRITEV)) {
						giovstatp->wr_bytes += ioevp->res;
						giovstatp->wr_cnt++;
						giovstatp->wr_time += elp_time;
						giovstatp->wr_max_time = MAX(giovstatp->wr_max_time, elp_time);
					} else if ((iocbp->op==IOCB_CMD_PREAD) || (iocbp->op==IOCB_CMD_PREADV)) {
						giovstatp->rd_bytes += ioevp->res;
						giovstatp->rd_cnt++;
						giovstatp->rd_time += elp_time;
						giovstatp->rd_max_time = MAX(giovstatp->rd_max_time, elp_time);
					}
				}
			}

			FIND_AND_REMOVE_IOCB(&ctxp->iocb_hash, (uint64)(ioevp->obj));
		}	
		i++;
		ioevp++;	
	}
}

/* create child pid (npid) structures and initialize stats */
int
ki_clone(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *npidp;
	uint64 npid;

	if (rec_ptr->ret <= 0) return 0;

	npidp = GET_PIDP(&globals->pid_hash, rec_ptr->ret);
	npidp->ppid = pidp->PID;

	if (pidp->cmd) {
		repl_command(&npidp->cmd, pidp->cmd);
	}
}

int
ki_fork(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
ki_execve(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;

        if (IS_ERR_VALUE(rec_ptr->ret)) return 0;

	if ((pidp->cmd == NULL) && (pidp->last_exec_fname)) {
		pidp->cmd = pidp->last_exec_fname;
		pidp->last_exec_fname = NULL;
	} else if (pidp->cmd && pidp->last_exec_fname) {
		if (strcmp(pidp->cmd, pidp->last_exec_fname)) {
			FREE(pidp->cmd);
			pidp->cmd = pidp->last_exec_fname;
			pidp->last_exec_fname=NULL;
		}
	}
	
} 

int
ki_recvfrom(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
ki_sendto(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
ki_readahead(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

int
dup_filename(pid_info_t *pidp, int fd1, int fd2)
{
	fd_info_t	*fd1infop, *fd2infop;

	if (fd1 == fd2) return 0;
	if ((fd1 < 0) || (fd2 < 0)) return 0;

	/*   if mult-threaded, change the filename of the TGID */
	if (pidp->tgid && (pidp->tgid != pidp->PID)) pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);

	fd1infop = GET_FDINFOP(&pidp->fdhash, fd1);
	fd2infop = GET_FDINFOP(&pidp->fdhash, fd2);	
	if (fd1infop->fnamep) {
		if (fd2infop->fnamep) {
			/* for the dup2 case, the newfd may have an old name, so let's free it first */
			FREE(fd2infop->fnamep);
			fd2infop->multiple_fnames++;
			fd2infop->fnamep = NULL;
		}
		if (fd2infop->fnamep = malloc(strlen(fd1infop->fnamep)+1)) {	
			strcpy(fd2infop->fnamep, fd1infop->fnamep);
		}
		MALLOC_LOG(fd2infop->fnamep, strlen(fd1infop->fnamep)+1);
	}
	fd2infop->dev = fd1infop->dev;
	fd2infop->node = fd1infop->node;
	fd2infop->ftype = fd1infop->ftype;

	/* duplicate socket info if it exists
	 * if there is sock info for new fd release it.
	 * if there is sock info for old fd, copy it
	 */
	FREE(fd2infop->lsock); fd2infop->lsock = NULL;
	FREE(fd2infop->rsock); fd2infop->rsock = NULL;
	if (fd1infop->lsock && fd1infop->rsock) {
		fd2infop->lsock = calloc(1, sizeof(struct sockaddr_in));
		CALLOC_LOG(fd2infop->lsock, 1, sizeof(struct sockaddr_in));
		fd2infop->rsock = calloc(1, sizeof(struct sockaddr_in));
		CALLOC_LOG(fd2infop->rsock, 1, sizeof(struct sockaddr_in));
		memcpy(fd2infop->lsock, fd1infop->lsock, sizeof(struct sockaddr_in));
		memcpy(fd2infop->rsock, fd1infop->rsock, sizeof(struct sockaddr_in));
	}

	return 0;
}


int
ki_dup(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;

	if (IS_ERR_VALUE(rec_ptr->ret)) return 0; 
	dup_filename(pidp, pidp->last_syscall_args[0], rec_ptr->ret);
}

int
ki_dup2(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
	pid_info_t *tgidp;

	if (IS_ERR_VALUE(rec_ptr->ret)) return 0; 
	if (rec_ptr->ret != pidp->last_syscall_args[1]) return 0;

	dup_filename(pidp, pidp->last_syscall_args[0], pidp->last_syscall_args[1]);
}

int
ki_fcntl(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;

	if (IS_ERR_VALUE(rec_ptr->ret)) return 0; 

	/* if F_DUPFD fcntl() then propgate the filename to the duped file */
	if (pidp->last_syscall_args[1] == F_DUPFD) {
		dup_filename(pidp, pidp->last_syscall_args[0], rec_ptr->ret);
	}
}

static inline void
incr_pid_futex_stats(syscall_exit_t *rec_ptr, pid_info_t *pidp, pid_futex_info_t *futexp, uint64 scalltime)
{
	futex_op_t *fopsp;
	futex_reque_t *requep;
	uint64 uaddr1, op, uaddr2;
	int64 ret = (int64)rec_ptr->ret;
	int tgid = 0;

        uaddr1 =  pidp->last_syscall_args[0];
        op     =  pidp->last_syscall_args[1];
        uaddr2 =  pidp->last_syscall_args[4];

	if (op & FUTEX_PRIVATE_FLAG) tgid = pidp->tgid;
	futexp->addr = uaddr1;
	futexp->cnt++;
	futexp->total_time += scalltime;
	if (scalltime > futexp->max_time) {
		futexp->max_time = scalltime;
		futexp->max_waker = futexp->last_waker;
	}

	fopsp = GET_FOPSP(&futexp->ops_hash, op);
	fopsp->cnt++;
	fopsp->total_time += scalltime;
	if (scalltime > fopsp->max_time) {
		fopsp->max_time = scalltime;
		fopsp->max_waker = futexp->last_waker;
	}

	if (IS_REQUEUE(op)) {
		requep = GET_RQFUTEXP(&futexp->uaddr2_hash,FUTEX_KEY(tgid, uaddr2));
		requep->cnt ++;
		requep->addr = uaddr2;
	}

	if ((int64)ret >= 0) {
		fopsp->ret_total += ret;
	} else if (ret == -11 ) {
		fopsp->n_eagain++;
	} else if (ret == -110 ) {
		fopsp->n_etimedout++;
	} else {
		fopsp->n_othererr++;
	}

#if DEBUG
	{
	pid_info_t *wpidp;
	if (!(op & FUTEX_PRIVATE_FLAG)) {
        	wpidp = GET_PIDP(&globals->pid_hash, futexp->last_waker);
		if ((pidp->tgid == wpidp->tgid) && (uaddr1 == futexp->last_waker_uaddr1)) {
			printf(stdout,"FUTEX 0x%llx shared by pids %d and %d is not using FUTEX_PRIVATE_FLAG \n",
				uaddr1, pidp->PID, futexp->last_waker);
		}
       	}
#endif
}

static inline void 
incr_gbl_futex_stats(syscall_exit_t *rec_ptr, pid_info_t *pidp, gbl_futex_info_t *futexp, uint64 scalltime, uint32 last_waker)
{
	futex_op_t *fopsp;
	futex_reque_t *requep;
	futex_pids_t *fpidp;
	futex_pids_t *foppidp;
	uint64 uaddr1, op, uaddr2;
	int64 ret = (int64)rec_ptr->ret;
	int tgid = 0;

        uaddr1 =  pidp->last_syscall_args[0];
        op     =  pidp->last_syscall_args[1];
        uaddr2 =  pidp->last_syscall_args[4];

	if (op & FUTEX_PRIVATE_FLAG) tgid = pidp->tgid;
	futexp->addr = uaddr1;
	futexp->cnt++;
	futexp->total_time += scalltime;
	if (scalltime > futexp->max_time) {
		futexp->max_time = scalltime;
		futexp->max_waker = last_waker;
	}

	fopsp = GET_FOPSP(&futexp->ops_hash, op);
	fopsp->cnt++;
	fopsp->total_time += scalltime;
	if (scalltime > fopsp->max_time) {
		fopsp->max_time = scalltime;
		fopsp->max_waker = last_waker;
	}

	if (IS_REQUEUE(op)) {
		requep = GET_RQFUTEXP(&futexp->uaddr2_hash,FUTEX_KEY(tgid, uaddr2));
		requep->cnt ++;
		requep->addr = uaddr2;
	}

        fpidp = GET_FPIDP(&futexp->pids_hash,rec_ptr->pid);
	fpidp->cnt++;
	fpidp->total_time += scalltime;
        if (scalltime > fpidp->max_time) {
                fpidp->max_time = scalltime;
                fpidp->max_waker =  last_waker;
        }

        foppidp = GET_FPIDP(&fopsp->pids_hash,rec_ptr->pid);
	foppidp->cnt++;
        foppidp->total_time += scalltime;
	if (scalltime > foppidp->max_time) {
		foppidp->max_time  = scalltime;
		foppidp->max_waker =  last_waker;
        }

	if (ret >= 0) {
		futexp->ret_total += ret;
		fopsp->ret_total += ret;
		fpidp->ret_total += ret;
		foppidp->ret_total += ret;
	} else if ((int64)rec_ptr->ret == -11 ) {
		futexp->n_eagain++;
		fopsp->n_eagain++;
		fpidp->n_eagain++;
		foppidp->n_eagain++;
	} else if ((int64)rec_ptr->ret == -110 ) {
		futexp->n_etimedout++;
		fopsp->n_etimedout++;
		fpidp->n_etimedout++;
		foppidp->n_etimedout++;
	} else {
		futexp->n_othererr++;
		fopsp->n_othererr++;
		fpidp->n_othererr++;
		foppidp->n_othererr++;
	}

	/* if (uaddr1 == 0x7d0a6a033c54) { 	
		printf ("ftuexp: 0x%llx uaddr=0x%llx tgid=%d cnt=%d n_eagain=%d op=0x%llx\n", futexp, uaddr1, tgid, futexp->cnt, futexp->n_eagain, op); } */
}

int
ki_futex(void *arg1, void *arg2, uint64 scalltime)
{
        syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
	pid_info_t *pidp = (pid_info_t *)arg2;
        pid_futex_info_t *pid_futex_infop;
        gbl_futex_info_t *gbl_futex_infop;
	uint64 uaddr1, op;
	int tgid = 0;

	if (futex_stats == 0) return 0;

	uaddr1 =	pidp->last_syscall_args[0];
	op =		pidp->last_syscall_args[1];
	if (rec_ptr->tgid && (pidp->tgid == 0)) pidp->tgid = rec_ptr->tgid;
	if (op & FUTEX_PRIVATE_FLAG) tgid = rec_ptr->tgid;

        /* Take care of the per-pid stats first */
        pid_futex_infop = GET_FUTEXP(&pidp->futex_hash,FUTEX_KEY(tgid, uaddr1));
	if (perpid_stats) {
		incr_pid_futex_stats(rec_ptr, pidp, pid_futex_infop, scalltime);
	}

        /* Now take care of the global stats */
	if (global_stats) {
        	gbl_futex_infop = GET_GFUTEXP(&globals->futex_hash,FUTEX_KEY(tgid,uaddr1));
		incr_gbl_futex_stats(rec_ptr, pidp, gbl_futex_infop, scalltime, pid_futex_infop->last_waker);
	} 

        pid_futex_infop->last_waker = 0;
        pid_futex_infop->last_waker_uaddr1 = 0;
}

int
ki_nosys(void *arg1, void *arg2, uint64 scalltime)
{ 
	syscall_exit_t *rec_ptr = (syscall_exit_t *)arg1;
}

static inline int 
print_pollfds(char *varptr, int nfds)
{
	int i;
        char *str = util_str;
	struct pollfd *ptr = (struct pollfd *)varptr;
	for (i = 0; i < nfds; i++) {
		printf ("%cpollfd[%d]={%ld 0x%hx 0x%hx", fsep, i, ptr[i].fd, ptr[i].events, ptr[i].revents);
		if (ptr[i].revents != 0) {	
        		str[0] = 0;
			if (ptr[i].revents & 0x8000) strcat(str,"POLL_BUSY_LOOP|");
			if (ptr[i].revents & 0x2000) strcat(str,"POLLRDHUP|");
			if (ptr[i].revents & 0x1000) strcat(str,"POLLREMOVE|");
			if (ptr[i].revents & 0x400) strcat(str,"POLLMSG|");
			if (ptr[i].revents & 0x200) strcat(str,"POLLWRBAND|");
			if (ptr[i].revents & 0x100) strcat(str,"POLLWRNORM|");
			if (ptr[i].revents & 0x80) strcat(str,"POLLRDBAND|");
			if (ptr[i].revents & 0x40) strcat(str,"POLLRDNORM|");
			if (ptr[i].revents & 0x20) strcat(str,"POLLNVAL|");
			if (ptr[i].revents & 0x10) strcat(str,"POLLHUP|");
			if (ptr[i].revents & 0x8) strcat(str,"POLLERR|");
			if (ptr[i].revents & 0x4) strcat(str,"POLLOUT|");
			if (ptr[i].revents & 0x2) strcat(str,"POLLPRI|");
			if (ptr[i].revents & 0x1) strcat(str,"POLLIN|");

        		if (strlen(str)) {
		                str[strlen(str)-1] = 0;
				printf("/%s", str);
        		}
		}
		printf ("}");
	}
}

static inline int 
print_iocbs(syscall_enter_t *rec_ptr, char *varptr)
{
	iocbsum_t *iocb = (iocbsum_t *)varptr;
	int i = 0;

	while ((char *)iocb < ((char *)rec_ptr + rec_ptr->reclen)) {
		printf ("%cIOCB[%d]: iocbp=0x%llx fd=%d op=%d bytes=%lld offset=0x%llx", fsep,
			i, iocb->iocbp, iocb->aio_fildes, iocb->aio_lio_opcode, iocb->aio_nbytes, iocb->aio_offset);
		i++;
		iocb++;
	}
}

static inline int 
print_io_events(syscall_exit_t *rec_ptr, char *varptr)
{
	struct io_event *ioevp = (struct io_event *)varptr;
	int i = 0;
		
	while ((char *)ioevp < ((char *)rec_ptr + rec_ptr->reclen)) {
		printf ("%cIOEV[%d]: iocbp=0x%llx res=%lld", fsep,
			i, ioevp->obj, ioevp->res);
		i++;
		ioevp++;
	}
}

static inline int 
print_fd_set(char *label, char *varptr, int fds_bytes)
{
	int i;

	printf ("%c%s0x", fsep, label);	
	for (i = fds_bytes - 1; i >= 0; i--) {
		printf ("%02hhx", varptr[i]);
	}
}

static inline int 
print_varargs_enter(syscall_enter_t *rec_ptr)
{
	char *varptr = (char *)rec_ptr + sizeof(syscall_enter_t);
	int varlen = rec_ptr->reclen - sizeof(syscall_exit_t) ;
	int nfds;
	int fds_bytes;
	struct timeval *t;
	struct sockaddr_in *lsock;
	struct sockaddr_in *rsock;

	switch (rec_ptr->syscallno) {
		case __NR_open :
		case __NR_openat :
		case __NR_stat :
		case __NR_creat : 
		case __NR_access : 
		case __NR_lstat :
		case __NR_unlink :
		case __NR_unlinkat :
		case __NR_execve : 
			printf ("%cfilename: %s", fsep, varptr);
			break;
		case __NR_select :
		case __NR_pselect6 :
			nfds = rec_ptr->args[0];
			fds_bytes = (nfds/8) + (nfds & 07ULL ? 1 : 0);
			t = (struct timeval *)varptr;
			printf ("%ctimeout=%d.%06d", fsep, t->tv_sec, t->tv_usec);

			if (fds_bytes) {
				varptr+= sizeof (struct timeval);
				print_fd_set("readfds=", varptr, fds_bytes);
				varptr+= fds_bytes;
				print_fd_set("writefds=", varptr, fds_bytes);
				varptr+= fds_bytes;
				print_fd_set("exceptfds=", varptr, fds_bytes);
			}
			break;
		case __NR_ppoll :
			t = (struct timeval *)varptr;
			printf ("%ctimeout=%d.%06d", fsep, t->tv_sec, t->tv_usec);
			varptr+= sizeof(struct timeval);
		case __NR_poll :
			nfds = rec_ptr->args[1];
			if (nfds) {
				print_pollfds(varptr, nfds);
			}
			break;
		case __NR_io_submit :
			print_iocbs(rec_ptr, varptr);
			break;
		default:
			fprintf(stderr, "Unexpected syscallno %d (entry), cannot format variable arguments.  Skipping...\n", rec_ptr->syscallno);
	}
}

static inline int 
print_varargs_exit(syscall_exit_t *rec_ptr)
{
	char *varptr = (char *)rec_ptr + sizeof(syscall_exit_t);
	int varlen = rec_ptr->reclen - sizeof(syscall_exit_t) ;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	char *ptr;
	fileaddr_t *faddr;
	int nfds;
	int fds_bytes;
	unsigned int dev;
	int i;
	short *st_addr;
	short sock_type = 0;

	switch (rec_ptr->syscallno) {
#ifndef __NR_sendmmsg
#define __NR_sendmmsg 307
#define __NR_recvmmsg 299
#endif
		case __NR_recvmmsg :
		case __NR_sendmmsg :	
			printf ("%cbytes=%lld", fsep, *(unsigned long *)varptr);
			varptr += sizeof(unsigned long);
			/* fall through to print socket addresses */
		case __NR_recvfrom:
		case __NR_sendto:
		case __NR_recvmsg:
		case __NR_sendmsg:
		case __NR_read:
		case __NR_readv:
		case __NR_pread64:
		case __NR_write :
		case __NR_writev :
		case __NR_pwrite64:
#if 0
			for (ptr=varptr, i=0; i < varlen; i++) {
				printf ("%02hhx", ptr[i]);
			}
#endif
			addr = (struct sockaddr_in *)varptr;
			if (addr->sin_family == AF_INET) {
				st_addr = (short *)(varptr + sizeof(struct sockaddr_in)*2);
				if (varlen > (sizeof(struct sockaddr_in) * 2)) {
					sock_type = *st_addr;
				}

				printf ("%cfamily=INET", fsep);
				if ((sock_type > 0) && (sock_type < 11)) printf ("%ctype=%s", fsep, socktype_name_index[sock_type]);
				printf ("%cL=", fsep); print_ip_port (addr, 1, NULL);
				if ((sock_type==0) || (sock_type != SOCK_DGRAM)) {
					addr++;
					printf ("%cR=", fsep); print_ip_port (addr, 1, NULL);
				}
			} else if (addr->sin_family == AF_REGFILE) {
				faddr = (fileaddr_t *)addr;
				dev = (unsigned int)faddr->dev;
				printf ("%ctype=REG%cdev=0x%08x%cino=%lu", fsep, 
					fsep, dev, fsep, faddr->i_ino);
			} else if (addr->sin_family == AF_INET6) {
				st_addr = (short *)(varptr + sizeof(struct sockaddr_in6)*2);
				if (varlen > (sizeof(struct sockaddr_in6) * 2)) {
					sock_type = *st_addr;
				}

				printf ("%cfamily=INET6", fsep);
				addr6 = (struct sockaddr_in6 *)addr; 
				if ((sock_type > 0) && (sock_type < 11)) printf ("%ctype=%s", fsep, socktype_name_index[sock_type]);
				printf ("%cL=", fsep); print_ip_port_v6 (addr6, 1, NULL);
				if ((sock_type==0) || (sock_type != SOCK_DGRAM)) {
					addr6++;
					printf ("%cR=", fsep); print_ip_port_v6 (addr6, 1, NULL);
				}
			}

			break;
		case __NR_io_getevents :
			print_io_events(rec_ptr, varptr);
			break;
		case __NR_poll : 
		case __NR_ppoll :
			nfds = varlen / sizeof(struct pollfd);
			if (nfds) {
				print_pollfds(varptr, nfds);
			}
			break;
		case __NR_select :
		case __NR_pselect6 :
			fds_bytes = (nfds/8) + (nfds & 07ULL ? 1 : 0);

			if (fds_bytes) {
				print_fd_set("readfds=", varptr, fds_bytes);
				varptr+= fds_bytes;
				print_fd_set("writefds=", varptr, fds_bytes);
				varptr+= fds_bytes;
				print_fd_set("exceptfds=", varptr, fds_bytes);
			}

			break;
		default:
			fprintf(stderr, "Unexpected syscallno %d (exit), cannot format variable arguments.  Skipping...\n", rec_ptr->syscallno);
	}
}

static inline int
print_syscall_retval(pid_info_t *pidp, int syscallno, uint64 retval)
{
	short idx;
        if ((syscallno < 0) || IS_ERR_VALUE(retval)) {               
        	printf ("%cret=%lld", fsep, retval);   
		return 0;
	}

	idx = pidp->syscall_index[syscallno];
	if (syscall_arg_list[idx].retval.format == DECIMAL)  {
       		printf ("%c%s=%lld", fsep, syscall_arg_list[idx].retval.label,  retval);
        } else {
        	printf ("%c%s=0x%llx", fsep, syscall_arg_list[idx].retval.label,  retval);
	}
	return 0;
}

static inline int
print_syscall_args(pid_info_t *pidp, int syscallno, uint64 *args)
{
        int i;
	short idx;
	uint64 argval;
	char *label;
	int format;

	idx = pidp->syscall_index[syscallno];
        for (i=0; i < MAXARGS; i++) {
		label = syscall_arg_list[idx].args[i].label;
		format = syscall_arg_list[idx].args[i].format;
		argval = args[i];
		if (sysargs_flag) {
			switch (format) {
				case SKIP: 		break;
				case DECIMAL:		printf ("%c%s=%i", fsep, label,  (int32)argval); break;
				case HEX:		printf ("%c%s=0x%llx", fsep, label,  argval); break;
				case OCTAL:		if (argval < 0xffffffff) 
								/* check for valid Octal number.  Argument may be optional */
								printf ("%c%s=0%llo", fsep, label, argval); break;
				case FUTEX_VAL3:	printf ("%c%s=0x%llx", fsep, label,  argval); 
							if ((args[1] == FUTEX_WAKE_OP) || (args[1] == FUTEX_WAKE_OP_PRIVATE)) 
								arg_actions[format].func(argval);
							break;
				default:
					printf ("%c%s=%s", fsep, label, arg_actions[format].func(argval)); 
					break;
			}
		} else if (format == DECIMAL) {
			printf (" A%d=%i", i,  (int32)argval); continue;
		} else {
			printf (" A%d=0x%llx", i,  argval); continue;
                }
        }

        return 0;
}

static inline int
print_sys_enter_rec(void *a, void *p)
{
        syscall_enter_t *rec_ptr = (syscall_enter_t *)a;
        pid_info_t *pidp = (pid_info_t *)p;

        PRINT_COMMON_FIELDS(rec_ptr);
        printf ("%c", fsep);
        PRINT_SYSCALL(pidp, rec_ptr->syscallno);
        printf ("%c[%d]%centry", fsep, rec_ptr->syscallno, fsep);
        print_syscall_args(pidp, rec_ptr->syscallno, &rec_ptr->args[0]);
        if (rec_ptr->reclen > sizeof(syscall_enter_t)) {
                /* Need to code for poll() and other arguments, only works for 64 bit processes */
		pidp->elf = ELF64;
                print_varargs_enter(rec_ptr);
        }
        printf ("\n");
        return 0;
}

static inline int
print_sys_exit_rec(void *a, void *p)
{
        syscall_exit_t *rec_ptr = (syscall_exit_t *)a;
        pid_info_t *pidp = (pid_info_t *)p;
        uint64 syscallbegtm;

        PRINT_COMMON_FIELDS(rec_ptr);

        if (rec_ptr->syscallno == -1) {
                printf ("%cukn [-1] ret=0x%llx", fsep, rec_ptr->ret);

        } else if (pidp->last_syscall_time && (pidp->last_syscall_id == rec_ptr->syscallno)) {
                /* check to see if last system call enter is the same */
                syscallbegtm = rec_ptr->hrtime - pidp->last_syscall_time;
                printf ("%c", fsep);
                PRINT_SYSCALL(pidp, rec_ptr->syscallno);
                printf ("%c[%d]", fsep, rec_ptr->syscallno);
                print_syscall_retval(pidp, rec_ptr->syscallno, rec_ptr->ret);
                if (abstime_flag) 
			printf ("%csyscallbeg=%12.09f", fsep, SECS(syscallbegtm));
                else 
			printf ("%csyscallbeg=%12.06f", fsep, SECS(syscallbegtm));
                print_syscall_args(pidp, rec_ptr->syscallno, &pidp->last_syscall_args[0]);
                /* printf (" reclen: %d, size: %d, elf: %d", rec_ptr->reclen, sizeof(syscall_exit_t), pidp->elf);  */
                if (rec_ptr->reclen > sizeof(syscall_exit_t)) {
                        /* Need to code for poll() and other arguments, only works for 64 bit processes */
			pidp->elf = ELF64;
                        print_varargs_exit(rec_ptr);
                }
        } else {
                /* we have a different syscall on enter than exit.  Assume we missed the enter */
                printf ("%c", fsep);
                PRINT_SYSCALL(pidp, rec_ptr->syscallno);
                printf ("%c[%d]", fsep, rec_ptr->syscallno);
                print_syscall_retval(pidp, rec_ptr->syscallno, rec_ptr->ret);
        }
        printf ("\n");
        return 0;
}

static inline int
sys_enter_func2(void *a)
{
	syscall_enter_t *rec_ptr = (syscall_enter_t *)a;
        pid_info_t *pidp, *tgidp;
	sched_info_t *schedp, *gschedp;
	cpu_info_t *cpuinfop;
	syscall_info_t *syscallp;	
	sched_stats_t *statp;
	fd_info_t *fdinfop;
	char *fnamestr;
	int old_state, new_state;
	uint64 delta;
	ks_action_t *ks_action;
	int fd;

        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	if (pertrc_stats) incr_trc_stats(rec_ptr, pidp);

	if (rec_ptr->syscallno < 0) {
		if (kitrace_flag) print_sys_enter_rec(rec_ptr, pidp);
		return 0;
	}

	SET_KS_ACTIONS(pidp, rec_ptr->is32bit);
	ks_action = &(KS_ACTION(pidp, rec_ptr->syscallno));

	/* update per-pid stats */
	schedp = (sched_info_t *)find_sched_info(pidp);
	statp = &schedp->sched_stats;

	/* these are the fields needed for the rest of the calculations */
	old_state = statp->state;
	new_state = RUNNING | SYS;

	/* update state of current PID */
	delta = update_sched_time(statp, rec_ptr->hrtime);
        update_sched_state(statp, old_state, new_state, delta);
	update_sched_cpu(schedp, rec_ptr->cpu);

	schedp->cur_wakeup_cnt = 0;
        pidp->last_syscall_id = rec_ptr->syscallno;
        pidp->last_syscall_time = rec_ptr->hrtime;
        memcpy(&pidp->last_syscall_args[0], &rec_ptr->args[0], MAXARGS * sizeof(uint64));

	/* update per-syscall stats */
	if (perpid_stats && scall_stats) {
		syscallp = GET_SYSCALLP(&pidp->scallhash, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
		delta = update_sched_time(&syscallp->sched_stats, rec_ptr->hrtime);
		update_sched_state(&syscallp->sched_stats, RUNNING | USER, RUNNING | SYS, 0);
	}

	/* update per-FD syscall statistics */
	if (perpid_stats && perfd_stats && scall_stats && (ks_action->scallop & FILEOP)) {
		fd =  pidp->last_syscall_args[0]; 		/* FD is first argument */
		if ((fd < 65536) && (fd >= 0))  {
			fdinfop = GET_FDINFOP(&pidp->fdhash, fd);
			syscallp = GET_SYSCALLP(&fdinfop->syscallp, SYSCALL_KEY(pidp->elf, 0ul, rec_ptr->syscallno));
			delta = update_sched_time(&syscallp->sched_stats, rec_ptr->hrtime);
			update_sched_state(&syscallp->sched_stats, RUNNING | USER, RUNNING | SYS, 0);
		}
	}

	/* update percpu stats */
	if (percpu_stats) {
		cpuinfop = GET_CPUP(&globals->cpu_hash, rec_ptr->cpu);
		schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
		delta = update_sched_time(&schedp->sched_stats, rec_ptr->hrtime);
		update_sched_state(&schedp->sched_stats, schedp->sched_stats.state, new_state, delta);
	}


	/* we need to do special processing for variable length syscall_enter records */
	if (perfd_stats && scall_stats && (ks_action->execute && rec_ptr->reclen > sizeof(syscall_enter_t))) {
		if (ks_action->func == ki_open) {
                	/* Need to code for poll() and other arguments */
	
			if (pidp->last_open_fname) {
				FREE(pidp->last_open_fname);
				pidp->last_open_fname = NULL;
			}
			fnamestr = (char *)rec_ptr + sizeof(syscall_enter_t);
               		pidp->last_open_fname = malloc(strlen(fnamestr)+4);
               		if (pidp->last_open_fname == NULL) {
				FATAL(errno,"malloc() of fname failed", NULL, -1);
			}
			MALLOC_LOG(pidp->last_open_fname, strlen(fnamestr)+4);
               		strcpy ((char *)pidp->last_open_fname, fnamestr);
		} else if (ks_action->func == ki_execve) {
			if (pidp->last_exec_fname) {
				FREE(pidp->last_exec_fname);
				pidp->last_exec_fname = NULL;
			}
			fnamestr = (char *)rec_ptr + sizeof(syscall_enter_t);
               		pidp->last_exec_fname = malloc(strlen(fnamestr)+4);
               		if (pidp->last_exec_fname == NULL) {
				FATAL(errno,"malloc() of fname failed", NULL, -1);
			}
			MALLOC_LOG(pidp->last_exec_fname, strlen(fnamestr)+4);
               		strcpy ((char *)pidp->last_exec_fname, fnamestr);
		} else if (ks_action->func == ki_io_submit) {	
			track_submit_ios(rec_ptr, pidp);
		}
	}

	if (kitrace_flag) print_sys_enter_rec(rec_ptr, pidp);
	return 0;
}

/* this is replaced by pid_update_fdinfo */
#if 0
static inline void 
socket_update_fdinfo(void *arg1, void *arg2)
{
	syscall_exit_t *rec_ptr =  (syscall_exit_t *)arg1;
	fd_info_t *fdinfop = (fd_info_t *)arg2;
	struct sockaddr_in *addr, *lsock_src, *rsock_src;
	struct sockaddr_in6 *lsock_dest, *rsock_dest;
	struct sockaddr_in6 *lsock_src6, *rsock_src6;
	unsigned long bytes;
	char *varptr;

	printf ("socket_update_fdinfo BEGIN\n");
	/* printf ("socket_update_fdinfo() rec_ptr: 0x%llx  reclen: %d %d\n", rec_ptr, rec_ptr->reclen, sizeof(syscall_exit_t));  */
	if (rec_ptr->reclen <= sizeof(syscall_exit_t)) return;

	varptr = (char *)rec_ptr + sizeof(syscall_exit_t);
	switch (rec_ptr->syscallno) {
#ifdef __NR_sendmmsg
                case __NR_recvmmsg :
                case __NR_sendmmsg :
                        bytes = *(unsigned long *)varptr;
                        varptr += sizeof(unsigned long);
                        /* fall through to print socket addresses */
#endif
                case __NR_recvfrom:
                case __NR_sendto:
                case __NR_recvmsg:
                case __NR_sendmsg:
                case __NR_read:
                case __NR_readv:
                case __NR_write :
                case __NR_writev :	
			printf ("socket_update_fdinfo\n");
			if (fdinfop->lsock || fdinfop->rsock) {
				break;
			}
	                addr = (struct sockaddr_in *)varptr;
			
			printf ("socket_update_fdinfo sin_family %d\n", addr->sin_family == AF_INET);
			if (addr->sin_family == AF_INET) {
				lsock_src = addr;
                        	rsock_src = (struct sockaddr_in *)(varptr+sizeof(struct sockaddr_in));

				if (fdinfop->lsock && fdinfop->rsock) {
					lsock_dest = fdinfop->lsock;
					rsock_dest = fdinfop->rsock;
				} else {
					if (lsock_dest = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(lsock_dest, 1, sizeof(struct sockaddr_in6));
						if (rsock_dest = calloc(1, sizeof(struct sockaddr_in6))) {
							CALLOC_LOG(rsock_dest, 1, sizeof(struct sockaddr_in6));
							fdinfop->lsock = lsock_dest;
							fdinfop->rsock = rsock_dest;
							fdinfop->ftype = F_IPv4;
							fdinfop->node = TCP_NODE;
						}
					}
				}

				/* Munge the IPv4 addr to the IPv6 addr */
				/* update the socket information in the fd_info_t structure */
				memcpy(&lsock_dest->sin6_addr.s6_addr[12], &lsock_src->sin_addr.s_addr, 4);
				memcpy(&rsock_dest->sin6_addr.s6_addr[12], &rsock_src->sin_addr.s_addr, 4);
				lsock_dest->sin6_port = BE2LE(lsock_src->sin_port);
				rsock_dest->sin6_port = BE2LE(rsock_src->sin_port);

			} else if (addr->sin_family == AF_INET6) {
				lsock_src6 = (struct sockaddr_in6 *)addr;
                        	rsock_src6 = (struct sockaddr_in6 *)(varptr+sizeof(struct sockaddr_in6));

				if (fdinfop->lsock && fdinfop->rsock) {
					lsock_dest = fdinfop->lsock;
					rsock_dest = fdinfop->rsock;
				} else {
					if (lsock_dest = calloc(1, sizeof(struct sockaddr_in6))) {
						CALLOC_LOG(lsock_dest, 1, sizeof(struct sockaddr_in6));
						if (rsock_dest = calloc(1, sizeof(struct sockaddr_in6))) {
							CALLOC_LOG(rsock_dest, 1, sizeof(struct sockaddr_in6));
							fdinfop->lsock = lsock_dest;
							fdinfop->rsock = rsock_dest;
							fdinfop->ftype = F_IPv6;
							fdinfop->node = TCP_NODE;
						}
					}
				}
				/* update the socket information in the fd_info_t structure */
				memcpy(&lsock_dest->sin6_addr.s6_addr[0], &lsock_src6->sin6_addr.s6_addr[0], 16);
				memcpy(&rsock_dest->sin6_addr.s6_addr[0], &rsock_src6->sin6_addr.s6_addr[0], 16);
				lsock_dest->sin6_port = BE2LE(lsock_src6->sin6_port);
				rsock_dest->sin6_port = BE2LE(rsock_src6->sin6_port);
				lsock_dest->sin6_family = lsock_src6->sin6_family;
				rsock_dest->sin6_family = rsock_src6->sin6_family;
			}

			break;
		default:
		;
	}
}
#endif

static inline int
sys_exit_func2(void *a)
{
	syscall_exit_t *rec_ptr =  (syscall_exit_t *)a;
	syscall_info_t *syscallp;
        pid_info_t *pidp, *tgidp;
	cpu_info_t *cpuinfop;
	sched_info_t *schedp, *gschedp;
	sched_stats_t *statp, *sstatp;
	fd_info_t *fdinfop, *tfdinfop, *ofdinfop;
	fdata_info_t *fdatap;
	sdata_info_t *sdatap;
        uint64 syscallbegtm;
	int old_state, new_state;
	uint64 delta;
	uint32 syscallno;
	uint64 key, device=0;
	uint64 node=0, ftype=0;
	trc_info_t *trcp;
	syscall_stats_t *syscall_statsp;
	ks_action_t *ks_action;
	struct sockaddr_in6 *lsock = NULL, *rsock = NULL;
	int fd;

#if DEBUG	
	if (debug) printf ("%9.6f cpu=%d sys_exit  pid: %d syscallno: %d\n", SECS(rec_ptr->hrtime), rec_ptr->cpu, rec_ptr->pid, rec_ptr->syscallno); 
#endif
	syscallno = rec_ptr->syscallno;

        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	if (is_alive) {
		if (pidp->tgid == 0) pidp->tgid = get_status_int(pidp->PID, "Tgid:");
		if (pidp->ppid == 0) pidp->ppid = get_status_int(pidp->PID, "PPid:");
	}

	SET_KS_ACTIONS(pidp, rec_ptr->is32bit); 

	pidp->num_tr_recs++;
	schedp = (sched_info_t *)find_sched_info(pidp);
	statp = &schedp->sched_stats;
	old_state = statp->state;
	new_state = statp->state = RUNNING | USER;

	/* update perpid stats */
	delta = update_sched_time(statp, rec_ptr->hrtime);
        update_sched_state(statp, old_state, new_state, delta);
	update_sched_cpu(schedp, rec_ptr->cpu);

	schedp->cur_wakeup_cnt = 0;
	if (pidp->last_syscall_time == 0) return 0;
        if (syscallno == -1) {
                syscallno = pidp->last_syscall_id;
        }

	if (pidp->last_syscall_time && (pidp->last_syscall_id == syscallno)) {
                /* check to see if last system call enter is the same */
                syscallbegtm = rec_ptr->hrtime - pidp->last_syscall_time;
	} else {
		/* we have a different syscall on exit than enter.  Assume we missed the enter and toss this one. */
		return 0;
	}

	ks_action = &(KS_ACTION(pidp, syscallno));
	
	if (global_stats) globals->total_traces++;

	if (perpid_stats) {
		pidp->syscall_cnt++;

		/* update per-pid syscall stats */
		if (scall_stats) {
			syscallp = GET_SYSCALLP(&pidp->scallhash, SYSCALL_KEY(pidp->elf, 0ul, syscallno));
			delta = update_sched_time(&syscallp->sched_stats, rec_ptr->hrtime);
			update_sched_state(&syscallp->sched_stats, old_state, new_state, delta);
			incr_syscall_stats(&syscallp->stats, rec_ptr->ret, syscallbegtm, ks_action->logio);
		}
	}

	/* update per-pid FD stats */
	/* don't collect per-file stats on system call if an EBADF occured as
	** this can add alot to the output of kipid/kifile
	 */
	if (perfd_stats && (ks_action->scallop & FILEOP) && (rec_ptr->ret != -EBADF)) {
		update_file_stats(rec_ptr, pidp, pidp->last_syscall_args[0], syscallbegtm, old_state, new_state, ks_action->logio);
	}

	if (percpu_stats) {
		cpuinfop = GET_CPUP(&globals->cpu_hash, rec_ptr->cpu);
		schedp = GET_ADD_SCHEDP(&cpuinfop->schedp);
		delta = update_sched_time(&schedp->sched_stats, rec_ptr->hrtime);
		update_sched_state(&schedp->sched_stats, schedp->sched_stats.state, new_state, delta);
	}

	/* update global trace */
	if (pertrc_stats) {
		key = TRC_KEY(pidp->elf, ftype, rec_ptr->id, syscallno);

		trcp = GET_TRCP(&globals->trc_hash, key);
		trcp->count++;
	       	syscall_statsp = GET_ADD_SCALL_STATSP(&trcp->syscall_statsp);
		incr_syscall_stats(syscall_statsp, rec_ptr->ret, syscallbegtm, 
				ks_action->logio);

		if (perpid_stats) {
			trcp = GET_TRCP(&pidp->trc_hash, key);
			trcp->count++;
	        	syscall_statsp = GET_ADD_SCALL_STATSP(&trcp->syscall_statsp);
			incr_syscall_stats(syscall_statsp, rec_ptr->ret, syscallbegtm, 
				ks_action->logio);
		}
	}

	if (ks_action->execute && ks_action->func) {
		ks_action->func(rec_ptr, pidp, syscallbegtm);
	}	

	if (kitrace_flag)  print_sys_exit_rec(rec_ptr, pidp);

        pidp->last_syscall_id = 0;      /* reset for next system call */
        pidp->last_syscall_time = 0;    /* reset for next system call */

	return 0;

}

int
futex_sys_enter_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
        char tt_rec_ptr[MAX_REC_LEN];
        syscall_enter_t *rec_ptr;
        pid_info_t      *pidp, *tgidp;
        uint64 syscallno;

        rec_ptr = conv_sys_enter(trcinfop, tt_rec_ptr);
        syscallno = rec_ptr->syscallno;
        if (rec_ptr->syscallno > KI_MAXSYSCALLS) {
                if (debug) printf ("Bad Syscall %d", rec_ptr->syscallno);
                if (debug) hex_dump(trcinfop->cur_event, 4);
                return 0;
        }
        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
        SET_KS_ACTIONS(pidp, rec_ptr->is32bit);

        /* we only want futex() system calls and ones that match the filter */
        if (!(KS_ACTION(pidp, syscallno).scallop & FUTEXOP))  return 0;
        if (!check_filter(f->f_uaddr, rec_ptr->args[0])) return 0;

        pidp->last_syscall_id = rec_ptr->syscallno;
        pidp->last_syscall_time = rec_ptr->hrtime;
        memcpy(&pidp->last_syscall_args[0], &rec_ptr->args[0], MAXARGS * sizeof(uint64));

        if (kitrace_flag) print_sys_enter_rec(rec_ptr, pidp);
        return 0;
}

int
trace_sys_enter_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
        char tt_rec_ptr[MAX_REC_LEN];
        syscall_enter_t *rec_ptr;
        pid_info_t *pidp, *tgidp;

        rec_ptr = conv_sys_enter(trcinfop, tt_rec_ptr);

        if (rec_ptr->syscallno > KI_MAXSYSCALLS) {
                hex_dump(trcinfop->cur_event, 4);
                hex_dump(rec_ptr, 2);
                FATAL(3001, "Bad system call number", "syscallno:", rec_ptr->syscallno);
        }

        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
        SET_KS_ACTIONS(pidp, rec_ptr->is32bit);

        /* save syscall info to print on syscall exit */
        pidp->last_syscall_id = rec_ptr->syscallno;
        pidp->last_syscall_time = rec_ptr->hrtime;
        memcpy(&pidp->last_syscall_args[0], &rec_ptr->args[0], MAXARGS * sizeof(uint64));

        if (sysenter_flag || kitrace_flag) {
                print_sys_enter_rec(rec_ptr, pidp);
        }
}

int
sys_enter_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
	char tt_rec_ptr[MAX_REC_LEN];
	syscall_enter_t *rec_ptr;

	/* trace_sys_enter_func(a, v); */
	rec_ptr = conv_sys_enter(trcinfop, tt_rec_ptr);

        if (rec_ptr->syscallno > KI_MAXSYSCALLS ) {
		fprintf (stderr, "pid_sys_enter_func()   pid: %d\n", rec_ptr->pid);
                fprintf (stderr, "Bad Syscall %d", rec_ptr->syscallno);
                if (debug) hex_dump(trcinfop->cur_event, 4);
                return 0;
        }

	sys_enter_func2(rec_ptr);

	return 0;
}

int
futex_sys_exit_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
        char tt_rec_ptr[MAX_REC_LEN];
        syscall_exit_t *rec_ptr;
        pid_info_t      *pidp, *tgidp;
        uint64 syscallno;
        uint64 syscallbegtm;

        rec_ptr = conv_sys_exit(trcinfop, tt_rec_ptr);
        syscallno = rec_ptr->syscallno;
        if (rec_ptr->syscallno > KI_MAXSYSCALLS) {
                if (debug) printf ("Bad Syscall %d", rec_ptr->syscallno);
                if (debug) hex_dump(trcinfop->cur_event, 4);
                return 0;
        }
        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
	if (is_alive) {
		if (pidp->tgid == 0) pidp->tgid = get_status_int(pidp->PID, "Tgid:");
		if (pidp->ppid == 0) pidp->ppid = get_status_int(pidp->PID, "PPid:");
	}
        SET_KS_ACTIONS(pidp, rec_ptr->is32bit);

        /* check for unexpected sys_exit */
        if ((pidp->last_syscall_time == 0) ||
            (pidp->last_syscall_id != syscallno) ||
             !(KS_ACTION(pidp, syscallno).scallop & FUTEXOP))  {
                pidp->last_syscall_time = 0;
                pidp->last_syscall_id = 0;
                return 0;
        }

        syscallbegtm = rec_ptr->hrtime - pidp->last_syscall_time;

        /* here, we really only want to call ki_futex() */
        if (KS_ACTION(pidp, syscallno).func == ki_futex) {
                ki_futex(rec_ptr, pidp, syscallbegtm);
        }

        if (kitrace_flag) print_sys_exit_rec(rec_ptr, pidp);
        /* reset last syscall info */
        pidp->last_syscall_time = 0;
        pidp->last_syscall_id = 0;
        return 0;
}


int
trace_sys_exit_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
        char tt_rec_ptr[MAX_REC_LEN];
        syscall_exit_t *rec_ptr;
        pid_info_t *pidp, *tgidp;

        rec_ptr = conv_sys_exit(trcinfop, tt_rec_ptr);

        if (debug) printf ("trace_sys_exit_func()\n");
        if (rec_ptr->syscallno > KI_MAXSYSCALLS || rec_ptr->syscallno < -1) {
                hex_dump(trcinfop->cur_event, 4);
                hex_dump(rec_ptr, 2);
                FATAL(3000, "Bad system call number", "syscallno:", rec_ptr->syscallno);
        }

        pidp = GET_PIDP(&globals->pid_hash, rec_ptr->pid);
        SET_KS_ACTIONS(pidp, rec_ptr->is32bit);

        print_sys_exit_rec(rec_ptr, pidp);

        pidp->last_syscall_id = 0;      /* reset for next system call */ 
        pidp->last_syscall_time = 0;    /* reset for next system call */
}

int
sys_exit_func(void *a, void *v)
{
       	trace_info_t *trcinfop = (trace_info_t *)a;
        filter_t *f = v;
	char tt_rec_ptr[MAX_REC_LEN];
	syscall_exit_t  *rec_ptr;

	rec_ptr = conv_sys_exit(trcinfop, tt_rec_ptr);

        if (rec_ptr->syscallno > KI_MAXSYSCALLS) {
		fprintf (stderr, "pid_sys_exit_func()   pid: %d\n", rec_ptr->pid);
                fprintf (stderr, "Bad Syscall %d", rec_ptr->syscallno);
                /* if (debug) */ hex_dump(trcinfop->cur_event, 4);
                return 0;
	}

	sys_exit_func2(rec_ptr);

	return 0;
}
