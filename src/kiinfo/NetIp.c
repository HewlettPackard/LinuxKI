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
#include "sys/socket.h"
#include "linux/in6.h"

#include "winki_util.h"

#define TCP_NONE        0
#define TCP_SEND        1
#define TCP_RECV        2
#define UDP_SEND        3
#define UDP_RECV        4

int
print_tcpsendipv4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpSendIPV4_t *p = (TcpSendIPV4_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d",
		p->Pid,
		p->size);

	if (debug) printf (" seqnum=%d connid=%d",
		p->seqnum,
		p->connid);

	printf (" src=%d.%d.%d.%d:%d",
		IP1(p->saddr),
		IP2(p->saddr),
		IP3(p->saddr),
		IP4(p->saddr),
		p->sport);

	printf (" dest=%d.%d.%d.%d:%d",
		IP1(p->daddr),
		IP2(p->daddr),
		IP3(p->daddr),
		IP4(p->daddr),
		p->dport);

	printf ("\n");

	if (debug) hex_dump(p, 2);

	return 0;
}

int
print_tcpsendipv6_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpSendIPV6_t *p = (TcpSendIPV6_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d seqnum=%d connid=%d",
		p->Pid,
		p->size,
		p->seqnum,
		p->connid);

	printf (" ");
	print_ip_v6(&p->saddr[0], NULL);
	printf (":%d", p->sport);

	printf (" ");
	print_ip_v6(&p->daddr[0], NULL);
	printf (":%d", p->dport);

	printf (" starttime=0x%x endtime=0x%x",
		p->starttime,
		p->endtime);

	printf ("\n");

	if (debug) hex_dump(p, 4);

	return 0;
}

int
print_tcpgroup1_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpGroup1_t *p = (TcpGroup1_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d",
		p->Pid,
		p->size);

	if (debug) printf (" seqnum=%d connid=%d",
		p->seqnum,
		p->connid);

	printf (" src=%d.%d.%d.%d:%d",
		IP1(p->saddr),
		IP2(p->saddr),
		IP3(p->saddr),
		IP4(p->saddr),
		p->sport);

	printf (" dest=%d.%d.%d.%d:%d",
		IP1(p->daddr),
		IP2(p->daddr),
		IP3(p->daddr),
		IP4(p->daddr),
		p->dport);

	printf ("\n");

	if (debug) hex_dump(p, 2);

	return 0;
}

int
print_tcpgroup2_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpGroup2_t *p = (TcpGroup2_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d seqnum=%d connid=%d, mss=%d, sackopt=0x%x, tsopt=0x%x, wsopt=0x%x, rcvwin=%d, rcvwinscale=%d, sndwinscale=%d",
		p->Pid,
		p->size,
		p->seqnum,
		p->connid,
		p->mss,
		p->sackopt,
		p->tsopt,
		p->wsopt,
		p->rcvwin,
		p->rcvwinscale,
		p->sndwinscale);

	printf (" src=%d.%d.%d.%d:%d",
		IP1(p->saddr),
		IP2(p->saddr),
		IP3(p->saddr),
		IP4(p->saddr),
		p->sport);

	printf (" dest=%d.%d.%d.%d:%d",
		IP1(p->daddr),
		IP2(p->daddr),
		IP3(p->daddr),
		IP4(p->daddr),
		p->dport);

	printf ("\n");

	if (debug) hex_dump(p, 2);

	return 0;
}

int
print_tcpgroup3_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpGroup3_t *p = (TcpGroup3_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d seqnum=%d connid=%d",
		p->Pid,
		p->size,
		p->seqnum,
		p->connid);

	printf (" ");
	print_ip_v6(&p->saddr[0], NULL);
	printf (":%d", p->sport);

	printf (" ");
	print_ip_v6(&p->daddr[0], NULL);
	printf (":%d", p->dport);

	printf ("\n");

	if (debug) hex_dump(p, 4);

	return 0;
}

int
print_tcpgroup4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	TcpGroup4_t *p = (TcpGroup4_t *)trcinfop->cur_event;

	PRINT_COMMON_FIELDS_C011(p, 0, 0);

	printf (" pid=%d size=%d seqnum=%d connid=%d, mss=%d, sackopt=0x%x, tsopt=0x%x, wsopt=0x%x, rcvwin=%d, rcvwinscale=%d, sndwinscale=%d",
		p->Pid,
		p->size,
		p->seqnum,
		p->connid,
		p->mss,
		p->sackopt,
		p->tsopt,
		p->wsopt,
		p->rcvwin,
		p->rcvwinscale,
		p->sndwinscale);

	printf (" ");
	print_ip_v6(&p->saddr[0], NULL);
	printf (":%d", p->sport);

	printf (" ");
	print_ip_v6(&p->daddr[0], NULL);
	printf (":%d", p->dport);

	printf ("\n");

	if (debug) hex_dump(p, 4);

	return 0;
}

static inline void
incr_winsock_stats(sd_stats_t *statp, uint32 size, uint32 Pid, int op)
{
	if (op == TCP_SEND) {
		 statp->wr_bytes += size;
		 statp->wr_cnt++;
	} else {
		 statp->rd_bytes += size;
		 statp->rd_cnt++;
	}
	statp->syscall_cnt++;
	statp->last_pid = Pid;
}

void 
incr_global_sock_stats(sdata_info_t *sdatap, struct sockaddr_in6 *saddrp, struct sockaddr_in6 *daddrp, uint32 size, uint32 pid, int op)
{
	ipip_info_t *ipipp;
	ip_info_t *lipp, *ripp;
	sock_info_t *lsockp, *rsockp;
	/* IP->IP stats */
	if ((ipipp = (ipip_info_t *)sdatap->ipipp) == NULL) {
		ipipp = GET_IPIPP(&globals->ipip_hash, SIN_ADDR(saddrp), SIN_ADDR(daddrp));
		cp_sockip(&ipipp->laddr, saddrp);
		cp_sockip(&ipipp->raddr, daddrp);
		incr_winsock_stats(&ipipp->stats, size, pid, op);
	}

	/* Local IP stats */
	if ((lipp = (ip_info_t *)sdatap->lipp) == NULL) {
		lipp = GET_IPP(&globals->lip_hash, SIN_ADDR(saddrp));
		cp_sockip(&lipp->saddr, saddrp);
		incr_winsock_stats(&lipp->stats, size, pid, op);
	}

	/* Remote IP stats */
	if ((ripp = (ip_info_t *)sdatap->ripp) == NULL) {
		ripp = GET_IPP(&globals->rip_hash, SIN_ADDR(daddrp));
		cp_sockip(&ripp->saddr, daddrp);
		incr_winsock_stats(&ripp->stats, size, pid, op);
	}
	
	/* Local IP:Port stats */
	if ((lsockp = (sock_info_t *)sdatap->lsockp) == NULL) {
		lsockp = GET_SOCKP(&globals->lsock_hash, SIN_ADDR(saddrp), SIN_PORT(saddrp));
		cp_sockaddr(&lsockp->saddr, saddrp);
		incr_winsock_stats(&lsockp->stats, size, pid, op);
	}

	/* Remote IP:Port stats */
	if ((rsockp = (sock_info_t *)sdatap->rsockp) == NULL) {
		rsockp = GET_SOCKP(&globals->rsock_hash, SIN_ADDR(daddrp), SIN_PORT(daddrp));
		cp_sockaddr(&rsockp->saddr, daddrp); incr_winsock_stats(&rsockp->stats, size, pid, op);
	}
}

void
incr_ipv4_stats(void *sdata_hash, NetCommonIPV4_t *p, int op, char global_flag)
{
	struct sockaddr_in6 saddr, daddr;
	struct sockaddr_in6 *saddrp = &saddr, *daddrp = &daddr;
	sdata_info_t *sdatap;

	bzero (saddrp, sizeof(struct sockaddr_in6));
	memcpy(&saddr.sin6_addr.s6_addr[12], &p->saddr, 4);
	saddr.sin6_addr.s6_addr16[5] = 0xffff;
	saddr.sin6_port = p->sport;
	saddr.sin6_family = AF_INET;

	bzero (daddrp, sizeof(struct sockaddr_in6));
	memcpy(&daddr.sin6_addr.s6_addr[12], &p->daddr, 4);
	daddr.sin6_addr.s6_addr16[5] = 0xffff;
	daddr.sin6_port = p->dport;
	daddr.sin6_family = AF_INET;	

	/* IP:port -> IP:port stats */
	sdatap = GET_SDATAP(sdata_hash, SIN_ADDR(saddrp), SIN_PORT(saddrp), 
					SIN_ADDR(daddrp), SIN_PORT(daddrp));
	cp_sockaddr(&sdatap->laddr, saddrp);
	cp_sockaddr(&sdatap->raddr, daddrp);
	sdatap->node = F_IPv4;
	if (op == TCP_SEND || op == TCP_RECV) {
		sdatap->type = TCP_NODE;
	} else {
		sdatap->type = UDP_NODE;
	}

	incr_winsock_stats(&sdatap->stats, p->size, p->Pid, op);

	if (global_flag) incr_global_sock_stats(sdatap, saddrp, daddrp, p->size, p->Pid, op);
}

void
incr_global_ipv4_stats(NetCommonIPV4_t *p, int op)
{
	incr_ipv4_stats(&globals->sdata_hash, p, op, TRUE);
}

void
incr_perpid_ipv4_stats(pid_info_t *pidp, NetCommonIPV4_t *p, int op)
{
	incr_ipv4_stats(&pidp->sdata_hash, p, op, FALSE);
}

void
incr_perpid_udp_recv_stats(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	NetCommonIPV4_t *p = (NetCommonIPV4_t *)arg2;

	incr_perpid_ipv4_stats(pidp, p, UDP_RECV);
}



int
tcpip_sendipv4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV4_t *p = (NetCommonIPV4_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	if (global_stats) {
		incr_global_ipv4_stats(p, TCP_SEND);
	}

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, p->Pid);	
		incr_perpid_ipv4_stats(pidp, p, TCP_SEND);
	}

	if (kitrace_flag) {
		print_tcpsendipv4_func(a, v);
	}

	return 0;
}

int
tcpip_recvipv4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV4_t *p = (NetCommonIPV4_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	if (global_stats) {
		incr_global_ipv4_stats(p, TCP_RECV);
	}

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, p->Pid);	
		incr_perpid_ipv4_stats(pidp, p, TCP_RECV);
	}

	if (kitrace_flag) {
		print_tcpgroup1_func(a, v);
	}

	return 0;
}

int
tcpip_connectipv4_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup2_func(a, v);
	}

	return 0;
}

int
tcpip_disconnectipv4_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup2_func(a, v);
	}

	return 0;
}

int
tcpip_retransmitipv4_func(void *a, void *v) 
{
	if (kitrace_flag) {
		print_tcpgroup1_func(a, v);
	}

	return 0;
}

int
tcpip_acceptipv4_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup2_func(a, v);
	}

	return 0;
}

int
tcpip_reconnectipv4_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup1_func(a, v);
	}

	return 0;
}

int
tcpip_fail_func(void *a, void *v)
{
	return 0;
}

int
tcpip_copyipv4_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup1_func(a, v);
	}

	return 0;
}

void
incr_global_ipv6_stats(NetCommonIPV6_t *p, int op)
{
	struct sockaddr_in6 saddr, daddr;
	struct sockaddr_in6 *saddrp = &saddr, *daddrp = &daddr;
	sdata_info_t *sdatap;
	ipip_info_t *ipipp;
	ip_info_t *lipp, *ripp;
	sock_info_t *lsockp, *rsockp;
	int i;
	uint32 size, pid;

	bzero (saddrp, sizeof(struct sockaddr_in6));
	memcpy(&saddr.sin6_addr.s6_addr[0], &p->saddr, 16);
	saddr.sin6_port = p->sport;
	saddr.sin6_family = AF_INET6;

	bzero (daddrp, sizeof(struct sockaddr_in6));
	memcpy(&daddr.sin6_addr.s6_addr[0], &p->daddr, 16);
	daddr.sin6_port = p->dport;
	daddr.sin6_family = AF_INET6;	

	size = p->size;
	pid = p->Pid;

	/* IP:port -> IP:port stats */
	sdatap = GET_SDATAP(&globals->sdata_hash, SIN_ADDR(saddrp), SIN_PORT(saddrp), 
						  SIN_ADDR(daddrp), SIN_PORT(daddrp));
	cp_sockaddr(&sdatap->laddr, saddrp);
	cp_sockaddr(&sdatap->raddr, daddrp);
	sdatap->node = F_IPv6;
	if (op == TCP_SEND || op == TCP_RECV) {
		sdatap->type = TCP_NODE;
	} else {
		sdatap->type = UDP_NODE;
	}
	incr_winsock_stats(&sdatap->stats, p->size, p->Pid, op);

	incr_global_sock_stats(sdatap, saddrp, daddrp, p->size, p->Pid, op);
}

int
tcpip_sendipv6_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV6_t *p = (NetCommonIPV6_t *)trcinfop->cur_event;

	if (global_stats) {
		incr_global_ipv6_stats(p, TCP_SEND);
	}

	if (perpid_stats) {
		/* incr_perpid_ipv6_stats(p, TCP_SEND); */
	}

	if (kitrace_flag) {
		print_tcpsendipv6_func(a, v);
	}

	return 0;
}

int
tcpip_recvipv6_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV6_t *p = (NetCommonIPV6_t *)trcinfop->cur_event;

	if (global_stats) {
		incr_global_ipv6_stats(p, TCP_RECV);
	}

	if (perpid_stats) {
		/* incr_perpid_ipv6_stats(p, TCP_RECV); */
	}
	if (kitrace_flag) {
		print_tcpgroup3_func(a, v);
	}

	return 0;
}

int
tcpip_connectipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup4_func(a, v);
	}

	return 0;
}

int
tcpip_disconnectipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup3_func(a, v);
	}

	return 0;
}

int
tcpip_retransmitipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup3_func(a, v);
	}

	return 0;
}

int
tcpip_acceptipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup4_func(a, v);
	}

	return 0;
}

int
tcpip_reconnectipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup3_func(a, v);
	}

	return 0;
}

int
tcpip_copyipv6_func(void *a, void *v)
{
	if (kitrace_flag) {
		print_tcpgroup3_func(a, v);
	}

	return 0;
}

int
print_udpgroup1_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        UdpGroup1_t *p = (UdpGroup1_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, 0, 0);

        printf (" pid=%d size=%d seqnum=%d connid=%d",
                p->Pid,
                p->size,
                p->seqnum,
                p->connid);

        printf (" src=%d.%d.%d.%d:%d",
                IP1(p->saddr),
                IP2(p->saddr),
                IP3(p->saddr),
                IP4(p->saddr),
                p->sport);

        printf (" dest=%d.%d.%d.%d:%d",
                IP1(p->daddr),
                IP2(p->daddr),
                IP3(p->daddr),
                IP4(p->daddr),
                p->dport);

        printf ("\n");

        if (debug) hex_dump(p, 2);
}

int
print_tcpudpfail_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        TcpUdpFail_t *p = (TcpUdpFail_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, 0, 0);

        printf (" proto=%d failure_code=%d");
        printf ("\n");

        if (debug) hex_dump(p, 2);
}

int
print_udpgroup2_func(void *a, void *v)
{
        trace_info_t *trcinfop = (trace_info_t *)a;
        UdpGroup2_t *p = (UdpGroup2_t *)trcinfop->cur_event;

        PRINT_COMMON_FIELDS_C011(p, 0, 0);

        printf (" pid=%d size=%d seqnum=%d connid=%d",
                p->Pid,
                p->size,
                p->seqnum,
                p->connid);

        printf (" ");
        print_ip_v6(&p->saddr[0], NULL);
        printf (":%d", p->sport);

        printf (" ");
        print_ip_v6(&p->daddr[0], NULL);
        printf (":%d", p->dport);

        printf ("\n");

        if (debug) hex_dump(p, 4);
}

int
udpip_sendipv4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV4_t *p = (NetCommonIPV4_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	if (global_stats) {
		incr_global_ipv4_stats(p, UDP_SEND);
	}

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, p->Pid);	
		incr_perpid_ipv4_stats(pidp, p, UDP_SEND);
	}

	if (kitrace_flag) {
		print_udpgroup1_func(a, v);
	}

	return 0;
}

int
udpip_recvipv4_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV4_t *p = (NetCommonIPV4_t *)trcinfop->cur_event;
	pid_info_t *pidp;

	if (global_stats) {
		incr_global_ipv4_stats(p, UDP_RECV);
	}

	if (perpid_stats) {
		pidp = GET_PIDP(&globals->pid_hash, p->Pid);	
		incr_perpid_ipv4_stats(pidp, p, UDP_RECV);
	}

	if (kitrace_flag) {
		print_udpgroup1_func(a, v);
	}

	return 0;
}

int
udpip_sendipv6_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV6_t *p = (NetCommonIPV6_t *)trcinfop->cur_event;

	if (global_stats) {
		incr_global_ipv6_stats(p, UDP_SEND);
	}

	if (perpid_stats) {
		/* incr_perpid_ipv6_stats(p, UDP_SEND); */
	}

	if (kitrace_flag) {
		print_udpgroup2_func(a, v);
	}

	return 0;
}

int
udpip_recvipv6_func(void *a, void *v)
{
	trace_info_t *trcinfop = (trace_info_t *)a;
	NetCommonIPV6_t *p = (NetCommonIPV6_t *)trcinfop->cur_event;

	if (global_stats) {
		incr_global_ipv6_stats(p, UDP_RECV);
	}

	if (perpid_stats) {
		/* incr_perpid_ipv6_stats(p, UDP_RECV); */
	}
	if (kitrace_flag) {
		print_udpgroup2_func(a, v);
	}

	return 0;
}

