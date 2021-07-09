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
extern int print_tcpsendipv4_func(void *, void *);
extern int print_tcpsendipv6_func(void *, void *);
extern int print_tcpgroup1_func(void *, void *);
extern int print_tcpgroup2_func(void *, void *);
extern int print_tcpgroup3_func(void *, void *);
extern int print_tcpgroup4_func(void *, void *);
extern int print_udpgroup1_func(void *, void *);
extern int print_udpgroup2_func(void *, void *);
extern int print_tcpudpfail_func(void *, void *);

extern int tcpip_sendipv4_func(void *, void *);
extern int tcpip_recvipv4_func(void *, void *);
extern int tcpip_connectipv4_func(void *, void *);
extern int tcpip_disconnectipv4_func(void *, void *);
extern int tcpip_retransmitipv4_func(void *, void *);
extern int tcpip_acceptipv4_func(void *, void *);
extern int tcpip_reconnectipv4_func(void *, void *);
extern int tcpip_fail_func(void *, void *);
extern int tcpip_copyipv4_func(void *, void *);
extern int tcpip_sendipv6_func(void *, void *);
extern int tcpip_recvipv6_func(void *, void *);
extern int tcpip_connectipv6_func(void *, void *);
extern int tcpip_disconnectipv6_func(void *, void *);
extern int tcpip_retransmitipv6_func(void *, void *);
extern int tcpip_acceptipv6_func(void *, void *);
extern int tcpip_reconnectipv6_func(void *, void *);
extern int tcpip_copyipv6_func(void *, void *);
extern int udpip_sendipv4_func(void *, void *);
extern int udpip_recvipv4_func(void *, void *);
extern int udpip_sendipv6_func(void *, void *);
extern int udpip_recvipv6_func(void *, void *);
