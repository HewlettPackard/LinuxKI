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

#define _MSG_TOC	"Table of Contents"
#define _MSG_LINK	"Link to Notes and Warnings"
#define _MSG_NEXT_NOTE  "[Next]"
#define _MSG_1_0	"1.0 What is it doing?"
#define _MSG_1_1	"1.1 Cluster-wide Server Summary"
#define _MSG_1_2	"1.1 Cluster-wide CPU Activity"
#define _MSG_1_2_1      "1.1.1 Server CPU Usage by Run Time"
#define _MSG_1_2_2      "1.1.2 Server CPU Usage by Sys Time"
#define _MSG_1_2_3      "1.1.3 Power Savings Report" 
#define _MSG_1_2_4      "1.1.4 Hyperthread CPU Usage" 
#define _MSG_1_3	"1.2 Cluster-wide CPU Usage by Task"  
#define _MSG_1_3_1	"1.2.1 Top Tasks sorted by Run Time"
#define _MSG_1_3_2	"1.2.2 Top Tasks sorted by System Time"
#define _MSG_1_4 	"1.4 Reports from HARDCLOCK traces"
#define _MSG_1_4_1	"1.4.1 Report of cpu states at clock tick"
#define _MSG_1_4_2	"1.4.2 Breakdown of functions by Top Tasks"       
#define _MSG_1_5	"1.5 Thundering Herd Detection"
#define _MSG_1_6	"1.6 Interrupt Request Queue (IRQ) Report"
#define _MSG_1_6_1	"1.6.1 Top Hard IRQ Events"
#define _MSG_1_6_2	"1.6.2 Top Hard IRQ Events Per CPU"
#define _MSG_1_6_3	"1.6.3 Top Soft IRQ Events"

#define _MSG_2_0	"2.0 What is it waiting for?"
#define _MSG_2_1	"2.1 Kernel sleep functions (SWITCH)"
#define _MSG_2_1_1	"2.1.1 Per-Task Sleep reports"
#define _MSG_2_1_2	"2.1.2 Kernel Sleep Functions of Top Tasks"
#define _MSG_2_2	"2.2 Cluster-wide RUNQ statistics (waiting for CPU)"
#define _MSG_2_2_1	"2.2.1 RUNQ latency stats per server (in Usecs)"
#define _MSG_2_2_2	"2.2.2 Top Tasks Waiting on CPU (in secs)"
#define _MSG_2_3	"2.3 Futex statistics"
#define _MSG_2_3_1	"2.3.1 Futex Operation & PID summary (sorted by Count)"
#define _MSG_2_3_2	"2.3.2 Futex Operation & PID summary (sorted by ElpTime)"
#define _MSG_2_3_3	"2.3.3 Futex requeued addr Statistics"
#define _MSG_2_3_4	"2.3.4 Futex Process shared Addrs Statistics"
#define _MSG_3_0	"3.0 File Activity"
#define _MSG_3_1	"3.1 Top Files sorted by Syscall Count"
#define _MSG_3_2	"3.2 Top Files sorted by Elapsed Time"
#define _MSG_3_3	"3.3 Top Files w/ Errors"
#define _MSG_3_4	"3.4 Top Files (Detail)"
#define _MSG_4_0	"4.0 Device Report"
#define _MSG_4_1	"4.1 Global IO Statistics"
#define _MSG_4_2	"4.2 Per-Device Statistics"
#define _MSG_4_2_1      "4.2.1 Most Active Disks"
#define _MSG_4_2_2      "4.2.2 Disks with highest Service Times (>5 ios/sec)"
#define _MSG_4_2_3      "4.2.3 Disks with highest Service Times (<5 ios/sec)"
#define _MSG_4_2_4      "4.2.4 Disks with highest Queue Wait Times"
#define _MSG_4_2_5      "4.2.5 Disks with Requeues"
#define _MSG_4_2_6      "4.2.6 Disk Response Time Histogram"
#define _MSG_4_3	"4.3 Device-Mapper Statistics"
#define _MSG_4_3_1	"4.3.1 Most Active Device-mapper devices"
#define _MSG_4_3_2	"4.3.2 Device-mapper devices with highest Service Times (>5 ios/sec)"
#define _MSG_4_4	"4.4 Tasks doing Multipath Active I/O"
#define _MSG_4_5	"4.5 Tasks doing Active I/O"
#define _MSG_4_6	"4.6 Disk block read frequency"
#define _MSG_4_7	"4.7 Disk block write frequency"
#define _MSG_4_8	"4.8 Logical vs Physical I/O Check"

#define _MSG_5_0	"5.0 Network Statistics"
#define _MSG_5_1	"5.1 Global Network Statistics"
#define _MSG_5_2	"5.2 Top IP->IP dataflows"
#define _MSG_5_3	"5.3 Top Local Sockets"
#define _MSG_5_4	"5.4 Most Active Sockets"
#define _MSG_6_0	"6.0 Warnings"

/*
#define _MSG_5_0	"5.0 Task Memory Statistics"
#define _MSG_5_1	"5.1 Top Tasks sorted by Resident Set Size (RSS)"
#define _MSG_5_2	"5.2 Top Tasks sorted by Virtual Set Size (VSS)"
#define _MSG_6_0	"6.0 Oracle Analysis"
#define _MSG_6_1	"6.1 Oracle Instances"
#define _MSG_6_2	"6.2 Oracle Log Writer Analysis"
#define _MSG_6_3	"6.3 Oracle Archive Log Analysis"
#define _MSG_6_4	"6.4 Oracle DB Writer Analysis"
#define _MSG_6_5	"6.5 Oracle Parallel Query Analysis"
#define _MSG_6_6	"6.6 Oracle Server Process Analysis"
#define _MSG_6_7	"6.7 Oracle IO Slave Analysis"
*/


/* Unused */
#define _MSG_7_1	"7.0 NFS Report"
#define _MSG_7_2	"7.1 NFS Client Report"
#define _MSG_7_3	"7.2 NFS Server Report"
#define _MSG_8_0	"8.0 Network Statistics"
#define _MSG_8_1	"8.1 Remote IP Activity"
#define _MSG_8_2	"8.2 Top 5 ports on Active Remote IP Addresses"
#define _MSG_8_3	"8.3 Local IP Activity"
#define _MSG_8_4	"8.4 Top 5 ports on Active Local IP Addresses"
#define _MSG_8_5	"8.5 Connections in CLOSE_WAIT status"
#define _MSG_9_0	"9.0 Faults and Traps"
#define _MSG_9_1	"9.1 Pfaults - Sorted by Elapsed PFAULT Time"
#define _MSG_9_2	"9.2 Pfaults - Sorted by Count"
#define _MSG_9_3	"9.3 Vfaults - Sorted by Elapsed VFAULT Time"
#define _MSG_9_4	"9.4 Traps - Sorted by Elapsed Trap Time"
#define _MSG_10_0	"10.0 Process Memory Statistics"
#define _MSG_10_1	"10.1 Top Tasks sorted by Resident Set Size (RSS)"
#define _MSG_10_2	"10.2 Top Tasks sorted by Virtual Set Size (VSS)"
#define _MSG_10_3	"10.3 Top Tasks sorted by Pageins"
#define _MSG_10_4	"10.4 Top Tasks sorted by Reclaims"

