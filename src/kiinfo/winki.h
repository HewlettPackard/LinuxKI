/* (C) Copyright 2015 Hewlett Packard Enterprise Development LP.
 * (C) Copyright 2000-2014 Hewlett-Packard Development Company, L.P.
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version. 
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details. 
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301, USA. 
 */

typedef struct etw_bufhd {
	uint32	bufsz;
	uint32	datasz;
	uint32  filler1;
	uint32  kiversion;
	uint64	timestamp;	  /* this will be 0 for the Trace Event Header */
	uint32  filler2[4];
	uint16	cpu;
	uint16  filler3;
	uint32  etw_version;      /* guessing */
	uint32  filler4[6];
} etw_bufhd_t;


/* Every trace records starts with a common set of fields */

#define ioreq_type(EventType)  (EventType == 0x10a ? IO_READ : IO_WRITE)
#define filereq_type(EventType)  (EventType == 0x443 ? IO_READ : IO_WRITE)

#define ETW_COMMON_FIELDS				\
  uint16 TraceVersion;					\
  uint16 ReservedHeaderField;				\
  uint16 EventSize;					\
  uint16 EventType;					

#define ETW_COMMON_FIELDS_c002				\
  ETW_COMMON_FIELDS;					\
  uint32 tid;						\
  uint32 pid;						\
  uint64 TimeStamp;					\
  uint32 KernelTime;					\
  uint32 UserTime;				

#define ETW_COMMON_FIELDS_c011				\
  ETW_COMMON_FIELDS;					\
  uint64 TimeStamp;

#define ETW_COMMON_FIELDS_c014				\
  uint16 EventSize;					\
  uint16 ReservedHeaderField;				\
  uint16 EventType;					\
  uint16 TraceVersion;					\
  uint32 Reserved1;					\
  uint32 Reserved2;					\
  uint64 TimeStamp;					


  

typedef struct etw_common_fields {
	ETW_COMMON_FIELDS;
} etw_common_t;

typedef struct etw_common_fields_c002 {
	ETW_COMMON_FIELDS_c002;
} etw_common_c002_t;

typedef struct etw_common_fields_c011 {
	ETW_COMMON_FIELDS_c011;
} etw_common_c011_t;

typedef struct etw_common_fields_c014 {
	ETW_COMMON_FIELDS_c014;
} etw_common_c014_t;

typedef struct etw_header_page {
        uint64          time;
        uint32          commit;
        uint32          version;
	uint32		bufsz;
	uint32		cpu;
} etw_header_page_t;

typedef struct EventTraceHdr
{
  ETW_COMMON_FIELDS;
  uint32 tid;
  uint32 pid;
  uint64 TimeStamp;
  uint32 KernelTime;
  uint32 UserTime;
  uint32 BufferSize;
  uint32 Version;
  uint32 ProviderVersion;
  uint32 NumberOfProcessors;
  uint64 EndTime;
  uint32 TimerResolution;
  uint32 MaxFileSize;
  uint32 LogFileMode;
  uint32 BuffersWritten;
  uint32 StartBuffers;
  uint32 PointerSize;
  uint32 EventsLost;
  uint32 CPUSpeed;
  uint32 LoggerName;
  uint32 LogFileName;
  uint8  TimeZoneInformation[184];
  uint64 BootTime;
  uint64 PerfFreq;
  uint64 StartTime;
  uint32 ReservedFlags;
  uint32 BuffersLost;
} EventTraceHdr_t;


typedef struct Provider
{
  ETW_COMMON_FIELDS_c014;
  uint32 guid[4];
  uint32 Reserved[2];
  uint16 Name[];
} Provider_t;

typedef struct ControlImage
{
  ETW_COMMON_FIELDS_c014;
  uint32 guid[4];
  uint32 Reserved[2];
  uint32 ImageSize;
  uint32 TimeDateStamp;
  uint16 Name[];
} ControlImage_t;


typedef struct PdbImage
{
  ETW_COMMON_FIELDS_c014;
  uint32 guid[4];
  uint32 Reserved[5];
  uint32 guid1;
  uint16 guid2;
  uint16 guid3;
  uint8  guid4[4];
  uint8  guid5[4];
  uint32 guid6;
  char Name[];
} PdbImage_t;


typedef struct Image_Load_c011
{
  ETW_COMMON_FIELDS_c011;
  uint64 ImageBase;
  uint64 ImageSize;
  uint32 ProcessId;
  uint32 ImageCheckSum;
  uint64 Reserved0;
  uint64 DefaultBase;
  uint32 Reserved1;
  uint32 Reserved2;
  uint32 Reserved3;
  uint32 Reserved4;
  uint16 FileName[];
} Image_Load_c011_t;
  
typedef struct Image_Load_c002
{
  ETW_COMMON_FIELDS_c002;
  uint64 ImageBase;
  uint64 ImageSize;
  uint32 ProcessId;
  uint32 ImageCheckSum;
  uint32 Reserved[8];
  uint16 FileName[];
} Image_Load_c002_t;

typedef struct Thread_TypeGroup1_v3
{
  ETW_COMMON_FIELDS_c002;
  int32 ProcessId;
  uint32 TThreadId;
  uint64 StackBase;
  uint64 StackLimit;
  uint64 UserStackBase;
  uint64 UserStackLimit;
  uint32 Affinity;
  uint32 filler;
  uint64 Win32StartAddr;
  uint64 TebBase;
  uint32 SubProcessTag;
  uint8  BasePriority;
  uint8  PagePriority;
  uint8  IoPriority;
  uint8  ThreadFlags;
} Thread_TypeGroup1_v3_t; 

typedef struct ThreadName
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 Tid;
  uint16 ThreadName[];
} ThreadName_t;

typedef struct ThreadAutoBoost
{
  ETW_COMMON_FIELDS_c011;
  uint64 Addr;
  uint32 Tid;
  int32 Value;
} ThreadAutoBoost_t;
  

typedef struct ReadyThread
{
  ETW_COMMON_FIELDS_c011;
  uint32 TThreadId;
  uint8 AdjustReason;
  uint8 AdjustIncrement;
  uint8 Flag;
  uint8 Reserved;
} ReadyThread_t;

typedef struct Process_TypeGroup1 
{
  ETW_COMMON_FIELDS_c011;
  uint64 UniqueProcessKey;
  uint32 ProcessID;
  uint32 ParentID;
  uint32 SessionID;
  uint32 ExitStatus;
  uint64 DirectoryTableBase;
  uint32 UserSID;
  char ImageFileName[];
} Process_TypeGroup1_t;

typedef struct ProcessLoad
{
  ETW_COMMON_FIELDS_c002;
  uint32 Reserved[4];
  uint32 ProcessID;
  uint32 PPid;
  uint32 Reerved[8];
  uint16 Name[];
} ProcessLoad_t;

typedef struct ProcessTerminate
{
  ETW_COMMON_FIELDS_c002;
  uint32 ProcessID;
  uint32 Status;
} ProcessTerminate_t;

typedef struct SysClEnter
{
  ETW_COMMON_FIELDS_c011;
  uint64 SysCallAddress;
} SysClEnter_t;

typedef struct SysClExit
{
  ETW_COMMON_FIELDS_c011;
  uint32 SysCallNtStatus;
} SysClExit_t;

typedef struct SampleProfile
{
  ETW_COMMON_FIELDS_c011;
  uint64 InstructionPointer;
  uint32 ThreadId;
  uint32 Count;
} SampleProfile_t;

typedef struct Interval
{
  ETW_COMMON_FIELDS_c002;
  uint32 ProfileSource;
  uint32 NewInterval;
  uint32 OldInterval;
  uint16 SourceName[0];
} Interval_t;

typedef struct DPC
{ 
  ETW_COMMON_FIELDS_c011;
  uint64 InitialTime;
  uint64 Routine;
} DPC_t;

typedef struct ISR
{ 
  ETW_COMMON_FIELDS_c011;
  uint64 InitialTime;
  uint64 Routine;
  uint8 ReturnValue;
  uint8 Vector;
  uint16 Reserved;
} ISR_t;

typedef struct Cstate
{
  ETW_COMMON_FIELDS_c011;
  uint32 prev_state;
  uint32 next_state;
  uint32 cpumask;
  uint32 filler;
} Cstate_t;
  

typedef struct HardFault
{
  ETW_COMMON_FIELDS_c011;
  uint64 InitialTime;
  uint64 ReadOffset;
  uint64 VirtualAddress;
  uint64 FileObject;
  uint32 TThreadId;
  uint32 ByteCount;
} HardFault_t;

typedef struct Cswitch
{
  ETW_COMMON_FIELDS_c011;
  uint32 NewThreadId;
  uint32 OldThreadId;
  uint8  NewThreadPriority;
  uint8  OldThreadPriority;
  uint8  PreviousCstate;
  uint8  SpareByte;
  uint8  OldThreadWaitReason;
  uint8  OldThreadWaitMode;
  uint8  OldThreadState;
  uint8  OldThreadWaitIdealProcessor;
  uint32 NewThreadWaitTime;
  uint32 Reserved;
} Cswitch_t;

typedef struct FileIo_Info
{
  ETW_COMMON_FIELDS_c002;
  uint64 IrpPtr;
  uint64 TTID;
  uint64 FileObject;
  uint64 FileKey;
  uint32 ThreadId;
  uint32 InfoClass;
} FileIo_Info_t;

typedef struct FileIo_Create
{
  ETW_COMMON_FIELDS_c002;
  uint64 IrpPtr;
  uint64 FileObject;
  uint32 Tid;
  uint32 CreateOptions;
  uint32 FileAttributes;
  uint32 ShareAccess;
  uint16 OpenPath[0];
} FileIo_Create_t;

typedef struct FileIo_ReadWrite
{
  ETW_COMMON_FIELDS_c002;
  uint64 Offset;
  uint64 IrpPtr;
  uint64 TTID;
  uint64 FileObject;
  uint32 FileKey;
  uint32 IoSize;
  uint32 IoFlags;
} FileIo_ReadWrite_t;

typedef struct FileIo_OpEnd
{
  ETW_COMMON_FIELDS_c002;
  uint64 IrpPtr;
  uint32 ExtraInfo;
  uint32 NtStatus;
} FileIo_OpEnd_t;

typedef struct FileIo_DirEnum
{
  ETW_COMMON_FIELDS_c002;
  uint64 IrpPtr;
  uint64 TTID;
  uint64 FileObject;
  uint32 FileKey;
  uint32 Length;
  uint32 InfoClass;
  uint32 FileIndex;
  uint16 FileName[];
} FileIo_DirEnum_t;

typedef struct FileIo_SimpleOp
{
  ETW_COMMON_FIELDS_c002;
  uint64 IrpPtr;
  uint64 TTID;
  uint64 FileObject;
  uint32 FileKey;
} FileIo_SimpleOp_t;

typedef struct FileIo_Name
{
  ETW_COMMON_FIELDS_c011;
  uint64 FileObject;
  uint16 FileName[];
} FileIo_FileName_t;

typedef struct DiskIo_ReadWrite
{
  ETW_COMMON_FIELDS_c011;
  uint32 DiskNumber;
  uint32 IrpFlags;
  uint32 TransferSize;
  uint32 Reserved;
  uint64 ByteOffset;
  uint64 FileObject;
  uint64 Irp;
  uint64 HighResResponseTime;
  uint32 IssuingThreadId;
} DiskIo_ReadWrite_t;

typedef struct DiskIo_Init
{
  ETW_COMMON_FIELDS_c002;
  uint64 Irp;
  uint32 IssuingThreadId;
} DiskIo_Init_t;

typedef struct DiskIo_Flush
{
  ETW_COMMON_FIELDS_c011;
  uint32 DiskNumber;
  uint32 IrpFlags;
  uint64 HighResResponseTime;
  uint64 Irp;
  uint32 IssuingThreadId;
} DiskIo_Flush_t;

typedef struct DiskIo_DrvMjFnCall
{
  ETW_COMMON_FIELDS_c011;
  uint32 MajorFunction;
  uint32 MinorFunction;
  uint64 RoutineAddr;
  uint64 FileObject;
  uint64 Irp;
  uint32 UniqMatchId;
} DiskIo_DrvMjFnCall_t;

typedef struct DiskIo_DrvMjFnRet
{
  ETW_COMMON_FIELDS_c011;
  uint64 Irp;
  uint32 UniqMatchId;
} DiskIo_DrvMjFnRet_t;

typedef struct DiskIo_DrvComplReq
{
  ETW_COMMON_FIELDS_c011;
  uint64 RoutineAddr;
  uint64 Irp;
  uint32 UniqMatchId;
} DiskIo_DrvComplReq_t;


typedef struct DiskIo_DrvComplReqRet
{
  ETW_COMMON_FIELDS_c011;
  uint64 Irp;
  uint32 UniqMatchId;
} DiskIo_DrvComplReqRet_t;

typedef struct DiskIo_DrvComplRout
{
  ETW_COMMON_FIELDS_c011;
  uint64 Routine;
  uint64 Irp;
  uint32 UniqMatchId;
} DiskIo_DrvComplRout_t;

typedef struct NetCommonIPV4
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint32 daddr;
  uint32 saddr;
  uint16 dport;
  uint16 sport;
} NetCommonIPV4_t;

typedef struct NetCommonIPV6
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint16 daddr[8];
  uint16 saddr[8];
  uint16 dport;
  uint16 sport;
} NetCommonIPV6_t;

typedef struct TcpGroup1
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint32 daddr;
  uint32 saddr;
  uint16 dport;
  uint16 sport;
  uint32 seqnum;
  uint32 connid;
} TcpGroup1_t;
  
typedef struct TcpGroup2
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid; 
  uint32 size;
  uint32 daddr;
  uint32 saddr;
  uint16 dport;
  uint16 sport;
  uint16 mss;
  uint16 sackopt;
  uint16 tsopt; 
  uint16 wsopt; 
  uint32 rcvwin; 
  uint16 rcvwinscale; 
  uint16 sndwinscale; 
  uint32 seqnum;
  uint32 connid;
} TcpGroup2_t;

typedef struct TcpGroup3
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint16 daddr[8];
  uint16 saddr[8];
  uint16 dport;
  uint16 sport;
  uint32 seqnum;
  uint32 connid;
} TcpGroup3_t;
  
typedef struct TcpGroup4
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid; 
  uint32 size;
  uint16 daddr[8];
  uint16 saddr[8];
  uint16 dport;
  uint16 sport;
  uint16 mss;
  uint16 sackopt;
  uint16 tsopt; 
  uint16 wsopt; 
  uint32 rcvwin; 
  uint16 rcvwinscale; 
  uint16 sndwinscale; 
  uint32 seqnum;
  uint32 connid;
} TcpGroup4_t;

typedef struct TcpSendIPV4
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid; 
  uint32 size;
  uint32 daddr;
  uint32 saddr;
  uint16 dport;
  uint16 sport;
  uint32 starttime;	/* 32-bit.  NOt sure tha tthis time is?? */
  uint32 endtime;
  uint32 seqnum;	/* Unused */
  uint32 connid;	/* Unused */
} TcpSendIPV4_t;

typedef struct TcpSendIPV6
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid; 
  uint32 size;
  uint16 daddr[8];
  uint16 saddr[8];
  uint16 dport;
  uint16 sport;
  uint32 starttime;
  uint32 endtime;
  uint32 seqnum;
  uint32 connid;
} TcpSendIPV6_t;

typedef struct TcpUdpFail
{
  ETW_COMMON_FIELDS_c011;
  uint16 Proto;
  uint16 FailureCode;
} TcpUdpFail_t;


typedef struct UdpGroup1
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint32 daddr;
  uint32 saddr;
  uint16 dport;
  uint16 sport;
  uint32 seqnum;
  uint32 connid;
} UdpGroup1_t;
  
typedef struct UdpGroup2
{
  ETW_COMMON_FIELDS_c011;
  uint32 Pid;
  uint32 size;
  uint16 daddr[8];
  uint16 saddr[8];
  uint16 dport;
  uint16 sport;
  uint32 seqnum;
  uint32 connid;
} UdpGroup2_t;

typedef struct UdpFail
{
  ETW_COMMON_FIELDS_c011;
  uint16 Protp;
  uint16 FailureCode;
} UdpFail_t;

typedef struct StackWalk
{
  ETW_COMMON_FIELDS_c011;
  uint64 EventTimeStamp;
  uint32 StackProcess;
  uint32 StackThread;
  uint64 Stack[];
} StackWalk_t;

typedef struct SysConfig_CPU 
{
  ETW_COMMON_FIELDS_c002;
  uint32 MHz;
  uint32 NumberOfProcessors;
  uint32 MemSize;
  uint32 PageSize;
  uint32 AllocationGranularity;
  uint16 ComputerName[256];
  uint16 DomainName[132];
  uint32 HyperThreadingFlag;
} SysConfig_CPU_t;


typedef struct SysConfig_NIC 
{
  ETW_COMMON_FIELDS_c011;
  uint64 PhysicalAddr;
  uint32 PhysicalAddrLen;
  uint32 Reserved1;
  uint64 Reserved2;
  uint32 Reserved3[3];
  uint16 Name[]; 
} SysConfig_NIC_t;


typedef struct SysConfig_PhysDisk
{
  ETW_COMMON_FIELDS_c002;
  uint32 DiskNumber;
  uint32 BytesPerSector;
  uint32 SectorsPerTrack;
  uint32 TrackesPerCylinder;
  uint64 Cylinders;
  uint32 SCSIPort;
  uint32 SCSIPath;
  uint32 SCSITarget;
  uint32 SCSILun;
  uint16 Manufacturer[256];
  uint32 PartitionCount;
  uint8 WriteCacheEnabled;
  uint16 BootDriveLetter[4];
} SysConfig_PhysDisk_t;

typedef struct SysConfig_LogDisk
{
  ETW_COMMON_FIELDS_c002;
  uint64 StartOffset;
  uint64 PartitionSize;
  uint32 DiskNumber;
  uint32 Size;
  uint32 DriveType;
  uint16 DriveLetterString[4];
  uint32 Pad1;
  uint32 PartitionNumber;
  uint32 SectorsPerCluster;
  uint32 BytesPerSector;
  uint32 Pad2;
  uint64 NumberofFreClusters;
  uint64 TotalNumberOfCluster;
  uint16 FileSystem[16];
  uint32 VolumeExt;
  uint32 Pad3;
} SysConfig_LogDisk_t;

typedef struct SysConfig_Services
{
  ETW_COMMON_FIELDS_c002;
  uint32 ProcessId;
  uint32 ServiceState;
  uint32 SubProcessTag;
  uint16 Name[];
} SysConfig_Services_t;

typedef struct SysConfig_PnP
{
  ETW_COMMON_FIELDS_c002;
  uint32 Reserved[8];
  uint16 Name[];
} SysConfig_PnP_t;

typedef struct SysConfig_IRQ
{
  ETW_COMMON_FIELDS_c002;
  uint64 IRQAffinity;
  uint32 Reserved;
  uint32 IRQNum;
  uint32 DeviceDescriptionLen;
  uint16 DeviceDescription[];
} SysConfig_IRQ_t;

typedef struct SysConfig_Power
{
  ETW_COMMON_FIELDS_c002;
  uint8 s1;
  uint8 s2;
  uint8 s3;
  uint8 s4;
  uint8 s5;
  uint8 Pad1;
  uint8 Pad2;
  uint8 Pad3;
} SysConfig_Power_t;

extern EventTraceHdr_t *winki_hdr;

#define WINKI_MAX_DEPTH 128
typedef struct winki_stack_info
{
        uint64 Stack[WINKI_MAX_DEPTH];
        int depth;
} winki_stack_info_t;

