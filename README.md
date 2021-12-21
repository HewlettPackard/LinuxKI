# LinuxKI Toolset v7.3

The LinuxKI Toolset (or LinuxKI for short) is an opensourced advanced mission critical performance troubleshooting tool for Linux.  It is designed to identify performance issues beyond the typical performance metrics and results in faster root cause for many performance issues. LinuxKI is a kernel tracing toolkit designed to answer two primary questions about the system:

* If it's running, what's it doing?
* If it's waiting, what's it waiting on?

LinuxKI analyzes the kernel trace data in different and often unique ways to help performance specialist drill down on often complex performance issues.   The following output is an example of data displayed for a specific task:

    PID:  133343 /home/mcr/bin/iotest8

    RunTime    :  3.730009  SysTime   :  3.650014   UserTime   :  0.078149   StealTime  :  0.000000
    SleepTime  :  5.654813  Sleep Cnt :    161700   Wakeup Cnt :     85898
    RunQTime   :  0.615273  Switch Cnt:    161708   PreemptCnt :         8
    Last CPU   :        57  CPU Migrs :        25   NODE Migrs :         0
    Policy     : SCHED_NORMAL     vss :      1074          rss :       159

       LLC_ref   LLC_hits  LLC_hit%     Instrs     Cycles      CPI   Avg_MHz  SMI_cnt
       148482k    143389k    96.57%    4884.9m   11920.2m     2.44   3200.00       33

    ------------------------- Top Hardclock Functions ---------------------------
       Count     Pct  State  Function
         115  23.71%  SYS    rwsem_wake
          76  15.67%  SYS    __blk_run_queue
          47   9.69%  SYS    __schedule
          32   6.60%  SYS    blk_queue_bio
          23   4.74%  SYS    blk_finish_plug

    ---------------------------- Top Wait Functions -----------------------------
       Count     SlpTime  Msec/Slp  MaxMsecs  Func
       79806    5.288981     0.066   579.234  io_schedule_timeout
       47151    0.217324     0.005     0.412  rwsem_down_read_failed
       34743    0.148508     0.004     0.409  rwsem_down_write_failed

    ------------------------ Total I/O ------------------------- ------------------- Write I/O ------------------- -------------------- Read I/O -------------------
    Device        IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv    IO/s    MB/s  AvIOsz AvInFlt   Avwait   Avserv
    All           7980      62       8    8.57     0.00     0.08    7980      62       8    8.57     0.00     0.08       0       0       8    0.00     0.00     0.04
    sdb           7980      62       8    8.57     0.00     0.08    7980      62       8    8.57     0.00     0.08       0       0       8    0.00     0.00     0.04

    ----------------------------- Top System Calls ------------------------------
    System Call Name     Count     Rate     ElpTime        Avg        Max    Errs    AvSz     KB/s
    write                79807   7980.6    9.892351   0.000124   0.579275       0    8192  63844.7  
       SLEEP            161700  16169.8    5.654813   0.000035
          Sleep Func     79806             5.288981   0.000066  io_schedule_timeout
          Sleep Func     47151             0.217324   0.000005  rwsem_down_read_failed
          Sleep Func     34743             0.148508   0.000004  rwsem_down_write_failed
       RUNQ                                0.615269
       CPU                                 3.622297
    lseek                79808   7980.7    0.029498   0.000000   0.000012       0

LinuxKI is designed to be easy to install, collect data, and generate reports.   It runs on Linux kernels 2.6.32 or later running on x86_64, arm64 and ppc64 platforms. It collects low-level detailed traces reflecting the behavior of the running workload, which can be analyzed online or bundled along with configuration and other performance data into a single gzip file suitable for transfer and offline analysis.  

LinuxKI only enables key tracepoints in the performance paths, such as scheduler events, system call events, block I/O events, interrupt events, and CPU profiling events.   It has the ability to collect system and user stack traces during sched_switch events and CPU profiling events, and much more.   LinuxKI can analyze the detailed trace data in many different ways - per-PID, per-device, per-HBA path, per-CPU, per-LDOM, per-interrupt, per-Docker container, and much more.  

LinuxKI can collect its trace data from either of two sources: the Linux ftrace facility, or the LiKI DLKM supplied as part of this toolset.   The default tracing mechanism used is LiKI, however you may chose to use ftrace if desired.  Here are some considerations:

  - LiKI is an opensource kernel tracing facility written by HPE specifically for large mission-critical servers. It collects significantly more detail than ftrace allowing more precise analysis, while imposing less overhead. However LiKI is a kernel module that is loaded into the kernel when collection begins, and removed immediately afterwards. Installation of the LiKI DLKM may taint some Linux kernels and is not supported by the Linux providers.

  - ftrace is a Linux kernel tracing facility that is built into most versions of the Linux kernels (2.6.32 and later), such as RHEL 6 and SLES 11 SP2.  The runki script  will use the ftrace data source if the LiKI DLKM fails to load or if the "-f" option is passed to the runki script.  Only a select set of tracepoints are enabled, keeping the overhead reasonably low. The LinuxKI Toolset will do all the work of enabling the trace points and collecting the data from its in-kernel ring buffers. While the ftrace code is included in more recent Linux kernels, it is generally disabled, so HPE cannot comment on how well it has been tested by the Linux vendor (RedHat, Novel).

Using the LiKI tracing module is the preferred method, but ftrace may be used in cases where where the LiKI DLKM cannot be installed, either due to missing dependencies, or inherent risks of installing a DLKM.

### Disclaimer of Warranty and Limitation of Liability Notices

Refer to the COPYING.liki, COPYING.kiinfo, LICENSE.txt files for additional information.

## Overview
The following documentation provides a brief overview for downloading and installing the LinuxKI Toolset, as well as data collection and report generation.   Be sure to refer to the LinuxKI MasterClass, LinuxKI Quick Reference Guide, and LinuxKI FAQ for complete documentation:

[LinuxKI Quick Reference Guide](https://github.com/HewlettPackard/LinuxKI/raw/master/documentation/LinuxKI_QuickRefGuide.pdf)
\
[LinuxKI Frequently Asked Questions](https://github.com/HewlettPackard/LinuxKI/raw/master/documentation/LinuxKI_FAQ.pdf)
\
[LinuxKI MasterClass](https://github.com/HewlettPackard/LinuxKI/raw/master/documentation/LinuxKI_MasterClass.pdf)

### Download
Pre-packaged RPM and DEB files are available on the [Releases Page](https://github.com/HewlettPackard/LinuxKI/releases).

### Prerequisites

There are no mandatory pre-requisites.   LinuxKI should install and run on most Linux systems from 2.6.32 through 5.14.21

However, if you would like to use the LiKI tracing mechanism (perferred method), you will need the following packages installed to compile the LiKI module from source code:

* kernel-devel
* kernel-headers
* gcc
* make

If LiKI fails to compile, you can resolve the dependency issue and execute the module_prep script to manually build the LiKI DLKM tracing module.  You can also continue to use the LinuxKI Toolset using the ftrace tracing mechanism.

### Installation

The LinuxKI Toolset is provided in an RPM Package and can be installed as follows:

    # rpm --install --nodeps linuxki.<version>.noarch.rpm

Or for Debian-related kernels, the toolset can be installed using the dpkg command:

    # dpkg --install linuxki.<version>_all.deb

The files are installed in the /opt/linuxki directory. You should add this directory to the PATH of the root user for the duration of the data collection session.

You can also use your favorite package manager, such as yum.

    # yum localinstall linuxki.<version>.noarch.rpm
    
### Verifying the LinuxKI toolset version

You can verify the version of the LinuxKI toolset using rpm or dpkg as follows:

     $ rpm --query linuxki
     linuxki-7.3-1.noarch

     $ dpkg --status linuxki | grep Version
     Version: 7.3-1

### Removing the LinuxKI toolset

You can remove the LinuxKI toolset using rpm or dpkg as follows:

     # rpm --erase linuxki

     # dpkg --remove linuxki
     # dpkg --purge linuxki

### Data collection

When the system is experiencing performance problems, the runki script can be executed to collect data. By default 20 seconds of trace data will be collected, and then runki will spend some time gathering other configuration and supplemental data, and then bundle this into a single gzip archive. It might take several minutes in all to complete. Root/superuser privilege is required to collect the trace data.  The data is stored in the current working directory, and may require several hundred megabytes or gigabytes of space per collection run, depending on the size of the system and amount of trace data generated.  The filesystem on which data is stored should be enabled to use the filesystem cache; directIO is not recommended.  If sufficient memory is available, the current working directory can be changed to /dev/shm and the runki script can collect the data in-memory and then copied to persistent storage later.

After installing the LinuxKI Toolset, a 20-second trace dump can easily be obtained as follows:

    $ export PATH=$PATH:/opt/linuxki 
    $ cd /dev/shm     # optional, to collect data in memory
    $ runki           # use LiKI tracing mechanism

or

    $ runki -f         # use ftrace tracing mechanism
    
When the data collection is complete, you will see a message similar to the following...

    === Trace completed and archived as ki_all.localhost.0613_1310.tgz

### Trace analysis

After data collection, a default set of reports can be generated as follows:

    $ kiall -r         # -r option creates a nodename/timestamp directory structure
    
Most of the generated reports are text based and can be viewed with a standard editor or text viewer.
