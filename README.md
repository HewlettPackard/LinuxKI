# LinuxKI Toolset

The LinuxKI Toolset (or LinuxKI for short) is an opensource, application centric, data-driven, advanced mission critical performance troubleshooting tool for Linux.  It designed to identify performance issues beyond the typical performance metrics and results in faster root cause for many performance issues. LinuxKI is a kernel tracing toolkit designed to answer two primary questions about the system:

* If its running, whats it doing?
* If its waiting, whats it waiting on?

LinuxKI is designed to be easy to install, collect data, and generate reports.   It runs on Linux kernels 2.6.32 or later running on x86_64 and arm64 platforms. It collects low-level detailed traces reflecting the behavior of the running workload, which can be analyzed online or bundled along with configuration and other performance data into a single gzip file suitable for transfer and offline analysis.  The KI data collected is also portable and can be collected on one system and analyzed on another system.

Kiinfo can collect its trace data from either of two sources: the Linux ftrace facility, or the LiKI DLKM supplied as part of this toolset.   The default tracing mechanism used is LiKI, however you may chose to use ftrace if desired.  Here are some considerations:

  - LiKI is an opensource kernel tracing facility written by HPE specifically for large mission-critical servers. It collects significantly more detail than ftrace allowing more precise analysis, while imposing less overhead. However LiKI is a kernel module that is loaded into the kernel when collection begins, and removed immediately afterwards. Installation of the LiKI DLKM may taint some Linux kernels and is not supported by the Linux providers.

  - ftrace is a Linux kernel tracing facility that is built into most versions of the Linux kernels (2.6.32 and later), such as RHEL 6 and SLES 11 SP2.  The runki script  will use the ftrace data source if the LiKI DLKM fails to load or if the "-f" option is passed to the runki script.  Only a select set of tracepoints are enabled, keeping the overhead reasonably low. The LinuxKI Toolset will do all the work of enabling the trace points and collecting the data from its in-kernel ring buffers. While the ftrace code is included in more recent Linux kernels, it is generally disabled, so HPE cannot comment on how well it has been tested by the Linux vendor (RedHat, Novel).

Using the LiKI tracing module is the preferred method, but ftrace may be used in cases where where the LiKI DLKM cannot be installed, either due to missing dependencies, or inherent risks of installing a DLKM.

###Disclaimer of Warranty and Limitation of Liability Notices

Refer to the COPYING.liki, COPYING.kiinfo, LICENSE.txt files for additional
information.

### Overview
After installing the LinuxKI Toolset, a 20-second trace dump can easily be obtained as follows:

    $ export PATH=$PATH:/opt/linuxki 
    $ /dev/shm        # to collect data in memory, optional
    $ runki           # use LiKI 

or

    $ runki -f         # use ftrace tracing

After data collection, a default set of reports can be generated as follows:

    $ kiall -r         # -r option creates a nodename/timestamp directory structure


###Download
Pre-packaged RPM and DEB files are available at the following locations:

(https://github.com/HewlettPackard/LinuxKI/tree/master/](https://github.com/HewlettPackard/LinuxKI/tree/master/rpms)

###Prerquisites

Install Linux kernel header/devel package(s) if you want to collect data using the LiKI DKLM tracing module.  You will also need basic developer tools like gcc and make.

###Installation

The LinuxKI Toolset is provided in an RPM Package and can be installed as
follows:

    # rpm --install --nodeps linuxki.<version>.noarch.rpm

Or for Debian-related kernels, the toolset can be installed using the dpkg
command:

    # dpkg --install linuxki.<version>_all.deb

The files are installed in the /opt/linuxki directory. You should add this directory to the PATH of the root user for the duration of the data collection session.

You can also use your favorite package manager, such as yum.

    # yum localinstall linuxki.<version>.noarch.rpm

###Removing the LinuxKI toolset

You can remove the LinuxKI toolset using rpm or dpkg as follows:

     # rpm --erase linuxki

     # dpkg --remove linuxki
     # dpkg --purge linuxki


###Compiling the LiKI module

The LinuxKI Toolset has a few pre-compiled likit.ko modules avaiable.  However, due to the large numbers of Linux distributes and versions available, it is not possible to pre-compile and test every version.

If the supplied LiKI kernel module (likit.ko) will not load on your distribuition, the toolset installation will attempt build a new LiKI modules directly from the source code.   In order to compile from source code, the following dependencies must be installed:

* kernel-devel
* kernel-headers
* gcc
* make

If LiKI fails to compile, you can resolve the dependency issue and execute the module_prep script to manually build the LiKI DLKM tracing module.  You can also continue to use the LinuxKI Toolset using the ftrace tracing
mechanism.

###Data Collection

When the system is experiencing performance problems, the runki script can be run to collect data. By default 20 seconds of sample data will be collected, and then runki will spend some time longer gathering other performance and configuration data and bundling this into a single gzip archive. It might take several minutes in all to complete. Only superuser can collect data.  Data is stored in the current working directory, and may require several hundred megabytes or gigabytes of space per collection run, depending on the size of the system and amount of trace data generated.  The filesystem on which data is stored should be enabled to use the filesystem cache; directIO is not recommended.  If sufficient memory is available, the current working directory can be changed to /dev/shm and the runki script can collect the data in-memory and then copied to persistent storage later.

You can execute the runki script using either ftrace or LiKI:

    $ runki                          # default uses LiKI

    $ runki -f                       # use -f to use ftrace

When the data collection is complete, you will see a message similar to the following...

    === Trace completed and archived as ki_all.localhost.0613_1310.tgz

### Verifying the LinuxKI toolset version

You can verify the version of the LinuxKI toolset using rpm or dpkg as follows:

     $ rpm --query linuxki
     linuxki-5.1-1.noarch

     $ dpkg --status linuxki | grep Version
     Version: 5.1-1

### For more information

For additional information, please refer to the following documents:

[LinuxKI Quick Reference Guide](https://github.com/HewlettPackard/LinuxKI/blob/master/documentation/LinuxKI_QuickRefGuide.pdf)
[LinuxKI Frequently Asked Questions](https://github.com/HewlettPackard/LinuxKI/blob/master/documentation/LinuxKI_FAQ.pdf)
[LinuxKI MasterClass)(https://github.com/HewlettPackard/LinuxKI/blob/master/documentation/LinuxKI_MasterClass.pdf)
