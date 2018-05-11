# LinuxKI Toolset v5.4

The LinuxKI Toolset version 5.4 is now available (05/11/2018).   Version 5.4 includes the following changes:

* Added support for Linux kernel through 4.16.3.
* IRQ trace events now enabled by default.
* Added new workqueue events as non-default events
* Added Kparse warning - How add_random impacts block device performance
* Added Kparse warning - Network-latency tuned profile may increase System CPU usage and decrease overall performance
* Added Kparse warning - High kworker CPU usage when using software RAID (md driver) with barrier writes
* Enabled Advanced CPU statistics on Skylake processors.
* Disabled Advanced CPU statistics for Virtual Machines as it was unreliable for some VMs.
* Added LinuxKI manpages.   See man linuxki(7).
* Added /etc/profile.d/linuxki.sh to add /opt/linuxki so the PATH variable.
* Added support to demangle C++ function names (and also an option to leave them mangled if desired).
* Added Top Tasks by Multipath device to kidsk/kparse/clparse output to help identify tasks generating IO when kworkers initiate the IO at the SCSI layer
* For runki script, added -p option to skip per-PID datat (lsof, stacks, numa_maps_maps) to avoid long delays if system has thousands of tasks on the system.
* Improved error reporting if online analysis is done without root access or if debugfs is not mounted.
* Added code to clear /sys/module/kgdboc/parameters/kgdboc to avoid crash as its incompatible with LinuxKI.    Typically, customer systems do not have kgdboc set, but some internal lab systems do.
* Change madvise/mmap/mmap2 length argument formatting from decimal to hex
* Fixed kiinfo coredump when parsing cpuinfo output due to missing “@” character when looking for the GHz speed for kiinfo -live, fixed Global CPU usage (usr/sys% is sometimes off) on main global screen
*:Fixed the multipath parsing to understand lines that start with “|-|-“
* Removed PID stats from CPU window when running kiinfo -live on dumps as this stat is not available with trace dumps.

For more information, be sure to check out the LinuxKI MasterClass:

[LinuxKI MasterClass](https://github.com/HewlettPackard/LinuxKI/raw/master/documentation/LinuxKI_MasterClass.pdf)
