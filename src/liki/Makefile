# Mandatory values that must be defined to the preprocessor are:
#
# HARDCLOCK_STACK_SKIP=<N>
#		The number of frames to discard from top of stack in a
#		hardclock trace. This is a lot deeper that all the
#		other cases because it includes the timer mechanism
#		frames
#		
# OTHER_STACK_SKIP=<N>
#		The number of frames to discard from top of stack in all
#		other traces
#		
# The following may be defined by adding to EXTRA_CFLAGS to modify behavior:
#
# SLES11	SLES11 has a very costly unwind mechanism that can cripple
#		performance and maybe even crash the system when executed 
#		frequently. Defining this tells LiKI to force the kernel to 
#		use the older less accurate but less costly unwind. Possibly 
#		other versions of SLES have the same issue; I haven't checked.
#
# BROKEN_PLATFORM_CLOCKS
#		Linux is supposed to provide monotonically increasing global
#		clocks through ktime_get(). If for some reason the times in
# 		a merged trace file appear inconsistent then define this to
#		revert to using the old LiKI clock code.
#
# __LIKI_DEBUG	Define __LIKI_DEBUG for a lot of extra runtime checking, but be 
#		aware that this changes the trace format, so you have to compile 
#		the module and LiKI userspace tools (likif etc.) with __LIKI_DEBUG
#		otherwise you'll get messages about corrupted tracefiles. Note 
#		that kiinfo does not udnerstand the debug record format.
#
# A bunch of things to which LiKI is sensitive have changed between kernel releases.
# LiKI tries to adapt to the kernel version for which it is being compiled by 
# comparing LINUX_VERSION_CODE to some threshold values, e.g.:
#
#  #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#    < do this >
#  #else 
#    < do this >
#  #endif
#
# I think I have most of the threshold values about right, but they are unlikely
# to be exact. So if you find your build barfing in code surrounded by one of 
# these conditions, you may need to fine-tune the kernel version threshold. If
# you do this please let me know so I can change my copy too.
#
# To cross-compile x86_64 to ARM64 invoke make thus:
# make ARCH=arm64 CROSS_COMPILE=aarch64-apm-linux-gnu-

hostkernel:=$(shell uname -r)
ifneq (,$(wildcard /etc/oracle-release))
   hostdistro:=ol
   hostversion:=$(shell grep -oE '[0-9]+\.[0-9]+' /etc/oracle-release)
else ifneq (,$(wildcard /etc/fedora-release))
   hostdistro:=fedora
   hostversion:=$(shell grep -oE '[0-9]+' /etc/fedora-release)
else ifneq (,$(wildcard /etc/centos-release))
   hostdistro:=centos
   hostversion:=$(shell grep -oE '[0-9]+\.[0-9]+' /etc/centos-release)
else ifneq (,$(wildcard /etc/redhat-release))
   hostdistro:=rhel
   hostversion:=$(shell grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release)
else ifneq (,$(wildcard /etc/SuSE-release))
   hostdistro:=sles
   hostversion:=$(shell awk '{if ($$1 == "VERSION") printf "%s.", $$3; \
                              else if ($$1 == "PATCHLEVEL") printf "%s", $$3}' \
                            /etc/SuSE-release)
else ifneq (,$(wildcard /etc/os-release))
   hostdistro:=$(shell grep "^ID=" /etc/os-release|awk -F= '{print $$2}')
   hostversion:=$(shell grep "^VERSION_ID=" /etc/os-release \
                        | awk -F= '{print $$2}' | sed -e 's/"//g')
else ifneq (,$(wildcard /etc/os-release))
   hostdistro:=$(shell grep "^ID=" /etc/os-release|awk -F= '{print $$2}')
   hostversion:=$(shell uname -r | sed 's/-/ /g' | sed 's/_/ /g' | awk '{print $$1}')
endif

$(info hostkernel=${hostkernel})
$(info hostdistro=${hostdistro})
$(info hostversion=${hostversion})

ifeq ($(hostdistro),rhel) # Red Hat Enterprise Linux (RHEL)
   ifneq (,$(findstring 6.,$(hostversion)))
      #RHEL6 (2.6)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 7.,$(hostversion)))
      #RHEL 7 (3.10)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=9 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.0,$(hostversion)))
      #RHEL 8.0 (4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.1,$(hostversion)))
      #RHEL 8.1(4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.,$(hostversion)))
      #RHEL 8.2 and later (4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL82 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   endif
else ifeq ($(hostdistro),centos) #  Centos
   ifneq (,$(findstring 6.,$(hostversion)))
      #RHEL6 (2.6)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 7.,$(hostversion)))
      #RHEL 7 (3.10)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=9 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.0,$(hostversion)))
      #RHEL 8.0 (4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.1,$(hostversion)))
      #RHEL 8.1(4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   else ifneq (,$(findstring 8.,$(hostversion)))
      #RHEL 8 (4.18)
      EXTRA_CFLAGS=-g -O3 -Wall -DRHEL82 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
   endif
else ifeq ($(hostdistro),ol) # Oracle Linux (OL)
   ifeq (,$(findstring uek,$(hostkernel)))
      #OL Red Hat compatible kernel
      ifneq (,$(findstring 6.,$(hostversion)))
         #RHEL6 (2.6)
         EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 7.,$(hostversion)))
         #RHEL 7 (3.10)
         EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=9 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.0,$(hostversion)))
         #RHEL 8.0 (4.18)
         EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.1,$(hostversion)))
        #RHEL 8.1(4.18)
        EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.,$(hostversion)))
        #RHEL 8.2 and later (4.18)
        EXTRA_CFLAGS=-g -O3 -Wall -DRHEL82 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifeq ($(hostdistro),ol) # Oracle Linux (OL)
   ifeq (,$(findstring uek,$(hostkernel)))
      #OL Red Hat compatible kernel
      ifneq (,$(findstring 6.,$(hostversion)))
         #RHEL6 (2.6)
         EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 7.,$(hostversion)))
         #RHEL 7 (3.10)
         EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=9 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.0,$(hostversion)))
         #RHEL 8.0 (4.18)
         EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.1,$(hostversion)))
        #RHEL 8.1(4.18)
        EXTRA_CFLAGS=-g -O3 -Wall -DRHEL8 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else ifneq (,$(findstring 8.,$(hostversion)))
        #RHEL 8.2 and later (4.18)
        EXTRA_CFLAGS=-g -O3 -Wall -DRHEL82 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      else
        EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      endif
   else ifneq (,$(findstring uek,$(hostkernel)))
      #OL Unbreakable Enterprise Kernel (UEK)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=2
   endif
else
        EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
      endif
   else ifneq (,$(findstring uek,$(hostkernel)))
      #OL Unbreakable Enterprise Kernel (UEK)
      EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=2
   endif
else ifneq (,$(findstring sles,$(hostdistro))) # SUSE Linux Enterprise Server (SLES)
    ifneq (,$(findstring 11.,$(hostversion)))
        #SLES11
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES11 -DHARDCLOCK_STACK_SKIP=11 -DOTHER_STACK_SKIP=3
    else ifneq (,$(findstring 12.,$(hostversion)))
        #SLES12
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES12 -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=3
    else ifneq (,$(findstring 15,$(hostversion)))
        #SLES15
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES15 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=3
    endif
else ifneq (,$(findstring opensuse,$(hostdistro))) # Open SUSE (opensuse)
    ifneq (,$(findstring 11.,$(hostversion)))
        #SLES11
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES11 -DHARDCLOCK_STACK_SKIP=11 -DOTHER_STACK_SKIP=3
    else ifneq (,$(findstring 12.,$(hostversion)))
        #SLES12
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES12 -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=3
    else ifneq (,$(findstring 15,$(hostversion)))
        #SLES15
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES15 -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=3
    endif
else ifeq ($(hostdistro),debian) # Debian, same as SLES
    ifneq (,$(findstring 8,$(hostversion)))
        #Debian 8
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES12 -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=3
    else ifneq (,$(findstring 9,$(hostversion)))
        #Debian 9
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES12 -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=3
    else
        EXTRA_CFLAGS=-g -O3 -Wall -DSLES11 -DHARDCLOCK_STACK_SKIP=11 -DOTHER_STACK_SKIP=3
    endif
else ifeq ($(hostdistro),fedora)
   #FEDORA 
   EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=6 -DOTHER_STACK_SKIP=2
else ifeq ($(hostdistro),ubuntu)
    ifneq (,$(findstring 18,$(hostversion)))
	#UBUNTU 18.X
        EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
    else
   	#UBUNTU 12.04, 12.10 (3.5)
        EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=2
    endif
else ifeq ($(hostdistro),arch)
   #ARCH Linux
   EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=8 -DOTHER_STACK_SKIP=0
else
   #
   # Defaults
   #
   EXTRA_CFLAGS=-g -O3 -Wall -DHARDCLOCK_STACK_SKIP=0 -DOTHER_STACK_SKIP=0
endif

$(info EXTRA_CFLAGS=${EXTRA_CFLAGS})
ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 

PWD := $(shell pwd)  

.PHONY: build clean  

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
	cp likit.ko likit.ko.$(shell uname -r)

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko* *.mod.c *.unsigned *.order Module*

install:
	cp likit.ko /opt/linuxki/modules/likit.ko.$(shell uname -r)
	mkdir /lib/modules/$(shell uname -r)/misc 2>/dev/null
	cp likit.ko /lib/modules/$(shell uname -r)/misc/

else

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m := likit.o

endif

