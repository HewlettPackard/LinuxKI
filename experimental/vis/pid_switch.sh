#!/bin/bash
set -x
export tag=$2
echo "start,end,cpu,pid,tgid,type,waker,scall_tgt,state,next_tgtcpu,func_ok,id,timestamp" > VIS/$1/pid_switch.csv

/opt/linuxki/kiinfo -kitrace pid=$1 -ts $2 -starttime $3 -endtime $4  > VIS/$1/pid_switch_sh.tmp1
do_stealtime=0
do_msrstats=0

grep stealtime VIS/$1/pid_switch_sh.tmp1
if [ $? == 0 ] ; then
	do_stealtime=1
fi
grep llcref VIS/$1/pid_switch_sh.tmp1 
if [ $? == 0 ] ; then
        do_msrstats=1
fi


cat VIS/$1/pid_switch_sh.tmp1  | grep -E " sched_wakeup target_pid=$1 | sched_switch " | grep "pid=$1"  > VIS/$1/pid_switch_sh.tmp2

if [ $do_stealtime -eq 1 ] && [ $do_msrstats -eq 1 ] ; then

	cat VIS/$1/pid_switch_sh.tmp2 | awk -f /opt/linuxki/experimental/vis/pid_switch_steal_msr.awkpgm | sed 's/=/ /g' | sed 's/n\/a/NA/g' | awk '{print $1",0,"$3","$5","$7","$8",0,"$10","$12","$14","$15",0,"ENVIRON["tag"]}'  >> VIS/$1/pid_switch.csv

fi

if [ $do_stealtime -eq 1 ] && [ $do_msrstats -eq 0 ] ; then

        cat VIS/$1/pid_switch_sh.tmp2 | awk -f /opt/linuxki/experimental/vis/pid_switch_steal.awkpgm | sed 's/=/ /g' | sed 's/n\/a/NA/g' | awk '{print $1",0,"$3","$5","$7","$8",0,"$10","$12","$14","$15",0,"ENVIRON["tag"]}'  >> VIS/$1/pid_switch.csv

fi

if [ $do_stealtime -eq 0 ] && [ $do_msrstats -eq 1 ] ; then

        cat VIS/$1/pid_switch_sh.tmp2 | awk -f /opt/linuxki/experimental/vis/pid_switch_msr.awkpgm | sed 's/=/ /g' | sed 's/n\/a/NA/g' | awk '{print $1",0,"$3","$5","$7","$8",0,"$10","$12","$14","$15",0,"ENVIRON["tag"]}'  >> VIS/$1/pid_switch.csv

fi

if [ $do_stealtime -eq 0 ] && [ $do_msrstats -eq 0 ] ; then

        cat VIS/$1/pid_switch_sh.tmp2 | awk -f /opt/linuxki/experimental/vis/pid_switch.awkpgm | sed 's/=/ /g' | sed 's/n\/a/NA/g' | awk '{print $1",0,"$3","$5","$7","$8",0,"$10","$12","$14","$15",0,"ENVIRON["tag"]}'  >> VIS/$1/pid_switch.csv

fi

# rm -f VIS/$1/pid_switch_sh.tmp*

ln -s /opt/linuxki/experimental/vis/pid_switch.html VIS/$1/pid_switch.html






