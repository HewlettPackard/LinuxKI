echo "time,device,rw,sector,length,qpid,spid,qtime,svctime" > kidsk_global.csv
grep  block_rq_complete ki.$1 | grep ' tgid=' > /dev/null
RETVAL=$?
if [ $RETVAL -ne 0 ] ; then
    grep ' block_rq_complete ' ki.$1 | awk '{print $1","$5","$6","$8","$9","$12","$13","$15","$17}' > kidsk_global.raw1
else 
    grep ' block_rq_complete ' ki.$1 | awk '{print $1","$6","$7","$9","$10","$13","$14","$16","$18}' > kidsk_global.raw1
fi
sed 's/,/ /g' kidsk_global.raw1| sed 's/=/ /g' | cut -d ' ' -f 1,3,5,7,9,11,13,14,15 >  kidsk_global.raw2
sed 's/ /,/g' kidsk_global.raw2 | head -20000  >> kidsk_global.csv
rm -Rf kidsk_global.raw*




