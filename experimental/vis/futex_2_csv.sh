#!/bin/bash
echo "time,cpu,pid,retval,sctime,addr,op,val" > futex_global.csv
grep ' futex ' ki.$1 |grep -v entry| awk '{print $1","$2","$3","$7","$9","$10","$11","$12}' > futex_global.raw1
grep -v ',,'  futex_global.raw1 >  futex_global.raw2
sed 's/,/ /g' futex_global.raw2| sed 's/=/ /g' | cut -d ' ' -f 1,3,5,7,8,10,12,14 >  futex_global.raw3
sed 's/ /,/g' futex_global.raw3 | head -20000 >> futex_global.csv
rm -Rf futex_global.raw*




