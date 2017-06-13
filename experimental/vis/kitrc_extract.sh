tag=$( ls ki.[0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9] 2>/dev/null | awk '{print substr($1,match($1,"[0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9]"))}'   )
cwd=$(pwd)
cd ../../
/opt/linuxki/kiinfo -kitrace -ts $tag -starttime $1 -endtime $2 > $cwd/kitrc.txt 2>&1
