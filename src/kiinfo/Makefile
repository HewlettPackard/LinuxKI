SRCS = "*.c"
TARGET = "kiinfo"

all: 
	gcc -g -O2 -lc -lrt -Wformat=0 -o kiinfo *.c -D__LIKI_RTMERGE -D_GNU_SOURCE -lpthread -lncurses

clean: 
	rm -rf kiinfo.aarch64
	rm -rf kiinfo
	rm -rf kiinfo.x86_64


