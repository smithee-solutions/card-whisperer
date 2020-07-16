PROGS=dump-fascn

CC=clang
CFLAGS=-c -g -Wall -Werror
LINK=clang
LDFLAGS=-g

all:	${PROGS}

clean:
	rm -f *.o core ${PROGS}

build:
	mkdir -p ../../opt/tester/bin
	cp ${PROGS} ../../opt/tester/bin

dump-fascn:	dump-fascn.o Makefile
	${LINK} -o dump-fascn dump-fascn.o ${LDFLAGS}

dump-fascn.o:	dump-fascn.c
	${CC} ${CFLAGS} dump-fascn.c

