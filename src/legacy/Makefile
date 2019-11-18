# make file for cardcalc

PROGS=cardcalc

CC=clang
LINK=clang
CFLAGS=-c -g -Wall -Werror
LDFLAGS=-g
BUILDDIR=../../opt/tester

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}
	( cd ${BUILDDIR}/bin; rm -f ${PROGS} )

build:	all
	mkdir -p ${BUILDDIR}/bin
	cp ${PROGS} ${BUILDDIR}/bin

cardcalc:	cardcalc.o Makefile
	${LINK} -o cardcalc cardcalc.o ${LDFLAGS}

cardcalc.o:	cardcalc.c
	${CC} ${CFLAGS} cardcalc.c

