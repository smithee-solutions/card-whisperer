# make file for cardcalc

PROGS=cardcalc

CC=clang
LINK=clang
CFLAGS=-c -g -Wall -Werror
LDFLAGS=-g

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

cardcalc:	cardcalc.o Makefile
	${LINK} -o cardcalc cardcalc.o ${LDFLAGS}

cardcalc.o:	cardcalc.c
	${CC} ${CFLAGS} cardcalc.c

