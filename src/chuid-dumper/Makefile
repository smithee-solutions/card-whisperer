PROGS=unwind

CC=clang
CFLAGS=-c -g -Wall -Werror
LINK=clang
LDFLAGS=-g

all:	${PROGS}

clean:
	rm -f *.o core ${PROGS}

unwind:	unwind.o Makefile
	${LINK} -o unwind unwind.o ${LDFLAGS}

unwind.o:	unwind.c
	${CC} ${CFLAGS} unwind.c

