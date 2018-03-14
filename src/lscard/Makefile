# Makefile for lscard

#  (C)Copyright 2017-2018 Smithee Solutions LLC

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PROGS=lscard ls73 read-fascn write-chuid
CC=clang
LINK=clang
BUILD_DIR=../../opt/tester
CFLAGS=-c -g -I../../include -I/usr/include/PCSC -Wall -Werror
LDFLAGS=-L${BUILD_DIR}/lib -lcardwhisper

all:	${PROGS}

clean:
	rm -rvf a.out core *.o ${PROGS}

build:	all
	mkdir -p ${BUILD_DIR}/bin
	cp ${PROGS} ${BUILD_DIR}/bin

lscard:	lscard.o ${BUILD_DIR}/lib/libcardwhisper.a Makefile
	clang -o lscard -g lscard.o \
	  -lpcsclite -lz ${LDFLAGS}
#	  dump-data.o whisper-comp.o whisper-utils.o

lscard.o:	lscard.c
	clang ${CFLAGS} lscard.c

ls73:	ls73.o ${BUILD_DIR}/lib/libcardwhisper.a Makefile
	${LINK} -o ls73 -g ls73.o -lpcsclite -lz ${LDFLAGS}
#  dump-data.o decode-fascn.o whisper-comp.o whisper-utils.o 

ls73.o:	ls73.c
	clang ${CFLAGS} ls73.c

read-fascn:	read-fascn.o Makefile
	${LINK} -o read-fascn read-fascn.o ${LDFLAGS}

read-fascn.o:	read-fascn.c
	${CC} ${CFLAGS} read-fascn.c

write-chuid:	write-chuid.o Makefile
	${LINK} -o write-chuid write-chuid.o ${LDFLAGS}

write-chuid.o:	write-chuid.c
	${CC} ${CFLAGS} write-chuid.c


