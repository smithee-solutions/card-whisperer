# Makefile for libcardwhisper

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

BUILT_LIBS=libcardwhisper.a
CC=clang
LINK=clang
INCSRC=../../include
CFLAGS=-c -g -I${INCSRC} -I/usr/include/PCSC -Wall -Werror
BUILD_DIR=../../opt/tester

all:	${BUILT_LIBS}

clean:
	rm -rvf a.out core *.o ${BUILT_LIBS}

build:	all
	mkdir -p ${BUILD_DIR}/lib
	cp ${BUILT_LIBS} ${BUILD_DIR}/lib

cssh-chuid.o:	cssh-chuid.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} cssh-chuid.c

decode-atr.o:	decode-atr.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} decode-atr.c

decode-fascn.o:	decode-fascn.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} decode-fascn.c

dump-data.o:	dump-data.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} dump-data.c

libcardwhisper.a:	cssh-chuid.o decode-atr.o decode-fascn.o dump-data.o \
		shifter.o whisper-command-line.o whisper-comp.o whisper-utils.o
	ar r libcardwhisper.a \
	  cssh-chuid.o decode-atr.o decode-fascn.o dump-data.o shifter.o \
	  whisper-command-line.o whisper-comp.o whisper-utils.o

read-fascn.o:	read-fascn.c
	clang ${CFLAGS} -Wall -Werror read-fascn.c

read-fascn:	read-fascn.o decode-fascn.o Makefile
	clang -o read-fascn -g read-fascn.o decode-fascn.o

shifter.o:	shifter.c
	${CC} ${CFLAGS} shifter.c

whisper-command-line.o:	whisper-command-line.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} whisper-command-line.c

whisper-comp.o:	whisper-comp.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} whisper-comp.c

whisper-utils.o:	whisper-utils.c ${INCSRC}/card-whisperer.h
	${CC} ${CFLAGS} whisper-utils.c

