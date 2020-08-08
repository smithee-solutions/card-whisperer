# Makefile for credwrench

#  (C)Copyright 2018 Smithee Solutions LLC

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PROGS=credwrench
CC=clang
LINK=clang
BUILD_DIR=../../opt/tester
CFLAGS=-c -g -I../../include -I/usr/include/PCSC -I/opt/tester/include -Wall -Werror
LDFLAGS=-g -L${BUILD_DIR}/lib -L/opt/tester/lib -lcardwhisper -ldl

all:	${PROGS}

clean:
	rm -rvf a.out core *.o ${PROGS}

build:	all
	mkdir -p ${BUILD_DIR}/bin
	cp ${PROGS} ${BUILD_DIR}/bin

credwrench:	credwrench.o wrench-command-line.o \
	  ${BUILD_DIR}/lib/libcardwhisper.a Makefile
	${LINK} -o credwrench -g credwrench.o \
	  wrench-command-line.o -lcrypto -lpcsclite -lz ${LDFLAGS}

credwrench.o:	credwrench.c ../../include/credwrench.h
	${CC} ${CFLAGS} credwrench.c

wrench-command-line.o:	wrench-command-line.c ../../include/credwrench.h
	${CC} ${CFLAGS} wrench-command-line.c

