# Make file to make OES file objects for a DESFire OES card

#  Copyright 2017-2018 Smithee Solutions LLC
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


PROGS=create-OES-contents read_mifare
CC=clang
LINK=clang
BUILD_DIR=../../opt/tester
CFLAGS=-c -g -I/opt/tester/include -I../../include -I. \
  -I/opt/tester/include -I/usr/include/PCSC -Wall -Werror
LDFLAGS=-L${BUILD_DIR}/lib -lcardwhisper /opt/tester/lib/aes.o -ljansson -lpcsclite

all:	${PROGS}

clean:
	rm -rvf ${PROGS} core *.o

build:	all
	mkdir -p ../../opt/tester/bin
	cp ${PROGS} ../../opt/tester/bin

create-OES-contents:	create-OES-contents.o \
	  oes-prims.o oes-messages.o Makefile
	${LINK} -o create-OES-contents create-OES-contents.o \
	  oes-prims.o oes-messages.o ${LDFLAGS}

create-OES-contents.o:	create-OES-contents.c
	${CC} ${CFLAGS} create-OES-contents.c

oes-messages.o:	oes-messages.c
	${CC} ${CFLAGS} oes-messages.c

oes-prims.o:	oes-prims.c
	${CC} ${CFLAGS} oes-prims.c

read_mifare:	read_mifare.o Makefile
	${LINK} -o read_mifare -g read_mifare.o ${LDFLAGS}

read_mifare.o:	read_mifare.c
	${CC} ${CFLAGS} read_mifare.c

