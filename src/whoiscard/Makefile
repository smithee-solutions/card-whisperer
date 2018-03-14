# Makefile for whoiscard

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
PROGS=whoiscard
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

whoiscard:	whoiscard.o cshh-command-line.o whois-oberthur.o  \
	  ${BUILD_DIR}/lib/libcardwhisper.a Makefile
	clang -o whoiscard -g whoiscard.o cshh-command-line.o whois-oberthur.o  \
	  -lpcsclite -lz ${LDFLAGS}

whoiscard.o:	whoiscard.c
	clang ${CFLAGS} whoiscard.c

cshh-command-line.o:	cshh-command-line.c
	clang ${CFLAGS} cshh-command-line.c

whois-oberthur.o:	whois-oberthur.c
	clang ${CFLAGS} whois-oberthur.c

