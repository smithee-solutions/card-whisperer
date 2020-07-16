# Makefile for card-whisperer tools and samples

# needs zlib1g-dev libpcsclite-dev pcscd

# (C)Copyright 2017-2018 Smithee Solutions LLC

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

CC=clang
LINK=clang
CFLAGS=-c -g -I../include -I/usr/include/PCSC -Wall -Werror
BUILD_DIR=../opt/tester

# libcardwhisper gets 'make build' so lib is there for openbadger

all:	
	(cd libcardwhisper; make build; cd ..)
	(cd lscard; make; cd ..)
	(cd openbadger; make; cd ..)
	(cd whoiscard; make; cd ..);
	(cd credwrench; make; cd ..);
	(cd pivdumper; make; cd ..);

clean:
	(cd libcardwhisper; make clean; cd ..)
	(cd lscard; make clean; cd ..)
	(cd openbadger; make clean; cd ..)
	(cd whoiscard; make clean; cd ..);
	(cd credwrench; make clean; cd ..);
	(cd pivdumper; make clean; cd ..);

build:	all
	(cd libcardwhisper; make build; cd ..)
	(cd lscard; make build; cd ..)
	(cd openbadger; make build; cd ..)
	(cd whoiscard; make build; cd ..)
	(cd credwrench; make build; cd ..);
	(cd pivdumper; make build; cd ..);

