INCLUDES=include/card-whisperer.h include/card-whisperer-version.h

all:
	(cd src; make)

clean:
	(cd src; make clean)
	rm -rvf opt

build:
	mkdir -p opt/tester/include
	cp ${INCLUDES} opt/tester/include
	(cd src; make build)

cardwhisperer:
	(cd src; make)

openbadger:
	(cd src/openbadger; make)

