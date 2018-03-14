all:
	(cd src; make)

clean:
	(cd src; make clean)
	rm -rvf opt

build:
	(cd src; make build)

cardwhisperer:
	(cd src; make)

openbadger:
	(cd src/openbadger; make)

