CC=g++
CFLAGS=-g -Wall -std=c++17
PROGS=application

all: ${PROGS}

application: main.cpp sha256.o
	${CC} ${CFLAGS} -o $@ $^

sha256.o: sha256.cpp sha256.h
	${CC} ${CFLAGS} -c $<

clean:
	rm -rf *.o ${PROGS}
