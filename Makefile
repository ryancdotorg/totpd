CC=gcc
CFLAGS=-ggdb -O2 -Wall -Wno-unused-function \
	-pedantic -Wextra \
	-Wvla -Wimplicit-fallthrough \
	-Wno-unused-parameter -Wno-unused-const-variable \
	-std=c11 -flto -flto-partition=none
#	-Wextra -pedantic -std=c11 -flto -flto-partition=none

LDFLAGS=$(CFLAGS)
LDLIBS=-lcrypto -lsystemd

BINARIES=test

%.o: %.c %.h config.h
	$(CC) $(CFLAGS) -o $@ -c $<

test: test.o comm.o base32.o mem.o otp.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

totpd: totpd.o comm.o base32.o mem.o otp.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

all: $(BINARIES)

.PHONY: all clean

.NOTPARALLEL:

clean:
	rm -f *.o $(BINARIES) || /bin/true
