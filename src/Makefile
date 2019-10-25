CFLAGS=-g -Wall -D CGICDEBUG
CC=gcc
AR=ar
RANLIB=ranlib
LIBS=-L./ -lcgic

all: libcgic.a mapport.cgi sepolicy.cgi

install: libcgic.a
	cp libcgic.a /usr/local/lib
	cp cgic.h /usr/local/include
	@echo libcgic.a is in /usr/local/lib. cgic.h is in /usr/local/include.

libcgic.a: cgic.o cgic.h
	rm -f libcgic.a
	$(AR) rc libcgic.a cgic.o
	$(RANLIB) libcgic.a

#mingw32 and cygwin users: replace .cgi with .exe

mapport.cgi: mapport.o libcgic.a
	gcc mapport.o -o mapport.cgi ${LIBS}

sepolicy.cgi: sepolicy.o libcgic.a
	gcc sepolicy.o -o sepolicy.cgi ${LIBS}

clean:
	rm -f *.o *.a mapport.cgi sepolicy.cgi

