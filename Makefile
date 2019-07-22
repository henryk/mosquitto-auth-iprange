all: mosquitto-auth-iprange.so
clean:
	rm -f mosquitto-auth-iprange.so
indent:
	indent -kr -i8 -nut mosquitto-auth-iprange.c mosquitto-auth-iprange.h

install: mosquitto-auth-iprange.so
	install -d $(DESTDIR)$(PREFIX)/lib
	install mosquitto-auth-iprange.so $(DESTDIR)$(PREFIX)/lib/

.PHONY: all clean indent install

PREFIX?=/usr/local
DESTDIR?=

CFLAGS_LIB=-fPIC -shared
LIBS=-lmosquitto
CFLAGS=-I/usr/include -ggdb --std=gnu99 -Wall -pedantic -fstack-protector -Werror=implicit-function-declaration
CC=gcc

mosquitto-auth-iprange.so: mosquitto-auth-iprange.c
	$(CC) $(CFLAGS) $(CFLAGS_LIB) $^ $(LIBS) -o $@
