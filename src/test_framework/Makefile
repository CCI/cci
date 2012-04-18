#
# Makefile for cci_init() test suite for check test framework
#
# Author: Lawrence MacIntyre
#
# Notes:
#
# History:
# 2012 Feb 7 : lpm : initial implementation
# 2012 Feb 10 : lpm : added cci_strerror
# 2012 Feb 11 : lpm : added cci_get_devices
# 2012 Feb 23 : lpm : added cci_create_endpoint
# 2012 Mar 03 : lpm : added cci_get_opt
# 2012 Mar 04 : lpm : added cci_set_opt
 
CC=gcc
CFLAGS=-g -Wall -pedantic --std=gnu99 -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lcci -lcheck -lpthread
RM=rm -f

OBJ=cci_check.o cci_init.o cci_strerror.o cci_get_devices.o \
    cci_create_endpoint.o cci_get_opt.o cci_set_opt.o
SRCS=cci_check.c cci_check.h cci_init.c cci_strerror.c Makefile \
     cci_get_devices.c cci_create_endpoint.c cci_get_opt.c cci_set_opt.c
BINS=cci_check

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

all:	$(BINS)

clean:
	$(RM) $(OBJ) $(BINS)

cci_check:	$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJS):	Makefile cci_check.h
cci_check.o:	cci_check.c
cci_init.o:	cci_init.c
cci_strerror.o:	cci_strerror.c
cci_get_devices.o:  cci_get_devices.c
test_get_devices.o:	test_get_devices.c
cci_create_endpoint.o:	cci_create_endpoint.c
cci_get_opt.o:  cci_get_opt.c
cci_set_opt.o:  cci_set_opt.c
