#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

AM_LDFLAGS = $(top_builddir)/src/libcci.la

bin_PROGRAMS = \
	cci_info

check_PROGRAMS = \
        init	\
	server	\
	client	\
	pingpong \
	stream	\
	register \
	rma_pipeline \
	rma_verify \
	opt \
	connect_reject \
	msg_verify \
	rma_register \
	loopback

rma_verify_SOURCES = rma_verify.c crc32.c

TESTS =
