/*
 * Copyright (c) 2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2012 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * Copyright © 2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include "cci.h"

char *proc_name = NULL;
int get = 0;
int set = 0;
uint32_t tx_timeout = -1;
uint32_t rx_buf_cnt = -1;
uint32_t tx_buf_cnt = -1;
uint32_t keepalive = -1;
cci_alignment_t alignment;
int align = -1;
int get_uri = -1;
char *uri = NULL;

cci_opt_handle_t handle;
cci_opt_level_t level;

void check_return(char *func, cci_endpoint_t *endpoint, int ret)
{
	if (ret) {
		fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}
	return;
}

void usage(void)
{
	printf("usage: %s [-G | -S] [-t[<usecs>]] [-r[<count>]] [-s[<count>]] "
	       "[-k[<usecs>]] [-a]\n", proc_name);
	printf("where:\n");
	printf("\t--get,-G\tGet value. If no other options set, get all options.\n");
	printf("\t--set,-S\tSet value. Requires at least one option and its value.\n");
	printf("\t  \t           This will call get_opt() before and after\n");
	printf("\t  \t           set_opt() to show the impact if any.\n");
	printf("\t--tx_timeout,-t\tSend timeout value in microseconds (us).\n");
	printf("\t--rx_buf_cnt,-r\tReceive buffer count.\n");
	printf("\t--tx_buf_cnt,-s\tSend buffer count.\n");
	printf("\t--keepalive,-k\tKeepalive timeout in microsconds (us).\n");
	printf("\t--align,-a\tRMA Alignment values.\n");
	printf("\t--uri,-u\tEndpoint's URI.\n");
	printf ("Note: There are no spaces between option flags and optional values.\n");
	exit(EXIT_FAILURE);
}

void test(cci_endpoint_t *endpoint, cci_opt_name_t name)
{
	int ret;
	uint32_t tmpval;
	void *oldval, *newval;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		oldval = &tmpval; newval = &tx_timeout;
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		oldval = &tmpval; newval = &rx_buf_cnt;
		break;
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		oldval = &tmpval; newval = &tx_buf_cnt;
		break;
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		oldval = &tmpval; newval = &keepalive;
		break;
	case CCI_OPT_ENDPT_RMA_ALIGN:
		oldval = &alignment; /* no newval yet */
		break;
	case CCI_OPT_ENDPT_URI:
		oldval = &uri; /* no newval */
		break;
	default:
		printf("unknown option\n");
		break;
	}

	ret = cci_get_opt(&handle, level, name, oldval);
	printf("\tcci_get_opt() returned %s\n", cci_strerror(endpoint, ret));

	if (ret == CCI_SUCCESS) {
		if (CCI_OPT_ENDPT_RMA_ALIGN != name) {
			if (CCI_OPT_ENDPT_URI == name) {
				printf("\t(uri = %s)\n\n", uri);
				return;
			}
			printf("\t(val = %u)\n", tmpval);
			if (set) {
				ret = cci_set_opt(&handle, level, name, newval);
				printf("\tcci_set_opt() returned %s\n",
					cci_strerror(endpoint, ret));
				if (ret == CCI_SUCCESS) {
					ret = cci_get_opt(&handle, level, name, oldval);
					printf("\tcci_get_opt() returned %s\n",
					cci_strerror(endpoint, ret));
					if (ret == CCI_SUCCESS)
						printf("\t(val = %u)\n", tmpval);
					else
						printf("\n");
				}
			}
		} else {
			printf("\trma_write_local_addr = %u\n", alignment.rma_write_local_addr);
			printf("\trma_write_remote_addr = %u\n", alignment.rma_write_remote_addr);
			printf("\trma_write_length = %u\n", alignment.rma_write_length);
			printf("\trma_read_local_addr = %u\n", alignment.rma_read_local_addr);
			printf("\trma_read_remote_addr = %u\n", alignment.rma_read_remote_addr);
			printf("\trma_read_length = %u\n", alignment.rma_read_length);
		}
	} else {
		printf("\n");
	}
	return;
}

int main(int argc, char *argv[])
{
	int c, ret, fd;
	uint32_t caps = 0;
	cci_endpoint_t *endpoint;

	static struct option opts[] = {
		{ "get",	no_argument,		NULL,		'G' },
		{ "set",	no_argument,		NULL,		'S' },
		{ "tx_timeout",	optional_argument,	NULL,		't' },
		{ "rx_buf_cnt",	optional_argument,	NULL,		'r' },
		{ "tx_buf_cnt",	optional_argument,	NULL,		's' },
		{ "keepalive",	optional_argument,	NULL,		'k' },
		{ "align",	no_argument,		&align,		 1  },
		{ "uri",	no_argument,		&get_uri,	 1  },
		{ NULL,		0,			NULL,		 0  }
	};

	proc_name = argv[0];

	while ((c = getopt_long_only(argc, argv, "GStrsk", opts, NULL)) != -1) {
		switch (c) {
		case 0:
			continue;
		case 'G':
			if (set)
				usage();
			get = 1;
			break;
		case 'S':
			if (get)
				usage();
			set = 1;
			break;
		case 't':
			if (optarg)
				tx_timeout = (uint32_t) atoi(optarg);
			else
				tx_timeout = 0;
			break;
		case 'r':
			if (optarg)
				rx_buf_cnt = (uint32_t) atoi(optarg);
			else
				rx_buf_cnt = 0;
			break;
		case 's':
			if (optarg)
				tx_buf_cnt = (uint32_t) atoi(optarg);
			else
				tx_buf_cnt = 0;
			break;
		case 'k':
			if (optarg)
				keepalive = (uint32_t) atoi(optarg);
			else
				keepalive = 0;
			break;
		default:
			usage();
			break;
		}
	}

	if (get && set)
		usage();
	if (!(get || set))
		usage();

	if ((tx_timeout == (uint32_t) - 1) &&
	    (rx_buf_cnt == (uint32_t) - 1) &&
	    (tx_buf_cnt == (uint32_t) - 1) &&
	    (keepalive == (uint32_t) - 1) &&
	    (align == -1 &&
	     get_uri == -1)) {
		if (get) {
			tx_timeout = rx_buf_cnt = tx_buf_cnt = keepalive = 0;
			align = get_uri = 1;
		} else {
			printf("Set requires an option and value to set");
			usage();
		}
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	check_return("cci_init", endpoint, ret);

	ret = cci_create_endpoint(NULL, 0, &endpoint, &fd);
	check_return("cci_create_endpoint", endpoint, ret);

	/* start tests */

	handle.endpoint = endpoint;
	level = CCI_OPT_LEVEL_ENDPOINT;

	if (tx_timeout != (uint32_t) - 1) {
		printf("Testing CCI_OPT_ENDPT_SEND_TIMEOUT\n");
		test(endpoint, CCI_OPT_ENDPT_SEND_TIMEOUT);
	}

	if (rx_buf_cnt != (uint32_t) - 1) {
		printf("Testing CCI_OPT_ENDPT_RECV_BUF_COUNT\n");
		test(endpoint, CCI_OPT_ENDPT_RECV_BUF_COUNT);
	}

	if (tx_buf_cnt != (uint32_t) - 1) {
		printf("Testing CCI_OPT_ENDPT_SEND_BUF_COUNT\n");
		test(endpoint, CCI_OPT_ENDPT_SEND_BUF_COUNT);
	}

	if (keepalive != (uint32_t) - 1) {
		printf("Testing CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT\n");
		test(endpoint, CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT);
	}

	if (align != -1) {
		printf("Testing CCI_OPT_ENDPT_RMA_ALIGN\n");
		test(endpoint, CCI_OPT_ENDPT_RMA_ALIGN);
	}

	if (get_uri != -1) {
		printf("Testing CCI_OPT_ENDPT_URI\n");
		test(endpoint, CCI_OPT_ENDPT_URI);
	}

	ret = cci_destroy_endpoint(endpoint);
	check_return("cci_destroy_endpoint", endpoint, ret);

	ret = cci_finalize();
	check_return("cci_finalize", endpoint, ret);

	return 0;
}
