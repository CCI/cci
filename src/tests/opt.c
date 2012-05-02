/*
 * Copyright (c) 2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2012 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#define _GNU_SOURCE
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
int align = -1;

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
	printf("\t-G\tGet value. If no other options set, get all options.\n");
	printf
	    ("\t-S\tSet value. Requires at least one option and its value.\n");
	printf("\t  \t           This will call get_opt() before and after\n");
	printf("\t  \t           set_opt() to show the impact if any.\n");
	printf("\t-t\tSend timeout value in microseconds (us).\n");
	printf("\t-r\tReceive buffer count.\n");
	printf("\t-s\tSend buffer count.\n");
	printf("\t-k\tKeepalive timeout in microsconds (us).\n");
	printf("\t-a\tRMA Alignment values.\n");
	printf
	    ("Note: There are no spaces between option flags and optional values.\n");
	printf("If no options are given, enter interactive mode.\n");
	exit(EXIT_FAILURE);
}

void test(cci_endpoint_t *endpoint, cci_opt_name_t name)
{
	int ret, len;
	uint32_t val;
	void *ptr;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		val = tx_timeout;
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		val = rx_buf_cnt;
		break;
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		val = tx_buf_cnt;
		break;
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		val = keepalive;
		break;
	case CCI_OPT_ENDPT_RMA_ALIGN:
		break;
	default:
		printf("unknown option\n");
		break;
	}

	ret = cci_get_opt(&handle, level, name, &ptr, &len);
	printf("cci_get_opt() returned %s\n", cci_strerror(endpoint, ret));

	if (ret == CCI_SUCCESS) {
		if (CCI_OPT_ENDPT_RMA_ALIGN != name) {
			printf(" (val = %u)\n", *((uint32_t *) ptr));
			if (set) {
				ret = cci_set_opt(&handle, level, name,
							&val, (int)sizeof(val));
				printf("cci_set_opt() returned %s\n",
					cci_strerror(endpoint, ret));
				if (ret == CCI_SUCCESS) {
					ret = cci_get_opt(&handle, level, name,
								&ptr, &len);
					printf("cci_get_opt() returned %s\n",
					cci_strerror(endpoint, ret));
					if (ret == CCI_SUCCESS)
						printf(" (val = %u)\n",
							*((uint32_t *) ptr));
					else
						printf("\n");
				}
			}
		} else {
			cci_alignment_t *align = (cci_alignment_t *)ptr;
			printf("rma_write_local_addr = %u\n", align->rma_write_local_addr);
			printf("rma_write_remote_addr = %u\n", align->rma_write_remote_addr);
			printf("rma_write_length = %u\n", align->rma_write_length);
			printf("rma_read_local_addr = %u\n", align->rma_read_local_addr);
			printf("rma_read_remote_addr = %u\n", align->rma_read_remote_addr);
			printf("rma_read_length = %u\n", align->rma_read_length);
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

	proc_name = argv[0];

	while ((c = getopt(argc, argv, "GSt::r::s::k::a")) != -1) {
		switch (c) {
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
		case 'a':
			align = 1;
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
	    (align == -1)) {
		if (get) {
			tx_timeout = rx_buf_cnt = tx_buf_cnt = keepalive = 0;
			align = 1;
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

	if (align) {
		printf("Testing CCI_OPT_ENDPT_RMA_ALIGN\n");
		test(endpoint, CCI_OPT_ENDPT_RMA_ALIGN);
	}

	ret = cci_destroy_endpoint(endpoint);
	check_return("cci_destroy_endpoint", endpoint, ret);

	ret = cci_finalize();
	check_return("cci_finalize", endpoint, ret);

	return 0;
}
