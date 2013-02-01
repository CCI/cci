/*
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>

#include "cci.h"

#define REGSIZE		(1024*1024)
#define TOTALSIZE	(512*1024*1024)

void check_return(cci_endpoint_t *endpoint, char *func, int ret)
{
	if (ret) {
		fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}
	return;
}

void usage(char *name)
{
	printf
	    ("usage: %s [-d] [-f] [-o <offset>] [-s <size>] [-t <total_allocation>]\n",
	     name);
	printf("where:\n");
	printf("\t-d\tMeasure deregister (default is register)\n");
	printf
	    ("\t-f\tPre-fault pages (default is unfaulted - malloc() only)\n");
	printf("\t-o\tOffset into page (default is page aligned)\n");
	printf("\t-s\tSize per registeration (default %u)\n", REGSIZE);
	printf("\t-t\tTotal memory to allocate (default is %u)\n", TOTALSIZE);
	printf("It will measure N [de]registrations where N is "
	       "(total memory / registration size)\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c, ret;
	int dereg = 0, prefault = 0;
	uint32_t pagesize = 0, offset = 0;
	uint64_t regsize = REGSIZE, totalsize = TOTALSIZE, count, i;
	uint32_t caps;
	cci_device_t * const *devices;
	cci_endpoint_t *endpoint;
	void *base, *ptr;
	uint64_t length;
	cci_rma_handle_t **handles = NULL;
	struct timeval start, end;
	uint64_t usecs = 0;

	pagesize = sysconf(_SC_PAGESIZE);

	while ((c = getopt(argc, argv, "dfo:s:t:")) != -1) {
		switch (c) {
		case 'd':
			dereg = 1;
			break;
		case 'f':
			prefault = 1;
			break;
		case 'o':
			offset = strtoul(optarg, NULL, 0);
			if (offset >= pagesize) {
				fprintf(stderr,
					"offset larger than pagesize (%u)\n",
					pagesize);
				usage(argv[0]);
			}
			break;
		case 's':
			regsize = strtoull(optarg, NULL, 0);
			if (regsize < pagesize) {
				printf("regsize (%" PRIu64
				       ") < pagesize (%u) - increasing to pagesize\n",
				       regsize, pagesize);
				regsize = pagesize;
			}
			break;
		case 't':
			totalsize = strtoull(optarg, NULL, 0);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	count = totalsize / regsize;

	ret = posix_memalign(&base, pagesize, totalsize + offset);
	check_return(NULL, "posix_memalign", ret);

	ptr = base + (uintptr_t) offset;
	length = regsize;

	handles = calloc(count, sizeof(*handles));
	check_return(NULL, "calloc", handles ? 0 : CCI_ENOMEM);

	if (prefault) {
		for (i = 0; i < totalsize; i += pagesize) {
			char *c = (char *)ptr + (uintptr_t) i;
			*c = '1';
		}
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	check_return(NULL, "cci_init", ret);

	ret = cci_get_devices(&devices);
	check_return(NULL, "cci_get_devices", ret);

	ret = cci_create_endpoint(NULL, 0, &endpoint, NULL);
	check_return(NULL, "cci_create_endpoint", ret);

	/* register */
	if (!dereg)
		gettimeofday(&start, NULL);

	for (i = 0; i < count; i++) {
		void *p = ptr + (uintptr_t) i;

		ret = cci_rma_register(endpoint, p, length, CCI_FLAG_READ|CCI_FLAG_WRITE, &handles[i]);
		check_return(endpoint, "cci_rma_register", ret);
	}

	if (!dereg)
		gettimeofday(&end, NULL);

	/* deregister */
	if (dereg)
		gettimeofday(&start, NULL);

	for (i = 0; i < count; i++) {
		ret = cci_rma_deregister(endpoint, handles[i]);
		check_return(endpoint, "cci_rma_register", ret);
	}

	if (dereg)
		gettimeofday(&end, NULL);

	usecs = (end.tv_sec - start.tv_sec) * 1000000 +
	    end.tv_usec - start.tv_usec;
	printf("%10s%10s%10s%10s\n", "RegSize", "Count", "usecs", "us/page");
	printf("%10" PRIu64 "%10" PRIu64 "%10" PRIu64 "%10.2lf\n",
	       regsize, count, usecs, (double)usecs / (double)count);

	ret = cci_destroy_endpoint(endpoint);
	check_return(endpoint, "cci_destroy_endpoint", ret);

        ret = cci_finalize();
	check_return(NULL, "cci_finalize", ret);

	return 0;
}
