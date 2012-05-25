/*
 * cci_create_endpoint.c
 *
 * test implementation of cci_create_endpoint() to ensure that it rejects invalid input.
 *
 * int cci_create_endpoint( cci_device_t const ***const devices );
 *
 * Author: Lawrence MacIntyre
 * 
 * History:
 * 2012 Feb 23 : lpm : initial implementation
 * 2012 Apr 05 : lpm : fixed cci_strerror() for new format
 * 2012 Apr 05 : lpm : fixed cci_get_devices() for new format
 */
 
#include <signal.h>		/* SIGSEGV */
#include "cci_check.h"

/*
 * try a correct invocation, check to see if device0 was chosen
 */
START_TEST (create_endpoint_correct) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
  cci_device_t const ** d = NULL;
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	char* ip;
	char* equalP;
	char** keyval;
	char* colonP;
	
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
 
	/* describe the endpoint  RBC = 1024  name = ip://<ip address>:<port>
	printf("Endpoint: receive buffer count: %d  --  name: %s\n          context %p\n",
						endpointP->max_recv_buffer_count, endpointP->name, (void*) endpointP->context);
	*/
//	for(d = devices, i=0; *d != NULL ; ++d, ++i) {
	d = devices;
	for(keyval = (char**) (*d)->conf_argv; *keyval != NULL; keyval++) {
		if(strstr(*keyval, "ip") != NULL) {
			equalP = strchr(*keyval, '=');
			ip = strchr(endpointP->name, '/');
			ip += 2;
			colonP = strchr(ip, ':');
			*colonP = '\0';
      equalP++;
			fail_unless(strcmp(ip, equalP) == 0, "endpoint Name != device IP (%s) != (%s)\n", ip, equalP);
		}
	}		
}
END_TEST

/*
 * Try initflags != 0 (should fail with EINVAL)
 */
START_TEST (create_endpoint_nonzero_flag) {
  uint32_t initFlags = 1;
  uint32_t capabilities = 0;
  uint32_t status = 0;
	cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 1;																				/* not yet implemented (MBZ) */
	cci_os_handle_t fd;																								/* endpoint handle */
 
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* attempt to create an endpoint with flags != 0 - should get EINVAL */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_EINVAL, "cci_create_endpoint() with flags != 0 received status %s", cci_strerror(NULL, status));
}
END_TEST

/*
 * Try endpoint = NULL (should fail with EINVAL)
 */
START_TEST (create_endpoint_null_endpoint) {
  uint32_t initFlags = 1;
  uint32_t capabilities = 0;
  uint32_t status = 0;
	cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented (MBZ) */
	cci_os_handle_t fd;																								/* endpoint handle */
 
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* attempt to create an endpoint with flags != 0 - should get EINVAL */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, (cci_endpoint_t**) endpointP, &fd);
  fail_unless(status == CCI_EINVAL, "cci_create_endpoint() with endpoint = NULL received status %s", cci_strerror(NULL, status));
}
END_TEST

/*
 * Try fd = NULL (should succeed with no SIGSEGV)
 */
START_TEST (create_endpoint_null_fd) {
  uint32_t initFlags = 1;
  uint32_t capabilities = 0;
  uint32_t status = 0;
	cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented (MBZ) */
	cci_os_handle_t fd = 0;																								/* endpoint handle */
 
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* attempt to create an endpoint with flags != 0 - should get EINVAL */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, (cci_os_handle_t*) fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() with fd = NULL received status %s", cci_strerror(NULL, status));
}
END_TEST

/*
 * devices = NULL, check to see if device0 was chosen
 */
START_TEST (create_endpoint_null_device) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
  cci_device_t const ** d = NULL;
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	char* ip;
	char* equalP;
	char** keyval;
	char* colonP;
	
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
	/* create an endpoint. Note that we haven't called get_devices() */
	status = cci_create_endpoint((cci_device_t*) devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));

  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	d = devices;
	for(keyval = (char**) (*d)->conf_argv; *keyval != NULL; keyval++) {
		if(strstr(*keyval, "ip") != NULL) {
			equalP = strchr(*keyval, '=');
			ip = strchr(endpointP->name, '/');
			ip += 2;
			colonP = strchr(ip, ':');
			*colonP = '\0';
      equalP++;
			fail_unless(strcmp(ip, equalP) == 0, "endpoint Name != device IP (%s) != (%s)\n", ip, equalP);
		}
	}		
}
END_TEST

START_TEST (create_endpoint_all_devices) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
  cci_device_t const ** d = NULL;
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	char* ip;
	char* equalP;
	char** keyval;
	char* colonP;
	uint32_t i;
	
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
   /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	for(d = devices, i=0; *d != NULL ; ++d, ++i) {
		/* create an endpoint. */
		/* should have new endpointP and fd for each one, but we won't for this test */
		status = cci_create_endpoint((cci_device_t*) *d, deviceFlags, &endpointP, &fd);
		fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));

		for(keyval = (char**) (*d)->conf_argv; *keyval != NULL; keyval++) {
			if(strstr(*keyval, "ip") != NULL) {
				equalP = strchr(*keyval, '=');
				ip = strchr(endpointP->name, '/');
				ip += 2;
				colonP = strchr(ip, ':');
				*colonP = '\0';
        equalP++;
				fail_unless(strcmp(ip, equalP) == 0, "endpoint Name != device IP (%s) != (%s)\n", ip, equalP);
			}
		}
	}
}
END_TEST

START_TEST (create_endpoint_loop) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
  cci_device_t const ** d = NULL;
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	uint32_t i;
	
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));

  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));
	
	for(i=0; i<10; ++i) {
		for(d = devices; *d != NULL; ++d) {
			status = cci_create_endpoint((cci_device_t*) *d, deviceFlags, &endpointP, &fd);
			fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));

			status = cci_destroy_endpoint(endpointP);
			fail_unless(status == CCI_SUCCESS, "cci_destroy_endpoint() failed with status %s", cci_strerror(NULL, status));
		}
	}
}
END_TEST

/* Now build the individual tests into a test suite */

Suite* cci_create_endpoint_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_create_endpoint");
	if(s == NULL) {
		perror("suite_create(cci_create_endpoint)");
		return NULL;
	}
	
	tc = tcase_create("create_endpoint_case");
	if(tc == NULL) {
		perror("tcase_create(create_endpoint_case)");
		return NULL;
	}
	
	tcase_add_test(tc, create_endpoint_correct);
	tcase_add_test(tc, create_endpoint_nonzero_flag);
	tcase_add_test_raise_signal(tc, create_endpoint_null_endpoint, SIGSEGV);
	tcase_add_test(tc, create_endpoint_null_fd);
	tcase_add_test(tc, create_endpoint_null_device);
	tcase_add_test(tc, create_endpoint_all_devices);
	tcase_add_test(tc, create_endpoint_loop);
	suite_add_tcase(s, tc);

	return s;
}