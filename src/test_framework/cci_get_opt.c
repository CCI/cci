/*
 * cci_get_opt.c
 *
 * test implementation of cci_get_opt() to ensure that it rejects invalid input.
 *
 * int cci get opt(cci_opt_handle_t *handle, cci_opt_name_t name, void val, int len);
 *
 * CCI_OPT_ENDPT_SEND_TIMEOUT
 * CCI_OPT_ENDPT_RECV_BUF_COUNT
 * CCI_OPT_ENDPT_SEND_BUF_COUNT
 * CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT
 * CCI_OPT_CONN_SEND_TIMEOUT
 *
 * Author: Lawrence MacIntyre
 * 
 * History:
 * 2012 Mar 03 : lpm : initial implementation
 * 2012 Apr 05 : lpm : fixed cci_strerror() for new format
 * 2012 Apr 05 : lpm : fixed cci_get_devices() for new format
 */
 
#include <signal.h>		/* SIGSEGV */
#include "cci_check.h"

#define DEFAULT_ENDPOINT_SEND_TIMEOUT 64000000
#define DEFAULT_ENDPOINT_RECV_BUF_COUNT 1024
#define DEFAULT_ENDPOINT_SEND_BUF_COUNT 128
#define DEFAULT_ENDPOINT_KEEPALIVE_TIMEOUT 0

/*
 * try a correct invocation, check to see if device0 was chosen
 */
START_TEST (get_opt_correct) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint file handle */
	cci_opt_handle_t *optHandle;																	/* endpoint handle */
  uint32_t setOption;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
 
  /* get an endpoint option */
  optHandle = endpointP;

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_SEND_TIMEOUT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_SUCCESS, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
  fail_unless(*optionP == DEFAULT_ENDPOINT_SEND_TIMEOUT, "cci_get_opt(CCI_OPT_ENDPT_SEND_TIMEOUT) returned %d instead of %d\n", *optionP,
                  DEFAULT_ENDPOINT_SEND_TIMEOUT);
  
  setOption = (*optionP +2) * 2;
  
  status = cci_set_opt(optHandle, CCI_OPT_ENDPT_SEND_TIMEOUT,
                    (void *) &setOption, (int) sizeof(setOption));
  fail_unless(status == CCI_SUCCESS, "cci_set_opt(CCI_OPT_ENDPT_SEND_TIMEOUT) failed with status %s\n", cci_strerror(NULL, status));

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_SEND_TIMEOUT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_SUCCESS, "cci_get_opt(CCI_OPT_ENDPT_SEND_TIMEOUT) failed with status %s\n", cci_strerror(NULL, status));
  fail_unless(*optionP == setOption, "cci_get_opt(CCI_OPT_ENDPT_SEND_TIMEOUT) returned %d instead of %d\n", *optionP,
                  setOption);
}
END_TEST

START_TEST (get_opt_null_handle) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
  cci_opt_handle_t* optHandle = NULL;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_SEND_TIMEOUT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_EINVAL, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
}
END_TEST

START_TEST (get_opt_invalid_option) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
  cci_opt_handle_t *optHandle;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));
	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
 
  /* get an endpoint option */
  optHandle = endpointP;

  status = cci_get_opt(optHandle, 100, (void*) &optionP, &optionSize);
  fail_unless(status == CCI_EINVAL, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
}
END_TEST

START_TEST (get_opt_rbc) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	cci_opt_handle_t *optHandle;
  uint32_t setOption;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
  
/* get an endpoint option */
  optHandle = endpointP;

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_RECV_BUF_COUNT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_SUCCESS, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
  fail_unless(*optionP == DEFAULT_ENDPOINT_RECV_BUF_COUNT, "cci_get_opt(CCI_OPT_ENDPT_RECV_BUF_COUNT) returned %d instead of %d\n", *optionP,
                  DEFAULT_ENDPOINT_RECV_BUF_COUNT);
  
  setOption = (*optionP +2) * 2;
  
  status = cci_set_opt(optHandle, CCI_OPT_ENDPT_RECV_BUF_COUNT,
                    (void *) &setOption, (int) sizeof(setOption));
  fail_unless((status == CCI_SUCCESS) || (status == CCI_ERR_NOT_IMPLEMENTED),
									"cci_set_opt(CCI_OPT_ENDPT_RECV_BUF_COUNT) failed with status %s\n", cci_strerror(NULL, status));
	
	/* assuming that cci_get_opt() is implemented for this option, see if it actually worked */
	if(status == CCI_SUCCESS) {
		status = cci_get_opt(optHandle, CCI_OPT_ENDPT_RECV_BUF_COUNT,
																		(void*) &optionP, &optionSize);
		
		fail_unless(status == CCI_SUCCESS, "cci_get_opt(CCI_OPT_ENDPT_RECV_BUF_COUNT) failed with status %s\n", cci_strerror(NULL, status));
		fail_unless(*optionP == setOption, "cci_get_opt(CCI_OPT_ENDPT_RECV_BUF_COUNT) returned %d instead of %d\n", *optionP,
										setOption);
	}
}
END_TEST

START_TEST (get_opt_sbc) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	cci_opt_handle_t *optHandle;
  uint32_t setOption;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
  
	/* get an endpoint option */
  optHandle = endpointP;

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_SEND_BUF_COUNT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_SUCCESS, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
  fail_unless(*optionP == DEFAULT_ENDPOINT_SEND_BUF_COUNT, "cci_get_opt(CCI_OPT_ENDPT_SEND_BUF_COUNT) returned %d instead of %d\n", *optionP,
                  DEFAULT_ENDPOINT_SEND_BUF_COUNT);
  
  setOption = (*optionP +2) * 2;
  
  status = cci_set_opt(optHandle, CCI_OPT_ENDPT_SEND_BUF_COUNT,
                    (void *) &setOption, (int) sizeof(setOption));
  fail_unless((status == CCI_SUCCESS) || (status == CCI_ERR_NOT_IMPLEMENTED), "cci_set_opt(CCI_OPT_ENDPT_SEND_BUF_COUNT) failed with status %s\n",
									cci_strerror(NULL, status));

	/* assuming that cci_get_opt() is implemented for this option, see if it actually worked */
	if(status == CCI_SUCCESS) {
		status = cci_get_opt(optHandle, CCI_OPT_ENDPT_SEND_BUF_COUNT,
																		(void*) &optionP, &optionSize);
		fail_unless(status == CCI_SUCCESS, "cci_get_opt(CCI_OPT_ENDPT_SEND_BUF_COUNT) failed with status %s\n", cci_strerror(NULL, status));
		fail_unless(*optionP == setOption, "cci_get_opt(CCI_OPT_ENDPT_SEND_BUF_COUNT) returned %d instead of %d\n", *optionP, setOption);
	}
}
END_TEST

START_TEST (get_opt_kt) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
	  cci_opt_handle_t *optHandle;
  uint32_t setOption;
  int32_t*  optionP;
  int32_t optionSize;                                           

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
  
  /* get an endpoint option */
  optHandle = endpointP;

  status = cci_get_opt(optHandle, CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT,
                                  (void*) &optionP, &optionSize);
  fail_unless(status == CCI_SUCCESS, "cci_get_opt failed with status %s\n", cci_strerror(NULL, status));
  fail_unless(*optionP == DEFAULT_ENDPOINT_KEEPALIVE_TIMEOUT, "cci_get_opt(CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT) returned %d instead of %d\n", *optionP,
                  DEFAULT_ENDPOINT_KEEPALIVE_TIMEOUT);
  
  setOption = (*optionP +2) * 2;
  
  status = cci_set_opt(optHandle, CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT,
                    (void *) &setOption, (int) sizeof(setOption));
  fail_unless((status == CCI_SUCCESS) || (status == CCI_ERR_NOT_IMPLEMENTED), "cci_set_opt(CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT) failed with status %s\n",
										cci_strerror(NULL, status));

	/* assuming that cci_get_opt() is implemented for this option, see if it actually worked */
	if(status == CCI_SUCCESS) {
		status = cci_get_opt(optHandle, CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT,
																		(void*) &optionP, &optionSize);
		fail_unless(status == CCI_SUCCESS, "cci_get_opt(CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT) failed with status %s\n", cci_strerror(NULL, status));
		fail_unless(*optionP == setOption, "cci_get_opt(CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT) returned %d instead of %d\n", *optionP,
										setOption);
	}
}
END_TEST


/* Now build the individual tests into a test suite */

Suite* cci_get_opt_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_get_opt");
	if(s == NULL) {
		perror("suite_create(cci_get_opt)");
		return NULL;
	}
	
	tc = tcase_create("get_opt_case");
	if(tc == NULL) {
		perror("tcase_create(get_opt_case)");
		return NULL;
	}
	
	tcase_add_test(tc, get_opt_correct);
	tcase_add_test(tc, get_opt_null_handle);
	tcase_add_test(tc, get_opt_invalid_option);
	tcase_add_test(tc, get_opt_rbc);
	tcase_add_test(tc, get_opt_sbc);
  tcase_add_test(tc, get_opt_kt);
	suite_add_tcase(s, tc);

	return s;
}
