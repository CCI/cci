/*
 * cci_set_opt.c
 *
 * test implementation of cci_set_opt() to ensure that it rejects invalid input.
 *
 * int cci set opt(cci_opt_handle_t handle, cci_opt_level_t level, cci_opt_name_t name, void val, int len);
 *
 * Author: Lawrence MacIntyre
 * 
 * History:
 * 2012 Mar 04 : lpm : initial implementation
 * 2012 Apr 05 : lpm : fixed cci_strerror() for new format
 * 2012 Apr 05 : lpm : fixed cci_get_devices() for new format
 */
 
#include <signal.h>		/* SIGSEGV */
#include "cci_check.h"

START_TEST (set_opt_null_handle) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
  cci_opt_handle_t* optHandle = NULL;
  int32_t option;

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
 
  status = cci_set_opt(optHandle, CCI_OPT_LEVEL_ENDPOINT, CCI_OPT_ENDPT_SEND_TIMEOUT,
                                  (void*) &option, sizeof(option));
  fail_unless(status == CCI_EINVAL, "cci_set_opt failed with status %s\n", cci_strerror(NULL, status));
}
END_TEST

START_TEST (set_opt_invalid_option) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
	cci_endpoint_t* endpointP = NULL;											/* pointer to endpoint structure */
	int32_t deviceFlags = 0;																				/* not yet implemented */
	cci_os_handle_t fd;																								/* endpoint handle */
  cci_opt_handle_t optHandle;
  int32_t* option;

  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));
	/* create an endpoint. For now, simply use the first device  - remember that fd can be used in select() */
	status = cci_create_endpoint((cci_device_t*) *devices, deviceFlags, &endpointP, &fd);
  fail_unless(status == CCI_SUCCESS, "cci_create_endpoint() failed with status %s", cci_strerror(NULL, status));
 
 	memset(&optHandle, 0, sizeof(union cci_opt_handle));

  /* get an endpoint option */
 optHandle.endpoint = endpointP;

  status = cci_set_opt(&optHandle, CCI_OPT_LEVEL_ENDPOINT, 100, (void*) &option, sizeof(option));
  fail_unless(status == CCI_EINVAL, "cci_set_opt failed with status %s\n", cci_strerror(NULL, status));
 }
END_TEST

/* Now build the individual tests into a test suite */

Suite* cci_set_opt_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_set_opt");
	if(s == NULL) {
		perror("suite_create(cci_set_opt)");
		return NULL;
	}
	
	tc = tcase_create("set_opt_case");
	if(tc == NULL) {
		perror("tcase_create(set_opt_case)");
		return NULL;
	}
	
	tcase_add_test(tc, set_opt_null_handle);
	tcase_add_test(tc, set_opt_invalid_option);
	suite_add_tcase(s, tc);

	return s;
}