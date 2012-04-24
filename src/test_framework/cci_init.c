/*
 * cci_init.c
 *
 * test implementation of cci_init() to ensure that it rejects invalid input.
 *
 * int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t caps);
 *
 * Author: Lawrence MacIntyre
 * 
 * History:
 * 2012 Feb 9 : lpm : initial implementation
 */
 
#include "cci_check.h"

/* check to see that CCI_ABI_VERSION = 1 */
START_TEST (init_abi_version_equals_1) {
	fail_unless(CCI_ABI_VERSION == 1, "CCI_ABI_VERSION == 1");
}
END_TEST

/* call cci_init with CCI_ABI_VERSION -= 1 - returns EINVAL */
START_TEST(init_abi_version_decremented) {
	uint32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t capabilities = 0;			                								/* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;									/* pointer to capabilities */
	uint32_t ABIVersion = CCI_ABI_VERSION-1;
	
  /* Initialize cci library */
  status = cci_init(ABIVersion, initFlags, capabilitiesP);
	fail_unless(status == CCI_EINVAL, "cci_init() with abi_version = CCI_ABI_VERSION - 1");
}
END_TEST

/* Ensure that abi_version cannot equal 2 */
START_TEST(init_abi_version_incremented) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t capabilities = 0;			                								/* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;
	uint32_t ABIVersion = CCI_ABI_VERSION+1;

  status = cci_init(ABIVersion, initFlags, capabilitiesP);
	fail_unless(status == CCI_EINVAL, "cci_init() with abi_version = CCI_ABI_VERSION + 1");
}
END_TEST

/* Ensure that caps cannot be NULL */	
START_TEST(init_address_of_capabilities_null) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t* capabilitiesP = NULL;
	uint32_t ABIVersion = CCI_ABI_VERSION;
  
  status = cci_init(ABIVersion, initFlags, capabilitiesP);	
	fail_unless(status == CCI_EINVAL, "cci_init() with &capabilities = NULL");
}
END_TEST

/* Ensure that flags cannot be 1  - We get CCI_SUCCESS here - failure? */
START_TEST(init_flags_equal_1) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 1;																					/* right now these don't exist */
	uint32_t capabilities = 0;			                								/* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;
	uint32_t ABIVersion = CCI_ABI_VERSION;

  status = cci_init(ABIVersion, initFlags, capabilitiesP);	
	fail_unless(status == CCI_EINVAL, "cci_init() with flags = 1");
}
END_TEST

/* This should work */
START_TEST(init_correct) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t capabilities = 0;			              /* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;
	uint32_t ABIVersion = CCI_ABI_VERSION;

  status = cci_init(ABIVersion, initFlags, capabilitiesP);	
	fail_unless(status == CCI_SUCCESS, "cci_init() with correct parameters");
}
END_TEST

/* This should work. If you call cci_init() twice with correct parameters, it should work both times */
START_TEST(init_repeat) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t capabilities = 0;			                								/* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;
	uint32_t ABIVersion = CCI_ABI_VERSION;

  status = cci_init(ABIVersion, initFlags, capabilitiesP);	
	fail_unless(status == CCI_SUCCESS, "cci_init() repeated with same parameters");
}
END_TEST

/* set capabilities to something bogus and call cci_init(). It should return 0 */
START_TEST(init_with_initial_capabilities_value) {
  int32_t status;								                      								/* return value from subroutine */
	uint32_t initFlags = 0;																					/* right now these don't exist */
	uint32_t capabilities = 0x01020304;			              /* capabilities for cci_init() */
	uint32_t* capabilitiesP = &capabilities;
	uint32_t ABIVersion = CCI_ABI_VERSION;

  status = cci_init(ABIVersion, initFlags, capabilitiesP);
  fail_unless(status == CCI_SUCCESS, "cci_init() should return status = CCI_SUCCESS");
	fail_unless(capabilities == 0, "cci_init() should return value of 0 for capabilities");
}
END_TEST

/* Now build the individual tests into a test suite */

Suite* cci_init_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_init");
	if(s == NULL) {
		perror("suite_create(cci_init)");
		return NULL;
	}
	
	tc = tcase_create("init_case");
	if(tc == NULL) {
		perror("tcase_create(init_case)");
		return NULL;
	}
	
	tcase_add_test(tc, init_abi_version_equals_1);
	tcase_add_test(tc, init_abi_version_decremented);
	tcase_add_test(tc, init_abi_version_incremented);
	tcase_add_test(tc, init_address_of_capabilities_null);
	tcase_add_test(tc, init_flags_equal_1);
	tcase_add_test(tc, init_correct);
	tcase_add_test(tc, init_repeat);
	tcase_add_test(tc, init_with_initial_capabilities_value);
	suite_add_tcase(s, tc);

	return s;
}