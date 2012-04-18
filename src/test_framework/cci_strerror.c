/*
 * cci_strerror.c
 *
 * test implementation of cci_strerror() to ensure that it emits the correct messages and that it
 * rejects invalid input.
 *
 * const char* cci_strerror(enum cci_status status);
 *
 * valid inputs are:
 *  CCI_SUCCESS = 0
 *  CCI_ERROR
 *  CCI_ERR_DISCONNECTED
 *  CCI_ERR_RNR
 *  CCI_ERR_DEVICE_DEAD
 *  CCI_ERR_RMA_HANDLE
 *  CCI_ERR_RMA_OP
 *  CCI_ERR_NOT_IMPLEMENTED
 *  CCI_ERR_NOT_FOUND
 *  CCI_EINVAL
 *  CCI_ETIMEDOUT
 *  CCI_ENOMEM
 *  CCI_ENODEV
 *  CCI_EBUSY
 *  CCI_ERANGE
 *  CCI_EAGAIN
 *  CCI_ENOBUFS
 *  CCI_EMSGSIZE
 *  CCI_ENOMSG
 *  CCI_EADDRNOTAVAIL
 *
 * Author: Lawrence MacIntyre
 * 
 * Notes:
 *		Using an illegal value for cci_strerror() causes a segment violation fault. We think
 *    that this is caused by some interaction between the fork() call and the use of shared
 *    libraries, but we are not sure (but we are very puzzled)
 *
 * History:
 * 2012 Feb 09 : lpm : initial implementation
 * 2012 Apr 05 : lpm : fixed cci_strerror() for new format
 */
 
#include "cci_check.h"
#include <string.h>		/* strcmp() */
#include <signal.h>		/* SIGSEGV */
	
typedef enum fake_nums {	/* 10 is actually illegal. 110 mimics ETIMEDOUT in illegal value test */
	TEN = 10,
	ONE_HUNDRED_TEN = 110
} fake_nums_t;

START_TEST(strerror_SUCCESS) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_SUCCESS);
  fail_unless(strcmp(msg, "CCI_SUCCESS") == 0, "cci_strerror(CCI_SUCCESS)");
}
END_TEST

START_TEST(strerror_ERROR) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERROR);
  fail_unless(strcmp(msg, "CCI_ERROR") == 0, "cci_strerror(CCI_ERROR)");
}
END_TEST

START_TEST(strerror_ERR_DISCONNECTED) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_DISCONNECTED);
  fail_unless(strcmp(msg, "CCI_ERR_DISCONNECTED") == 0, "cci_strerror(CCI_)ERR_DISCONNECTED");
}
END_TEST

START_TEST(strerror_ERR_RNR) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_RNR);
  fail_unless(strcmp(msg, "CCI_ERR_RNR") == 0, "cci_strerror(CCI_ERR_RNR)");
}
END_TEST

START_TEST(strerror_ERR_DEVICE_DEAD) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_DEVICE_DEAD);
  fail_unless(strcmp(msg, "CCI_ERR_DEVICE_DEAD") == 0, "cci_strerror(CCI_ERR_DEVICE_DEAD)");
}
END_TEST

START_TEST(strerror_ERR_RMA_HANDLE) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_RMA_HANDLE);
  fail_unless(strcmp(msg, "CCI_ERR_RMA_HANDLE") == 0, "cci_strerror(CCI_RMA_HANDLE)");
}
END_TEST

START_TEST(strerror_ERR_RMA_OP) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_RMA_OP);
  fail_unless(strcmp(msg, "CCI_ERR_RMA_OP") == 0, "cci_strerror(CCI_RMA_OP)");
}
END_TEST

START_TEST(strerror_ERR_NOT_IMPLEMENTED) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_NOT_IMPLEMENTED);
  fail_unless(strcmp(msg, "CCI_ERR_NOT_IMPLEMENTED") == 0, "cci_strerror(CCI_ERR_NOT_IMPLEMENTED)");
}
END_TEST

START_TEST(strerror_ERR_NOT_FOUND) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERR_NOT_FOUND);
  fail_unless(strcmp(msg, "CCI_ERR_NOT_FOUND") == 0, "cci_strerror(CCI_ERR_NOT_FOUND)");
}
END_TEST

START_TEST(strerror_EINVAL) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_EINVAL);
  fail_unless(strcmp(msg, "CCI_EINVAL") == 0, "cci_strerror(CCI_EINVAL)");
}
END_TEST

START_TEST(strerror_ETIMEDOUT) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ETIMEDOUT);
  fail_unless(strcmp(msg, "CCI_ETIMEDOUT") == 0, "cci_strerror(CCI_ETIMEDOUT)");
}
END_TEST

START_TEST(strerror_ENOMEM) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ENOMEM);
  fail_unless(strcmp(msg, "CCI_ENOMEM") == 0, "cci_strerror(CCI_ENOMEM)");
}
END_TEST

START_TEST(strerror_ENODEV) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ENODEV);
  fail_unless(strcmp(msg, "CCI_ENODEV") == 0, "cci_strerror(CCI_ENODEV)");
}
END_TEST

START_TEST(strerror_EBUSY) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_EBUSY);
  fail_unless(strcmp(msg, "CCI_EBUSY") == 0, "cci_strerror(CCI_EBUSY)");
}
END_TEST

START_TEST(strerror_ERANGE) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ERANGE);
  fail_unless(strcmp(msg, "CCI_ERANGE") == 0, "cci_strerror(CCI_ERANGE)");
}
END_TEST

START_TEST(strerror_EAGAIN) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_EAGAIN);
  fail_unless(strcmp(msg, "CCI_EAGAIN") == 0, "cci_strerror(CCI_EAGAIN)");
}
END_TEST

START_TEST(strerror_ENOBUFS) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ENOBUFS);
  fail_unless(strcmp(msg, "CCI_ENOBUFS") == 0, "cci_strerror(CCI_ENOBUFS)");
}
END_TEST

START_TEST(strerror_EMSGSIZE) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_EMSGSIZE);
  fail_unless(strcmp(msg, "CCI_EMSGSIZE") == 0, "cci_strerror(CCI_EMSGSIZE)");
}
END_TEST

START_TEST(strerror_ENOMSG) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_ENOMSG);
  fail_unless(strcmp(msg, "CCI_ENOMSG") == 0, "cci_strerror(CCI_ENOMSG)");
}
END_TEST

START_TEST(strerror_EADDRNOTAVAIL) {
	char* msg=NULL;
	
  msg = (char*) cci_strerror(NULL, CCI_EADDRNOTAVAIL);
  fail_unless(strcmp(msg, "CCI_EADDRNOTAVAIL") == 0, "cci_strerror(CCI_EADDRNOTAVAIL)");
}
END_TEST

START_TEST(strerror_Illegal_Input_Value) {
	char* msg=NULL;
	uint32_t msgValue = TEN;
	
  msg = (char*) cci_strerror(NULL, msgValue);
	printf("strerror_Illegal_Input_Value: %s\n", msg);
  fail_unless(msg == NULL, "cci_strerror(<illegal value>)");	/* Won't get here, SIGSEGV generated above */
}
END_TEST


/* Now build the individual tests into a test suite */

Suite* cci_strerror_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_strerror");
	if(s == NULL) {
		perror("suite_create(cci_strerror)");
		return NULL;
	}
	
	tc = tcase_create("strerror_case");
	if(s == NULL) {
		perror("tcase_create(strerror_case)");
		return NULL;
	}	

	tcase_add_test(tc, strerror_SUCCESS);
	tcase_add_test(tc, strerror_ERROR);
	tcase_add_test(tc, strerror_ERR_DISCONNECTED);
	tcase_add_test(tc, strerror_ERR_RNR);
	tcase_add_test(tc, strerror_ERR_DEVICE_DEAD);
	tcase_add_test(tc, strerror_ERR_RMA_HANDLE);
	tcase_add_test(tc, strerror_ERR_RMA_OP);
	tcase_add_test(tc, strerror_ERR_NOT_IMPLEMENTED);
	tcase_add_test(tc, strerror_ERR_NOT_FOUND);
	tcase_add_test(tc, strerror_EINVAL);
	tcase_add_test(tc, strerror_ETIMEDOUT);
	tcase_add_test(tc, strerror_ENOMEM);
	tcase_add_test(tc, strerror_ENODEV);
	tcase_add_test(tc, strerror_EBUSY);
	tcase_add_test(tc, strerror_ERANGE);
	tcase_add_test(tc, strerror_EAGAIN);
	tcase_add_test(tc, strerror_ENOBUFS);
	tcase_add_test(tc, strerror_EMSGSIZE);
	tcase_add_test(tc, strerror_ENOMSG);
	tcase_add_test(tc, strerror_EADDRNOTAVAIL);
//	tcase_add_test(tc, strerror_Illegal_Input_Value);		/* fails with SIGSEGV unless --nofork is requested */
	tcase_add_test_raise_signal(tc, strerror_Illegal_Input_Value, SIGSEGV);

	suite_add_tcase(s, tc);

	return s;
}