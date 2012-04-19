/*
 * cci_check.h
 *
 * include all of the suites
 *
 * Author: Lawrence MacIntyre
 * 
 * Notes:
 *
 * History:
 * 2012 Feb 09 : lpm : initial implementation
 * 2012 Feb 10 : lpm : added strerror_suite
 * 2012 Feb 11 : lpm : added get_devices_suite
 * 2012 Mar 03 : lpm : added errno.h
 * 2012 Apr 05 : lpm : added cci_set_opt_suite
 */
 
#ifndef CCI_CHECK_H
#define CCI_CHECK_H

#include <check.h>		/* set up check library */
#include <cci.h>					/* set up CCI library */
#include <stdint.h>			/* define uint32_t and friends */
#include <stdio.h>			/* perror(), etc. */
#include <stdlib.h>			/* define NULL */
#include <errno.h>      /* error numbers */

Suite* cci_init_suite(void);
Suite* cci_strerror_suite(void);
Suite* cci_get_devices_suite(void);
Suite* cci_create_endpoint_suite(void);
Suite* cci_get_opt_suite(void);
Suite* cci_set_opt_suite(void);

#endif /* CCI_CHECK_H */