/*
 * Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2005 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2007 High Performance Computing Center Stuttgart, 
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2009      Sun Microsystems, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_PRIVATE_CONFIG_H
#define CCI_PRIVATE_CONFIG_H

#ifdef CCI_H
#error cci/private_config.h must be included before cci.h
#endif

/* Include all the output from configure */
#include "cci/configure_output.h"

/**
 * The attribute definition should be included before any potential
 * usage.
 */
#if CCI_HAVE_ATTRIBUTE_ALIGNED
#define __cci_attribute_aligned__(a)    __attribute__((__aligned__(a)))
#define __cci_attribute_aligned_max__   __attribute__((__aligned__))
#else
#define __cci_attribute_aligned__(a)
#define __cci_attribute_aligned_max__
#endif

#if CCI_HAVE_ATTRIBUTE_ALWAYS_INLINE
#define __cci_attribute_always_inline__ __attribute__((__always_inline__))
#else
#define __cci_attribute_always_inline__
#endif

#if CCI_HAVE_ATTRIBUTE_COLD
#define __cci_attribute_cold__          __attribute__((__cold__))
#else
#define __cci_attribute_cold__
#endif

#if CCI_HAVE_ATTRIBUTE_CONST
#define __cci_attribute_const__         __attribute__((__const__))
#else
#define __cci_attribute_const__
#endif

#if CCI_HAVE_ATTRIBUTE_DEPRECATED
#define __cci_attribute_deprecated__    __attribute__((__deprecated__))
#else
#define __cci_attribute_deprecated__
#endif

#if CCI_HAVE_ATTRIBUTE_FORMAT
#define __cci_attribute_format__(a,b,c) __attribute__((__format__(a, b, c)))
#else
#define __cci_attribute_format__(a,b,c)
#endif

#if CCI_HAVE_ATTRIBUTE_HOT
#define __cci_attribute_hot__           __attribute__((__hot__))
#else
#define __cci_attribute_hot__
#endif

#if CCI_HAVE_ATTRIBUTE_MALLOC
#define __cci_attribute_malloc__        __attribute__((__malloc__))
#else
#define __cci_attribute_malloc__
#endif

#if CCI_HAVE_ATTRIBUTE_MAY_ALIAS
#define __cci_attribute_may_alias__     __attribute__((__may_alias__))
#else
#define __cci_attribute_may_alias__
#endif

#if CCI_HAVE_ATTRIBUTE_NO_INSTRUMENT_FUNCTION
#define __cci_attribute_no_instrument_function__  __attribute__((__no_instrument_function__))
#else
#define __cci_attribute_no_instrument_function__
#endif

#if CCI_HAVE_ATTRIBUTE_NONNULL
#define __cci_attribute_nonnull__(a)    __attribute__((__nonnull__(a)))
#define __cci_attribute_nonnull_all__   __attribute__((__nonnull__))
#else
#define __cci_attribute_nonnull__(a)
#define __cci_attribute_nonnull_all__
#endif

#if CCI_HAVE_ATTRIBUTE_NORETURN
#define __cci_attribute_noreturn__      __attribute__((__noreturn__))
#else
#define __cci_attribute_noreturn__
#endif

#if CCI_HAVE_ATTRIBUTE_PACKED
#define __cci_attribute_packed__        __attribute__((__packed__))
#else
#define __cci_attribute_packed__
#endif

#if CCI_HAVE_ATTRIBUTE_PURE
#define __cci_attribute_pure__          __attribute__((__pure__))
#else
#define __cci_attribute_pure__
#endif

#if CCI_HAVE_ATTRIBUTE_SENTINEL
#define __cci_attribute_sentinel__      __attribute__((__sentinel__))
#else
#define __cci_attribute_sentinel__
#endif

#if CCI_HAVE_ATTRIBUTE_UNUSED
#define __cci_attribute_unused__        __attribute__((__unused__))
#else
#define __cci_attribute_unused__
#endif

#if CCI_HAVE_VISIBILITY
#define __cci_attribute_visibility__(a) __attribute__((__visibility__(a)))
#else
#define __cci_attribute_visibility__(a)
#endif

#if CCI_HAVE_ATTRIBUTE_WARN_UNUSED_RESULT
#define __cci_attribute_warn_unused_result__ __attribute__((__warn_unused_result__))
#else
#define __cci_attribute_warn_unused_result__
#endif

#if CCI_HAVE_ATTRIBUTE_WEAK_ALIAS
#define __cci_attribute_weak_alias__(a) __attribute__((__weak__, __alias__(a)))
#else
#define __cci_attribute_weak_alias__(a)
#endif

#endif /* CCI_PRIVATE_CONFIG_H */
