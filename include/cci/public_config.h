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

#ifndef CCI_PUBLIC_CONFIG_H
#define CCI_PUBLIC_CONFIG_H

/*
 * BEGIN_C_DECLS should be used at the beginning of your declarations,
 * so that C++ compilers don't mangle their names.  Use END_C_DECLS at
 * the end of C declarations.
 */
#undef BEGIN_C_DECLS
#undef END_C_DECLS
#if defined(c_plusplus) || defined(__cplusplus)
#define BEGIN_C_DECLS extern "C" {
#define END_C_DECLS }
#else
#define BEGIN_C_DECLS		/* empty */
#define END_C_DECLS		/* empty */
#endif

/* Shortcut to see if we're on any flavor of Windows */
#if !defined(__WINDOWS__)
#if defined(_WIN32) || defined(WIN32) || defined(WIN64)
#define __WINDOWS__
#endif
#endif /* !defined(__WINDOWS__) */

#if defined(__WINDOWS__)
#if defined(_USRDLL)		/* building shared libraries (.DLL) */
#define CCI_DECLSPEC        __declspec(dllexport)
#else /* building static library */
#define CCI_DECLSPEC        __declspec(dllimport)
#endif /* defined(_USRDLL) */
#else
#if (defined CCI_HAVE_VISIBILITY) && CCI_HAVE_VISIBILITY
#define CCI_DECLSPEC           __cci_attribute_visibility__("default")
#else
#define CCI_DECLSPEC
#endif
#endif /* defined(__WINDOWS__) */

#endif /* CCI_PUBLIC_CONFIG_H */
