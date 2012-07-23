/*
 * Copyright (c) 2010-2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2010-2011 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 * Private data structures for the Common Communications Interface (CCI).
 */

#ifndef CCI_LIB_TYPES_H
#define CCI_LIB_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stddef.h>
#include "bsd/queue.h"
#include "plugins/ctp/ctp.h"

BEGIN_C_DECLS
#define CCI_MAX_DEVICES     32
#define CCI_MAX_ARGS        32
#define CCI_MAX_KEY_LEN     256
#define CCI_MAX_VALUE_LEN   512
/* NOTE: struct naming scheme
 *       - Private structs start with cci__
 *       - Names should not be be the same as the public counterpart
 *         to avoid accidentally using the public struct or vice versa
 *         (e.g. cci__device_t)
 *       - List entry variables are entry if only one per struct
 *         else they start with the first letter of the struct
 *         that they will hang on
 *         (e.g. dentry will hang on a device
 *               sentry will hang on a service)
 *       - Public struct field names should be their name
 *         (e.g. cci_device_t device;)
 */
/*! CCI private device */
    typedef struct cci__dev {
	/*! Pointer to the plugin structure */
	struct cci_plugin_ctp *plugin; /* set by the plugin init() */

	/*! Public device (name, info, argv, max_send_size, rate, pci) */
	struct cci_device device;

	/*! Priority (0-100, default = 50) */
	int priority;

	/*! Default device? */
	int is_default;

	/*! entry to hang this dev on the globals->devs */
	 TAILQ_ENTRY(cci__dev) entry;

	/*! Endpoints */
	 TAILQ_HEAD(s_eps, cci__ep) eps;

	/*! Lock for eps, leps */
	pthread_mutex_t lock;

	/*! Pointer to device specific struct */
	void *priv;

	/*! Device RMA alignment requirements. Used for CCI_OPT_ENDPT_RMA_ALIGN. */
	cci_alignment_t align;
} cci__dev_t;

/* export for transports as needed */
void cci__init_dev(cci__dev_t *dev);

/*! CCI private endpoint */
typedef struct cci__ep {
	/*! Pointer to the plugin structure */
	struct cci_plugin_ctp *plugin; /* set by the ctp before passing the newly allocated endpoint to the plugin create_endpoint() */

	/*! Public endpoint (max_recv_buffer_count) */
	struct cci_endpoint endpoint;

	/*! Number of rx buffers. Used for CCI_OPT_ENDPT_RECV_BUF_COUNT. */
	uint32_t rx_buf_cnt;

	/*! Number of tx buffers. Used for CCI_OPT_ENDPT_SEND_BUF_COUNT. */
	uint32_t tx_buf_cnt;

	/*! Size of rx/tx buffers. Sets initial connection->max_send_size. */
	uint32_t buffer_len;

	/*! Send timeout in microseconds. Used for CCI_OPT_ENDPT_SEND_TIMEOUT. */
	uint32_t tx_timeout;

	/*! Keepalive timeout in microseconds. Used for CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT. */
	uint32_t keepalive_timeout;

	/*! Events ready for process */
	 TAILQ_HEAD(s_evts, cci__evt) evts;

	/*! Lock to protect evts */
	pthread_mutex_t lock;

	/*! Is closing down? */
	int closing;

	/*! Owning dev */
	cci__dev_t *dev;

	/*! Entry to hang on dev->eps */
	 TAILQ_ENTRY(cci__ep) entry;

	/*! Pointer to device specific struct */
	void *priv;

	/*! Endpoint URI. Used for CCI_OPT_ENDPT_URI. This endpoint's
	    listening address that client's can pass to cci_connect().
	    The application should never need to parse this URI. */
	char *uri;
} cci__ep_t;

/*! CCI private connection */
typedef struct cci__conn {
	/*! Pointer to the plugin structure */
	struct cci_plugin_ctp *plugin; /* set by the plugin before returning the connection in connect/accept events */

	/*! Public connection (max_send_size, endpoint, attribute) */
	struct cci_connection connection;

	/*! URI we connected to if we called connect */
	const char *uri;

	/*! Send timeout in microseconds (if 0 use ep->tx_timeout) */
	uint32_t tx_timeout;

	/*! Keepalive timeout in microseconds */
	uint32_t keepalive_timeout;

	/*! Pointer to device specific struct */
	void *priv;
} cci__conn_t;

static inline int cci_conn_is_reliable(cci__conn_t * conn)
{
	return (conn->connection.attribute == CCI_CONN_ATTR_RO ||
		conn->connection.attribute == CCI_CONN_ATTR_RU);
}

/*! CCI private event */
typedef struct cci__evt {
	/*! Public event (type, union of send/recv/other) */
	union cci_event event;

	/*! Owning endpoint */
	cci__ep_t *ep;

	/*! Owning connection */
	cci__conn_t *conn;

	/*! Entry to hang on ep->evts */
	 TAILQ_ENTRY(cci__evt) entry;

	/*! Pointer to device specific struct */
	void *priv;
} cci__evt_t;

/*! CCI private global state */
typedef struct cci__globals {
	/*! List of all known devices */
	TAILQ_HEAD(s_devs, cci__dev) devs;

	/*! Temporary list of devices read from the config file */
	struct s_devs configfile_devs;

	/*! Array of user devices */
	struct cci_device **devices;

	/*! Lock to protect svcs */
	pthread_mutex_t lock;

	/*! Set if a configfile was specified and read */
	int configfile;

	/*! Flags given to cci_init() */
	uint32_t flags;
} cci__globals_t;

extern pthread_mutex_t init_lock; /*! Protects initialized and globals during cci_init() and cci_finalize() */
extern int initialized; /*! How many times cci_init() was called minus how many times cci_finalize() was called */
extern cci__globals_t *globals;

/*! Obtain the private struct from the public struct
 *  Example 1:
 *    cci_endpoint_t *endpt;
 *    cci__ep_t *ep;
 *
 *    ep = container_of(endpt, cci__ep_t, endpoint);
 *
 *  Example 2:
 *    cci_device_t *device;
 *    cci__dev_t *dev;
 *
 *    dev = container_of(device, cci__dev_t, device);
 *
 *    where the first use of "device" is the variable
 *    the "cci__dev_t" is the parent struct
 *    and the second device is the name of the field in the parent struct
 *
 *    If we always use the name of the field in the parent struct for
 *    the local variable name, then the name is repeated as in
 *    example 2 */
#define container_of(p,stype,field) ((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))

extern int cci__debug;

/*
 * Debugging macros.
 */
#define CCI_DB_MEM    (1 << 0)	/* memory alloc/free and accounting */
#define CCI_DB_MSG    (1 << 1)	/* handling tx/rx structures, sending/receiving */
#define CCI_DB_PEER   (1 << 2)	/* modifying peers */
#define CCI_DB_CONN   (1 << 3)	/* connection handling */
#define CCI_DB_ERR    (1 << 4)	/* fatal errors, should always be followed by exit() */
#define CCI_DB_FUNC   (1 << 5)	/* enterling/leaving functions */
#define CCI_DB_INFO   (1 << 6)	/* just informational */
#define CCI_DB_WARN   (1 << 7)	/* non-fatal error */
#define CCI_DB_DRVR   (1 << 8)	/* transport function returned error */
#define CCI_DB_EP     (1 << 9)	/* endpoint handling */

#define CCI_DB_ALL    (~0)	/* print everything */
#define CCI_DB_DFLT   (CCI_DB_ERR|CCI_DB_WARN)

#define CCI_DEBUG     1		/* Turn on for developing */

#if CCI_DEBUG
#define debug(lvl,fmt,args...)                          \
  do {                                                  \
      if (lvl & cci__debug)                         \
          fprintf(stderr, "cci: " fmt "\n", ##args);    \
  } while (0)
#else /* ! CCI_DEBUG */
#define debug(lvl,fmt,...) do { } while (0)
#endif /* CCI_DEBUG */

#define CCI_ENTER                                                               \
  do {                                                                          \
        debug(CCI_DB_FUNC, "entering %s", __func__);                            \
  } while (0);

#define CCI_EXIT                                                                \
  do {                                                                          \
        debug(CCI_DB_FUNC, "exiting  %s", __func__);                            \
  } while (0);

#if HAVE_DECL_VALGRIND_MAKE_MEM_NOACCESS
#include <valgrind/memcheck.h>
#define CCI_VALGRIND_MEMORY_MAKE_NOACCESS(p, s) VALGRIND_MAKE_MEM_NOACCESS(p, s)
#define CCI_VALGRIND_MEMORY_MAKE_WRITABLE(p, s) VALGRIND_MAKE_MEM_UNDEFINED(p, s)
#define CCI_VALGRIND_MEMORY_MAKE_READABLE(p, s) VALGRIND_MAKE_MEM_DEFINED(p, s)
#define CCI_VALGRIND_CHECK_DEFINED(p, s) VALGRIND_CHECK_VALUE_IS_DEFINED(p, s)
#define CCI_VALGRIND_CHECK_WRITABLE(p, s) VALGRIND_CHECK_VALUE_IS_WRITABLE(p, s)
#else /* !HAVE_DECL_VALGRIND_MAKE_MEM_NOACCESS */
#define CCI_VALGRIND_MEMORY_MAKE_NOACCESS(p, s) /* nothing */
#define CCI_VALGRIND_MEMORY_MAKE_WRITABLE(p, s) /* nothing */
#define CCI_VALGRIND_MEMORY_MAKE_READABLE(p, s) /* nothing */
#define CCI_VALGRIND_CHECK_DEFINED(p, s) /* nothing */
#define CCI_VALGRIND_CHECK_WRITABLE(p, s) /* nothing */
#endif /* !HAVE_DECL_VALGRIND_MAKE_MEM_NOACCESS */

END_C_DECLS
#endif /* CCI_LIB_TYPES_H */
