/*
 * Copyright (c) 2010-2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2010-2011 Oak Ridge National Labs.  All rights reserved.
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
    /*! Public device (name, info, argv, max_send_size, rate, pci) */
    cci_device_t device;

    /*! Driver name */
    char *driver;

    /*! Priority (0-100, default = 50) */
    int priority;

    /*! Default device? */
    int is_default;

    /*! Is the device up? */
    int is_up;

    /*! entry to hang this dev on the globals->devs */
    TAILQ_ENTRY(cci__dev) entry;

    /*! Endpoints */
    TAILQ_HEAD(s_eps, cci__ep) eps;

    /*! Listening endpoints */
    TAILQ_HEAD(s_dleps, cci__lep) leps;

    /*! Lock for eps, leps */
    pthread_mutex_t lock;

    /*! Pointer to device specific struct */
    void *priv;
} cci__dev_t;

/*! CCI private endpoint */
typedef struct cci__ep {
    /*! Public endpoint (max_recv_buffer_count) */
    cci_endpoint_t endpoint;

    /*! Max header size for txs and RMAs */
    uint8_t max_hdr_size;

    /*! Number of rx buffers */
    uint32_t rx_buf_cnt;

    /*! Number of tx buffers */
    uint32_t tx_buf_cnt;

    /*! Size of rx/tx buffers */
    uint32_t buffer_len;

    /*! Send timeout in microseconds */
    uint32_t tx_timeout;

    /*! Keepalive timeout in microseconds */
    uint32_t keepalive_timeout;

    /*! Events ready for process */
    TAILQ_HEAD(s_evts, cci__evt) evts;

    /*! Lock to protect evts */
    pthread_mutex_t lock;

    /*! Owning dev */
    cci__dev_t *dev;

    /*! Entry to hang on dev->eps */
    TAILQ_ENTRY(cci__ep) entry;

    /*! Pointer to device specific struct */
    void *priv;
} cci__ep_t;

/*! CCI private connection request */
typedef struct cci__crq {
    /*! Public connection request (devices, cnt, ptr, len, attribute) */
    cci_conn_req_t conn_req;

    /*! Owning listening endpoint */
    struct cci__lep *lep;

    /*! Entry to hang on lep->crqs and svc->crqs */
    TAILQ_ENTRY(cci__crq) entry;

    /*! Entry to hang on lep->all_crqs for clean up */
    TAILQ_ENTRY(cci__crq) lentry;

    /*! Pointer to device specific struct */
    void *priv;
} cci__crq_t;

/*! CCI private connection */
typedef struct cci__conn {
    /*! Public connection (max_send_size, endpoint, attribute) */
    cci_connection_t connection;

    /*! URI we connected to if we called connect */
    const char *uri;

    /*! Send timeout in microseconds (if 0 use ep->tx_timeout) */
    uint32_t tx_timeout;

    /*! Pointer to device specific struct */
    void *priv;
} cci__conn_t;

/*! CCI private connection manager service */
typedef struct cci__svc {
    /*! Public service (bogus) */
    cci_service_t service;

    /*! Port to listen on */
    uint32_t port;

    /*! Bound listening endpoints */
    TAILQ_HEAD(s_sleps, cci__lep) leps;

    /*! Pending connection requests */
    TAILQ_HEAD(s_scrqs, cci__crq) crqs;

    /*! Lock to protect leps and crqs */
    pthread_mutex_t lock;

    /* Entry to hang on globals->svcs */
    TAILQ_ENTRY(cci__svc) entry;
} cci__svc_t;

/*! CCI private event */
typedef struct cci__evt {
    /*! Public event (type, union of send/recv/other) */
    cci_event_t event;

    /*! Owning endpoint */
    cci__ep_t *ep;

    /*! Owning connection */
    cci__conn_t *conn;

    /*! Entry to hang on ep->evts */
    TAILQ_ENTRY(cci__evt) entry;

    /*! Pointer to device specific struct */
    void *priv;
} cci__evt_t;

typedef enum cci__lep_state {
    CCI_LEP_CLOSING = -1,
    CCI_LEP_INIT,
    CCI_LEP_READY,
} cci__lep_state_t;

/*! CCI private listening endpoint (created when device is bound to service) */
typedef struct cci__lep {
    /*! Is this listening endpoint usable? */
    cci__lep_state_t state;

    /*! Owning device */
    cci__dev_t *dev;

    /*! Service we are bound to */
    struct cci__svc *svc;

    /*! Number of crqs when bound */
    int backlog;

    /*! Entry to hang on svc->leps */
    TAILQ_ENTRY(cci__lep) sentry;

    /*! Entry to hang on dev->leps */
    TAILQ_ENTRY(cci__lep) dentry;

    /*! List of idle connection requests */
    TAILQ_HEAD(s_lcrqs, cci__crq) crqs;

    /*! List of all connection requests */
    TAILQ_HEAD(s_acrqs, cci__crq) all_crqs;

    /*! List of passive connections pending REJECT replies */
    TAILQ_HEAD(s_passive, cci__crq) passive;

    /*! Lock to protect crqs */
    pthread_mutex_t lock;

    /*! Pointer to device specific struct */
    void *priv;

    /*! Debug mask */
    uint32_t debug;
} cci__lep_t;

/*! CCI private global state */
typedef struct cci__globals {
    /*! List of all known devices */
    TAILQ_HEAD(s_devs, cci__dev) devs;

    /*! Array of user devices */
    cci_device_t **devices;

    /*! Lock to protect svcs */
    pthread_mutex_t lock;

    /*! List of connection manager services sorted by port number */
    TAILQ_HEAD(s_svcs, cci__svc) svcs;
} cci__globals_t;

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

static inline uint32_t
cci__get_svc_port(uint32_t *port)
{
    uint32_t p = 4096;
    cci__svc_t *svc;

    if (*port)
        p = *port;

    TAILQ_FOREACH(svc, &globals->svcs, entry) {
        if (svc->port > p) {
            return CCI_SUCCESS;
        } else if (svc->port == p) {
            if (*port)
                return CCI_EBUSY;
            else
                p++;
        }
        if (p == 0) {
            /* we rolled over */
            return CCI_EBUSY;
        }
    }

    return CCI_SUCCESS;
}

extern int cci__debug;

/*
 * Debugging macros.
 */
#define CCI_DB_MEM    (1 << 0) /* memory alloc/free and accounting */
#define CCI_DB_MSG    (1 << 1) /* handling tx/rx structures, sending/receiving */
#define CCI_DB_PEER   (1 << 2) /* modifying peers */
#define CCI_DB_CONN   (1 << 3) /* connection handling */
#define CCI_DB_ERR    (1 << 4) /* fatal errors, should always be followed by exit() */
#define CCI_DB_FUNC   (1 << 5) /* enterling/leaving functions */
#define CCI_DB_INFO   (1 << 6) /* just informational */
#define CCI_DB_WARN   (1 << 7) /* non-fatal error */
#define CCI_DB_DRVR   (1 << 8) /* driver function returned error */

#define CCI_DB_ALL    (~0)     /* print everything */
#define CCI_DB_DFLT   (CCI_DB_ERR|CCI_DB_WARN)

#define CCI_DEBUG     1        /* Turn on for developing */

#if CCI_DEBUG
#define debug(lvl,fmt,args...)                          \
  do {                                                  \
      if (lvl & cci__debug)                         \
          fprintf(stderr, "cci: " fmt "\n", ##args);    \
  } while (0)
#else  /* ! CCI_DEBUG */
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

END_C_DECLS

#endif /* CCI_LIB_TYPES_H */
