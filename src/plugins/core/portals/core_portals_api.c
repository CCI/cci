/*
 *; Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#if defined(__INTEL_COMPILER)
#pragma warning(disable:593)
#pragma warning(disable:869)
#pragma warning(disable:981)
#pragma warning(disable:1338)
#pragma warning(disable:2259)
#endif //   __INTEL_COMPILER

#include "cci/config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "cci.h"
#include "plugins/core/core.h"
#include "core_portals.h"

volatile int portals_shut_down = 0;
portals_globals_t *pglobals=NULL;
pthread_t progress_tid;

/******* cycle counting sampling code ****/
#define ENABLE_PORTALS_SAMPLING 0
#if ENABLE_PORTALS_SAMPLING
#define PORTALS_NUM_SAMPLES (1000)
uint64_t *portals_start_ns;
uint64_t *portals_end_ns;
static int portals_num_samples = PORTALS_NUM_SAMPLES;
static int portals_sample = 0;
#define PORTALS_SAMPLE_START                                    \
do {                                                            \
    if (!portals_start_ns)                                      \
        break;                                                  \
    if (portals_sample < portals_num_samples)                   \
        portals_start_ns[portals_sample] = portals_get_nsecs(); \
} while(0)

#define PORTALS_SAMPLE_END                                      \
do {                                                            \
    if (!portals_end_ns)                                        \
        break;                                                  \
    if (portals_sample < portals_num_samples)                   \
        portals_end_ns[portals_sample++] = portals_get_nsecs(); \
} while(0)
int portals_debug_is_server = 0;
#define PORTALS_IS_SERVER           \
do {                                \
    portals_debug_is_server = 1;    \
} while (0)

static inline void portals_sample_init(void)
{
    int i;

    portals_start_ns = calloc(PORTALS_NUM_SAMPLES, sizeof(*portals_start_ns));
    portals_end_ns = calloc(PORTALS_NUM_SAMPLES, sizeof(*portals_end_ns));
    if (!portals_start_ns || !portals_end_ns) {
        if (portals_start_ns)
            free(portals_start_ns);
        else
            free(portals_end_ns);
        portals_num_samples = 0;
        return;
    }
    for (i = 0; i < PORTALS_NUM_SAMPLES; i++) {
        portals_start_ns[i] = 0;
        portals_end_ns[i] = 0;
    }
    portals_sample = 0;
}
#define PORTALS_SAMPLE_INIT     \
do {                            \
    portals_sample_init();      \
} while (0)

#define PORTALS_SAMPLE_FREE     \
do {                            \
    if (portals_start_ns)       \
        free(portals_start_ns); \
    if (portals_end_ns)         \
        free(portals_end_ns);   \
} while (0)

#define PORTALS_SAMPLE_PRINT                                \
do {                                                        \
    int i;                                                  \
    for (i = 0; i < PORTALS_NUM_SAMPLES; i++) {             \
        debug(CCI_DB_WARN, "%4d %6lld",                     \
              i, (unsigned long long) (portals_end_ns[i] - portals_start_ns[i])); \
    }                                                       \
} while (0)

#else /* ENABLE_PORTALS_SAMPLING == 1 */
#define PORTALS_SAMPLE_INIT
#define PORTALS_SAMPLE_START
#define PORTALS_SAMPLE_END
#define PORTALS_SAMPLE_PRINT
#define PORTALS_SAMPLE_FREE
#define PORTALS_IS_SERVER
#endif /* ENABLE_PORTALS_SAMPLING == 1 */
/******* end cycle counting sampling code ****/


/*
 * Local functions
 */
static int portals_init(             uint32_t             abi_ver,
                                     uint32_t             flags,
                                     uint32_t             *caps );
static const char *portals_strerror( enum cci_status      status );
static int portals_get_devices(      cci_device_t const   ***devices );
static int portals_free_devices(     cci_device_t const   **devices );
static int portals_create_endpoint(  cci_device_t         *device,
                                     int                  flags,
                                     cci_endpoint_t       **endpoint,
                                     cci_os_handle_t      *fd );
static int portals_destroy_endpoint( cci_endpoint_t       *endpoint );
static int portals_accept(           union cci_event      *event,
                                     cci_connection_t     **connection );
static int portals_reject(           union cci_event      *event );
static int portals_connect(          cci_endpoint_t       *endpoint,
                                     char                 *server_uri,
                                     void                 *data_ptr,
                                     uint32_t             data_len,
                                     cci_conn_attribute_t attribute,
                                     void                 *context,
                                     int                  flags,
                                     struct timeval       *timeout );
static int portals_disconnect(       cci_connection_t     *connection );
static int portals_set_opt(          cci_opt_handle_t     *handle,
                                     cci_opt_level_t      level,
                                     cci_opt_name_t       name,
                                     const void           *val,
                                     int                  len );
static int portals_get_opt(          cci_opt_handle_t     *handle,
                                     cci_opt_level_t      level,
                                     cci_opt_name_t       name,
                                     void                 **val,
                                     int                  *len );
static int portals_arm_os_handle(    cci_endpoint_t       *endpoint,
                                     int                  flags );
static int portals_get_event(        cci_endpoint_t       *endpoint,
                                     cci_event_t ** const event);
static int portals_return_event(     cci_event_t          *event );
static int portals_send(             cci_connection_t     *connection,
                                     void                 *ptr,
                                     uint32_t             len,
                                     void                 *context,
                                     int                  flags );
static int portals_sendv(            cci_connection_t     *connection,
                                     struct iovec         *data,
                                     uint32_t             iovcnt,
                                     void                 *context,
                                     int                  flags );
static int portals_rma_register(     cci_endpoint_t       *endpoint,
                                     cci_connection_t     *connection,
                                     void                 *start,
                                     uint64_t             length,
                                     uint64_t             *rma_handle );
static int portals_rma_register_phys(cci_endpoint_t       *endpoint,
                                     cci_connection_t     *connection,
                                     cci_sg_t             *sg_list,
                                     uint32_t             sg_cnt,
                                     uint64_t             *rma_handle );
static int portals_rma_deregister(   uint64_t             rma_handle );
static int portals_rma(              cci_connection_t     *connection,
                                     void                 *msg_ptr,
                                     uint32_t             msg_len,
                                     uint64_t             local_handle,
                                     uint64_t             local_offset,
                                     uint64_t             remote_handle,
                                     uint64_t             remote_offset,
                                     uint64_t             data_len,
                                     void                 *context,
                                     int                  flags);

static void *portals_progress_thread(void                 *arg );
static inline void portals_progress_dev(
                                     cci__dev_t *dev);
static void portals_get_event_ep(cci__ep_t *ep);
static void portals_rma_handle_decref(portals_rma_handle_t *handle);


/*
 * Public plugin structure.
 *
 * The name of this structure must be of the following form:
 *
 *    cci_core_<your_plugin_name>_plugin
 *
 * This allows the symbol to be found after the plugin is dynamically
 * opened.
 *
 * Note that your_plugin_name should match the direct name where the
 * plugin resides.
 */
cci_plugin_core_t cci_core_portals_plugin={
    {
        /* Logistics */

        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "portals",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,
        cci_core_portals_post_load, /* Bootstrap function pointers */
        cci_core_portals_pre_unload,
    },

    /* API function pointers */
    portals_init,
    portals_strerror,
    portals_get_devices,
    portals_free_devices,
    portals_create_endpoint,
    portals_destroy_endpoint,
    portals_accept,
    portals_reject,
    portals_connect,
    portals_disconnect,
    portals_set_opt,
    portals_get_opt,
    portals_arm_os_handle,
    portals_get_event,
    portals_return_event,
    portals_send,
    portals_sendv,
    portals_rma_register,
    portals_rma_register_phys,
    portals_rma_deregister,
    portals_rma
};


static int portals_init(
    uint32_t               abi_ver,
    uint32_t               flags,
    uint32_t               *caps ) {

    int                    iRC;
    int                    iMax_devices;
    int                    iReject;
    cci_device_t           **ds;
    cci__dev_t             *dev;
    ptl_interface_t        ifID;
    ptl_ni_limits_t        niLimit;
    ptl_handle_ni_t        niHandle;

    CCI_ENTER;

    PORTALS_SAMPLE_INIT;

/*
 * Step 1.  Extract portals devices from global configuration.
 */
    if( !(pglobals=calloc( 1, sizeof(*pglobals) )) )
        return CCI_ENOMEM;         /* cannot save portals device list */

    if( !(ds=calloc( CCI_MAX_DEVICES, sizeof(*pglobals->devices) )) ) {

        free(pglobals);
        pglobals=NULL;
        return CCI_ENOMEM;         /* cannot save list of devices */
    }

    srandom((unsigned int) portals_get_usecs());

/*
 * Step 2.  Initialize the portals library.
 */
    if( (iRC=PtlInit( &iMax_devices ))!=PTL_OK ) {

        free(ds);
        free(pglobals);
        pglobals=NULL;
        return CCI_ERROR;
    }

/*
 * An interesting feature of portals that a "portals interface" consists
 * of a combination of a bridge and a NAL.  The NAL that you select is
 * dependent on your hardware configuration.  In turn, this (largely)
 * determines the bridge needed.
 *
 * TODO: Add code to support NIC-based portals, kernel-bridge,
 *       GM/Myrnet NAL, and possibly the Catamount semantic.
 */
    ifID=IFACE_FROM_BRIDGE_AND_NALID( PTL_BRIDGE_UK, PTL_IFACE_SS );
/*
 * Step 3.  Initialize the network interface.
 */
    iRC=PtlNIInit( ifID, PTL_PID_ANY, NULL, &niLimit, &niHandle );
    if( iRC!=PTL_OK ) {

        switch(iRC) {
            case PTL_IFACE_DUP:    /* Usually PMI is loaded */
                 iRC=PTL_OK;
                 goto false_alarm;
            case PTL_NO_INIT:      /* Usually dup PtlNIInit() call */
            case PTL_IFACE_INVALID:/* Bad interface options */
                 iRC = CCI_ENODEV;
                 break;
            case PTL_PID_INVALID:  /* This one should not happen */
            case PTL_SEGV:         /* This one should not happen */
                 iRC = CCI_EINVAL;
                 break;
            case PTL_NO_SPACE:     /* Well, well, well */
                 iRC =  CCI_ENOMEM;
                 break;
            default:               /* Undocumented portals error */
                 debug( CCI_DB_WARN, "NI: %s", portals_strerror((enum cci_status)iRC) );
                 iRC = CCI_ERROR;
        }
        goto out_with_init;
    }

    false_alarm:

/*
 * Start searching global configuration for portals devices.
 */
    iReject=1;
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char         **arg;
        cci_device_t       *device;
        portals_dev_t      *pdev;

/*      Reject until portals driver found in configuration. */
        if(strcmp( "portals", dev->driver )) continue;

        iReject=0;                 /* portals configured */
        device=&dev->device;       /* Select device */

        device->max_send_size=PORTALS_DEFAULT_MSS;
        device->rate=46000000000;  /* SeaStar2+, 6 ports, bps */
        device->pci.domain=-1;     /* per CCI spec */
        device->pci.bus=-1;        /* per CCI spec */
        device->pci.dev=-1;        /* per CCI spec */
        device->pci.func=-1;       /* per CCI spec */

        if( !(dev->priv=calloc( 1, sizeof(*pdev) )) ) {

            free(pglobals->devices);
            free(pglobals);
            pglobals=NULL;
            iRC = CCI_ENOMEM;
            goto out_with_ni_init;
        }

        pdev=dev->priv;            /* select private device */

        pdev->is_progressing=0;    /* initialize progress flag */

/*      Save off portals ID of device. */
        pdev->niHandle=niHandle;
        PtlGetId( niHandle, &pdev->idp );
        pdev->max_mes=niLimit.max_mes;
        pdev->max_mds=niLimit.max_mds;
        pdev->max_eqs=niLimit.max_eqs;
        pdev->max_ac_index=niLimit.max_ac_index;
        pdev->max_pt_index=niLimit.max_pt_index;
        pdev->max_md_iovecs=niLimit.max_md_iovecs;
        pdev->max_me_list=niLimit.max_me_list;
        pdev->max_getput_md=niLimit.max_getput_md;
        debug( CCI_DB_INFO, "My portals NID:PID is: %u:%hu",
                 (pdev->idp).nid, (pdev->idp).pid );
        debug( CCI_DB_INFO, "My portals limits are: max_mes=%d",
                 pdev->max_mes );
        debug( CCI_DB_INFO, "                       max_mds=%d",
                 pdev->max_mds );
        debug( CCI_DB_INFO, "                       max_eqs=%d",
                 pdev->max_eqs );
        debug( CCI_DB_INFO, "                       max_ac_index=%d",
                 pdev->max_ac_index );
        debug( CCI_DB_INFO, "                       max_pt_index=%d",
                 pdev->max_pt_index );
        debug( CCI_DB_INFO, "                       max_md_iovecs=%d",
                 pdev->max_md_iovecs );
        debug( CCI_DB_INFO, "                       max_me_list=%d",
                 pdev->max_me_list );
        debug( CCI_DB_INFO, "                       max_getput_md=%d",
                 pdev->max_getput_md );

        /* TODO allocate based on max_pt_index */
        pdev->ep_idxs = calloc(PORTALS_NUM_BLOCKS, sizeof(*pdev->ep_idxs));
        if (!pdev->ep_idxs) {
            free(pglobals->devices);
            free(pglobals);
            pglobals=NULL;
            iRC = CCI_ENOMEM;
            goto out_with_ni_init;
        }
        ds[pglobals->count]=device;
        pglobals->count++;
        dev->is_up=1;
        pdev->min_idx = PORTALS_MIN_INDEX;

        /* parse conf_argv */
        for( arg=device->conf_argv; *arg!=NULL; arg++ ) {

           if(!strncmp( "min_idx=", *arg, 8 )) {

               const char *table = *arg + 8;

               pdev->min_idx= atoi(table);
               if (pdev->min_idx >= pdev->max_pt_index) {
                   debug(CCI_DB_WARN, "requested min_idx (%u) is larger than the "
                                      "max_pt_index (%d)",
                                      pdev->min_idx, pdev->max_pt_index);
                   pdev->min_idx = pdev->max_pt_index - 1;
               }
               debug( CCI_DB_INFO, "setting portals min_idx=%u",
                        pdev->min_idx );
            } else if (0 == strncmp("mss=", *arg, 4)) {
                const char *mss_str = *arg + 4;
                uint32_t mss = strtol(mss_str, NULL, 0);
                if (mss > PORTALS_MAX_MSS)
                    mss = PORTALS_MAX_MSS;
                else if (mss < PORTALS_MIN_MSS)
                    mss = PORTALS_MIN_MSS;

                device->max_send_size = mss;
            }

        }
    }

    if(iReject) {                  /* No portals devices configured */

        free(pglobals->devices);
        free(pglobals);
        pglobals=NULL;
        iRC = CCI_ENODEV;
        goto out_with_ni_init;
    }

/*  Increment list of devices. */
    ds=realloc( ds, (pglobals->count+1)*sizeof(cci_device_t *));
    ds[pglobals->count]=NULL;
    *((cci_device_t ***)&pglobals->devices)=ds;

/*  Try to create progress thread. */
    iRC=pthread_create( &progress_tid, NULL, portals_progress_thread, NULL );
    if(iRC) {                      /* Failed */

        if(ds){                    /* Free private device */

            cci_device_t  *device;

            for (device = ds[0];
             device != NULL;
             device++) {
                dev=container_of( device, cci__dev_t, device );
                if(dev->priv)
                    free(dev->priv);
            }
        }
        free(ds);                  /* Free pointer to private device */

        if(pglobals) {

            free(pglobals->devices);
            free(pglobals);
            pglobals=NULL;
        }

        CCI_EXIT;
        return iRC;
    }

    CCI_EXIT;
    return CCI_SUCCESS;

out_with_ni_init:
    PtlNIFini(niHandle);
out_with_init:
    PtlFini();

    CCI_EXIT;
    return iRC;
}


static const char *portals_strerror(
    enum cci_status        status ) {
    const char             *cp;

    CCI_ENTER;
    cp=ptl_err_str[status];
    CCI_EXIT;

    return cp;
}


static int portals_get_devices(
    cci_device_t const     ***devices ) {

    cci_device_t const     *device;
    cci__dev_t             *dev;
    portals_dev_t          *pdev;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    *devices=pglobals->devices;
    debug( CCI_DB_INFO, "There are %d devices.", pglobals->count );

    device=**devices;
    dev=container_of( device, cci__dev_t, device );
    pdev=dev->priv;

    debug( CCI_DB_INFO, "Got portals ID of: %u:%hu",
             pdev->idp.nid, pdev->idp.pid );

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int portals_free_devices(cci_device_t const **devices )
{
    cci__dev_t  *dev;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    pthread_mutex_lock(&globals->lock);
    portals_shut_down = 1;
    pthread_mutex_unlock(&globals->lock);
    pthread_join(progress_tid, NULL);

    pthread_mutex_lock(&globals->lock);
    TAILQ_FOREACH(dev, &globals->devs, entry) {
        portals_dev_t *pdev = dev->priv;
        if(pdev) {                           // Only for portals device
            PtlNIFini(pdev->niHandle);
            if (pdev->ep_idxs)
                free(pdev->ep_idxs);
            free(dev->priv);
        }
    }
    pthread_mutex_unlock(&globals->lock);
    PtlFini();

    free(pglobals->devices);
    free((void *)pglobals);

    PORTALS_SAMPLE_PRINT;
    PORTALS_SAMPLE_FREE;

    CCI_EXIT;
    return CCI_SUCCESS;
}

/* NOTE never return 0 */
static void portals_get_ep_idx(
    portals_dev_t          *pdev,
    uint32_t               *idx ) {

    uint32_t               block;
    uint32_t               offset;
    uint64_t               *b;
    uint32_t               i;

    for (i = pdev->min_idx; i < pdev->max_pt_index; i++) {

        block=i/PORTALS_BLOCK_SIZE;
        offset=i%PORTALS_BLOCK_SIZE;
        b=&pdev->ep_idxs[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *idx=(block*PORTALS_BLOCK_SIZE)+offset;
            debug(CCI_DB_CONN, "getting EP idx %u block=%"PRIx64"", *idx, *b);
            break;
        }
    }
    return;
}

static void
portals_put_ep_idx(portals_dev_t *pdev, uint32_t idx)
{
    uint32_t block, offset;
    uint64_t *b;

    block = idx / PORTALS_BLOCK_SIZE;
    offset = idx % PORTALS_BLOCK_SIZE;
    b = &pdev->ep_idxs[block];

    debug(CCI_DB_CONN, "putting EP idx %u block=%"PRIx64"", idx, *b);
    assert(((*b >> offset) & 0x1) == 1);
    *b &= ~(1ULL << offset);

    return;
}

/* Free a tx.
 *
 * \param[in] pep   Portals endpoint
 * \param[in] force If force, selct from all txs
 *                  otherwise, only select from idle txs
 *
 * Only use force if closeing the endpoint and we do not
 * casre if the application is holding an event (tx).
 *
 * Caller must be holding ep->lock.
 */
static int
portals_free_tx(portals_ep_t *pep, int force)
{
    portals_tx_t    *tx;

    if (force)
        tx = TAILQ_FIRST(&pep->txs);
    else
        tx = TAILQ_FIRST(&pep->idle_txs);

    if (!tx)
        return 0;

    TAILQ_REMOVE(&pep->txs, tx, tentry);
    TAILQ_REMOVE(&pep->idle_txs, tx, dentry);

    if(tx->buffer)
        free(tx->buffer);
    free(tx);

    return 1;
}

/* Caller must be holding ep->lock */
static int
portals_add_tx(cci__ep_t *ep)
{
    int             ret     = 1;
    ptl_md_t        md;
    portals_ep_t    *pep    = ep->priv;
    portals_tx_t    *tx;
    portals_dev_t   *pdev   = ep->dev->priv;

    tx = calloc(1, sizeof(*tx));
    if(!tx) {
        ret = 0;
        goto out;
    }
    tx->evt.event.type = CCI_EVENT_SEND;
    tx->evt.ep = ep;
    tx->buffer = calloc(1, ep->buffer_len);
    if(!tx->buffer) {
        ret = 0;
        goto out;
    }
    tx->len = 0;

    /*  Create the memory descriptor. */
    md.start = tx->buffer;
    md.length = ep->buffer_len;
    md.threshold = PTL_MD_THRESH_INF;
    md.eq_handle = pep->eqh;
    md.options  = PTL_MD_OP_PUT;
    md.options |= PTL_MD_EVENT_START_DISABLE;
    md.user_ptr = tx;

    ret = PtlMDBind(pdev->niHandle, md, PTL_RETAIN, &tx->mdh);
    if (ret) {                               /* PtlMDBind failed */
        ret = 0;
        goto out;
    }
    ret = 1;

    TAILQ_INSERT_TAIL(&pep->txs, tx, tentry);
    TAILQ_INSERT_TAIL(&pep->idle_txs, tx, dentry);
out:
    if (!ret) {
        if (tx) {
            if (tx->buffer)
                free(tx->buffer);
            free(tx);
        }
    }
    return ret;
}

/* Caller must be holding ep->lock */
static int
portals_add_rx(cci__ep_t *ep)
{
    int             ret     = 1;
    portals_ep_t    *pep    = ep->priv;
    portals_rx_t    *rx;

    rx = calloc(1, sizeof(*rx));
    if(!rx) {
        ret = 0;
        goto out;
    }

    rx->evt.event.type = CCI_EVENT_RECV;
    rx->evt.ep = ep;
    TAILQ_INSERT_TAIL(&pep->rxs, rx, gentry);
    TAILQ_INSERT_TAIL(&pep->idle_rxs, rx, entry);

out:
    return ret;
}

/* Free a rx.
 *
 * \param[in] pep    Portals endpoint
 * \param[in] force If force, selct from all rxs
 *                  otherwise, only select from idle rxs
 *
 * Only use force if closeing the endpoint and we do not
 * casre if the application is holding an event (rx).
 *
 * Caller must be holding ep->lock.
 */
static int
portals_free_rx(portals_ep_t *pep, int force)
{
    portals_rx_t    *rx;

    if (force)
        rx = TAILQ_FIRST(&pep->rxs);
    else
        rx = TAILQ_FIRST(&pep->idle_rxs);

    if (!rx)
        return 0;

    TAILQ_REMOVE(&pep->rxs, rx, gentry);
    TAILQ_REMOVE(&pep->idle_rxs, rx, entry);

    free(rx);
    return 1;
}

static int
portals_post_am_buffer(cci__ep_t *ep, portals_am_buffer_t *am)
{
    int                 ret     = CCI_SUCCESS;
    cci__dev_t          *dev    = ep->dev;
    portals_ep_t        *pep    = ep->priv;
    portals_dev_t       *pdev   = dev->priv;
    ptl_process_id_t    pid_any = PORTALS_WILDCARD;
    ptl_match_bits_t    bits    = 0ULL;
    ptl_match_bits_t    ignore  = 0ULL;

    CCI_ENTER;

    bits = 0ULL;
    ignore = ~(bits);

    ret = PtlMEMDAttach(pdev->niHandle,
                        pep->idx,
                        pid_any,
                        bits,
                        ignore,
                        PTL_UNLINK,
                        PTL_INS_AFTER,
                        am->md,
                        PTL_UNLINK,
                        &(am->meh),
                        &(am->mdh));
    if( ret != PTL_OK ) {
        am->meh = PTL_HANDLE_NONE;
        am->mdh = PTL_HANDLE_NONE;
        switch(ret) {

            case PTL_NO_INIT:           /* Portals library issue */
            case PTL_NI_INVALID:        /* Bad NI Handle */
            case PTL_PT_INDEX_INVALID:  /* Bad table index */
            case PTL_PROCESS_INVALID:
                 ret = CCI_ENODEV;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 ret = CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 ret = CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 debug(CCI_DB_WARN, "PtlMEMDAttach() returned %s", ptl_err_str[ret]);
                 ret = CCI_ERROR;
        }
    } else {
        ret = CCI_SUCCESS;
        am->state = PORTALS_AM_ACTIVE;
    }

    CCI_EXIT;
    return ret;
}

static int
portals_create_am_buffer(cci__ep_t *ep, uint64_t length)
{
    int                 ret     = CCI_SUCCESS;
    portals_ep_t        *pep    = ep->priv;
    portals_am_buffer_t *am     = NULL;

    CCI_ENTER;

    am = calloc(1, sizeof(*am));
    if (!am) {
        ret = CCI_ENOMEM;
        goto out;
    }

    am->buffer = calloc(1, length);
    if (!am->buffer) {
        ret = CCI_ENOMEM;
        goto out;
    }
    debug( CCI_DB_MEM, "Created AM buffer=%p length=%zx",
           am->buffer, (size_t) length );

    am->length = length;
    am->pep = pep;
    am->meh = PTL_HANDLE_NONE;
    am->mdh = PTL_HANDLE_NONE;

    /*  Create the memory descriptor. */
    am->md.start = am->buffer;
    am->md.length = am->length;
    am->md.max_size = ep->buffer_len;
    am->md.user_ptr = am;
    am->md.threshold = PTL_MD_THRESH_INF;
    am->md.eq_handle = pep->eqh;
    am->md.options  = PTL_MD_OP_PUT;
    am->md.options |= PTL_MD_TRUNCATE;
    am->md.options |= PTL_MD_MAX_SIZE;

    ret = portals_post_am_buffer(ep, am);
    if (ret == 0)
        TAILQ_INSERT_TAIL(&pep->ams, am, entry);

out:
    if (ret) {
        if (am) {
            if (am->buffer)
                free(am->buffer);
            free(am);
        }
    }
    CCI_EXIT;
    return ret;
}

/* Caller must be holding ep->lock */
static void portals_free_orphan_ams(portals_ep_t *pep)
{
    int iRC;
    portals_am_buffer_t *am, *tmp;

    TAILQ_FOREACH_SAFE(am, &pep->orphan_ams, entry, tmp) {
        if (am->refcnt > 0)
            continue;

        TAILQ_REMOVE(&pep->orphan_ams, am, entry);
        if (am->buffer) {
            while (am->meh != PTL_HANDLE_NONE) {
                iRC = PtlMEUnlink(am->meh);
                if (iRC == PTL_OK || iRC == PTL_ME_INVALID) {
                    am->meh = PTL_HANDLE_NONE;
                } else {
                    debug(CCI_DB_DRVR, "PtlMEUnlink() returned %s", ptl_err_str[iRC]);
                }
            }
            free(am->buffer);
        }
        free(am);
    }
    return;
}

static int portals_create_endpoint(
    cci_device_t           *device,
    int                    flags,
    cci_endpoint_t         **endpoint,
    cci_os_handle_t        *fd) {

    int                    i;
    int                    iRC;
    int                    token=0;
    cci__dev_t             *dev=NULL;
    cci__ep_t              *ep=NULL;
    portals_ep_t           *pep=NULL;
    portals_dev_t          *pdev=NULL;
    uint32_t               msg_length;
    char                   name[64];

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev=container_of(device, cci__dev_t, device);
    if(strcmp( "portals", dev->driver )) {

        iRC=CCI_EINVAL;
        goto out;
    }
    pdev=dev->priv;

    ep=container_of(*endpoint, cci__ep_t, endpoint);
    ep->priv=calloc(1, sizeof(*pep));
    if(!ep->priv) {

        iRC=CCI_ENOMEM;
        goto out;
    }

    (*endpoint)->max_recv_buffer_count=PORTALS_EP_RX_CNT;
    ep->rx_buf_cnt=PORTALS_EP_RX_CNT;
    ep->tx_buf_cnt=PORTALS_EP_TX_CNT;
    ep->buffer_len=dev->device.max_send_size;
    ep->tx_timeout=0;

    pep=ep->priv;

    TAILQ_INIT(&pep->txs);
    TAILQ_INIT(&pep->idle_txs);
    TAILQ_INIT(&pep->rxs);
    TAILQ_INIT(&pep->idle_rxs);
    TAILQ_INIT(&pep->ams);
    TAILQ_INIT(&pep->orphan_ams);
    TAILQ_INIT(&pep->conns);
    TAILQ_INIT(&pep->handles);
    TAILQ_INIT(&pep->rma_ops);

    /* to avoid potential races with the progress thread, set the dev
     * as progressing until we are done. */
    do {
        pthread_mutex_lock(&dev->lock);
        if( pdev->is_progressing==0) {
            pdev->is_progressing=1;
            token=1;
            /* get endpoint id */
            portals_get_ep_idx(pdev, &pep->idx);
        }
        pthread_mutex_unlock(&dev->lock);
    } while (!token);

    debug(CCI_DB_CONN, "%s: idx=%u", __func__, pep->idx);

    /* create event queue for endpoint */
    iRC=PtlEQAlloc( pdev->niHandle,
                    (PORTALS_EP_RX_CNT + PORTALS_EP_TX_CNT) * 4,
                    PTL_EQ_HANDLER_NONE,
                    &(pep->eqh) );
    if( iRC!=PTL_OK ) {

        pep->eqh = PTL_EQ_NONE;
        switch(iRC) {

            case PTL_NO_INIT:      /* Portals library issue */
            case PTL_NI_INVALID:   /* Bad NI Handle */
                 iRC = CCI_ENODEV;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 iRC = CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 iRC = CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 iRC = CCI_ERROR;
        }
        goto out;
    }

    for( i=0; i<ep->tx_buf_cnt; i++ ) {
        iRC = portals_add_tx(ep);
        if (iRC != 1) {
            iRC = CCI_ENOMEM;
            goto out;
        }
    }

    /* Creating receive buffers/MDs/MEs. */
    msg_length = ep->rx_buf_cnt * ep->buffer_len / 2;
    for (i = 0; i < 2; i++) {
        iRC = portals_create_am_buffer(ep, msg_length);
        if (iRC)
            goto out;
    }

    for( i=0; i<ep->rx_buf_cnt; i++ ) {
        iRC = portals_add_rx(ep);
        if (iRC != 1) {
            iRC = CCI_ENOMEM;
            goto out;
        }
    }

    memset(name, 0, sizeof(name));
    snprintf(name, 64, "%s%u:%hu:%u", PORTALS_URI, pdev->idp.nid, pdev->idp.pid, pep->idx);
    *((char **)(&(*endpoint)->name)) = strdup(name);
    if (!(*endpoint)->name) {
        iRC = CCI_ENOMEM;
        goto out;
    }

    debug(CCI_DB_EP, "opening %s", (*endpoint)->name);

    pthread_mutex_lock(&dev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&dev->lock);

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    pthread_mutex_lock(&dev->lock);
    if (token)
        pdev->is_progressing=0;
    TAILQ_REMOVE( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);

    if(pep) {

        if (pep->idx)
            portals_put_ep_idx(pdev, pep->idx);

        if (pep->eqh != PTL_EQ_NONE)
            PtlEQFree(pep->eqh);

        while (!TAILQ_EMPTY(&pep->ams)) {
            portals_am_buffer_t *am = TAILQ_FIRST(&pep->ams);
            TAILQ_REMOVE(&pep->ams, am, entry);
            if (am->buffer) {
                if (am->state == PORTALS_AM_ACTIVE) {
                    iRC = PtlMEUnlink(am->meh);
                    if (iRC != PTL_OK)
                        debug(CCI_DB_DRVR, "PtlMEUnlink() returned %s", ptl_err_str[iRC]);
                }
                free(am->buffer);
            }
            free(am);
        }

        portals_free_orphan_ams(pep);

        while(!TAILQ_EMPTY(&pep->txs))
            portals_free_tx(pep, 1);

        while(!TAILQ_EMPTY(&pep->rxs))
            portals_free_rx(pep, 1);

        free(pep);
    }

    if(ep)
        free(ep);
    *endpoint=NULL;

    CCI_EXIT;
    return iRC;
}


static int portals_destroy_endpoint(cci_endpoint_t *endpoint)
{
    cci__ep_t       *ep     = NULL;
    cci__dev_t      *dev    = NULL;
    portals_ep_t    *pep    = NULL;
    portals_dev_t   *pdev   = NULL;
    int             iRC;
    int             token   = 0;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    dev = ep->dev;
    pep = ep->priv;
    pdev = dev->priv;

    do {
        pthread_mutex_lock(&ep->lock);
        if (!pep->in_use) {
            pep->in_use = 1;
            token = 1;
        }
        pthread_mutex_unlock(&ep->lock);
    } while (!token);

    pthread_mutex_lock(&dev->lock);
    pthread_mutex_lock(&ep->lock);

    ep->priv = NULL;

    if (pep) {
        if (pep->idx)
            portals_put_ep_idx(pdev, pep->idx);

        if (pep->eqh != PTL_EQ_NONE) {
            iRC = PtlEQFree(pep->eqh);
            if (iRC != PTL_OK)
                debug(CCI_DB_DRVR, "PtlEQFree() returned %s", ptl_err_str[iRC]);
        }

        while (!TAILQ_EMPTY(&pep->ams)) {
            portals_am_buffer_t *am = TAILQ_FIRST(&pep->ams);
            TAILQ_REMOVE(&pep->ams, am, entry);
            if (am->buffer) {
                if (am->state == PORTALS_AM_ACTIVE) {
                    while (am->meh != PTL_HANDLE_NONE) {
                        iRC = PtlMEUnlink(am->meh);
                        if (iRC == PTL_OK || iRC == PTL_ME_INVALID) {
                            am->meh = PTL_HANDLE_NONE;
                        } else {
                            debug(CCI_DB_DRVR, "PtlMEUnlink() returned %s", ptl_err_str[iRC]);
                        }
                    }
                }
                debug( CCI_DB_MEM, "Free AM buffer=%p", am->buffer );
                free(am->buffer);
                am->buffer=NULL;
            }
            free(am);
        }

        portals_free_orphan_ams(pep);

        while(!TAILQ_EMPTY(&pep->conns)) {
            cci__conn_t     *conn;
            portals_conn_t  *pconn;

            pconn=TAILQ_FIRST(&pep->conns);
            TAILQ_REMOVE(&pep->conns, pconn, entry);
            conn = pconn->conn;
            free(pconn);
            free(conn);
        }

        while(!TAILQ_EMPTY(&pep->txs))
            portals_free_tx(pep, 1);

        while(!TAILQ_EMPTY(&pep->rxs))
            portals_free_rx(pep, 1);

        free(pep);
    }
    pthread_mutex_unlock(&ep->lock);
    pthread_mutex_unlock(&dev->lock);

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int portals_accept(
    union cci_event        *event,
    cci_connection_t       **connection ) {

    int             ret;
    cci__ep_t       *ep     = NULL;
    cci__dev_t      *dev    = NULL;
    cci__evt_t      *evt    = NULL;
    cci__conn_t     *conn   = NULL;
    portals_ep_t    *pep    = NULL;
    portals_dev_t   *pdev   = NULL;
    portals_conn_t  *pconn  = NULL;
    portals_conn_request_t *request = NULL;
    portals_conn_accept_t accept;
    cci_endpoint_t  *endpoint = NULL;
    uint64_t        bits;
    int             ac_len  = sizeof(accept);
    portals_rx_t    *rx     = NULL;
    portals_tx_t    *tx     = NULL;

    CCI_ENTER;

    if(!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    evt = container_of(event, cci__evt_t, event);
    rx = container_of(evt, portals_rx_t, evt);
    ep = evt->ep;
    endpoint = &ep->endpoint;
    pep = ep->priv;
    dev = ep->dev;
    pdev = dev->priv;

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        ret = CCI_ENOMEM;
        goto out_with_rx;
    }

    conn->tx_timeout = ep->tx_timeout;
    conn->priv = calloc(1, sizeof(*pconn));
    if (!conn->priv) {
        ret = CCI_ENOMEM;
        goto out_with_conn;
    }
    pconn = conn->priv;
    pconn->conn = conn;

    request = (portals_conn_request_t *) (rx->pevent.md.start + rx->pevent.offset);

    /* prepare accept msg */

    accept.max_send_size = request->max_send_size;
    accept.max_recv_buffer_count = request->max_recv_buffer_count;
    accept.server_conn_upper = (uint32_t)((uintptr_t)conn >> 32);
    accept.server_conn_lower = (uint32_t)((uintptr_t)conn & 0xFFFFFFFF);

    debug(CCI_DB_CONN, "accept.max_send_size = %u", accept.max_send_size);
    debug(CCI_DB_CONN, "accept.max_recv_buffer_count = %u", accept.max_recv_buffer_count);
    debug(CCI_DB_CONN, "accept.server_conn_upper = 0x%x", accept.server_conn_upper);
    debug(CCI_DB_CONN, "accept.server_conn_lower = 0x%x", accept.server_conn_lower);

    /* setup connection */

    conn->connection.attribute = event->request.attribute;
    conn->connection.endpoint = endpoint;
    conn->connection.max_send_size = dev->device.max_send_size;

    pconn->idp = rx->pevent.initiator;
    pconn->idx = request->client_ep_idx;
    pconn->peer_conn = rx->pevent.hdr_data;
    pconn->mss = request->max_send_size;
    pconn->max_tx_cnt = request->max_recv_buffer_count;

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&pep->conns, pconn, entry);
    pthread_mutex_unlock(&ep->lock);

    bits  = ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REPLY) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_txs)) {
        tx=TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE( &pep->idle_txs, tx, dentry );
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        ret = CCI_ENOBUFS;
        goto out_with_queued;
    }

    /* prep the tx */
    tx->msg_type=PORTALS_MSG_OOB;
    tx->oob_type=PORTALS_MSG_OOB_CONN_REPLY;

    tx->evt.ep=ep;
    tx->evt.conn=conn;
    tx->evt.event.type=CCI_EVENT_SEND;
    memcpy(tx->buffer, &accept, ac_len);

    debug(CCI_DB_CONN, "%s: to %u:%hu:%u peer_conn=%llx",
          __func__, pconn->idp.nid, pconn->idp.pid, pconn->idx,
          (unsigned long long) pconn->peer_conn);
    ret = PtlPutRegion(tx->mdh,           /* Handle to MD */
                 0,
                 ac_len,
                 PTL_NOACK_REQ,     /* ACK disposition */
                 pconn->idp,        /* target port */
                 pconn->idx,        /* table entry to use */
                 0,                 /* access entry to use */
                 bits,              /* match bits */
                 0,                 /* remote offset */
                 (uintptr_t) pconn->peer_conn); /* hdr_data */
    if (ret != PTL_OK) {
        switch (ret) {
            case PTL_NO_INIT:
                ret = CCI_ENODEV;
                break;
            case PTL_MD_INVALID:
            case PTL_MD_ILLEGAL:
            default:
                ret = CCI_ERROR;
                break;
            case PTL_PROCESS_INVALID:
                ret = CCI_EADDRNOTAVAIL;
                break;
        }
        goto out_with_queued;
    }

    *connection = &conn->connection;

    CCI_EXIT;
    return CCI_SUCCESS;

out_with_queued:
    pthread_mutex_lock(&ep->lock);
    TAILQ_REMOVE(&pep->conns, pconn, entry);
    pthread_mutex_unlock(&ep->lock);
    free(pconn);
out_with_conn:
    free(conn);
out_with_rx:
    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_HEAD(&pep->idle_rxs, rx, entry);
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return ret;
}


static int portals_reject(union cci_event *event)
{
    int             ret     = CCI_SUCCESS;
    cci__ep_t       *ep     = NULL;
    cci__dev_t      *dev    = NULL;
    cci__evt_t      *evt    = NULL;
    portals_ep_t    *pep    = NULL;
    portals_dev_t   *pdev   = NULL;
    cci_endpoint_t  *endpoint = NULL;
    portals_conn_request_t *request = NULL;
    uint64_t        bits    = 0ULL;
    ptl_md_t        md;
    ptl_handle_md_t mdh;
    portals_rx_t    *rx     = NULL;
    uint32_t        idx     = 0;

    CCI_ENTER;

    if(!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    evt = container_of(event, cci__evt_t, event);
    rx = container_of(evt, portals_rx_t, evt);
    ep = evt->ep;
    endpoint = &ep->endpoint;
    pep = ep->priv;
    dev = ep->dev;
    pdev = dev->priv;

    idx = (uint32_t) (rx->pevent.match_bits >> 32);
    request = (portals_conn_request_t *) (rx->pevent.md.start + rx->pevent.offset);

    bits  = ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REPLY) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    memset(&md, 0, sizeof(md));
    md.threshold = 1;
    md.eq_handle = PTL_EQ_NONE;
    md.options = PTL_MD_OP_PUT;
    md.options |= PTL_MD_EVENT_START_DISABLE;

    ret = PtlMDBind(pdev->niHandle, md, PTL_UNLINK, &mdh);
    if (ret != PTL_OK) {
        switch (ret) {
            case PTL_NO_INIT:
            case PTL_NI_INVALID:
                ret = CCI_ENODEV;
                break;
            case PTL_NO_SPACE:
                ret = CCI_ENOMEM;
                break;
            default:
                ret = CCI_ERROR;
                break;
        }
        goto cleanup;
    }

    ret = PtlPut(mdh,
                 PTL_NOACK_REQ,
                 rx->pevent.initiator,
                 idx,
                 0,
                 bits,
                 0,
                 (uintptr_t) rx->pevent.hdr_data);
    if (ret != PTL_OK) {
        switch (ret) {
            case PTL_NO_INIT:
                ret = CCI_ENODEV;
                break;
            case PTL_PROCESS_INVALID:
                ret = CCI_EADDRNOTAVAIL;
                break;
            default:
                ret = CCI_ERROR;
                break;
        }
    }

cleanup:
    CCI_EXIT;
    return ret;
}


/* Extract the portals ID from the URI. */
static int portals_getaddrinfo(
    const char             *uri,
    ptl_process_id_t       *idp,
    uint32_t               *idx ) {

    CCI_ENTER;
    char                   *addr;
    char                   *cp;
    char                   *pid;
    int                    len = 0;

    len = strlen(PORTALS_URI);

    if(!strncmp( PORTALS_URI, uri, len )) {  /* URI to portals ID */

        addr=strdup(&uri[len]);              /* ASCII NID:PID:IDX */
        cp=strchr( addr, ':' );              /* NID:PID delimiter address */
        if(cp)
            *cp='\0';                        /* local overwrite only */
        else {
            debug(CCI_DB_INFO, "%s: cannot parse %s - no NID:PID colon", __func__, uri);
            free(addr);
            return CCI_EINVAL;
        }

        cp++;
        pid = cp;
        cp=strchr( pid, ':' );               /* PID:IDX delimiter address */
        if(cp)
            *cp='\0';                        /* local overwrite only */
        else {
            debug(CCI_DB_INFO, "%s: cannot parse %s - no PID:IDX colon", __func__, uri);
            free(addr);
            return CCI_EINVAL;
        }

        cp++;
        idp->nid=atoi(addr);                 /* ASCII to portals ID */
        idp->pid=atoi(pid);
        *idx=atoi(cp);
        free(addr);
    } else {                                 /* something else */

        debug(CCI_DB_INFO, "%s: cannot parse %s (base %s len %d)", __func__, uri, PORTALS_URI, len);
        CCI_EXIT;
        return CCI_EINVAL;
    }

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int portals_connect(
    cci_endpoint_t         *endpoint,
    char                   *server_uri,
    void                   *data_ptr,
    uint32_t               data_len,
    cci_conn_attribute_t   attribute,
    void                   *context,
    int                    flags,
    struct timeval         *timeout ) {

    int                    iRC;
    cci__ep_t              *ep=NULL;
    cci__dev_t             *dev=NULL;
    cci__conn_t            *conn=NULL;
    portals_ep_t           *pep=NULL;
    portals_dev_t          *pdev=NULL;
    cci_connection_t       *connection=NULL;
    portals_conn_t         *pconn=NULL;
    portals_tx_t           *tx=NULL;
    cci__evt_t             *evt=NULL;
    cci_event_t            *event=NULL;
    ptl_process_id_t       idp;
    uint32_t               idx;
    portals_conn_request_t conn_request;
    ptl_match_bits_t       bits = 0ULL;
    int                    cr_len = sizeof(conn_request);

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    /* allocate a new connection */
    conn=calloc( 1, sizeof(*conn) );
    if (!conn) {

        CCI_EXIT;
        return CCI_ENOMEM;
    }

    conn->priv=calloc( 1, sizeof(*pconn) );
    if(!conn->priv) {

        iRC=CCI_ENOMEM;
        goto out;
    }

    pconn=conn->priv;
    pconn->conn=conn;

    /* conn->tx_timeout=0  by default */
    connection=&conn->connection;
    connection->attribute=attribute;
    connection->endpoint=endpoint;

    memset(&idp, 0, sizeof(idp)); /* satisfy -Wall -Werror */
    iRC=portals_getaddrinfo( server_uri, &idp, &idx );
    if(iRC)
        goto out;

   /* peer will assign id */

    /* get our endpoint and device */
    ep=container_of( endpoint, cci__ep_t, endpoint );
    pep=ep->priv;
    dev=ep->dev;
    pdev=dev->priv;

    connection->max_send_size=dev->device.max_send_size;
    pconn->idp=idp;
    pconn->idx=idx;

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_txs)) {
        tx=TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE( &pep->idle_txs, tx, dentry );
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        iRC = CCI_ENOBUFS;
        goto out;
    }

    /* prep the tx */
    tx->msg_type=PORTALS_MSG_OOB;
    tx->oob_type=PORTALS_MSG_OOB_CONN_REQUEST;
    pconn->tx = tx; /* we need its event for the accept|reject */

    evt=&tx->evt;
    evt->ep=ep;
    evt->conn=conn;
    event=&evt->event;
    event->type=CCI_EVENT_CONNECT_ACCEPTED; /* for now */
    event->accepted.context=context;
    event->accepted.connection=connection;

    /* pack the bits */
    bits  = ((ptl_match_bits_t) (data_len & 0xFFFF)) << 16;
    bits |= ((ptl_match_bits_t) attribute) << 8;
    bits |= ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REQUEST) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* pack the payload */
    conn_request.max_send_size = connection->max_send_size;
    conn_request.max_recv_buffer_count = endpoint->max_recv_buffer_count;
    conn_request.client_ep_idx = pep->idx;

    memcpy(tx->buffer, &conn_request, cr_len);
    if (data_len)
        memcpy(tx->buffer + cr_len, data_ptr, data_len);

    debug(CCI_DB_CONN, "%s: to "PORTALS_URI"%u:%hu:%u conn=%p",
          __func__, pconn->idp.nid, pconn->idp.pid, pconn->idx, conn);
    iRC = PtlPutRegion(tx->mdh,           /* Handle to MD */
                       0,                 /* offset */
                       cr_len + data_len, /* payload len */
                       PTL_NOACK_REQ,     /* ACK disposition */
                       pconn->idp,        /* target port */
                       pconn->idx,        /* table entry to use */
                       0,                 /* access entry to use */
                       bits,              /* match bits */
                       0,                 /* remote offset */
                       (uintptr_t) conn); /* hdr_data */
    if (iRC != PTL_OK) {
        switch (iRC) {
            case PTL_NO_INIT:
                iRC = CCI_ENODEV;
                break;
            case PTL_MD_INVALID:
            case PTL_MD_ILLEGAL:
            default:
                iRC = CCI_ERROR;
                break;
            case PTL_PROCESS_INVALID:
                iRC = CCI_EADDRNOTAVAIL;
                break;
        }
        goto out;
    }


    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if(conn) {
        if(conn->uri)
            free((char *)conn->uri);
        if(conn->priv)
            free(conn->priv);
        free(conn);
    }
    CCI_EXIT;
    return iRC;
}


static int portals_disconnect(cci_connection_t *connection)
{
    cci__conn_t     *conn   = NULL;
    cci__ep_t       *ep     = NULL;
    portals_conn_t  *pconn  = NULL;
    portals_ep_t    *pep    = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    conn = container_of(connection, cci__conn_t, connection);
    pconn = conn->priv;
    ep = container_of(connection->endpoint, cci__ep_t, endpoint);
    pep = ep->priv;

    if (conn->uri)
        free((char *) conn->uri);

    pthread_mutex_lock(&ep->lock);
    TAILQ_REMOVE(&pep->conns, pconn, entry);
    pthread_mutex_unlock(&ep->lock);

    free(pconn);
    free(conn);

    CCI_EXIT;
    return CCI_SUCCESS;
}

/* Caller must be holding ep->lock
 *
 * When reducing the number of txs, we try to free
 * (current - new_count) txs. If the txs are in use and
 * not enough are in the idle txs list, we will report
 * success. In this case, we will set the ep->tx_buf_cnt
 * to the number left which might be higher than new_count.
 */
static int
portals_set_ep_tx_buf_cnt(cci__ep_t *ep, uint32_t new_count)
{
    int             i;
    uint32_t        current = ep->tx_buf_cnt;
    portals_ep_t    *pep    = ep->priv;

    if (ep->closing)
        return CCI_SUCCESS;

    if (new_count == 0)
        return CCI_EINVAL;

    if (new_count == current)
        return CCI_SUCCESS;

    if (new_count < current) {
        /* reduce txs */
        for (i = 0; i < (current - new_count); i++)
            ep->tx_buf_cnt -= portals_free_tx(pep, 0);
    } else {
        /* add txs */
        for (i = 0; i < (new_count - current); i++)
            ep->tx_buf_cnt += portals_add_tx(ep);
    }
    return CCI_SUCCESS;
}

/* Caller must be holding ep->lock */
static int
portals_orphan_am_buffer(cci__ep_t *ep, portals_am_buffer_t *am)
{
    int             ret     = PTL_OK;
    portals_ep_t    *pep    = ep->priv;

    CCI_ENTER;

    assert(am->state != PORTALS_AM_DONE);

    /* remove from AM list */
    TAILQ_REMOVE(&pep->ams, am, entry);

    /* if ACTIVE, unlink */
    if (am->state == PORTALS_AM_ACTIVE) {
        if (am->meh != PTL_HANDLE_NONE) {
            ret = PtlMEUnlink(am->meh);
            if (ret == PTL_OK || ret == PTL_ME_INVALID) {
                am->meh = PTL_HANDLE_NONE;
            }
        }
    } else {
        am->meh = PTL_HANDLE_NONE;
    }
    /* we no longer need the mdh */
    am->mdh = PTL_HANDLE_NONE;

    /* set state to DONE */
    am->state = PORTALS_AM_DONE;

    /* if refcnt == 0 and unlinked, free it */
    if (am->refcnt == 0) {
        if (am->meh == PTL_HANDLE_NONE) {
            free(am->buffer);
            free(am);
            goto out;
        }
    }

    /* add to orphan AM list */
    TAILQ_INSERT_TAIL(&pep->orphan_ams, am, entry);

out:
    CCI_EXIT;
    return CCI_SUCCESS;
}

/* Caller must be holding ep->lock
 *
 * Before changing the number of rxs, we first create
 * two new AM buffers. If we can't, we return error.
 * If we can, we then try to free the existing AM
 * buffers. If they are busy (refcnt != 0) or unlinking
 * fails, we will orphan them. In this case, the memory
 * used will be temporarily the size of the old buffers
 * plus the size of the new buffers. Once the events for
 * the old buffers are returned, we will free the old
 * buffers.
 *
 * When reducing the number of rxs, we try to free
 * (current - new_count) rxs. If the rxs are in use and
 * not enough are in the idle rxs list, we will report
 * success. In this case, we will set the ep->rx_buf_cnt
 * to the number left which might be higher than new_count.
 */
static int
portals_set_ep_rx_buf_cnt(cci__ep_t *ep, uint32_t new_count)
{
    int             ret     = CCI_SUCCESS;
    int             i;
    uint32_t        current = ep->rx_buf_cnt;
    uint64_t        length  = (uint64_t) new_count * (uint64_t) ep->buffer_len;
    portals_ep_t    *pep    = ep->priv;

    CCI_ENTER;

    if (ep->closing) {
        ret = CCI_SUCCESS;
        goto out;
    }

    if (new_count == 0) {
        ret = CCI_EINVAL;
        goto out;
    }

    if (new_count == current) {
        ret = CCI_SUCCESS;
        goto out;
    }

    /* create new AM buffers */
    length /= 2;
    for (i = 0; i < 2; i++) {
        ret = portals_create_am_buffer(ep, length);
        if (ret)
            goto out;
    }
    /* free or orphan the old buffers */
    for (i = 0; i < 2; i++) {
        portals_am_buffer_t *am = TAILQ_FIRST(&pep->ams);
        if (am)
            portals_orphan_am_buffer(ep, am);
    }

    /* adjust rxs */
    if (new_count < current) {
        /* reduce rxs */
        for (i = 0; i < (current - new_count); i++)
            ep->rx_buf_cnt -= portals_free_rx(pep, 0);
    } else {
        /* add rxs */
        for (i = 0; i < (new_count - current); i++)
            ep->rx_buf_cnt += portals_add_rx(ep);
    }

out:
    CCI_EXIT;
    return ret;
}

static int portals_set_opt(cci_opt_handle_t *handle,
                           cci_opt_level_t level,
                           cci_opt_name_t name,
                           const void *val,
                           int len )
{
    int             ret     = CCI_SUCCESS;
    cci__ep_t       *ep     = NULL;
    cci__conn_t     *conn   = NULL;
    portals_ep_t    *pep    = NULL;
    portals_conn_t  *pconn  = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    if (CCI_OPT_LEVEL_ENDPOINT == level) {
        ep = container_of(handle->endpoint, cci__ep_t, endpoint);
        pep = ep->priv;
    } else {
        conn = container_of(handle->connection, cci__conn_t, connection);
        pconn = conn->priv;
    }

    switch (name) {
    case CCI_OPT_ENDPT_SEND_TIMEOUT:
        ret = CCI_ERR_NOT_IMPLEMENTED; /* not supported */
        break;
    case CCI_OPT_ENDPT_RECV_BUF_COUNT:
    {
        uint32_t new_count;

        if (len != sizeof(new_count)) {
            ret = CCI_EINVAL;
            break;
        }
        memcpy(&new_count, val, len);
        pthread_mutex_lock(&ep->lock);
        ret = portals_set_ep_rx_buf_cnt(ep, new_count);
        pthread_mutex_unlock(&ep->lock);
        break;
    }
    case CCI_OPT_ENDPT_SEND_BUF_COUNT:
    {
        uint32_t new_count;

        if (len != sizeof(new_count)) {
            ret = CCI_EINVAL;
            break;
        }
        memcpy(&new_count, val, len);
        pthread_mutex_lock(&ep->lock);
        ret = portals_set_ep_tx_buf_cnt(ep, new_count);
        pthread_mutex_unlock(&ep->lock);
        break;
    }
    case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
        assert(len == sizeof(ep->keepalive_timeout));
        memcpy(&ep->keepalive_timeout, val, len);
        break;
    case CCI_OPT_CONN_SEND_TIMEOUT:
        ret = CCI_ERR_NOT_IMPLEMENTED; /* not supported */
        break;
    default:
        debug(CCI_DB_INFO, "unknown option %u", (enum cci_opt_name)name);
        ret = CCI_EINVAL;
    }

    CCI_EXIT;

    return ret;
}


static int portals_get_opt(
    cci_opt_handle_t       *handle,
    cci_opt_level_t        level,
    cci_opt_name_t         name,
    void                   **val,
    int                    *len ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_EINVAL;
}


// Todo
static int portals_arm_os_handle(
    cci_endpoint_t         *endpoint,
    int                    flags ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_get_event(cci_endpoint_t *endpoint,
                             cci_event_t **const event)
{
    int             ret = CCI_SUCCESS;
    cci__ep_t       *ep;
    cci__evt_t      *ev = NULL, *e;
    cci__dev_t      *dev;
    portals_ep_t    *pep;

    //CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    dev = ep->dev;

    portals_get_event_ep(ep);

    pthread_mutex_lock(&ep->lock);

    /* give the user the first event */
    TAILQ_FOREACH(e, &ep->evts, entry) {
        if (e->event.type == CCI_EVENT_SEND) {
            if (e->priv) {
                portals_rma_op_t *rma_op = e->priv;
                if (rma_op->flags & CCI_FLAG_BLOCKING) {
                    continue;
                } else {
                    ev = e;
                    break;
                }
            } else {
                /* NOTE: if it is blocking, skip it since portals_send()
                 * is waiting on it
                 */
                portals_tx_t *tx = container_of(e, portals_tx_t, evt);
                if (tx->flags & CCI_FLAG_BLOCKING) {
                    continue;
                } else {
                    ev = e;
                    break;
                }
            }
        } else {
            ev = e;
            break;
        }
    }

    if (ev)
        TAILQ_REMOVE(&ep->evts, ev, entry);
    else
        ret = CCI_EAGAIN;

    pthread_mutex_unlock(&ep->lock);

    /* TODO drain fd so that they can block again */

    *event = &ev->event;

    //CCI_EXIT;

    return ret;
}


static int portals_return_event( cci_event_t *event )
{
    int                 iRC     = CCI_SUCCESS;
    cci__ep_t           *ep     = NULL;
    portals_ep_t        *pep    = NULL;
    cci__evt_t          *evt    = NULL;
    portals_tx_t        *tx     = NULL;
    portals_rx_t        *rx     = NULL;
    portals_rma_op_t    *rma_op = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    evt = container_of(event, cci__evt_t, event);

    ep = evt->ep;
    pep = ep->priv;

    /* enqueue the event */

    switch (event->type) {
    case CCI_EVENT_SEND:
        if (evt->priv) {
            portals_conn_t *pconn = NULL;
            portals_rma_handle_t *local;

            /* we are done, cleanup */
            rma_op = evt->priv;
            local = (void *) rma_op->local_handle;
            pconn = evt->conn->priv;

            pthread_mutex_lock(&ep->lock);
            TAILQ_REMOVE(&pep->rma_ops, rma_op, entry);
            portals_rma_handle_decref(local);
            pthread_mutex_unlock(&ep->lock);
            free(rma_op);
        } else {
            tx = container_of(evt, portals_tx_t, evt);
            pthread_mutex_lock(&ep->lock);
            /* insert at head to keep it in cache */
            TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
            pthread_mutex_unlock(&ep->lock);
        }
        break;
    case CCI_EVENT_CONNECT_REQUEST:
    case CCI_EVENT_CONNECT_ACCEPTED:
    case CCI_EVENT_CONNECT_REJECTED:
    case CCI_EVENT_RECV:
    {
        portals_am_buffer_t *am;

        rx = container_of(evt, portals_rx_t, evt);
        am = rx->am;

        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_HEAD(&pep->idle_rxs, rx, entry);
        am->refcnt--;
        if (am->refcnt == 0 && am->state == PORTALS_AM_INACTIVE) {
            iRC = portals_post_am_buffer(ep, am);
            if (iRC) {
                debug(CCI_DB_WARN, "%s: post_am_buffer() returned %s",
                      __func__, cci_strerror((enum cci_status)iRC));
            }
        }
        pthread_mutex_unlock(&ep->lock);
        break;
    }
    default:
        /* TODO */
        break;
    }

    CCI_EXIT;

    return iRC;
}


/* Portals assumes reliability (retransmission) so we do not have to.
 * A put generates up to four events on the initiator:
 *   send_start, send_end, ack, and unlink.
 *
 * We always buffer (we ignore CCI_FLAG_NO_COPY) to avoid having to
 * re-bind the TX buffer.
 *
 * For all connections, we have disabled send_start.
 *
 * For unreliable connections, we do not request an ack. We need send_end to
 * generate the CCI_EVENT_SEND or, if CCI_FLAG_SILENT is set, to return it to
 * idle_txs.
 *
 * For reliable connections, we ignore send_end, and we request an ack, which
 * will trigger our CCI event.
 */
static int portals_send_common(
    cci_connection_t       *connection,
    struct iovec           *data,
    uint32_t               iovcnt,
    void                   *context,
    int                    flags,
    portals_rma_op_t       *rma_op ) {

    int                    i            = 0;
    int                    ret          = CCI_SUCCESS;
    int                    is_reliable  = 0;
    uint32_t               data_len     = 0;
    cci_endpoint_t         *endpoint    = connection->endpoint;
    cci__conn_t            *conn        = NULL;
    cci__ep_t              *ep          = NULL;
    cci__dev_t             *dev         = NULL;
    portals_conn_t         *pconn       = NULL;
    portals_ep_t           *pep         = NULL;
    portals_dev_t          *pdev        = NULL;
    portals_tx_t           *tx          = NULL;
    ptl_match_bits_t       bits         = 0ULL;
    ptl_ack_req_t          ack          = PTL_ACK_REQ;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    for (i = 0; i < iovcnt; i++)
        data_len += (uint32_t) data[i].iov_len;

    if (data_len > connection->max_send_size) {
        CCI_EXIT;
        return CCI_EMSGSIZE;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    conn=container_of( connection, cci__conn_t, connection );
    pconn = conn->priv;
    dev = ep->dev;
    pdev = dev->priv;

    is_reliable = cci_conn_is_reliable(conn);

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if (!TAILQ_EMPTY(&pep->idle_txs)) {
        tx = TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE(&pep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&ep->lock);

    if (!tx) {
        debug(CCI_DB_WARN, "%s: no txs", __func__);
        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    /* tx bookkeeping */
    tx->msg_type = PORTALS_MSG_SEND;
    tx->flags = flags;
    tx->rma_op = NULL; /* only set if RMA completion msg */

    /* setup generic CCI event */
    tx->evt.conn = conn;
    tx->evt.ep = ep;
    tx->evt.event.type = CCI_EVENT_SEND;
    tx->evt.event.send.connection = connection;
    tx->evt.event.send.context = context;
    tx->evt.event.send.status = CCI_SUCCESS; /* for now */

    /* pack match bits */
    bits  = ((ptl_match_bits_t) data_len) << 11;
    bits |= (ptl_match_bits_t) PORTALS_MSG_SEND;

    if (is_reliable) {
        /* set the Reliable flag which tells us to ignore the SEND_END
         * and to wait for the ACK */
        bits |= (ptl_match_bits_t) 0x4;
    } else {
        /* we need to know when we can reuse the tx
         * leave SEND_END enabled, but suppress the the ack */
        ack = PTL_NOACK_REQ;
    }

    /* always copy into tx's attached buffer */
    if (data_len) {
        uint32_t offset = 0;

        for (i = 0; i < iovcnt; i++) {
            memcpy(tx->buffer + offset, data[i].iov_base, data[i].iov_len);
            offset += data[i].iov_len;
        }
    }
    tx->len = data_len;

#ifdef    PORTALS_8B_OOB
    if( data_len < 9 ) {                       /* Send up to 8B OOB */
        ptl_hdr_data_t *hdr_data=(ptl_hdr_data_t *)tx->buffer;

        ret = PtlPutRegion(tx->mdh,            /* Handle to MD */
                       0,                      /* local offset */
                       0,                      /* length */
                       ack,                    /* ACK disposition */
                       pconn->idp,             /* target port */
                       pconn->idx,             /* table entry to use */
                       0,                      /* access entry to use */
                       bits,                   /* match bits */
                       0,                      /* remote offset */
                       *hdr_data );            /* hdr_data */
    } else
#endif // PORTALS_8B_OOB
    ret = PtlPutRegion(tx->mdh,                 /* Handle to MD */
                       0,                       /* local offset */
                       data_len,                /* length */
                       ack,                     /* ACK disposition */
                       pconn->idp,              /* target port */
                       pconn->idx,              /* table entry to use */
                       0,                       /* access entry to use */
                       bits,                    /* match bits */
                       0,                       /* remote offset */
                       pconn->peer_conn);       /* hdr_data */
    if (ret != PTL_OK) {
        switch (ret) {
            case PTL_NO_INIT:
                ret = CCI_ENODEV;
                break;
            case PTL_PROCESS_INVALID:
                ret = CCI_EADDRNOTAVAIL;
                break;
            default: /* PTL_MD_[INVALID|ILLEGAL] */
                ret = CCI_ERROR;
                break;
        }
        goto out;
    }
    debug(CCI_DB_MSG,
             "%s: ("PORTALS_URI"%u:%hu:%u): posted:"
             " ret=%s len=%d", __func__, pconn->idp.nid, pconn->idp.pid,
                                 pconn->idx, ptl_err_str[ret], data_len );
    /*
     * If blocking, only wait if reliable. Unreliable only needs local
     * completion and since we always buffer, they are locally complete.
     * If unreliable, we will silently ignore the send_end.
     *
     * Check for event in ep->evts.
     */
    if (flags & CCI_FLAG_BLOCKING && is_reliable) {
        cci__evt_t *e, *evt = NULL;
        do {
            pthread_mutex_lock(&ep->lock);
            TAILQ_FOREACH(e, &ep->evts, entry) {
                if (&tx->evt == e) {
                    evt = e;
                    TAILQ_REMOVE(&ep->evts, evt, entry);
                    ret = evt->event.send.status;
                }
            }
            pthread_mutex_unlock(&ep->lock);
        } while (evt == NULL);
        /* if successful, queue the tx now,
         * if not, queue it below */
        if (ret == CCI_SUCCESS) {
            pthread_mutex_lock(&ep->lock);
            TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
            pthread_mutex_unlock(&ep->lock);
        }
    }

out:
    if (ret) {
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&ep->lock);
    }

    CCI_EXIT;
    return ret;
}

static int portals_sendv(
    cci_connection_t       *connection,
    struct iovec           *data,
    uint32_t                iovcnt,
    void                   *context,
    int                    flags ) {

    int         i, ret;
    uint32_t    data_len    = 0;

    CCI_ENTER;

    for (i = 0; i < iovcnt; i++)
        data_len += (uint32_t) data[i].iov_len;

    ret = portals_send_common(connection, data, iovcnt, context, flags, NULL);

    CCI_EXIT;
    return ret;
}

static int portals_send(
    cci_connection_t       *connection,
    void                   *msg_ptr,
    uint32_t               msg_len,
    void                   *context,
    int                    flags ) {

    int ret = CCI_SUCCESS;
    uint8_t iovcnt = 0;
    struct iovec iov = { NULL, 0 };

    CCI_ENTER;

    if (msg_ptr && msg_len > 0) {
        iovcnt = 1;
        iov.iov_base = msg_ptr;
        iov.iov_len = msg_len;
    }

    ret = portals_send_common(connection, &iov, iovcnt, context, flags, NULL);
    CCI_EXIT;
    return ret;
}



/* We do not know if this buffer will be the source or sink,
 * so we must post a ME in case it will be a sink.
 * If the connection is not specified, we will return the
 * start address as the handle. If connection is specified,
 * we will return a EP ID/Conn ID value.
 * NOTE: returning a EP/conn combo does not restrict access
 * to that connection since we cannot check the connection
 * before Portals matches the ME. */
static int portals_rma_register(
    cci_endpoint_t         *endpoint,
    cci_connection_t       *connection,
    void                   *start,
    uint64_t               length,
    uint64_t               *rma_handle ) {

    int                     iRC     = CCI_SUCCESS;
    cci__ep_t               *ep     = NULL;
    cci__conn_t             *conn   = NULL;
    portals_ep_t            *pep    = NULL;
    portals_dev_t           *pdev   = NULL;
    portals_rma_handle_t    *handle = NULL;
    ptl_process_id_t       pid_any=PORTALS_WILDCARD;
    ptl_md_t               md;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    pdev = ep->dev->priv;
    conn = container_of(connection, cci__conn_t, connection);

    handle = calloc(1, sizeof(*handle));
    if (!handle) {
        debug( CCI_DB_WARN, "No memory for handle" );
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    handle->ep = ep;
    handle->conn = conn;
    handle->length = length;
    handle->start = start;
    handle->refcnt = 1;
    TAILQ_INIT(&handle->rma_ops);

    md.start     = start;
    md.length    = length;
    md.threshold = PTL_MD_THRESH_INF;
    md.eq_handle = pep->eqh;
    md.options   = PTL_MD_OP_PUT;
    md.options  |= PTL_MD_OP_GET;
    md.options  |= PTL_MD_TRUNCATE;
    md.options  |= PTL_MD_EVENT_START_DISABLE;
    md.options  |= PTL_MD_MANAGE_REMOTE;
    md.user_ptr  = handle;

    iRC = PtlMEMDAttach(pdev->niHandle,
                        pep->idx,
                        pid_any,
                        (uintptr_t) handle,
                        0x3ULL,
                        PTL_RETAIN,
                        PTL_INS_AFTER,
                        md,
                        PTL_RETAIN,
                        &handle->meh,
                        &handle->mdh);
    if( iRC!=PTL_OK ) {

        switch(iRC) {

            case PTL_NO_INIT:           /* Portals library issue */
            case PTL_NI_INVALID:        /* Bad NI Handle */
            case PTL_PT_INDEX_INVALID:  /* Bad table index */
            case PTL_PROCESS_INVALID:
                 iRC = CCI_ENODEV;;
                 break;

            case PTL_NO_SPACE:     /* Well, well, well */
                 debug( CCI_DB_WARN, "No memory for ME/MD" );
                 iRC = CCI_ENOMEM;;
                 break;

            case PTL_SEGV:         /* This one should not happen */
                 iRC = CCI_EINVAL;;
                 break;

            default:               /* Undocumented portals error */
                 debug( CCI_DB_WARN, "portals=%d", iRC );
                 iRC = CCI_ERROR;
        }
        free(handle);
        goto out;
    }
    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&pep->handles, handle, entry);
    pthread_mutex_unlock(&ep->lock);

    *rma_handle = (uint64_t)((uintptr_t)handle);

    CCI_EXIT;

out:
    return iRC;
}


// Todo
static int portals_rma_register_phys(
    cci_endpoint_t         *endpoint,
    cci_connection_t       *connection,
    cci_sg_t               *sg_list,
    uint32_t               sg_cnt,
    uint64_t               *rma_handle ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}

/* NOTE: caller should hold ep->lock */
static void portals_rma_handle_decref(portals_rma_handle_t *handle)
{
    int             ret     = 0;
    cci__ep_t       *ep     = NULL;
    portals_ep_t    *pep    = NULL;

    ep = handle->ep;
    pep = ep->priv;

    assert(handle->refcnt >= 1);

    handle->refcnt--;

    if (handle->refcnt == 0) {
        if (handle->meh != PTL_HANDLE_NONE) {
            /* unlink buffer if needed */
            ret = PtlMEUnlink(handle->meh);
            if (ret != PTL_OK) {
                debug(CCI_DB_WARN, "Could not unlink RMA from match list");
            }
        }
        TAILQ_REMOVE(&pep->handles, handle, entry);
        memset(handle, 0, sizeof(*handle));
        free(handle);
    }

    return;
}


static int portals_rma_deregister(uint64_t rma_handle)
{
    int                     ret     = CCI_EINVAL;
    portals_rma_handle_t    *handle = (portals_rma_handle_t *) rma_handle;
    cci__ep_t               *ep     = NULL;
    portals_ep_t            *pep    = NULL;
    portals_rma_handle_t    *h      = NULL;
    portals_rma_handle_t    *tmp    = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = handle->ep;
    pep = ep->priv;

    pthread_mutex_lock(&ep->lock);
    TAILQ_FOREACH_SAFE(h, &pep->handles, entry, tmp) {
        if (h == handle) {
            if (handle->meh != PTL_HANDLE_NONE) {
                ret = PtlMEUnlink(handle->meh);
                if (ret == PTL_OK)
                    handle->meh = PTL_HANDLE_NONE;
                else
                    debug(CCI_DB_DRVR, "Could not unlink RMA from match list");
            }
            portals_rma_handle_decref(handle);
            ret = CCI_SUCCESS;
            break;
        }
    }
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return ret;
}


static int portals_rma(cci_connection_t *connection,
                       void *msg_ptr, uint32_t msg_len,
                       uint64_t local_handle, uint64_t local_offset,
                       uint64_t remote_handle, uint64_t remote_offset,
                       uint64_t data_len, void *context, int flags)
{
    int                     ret     = CCI_SUCCESS;
    cci__ep_t               *ep     = NULL;
    cci__dev_t              *dev    = NULL;
    cci__conn_t             *conn   = NULL;
    portals_ep_t            *pep    = NULL;
    portals_dev_t           *pdev   = NULL;
    portals_conn_t          *pconn  = NULL;
    portals_rma_handle_t    *local  = (portals_rma_handle_t *)((uintptr_t)local_handle);
    portals_rma_op_t        *rma_op = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    conn = container_of(connection, cci__conn_t, connection);
    pconn = conn->priv;
    ep = container_of(connection->endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    dev = ep->dev;
    pdev = dev->priv;

    if (!local) {
        debug(CCI_DB_INFO, "%s: invalid local RMA handle", __func__);
        CCI_EXIT;
        return CCI_EINVAL;
    } else if (local->conn && local->conn != conn) {
        debug(CCI_DB_INFO, "%s: invalid connection for this RMA handle", __func__);
        CCI_EXIT;
        return CCI_EINVAL;
    }

    if (local->ep != ep) {
        debug(CCI_DB_INFO, "%s: invalid endpoint for this RMA handle", __func__);
        CCI_EXIT;
        return CCI_EINVAL;
    }
    /* if refcnt == 0, app handed us an invalid handle or is multi-threaded
     * another thread just unregistered it. Warn them. */
    if (local->refcnt == 0)
        debug(CCI_DB_WARN, "%s: local handle refcnt is 0", __func__);

    local->refcnt++;

    rma_op = calloc(1, sizeof(*rma_op));
    if (!rma_op) {
        pthread_mutex_lock(&ep->lock);
        local->refcnt--;
        /* if refcnt == 0, app handed us an invalid handle or is multi-threaded
         * another thread just unregistered it. Warn them. */
        debug(CCI_DB_WARN, "%s: local handle refcnt is 0", __func__);
        pthread_mutex_unlock(&ep->lock);
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    rma_op->data_len = data_len;
    rma_op->local_handle = local_handle;
    rma_op->local_offset = local_offset;
    rma_op->remote_handle = remote_handle;
    rma_op->remote_offset = remote_offset;
    rma_op->completed = 0;
    rma_op->status = CCI_SUCCESS; /* for now */
    rma_op->context = context;
    rma_op->flags = flags;
    rma_op->msg_len = (uint16_t) msg_len;
    rma_op->tx = NULL;

    rma_op->evt.event.type = CCI_EVENT_SEND;
    rma_op->evt.event.send.connection = connection;
    rma_op->evt.event.send.context = context;
    rma_op->evt.event.send.status = CCI_SUCCESS; /* for now */
    rma_op->evt.ep = ep;
    rma_op->evt.conn = conn;
    rma_op->evt.priv = rma_op;

    if (msg_len)
        rma_op->msg_ptr = msg_ptr;
    else
        rma_op->msg_ptr = NULL;

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&local->rma_ops, rma_op, hentry);
    TAILQ_INSERT_TAIL(&pep->rma_ops, rma_op, entry);
    pthread_mutex_unlock(&ep->lock);

    if (flags & CCI_FLAG_WRITE) {
        ret = PtlPutRegion(local->mdh,              /* Handle to MD */
                           local_offset,            /* local offset */
                           data_len,                /* length */
                           PTL_ACK_REQ,             /* ACK disposition */
                           pconn->idp,              /* target port */
                           pconn->idx,              /* table entry to use */
                           0,                       /* access entry to use */
                           remote_handle | PORTALS_MSG_RMA_WRITE, /* match bits */
                           remote_offset,           /* remote offset */
                           0);                      /* hdr_data */
        debug(CCI_DB_MSG, "%s: RMA WRITE bits=0x%"PRIx64" offset=%"PRIu64
                          " returned=%s len=%"PRIu64"", __func__,
                          remote_handle | PORTALS_MSG_RMA_WRITE,
                          remote_offset, ptl_err_str[ret], data_len);
        if (ret == PTL_OK) {
            ret = CCI_SUCCESS;
        } else {
            ret = CCI_ERROR;
            goto out;
        }
    } else if (flags & CCI_FLAG_READ) {
        ret = PtlGetRegion(local->mdh,              /* Handle to MD */
                           local_offset,            /* local offset */
                           data_len,                /* length */
                           pconn->idp,              /* target port */
                           pconn->idx,              /* table entry to use */
                           0,                       /* access entry to use */
                           remote_handle | PORTALS_MSG_RMA_READ, /* match bits */
                           remote_offset);          /* remote offset */
        debug(CCI_DB_MSG, "%s: RMA READ bits=0x%"PRIx64" offset=%"PRIu64
                          " returned=%s len=%"PRIu64"", __func__,
                          remote_handle | PORTALS_MSG_RMA_READ,
                          remote_offset, ptl_err_str[ret], data_len);
        if (ret == PTL_OK) {
            ret = CCI_SUCCESS;
        } else {
            ret = CCI_ERROR;
            goto out;
        }
    }

    if (flags & CCI_FLAG_BLOCKING) {
        cci__evt_t *e, *evt = NULL;
        do {
            /* check event queue for completion */
            pthread_mutex_lock(&ep->lock);
            TAILQ_FOREACH(e, &ep->evts, entry) {
                if (rma_op == e->priv) {
                    evt = e;
                    TAILQ_REMOVE(&ep->evts, evt, entry);
                    ret = evt->event.send.status;
                }
            }
            pthread_mutex_unlock(&ep->lock);

            /* if header, send completion message and block */
            /* TODO */
        } while (evt == NULL);
    }

out:
    if (ret != CCI_SUCCESS ||
        flags & CCI_FLAG_BLOCKING) {
        pthread_mutex_lock(&ep->lock);
        TAILQ_REMOVE(&local->rma_ops, rma_op, hentry);
        TAILQ_REMOVE(&pep->rma_ops, rma_op, entry);
        pthread_mutex_unlock(&ep->lock);
        free(rma_op);
    }

    CCI_EXIT;
    return ret;
}


static inline void portals_progress_dev(
    cci__dev_t             *dev ) {

    int                    have_token= 0;
    portals_dev_t          *pdev;
    cci__ep_t              *ep;

    //CCI_ENTER;

    pdev=dev->priv;

    pthread_mutex_lock(&dev->lock);
    if( pdev->is_progressing==0) {

        pdev->is_progressing=1;
        have_token=1;
    }
    pthread_mutex_unlock(&dev->lock);

    if(!have_token) {

        CCI_EXIT;
        return;
    }

    TAILQ_FOREACH( ep, &dev->eps, entry) {
        portals_ep_t *pep = ep->priv;

        portals_get_event_ep(ep);
        portals_free_orphan_ams(pep);
    }

    pthread_mutex_lock(&dev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&dev->lock);

    //CCI_EXIT;
    return;
}

static void *portals_progress_thread(
    void                   *arg ) {

    while(!portals_shut_down) {

        cci__dev_t          *dev;
        cci_device_t const  **device;

        /* for each device, try progressing */
        for( device=pglobals->devices; *device!=NULL; device++ ) {

            dev=container_of( *device, cci__dev_t, device );
            portals_progress_dev(dev);
        }
        usleep(PORTALS_PROG_TIME_US);
    }
    pthread_exit(NULL);
    return(NULL);                            /* make pgcc happy */
}


static void portals_handle_conn_request(cci__ep_t *ep, ptl_event_t pevent)
{
    portals_ep_t    *pep    = ep->priv;
    portals_rx_t    *rx     = NULL;
    cci__dev_t      *dev    = ep->dev;
    portals_am_buffer_t *am = pevent.md.user_ptr;

    CCI_ENTER;

    /* do we need to unlink this buffer? */
    if (am->length - (pevent.offset + pevent.mlength) < dev->device.max_send_size) {
        int active = 0;
        portals_am_buffer_t *a;

        am->state = PORTALS_AM_INACTIVE;
        debug((CCI_DB_INFO|CCI_DB_MSG), "%s: unlinking active message buffer", __func__);
        TAILQ_FOREACH(a, &pep->ams, entry) {
            if (a->state == PORTALS_AM_ACTIVE)
                active++;
        }
        if (!active)
            debug(CCI_DB_WARN, "both active message buffers inactive");
    }

    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_rxs)) {
        rx=TAILQ_FIRST(&pep->idle_rxs);
        TAILQ_REMOVE( &pep->idle_rxs, rx, entry );
    }
    pthread_mutex_unlock(&ep->lock);

    if (!rx) {
        debug((CCI_DB_WARN|CCI_DB_MSG), "no rx available for incoming CONN_REQ");
        return;
    }

    rx->pevent = pevent;
    rx->am = am;
    rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
    rx->evt.event.request.attribute =
        (enum cci_conn_attribute)((pevent.match_bits >> 8) & 0xFF);
    *((uint32_t *) &rx->evt.event.request.data_len) = (pevent.match_bits >> 16) & 0xFFFF;
    if (rx->evt.event.request.data_len)
        *((void **) &rx->evt.event.request.data_ptr) =
                pevent.md.start + pevent.offset + (uintptr_t)sizeof(portals_conn_request_t);
    else
        *((void **) &rx->evt.event.request.data_ptr) = NULL;


    debug(CCI_DB_CONN, "%s: from "PORTALS_URI"%u:%hu:%u client_conn=0x%llx",
          __func__, pevent.initiator.nid, pevent.initiator.pid,
          ((portals_conn_request_t *)(pevent.md.start + pevent.offset))->client_ep_idx,
          (unsigned long long) pevent.hdr_data);

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return;
}

/* If hdr_data is 0, it is a reject */
static void portals_handle_conn_reply(cci__ep_t *ep, ptl_event_t pevent)
{
    cci__conn_t             *conn   = (void *)((uintptr_t)pevent.hdr_data);
    portals_conn_t          *pconn  = conn->priv;
    portals_ep_t            *pep    = ep->priv;
    portals_rx_t            *rx     = NULL;
    portals_conn_accept_t   *accept = (void*)(pevent.md.start) + pevent.offset;
    cci__evt_t              *evt    = NULL;
    cci__dev_t              *dev    = ep->dev;
    portals_am_buffer_t     *am     = pevent.md.user_ptr;

    CCI_ENTER;

    debug(CCI_DB_CONN, "accept->max_send_size = %u", accept->max_send_size);
    debug(CCI_DB_CONN, "accept->max_recv_buffer_count = %u", accept->max_recv_buffer_count);
    debug(CCI_DB_CONN, "accept->server_conn_upper = 0x%x", accept->server_conn_upper);
    debug(CCI_DB_CONN, "accept->server_conn_lower = 0x%x", accept->server_conn_lower);

    /* do we need to unlink this buffer? */
    if (am->length - (pevent.offset + pevent.mlength) < dev->device.max_send_size) {
        int active = 0;
        portals_am_buffer_t *a;

        /* FIXME */
        PtlMEUnlink(am->meh);
        am->state = PORTALS_AM_INACTIVE;
        debug((CCI_DB_INFO|CCI_DB_CONN), "%s: unlinking active message buffer", __func__);
        TAILQ_FOREACH(a, &pep->ams, entry) {
            if (a->state == PORTALS_AM_ACTIVE)
                active++;
        }
        if (!active)
            debug(CCI_DB_WARN, "both active message buffers inactive");
    }

    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_rxs)) {
        rx=TAILQ_FIRST(&pep->idle_rxs);
        TAILQ_REMOVE( &pep->idle_rxs, rx, entry );
    }
    pthread_mutex_unlock(&ep->lock);

    if (!rx) {
        debug((CCI_DB_WARN|CCI_DB_MSG), "no rx available for incoming conn_reply");
        return;
    }

    rx->pevent = pevent;
    rx->am = am;

    evt = &rx->evt;
    evt->event.accepted.context = pconn->tx->evt.event.send.context;

    if (pevent.mlength == sizeof(*accept)) {
        /* accept */

        conn->connection.max_send_size = accept->max_send_size;
        pconn->peer_conn = ((uint64_t)accept->server_conn_upper) << 32;
        pconn->peer_conn |= (uint64_t)accept->server_conn_lower;

        evt->event.type = CCI_EVENT_CONNECT_ACCEPTED;
        evt->event.accepted.connection = &conn->connection;

        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL(&pep->conns, pconn, entry);
        pthread_mutex_unlock(&ep->lock);
    } else {
        /* reject */
        free(pconn);
        if (conn->uri)
            free((void *)conn->uri);
        free(conn);
        evt->event.type = CCI_EVENT_CONNECT_REJECTED;
        /* context already set in connect() */
        debug(CCI_DB_CONN, "%s: recv'd reject", __func__);
    }
    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
    TAILQ_INSERT_HEAD(&pep->idle_txs, pconn->tx, dentry);
    pconn->tx = NULL;
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;

    return;
}

static void portals_handle_active_msg(cci__ep_t *ep, ptl_event_t pevent)
{
#ifdef    PORTALS_8B_OOB
    int             len;
#endif // PORTALS_8B_OOB
    portals_ep_t    *pep    = ep->priv;
    portals_rx_t    *rx     = NULL;
    cci__evt_t      *evt    = NULL;
    cci__dev_t      *dev    = ep->dev;
    portals_am_buffer_t *am = pevent.md.user_ptr;

    CCI_ENTER;

    /* do we need to unlink this buffer? */
    if (am->length - (pevent.offset + pevent.mlength) < dev->device.max_send_size) {
        int active = 0;
        portals_am_buffer_t *a;

        am->state = PORTALS_AM_INACTIVE;
        debug((CCI_DB_INFO|CCI_DB_MSG), "%s: unlinking active message buffer", __func__);
        TAILQ_FOREACH(a, &pep->ams, entry) {
            if (a->state == PORTALS_AM_ACTIVE)
                active++;
        }
        if (!active)
            debug(CCI_DB_WARN, "both active message buffers inactive");
    }

    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_rxs)) {
        rx=TAILQ_FIRST(&pep->idle_rxs);
        TAILQ_REMOVE( &pep->idle_rxs, rx, entry );
    }
    pthread_mutex_unlock(&ep->lock);

    if (!rx) {
        debug((CCI_DB_WARN|CCI_DB_MSG), "no rx available for incoming AM");
        return;
    }

    rx->pevent = pevent;
    rx->am = am;

    evt = &rx->evt;
    evt->event.type = CCI_EVENT_RECV;

    *((uint32_t *)&evt->event.recv.len) =
        (uint32_t) ((pevent.match_bits >> 11) & 0xFFFF);
    if (evt->event.recv.len)
        *((void **)&evt->event.recv.ptr) =
            pevent.md.start + pevent.offset;
    else
        *((void **)&evt->event.recv.ptr) = NULL;

    debug(CCI_DB_MSG, "%s: recv'd len=%d ptr=%p",
          __func__,
          evt->event.recv.len,
          evt->event.recv.ptr);

#ifdef    PORTALS_8B_OOB
    len=evt->event.recv.len;
    if( len < 9 )                               /* Receive to 8B OOB */
        memcpy(pevent.md.start + pevent.offset, &pevent.hdr_data, len);
#endif // PORTALS_8B_OOB

    /* queue event on endpoint's completed event queue */

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return;
}

static void
portals_complete_rma(portals_rma_op_t *rma_op, portals_rma_handle_t *local, ptl_event_t event)
{
    cci__ep_t       *ep     = local->ep;
    portals_ep_t    *pep    = ep->priv;

    if (rma_op->flags & CCI_FLAG_SILENT) {
        /* we are done, cleanup */
        pthread_mutex_lock(&ep->lock);
        TAILQ_REMOVE(&pep->rma_ops, rma_op, entry);
        portals_rma_handle_decref(local);
        pthread_mutex_unlock(&ep->lock);
        free(rma_op);
    } else {
        /* we are done, issue completion */
        rma_op->evt.event.send.status =
            event.ni_fail_type == PTL_NI_OK ? CCI_SUCCESS : CCI_ERROR;
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_HEAD(&ep->evts, &rma_op->evt, entry);
        pthread_mutex_unlock(&ep->lock);
    }
    return;
}

static void portals_get_event_ep(cci__ep_t *ep)
{
    int             ret     = CCI_SUCCESS;
    int             have_token   = 0;
    portals_ep_t    *pep    = ep->priv;
    ptl_event_t     event;

    //CCI_ENTER;

    pthread_mutex_lock(&ep->lock);
    if (ep->closing) {
        pthread_mutex_unlock(&ep->lock);
        return;
    }
    if (pep->in_use == 0) {
        pep->in_use = 1;
        have_token = 1;
    }
    pthread_mutex_unlock(&ep->lock);

    if (!have_token) {
        //CCI_EXIT;
        return;
    }

    if (pep->eqh == PTL_EQ_NONE)
        debug(CCI_DB_WARN, "%s: endpoint has no event queue", __func__);

    ret = PtlEQGet(pep->eqh, &event);
    if (!(ret == PTL_OK || ret == PTL_EQ_DROPPED)) {
        goto out;
    }

    if (ret == PTL_EQ_DROPPED)
        debug(CCI_DB_WARN, "portals dropped one or more events");

    debug(CCI_DB_INFO, "%s: got portals %s event", __func__, ptl_event_str[event.type]);
    switch (event.type) {
    case PTL_EVENT_SEND_START:
        debug((CCI_DB_WARN|CCI_DB_INFO), "we missed disabling a portals send_start");
        break;
    case PTL_EVENT_SEND_END:
    {
        portals_msg_type_t msg_type = (enum portals_msg_type)(event.match_bits & 0x3);
        int is_reliable = (int) (event.match_bits & 0x4);
        portals_tx_t *tx = (void *)event.md.user_ptr;

        if (msg_type == PORTALS_MSG_RMA_WRITE ||
            msg_type == PORTALS_MSG_RMA_READ  ||
            is_reliable) {
            /* wait for the ACK instead */
            debug(CCI_DB_MSG, "%s: ignoring SEND_END for reliable %s", __func__,
                              msg_type == PORTALS_MSG_SEND ? "SEND" :
                              msg_type == PORTALS_MSG_RMA_WRITE ? "RMA WRITE" :
                              msg_type == PORTALS_MSG_RMA_READ ? "RMA READ" :
                              "OOB");
            break;
        }

        /* cleanup tx for connect and UU sends */
        switch (tx->msg_type) {
        case PORTALS_MSG_OOB:
        case PORTALS_MSG_SEND:
            debug(CCI_DB_MSG, "%s: send_end for SEND", __func__);
            if (tx->flags & CCI_FLAG_SILENT ||
                tx->flags & CCI_FLAG_BLOCKING) {
                /* queue on idle_txs */
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
                pthread_mutex_unlock(&ep->lock);
            } else {
                /* generate CCI_EVENT_SEND */
                tx->evt.event.send.status =
                    event.ni_fail_type == PTL_NI_OK ? CCI_SUCCESS : CCI_ERROR;
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
                pthread_mutex_unlock(&ep->lock);
            }
            break;
        default:
            debug(CCI_DB_INFO, "we missed disabling a portals send_end for "
                  "msg_type %u", (enum portals_msg_type)(tx->msg_type));
            break;
        }

        break;
    }
    case PTL_EVENT_PUT_START:
    {
        portals_msg_type_t  type;
        uint64_t            a;

        portals_parse_match_bits(event.match_bits, &type, &a);
        switch (type) {
        case PORTALS_MSG_SEND:
        case PORTALS_MSG_OOB:
        {
            portals_am_buffer_t *am = event.md.user_ptr;
            pthread_mutex_lock(&ep->lock);
            am->refcnt++;
            pthread_mutex_unlock(&ep->lock);
            break;
        }
        default:
            break;
        }
        break;
    }
    case PTL_EVENT_PUT_END:
      {
        portals_msg_type_t  type;
        uint64_t            a;

        portals_parse_match_bits(event.match_bits, &type, &a);
        switch (type) {
        case PORTALS_MSG_SEND:
            /* incoming active message */
            portals_handle_active_msg(ep, event);
            break;
        case PORTALS_MSG_RMA_WRITE:
            /* incoming RMA write */
            break;
        case PORTALS_MSG_RMA_READ:
            /* incoming RMA read */
            break;
        case PORTALS_MSG_OOB:
          {
            /* incoming OOB msg */
            portals_msg_oob_type_t oob_type = (enum portals_msg_oob_type)((event.match_bits >> 2) & 0x3);

            switch (oob_type) {
            case PORTALS_MSG_OOB_CONN_REQUEST:
                portals_handle_conn_request(ep, event);
                break;
            case PORTALS_MSG_OOB_CONN_REPLY:
                portals_handle_conn_reply(ep, event);
                break;
            default:
                debug(CCI_DB_INFO, "missed oob type %u", (enum portals_msg_oob_type)oob_type);
                break;
            }
            break;
          }
        }
        /* TODO unlink md and relink? */
        break;
      }
    case PTL_EVENT_GET_START:
        break;
    case PTL_EVENT_GET_END:
        break;
    case PTL_EVENT_REPLY_START:
        break;
    case PTL_EVENT_REPLY_END:
    {
        portals_msg_type_t msg_type = (portals_msg_type_t) (event.match_bits & 0x3);
        //portals_tx_t *tx = NULL;
        portals_rma_handle_t *handle = NULL, *local = NULL;
        portals_rma_op_t *rma_op = NULL, *ro = NULL, *tmp = NULL;

        assert(msg_type == PORTALS_MSG_RMA_READ);

        handle = event.md.user_ptr;
        TAILQ_FOREACH_SAFE(ro, &handle->rma_ops, hentry, tmp) {
            portals_conn_t *pconn = ro->evt.conn->priv;
            if (event.match_bits == (ro->remote_handle | PORTALS_MSG_RMA_READ) &&
                event.initiator.nid == pconn->idp.nid &&
                event.initiator.pid == pconn->idp.pid &&
                event.rlength == ro->data_len &&
                event.offset == ro->remote_offset) {

                TAILQ_REMOVE(&handle->rma_ops, ro, hentry);
                rma_op = ro;
                break;
            } else
            debug( CCI_DB_WARN,
                   "match=%"PRIx64"..%"PRIx64"  length=%"PRIu64"..%"PRIu64"  offset=%"PRIu64"..%"PRIu64"",
                   (uint64_t) event.match_bits,
                   (uint64_t) (ro->remote_handle | PORTALS_MSG_RMA_READ),
                   (uint64_t) event.rlength, (uint64_t) ro->data_len,
                   (uint64_t) event.offset, (uint64_t) ro->remote_offset );

        }
        if (!rma_op) {
            /* FIXME do what now? */
        }

        local = (void *)rma_op->local_handle;

        if (rma_op->msg_len) {
            struct iovec msg;

            /* send remote completion msg */
            msg.iov_base = rma_op->msg_ptr;
            msg.iov_len = rma_op->msg_len;
            ret = portals_send_common(&local->conn->connection,
                                      &msg, 1, rma_op->context,
                                      rma_op->flags, rma_op);
            /* FIXME do what if failed? */
        } else {
            portals_complete_rma(rma_op, local, event);
        }
        break;
    }
    case PTL_EVENT_ACK:
    {
        portals_msg_type_t msg_type = (portals_msg_type_t) (event.match_bits & 0x3);
        portals_tx_t *tx = NULL;
        portals_rma_handle_t *handle = NULL;
        portals_rma_op_t *rma_op = NULL, *ro = NULL, *tmp = NULL;

        debug(CCI_DB_MSG, "%s: got ACK for %s msg", __func__,
                          msg_type == PORTALS_MSG_SEND ? "SEND" :
                          msg_type == PORTALS_MSG_RMA_WRITE ?
                          "RMA WRITE" : "RMA_READ");
        if (event.ni_fail_type != PTL_NI_OK)
            debug(CCI_DB_WARN, "%s: send failed with ni_fail_type %u",
                  __func__, event.ni_fail_type);

        switch (msg_type) {
        case PORTALS_MSG_SEND:
            /* a reliable msg completed, generate CCI event */

            tx = event.md.user_ptr;
            rma_op = tx->rma_op;

            /* queue on ep->evts unless SILENT */
            if (tx->flags & CCI_FLAG_SILENT || rma_op) {
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
                pthread_mutex_unlock(&ep->lock);
            } else {
                tx->evt.event.send.status =
                    event.ni_fail_type == PTL_NI_OK ? CCI_SUCCESS : CCI_ERROR;
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&ep->evts, &tx->evt, entry);
                pthread_mutex_unlock(&ep->lock);
            }
            if (rma_op) {
                portals_rma_handle_t *local = (void *)rma_op->local_handle;
                portals_complete_rma(rma_op, local, event);
            }
            break;
        case PORTALS_MSG_RMA_WRITE:
        {
            portals_rma_handle_t *local = NULL;

            handle = event.md.user_ptr;
            TAILQ_FOREACH_SAFE(ro, &handle->rma_ops, hentry, tmp) {
                portals_conn_t *pconn = ro->evt.conn->priv;
                if (event.match_bits == (ro->remote_handle | PORTALS_MSG_RMA_WRITE) &&
                    event.initiator.nid == pconn->idp.nid &&
                    event.initiator.pid == pconn->idp.pid &&
                    event.rlength == ro->data_len &&
                    event.offset == ro->remote_offset) {

                    /* FIXME need lock? */
                    TAILQ_REMOVE(&handle->rma_ops, ro, hentry);
                    /* FIXME need unlock? */
                    rma_op = ro;
                    break;
                }
            }

            if (!rma_op) {
                debug(CCI_DB_WARN, "%s: unable to find rma_op for RMA WRITE "
                                   "completion", __func__);
                break;
            }

            local = (void *)rma_op->local_handle;

            if (rma_op->msg_len) {
                struct iovec msg;

                /* send remote completion msg */
                msg.iov_base = rma_op->msg_ptr;
                msg.iov_len = rma_op->msg_len;
                ret = portals_send_common(&local->conn->connection,
                                          &msg, 1, rma_op->context,
                                          rma_op->flags, rma_op);
                /* FIXME do what if failed? */
            } else {
                portals_complete_rma(rma_op, local, event);
            }
            break;
        }
        default:
            debug(CCI_DB_INFO, "we missed disabling a portals ack for "
                  "msg_type %u", (enum portals_msg_type)tx->msg_type);
            break;
        }
        break;
    }
    case PTL_EVENT_UNLINK:
        debug(CCI_DB_WARN, "unlink event");
        break;
    default:
        debug(CCI_DB_INFO, "unexpected portals event %u", (enum cci_event_type)event.type);
        break;
    }

out:
    pthread_mutex_lock(&ep->lock);
    pep->in_use = 0;
    pthread_mutex_unlock(&ep->lock);
    return;
}
