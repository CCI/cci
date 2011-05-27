/*
 *; Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

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



extern const char *ptl_err_str[];
extern const char *ptl_event_str[];

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
static int portals_bind(             cci_device_t         *device,
                                     int                  backlog,
                                     uint32_t             *port, 
                                     cci_service_t        **service,
                                     cci_os_handle_t      *fd );
static int portals_unbind(           cci_service_t        *service,
                                     cci_device_t         *device );
static int portals_get_conn_req(     cci_service_t        *service, 
                                     cci_conn_req_t       **conn_req );
static int portals_accept(           cci_conn_req_t       *conn_req, 
                                     cci_endpoint_t       *endpoint, 
                                     cci_connection_t     **connection );
static int portals_reject(           cci_conn_req_t       *conn_req );
static int portals_connect(          cci_endpoint_t       *endpoint,
                                     char                 *server_uri, 
                                     uint32_t             port,
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
                                     cci_event_t ** const event,
                                     uint32_t             flags );
static int portals_return_event(     cci_endpoint_t       *endpoint, 
                                     cci_event_t          *event );
static int portals_send(             cci_connection_t     *connection, 
                                     void                 *header_ptr,
                                     uint32_t             header_len, 
                                     void                 *data_ptr,
                                     uint32_t             data_len, 
                                     void                 *context,
                                     int                  flags );
static int portals_sendv(            cci_connection_t     *connection, 
                                     void                 *header_ptr,
                                     uint32_t             header_len, 
                                     char                 **data_ptrs,
                                     int                  *data_lens,
                                     uint8_t              segment_cnt,
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
                                     void                 *header_ptr,
                                     uint32_t             header_len, 
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
static int portals_events(           ptl_event_t          *event );
static void portals_get_event_ep(cci__ep_t *ep);
static void portals_get_event_lep(cci__lep_t *lep);

portals_msg_type_t portals_msg_type (portals_msg_type_t     type ) {

    return type;
}


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
    portals_bind,
    portals_unbind,
    portals_get_conn_req,
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
    //ptl_handle_eq_t        eqhSend;
    //ptl_handle_eq_t        eqhRecv;

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
 * Step 3.  Initialize the portals library.
 */
    if( (iRC=PtlInit( &iMax_devices ))!=PTL_OK ) {

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
 * Step 4.  Initialize the network interface.
 */
    iRC=PtlNIInit( ifID, PTL_PID_ANY, NULL, &niLimit, &niHandle );
    if( iRC!=PTL_OK ) {

        switch(iRC) {
            case PTL_NO_INIT:      /* Usually dup PtlNIInit() call */
                 return CCI_ENODEV;;

            case PTL_IFACE_INVALID:/* Bad interface options */
                 return CCI_ENODEV;;

            case PTL_PID_INVALID:  /* This one should not happen */
                 return CCI_EINVAL;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 return CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 return CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 return CCI_ERROR;
        }
    }

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

        TAILQ_INIT(&dev->leps);

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
            return CCI_ENOMEM;
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
        debug( CCI_DB_INFO, "My portals ID is: (%10d, %5d).\n",
                 (pdev->idp).nid, (pdev->idp).pid );
        debug( CCI_DB_INFO, "My portals limits are: max_mes=%d\n",
                 pdev->max_mes );
        debug( CCI_DB_INFO, "                       max_mds=%d\n",
                 pdev->max_mds );
        debug( CCI_DB_INFO, "                       max_eqs=%d\n",
                 pdev->max_eqs );
        debug( CCI_DB_INFO, "                       max_ac_index=%d\n",
                 pdev->max_ac_index );
        debug( CCI_DB_INFO, "                       max_pt_index=%d\n",
                 pdev->max_pt_index );
        debug( CCI_DB_INFO, "                       max_md_iovecs=%d\n",
                 pdev->max_md_iovecs );
        debug( CCI_DB_INFO, "                       max_me_list=%d\n",
                 pdev->max_me_list );
        debug( CCI_DB_INFO, "                       max_getput_md=%d\n",
                 pdev->max_getput_md );

        pdev->ep_ids = calloc(PORTALS_NUM_BLOCKS, sizeof(*pdev->ep_ids));
        // FIXME check ep_ids
        ds[pglobals->count]=device;
        pglobals->count++;
        dev->is_up=1;

        /* parse conf_argv */
        for( arg=device->conf_argv; *arg!=NULL; arg++ ) {

           if(!strncmp( "pt_index=", *arg, 9 )) {

               const char *table = *arg + 9;
    
               pdev->table_index= atoi(table);
               debug( CCI_DB_INFO, "found portals index=%d\n",
                        pdev->table_index );
            } else if (0 == strncmp("mtu=", *arg, 4)) {
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
        return CCI_ENODEV;
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
}


// Todo
static const char *portals_strerror(
    enum cci_status        status ) {

    CCI_ENTER;
    CCI_EXIT;

    return NULL;
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
    debug( CCI_DB_INFO, "There are %d devices.\n", pglobals->count );

    device=**devices;
    dev=container_of( device, cci__dev_t, device );
    pdev=dev->priv;

    debug( CCI_DB_INFO, "Got portals ID of: (%10d, %5d).\n",
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
        PtlNIFini(pdev->niHandle);
        if (pdev->ep_ids)
            free(pdev->ep_ids);
        free(dev->priv);
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
static void portals_get_ep_id(
    portals_dev_t          *pdev,
    uint32_t               *id ) {

    uint32_t               n;
    uint32_t               block;
    uint32_t               offset;
    uint64_t               *b;

    while (1) {

        n=random()%PORTALS_MAX_EP_ID;
        if ( n==0 )
            continue;
        block=n/PORTALS_BLOCK_SIZE;
        offset=n%PORTALS_BLOCK_SIZE;
        b=&pdev->ep_ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*PORTALS_BLOCK_SIZE)+offset;
            debug(CCI_DB_CONN, "getting EP id %u block=%"PRIx64"", *id, *b);
            break;
        }
    }
    return;
}

static void
portals_put_ep_id(portals_dev_t *pdev, uint32_t id)
{
    uint32_t block, offset;
    uint64_t *b;

    block = id / PORTALS_BLOCK_SIZE;
    offset = id % PORTALS_BLOCK_SIZE;
    b = &pdev->ep_ids[block];

    debug(CCI_DB_CONN, "putting EP id %u block=%"PRIx64"", id, *b);
    assert(((*b >> offset) & 0x1) == 1);
    *b &= ~(1ULL << offset);

    return;
}

static int portals_create_endpoint(
    cci_device_t           *device, 
    int                    flags, 
    cci_endpoint_t         **endpoint, 
    cci_os_handle_t        *fd) {

    int                    i;
    int                    iRC;
    cci__dev_t             *dev=NULL;
    cci__ep_t              *ep=NULL;
    portals_ep_t           *pep=NULL;
    portals_dev_t          *pdev;
    ptl_handle_ni_t        niHandle;
    ptl_process_id_t       pid_any=PORTALS_WILDCARD;
    ptl_match_bits_t       bits = 0ULL;
    ptl_match_bits_t       ignore = 0ULL;
    uint32_t               am_length;
    ptl_md_t               md;

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
    niHandle=pdev->niHandle;

    ep=container_of(*endpoint, cci__ep_t, endpoint);
    ep->priv=calloc(1, sizeof(*pep));
    if(!ep->priv) {

        iRC=CCI_ENOMEM;
        goto out;
    }

    (*endpoint)->max_recv_buffer_count=PORTALS_EP_RX_CNT;
    ep->max_hdr_size=PORTALS_EP_MAX_HDR_SIZE;
    ep->rx_buf_cnt=PORTALS_EP_RX_CNT;
    ep->tx_buf_cnt=PORTALS_EP_TX_CNT;
    ep->buffer_len=PORTALS_EP_BUF_LEN;
    ep->tx_timeout=0;

    pep=ep->priv;

    TAILQ_INIT(&pep->txs);
    TAILQ_INIT(&pep->idle_txs);
    TAILQ_INIT(&pep->rxs);
    TAILQ_INIT(&pep->idle_rxs);
    TAILQ_INIT(&pep->conns);
    TAILQ_INIT(&pep->handles);
    TAILQ_INIT(&pep->rma_ops);

    /* get endpoint id */
    pthread_mutex_lock(&dev->lock);
    portals_get_ep_id(pdev, &pep->id);
    pthread_mutex_unlock(&dev->lock);
    debug(CCI_DB_CONN, "%s: id=%u", __func__, pep->id);

    /* create event queue for endpoint */
    iRC=PtlEQAlloc( pdev->niHandle,
                    PORTALS_EP_RX_CNT + PORTALS_EP_TX_CNT,
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

    /*  Create the memory descriptor. */
    md.threshold=PTL_MD_THRESH_INF;
    md.eq_handle=pep->eqh;
    md.options  =PTL_MD_OP_PUT;
    md.options |=PTL_MD_TRUNCATE;
    md.options |=PTL_MD_EVENT_START_DISABLE;

    for( i=0; i<ep->tx_buf_cnt; i++ ) {

        portals_tx_t       *tx;

        tx=calloc( 1, sizeof(*tx) );
        if(!tx) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        tx->evt.event.type=CCI_EVENT_SEND;
        tx->evt.ep=ep;
        tx->buffer=calloc(1, ep->buffer_len);
        if(!tx->buffer) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        tx->len=0;

        md.user_ptr = tx;
        md.start = tx->buffer;
        md.length = ep->buffer_len;

        iRC = PtlMDBind(pdev->niHandle, md, PTL_RETAIN, &tx->mdh);
        if (iRC) {
            iRC = CCI_ENODEV;
            goto out;
        }

        TAILQ_INSERT_TAIL( &pep->txs, tx, tentry );
        TAILQ_INSERT_TAIL( &pep->idle_txs, tx, dentry );
    }

    /* all non-RMA messages place the endpoint ID in the upper 32 bits */
    bits = ((ptl_match_bits_t) pep->id) << PORTALS_EP_SHIFT;

    /* and ignore the lower 32 bits */
    ignore = (((ptl_match_bits_t) 1) << PORTALS_EP_SHIFT) - 1;

    md.max_size= dev->device.max_send_size;
    md.options |=PTL_MD_MAX_SIZE;

/*  Creating receive buffers/MDs/MEs. */
    am_length = pdev->max_mds * dev->device.max_send_size / 2;
    for (i = 0; i < 2; i++) {
        int j;

        pep->am[i].buffer = calloc(1, am_length);
        if (!pep->am[i].buffer) {
            iRC = CCI_ENOMEM;
            goto out;
        }
        for (j = 0; j < am_length; j += 4096)
            *((char *)pep->am[i].buffer + j) = 1;

        pep->am[i].length = am_length;
        pep->am[i].pep = pep;
        md.start=    pep->am[i].buffer;
        md.length=   pep->am[i].length;
        md.user_ptr =&pep->am[i];
        iRC = PtlMEMDAttach(pdev->niHandle,
                            pdev->table_index,
                            pid_any,
                            bits,
                            ignore,
                            PTL_RETAIN,
                            PTL_INS_AFTER,
                            md,
                            PTL_RETAIN,
                            &(pep->am[i].meh),
                            &(pep->am[i].mdh));
        if( iRC!=PTL_OK ) {

            pep->eqh = PTL_EQ_NONE;
            switch(iRC) {

                case PTL_NO_INIT:           /* Portals library issue */
                case PTL_NI_INVALID:        /* Bad NI Handle */
                case PTL_PT_INDEX_INVALID:  /* Bad table index */
                case PTL_PROCESS_INVALID:
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
        pep->am[i].active = 1;
    }

    for( i=0; i<ep->rx_buf_cnt; i++ ) {

        portals_rx_t       *rx;

        rx=calloc( 1, sizeof(*rx) );
        if(!rx) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        rx->evt.event.type=CCI_EVENT_RECV;
        rx->evt.ep=ep;
        TAILQ_INSERT_TAIL( &pep->rxs, rx, gentry );
        TAILQ_INSERT_TAIL( &pep->idle_rxs, rx, entry );
    }

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);
    if(pep) {

        if (pep->id)
            portals_put_ep_id(pdev, pep->id);

        if (pep->eqh != PTL_EQ_NONE)
            PtlEQFree(pep->eqh);

        if (pep->am[0].buffer)
            free(pep->am[0].buffer);
        if (pep->am[1].buffer)
            free(pep->am[1].buffer);
        while(!TAILQ_EMPTY(&pep->txs)) {

            portals_tx_t   *tx;

            tx=TAILQ_FIRST(&pep->txs);
            TAILQ_REMOVE( &pep->txs, tx, tentry );
            if(tx->buffer)
                free(tx->buffer);
            free(tx);
        }

        while(!TAILQ_EMPTY(&pep->rxs)) {

            portals_rx_t   *rx;

            rx=TAILQ_FIRST(&pep->rxs);
            TAILQ_REMOVE( &pep->rxs, rx, gentry );
            free(rx);
        }

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

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    dev = ep->dev;
    pep = ep->priv;
    pdev = dev->priv;

    pthread_mutex_lock(&dev->lock);
    pthread_mutex_lock(&ep->lock);

    ep->priv = NULL;

    if (pep) {
        if (pep->id)
            portals_put_ep_id(pdev, pep->id);

        if (pep->eqh != PTL_EQ_NONE)
            PtlEQFree(pep->eqh);

        if (pep->am[0].buffer)
            free(pep->am[0].buffer);
        if (pep->am[1].buffer)
            free(pep->am[1].buffer);

        while(!TAILQ_EMPTY(&pep->conns)) {
            cci__conn_t     *conn;
            portals_conn_t  *pconn;

            pconn=TAILQ_FIRST(&pep->conns);
            TAILQ_REMOVE(&pep->conns, pconn, entry);
            conn = pconn->conn;
            free(pconn);
            free(conn);
        }

        while(!TAILQ_EMPTY(&pep->txs)) {
            portals_tx_t   *tx;

            tx=TAILQ_FIRST(&pep->txs);
            TAILQ_REMOVE(&pep->txs, tx, tentry);
            if(tx->buffer)
                free(tx->buffer);
            free(tx);
        }

        while(!TAILQ_EMPTY(&pep->rxs)) {
            portals_rx_t   *rx;

            rx=TAILQ_FIRST(&pep->rxs);
            TAILQ_REMOVE(&pep->rxs, rx, gentry);
            free(rx);
        }

        free(pep);
    }
    pthread_mutex_unlock(&ep->lock);
    pthread_mutex_unlock(&dev->lock);

    debug(CCI_DB_WARN, "%s: leaving", __func__);
    CCI_EXIT;
    return CCI_SUCCESS;
}


static int portals_bind(
    cci_device_t           *device,
    int                    backlog,
    uint32_t               *port, 
    cci_service_t          **service,
    cci_os_handle_t        *fd ) {

    int                    iRC;
    size_t                 len;
    cci__dev_t             *dev=NULL;
    cci__svc_t             *svc=NULL;
    cci__lep_t             *lep=NULL;
    cci__crq_t             *crq=NULL;
    portals_lep_t          *plep=NULL;
    portals_crq_t          *pcrq=NULL;
    portals_dev_t          *pdev;
    uint64_t               bits    = 0ULL;
    uint64_t               ignore  = 0ULL;
    ptl_process_id_t       pid_any=PORTALS_WILDCARD;
    ptl_md_t               md;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev=container_of( device, cci__dev_t, device );
    if(strcmp("portals", dev->driver)) {

        iRC=CCI_EINVAL;
        goto out;
    }

    pdev=dev->priv;
    if(pdev->table_index>pdev->max_pt_index) {
        CCI_EXIT;
        return CCI_ERANGE;
    }

    svc=container_of( *service, cci__svc_t, service );
    TAILQ_FOREACH( lep, &svc->leps, sentry ) {
        if( lep->dev==dev )
            break;
    }

    /* allocate portals listening endpoint */
    if(!(plep=calloc( 1, sizeof(*plep) ))) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    /* create event queue for endpoint */
    iRC=PtlEQAlloc( pdev->niHandle,
                    backlog * 8,
                    PTL_EQ_HANDLER_NONE,
                    &(plep->eqh) );
    if( iRC!=PTL_OK ) {
        switch(iRC) {

        case PTL_NO_INIT:      /* Portals library issue */
        case PTL_NI_INVALID:   /* Bad NI Handle */
            iRC = CCI_ENODEV;
            break;
        case PTL_NO_SPACE:     /* Well, well, well */
            iRC = CCI_ENOMEM;
            break;
        case PTL_SEGV:         /* This one should not happen */
            iRC = CCI_EINVAL;
            break;
        default:               /* Undocumented portals error */
             iRC = CCI_ERROR;
        }
        goto out;
    }

    /* all conn_req messages place the bound port in the upper 32 bits */
    bits = ((ptl_match_bits_t) svc->port) << PORTALS_EP_SHIFT;
    bits |= ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REQUEST) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* ignore bits 4-31 */
    ignore = ((((ptl_match_bits_t) 1) << 28) - 1) << 4;

    /* prepare memory descriptor */
    memset(&md, 0, sizeof(md));
    md.max_size= 1024; //FIXME magic number
    md.length=   1024; //FIXME magic number
    md.threshold=PTL_MD_THRESH_INF;
    md.eq_handle=plep->eqh;
    md.options  =PTL_MD_OP_PUT;
    md.options |=PTL_MD_TRUNCATE;
    md.options |=PTL_MD_EVENT_START_DISABLE;

    /* alloc portal for each cci__crq_t */
    TAILQ_FOREACH( crq, &lep->crqs, entry ) {

        if(!(crq->priv=calloc( 1, sizeof(*pcrq) ))) {
            iRC=CCI_ENOMEM;
            goto out;
        }
        pcrq = crq->priv;
        len = 1024; //FIXME magic number
        if( !(pcrq->buffer=calloc( 1, len )) ) {
            iRC=CCI_ENOMEM;
            goto out;
        }

        /*  Create the memory descriptor. */
        md.start = pcrq->buffer;
        md.user_ptr = crq;

        iRC = PtlMEMDAttach(pdev->niHandle,
                            pdev->table_index,
                            pid_any,
                            bits,
                            ignore,
                            PTL_UNLINK,
                            PTL_INS_AFTER,
                            md,
                            PTL_UNLINK,
                            &pcrq->meh,
                            &pcrq->mdh);
        if( iRC!=PTL_OK ) {
            switch(iRC) {
                case PTL_NO_INIT:            /* Portals library issue */
                    //FIXME
                    iRC = CCI_ENODEV;
                    break;
                case PTL_NO_SPACE:           /* Well, well, well */
                    //FIXME
                    iRC = CCI_ENOMEM;
                    break;
                default:                     /* Undocumented error */
                    debug( CCI_DB_WARN, "Failed with iRC=%d\n", iRC );
                    //FIXME
                    iRC = CCI_ERROR;
            }
            goto out;
        }
    }

    TAILQ_INIT(&lep->passive);

    debug(CCI_DB_INFO, "%s: port://%u,%hu bound on port %u\n", __func__,
                       pdev->idp.nid, pdev->idp.pid, svc->port);

    /* create OS handle */
    /* TODO */

    lep->priv=plep;

    PORTALS_IS_SERVER;  /* allows sampling for server vs client */

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if(plep) {

        TAILQ_FOREACH( crq, &lep->crqs, entry ) {

            pcrq=crq->priv;
            if(pcrq) {
                if(pcrq->buffer)
                    free(pcrq->buffer);

                free(pcrq);
                crq->priv=NULL;
            }
        }

        free(plep);
        lep->priv=NULL;
    }

    CCI_EXIT;
    return iRC;
}


static int portals_unbind(cci_service_t *service, cci_device_t *device)
{
    cci__dev_t      *dev    = NULL;
    cci__svc_t      *svc    = NULL;
    cci__lep_t      *lep    = NULL;
    cci__crq_t      *crq    = NULL;
    portals_lep_t   *plep   = NULL;
    portals_crq_t   *pcrq   = NULL;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev = container_of(device, cci__dev_t, device);
    svc = container_of(service, cci__svc_t, service);

    pthread_mutex_lock(&svc->lock);
    TAILQ_FOREACH(lep, &svc->leps, sentry) {
        if (lep->dev == dev) {
            break;
        }
    }
    pthread_mutex_unlock(&svc->lock);

    plep = lep->priv;

    pthread_mutex_lock(&lep->lock);
    TAILQ_FOREACH(crq, &lep->all_crqs, lentry) {
        pcrq = crq->priv;
        free(pcrq->buffer);
        free(pcrq);
    }
    pthread_mutex_unlock(&lep->lock);

    free(plep);

    CCI_EXIT;
    return CCI_SUCCESS;
}


/* currently, never called */
static int portals_get_conn_req(
    cci_service_t          *service, 
    cci_conn_req_t         **conn_req ) {

    int                    iRC;
    cci__crq_t             *crq;
    cci__lep_t             *lep;
    const cci_device_t     **devices;
    cci__dev_t             *dev;
    
    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    iRC=CCI_ENODEV;
    devices=pglobals->devices;
    dev=container_of(*devices, cci__dev_t, device);
    TAILQ_FOREACH( lep, &dev->leps, dentry ) {

        portals_get_event_lep(lep);

        pthread_mutex_lock(&lep->lock);
        TAILQ_FOREACH( crq, &lep->crqs, entry ) {

            uint32_t count=crq->conn_req.devices_cnt;
            cci_device_t **remote;
            cci_device_t **local;

            if( count==1 ) {

                local=calloc( 1, sizeof(cci_device_t * ) );
                local[0]=calloc( 1, sizeof(cci_device_t));
                local[0]->name=calloc( 1, 24 );
                remote=*((cci_device_t ***)&(crq->conn_req.devices));
                strcpy( (char *)local[0]->name,
                        (char *)remote[0]->name );
                *((cci_device_t ***)&((**conn_req).devices))=local;
                TAILQ_REMOVE( &lep->crqs, crq, entry );
                free((char *)remote[0]->name);
                free(remote[0]);
                free(remote);
                free(crq);
                crq=container_of( conn_req[0], cci__crq_t, conn_req );
                crq->lep=lep;
                iRC=CCI_SUCCESS;
                fprintf( stderr, "In portals_get_conn_req:  "
                    "**conn_req.devices[0].name=\"%s\"\n",
                    (*(&((**conn_req).devices)))[0]->name );
            }
        }
        pthread_mutex_unlock(&lep->lock);
    }
    return iRC;
}

static int portals_accept(
    cci_conn_req_t         *conn_req, 
    cci_endpoint_t         *endpoint, 
    cci_connection_t       **connection ) {

    int             ret;
    cci__ep_t       *ep     = NULL;
    cci__dev_t      *dev    = NULL;
    cci__conn_t     *conn   = NULL;
    cci__crq_t      *crq    = NULL;
    portals_ep_t    *pep    = NULL;
    portals_dev_t   *pdev   = NULL;
    portals_crq_t   *pcrq   = NULL;
    portals_conn_t  *pconn  = NULL;
    portals_conn_accept_t accept;
    uint64_t        bits;
    int             ac_len  = sizeof(accept);
    portals_tx_t    *tx     = NULL;

    CCI_ENTER;

    if(!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    crq = container_of(conn_req, cci__crq_t, conn_req);
    pcrq = crq->priv;
    dev = ep->dev;
    pdev = dev->priv;

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    conn->tx_timeout = ep->tx_timeout;
    conn->priv = calloc(1, sizeof(*pconn));
    if (!conn->priv) {
        free(conn);
        CCI_EXIT;
        return CCI_ENOMEM;
    }
    pconn = conn->priv;
    pconn->conn = conn;

    TAILQ_INIT(&pconn->rmas);

    /* prepare accept msg */

    accept.server_ep_id = pep->id;
    accept.max_send_size = pcrq->mss;
    accept.max_recv_buffer_count = pcrq->max_recv_buffer_count;
    accept.server_conn_upper = (uint32_t)((uintptr_t)conn >> 32);
    accept.server_conn_lower = (uint32_t)((uintptr_t)conn & 0xFFFFFFFF);

    debug(CCI_DB_CONN, "accept.server_ep_id = %u", accept.server_ep_id);
    debug(CCI_DB_CONN, "accept.max_send_size = %u", accept.max_send_size);
    debug(CCI_DB_CONN, "accept.max_recv_buffer_count = %u", accept.max_recv_buffer_count);
    debug(CCI_DB_CONN, "accept.server_conn_upper = 0x%x", accept.server_conn_upper);
    debug(CCI_DB_CONN, "accept.server_conn_lower = 0x%x", accept.server_conn_lower);

    /* setup connection */

    conn->connection.attribute = crq->conn_req.attribute;
    conn->connection.endpoint = endpoint;
    conn->connection.max_send_size = dev->device.max_send_size;

    pconn->idp = pcrq->idp;
    pconn->peer_conn = pcrq->client_conn;
    pconn->peer_ep_id = pcrq->client_id;
    pconn->mss = pcrq->mss;
    pconn->max_tx_cnt = pcrq->max_recv_buffer_count;

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&pep->conns, pconn, entry);
    pthread_mutex_unlock(&ep->lock);

    bits = ((ptl_match_bits_t) pconn->peer_ep_id) << PORTALS_EP_SHIFT;
    bits |= ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REPLY) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_txs)) {
        tx=TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE( &pep->idle_txs, tx, dentry );
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        // FIXME leak
        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    /* prep the tx */
    tx->msg_type=PORTALS_MSG_OOB;
    tx->oob_type=PORTALS_MSG_OOB_CONN_REPLY;

    tx->evt.ep=ep;
    tx->evt.conn=conn;
    tx->evt.event.type=CCI_EVENT_SEND;
    memcpy(tx->buffer, &accept, ac_len);

    debug(CCI_DB_CONN, "%s: to %d,%d client_id=%d peer_conn=%llx",
          __func__, pconn->idp.nid, pconn->idp.pid, pconn->peer_ep_id,
          (unsigned long long) pconn->peer_conn);
    ret = PtlPutRegion(tx->mdh,           /* Handle to MD */
                 0,
                 ac_len,
                 PTL_NOACK_REQ,     /* ACK disposition */
                 pconn->idp,        /* target port */
                 pdev->table_index, /* table entry to use */
                 0,                 /* access entry to use */
                 bits,              /* match bits */
                 0,                 /* remote offset */
                 (uintptr_t) pconn->peer_conn); /* hdr_data */

    *connection = &conn->connection;

    CCI_EXIT;
    return CCI_SUCCESS;
}


// Todo
static int portals_reject(
    cci_conn_req_t         *conn_req ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


/* Extract the portals ID from the URI. */
static int portals_getaddrinfo(
    const char             *uri,
    ptl_process_id_t       *idp ) {

    CCI_ENTER;
    char                   *addr;
    char                   *cp;

    if(!strncmp( "port://", uri, 7 )) {      /* URI to portals ID */

        addr=strdup(&uri[7]);                /* ASCII NID,PID */
        cp=strchr( addr, ',' );              /* NID delimiter address */
        if(cp)
            *cp='\0';                        /* local overwrite only */
        cp++;
        idp->nid=atoi(addr);                 /* ASCII to portals ID */
        idp->pid=atoi(cp);
        free(addr);
    } else {                                 /* something else */

        CCI_EXIT;
        return CCI_EINVAL;
    }

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int portals_connect(
    cci_endpoint_t         *endpoint,
    char                   *server_uri, 
    uint32_t               port,
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
    cci_event_other_t      *other=NULL;
    ptl_process_id_t       idp;
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

    TAILQ_INIT(&pconn->rmas);

    /* conn->tx_timeout=0  by default */
    connection=&conn->connection;
    connection->attribute=attribute;
    connection->endpoint=endpoint;

    iRC=portals_getaddrinfo( server_uri, &idp );
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

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&pep->idle_txs)) {
        tx=TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE( &pep->idle_txs, tx, dentry );
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        // FIXME leak
        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    /* prep the tx */
    tx->msg_type=PORTALS_MSG_OOB;
    tx->oob_type=PORTALS_MSG_OOB_CONN_REQUEST;
    pconn->tx = tx; /* we need its event for the accept|reject */

    evt=&tx->evt;
    evt->ep=ep;
    evt->conn=conn;
    event=&evt->event;
    event->type=CCI_EVENT_CONNECT_SUCCESS; /* for now */

    other=&event->info.other;
    other->context=context;
    other->u.connect.connection=connection;

    /* pack the bits */
    bits = ((ptl_match_bits_t) port) << PORTALS_EP_SHIFT;
    bits |= ((ptl_match_bits_t) (data_len & 0xFFFF)) << 16;
    bits |= ((ptl_match_bits_t) attribute) << 8;
    bits |= ((ptl_match_bits_t) PORTALS_MSG_OOB_CONN_REQUEST) << 2;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* pack the payload */
    conn_request.max_send_size = connection->max_send_size;
    conn_request.max_recv_buffer_count = endpoint->max_recv_buffer_count;
    conn_request.client_ep_id = pep->id;

    memcpy(tx->buffer, &conn_request, cr_len);
    if (data_len)
        memcpy(tx->buffer + cr_len, data_ptr, data_len);

    debug(CCI_DB_CONN, "%s: to %d,%d port %d client_id=%d conn=%p",
          __func__, pconn->idp.nid, pconn->idp.pid, port, pep->id, conn);
    iRC = PtlPutRegion(tx->mdh,           /* Handle to MD */
                       0,                 /* offset */
                       cr_len + data_len, /* payload len */
                       PTL_NOACK_REQ,     /* ACK disposition */
                       pconn->idp,        /* target port */
                       pdev->table_index, /* table entry to use */
                       0,                 /* access entry to use */
                       bits,              /* match bits */
                       0,                 /* remote offset */
                       (uintptr_t) conn); /* hdr_data */

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


// Todo
static int portals_disconnect(
    cci_connection_t       *connection ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_set_opt(
    cci_opt_handle_t       *handle, 
    cci_opt_level_t        level, 
    cci_opt_name_t         name,
    const void             *val,
    int                    len ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_get_opt(
    cci_opt_handle_t       *handle, 
    cci_opt_level_t        level, 
    cci_opt_name_t         name,
    void                   **val,
    int                    *len ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
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
                             cci_event_t **const event,
                             uint32_t flags )
{
    int             ret = CCI_SUCCESS;
    cci__ep_t       *ep;
    cci__evt_t      *ev = NULL, *e;
    cci__dev_t      *dev;
    portals_ep_t    *pep;
    cci_event_t     *tmp;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;
    dev = ep->dev;

    portals_get_event_ep(ep);

    pthread_mutex_lock(&ep->lock);
    if (TAILQ_EMPTY(&ep->evts)) {
        pthread_mutex_unlock(&ep->lock);
        *event = NULL;
        CCI_EXIT;
        return CCI_EAGAIN;
    }

    if (!flags) {
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
    } else {
        TAILQ_FOREACH(e, &ep->evts, entry) {
            tmp = &e->event;

            if (flags & CCI_PE_SEND_EVENT &&
                tmp->type == CCI_EVENT_SEND) {
                portals_tx_t *tx = container_of(e, portals_tx_t, evt);
                if (tx->flags & CCI_FLAG_BLOCKING) {
                    continue;
                } else {
                    ev = e;
                    break;
                }
            } else if (flags & CCI_PE_RECV_EVENT &&
                       tmp->type == CCI_EVENT_RECV) {
                ev = e;
                break;
            } else if (flags & CCI_PE_OTHER_EVENT &&
                       !(tmp->type == CCI_EVENT_SEND ||
                         tmp->type == CCI_EVENT_RECV)) {
                ev = e;
                break;
            }
        }
    }

    if (ev)
        TAILQ_REMOVE(&ep->evts, ev, entry);
    else
        ret = CCI_EAGAIN;

    pthread_mutex_unlock(&ep->lock);

    /* TODO drain fd so that they can block again */

    *event = &ev->event;

    CCI_EXIT;

    return ret;
}


static int portals_return_event(cci_endpoint_t *endpoint, 
                                cci_event_t *event )
{
    int iRC;
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

    ep = container_of(endpoint, cci__ep_t, endpoint);
    pep = ep->priv;

    evt = container_of(event, cci__evt_t, event);

    if (evt->ep != ep) {
        CCI_EXIT;
        return CCI_EINVAL;
    }

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
            local->refcnt--;
            /* FIXME check for refcnt == 0 */
            TAILQ_REMOVE(&pep->rma_ops, rma_op, entry);
            TAILQ_REMOVE(&pconn->rmas, rma_op, rmas);
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
    case CCI_EVENT_CONNECT_SUCCESS:
    case CCI_EVENT_CONNECT_REJECTED:
    case CCI_EVENT_RECV:
    {
        uint64_t            bits, ignore;
        cci__dev_t          *dev = ep->dev;
        portals_dev_t       *pdev = dev->priv;
        ptl_process_id_t    pid_any=PORTALS_WILDCARD;
        portals_am_buffer_t *am;

        rx = container_of(evt, portals_rx_t, evt);
        am = rx->am;

        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_HEAD(&pep->idle_rxs, rx, entry);
        am->refcnt--;
        if (am->refcnt == 0 && !am->active) {
            ptl_md_t    md;

            /* all non-RMA messages place the endpoint ID in the upper 32 bits */
            bits = ((ptl_match_bits_t) pep->id) << PORTALS_EP_SHIFT;

            /* and ignore the lower 32 bits */
            ignore = (((ptl_match_bits_t) 1) << PORTALS_EP_SHIFT) - 1;

            md.start=    am->buffer;
            md.length=   am->length;
            md.user_ptr =am;
            md.max_size= dev->device.max_send_size;
            md.threshold=PTL_MD_THRESH_INF;
            md.eq_handle=pep->eqh;
            md.options  =PTL_MD_OP_PUT;
            md.options |=PTL_MD_TRUNCATE;
            md.options |=PTL_MD_MAX_SIZE;
            md.options |=PTL_MD_EVENT_START_DISABLE;
            iRC = PtlMEMDAttach(pdev->niHandle,
                                pdev->table_index,
                                pid_any,
                                bits,
                                ignore,
                                PTL_RETAIN,
                                PTL_INS_AFTER,
                                md,
                                PTL_RETAIN,
                                &am->meh,
                                &am->mdh);
            if (iRC != PTL_OK) {
                //FIXME
                debug(CCI_DB_WARN, "PtlMEMDAttach() returned %s", ptl_err_str[iRC]);
                abort();
            }
            am->active = 1;
        }
        pthread_mutex_unlock(&ep->lock);
        break;
    }
    default:
        /* TODO */
        break;
    }

    CCI_EXIT;

    return CCI_SUCCESS;
}


/* Portals assumes reliability (retransmission) so we do not ahve to.
 * A put generates up to four events on the initiator:
 *   send_start, send_end, ack, and unlink.
 *
 * For unreliable connections, we always buffer and completion is when
 * we return. We ignore send_start and disable ack. We need send_end
 * but only to return the tx to idle_txs (no CCI event).
 *
 * For reliable connections, we buffer unless CCI_FLAG_NO_COPY is set.
 * We disable send_start and send_end and we request an ack, which will
 * trigger our CCI event.
 */
static int portals_send(
    cci_connection_t       *connection, 
    void                   *header_ptr,
    uint32_t               header_len, 
    void                   *data_ptr,
    uint32_t               data_len, 
    void                   *context,
    int                    flags ) {

    int                    ret          = CCI_SUCCESS;
    int                    is_reliable  = 0;
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

    if (!data_ptr && data_len) {
        CCI_EXIT;
        return CCI_EINVAL;
    }

    if (header_len + data_len > connection->max_send_size) {
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

    /* setup generic CCI event */
    tx->evt.conn = conn;
    tx->evt.ep = ep;
    tx->evt.event.type = CCI_EVENT_SEND;
    tx->evt.event.info.send.connection = connection;
    tx->evt.event.info.send.context = context;
    tx->evt.event.info.send.status = CCI_SUCCESS; /* for now */

    /* pack match bits */
    bits = ((ptl_match_bits_t) pconn->peer_ep_id) << PORTALS_EP_SHIFT;
    bits |= ((ptl_match_bits_t) header_len) << 27;
    bits |= ((ptl_match_bits_t) data_len) << 11;
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
    if (header_len)
        memcpy(tx->buffer, header_ptr, header_len);
    if (data_len)
        memcpy(tx->buffer + header_len, data_ptr, data_len);

    ret = PtlPutRegion(tx->mdh,                 /* Handle to MD */
                       0,                       /* local offset */
                       header_len + data_len,   /* length */
                       ack,                     /* ACK disposition */
                       pconn->idp,              /* target port */
                       pdev->table_index,       /* table entry to use */
                       0,                       /* access entry to use */
                       bits,                    /* match bits */
                       0,                       /* remote offset */
                       pconn->peer_conn);       /* hdr_data */
    debug(CCI_DB_MSG,
             "%s: (%d,%d) table %d: posted:"
             " ret=%s len=%d\n", __func__, pconn->idp.nid, pconn->idp.pid,
                                 pdev->table_index, ptl_err_str[ret], tx->len );
    if (flags & CCI_FLAG_BLOCKING && is_reliable) {
        ptl_event_t event;

        do {
            ret = PtlEQGet(pep->eqh, &event);
            if (!(ret == PTL_OK || ret == PTL_EQ_DROPPED))
                continue;

            if (event.md_handle == tx->mdh) {
                assert(event.type == PTL_EVENT_ACK);
                if (event.ni_fail_type != PTL_NI_OK)
                    tx->evt.event.info.send.status = CCI_ERROR;
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
                pthread_mutex_unlock(&ep->lock);
                break;
            } else {
                /* queue for cci_get_event() */
                /* TODO */
            }
        } while (1);
    }

    CCI_EXIT;
    return ret;
}


// Todo
static int portals_sendv(
     cci_connection_t      *connection, 
     void                  *header_ptr,
     uint32_t              header_len, 
     char                  **data_ptrs,
     int                   *data_lens,
     uint8_t               segment_cnt,
     void                  *context,
     int                   flags ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
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
    md.options  |= PTL_MD_EVENT_END_DISABLE;    /* we only want the ACK */
    md.options  |= PTL_MD_MANAGE_REMOTE;
    md.user_ptr  = handle;

    iRC = PtlMEMDAttach(pdev->niHandle,
                        pdev->table_index,
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
                 iRC = CCI_ENOMEM;;
                 break;

            case PTL_SEGV:         /* This one should not happen */
                 iRC = CCI_EINVAL;;
                 break;

            default:               /* Undocumented portals error */
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
            ret = CCI_SUCCESS;
            handle->refcnt--;
            if (handle->refcnt == 0) {
                TAILQ_REMOVE(&pep->handles, handle, entry);
                memset(handle, 0, sizeof(*handle));
                free(handle);
            }
            break;
        }
    }
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return ret;
}


static int portals_rma(cci_connection_t *connection, 
                       void *header_ptr, uint32_t header_len, 
                       uint64_t local_handle, uint64_t local_offset, 
                       uint64_t remote_handle, uint64_t remote_offset,
                       uint64_t data_len, void *context, int flags)
{
    int                     ret     = CCI_ERR_NOT_IMPLEMENTED;
    cci__ep_t               *ep     = NULL;
    cci__dev_t              *dev    = NULL;
    cci__conn_t             *conn   = NULL;
    portals_ep_t            *pep    = NULL;
    portals_dev_t           *pdev   = NULL;
    portals_conn_t          *pconn  = NULL;
    portals_rma_handle_t    *local  = (portals_rma_handle_t *)((uintptr_t)local_handle);
    portals_rma_handle_t    *h      = NULL;
    portals_rma_op_t        *rma_op = NULL;

    CCI_ENTER;

    if (!pglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    if (header_len > 32) {
        debug(CCI_DB_MSG, "%s: header_len %d > 32", __func__, header_len);
        CCI_EXIT;
        return CCI_EINVAL;
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

    pthread_mutex_lock(&ep->lock);
    TAILQ_FOREACH(h, &pep->handles, entry) {
        if (h == local) {
            local->refcnt++;
            break;
        }
    }
    pthread_mutex_unlock(&ep->lock);

    if (h != local) {
        debug(CCI_DB_INFO, "%s: invalid endpoint for this RMA handle", __func__);
        CCI_EXIT;
        return CCI_EINVAL;
    }

    rma_op = calloc(1, sizeof(*rma_op));
    if (!rma_op) {
        pthread_mutex_lock(&ep->lock);
        local->refcnt--;
        /* FIXME check if refcnt == 0 and free */
        pthread_mutex_unlock(&ep->lock);
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    rma_op->data_len = data_len;
    rma_op->local_handle = local_handle;
    rma_op->local_offset = local_offset;
    rma_op->remote_handle = remote_handle;
    rma_op->remote_offset = remote_offset;
    rma_op->id = ++(pconn->rma_id);
    rma_op->completed = 0;
    rma_op->status = CCI_SUCCESS; /* for now */
    rma_op->context = context;
    rma_op->flags = flags;
    rma_op->header_len = (uint8_t) header_len;
    rma_op->tx = NULL;

    rma_op->evt.event.type = CCI_EVENT_SEND;
    rma_op->evt.event.info.send.connection = connection;
    rma_op->evt.event.info.send.context = context;
    rma_op->evt.event.info.send.status = CCI_SUCCESS; /* for now */
    rma_op->evt.ep = ep;
    rma_op->evt.conn = conn;
    rma_op->evt.priv = rma_op;

    if (header_len)
        memcpy(rma_op->header, header_ptr, header_len);

    TAILQ_INSERT_TAIL(&local->rma_ops, rma_op, hentry);

    if (flags & CCI_FLAG_WRITE) {
        ret = PtlPutRegion(local->mdh,              /* Handle to MD */
                           local_offset,            /* local offset */
                           data_len,                /* length */
                           PTL_ACK_REQ,             /* ACK disposition */
                           pconn->idp,              /* target port */
                           pdev->table_index,       /* table entry to use */
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
        goto out;
    }

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&pconn->rmas, rma_op, rmas);
    TAILQ_INSERT_TAIL(&pep->rma_ops, rma_op, entry);
    pthread_mutex_unlock(&ep->lock);

    /* TODO handle flags & BLOCKING */

out:
    CCI_EXIT;
    return ret;
}


// Todo
static void portals_recvfrom_ep(
    cci__ep_t              *ep ) {

    ptl_event_t          event;

    return;

    return;
    portals_events(&event);
//  printf("In portals_recvfrom_ep\n");
    //sleep(2);
    return;
}


// Todo
static void portals_recvfrom_lep(
    cci__lep_t             *lep ) {

    int                  iRC;
    ptl_event_t          event;
    cci__crq_t           *crq;

    return;

    return;
    iRC=portals_events(&event);
    if(!iRC) {                               /* Got an event */

        cci_device_t **remote;

        remote=calloc( 1, sizeof(cci_device_t * ) );
        remote[0]=calloc( 1, sizeof(cci_device_t));
        remote[0]->name=calloc( 1, 24 );
        sprintf( (char *)remote[0]->name, "port://%d,%d",
                 event.initiator.nid, event.initiator.pid );
        crq=calloc( 1, sizeof(cci__crq_t) );
        crq->conn_req.devices_cnt=1;
        *((cci_device_t ***)&(crq->conn_req.devices))=remote;
        pthread_mutex_lock(&lep->lock);
        TAILQ_INSERT_HEAD( &lep->crqs, crq, entry );
        pthread_mutex_unlock(&lep->lock);
        fprintf( stderr, "In portals_recvfrom_lep:  added crq  "
                 "remote->name=\"%s\"\n", remote[0]->name );
    } else {
        fprintf( stderr, "In portals_recvfrom_lep  lep=%p\n", lep );
    }
    return;
}


static inline void portals_progress_dev(
    cci__dev_t             *dev ) {

    int                    have_token= 0;
    portals_dev_t          *pdev;
    cci__ep_t              *ep;
    cci__lep_t             *lep;

    CCI_ENTER;

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
        portals_recvfrom_ep(ep);
        portals_get_event_ep(ep);
    }
    TAILQ_FOREACH( lep, &dev->leps, dentry ) {
        lep->dev=dev;
        portals_recvfrom_lep(lep);
        portals_get_event_lep(lep);
    }

    pthread_mutex_lock(&dev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&dev->lock);

    CCI_EXIT;
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
}


static void portals_handle_conn_request(cci__lep_t *lep, ptl_event_t event)
{
    cci__crq_t      *crq    = event.md.user_ptr;
    cci__svc_t      *svc    = lep->svc;
    portals_crq_t   *pcrq   = crq->priv;
    portals_conn_request_t  *cr = pcrq->buffer;

    CCI_ENTER;

    *((cci_device_t ***) &(crq->conn_req.devices)) = (cci_device_t **) pglobals->devices;
    crq->conn_req.devices_cnt = pglobals->count;
    crq->conn_req.data_len = (event.match_bits >> 16) & 0xFFFF;
    crq->conn_req.data_ptr = pcrq->buffer + 12;
    crq->conn_req.attribute = (event.match_bits >> 8) & 0xFF;

    pcrq->idp = event.initiator;
    pcrq->mss = cr->max_send_size;
    pcrq->max_recv_buffer_count = cr->max_recv_buffer_count;
    pcrq->client_id = cr->client_ep_id;
    pcrq->client_conn = event.hdr_data;

    debug(CCI_DB_CONN, "%s: from %d,%d client_id=%d client_conn=0x%llx",
          __func__, pcrq->idp.nid, pcrq->idp.pid, pcrq->client_id,
          (unsigned long long) pcrq->client_conn);

    pthread_mutex_lock(&svc->lock);
    TAILQ_INSERT_TAIL(&svc->crqs, crq, entry);
    pthread_mutex_unlock(&svc->lock);

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

    debug(CCI_DB_CONN, "accept->server_ep_id = %u", accept->server_ep_id);
    debug(CCI_DB_CONN, "accept->max_send_size = %u", accept->max_send_size);
    debug(CCI_DB_CONN, "accept->max_recv_buffer_count = %u", accept->max_recv_buffer_count);
    debug(CCI_DB_CONN, "accept->server_conn_upper = 0x%x", accept->server_conn_upper);
    debug(CCI_DB_CONN, "accept->server_conn_lower = 0x%x", accept->server_conn_lower);

    /* do we need to unlink this buffer? */
    if (am->length - (pevent.offset + pevent.mlength) < dev->device.max_send_size) {
        PtlMEUnlink(am->meh);
        am->active = 0;
        debug((CCI_DB_INFO|CCI_DB_CONN), "%s: unlinking active message buffer", __func__);
        if (pep->am[0].active == 0 && pep->am[1].active == 0)
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
    evt->event.info.other.context = pconn->tx->evt.event.info.other.context;

    if (pevent.mlength == sizeof(*accept)) {
        /* accept */

        conn->connection.max_send_size = accept->max_send_size;
        pconn->peer_ep_id = accept->server_ep_id;
        pconn->peer_conn = ((uint64_t)accept->server_conn_upper) << 32;
        pconn->peer_conn |= (uint64_t)accept->server_conn_lower;

        evt->event.type = CCI_EVENT_CONNECT_SUCCESS;
        evt->event.info.other.u.connect.connection = &conn->connection;

        debug(CCI_DB_CONN, "%s: recv'd accept peer_ep_id=%u", __func__, pconn->peer_ep_id);
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
    am->refcnt++;
    TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
    TAILQ_INSERT_HEAD(&pep->idle_txs, pconn->tx, dentry);
    pconn->tx = NULL;
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;

    return;
}

static void portals_handle_active_msg(cci__ep_t *ep, ptl_event_t pevent)
{
    portals_ep_t    *pep    = ep->priv;
    portals_rx_t    *rx     = NULL;
    cci__evt_t      *evt    = NULL;
    cci__dev_t      *dev    = ep->dev;
    portals_am_buffer_t *am = pevent.md.user_ptr;

    CCI_ENTER;

    /* do we need to unlink this buffer? */
    if (am->length - (pevent.offset + pevent.mlength) < dev->device.max_send_size) {
        PtlMEUnlink(am->meh);
        am->active = 0;
        debug((CCI_DB_INFO|CCI_DB_MSG), "%s: unlinking active message buffer", __func__);
        if (pep->am[0].active == 0 && pep->am[1].active == 0)
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

    *((uint32_t *)&evt->event.info.recv.header_len) =
        (uint32_t) ((pevent.match_bits >> 27) & 0x1F);
    *((uint32_t *)&evt->event.info.recv.data_len) =
        (uint32_t) ((pevent.match_bits >> 11) & 0xFFFF);
    if (evt->event.info.recv.header_len)
        *((void **)&evt->event.info.recv.header_ptr) = pevent.md.start + pevent.offset;
    else
        *((void **)&evt->event.info.recv.header_ptr) = NULL;
    if (evt->event.info.recv.data_len)
        *((void **)&evt->event.info.recv.data_ptr) =
            pevent.md.start + pevent.offset + evt->event.info.recv.header_len;
    else
        *((void **)&evt->event.info.recv.data_ptr) = NULL;

    debug(CCI_DB_MSG, "%s: recv'd hdr len=%d ptr=%p data len=%d ptr=%p",
          __func__, evt->event.info.recv.header_len,
          evt->event.info.recv.header_ptr,
          evt->event.info.recv.data_len,
          evt->event.info.recv.data_ptr);

    /* queue event on endpoint's completed event queue */

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
    am->refcnt++;
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return;
}

static void portals_get_event_ep(cci__ep_t *ep)
{
    int             ret     = CCI_SUCCESS;
    int             count   = 0;
    int             have_token   = 0;
    portals_ep_t    *pep    = ep->priv;
    ptl_event_t     event;

    CCI_ENTER;

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
        CCI_EXIT;
        return;
    }

again:
    ret = PtlEQGet(pep->eqh, &event);
    if (!(ret == PTL_OK || ret == PTL_EQ_DROPPED)) {
        goto out;
    }
    count++;

    if (ret == PTL_EQ_DROPPED)
        debug(CCI_DB_WARN, "portals dropped one or more events");

    debug(CCI_DB_INFO, "%s: got portals %s event", __func__, ptl_event_str[event.type]);
    switch (event.type) {
    case PTL_EVENT_SEND_START:
        debug((CCI_DB_WARN|CCI_DB_INFO), "we missed disabling a portals send_start");
        break;
    case PTL_EVENT_SEND_END:
    {
        portals_msg_type_t msg_type = event.match_bits & 0x3;
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
            /* queue on idle_txs */
            pthread_mutex_lock(&ep->lock);
            TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
            pthread_mutex_unlock(&ep->lock);
            break;
        default:
            debug(CCI_DB_INFO, "we missed disabling a portals send_end for "
                  "msg_type %d", tx->msg_type);
            break;
        }
        
        break;
    }
    case PTL_EVENT_PUT_START:
        debug(CCI_DB_INFO, "we missed disabling a put_start");
        break;
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
            portals_msg_oob_type_t oob_type = (uint32_t)((event.match_bits >> 2) & 0x3);

            switch (oob_type) {
                case PORTALS_MSG_OOB_CONN_REPLY:
                portals_handle_conn_reply(ep, event);
                break;
            default:
                debug(CCI_DB_INFO, "missed oob type %d", oob_type);
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
        break;
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

        switch (msg_type) {
        case PORTALS_MSG_SEND:
            /* a reliable msg completed, generate CCI event */

            tx = event.md.user_ptr;

            /* queue on ep->evts unless SILENT */
            if (tx->flags & CCI_FLAG_SILENT) {
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&pep->idle_txs, tx, dentry);
                pthread_mutex_unlock(&ep->lock);
            } else {
                pthread_mutex_lock(&ep->lock);
                TAILQ_INSERT_HEAD(&ep->evts, &tx->evt, entry);
                pthread_mutex_unlock(&ep->lock);
            }
            break;
        case PORTALS_MSG_RMA_WRITE:
            handle = event.md.user_ptr;
            TAILQ_FOREACH_SAFE(ro, &handle->rma_ops, hentry, tmp) {
                portals_conn_t *pconn = ro->evt.conn->priv;
                if (event.match_bits == (ro->remote_handle | PORTALS_MSG_RMA_WRITE) &&
                    event.initiator.nid == pconn->idp.nid &&
                    event.initiator.pid == pconn->idp.pid &&
                    event.rlength == ro->data_len &&
                    event.offset == ro->remote_offset) {

                    TAILQ_REMOVE(&handle->rma_ops, ro, hentry);
                    rma_op = ro;
                    break;
                }
            }

            if (rma_op->header_len) {
                /* send remote completion msg */
                /* TODO */
            } else {
                if (rma_op->flags & CCI_FLAG_SILENT) {
                    portals_conn_t *pconn = rma_op->evt.conn->priv;
                    portals_rma_handle_t *local = (void *)rma_op->local_handle;

                    /* we are done, cleanup */
                    pthread_mutex_lock(&ep->lock);
                    local->refcnt--;
                    /* FIXME check for refcnt == 0 */
                    TAILQ_REMOVE(&pep->rma_ops, rma_op, entry);
                    TAILQ_REMOVE(&pconn->rmas, rma_op, rmas);
                    pthread_mutex_unlock(&ep->lock);
                    free(rma_op);
                } else {
                    /* we are done, issue completion */
                    pthread_mutex_lock(&ep->lock);
                    TAILQ_INSERT_HEAD(&ep->evts, &rma_op->evt, entry);
                    pthread_mutex_unlock(&ep->lock);
                }
            }
            break;
        default:
            debug(CCI_DB_INFO, "we missed disabling a portals ack for "
                  "msg_type %d", tx->msg_type);
            break;
        }
        break;
    }
    case PTL_EVENT_UNLINK:
        debug(CCI_DB_WARN, "unlink event");
        break;
    default:
        debug(CCI_DB_INFO, "unexpected portals event %d", event.type);
        break;
    }
    if (count < 4) goto again;

out:
    pthread_mutex_lock(&ep->lock);
    pep->in_use = 0;
    pthread_mutex_unlock(&ep->lock);
    return;
}

static void portals_get_event_lep(cci__lep_t *lep)
{
    int             ret     = CCI_SUCCESS;
    portals_ep_t    *plep   = lep->priv;
    ptl_event_t     event;

    if (!plep)
        return;

    ret = PtlEQGet(plep->eqh, &event);
    if (!(ret == PTL_OK || ret == PTL_EQ_DROPPED)) {
        return;
    }

    if (ret == PTL_EQ_DROPPED)
        debug(CCI_DB_INFO, "portals dropped one or more events");

    switch (event.type) {
    case PTL_EVENT_PUT_END:
      {
        portals_msg_type_t  type;
        uint64_t            a;

        /* incoming msg - is it a OOB msg? */
        portals_parse_match_bits(event.match_bits, &type, &a);

        switch (type) {
        default:
            debug(CCI_DB_WARN, "ignoring incoming %d msg on listening endpoint", type);
            break;
        case PORTALS_MSG_OOB:
            {
                portals_msg_oob_type_t oob_type = (a & 0xF) >> 2;

                switch (oob_type) {
                    case PORTALS_MSG_OOB_CONN_REQUEST:
                        portals_handle_conn_request(lep, event);
                        break;
                    default:
                        debug(CCI_DB_INFO, "ignoring incoming oob %d msg", oob_type);
                        break;
                }
            }
            break;
        }
        break;
      }
    case PTL_EVENT_ACK:
        /* reject completed */
        break;
    default:
        debug(CCI_DB_INFO, "unexpected portals event %d", event.type);
        break;
    }
    /* TODO unlink md and relink? */
    return;
}

static int portals_events(
    ptl_event_t            *event ) {

    int                    iRC;
    int                    id;
    const cci_device_t     **devices;
    cci__dev_t             *dev;
    portals_dev_t          *pdev;
    ptl_handle_eq_t        eqh[2];
    //portals_msg_type_t     type;
    //uint8_t                a;
    //uint16_t               b;
    //uint32_t               c;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return 0;
    }

    for( devices=pglobals->devices; *devices!=NULL; devices++ ) {

        dev=container_of( devices, cci__dev_t, device );
        pdev=dev->priv;

        //eqh[0]=pdev->eqhSend;
        //eqh[1]=pdev->eqhRecv;

        iRC=PtlEQPoll( eqh, 2, 10, event, &id );
        if( iRC==PTL_OK ) {

            switch( event->type ) {

                case PTL_EVENT_SEND_START:
                     fprintf( stderr, "PTL_EVENT_SEND_START\n" );
                     break;;

                case PTL_EVENT_SEND_END:
                     fprintf( stderr, "PTL_EVENT_SEND_END "
                              " mlength=%lld  rlength=%lld\n",
                              event->mlength, event->rlength );
                     break;;

                case PTL_EVENT_PUT_START:
                     fprintf( stderr, "PTL_EVENT_PUT_START\n" );
                     break;;

                case PTL_EVENT_PUT_END:
                     fprintf( stderr, "PTL_EVENT_PUT_END "
                              " mlength=%lld  rlength=%lld\n",
                              event->mlength, event->rlength );
                     fprintf( stderr, "md.length=%lld\n",
                              event->md.length );
                     //portals_parse_header( event->md.start, &type,
                                           //&a, &b, &c );
                     //fprintf( stderr,
                              //"Got buffer: type=%d a=%d b=%d c=%d\n",
                              //type, a, b, c );
                     
                     break;;

                case PTL_EVENT_ACK:
                     fprintf( stderr, "PTL_EVENT_ACK  mlength=%lld "
                              " rlength=%lld\n",
                              event->mlength, event->rlength );
                     break;;

                default:
                     fprintf( stderr, "Unexpected event\n" );
                     break;;
            }
        }
    }
    return iRC;
}
