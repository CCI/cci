/*
 *; Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "cci.h"
#include "plugins/core/core.h"
#include "core_portals.h"

volatile int shut_down = 0;
portals_globals_t *pglobals=NULL;


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
#if 0
static int portals_sendto(           cci_os_handle_t      portals,
                                     ptl_handle_eq_t      eqh,
                                     void                 *buf,
                                     int                  len,
                                     const ptl_process_id_t idp,
                                     const ptl_pt_index_t pt_index );
#endif
static int portals_events(           ptl_event_t          *event );


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
    pthread_t              tid;
    cci_device_t           **ds;
    cci__dev_t             *dev;
    ptl_interface_t        ifID;
    ptl_ni_limits_t        niLimit;
    ptl_handle_ni_t        niHandle;
    //ptl_handle_eq_t        eqhSend;
    //ptl_handle_eq_t        eqhRecv;

    CCI_ENTER;

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

#if 0
    /* Create cq for each endpoint */

/*
 * Step 5.  Create event queues for notifications.  Hint:  OMPI uses
 *          two EQs (sends, default depth 8192; receives default depth
 *          16384).  Note that total must not exceed niLimit.max_eqs
 *          (currently 65534).
 */
    iRC=PtlEQAlloc( niHandle, PORTALS_EQ_TX_CNT, PTL_EQ_HANDLER_NONE,
                    &eqhSend );
    if( iRC!=PTL_OK ) {

        switch(iRC) {

            case PTL_NO_INIT:      /* Portals library issue */
                 return CCI_ENODEV;;

            case PTL_NI_INVALID:   /* Bad NI Handle */
                 return CCI_ENODEV;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 return CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 return CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 return CCI_ERROR;
        }
    }
    fprintf( stderr, "Allocated Send EQ\n" );

    iRC=PtlEQAlloc( niHandle, PORTALS_EQ_RX_CNT, PTL_EQ_HANDLER_NONE,
                    &eqhRecv );
    if( iRC!=PTL_OK ) {

        switch(iRC) {

            case PTL_NO_INIT:      /* Portals library issue */
                 return CCI_ENODEV;;

            case PTL_NI_INVALID:   /* Bad NI Handle */
                 return CCI_ENODEV;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 return CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 return CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 return CCI_ERROR;
        }
    }
    fprintf( stderr, "Allocated Recv EQ\n" );
#endif


/*
 * Start searching global configuration for portals devices.
 */
    iReject=1;
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char         **arg;
        cci_device_t       *device;
        portals_dev_t      *pdev;
        //cci__lep_t         *lep;
        //cci__crq_t         *crq;

/*      Reject until portals driver found in configuration. */
        if(strcmp( "portals", dev->driver )) continue;

        TAILQ_INIT(&dev->leps);
/*
        TAILQ_FOREACH( lep, &dev->leps, dentry ) {
            TAILQ_FOREACH( crq, &lep->crqs, entry ) {
                crq->conn_req=NULL;
            }
        }
*/
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
        //pdev->eqhSend=eqhSend;
        //pdev->eqhRecv=eqhRecv;
        PtlGetId( niHandle, &pdev->idp );
        pdev->max_mes=niLimit.max_mes;
        pdev->max_mds=niLimit.max_mds;
        pdev->max_eqs=niLimit.max_eqs;
        pdev->max_ac_index=niLimit.max_ac_index;
        pdev->max_pt_index=niLimit.max_pt_index;
        pdev->max_md_iovecs=niLimit.max_md_iovecs;
        pdev->max_me_list=niLimit.max_me_list;
        pdev->max_getput_md=niLimit.max_getput_md;
        fprintf( stdout, "My portals ID is: (%10d, %5d).\n",
                 (pdev->idp).nid, (pdev->idp).pid );
        fprintf( stdout, "My portals limits are: max_mes=%d\n",
                 pdev->max_mes );
        fprintf( stdout, "                       max_mds=%d\n",
                 pdev->max_mds );
        fprintf( stdout, "                       max_eqs=%d\n",
                 pdev->max_eqs );
        fprintf( stdout, "                       max_ac_index=%d\n",
                 pdev->max_ac_index );
        fprintf( stdout, "                       max_pt_index=%d\n",
                 pdev->max_pt_index );
        fprintf( stdout, "                       max_md_iovecs=%d\n",
                 pdev->max_md_iovecs );
        fprintf( stdout, "                       max_me_list=%d\n",
                 pdev->max_me_list );
        fprintf( stdout, "                       max_getput_md=%d\n",
                 pdev->max_getput_md );

        ds[pglobals->count]=device;
        pglobals->count++;
        dev->is_up=1;

        /* parse conf_argv */
        for( arg=device->conf_argv; *arg!=NULL; arg++ ) {

           if(!strncmp( "pt_index=", *arg, 9 )) {

               const char *table = *arg + 9;
    
               pdev->table_index= atoi(table);
               fprintf( stderr, "found portals index=%d\n",
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
    iRC=pthread_create( &tid, NULL, portals_progress_thread, NULL );
    if(iRC) {                      /* Failed */

        if(ds){                    /* Free private device */

            cci_device_t  *device;
   
            dev=container_of( device, cci__dev_t, device );
            if(dev->priv)
                free(dev->priv);
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
    fprintf( stdout, "There are %d devices.\n", pglobals->count );

    device=**devices;
    dev=container_of( device, cci__dev_t, device );
    pdev=dev->priv;

    fprintf( stdout, "Got portals ID of: (%10d, %5d).\n",
             pdev->idp.nid, pdev->idp.pid );

    CCI_EXIT;
    return CCI_SUCCESS;
}


// Todo
static int portals_free_devices(
    cci_device_t const     **devices ) {

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    /* tear everything down */

    /* for each device
     *     for each endpoint
     *         for each connection
     *             close conn
     *         for each tx/rx
     *             free it
     *         close portal
     *     for each listening endpoint
     *         remove from service
     *         for each conn_req
     *             free it
     *         close portal
     */

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}

static void portals_get_ep_id(
    portals_dev_t          *pdev,
    uint32_t               *id ) {

    uint32_t               n;
    uint32_t               block;
    uint32_t               offset;
    uint64_t               *b;

    while (1) {

        n=random()%PORTALS_MAX_EP_ID;
        block=n/PORTALS_BLOCK_SIZE;
        offset=n%PORTALS_BLOCK_SIZE;
        b=&pdev->ep_ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*PORTALS_BLOCK_SIZE)+offset;
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

    assert((*b & (1 << offset)) == 1);
    *b &= ~(1 << offset);

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

    (*endpoint)->max_recv_buffer_count=pdev->max_mds;
    ep->max_hdr_size=PORTALS_EP_MAX_HDR_SIZE;
    ep->rx_buf_cnt=PORTALS_EP_RX_CNT;
    ep->tx_buf_cnt=PORTALS_EP_TX_CNT;
    ep->buffer_len=PORTALS_EP_BUF_LEN;
    ep->tx_timeout=0;

    pep=ep->priv;
#if 0
    pep->conn_ids=calloc( PORTALS_NUM_BLOCKS, sizeof(*pep->conn_ids ));
    if(!pep->conn_ids) {

        iRC=CCI_ENOMEM;
        goto out;
    }
#endif

    TAILQ_INIT(&pep->txs);
    TAILQ_INIT(&pep->idle_txs);
    TAILQ_INIT(&pep->rxs);
    TAILQ_INIT(&pep->idle_rxs);

    /* get endpoint id */
    pthread_mutex_lock(&dev->lock);
    portals_get_ep_id(pdev, &pep->id);
    pthread_mutex_unlock(&dev->lock);

    /* create event queue for endpoint */
    iRC=PtlEQAlloc( pdev->niHandle,
                    PORTALS_EP_RX_CNT + PORTALS_EP_TX_CNT,
                    PTL_EQ_HANDLER_NONE,
                    &(pep->eqh) );
    if( iRC!=PTL_OK ) {

        portals_put_ep_id(pdev, pep->id);

        switch(iRC) {

            case PTL_NO_INIT:      /* Portals library issue */
                 return CCI_ENODEV;;

            case PTL_NI_INVALID:   /* Bad NI Handle */
                 return CCI_ENODEV;;

            case PTL_NO_SPACE:     /* Well, well, well */
                 return CCI_ENOMEM;;

            case PTL_SEGV:         /* This one should not happen */
                 return CCI_EINVAL;;

            default:               /* Undocumented portals error */
                 return CCI_ERROR;
        }
    }

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
        TAILQ_INSERT_TAIL( &pep->txs, tx, tentry );
        TAILQ_INSERT_TAIL( &pep->idle_txs, tx, dentry );
    }

    /* all non-RMA messages place the endpoint ID in the upper 32 bits */
    bits = ((ptl_match_bits_t) pep->id) << PORTALS_EP_SHIFT;

    /* and ignore the lower 32 bits */
    ignore = (((ptl_match_bits_t) 1) << PORTALS_EP_SHIFT) - 1;

/*  Creating receive buffers/MDs/MEs. */
    for( i=0; i<ep->rx_buf_cnt; i++ ) {

        portals_rx_t       *rx;
        ptl_md_t           md;

        rx=calloc( 1, sizeof(*rx) );
        if(!rx) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        rx->evt.event.type=CCI_EVENT_RECV;
        rx->evt.ep=ep;
        rx->buffer=calloc(1, ep->buffer_len);
        if(!rx->buffer) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        rx->len=0;
        TAILQ_INSERT_TAIL( &pep->rxs, rx, gentry );
        TAILQ_INSERT_TAIL( &pep->idle_rxs, rx, entry );

        /*  Create the memory descriptor. */
        md.start=    rx->buffer;
        md.max_size= ep->buffer_len;
        md.length=   ep->buffer_len;
        md.threshold=PTL_MD_THRESH_INF;
        md.user_ptr =rx;
        md.eq_handle=pep->eqh;
        md.options  =PTL_MD_OP_PUT;
        md.options |=PTL_MD_OP_GET;
        md.options |=PTL_MD_TRUNCATE;
        md.options |=PTL_MD_EVENT_START_DISABLE;

        iRC=PtlMEAttach( niHandle, pdev->table_index, pid_any, 
                         bits, ignore,
                         PTL_RETAIN, PTL_INS_AFTER, &rx->meh );
        if( iRC!=PTL_OK ) {

            fprintf( stderr, "PtlMEAttach failure\n" );
            // FIXME
            return CCI_ERROR;
        }

        iRC=PtlMDAttach( rx->meh, md, PTL_RETAIN, &rx->mdh );
        if( iRC!=PTL_OK ) {

            switch(iRC) {

                case PTL_NO_INIT:            /* Portals library issue */
                     fprintf( stderr, "Portals library issue\n" );
                     //FIXME
                     return CCI_ENODEV;;

                case PTL_ME_IN_USE:          /* ME in use */
                     fprintf( stderr, "Tried to reuse ME\n" );
                     //FIXME
                     return CCI_ENODEV;;

                case PTL_ME_INVALID:         /* Bad ME handle */
                     fprintf( stderr, "Bad ME handle\n" );
                     //FIXME
                     return CCI_ENODEV;;

                case PTL_MD_ILLEGAL:         /* Bad MD */
                     fprintf( stderr, "Bad MD\n" );
                     //FIXME
                     return CCI_ENODEV;;

                case PTL_EQ_INVALID:         /* Bad EQ */
                     fprintf( stderr, "Bad EQ\n" );
                     //FIXME
                     return CCI_ENODEV;;

                case PTL_NO_SPACE:           /* Well, well, well */
                     fprintf( stderr, "Out of memory\n" );
                     //FIXME
                     return CCI_ENOMEM;;

                case PTL_SEGV:               /* This shouldn't happen */
                     fprintf( stderr, "Oops!\n" );
                     //FIXME
                     return CCI_EINVAL;;

                default:                     /* Undocumented error */
                     fprintf( stderr, "Failed with iRC=%d\n", iRC );
                     //FIXME
                     return CCI_ERROR;
            }
        }
    }
    fprintf( stdout, "Allocated %d buffers\n", ep->rx_buf_cnt );

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);
    if(pep) {

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
            if(rx->buffer)
                free(rx->buffer);
            free(rx);
        }

        if (pep->id)
            portals_put_ep_id(pdev, pep->id);

        free(pep);
    }

    if(ep)
        free(ep);
    *endpoint=NULL;

    CCI_EXIT;
    return iRC;
}


// Todo
static int portals_destroy_endpoint(
    cci_endpoint_t         *endpoint ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
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
    fprintf( stderr, "Binding server address (%d,%d) table_index %d\n",
             pdev->idp.nid, pdev->idp.pid, pdev->table_index );

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

    /* alloc portal for each cci__crq_t */
    TAILQ_FOREACH( crq, &lep->crqs, entry ) {

        if(!(crq->priv=calloc( 1, sizeof(*pcrq) ))) {

            iRC=CCI_ENOMEM;
            goto out;
        }

        len=CCI_CONN_REQ_LEN+0; //FIXME
        pcrq=crq->priv;
        if( !(pcrq->buffer=calloc( 1, len )) ) {

            iRC=CCI_ENOMEM;
            goto out;
        }
    }

    TAILQ_INIT(&lep->passive);

    /* create OS handle */
    /* TODO */

    lep->priv=plep;

    fprintf( stdout, "Successfully bound portals\n" );
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


// Todo
static int portals_unbind(
    cci_service_t          *service,
    cci_device_t           *device ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


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
    //sleep(2);
    //fprintf( stderr, "Exit portals_get_conn_req\n" );
    return iRC;
}


#if 0
static void portals_get_conn_id(
    portals_ep_t           *ep,
    uint32_t               *id ) {

    uint32_t               n;
    uint32_t               block;
    uint32_t               offset;
    uint64_t               *b;

    while (1) {

        n=random()%PORTALS_NUM_BLOCKS;
        block=n/PORTALS_BLOCK_SIZE;
        offset=n%PORTALS_BLOCK_SIZE;
        b=&ep->conn_ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*PORTALS_BLOCK_SIZE)+offset;
            break;
        }
    }
    return;
}
#endif

// Todo
static int portals_accept(
    cci_conn_req_t         *conn_req, 
    cci_endpoint_t         *endpoint, 
    cci_connection_t       **connection ) {

    cci__conn_t            *conn;
    cci_connection_t       *pconn;
    cci_device_t           **local;

    CCI_ENTER;

    pconn=calloc( 1, sizeof(cci_connection_t) );
    pconn->max_send_size=PORTALS_EP_BUF_LEN;
    pconn->endpoint=endpoint;
    *connection=pconn;

    conn=container_of( *connection, cci__conn_t, connection );
    conn->uri=calloc( 1, 24 );
    strcpy( (char *)conn->uri,
            (*((cci_device_t ***)&((*conn_req).devices)))[0]->name );
    conn_req->devices_cnt=0;
    local=*((cci_device_t ***)&((*conn_req).devices));
    free((char *)local[0]->name);
    free(local[0]);
    free(local);
   
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
    ptl_md_iovec_t         iov[2];
    ptl_md_t               md;

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
    tx->msg_type=PORTALS_MSG_OOB_CONN_REQUEST;
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
    bits |= ((ptl_match_bits_t) data_len) << 16;
    bits |= ((ptl_match_bits_t) attribute) << 8;
    bits |= (ptl_match_bits_t) PORTALS_MSG_OOB;

    /* pack the payload */
    conn_request.msg_oob_type = PORTALS_MSG_OOB_CONN_REQUEST;
    conn_request.max_send_size = connection->max_send_size;
    conn_request.max_recv_buffer_count = endpoint->max_recv_buffer_count;
    conn_request.client_ep_id = pep->id;

    /* prepare memory descriptor */
    memset(&md, 0, sizeof(md));
    md.threshold = PTL_MD_THRESH_INF;
    md.options = PTL_MD_OP_PUT;
    /* disable events - we only want the server's accept|reject */
    md.eq_handle = PTL_EQ_NONE;

    if (data_len) {
        iov[0].iov_base = &conn_request;
        iov[0].iov_len = sizeof(conn_request);
        iov[1].iov_base = data_ptr;
        iov[1].iov_len = data_len;
        md.options |= PTL_MD_IOVEC;
        md.start = iov;
        md.length = 2;
    } else {
        md.start = &conn_request;
        md.length = sizeof(conn_request);
    }
    
    PtlMDBind(pdev->niHandle, md, PTL_RETAIN, &tx->mdh);
    /* FIXME check return */

    iRC = PtlPut(tx->mdh,           /* Handle to MD */
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


// Todo
static int portals_get_event(
    cci_endpoint_t         *endpoint, 
    cci_event_t            **const event,
    uint32_t               flags ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_return_event(
    cci_endpoint_t         *endpoint, 
    cci_event_t            *event ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
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
    ptl_md_t               md;
    ptl_md_iovec_t         iov[2];
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

    /* prepare memory descriptor */
    memset(&md, 0, sizeof(md));
    md.threshold = PTL_MD_THRESH_INF;
    md.options = PTL_MD_OP_PUT;
    md.options |= PTL_MD_EVENT_START_DISABLE; /* we don't care */
    md.eq_handle = pep->eqh;
    md.user_ptr = tx;
    if (is_reliable)
        md.options |= PTL_MD_EVENT_END_DISABLE; /* we just want the ack */
    else
        ack = PTL_NOACK_REQ; /* we need to know when we can reuse the tx */

    /* if unreliable or ! NO_COPY, copy into tx->buffer */
    if (!(flags & CCI_FLAG_NO_COPY) || !is_reliable) {
        if (header_len) {
            memcpy(tx->buffer, header_ptr, header_len);
            header_ptr = tx->buffer;
        }
        if (data_len) {
            memcpy(tx->buffer + header_len, data_ptr, data_len);
            data_ptr = tx->buffer + header_len;
        }
    }

    if (header_len && data_len) {
        iov[0].iov_base = header_ptr;
        iov[0].iov_len = header_len;
        iov[1].iov_base = data_ptr;
        iov[1].iov_len = data_len;
        md.options |= PTL_MD_IOVEC;
        md.start = iov;
        md.length = 2;
    } else if (header_len && !data_len) {
        md.start = header_ptr;
        md.length = header_len;
    } else if (!header_len && data_len) {
        md.start = data_ptr;
        md.length = data_len;
    } else {
        /* else no header or data */
        /* but we need to send 1 byte to ensure it goes */
        md.start = tx->buffer;
        md.length = 1;
    }

    PtlMDBind(pdev->niHandle, md, PTL_RETAIN, &tx->mdh);
    /* FIXME check return */

    /* pack match bits */
    bits = ((ptl_match_bits_t) pconn->peer_ep_id) << PORTALS_EP_SHIFT;
    bits |= ((ptl_match_bits_t) header_len) << 27;
    bits |= ((ptl_match_bits_t) data_len) << 11;
    bits |= (ptl_match_bits_t) PORTALS_MSG_SEND;

    ret = PtlPut(tx->mdh,           /* Handle to MD */
                 ack,               /* ACK disposition */
                 pconn->idp,        /* target port */
                 pdev->table_index, /* table entry to use */
                 0,                 /* access entry to use */
                 bits,              /* match bits */
                 0,                 /* remote offset */
                 pconn->peer_conn); /* hdr_data */
    fprintf( stderr,
             "In portals_send: (%d,%d) table %d: posted:"
             " ret=%d len=%d\n", pconn->idp.nid, pconn->idp.pid,
                                 pdev->table_index, ret, tx->len );

    if (flags & CCI_FLAG_BLOCKING && is_reliable) {
        ptl_event_t event;

        do {
            ret = PtlEQGet(pep->eqh, &event);
            if (ret != PTL_OK)
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


// Todo
static int portals_rma_register(
    cci_endpoint_t         *endpoint,
    cci_connection_t       *connection,
    void                   *start, 
    uint64_t               length,
    uint64_t               *rma_handle ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
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


// Todo
static int portals_rma_deregister(
    uint64_t               rma_handle ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_rma(
     cci_connection_t      *connection, 
     void                  *header_ptr,
     uint32_t              header_len, 
     uint64_t              local_handle,
     uint64_t              local_offset, 
     uint64_t              remote_handle,
     uint64_t              remote_offset,
     uint64_t              data_len,
     void                  *context,
     int                   flags ) {

    CCI_ENTER;
    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static void portals_recvfrom_ep(
    cci__ep_t              *ep ) {

    ptl_event_t          event;

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

    TAILQ_FOREACH( ep, &dev->eps, entry)
        portals_recvfrom_ep(ep);
    TAILQ_FOREACH( lep, &dev->leps, dentry ) {
        lep->dev=dev;
        portals_recvfrom_lep(lep);
    }

    pthread_mutex_lock(&dev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&dev->lock);

    fprintf( stderr, "Exit portals_progress_dev\n");
    CCI_EXIT;
    return;
}

static void *portals_progress_thread(
    void                   *arg ) {

    while(!shut_down) {

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


#if 0
static int portals_sendto(
    cci_os_handle_t        niHandle,
    ptl_handle_eq_t        eqhSend,
    void                   *buf,
    int                    len,
    const ptl_process_id_t idp,
    const ptl_pt_index_t   portals_table ) {

    int                    iRC;
    ptl_handle_md_t        mdHandle;         /* MD handle */
    ptl_match_bits_t       bits;
    ptl_hdr_data_t         hdr;
    ptl_md_t               *pmd;

/*  First, create the memory descriptor. */
    pmd=calloc( 1, sizeof(ptl_md_t) );
    pmd->start=    buf;
    pmd->length=   len;
    pmd->max_size= PORTALS_EP_BUF_LEN;
    pmd->threshold=PTL_MD_THRESH_INF;
    pmd->user_ptr =NULL;
    pmd->eq_handle=eqhSend;
    pmd->options  =PTL_MD_OP_PUT;
    pmd->options |=PTL_MD_OP_GET;
    pmd->options |=PTL_MD_EVENT_START_DISABLE;
//  pmd->options |=PTL_MD_MANAGE_REMOTE;

    iRC=PtlMDBind( niHandle,                 /* Handle to Seastar */
                   *pmd,                     /* Memory descriptor */
                   PTL_RETAIN,               /* MD disposition */
                   &mdHandle );              /* MD Handle (created) */
    fprintf( stderr, "MDBind=%d\n", iRC );

    iRC=PtlPut(    mdHandle,                 /* Handle to MD */
                   PTL_ACK_REQ,              /* ACK disposition */
                   idp,                      /* target port */
                   portals_table,            /* table entry to use */
                   0,                        /* access entry to use */
                   bits,                     /* match bits */
                   0,                        /* remote offset */
                   hdr );                    /* hdr_data */
    fprintf( stderr,
             "In portals_sendto: (%d,%d) table %d: posted:"
             " iRC=%d len=%d\n", idp.nid, idp.pid,
                                 portals_table, iRC, len );

    free(pmd);
    return iRC;
}
#endif

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
