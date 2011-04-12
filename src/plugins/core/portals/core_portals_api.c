/*
 *; Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"
#include <stdio.h>
#include <string.h>
#include "cci.h"
#include "plugins/core/core.h"
#include "core_portals.h"

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

static void portals_progress_sends(  portals_dev_t        *pdev );
static void *portals_progress_thread(void                 *arg );
static inline void portals_progress_dev(
                                     cci__dev_t *dev);
static int portals_sendto(           cci_os_handle_t      portals,
                                     ptl_handle_eq_t      eqh,
                                     void                 *buf,
                                     int                  len,
                                     const ptl_process_id_t idp,
                                     const ptl_pt_index_t pt_index );
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
    ptl_handle_eq_t        eqhSend;
    ptl_handle_eq_t        eqhRecv;

    CCI_ENTER;
printf( "In portals_init\n" );

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


/*
 * Start searching global configuration for portals devices.
 */
    iReject=1;
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char         **arg;
        cci_device_t       *device;
        portals_dev_t      *pdev;
        cci__lep_t         *lep;
        cci__crq_t         *crq;

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

/*      Wired to 256MB for now; need testing for good size. */
        device->max_send_size=268435456;
        device->rate=46000000000;  /* SeaStar2+, 6 ports, bps */
        device->pci.domain=-1;     /* per CCI spec */
        device->pci.bus=-1;        /* per CCI spec */
        device->pci.dev=-1;        /* per CCI spec */
        device->pci.func=-1;       /* per CCI spec */

        if( !(dev->priv=calloc( 1, sizeof(*dev->priv) )) ) {

            free(pglobals->devices);
            free(pglobals);
            pglobals=NULL;
            return CCI_ENOMEM;
        }

        pdev=dev->priv;            /* select private device */
        TAILQ_INIT(&pdev->queued); /* create request queue */
        TAILQ_INIT(&pdev->pending);/* create pending queue */

/*      Create mutex lock for queues. */
        pthread_mutex_init( &pdev->lock, NULL );
        pdev->is_progressing=0;    /* initialize progress flag */

/*      Save off portals ID of device. */
        pdev->niHandle=niHandle;
        pdev->eqhSend=eqhSend;
        pdev->eqhRecv=eqhRecv;
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

    printf("In portals_sterrror\n");
    return NULL;
}


static int portals_get_devices(
    cci_device_t const     ***devices ) {

    cci_device_t const     *device;
    cci__dev_t             *dev;
    portals_dev_t          *pdev;

    CCI_ENTER;
printf( "In portals_get_devices\n" );

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
    ptl_pt_index_t         table_index;
    ptl_handle_eq_t        eqhSend;
    ptl_handle_eq_t        eqhRecv;
    ptl_process_id_t       pid_any=PORTALS_WILDCARD;
    ptl_handle_me_t        meh;
    ptl_handle_md_t        mdh;

    CCI_ENTER;
    fprintf( stderr, "In portals_create_endpoint\n" );

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
    table_index=pdev->table_index;
    eqhSend=pdev->eqhSend;
    fprintf( stderr, "Using table_index=%d\n", table_index );

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
    ep->tx_timeout=PORTALS_EP_TX_TIMEOUT_SEC*1000000;

    pep=ep->priv;
    pep->ids=calloc( PORTALS_NUM_BLOCKS, sizeof(*pep->ids ));
    if(!pep->ids) {

        iRC=CCI_ENOMEM;
        goto out;
    }

    TAILQ_INIT(&pep->txs);
    TAILQ_INIT(&pep->idle_txs);
    TAILQ_INIT(&pep->rxs);
    TAILQ_INIT(&pep->idle_rxs);
    pthread_mutex_init( &pep->lock, NULL );

    for( i=0; i<ep->tx_buf_cnt; i++ ) {

        portals_tx_t       *tx;

        tx=calloc( 1, sizeof(*tx) );
        if(!tx) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        tx->evt.event.type=CCI_EVENT_SEND;
        tx->evt.ep=ep;
        tx->buffer=malloc(ep->buffer_len);
        if(!tx->buffer) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        tx->len=0;
        TAILQ_INSERT_TAIL( &pep->txs, tx, tentry );
        TAILQ_INSERT_TAIL( &pep->idle_txs, tx, dentry );
    }

/*  Creating receive buffers/MDs/MEs. */
    for( i=0; i<ep->rx_buf_cnt; i++ ) {

        portals_rx_t       *rx;
        ptl_md_t           *pmd;

        rx=calloc( 1, sizeof(*rx) );
        if(!rx) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        rx->evt.event.type=CCI_EVENT_RECV;
        rx->evt.ep=ep;
        rx->buffer=malloc(ep->buffer_len);
        if(!rx->buffer) {

            iRC=CCI_ENOMEM;
            goto out;
        }
        rx->len=0;
        TAILQ_INSERT_TAIL( &pep->rxs, rx, gentry );
        TAILQ_INSERT_TAIL( &pep->idle_rxs, rx, entry );
        pmd=calloc( 1, sizeof(ptl_md_t) );

        /*  Create the memory descriptor. */
        pmd->start=    rx->buffer;
        pmd->max_size= ep->buffer_len;
        pmd->length=   ep->buffer_len;
        pmd->threshold=PTL_MD_THRESH_INF;
        pmd->user_ptr =NULL;
        pmd->eq_handle=eqhSend;
        pmd->options  =PTL_MD_OP_PUT;
        pmd->options |=PTL_MD_OP_GET;
        pmd->options |=PTL_MD_TRUNCATE;
        pmd->options |=PTL_MD_EVENT_START_DISABLE;

        iRC=PtlMEAttach( niHandle, table_index, pid_any, 
                         PORTALS_EP_MATCH, PORTALS_EP_IGNORE,
                         PTL_RETAIN, PTL_INS_AFTER, &meh );
        if( iRC!=PTL_OK ) {

            fprintf( stderr, "PtlMEAttach failure\n" );
            return CCI_ERROR;
        }

        iRC=PtlMDAttach( meh, *pmd, PTL_RETAIN, &mdh );
        free(pmd);
        if( iRC!=PTL_OK ) {

            switch(iRC) {

                case PTL_NO_INIT:            /* Portals library issue */
                     fprintf( stderr, "Portals library issue\n" );
                     return CCI_ENODEV;;

                case PTL_ME_IN_USE:          /* ME in use */
                     fprintf( stderr, "Tried to reuse ME\n" );
                     return CCI_ENODEV;;

                case PTL_ME_INVALID:         /* Bad ME handle */
                     fprintf( stderr, "Bad ME handle\n" );
                     return CCI_ENODEV;;

                case PTL_MD_ILLEGAL:         /* Bad MD */
                     fprintf( stderr, "Bad MD\n" );
                     return CCI_ENODEV;;

                case PTL_EQ_INVALID:         /* Bad EQ */
                     fprintf( stderr, "Bad EQ\n" );
                     return CCI_ENODEV;;

                case PTL_NO_SPACE:           /* Well, well, well */
                     fprintf( stderr, "Out of memory\n" );
                     return CCI_ENOMEM;;

                case PTL_SEGV:               /* This shouldn't happen */
                     fprintf( stderr, "Oops!\n" );
                     return CCI_EINVAL;;

                default:                     /* Undocumented error */
                     fprintf( stderr, "Failed with iRC=%d\n", iRC );
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

        if(pep->ids)
            free(pep->ids);
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

    printf("In portals_destroy_endpoint\n");
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
    printf("In portals_bind\n");

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

        len=CCI_CONN_REQ_LEN+PORTALS_CONN_REQ_HDR_LEN;
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

    printf("In portals_unbind\n");
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
    
    if(!pglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    //fprintf( stderr, "Enter In portals_get_conn_req\n" );
    iRC=CCI_ENODEV;
    devices=pglobals->devices;
    dev=container_of(*devices, cci__dev_t, device);
    TAILQ_FOREACH( lep, &dev->leps, dentry ) {

        pthread_mutex_lock(&lep->lock);
        TAILQ_FOREACH( crq, &lep->crqs, entry ) {

            uint32_t i;
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
    sleep(2);
    //fprintf( stderr, "Exit portals_get_conn_req\n" );
    return iRC;
}


static void portals_get_id(
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
        b=&ep->ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*PORTALS_BLOCK_SIZE)+offset;
            break;
        }
    }
    return;
}


static inline uint32_t portals_get_new_seq(void) {

    return ((uint32_t)random()&PORTALS_SEQ_MASK);
}


// Todo
static int portals_accept(
    cci_conn_req_t         *conn_req, 
    cci_endpoint_t         *endpoint, 
    cci_connection_t       **connection ) {

    cci__conn_t            *conn;
    cci_connection_t       *pconn;
    cci_device_t           **local;

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
   
    printf( "In portals_accept  conn->uri=%s\n", conn->uri );
    return CCI_SUCCESS;
}


// Todo
static int portals_reject(
    cci_conn_req_t         *conn_req ) {

    printf("In portals_reject\n");
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


/* The endpoint maintains 256 lists. Hash the portals ID and return the
 * index of the list. We use all six bytes and this is endian agnostic.
 * It evenly disperses large blocks of addresses as well as large ranges
 * of ports on the same address.  */
uint8_t portals_idp_hash(
    ptl_process_id_t       idp ) {

    uint16_t               port;

    port=idp.pid;                            /* pid is 16 bits */
    port^=(idp.nid&0x0000FFFF);              /* lower 16 btis of nid */
    port^=(idp.nid&0xFFFF0000)>>16;          /* upper 16 bits of nid */

    return (port&0x00FF)^((port&0xFF00)>>8);
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

    int                    i;
    int                    iRC;
    cci__ep_t              *ep=NULL;
    cci__dev_t             *dev=NULL;
    cci__conn_t            *conn=NULL;
    portals_ep_t           *pep=NULL;
    portals_dev_t          *pdev=NULL;
    cci_connection_t       *connection=NULL;
    portals_conn_t         *pconn=NULL;
    portals_tx_t           *tx=NULL;
    portals_header_r_t     *hdr_r=NULL;
    cci__evt_t             *evt=NULL;
    cci_event_t            *event=NULL;
    cci_event_other_t      *other=NULL;
    ptl_process_id_t       idp;
    void                   *ptr=NULL;
    struct p_active        *active_list;
    uint32_t               ts=0;
    portals_handshake_t    *hs=NULL;
    CCI_ENTER;

    printf("In portals_connect\n");
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
    TAILQ_INIT(&pconn->tx_seqs);
    TAILQ_INIT(&pconn->acks);

    /* conn->tx_timeout=0  by default */
    connection=&conn->connection;
    connection->attribute=attribute;
    connection->endpoint=endpoint;

    iRC=portals_getaddrinfo( server_uri, &idp );
    if(iRC)
        goto out;

   /* peer will assign id */
    pthread_mutex_init( &pconn->lock, NULL );

    /* get our endpoint and device */
    ep=container_of( endpoint, cci__ep_t, endpoint );
    pep=ep->priv;
    dev=ep->dev;
    pdev=dev->priv;

    connection->max_send_size=dev->device.max_send_size;
    pconn->idp=idp;
    pconn->table_index=pdev->table_index;;
    fprintf( stderr, "Got server address (%d,%d) table_index %d\n",
             idp.nid, idp.pid, pdev->table_index );

    i=portals_idp_hash(idp);
    active_list=&pep->active_hash[i];
    pthread_mutex_lock(&pep->lock);
    TAILQ_INSERT_HEAD( active_list, pconn, entry );
    pthread_mutex_unlock(&pep->lock);

    /* get a tx */
    pthread_mutex_lock(&pep->lock);
    if(!TAILQ_EMPTY(&pep->idle_txs)) {
        tx=TAILQ_FIRST(&pep->idle_txs);
        TAILQ_REMOVE( &pep->idle_txs, tx, dentry );
    }
    pthread_mutex_unlock(&pep->lock);

    if(!tx) {

        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    /* prep the tx */
    tx->msg_type=PORTALS_MSG_CONN_REQUEST;

    evt=&tx->evt;
    evt->ep=ep;
    evt->conn=conn;
    event=&evt->event;
    event->type=CCI_EVENT_CONNECT_SUCCESS; /* for now */

    other=&event->info.other;
    other->context=context;
    other->u.connect.connection=connection;

    /* pack the msg */
    hdr_r=(portals_header_r_t *)tx->buffer;
    portals_get_id( pep, &pconn->id );
    /* FIXME silence -Wall -Werror until it is used */
    if(0)portals_put_id( pep, 0 );
    portals_pack_conn_request( &hdr_r->header, attribute,
                               (uint16_t)data_len, 0 );
    tx->len=sizeof(*hdr_r);
    ptr=tx->buffer+tx->len;

    /* add seq and ack */
    pconn->seq=portals_get_new_seq();
    pconn->seq_pending=pconn->seq-1;
    pconn->last_ack_seq=pconn->seq;
    tx->seq=pconn->seq;
    portals_pack_seq_ts( &hdr_r->seq_ts, tx->seq, ts );

    /* add handshake */
    hs=(portals_handshake_t *)ptr;
    portals_pack_handshake( hs, pconn->id, 0,
                            endpoint->max_recv_buffer_count,
                            connection->max_send_size);

    tx->len+=sizeof(*hs);
    ptr=tx->buffer+tx->len;

    debug( CCI_DB_CONN, 
           "queuing conn_request with seq %u ts %x", tx->seq, ts );

    /* zero even if unreliable */
    tx->last_attempt_us=0ULL;
    tx->timeout_us=0ULL;

    if(data_len)
            memcpy( ptr, data_ptr, data_len );

    tx->len+=data_len;
    assert( tx->len<=ep->buffer_len );

    /* insert at tail of device's queued list */
    dev=ep->dev;
    pdev=dev->priv;

    tx->state=PORTALS_TX_QUEUED;
    pthread_mutex_lock(&pdev->lock);
    TAILQ_INSERT_TAIL( &pdev->queued, tx, dentry );
    pthread_mutex_unlock(&pdev->lock);

    /* try to progress txs */
    fprintf( stderr, "Enter portals_progress_dev\n" );
    portals_progress_dev(dev);
    fprintf( stderr, "Returning from portals_connect\n" );

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

    printf("In portals_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_set_opt(
    cci_opt_handle_t       *handle, 
    cci_opt_level_t        level, 
    cci_opt_name_t         name,
    const void             *val,
    int                    len ) {

    printf("In portals_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_get_opt(
    cci_opt_handle_t       *handle, 
    cci_opt_level_t        level, 
    cci_opt_name_t         name,
    void                   **val,
    int                    *len ) {

    printf("In portals_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_arm_os_handle(
    cci_endpoint_t         *endpoint,
    int                    flags ) {

    printf("In portals_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_get_event(
    cci_endpoint_t         *endpoint, 
    cci_event_t            **const event,
    uint32_t               flags ) {

    //printf("In portals_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_return_event(
    cci_endpoint_t         *endpoint, 
    cci_event_t            *event ) {

    printf("In portals_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_send(
    cci_connection_t       *connection, 
    void                   *header_ptr,
    uint32_t               header_len, 
    void                   *data_ptr,
    uint32_t               data_len, 
    void                   *context,
    int                    flags ) {

    cci__conn_t            *conn;

    conn=container_of( connection, cci__conn_t, connection );
    printf( "In portals_send  conn->uri=\"%s\"\n", conn->uri );
    return CCI_ERR_NOT_IMPLEMENTED;
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

    printf("In portals_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_rma_register(
    cci_endpoint_t         *endpoint,
    cci_connection_t       *connection,
    void                   *start, 
    uint64_t               length,
    uint64_t               *rma_handle ) {

    printf("In portals_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_rma_register_phys(
    cci_endpoint_t         *endpoint, 
    cci_connection_t       *connection,
    cci_sg_t               *sg_list,
    uint32_t               sg_cnt, 
    uint64_t               *rma_handle ) {

    printf("In portals_rma_register_phys\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static int portals_rma_deregister(
    uint64_t               rma_handle ) {

    printf("In portals_rma_deregister\n");
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

    printf("In portals_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


// Todo
static void portals_recvfrom_ep(
    cci__ep_t              *ep ) {

    ptl_event_t          event;

    portals_events(&event);
//  printf("In portals_recvfrom_ep\n");
    sleep(2);
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
        fprintf( stderr, "In portals_recvfrom_lep  lep=%lx\n", lep );
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

    pthread_mutex_lock(&pdev->lock);
    if( pdev->is_progressing==0) {

        pdev->is_progressing=1;
        have_token=1;
    }
    pthread_mutex_unlock(&pdev->lock);

    if(!have_token) {

        CCI_EXIT;
        return;
    }

    portals_progress_sends(pdev);

    TAILQ_FOREACH( ep, &dev->eps, entry)
        portals_recvfrom_ep(ep);
    TAILQ_FOREACH( lep, &dev->leps, dentry ) {
        lep->dev=dev;
        portals_recvfrom_lep(lep);
    }

    pthread_mutex_lock(&pdev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&pdev->lock);

    fprintf( stderr, "Exit portals_progress_dev\n");
    CCI_EXIT;
    return;
}

static void *portals_progress_thread(
    void                   *arg ) {

    while(!pglobals->shutdown) {

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
    portals_msg_type_t     type;
    uint8_t                a;
    uint16_t               b;
    uint32_t               c;

    portals_parse_header( buf, &type, &a, &b, &c );
    fprintf( stderr, "Send buffer: type=%d a=%d b=%d c=%d\n",
             type, a, b, c );

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


static void portals_progress_pending(
    portals_dev_t          *pdev ) {

    int iRC;
    uint64_t               now;
    portals_tx_t           *tx;
    portals_tx_t           *tmp;
    cci__evt_t             *evt;
    cci_event_t            *event;           /* generic CCI event */
    cci_connection_t       *connection;      /* generic CCI connect */
    cci__conn_t            *conn;
    portals_conn_t         *pconn;
    cci__ep_t              *ep;
    portals_ep_t           *pep;
    ptl_handle_ni_t        niHandle;

    CCI_ENTER;

    TAILQ_HEAD( p_idle_txs, portals_tx ) idle_txs=
                                       TAILQ_HEAD_INITIALIZER(idle_txs);
    TAILQ_HEAD( p_evts, cci__evt ) evts=TAILQ_HEAD_INITIALIZER(evts);
    TAILQ_INIT(&idle_txs);
    TAILQ_INIT(&evts);

    now=portals_get_usecs();

    /* This is only for reliable messages.
     * Do not dequeue txs, just walk the list.
     */
    pthread_mutex_lock(&pdev->lock);
    TAILQ_FOREACH_SAFE( tx, &pdev->pending, dentry, tmp ) {

        evt=&(tx->evt);
        conn=evt->conn;
        connection=&conn->connection;
        pconn=conn->priv;
        event=&evt->event;

        ep=container_of( connection->endpoint, cci__ep_t, endpoint );
        pep=ep->priv;

        tx->last_attempt_us=now;             /* need to send it */
        fprintf( stderr, "sending %d msg seq %u\n",
                 portals_msg_type(tx->msg_type), tx->seq );

        niHandle=pdev->niHandle;
        fprintf( stderr, "Sending tx->len=%d\n", tx->len );
        iRC=portals_sendto( niHandle, pdev->eqhSend, tx->buffer,
                            tx->len, pconn->idp, pconn->table_index );
        if( iRC!=0 ) {

            fprintf( stderr, "sendto() failed with %s\n",
                     cci_strerror(errno) );
            continue;
        }

        /* has it timed out? */
        if( PORTALS_U64_LT( tx->timeout_us, now )) {

            /* dequeue */
            TAILQ_REMOVE( &pdev->pending, tx, dentry );

            /* set status and add to completed events */
            switch(tx->msg_type) {

                case PORTALS_MSG_SEND:
                    event->info.send.status=CCI_ETIMEDOUT;
                    break;

                case PORTALS_MSG_CONN_REQUEST: {

                    int i;
                    struct p_active *active_list;

                    event->type=CCI_EVENT_CONNECT_TIMEOUT;
                    if (conn->uri)
                        free((char *)conn->uri);
                    pconn->status=PORTALS_CONN_CLOSING;
                    i=portals_idp_hash(pconn->idp);
                    active_list=&pep->active_hash[i];
                    pthread_mutex_lock(&pep->lock);
                    TAILQ_REMOVE(active_list, pconn, entry);
                    pthread_mutex_unlock(&pep->lock);
                    free(pconn);
                    free(conn);
                    pconn=NULL;
                    conn=NULL;
                    tx->evt.ep=ep;
                    tx->evt.conn=NULL;
                    break;
                }

                case PORTALS_MSG_CONN_REPLY:
                case PORTALS_MSG_CONN_ACK:
                default:
                    /* TODO */
                    CCI_EXIT;
                    return;
            }

            /* if SILENT, put idle tx */
            if( tx->msg_type==PORTALS_MSG_SEND && 
                tx->flags&CCI_FLAG_SILENT ) {

                tx->state=PORTALS_TX_IDLE;
                /* store locally until we can drop the pdev->lock */
                TAILQ_INSERT_HEAD( &idle_txs, tx, dentry );
            } else {

                tx->state=PORTALS_TX_COMPLETED;
                /* store locally until we can drop the pdev->lock */
                TAILQ_INSERT_TAIL( &evts, evt, entry );
            }
            continue;
        }

        /* is it time to resend? */
        if( (tx->last_attempt_us+
             (PORTALS_RESEND_TIME_SEC*1000000*tx->send_count++))>now )
            continue;

        tx->last_attempt_us=now;             /* need to resend it */
        fprintf( stderr, "re-sending %d msg seq %u\n",
                 portals_msg_type(tx->msg_type), tx->seq );

        niHandle=pdev->niHandle;
        fprintf( stderr, "Sending tx->len=%d\n", tx->len );
        iRC=portals_sendto( niHandle, pdev->eqhSend, tx->buffer,
                            tx->len, pconn->idp, pconn->table_index );
        if( iRC!=0 ) {

            fprintf( stderr, "sendto() failed with %s\n",
                     cci_strerror(errno) );
            continue;
        }
    }
    pthread_mutex_unlock(&pdev->lock);

    /* transfer txs to portals ep's list */
    while( !TAILQ_EMPTY(&idle_txs) ) {

        tx=TAILQ_FIRST(&idle_txs);
        TAILQ_REMOVE( &idle_txs, tx, dentry );
        ep=tx->evt.ep;
        pep=ep->priv;
        pthread_mutex_lock(&pep->lock);
        TAILQ_INSERT_HEAD( &pep->idle_txs, tx, dentry );
        pthread_mutex_unlock(&pep->lock);
    }

    /* transfer evts to the ep's list */
    while( !TAILQ_EMPTY(&evts) ) {

        evt=TAILQ_FIRST(&evts);
        TAILQ_REMOVE( &evts, evt, entry );
        ep=evt->ep;
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL( &ep->evts, evt, entry );
        pthread_mutex_unlock(&ep->lock);
    }

    CCI_EXIT;

    return;
}


static void portals_progress_queued(
    portals_dev_t          *pdev ) {

    int iRC;
    uint64_t               now;
    portals_tx_t           *tx;
    portals_tx_t           *tmp;
    cci__evt_t             *evt;
    cci_event_t            *event;           /* generic CCI event */
    cci_connection_t       *connection;      /* generic CCI connect */
    cci__conn_t            *conn;
    portals_conn_t         *pconn;
    cci__ep_t              *ep;
    portals_ep_t           *pep;
    ptl_handle_ni_t        niHandle;

    CCI_ENTER;

    TAILQ_HEAD( p_idle_txs, portals_tx ) idle_txs=
                                       TAILQ_HEAD_INITIALIZER(idle_txs);
    TAILQ_HEAD( p_evts, cci__evt ) evts=TAILQ_HEAD_INITIALIZER(evts);
    TAILQ_INIT(&idle_txs);
    TAILQ_INIT(&evts);

    now=portals_get_usecs();

    /* This is only for reliable messages.
     * Do not dequeue txs, just walk the list.
     */
    pthread_mutex_lock(&pdev->lock);
    TAILQ_FOREACH_SAFE( tx, &pdev->queued, dentry, tmp ) {

        evt=&(tx->evt);
        conn=evt->conn;
        connection=&conn->connection;
        pconn=conn->priv;
        event=&evt->event;

        ep=container_of( connection->endpoint, cci__ep_t, endpoint );
        pep=ep->priv;

        tx->last_attempt_us=now;             /* need to send it */
        fprintf( stderr, "sending %d msg seq %u\n",
                 portals_msg_type(tx->msg_type), tx->seq );

        niHandle=pdev->niHandle;
        fprintf( stderr, "Sending tx->len=%d\n", tx->len );
        iRC=portals_sendto( niHandle, pdev->eqhSend, tx->buffer,
                            tx->len, pconn->idp, pconn->table_index );
        if( iRC!=0 ) {

            fprintf( stderr, "sendto() failed with %s\n",
                     cci_strerror(errno) );
            continue;
        }

        /* has it timed out? */
        if( PORTALS_U64_LT( tx->timeout_us, now )) {

            /* dequeue */
            TAILQ_REMOVE( &pdev->queued, tx, dentry );

            /* set status and add to completed events */
            switch(tx->msg_type) {

                case PORTALS_MSG_SEND:
                    event->info.send.status=CCI_ETIMEDOUT;
                    break;

                case PORTALS_MSG_CONN_REQUEST: {

                    int i;
                    struct p_active *active_list;

                    event->type=CCI_EVENT_CONNECT_TIMEOUT;
                    if (conn->uri)
                        free((char *)conn->uri);
                    pconn->status=PORTALS_CONN_CLOSING;
                    i=portals_idp_hash(pconn->idp);
                    active_list=&pep->active_hash[i];
                    pthread_mutex_lock(&pep->lock);
                    TAILQ_REMOVE(active_list, pconn, entry);
                    pthread_mutex_unlock(&pep->lock);
                    free(pconn);
                    free(conn);
                    pconn=NULL;
                    conn=NULL;
                    tx->evt.ep=ep;
                    tx->evt.conn=NULL;
                    break;
                }

                case PORTALS_MSG_CONN_REPLY:
                case PORTALS_MSG_CONN_ACK:
                default:
                    /* TODO */
                    CCI_EXIT;
                    return;
            }

            /* if SILENT, put idle tx */
            if( tx->msg_type==PORTALS_MSG_SEND && 
                tx->flags&CCI_FLAG_SILENT ) {

                tx->state=PORTALS_TX_IDLE;
                /* store locally until we can drop the pdev->lock */
                TAILQ_INSERT_HEAD( &idle_txs, tx, dentry );
            } else {

                tx->state=PORTALS_TX_COMPLETED;
                /* store locally until we can drop the pdev->lock */
                TAILQ_INSERT_TAIL( &evts, evt, entry );
            }
            continue;
        }

        /* is it time to resend? */
        if( (tx->last_attempt_us+
             (PORTALS_RESEND_TIME_SEC*1000000*tx->send_count++))>now )
            continue;

        tx->last_attempt_us=now;             /* need to resend it */
        fprintf( stderr, "re-sending %d msg seq %u\n",
                 portals_msg_type(tx->msg_type), tx->seq );

        niHandle=pdev->niHandle;
        fprintf( stderr, "Sending tx->len=%d\n", tx->len );
        iRC=portals_sendto( niHandle, pdev->eqhSend, tx->buffer,
                            tx->len, pconn->idp, pconn->table_index );
        if( iRC!=0 ) {

            fprintf( stderr, "sendto() failed with %s\n",
                     cci_strerror(errno) );
            continue;
        }
    }
    pthread_mutex_unlock(&pdev->lock);

    /* transfer txs to portals ep's list */
    while( !TAILQ_EMPTY(&idle_txs) ) {

        tx=TAILQ_FIRST(&idle_txs);
        TAILQ_REMOVE( &idle_txs, tx, dentry );
        ep=tx->evt.ep;
        pep=ep->priv;
        pthread_mutex_lock(&pep->lock);
        TAILQ_INSERT_HEAD( &pep->idle_txs, tx, dentry );
        pthread_mutex_unlock(&pep->lock);
    }

    /* transfer evts to the ep's list */
    while( !TAILQ_EMPTY(&evts) ) {

        evt=TAILQ_FIRST(&evts);
        TAILQ_REMOVE( &evts, evt, entry );
        ep=evt->ep;
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL( &ep->evts, evt, entry );
        pthread_mutex_unlock(&ep->lock);
    }

    CCI_EXIT;

    return;
}


static void portals_progress_sends(
    portals_dev_t         *pdev ) {

    portals_progress_pending(pdev);
    portals_progress_queued(pdev);

    return;
}


static int portals_events(
    ptl_event_t            *event ) {

    int                    iRC;
    int                    id;
    int                    i;
    const cci_device_t     **devices;
    cci__dev_t             *dev;
    portals_dev_t          *pdev;
    ptl_handle_eq_t        eqh[2];
    portals_msg_type_t     type;
    uint8_t                a;
    uint16_t               b;
    uint32_t               c;

    CCI_ENTER;

    if(!pglobals) {

        CCI_EXIT;
        return;
    }

    for( devices=pglobals->devices; *devices!=NULL; devices++ ) {

        dev=container_of( devices, cci__dev_t, device );
        pdev=dev->priv;

        eqh[0]=pdev->eqhSend;
        eqh[1]=pdev->eqhRecv;

        iRC=PtlEQPoll( eqh, 2, 10, event, &id );
        if( iRC==PTL_OK ) {

            switch( event->type ) {

                case PTL_EVENT_SEND_START:
                     fprintf( stderr, "PTL_EVENT_SEND_START\n" );
                     break;;

                case PTL_EVENT_SEND_END:
                     fprintf( stderr, "PTL_EVENT_SEND_END "
                              " mlength=%d  rlength=%d\n",
                              event->mlength, event->rlength );
                     break;;

                case PTL_EVENT_PUT_START:
                     fprintf( stderr, "PTL_EVENT_PUT_START\n" );
                     break;;

                case PTL_EVENT_PUT_END:
                     fprintf( stderr, "PTL_EVENT_PUT_END "
                              " mlength=%d  rlength=%d\n",
                              event->mlength, event->rlength );
                     fprintf( stderr, "md.length=%d\n",
                              event->md.length );
                     portals_parse_header( event->md.start, &type,
                                           &a, &b, &c );
                     fprintf( stderr,
                              "Got buffer: type=%d a=%d b=%d c=%d\n",
                              type, a, b, c );
                     
                     break;;

                case PTL_EVENT_ACK:
                     fprintf( stderr, "PTL_EVENT_ACK  mlength=%d "
                              " rlength=%d\n",
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
