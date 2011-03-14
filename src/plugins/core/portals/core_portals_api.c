/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"
#include <stdio.h>
#include "cci.h"
#include "plugins/core/core.h"
#include "core_portals.h"

portals_globals_t *pglobals = NULL;


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
                                     void                 *start, 
                                     uint64_t             length,
                                     uint64_t             *rma_handle );
static int portals_rma_register_phys(cci_endpoint_t       *endpoint, 
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
                                     void                 *buf,
                                     int                  len,
                                     const ptl_process_id_t idp );



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
    uint32_t              abi_ver,
    uint32_t              flags,
    uint32_t              *caps ) {

    int                   iRC;
    int                   iMax_devices;
    int                   iReject;
    pthread_t             tid;
    cci_device_t          **ds;
    cci__dev_t            *dev;
    ptl_interface_t       ifID;
    ptl_ni_limits_t       niLimit;
    ptl_handle_ni_t       niHandle;

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

/*
 * Start searching global configuration for portals devices.
 */
    iReject=1;
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char        **arg;
        cci_device_t      *device;
        portals_dev_t     *pdev;

/*      Reject until portals driver found in configuration. */
        if(strcmp( "portals", dev->driver )) continue;

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
        PtlGetId( niHandle, &pdev->idp );
        fprintf( stdout, "My portals ID is: (%10d, %5d).\n",
                 (pdev->idp).nid, (pdev->idp).pid );

        ds[pglobals->count]=device;
        pglobals->count++;
        dev->is_up=1;
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


static const char *portals_strerror(enum cci_status status)
{
    printf("In portals_sterrror\n");
    return NULL;
}


static int portals_get_devices(
    cci_device_t const    ***devices ) {

    cci_device_t          *device;
    cci__dev_t            *dev;
    portals_dev_t         *pdev;

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


static int portals_free_devices(cci_device_t const **devices)
{
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
     *         close socket
     *     for each listening endpoint
     *         remove from service
     *         for each conn_req
     *             free it
     *         close socket
     */

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_create_endpoint(cci_device_t *device, 
                                   int flags, 
                                   cci_endpoint_t **endpoint, 
                                   cci_os_handle_t *fd)
{
    printf("In portals_create_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_destroy_endpoint(cci_endpoint_t *endpoint)
{
    printf("In portals_destroy_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_bind(cci_device_t *device,
                        int backlog,
                        uint32_t *port, 
                        cci_service_t **service,
                        cci_os_handle_t *fd)
{
    printf("In portals_bind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_unbind(cci_service_t *service,
                          cci_device_t *device)
{
    printf("In portals_unbind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_get_conn_req(cci_service_t *service, 
                                cci_conn_req_t **conn_req)
{
    printf("In portals_get_conn_req\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_accept(cci_conn_req_t *conn_req, 
                          cci_endpoint_t *endpoint, 
                          cci_connection_t **connection)
{
    printf("In portals_accept\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_reject(cci_conn_req_t *conn_req)
{
    printf("In portals_reject\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_connect(cci_endpoint_t *endpoint,
                           char *server_uri, 
                           uint32_t port,
                           void *data_ptr,
                           uint32_t data_len, 
                           cci_conn_attribute_t attribute,
                           void *context,
                           int flags, 
                           struct timeval *timeout)
{
    printf("In portals_connect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_disconnect(cci_connection_t *connection)
{
    printf("In portals_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_set_opt(cci_opt_handle_t *handle, 
                           cci_opt_level_t level, 
                           cci_opt_name_t name,
                           const void* val,
                           int len)
{
    printf("In portals_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_get_opt(cci_opt_handle_t *handle, 
                           cci_opt_level_t level, 
                           cci_opt_name_t name,
                           void** val,
                           int *len)
{
    printf("In portals_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_arm_os_handle(cci_endpoint_t *endpoint,
                                 int flags)
{
    printf("In portals_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_get_event(cci_endpoint_t *endpoint, 
                             cci_event_t ** const event,
                             uint32_t flags)
{
    printf("In portals_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_return_event(cci_endpoint_t *endpoint, 
                                cci_event_t *event)
{
    printf("In portals_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_send(cci_connection_t *connection, 
                        void *header_ptr,
                        uint32_t header_len, 
                        void *data_ptr,
                        uint32_t data_len, 
                        void *context,
                        int flags)
{
    printf("In portals_send\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_sendv(cci_connection_t *connection, 
                         void *header_ptr,
                         uint32_t header_len, 
                         char **data_ptrs,
                         int *data_lens,
                         uint8_t segment_cnt,
                         void *context,
                         int flags)
{
    printf("In portals_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_rma_register(cci_endpoint_t *endpoint,
                                void *start, 
                                uint64_t length,
                                uint64_t *rma_handle)
{
    printf("In portals_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_rma_register_phys(cci_endpoint_t *endpoint, 
                                     cci_sg_t *sg_list,
                                     uint32_t sg_cnt, 
                                     uint64_t *rma_handle)
{
    printf("In portals_rma_register_phys\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_rma_deregister(uint64_t rma_handle)
{
    printf("In portals_rma_deregister\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int portals_rma(cci_connection_t *connection, 
                       void *header_ptr,
                       uint32_t header_len, 
                       uint64_t local_handle,
                       uint64_t local_offset, 
                       uint64_t remote_handle,
                       uint64_t remote_offset,
                       uint64_t data_len,
                       void *context,
                       int flags)
{
    printf("In portals_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static void portals_recvfrom_ep(cci__ep_t *ep)
{
    printf("In portals_recvfrom_ep\n");
    return;
}


static void portals_recvfrom_lep(cci__lep_t *lep)
{
    printf("In portals_recvfrom_lep\n");
    return;
}


static inline void portals_progress_dev(cci__dev_t *dev)
{
    int           have_token= 0;
    portals_dev_t *pdev;
    cci__ep_t     *ep;
    cci__lep_t    *lep;

    CCI_ENTER;

    pdev=dev->priv;

    pthread_mutex_lock(&pdev->lock);
    if( pdev->is_progressing==0) {

        pdev->is_progressing=1;
        have_token=1;
    }
    pthread_mutex_unlock(&pdev->lock);

    if (!have_token) {

        CCI_EXIT;
        return;
    }

    portals_progress_sends(pdev);

    TAILQ_FOREACH( ep, &dev->eps, entry)
        portals_recvfrom_ep(ep);
    TAILQ_FOREACH(lep, &dev->leps, dentry)
        portals_recvfrom_lep(lep);

    pthread_mutex_lock(&pdev->lock);
    pdev->is_progressing=0;
    pthread_mutex_unlock(&pdev->lock);

    CCI_EXIT;
    return;
}

static void *portals_progress_thread(void *arg)
{

    while (!pglobals->shutdown) {

        cci__dev_t *dev;
        cci_device_t const **device;

        /* for each device, try progressing */
        for( device=pglobals->devices; *device!=NULL; device++ ) {

            dev=container_of( *device, cci__dev_t, device );
            portals_progress_dev(dev);
        }

        usleep(PORTALS_PROG_TIME_US);
    }

    pthread_exit(NULL);
}


static void portals_progress_pending(portals_dev_t *pdev)
{

    printf("In portals_progress_pending\n");
    return;
}


static void portals_progress_queued(portals_dev_t *pdev)
{

    printf("In portals_progress_queued\n");
    return;
}


static void portals_progress_sends(portals_dev_t *pdev)
{
    portals_progress_pending(pdev);
    portals_progress_queued(pdev);

    return;
}


