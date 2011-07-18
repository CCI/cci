/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */


#if defined(__INTEL_COMPILER)
#pragma warning(disable:593)
#pragma warning(disable:869)
#pragma warning(disable:981)
#pragma warning(disable:1338)
#pragma warning(disable:2259)
#endif //   __INTEL_COMPILER

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "cci/config.h"
#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"
uint32_t                        cookie;
uint32_t                        modes=0;
volatile int                    gni_shut_down=0;
gni_globals_t *                 gglobals=NULL;
pthread_t                       progress_tid;

/******* cycle counting sampling code ****/
#define ENABLE_GNI_SAMPLING 0
#if ENABLE_GNI_SAMPLING
#define GNI_NUM_SAMPLES (1000)
uint64_t *                      gni_start_ns;
uint64_t *                      gni_end_ns;
static int                      gni_num_samples=GNI_NUM_SAMPLES;
static int                      gni_sample=0;
#define GNI_SAMPLE_START                                              \
do {                                                                  \
    if(!gni_start_ns)                                                 \
        break;                                                        \
    if( gni_sample < gni_num_samples )                                \
        gni_start_ns[gni_sample]=gni_get_nsecs();                     \
} while(0)

#define GNI_SAMPLE_END                                                \
do {                                                                  \
    if(!gni_end_ns)                                                   \
        break;                                                        \
    if( gni_sample < gni_num_samples )                                 \
        gni_end_ns[gni_sample++]=gni_get_nsecs();                     \
} while(0)
int gni_debug_is_server=0;
#define GNI_IS_SERVER                                                 \
do {                                                                  \
    gni_debug_is_server=1;                                            \
} while (0)

static inline void gni_sample_init(void) {

    int i;

    gni_start_ns=calloc( GNI_NUM_SAMPLES, sizeof(*gni_start_ns) );
    gni_end_ns=calloc( GNI_NUM_SAMPLES, sizeof(*gni_end_ns) );
    if( !gni_start_ns || !gni_end_ns ) {

        if(gni_start_ns)
            free(gni_start_ns);
        else
            free(gni_end_ns);
        gni_num_samples=0;
        return;
    }
    for( i=0; i<GNI_NUM_SAMPLES; i++ ) {

        gni_start_ns[i]=0;
        gni_end_ns[i]=0;
    }
    gni_sample=0;
}
#define GNI_SAMPLE_INIT                                               \
do {                                                                  \
    gni_sample_init();                                                \
} while (0)

#define GNI_SAMPLE_FREE                                               \
do {                                                                  \
    if(gni_start_ns)                                                  \
        free(gni_start_ns);                                           \
    if(gni_end_ns)                                                    \
        free(gni_end_ns);                                             \
} while (0)

#define GNI_SAMPLE_PRINT                                              \
do {                                                                  \
    int i;                                                            \
    for( i=0; i<GNI_NUM_SAMPLES; i++ ) {                              \
        debug( CCI_DB_WARN, "%4d %6lld", i,                           \
              (unsigned long long)(gni_end_ns[i] - gni_start_ns[i]) );\
    }                                                                 \
} while (0)

#else                                        // ENABLE_GNI_SAMPLING==1
#define GNI_SAMPLE_INIT
#define GNI_SAMPLE_START
#define GNI_SAMPLE_END
#define GNI_SAMPLE_PRINT
#define GNI_SAMPLE_FREE
#define GNI_IS_SERVER
#endif                                       // ENABLE_GEMINI_SAMPLING==1
/******* end cycle counting sampling code ****/


// Local functions
static int         gni_init(
    uint32_t                    abi_ver,
    uint32_t                    flags,
    uint32_t *                  caps );
static const char *gni_strerror(
    enum cci_status             status );
static int         gni_get_devices(
    cci_device_t const ***      devices );
static int         gni_free_devices(
    cci_device_t const **       devices );
static int         gni_create_endpoint(
    cci_device_t *              device,
    int                         flags,
    cci_endpoint_t **           endpoint,
    cci_os_handle_t *           fd );
static int         gni_destroy_endpoint(
    cci_endpoint_t *            endpoint );
static int         gni_bind(
    cci_device_t *              device,
    int                         backlog,
    uint32_t *                  port,
    cci_service_t **            service,
    cci_os_handle_t *           fd );
static int         gni_unbind(
    cci_service_t *             service,
    cci_device_t *              device );
static int         gni_get_conn_req(
    cci_service_t *             service,
    cci_conn_req_t **           conn_req );
static int         gni_accept(
    cci_conn_req_t *            conn_req,
    cci_endpoint_t *            endpoint,
    cci_connection_t **         connection );
static int         gni_reject(
    cci_conn_req_t *            conn_req );
static int         gni_connect(
    cci_endpoint_t *            endpoint,
    char *                      server_uri,
    uint32_t                    port,
    void *                      data_ptr,
    uint32_t                    data_len,
    cci_conn_attribute_t        attribute,
    void *                      context,
    int                         flags,
    struct timeval *            timeout );
static int         gni_disconnect(
    cci_connection_t *          connection );
static int         gni_set_opt(
    cci_opt_handle_t *          handle,
    cci_opt_level_t             level,
    cci_opt_name_t              name,
    const void *                val,
    int                         len );
static int         gni_get_opt(
    cci_opt_handle_t *          handle,
    cci_opt_level_t             level,
    cci_opt_name_t              name,
    void **                     val,
    int *                       len );
static int         gni_arm_os_handle(
    cci_endpoint_t *            endpoint,
    int                         flags );
static int         gni_get_event(
    cci_endpoint_t *            endpoint,
    cci_event_t ** const        event,
    uint32_t                    flags );
static int         gni_return_event(
    cci_endpoint_t *            endpoint,
    cci_event_t *               event );
static int         gni_send(
    cci_connection_t *          connection,
    void *                      header_ptr,
    uint32_t                    header_len,
    void *                      data_ptr,
    uint32_t                    data_len,
    void *                      context,
    int                         flags );
static int         gni_sendv(
    cci_connection_t *          connection,
    void *                      header_ptr,
    uint32_t                    header_len,
    struct iovec *              data,
    uint8_t                     iovcnt,
    void *                      context,
    int                         flags );
static int         gni_rma_register(
    cci_endpoint_t *            endpoint,
    cci_connection_t *          connection,
    void *                      start,
    uint64_t                    length,
    uint64_t *                  rma_handle );
static int         gni_rma_register_phys(
    cci_endpoint_t *            endpoint,
    cci_connection_t *          connection,
    cci_sg_t *                  sg_list,
    uint32_t                    sg_cnt,
    uint64_t *                  rma_handle );
static int         gni_rma_deregister(
    uint64_t                  rma_handle );
static int         gni_rma(
    cci_connection_t *          connection,
    void *                      header_ptr,
    uint32_t                    header_len,
    uint64_t                    local_handle,
    uint64_t                    local_offset,
    uint64_t                    remote_handle,
    uint64_t                    remote_offset,
    uint64_t                    data_len,
    void *                      context,
    int                         flags );

static uint8_t     gni_get_ptag(    void);
static uint32_t    gni_get_cookie( void);
static void *      gni_progress_thread(
    void *                      arg );


// Public plugin structure.
//
// The name of this structure must be of the following form:
//
//    cci_core_<your_plugin_name>_plugin
//
// This allows the symbol to be found after the plugin is dynamically
// opened.
//
// Note that your_plugin_name should match the direct name where the
// plugin resides.
cci_plugin_core_t cci_core_gni_plugin= {
    {
//      Logistics
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "gni",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,

//      Bootstrap function pointers
        cci_core_gni_post_load,
        cci_core_gni_pre_unload,
    },

//  API function pointers
    gni_init,
    gni_strerror,
    gni_get_devices,
    gni_free_devices,
    gni_create_endpoint,
    gni_destroy_endpoint,
    gni_bind,
    gni_unbind,
    gni_get_conn_req,
    gni_accept,
    gni_reject,
    gni_connect,
    gni_disconnect,
    gni_set_opt,
    gni_get_opt,
    gni_arm_os_handle,
    gni_get_event,
    gni_return_event,
    gni_send,
    gni_sendv,
    gni_rma_register,
    gni_rma_register_phys,
    gni_rma_deregister,
    gni_rma
};


static uint8_t gni_get_ptag(void) {

    char *                    ptr;
    char *                    token;
    uint8_t                   ptag;

    ptr=getenv("PMI_GNI_PTAG");
    assert(ptr);                             // something wrong like PMI_Init not called
    token=strtok( ptr, ":" );
    ptag=(uint8_t)atoi(token);
    return(ptag);
}


static uint32_t gni_get_cookie(void) {

    char *                    ptr;
    char *                    token;
    uint32_t                  cookie;

    ptr=getenv("PMI_GNI_COOKIE");
    assert(ptr);                             // again, probably PMI_Init not called
    token=strtok( ptr, ":" );
    cookie=(uint32_t)atoi(token);
    return(cookie); 
}


static int gni_init(
    uint32_t                    abi_ver,
    uint32_t                    flags,
    uint32_t *                  caps ) {

    int                         iRC;
    int                         iRank;
    int                         iReject;
    int                         iFirst;
    int                         device_id=0;
    uint8_t                     ptag;
    unsigned int                local_addr;
    cci__dev_t *                dev;
    cci_device_t **             ds;
    gni_cdm_handle_t            cdm_hndl;
    gni_nic_handle_t            nic_hndl;
    gni_return_t                status;

    CCI_ENTER;
    GNI_SAMPLE_INIT;

    debug( CCI_DB_WARN, "In gni_init" );
    iRC=PMI_Init(&iFirst);
    if(iRC!=PMI_SUCCESS) {

        debug( CCI_DB_WARN, "FAIL: PMI_Init returned error %s", gni_err_str[iRC] );
        return CCI_ERROR;
    }
    iRC=PMI_Get_rank(&iRank);
    if(iRC!=PMI_SUCCESS) {

        debug( CCI_DB_WARN, "FAIL: PMI_Get_rank returned error %s", gni_err_str[iRC] );
        return CCI_ERROR;
    }
    ptag=gni_get_ptag();
    cookie=gni_get_cookie();
    debug( CCI_DB_INFO, "Rank=%.5d  ptag=%u  cookie=0x%zx", iRank, ptag, cookie );

    status=GNI_CdmCreate( iRank, ptag, cookie, modes, &cdm_hndl );
    if( status != GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: GNI_CdmCreate returned error %s", gni_err_str[status] );
        return CCI_ERROR;
    }

    status=GNI_CdmAttach( cdm_hndl, device_id, &local_addr, &nic_hndl );
    if( status != GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: GNI_CdmAttach returned error %s\n", gni_err_str[status] );
        return CCI_ERROR;
    }
    debug( CCI_DB_INFO, "Rank=%.5d  cdm_hndl=0x%zx  nic_hndl=0x%zx", iRank, cdm_hndl, nic_hndl );

//  Step 1.  Extract gemini devices from global configuration.
    if( !(gglobals=calloc( 1, sizeof(*gglobals) )) )
        return CCI_ENOMEM;         /* cannot save gemini device list */

    if( !(ds=calloc( CCI_MAX_DEVICES, sizeof(*gglobals->devices) )) ) {

        free(gglobals);
        gglobals=NULL;
        return CCI_ENOMEM;         /* cannot save list of devices */
    }

    srandom((unsigned int)gni_get_usecs());

//  Start searching global configuration for Gemini devices.
    iReject=1;
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char **           arg;  
        cci_device_t *          device;
        gni_dev_t *             gdev;  

//      Reject until Gemini driver found in configuration.
        if(strcmp( "gni", dev->driver )) continue;

        TAILQ_INIT(&dev->leps);

        iReject=0;                 // Gemini configured
        device=&dev->device;       // Select device

        device->max_send_size=GNI_DEFAULT_MSS;
        device->rate=160000000000; // Gemini interconnect
        device->pci.domain=-1;     // per CCI spec
        device->pci.bus=-1;        // per CCI spec
        device->pci.dev=-1;        // per CCI spec
        device->pci.func=-1;       // per CCI spec

        if( !(dev->priv=calloc( 1, sizeof(*gdev) )) ) {

            free(gglobals->devices);
            free(gglobals);
            gglobals=NULL;
            iRC=CCI_ENOMEM;
            goto out;
        }       

        gdev=dev->priv;            // select private device

        gdev->is_progressing=0;    // initialize progress flag
        gdev->cookie=cookie;       // GNI parameters
        gdev->ptag=ptag;           // 'd.o.'
        gdev->cdm_hndl=cdm_hndl;   // 'd.o.'
        gdev->nic_hndl=nic_hndl;   // 'd.o.'

        gdev->ep_ids=calloc( GNI_NUM_BLOCKS, sizeof(*gdev->ep_ids) );
        if (!gdev->ep_ids) {

            free(gglobals->devices);
            free(gglobals);
            gglobals=NULL;
            iRC=CCI_ENOMEM;
            goto out;
        }
        ds[gglobals->count]=device;
        gglobals->count++;
        dev->is_up=1;

        /* parse conf_argv */
        for( arg=device->conf_argv; *arg!=NULL; arg++ ) {

            if(!strncmp( "mtu=", *arg, 4 )) {

                const char *    mss_str=*arg+4;
                uint32_t        mss=strtol( mss_str, NULL, 0 );

                if( mss>GNI_MAX_MSS )
                    mss=GNI_MAX_MSS;
                else if( mss<GNI_MIN_MSS )
                    mss=GNI_MIN_MSS;

                device->max_send_size=mss;
            }
        }
    }

    if(iReject) {                  // No Gemini devices configured

        free(gglobals->devices);
        free(gglobals);
        gglobals=NULL;
        iRC=CCI_ENODEV;
        goto out;
    }

/*  Increment list of devices. */
    ds=realloc( ds, (gglobals->count+1)*sizeof(cci_device_t *) );
    ds[gglobals->count]=NULL;
    *((cci_device_t ***)&gglobals->devices)=ds;

/*  Try to create progress thread. */
    iRC=pthread_create( &progress_tid, NULL, gni_progress_thread, NULL );
    if(iRC) {                      // Failed

        if(ds){                    // Free private device

            cci_device_t        *device;

            for( device=ds[0]; device!=NULL; device++ ) {

                dev=container_of( device, cci__dev_t, device );
                if(dev->priv)
                    free(dev->priv);
            }
        }
        free(ds);                  /* Free pointer to private device */

        if(gglobals) {

            free(gglobals->devices);
            free(gglobals);
            gglobals=NULL;
        }

        CCI_EXIT;
        return iRC;
    }

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    CCI_EXIT;
    return iRC;
}


static const char *gni_strerror(  enum cci_status        status ) {

    debug( CCI_DB_WARN, "In gni_strerror" );
    return gni_err_str[(enum cci_status)status];
}


static int gni_get_devices(
    cci_device_t const ***      devices ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    CCI_ENTER;
    debug( CCI_DB_WARN, "In gni_get_devices" );

    if(!gglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    *devices=gglobals->devices;
    debug( CCI_DB_INFO, "There are %d devices.", gglobals->count );

    device=**devices;
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int gni_free_devices(      cci_device_t const **  devices ) {

    cci__dev_t *                dev;

    CCI_ENTER;

    debug( CCI_DB_WARN, "In gni_free_devices" );
    if(!gglobals) {

        CCI_EXIT;
        return CCI_ENODEV;
    }

    pthread_mutex_lock(&globals->lock);
    gni_shut_down=1;
    pthread_mutex_unlock(&globals->lock);
    pthread_join(progress_tid, NULL);

    pthread_mutex_lock(&globals->lock);
    TAILQ_FOREACH( dev, &globals->devs, entry ) {
        gni_dev_t *             gdev=dev->priv;
        if(gdev) {                           // Only for Gemini device
            if(gdev->ep_ids)
                free(gdev->ep_ids);
            free(dev->priv);
        }
    }
    pthread_mutex_unlock(&globals->lock);

    free(gglobals->devices);
    free((void *)gglobals);

    GNI_SAMPLE_PRINT;
    GNI_SAMPLE_FREE;
    CCI_EXIT;

    return CCI_SUCCESS;
}


static int gni_create_endpoint(   cci_device_t *         device,
                                  int                    flags,
                                  cci_endpoint_t **      endpoint,
                                  cci_os_handle_t *      fd ) {

    debug( CCI_DB_WARN, "In gni_create_endpoint" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_destroy_endpoint(  cci_endpoint_t *       endpoint ) {

    debug( CCI_DB_WARN, "In gni_destroy_endpoint" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_bind(              cci_device_t *         device,
                                  int                    backlog,
                                  uint32_t *             port,
                                  cci_service_t **       service,
                                  cci_os_handle_t *      fd ) {

    debug( CCI_DB_WARN, "In gni_bind" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_unbind(            cci_service_t *        service,
                                  cci_device_t *         device ) {

    debug( CCI_DB_WARN, "In gni_unbind" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_get_conn_req(      cci_service_t *        service,
                                  cci_conn_req_t **      conn_req ) {

    debug( CCI_DB_WARN, "In gni_get_conn_req" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_accept(            cci_conn_req_t *       conn_req,
                                  cci_endpoint_t *       endpoint,
                                  cci_connection_t **    connection ) {

    debug( CCI_DB_WARN, "In gni_accept" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_reject(            cci_conn_req_t *       conn_req ) {

    debug( CCI_DB_WARN, "In gni_reject" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_connect(           cci_endpoint_t *       endpoint,
                                  char *                 server_uri,
                                  uint32_t               port,
                                  void *                 data_ptr,
                                  uint32_t               data_len,
                                  cci_conn_attribute_t   attribute,
                                  void *                 context,
                                  int                    flags,
                                  struct timeval *       timeout  ) {

    debug( CCI_DB_WARN, "In gni_connect" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_disconnect(        cci_connection_t *     connection ) {

    debug( CCI_DB_WARN, "In gni_disconnect" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_set_opt(           cci_opt_handle_t *     handle,
                                  cci_opt_level_t        level,
                                  cci_opt_name_t         name,
                                  const void *           val,
                                  int                    len ) {

    debug( CCI_DB_WARN, "In gni_set_opt" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_get_opt(           cci_opt_handle_t *     handle,
                                  cci_opt_level_t        level,
                                  cci_opt_name_t         name,
                                  void **                val,
                                  int *                  len ) {

    debug( CCI_DB_WARN, "In gni_get_opt" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_arm_os_handle(     cci_endpoint_t *       endpoint,
                                  int                    flags ) {

    debug( CCI_DB_WARN, "In gni_arm_os_handle" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_get_event(         cci_endpoint_t *         endpoint,
                                  cci_event_t ** const     event,
                                  uint32_t                 flags ) {

    debug( CCI_DB_WARN, "In gni_get_event" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_return_event(      cci_endpoint_t *       endpoint,
                                  cci_event_t *          event ) {

    debug( CCI_DB_WARN, "In gni_return_event" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_send(              cci_connection_t *     connection,
                                  void *                 header_ptr,
                                  uint32_t               header_len,
                                  void *                 data_ptr,
                                  uint32_t               data_len,
                                  void *                 context,
                                  int                    flags ) {

    debug( CCI_DB_WARN, "In gni_send" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_sendv(             cci_connection_t *     connection,
                                  void *                 header_ptr,
                                  uint32_t               header_len,
                                  struct iovec *         data,
                                  uint8_t                iovcnt,
                                  void *                 context,
                                  int                    flags ) {

    debug( CCI_DB_WARN, "In gni_sendv" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_rma_register(      cci_endpoint_t *       endpoint,
                                  cci_connection_t *     connection,
                                  void *                 start,
                                  uint64_t               length,
                                  uint64_t *             rma_handle ) {

    debug( CCI_DB_WARN, "In gni_rma_register" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_rma_register_phys( cci_endpoint_t *       endpoint,
                                  cci_connection_t *     connection,
                                  cci_sg_t *             sg_list,
                                  uint32_t               sg_cnt,
                                  uint64_t *             rma_handle ) {

    debug( CCI_DB_WARN, "In gni_rma_register_phys" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_rma_deregister(    uint64_t               rma_handle ) {

    debug( CCI_DB_WARN, "In gni_rma_deregister" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_rma(               cci_connection_t *     connection,
                                  void *                 header_ptr,
                                  uint32_t               header_len,
                                  uint64_t               local_handle,
                                  uint64_t               local_offset,
                                  uint64_t               remote_handle,
                                  uint64_t               remote_offset,
                                  uint64_t               data_len,
                                  void *                 context,
                                  int                    flags ) {

    debug( CCI_DB_WARN, "In gni_rma" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static void *gni_progress_thread(
    void *                      arg ) {

    while(!gni_shut_down) {

        cci__dev_t *            dev;
        cci_device_t const **   device;

        /* for each device, try progressing */
        for( device=gglobals->devices; *device!=NULL; device++ ) {

            dev=container_of( *device, cci__dev_t, device );
//          gni_progress_dev(dev);
        }
        usleep(GNI_PROG_TIME_US);
    }
    pthread_exit(NULL);
    return(NULL);                            /* make pgcc happy */
}
