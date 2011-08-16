/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */


#if       __INTEL_COMPILER
#pragma warning(disable:593)
#pragma warning(disable:869)
#pragma warning(disable:981)
#pragma warning(disable:1338)
#pragma warning(disable:2259)
#endif // __INTEL_COMPILER

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "cci/config.h"
#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"

volatile int32_t                gni_shut_down=0;
gni_globals_t *                 gglobals=NULL;
pthread_t                       tid;

// Cycle count sampling code -- START
#define   ENABLE_GNI_SAMPLING 0
#if       ENABLE_GNI_SAMPLING
#define   GNI_NUM_SAMPLES     1000
uint64_t *                      gni_start_ns;
uint64_t *                      gni_end_ns;
static int32_t                  gni_num_samples=GNI_NUM_SAMPLES;
static int32_t                  gni_sample=0;
int32_t                         gni_debug_is_server=0;

static inline void gni_sample_init(void) {

    int32_t                     i;

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

#define   GNI_SAMPLE_START                                            \
do {                                                                  \
    if(!gni_start_ns)                                                 \
        break;                                                        \
    if( gni_sample<gni_num_samples )                                  \
        gni_start_ns[gni_sample]=gni_get_nsecs();                     \
} while(0)

#define   GNI_SAMPLE_END                                              \
do {                                                                  \
    if(!gni_end_ns)                                                   \
        break;                                                        \
    if( gni_sample<gni_num_samples )                                  \
        gni_end_ns[gni_sample++]=gni_get_nsecs();                     \
} while(0)

#define   GNI_IS_SERVER                                               \
do {                                                                  \
    gni_debug_is_server=1;                                            \
} while(0)

#define   GNI_SAMPLE_INIT                                             \
do {                                                                  \
    gni_sample_init();                                                \
} while(0)

#define   GNI_SAMPLE_FREE                                             \
do {                                                                  \
    if(gni_start_ns)                                                  \
        free(gni_start_ns);                                           \
    if(gni_end_ns)                                                    \
        free(gni_end_ns);                                             \
} while(0)

#define   GNI_SAMPLE_PRINT                                            \
do {                                                                  \
    int32_t                     i;                                    \
    for( i=0; i<GNI_NUM_SAMPLES; i++ ) {                              \
        debug( CCI_DB_WARN, "%4d %6llu", i,                           \
              (unsigned long long)(gni_end_ns[i]-gni_start_ns[i]) );  \
    }                                                                 \
} while(0)

#else  // ENABLE_GNI_SAMPLING
#define   GNI_SAMPLE_INIT
#define   GNI_SAMPLE_START
#define   GNI_SAMPLE_END
#define   GNI_SAMPLE_PRINT
#define   GNI_SAMPLE_FREE
#define   GNI_IS_SERVER
#endif // ENABLE_GNI_SAMPLING
// Cycle count sampling code -- FINISH


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
    int32_t                     flags,
    cci_endpoint_t **           endpoint,
    cci_os_handle_t *           fd );
static int         gni_destroy_endpoint(
    cci_endpoint_t *            endpoint );
static int         gni_bind(
    cci_device_t *              device,
    int32_t                     backlog,
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
    int32_t                     flags,
    struct timeval *            timeout );
static int         gni_disconnect(
    cci_connection_t *          connection );
static int         gni_set_opt(
    cci_opt_handle_t *          handle,
    cci_opt_level_t             level,
    cci_opt_name_t              name,
    const void *                val,
    int32_t                     len );
static int         gni_get_opt(
    cci_opt_handle_t *          handle,
    cci_opt_level_t             level,
    cci_opt_name_t              name,
    void **                     val,
    int32_t *                   len );
static int         gni_arm_os_handle(
    cci_endpoint_t *            endpoint,
    int32_t                     flags );
static int         gni_get_event(
    cci_endpoint_t *            endpoint,
    cci_event_t ** const        event,
    uint32_t                    flags );
static int         gni_return_event(
    cci_endpoint_t *            endpoint,
    cci_event_t *               event );
static int         gni_send(
    cci_connection_t *          connection,
    void *                      ptr,
    uint32_t                    len,
    void *                      context,
    int32_t                     flags );
static int         gni_sendv(
    cci_connection_t *          connection,
    struct iovec *              data,
    uint8_t                     iovcnt,
    void *                      context,
    int32_t                     flags );
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
    void *                      msg_ptr,
    uint32_t                    msg_len,
    uint64_t                    local_handle,
    uint64_t                    local_offset,
    uint64_t                    remote_handle,
    uint64_t                    remote_offset,
    uint64_t                    len,
    void *                      context,
    int32_t                     flags );

static uint8_t     gni_get_ptag(    void);
static uint32_t    gni_get_cookie( void);
static void        gni_get_ep_id(
    gni_dev_t *                 gdev,  
    uint32_t *                  id );
static void        gni_put_ep_id(
    gni_dev_t *                 gdev,
    uint32_t                    id );
static int gni_add_tx(
    int                         i,
    cci__ep_t *                 ep );
static int gni_add_rx(
    int                         i,
    cci__ep_t *                 ep );
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
    assert(ptr);                             // maybe PMI_Init uncalled
    token=strtok( ptr, ":" );
    ptag=(uint8_t)atoi(token);
    return(ptag);
}


static uint32_t gni_get_cookie(void) {

    char *                    ptr;
    char *                    token;
    uint32_t                  cookie;

    ptr=getenv("PMI_GNI_COOKIE");
    assert(ptr);                             // maybe PMI_Init uncalled
    token=strtok( ptr, ":" );
    cookie=(uint32_t)atoi(token);
    return(cookie); 
}


static int gni_init(
    uint32_t                    abi_ver,
    uint32_t                    flags,
    uint32_t *                  caps ) {

    int32_t                     iRC;
    int32_t                     iReject;
    int32_t                     iFirst;
    int32_t                     iRank;
    cci__dev_t *                dev;
    cci_device_t **             dl;
    gni_return_t                status;

    CCI_ENTER;
    GNI_SAMPLE_INIT;

//  Step 1.  Satisfy PMI dependencies on startup.
    iRC=PMI_Init(&iFirst);
    if(iRC!=PMI_SUCCESS) {

        debug( CCI_DB_WARN, "FAIL: PMI_Init returned error %s",
               gni_err_str[iRC] );
        return(CCI_ERROR);
    }
    iRC=PMI_Get_rank(&iRank);
    if(iRC!=PMI_SUCCESS) {

        debug( CCI_DB_WARN, "FAIL: PMI_Get_rank returned error %s",
               gni_err_str[iRC] );
        return(CCI_ERROR);
    }
    debug( CCI_DB_WARN, "Rank=%.8d In gni_init", iRank );

//  Step 2.  Extract gemini devices from global configuration.
    if( !(gglobals=calloc( 1, sizeof(*gglobals) )) )
        return(CCI_ENOMEM);
    if( !(dl=calloc( CCI_MAX_DEVICES, sizeof(*gglobals->devices) )) ) {

        free(gglobals);
        gglobals=NULL;
        return(CCI_ENOMEM);                  // List of devices unsaved
    }

    iReject=1;                               // Assume search will fail
    srandom( (unsigned int)gni_get_usecs() );
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char **           arg;  
        cci_device_t *          device;
        gni_dev_t *             gdev;  

//      Search until GNI driver found in configuration.
        if(strcmp( "gni", dev->driver )) continue;

        iReject=0;                           // Gemini configured
        device=&dev->device;                 // Select device

        device->max_send_size=GNI_DEFAULT_MSS;
        device->rate=160000000000;           // per Gemini spec
        device->pci.domain=-1;               // per CCI spec
        device->pci.bus=-1;                  // per CCI spec
        device->pci.dev=-1;                  // per CCI spec
        device->pci.func=-1;                 // per CCI spec
        TAILQ_INIT(&dev->leps);

        if( !(dev->priv=calloc( 1, sizeof(*gdev) )) ) {

            iRC=CCI_ENOMEM;
            goto out;                        // GNI parameters unsaved
        }       
        gdev=dev->priv;                      // Select GNI device

        gdev->progressing=0;                 // initialize progress flag
        gdev->ptag=gni_get_ptag();           // Retrieve GNI parameters
        gdev->cookie=gni_get_cookie();       // 'd.o.'
        gdev->Rank=iRank;                    // 'd.o.'
        gdev->modes=0;                       // for now...
        gdev->kid=0;                         // On arthur-login1...
        debug( CCI_DB_INFO, "Rank=%.8d %s: ptag =%3u  cookie=0x%zx",
               gdev->Rank, __func__, gdev->ptag, gdev->cookie );
        debug( CCI_DB_INFO, "Rank=%.8d %s: modes=0x%zx  kid   =0x%zx",
               gdev->Rank, __func__, gdev->modes, gdev->kid );

        status=GNI_CdmCreate( gdev->Rank, gdev->ptag, gdev->cookie,
                              gdev->modes, &(gdev->cdh) );
        if( status!=GNI_RC_SUCCESS ) {

            debug( CCI_DB_WARN, "FAIL: GNI_CdmCreate returned error %s",
                   gni_err_str[status] );
            return(CCI_ERROR);
        }
        debug( CCI_DB_INFO, "Rank=%.8d %s: CdmCreate: cdh   =0x%zx",
               gdev->Rank, __func__, gdev->cdh );

        status=GNI_CdmAttach( gdev->cdh, gdev->kid, &(gdev->idpe),
                              &(gdev->nh) );
        if( status!=GNI_RC_SUCCESS ) {

            debug( CCI_DB_WARN, "FAIL: GNI_CdmAttach returned error %s",
                   gni_err_str[status] );
            return(CCI_ERROR);
        }
        debug( CCI_DB_INFO,
               "Rank=%.8d %s: CdmAttach: cdh   =0x%zx nh    =0x%zx",
               gdev->Rank, __func__, gdev->cdh, gdev->nh );
        debug( CCI_DB_INFO,
               "Rank=%.8d %s: CdmAttach: cdh   =0x%zx idpe  =0x%zx",
               gdev->Rank, __func__, gdev->cdh, gdev->idpe );

        gdev->ep_ids=calloc( GNI_NUM_BLOCKS, sizeof(*gdev->ep_ids) );
        if (!gdev->ep_ids) {

            iRC=CCI_ENOMEM;
            goto out;
        }

        dl[gglobals->count]=device;
        gglobals->count++;
        dev->is_up=1;

//      Parse conf_argv (configuration file parameters).
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

    if(iReject) {                            // Gemini not configured

        iRC=CCI_ENODEV;
        goto out;
    }

//  Increment list of devices.
    dl=realloc( dl, (gglobals->count+1)*sizeof(cci_device_t *) );
    dl[gglobals->count]=NULL;
    *((cci_device_t ***)&gglobals->devices)=dl;

//  Try to create progress thread.
    iRC=pthread_create( &tid, NULL, gni_progress_thread, NULL );

out:
    if(iRC) {                                // Failed

        if(dl){                              // Free GNI device(s)

            cci_device_t        *device;

            for( device=dl[0]; device!=NULL; device++ ) {

                dev=container_of( device, cci__dev_t, device );
                if(dev->priv)
                    free(dev->priv);
            }
        }
        free(dl);                            // Free devices list

        if(gglobals) {

            free(gglobals);
            gglobals=NULL;
        }

        CCI_EXIT;
        return(iRC);
    }

    CCI_EXIT;
    return(CCI_SUCCESS);
}


static const char *gni_strerror(  enum cci_status        status ) {

    debug( CCI_DB_WARN, "In gni_strerror" );
    return(gni_err_str[(enum cci_status)status]);
}


static int gni_get_devices(
    cci_device_t const ***      devices ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }

    *devices=gglobals->devices;
    device=**devices;
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;

    debug( CCI_DB_WARN, "Rank=%.8d In gni_get_devices", gdev->Rank );
    debug( CCI_DB_INFO, "Rank=%.8d %s: Found %d devices",
           gdev->Rank, __func__, gglobals->count );

    CCI_EXIT;
    return(CCI_SUCCESS);
}


static int gni_free_devices(
    cci_device_t const **       devices ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*devices;
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;

    debug( CCI_DB_WARN, "Rank=%.8d In gni_free_devices", gdev->Rank );
    pthread_mutex_lock(&globals->lock);
    gni_shut_down=1;
    pthread_mutex_unlock(&globals->lock);
    pthread_join( tid, NULL );

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

    return(CCI_SUCCESS);
}


static void gni_get_ep_id(
    gni_dev_t *                 gdev,  
    uint32_t *                  id ) { 

    uint32_t                    n;      
    uint32_t                    block;  
    uint32_t                    offset; 
    uint64_t *                  b;     

    while(1) {

        n=random()%GNI_MAX_EP_ID;
        if ( n==0 )
            continue;
        block=n/GNI_BLOCK_SIZE;
        offset=n%GNI_BLOCK_SIZE;
        b=&gdev->ep_ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*GNI_BLOCK_SIZE)+offset;
            debug( CCI_DB_CONN, "Rank %.8d %s: id=%u block=%"PRIx64"",
                   gdev->Rank, __func__, *id, *b );
            break;  
        }       
    }
    return; 
}

static void gni_put_ep_id(
    gni_dev_t *                 gdev,
    uint32_t                    id ) {

    uint32_t                    block; 
    uint32_t                    offset; 
    uint64_t *                  b;

    block=id/GNI_BLOCK_SIZE;
    offset=id%GNI_BLOCK_SIZE;
    b=&gdev->ep_ids[block];

    debug( CCI_DB_CONN, "Rank %.8d %s: id=%u block=%"PRIx64"",
           gdev->Rank, __func__, id, *b );
    assert( ((*b>>offset)&0x1)==1 );
    *b&=~(1ULL<<offset);

    return; 
}


static int gni_add_tx(                       // Caller must hold ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    int                         ret=1;    
    uint32_t                    remote_addr;
    gni_ep_t *                  gep=ep->priv;
    gni_tx_t *                  tx;    
    gni_dev_t *                 gdev=ep->dev->priv;
    gni_return_t                status;

    status=0;
    remote_addr=0;
    tx=calloc( 1, sizeof(*tx) );
    if(!tx) {

        ret=0;
        goto out;
    }
    tx->evt.event.type=CCI_EVENT_SEND;
    tx->evt.ep=ep;

    tx->buffer=gep->txbuf+i*ep->buffer_len;
    tx->len=0;

    status=GNI_EpCreate( gdev->nh, gep->cqhl, &(tx->eph) );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: %s: GNI_EpCreate returned error %s",
               __func__, gni_err_str[(enum cci_status)status] );
        goto out;
    }
    status=GNI_EpBind( tx->eph, remote_addr, i );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: %s: GNI_EpBind returned error %s",
               __func__, gni_err_str[(enum cci_status)status] );
        goto out;
    }

    TAILQ_INSERT_TAIL( &gep->txs, tx, tentry );
    TAILQ_INSERT_TAIL( &gep->idle_txs, tx, dentry );
out:
    if(!ret) {
        if(tx) {
            if(tx->buffer)
                free(tx->buffer);
            free(tx);
        }
    }
//  debug( CCI_DB_INFO, "Rank %.8d Leaving %s: %d", gdev->Rank, __func__, i );
    return(ret);
}


static int gni_add_rx(                       // Caller must hold ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    int                         ret=1;
    uint32_t                    remote_addr;
    gni_ep_t *                  gep=ep->priv;
    gni_rx_t *                  rx;
    gni_dev_t *                 gdev=ep->dev->priv;
    gni_return_t                status;

    status=0;
    remote_addr=0;
    rx=calloc( 1, sizeof(*rx) );
    if(!rx) {

        ret=0;
        goto out;
    }
    rx->evt.event.type=CCI_EVENT_RECV;
    rx->evt.ep=ep;

    rx->buffer=gep->rxbuf+i*ep->buffer_len;
    rx->len=0;

    status=GNI_EpCreate( gdev->nh, gep->cqhl, &(rx->eph) );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: %s: GNI_EpCreate returned error %s",
               __func__, gni_err_str[(enum cci_status)status] );
        goto out;
    }
    status=GNI_EpBind( rx->eph, remote_addr, i );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: %s: GNI_EpBind returned error %s",
               __func__, gni_err_str[(enum cci_status)status] );
        goto out;
    }

    TAILQ_INSERT_TAIL(&gep->rxs, rx, gentry);
    TAILQ_INSERT_TAIL(&gep->idle_rxs, rx, entry);
out:
    if(!ret) {
        if(rx) {
            if(rx->buffer)
                free(rx->buffer);
            free(rx);
        }
    }
//  debug( CCI_DB_INFO, "Rank %.8d Leaving %s: %d", gdev->Rank, __func__, i );
    return(ret);
}


static int gni_create_endpoint(   cci_device_t *         device,
                                  int32_t                flags,
                                  cci_endpoint_t **      endpoint,
                                  cci_os_handle_t *      fd ) {

    int32_t                     i;      
    int32_t                     iRC;    
    cci__dev_t *                dev=NULL;
    cci__ep_t *                 ep=NULL;
    gni_ep_t *                  gep=NULL;
    gni_dev_t *                 gdev=NULL;
    gni_return_t                status;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }

    dev=container_of(device, cci__dev_t, device);
    if(strcmp( "gni", dev->driver )) {

        iRC=CCI_EINVAL;
        goto out;
    }
    gdev=dev->priv;
    debug(CCI_DB_WARN, "Rank=%.8d In gni_create_endpoint", gdev->Rank);

    ep=container_of( *endpoint, cci__ep_t, endpoint );
    ep->priv=calloc( 1, sizeof(*gep) );
    if(!ep->priv) {

        iRC=CCI_ENOMEM;
        goto out;
    }

    (*endpoint)->max_recv_buffer_count=GNI_EP_RX_CNT;
    ep->max_hdr_size=GNI_EP_MAX_HDR_SIZE;
    ep->rx_buf_cnt=GNI_EP_RX_CNT;
    ep->tx_buf_cnt=GNI_EP_TX_CNT;
    ep->buffer_len=dev->device.max_send_size;
    ep->tx_timeout=0;

    gep=ep->priv;

    TAILQ_INIT(&gep->txs);
    TAILQ_INIT(&gep->idle_txs);
    TAILQ_INIT(&gep->rxs);
    TAILQ_INIT(&gep->idle_rxs);
    TAILQ_INIT(&gep->conns);
    TAILQ_INIT(&gep->handles);
    TAILQ_INIT(&gep->rma_ops);

//  Get endpoint id.
    pthread_mutex_lock(&dev->lock);
    gni_get_ep_id( gdev, &gep->id );
    pthread_mutex_unlock(&dev->lock);
    debug( (CCI_DB_CONN|CCI_DB_INFO), "Rank=%.8d %s: id=%u",
           gdev->Rank, __func__, gep->id );

//  Create completion queues for endpoint.
    status=GNI_CqCreate( gdev->nh,           // Local CQ
                         GNI_EP_RX_CNT,
                         0,
                         GNI_CQ_NOBLOCK,
                         NULL,
                         NULL,
                         &(gep->cqhl) );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: GNI_CqCreate returned error %s",
               gni_err_str[status] );
        return(CCI_ERROR);
    }
    debug( CCI_DB_INFO,
           "Rank=%.8d %s: CqCreate: nh=0x%zx cqhl=0x%zx",
           gdev->Rank, __func__, gdev->nh, gep->cqhl );

    status=GNI_CqCreate( gdev->nh,           // Destination CQ
                         GNI_EP_TX_CNT,
                         0,
                         GNI_CQ_NOBLOCK,
                         NULL,
                         NULL,
                         &(gep->cqhd) );
    if( status!=GNI_RC_SUCCESS ) {

        debug( CCI_DB_WARN, "FAIL: GNI_CqCreate returned error %s",
               gni_err_str[status] );
        return(CCI_ERROR);
    }
    debug( CCI_DB_INFO,
           "Rank=%.8d %s: CqCreate: nh=0x%zx cqhd=0x%zx",
           gdev->Rank, __func__, gdev->nh, gep->cqhd );

//  Allocate tx buffer space and assign short message send buffers.
    gep->txbuf=calloc( ep->tx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->tx_buf_cnt; i++ )
        if( (iRC=gni_add_tx( i, ep ))!=1 ) {
  
            iRC=CCI_ENOMEM;
            goto out;
        }
    debug( CCI_DB_INFO, "Rank=%.8d %s: gni_add_tx: buffers=%d",
           gdev->Rank, __func__, ep->tx_buf_cnt );

//  Allocate rx buffer space and assign short message receive buffers.
    gep->rxbuf=calloc( ep->rx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->rx_buf_cnt; i++ )
        if( (iRC=gni_add_rx( i, ep ))!=1 ) {
  
            iRC=CCI_ENOMEM;
            goto out;
        }
    debug( CCI_DB_INFO, "Rank=%.8d %s: gni_add_rx: buffers=%d",
           gdev->Rank, __func__, ep->rx_buf_cnt );

    CCI_EXIT;
    return(CCI_SUCCESS);

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);
    if(gep) {

        if(gep->id)
            gni_put_ep_id( gdev, gep->id );

        if( gep->cqhl!=0 )
            if( (status=GNI_CqDestroy(gep->cqhl))!=GNI_RC_SUCCESS ) {

                debug( CCI_DB_WARN,
                       "FAIL: GNI_CqDestroy returned error %s",
                       gni_err_str[status] );
                return(CCI_ERROR);
            }

        if( gep->cqhd!=0 )
            if( (status=GNI_CqDestroy(gep->cqhd))!=GNI_RC_SUCCESS ) {

                debug( CCI_DB_WARN,
                       "FAIL: GNI_CqDestroy returned error %s",
                       gni_err_str[status] );
                return(CCI_ERROR);
            }

//      while( !TAILQ_EMPTY(&gep->txs) )
//          gni_free_tx( gep, 1 );

//      while( !TAILQ_EMPTY(&gep->rxs) )
//          gni_free_rx( gep, 1 );

        free(gep);
    }

    if(ep)
        free(ep);
    *endpoint=NULL;

    CCI_EXIT;
    return(iRC);
}


static int gni_destroy_endpoint(  cci_endpoint_t *       endpoint ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_destroy_endpoint", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_bind(              cci_device_t *         device,
                                  int32_t                backlog,
                                  uint32_t *             port,
                                  cci_service_t **       service,
                                  cci_os_handle_t *      fd ) {

    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_bind", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_unbind(            cci_service_t *        service,
                                  cci_device_t *         device ) {

    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_unbind", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_get_conn_req(      cci_service_t *        service,
                                  cci_conn_req_t **      conn_req ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_get_conn_req", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_accept(            cci_conn_req_t *       conn_req,
                                  cci_endpoint_t *       endpoint,
                                  cci_connection_t **    connection ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_accept", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_reject(            cci_conn_req_t *       conn_req ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_reject", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_connect(           cci_endpoint_t *       endpoint,
                                  char *                 server_uri,
                                  uint32_t               port,
                                  void *                 data_ptr,
                                  uint32_t               data_len,
                                  cci_conn_attribute_t   attribute,
                                  void *                 context,
                                  int32_t                flags,
                                  struct timeval *       timeout  ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_connect", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_disconnect(        cci_connection_t *     connection ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_disconnect", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_set_opt(           cci_opt_handle_t *     handle,
                                  cci_opt_level_t        level,
                                  cci_opt_name_t         name,
                                  const void *           val,
                                  int32_t                len ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_set_opt", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_get_opt(           cci_opt_handle_t *     handle,
                                  cci_opt_level_t        level,
                                  cci_opt_name_t         name,
                                  void **                val,
                                  int32_t *              len ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_get_opt", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_arm_os_handle(     cci_endpoint_t *       endpoint,
                                  int32_t                flags ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_arm_os_handle", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_get_event(         cci_endpoint_t *         endpoint,
                                  cci_event_t ** const     event,
                                  uint32_t                 flags ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_get_event", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_return_event(      cci_endpoint_t *       endpoint,
                                  cci_event_t *          event ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_return_event", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_send(              cci_connection_t *     connection,
                                  void *                 ptr,
                                  uint32_t               len,
                                  void *                 context,
                                  int32_t                flags ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_send", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_sendv(             cci_connection_t *     connection,
                                  struct iovec *         data,
                                  uint8_t                iovcnt,
                                  void *                 context,
                                  int32_t                flags ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_sendv", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_rma_register(      cci_endpoint_t *       endpoint,
                                  cci_connection_t *     connection,
                                  void *                 start,
                                  uint64_t               length,
                                  uint64_t *             rma_handle ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_rma_register", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_rma_register_phys( cci_endpoint_t *       endpoint,
                                  cci_connection_t *     connection,
                                  cci_sg_t *             sg_list,
                                  uint32_t               sg_cnt,
                                  uint64_t *             rma_handle ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_rma_register_phys", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_rma_deregister(    uint64_t               rma_handle ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_rma_deregister", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_rma(               cci_connection_t *     connection,
                                  void *                 msg_ptr,
                                  uint32_t               msg_len,
                                  uint64_t               local_handle,
                                  uint64_t               local_offset,
                                  uint64_t               remote_handle,
                                  uint64_t               remote_offset,
                                  uint64_t               len,
                                  void *                 context,
                                  int32_t                flags ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_WARN,
           "Rank=%.8d In gni_rma", gdev->Rank );

    return(CCI_ERR_NOT_IMPLEMENTED);
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
