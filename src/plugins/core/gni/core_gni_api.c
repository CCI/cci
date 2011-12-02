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

#include "cci/config.h"
#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"

volatile int32_t                gni_shut_down=0;
gni_globals_t *                 gglobals=NULL;
pthread_t                       gni_tid;
size_t                          gni_page;    // Page size
size_t                          gni_line;    // Data cacheline size


// Retrieve GNI ptag from environment.
uint8_t gni_get_ptag(void) {                 // Still PMI/ALPS based

    char *                   cpPtr;          // character temp
    char *                   cpTok;
    uint8_t                  ptag;           // return value

    cpPtr=getenv("PMI_GNI_PTAG");            // from PMI
    assert( cpPtr!=NULL );                   // something wrong
    cpTok=strtok( cpPtr, ":" );
    ptag=(uint8_t)atoi(cpTok);
    return(ptag);
}


// Retrieve GNI cookie from environment.
uint32_t gni_get_cookie(void) {              // Still PMI/ALPS based

    char *                   cpPtr;          // character temp
    char *                   cpTok;
    uint32_t                 cookie;         // return value

    cpPtr=getenv("PMI_GNI_COOKIE");          // from PMI
    assert( cpPtr!=NULL );                   // something wrong
    cpTok=strtok( cpPtr, ":" );
    cookie=(uint32_t)atoi(cpTok);
    return(cookie);
}


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
    enum cci_status             gRv );
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
static int         gni_accept(
    union cci_event *           conn_req,
    cci_connection_t **         connection );
static int         gni_reject(
    union cci_event *           conn_req );
static int         gni_connect(
    cci_endpoint_t *            endpoint,
    char *                      server_uri,
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
    cci_event_t ** const        event );
static int         gni_return_event(
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
    uint32_t                    iovcnt,
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


// Retrieve GNI NIC address from environment.  Note this is the address
// of the host (PE) upon which we are running.
unsigned int gni_get_nic_address(
    int                      iDev ) {        // Device for which to look

    uint32_t                 Address;
    uint32_t                 Device;
    gni_return_t             gRv;

    gRv=GNI_CdmGetNicAddress( iDev, &Address,// Only physical address
                                    &Device );
    if( gRv!=GNI_RC_SUCCESS )            // gripe if GNI API fails
        fprintf( stderr, "GNI_CdmGetNicAddress returned error %d\n",
                 gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return(Address);
}


void gni_log(
    char *                      pcA,         // failed function
    char *                      nodename,
    uint32_t                    inst_id,
    gni_return_t                gRv ) {      // GNI API return value

    if( gRv!=GNI_RC_SUCCESS )                // Gripe if GNI API fails
        fprintf( stderr, "%8s.%5d %s error %s\n",
                 nodename, inst_id, pcA, gni_err_str[gRv] );
    return;
}


/*
void gni_clear_cd(
    gni_cdm_handle_t *          pcdh ) {     // GNI API cd handle

    gni_return_t                gRv;         // GNI API return value

//  Destroy instance of Communication Domain.
    gRv=GNI_CdmDestroy(*pcdh);               // cd handle
    gni_log( "GNI_CdmDestroy returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return;
}


void gni_clear_cq(
    gni_cq_handle_t *           pcqh ) {     // GNI API CQ handle - recv

    gni_return_t                gRv;         // GNI API return value

//  Destroy CQ.
    gRv=GNI_CqDestroy(*pcqh);                // Get CQ (sends) handle
    gni_log( "GNI_CqDestroy returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return;
}


void gni_clear_vmd(
    uint64_t **                 ppvmd,       // address of memory region
    gni_mem_handle_t *          pmdh ) {     // GNI API region handle

    gni_return_t                gRv;         // GNI API return value

    gRv=GNI_MemDeregister( gni_nich,         // Note NIC handle
                           pmdh );           // Memory handle
    gni_log( "GNI_MemDeregister returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    free(*ppvmd);
    return;
}


void gni_clear_ep(
    gni_ep_handle_t *           peph ) {     // GNI API ep handles list

    gni_return_t                gRv;         // GNI API return value

    gRv=GNI_EpDestroy(*peph);
    gni_log( "GNI_EpDestroy returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return;
}


void gni_create_ep(
    gni_cq_handle_t             cqh,         // GNI API cq handle
    uint32_t                    nic_addr,    // NIC address
    uint32_t                    id,          // message ID
    gni_ep_handle_t *           peph ) {     // GNI API ep handles list

    gni_return_t                gRv;         // GNI API return value

    gRv=GNI_EpCreate( gni_nich,              // Note NIC handle
                      cqh,                   // Note cq handle
                      peph );                // Get ep handle
    gni_log( "GNI_EpCreate returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );

//  Bind endpoint to remote address and message id.  Note: sends
//  require a bound (to remote PE) ep.
    gRv=GNI_EpBind( *peph,                   // Note ep handle
                    nic_addr,                // Remote PE
                    id );                    // Message ID
    gni_log( "GNI_EpBind returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return;
}


void gni_poll_cq(
    gni_cq_handle_t             cqh,         // GNI API CQ handle
    gni_cq_entry_t *            pev ) {      // GNI API CQ (event) entry

    gni_return_t                gRv;         // GNI API return value

//  Poll destination queue for completion.
    gRv=GNI_RC_NOT_DONE;
    while( gRv==GNI_RC_NOT_DONE ) {          // Theoretically, can hang

        gRv=GNI_CqGetEvent( cqh, pev );
        if( gRv!=GNI_RC_SUCCESS && GNI_CQ_OVERRUN(*pev) )
            gni_log( "GNI_CqGetEvent (OVERRUN)", gRv );
        else if( gRv!=GNI_RC_NOT_DONE )
            gni_log( "GNI_CqGetEvent", gRv );
    }
    assert( gRv==GNI_RC_SUCCESS );
    assert(*pev);
    return;
}


void gni_get_cqe(
    gni_cq_handle_t             cqh,         // GNI API CQ handle - recv
    gni_cq_entry_t *            pev ) {      // GNI API CQ (event) entry

    gni_poll_cq( cqh, pev );                 // Get next event off of CQ
    return;
}


void gni_get_checked_event(
    gni_cq_handle_t             cqh,         // GNI API cq handle - send
    gni_post_descriptor_t **    ppdpost,     // GNI API post retrieval
    gni_cq_entry_t *            pev ) {      // GNI API cq (event) entry

    gni_return_t                gRv;      // GNI API return value

    gni_poll_cq( cqh, pev );                 // Get next event off of CQ

//  Check for error in event.
    gRv=GNI_GetCompleted( cqh, *pev, ppdpost );
    gni_log( "GNI_GetCompleted returned", gRv );
    assert( gRv==GNI_RC_SUCCESS );
    return;
}
*/


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


static int gni_init(
    uint32_t                    abi_ver,
    uint32_t                    flags,
    uint32_t *                  caps ) {

    int32_t                     iRv;
    int32_t                     iReject;
    int32_t                     iLength;
//  int32_t                     ntt_base;    // 
    uint32_t                    iPE;
    struct utsname              uBuf;
    pid_t                       pid;
    cci__dev_t *                dev;
    cci_device_t **             dl;
    gni_return_t                gRv;

    CCI_ENTER;
    GNI_SAMPLE_INIT;

    pid=getpid();
    uname(&uBuf);                            // Get nodename
    iLength=strlen(uBuf.nodename)+1;
    debug( CCI_DB_WARN, "%8s.%5d In gni_init()", uBuf.nodename, pid );
#ifdef    linux
    gni_line=                                // Get L1 dcache line size
        sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    gni_page=sysconf(_SC_PAGESIZE);          // Get page size attribute
#else  // linux
    gni_line=GNI_LINE_SIZE;                  // Default if no OS tuning
    gni_page=GNI_PAGE_SIZE;                  // Default if no OS tuning
#endif
    debug( CCI_DB_INFO,
           "%8s.%5d %s: DCACHE_LINESIZE=                       %3zdB",
           uBuf.nodename, pid, __func__, gni_line );
    debug( CCI_DB_INFO,
           "%8s.%5d %s: PAGE_SIZE=                      %10zdB",
           uBuf.nodename, pid, __func__, gni_page );
/*
    ntt_base=-1;
    gRv=GNI_ConfigureNTT( gni_kid, NULL, (uint32_t *)&ntt_base );
    assert( gRv==GNI_RC_SUCCESS );
*/

//  Step 1.  Extract gemini devices from global configuration.
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

        if( !(dev->priv=calloc( 1, sizeof(*gdev) )) ) {

            iRv=CCI_ENOMEM;
            goto out;                        // GNI parameters unsaved
        }       
        gdev=dev->priv;                      // Select GNI device

        gdev->progressing=0;                 // Initialize progress flag

        gdev->nodename=malloc(iLength);      // Memory for nodename
        memset( gdev->nodename, iLength, 0 );
        strcpy( gdev->nodename,              // Set nodename
                uBuf.nodename );
        gdev->inst_id=pid;                   // Use PID for instance ID

//      Only interface available on Cray is 0.
        gdev->kid=0;                         // Set kernel interface
        debug( CCI_DB_INFO,
               "%8s.%5d %s: kid=                                  %4u",
               gdev->nodename, gdev->inst_id, __func__, gdev->kid );

        gdev->ptag=gni_get_ptag();           // Retrieve ptag
        debug( CCI_DB_INFO,
               "%8s.%5d %s: ptag=                               0x%.4x",
               gdev->nodename, gdev->inst_id, __func__, gdev->ptag );

        gdev->cookie=gni_get_cookie();       // Retrieve cookie
        debug( CCI_DB_INFO,
               "%8s.%5d %s: cookie=                         0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__, gdev->cookie );

        gdev->modes=GNI_CDM_MODE_FORK_NOCOPY |\
                    GNI_CDM_MODE_FMA_SHARED  |\
                    0;                       // Set flags on CD
        debug( CCI_DB_INFO,
               "%8s.%5d %s: modes=                          0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__, gdev->modes );

        gRv=GNI_CdmGetNicAddress(
            gdev->kid,                       // device kernel ID
            &(gdev->nic_address),            // Only physical address
            &iPE );                          // PE directly connected
        gni_log( "GNI_CdmGetNicAddress returned",
                 gdev->nodename, gdev->inst_id, gRv );
        assert( gRv==GNI_RC_SUCCESS );
        debug( CCI_DB_INFO,
               "%8s.%5d %s: nic_address=                    0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__,
               gdev->nic_address );


        gRv=GNI_CdmCreate(                   // Get Communication Domain
            gdev->inst_id,                   // instance ID
            gdev->ptag,                      // ptag
            gdev->cookie,                    // cookie
            gdev->modes,                     // CD bit-wise flags
            &(gdev->cd_hndl) );              // Get CD handle
        gni_log( "GNI_CdmCreate returned",
                 gdev->nodename, gdev->inst_id, gRv );
        assert( gRv==GNI_RC_SUCCESS );
        debug( CCI_DB_INFO,
               "%8s.%5d %s: cd_hndl=                        0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__, gdev->cd_hndl );

        gRv=GNI_CdmAttach(                   // Attach to CD
            gdev->cd_hndl,                   // CD handle
            gdev->kid,                       // device kernel ID
            &iPE,                            // PE directly connected
            &(gdev->nic_hndl) );             // Get NIC handle
        gni_log( "GNI_CdmAttach returned",
            gdev->nodename, gdev->inst_id, gRv );
        assert( gRv==GNI_RC_SUCCESS );
        debug( CCI_DB_INFO,
               "%8s.%5d %s: nic_hndl=                       0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__,
               gdev->nic_hndl );

        gdev->ep_ids=calloc( GNI_NUM_BLOCKS, sizeof(*gdev->ep_ids) );
        if(!gdev->ep_ids) {

            iRv=CCI_ENOMEM;
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

        iRv=CCI_ENODEV;
        goto out;
    }

//  Increment list of devices.
    dl=realloc( dl, (gglobals->count+1)*sizeof(cci_device_t *) );
    dl[gglobals->count]=NULL;
    *((cci_device_t ***)&gglobals->devices)=dl;

//  Try to create progress thread.
    iRv=pthread_create( &gni_tid, NULL, gni_progress_thread, NULL );

out:
    if(iRv) {                                // Failed

        if(dl){                              // Free GNI device(s)

            cci_device_t *      device;
            gni_dev_t *         gdev;

            for( device=dl[0]; device!=NULL; device++ ) {

                dev=container_of( device, cci__dev_t, device );
                if(dev->priv) {

                    gdev=dev->priv;
                    gRv=GNI_CdmDestroy(gdev->cd_hndl);
                    gni_log( "GNI_CdmDestroy returned",
                        gdev->nodename, gdev->inst_id, gRv );
                    assert( gRv==GNI_RC_SUCCESS );
                    free(gdev);
                }
            }
        }
        free(dl);                            // Free devices list

        if(gglobals) {

            free(gglobals);
            gglobals=NULL;
        }

        CCI_EXIT;
        return(iRv);
    }

    CCI_EXIT;
    return(CCI_SUCCESS);
}


static const char *gni_strerror(  enum cci_status        gRv ) {

    debug( CCI_DB_WARN, "In gni_strerror()" );
    return(gni_err_str[(enum cci_status)gRv]);
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

    debug( CCI_DB_WARN, "%8s.%5d In gni_get_devices()",
           gdev->nodename, gdev->inst_id );
    debug( CCI_DB_INFO, "%8s.%5d %s: devices=                   %8d",
           gdev->nodename, gdev->inst_id, __func__, gglobals->count );

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

    debug( CCI_DB_WARN, "%8s.%5d In gni_free_devices()",
           gdev->nodename, gdev->inst_id );
    pthread_mutex_lock(&globals->lock);
    gni_shut_down=1;
    pthread_mutex_unlock(&globals->lock);
    pthread_join( gni_tid, NULL );

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
        if( n==0 )
            continue;
        block=n/GNI_BLOCK_SIZE;
        offset=n%GNI_BLOCK_SIZE;
        b=&gdev->ep_ids[block];

        if( (*b & (1ULL<<offset))==0 ) {

            *b|=(1ULL<<offset);
            *id=(block*GNI_BLOCK_SIZE)+offset;
            debug( CCI_DB_CONN, "%8s.%5d %s: id=%u block=%"PRIx64"",
                   gdev->nodename, gdev->inst_id, __func__, *id, *b );
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

    debug( CCI_DB_CONN, "%8s.%5d %s: id=%u block=%"PRIx64"",
           gdev->nodename, gdev->inst_id, __func__, id, *b );
    assert( ((*b>>offset)&0x1)==1 );
    *b&=~(1ULL<<offset);

    return; 
}


static int gni_add_tx(                       // Caller must hold ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    int                         ret=1;    
    gni_ep_t *                  gep=ep->priv;
    gni_tx_t *                  tx;    

    tx=calloc( 1, sizeof(*tx) );
    if(!tx) {

        ret=0;
        goto out;
    }
    tx->evt.event.type=CCI_EVENT_SEND;
    tx->evt.ep=ep;

    tx->buffer=gep->txbuf+i*ep->buffer_len;
    tx->len=0;

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
    return(ret);
}


static int gni_add_rx(                       // Caller must hold ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    int                         ret=1;
    gni_ep_t *                  gep=ep->priv;
    gni_rx_t *                  rx;

    rx=calloc( 1, sizeof(*rx) );
    if(!rx) {

        ret=0;
        goto out;
    }
    rx->evt.event.type=CCI_EVENT_RECV;
    rx->evt.ep=ep;

    rx->buffer=gep->rxbuf+i*ep->buffer_len;
    rx->len=0;

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
    return(ret);
}


static int gni_create_endpoint(   cci_device_t *         device,
                                  int32_t                flags,
                                  cci_endpoint_t **      endpoint,
                                  cci_os_handle_t *      fd ) {

    int32_t                     i;      
    int32_t                     iRv;    
    char *                      name=NULL;
    cci__dev_t *                dev=NULL;
    cci__ep_t *                 ep=NULL;
    gni_ep_t *                  gep=NULL;
    gni_dev_t *                 gdev=NULL;
    uint32_t                    Size;         // Size SMSG mailbox
    uint64_t *                  buffer;
    gni_return_t                gRv;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }

    dev=container_of(device, cci__dev_t, device);
    if(strcmp( "gni", dev->driver )) {

        iRv=CCI_EINVAL;
        goto out;
    }
    gdev=dev->priv;
    debug(CCI_DB_WARN, "%8s.%5d In gni_create_endpoint()",
          gdev->nodename, gdev->inst_id );

    ep=container_of( *endpoint, cci__ep_t, endpoint );
    ep->priv=calloc( 1, sizeof(*gep) );
    if(!ep->priv) {

        iRv=CCI_ENOMEM;
        goto out;
    }

    (*endpoint)->max_recv_buffer_count=GNI_EP_RX_CNT;
    ep->rx_buf_cnt=GNI_EP_RX_CNT;
    ep->tx_buf_cnt=GNI_EP_TX_CNT;
    ep->buffer_len=dev->device.max_send_size;
    ep->tx_timeout=0;

    gep=ep->priv;

//  Get endpoint id.
    pthread_mutex_lock(&dev->lock);
    gni_get_ep_id( gdev, &gep->id );
    pthread_mutex_unlock(&dev->lock);
    debug( (CCI_DB_CONN|CCI_DB_INFO),
           "%8s.%5d %s: id=                  0x%.8x",
           gdev->nodename, gdev->inst_id, __func__, gep->id );

    gep->vmd_flags=GNI_MEM_READWRITE;        // memory region attributes
    debug( CCI_DB_INFO, "%8s.%5d %s: vmd_flags=           0x%.8x",
           gdev->nodename, gdev->inst_id, __func__, gep->vmd_flags );

    gep->vmd_index=-1;                       // Use next available entry
                                             //   in Memory Domain
                                             //   Desciptor Block
    debug( CCI_DB_INFO, "%8s.%5d %s: vmd_index=             %8d",
           gdev->nodename, gdev->inst_id, __func__, gep->vmd_index );

    gRv=GNI_CqCreate(                        // Create local CQ
        gdev->nic_hndl,                      // NIC handle
        2*GNI_EP_TX_CNT,                     // max events
        0,                                   // interrupt on every event
        GNI_CQ_NOBLOCK,                      // interrupt on every event
        NULL,                                // address of event handler
        NULL,                                // context for handler
        &(gep->src_cq_hndl) );               // Get CQ (sends) handle
    gni_log( "GNI_CqCreate returned",
             gdev->nodename, gdev->inst_id, gRv );
    assert( gRv==GNI_RC_SUCCESS );
    debug( CCI_DB_INFO,
           "%8s.%5d %s: src_cq_hndl=         0x%.8zx depth=  %8d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->src_cq_hndl, 2*GNI_EP_TX_CNT );

    gRv=GNI_CqCreate(                        // Create destination CQ
        gdev->nic_hndl,                      // NIC handle
        2*GNI_EP_RX_CNT,                     // max events
        0,                                   // interrupt on every event
        GNI_CQ_NOBLOCK,                      // interrupt on every event
        NULL,                                // address of event handler
        NULL,                                // context for handler
        &(gep->dst_cq_hndl) );               // Get CQ (receives) handle
    gni_log( "GNI_CqCreate returned",
             gdev->nodename, gdev->inst_id, gRv );
    assert( gRv==GNI_RC_SUCCESS );
    debug( CCI_DB_INFO,
           "%8s.%5d %s: dst_cq_hndl=         0x%.8zx depth=  %8d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->dst_cq_hndl, 2*GNI_EP_RX_CNT );

//  Set up mailbox.
    gep->mailbox.nic_address=gdev->nic_address;
    debug( CCI_DB_INFO, "%8s.%5d %s: nic_address=         0x%.8x",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.nic_address );

    gep->mailbox.inst_id=gdev->inst_id;
    debug( CCI_DB_INFO, "%8s.%5d %s: inst_id=             0x%.8x",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.inst_id );

    gep->mailbox.attributes.msg_type=GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
    gep->mailbox.attributes.mbox_maxcredit=GNI_EP_TX_CNT;
    gep->mailbox.attributes.msg_maxsize=GNI_MAX_SIZE;
    gRv=GNI_SmsgBufferSizeNeeded( 
        &(gep->mailbox.attributes),          // Mailbox attributes
        &Size );                             // Get mailbox size
    gni_log( "GNI_SmsgBufferSizeNeeded",
             gdev->nodename, gdev->inst_id, gRv );
    assert( gRv==GNI_RC_SUCCESS );
    Size+=(gni_page-(Size%gni_page));        // Align to page boundary
    gep->mailbox.attributes.buff_size=Size;  // mbox is page-aligned
    debug( CCI_DB_INFO,
           "%8s.%5d %s: VMD size=              %8d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.attributes.buff_size );

    gep->mailbox.attributes.mbox_offset=0;
    debug( CCI_DB_INFO,
           "%8s.%5d %s: VMD offset=            %8d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.attributes.mbox_offset );

    posix_memalign(                          // Allocate mailbox buffer
        (void **)&buffer,                    // pointer to VMD
        gni_page,                            // put VMD on page boundary
        Size );
    assert(buffer);                          // Keeping it real
    gep->mailbox.attributes.msg_buffer=buffer;
    debug( CCI_DB_INFO,
           "%8s.%5d %s: VMD buffer=      %.12zp",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.attributes.msg_buffer );

    gRv=GNI_MemRegister(
        gdev->nic_hndl,                      // NIC handle
        (uint64_t)buffer,                    // Memory block
        Size,                                // Size of memory block
        gep->dst_cq_hndl,                    // Note cq handle
        gep->vmd_flags,                      // Memory region attributes
        gep->vmd_index,                      // Allocation option
        &(gep->mailbox.attributes.mem_hndl) );// Memory handle
    gni_log( "GNI_MemRegister returned",
             gdev->nodename, gdev->inst_id, gRv );
    assert( gRv==GNI_RC_SUCCESS );
    debug( CCI_DB_INFO,                      // mem_hndl is 2 qwords
           "%8s.%5d %s: VMD mem_hndl=0x%.16zx",
           gdev->nodename, gdev->inst_id, __func__,
           gep->mailbox.attributes.mem_hndl );

//  Allocate tx buffer space and assign short message send buffers.
    gep->txbuf=calloc( ep->tx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->tx_buf_cnt; i++ )
        if( (iRv=gni_add_tx( i, ep ))!=1 ) {
  
            iRv=CCI_ENOMEM;
            goto out;
        }
    debug( CCI_DB_INFO, "%8s.%5d %s: gni_add_tx:    buffers= %8d",
           gdev->nodename, gdev->inst_id, __func__, ep->tx_buf_cnt );

//  Allocate rx buffer space and assign short message receive buffers.
    gep->rxbuf=calloc( ep->rx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->rx_buf_cnt; i++ )
        if( (iRv=gni_add_rx( i, ep ))!=1 ) {
  
            iRv=CCI_ENOMEM;
            goto out;
        }
    debug( CCI_DB_INFO, "%8s.%5d %s: gni_add_rx:    buffers= %8d",
           gdev->nodename, gdev->inst_id, __func__, ep->rx_buf_cnt );

    name=malloc(80);
    sprintf( name, "%s%s.%d.%d", GNI_URI, gdev->nodename,
             gep->mailbox.nic_address, gep->mailbox.inst_id );
    *((char **)(&(*endpoint)->name))=strdup(name);
    free(name);
    debug( CCI_DB_WARN, "%8s.%5d %s: %s",
           gdev->nodename, gdev->inst_id, __func__,
           *((char **)(&(*endpoint)->name)) );

    TAILQ_INIT(&gep->txs);
    TAILQ_INIT(&gep->idle_txs);
    TAILQ_INIT(&gep->rxs);
    TAILQ_INIT(&gep->idle_rxs);
    TAILQ_INIT(&gep->conns);
    TAILQ_INIT(&gep->handles);
    TAILQ_INIT(&gep->rma_ops);

    CCI_EXIT;
    return(CCI_SUCCESS);

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);
    if(gep) {

        if(gep->id)
            gni_put_ep_id( gdev, gep->id );

//      if( gep->src_cq_hndl!=0 )
//          gni_clear_cq( &(gep->src_cq_hndl) );

//      if( gep->dst_cq_hndl!=0 )
//          gni_clear_cq( &(gep->dst_cq_hndl) );

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
    return(iRv);
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
           "%8s.%5d In gni_destroy_endpoint()",
           gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_accept(            union cci_event *      conn_req,
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
           "%8s.%5d In gni_accept()", gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_reject(            union cci_event *      conn_req ) {

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
           "%8s.%5d In gni_reject()", gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_connect(           cci_endpoint_t *       endpoint,
                                  char *                 server_uri,
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
           "%8s.%5d In gni_connect()", gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_disconnect()",
           gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_set_opt()", gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_get_opt()", gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_arm_os_handle()",
           gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_get_event(         cci_endpoint_t *         endpoint,
                                  cci_event_t ** const     event ) {

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
           "%8s.%5d In gni_get_event()",
           gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_return_event(      cci_event_t *          event ) {

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
           "%8s.%5d In gni_return_event()",
           gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_send()", gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_sendv(             cci_connection_t *     connection,
                                  struct iovec *         data,
                                  uint32_t               iovcnt,
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
           "%8s.%5d In gni_sendv()", gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_rma_register()",
           gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_rma_register_phys()",
           gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_rma_deregister()",
           gdev->nodename, gdev->inst_id );

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
           "%8s.%5d In gni_rma()", gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static void *gni_progress_thread(
    void *                      arg ) {

    while(!gni_shut_down) {

//      cci__dev_t *            dev;
        cci_device_t const **   device;

        /* for each device, try progressing */
        for( device=gglobals->devices; *device!=NULL; device++ ) {

//          dev=container_of( *device, cci__dev_t, device );
//          gni_progress_dev(dev);
        }
        usleep(GNI_PROG_TIME_US);
    }
    pthread_exit(NULL);
    return(NULL);                            /* make pgcc happy */
}
