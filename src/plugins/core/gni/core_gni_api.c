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
#ifdef    USE_PMI
char *                          cpPTAG="PMI_GNI_PTAG";
char *                          cpCOOKIE="PMI_GNI_COOKIE";
char *                          cpLOC_ADDR="PMI_GNI_LOC_ADDR";
#else  // USE_PMI
char *                          cpPTAG="SHARED_PD_PTAG";
char *                          cpCOOKIE="SHARED_PD_COOKIE";
#endif // USE_PMI


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
    void *                      context,
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


static char *      gni_cci_attribute_to_str(
    const cci_conn_attribute_t  attr ) {

    static char *str[]={

        "CCI_CONN_ATTR_RO",
        "CCI_CONN_ATTR_RU",
        "CCI_CONN_ATTR_UU",
        "CCI_CONN_ATTR_UU_MC_TX",
        "CCI_CONN_ATTR_UU_MC_RX"
    };

    return str[attr];
}


static char * gni_conn_status_to_str(
    const gni_conn_status_t     status ) {

    static char *str[]={
        "GNI_CONN_PENDING",
        "GNI_CONN_ACCEPTED",
        "GNI_CONN_REJECTED",
        "GNI_CONN_GONE"
    };

    return str[status];
}


static void gni_log_sys(                     // Convenience function to
    const cci_device_t *        device,      //   report system errors
    const char *                pcW,
    const char *                pcA ) {

    cci__dev_t *                dev=container_of( device, cci__dev_t,
                                                  device );
    gni_dev_t *                 gdev=dev->priv;

    CCI_ENTER;

    if( gglobals &&                          // Sanity check
        errno!=0 )                           // Report only if error
        debug( CCI_DB_WARN, "%8s.%5d %s: %s: error: %s\n",
               gdev->nodename, gdev->inst_id, pcW, pcA,
                strerror(errno) );

    CCI_EXIT;
    return;
}


static void gni_log_gni(                     // Convenience function to
    const cci_device_t *        device,      //   report GNI errors
    const char *                pcW,
    const char *                pcA,
    gni_return_t                gRv ) {      // GNI API return value

    cci__dev_t *                dev=container_of( device, cci__dev_t,
                                                  device );
    gni_dev_t *                 gdev=dev->priv;

    CCI_ENTER;

    if( gglobals &&                          // Sanity check
        gRv!=GNI_RC_SUCCESS )                // Report only if error
        debug( CCI_DB_WARN, "%8s.%5d %s: %s: error: %s\n",
               gdev->nodename, gdev->inst_id, pcW, pcA,
               gni_err_str[gRv] );

    CCI_EXIT;
    return;
}


#ifdef    USE_PMI
static char * colon_tok(                     // Return i'th token
    char *                      cpPtr,       // String to tokenize
    int                         i ) {        // entry to search out

    char *                      cp;          // Character temp
    char *                      cpTok;       // Return value
    int                         j=-1;        // Initialize counter to -1

    cp=cpPtr;                                // Colon-delimited list
    while( (cpTok=strtok( cp, ":" )) ) {     // Search list

        cp=NULL;                             // Continue with list
        if( (++j)<i )                        // Skip to i'th entry
            continue;
        break;
    }
    return(cpTok);
}
#endif // USE_PMI


uint8_t gni_get_ptag(void) {                 // Return ptag

    uint8_t                     ptag;        // Return value
    char *                      cp;          // Character temp

    assert( (cp=getenv(cpPTAG)) );           // Environment must exist
#ifdef    USE_PMI
    ptag=(uint8_t)atoi(colon_tok( cp, 0 ));
#else  // USE_PMI
    ptag=(uint8_t)strtol( cp, NULL, 0 );
#endif // USE_PMI

    return(ptag);
}


uint32_t gni_get_cookie(void) {              // Return cookie

    uint32_t                    cookie;      // Return value
    char *                      cp;          // Character temp

    assert( (cp=getenv(cpCOOKIE)) );         // Environment must exist
#ifdef    USE_PMI
    cookie=(uint32_t)atoi(colon_tok( cp, 0 ));
#else  // USE_PMI
    cookie=(uint32_t)strtol( cp, NULL, 0 );
#endif // USE_PMI

    return(cookie);
}


uint32_t gni_get_nic_addr(                   // Return NIC address
    const cci_device_t *        device,      // driver device
    const uint8_t               i ) {        // i'th GNI kernel driver

    uint32_t                    nic_addr;    // Return value
#ifdef    USE_PMI
    char *                      cp;          // Character temp

    assert( (cp=getenv(cpLOC_ADDR)) );       // Environment must exist
    assert( (cp=colon_tok( cp, i )) );       // Bad if entry not found
    nic_addr=(uint32_t)atoi(cp);
#else  // USE_PMI
    uint32_t                    iPE;
    gni_return_t                gRv;

    gRv=GNI_CdmGetNicAddress( i,             // device kernel ID
                              &nic_addr,     // Only physical address
                              &iPE );        // PE directly connected
    gni_log_gni( device, __func__, "GNI_CdmGetNicAddress", gRv );
    assert( gRv==GNI_RC_SUCCESS );
#endif // USE_PMI

    return(nic_addr);
}


int gni_get_socket(                          // To initialize GNI, we
    cci_device_t *              device ) {   //    need socket to get
                                             //    remote gni_mailbox_t
    int                         iRv;
    int                         flags;
    struct sockaddr_in          sin;
    struct ifaddrs *            pif;

    int                         sd=-1;       // Socket descriptor
    int                         backlog=128;
    struct ifaddrs *            pif0=NULL;
    socklen_t                   is=sizeof(sin);
    cci__dev_t *                dev=container_of( device, cci__dev_t,
                                                  device );
    gni_dev_t *                 gdev=dev->priv;
    cci_status_t                cRv=CCI_ENODEV;

    CCI_ENTER;

    if(!gglobals)                            // Sanity check
        goto FAIL;

    sd=socket( AF_INET, SOCK_STREAM, 0 );    // Try to create socket
    if( sd==-1 ) {                           // .. failed

        gni_log_sys( device, __func__, "socket" );
        goto FAIL;
    }

    if( getifaddrs(&pif0)==-1 ) {            // Get list of interfaces

        gni_log_sys( device, __func__, "getifaddrs" );
        goto FAIL;
    }

    for( pif=pif0; pif!=NULL;                // Search list
         pif=pif->ifa_next ) {

        if( strncmp( pif->ifa_name, GNI_IP_IF, strlen(GNI_IP_IF) ) )
            continue;                        // Skip unless names match

        if( pif->ifa_addr->sa_family!=AF_INET )
            continue;                        // Skip if not TCP/IP

        if( pif->ifa_flags & IFF_UP );
            break;                           // Stop if up
    }

    if(!pif) {                               // Search failed

        errno=ENODEV;                        // Set errno
        gni_log_sys( device, __func__, "Search failed" );
        goto FAIL;
    }

    memcpy( &sin, pif->ifa_addr, is );       // Get address of interface
    if(gdev->port)                           // Set port
        sin.sin_port=gdev->port;             // .. not ephemeral port

    iRv=bind( sd,                            // Bind socket
              (const struct sockaddr *)&sin,
              is );
    if( iRv==-1 ) {                          // .. failed

        gni_log_sys( device, __func__, "bind" );
        goto FAIL;
    }

    flags=fcntl( sd, F_GETFL, 0 );           // Get socket flags
    if( flags==-1 )                          // .. failed .. reset
        flags=0;

    iRv=fcntl( sd, F_SETFL,                  // Try to set non-blocking
               flags | O_NONBLOCK );         // .. want asynchronous
    if( iRv==-1 ) {                          // .. failed

        gni_log_sys( device, __func__, "fcntl" );
        goto FAIL;
    }

    iRv=getsockname( sd,                     // If socket was ephemeral
                     (struct sockaddr *)&sin,// .. need to get updated
                     &is );                  // .. address (port)
    if( iRv==-1 ) {                          // .. failed

        gni_log_sys( device, __func__, "getsockname" );
        goto FAIL;
    }

    if( listen( sd, backlog )==-1 ) {        // Set socket to listen

        gni_log_sys( device, __func__, "listen" );
        goto FAIL;
    }

    gdev->port=sin.sin_port;                 // Update (ephemeral port)
    gdev->sd=sd;                             // sd for listen port
    debug( CCI_DB_INFO, "%8s.%5d %s: listen on if=%s addr=%s:%d sd=%d",
           gdev->nodename, gdev->inst_id, __func__, pif->ifa_name,
           inet_ntoa(sin.sin_addr), gdev->port, gdev->sd );

    cRv=CCI_SUCCESS;

    FAIL:
    if(pif0)
        freeifaddrs(pif0);

    if( cRv!=CCI_SUCCESS ) {

        if( sd!=-1 )
            close(sd);
        gdev->sd=-1;
    }

    CCI_EXIT;
    return(cRv);
}


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
    gni_rma_deregister,
    gni_rma
};


static int gni_init(
    uint32_t                    abi_ver,
    uint32_t                    flags,
    uint32_t *                  caps ) {

    int32_t                     iTmp;        // integer temporary
    uint32_t                    iPE;
    struct utsname              uBuf;
    pid_t                       pid;
    cci__dev_t *                dev;
    gni_return_t                gRv;

    int32_t                     iReject=1;   // Default to no device
    cci_status_t                cRv=CCI_ENOMEM;
    cci_device_t **             dl=NULL;

    CCI_ENTER;
    GNI_SAMPLE_INIT;

    uname(&uBuf);                            // Get nodename
    pid=getpid();                            // Get PID
    iTmp=strlen(uBuf.nodename)+1;            // We will need this later
    debug( CCI_DB_FUNC, "%8s.%5d In gni_init()", uBuf.nodename, pid );

//  Allocate container for GNI devices.
    if( !(gglobals=calloc( 1, sizeof(*gglobals) )) )
        goto FAIL;

//  Allocate array of GNI devices.
    if( !(dl=calloc( CCI_MAX_DEVICES, sizeof(*gglobals->devices) )) )
        goto FAIL;

//  Get page size.
#ifdef    linux
    gni_page=sysconf(_SC_PAGESIZE);          // Get page size attribute
#else  // linux
    gni_page=GNI_PAGE_SIZE;                  // Default if no OS tuning
#endif
    debug( CCI_DB_INFO,
           "%8s.%5d %s: PAGE_SIZE=                      %10zdB",
           uBuf.nodename, pid, __func__, gni_page );

//  Get L1 Dcache size (not needed at present).
#ifdef    linux
    gni_line=                                // Get L1 dcache line size
        sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
#else  // linux
    gni_line=GNI_LINE_SIZE;                  // Default if no OS tuning
#endif
    debug( CCI_DB_INFO,
           "%8s.%5d %s: DCACHE_LINESIZE=                       %3zdB",
           uBuf.nodename, pid, __func__, gni_line );

//  Step 1.  Extract Gemini device(s) from global configuration.
    srandom( (unsigned int)gni_get_usecs() );
    TAILQ_FOREACH( dev, &globals->devs, entry ) {

        const char **           arg;  
        cci_device_t *          device;
        gni_dev_t *             gdev;  

        if(strcmp( "gni", dev->driver ))     // Go to next device if not
            continue;                        // .. using "gni" driver

        gdev=calloc( 1, sizeof(*gdev) );     // Try to create GNI device
        if(!gdev)                            // .. failed
            goto FAIL;

        gdev->ep_ids=calloc( GNI_NUM_BLOCKS, sizeof(*gdev->ep_ids) );
        if(!gdev->ep_ids)
            goto FAIL;

        iReject=0;                           // Gemini configured
        dev->priv=gdev;                      // Set to GNI device

        device=&dev->device;                 // Select this device
        device->rate=160000000000;           // per Gemini spec
        device->pci.domain=-1;               // per CCI spec
        device->pci.bus=-1;                  // per CCI spec
        device->pci.dev=-1;                  // per CCI spec
        device->pci.func=-1;                 // per CCI spec
        device->max_send_size=GNI_DEFAULT_MSS;

        gdev->progressing=0;                 // Initialize progress flag
        gdev->nodename=malloc(iTmp);         // Allocate nodename
        memset( gdev->nodename, iTmp, 0 );   // Clear nodename
        strcpy( gdev->nodename,              // Set nodename
                uBuf.nodename );
        gdev->inst_id=pid;                   // Use PID for instance ID

        if(*caps)                            // Server
            gdev->port=GNI_LISTEN_PORT;      // Use default port
        else                                 // Client
            gdev->port=0;                    // Use ephemeral port


//      Only kernel interface available on Cray is 0.
        gdev->kid=0;
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

        gdev->nic_addr=gni_get_nic_addr( device, gdev->kid );

        debug( CCI_DB_INFO,
               "%8s.%5d %s: nic_addr=                       0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__,
               gdev->nic_addr );

        gRv=GNI_CdmCreate(                   // Get Communication Domain
            gdev->inst_id,                   // instance ID
            gdev->ptag,                      // ptag
            gdev->cookie,                    // cookie
            gdev->modes,                     // CD bit-wise flags
            &(gdev->cd_hndl) );              // Get CD handle
        if( gRv!=GNI_RC_SUCCESS ) {

            gni_log_gni( device, __func__, "GNI_CdmCreate", gRv );
            cRv=CCI_ENODEV;
            goto FAIL;
        }
        debug( CCI_DB_INFO,
               "%8s.%5d %s: cd_hndl=                        0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__, gdev->cd_hndl );

        gRv=GNI_CdmAttach(                   // Attach to CD
            gdev->cd_hndl,                   // CD handle
            gdev->kid,                       // device kernel ID
            &iPE,                            // PE directly connected
            &(gdev->nic_hndl) );             // Get NIC handle
        if( gRv!=GNI_RC_SUCCESS ) {

            gni_log_gni( device, __func__, "GNI_CdmAttach", gRv );
            cRv=CCI_ENODEV;
            goto FAIL;
        }
        debug( CCI_DB_INFO,
               "%8s.%5d %s: nic_hndl=                       0x%.8zx",
               gdev->nodename, gdev->inst_id, __func__,
               gdev->nic_hndl );

        dl[gglobals->count]=device;
        gglobals->count++;
        dev->is_up=1;

//      Parse conf_argv (configuration file parameters).
        for( arg=device->conf_argv; *arg!=NULL; arg++ ) {

            if(!strncmp( "mtu=", *arg, 4 )) {// Config file override

                const char *    mss_str=*arg+4;
                uint32_t        mss=strtol( mss_str, NULL, 0 );

                if( mss>GNI_MAX_MSS )        // Conform to upper limit
                    mss=GNI_MAX_MSS;
                else if( mss<GNI_MIN_MSS )   // Conform to lower limit
                    mss=GNI_MIN_MSS;
                device->max_send_size=mss;   // Override max_send_size
            }

//          For the purpose of establishing a "connection" with another
//          instance on the Gemini network, the instance requesting the
//          connection is defined to be a client; the instance receiving
//          this request is a server.  The client needs to know the URI
//          of the server in order to make this request.  The server
//          just needs to listen for requests.
//
//          So, the client must specify the IP part of the URI of the
//          server in its connection request.  For example:
//
//              ip://nodename:port
//
//          This allows the client to send its GNI address information
//          and mailbox attributes (along with the CCI connection
//          attributes, length of payload, and optional payload) in the
//          form of a connection request.  In turn, the server will
//          reply with its accept or reject and mailbox attributes.
            if( *caps &&
                !strncmp( "server=", *arg, 7 ) ) {

                char *          server=strdup(*arg+7);
                char *          port;

                for( port=server;
                     *port!=' ' && *port!='\t' &&
                     *port!=':' && *port!='\0';
                     port++ );

                if( *port!=':' )             // Not a delimiter
                    gdev->port=GNI_LISTEN_PORT;
                else                         // Get port override
                    gdev->port=atoi(++port);

                free(server);
            }
        }
        gni_get_socket(device);              // initialization socket
    }

    if(iReject) {                            // Gemini not configured

        cRv=CCI_ENODEV;
        goto FAIL;
    }

//  Increment list of devices.
    dl=realloc( dl, (gglobals->count+1)*sizeof(cci_device_t *) );
    dl[gglobals->count]=NULL;
    *((cci_device_t ***)&gglobals->devices)=dl;

//  Try to create progress thread.
    errno=pthread_create( &gni_tid, NULL, gni_progress_thread, NULL );
    if(errno) {

        gni_log_sys( gglobals->devices[0], __func__, "pthread_create" );
        goto FAIL;
    }
    cRv=CCI_SUCCESS;

    FAIL:
    if( cRv!=CCI_SUCCESS) {                  // Failed

        if(dl){                              // Free GNI device(s)

            cci_device_t *      device;
            gni_dev_t *         gdev;

            for( device=dl[0]; device!=NULL; device++ ) {

                dev=container_of( device, cci__dev_t, device );
                if(dev->priv) {

                    gdev=dev->priv;
                    gRv=GNI_CdmDestroy(gdev->cd_hndl);
                    gni_log_gni( device, __func__, "GNI_CdmDestroy",
                                 gRv );
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
    }

    CCI_EXIT;
    return(cRv);
}


static const char *gni_strerror(  enum cci_status        gRv ) {

    debug( CCI_DB_FUNC, "In gni_strerror()" );
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

    debug( CCI_DB_FUNC, "%8s.%5d In gni_get_devices()",
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

    debug( CCI_DB_FUNC, "%8s.%5d In gni_free_devices()",
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


static int gni_add_tx(                       // Caller holds ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    gni_ep_t *                  gep=ep->priv;
    gni_tx_t *                  tx;    

    int                         ret=1;    

    tx=calloc( 1, sizeof(*tx) );
    if(!tx) {

        ret=0;
        goto FAIL;
    }

    tx->evt.event.type=CCI_EVENT_SEND;
    tx->evt.ep=ep;
    tx->buffer=gep->txbuf+i*ep->buffer_len;
    tx->len=0;
    TAILQ_INSERT_TAIL( &gep->txs, tx, tentry );
    TAILQ_INSERT_TAIL( &gep->idle_txs, tx, dentry );

    FAIL:
        if(!ret) {
            if(tx) {
                if(tx->buffer)
                    free(tx->buffer);
                free(tx);
            }
        }
        return(ret);
}


static int gni_add_rx(                       // Caller holds ep->lock
    int                         i,
    cci__ep_t *                 ep ) {

    gni_ep_t *                  gep=ep->priv;
    gni_rx_t *                  rx;

    int                         ret=1;

    rx=calloc( 1, sizeof(*rx) );
    if(!rx) {

        ret=0;
        goto FAIL;
    }

    rx->evt.event.type=CCI_EVENT_RECV;
    rx->evt.ep=ep;
    rx->buffer=gep->rxbuf+i*ep->buffer_len;
    rx->len=0;
    TAILQ_INSERT_TAIL(&gep->rxs, rx, gentry);
    TAILQ_INSERT_TAIL(&gep->idle_rxs, rx, entry);

    FAIL:
        if(!ret) {
            if(rx) {
                if(rx->buffer)
                    free(rx->buffer);
                free(rx);
            }
        }
        return(ret);
}


static int gni_create_endpoint(
    cci_device_t *              device,
    int32_t                     flags,
    cci_endpoint_t **           endpoint,
    cci_os_handle_t *           fd ) {

    int32_t                     i;      
    uint32_t                    Size;         // Size SMSG mailbox
    uint64_t *                  buffer;
    gni_return_t                gRv;

    char *                      name=NULL;
    cci__dev_t *                dev=NULL;
    cci__ep_t *                 ep=NULL;
    gni_ep_t *                  gep=NULL;
    gni_dev_t *                 gdev=NULL;
    cci_status_t                cRv=CCI_ENODEV;    

    CCI_ENTER;

    if(!gglobals)
        goto FAIL;

    dev=container_of(device, cci__dev_t, device);
    if(strcmp( "gni", dev->driver )) {

        cRv=CCI_EINVAL;
        goto FAIL;
    }

    gdev=dev->priv;
    debug(CCI_DB_FUNC, "%8s.%5d In gni_create_endpoint()",
          gdev->nodename, gdev->inst_id );

    ep=container_of( *endpoint, cci__ep_t, endpoint );
    ep->priv=calloc( 1, sizeof(*gep) );
    if(!ep->priv) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }
    debug(CCI_DB_INFO,
          "%8s.%5d %s: device->name=%18s",
          gdev->nodename, gdev->inst_id, __func__, device->name );

    (*endpoint)->max_recv_buffer_count=GNI_EP_RX_CNT;
    ep->rx_buf_cnt=GNI_EP_RX_CNT;
    ep->tx_buf_cnt=GNI_EP_TX_CNT;
    ep->buffer_len=dev->device.max_send_size;
    ep->tx_timeout=0;
    gep=ep->priv;
    gep->sd=-1;

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
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_CqCreate[src_cq]", gRv );
        goto FAIL;
    }
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
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_CqCreate[dst_cq]", gRv );
        goto FAIL;
    }
    debug( CCI_DB_INFO,
           "%8s.%5d %s: dst_cq_hndl=         0x%.8zx depth=  %8d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->dst_cq_hndl, 2*GNI_EP_RX_CNT );

//  Set up mailbox.
    gep->src_box.nic_addr=gdev->nic_addr;
    gep->src_box.inst_id=gdev->inst_id;
    gep->src_box.attr.msg_type=GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
    gep->src_box.attr.mbox_maxcredit=GNI_EP_TX_CNT;
    gep->src_box.attr.msg_maxsize=dev->device.max_send_size;
    gRv=GNI_SmsgBufferSizeNeeded( 
        &(gep->src_box.attr),                // SMSG attributes
        &Size );                             // Get mailbox size
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_SmsgBufferSizeNeeded",
                     gRv );
        goto FAIL;
    }
    Size+=(gni_page-(Size%gni_page));        // Align to page boundary
    gep->src_box.attr.buff_size=Size;        // mbox is page-aligned
    gep->src_box.attr.mbox_offset=0;
    posix_memalign(                          // Allocate mailbox buffer
        (void **)&buffer,                    // pointer to VMD
        gni_page,                            // put VMD on page boundary
        Size );
    if(!buffer) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }

    gep->src_box.attr.msg_buffer=buffer;
    gRv=GNI_MemRegister(
        gdev->nic_hndl,                      // NIC handle
        (uint64_t)buffer,                    // Memory block
        Size,                                // Size of memory block
        gep->dst_cq_hndl,                    // Note cq handle
        gep->vmd_flags,                      // Memory region attributes
        gep->vmd_index,                      // Allocation option
        &(gep->src_box.attr.mem_hndl) );     // Memory handle
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_MemRegister", gRv );
        goto FAIL;
    }
    debug( CCI_DB_INFO, 
           "%8s.%5d %s: 0x%.8x 0x%.4x %d %zp %d %x %x %d %d %d",
           gdev->nodename, gdev->inst_id, __func__,
           gep->src_box.nic_addr, gep->src_box.inst_id,
           gep->src_box.attr.msg_type,
           gep->src_box.attr.msg_buffer,
           gep->src_box.attr.buff_size,
           gep->src_box.attr.mem_hndl,
           gep->src_box.attr.mbox_offset,
           gep->src_box.attr.mbox_maxcredit,
           gep->src_box.attr.msg_maxsize );

//  Initialize queues.
    TAILQ_INIT(&gep->conns);

    TAILQ_INIT(&gep->txs);
    TAILQ_INIT(&gep->idle_txs);
    TAILQ_INIT(&gep->rxs);
    TAILQ_INIT(&gep->idle_rxs);
    TAILQ_INIT(&gep->handles);
    TAILQ_INIT(&gep->rma_ops);

//  Allocate tx buffer space and assign short message send buffers.
    gep->txbuf=calloc( ep->tx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->tx_buf_cnt; i++ )
        if( (cRv=gni_add_tx( i, ep ))!=1 ) {
  
            cRv=CCI_ENOMEM;
            goto FAIL;
        }
    debug( CCI_DB_INFO, "%8s.%5d %s: gni_add_tx:    buffers= %8d",
           gdev->nodename, gdev->inst_id, __func__, ep->tx_buf_cnt );

//  Allocate rx buffer space and assign short message receive buffers.
    gep->rxbuf=calloc( ep->rx_buf_cnt, ep->buffer_len );
    for( i=0; i<ep->rx_buf_cnt; i++ )
        if( (cRv=gni_add_rx( i, ep ))!=1 ) {
  
            cRv=CCI_ENOMEM;
            goto FAIL;
        }
    debug( CCI_DB_INFO, "%8s.%5d %s: gni_add_rx:    buffers= %8d",
           gdev->nodename, gdev->inst_id, __func__, ep->rx_buf_cnt );

    name=malloc(GNI_URI_MAX_LENGTH);
    if(!name) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }
    sprintf( name,
             "%s0x%.8zx:0x%.4x:%s:0x%.4x",
             GNI_URI, gep->src_box.nic_addr, gep->src_box.inst_id,
             gdev->nodename, gdev->port );
    *((char **)(&(*endpoint)->name))=strdup(name);
    free(name);
    debug( CCI_DB_INFO, "%8s.%5d %s: %s",
           gdev->nodename, gdev->inst_id, __func__,
           *((char **)(&(*endpoint)->name)) );

    pthread_mutex_lock(&dev->lock);
    TAILQ_INSERT_TAIL( &dev->eps, ep, entry );
    pthread_mutex_unlock(&dev->lock);
    cRv=CCI_SUCCESS;

    FAIL:
    if( cRv!=CCI_SUCCESS ) {

        pthread_mutex_lock(&dev->lock);
        TAILQ_REMOVE( &dev->eps, ep, entry );
        pthread_mutex_unlock(&dev->lock);
        if(gep) {

            if(gep->id)
                gni_put_ep_id( gdev, gep->id );

//          if( gep->src_cq_hndl!=0 )
//              gni_clear_cq( &(gep->src_cq_hndl) );

//          if( gep->dst_cq_hndl!=0 )
//              gni_clear_cq( &(gep->dst_cq_hndl) );

//          while( !TAILQ_EMPTY(&gep->txs) )
//              gni_free_tx( gep, 1 );

//          while( !TAILQ_EMPTY(&gep->rxs) )
//              gni_free_rx( gep, 1 );

            free(gep);
        }

        if(ep)
            free(ep);
        *endpoint=NULL;
    }

    CCI_EXIT;
    return(cRv);
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
    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_destroy_endpoint()",
           gdev->nodename, gdev->inst_id );

    return(CCI_ERR_NOT_IMPLEMENTED);
}


static int gni_accept(
    union cci_event *           event,
    void *                      context,
    cci_connection_t **         connection ) {

    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;
    gni_return_t                gRv;

    int                         sz=sizeof(gni_mailbox_t);
    cci__evt_t *                evt=container_of( event, cci__evt_t,
                                                  event );
    cci__ep_t *                 ep=evt->ep;
    cci_endpoint_t *            endpoint=&ep->endpoint;
    gni_ep_t *                  gep=ep->priv;
    cci__conn_t *               conn=NULL;
    gni_conn_t *                gconn=NULL;
    cci_status_t                cRv=CCI_ENODEV;

    CCI_ENTER;

    if(!gglobals)
        goto FAIL;

    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_accept()", gdev->nodename, gdev->inst_id );

    conn=calloc( 1, sizeof(*conn) );
    if(!conn) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }

    gconn=calloc( 1, sizeof(*gconn) );       // Now, the GNI part
    if(!gconn) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }

    conn->tx_timeout=ep->tx_timeout;         // timeout presently unused
    conn->connection.endpoint=endpoint;
    conn->connection.context=context;
    gconn->status=GNI_CONN_FAILED;
    gconn->conn=conn;                        // point back to conn
    conn->priv=gconn;

//  Accept client attributes.
    conn->connection.attribute=gep->dst_box.cci_attr;

//  Arbitrate connection to smaller of send sizes.
    if( gep->dst_box.attr.msg_maxsize<dev->device.max_send_size )
        conn->connection.max_send_size=gep->dst_box.attr.msg_maxsize;
    else
        conn->connection.max_send_size=dev->device.max_send_size;

//  Add to list of gconn on this endpoint.
    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL( &gep->conns, gconn, entry );
    pthread_mutex_unlock(&ep->lock);

//  Set up GNI endpoint for remote connection.
    gRv=GNI_EpCreate( gdev->nic_hndl,        // Note NIC handle
                      gep->src_cq_hndl,      // Note cq handle
                      &(gep->ep_hndl) );     // Get ep handle
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_EpCreate", gRv );
        goto FAIL;
    }

    gRv=GNI_EpBind( gep->ep_hndl,            // Note ep handle
                    gep->dst_box.nic_addr,   // remote NIC address
                    gep->dst_box.inst_id );  // remote instance
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_EpCreate", gRv );
        goto FAIL;
    }

//  Initialize SMSG mailbox for remote connection.
    gRv=GNI_SmsgInit( gep->ep_hndl,
                      &(gep->src_box.attr),
                      &(gep->dst_box.attr) );
    if( gRv!=GNI_RC_SUCCESS ) {

        gni_log_gni( device, __func__, "GNI_SmsgInit", gRv );
        goto FAIL;
    }

//  Accept connection request; send reply.
    gep->src_box.info.reply=GNI_CONN_ACCEPTED;
    if( sz!=send( gep->sd, &(gep->src_box), sz, 0 ) ) {

        gni_log_sys( device, __func__, "send" );
        goto FAIL;
    }
    *connection=&conn->connection;
    gconn->status=GNI_CONN_ACCEPTED;

    cRv=CCI_SUCCESS;

    FAIL:
    close(gep->sd);
    gep->sd=-1;
    pthread_mutex_unlock(&gep->lock);        // locked by progress

    CCI_EXIT;
    return(cRv);
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


static int gni_connect(
    cci_endpoint_t *            endpoint,
    char *                      server_uri,
    void *                      data_ptr,
    uint32_t                    data_len,
    cci_conn_attribute_t        attribute,
    void *                      context,
    int32_t                     flags,
    struct timeval *            timeout  ) {

    int                         iRv;
    char *                      port;
    struct sockaddr_in          sin;
    struct addrinfo *           info;
    struct addrinfo             hint;
    cci_connection_t *          connection;

    char *                      hostname=NULL;
    socklen_t                   is=sizeof(sin);
    cci_device_t const *        device=gglobals->devices[0];
    cci__dev_t *                dev=container_of( device, cci__dev_t,
                                                  device );
    gni_dev_t *                 gdev=dev->priv;
    cci__ep_t *                 ep=container_of( endpoint, cci__ep_t,
                                                 endpoint );
    gni_ep_t *                  gep=ep->priv;
    cci__conn_t *               conn=NULL;
    gni_conn_t *                gconn=NULL;
    cci_status_t                cRv=CCI_ENODEV;

    CCI_ENTER;

    if(!gglobals)
        goto FAIL;

    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_connect()", gdev->nodename, gdev->inst_id );

    conn=calloc( 1, sizeof(*conn) );         // Create a cci__conn_t
    if(!conn) {                              // includes the
                                             // .. cci_connection_t
        cRv=CCI_ENOMEM;
        goto FAIL;
    }

    gconn=calloc( 1, sizeof(*gconn) );       // Now, the GNI part
    if(!gconn) {

        cRv=CCI_ENOMEM;
        goto FAIL;
    }

    hostname=strchr( server_uri, '/' );      // Extracting hostname
    if(!hostname) {

        cRv=CCI_EINVAL;                      // Not found
        goto FAIL;
    }
    hostname+=2;                             // Go to start of hostname
    hostname=strdup(hostname);               // Work with a copy

    port=strchr( hostname, ':' );            // Find delimiter
    if(!port) {

        cRv=CCI_EINVAL;                      // Not found
        goto FAIL;
    }
    *port='\0';                              // .. replace with '\0'
    port++;                                  // Skip to port

    memset( &hint, 0, sizeof(hint) );        // Set hints
    hint.ai_family=AF_INET;                  // .. only IP
    hint.ai_socktype=SOCK_STREAM;            // .. only streams
    hint.ai_protocol=IPPROTO_TCP;            // .. only TCP
    if( (iRv=getaddrinfo( hostname, NULL, &hint, &info )) ) {

        debug( CCI_DB_INFO, "%8s.%5d %s: getaddrinfo(%s): %d",
               gdev->nodename, gdev->inst_id, __func__, hostname,
               gai_strerror(iRv) );
        goto FAIL;
    }

    memcpy( &sin, info->ai_addr, is );       // Save socket address
    sin.sin_port=atoi(port);                 // Set server listen port
    freeaddrinfo(info);

//  Set members of cci__conn_t structure.
    connection=&conn->connection;            // Start w/cci_connection_t
    connection->max_send_size=device->max_send_size;
    connection->endpoint=endpoint;
    connection->attribute=attribute;
    connection->context=context;

    conn->uri=strdup(server_uri);            // continue with others
    conn->tx_timeout=ep->tx_timeout;         // Default to ep timeout
    if(timeout)                              // convert to micro-seconds
        conn->tx_timeout=(timeout->tv_sec*1000000)+timeout->tv_usec;
    conn->priv=gconn;

    gconn->status=GNI_CONN_PENDING;          // continue with GNI part
    gconn->data_ptr=data_ptr;                // optional payload
    gconn->data_len=data_len;                // payload length
    gconn->sin=sin;                          // target socket address
    gconn->conn=conn;                        // point back to conn

//  Add to list of gconn on this endpoint.
    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL( &gep->conns, gconn, entry );
    pthread_mutex_unlock(&ep->lock);

    cRv=CCI_SUCCESS;

    FAIL:
    if(hostname)
        free(hostname);
    if( cRv!=CCI_SUCCESS ) {

        if(gconn)
            free(gconn);
        if(conn)
            free(conn);
    }

    CCI_EXIT;
    return(cRv);
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

//  cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;
    cci__ep_t *                 ep;
    cci__evt_t *                evt;
    cci_status_t                cRv;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }

    ep=container_of(endpoint, cci__ep_t, endpoint);
    dev=ep->dev;
    gdev=dev->priv;
    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_get_event()",
           gdev->nodename, gdev->inst_id );

    pthread_mutex_lock(&ep->lock);
    if( !TAILQ_EMPTY(&ep->evts) ) {

        evt=TAILQ_FIRST(&ep->evts);
        *event=&evt->event;
        cRv=CCI_SUCCESS;
    } else
        cRv=CCI_EAGAIN;
    pthread_mutex_unlock(&ep->lock);
    usleep(GNI_PROG_TIME_US);

    return(cRv);
}


static int gni_return_event(
    cci_event_t *               event ) {

    void *                      buffer;
    cci_device_t const *        device;
    cci__dev_t *                dev;
    gni_dev_t *                 gdev;

    cci__evt_t *                evt =container_of( event, cci__evt_t,
                                                   event );
    cci__ep_t *                 ep=evt->ep;
//  gni_ep_t *                  gep=ep->priv;
    cci_status_t                cRv=CCI_ERR_NOT_IMPLEMENTED;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }

    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_return_event()",
           gdev->nodename, gdev->inst_id );

    switch(event->type) {

        case CCI_EVENT_RECV:
            buffer=*((void **)&evt->event.recv.ptr);
//          Mark buffer as no longer in use.
            goto event_next;

        case CCI_EVENT_CONNECT_REQUEST:
            buffer=*((void **)&evt->event.request.data_ptr);
            free(buffer);

        case CCI_EVENT_SEND:
        case CCI_EVENT_CONNECT_TIMEDOUT:
        case CCI_EVENT_CONNECT_REJECTED:
        case CCI_EVENT_CONNECT_ACCEPTED:
            event_next:
            pthread_mutex_lock(&ep->lock);
            TAILQ_REMOVE( &ep->evts, evt, entry );
            pthread_mutex_unlock(&ep->lock);
            free(evt);
            cRv=CCI_SUCCESS;
            break;

        case CCI_EVENT_NONE:
        case CCI_EVENT_KEEPALIVE_TIMEDOUT:
        case CCI_EVENT_ENDPOINT_DEVICE_FAILED:
            break;
    }

    return(cRv);
}


static int gni_send(              cci_connection_t *     connection,
                                  void *                 ptr,
                                  uint32_t               len,
                                  void *                 context,
                                  int32_t                flags ) {

    cci_device_t const *        device;
    cci_endpoint_t *            endpoint=connection->endpoint;
    cci__ep_t *                 ep;
    cci__dev_t *                dev;
//  cci__conn_t *               conn;
    gni_ep_t *                  gep;
    gni_dev_t *                 gdev;
//  gni_conn_t *                gconn;
    uint64_t                    hdr[2];
    gni_return_t                gRv;

    if(!gglobals) {

        CCI_EXIT;
        return(CCI_ENODEV);
    }
    device=*(gglobals->devices);
    dev=container_of( device, cci__dev_t, device );
    gdev=dev->priv;
    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_send()", gdev->nodename, gdev->inst_id );
//  conn=container_of( connection, cci__conn_t, connection );
//  gconn=conn->priv;
    ep=container_of( endpoint, cci__ep_t, endpoint );
    gep=ep->priv;

    gRv=GNI_EpSetEventData( gep->ep_hndl,
                            0,      
                            gep->id );  
    assert( gRv==GNI_RC_SUCCESS );

    hdr[0]=gep->id;
    hdr[1]=len;
    debug( CCI_DB_INFO,
           "%8s.%5d %s: send %lx %ld %lx %lx %lx",
           gdev->nodename, gdev->inst_id, __func__, hdr[0], hdr[1],
           *((uint64_t *)(ptr+0)), *((uint64_t *)(ptr+8)),
           *((uint64_t *)(ptr+16)) );
    gRv=GNI_SmsgSend(       gep->ep_hndl,    // Target GNI endpoint
                            hdr,             // header
                            16,              // length of header
                            ptr,             // payload
                            len,             // length of payload
                            gep->id );       // message ID
    assert( gRv==GNI_RC_SUCCESS );

    return(CCI_SUCCESS);
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


static void gni_progress_recv(
    cci__dev_t *                dev ) {

    uint64_t *                  hdrs;
    cci__ep_t *                 ep;
    gni_ep_t *                  gep;
    gni_conn_t *                gconn;
//  cci__conn_t *               conn;
//  cci_connection_t *          connection;
    gni_cq_entry_t              cqe;
    gni_return_t                gRv;

    gni_dev_t *                 gdev=dev->priv;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return;
    }

    debug( CCI_DB_FUNC, "%8s.%5d In gni_progress_recv()",
           gdev->nodename, gdev->inst_id );

    pthread_mutex_lock(&dev->lock);          // Get CCI endpoint
    ep=TAILQ_FIRST(&dev->eps);               // ### Fix multiple ep's
    pthread_mutex_unlock(&dev->lock);
    gep=ep->priv;

    pthread_mutex_lock(&ep->lock);           // Lock other changes to ep
//  Search all connections on this endpoint.
    TAILQ_FOREACH( gconn, &gep->conns, entry ) {

        if( gconn->status!=GNI_CONN_ACCEPTED )
            continue;

        gRv=GNI_CqGetEvent( gep->dst_cq_hndl, &cqe );
        if( gRv==GNI_RC_NOT_DONE )
            continue;

        debug( CCI_DB_INFO, "%8s.%5d %s: GNI_CqGetEvent=%s ID=%lx",
               gdev->nodename, gdev->inst_id, __func__,
               gni_err_str[gRv], GNI_CQ_GET_INST_ID(cqe) );

        if( gRv==GNI_RC_INVALID_PARAM )      // CQ handle was invalid
            continue;

        if( gRv==GNI_RC_ERROR_RESOURCE )     // CQ is in overrun state
            continue;

        if( gRv==GNI_RC_TRANSACTION_ERROR )  // network error
            continue;

        gRv=GNI_RC_NOT_DONE;
        while( gRv==GNI_RC_NOT_DONE )
            gRv=GNI_SmsgGetNext( gep->ep_hndl, (void **)&hdrs );
        assert( gRv==GNI_RC_SUCCESS );

        debug( CCI_DB_INFO,
               "%8s.%5d %s: got recv completion %lx %ld %lx %lx %lx",
               gdev->nodename, gdev->inst_id, __func__, hdrs[0],
               hdrs[1], hdrs[2], hdrs[3], hdrs[4] );
        gRv=GNI_SmsgRelease( gep->ep_hndl );
        assert( gRv==GNI_RC_SUCCESS );
    }
    pthread_mutex_unlock(&ep->lock);
}


static void gni_progress_send(
    cci__dev_t *                dev ) {

    cci__ep_t *                 ep;
    gni_ep_t *                  gep;
    gni_conn_t *                gconn;
//  cci__conn_t *               conn;
//  cci_connection_t *          connection;
    gni_cq_entry_t              cqe;
    gni_return_t                gRv;

    gni_dev_t *                 gdev=dev->priv;

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return;
    }

    debug( CCI_DB_FUNC, "%8s.%5d In gni_progress_send()",
           gdev->nodename, gdev->inst_id );

    pthread_mutex_lock(&dev->lock);          // Get CCI endpoint
    ep=TAILQ_FIRST(&dev->eps);               // ### Fix multiple ep's
    pthread_mutex_unlock(&dev->lock);
    gep=ep->priv;

    pthread_mutex_lock(&ep->lock);           // Lock other changes to ep
//  Search all connections on this endpoint.
    TAILQ_FOREACH( gconn, &gep->conns, entry ) {

        if( gconn->status!=GNI_CONN_ACCEPTED )
            continue;

        gRv=GNI_CqGetEvent( gep->src_cq_hndl, &cqe );
        if( gRv==GNI_RC_NOT_DONE )
            continue;

        debug( CCI_DB_INFO, "%8s.%5d %s: GNI_CqGetEvent=%s ID=%lx",
               gdev->nodename, gdev->inst_id, __func__,
               gni_err_str[gRv], GNI_CQ_GET_INST_ID(cqe) );

        if( gRv==GNI_RC_INVALID_PARAM )      // CQ handle was invalid
            continue;

        if( gRv==GNI_RC_ERROR_RESOURCE )     // CQ is in overrun state
            continue;

        if( gRv==GNI_RC_TRANSACTION_ERROR )  // happens when target
            continue;                        // .. NIC address is bad

        debug( CCI_DB_INFO, "%8s.%5d %s: got send completion",
               gdev->nodename, gdev->inst_id, __func__ );
    }
    pthread_mutex_unlock(&ep->lock);
}


static void gni_progress_connection_request(
    cci__dev_t *                dev ) {

    int                         iRv;
    uint32_t                    len;
    cci__ep_t *                 ep;
    gni_ep_t *                  gep;
    gni_conn_t *                gconn;
    cci__conn_t *               conn;
    cci_connection_t *          connection;
    cci__evt_t *                evt;
    gni_return_t                gRv;

    uint32_t                    sz=sizeof(gni_mailbox_t);
    int                         sd=-1;
    cci_device_t *              device=&dev->device;
    gni_dev_t *                 gdev=dev->priv;
    socklen_t                   is=sizeof(struct sockaddr_in);

    CCI_ENTER;

    if(!gglobals) {

        CCI_EXIT;
        return;
    }

    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_progress_connection_request()",
           gdev->nodename, gdev->inst_id );

    pthread_mutex_lock(&dev->lock);          // Get CCI endpoint
    ep=TAILQ_FIRST(&dev->eps);               // ### Fix multiple ep's
    pthread_mutex_unlock(&dev->lock);
    gep=ep->priv;

    pthread_mutex_lock(&ep->lock);           // Lock other changes to ep

//  Search all connections on this endpoint.
    TAILQ_FOREACH( gconn, &gep->conns, entry ) {

        if( gconn->status!=GNI_CONN_PENDING )// Ignore unless pending
            continue;

        len=gconn->data_len;                 // Optional payload length
        conn=gconn->conn;
        connection=&conn->connection;

        evt=calloc( 1, sizeof(*evt) );       // Create CCI event
        evt->ep=ep;
        evt->event.type=CCI_EVENT_ENDPOINT_DEVICE_FAILED;

        sd=socket( AF_INET, SOCK_STREAM, 0 );// Try to create socket
        if( sd==-1 ) {                       // .. failed

            gni_log_sys( device, __func__, "socket" );
            goto FAIL;
        }

        iRv=connect( sd,                     // Attempt connection
                     (const struct sockaddr *)&gconn->sin, is );
        if( iRv==-1 ) {

            gni_log_sys( device, __func__, "connect" );
            goto FAIL;
        }

//      Note info and cci_attr have nothing to do with the SMSG mailbox;
//      they are placed in structure to simplify the connection request.
        gep->src_box.cci_attr=connection->attribute;
        gep->src_box.info.length=len;

//      We use mailbox associated with listen...could cause performance
//      issues.  If necessary, we can define a separate mailbox later.
        if( sz!=send( sd, &(gep->src_box), sz, 0 ) ) {

            gni_log_sys( device, __func__, "send" );
            goto FAIL;
        }

        if(len)                              // Optional payload
            if( send( sd, gconn->data_ptr, len, 0 )!=len ) {

                gni_log_sys( device, __func__, "send" );
                goto FAIL;
            }

//      Receive remote mailbox structure.
        if( recv( sd, &(gep->dst_box), sz, MSG_WAITALL )!=sz ) {

            gni_log_sys( device, __func__, "recv" );
            goto FAIL;
        }
        debug( CCI_DB_INFO,                  // Contents of reply
               "%8s.%5d %s: recv=%d 0x%.8x 0x%.4x %d %zp %d %x %x"
               " %d %d %d %s %s",
               gdev->nodename, gdev->inst_id, __func__, sz,
               gep->dst_box.nic_addr,
               gep->dst_box.inst_id,
               gep->dst_box.attr.msg_type,
               gep->dst_box.attr.msg_buffer,
               gep->dst_box.attr.buff_size,
               gep->dst_box.attr.mem_hndl,
               gep->dst_box.attr.mbox_offset,
               gep->dst_box.attr.mbox_maxcredit,
               gep->dst_box.attr.msg_maxsize,
               gni_cci_attribute_to_str(gep->dst_box.cci_attr),
               gni_conn_status_to_str(gep->dst_box.info.reply) );

//      Update status so that we do not retry.
        gconn->status=gep->dst_box.info.reply;

        if( gconn->status==GNI_CONN_ACCEPTED ) {

            gRv=GNI_EpCreate( gdev->nic_hndl,// Create GNI endpoint
                              gep->src_cq_hndl,
                              &(gep->ep_hndl) );
            if( gRv!=GNI_RC_SUCCESS ) {

                gni_log_gni( device, __func__, "GNI_EpCreate", gRv );
                goto FAIL;
            }

            gRv=GNI_EpBind( gep->ep_hndl,    // Bind to remote instance
                            gep->dst_box.nic_addr,
                            gep->dst_box.inst_id );
            if( gRv!=GNI_RC_SUCCESS ) {

                gni_log_gni( device, __func__, "GNI_EpCreate", gRv );
                goto FAIL;
            }

            gRv=GNI_SmsgInit( gep->ep_hndl,  // Initialize mailbox
                              &(gep->src_box.attr),
                              &(gep->dst_box.attr) );
            if( gRv!=GNI_RC_SUCCESS ) {

                gni_log_gni( device, __func__, "GNI_SmsgInit", gRv );
                goto FAIL;
            }

//          Arbitrate connection to smaller of send sizes.
            if(gep->dst_box.attr.msg_maxsize<dev->device.max_send_size)
                connection->max_send_size=gep->dst_box.attr.msg_maxsize;
            else
                connection->max_send_size=dev->device.max_send_size;
            evt->event.type=CCI_EVENT_CONNECT_ACCEPTED;
            evt->event.accepted.connection=connection;
        } else
            evt->event.type=CCI_EVENT_CONNECT_REJECTED;

        FAIL:
        if( gconn->status==GNI_CONN_PENDING )
            gconn->status=GNI_CONN_FAILED;

        if( sd!=-1 )                         // Finished with socket
            close(sd);

//      Queue event...connection complete.
        TAILQ_INSERT_TAIL( &ep->evts, evt, entry );
    }
    pthread_mutex_unlock(&ep->lock);

    CCI_EXIT;
    return;
}


static void gni_progress_connection_reply(
    cci__dev_t *                dev ) {

    uint32_t                    len;
    cci__ep_t *                 ep;
    gni_ep_t *                  gep;

    int                         sd=-1;
    uint32_t                    sz=sizeof(gni_mailbox_t);
    gni_dev_t *                 gdev=dev->priv;
    cci_device_t *              device=&dev->device;
    void *                      buffer=NULL;
    cci__evt_t *                evt=NULL;

    if(!gglobals)
        goto FAIL;

    debug( CCI_DB_FUNC,
           "%8s.%5d In gni_progress_connection_reply()",
           gdev->nodename, gdev->inst_id );

//  Get CCI endpoint.
    pthread_mutex_lock(&dev->lock);
    ep=TAILQ_FIRST(&dev->eps);               // ### Fix multiple ep's
    pthread_mutex_unlock(&dev->lock);
    gep=ep->priv;

//  Check for connection request.
    if( (sd=accept( gdev->sd, NULL, NULL ))==-1 ) {

        if( errno!=EAGAIN )                  // OK to not have a request
            gni_log_sys( device, __func__, "accept" );
        goto FAIL;
    }

//  Find out attributes of connection request.
    if( sz!=recv( sd, &(gep->dst_box), sz, MSG_WAITALL ) ) {

        gni_log_sys( device, __func__, "recv" );
        goto FAIL;
    }

    if( (len=gep->dst_box.info.length) ) {   // Optional payload

        buffer=malloc(len+1);                // Allocate payload memory
        memset( buffer, 0, len+1);           // .. clear it

        if( len!=recv( sd, buffer, len, MSG_WAITALL ) ) {

            gni_log_sys( device, __func__, "recv" );
            goto FAIL;
        }
    }
    debug( CCI_DB_INFO, 
           "%8s.%5d %s: recv=%d 0x%.8x 0x%.4x %d %zp %d %x %x"
           " %d %d %d %s %d",
           gdev->nodename, gdev->inst_id, __func__, sz,
           gep->dst_box.nic_addr,
           gep->dst_box.inst_id,
           gep->dst_box.attr.msg_type,
           gep->dst_box.attr.msg_buffer,
           gep->dst_box.attr.buff_size,
           gep->dst_box.attr.mem_hndl,
           gep->dst_box.attr.mbox_offset,
           gep->dst_box.attr.mbox_maxcredit,
           gep->dst_box.attr.msg_maxsize,
           gni_cci_attribute_to_str(gep->src_box.cci_attr),
           gep->dst_box.info.length );

    evt=calloc( 1, sizeof(*evt) );           // Create CCI event
    evt->ep=ep;
    evt->event.type=CCI_EVENT_CONNECT_REQUEST;
    evt->event.request.data_ptr=buffer;
    evt->event.request.data_len=len;

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL( &ep->evts, evt, entry );
    pthread_mutex_unlock(&ep->lock);

    pthread_mutex_lock(&gep->lock);          // Must hold lock until
    gep->sd=sd;                              //   we accept or reject

    CCI_EXIT;
    return;

    FAIL:
    if( sd!=-1 )
        close(sd);

    CCI_EXIT;
    return;
}


static void gni_progress_dev(
    cci__dev_t *                dev ) {

    if(!gglobals)
        goto FAIL;

    gni_progress_connection_request(dev);
    gni_progress_connection_reply(dev);
    gni_progress_send(dev);
    gni_progress_recv(dev);

    FAIL:
    CCI_EXIT;
    return;
}

static void *gni_progress_thread(
    void *                      arg ) {

    while(!gni_shut_down) {

        cci__dev_t *            dev;
        cci_device_t const **   device;

        /* for each device, try progressing */
        for( device=gglobals->devices; *device!=NULL; device++ ) {

            dev=container_of( *device, cci__dev_t, device );
            gni_progress_dev(dev);
        }
        usleep(GNI_PROG_TIME_US);
    }
    pthread_exit(NULL);
    return(NULL);                            /* make pgcc happy */
}
