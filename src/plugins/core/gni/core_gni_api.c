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
#include "cci/config.h"
#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"


// Local functions
static int         gni_init(              uint32_t               abi_ver,
                                          uint32_t               flags,
                                          uint32_t *             caps );
static const char *gni_strerror(          enum cci_status        status );
static int         gni_get_devices(       cci_device_t const *** devices );
static int         gni_free_devices(      cci_device_t const **  devices );
static int         gni_create_endpoint(   cci_device_t *         device,
                                          int                    flags,
                                          cci_endpoint_t **      endpoint,
                                          cci_os_handle_t *      fd );
static int         gni_destroy_endpoint(  cci_endpoint_t *       endpoint );
static int         gni_bind(              cci_device_t *         device,
                                          int                    backlog,
                                          uint32_t *             port,
                                          cci_service_t **       service,
                                          cci_os_handle_t *      fd );
static int         gni_unbind(            cci_service_t *        service,
                                          cci_device_t *         device );
static int         gni_get_conn_req(      cci_service_t *        service,
                                          cci_conn_req_t **      conn_req );
static int         gni_accept(            cci_conn_req_t *       conn_req,
                                          cci_endpoint_t *       endpoint,
                                          cci_connection_t **    connection );
static int         gni_reject(            cci_conn_req_t *       conn_req );
static int         gni_connect(           cci_endpoint_t *       endpoint,
                                          char *                 server_uri,
                                          uint32_t               port,
                                          void *                 data_ptr,
                                          uint32_t               data_len,
                                          cci_conn_attribute_t   attribute,
                                          void *                 context,
                                          int                    flags,
                                          struct timeval *       timeout );
static int         gni_disconnect(        cci_connection_t *     connection );
static int         gni_set_opt(           cci_opt_handle_t *     handle,
                                          cci_opt_level_t        level,
                                          cci_opt_name_t         name,
                                          const void *           val,
                                          int                    len );
static int         gni_get_opt(           cci_opt_handle_t *     handle,
                                          cci_opt_level_t        level,
                                          cci_opt_name_t         name,
                                          void **                val,
                                          int *                  len );
static int         gni_arm_os_handle(     cci_endpoint_t *       endpoint,
                                          int                    flags );
static int         gni_get_event(         cci_endpoint_t *       endpoint,
                                          cci_event_t ** const   event,
                                          uint32_t               flags );
static int         gni_return_event(      cci_endpoint_t *       endpoint,
                                          cci_event_t *          event );
static int         gni_send(              cci_connection_t *     connection,
                                          void *                 header_ptr,
                                          uint32_t               header_len,
                                          void *                 data_ptr,
                                          uint32_t               data_len,
                                          void *                 context,
                                          int                    flags );
static int         gni_sendv(             cci_connection_t *     connection,
                                          void *                 header_ptr,
                                          uint32_t               header_len,
                                          struct iovec *         data,
                                          uint8_t                iovcnt,
                                          void *                 context,
                                          int                    flags );
static int         gni_rma_register(      cci_endpoint_t *       endpoint,
                                          cci_connection_t *     connection,
                                          void *                 start,
                                          uint64_t               length,
                                          uint64_t *             rma_handle );
static int         gni_rma_register_phys( cci_endpoint_t *       endpoint,
                                          cci_connection_t *     connection,
                                          cci_sg_t *             sg_list,
                                          uint32_t               sg_cnt,
                                          uint64_t *             rma_handle );
static int         gni_rma_deregister(    uint64_t               rma_handle );
static int         gni_rma(               cci_connection_t *     connection,
                                          void *                 header_ptr,
                                          uint32_t               header_len,
                                          uint64_t               local_handle,
                                          uint64_t               local_offset,
                                          uint64_t               remote_handle,
                                          uint64_t               remote_offset,
                                          uint64_t               data_len,
                                          void *                 context,
                                          int                    flags );


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
cci_plugin_core_t cci_core_gni_plugin = {
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


static int gni_init(              uint32_t               abi_ver,
                                  uint32_t               flags,
                                  uint32_t *             caps ) {

    debug( CCI_DB_WARN, "In gni_init" );
    return CCI_SUCCESS;
}


static const char *gni_strerror(  enum cci_status        status ) {

    debug( CCI_DB_WARN, "In gni_sterrror" );
    return NULL;
}


static int gni_get_devices(       cci_device_t const *** devices ) {

    debug( CCI_DB_WARN, "In gni_get_devices" );
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int gni_free_devices(      cci_device_t const **  devices ) {

    debug( CCI_DB_WARN, "In gni_free_devices" );
    return CCI_ERR_NOT_IMPLEMENTED;
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
