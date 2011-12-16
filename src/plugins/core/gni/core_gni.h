/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_GNI_H
#define CCI_CORE_GNI_H

#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gni_pub.h>
#include <resolv.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "cci/config.h"

BEGIN_C_DECLS

// The format of the GNI URI is:
//
//     gni://{NODENAME}.{NIC ADDRESS}.{INSTANCE ID}
//
#define GNI_URI               "gni://"
#define GNI_URI_MAX_LENGTH    (256)
#define GNI_LINE_SIZE         (64)           // .. if not tuned via OS
#define GNI_PAGE_SIZE         (4096)         // .. if not tuned via OS
#define GNI_IP_IF             "ipogif"
#define GNI_LISTEN_PORT       (60000)        // server initialization

#define GNI_MAX_HDR_SIZE      (32)           // per CCI spec
#define GNI_DEFAULT_MSS       (768)          // 
#define GNI_MIN_MSS           (768)
#define GNI_MAX_SIZE          (64 * 1024 - 1)// max payload + header
#define GNI_MAX_MSS           (GNI_MAX_SIZE - GNI_MAX_HDR_SIZE - 8)

#define GNI_BLOCK_SIZE        (64)           // bytes for id storage
#define GNI_EP_MAX_HDR_SIZE   (GNI_MAX_HDR_SIZE)
#define GNI_EP_BUF_LEN        (GNI_MAX_MSS)  // 65495 B
#define GNI_EP_RX_CNT         (1024)         // MAX rx messages
#define GNI_EP_TX_CNT         (32)           // MAX tx messages
#define GNI_NUM_BLOCKS        (16384)        // number of blocks
#define GNI_MAX_EP_ID         (GNI_BLOCK_SIZE * GNI_NUM_BLOCKS)
#define GNI_EP_BITS           (32)
#define GNI_EP_SHIFT          (32)
#define GNI_PROG_TIME_US      (2000000)      // progress delay micro-sec

#define GNI_EP_MATCH          ((uint64_t)0)
#define GNI_EP_IGNORE         (~((uint64_t)0))


static inline uint64_t gni_tv_to_usecs(
    struct timeval              tv ) {
        
    return((tv.tv_sec*1000000)+tv.tv_usec);
}   


#define GNI_TV_TO_USECS(tv)     (((tv).tv_sec*1000000)+(tv).tv_usec)
static inline uint64_t gni_get_usecs(void) {
        
    struct timeval              tv;

    gettimeofday( &tv, NULL );
    return gni_tv_to_usecs(tv);
}   


#if 0
static inline uint64_t gni_get_nsecs(void) {
    struct timespec             ts;
        
    clock_gettime( CLOCK_THREAD_CPUTIME_ID, &ts );
    return((ts.tv_sec * 1000000000) + ts.tv_nsec);
}       
#else   
static inline uint64_t rdtsc(void) {

    uint32_t                    lo;
    uint32_t                    hi;

    __asm__ __volatile__(                    // serialize
        "xorl %%eax,%%eax \n        cpuid"
        ::: "%rax", "%rbx", "%rcx", "%rdx" );
//  We cannot use "=A", since this would use %rax on x86_64
//  and return only the lower 32bits of the TSC
    __asm__ __volatile__( "rdtsc" : "=a" (lo), "=d" (hi) );
    return((uint64_t)hi<<32 | lo);
}


static inline uint64_t gni_get_nsecs(void) {

    return((uint64_t)((double)rdtsc()/2.6));
}
#endif


// Use "double" data type, if no statistcal processing on the raw time
// variable is to be done.  IEEE will provide almost 16 digits of
// precision; while current date requires only slightly above 15 digits.
// If standard deviations are to be computed, time^2 requires somewhat
// more than 30 digits, necessitating use of "long double".  For further
// reference, see:
//
//     http://en.wikipedia.org/wiki/IEEE_754-2008
static inline long double gni_get_time(void) {

    struct timeval           tv;             // time temp

    gettimeofday( &tv, NULL );
    return( ((long double)tv.tv_usec/(long double)1000000) +
             (long double)tv.tv_sec );
}


typedef struct gni_globals {

    int32_t                     count;       // GNI devices
    const cci_device_t **       devices;     // Array of devices
}                               gni_globals_t;

typedef struct gni_dev {

    uint8_t                     kid;         // 
    uint8_t                     ptag;        // protection tag
    uint16_t                    pad;         // pad
    uint32_t                    cookie;      // GNI cookie
    uint32_t                    modes;       // CD flag(s)
    uint32_t                    nic_addr;    // NIC address of device
    uint32_t                    inst_id;     // instance ID/PID
    int32_t                     sd;          // listen sd (always open)
    uint32_t                    progressing; // Being progressed?
    uint32_t                    port;        // Override port
    char                        service[16]; // application protocol
    gni_cdm_handle_t            cd_hndl;     // CD handle
    gni_nic_handle_t            nic_hndl;    // NIC handle
    char *                      nodename;    // 
    uint64_t *                  ep_ids;      // Endpoint id blocks
}                               gni_dev_t;

// Limit of 4 message types to ensure we only use 2 bits for msg type
typedef enum gni_msg_type {

    GNI_MSG_SEND,
    GNI_MSG_RMA_WRITE,
    GNI_MSG_RMA_READ,
    GNI_MSG_OOB
}                               gni_msg_type_t;

// OOB msg types
typedef enum gni_msg_oob_type {

    GNI_MSG_OOB_CONN_REQUEST,
    GNI_MSG_OOB_CONN_REPLY,
    GNI_MSG_KEEPALIVE
}                               gni_msg_oob_type_t;

typedef struct gni_rx {
    cci__evt_t                  evt;         // associated event
    gni_msg_type_t              msg_type;    // message type
    gni_msg_oob_type_t          oob_type;    // oob type
    int32_t                     flags;       // CCI flags
    void *                      buffer;      // active msg buffer
    uint16_t                    len;         // length of buffer
    gni_ep_handle_t             ep_hndl;     // ep handle
    TAILQ_ENTRY(gni_rx)         gentry;      // Hangs on ep->rxs
    TAILQ_ENTRY(gni_rx)         entry;       // Hangs on ep->idle_rxs
}                               gni_rx_t;

typedef struct gni_tx {

    cci__evt_t                  evt;         // associated event
    gni_msg_type_t              msg_type;    // message type
    gni_msg_oob_type_t          oob_type;    // oob type
    int32_t                     flags;       // CCI flags
    void *                      buffer;      // active msg buffer
    uint16_t                    len;         // length of buffer
    gni_ep_handle_t             ep_hndl;     // ep handle
    TAILQ_ENTRY(gni_tx)         tentry;      // Hangs on ep->txs
    TAILQ_ENTRY(gni_tx)         dentry;      // Hangs on ep->idle_txs
                                             //          dev->queued
                                             //          dev->pending
}                               gni_tx_t;

// GNI connection status
typedef enum gni_conn_status {

    GNI_CONN_PENDING,
    GNI_CONN_ACCEPTED,
    GNI_CONN_REJECTED,
    GNI_CONN_FAILED,
    GNI_CONN_DISCONNECTED
}                               gni_conn_status_t;

typedef struct gni_mailbox {
    uint32_t                    nic_addr;    // NIC address of instance
    uint32_t                    inst_id;     // PID of instance
    gni_smsg_attr_t             attr;        // mailbox attributes
    cci_conn_attribute_t        cci_attr;    // connection attributes
    union {
        uint32_t                length;      // connection payload size
        gni_conn_status_t       reply;       // connection reply
    }                           info;
}                               gni_mailbox_t;

typedef struct gni_ep {

    uint32_t                    id;          // id for multiplexing
    int32_t                     in_use;      // to serialize get_event
    int32_t                     vmd_index;   // VMD option(s)
    uint64_t                    vmd_flags;   // VMD flag(s)
    pthread_mutex_t             lock;        // lock to protect sd
    int32_t                     sd;          // request sd
    gni_cq_handle_t             src_cq_hndl; // Local CQ handle
    gni_cq_handle_t             dst_cq_hndl; // Destination CQ handle
    gni_mailbox_t               src_box;     // Local SMSG mailbox
    gni_mailbox_t               dst_box;     // Destination SMSG mailbox
    gni_ep_handle_t             ep_hndl;     // ep handle
    void *                      txbuf;       // Large buffer for tx's
    void *                      rxbuf;       // Large buffer for rx's
    TAILQ_HEAD(g_evts, gni_evt) evts;        // List of all evts
    TAILQ_HEAD(g_txs, gni_tx)   txs;         // List of all txs
    TAILQ_HEAD(g_txsi, gni_tx)  idle_txs;    // List of idle txs
    TAILQ_HEAD(g_rxs, gni_rx)   rxs;         // List of all rxs
    TAILQ_HEAD(g_rxsi, gni_rx)  idle_rxs;    // List of idle rxs
    TAILQ_HEAD(g_conns, gni_conn)
                                conns;       // List of all conns
    TAILQ_HEAD(g_handles, gni_rma_handle)
                                handles;     // List of RMA regions
    TAILQ_HEAD(g_ops, gni_rma_op)
                                rma_ops;     // List of RMA operations
}                               gni_ep_t;

typedef struct gni_conn {

    cci__conn_t *               conn;
    void *                      data_ptr;
    uint32_t                    data_len;
    gni_conn_status_t           status;      // status of connection
    struct sockaddr_in          sin;
    TAILQ_ENTRY(gni_conn)       entry;
}                               gni_conn_t;

typedef struct gni_lep {

    gni_cq_handle_t             cqhd;        // destination queue
    gni_cq_handle_t             cqhl;        // destination queue
    gni_ep_handle_t *           ep_hndl_list;
}                               gni_lep_t;

int cci_core_gni_post_load(
    cci_plugin_t *              me );
int cci_core_gni_pre_unload(
    cci_plugin_t *              me );

END_C_DECLS

#endif /* CCI_CORE_GNI_H */
