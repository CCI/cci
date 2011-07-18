/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_GNI_H
#define CCI_CORE_GNI_H

#include <assert.h>
#include <gni_pub.h>
#include <pmi.h>
#include "cci/config.h"

BEGIN_C_DECLS

#define GNI_DEFAULT_MSS       ( 8 * 1024)    // 8 kB
#define GNI_MIN_MSS           (1024)
#define GNI_MAX_MSS           (64 * 1024)

#define GNI_BLOCK_SIZE        (64)           // bytes for id storage
#define GNI_EP_MAX_HDR_SIZE   (32)           // per spec
#define GNI_EP_BUF_LEN        (8192)         // 8 kB for now
#define GNI_EP_RX_CNT         (1024)         // max rx messages
#define GNI_EP_TX_CNT         (128)          // max tx messages
#define GNI_EQ_RX_CNT         GNI_EP_RX_CNT * 3
#define GNI_EQ_TX_CNT         GNI_EP_TX_CNT * 4
#define GNI_BLOCK_SIZE        (64)           // 64b blocks for id
#define GNI_NUM_BLOCKS        (16384)        // number of blocks
#define GNI_MAX_EP_ID         (GNI_BLOCK_SIZE * GNI_NUM_BLOCKS)
#define GNI_EP_BITS           (32)
#define GNI_EP_SHIFT          (32)
#define GNI_PROG_TIME_US      (10000) // try progress every N microseconds

#define GNI_EP_MATCH          ((uint64_t)0)
#define GNI_EP_IGNORE         (~((uint64_t)0))

typedef struct gni_globals {
    int                         count;       // gni devices
    const cci_device_t **       devices;     // Array of devices
}   gni_globals_t;

typedef struct gni_dev {
    uint8_t                     ptag;
    uint32_t                    cookie;
    gni_cdm_handle_t            cdm_hndl;
    gni_nic_handle_t            nic_hndl;
    int                         is_progressing; // Being progressed?
    uint64_t *                  ep_ids;         // Endpoint id blocks
}   gni_dev_t;

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


int cci_core_gni_post_load(       cci_plugin_t *         me );
int cci_core_gni_pre_unload(      cci_plugin_t *         me );

END_C_DECLS

#endif /* CCI_CORE_GNI_H */
