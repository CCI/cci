/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/types.h>

#define CCIETH_IOCTL_GET_INFO 0x1

struct ccieth_ioctl_get_info {
  __u8 addr[6];
  __u8 pad1[2];
  /* 8 */
  __u16 max_send_size;
  __u16 pci_domain;
  __u8 pci_bus;
  __u8 pci_dev;
  __u8 pci_func;
  __u8 pad2;
  /* 16 */
  __u64 rate;
  /* 24 */
};

#define CCIETH_IOCTL_CREATE_ENDPOINT 0x8542

struct ccieth_ioctl_create_endpoint {
  __u8 addr[6];
  __u8 pad1[2];
  /* 8 */
  __u32 id;
  __u32 pad2;
  /* 16 */
};

#define CCIETH_IOCTL_GET_EVENT 0x6734

struct ccieth_ioctl_get_event {
  __u8 type;
  __u8 pad1;
  __u16 data_length;
  __u32 data_offset;
  /* 8 */
  __u32 event_offset; /* FIXME: not needed when passing events through the mmap'ed recvq */
  __u32 pad2;
  /* 16 */
};

#define CCIETH_IOCTL_RETURN_EVENT 0x5678

struct ccieth_ioctl_return_event {
  __u32 event_offset;
};

#define CCIETH_MMAP_RECVQ_OFFSET 0x0

struct ccieth_recvq_slot {
  __u8 type;
  __u8 pad1;
  __u16 data_length;
  __u32 data_offset;
  /* 8 */
  __u32 next_busy_offset; /* offset of the next slot to handle, or -1 if none yet (set by the kernel, read by the lib) */
  __u32 next_free_offset; /* offset of the next free slot if we're not busy anymore, or -1 if none yet (kernel use only) */
  /* 16 */
};
