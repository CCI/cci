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
};
