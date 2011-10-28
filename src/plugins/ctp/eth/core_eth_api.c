/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 INRIA.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "../contrib/driver/ccieth/linux/ccieth_io.h"

#include "cci.h"
#include "plugins/core/core.h"
#include "core_eth.h"


/*
 * Local functions
 */
static int eth_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *eth_strerror(enum cci_status status);
static int eth_get_devices(cci_device_t const ***devices);
static int eth_free_devices(cci_device_t const **devices);
static int eth_create_endpoint(cci_device_t *device,
                               int flags,
                               cci_endpoint_t **endpoint,
                               cci_os_handle_t *fd);
static int eth_destroy_endpoint(cci_endpoint_t *endpoint);
static int eth_accept(union cci_event *event,
                      cci_connection_t **connection);
static int eth_reject(union cci_event *event);
static int eth_connect(cci_endpoint_t *endpoint, char *server_uri,
                       void *data_ptr, uint32_t data_len,
                       cci_conn_attribute_t attribute,
                       void *context, int flags,
                       struct timeval *timeout);
static int eth_disconnect(cci_connection_t *connection);
static int eth_set_opt(cci_opt_handle_t *handle,
                       cci_opt_level_t level,
                       cci_opt_name_t name, const void* val, int len);
static int eth_get_opt(cci_opt_handle_t *handle,
                       cci_opt_level_t level,
                       cci_opt_name_t name, void** val, int *len);
static int eth_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int eth_get_event(cci_endpoint_t *endpoint,
                         cci_event_t ** const event);
static int eth_return_event(cci_event_t *event);
static int eth_send(cci_connection_t *connection,
                    void *msg_ptr, uint32_t msg_len,
                    void *context, int flags);
static int eth_sendv(cci_connection_t *connection,
                     struct iovec *data, uint32_t iovcnt,
                     void *context, int flags);
static int eth_rma_register(cci_endpoint_t *endpoint,
                            cci_connection_t *connection,
                            void *start, uint64_t length,
                            uint64_t *rma_handle);
static int eth_rma_register_phys(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 cci_sg_t *sg_list, uint32_t sg_cnt,
                                 uint64_t *rma_handle);
static int eth_rma_deregister(uint64_t rma_handle);
static int eth_rma(cci_connection_t *connection,
                   void *msg_ptr, uint32_t msg_len,
                   uint64_t local_handle, uint64_t local_offset,
                   uint64_t remote_handle, uint64_t remote_offset,
                   uint64_t data_len, void *context, int flags);


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
cci_plugin_core_t cci_core_eth_plugin = {
    {
        /* Logistics */
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "eth",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,

        /* Bootstrap function pointers */
        cci_core_eth_post_load,
        cci_core_eth_pre_unload,
    },

    /* API function pointers */
    eth_init,
    eth_strerror,
    eth_get_devices,
    eth_free_devices,
    eth_create_endpoint,
    eth_destroy_endpoint,
    eth_accept,
    eth_reject,
    eth_connect,
    eth_disconnect,
    eth_set_opt,
    eth_get_opt,
    eth_arm_os_handle,
    eth_get_event,
    eth_return_event,
    eth_send,
    eth_sendv,
    eth_rma_register,
    eth_rma_register_phys,
    eth_rma_deregister,
    eth_rma
};


static int eth_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    printf("In eth_init\n");
    return CCI_SUCCESS;
}


static const char *eth_strerror(enum cci_status status)
{
    printf("In eth_sterrror\n");
    return NULL;
}

static int eth__get_device_info(cci_device_t *device, struct sockaddr_ll *ll)
{
  int fd;
  int ret;
  struct ccieth_ioctl_get_info arg;
  cci__dev_t *_dev = container_of(device, cci__dev_t, device);

  fd = open("/dev/ccieth", O_RDONLY);
  if (fd < 0)
    return -1;

  /* FIXME: rather use the ethtool interface (get_settings for speed), and SIOCGIFMTU */
  memcpy(&arg.addr, &ll->sll_addr, 6);
  ret = ioctl(fd, CCIETH_IOCTL_GET_INFO, &arg);
  if (ret < 0)
    return -1;

  close(fd);

  printf("max %d rate %lld pci %04x:%02x:%02x.%01x\n",
	 arg.max_send_size, arg.rate, arg.pci_domain, arg.pci_bus, arg.pci_dev, arg.pci_func);

  /* FIXME get those from the driver */
  device->max_send_size = 1024;
  device->rate = 10000000000ULL;
  device->pci.domain = -1;
  device->pci.bus = -1;
  device->pci.dev = -1;
  device->pci.func = -1;
  /* FIXME: check if up */
  _dev->is_up = 1;
  /* get the iface name and use it for dev->name if not reading the config file */

  return 0;
}

static int eth_get_devices(cci_device_t const ***devices_p)
{
    int ret;
    cci__dev_t *_dev;
    cci_device_t **devices;
    unsigned count = 0;
    cci_device_t *device;
    eth__dev_t *edev;

    CCI_ENTER;

    devices = calloc(CCI_MAX_DEVICES, sizeof(*devices));
    if (!devices) {
        ret = CCI_ENOMEM;
        goto out;
    }

    if (TAILQ_EMPTY(&globals->devs)) {
      /* get all ethernet devices from the system */
      struct ifaddrs *addrs, *addr;
      struct sockaddr_ll *lladdr;

      if (getifaddrs(&addrs) == -1) {
	ret = errno;
	goto out;
      }

      for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
	/* need a packet iface with an address */
	if (addr->ifa_addr == NULL
	    || addr->ifa_addr->sa_family != AF_PACKET)
	  continue;
	/* ignore loopback and */
	if (addr->ifa_flags & IFF_LOOPBACK)
	  continue;
	/* ignore iface if not up */
	if (!(addr->ifa_flags & IFF_UP))
	  continue;
	/* make sure this is mac address ?! */
	lladdr = (struct sockaddr_ll*) addr->ifa_addr;
	if (lladdr->sll_halen != 6)
	  continue;

	_dev = calloc(1, sizeof(*_dev));
	edev = calloc(1, sizeof(*edev));
	if (!_dev || !edev) {
	  free(_dev);
	  free(edev);
	  ret = CCI_ENOMEM;
	  goto out;
	}
	device = &_dev->device;
	_dev->priv = edev;

	device->name = strdup(addr->ifa_name);
	memcpy(&edev->addr.sll_addr, &lladdr->sll_addr, 6);

	if (eth__get_device_info(device, &edev->addr) < 0) {
	  free(edev);
	  continue;
	}

	devices[count] = device;
	count++;
      }

      freeifaddrs(addrs);

    } else {
      /* find devices that we own in the config file */
      TAILQ_FOREACH(_dev, &globals->devs, entry) {
        if (0 == strcmp("eth", _dev->driver)) {
	  const char **arg;
	  int gotmac = 0;

	  device = &_dev->device;

	  edev = calloc(1, sizeof(*edev));
	  if (!edev) {
	    ret = CCI_ENOMEM;
	    goto out;
	  }
	  _dev->priv = edev;

	  /* parse conf_argv */
	  for (arg = device->conf_argv;
	       *arg != NULL;
	       arg++) {
	    unsigned char addr[6];
	    if (6 == sscanf(*arg, "mac=%02x:%02x:%02x:%02x:%02x:%02x",
			    &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])) {
	      edev->addr.sll_halen = 6;
	      memcpy(&edev->addr.sll_addr, addr, 6);
	      gotmac = 1;
	    }
	  }

	  if (!gotmac || eth__get_device_info(device, &edev->addr) < 0) {
	    free(edev);
	    continue;
	  }

	  devices[count] = device;
	  count++;
        }
      }
    }

    {
      int i;
      debug(CCI_DB_INFO, "listing devices:");
      for(i=0; i<count; i++) {
	cci_device_t *device = devices[i];
	cci__dev_t *_dev = container_of(device, cci__dev_t, device);
        eth__dev_t *edev = _dev->priv;
	struct sockaddr_ll *addr = &edev->addr;
	debug(CCI_DB_INFO, "  device `%s' has address %02x:%02x:%02x:%02x:%02x:%02x",
	       device->name,
	       addr->sll_addr[0],
	       addr->sll_addr[1],
	       addr->sll_addr[2],
	       addr->sll_addr[3],
	       addr->sll_addr[4],
	       addr->sll_addr[5]);
      }
      debug(CCI_DB_INFO, "end of device list.");
    }

    devices = realloc(devices, (count + 1) * sizeof(cci_device_t *));
    devices[count] = NULL;

    *devices_p = devices;

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if (devices) {
        cci_device_t const *device;
        cci__dev_t *my_dev;

        for (device = devices[0];
             device != NULL;
             device++) {
            my_dev = container_of(device, cci__dev_t, device);
            if (my_dev->priv)
                free(my_dev->priv);
        }
        free(devices);
    }
    CCI_EXIT;
    return ret;
}


static int eth_free_devices(cci_device_t const **devices)
{
    printf("In eth_free_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}

#define CCIETH_URI_LENGTH (6 /* prefix */ + 17 /* mac */ + 1 /* colon */ + 8 /* id */ + 1 /* \0 */)

static void
ccieth_uri_sprintf(char *name, const uint8_t *addr, uint32_t id)
{
  sprintf(name, "eth://%02x:%02x:%02x:%02x:%02x:%02x:%08x",
	  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], id);
}

static int
ccieth_uri_sscanf(const char *name, uint8_t *addr, uint32_t id)
{
  return sscanf(name, "eth://%02x:%02x:%02x:%02x:%02x:%02x:%08x",
		&addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5], &id) == 7 ? 0 : -1;
}

static int eth_create_endpoint(cci_device_t *device,
                               int flags,
                               cci_endpoint_t **endpoint,
                               cci_os_handle_t *fdp)
{
  struct ccieth_ioctl_create_endpoint arg;
  cci__dev_t *_dev = container_of(device, cci__dev_t, device);
  eth__dev_t *edev = _dev->priv;
  cci__ep_t *_ep;
  eth__ep_t *eep;
  void *recvq;
  char *name;
  int fd;
  int ret;

  _ep = container_of(*endpoint, cci__ep_t, endpoint);
  eep = calloc(1, sizeof(eth__ep_t));
  if (!eep) {
    ret = CCI_ENOMEM;
    goto out;
  }
  _ep->priv = eep;

  name = malloc(CCIETH_URI_LENGTH);
  if (!name) {
    ret = CCI_ENOMEM;
    goto out_with_eep;
  }

  fd = open("/dev/ccieth", O_RDWR);
  if (fd < 0) {
    ret = errno;
    goto out_with_name;
  }

  memcpy(&arg.addr, &edev->addr.sll_addr, 6);
  ret = ioctl(fd, CCIETH_IOCTL_CREATE_ENDPOINT, &arg);
  if (ret < 0) {
    ret = errno;
    goto out_with_fd;
  }

  ccieth_uri_sprintf(name, (const uint8_t *)&edev->addr.sll_addr, arg.id);
  *((char **)&(*endpoint)->name) = name;

  recvq = mmap(NULL, 4096*1024 /* FIXME */, PROT_READ, MAP_SHARED, fd, CCIETH_MMAP_RECVQ_OFFSET);
  printf("recvq %p\n", recvq);
  if (recvq == MAP_FAILED) {
    ret = errno;
    goto out_with_fd;
  }
  eep->recvq = recvq;

  *fdp = eep->fd = fd;
  return CCI_SUCCESS;

 out_with_fd:
  close(fd);
 out_with_name:
  free(name);
 out_with_eep:
  free(eep);
 out:
  return ret;
}


static int eth_destroy_endpoint(cci_endpoint_t *endpoint)
{
  cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
  eth__ep_t *eep = ep->priv;
  close(eep->fd);
  free(eep);
  return CCI_SUCCESS;
}


static int eth_accept(union cci_event *event,
                      cci_connection_t **connection)
{
    printf("In eth_accept\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_reject(union cci_event *event)
{
    printf("In eth_reject\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_connect(cci_endpoint_t *endpoint, char *server_uri,
                       void *data_ptr, uint32_t data_len,
                       cci_conn_attribute_t attribute,
                       void *context, int flags,
                       struct timeval *timeout)
{
    printf("In eth_connect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_disconnect(cci_connection_t *connection)
{
    printf("In eth_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_set_opt(cci_opt_handle_t *handle,
                       cci_opt_level_t level,
                       cci_opt_name_t name, const void* val, int len)
{
    printf("In eth_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_get_opt(cci_opt_handle_t *handle,
                       cci_opt_level_t level,
                       cci_opt_name_t name, void** val, int *len)
{
    printf("In eth_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    printf("In eth_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_get_event(cci_endpoint_t *endpoint,
                         cci_event_t ** const event)
{
    printf("In eth_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_return_event(cci_event_t *event)
{
    printf("In eth_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_send(cci_connection_t *connection,
                    void *msg_ptr, uint32_t msg_len,
                    void *context, int flags)
{
    printf("In eth_send\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_sendv(cci_connection_t *connection,
                     struct iovec *data, uint32_t iovcnt,
                     void *context, int flags)
{
    printf("In eth_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_rma_register(cci_endpoint_t *endpoint,
                            cci_connection_t *connection,
                            void *start, uint64_t length,
                            uint64_t *rma_handle)
{
    printf("In eth_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_rma_register_phys(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 cci_sg_t *sg_list, uint32_t sg_cnt,
                                 uint64_t *rma_handle)
{
    printf("In eth_rma_register_phys\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_rma_deregister(uint64_t rma_handle)
{
    printf("In eth_rma_deregister\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int eth_rma(cci_connection_t *connection,
                   void *msg_ptr, uint32_t msg_len,
                   uint64_t local_handle, uint64_t local_offset,
                   uint64_t remote_handle, uint64_t remote_offset,
                   uint64_t data_len, void *context, int flags)
{
    printf("In eth_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}
