/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2011-2012 Inria.  All rights reserved.
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

static int eth__get_device_info(cci__dev_t *_dev, struct ifaddrs *addr)
{
  int fd;
  int ret;
  struct ccieth_ioctl_get_info arg;
  cci_device_t *device = &_dev->device;
  struct sockaddr_ll *lladdr = (struct sockaddr_ll*) addr->ifa_addr;

  _dev->is_up = (addr->ifa_flags & IFF_UP != 0);

  fd = open("/dev/ccieth", O_RDONLY);
  if (fd < 0)
    return -1;

  memcpy(&arg.addr, &lladdr->sll_addr, 6);

  ret = ioctl(fd, CCIETH_IOCTL_GET_INFO, &arg);
  if (ret < 0)
    return -1;

  close(fd);

  printf("max %d rate %lld pci %04x:%02x:%02x.%01x\n",
	 arg.max_send_size, arg.rate, arg.pci_domain, arg.pci_bus, arg.pci_dev, arg.pci_func);

  device->max_send_size = arg.max_send_size;
  device->rate = arg.rate;
  device->pci.domain = arg.pci_domain;
  device->pci.bus = arg.pci_bus;
  device->pci.dev = arg.pci_dev;
  device->pci.func = arg.pci_func;

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
    struct ifaddrs *addrs = NULL, *addr;
    struct sockaddr_ll *lladdr;

    CCI_ENTER;

    devices = calloc(CCI_MAX_DEVICES, sizeof(*devices));
    if (!devices) {
        ret = CCI_ENOMEM;
        goto out;
    }

    if (getifaddrs(&addrs) == -1) {
      ret = errno;
      goto out;
    }

    if (TAILQ_EMPTY(&globals->devs)) {
      /* get all ethernet devices from the system */
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

	/* get what would have been in the config file */
	device->name = strdup(addr->ifa_name);
	memcpy(&edev->addr.sll_addr, &lladdr->sll_addr, 6);

	/* get all remaining info as usual */
	if (eth__get_device_info(_dev, addr) < 0) {
	  free(_dev);
	  free(edev);
	  continue;
	}

	devices[count] = device;
	count++;
      }

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
	    unsigned char lladdr[6];
	    if (6 == sscanf(*arg, "mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			    &lladdr[0], &lladdr[1], &lladdr[2], &lladdr[3], &lladdr[4], &lladdr[5])) {
	      edev->addr.sll_halen = 6;
	      memcpy(&edev->addr.sll_addr, lladdr, 6);
	      gotmac = 1;
	    }
	  }

	  /* we need at least an address */
	  if (!gotmac) {
	    free(edev);
	    continue;
	  }

	  /* find the corresponding ifaddr in the system list */
	  for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
	    /* need a packet iface with an address */
	    if (!addr->ifa_addr)
	      continue;
	    if (addr->ifa_addr->sa_family != AF_PACKET)
	      continue;
	    /* make sure this is mac address ?! */
	    lladdr = (struct sockaddr_ll*) addr->ifa_addr;
	    if (lladdr->sll_halen != 6)
	      continue;
	    /* is this the address we want ? */
	    if (!memcmp(&edev->addr.sll_addr, &lladdr->sll_addr, 6))
	      break;
	  }
	  if (!addr) {
	    free(edev);
	    continue;
	  }

	  /* get all remaining info as usual */
	  if (eth__get_device_info(_dev, addr) < 0) {
	    free(edev);
	    continue;
	  }

	  devices[count] = device;
	  count++;
        }
      }
    }

    freeifaddrs(addrs);
    addrs = NULL;

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

    *devices_p = (cci_device_t const **) devices;

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if (addrs) {
      freeifaddrs(addrs);
    }
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
ccieth_uri_sscanf(const char *name, uint8_t *addr, uint32_t *id)
{
  return sscanf(name, "eth://%02x:%02x:%02x:%02x:%02x:%02x:%08x",
		&addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5], id) == 7 ? 0 : -1;
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
  int eid;
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

  fd = open("/dev/ccieth", O_RDONLY);
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
  eid = arg.id;

  ccieth_uri_sprintf(name, (const uint8_t *)&edev->addr.sll_addr, arg.id);
  *((char **)&(*endpoint)->name) = name;

  *fdp = eep->fd = fd;

  {
	  /* debugging */

	  cci_connection_t * connection;
	  cci_event_t * event;

	  /* connect */
	  cci_connect(*endpoint, name, "hello world!", 13, 123, (void*)0xdeadbeef, 0, NULL);

	  /* handle connect request and accept it */
	  while (cci_get_event(*endpoint, &event) == -EAGAIN);
	  printf("got event type %d\n", event->type);
	  if (event->type == CCI_EVENT_CONNECT_REQUEST) {
		  if (event->request.data_len)
			  printf("got data len %d data %s\n",
				 event->request.data_len, event->request.data_ptr);
		  printf("got attr %d\n",
			 event->request.attribute);
	  }
	  cci_accept(event, &connection);
	  printf("accepted conn %p attr %d mss %d\n",
		 connection, connection->attribute, connection->max_send_size);
	  cci_return_event(event);

	  /* handle connect accepted */
	  while (cci_get_event(*endpoint, &event) == -EAGAIN);
	  printf("got event type %d\n", event->type);
	  if (event->type == CCI_EVENT_CONNECT_ACCEPTED) {
		  connection = event->accepted.connection;
		  printf("got conn %p attr %d context %p mss %d\n",
			 connection, connection->attribute, connection->context, connection->max_send_size);
	  }
	  cci_return_event(event);

	  /* send msg */
	  cci_send(connection, "bye world!", 11, (void*)0x012345678, 0);
	  printf("send 11 bytes\n");

	  /* handle msg */
	  while (cci_get_event(*endpoint, &event) == -EAGAIN);
	  printf("got event type %d\n", event->type);
	  if (event->type == CCI_EVENT_RECV) {
		  printf("got msg len %d data %s\n",
			 event->recv.len, event->recv.ptr);
	  }
	  cci_return_event(event);

	  /* handle send completion */
	  while (cci_get_event(*endpoint, &event) == -EAGAIN);
	  printf("got event type %d\n", event->type);
	  if (event->type == CCI_EVENT_SEND) {
		  printf("got send completion context %llx\n", event->send.context);
	  }
	  cci_return_event(event);

	  /* end of debugging */
  }
	  
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
	cci__evt_t *_ev = container_of(event, cci__evt_t, event);
	cci__ep_t *_ep = _ev->ep;
	eth__ep_t *eep = _ep->priv;
	struct ccieth_ioctl_get_event *ge = (void*) (_ev + 1);
	__u32 conn_id = ge->connect_request.conn_id;
	struct ccieth_ioctl_connect_accept ac;
	cci__conn_t *_conn;
	eth__conn_t *econn;
	int err;

	_conn = malloc(sizeof(*_conn) + sizeof(*econn));
	if (!_conn)
		return CCI_ENOMEM;
	econn = (void*) (_conn+1);
	_conn->priv = econn;
	econn->id = conn_id;

	ac.conn_id = conn_id;
	ac.user_conn_id = (uintptr_t) _conn;
	ac.max_send_size = ge->connect_request.max_send_size;
	err = ioctl(eep->fd, CCIETH_IOCTL_CONNECT_ACCEPT, &ac);
	if (err < 0) {
		free(_conn);
		return errno;
	}

	_conn->connection.max_send_size = ge->connect_request.max_send_size;
	_conn->connection.endpoint = &_ep->endpoint;
	_conn->connection.attribute = ge->connect_request.attribute;
	_conn->connection.context = NULL;

	*connection = &_conn->connection;
	return CCI_SUCCESS;
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
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = ep->priv;
	cci__conn_t *_conn;
	eth__conn_t *econn;
	struct ccieth_ioctl_connect_request arg;
	int ret;

	if (ccieth_uri_sscanf(server_uri, (uint8_t*) &arg.dest_addr, &arg.dest_eid) < 0)
		return CCI_EINVAL;

	_conn = malloc(sizeof(*_conn) + sizeof(*econn));
	if (!_conn)
		return CCI_ENOMEM;
	econn = (void*) (_conn+1);
	_conn->priv = econn;
	_conn->connection.endpoint = endpoint;
	_conn->connection.context = context;

	arg.data_len = data_len;
	arg.data_ptr = (uintptr_t) data_ptr;
	arg.attribute = attribute;
	arg.flags = flags;
	arg.user_conn_id = (uintptr_t) _conn;
	arg.timeout_sec = timeout ? timeout->tv_sec : -1ULL;
	arg.timeout_usec = timeout ? timeout->tv_usec : -1;
	ret = ioctl(eep->fd, CCIETH_IOCTL_CONNECT_REQUEST, &arg);
	if (ret < 0) {
		free(_conn);
		return errno;
	}

	return CCI_SUCCESS;
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
                         cci_event_t ** const eventp)
{
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	cci__evt_t *_ev;
	cci_event_t *event;
	struct ccieth_ioctl_get_event *ge;
	char *data;
	int ret;

	_ev = malloc(sizeof(*_ev) + sizeof(*ge) + _ep->dev->device.max_send_size);
	if (!_ev)
		return CCI_ENOMEM;
	_ev->ep = _ep;
	event = &_ev->event;
	ge = (void*) (_ev + 1);
	data = (void*) (ge + 1);

	ret = ioctl(eep->fd, CCIETH_IOCTL_GET_EVENT, ge);
	if (ret < 0) {
		if (errno == EAGAIN)
			goto out_with_event;
		perror("get event");
	}

	switch (ge->type) {
	case CCIETH_IOCTL_EVENT_SEND:
		event->type = CCI_EVENT_SEND;
		event->send.status = ge->send.status;
		event->send.context = (void*)(uintptr_t) ge->send.context;
		event->send.connection = &((cci__conn_t*)(uintptr_t) ge->send.user_conn_id)->connection;
		break;
	case CCIETH_IOCTL_EVENT_RECV:
		event->type = CCI_EVENT_RECV;
		*((uint32_t *) &event->recv.len) = ge->data_length;
		*((void **) &event->recv.ptr) = ge->data_length ? data : NULL;
		event->recv.connection = &((cci__conn_t*)(uintptr_t) ge->recv.user_conn_id)->connection;
		break;
	case CCIETH_IOCTL_EVENT_CONNECT_REQUEST:
		event->type = CCI_EVENT_CONNECT_REQUEST;
		event->request.data_len = ge->data_length;
		event->request.data_ptr = ge->data_length ? data : NULL;
		event->request.attribute = ge->connect_request.attribute;
		break;
	case CCIETH_IOCTL_EVENT_CONNECT_ACCEPTED: {
		cci__conn_t *_conn = (void*)(uintptr_t) ge->connect_accepted.user_conn_id;
		eth__conn_t *econn = (void*) (_conn+1);

		econn->id = ge->connect_accepted.conn_id;
		_conn->connection.max_send_size = ge->connect_accepted.max_send_size;
		_conn->connection.attribute = ge->connect_accepted.attribute;

		event->type = CCI_EVENT_CONNECT_ACCEPTED;
		event->accepted.context = _conn->connection.context;
		event->accepted.connection = &_conn->connection;
		break;
	}
	default:
		printf("got invalid event type %d\n", ge->type);
		goto out_with_event;
	}
	*eventp = event;
	return CCI_SUCCESS;

out_with_event:
	free(event);
	return CCI_EAGAIN;
}


static int eth_return_event(cci_event_t *event)
{
	free(event);
	return 0;
}


static int eth_send(cci_connection_t *connection,
                    void *msg_ptr, uint32_t msg_len,
                    void *context, int flags)
{
	cci__conn_t *_conn = container_of(connection, cci__conn_t, connection);
	eth__conn_t *econn = _conn->priv;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	struct ccieth_ioctl_msg arg;
	int ret;

	arg.conn_id = econn->id;
	arg.msg_ptr = (uintptr_t) msg_ptr;
	arg.msg_len = msg_len;
	arg.context = (uintptr_t) context;
	arg.flags = flags;

	ret = ioctl(eep->fd, CCIETH_IOCTL_MSG, &arg);
	if (ret < 0) {
		perror("send");
		return errno;
	}

	/* FIXME: implement flags */

	return CCI_SUCCESS;
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
