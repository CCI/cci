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
#include <assert.h>

#include "ccieth_io.h"

#include "cci.h"
#include "plugins/core/core.h"
#include "core_eth.h"

#define ETH_BUILD_ASSERT(condition) ((void)sizeof(char[1 - 2*!(condition)]))

struct eth__globals *eglobals = NULL;

/*
 * Local functions
 */
static int eth_init(cci_plugin_core_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int eth_finalize(cci_plugin_core_t *plugin);
static const char *eth_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int eth_create_endpoint(cci_device_t * device,
			       int flags,
			       cci_endpoint_t ** endpoint,
			       cci_os_handle_t * fd);
static int eth_destroy_endpoint(cci_endpoint_t * endpoint);
static int eth_accept(cci_event_t *event, const void *context);
static int eth_reject(cci_event_t *event);
static int eth_connect(cci_endpoint_t * endpoint, const char *server_uri,
		       const void *data_ptr, uint32_t data_len,
		       cci_conn_attribute_t attribute,
		       const void *context, int flags, const struct timeval *timeout);
static int eth_disconnect(cci_connection_t * connection);
static int eth_set_opt(cci_opt_handle_t * handle,
		       cci_opt_level_t level,
		       cci_opt_name_t name, const void *val);
static int eth_get_opt(cci_opt_handle_t * handle,
		       cci_opt_level_t level,
		       cci_opt_name_t name, void *val);
static int eth_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int eth_get_event(cci_endpoint_t * endpoint, cci_event_t ** event);
static int eth_return_event(cci_event_t * event);
static int eth_send(cci_connection_t * connection,
		    const void *msg_ptr, uint32_t msg_len, const void *context, int flags);
static int eth_sendv(cci_connection_t * connection,
		     const struct iovec *data, uint32_t iovcnt,
		     const void *context, int flags);
static int eth_rma_register(cci_endpoint_t * endpoint,
			    cci_connection_t * connection,
			    void *start, uint64_t length,
			    uint64_t * rma_handle);
static int eth_rma_deregister(uint64_t rma_handle);
static int eth_rma(cci_connection_t * connection,
		   const void *msg_ptr, uint32_t msg_len,
		   uint64_t local_handle, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset,
		   uint64_t data_len, const void *context, int flags);

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
	 40, /* higher than sock, lower than verbs */

	 /* Bootstrap function pointers */
	 cci_core_eth_post_load,
	 cci_core_eth_pre_unload,
	 },

	/* API function pointers */
	eth_init,
	eth_finalize,
	eth_strerror,
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

static int eth__get_device_info(cci__dev_t * _dev, struct ifaddrs *addr)
{
	struct cci_device *device = &_dev->device;
	struct sockaddr_ll *lladdr = (struct sockaddr_ll *)addr->ifa_addr;
	struct ccieth_ioctl_get_info ioctl_arg;
	int err;

	/* default values */
	device->max_send_size = -1;

	if (getenv("CCIETH_FORCE_GET_INFO_IOCTL"))
		/* force testing of our fallback for old kernels */
		goto fallback_ioctl;

#ifdef HAVE_GETIFADDRS
	err = cci__get_dev_ifaddrs_info(_dev, addr);
	if (!err)
		goto done;
#endif

fallback_ioctl:
	debug(CCI_DB_INFO, "querying interface %s info with custom ioctl",
	      addr->ifa_name);

	memcpy(&ioctl_arg.addr, &lladdr->sll_addr, 6);
	if (ioctl(eglobals->fd, CCIETH_IOCTL_GET_INFO, &ioctl_arg) < 0) {
		if (errno != ENODEV)
			perror("ioctl get info");
		goto out;
	}
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.max_send_size,
					     sizeof(ioctl_arg.max_send_size));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.pci_domain,
					     sizeof(ioctl_arg.pci_domain));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.pci_bus,
					     sizeof(ioctl_arg.pci_bus));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.pci_dev,
					     sizeof(ioctl_arg.pci_dev));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.pci_func,
					     sizeof(ioctl_arg.pci_func));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ioctl_arg.rate,
					     sizeof(ioctl_arg.rate));

	device->max_send_size = ioctl_arg.max_send_size;
	device->rate = ioctl_arg.rate;
	device->pci.domain = ioctl_arg.pci_domain;
	device->pci.bus = ioctl_arg.pci_bus;
	device->pci.dev = ioctl_arg.pci_dev;
	device->pci.func = ioctl_arg.pci_func;

	/* up flag is easy */
	device->up = (addr->ifa_flags & IFF_UP != 0);

done:
	/* normalize what cci__get_dev_ifaddrs_info() returned */
	device->max_send_size = ccieth_max_send_size(device->max_send_size);

	debug(CCI_DB_INFO, "max %d rate %lld pci %04x:%02x:%02x.%01x",
	      device->max_send_size, device->rate,
	      device->pci.domain, device->pci.bus, device->pci.dev,
	      device->pci.func);
	return 0;

out:
	return -1;
}

static int eth__get_devices(cci_plugin_core_t *plugin)
{
	int ret;
	cci__dev_t *_dev, *_ndev;
	unsigned count = 0;
	struct cci_device *device;
	eth__dev_t *edev;
	struct ifaddrs *addrs = NULL, *addr;
	struct sockaddr_ll *lladdr;
	int no_default;

	CCI_ENTER;

	if (getifaddrs(&addrs) == -1) {
		ret = errno;
		goto out;
	}

	if (!globals->configfile) {
		int loopback_ok = (getenv("CCIETH_ALLOW_LOOPBACK") != NULL);
		/* get all ethernet devices from the system */
		for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
			int is_loopback = 0;
			/* need a packet iface with an address */
			if (addr->ifa_addr == NULL
			    || addr->ifa_addr->sa_family != AF_PACKET)
				continue;
			/* ignore loopback and */
			if (addr->ifa_flags & IFF_LOOPBACK) {
				if (loopback_ok)
					is_loopback = 1;
				else
					continue;
			}
			/* ignore iface if not up */
			if (!(addr->ifa_flags & IFF_UP))
				continue;
			/* make sure this is mac address ?! */
			lladdr = (struct sockaddr_ll *)addr->ifa_addr;
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

			cci__init_dev(_dev);
			_dev->plugin = plugin;
			_dev->priority = plugin->base.priority;
			_dev->driver = strdup("eth");
			if (is_loopback)
				_dev->is_default = 1;

			/* get what would have been in the config file */
			device->name = strdup(addr->ifa_name);
			memcpy(&edev->addr.sll_addr, &lladdr->sll_addr, 6);

			/* get all remaining info as usual */
			if (eth__get_device_info(_dev, addr) < 0) {
				free(_dev);
				free(edev);
				continue;
			}

			cci__add_dev(_dev);
		}

	} else {
		/* find devices that we own in the config file */
		TAILQ_FOREACH_SAFE(_dev, &globals->configfile_devs, entry, _ndev) {
			if (0 == strcmp("eth", _dev->driver)) {
				const char * const *arg;
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
				     *arg != NULL; arg++) {
					unsigned char lladdr[6];
					if (6 ==
					    sscanf(*arg,
						   "mac=%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
						   &lladdr[0], &lladdr[1],
						   &lladdr[2], &lladdr[3],
						   &lladdr[4], &lladdr[5])) {
						edev->addr.sll_halen = 6;
						memcpy(&edev->addr.sll_addr,
						       lladdr, 6);
						gotmac = 1;
					}
				}

				/* we need at least an address */
				if (!gotmac) {
					free(edev);
					continue;
				}

				/* find the corresponding ifaddr in the system list */
				for (addr = addrs; addr != NULL;
				     addr = addr->ifa_next) {
					/* need a packet iface with an address */
					if (!addr->ifa_addr)
						continue;
					if (addr->ifa_addr->sa_family !=
					    AF_PACKET)
						continue;
					/* make sure this is mac address ?! */
					lladdr =
					    (struct sockaddr_ll *)
					    addr->ifa_addr;
					if (lladdr->sll_halen != 6)
						continue;
					/* is this the address we want ? */
					if (!memcmp
					    (&edev->addr.sll_addr,
					     &lladdr->sll_addr, 6))
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

				_dev->plugin = plugin;
				if (_dev->priority == -1)
					_dev->priority = plugin->base.priority;

				TAILQ_REMOVE(&globals->configfile_devs, _dev, entry);
				cci__add_dev(_dev);
			}
		}
	}

	freeifaddrs(addrs);
	addrs = NULL;

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	if (addrs) {
		freeifaddrs(addrs);
	}
	CCI_EXIT;
	return ret;
}

static int eth_init(cci_plugin_core_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret;

	CCI_ENTER;

	eglobals = malloc(sizeof(*eglobals));
	if (!eglobals) {
		ret = CCI_ENOMEM;
		goto out;
	}

	eglobals->fd = open("/dev/ccieth", O_RDONLY);
        if (eglobals->fd < 0) {
		ret = errno;
                goto out_with_eglobals;
	}

	ret = eth__get_devices(plugin);
	if (ret)
		goto out_with_fd;

	CCI_EXIT;
	return CCI_SUCCESS;

out_with_fd:
	close(eglobals->fd);
out_with_eglobals:
	free(eglobals);
out:
	CCI_EXIT;
	return ret;
}

static int eth_finalize(cci_plugin_core_t *plugin)
{
	cci__dev_t *_dev = NULL;

        TAILQ_FOREACH(_dev, &globals->devs, entry)
		if (!strcmp(_dev->driver, "eth"))
			free(_dev->priv);

	close(eglobals->fd);
	free(eglobals);
	return CCI_SUCCESS;
}

static const char *eth_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	printf("In eth_sterrror\n");
	return NULL;
}

#define CCIETH_URI_LENGTH (6 /* prefix */ + 17 /* mac */ + 1 /* colon */ + 8 /* id */ + 1 /* \0 */)

static void ccieth_uri_sprintf(char *uri, const uint8_t * addr, uint32_t id)
{
	sprintf(uri, "eth://%02x:%02x:%02x:%02x:%02x:%02x:%08x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], id);
}

static int ccieth_uri_sscanf(const char *uri, uint8_t * addr, uint32_t * id)
{
	return sscanf(uri, "eth://%02x:%02x:%02x:%02x:%02x:%02x:%08x",
		      &addr[0], &addr[1], &addr[2], &addr[3], &addr[4],
		      &addr[5], id) == 7 ? 0 : -1;
}

static int eth_create_endpoint(cci_device_t * device,
			       int flags,
			       cci_endpoint_t ** endpointp,
			       cci_os_handle_t * fdp)
{
	struct ccieth_ioctl_create_endpoint arg;
	cci__dev_t *_dev = container_of(device, cci__dev_t, device);
	eth__dev_t *edev = _dev->priv;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	cci__ep_t *_ep;
	eth__ep_t *eep;
	int eid;
	char *uri;
	int fd;
	int ret;

	_ep = container_of(endpoint, cci__ep_t, endpoint);
	eep = calloc(1, sizeof(eth__ep_t));
	if (!eep) {
		ret = CCI_ENOMEM;
		goto out;
	}
	_ep->priv = eep;

	uri = malloc(CCIETH_URI_LENGTH);
	if (!uri) {
		ret = CCI_ENOMEM;
		goto out_with_eep;
	}

	fd = open("/dev/ccieth", O_RDONLY);
	if (fd < 0) {
		ret = errno;
		goto out_with_uri;
	}

	memcpy(&arg.addr, &edev->addr.sll_addr, 6);
	ret = ioctl(fd, CCIETH_IOCTL_CREATE_ENDPOINT, &arg);
	if (ret < 0) {
		perror("ioctl create endpoint");
		ret = errno;
		goto out_with_fd;
	}
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&arg.id, sizeof(arg.id));
	eid = arg.id;

	ccieth_uri_sprintf(uri, (const uint8_t *)&edev->addr.sll_addr, arg.id);
	_ep->uri = uri;

	TAILQ_INIT(&eep->connections);

	*fdp = eep->fd = fd;
	return CCI_SUCCESS;

out_with_fd:
	close(fd);
out_with_uri:
	free(uri);
out_with_eep:
	free(eep);
out:
	return ret;
}

static int eth_destroy_endpoint(cci_endpoint_t * endpointp)
{
	struct cci_endpoint *endpoint = (struct cci_endpoint *) endpointp;
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;

	while (!TAILQ_EMPTY(&eep->connections)) {
		eth__conn_t *econn = TAILQ_FIRST(&eep->connections);
		TAILQ_REMOVE(&eep->connections, econn, entry);
		free(econn);
	}

	close(eep->fd);
	free((void *) _ep->uri);
	free(eep);
	return CCI_SUCCESS;
}

static int eth_accept(cci_event_t *event, const void *context)
{
	cci__evt_t *_ev = container_of(event, cci__evt_t, event);
	eth__evt_t *eev = container_of(_ev, eth__evt_t, _ev);
	struct ccieth_ioctl_get_event *ge = &eev->ioctl_event;
	cci__ep_t *_ep = _ev->ep;
	eth__ep_t *eep = _ep->priv;
	__u32 conn_id = ge->connect_request.conn_id;
	struct ccieth_ioctl_connect_accept ac;
	cci__conn_t *_conn;
	eth__conn_t *econn;
	int err;

	if (event->type != CCI_EVENT_CONNECT_REQUEST
	    || !eev->type_params.connect_request.need_reply)
		return CCI_EINVAL;

	econn = malloc(sizeof(*econn));
	if (!econn)
		return CCI_ENOMEM;
	_conn = &econn->_conn;
	_conn->plugin = _ep->plugin;

	econn->id = conn_id;
	assert(econn->id != CCIETH_CONNECTION_INVALID_ID);

	ac.conn_id = conn_id;
	ac.user_conn_id = (uintptr_t) econn;
	err = ioctl(eep->fd, CCIETH_IOCTL_CONNECT_ACCEPT, &ac);
	if (err < 0) {
		perror("ioctl connect accept");
		free(econn);
		return errno;
	}

	eev->type_params.connect_request.need_reply = 0;

	_conn->connection.max_send_size = ge->connect_request.max_send_size;
	_conn->connection.endpoint = &_ep->endpoint;
	_conn->connection.attribute = ge->connect_request.attribute;
	_conn->connection.context = (void *)context;


	pthread_mutex_lock(&_ep->lock);
	TAILQ_INSERT_TAIL(&eep->connections, econn, entry);
	pthread_mutex_unlock(&_ep->lock);

	return CCI_SUCCESS;
}

static int eth_reject(cci_event_t *event)
{
	cci__evt_t *_ev = container_of(event, cci__evt_t, event);
	eth__evt_t *eev = container_of(_ev, eth__evt_t, _ev);
	struct ccieth_ioctl_get_event *ge = &eev->ioctl_event;
	cci__ep_t *_ep = _ev->ep;
	eth__ep_t *eep = _ep->priv;
	__u32 conn_id = ge->connect_request.conn_id;
	struct ccieth_ioctl_connect_reject rj;
	int err;

	if (event->type != CCI_EVENT_CONNECT_REQUEST
	    || !eev->type_params.connect_request.need_reply)
		return CCI_EINVAL;

	rj.conn_id = conn_id;
	err = ioctl(eep->fd, CCIETH_IOCTL_CONNECT_REJECT, &rj);
	if (err < 0) {
		perror("ioctl connect reject");
		return errno;
	}

	eev->type_params.connect_request.need_reply = 0;

	return CCI_SUCCESS;
}

static int eth_connect(cci_endpoint_t * endpoint, const char *server_uri,
		       const void *data_ptr, uint32_t data_len,
		       cci_conn_attribute_t attribute,
		       const void *context, int flags, const struct timeval *timeout)
{
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	cci__conn_t *_conn;
	eth__conn_t *econn;
	struct ccieth_ioctl_connect_request arg;
	int ret;

	if (ccieth_uri_sscanf
	    (server_uri, (uint8_t *) & arg.dest_addr, &arg.dest_eid) < 0)
		return CCI_EINVAL;

	econn = malloc(sizeof(*econn));
	if (!econn)
		return CCI_ENOMEM;
	_conn = &econn->_conn;
	_conn->plugin = _ep->plugin;
	_conn->connection.endpoint = endpoint;
	_conn->connection.attribute = attribute;
	_conn->connection.context = (void *)context;

	arg.data_len = data_len;
	arg.data_ptr = (uintptr_t) data_ptr;
	arg.attribute = attribute;
	arg.flags = flags;
	arg.user_conn_id = (uintptr_t) econn;
	arg.timeout_sec = timeout ? timeout->tv_sec : -1ULL;
	arg.timeout_usec = timeout ? timeout->tv_usec : -1;
	ret = ioctl(eep->fd, CCIETH_IOCTL_CONNECT_REQUEST, &arg);
	if (ret < 0) {
		perror("ioctl connect request");
		free(econn);
		return errno;
	}

	pthread_mutex_lock(&_ep->lock);
	TAILQ_INSERT_TAIL(&eep->connections, econn, entry);
	pthread_mutex_unlock(&_ep->lock);

	return CCI_SUCCESS;
}

static int eth_disconnect(cci_connection_t * connection)
{
	cci__conn_t *_conn = container_of(connection, cci__conn_t, connection);
	eth__conn_t *econn = container_of(_conn, eth__conn_t, _conn);
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	struct ccieth_ioctl_disconnect arg;
	int ret;

	arg.conn_id = econn->id;
	ret = ioctl(eep->fd, CCIETH_IOCTL_DISCONNECT, &arg);
	if (ret < 0) {
		perror("ioctl disconnect");
		return errno;
	}

	pthread_mutex_lock(&_ep->lock);
	TAILQ_REMOVE(&eep->connections, econn, entry);
	pthread_mutex_unlock(&_ep->lock);
	free(econn);

	return CCI_SUCCESS;
}

static int eth_set_opt(cci_opt_handle_t * handle,
		       cci_opt_level_t level,
		       cci_opt_name_t name, const void *val)
{
	printf("In eth_set_opt\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int eth_get_opt(cci_opt_handle_t * handle,
		       cci_opt_level_t level,
		       cci_opt_name_t name, void *val)
{
	printf("In eth_get_opt\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int eth_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	return CCI_SUCCESS;
}

static int eth_get_event(cci_endpoint_t * endpoint, cci_event_t ** const eventp)
{
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	cci__evt_t *_ev;
	eth__evt_t *eev;
	union cci_event *event;
	struct ccieth_ioctl_get_event *ge;
	char *data;
	int ret;

	eev = malloc(sizeof(*eev) + _ep->dev->device.max_send_size);
	if (!eev)
		return CCI_ENOMEM;
	_ev = &eev->_ev;
	event = &_ev->event;
	ge = &eev->ioctl_event;
	data = eev->data;

	_ev->ep = _ep;

	ret = ioctl(eep->fd, CCIETH_IOCTL_GET_EVENT, ge);
	if (ret < 0) {
		if (errno == EAGAIN)
			goto out_with_event;
		perror("ioctl get event");
	}
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->type, sizeof(ge->type));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->data_length,
					     sizeof(ge->data_length));
	CCIETH_VALGRIND_MEMORY_MAKE_READABLE(data, ge->data_length);

	switch (ge->type) {
	case CCIETH_IOCTL_EVENT_SEND:
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->send.status,
						     sizeof(ge->send.status));
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->send.context,
						     sizeof(ge->send.context));
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->send.user_conn_id,
						     sizeof(ge->
							    send.user_conn_id));
		event->type = CCI_EVENT_SEND;
		event->send.status = ge->send.status;
		event->send.context = (void *)(uintptr_t) ge->send.context;
		event->send.connection =
		    &((eth__conn_t *) (uintptr_t) ge->send.
		      user_conn_id)->_conn.connection;
		break;
	case CCIETH_IOCTL_EVENT_RECV:
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->recv.user_conn_id,
						     sizeof(ge->
							    recv.user_conn_id));
		event->type = CCI_EVENT_RECV;
		event->recv.len = ge->data_length;
		event->recv.ptr = ge->data_length ? data : NULL;
		event->recv.connection =
		    &((eth__conn_t *) (uintptr_t) ge->recv.
		      user_conn_id)->_conn.connection;
		break;
	case CCIETH_IOCTL_EVENT_CONNECT_REQUEST:
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->
						     connect_request.conn_id,
						     sizeof(ge->
							    connect_request.conn_id));
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->
						     connect_request.attribute,
						     sizeof(ge->
							    connect_request.attribute));
		CCIETH_VALGRIND_MEMORY_MAKE_READABLE(&ge->
						     connect_request.max_send_size,
						     sizeof(ge->
							    connect_request.max_send_size));
		event->type = CCI_EVENT_CONNECT_REQUEST;
		event->request.data_len = ge->data_length;
		event->request.data_ptr = ge->data_length ? data : NULL;
		event->request.attribute = ge->connect_request.attribute;
		eev->type_params.connect_request.need_reply = 1;
		break;
	case CCIETH_IOCTL_EVENT_CONNECT:{
			eth__conn_t *econn;

			CCIETH_VALGRIND_MEMORY_MAKE_READABLE
				(&ge->connect.status,
			     sizeof(ge->connect.status));
			CCIETH_VALGRIND_MEMORY_MAKE_READABLE
			    (&ge->connect.user_conn_id,
			     sizeof(ge->connect.user_conn_id));
			econn =
			    (void *)(uintptr_t) ge->connect.user_conn_id;

			event->type = CCI_EVENT_CONNECT;
			event->connect.status = ge->connect.status;
			event->connect.context = econn->_conn.connection.context;

			if (ge->connect.status != 0) {
				/* failed */
				event->connect.connection = NULL;
				pthread_mutex_lock(&_ep->lock);
				TAILQ_REMOVE(&eep->connections, econn, entry);
				pthread_mutex_unlock(&_ep->lock);
				free(econn);
			} else {
				/* success */
				CCIETH_VALGRIND_MEMORY_MAKE_READABLE
					(&ge->connect.max_send_size,
					 sizeof(ge->connect.max_send_size));
				CCIETH_VALGRIND_MEMORY_MAKE_READABLE
					(&ge->connect.conn_id,
					 sizeof(ge->connect.conn_id));

				econn->id = ge->connect.conn_id;
				assert(econn->id != CCIETH_CONNECTION_INVALID_ID);
				econn->_conn.connection.max_send_size =
					ge->connect.max_send_size;

				event->connect.connection = &econn->_conn.connection;
			}
			break;
		}
	case CCIETH_IOCTL_EVENT_ACCEPT: {
			eth__conn_t *econn;

			CCIETH_VALGRIND_MEMORY_MAKE_READABLE
				(&ge->accept.status,
			     sizeof(ge->accept.status));
			CCIETH_VALGRIND_MEMORY_MAKE_READABLE
			    (&ge->accept.user_conn_id,
			     sizeof(ge->accept.user_conn_id));
			econn =
			    (void *)(uintptr_t) ge->accept.user_conn_id;

			event->type = CCI_EVENT_ACCEPT;
			event->connect.status = ge->connect.status;
			event->connect.context = econn->_conn.connection.context;

			if (ge->connect.status != 0) {
				/* failed */
				event->connect.connection = NULL;
				pthread_mutex_lock(&_ep->lock);
				TAILQ_REMOVE(&eep->connections, econn, entry);
				pthread_mutex_unlock(&_ep->lock);
				free(econn);
			} else {
				/* success */
				/* max_send_size and conn_id initialized on connect_request event */
				event->connect.connection = &econn->_conn.connection;
			}
			break;
		}
	case CCIETH_IOCTL_EVENT_DEVICE_FAILED:
		event->type = CCI_EVENT_ENDPOINT_DEVICE_FAILED;
		event->dev_failed.endpoint = endpoint;
		break;
	case CCIETH_IOCTL_EVENT_CONNECTION_CLOSED:{
			eth__conn_t *econn;

			CCIETH_VALGRIND_MEMORY_MAKE_READABLE
			    (&ge->connection_closed.user_conn_id,
			     sizeof(ge->connection_closed.user_conn_id));
			econn =
			    (void *)(uintptr_t) ge->
			    connection_closed.user_conn_id;
			econn->id = CCIETH_CONNECTION_INVALID_ID;	/* keep the connection, but make it unusable */
			printf("marked connection as closed\n");
			break;
		}
	default:
		printf("got invalid event type %d\n", ge->type);
		goto out_with_event;
	}
	*eventp = event;
	return CCI_SUCCESS;

out_with_event:
	free(eev);
	return CCI_EAGAIN;
}

static int eth_return_event(cci_event_t * event)
{
	cci__evt_t *_ev = container_of(event, cci__evt_t, event);
	eth__evt_t *eev = container_of(_ev, eth__evt_t, _ev);

	if (event->type == CCI_EVENT_CONNECT_REQUEST
	    && eev->type_params.connect_request.need_reply)
		return CCI_EINVAL;

	free(eev);
	return 0;
}

static int eth_send(cci_connection_t * connection,
		    const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	cci__conn_t *_conn = container_of(connection, cci__conn_t, connection);
	eth__conn_t *econn = container_of(_conn, eth__conn_t, _conn);
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *_ep = container_of(endpoint, cci__ep_t, endpoint);
	eth__ep_t *eep = _ep->priv;
	struct ccieth_ioctl_msg arg;
	int ret;

	/* ccieth always copies to kernel sk_buffs */
	flags &= ~CCI_FLAG_NO_COPY;

	/* FIXME */
	if (flags & CCI_FLAG_SILENT)
		return ENOSYS;

	/* make sure API flag match */
	ETH_BUILD_ASSERT(CCI_FLAG_BLOCKING == CCIETH_FLAG_BLOCKING);
	ETH_BUILD_ASSERT(CCI_FLAG_SILENT == CCIETH_FLAG_SILENT);
	/* make sure internal flags don't conflict with API flags */
	assert(!(flags & CCIETH_FLAG_RELIABLE));

	/* add internal flags */
	if (connection->attribute != CCI_CONN_ATTR_UU)
		flags |= CCIETH_FLAG_RELIABLE;

	arg.conn_id = econn->id;
	arg.msg_ptr = (uintptr_t) msg_ptr;
	arg.msg_len = msg_len;
	arg.context = (uintptr_t) context;
	arg.flags = flags;

	ret = ioctl(eep->fd, CCIETH_IOCTL_MSG, &arg);
	if (ret < 0) {
		perror("ioctl send");
		return errno;
	}

	return CCI_SUCCESS;
}

static int eth_sendv(cci_connection_t * connection,
		     const struct iovec *iov_ptr, uint32_t iov_len,
		     const void *context, int flags)
{
	void *buffer;
	size_t length, offset;
	unsigned i;
	int ret;

	for(i = 0, length = 0;
	    i < iov_len;
	    length += iov_ptr[i].iov_len, i++);

	buffer = malloc(length);
	if (!buffer)
		return CCI_ENOMEM;

	for(i = 0, offset = 0; i < iov_len; offset += iov_ptr[i].iov_len, i++)
		memcpy(buffer + offset, iov_ptr[i].iov_base, iov_ptr[i].iov_len);

	ret = cci_send(connection, buffer, length, context, flags);

	free(buffer);

	return ret;
}

static int eth_rma_register(cci_endpoint_t * endpoint,
			    cci_connection_t * connection,
			    void *start, uint64_t length, uint64_t * rma_handle)
{
	printf("In eth_rma_register\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int eth_rma_deregister(uint64_t rma_handle)
{
	printf("In eth_rma_deregister\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int eth_rma(cci_connection_t * connection,
		   const void *msg_ptr, uint32_t msg_len,
		   uint64_t local_handle, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset,
		   uint64_t data_len, const void *context, int flags)
{
	printf("In eth_rma\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}
