/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#if defined(__INTEL_COMPILER)
#pragma warning(disable:593)
#pragma warning(disable:869)
#pragma warning(disable:981)
#pragma warning(disable:1338)
#pragma warning(disable:2259)
#endif				//   __INTEL_COMPILER

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/core/core.h"
#include "core_tcp.h"

#define DEBUG_RNR 0

#if DEBUG_RNR
#include <stdbool.h>
bool conn_established = false;
#endif

volatile int tcp_shut_down = 0;
tcp_globals_t *sglobals = NULL;
static int threads_running = 0;
pthread_t progress_tid, recv_tid;

/*
 * Local functions
 */
static int tcp_init(cci_plugin_core_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int tcp_finalize(cci_plugin_core_t * plugin);
static const char *tcp_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status);
static int tcp_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpoint,
				cci_os_handle_t * fd);
static int tcp_destroy_endpoint(cci_endpoint_t * endpoint);
static int tcp_accept(cci_event_t *event, const void *context);
static int tcp_reject(cci_event_t *conn_req);
static int tcp_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout);
static int tcp_disconnect(cci_connection_t * connection);
static int tcp_set_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, const void *val, int len);
static int tcp_get_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, void **val, int *len);
static int tcp_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int tcp_get_event(cci_endpoint_t * endpoint,
			  cci_event_t ** const event);
static int tcp_return_event(cci_event_t * event);
static int tcp_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags);
static int tcp_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags);
static int tcp_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle);
static int tcp_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle);
static int tcp_rma(cci_connection_t * connection,
		    const void *header_ptr, uint32_t header_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags);

static uint8_t tcp_ip_hash(in_addr_t ip, uint16_t port);
static void tcp_progress_sends(cci__dev_t * dev);
static void *tcp_progress_thread(void *arg);
static void *tcp_recv_thread(void *arg);
static inline void tcp_progress_dev(cci__dev_t * dev);
static int tcp_sendto(cci_os_handle_t sock, void *buf, int len,
		       const struct sockaddr_in sin);

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
cci_plugin_core_t cci_core_tcp_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CORE_API_VERSION,
	 "sock",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 30,

	 /* Bootstrap function pointers */
	 cci_core_tcp_post_load,
	 cci_core_tcp_pre_unload,
	 },

	/* API function pointers */
	tcp_init,
	tcp_finalize,
	tcp_strerror,
	tcp_create_endpoint,
	tcp_destroy_endpoint,
	tcp_accept,
	tcp_reject,
	tcp_connect,
	tcp_disconnect,
	tcp_set_opt,
	tcp_get_opt,
	tcp_arm_os_handle,
	tcp_get_event,
	tcp_return_event,
	tcp_send,
	tcp_sendv,
	tcp_rma_register,
	tcp_rma_deregister,
	tcp_rma
};

static inline void
tcp_sin_to_name(struct sockaddr_in sin, char *buffer, int len)
{
	snprintf(buffer, len, "%s:%d", inet_ntoa(sin.sin_addr),
		 ntohs(sin.sin_port));
	return;
}

static inline const char *tcp_msg_type(tcp_msg_type_t type)
{
	switch (type) {
	case TCP_MSG_CONN_REQUEST:
		return "conn_request";
	case TCP_MSG_CONN_REPLY:
		return "conn_reply";
	case TCP_MSG_CONN_ACK:
		return "conn_ack";
	case TCP_MSG_DISCONNECT:
		return "disconnect";
	case TCP_MSG_SEND:
		return "send";
	case TCP_MSG_RNR:
		return "receiver not ready";
	case TCP_MSG_KEEPALIVE:
		return "keepalive";
	case TCP_MSG_PING:
		return "ping for RTTM";
	case TCP_MSG_ACK_ONLY:
		return "ack_only";
	case TCP_MSG_ACK_UP_TO:
		return "ack_up_to";
	case TCP_MSG_SACK:
		return "selective ack";
	case TCP_MSG_RMA_WRITE:
		return "RMA write";
	case TCP_MSG_RMA_READ_REQUEST:
		return "RMA read request";
	case TCP_MSG_RMA_READ_REPLY:
		return "RMA read reply";
	case TCP_MSG_RMA_INVALID:
		return "invalid RMA handle";
	case TCP_MSG_INVALID:
		assert(0);
		return "invalid";
	case TCP_MSG_TYPE_MAX:
		assert(0);
		return "type_max";
	}
	return NULL;
}

static int
tcp_find_devices(void)
{
	int ret = CCI_SUCCESS, i = 0;
	struct ifaddrs *addrs = NULL, *ifa = NULL, *tmp = NULL;

	CCI_ENTER;

	addrs = calloc(CCI_MAX_DEVICES + 1, sizeof(*addrs));
	if (!addrs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ret = getifaddrs(&ifa);
	if (ret) {
		ret = errno;
		debug(CCI_DB_DRVR, "%s: getifaddrs() returned %s",
				__func__, strerror(ret));
		goto out;
	}

	for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
		if (tmp->ifa_addr->sa_family == AF_INET &&
			!(tmp->ifa_flags & IFF_LOOPBACK)) {

			int len = sizeof(struct sockaddr);

			addrs[i] .ifa_name = strdup(tmp->ifa_name);
			addrs[i].ifa_flags = tmp->ifa_flags;
			addrs[i].ifa_addr = calloc(1, len);
			if (!addrs[i].ifa_addr) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(addrs[i].ifa_addr, tmp->ifa_addr, len);
			addrs[i].ifa_netmask = calloc(1, len);
			if (!addrs[i].ifa_netmask) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(addrs[i].ifa_netmask, tmp->ifa_netmask, len);
			addrs[i].ifa_broadaddr = calloc(1, len);
			if (!addrs[i].ifa_broadaddr) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(addrs[i].ifa_broadaddr, tmp->ifa_broadaddr, len);
			i++;
		}
	}
	sglobals->ifa_count = i;

	if (sglobals->ifa_count) {
		int len = (sglobals->ifa_count + 1) * sizeof(*addrs);

		addrs = realloc(addrs, len);
		sglobals->ifaddrs = addrs;
	} else {
		ret = CCI_ENODEV;
	}
out:
	if (ret) {
		if (addrs) {
			for (i = 0; i < CCI_MAX_DEVICES; i++) {
				free(addrs[i].ifa_name);
				free(addrs[i].ifa_addr);
				free(addrs[i].ifa_netmask);
				free(addrs[i].ifa_broadaddr);
			}
		}
	}
	CCI_EXIT;
	return ret;
}

static int tcp_init(cci_plugin_core_t *plugin,
		     uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret, count = 0;
	cci__dev_t *dev, *ndev;
	cci_device_t **devices;

	CCI_ENTER;

#if DEBUG_RNR
	fprintf(stderr, "Warning, debug mode (RNR testing)!\n");
#endif

	/* init sock globals */
	sglobals = calloc(1, sizeof(*sglobals));
	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	pthread_mutex_init(&sglobals->lock, NULL);

	srandom((unsigned int)tcp_get_usecs());

	devices = calloc(CCI_MAX_DEVICES, sizeof(*sglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ret = tcp_find_devices();
	if (ret) {
		goto out;
	}

	if (!globals->configfile) {
		int i;

		for (i = 0; i < sglobals->ifa_count; i++) {
			struct cci_device *device;
			tcp_dev_t *sdev;

			dev = calloc(1, sizeof(*dev));
			if (!dev) {
				ret = CCI_ENOMEM;
				goto out;
			}
			dev->priv = calloc(1, sizeof(*sdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}
			sdev = dev->priv;
			sdev->ifa = &sglobals->ifaddrs[i];

			cci__init_dev(dev);
			dev->plugin = plugin;
			dev->priority = plugin->base.priority;

			device = &dev->device;
			device->max_send_size = TCP_DEFAULT_MSS;
			device->name = sdev->ifa->ifa_name;
			device->up = sdev->ifa->ifa_flags & IFF_UP;

			device->rate = 0;
			device->pci.domain = -1;    /* per CCI spec */
			device->pci.bus = -1;       /* per CCI spec */
			device->pci.dev = -1;       /* per CCI spec */
			device->pci.func = -1;      /* per CCI spec */

			sdev = dev->priv;
			//TAILQ_INIT(&sdev->queued);
			//TAILQ_INIT(&sdev->pending);
			//sdev->is_progressing = 0;

			dev->driver = strdup("tcp");
			cci__add_dev(dev);
			devices[i] = device;
		}
		count = sglobals->ifa_count;

	} else
	/* find devices that we own */
	TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("tcp", dev->driver)) {
			const char * const *arg;
			struct cci_device *device;
			tcp_dev_t *sdev;
			in_addr_t dev_ip = 0;
			uint32_t port = 0;

			dev->plugin = plugin;
			if (dev->priority == -1)
				dev->priority = plugin->base.priority;

			device = &dev->device;
			device->max_send_size = TCP_DEFAULT_MSS;

			/* TODO determine link rate
			 *
			 * linux->driver->get ethtool settings->speed
			 * bsd/darwin->ioctl(SIOCGIFMEDIA)->ifm_active
			 * windows ?
			 */
			device->rate = 0;

			device->pci.domain = -1;	/* per CCI spec */
			device->pci.bus = -1;	/* per CCI spec */
			device->pci.dev = -1;	/* per CCI spec */
			device->pci.func = -1;	/* per CCI spec */

			dev->priv = calloc(1, sizeof(*sdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}

			sdev = dev->priv;
			//TAILQ_INIT(&sdev->queued);
			//TAILQ_INIT(&sdev->pending);
			//sdev->is_progressing = 0;

			/* parse conf_argv */
			for (arg = device->conf_argv; *arg != NULL; arg++) {
				if (0 == strncmp("ip=", *arg, 3)) {
					int i;
					const char *ip = *arg + 3;

					dev_ip = inet_addr(ip);	/* network order */
					for (i = 0; i < sglobals->ifa_count; i++) {
						struct ifaddrs *ifa = &sglobals->ifaddrs[i];
						struct sockaddr_in *sin =
							(struct sockaddr_in*) ifa->ifa_addr;

						if (sin->sin_addr.s_addr == dev_ip) {
							sdev->ifa = ifa;
						}
					}
				} else if (0 == strncmp("mtu=", *arg, 4)) {
					const char *mss_str = *arg + 4;
					uint32_t mss = strtol(mss_str, NULL, 0);
					if (mss > TCP_MAX_MSS)
						mss = TCP_MAX_MSS;

					mss -= TCP_MAX_HDR_SIZE;

					assert(mss >= TCP_MIN_MSS);
					device->max_send_size = mss;
				} else if (0 == strncmp("interface=", *arg, 10)) {
					int i;
					const char *ifa_name = *arg + 10;

					if (sdev->ifa)
						continue;
					for (i = 0; i < sglobals->ifa_count; i++) {
						struct ifaddrs *ifa = &sglobals->ifaddrs[i];

						if (0 == strncmp(ifa_name, ifa->ifa_name,
								strlen(ifa->ifa_name))) {
							sdev->ifa = ifa;
						}
					}
				} else if (0 == strncmp("port=", *arg, 5)) {
					const char *port_str = *arg + 5;
					port = strtol(port_str, NULL, 0);
				}
			}
			if (sdev->ifa) {
				if (port) {
					struct sockaddr_in *sin =
						(struct sockaddr_in*) sdev->ifa->ifa_addr;

					sin->sin_port = htons(port);
				}
				TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
				device->up = sdev->ifa->ifa_flags & IFF_UP;
				cci__add_dev(dev);
				devices[count++] = device;
			} else {
				/* FIXME clean up this device */
				debug(CCI_DB_DRVR, "%s: device [%s] specified but not found."
					"Does the config file have a valid ip= or "
					"interface=?", __func__, device->name);
			}
		}
	}

	sglobals->count = count;

	devices =
	    realloc(devices, (sglobals->count + 1) * sizeof(cci_device_t *));
	devices[sglobals->count] = NULL;

	*((cci_device_t ***) & sglobals->devices) = devices;

	CCI_EXIT;
	return CCI_SUCCESS;

      out:
	if (devices) {
		cci_device_t const *device;
		cci__dev_t *my_dev;

		for (device = devices[0]; device != NULL; device++) {
			my_dev = container_of(device, cci__dev_t, device);
			if (my_dev->priv)
				free(my_dev->priv);
		}
		free(devices);
	}
	if (sglobals) {
		int i;

		for (i = 0; i < sglobals->count; i++) {
			struct ifaddrs *ifa = &sglobals->ifaddrs[i];
			free(ifa->ifa_name);
			free(ifa->ifa_netmask);
			free(ifa->ifa_broadaddr);
		}
		free(sglobals->ifaddrs);
		free((void *)sglobals);
		sglobals = NULL;
	}
	CCI_EXIT;
	return ret;
}

static const char *tcp_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status)
{
	char *str;

	CCI_ENTER;

	str = strerror(status);

	CCI_EXIT;
	return str;
}

/* NOTE the CCI layer has already unbound all devices
 *      and destroyed all endpoints.
 *      All we need to do if free dev->priv
 */
static int tcp_finalize(cci_plugin_core_t * plugin)
{
	int i;
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	/* let the progress thread know we are going away */
	tcp_shut_down = 1;

	TAILQ_FOREACH(dev, &globals->devs, entry)
		if (!strcmp(dev->driver, "tcp"))
			free(dev->priv);

	for (i = 0; i < sglobals->ifa_count; i++) {
		struct ifaddrs *ifa = &sglobals->ifaddrs[i];
		free(ifa->ifa_name);
		free(ifa->ifa_netmask);
		free(ifa->ifa_broadaddr);
	}
	free(sglobals->ifaddrs);
	free(sglobals->devices);
	free((void *)sglobals);
	sglobals = NULL;

	CCI_EXIT;
	return CCI_SUCCESS;
}

static inline int
tcp_set_nonblocking(cci__ep_t *ep, cci__conn_t *conn)
{
	int ret, flags;
	tcp_ep_t *sep = ep->priv;
	tcp_conn_t *sconn = conn->priv;

	flags = fcntl(sconn->sock, F_GETFL, 0);
	if (-1 == flags)
		flags = 0;
	ret = fcntl(sconn->sock, F_SETFL, flags | O_NONBLOCK);
	if (-1 == ret)
		return errno;
	pthread_mutex_lock(&ep->lock);
	FD_SET(sconn->sock, &sep->fds);
	if (sconn->sock >= sep->nfds)
		sep->nfds = sconn->sock + 1;
	pthread_mutex_unlock(&ep->lock);
	return 0;
}

static inline void tcp_close_socket(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *sep = ep->priv;
	tcp_conn_t *sconn = conn->priv;

	pthread_mutex_lock(&ep->lock);
	FD_CLR(sconn->sock, &sep->fds);
#if 1
	/* TODO reverse walk tree to find highest fd */
#else
	if (sconn->sock == sep->nfds - 1) {
		int i;
		tcp_fd_idx_t *idx;
		for (i = sock - 1; i >= 0; i--) {
			idx = (tcp_fd_idx_t *) & sglobals->fd_idx[i];
			if (idx->type != TCP_FD_UNUSED) {
				sglobals->nfds = i + 1;
				found = 1;
				break;
			}
		}
		if (!found)
			sglobals->nfds = 0;
	}
#endif
	pthread_mutex_unlock(&ep->lock);
	close(sconn->sock);
	return;
}

static int tcp_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpointp,
				cci_os_handle_t * fd)
{
	int i, ret;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	tcp_ep_t *sep = NULL;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	tcp_dev_t *sdev;
	struct sockaddr_in sin;
	socklen_t slen;
	char name[40];

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	if (0 != strcmp("sock", dev->driver)) {
		ret = CCI_EINVAL;
		goto out;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*sep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}

	endpoint->max_recv_buffer_count = TCP_EP_RX_CNT;
	ep->rx_buf_cnt = TCP_EP_RX_CNT;
	ep->tx_buf_cnt = TCP_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size + TCP_MAX_HDRS;
	ep->tx_timeout = TCP_EP_TX_TIMEOUT_SEC * 1000000;

	sep = ep->priv;
	sep->ids = calloc(TCP_NUM_BLOCKS, sizeof(*sep->ids));
	if (!sep->ids) {
		ret = CCI_ENOMEM;
		goto out;
	}

	sep->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sep->sock == -1) {
		ret = errno;
		goto out;
	}
	/* bind socket to device */
	sdev = dev->priv;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = sdev->ip;

	ret = bind(sep->sock, (const struct sockaddr *)&sin, sizeof(sin));
	if (ret) {
		ret = errno;
		goto out;
	}

	slen = sizeof(sep->sin);

	ret = getsockname(sep->sock, (struct sockaddr *)&sep->sin, &slen);
	if (ret) {
		ret = errno;
		goto out;
	}

	memset(name, 0, sizeof(name));
	sprintf(name, "ip://");
	tcp_sin_to_name(sep->sin, name + (uintptr_t) 5, sizeof(name) - 5);
	endpoint->name = strdup(name);

	for (i = 0; i < TCP_EP_HASH_SIZE; i++) {
		TAILQ_INIT(&sep->conn_hash[i]);
		TAILQ_INIT(&sep->active_hash[i]);
	}

	TAILQ_INIT(&sep->txs);
	TAILQ_INIT(&sep->idle_txs);
	TAILQ_INIT(&sep->rxs);
	TAILQ_INIT(&sep->idle_rxs);
	TAILQ_INIT(&sep->handles);
	TAILQ_INIT(&sep->rma_ops);
	TAILQ_INIT(&sep->ka_conns);

	/* alloc txs */
	for (i = 0; i < ep->tx_buf_cnt; i++) {
		tcp_tx_t *tx;

		tx = calloc(1, sizeof(*tx));
		if (!tx) {
			ret = CCI_ENOMEM;
			goto out;
		}
		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.ep = ep;
		tx->buffer = calloc(1, ep->buffer_len);
		if (!tx->buffer) {
			ret = CCI_ENOMEM;
			goto out;
		}
		tx->len = 0;
		TAILQ_INSERT_TAIL(&sep->txs, tx, tentry);
		TAILQ_INSERT_TAIL(&sep->idle_txs, tx, dentry);
	}

	/* alloc rxs */
	for (i = 0; i < ep->rx_buf_cnt; i++) {
		tcp_rx_t *rx;

		rx = calloc(1, sizeof(*rx));
		if (!rx) {
			ret = CCI_ENOMEM;
			goto out;
		}
		rx->evt.event.type = CCI_EVENT_RECV;
		rx->evt.ep = ep;
		rx->buffer = calloc(1, ep->buffer_len);
		if (!rx->buffer) {
			ret = CCI_ENOMEM;
			goto out;
		}
		rx->len = 0;
		TAILQ_INSERT_TAIL(&sep->rxs, rx, gentry);
		TAILQ_INSERT_TAIL(&sep->idle_rxs, rx, entry);
	}

	ret = tcp_set_nonblocking(sep->sock, TCP_FD_EP, ep);
	if (ret)
		goto out;

	CCI_EXIT;
	return CCI_SUCCESS;

      out:
	pthread_mutex_lock(&dev->lock);
	if (!TAILQ_EMPTY(&dev->eps)) {
		TAILQ_REMOVE(&dev->eps, ep, entry);
	}
	pthread_mutex_unlock(&dev->lock);
	if (sep) {
		while (!TAILQ_EMPTY(&sep->txs)) {
			tcp_tx_t *tx;

			tx = TAILQ_FIRST(&sep->txs);
			TAILQ_REMOVE(&sep->txs, tx, tentry);
			if (tx->buffer)
				free(tx->buffer);
			free(tx);
		}
		while (!TAILQ_EMPTY(&sep->rxs)) {
			tcp_rx_t *rx;

			rx = TAILQ_FIRST(&sep->rxs);
			TAILQ_REMOVE(&sep->rxs, rx, gentry);
			if (rx->buffer)
				free(rx->buffer);
			free(rx);
		}
		if (sep->ids)
			free(sep->ids);
		if (sep->sock)
			tcp_close_socket(sep->sock);
		free(sep);
	}
	if (ep)
		free(ep);
	*endpointp = NULL;
	CCI_EXIT;
	return ret;
}

static int tcp_destroy_endpoint(cci_endpoint_t * endpoint)
{
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	tcp_ep_t *sep = NULL;
	tcp_dev_t *sdev = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;
	sep = ep->priv;
	sdev = dev->priv;

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);

	ep->priv = NULL;

	if (sep) {
		int i;
		cci__conn_t *conn;
		tcp_conn_t *sconn;

		sep->closing = 1;

		if (sep->sock)
			tcp_close_socket(sep->sock);

		for (i = 0; i < TCP_EP_HASH_SIZE; i++) {
			while (!TAILQ_EMPTY(&sep->conn_hash[i])) {
				sconn = TAILQ_FIRST(&sep->conn_hash[i]);
				TAILQ_REMOVE(&sep->conn_hash[i], sconn, entry);
				conn = sconn->conn;

				free(conn);
				free(sconn);
			}
			while (!TAILQ_EMPTY(&sep->active_hash[i])) {
				sconn = TAILQ_FIRST(&sep->active_hash[i]);
				TAILQ_REMOVE(&sep->active_hash[i], sconn,
					     entry);
				conn = sconn->conn;

				free(conn);
				free(sconn);
			}
		}
		while (!TAILQ_EMPTY(&sep->txs)) {
			tcp_tx_t *tx;

			tx = TAILQ_FIRST(&sep->txs);
			TAILQ_REMOVE(&sep->txs, tx, tentry);
			if (tx->state == TCP_TX_QUEUED)
				TAILQ_REMOVE(&sdev->queued, tx, dentry);
			else if (tx->state == TCP_TX_PENDING)
				TAILQ_REMOVE(&sdev->pending, tx, dentry);
			if (tx->buffer)
				free(tx->buffer);
			free(tx);
		}
		while (!TAILQ_EMPTY(&sep->rxs)) {
			tcp_rx_t *rx;

			rx = TAILQ_FIRST(&sep->rxs);
			TAILQ_REMOVE(&sep->rxs, rx, gentry);
			if (rx->buffer)
				free(rx->buffer);
			free(rx);
		}
		while (!TAILQ_EMPTY(&sep->rma_ops)) {
			tcp_rma_op_t *rma_op = TAILQ_FIRST(&sep->rma_ops);
			TAILQ_REMOVE(&sep->rma_ops, rma_op, entry);
			free(rma_op);
		}
		while (!TAILQ_EMPTY(&sep->handles)) {
			tcp_rma_handle_t *handle = TAILQ_FIRST(&sep->handles);
			TAILQ_REMOVE(&sep->handles, handle, entry);
			free(handle);
		}
		if (sep->ids)
			free(sep->ids);
		free(sep);
		ep->priv = NULL;
	}
	if (endpoint->name)
		free((char *)endpoint->name);
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static void tcp_get_id(tcp_ep_t * ep, uint32_t * id)
{
	uint32_t n, block, offset;
	uint64_t *b;

	while (1) {
		n = random() % TCP_NUM_BLOCKS;
		block = n / TCP_BLOCK_SIZE;
		offset = n % TCP_BLOCK_SIZE;
		b = &ep->ids[block];

		if ((*b & (1ULL << offset)) == 0) {
			*b |= (1ULL << offset);
			*id = (block * TCP_BLOCK_SIZE) + offset;
			break;
		}
	}
	return;
}

static void tcp_put_id(tcp_ep_t * ep, uint32_t id)
{
	uint32_t block, offset;
	uint64_t *b;

	block = id / TCP_BLOCK_SIZE;
	offset = id % TCP_BLOCK_SIZE;
	b = &ep->ids[block];

	assert((*b & (1 << offset)) == 1);
	*b &= ~(1 << offset);

	return;
}

static inline uint32_t tcp_get_new_seq(void)
{
	return ((uint32_t) random() & TCP_SEQ_MASK);
}

/* The endpoint maintains 256 lists. Hash the ip and port and return the index
 * of the list. We use all six bytes and this is endian agnostic. It evenly
 * disperses large blocks of addresses as well as large ranges of ports on the
 * same address.
 */
static uint8_t tcp_ip_hash(in_addr_t ip, uint16_t port)
{
	port ^= (ip & 0x0000FFFF);
	port ^= (ip & 0xFFFF0000) >> 16;
	return (port & 0x00FF) ^ ((port & 0xFF00) >> 8);
}

static int tcp_accept(cci_event_t *event, const void *context)
{
	uint8_t a;
	uint16_t b;
	uint32_t unused;
	uint32_t peer_seq;
	uint32_t peer_ts;
	int i;
	cci_endpoint_t *endpoint;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	cci__dev_t *dev = NULL;
	tcp_ep_t *sep = NULL;
	tcp_conn_t *sconn = NULL;
	tcp_dev_t *sdev = NULL;
	tcp_header_r_t *hdr_r = NULL;
	tcp_msg_type_t type;
	tcp_tx_t *tx = NULL;
	tcp_rx_t *rx = NULL;
	tcp_handshake_t *hs = NULL;
	uint32_t id, ack, max_recv_buffer_count, mss = 0, ka;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	rx = container_of(evt, tcp_rx_t, evt);
	ep = evt->ep;
	endpoint = &ep->endpoint;
	sep = ep->priv;
	dev = ep->dev;
	sdev = dev->priv;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}
	conn->plugin = ep->plugin;

	conn->tx_timeout = ep->tx_timeout;
	conn->priv = calloc(1, sizeof(*sconn));
	if (!conn->priv) {
		free(conn);
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	/* get a tx */
	pthread_mutex_lock(&ep->lock);
	if (!TAILQ_EMPTY(&sep->idle_txs)) {
		tx = TAILQ_FIRST(&sep->idle_txs);
		TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
	}
	pthread_mutex_unlock(&ep->lock);

	if (!tx) {
		free(conn->priv);
		free(conn);
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	hdr_r = rx->buffer;
	tcp_parse_header(&hdr_r->header, &type, &a, &b, &unused);
	tcp_parse_seq_ts(&hdr_r->seq_ts, &peer_seq, &peer_ts);

	conn->connection.attribute = (enum cci_conn_attribute)a;
	conn->connection.endpoint = endpoint;
	conn->connection.context = (void *)context;
	conn->connection.max_send_size = dev->device.max_send_size;

	hs = (tcp_handshake_t *) (rx->buffer +
				   (uintptr_t) sizeof(tcp_header_r_t));
	tcp_parse_handshake(hs, &id, &ack, &max_recv_buffer_count, &mss, &ka);
	if (ka != 0UL) {
		debug(CCI_DB_CONN, "keepalive timeout: %d", ka);
		conn->keepalive_timeout = ka;
	}
	if (mss < TCP_MIN_MSS) {
		/* FIXME do what? */
	}
	if (mss < conn->connection.max_send_size)
		conn->connection.max_send_size = mss;

	sconn = conn->priv;
	TAILQ_INIT(&sconn->tx_seqs);
	TAILQ_INIT(&sconn->acks);
	TAILQ_INIT(&sconn->rmas);
	sconn->conn = conn;
	sconn->cwnd = TCP_INITIAL_CWND;
	sconn->status = TCP_CONN_READY;	/* set ready since the app thinks it is */
	*((struct sockaddr_in *)&sconn->sin) = rx->sin;
	sconn->peer_id = id;
	tcp_get_id(sep, &sconn->id);
	sconn->seq = tcp_get_new_seq();	/* even for UU since this reply is reliable */
	sconn->seq_pending = sconn->seq - 1;
	if (cci_conn_is_reliable(conn)) {
		sconn->max_tx_cnt = max_recv_buffer_count < ep->tx_buf_cnt ?
		    max_recv_buffer_count : ep->tx_buf_cnt;
		sconn->last_ack_seq = sconn->seq;
		sconn->last_ack_ts = tcp_get_usecs();
		sconn->ssthresh = sconn->max_tx_cnt;
	}

	/* insert in sock ep's list of conns */

	i = tcp_ip_hash(sconn->sin.sin_addr.s_addr, sconn->sin.sin_port);
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "accepting conn with hash %d", i);

	/* prepare conn_reply */

	tx->msg_type = TCP_MSG_CONN_REPLY;
	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;

	evt = &tx->evt;
	evt->ep = ep;
	evt->conn = conn;
	evt->event.type = CCI_EVENT_ACCEPT;
	evt->event.accept.status = CCI_SUCCESS;	/* for now */
	evt->event.accept.context = (void *)context;
	evt->event.accept.connection = &conn->connection;

	/* pack the msg */

	hdr_r = (tcp_header_r_t *) tx->buffer;
	tcp_pack_conn_reply(&hdr_r->header, CCI_SUCCESS /* FIXME */ ,
			     sconn->peer_id);
	tcp_pack_seq_ts(&hdr_r->seq_ts, sconn->seq,
			 (uint32_t) sconn->last_ack_ts);
	hs = (tcp_handshake_t *) (tx->buffer + sizeof(*hdr_r));
	tcp_pack_handshake(hs, sconn->id, peer_seq,
			    ep->endpoint.max_recv_buffer_count,
			    conn->connection.max_send_size, 0);

	tx->len = sizeof(*hdr_r) + sizeof(*hs);
	tx->seq = sconn->seq;

	debug(CCI_DB_CONN, "queuing conn_reply with seq %u ts %x", sconn->seq, sconn->ts);	// FIXME

	/* insert at tail of device's queued list */

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&dev->lock);
	TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
	pthread_mutex_unlock(&dev->lock);

	/* try to progress txs */

	tcp_progress_dev(dev);

	CCI_EXIT;

	return CCI_SUCCESS;
}

/* Send reject reply to client.
 *
 * We cannot use the event's buffer since the app will most likely return the
 * event before we get an ack from the client. We will get a tx for the reply.
 */
static int tcp_reject(cci_event_t *event)
{
	int ret = CCI_SUCCESS;
	uint8_t a;
	uint16_t b;
	uint32_t peer_id;
	uint32_t peer_seq;
	uint32_t peer_ts;
	cci__evt_t *evt = NULL;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	tcp_ep_t *sep = NULL;
	tcp_dev_t *sdev = NULL;
	tcp_header_r_t *hdr_r = NULL;
	tcp_msg_type_t type;
	char name[32];
	tcp_rx_t *rx = NULL;
	tcp_tx_t *tx = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	hdr_r = (void *)event->request.data_ptr;
	tcp_parse_header(&hdr_r->header, &type, &a, &b, &peer_id);
	tcp_parse_seq_ts(&hdr_r->seq_ts, &peer_seq, &peer_ts);

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	sep = ep->priv;
	rx = container_of(evt, tcp_rx_t, evt);

	/* get a tx */
	pthread_mutex_lock(&ep->lock);
	if (!TAILQ_EMPTY(&sep->idle_txs)) {
		tx = TAILQ_FIRST(&sep->idle_txs);
		TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
	}
	pthread_mutex_unlock(&ep->lock);

	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	/* prep the tx */

	tx->msg_type = TCP_MSG_CONN_REPLY;
	tx->evt.ep = ep;
	tx->evt.conn = NULL;
	tx->evt.event.type = CCI_EVENT_CONNECT;
	tx->evt.event.connect.status = ECONNREFUSED;
	tx->evt.event.connect.connection = NULL;
	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;
	tx->sin = rx->sin;

	/* prepare conn_reply */

	hdr_r = (tcp_header_r_t *) tx->buffer;
	tcp_pack_conn_reply(&hdr_r->header, CCI_ECONNREFUSED /* FIXME */ ,
			     peer_id);
	tcp_pack_seq_ts(&hdr_r->seq_ts, peer_seq, 0);

	tx->len = sizeof(*hdr_r);

	/* insert at tail of device's queued list */

	dev = ep->dev;
	sdev = dev->priv;

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&dev->lock);
	TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
	pthread_mutex_unlock(&dev->lock);

	/* try to progress txs */

	tcp_progress_dev(dev);

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(rx->sin, name, sizeof(name));
	debug((CCI_DB_MSG | CCI_DB_CONN), "ep %d sending reject to %s",
	      sep->sock, name);

      out:
	CCI_EXIT;
	return ret;
}

static int tcp_getaddrinfo(const char *uri, in_addr_t * in, uint16_t * port)
{
	int ret;
	char *hostname, *svc, *colon;
	struct addrinfo *ai = NULL, hints;

	if (0 == strncmp("ip://", uri, 5))
		hostname = strdup(&uri[5]);
	else {
		CCI_EXIT;
		return CCI_EINVAL;
	}

	colon = strchr(hostname, ':');
	if (colon) {
		*colon = '\0';
	} else {
		free(hostname);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	colon++;
	svc = colon;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_UDP;

	ret = getaddrinfo(hostname, svc, &hints, &ai);
	free(hostname);

	if (ret) {
		if (ai)
			freeaddrinfo(ai);
		CCI_EXIT;
		return ret;
	}

	*in = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	*port = ((struct sockaddr_in *)ai->ai_addr)->sin_port;
	freeaddrinfo(ai);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static tcp_conn_t *tcp_find_open_conn(tcp_ep_t * sep, in_addr_t ip,
					uint16_t port, uint32_t id)
{
	uint8_t i;
	struct s_conns *conn_list;
	tcp_conn_t *sconn = NULL, *sc;

	CCI_ENTER;

	i = tcp_ip_hash(ip, port);
	conn_list = &sep->conn_hash[i];
	TAILQ_FOREACH(sc, conn_list, entry) {
		if (sc->sin.sin_addr.s_addr == ip &&
		    sc->sin.sin_port == port && sc->id == id) {
			sconn = sc;
			break;
		}
	}

	CCI_EXIT;
	return sconn;
}

static tcp_conn_t *tcp_find_active_conn(tcp_ep_t * sep, in_addr_t ip,
					  uint32_t id)
{
	uint8_t i;
	struct s_active *active_list;
	tcp_conn_t *sconn = NULL, *sc;

	CCI_ENTER;
	i = tcp_ip_hash(ip, 0);
	active_list = &sep->active_hash[i];
	TAILQ_FOREACH(sc, active_list, entry) {
		if (sc->sin.sin_addr.s_addr == ip && sc->id == id) {
			sconn = sc;
			break;
		}
	}
	CCI_EXIT;
	return sconn;
}

static tcp_conn_t *tcp_find_conn(tcp_ep_t * sep, in_addr_t ip, uint16_t port,
				   uint32_t id, tcp_msg_type_t type)
{
	switch (type) {
	case TCP_MSG_CONN_REPLY:
		return tcp_find_active_conn(sep, ip, id);
	default:
		return tcp_find_open_conn(sep, ip, port, id);
	}
}

static int tcp_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout)
{
	int ret;
	int i;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *sep = NULL;
	tcp_dev_t *sdev = NULL;
	tcp_conn_t *sconn = NULL;
	tcp_tx_t *tx = NULL;
	tcp_header_r_t *hdr_r = NULL;
	cci__evt_t *evt = NULL;
	struct cci_connection *connection = NULL;
	struct sockaddr_in *sin = NULL;
	void *ptr = NULL;
	in_addr_t ip;
	uint32_t ts = 0;
	struct s_active *active_list;
	tcp_handshake_t *hs = NULL;
	uint16_t port;
	uint32_t keepalive = 0ULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	/* allocate a new connection */
	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	conn->priv = calloc(1, sizeof(*sconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	sconn = conn->priv;
	sconn->conn = conn;
	TAILQ_INIT(&sconn->tx_seqs);
	TAILQ_INIT(&sconn->acks);
	TAILQ_INIT(&sconn->rmas);

	/* conn->tx_timeout = 0  by default */

	connection = &conn->connection;
	connection->attribute = attribute;
	connection->endpoint = endpoint;
	connection->context = (void *)context;

	/* set up sock specific info */

	sconn->status = TCP_CONN_ACTIVE;
	sconn->cwnd = TCP_INITIAL_CWND;
	sin = (struct sockaddr_in *)&sconn->sin;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;

	ret = tcp_getaddrinfo(server_uri, &ip, &port);
	if (ret)
		goto out;
	sin->sin_addr.s_addr = ip;	/* already in network order */
	sin->sin_port = port;	/* already in network order */

	/* peer will assign id */

	/* get our endpoint and device */
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	dev = ep->dev;
	sdev = dev->priv;

	connection->max_send_size = dev->device.max_send_size;
	conn->plugin = ep->plugin;

	/* Dealing with keepalive, if set, include the keepalive timeout value into
	   the connection request */
	if ((((attribute & CCI_CONN_ATTR_RO) == CCI_CONN_ATTR_RO)
	     || ((attribute & CCI_CONN_ATTR_RU) == CCI_CONN_ATTR_RU))
	    && ep->keepalive_timeout != 0UL) {
		keepalive = ep->keepalive_timeout;
	}

	i = tcp_ip_hash(ip, 0);
	active_list = &sep->active_hash[i];
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(active_list, sconn, entry);
	pthread_mutex_unlock(&ep->lock);

	/* get a tx */
	pthread_mutex_lock(&ep->lock);
	if (!TAILQ_EMPTY(&sep->idle_txs)) {
		tx = TAILQ_FIRST(&sep->idle_txs);
		TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
	}
	pthread_mutex_unlock(&ep->lock);

	if (!tx) {
		/* FIXME leak */
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	/* prep the tx */
	tx->msg_type = TCP_MSG_CONN_REQUEST;

	evt = &tx->evt;
	evt->ep = ep;
	evt->conn = conn;
	evt->event.type = CCI_EVENT_CONNECT;	/* for now */
	evt->event.connect.status = CCI_SUCCESS;
	evt->event.connect.context = (void *)context;
	evt->event.connect.connection = connection;

	/* pack the msg */

	hdr_r = (tcp_header_r_t *) tx->buffer;
	tcp_get_id(sep, &sconn->id);
	/* FIXME silence -Wall -Werror until it is used */
	if (0)
		tcp_put_id(sep, 0);
	tcp_pack_conn_request(&hdr_r->header, attribute,
			       (uint16_t) data_len, 0);
	tx->len = sizeof(*hdr_r);

	/* add seq and ack */

	sconn->seq = tcp_get_new_seq();
	sconn->seq_pending = sconn->seq - 1;
	sconn->last_ack_seq = sconn->seq;
	tx->seq = sconn->seq;
	tcp_pack_seq_ts(&hdr_r->seq_ts, tx->seq, ts);

	/* add handshake */
	hs = (tcp_handshake_t *) & hdr_r->data;
	if (keepalive != 0UL)
		conn->keepalive_timeout = keepalive;
	tcp_pack_handshake(hs, sconn->id, 0,
			    endpoint->max_recv_buffer_count,
			    connection->max_send_size, keepalive);

	tx->len += sizeof(*hs);
	ptr = tx->buffer + tx->len;

	debug(CCI_DB_CONN, "queuing conn_request with seq %u ts %x",
	      tx->seq, ts);

	/* zero even if unreliable */

	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;

	if (data_len)
		memcpy(ptr, data_ptr, data_len);

	tx->len += data_len;
	assert(tx->len <= ep->buffer_len);

	/* insert at tail of device's queued list */

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&dev->lock);
	TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
	pthread_mutex_unlock(&dev->lock);

	/* try to progress txs */

	tcp_progress_dev(dev);

	CCI_EXIT;
	return CCI_SUCCESS;

      out:
	if (conn) {
		if (conn->uri)
			free((char *)conn->uri);
		if (conn->priv)
			free(conn->priv);
		free(conn);
	}
	CCI_EXIT;
	return ret;
}

static int tcp_disconnect(cci_connection_t * connection)
{
	int i = 0;
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;
	tcp_conn_t *sconn = NULL;
	tcp_ep_t *sep = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	/* need to clean up */

	/* remove conn from ep->conn_hash[i] */
	/* if sock conn uri, free it
	 * free sock conn
	 * free conn
	 */

	conn = container_of(connection, cci__conn_t, connection);
	sconn = conn->priv;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	if (conn->keepalive_timeout != 0UL && cci_conn_is_reliable(conn)) {
		/* Remove the connection is the list of connections using keepalive */
		TAILQ_REMOVE(&sglobals->ka_conns, sconn, entry);
	}

	if (conn->uri)
		free((char *)conn->uri);

	i = tcp_ip_hash(sconn->sin.sin_addr.s_addr, sconn->sin.sin_port);
	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&sep->conn_hash[i], sconn, entry);
	pthread_mutex_unlock(&ep->lock);

	free(sconn);
	free(conn);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int tcp_set_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, const void *val, int len)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (CCI_OPT_LEVEL_ENDPOINT == level) {
		ep = container_of(handle->endpoint, cci__ep_t, endpoint);
	} else {
		conn =
		    container_of(handle->connection, cci__conn_t, connection);
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		assert(len == sizeof(ep->tx_timeout));
		memcpy(&ep->tx_timeout, val, len);
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		assert(len == sizeof(ep->keepalive_timeout));
		memcpy(&ep->keepalive_timeout, val, len);
		break;
	case CCI_OPT_CONN_SEND_TIMEOUT:
		assert(len == sizeof(conn->tx_timeout));
		memcpy(&conn->tx_timeout, val, len);
		break;
	default:
		debug(CCI_DB_INFO, "unknown option %u", name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;

	return ret;
}

static int tcp_get_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, void **val, int *len)
{
	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;

	return CCI_EINVAL;
}

static int tcp_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int tcp_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep;
	cci__evt_t *ev = NULL, *e;
	cci__dev_t *dev;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;

	tcp_progress_dev(dev);

	pthread_mutex_lock(&ep->lock);

	/* give the user the first event */
	TAILQ_FOREACH(e, &ep->evts, entry) {
		if (e->event.type == CCI_EVENT_SEND) {
			/* NOTE: if it is blocking, skip it since tcp_sendv()
			 * is waiting on it
			 */
			tcp_tx_t *tx = container_of(e, tcp_tx_t, evt);
			if (tx->flags & CCI_FLAG_BLOCKING) {
				continue;
			} else {
				ev = e;
				break;
			}
		} else {
			ev = e;
			break;
		}
	}

	if (ev)
		TAILQ_REMOVE(&ep->evts, ev, entry);
	else
		ret = CCI_EAGAIN;

	pthread_mutex_unlock(&ep->lock);

	/* TODO drain fd so that they can block again */

	*event = &ev->event;

	CCI_EXIT;
	return ret;
}

static int tcp_return_event(cci_event_t * event)
{
	cci__ep_t *ep;
	tcp_ep_t *sep;
	cci__evt_t *evt;
	tcp_tx_t *tx;
	tcp_rx_t *rx;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);

	ep = evt->ep;
	sep = ep->priv;

	/* enqueue the event */

	switch (event->type) {
	case CCI_EVENT_SEND:
		tx = container_of(evt, tcp_tx_t, evt);
		pthread_mutex_lock(&ep->lock);
		/* insert at head to keep it in cache */
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
		break;
	case CCI_EVENT_RECV:
		rx = container_of(evt, tcp_rx_t, evt);
		pthread_mutex_lock(&ep->lock);
		/* insert at head to keep it in cache */
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
		break;
	default:
		/* TODO */
		break;
	}

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int tcp_sendmsg(cci_os_handle_t sock, void **ptrs, uint32_t * lens,
			uint8_t count, const struct sockaddr_in sin)
{
	int ret, i;
	struct iovec *iov = NULL;
	struct msghdr msg;
	ssize_t sent = 0;

	iov = calloc(count, sizeof(*iov));
	if (!iov)
		return CCI_ENOMEM;

	for (i = 0; i < count; i++) {
		iov[i].iov_base = (void *)ptrs[i];
		iov[i].iov_len = (size_t) lens[i];
		sent += lens[i];
	}

	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = count;

	ret = sendmsg(sock, &msg, 0);
	if (ret != -1)
		assert(ret == sent);

	return ret;
}

static int tcp_sendto(cci_os_handle_t sock, void *buf, int len,
		       const struct sockaddr_in sin)
{
	int ret;
	const struct sockaddr *s = (const struct sockaddr *)&sin;
	socklen_t slen = sizeof(sin);

	if (0)
		tcp_sendmsg(sock, NULL, NULL, 0, sin);

	ret = sendto(sock, buf, len, 0, s, slen);
	if (ret != -1)
		assert(ret == len);

	return ret;
}

static void tcp_progress_pending(cci__dev_t * dev)
{
	int ret;
	uint64_t now;
	tcp_tx_t *tx, *tmp;
	cci__evt_t *evt;
	union cci_event *event;	/* generic CCI event */
	cci_connection_t *connection;	/* generic CCI connection */
	cci__conn_t *conn;
	tcp_conn_t *sconn;
	cci__ep_t *ep;
	tcp_ep_t *sep;
	tcp_dev_t *sdev = dev->priv;

	CCI_ENTER;

	if (!sdev)
		return;

	TAILQ_HEAD(s_idle_txs, tcp_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);

	now = tcp_get_usecs();

	/* This is only for reliable messages.
	 * Do not dequeue txs, just walk the list.
	 */

	pthread_mutex_lock(&dev->lock);
	TAILQ_FOREACH_SAFE(tx, &sdev->pending, dentry, tmp) {

		evt = &(tx->evt);
		conn = evt->conn;
		connection = &conn->connection;
		sconn = conn->priv;
		event = &evt->event;

		ep = container_of(connection->endpoint, cci__ep_t, endpoint);
		sep = ep->priv;

		assert(tx->last_attempt_us != 0ULL);

		/* has it timed out? */
		if (TCP_U64_LT(tx->timeout_us, now)) {
			/* dequeue */

			TAILQ_REMOVE(&sdev->pending, tx, dentry);

			/* set status and add to completed events */

			if (tx->msg_type == TCP_MSG_SEND)
				sconn->pending--;

			switch (tx->msg_type) {
			case TCP_MSG_SEND:
				event->send.status = CCI_ETIMEDOUT;
				if (tx->rnr != 0) {
					event->send.status = CCI_ERR_RNR;
					/* If a message that is already marked RNR times out,
					   and if the connection is reliable and ordered, we
					   mark all following messages as RNR */
					if (conn->connection.attribute ==
					    CCI_CONN_ATTR_RO) {
						tcp_tx_t *my_temp_tx;
						TAILQ_FOREACH_SAFE(my_temp_tx,
								   &sdev->
								   pending,
								   dentry,
								   tmp) {
							if (my_temp_tx->seq >
							    tx->seq)
								my_temp_tx->
								    rnr = 1;
						}
					}
				}
				break;
			case TCP_MSG_RMA_WRITE:
				pthread_mutex_lock(&ep->lock);
				tx->rma_op->pending--;
				tx->rma_op->status = CCI_ETIMEDOUT;
				pthread_mutex_unlock(&ep->lock);
				break;
			case TCP_MSG_CONN_REQUEST:
				{
					int i;
					struct s_active *active_list;

					event->connect.status = CCI_ETIMEDOUT;
					event->connect.connection = NULL;
					if (conn->uri)
						free((char *)conn->uri);
					sconn->status = TCP_CONN_CLOSING;
					i = tcp_ip_hash(sconn->sin.
							 sin_addr.s_addr, 0);
					active_list = &sep->active_hash[i];
					pthread_mutex_lock(&ep->lock);
					TAILQ_REMOVE(active_list, sconn, entry);
					pthread_mutex_unlock(&ep->lock);
					free(sconn);
					free(conn);
					sconn = NULL;
					conn = NULL;
					tx->evt.ep = ep;
					tx->evt.conn = NULL;
					break;
				}
			case TCP_MSG_CONN_REPLY:
			case TCP_MSG_CONN_ACK:
			default:
				/* TODO */
				CCI_EXIT;
				return;
			}
			/* if SILENT, put idle tx */
			if (tx->flags & CCI_FLAG_SILENT &&
			    (tx->msg_type == TCP_MSG_SEND ||
			     tx->msg_type == TCP_MSG_RMA_WRITE)) {

				tx->state = TCP_TX_IDLE;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
			} else {
				tx->state = TCP_TX_COMPLETED;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_TAIL(&evts, evt, entry);
			}
			continue;
		}

		/* is it time to resend? */

		if ((tx->last_attempt_us +
		     ((1 << tx->send_count) * TCP_RESEND_TIME_SEC * 1000000)) >
		    now)
			continue;

		/* need to resend it */

#if 0
		if (tx->send_count == 1 && tx->msg_type == TCP_MSG_SEND && 0) {
			debug(CCI_DB_INFO, "%s: reducing cwnd from %d to %d"
			      "    reducing ssthresh from %d to %d",
			      __func__, sconn->cwnd, 2, sconn->ssthresh,
			      sconn->pending / 2 + 1);
			/* reduce the slow start threshhold */
			sconn->ssthresh = (sconn->pending / 2) + 1;
			if (sconn->ssthresh < 2)
				sconn->ssthresh = 2;
			sconn->cwnd = 2;
		}
#endif

		tx->last_attempt_us = now;
		tx->send_count++;

		debug(CCI_DB_MSG, "re-sending %s msg seq %u count %u",
		      tcp_msg_type(tx->msg_type), tx->seq, tx->send_count);
		ret = tcp_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
		if (ret != tx->len) {
			debug((CCI_DB_MSG | CCI_DB_INFO),
			      "sendto() failed with %s",
			      cci_strerror(&ep->endpoint, (enum cci_status)errno));
			continue;
		}
	}
	pthread_mutex_unlock(&dev->lock);

	/* transfer txs to sock ep's list */
	while (!TAILQ_EMPTY(&idle_txs)) {
		tx = TAILQ_FIRST(&idle_txs);
		TAILQ_REMOVE(&idle_txs, tx, dentry);
		ep = tx->evt.ep;
		sep = ep->priv;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
	}

	/* transfer evts to the ep's list */
	while (!TAILQ_EMPTY(&evts)) {
		evt = TAILQ_FIRST(&evts);
		TAILQ_REMOVE(&evts, evt, entry);
		ep = evt->ep;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	CCI_EXIT;

	return;
}

static void tcp_progress_queued(cci__dev_t * dev)
{
	int ret, is_reliable;
	uint32_t timeout;
	uint64_t now;
	tcp_tx_t *tx, *tmp;
	cci__ep_t *ep;
	cci__evt_t *evt;
	cci__conn_t *conn;
	tcp_ep_t *sep;
	tcp_conn_t *sconn;
	tcp_dev_t *sdev = dev->priv;
	union cci_event *event;	/* generic CCI event */
	cci_connection_t *connection;	/* generic CCI connection */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */

	CCI_ENTER;

	TAILQ_HEAD(s_idle_txs, tcp_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);

	if (!sdev)
		return;

	now = tcp_get_usecs();

	pthread_mutex_lock(&dev->lock);
	TAILQ_FOREACH_SAFE(tx, &sdev->queued, dentry, tmp) {
		evt = &(tx->evt);
		event = &(evt->event);
		conn = evt->conn;
		connection = &conn->connection;
		sconn = conn->priv;
		is_reliable = cci_conn_is_reliable(conn);

		endpoint = connection->endpoint;
		ep = container_of(endpoint, cci__ep_t, endpoint);
		sep = ep->priv;

		/* try to send it */

		if (tx->last_attempt_us == 0ULL) {
			timeout =
			    conn->tx_timeout ? conn->
			    tx_timeout : ep->tx_timeout;
			tx->timeout_us = now + (uint64_t) timeout;
		}

		if (TCP_U64_LT(tx->timeout_us, now)) {

			/* set status and add to completed events */
			switch (tx->msg_type) {
			case TCP_MSG_SEND:
				if (tx->rnr != 0) {
					event->send.status = CCI_ERR_RNR;
				} else {
					event->send.status = CCI_ETIMEDOUT;
				}
				break;
			case TCP_MSG_CONN_REQUEST:
				/* FIXME only CONN_REQUEST gets an event
				 * the other two need to disconnect the conn */
				event->connect.status = CCI_ETIMEDOUT;
				event->connect.connection = NULL;
				break;
			case TCP_MSG_RMA_WRITE:
				pthread_mutex_lock(&ep->lock);
				tx->rma_op->pending--;
				tx->rma_op->status = CCI_ETIMEDOUT;
				pthread_mutex_unlock(&ep->lock);
				break;
			case TCP_MSG_CONN_REPLY:
			case TCP_MSG_CONN_ACK:
			default:
				/* TODO */
				debug(CCI_DB_WARN, "%s: timeout of %s msg",
				      __func__, tcp_msg_type(tx->msg_type));
				CCI_EXIT;
				return;
			}
			TAILQ_REMOVE(&sdev->queued, tx, dentry);

			/* if SILENT, put idle tx */
			if (tx->flags & CCI_FLAG_SILENT &&
			    (tx->msg_type == TCP_MSG_SEND ||
			     tx->msg_type == TCP_MSG_RMA_WRITE)) {

				tx->state = TCP_TX_IDLE;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
			} else {
				tx->state = TCP_TX_COMPLETED;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_TAIL(&evts, evt, entry);
			}
			continue;
		}

		if ((tx->last_attempt_us + (TCP_RESEND_TIME_SEC * 1000000)) >
		    now)
			continue;

#if 0
		if (sconn->pending > sconn->cwnd &&
		    tx->msg_type == TCP_MSG_SEND && 0) {
			continue;
		}
#endif

		tx->last_attempt_us = now;
		tx->send_count = 1;

		if (is_reliable &&
		    !(tx->msg_type == TCP_MSG_CONN_REQUEST ||
		      tx->msg_type == TCP_MSG_CONN_REPLY)) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&sconn->tx_seqs, tx, tx_seq);
			pthread_mutex_unlock(&ep->lock);
		}

		/* if reliable and ordered, we have to check whether the tx is marked
		   RNR */
		if (is_reliable
		    && conn->connection.attribute == CCI_CONN_ATTR_RO
		    && tx->rnr != 0) {
			event->send.status = CCI_ERR_RNR;
		}

		/* need to send it */

		debug(CCI_DB_MSG, "sending %s msg seq %u",
		      tcp_msg_type(tx->msg_type), tx->seq);
		ret = tcp_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
		if (ret == -1) {
			switch (errno) {
			default:
				debug((CCI_DB_MSG | CCI_DB_INFO),
				      "sendto() failed with %s",
				      strerror(errno));
				/* fall through */
			case EINTR:
			case EAGAIN:
			case ENOMEM:
			case ENOBUFS:
				if (is_reliable &&
				    !(tx->msg_type == TCP_MSG_CONN_REQUEST ||
				      tx->msg_type == TCP_MSG_CONN_REPLY)) {
					TAILQ_REMOVE(&sconn->tx_seqs, tx,
						     tx_seq);
				}
				continue;
			}
		}
		/* msg sent, dequeue */
		TAILQ_REMOVE(&sdev->queued, tx, dentry);
		if (tx->msg_type == TCP_MSG_SEND)
			sconn->pending++;

		/* if reliable or connection, add to pending
		 * else add to idle txs */

		if (is_reliable ||
		    tx->msg_type == TCP_MSG_CONN_REQUEST ||
		    tx->msg_type == TCP_MSG_CONN_REPLY) {

			tx->state = TCP_TX_PENDING;
			TAILQ_INSERT_TAIL(&sdev->pending, tx, dentry);
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "moving queued %s tx to pending",
			      tcp_msg_type(tx->msg_type));
		} else {
			tx->state = TCP_TX_COMPLETED;
			TAILQ_INSERT_TAIL(&idle_txs, tx, dentry);
		}
	}
	pthread_mutex_unlock(&dev->lock);

	/* transfer txs to sock ep's list */
	while (!TAILQ_EMPTY(&idle_txs)) {
		tx = TAILQ_FIRST(&idle_txs);
		TAILQ_REMOVE(&idle_txs, tx, dentry);
		ep = tx->evt.ep;
		sep = ep->priv;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
	}

	/* transfer evts to the ep's list */
	while (!TAILQ_EMPTY(&evts)) {
		evt = TAILQ_FIRST(&evts);
		TAILQ_REMOVE(&evts, evt, entry);
		ep = evt->ep;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	CCI_EXIT;

	return;
}

static void tcp_progress_sends(cci__dev_t * dev)
{
	tcp_progress_pending(dev);
	tcp_progress_queued(dev);

	return;
}

static int tcp_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	if (msg_ptr && msg_len) {
		iovcnt = 1;
		iov.iov_base = (void *) msg_ptr;
		iov.iov_len = msg_len;
	}

	return tcp_sendv(connection, &iov, iovcnt, context, flags);
}

static int tcp_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags)
{
	int i, ret, is_reliable = 0, data_len = 0;
	char *func = iovcnt < 2 ? "send" : "sendv";
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep;
	cci__dev_t *dev;
	cci__conn_t *conn;
	tcp_ep_t *sep;
	tcp_conn_t *sconn;
	tcp_dev_t *sdev;
	tcp_tx_t *tx = NULL;
	tcp_header_t *hdr;
	void *ptr;
	cci__evt_t *evt;
	union cci_event *event;	/* generic CCI event */

	debug(CCI_DB_FUNC, "entering %s", func);

	if (!sglobals) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_ENODEV;
	}

	for (i = 0; i < iovcnt; i++)
		data_len += data[i].iov_len;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);
	sconn = conn->priv;
	dev = ep->dev;
	sdev = dev->priv;

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	pthread_mutex_lock(&ep->lock);
	if (!TAILQ_EMPTY(&sep->idle_txs)) {
		tx = TAILQ_FIRST(&sep->idle_txs);
		TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
	}
	pthread_mutex_unlock(&ep->lock);

	if (!tx) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_ENOBUFS;
	}

	/* tx bookkeeping */
	tx->msg_type = TCP_MSG_SEND;
	tx->flags = flags;

	/* zero even if unreliable */
	if (!is_reliable) {
		tx->last_attempt_us = 0ULL;
		tx->timeout_us = 0ULL;
		/* If the connection is not reliable, it cannot be a RMA operation */
		tx->rma_op = NULL;
	} else {
		tx->last_attempt_us = 0ULL;
		tx->timeout_us =
		    tcp_get_usecs() + TCP_EP_TX_TIMEOUT_SEC * 1000000;
	}

	/* setup generic CCI event */
	evt = &tx->evt;
	evt->ep = ep;
	evt->conn = conn;
	event = &evt->event;
	event->type = CCI_EVENT_SEND;
	event->send.connection = connection;
	event->send.context = (void *)context;
	event->send.status = CCI_SUCCESS;	/* for now */

	/* pack buffer */
	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_send(hdr, data_len, sconn->peer_id);
	tx->len = sizeof(*hdr);

	/* if reliable, add seq and ack */

	if (is_reliable) {
		tcp_header_r_t *hdr_r = tx->buffer;
		uint32_t ts = 0;

		pthread_mutex_lock(&ep->lock);
		tx->seq = ++(sconn->seq);
		pthread_mutex_unlock(&ep->lock);

		tcp_pack_seq_ts(&hdr_r->seq_ts, tx->seq, ts);
		tx->len = sizeof(*hdr_r);
	}
	ptr = tx->buffer + tx->len;

	/* copy user data to buffer
	 * NOTE: ignore CCI_FLAG_NO_COPY because we need to
	 send the entire packet in one shot. We could
	 use sendmsg() with an iovec. */

	for (i = 0; i < iovcnt; i++) {
		memcpy(ptr, data[i].iov_base, data[i].iov_len);
		ptr += data[i].iov_len;
		tx->len += data[i].iov_len;
	}

	/* if unreliable, try to send */
	if (!is_reliable) {
		ret = tcp_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
		if (ret == tx->len) {
			/* queue event on enpoint's completed queue */
			tx->state = TCP_TX_COMPLETED;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_MSG, "sent UU msg with %d bytes",
			      tx->len - (int)sizeof(tcp_header_t));

			tcp_progress_dev(dev);

			debug(CCI_DB_FUNC, "exiting %s", func);

			return CCI_SUCCESS;
		}

		/* if error, fall through */
	}

	/* insert at tail of sock device's queued list */

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&dev->lock);
	TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
	pthread_mutex_unlock(&dev->lock);

	/* try to progress txs */

	tcp_progress_dev(dev);

	/* if unreliable, we are done since it is buffered internally */
	if (!is_reliable) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_SUCCESS;
	}

	ret = CCI_SUCCESS;

	/* if blocking, wait for completion */

	if (tx->flags & CCI_FLAG_BLOCKING) {
		struct timeval tv = { 0, TCP_PROG_TIME_US / 2 };

		while (tx->state != TCP_TX_COMPLETED)
			select(0, NULL, NULL, NULL, &tv);

		/* get status and cleanup */
		ret = event->send.status;

		/* FIXME race with get_event()
		 *       get_event() must ignore sends with
		 *       flags & CCI_FLAG_BLOCKING */

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
	}

	debug(CCI_DB_FUNC, "exiting %s", func);
	return ret;
}

static int tcp_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle)
{
	/* FIXME use read/write flags? */
	cci__ep_t *ep = NULL;
	tcp_ep_t *sep = NULL;
	tcp_rma_handle_t *handle = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	handle->ep = ep;
	handle->length = length;
	handle->start = start;
	handle->refcnt = 1;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = (uint64_t) ((uintptr_t) handle);

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int tcp_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle)
{
	int ret = CCI_EINVAL;
	tcp_rma_handle_t *handle =
	    (tcp_rma_handle_t *) ((uintptr_t) rma_handle);
	cci__ep_t *ep = NULL;
	tcp_ep_t *sep = NULL;
	tcp_rma_handle_t *h = NULL;
	tcp_rma_handle_t *tmp = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = handle->ep;
	sep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(h, &sep->handles, entry, tmp) {
		if (h == handle) {
			handle->refcnt--;
			if (handle->refcnt == 1)
				TAILQ_REMOVE(&sep->handles, handle, entry);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h == handle) {
		if (handle->refcnt == 1) {
			memset(handle, 0, sizeof(*handle));
			free(handle);
		}
		ret = CCI_SUCCESS;
	}

	CCI_EXIT;
	return ret;
}

/*
 * This function is designed to track contexts specified for RMA read ops.
 * The problem is the following: when performing a RMA read operating, we have
 * to track the context used for operation so we can return an event to the
 * application with the appropriate completion context. Firthermore, since the
 * context is implemented with a pointer, the simpler solution is to assign a
 * unique ID for each context. To do this, we simply manage an array where we
 * store the context, the index being the unique ID. Upon completion (return
 * the event to the application), the ID is "freed".
 * Note that we handle the array by blocks so we do not reallocate memory all
 * the time.
 */
#define CONTEXTS_BLOCK_SIZE 10
static inline void
generate_context_id(tcp_conn_t * sconn, const void *context, uint64_t * context_id)
{
	uint64_t index = 0;

	if (sconn->rma_contexts == NULL) {
		/* We do not have the array allocated yet, so we perform the alloc */
		/* FIXME: we never free that memory */
		sconn->rma_contexts =
		    calloc(0, CONTEXTS_BLOCK_SIZE * sizeof(void *));
		sconn->max_rma_contexts = CONTEXTS_BLOCK_SIZE;
	}

	/* We look for an empty element in the array, the index will be used as
	   unique ID for that specific context */
	while (sconn->rma_contexts[index] != NULL) {
		index++;
		if (index == sconn->max_rma_contexts) {
			/* We reach the end of the array and the array is full, we extend
			   the array */
			sconn->rma_contexts = realloc(sconn->rma_contexts,
						      sconn->max_rma_contexts +
						      CONTEXTS_BLOCK_SIZE);
			for (index = sconn->max_rma_contexts;
			     index <
			     sconn->max_rma_contexts + CONTEXTS_BLOCK_SIZE;
			     index++) {
				sconn->rma_contexts[index] = NULL;
			}
			index = sconn->max_rma_contexts;
			sconn->max_rma_contexts += CONTEXTS_BLOCK_SIZE;
		}
	}

	sconn->rma_contexts[index] = context;
	*context_id = index;
}

static int tcp_rma(cci_connection_t * connection,
		    const void *msg_ptr, uint32_t msg_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *sep = NULL;
	tcp_dev_t *sdev = NULL;
	tcp_conn_t *sconn = NULL;
	tcp_rma_handle_t *local =
	    (tcp_rma_handle_t *) ((uintptr_t) local_handle);
	tcp_rma_handle_t *h = NULL;
	tcp_rma_op_t *rma_op = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	sconn = conn->priv;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	dev = ep->dev;
	sdev = dev->priv;

	if (!local) {
		debug(CCI_DB_INFO, "%s: invalid local RMA handle", __func__);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &sep->handles, entry) {
		if (h == local) {
			local->refcnt++;
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != local) {
		debug(CCI_DB_INFO, "%s: invalid endpoint for this RMA handle",
		      __func__);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	rma_op = calloc(1, sizeof(*rma_op));
	if (!rma_op) {
		pthread_mutex_lock(&ep->lock);
		local->refcnt--;
		pthread_mutex_unlock(&ep->lock);
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	rma_op->data_len = data_len;
	rma_op->local_handle = local_handle;
	rma_op->local_offset = local_offset;
	rma_op->remote_handle = remote_handle;
	rma_op->remote_offset = remote_offset;
	rma_op->id = ++(sconn->rma_id);
	rma_op->num_msgs = data_len / connection->max_send_size;
	if (data_len % connection->max_send_size)
		rma_op->num_msgs++;
	rma_op->completed = 0;
	rma_op->status = CCI_SUCCESS;	/* for now */
	rma_op->context = (void *)context;
	rma_op->flags = flags;
	rma_op->msg_len = (uint16_t) msg_len;
	rma_op->tx = NULL;

	if (msg_len)
		rma_op->msg_ptr = (void *) msg_ptr;
	else
		rma_op->msg_ptr = NULL;

	if (flags & CCI_FLAG_WRITE) {
		int i, cnt, err = 0;
		tcp_tx_t **txs = NULL;
		uint64_t old_seq = 0ULL;

		cnt = rma_op->num_msgs < TCP_RMA_DEPTH ?
		    rma_op->num_msgs : TCP_RMA_DEPTH;

		txs = calloc(cnt, sizeof(*txs));
		if (!txs) {
			pthread_mutex_lock(&ep->lock);
			local->refcnt--;
			pthread_mutex_unlock(&ep->lock);
			free(rma_op);
			CCI_EXIT;
			return CCI_ENOMEM;
		}

		pthread_mutex_lock(&ep->lock);
		old_seq = sconn->seq;
		for (i = 0; i < cnt; i++) {
			if (!TAILQ_EMPTY(&sep->idle_txs)) {
				txs[i] = TAILQ_FIRST(&sep->idle_txs);
				TAILQ_REMOVE(&sep->idle_txs, txs[i], dentry);
				txs[i]->seq = ++(sconn->seq);
			} else
				err++;
		}
		if (err) {
			for (i = 0; i < cnt; i++) {
				if (txs[i])
					TAILQ_INSERT_HEAD(&sep->idle_txs,
							  txs[i], dentry);
			}
			local->refcnt--;
			sconn->seq = old_seq;
		}
		pthread_mutex_unlock(&ep->lock);

		if (err) {
			free(txs);
			free(rma_op);
			CCI_EXIT;
			return CCI_ENOBUFS;
		}

		/* we have all the txs we need, pack them and queue them */
		for (i = 0; i < cnt; i++) {
			tcp_tx_t *tx = txs[i];
			uint64_t offset =
			    (uint64_t) i * (uint64_t) connection->max_send_size;
			tcp_rma_header_t *write =
			    (tcp_rma_header_t *) tx->buffer;

			rma_op->next = i + 1;
			tx->msg_type = TCP_MSG_RMA_WRITE;
			tx->flags = flags | CCI_FLAG_SILENT;
			tx->state = TCP_TX_QUEUED;
			/* payload size for now */
			tx->len = (uint16_t) connection->max_send_size;
			tx->send_count = 0;
			tx->last_attempt_us = 0ULL;
			tx->timeout_us = 0ULL;
			tx->rma_op = rma_op;

			tx->evt.event.type = CCI_EVENT_SEND;
			tx->evt.event.send.connection = connection;
			tx->evt.conn = conn;
			tx->evt.ep = ep;

			if (i == (rma_op->num_msgs - 1)) {
				if (data_len % connection->max_send_size)
					tx->len =
					    data_len %
					    connection->max_send_size;
			}

			tcp_pack_rma_write(write, tx->len, sconn->peer_id,
					    tx->seq, 0, local_handle,
					    local_offset + offset,
					    remote_handle,
					    remote_offset + offset);
			memcpy(write->data, local->start + offset, tx->len);
			/* now include the header */
			tx->len += sizeof(tcp_rma_header_t);
		}
		pthread_mutex_lock(&dev->lock);
		pthread_mutex_lock(&ep->lock);
		for (i = 0; i < cnt; i++)
			TAILQ_INSERT_TAIL(&sdev->queued, txs[i], dentry);
		TAILQ_INSERT_TAIL(&sconn->rmas, rma_op, rmas);
		TAILQ_INSERT_TAIL(&sep->rma_ops, rma_op, entry);
		pthread_mutex_unlock(&ep->lock);
		pthread_mutex_unlock(&dev->lock);

		/* it is no longer needed */
		free(txs);

		ret = CCI_SUCCESS;
	} else if (flags & CCI_FLAG_READ) {
		tcp_tx_t *tx = NULL;
		tcp_rma_header_t *read = NULL;
		//uint32_t seq;
		uint64_t context_id;
		//void *msg_ptr = NULL;

		/* RMA_READ is implemented using RMA_WRITE: we send a request to the
		   remote peer which will perform a RMA_WRITE */

		/* Get a TX */
		pthread_mutex_lock(&ep->lock);
		if (!TAILQ_EMPTY(&sep->idle_txs)) {
			tx = TAILQ_FIRST(&sep->idle_txs);
			TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
		}
		pthread_mutex_unlock(&ep->lock);

		/* Prepare and send the msg */
		read = tx->buffer;
		sep = ep->priv;
		memset(tx->buffer, 0, sizeof(tcp_rma_header_t));
		tx->seq = ++(sconn->seq);
		tx->timeout_us = 0ULL;
		tx->last_attempt_us = 0ULL;
		tcp_pack_rma_read(read, data_len, sconn->peer_id, tx->seq, 0,
				   local_handle, local_offset,
				   remote_handle, remote_offset);
		tx->len = sizeof(tcp_rma_header_t);
		generate_context_id(sconn, context, &context_id);
		memcpy(read->data, &data_len, sizeof(uint64_t));
		//msg_ptr = (void *)(read->data + sizeof(uint64_t));
		memcpy((void *)(((char *)read->data) + sizeof(uint64_t)),
		       &context_id, sizeof(uint64_t));
		tx->len += 2 * sizeof(uint64_t);
		tx->msg_type = TCP_MSG_SEND;
		tx->rma_op = NULL;

		/* Queuing the RMA_READ_REQUEST message */
		tx->state = TCP_TX_QUEUED;
		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.event.send.connection = connection;
		tx->evt.conn = conn;
		pthread_mutex_lock(&dev->lock);
		TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
		pthread_mutex_unlock(&dev->lock);
		ret = CCI_SUCCESS;
	}

	tcp_progress_dev(dev);

	CCI_EXIT;
	return ret;
}

/*!
  Handle incoming sequence number

  If we have acked it
    ignore it
  Walk sconn->acks:
    if it exists in a current entry
      do nothing
    if it borders a current entry
      add it to the entry
    if it falls between two entries without boardering them
      add a new entry between them
    else
      add a new entry at the tail

 */
static inline void tcp_handle_seq(tcp_conn_t * sconn, uint32_t seq)
{
	int done = 0;
	tcp_ack_t *ack = NULL;
	tcp_ack_t *last = NULL;
	tcp_ack_t *tmp = NULL;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);

	if (TCP_SEQ_LTE(seq, sconn->acked)) {
		debug(CCI_DB_MSG, "%s ignoring seq %u (acked %u) ***", __func__,
		      seq, sconn->acked);
		return;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(ack, &sconn->acks, entry, tmp) {
		if (TCP_SEQ_GTE(seq, ack->start) &&
		    TCP_SEQ_LTE(seq, ack->end)) {
			/* seq exists in this entry,
			   do nothing */
			debug(CCI_DB_MSG, "%s seq %u exists between %u-%u",
			      __func__, seq, ack->start, ack->end);
			done = 1;
			break;
		} else if (seq == ack->start - 1) {
			/* add it to start of this entry */
			ack->start = seq;
			debug(CCI_DB_MSG, "%s seq %u exists before %u-%u",
			      __func__, seq, ack->start, ack->end);
			done = 1;
			break;
		} else if (seq == ack->end + 1) {
			tcp_ack_t *next = TAILQ_NEXT(ack, entry);

			/* add it to the end of this entry */
			debug(CCI_DB_MSG, "%s seq %u exists after %u-%u",
			      __func__, seq, ack->start, ack->end);
			ack->end = seq;

			/* did we plug a hole between entries? */
			if (next) {
				/* add this range to next and delete this entry */
				debug(CCI_DB_MSG,
				      "%s merging acks %u-%u with %u-%u",
				      __func__, ack->start, ack->end,
				      next->start, next->end);
				next->start = ack->start;
				TAILQ_REMOVE(&sconn->acks, ack, entry);
				free(ack);
			}
			done = 1;
			break;
		} else if (last && TCP_SEQ_GT(seq, last->end) &&
			   TCP_SEQ_LT(seq, ack->start)) {
			tcp_ack_t *new;

			/* add a new entry before this entry */
			new = calloc(1, sizeof(*new));
			if (new) {
				debug(CCI_DB_MSG,
				      "%s seq %u insert after %u-%u before %u-%u ",
				      __func__, seq, last->start, last->end,
				      ack->start, ack->end);
				new->start = new->end = seq;
				TAILQ_INSERT_BEFORE(ack, new, entry);
			}
			done = 1;
			break;
		}
		last = ack;
	}
	if (!done) {
		/* add new entry to tail */
		ack = calloc(1, sizeof(*ack));
		if (ack) {
			ack->start = ack->end = seq;
			TAILQ_INSERT_TAIL(&sconn->acks, ack, entry);
			debug(CCI_DB_MSG, "%s seq %u add at tail", __func__,
			      seq);
		}
	}
	pthread_mutex_unlock(&ep->lock);

	return;
}

static void
tcp_handle_active_message(tcp_conn_t * sconn,
			   tcp_rx_t * rx, uint16_t len, uint32_t id)
{
	cci__evt_t *evt;
	cci__conn_t *conn = sconn->conn;
	tcp_header_t *hdr;	/* wire header */
	union cci_event *event;	/* generic CCI event */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	cci__ep_t *ep;

	CCI_ENTER;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);

	/* get cci__evt_t to hang on ep->events */

	evt = &rx->evt;

	/* set wire header so we can find user header */

	hdr = (tcp_header_t *) rx->buffer;

	/* setup the generic event for the application */

	event = & evt->event;
	event->type = CCI_EVENT_RECV;
	event->recv.len = len;
	event->recv.ptr = (void *)&hdr->data;
	event->recv.connection = &conn->connection;

	/* if a reliable connection, handle the ack */

	if (cci_conn_is_reliable(conn)) {
		tcp_header_r_t *hdr_r = (tcp_header_r_t *) rx->buffer;
		event->recv.ptr = (void *)&hdr_r->data;

	}

	/* queue event on endpoint's completed event queue */

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* TODO notify via ep->fd */

	CCI_EXIT;

	return;
}

/*!
  Handle incoming RNR messages
 */
static void tcp_handle_rnr(tcp_conn_t * sconn, uint32_t seq, uint32_t ts)
{
	tcp_tx_t *tx = NULL;
	tcp_tx_t *tmp = NULL;

	/* Find the corresponding SEQ/TS */
	TAILQ_FOREACH_SAFE(tx, &sconn->tx_seqs, tx_seq, tmp) {
		if (tx->seq == seq) {
			debug(CCI_DB_MSG,
			      "[%s,%d] Receiver not ready (seq: %u)", __func__,
			      __LINE__, seq);
			tx->rnr = 1;
		}
	}

	/* We also mark the conn as RNR */
	if (sconn->rnr == 0)
		sconn->rnr = seq;
}

/*!
  Handle incoming ack

  Check the device pending list for the matching tx
    if found, remove it and hang it on the completion list
    if not found, ignore (it is a duplicate)
 */
static void
tcp_handle_ack(tcp_conn_t * sconn,
		tcp_msg_type_t type, tcp_rx_t * rx, int count, uint32_t id)
{
	int i = 0;
	int found = 0;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__dev_t *dev = ep->dev;
	tcp_ep_t *sep = ep->priv;
	tcp_dev_t *sdev = dev->priv;
	tcp_tx_t *tx = NULL;
	tcp_tx_t *tmp = NULL;
	tcp_header_r_t *hdr_r = rx->buffer;
	uint32_t acks[TCP_MAX_SACK * 2];

	TAILQ_HEAD(s_idle_txs, tcp_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);
	TAILQ_HEAD(s_queued, tcp_tx) queued = TAILQ_HEAD_INITIALIZER(queued);
	TAILQ_INIT(&queued);

	assert(id == sconn->id);
	assert(count > 0);

	if (count == 1) {
		assert(type == TCP_MSG_ACK_ONLY || type == TCP_MSG_ACK_UP_TO);
	} else {
		assert(type == TCP_MSG_SACK);
	}
	tcp_parse_ack(hdr_r, type, acks, count);

	if (type == TCP_MSG_ACK_ONLY) {
		if (sconn->seq_pending == acks[0] - 1)
			sconn->seq_pending = acks[0];
	} else if (type == TCP_MSG_ACK_UP_TO) {
		sconn->seq_pending = acks[0];
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(tx, &sconn->tx_seqs, tx_seq, tmp) {
		if (type == TCP_MSG_ACK_ONLY) {
			if (tx->seq == acks[0]) {
				if (tx->state == TCP_TX_PENDING) {
					debug(CCI_DB_MSG,
					      "%s acking only seq %u", __func__,
					      acks[0]);
					TAILQ_REMOVE(&sdev->pending, tx,
						     dentry);
					TAILQ_REMOVE(&sconn->tx_seqs, tx,
						     tx_seq);
					if (tx->msg_type == TCP_MSG_SEND) {
						sconn->pending--;
#if 0
						if (sconn->pending <=
						    sconn->ssthresh) {
							sconn->cwnd++;
							debug(CCI_DB_INFO,
							      "%s increase cwnd from %d to %d",
							      __func__,
							      sconn->cwnd - 1,
							      sconn->cwnd);
						} else {
							sconn->cwnd++;
						}
#endif
					}
					/* if SILENT, put idle tx */
					if (tx->flags & CCI_FLAG_SILENT) {
						tx->state = TCP_TX_IDLE;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_HEAD(&idle_txs, tx,
								  dentry);
					} else {
						tx->state = TCP_TX_COMPLETED;
						/* In the context of an ordered reliable connection,
						   if the receiver was always ready to receive, the 
						   complete the send with a success status. Otherwise,
						   we complete the send with a RNR status */
						if (conn->
						    connection.attribute ==
						    CCI_CONN_ATTR_RO
						    && tx->rnr != 0) {
							tx->evt.event.
							    send.status =
							    CCI_ERR_RNR;
						} else {
							tx->evt.event.
							    send.status =
							    CCI_SUCCESS;
						}
						/* store locally until we can drop the locks */
						TAILQ_INSERT_TAIL(&evts,
								  &tx->evt,
								  entry);
					}
				}
				found = 1;
				break;
			}
		} else if (type == TCP_MSG_ACK_UP_TO) {
			if (TCP_SEQ_LTE(tx->seq, acks[0])) {
				if (tx->state == TCP_TX_PENDING) {
					debug(CCI_DB_MSG,
					      "%s acking tx seq %u (up to seq %u)",
					      __func__, tx->seq, acks[0]);
					TAILQ_REMOVE(&sdev->pending, tx,
						     dentry);
					TAILQ_REMOVE(&sconn->tx_seqs, tx,
						     tx_seq);
					if (tx->msg_type == TCP_MSG_SEND) {
						sconn->pending--;
#if 0
						if (sconn->pending <=
						    sconn->ssthresh) {
							sconn->cwnd++;
							debug(CCI_DB_INFO,
							      "%s increase cwnd from %d to %d",
							      __func__,
							      sconn->cwnd - 1,
							      sconn->cwnd);
						} else {
							sconn->cwnd++;
						}
#endif
					}
					/* if SILENT, put idle tx */
					if (tx->flags & CCI_FLAG_SILENT) {
						tx->state = TCP_TX_IDLE;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_HEAD(&idle_txs, tx,
								  dentry);
					} else {
						tx->state = TCP_TX_COMPLETED;
						/* In the context of an ordered reliable connection,
						   if the receiver was always ready to receive, the 
						   complete the send with a success status. Otherwise,
						   we complete the send with a RNR status */
						if (conn->
						    connection.attribute ==
						    CCI_CONN_ATTR_RO
						    && tx->rnr != 0) {
							tx->evt.event.
							    send.status =
							    CCI_ERR_RNR;
						} else {
							tx->evt.event.
							    send.status =
							    CCI_SUCCESS;
						}
						/* store locally until we can drop the locks */
						TAILQ_INSERT_TAIL(&evts,
								  &tx->evt,
								  entry);
					}
					found++;
				}
			} else {
				break;
			}
		} else {	/* SACK */
			for (i = 0; i < count; i += 2) {
				if (TCP_SEQ_GTE(tx->seq, acks[i]) &&
				    TCP_SEQ_LTE(tx->seq, acks[i + 1])) {
					if (sconn->seq_pending == acks[i] - 1)
						sconn->seq_pending =
						    acks[i + 1];
					if (tx->state == TCP_TX_PENDING) {
						debug(CCI_DB_MSG,
						      "%s sacking seq %u",
						      __func__, acks[0]);
						found++;
						TAILQ_REMOVE(&sdev->pending, tx,
							     dentry);
						TAILQ_REMOVE(&sconn->tx_seqs,
							     tx, tx_seq);
						if (tx->msg_type ==
						    TCP_MSG_SEND) {
							sconn->pending--;
#if 0
							if (sconn->pending <=
							    sconn->ssthresh) {
								sconn->cwnd++;
								debug
								    (CCI_DB_INFO,
								     "%s increase cwnd from %d to %d",
								     __func__,
								     sconn->cwnd
								     - 1,
								     sconn->
								     cwnd);
							} else {
								sconn->cwnd++;
							}
#endif
						}
						/* if SILENT, put idle tx */
						if (tx->flags & CCI_FLAG_SILENT) {
							tx->state =
							    TCP_TX_IDLE;
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_HEAD
							    (&idle_txs, tx,
							     dentry);
						} else {
							tx->state =
							    TCP_TX_COMPLETED;
							/* In the context of an ordered reliable connection
							   if the receiver was always ready to receive, the
							   complete the send with a success status.
							   Otherwise, we complete the send with a RNR status
							 */
							if (conn->
							    connection.attribute
							    == CCI_CONN_ATTR_RO
							    && tx->rnr != 0) {
								tx->evt.
								    event.send.
								    status =
								    CCI_ERR_RNR;
							} else {
								tx->evt.
								    event.send.
								    status =
								    CCI_SUCCESS;
							}
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_TAIL(&evts,
									  &tx->
									  evt,
									  entry);
						}
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	debug(CCI_DB_MSG, "%s acked %d msgs (%s %u)", __func__, found,
	      tcp_msg_type(type), acks[0]);

	pthread_mutex_lock(&ep->lock);
	/* transfer txs to sock ep's list */
	while (!TAILQ_EMPTY(&idle_txs)) {
		tcp_rma_op_t *rma_op = NULL;

		tx = TAILQ_FIRST(&idle_txs);
		TAILQ_REMOVE(&idle_txs, tx, dentry);

		rma_op = tx->rma_op;
		if (rma_op && rma_op->status == CCI_SUCCESS) {
			tcp_rma_handle_t *local =
			    (tcp_rma_handle_t *) ((uintptr_t) rma_op->
						   local_handle);
			rma_op->completed++;

			/* progress RMA */
			if (tx == rma_op->tx) {
				int flags = rma_op->flags;
				void *context = rma_op->context;

				/* they acked our remote completion */
				TAILQ_REMOVE(&sep->rma_ops, rma_op, entry);
				TAILQ_REMOVE(&sconn->rmas, rma_op, rmas);
				local->refcnt--;

				free(rma_op);
				if (!(flags & CCI_FLAG_SILENT)) {
					tx->evt.event.send.status = CCI_SUCCESS;
					tx->evt.event.send.context = context;
					TAILQ_INSERT_HEAD(&evts, &tx->evt,
							  entry);
					continue;
				}
			}
			/* they acked a data segment,
			 * do we need to send more or send the remote completion? */
			if (rma_op->next < rma_op->num_msgs) {
				tcp_rma_header_t *write =
				    (tcp_rma_header_t *) tx->buffer;
				uint64_t offset = 0ULL;

				/* send more data */
				i = rma_op->next++;
				tx->flags = rma_op->flags | CCI_FLAG_SILENT;
				tx->state = TCP_TX_QUEUED;
				/* payload size for now */
				tx->len = (uint16_t) connection->max_send_size;
				tx->send_count = 0;
				tx->last_attempt_us = 0ULL;
				tx->timeout_us = 0ULL;
				tx->rma_op = rma_op;

				tx->evt.event.type = CCI_EVENT_SEND;
				tx->evt.event.send.connection = connection;
				tx->evt.conn = conn;
				if (i == (rma_op->num_msgs - 1)) {
					if (rma_op->data_len %
					    connection->max_send_size)
						tx->len =
						    rma_op->data_len %
						    connection->max_send_size;
				}
				tx->seq = ++(sconn->seq);

				offset = (uint64_t) i *(uint64_t)
				 connection->max_send_size;

				tcp_pack_rma_write(write, tx->len,
						    sconn->peer_id, tx->seq, 0,
						    rma_op->local_handle,
						    rma_op->local_offset +
						    offset,
						    rma_op->remote_handle,
						    rma_op->remote_offset +
						    offset);
				memcpy(write->data, local->start + offset,
				       tx->len);
				/* now include the header */
				tx->len += sizeof(tcp_rma_header_t);
				TAILQ_INSERT_TAIL(&queued, tx, dentry);
				continue;
			} else if (rma_op->completed == rma_op->num_msgs) {

				/* send remote completion? */
				if (rma_op->msg_len) {
					tcp_header_r_t *hdr_r = tx->buffer;
					tcp_rma_header_t *write = NULL;
					uint64_t context_id;
					void *msg_ptr = NULL;

					rma_op->tx = tx;
					tx->msg_type = TCP_MSG_SEND;
					tx->flags =
					    rma_op->flags | CCI_FLAG_SILENT;
					tx->state = TCP_TX_QUEUED;
					/* payload size for now */
					tx->len = (uint16_t) rma_op->msg_len;
					tx->send_count = 0;
					tx->last_attempt_us = 0ULL;
					tx->timeout_us = 0ULL;
					tx->rma_op = rma_op;
					tx->seq = ++(sconn->seq);

					tx->evt.event.type = CCI_EVENT_SEND;
					tx->evt.event.send.connection =
					    connection;
					tx->evt.event.send.context =
					    rma_op->context;
					tx->evt.conn = conn;
					tx->evt.ep = ep;
					memset(tx->buffer, 0,
					       sizeof(tcp_rma_header_t));
					write =
					    (tcp_rma_header_t *) tx->buffer;
					context_id = (uint64_t) rma_op->context;
					tcp_pack_rma_write_done(write,
								 sconn->peer_id,
								 tx->seq, 0);
					/* Include the context id */
					memcpy(&hdr_r->data, &context_id,
					       sizeof(uint64_t));
					msg_ptr =
					    (void *)(hdr_r->data +
						     sizeof(uint64_t));
					memcpy(msg_ptr, rma_op->msg_ptr,
					       tx->len);
					tx->len +=
					    sizeof(tcp_rma_header_t) +
					    sizeof(uint64_t);
					TAILQ_INSERT_TAIL(&queued, tx, dentry);
					continue;
				} else {
					int flags = rma_op->flags;
					void *context = rma_op->context;

					/* complete now */
					TAILQ_REMOVE(&sep->rma_ops, rma_op,
						     entry);
					TAILQ_REMOVE(&sconn->rmas, rma_op,
						     rmas);
					local->refcnt--;
					free(rma_op);

					if (!(flags & CCI_FLAG_SILENT)) {
						tx->evt.event.send.status =
						    CCI_SUCCESS;
						tx->evt.event.send.context =
						    context;
						TAILQ_INSERT_HEAD(&evts,
								  &tx->evt,
								  entry);
						continue;
					}
				}
			}
		}

		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
	}

	/* transfer evts to the ep's list */
	while (!TAILQ_EMPTY(&evts)) {
		cci__evt_t *evt;
		evt = TAILQ_FIRST(&evts);
		TAILQ_REMOVE(&evts, evt, entry);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	}
	pthread_mutex_unlock(&ep->lock);

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);
	while (!TAILQ_EMPTY(&queued)) {
		tcp_tx_t *my_tx;
		my_tx = TAILQ_FIRST(&queued);
		TAILQ_REMOVE(&queued, my_tx, dentry);
		TAILQ_INSERT_TAIL(&sdev->queued, my_tx, dentry);
	}
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	CCI_EXIT;
	return;
}

static void
tcp_handle_conn_request(tcp_rx_t * rx,
			 cci_conn_attribute_t attr,
			 uint16_t len, struct sockaddr_in sin, cci__ep_t * ep)
{
	char name[32];

	CCI_ENTER;

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(sin, name, sizeof(name));
	debug(CCI_DB_CONN, "recv'd conn_req from %s", name);

	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.event.request.attribute = attr;
	*((uint32_t *) & rx->evt.event.request.data_len) = len;
	if (len)
		*((void **)&rx->evt.event.request.data_ptr) =
		    (void *)((((tcp_header_r_t *) rx->buffer)->data) +
			     (uintptr_t) sizeof(tcp_handshake_t));
	else
		*((void **)&rx->evt.event.request.data_ptr) = NULL;

	/* queue event on endpoint's completed event queue */

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* TODO notify via ep->fd */

	CCI_EXIT;
	return;
}

/* Possible states and what to do:
 *
 * Recv         send        send        with        complete    switch
 * Success      conn_ack    reliably    seq_ts      event       lists
 * -------------------------------------------------------------------
 * No conn      Error
 * Active conn  Yes         Yes         Yes         Yes         Yes
 * Ready conn   Yes         Yes         Yes         No          No
 * ===================================================================
 * Recv         send        send        with        complete    free
 * Rejected     conn_ack    reliably    seq_ts      event       conn
 * -------------------------------------------------------------------
 * No conn      Yes         No          No          No          No
 * Active conn  Yes         No          No          Yes         Yes
 * Ready conn   Error
 */
static void tcp_handle_conn_reply(tcp_conn_t * sconn,	/* NULL if rejected */
				   tcp_rx_t * rx, uint8_t reply,	/* CCI_SUCCESS or CCI_ECONNREFUSED */
				   uint16_t unused,
				   uint32_t id,
				   struct sockaddr_in sin, cci__ep_t * ep)
{
	int i, ret;
	cci__evt_t *evt = NULL;
	cci__dev_t *dev = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *sep = NULL;
	tcp_dev_t *sdev = NULL;
	tcp_tx_t *tx = NULL, *tmp = NULL, *t = NULL;
	tcp_header_r_t *hdr_r;	/* wire header */
	union cci_event *event;	/* generic CCI event */
	uint32_t seq;		/* peer's seq */
	uint32_t ts;		/* FIXME our original seq */
	tcp_handshake_t *hs = NULL;

	CCI_ENTER;

	sep = ep->priv;

	if (!sconn) {
		/* either this is a dup and the conn is now ready or
		 * the conn is closed and we simply ack the msg
		 */
		/* look for a conn that is ready */
		sconn =
		    tcp_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
				   TCP_MSG_SEND);
		if (!sconn) {
			tcp_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char from[32];

			memset(from, 0, sizeof(from));
			tcp_sin_to_name(sin, from, sizeof(from));
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "ep %d recv'd conn_reply (%s) from %s"
			      " with no matching conn", sep->sock,
			      reply ==
			      CCI_SUCCESS ? "success" : "rejected", from);
			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			tcp_pack_conn_ack(&hdr.header, sconn->peer_id);
			ret = tcp_sendto(sep->sock, &hdr, len, sin);
			if (ret != len) {
				debug((CCI_DB_CONN | CCI_DB_MSG),
				      "ep %d failed to send conn_ack with %s",
				      sep->sock,
				      cci_strerror(&ep->endpoint, (enum cci_status)ret));
			}
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
			pthread_mutex_unlock(&ep->lock);
			CCI_EXIT;
			return;
		}
		/* else we have a connection and we can ack normally */
	}

	conn = sconn->conn;
	dev = ep->dev;
	sdev = dev->priv;

	/* set wire header so we can find user header */

	hdr_r = (tcp_header_r_t *) rx->buffer;

	/* TODO handle ack */

	tcp_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);	//FIXME do something with ts

	if (sconn->status == TCP_CONN_ACTIVE) {
		uint32_t peer_id, ack, max_recv_buffer_count, mss, keepalive;
		struct s_active *active_list;

		debug(CCI_DB_CONN, "transition active connection to ready");

		hs = (tcp_handshake_t *) (rx->buffer + sizeof(*hdr_r));
		/* With conn_reply, we do not care about the keepalive param */
		tcp_parse_handshake(hs, &peer_id, &ack, &max_recv_buffer_count,
				     &mss, &keepalive);

		/* get pending conn_req tx, create event, move conn to conn_hash */
		pthread_mutex_lock(&dev->lock);
		TAILQ_FOREACH_SAFE(t, &sdev->pending, dentry, tmp) {
			if (t->seq == ack) {
				TAILQ_REMOVE(&sdev->pending, t, dentry);
				tx = t;
				break;
			}
		}
		pthread_mutex_unlock(&dev->lock);

		if (!tx) {
			char from[32];

			memset(from, 0, sizeof(from));
			tcp_sin_to_name(sin, from, sizeof(from));

			/* how can we be active without a tx pending? */
			debug(CCI_DB_WARN,
			      "ep %d received conn_reply (%s) from %s "
			      "with an active conn and no matching tx",
			      sep->sock,
			      reply ==
			      CCI_SUCCESS ? "success" : "rejected", from);
			/* we can't transition to ready since we do not have the
			 * context from the conn_request tx */
			assert(0);
		}

		/* check mss and rx count */
		if (mss < conn->connection.max_send_size)
			conn->connection.max_send_size = mss;

		if (cci_conn_is_reliable(conn)) {
			sconn->max_tx_cnt =
			    max_recv_buffer_count <
			    ep->
			    tx_buf_cnt ? max_recv_buffer_count : ep->tx_buf_cnt;
			sconn->ssthresh = sconn->max_tx_cnt;
		}

		/* get cci__evt_t to hang on ep->events */

		evt = &rx->evt;

		/* setup the generic event for the application */

		event = & evt->event;
		event->type = CCI_EVENT_CONNECT;
		event->connect.status = reply;
		event->connect.connection =
		    reply == CCI_SUCCESS ? &conn->connection : NULL;
		event->connect.context = conn->connection.context;

		i = tcp_ip_hash(sin.sin_addr.s_addr, 0);
		active_list = &sep->active_hash[i];
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(active_list, sconn, entry);
		pthread_mutex_unlock(&ep->lock);

		if (CCI_SUCCESS == reply) {
			sconn->peer_id = peer_id;
			sconn->status = TCP_CONN_READY;
			*((struct sockaddr_in *)&sconn->sin) = sin;
			sconn->acked = seq;

			i = tcp_ip_hash(sin.sin_addr.s_addr, sin.sin_port);
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
			pthread_mutex_unlock(&ep->lock);

			debug(CCI_DB_CONN, "conn ready on hash %d", i);

		} else {
			tcp_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char name[32];

			free(sconn);
			if (conn->uri)
				free((char *)conn->uri);
			free(conn);

			/* send unreliable conn_ack */
			memset(name, 0, sizeof(name));
			tcp_sin_to_name(sin, name, sizeof(name));
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "ep %d recv'd conn_reply (rejected) from %s"
			      " - closing conn", sep->sock, name);

			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			tcp_pack_conn_ack(&hdr.header, sconn->peer_id);
			ret = tcp_sendto(sep->sock, &hdr, len, sin);
			if (ret != len) {
				debug((CCI_DB_CONN | CCI_DB_MSG),
				      "ep %d failed to send conn_ack with %s",
				      sep->sock,
				      cci_strerror(&ep->endpoint, (enum cci_status)ret));
			}
		}
		/* add rx->evt to ep->evts */
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
		pthread_mutex_unlock(&ep->lock);

		if (reply != CCI_SUCCESS) {
			CCI_EXIT;
			return;
		}
	} else if (sconn->status == TCP_CONN_READY) {
		pthread_mutex_lock(&ep->lock);
		if (!TAILQ_EMPTY(&sep->idle_txs)) {
			tx = TAILQ_FIRST(&sep->idle_txs);
			TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
		}
		pthread_mutex_unlock(&ep->lock);

		if (!tx) {
			char to[32];

			memset(to, 0, sizeof(to));
			tcp_sin_to_name(sin, to, sizeof(to));

			/* we can't ack, cleanup */
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "ep %d does not have any tx "
			      "buffs to send a conn_ack to %s", sep->sock, to);
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
			pthread_mutex_unlock(&ep->lock);

			CCI_EXIT;
			return;
		}
	}

	/* we have a tx for the conn_ack */

	tx->seq = ++(sconn->seq);

	tx->flags = CCI_FLAG_SILENT;
	tx->msg_type = TCP_MSG_CONN_ACK;
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.connect.connection = &conn->connection;
	tx->evt.ep = ep;
	tx->evt.conn = conn;

	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;

	hdr_r = tx->buffer;
	tcp_pack_conn_ack(&hdr_r->header, sconn->peer_id);
	sconn->last_ack_ts = tcp_get_usecs();
	/* the conn_ack acks the server's seq in the timestamp */
	tcp_pack_seq_ts(&hdr_r->seq_ts, tx->seq, seq);

	debug(CCI_DB_CONN, "%s:%d queuing conn_ack with seq %u", __func__,
	      __LINE__, tx->seq);

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&dev->lock);
	TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
	pthread_mutex_unlock(&dev->lock);

#if DEBUG_RNR
	conn_established = true;
#endif

	/* try to progress txs */

	tcp_progress_dev(dev);

	CCI_EXIT;

	return;
}

/*
 * GV [2012/01/16] Not sure that an event needs to be returned on the server
 * side so part of the following comments may be wrong. The event related code
 * is deactivated until this is clarified.
 * First of all, remember that on the server side, we always receive a conn_ack
 * for both an accepted and a rejected connection (in the context of a reliable
 * connection). Therefore, the conn_ack follows a conn_reply that was either
 * a CCI_EVENT_CONNECT_ACCEPTED or a CCI_EVENT_CONNECT_REJECTED. When receiving
 * the conn_reply, we quere the conn_ack, we check the "context" (accept or
 * reject) and generate an event to the server application.
 * Therefore, when receiving a CONN_ACK, we have to:
 * - find the corresponding CONN_REPLY TX and "release" it (the TX is also used
 *   to know the context of the conn_reply (i.e., accept or reject),
 * - if the connection is accepted, return an event to the server app with the 
 *   ID of the remote peer,
 * - if the connection is rejected, return an event to the app specifying that
 *   no ID has assigned to the remote peer.
 */
static void
tcp_handle_conn_ack(tcp_conn_t * sconn,
		     tcp_rx_t * rx,
		     uint8_t unused1,
		     uint16_t unused2, uint32_t peer_id, struct sockaddr_in sin)
{
	cci__ep_t *ep;
	cci__dev_t *dev;
	cci__conn_t *conn = sconn->conn;
	tcp_ep_t *sep;
	tcp_dev_t *sdev;
	tcp_tx_t *tx = NULL, *tmp = NULL, *t = NULL;
	tcp_header_r_t *hdr_r;	/* wire header */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	uint32_t seq;
	uint32_t ts;

	CCI_ENTER;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	dev = ep->dev;
	sdev = dev->priv;

	/* we check whether the connection ack match the id associated to the
	   connection */
	assert(peer_id == sconn->id);

	hdr_r = rx->buffer;
	tcp_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

	debug(CCI_DB_CONN, "%s: seq %u ack %u", __func__, seq, ts);

	pthread_mutex_lock(&dev->lock);
	TAILQ_FOREACH_SAFE(t, &sdev->pending, dentry, tmp) {
		/* the conn_ack stores the ack for the conn_reply in ts */
		if (t->seq == ts) {
			TAILQ_REMOVE(&sdev->pending, t, dentry);
			tx = t;
			debug(CCI_DB_CONN, "%s: found conn_reply", __func__);
			break;
		}
	}
	pthread_mutex_unlock(&dev->lock);

	if (!tx) {
		/* FIXME do what here? */
		/* if no tx, then it timed out or this is a duplicate,
		 * but we have a sconn */
		debug((CCI_DB_MSG | CCI_DB_CONN), "received conn_ack and no matching tx " "(seq %u ack %u)", seq, ts);	//FIXME
	} else {
		pthread_mutex_lock(&ep->lock);
		if (tx->evt.event.accept.connection) {
			TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
		} else {
			TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		}
		pthread_mutex_unlock(&ep->lock);
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;

	return;
}

/*
 * Function called to handle RMA_READ_REQUEST messages. This will do the
 * following:
 * 1/ Initiate the corresponding rma_write (rma_reads are implemented via
 *    rma_write).
 * 2/ Send a RMA_WRITE_DONE message to notify the remote peer that the rma_write
 *    succeeded. This message is used on the remote node to trigger completion
 *    at the application level.
 */
static void
tcp_handle_rma_read_request(tcp_conn_t * sconn, tcp_rx_t * rx,
			     uint16_t data_len)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	tcp_rma_header_t *read = rx->buffer;
	cci_connection_t *connection = NULL;
	//tcp_rma_header_t *write = NULL;
	//tcp_tx_t *tx = NULL;
	tcp_ep_t *sep = NULL;
	void *context = NULL;
	//uint32_t msg_len = 1;
	//void *msg_ptr = (void *)"RMAREAD";
	int flags = 0;
	//tcp_rma_handle_t *remote;
	uint64_t msg_local_handle;
	uint64_t msg_local_offset;
	uint64_t msg_remote_handle;
	uint64_t msg_remote_offset;
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;
	uint64_t remote_offset;
	uint32_t seq, ts;
	int rc;
	//cci__dev_t *dev = NULL;
	//tcp_dev_t *sdev = NULL;
	uint64_t context_id;
	uint64_t toto;
	//cci__evt_t *evt;
	//tcp_header_t *hdr;   /* wire header */
	//cci_event_t *event;   /* generic CCI event */
	//cci_endpoint_t *endpoint;     /* generic CCI endpoint */
	tcp_header_r_t *hdr_r;

	connection = &conn->connection;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	//dev = ep->dev;
	//sdev = dev->priv;

	hdr_r = (tcp_header_r_t *) rx->buffer;

	/* Parse the RMA read request message */
	tcp_parse_rma_handle_offset(&read->local,
				     &msg_local_handle, &msg_local_offset);
	tcp_parse_rma_handle_offset(&read->remote,
				     &msg_remote_handle, &msg_remote_offset);

	tcp_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
	tcp_handle_seq(sconn, seq);
	//remote = (tcp_rma_handle_t *) (uintptr_t) remote_handle;
	memcpy(&toto, read->data, sizeof(uint64_t));
	memcpy(&context_id, (void *)((char *)read->data + sizeof(uint64_t)),
	       sizeof(uint64_t));

	local_handle = msg_remote_handle;
	local_offset = msg_remote_offset;
	remote_handle = msg_local_handle;
	remote_offset = msg_local_offset;

	flags |= CCI_FLAG_WRITE;
	flags |= CCI_FLAG_SILENT;

	rc = tcp_rma(connection,
		      &context_id, sizeof(uint64_t),
		      local_handle, local_offset,
		      remote_handle, remote_offset, toto, context, flags);
	if (rc != CCI_SUCCESS)
		debug(CCI_DB_MSG, "%s: RMA Write failed", __func__);

	/* Put the RMA_READ_REQUEST into the pending queue until the msg is
	   acked */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);
}

static void
tcp_handle_rma_write(tcp_conn_t * sconn, tcp_rx_t * rx, uint16_t len)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	tcp_ep_t *sep = NULL;
	tcp_rma_header_t *write = rx->buffer;
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;	/* our handle */
	uint64_t remote_offset;	/* our offset */
	tcp_rma_handle_t *remote, *h;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	tcp_parse_rma_handle_offset(&write->local, &local_handle,
				     &local_offset);
	tcp_parse_rma_handle_offset(&write->remote, &remote_handle,
				     &remote_offset);
	remote = (tcp_rma_handle_t *) (uintptr_t) remote_handle;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &sep->handles, entry) {
		if (h == remote) {
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != remote) {
		/* remote is no longer valid, send nack */
		debug(CCI_DB_WARN, "%s: remote handle not valid", __func__);
		// TODO
		// Note: we have already handled the seq for this rx
		//       and we may have acked it. If it was the last
		//       piece, then we lost the race. We should defer
		//       the ack until we deliver the data.

		goto out;
	} else if (remote->start + (uintptr_t) remote_offset >
		   remote->start + (uintptr_t) remote->length) {
		/* offset exceeds remote handle's range, send nak */
		debug(CCI_DB_WARN, "%s: remote offset not valid", __func__);
		// TODO
		// Note: we have already handled the seq for this rx
		//       and we may have acked it. If it was the last
		//       piece, then we lost the race. We should defer
		//       the ack until we deliver the data.

		goto out;
	} else if (remote->start + (uintptr_t) remote_offset + (uintptr_t) len >
		   remote->start + (uintptr_t) remote->length) {
		/* length exceeds remote handle's range, send nak */
		debug(CCI_DB_WARN, "%s: remote length not valid", __func__);
		// TODO
		// Note: we have already handled the seq for this rx
		//       and we may have acked it. If it was the last
		//       piece, then we lost the race. We should defer
		//       the ack until we deliver the data.

		goto out;
	}

	/* valid remote handle, copy the data */
	debug(CCI_DB_INFO, "%s: copying data into target buffer", __func__);
	memcpy(remote->start + (uintptr_t) remote_offset, &write->data, len);

      out:
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	return;
}

/* Based on a context ID, we get the corresponding context. This is mainly
   used for RMA reads, not for RMA writes. */
static inline void
lookup_contextid(tcp_conn_t * sconn, uint64_t context_id, const void **context)
{
	/* Remember, the unique ID is actually the index in the array we use to
	   track the different contexts used in context of RMA read operations. */
	const void *c;

	if (sconn->rma_contexts == NULL) {
		*context = NULL;
	} else {
		if (sconn->rma_contexts[context_id] != NULL) {
			c = sconn->rma_contexts[context_id];
			*context = c;
			sconn->rma_contexts[context_id] = NULL;
		} else {
			*context = NULL;
		}
	}
}

static void
tcp_handle_rma_write_done(tcp_conn_t * sconn, tcp_rx_t * rx, uint16_t len)
{
	cci__evt_t *evt;
	cci__conn_t *conn = sconn->conn;
	union cci_event *event;	/* generic CCI event */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	cci__ep_t *ep;
	uint64_t context_id = 0;
	//tcp_rma_header_t *rma_hdr = rx->buffer;
	const void *context;
	tcp_header_r_t *hdr_r = rx->buffer;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);

	memcpy(&context_id, hdr_r->data, sizeof(uint64_t));

	/* get cci__evt_t to hang on ep->events */
	evt = &rx->evt;

	/* setup the generic event for the application */
	event = & evt->event;
	event->type = CCI_EVENT_RECV;
	event->recv.len = len;
	lookup_contextid(sconn, context_id, &context);
	event->recv.ptr = context;
	event->recv.connection = &conn->connection;

	/* queue event on endpoint's completed event queue */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);
}

static inline void tcp_drop_msg(cci_os_handle_t sock)
{
	char buf[4];
	struct sockaddr sa;
	socklen_t slen = sizeof(sa);

	recvfrom(sock, buf, 4, 0, &sa, &slen);
	return;
}

static int tcp_recvfrom_ep(cci__ep_t * ep)
{
	int ret = 0, drop_msg = 0, q_rx = 0, reply = 0, request = 0, again = 0;
	int ka = 0;
	uint8_t a;
	uint16_t b;
	uint32_t id;
	//uint32_t keepalive;
	tcp_rx_t *rx = NULL;
	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(sin);
	tcp_conn_t *sconn = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *sep;
	tcp_msg_type_t type;
	uint32_t seq;
	uint32_t ts;

	CCI_ENTER;

	/* get idle rx */

	sep = ep->priv;
	if (!sep || sep->closing)
		return 0;

	pthread_mutex_lock(&ep->lock);
	if (ep->closing) {
		pthread_mutex_unlock(&ep->lock);
		CCI_EXIT;
		return 0;
	}
	if (!TAILQ_EMPTY(&sep->idle_rxs)) {
		rx = TAILQ_FIRST(&sep->idle_rxs);
		TAILQ_REMOVE(&sep->idle_rxs, rx, entry);
	}
	pthread_mutex_unlock(&ep->lock);

	/* If we run out of RX, we fall down to a special case: we have to use a
	   special buffer to receive the message, parse it. Ultimately, we need
	   the TS and the SEQ (so we can send the RNR msg), as well as the entire
	   header so we can know if we are in the context of a reliable connection
	   (otherwise RNR does not apply). */
#if DEBUG_RNR
	if (conn_established) {
		/* We sumilate a case where we are not ready to receive 25% of the
		   time */
		int n = (int)(4.0 * rand() / (RAND_MAX + 1.0));
		if (n == 0) {
			fprintf(stderr, "Simulating lack of RX buffer...\n");
			rx = NULL;
		}
	}
#endif
	if (!rx) {
		char tmp_buff[TCP_UDP_MAX];
		tcp_header_t *hdr = NULL;

		debug(CCI_DB_INFO,
		      "no rx buffers available on endpoint %d", sep->sock);

		/* We do the receive using a temporary buffer so we can get enough
		   data to send a RNR NACK */
		ret = recvfrom(sep->sock, (void *)tmp_buff, TCP_UDP_MAX,
			       0, (struct sockaddr *)&sin, &sin_len);
		if (ret < (int)sizeof(tcp_header_t)) {
			debug(CCI_DB_INFO,
			      "Did not receive enough data to get the msg header");
			CCI_EXIT;
			return 0;
		}

		/* Now we get the header and parse it so we can know if we are in the
		   context of a reliable connection */
		hdr = (tcp_header_t *) tmp_buff;
		tcp_parse_header(hdr, &type, &a, &b, &id);
		sconn =
		    tcp_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
				   type);
		conn = sconn->conn;
		if (sconn == NULL) {
			/* If the connection is not already established, we just drop the
			   message */
			debug(CCI_DB_INFO,
			      "Connection not established, dropping msg\n");
			CCI_EXIT;
			return 0;
		}

		/* If this is a reliable connection, we issue a RNR message */
		if (cci_conn_is_reliable(sconn->conn)) {
			tcp_header_r_t *header_r = NULL;

			/* We do the receive using a temporary buffer so we can get enough
			   data to send a RNR NACK */

			/* From the buffer, we get the TS and SEQ from the header (this is 
			   the only we need to deal with RNR) and will be used later on */
			header_r = (tcp_header_r_t *) tmp_buff;
			tcp_parse_seq_ts(&header_r->seq_ts, &seq, &ts);
			sconn->rnr = seq;
			drop_msg = 1;
			goto out;
		} else {
			/* If the connection is unreliable, we simply exit */
			CCI_EXIT;
			return 0;
		}
	}

	ret = recvfrom(sep->sock, rx->buffer, ep->buffer_len,
		       0, (struct sockaddr *)&sin, &sin_len);
	if (ret < (int)sizeof(tcp_header_t)) {
		q_rx = 1;
		goto out;
	}

	again = 1;

	/* lookup connection from sin and id */

	tcp_parse_header(rx->buffer, &type, &a, &b, &id);
	if (TCP_MSG_CONN_REPLY == type) {
		reply = 1;
	} else if (TCP_MSG_CONN_REQUEST == type) {
		request = 1;
		rx->sin = sin;
	}

	if (TCP_MSG_KEEPALIVE == type)
		ka = 1;

	if (!request)
		sconn =
		    tcp_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
				   type);

	{
		char name[32];

		if (CCI_DB_MSG & cci__debug) {
			memset(name, 0, sizeof(name));
			tcp_sin_to_name(sin, name, sizeof(name));
			debug((CCI_DB_MSG),
			      "ep %d recv'd %s msg from %s with %d bytes",
			      sep->sock, tcp_msg_type(type), name, a + b);
		}
	}

	/* if no conn, drop msg, requeue rx */
	if (!ka && !sconn && !reply && !request) {
		debug((CCI_DB_CONN | CCI_DB_MSG),
		      "no sconn for incoming %s msg " "from %s:%d",
		      tcp_msg_type(type), inet_ntoa(sin.sin_addr),
		      ntohs(sin.sin_port));
		q_rx = 1;
		goto out;
	}

	if (sconn && cci_conn_is_reliable(sconn->conn) &&
	    !(type == TCP_MSG_CONN_REPLY)) {
		tcp_header_r_t *hdr_r = rx->buffer;
		tcp_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
		tcp_handle_seq(sconn, seq);
	}

	/* Make sure the connection is already established */
	if (sconn) {
		/* If the connection is RNR and the seq is superior to seq for which
		   the RNR was generated, we drop the msg */
		conn = sconn->conn;
		if (conn->connection.attribute == CCI_CONN_ATTR_RO
		    && sconn->rnr != 0 && seq > sconn->rnr) {
			/* We just drop the message */
			debug(CCI_DB_MSG,
			      "RNR connection, dropping msg (seq: %u)", seq);
			drop_msg = 1;
			goto out;
		}

		/* If we receive again the message that created the RNR status, we
		   resume normal operation */
		if (sconn->rnr > 0 && sconn->rnr == seq)
			sconn->rnr = 0;
	}

	/* TODO handle types */

	switch (type) {
	case TCP_MSG_CONN_REQUEST:
		tcp_handle_conn_request(rx, a, b, sin, ep);
		break;
	case TCP_MSG_CONN_REPLY:
		tcp_handle_conn_reply(sconn, rx, a, b, id, sin, ep);
		break;
	case TCP_MSG_CONN_ACK:
		tcp_handle_conn_ack(sconn, rx, a, b, id, sin);
		break;
	case TCP_MSG_DISCONNECT:
		break;
	case TCP_MSG_SEND:
		tcp_handle_active_message(sconn, rx, b, id);
		break;
	case TCP_MSG_RNR:{
			tcp_header_r_t *hdr_r = rx->buffer;

			tcp_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
			tcp_handle_rnr(sconn, seq, ts);
			break;
		}
	case TCP_MSG_KEEPALIVE:
		/* Nothing to do? */
		break;
	case TCP_MSG_ACK_ONLY:
	case TCP_MSG_ACK_UP_TO:
	case TCP_MSG_SACK:
		tcp_handle_ack(sconn, type, rx, (int)a, id);
		break;
	case TCP_MSG_RMA_WRITE:
		tcp_handle_rma_write(sconn, rx, b);
		break;
	case TCP_MSG_RMA_WRITE_DONE:
		tcp_handle_rma_write_done(sconn, rx, b);
		break;
	case TCP_MSG_RMA_READ_REQUEST:
		tcp_handle_rma_read_request(sconn, rx, b);
		break;
	case TCP_MSG_RMA_READ_REPLY:
		break;
	default:
		debug(CCI_DB_MSG, "unknown active message with type %u",
		      (enum tcp_msg_type)type);
	}

      out:
	if (q_rx) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	if (drop_msg) {
		if (cci_conn_is_reliable(sconn->conn) && sconn->rnr == seq) {
			char buffer[TCP_MAX_HDR_SIZE];
			int len = 0;
			tcp_header_r_t *hdr_r = NULL;

			/* 
			   Getting here, we are in the new RNR context on the receiver side.
			   Note that we already got the TS and SEQ from the message header 
			 */

			/* Receiver side and reliable-ordered connections: we store the seq of
			   the msg for which we were RNR so we can drop all other following 
			   messages. */
			if (conn->connection.attribute == CCI_CONN_ATTR_RO
			    && sconn->rnr == 0)
				sconn->rnr = seq;

			/* Send a RNR NACK back to the sender */
			memset(buffer, 0, sizeof(buffer));
			hdr_r = (tcp_header_r_t *) buffer;
			tcp_pack_nack(hdr_r,
				       TCP_MSG_RNR,
				       sconn->peer_id, seq, ts, 0);
			len = sizeof(*hdr_r);

			/* XXX: Should we queue the message or we send it? 
			   I seems to me that it should be queued to maintain order as much as
			   possible (but what about RU connections? */
			tcp_sendto(sep->sock, buffer, len, sconn->sin);
		}

		/* Drop the message */
		tcp_drop_msg(sep->sock);
	}

	CCI_EXIT;

	return again;
}

/*
 * Check whether a keeplive timeout expired for a given endpoint.
 */
static void tcp_keepalive(void)
{
	tcp_conn_t *sconn;
	cci__conn_t *conn;
	uint64_t now = 0ULL;
	uint32_t ka_timeout;

	CCI_ENTER;

	if (TAILQ_EMPTY(&sglobals->ka_conns))
		return;

	now = tcp_get_usecs();

	TAILQ_FOREACH(sconn, &sglobals->ka_conns, entry) {
		conn = sconn->conn;

		if (conn->keepalive_timeout == 0ULL)
			return;

		/* The keepalive is assumed to expire if we did not hear anything from the
		   peer since the last receive + keepalive timeout. */
		ka_timeout = sconn->ts + conn->keepalive_timeout;

		if (TCP_U64_LT(now, ka_timeout)) {
			int len;
			char buffer[TCP_MAX_HDR_SIZE];
			tcp_header_t *hdr = NULL;
			cci_event_keepalive_timedout_t *event = NULL;
			cci__evt_t *evt = NULL;
			cci__ep_t *ep = NULL;
			tcp_ep_t *sep = NULL;
			tcp_tx_t *tx = NULL;

			/*
			 * We generate a keepalive event
			 */

			TAILQ_HEAD(s_evts, cci__evt) evts =
			    TAILQ_HEAD_INITIALIZER(evts);
			TAILQ_INIT(&evts);
			evt = TAILQ_FIRST(&evts);
			event = (cci_event_keepalive_timedout_t *) evt;
			event->type = CCI_EVENT_KEEPALIVE_TIMEDOUT;
			event->connection = &conn->connection;
			TAILQ_REMOVE(&evts, evt, entry);
			ep = evt->ep;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);

			/*
			 * Finally we send an heartbeat
			 */

			/* Get a TX */
			pthread_mutex_lock(&ep->lock);
			if (!TAILQ_EMPTY(&sep->idle_txs)) {
				tx = TAILQ_FIRST(&sep->idle_txs);
				TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
			}
			pthread_mutex_unlock(&ep->lock);

			/* Prepare and send the msg */
			ep = container_of(conn->connection.endpoint, cci__ep_t,
					  endpoint);
			sep = ep->priv;
			memset(buffer, 0, sizeof(buffer));
			hdr = (tcp_header_t *) buffer;
			tcp_pack_keepalive(hdr, sconn->peer_id);
			len = sizeof(*hdr);
			tcp_sendto(sep->sock, buffer, len, sconn->sin);
		}
	}

	CCI_EXIT;
	return;
}

static void tcp_ack_conns(cci__ep_t * ep)
{
	int i;
	cci__dev_t *dev = ep->dev;
	tcp_dev_t *sdev = dev->priv;
	tcp_ep_t *sep = ep->priv;
	tcp_conn_t *sconn = NULL;
	tcp_tx_t *tx = NULL;
	static uint64_t last = 0ULL;
	uint64_t now = 0ULL;

	TAILQ_HEAD(s_txs, tcp_tx) txs = TAILQ_HEAD_INITIALIZER(txs);
	TAILQ_INIT(&txs);

	CCI_ENTER;

	now = tcp_get_usecs();

	if (last == 0ULL)
		last = now;
	else if (last + 10ULL > now)
		return;

	last = now;

	pthread_mutex_lock(&ep->lock);
	for (i = 0; i < TCP_EP_HASH_SIZE; i++) {
		if (!TAILQ_EMPTY(&sep->conn_hash[i])) {
			TAILQ_FOREACH(sconn, &sep->conn_hash[i], entry) {
				if (!TAILQ_EMPTY(&sconn->acks)) {
					int count = 1;
					tcp_header_r_t *hdr_r;
					uint32_t acks[TCP_MAX_SACK * 2];
					tcp_ack_t *ack = NULL;
					tcp_msg_type_t type =
					    TCP_MSG_ACK_UP_TO;
					char buffer[TCP_MAX_HDR_SIZE];
					int len = 0;

					memset(buffer, 0, sizeof(buffer));

					if (1 == tcp_need_sack(sconn)) {
						tcp_ack_t *tmp;

						type = TCP_MSG_SACK;
						count = 0;

						TAILQ_FOREACH_SAFE(ack,
								   &sconn->acks,
								   entry, tmp) {
							TAILQ_REMOVE
							    (&sconn->acks, ack,
							     entry);
							acks[count++] =
							    ack->start;
							acks[count++] =
							    ack->end;
							free(ack);
							if (count ==
							    TCP_MAX_SACK * 2)
								break;
						}
						if (acks[0] == sconn->acked + 1) {
							sconn->acked = acks[1];
						}
					} else {
						ack = TAILQ_FIRST(&sconn->acks);
						TAILQ_REMOVE(&sconn->acks, ack,
							     entry);
						if (ack->start == sconn->acked)
							sconn->acked = ack->end;
						acks[0] = ack->end;
						if (ack->start == ack->end)
							type =
							    TCP_MSG_ACK_ONLY;
						free(ack);
					}
					hdr_r = (tcp_header_r_t *) buffer;
					tcp_pack_ack(hdr_r, type,
						      sconn->peer_id, 0, 0,
						      acks, count);

					len =
					    sizeof(*hdr_r) +
					    (count * sizeof(acks[0]));
					tcp_sendto(sep->sock, buffer, len,
						    sconn->sin);
				}
			}
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&txs)) {
		tx = TAILQ_FIRST(&txs);
		TAILQ_REMOVE(&txs, tx, dentry);
		pthread_mutex_lock(&dev->lock);
		TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
		pthread_mutex_unlock(&dev->lock);
	}

	CCI_EXIT;
	return;
}

static inline void tcp_progress_dev(cci__dev_t * dev)
{
	int have_token = 0;
	tcp_dev_t *sdev;
	cci__ep_t *ep;

	CCI_ENTER;

	sdev = dev->priv;
	pthread_mutex_lock(&dev->lock);
	if (sdev->is_progressing == 0) {
		sdev->is_progressing = 1;
		have_token = 1;
	}
	pthread_mutex_unlock(&dev->lock);
	if (!have_token) {
		CCI_EXIT;
		return;
	}

	tcp_progress_sends(dev);

	/* FIXME need to hold ep->lock */
	TAILQ_FOREACH(ep, &dev->eps, entry)
	    tcp_ack_conns(ep);

	/* TODO progress lep->passive? */

	pthread_mutex_lock(&dev->lock);
	sdev->is_progressing = 0;
	pthread_mutex_unlock(&dev->lock);

	CCI_EXIT;
	return;
}

static void *tcp_progress_thread(void *arg)
{
	struct timeval tv = { 0, TCP_PROG_TIME_US };

	assert(!arg);
	pthread_mutex_lock(&sglobals->lock);
	while (!tcp_shut_down) {
		cci__dev_t *dev;
		cci_device_t const **device;

		pthread_mutex_unlock(&sglobals->lock);

		/* For each connection with keepalive set. We do here since the list
		   of such connections is independent from any device (we do not want
		   to go from device to connections. */
		tcp_keepalive();

		/* for each device, try progressing */
		for (device = sglobals->devices; *device != NULL; device++) {
			dev = container_of(*device, cci__dev_t, device);
			tcp_progress_dev(dev);
		}
		select(0, NULL, NULL, NULL, &tv);
		pthread_mutex_lock(&sglobals->lock);
	}
	pthread_mutex_unlock(&sglobals->lock);

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}

static void *tcp_recv_thread(void *arg)
{
	int i = 0;
	int ret = 0;
	static int start = 0;
	struct timeval tv = { 0, TCP_PROG_TIME_US };
	int nfds = 0;
	fd_set fds;

	assert(!arg);
	pthread_mutex_lock(&sglobals->lock);
	while (!tcp_shut_down) {
		nfds = sglobals->nfds;
		FD_ZERO(&fds);
		for (i = 0; i < nfds; i++) {
			if (sglobals->fd_idx[i].type != TCP_FD_UNUSED)
				FD_SET(i, &fds);
		}
		pthread_mutex_unlock(&sglobals->lock);

		ret = select(nfds, &fds, NULL, NULL, &tv);
		if (ret == -1) {
			switch (errno) {
			case EBADF:
				debug(CCI_DB_INFO, "select() failed with %s",
				      strerror(errno));
				break;
			default:
				break;
			}
			goto relock;
		} else if (ret == 0) {
			goto relock;
		}

		if (start >= nfds)
			start = 0;

		i = start;
		do {
			if (FD_ISSET(i, &fds)) {
				tcp_fd_idx_t *idx =
				    (tcp_fd_idx_t *) & sglobals->fd_idx[i];

				if (idx->type == TCP_FD_EP)
					tcp_recvfrom_ep(idx->ep);
				start = i;
			}
			i = (i + 1) % nfds;
		} while (i != start);
	      relock:
		pthread_mutex_lock(&sglobals->lock);
	}
	pthread_mutex_unlock(&sglobals->lock);

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}
