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

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>
#include <search.h>
#ifdef HAVE_IFADDRS_H
#include <net/if.h>
#include <ifaddrs.h>
#endif

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/ctp/ctp.h"
#include "ctp_tcp.h"

#define DEBUG_RNR 0

#if DEBUG_RNR
#include <stdbool.h>
bool conn_established = false;
#endif

tcp_globals_t *tglobals = NULL;

/*
 * Local functions
 */
static int ctp_tcp_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_tcp_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_tcp_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status);
static int ctp_tcp_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpoint,
				cci_os_handle_t * fd);
static int ctp_tcp_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_tcp_accept(cci_event_t *event, const void *context);
static int ctp_tcp_reject(cci_event_t *conn_req);
static int ctp_tcp_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout);
static int ctp_tcp_disconnect(cci_connection_t * connection);
static int ctp_tcp_set_opt(cci_opt_handle_t * handle,
			cci_opt_name_t name, const void *val);
static int ctp_tcp_get_opt(cci_opt_handle_t * handle,
			cci_opt_name_t name, void *val);
static int ctp_tcp_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_tcp_get_event(cci_endpoint_t * endpoint,
			  cci_event_t ** const event);
static int ctp_tcp_return_event(cci_event_t * event);
static int ctp_tcp_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags);
static int ctp_tcp_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags);
static int ctp_tcp_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle);
static int ctp_tcp_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle);
static int ctp_tcp_rma(cci_connection_t * connection,
		    const void *header_ptr, uint32_t header_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags);

static void tcp_progress_sends(cci__ep_t * ep);
static void *tcp_progress_thread(void *arg);
static int tcp_progress_ep(cci__ep_t *ep);
static int tcp_poll_events(cci__ep_t *ep);
static int tcp_sendto(cci_os_handle_t sock, void *buf, int len,
			void *rma_ptr, uint32_t rma_len, uintptr_t *offset);
static inline void tcp_progress_conn_sends(cci__conn_t *conn);

/*
 * Public plugin structure.
 *
 * The name of this structure must be of the following form:
 *
 *    cci_ctp_<your_plugin_name>_plugin
 *
 * This allows the symbol to be found after the plugin is dynamically
 * opened.
 *
 * Note that your_plugin_name should match the direct name where the
 * plugin resides.
 */
cci_plugin_ctp_t cci_ctp_tcp_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "tcp",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 30,

	 /* Bootstrap function pointers */
	 cci_ctp_tcp_post_load,
	 cci_ctp_tcp_pre_unload,
	 },

	/* API function pointers */
	ctp_tcp_init,
	ctp_tcp_finalize,
	ctp_tcp_strerror,
	ctp_tcp_create_endpoint,
	ctp_tcp_destroy_endpoint,
	ctp_tcp_accept,
	ctp_tcp_reject,
	ctp_tcp_connect,
	ctp_tcp_disconnect,
	ctp_tcp_set_opt,
	ctp_tcp_get_opt,
	ctp_tcp_arm_os_handle,
	ctp_tcp_get_event,
	ctp_tcp_return_event,
	ctp_tcp_send,
	ctp_tcp_sendv,
	ctp_tcp_rma_register,
	ctp_tcp_rma_deregister,
	ctp_tcp_rma
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
		return "ditconnect";
	case TCP_MSG_SEND:
		return "send";
	case TCP_MSG_ACK:
		return "ack";
	case TCP_MSG_RNR:
		return "receiver not ready";
	case TCP_MSG_KEEPALIVE:
		return "keepalive";
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

static inline int tcp_create_thread(cci__ep_t *ep)
{
	int ret;
	tcp_ep_t *tep;

	assert (ep);

	tep = ep->priv;

	ret = pthread_create(&tep->tid, NULL, tcp_progress_thread, (void*)ep);

	return ret;
}

static inline int tcp_terminate_threads (tcp_ep_t *tep)
{
	assert (tep);

	if (tep->tid)
		pthread_join(tep->tid, NULL);

	return CCI_SUCCESS;
}

static int ctp_tcp_init(cci_plugin_ctp_t *plugin,
		     uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret;
	cci__dev_t *dev, *ndev;
	cci_device_t **devices;
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *addrs = NULL, *addr;
#endif

	CCI_ENTER;

	/* init sock globals */
	tglobals = calloc(1, sizeof(*tglobals));
	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	srandom((unsigned int)tcp_get_usecs());

#ifdef HAVE_GETIFADDRS
        getifaddrs(&addrs);
	/* ignore errors, we'll use defaults */
#endif

	devices = calloc(CCI_MAX_DEVICES, sizeof(*tglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	if (!globals->configfile) {
#ifdef HAVE_GETIFADDRS
		if (addrs) {
			for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
				struct cci_device *device;
				tcp_dev_t *tdev;
				uint32_t mtu = (uint32_t) -1;
				struct sockaddr_in *sin;

				if (!addr->ifa_addr)
					continue;
				if (addr->ifa_addr->sa_family != AF_INET)
					continue;
				if (addr->ifa_flags & IFF_LOOPBACK)
                                        continue;

				dev = calloc(1, sizeof(*dev));
				if (!dev) {
					ret = CCI_ENOMEM;
					goto out;
				}
				dev->priv = calloc(1, sizeof(*tdev));
				if (!dev->priv) {
					free(dev);
					ret = CCI_ENOMEM;
					goto out;
				}

				cci__init_dev(dev);
				dev->plugin = plugin;
				dev->priority = plugin->base.priority;

				/* FIXME GV: could use macro here */
				device = &dev->device;
				device->transport = strdup("tcp");
				device->name = strdup(addr->ifa_name);

				tdev = dev->priv;

				sin = (struct sockaddr_in *) addr->ifa_addr;
				memcpy(&tdev->ip, &sin->sin_addr, sizeof(sin->sin_addr));

				/* default values */
				device->up = 1;
				device->rate = 0;
				device->pci.domain = -1;    /* per CCI spec */
				device->pci.bus = -1;       /* per CCI spec */
				device->pci.dev = -1;       /* per CCI spec */
				device->pci.func = -1;      /* per CCI spec */
				/* try to get the actual values */
				cci__get_dev_ifaddrs_info(dev, addr);

				mtu = device->max_send_size;
				if (mtu == (uint32_t) -1) {
					/* if no mtu, use default */
					device->max_send_size = TCP_DEFAULT_MSS;
				} else {
					/* compute mss from mtu */
					if (mtu > TCP_MAX_MSS)
						mtu = TCP_MAX_MSS;
					mtu -= TCP_HDR_LEN;
					assert(mtu >= TCP_MIN_MSS); /* FIXME rather ignore the device? */
					device->max_send_size = mtu;
				}

				cci__add_dev(dev);
				devices[tglobals->count] = device;
				tglobals->count++;
			}
		}
#endif

	} else
	/* find devices that we own */
		TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("tcp", dev->device.transport)) {
			const char * const *arg;
			struct cci_device *device;
			tcp_dev_t *tdev;
			uint32_t mtu = (uint32_t) -1;

			dev->plugin = plugin;
			if (dev->priority == -1)
				dev->priority = plugin->base.priority;

			device = &dev->device;

			/* TODO determine link rate
			 *
			 * linux->driver->get ethtool settings->speed
			 * bsd/darwin->ioctl(SIOCGIFMEDIA)->ifm_active
			 * windows ?
			 */

			dev->priv = calloc(1, sizeof(*tdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}

			tdev = dev->priv;

			/* default values */
			device->up = 1;
			device->rate = 0;
			device->pci.domain = -1;	/* per CCI spec */
			device->pci.bus = -1;	/* per CCI spec */
			device->pci.dev = -1;	/* per CCI spec */
			device->pci.func = -1;	/* per CCI spec */

			/* parse conf_argv */
			for (arg = device->conf_argv; *arg != NULL; arg++) {
				if (0 == strncmp("ip=", *arg, 3)) {
					const char *ip = *arg + 3;

					tdev->ip = inet_addr(ip);	/* network order */
				} else if (0 == strncmp("mtu=", *arg, 4)) {
					const char *mtu_str = *arg + 4;
					mtu = strtol(mtu_str, NULL, 0);
				} else if (0 == strncmp("port=", *arg, 5)) {
					const char *s_port = *arg + 5;
					uint16_t    port;
					port = atoi (s_port);
					tdev->port = htons(port);
				}
			}
			if (tdev->ip != 0) {
				/* try to get the actual values now */
#ifdef HAVE_GETIFADDRS
				if (addrs) {
					for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
						struct sockaddr_in *sin;
						if (!addr->ifa_addr)
							continue;
						if (addr->ifa_addr->sa_family != AF_INET)
							continue;
						sin = (struct sockaddr_in *) addr->ifa_addr;
						if (!memcmp(&tdev->ip, &sin->sin_addr, sizeof(tdev->ip)))
							break;
					}
					if (!addr)
						/* no such device, don't initialize it */
						continue;

					cci__get_dev_ifaddrs_info(dev, addr);
				}
#endif
				if (mtu == (uint32_t) -1)
					/* if mtu not specified, use the ifaddr one */
					mtu = device->max_send_size;
				if (mtu == (uint32_t) -1) {
					/* if still no mtu, use default */
					device->max_send_size = TCP_DEFAULT_MSS;
				} else {
					/* compute mss from mtu */
					if (mtu > TCP_MAX_MSS)
						mtu = TCP_MAX_MSS;
					mtu -= TCP_HDR_LEN;
					assert(mtu >= TCP_MIN_MSS); /* FIXME rather ignore the device? */
					device->max_send_size = mtu;
				}
				/* queue to the main device list now */
				TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
				cci__add_dev(dev);
				devices[tglobals->count] = device;
				tglobals->count++;
			}
		}
		}

	devices =
	    realloc(devices, (tglobals->count + 1) * sizeof(cci_device_t *));
	devices[tglobals->count] = NULL;

	*((cci_device_t ***) & tglobals->devices) = devices;

#ifdef HAVE_GETIFADDRS
	freeifaddrs(addrs);
#endif

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	if (devices) {
		int i = 0;
		cci_device_t const *device;
		cci__dev_t *my_dev;

		while (devices[i] != NULL) {
			device = devices[i];
			my_dev = container_of(device, cci__dev_t, device);
			if (my_dev->priv)
				free(my_dev->priv);
		}
		free(devices);
	}
	if (tglobals) {
		free((void *)tglobals);
		tglobals = NULL;
	}
#ifdef HAVE_GETIFADDRS
	if (addrs) {
		freeifaddrs(addrs);
	}
#endif
	CCI_EXIT;
	return ret;
}

static const char *ctp_tcp_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status)
{
	return strerror(status);
}

/* NOTE the CCI layer has already unbound all devices
 *      and destroyed all endpoints.
 *      All we need to do if free dev->priv
 */
static int ctp_tcp_finalize(cci_plugin_ctp_t * plugin)
{
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	TAILQ_FOREACH(dev, &globals->devs, entry)
		if (!strcmp(dev->device.transport, "tcp"))
			free(dev->priv);

	free(tglobals->devices);
	free((void *)tglobals);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static inline int
tcp_set_nonblocking(cci_os_handle_t sock)
{
	int ret, flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (-1 == flags)
		flags = 0;
	ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	if (-1 == ret)
		return errno;

	return 0;
}

static inline void tcp_close_socket(cci_os_handle_t sock)
{
	close(sock);
	return;
}

static int ctp_tcp_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpointp,
				cci_os_handle_t * fd)
{
	int i, ret, one = 1;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	tcp_ep_t *tep = NULL;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	tcp_dev_t *tdev;
	struct sockaddr_in sin;
	socklen_t slen;
	char name[256 + 6];	/* POSIX HOST_NAME_MAX + tcp:// */

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	if (0 != strcmp("tcp", device->transport)) {
		ret = CCI_EINVAL;
		goto out;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*tep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ep->rx_buf_cnt = TCP_EP_RX_CNT;
	ep->tx_buf_cnt = TCP_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size + TCP_HDR_LEN;
	ep->tx_timeout = 0;

	tep = ep->priv;

	tep->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (tep->sock == -1) {
		ret = errno;
		goto out;
	}

	ret = setsockopt(tep->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret) {
		ret = errno;
		debug(CCI_DB_EP, "%s: setting SO_REUSEADDR returned %s",
			__func__, strerror(ret));
	}

	/* bind socket to device */
	tdev = dev->priv;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = tdev->ip;
	if (tdev->port != 0)
        sin.sin_port = tdev->port;

	ret = bind(tep->sock, (const struct sockaddr *)&sin, sizeof(sin));
	if (ret) {
		ret = errno;
		goto out;
	}

	slen = sizeof(tep->sin);

	ret = getsockname(tep->sock, (struct sockaddr *)&tep->sin, &slen);
	if (ret) {
		ret = errno;
		goto out;
	}

	memset(name, 0, sizeof(name));
	sprintf(name, "tcp://");
	tcp_sin_to_name(tep->sin, name + (uintptr_t) 6, sizeof(name) - 6);
	ep->uri = strdup(name);

	TAILQ_INIT(&tep->conns);
	TAILQ_INIT(&tep->active);
	TAILQ_INIT(&tep->passive);

	TAILQ_INIT(&tep->idle_txs);
	TAILQ_INIT(&tep->idle_rxs);
	TAILQ_INIT(&tep->handles);
	TAILQ_INIT(&tep->rma_ops);

	tep->fds = calloc(TCP_EP_MAX_CONNS, sizeof(*tep->fds));
	if (!tep->fds) {
		ret = CCI_ENOMEM;
		goto out;
	}

	tep->fds[0].fd = tep->sock;
	tep->fds[0].events = POLLIN;
	tep->nfds = 1;

	tep->c = calloc(TCP_EP_MAX_CONNS, sizeof(*tep->c));
	if (!tep->c) {
		ret = CCI_ENOMEM;
		goto out;
	}
	/* NOTE: tep->c[0] is the listening socket and not a connection */

	tep->tx_buf = calloc(1, ep->tx_buf_cnt * ep->buffer_len);
	if (!tep->tx_buf) {
		ret = CCI_ENOMEM;
		goto out;
	}

	tep->txs = calloc(1, ep->tx_buf_cnt * sizeof(tcp_tx_t));
	if (!tep->txs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* alloc txs */
	for (i = 0; i < ep->tx_buf_cnt; i++) {
		tcp_tx_t *tx = &tep->txs[i];

		tx->id = i;

		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.ep = ep;
		tx->buffer = tep->tx_buf + (i * ep->buffer_len);
		tx->len = 0;
		TAILQ_INSERT_TAIL(&tep->idle_txs, &tx->evt, entry);
	}

	tep->rx_buf = calloc(1, ep->rx_buf_cnt * ep->buffer_len);
	if (!tep->rx_buf) {
		ret = CCI_ENOMEM;
		goto out;
	}

	tep->rxs = calloc(1, ep->rx_buf_cnt * sizeof(tcp_rx_t));
	if (!tep->rxs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* alloc rxs */
	for (i = 0; i < ep->rx_buf_cnt; i++) {
		tcp_rx_t *rx = &tep->rxs[i];

		rx->id = i;

		rx->evt.event.type = CCI_EVENT_RECV;
		rx->evt.ep = ep;
		rx->buffer = tep->rx_buf + (i * ep->buffer_len);
		rx->len = 0;
		TAILQ_INSERT_TAIL(&tep->idle_rxs, &rx->evt, entry);
	}

	ret = tcp_set_nonblocking(tep->sock);
	if (ret)
		goto out;

	ret = listen(tep->sock, SOMAXCONN);
	if (ret) {
		ret = errno;
		goto out;
	}

	if (fd) {
		ret = pipe(tep->pipe);
		if (ret) {
			ret = errno;
			goto out;
		}
		*fd = tep->pipe[0];

		ret = tcp_create_thread(ep);
		if (ret)
			goto out;
	}

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	pthread_mutex_lock(&dev->lock);
	if (!TAILQ_EMPTY(&dev->eps)) {
		TAILQ_REMOVE(&dev->eps, ep, entry);
	}
	pthread_mutex_unlock(&dev->lock);
	if (tep) {
		free(tep->txs);
		free(tep->tx_buf);

		free(tep->rxs);
		free(tep->rx_buf);

		free(tep->fds);

		if (tep->ids)
			free(tep->ids);
		if (tep->sock)
			tcp_close_socket(tep->sock);
		free(tep);
	}
	if (ep) {
		free(ep->uri);
		free(ep);
	}
	*endpointp = NULL;
	CCI_EXIT;
	return ret;
}

static void
tcp_disconnect_locked(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	free((char *)conn->uri);

	TAILQ_REMOVE(&tep->conns, tconn, entry);

	//tcp_remove_conn(tep, tconn);

	/* TODO remove tconn from tep->c and tep->fds
	 *      move last fd to our spot and decrement nfds
	 *      move last conn to tep->c[our index]
	 */

	free(tconn);
	free(conn);

	return;
}

static int ctp_tcp_destroy_endpoint(cci_endpoint_t * endpoint)
{
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	tcp_ep_t *tep = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;
	tep = ep->priv;

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);

	if (tep) {
		cci__conn_t *conn;
		tcp_conn_t *tconn;

		ep->closing = 1;

		pthread_mutex_unlock(&dev->lock);
		pthread_mutex_unlock(&ep->lock);
		tcp_terminate_threads (tep);
		pthread_mutex_lock(&dev->lock);
		pthread_mutex_lock(&ep->lock);

		if (tep->sock)
			tcp_close_socket(tep->sock);

		while (!TAILQ_EMPTY(&tep->conns)) {
			tconn = TAILQ_FIRST(&tep->conns);
			conn = tconn->conn;
			tcp_disconnect_locked(ep, conn);
		}
		while (!TAILQ_EMPTY(&tep->active)) {
			tconn = TAILQ_FIRST(&tep->active);
			conn = tconn->conn;
			tcp_disconnect_locked(ep, conn);
		}
		free(tep->txs);
		free(tep->tx_buf);

		free(tep->rxs);
		free(tep->rx_buf);

		free(tep->fds);
		free(tep->c);

		while (!TAILQ_EMPTY(&tep->rma_ops)) {
			tcp_rma_op_t *rma_op = TAILQ_FIRST(&tep->rma_ops);
			TAILQ_REMOVE(&tep->rma_ops, rma_op, entry);
			free(rma_op);
		}
		while (!TAILQ_EMPTY(&tep->handles)) {
			tcp_rma_handle_t *handle = TAILQ_FIRST(&tep->handles);
			TAILQ_REMOVE(&tep->handles, handle, entry);
			free(handle);
		}
		free(tep->ids);
		free(tep);
	}
	ep->priv = NULL;
	free((char *)ep->uri);
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static inline tcp_tx_t *
tcp_get_tx_locked(tcp_ep_t *tep)
{
	tcp_tx_t *tx = NULL;

	if (!TAILQ_EMPTY(&tep->idle_txs)) {
		cci__evt_t *evt = TAILQ_FIRST(&tep->idle_txs);
		TAILQ_REMOVE(&tep->idle_txs, evt, entry);
		tx = container_of(evt, tcp_tx_t, evt);
		tx->offset = 0;
		tx->rma_ptr = NULL;
		tx->rma_len = 0;
		tx->rma_op = NULL;
		tx->rma_id = 0;
		tx->evt.conn = NULL;
		debug(CCI_DB_MSG, "%s: getting tx %p", __func__, tx);
	}
	return tx;
}

static inline tcp_tx_t *
tcp_get_tx(cci__ep_t *ep, int allocate)
{
	tcp_ep_t *tep = ep->priv;
	tcp_tx_t *tx = NULL;

	pthread_mutex_lock(&ep->lock);
	tx = tcp_get_tx_locked(tep);
	pthread_mutex_unlock(&ep->lock);

	if (!tx && allocate) {
		do {
			tx = calloc(1, sizeof(*tx));
		} while (!tx);
		do {
			tx->buffer = calloc(1, sizeof(*ack));
		} while (!tx->buffer);
	}

	return tx;
}

static inline void
tcp_put_tx_locked(tcp_ep_t *tep, tcp_tx_t *tx)
{
	debug(CCI_DB_MSG, "%s: putting tx %p", __func__, tx);
	TAILQ_INSERT_HEAD(&tep->idle_txs, &tx->evt, entry);

	return;
}

static inline void
tcp_put_tx(tcp_tx_t *tx)
{
	cci__ep_t *ep = tx->evt.ep;
	tcp_ep_t *tep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	tcp_put_tx_locked(tep, tx);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static inline tcp_rx_t *
tcp_get_rx_locked(tcp_ep_t *tep)
{
	tcp_rx_t *rx = NULL;

	if (!TAILQ_EMPTY(&tep->idle_rxs)) {
		cci__evt_t *evt = TAILQ_FIRST(&tep->idle_rxs);
		TAILQ_REMOVE(&tep->idle_rxs, evt, entry);
		rx = container_of(evt, tcp_rx_t, evt);
	}
	return rx;
}

static inline tcp_rx_t *
tcp_get_rx(cci__ep_t *ep)
{
	tcp_ep_t *tep = ep->priv;
	tcp_rx_t *rx = NULL;

	pthread_mutex_lock(&ep->lock);
	rx = tcp_get_rx_locked(tep);
	pthread_mutex_unlock(&ep->lock);

	return rx;
}

static inline void
tcp_put_rx_locked(tcp_ep_t *tep, tcp_rx_t *rx)
{
	TAILQ_INSERT_HEAD(&tep->idle_rxs, &rx->evt, entry);

	return;
}

static inline void
tcp_put_rx(tcp_rx_t *rx)
{
	cci__ep_t *ep = rx->evt.ep;
	tcp_ep_t *tep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	tcp_put_rx_locked(tep, rx);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static int ctp_tcp_accept(cci_event_t *event, const void *context)
{
	cci_endpoint_t *endpoint;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	tcp_header_t *hdr = NULL, *request_hdr = NULL;
	tcp_tx_t *tx = NULL;
	tcp_rx_t *rx = NULL;
	tcp_handshake_t *hs = NULL;
	uint32_t client_tx_id = 0;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	rx = container_of(evt, tcp_rx_t, evt);
	ep = evt->ep;
	endpoint = &ep->endpoint;
	tep = ep->priv;

	request_hdr = rx->buffer;
	client_tx_id = ntohl(request_hdr->b);

	conn = evt->conn;
	tconn = conn->priv;

	/* get a tx */
	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		/* TODO send reject */
		/* TODO remove from tep->fds, t->c, tep->nfds-- */

		close(tconn->fd);

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&tep->passive, tconn, entry);
		pthread_mutex_unlock(&ep->lock);

		free(conn->priv);
		free(conn);
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	conn->connection.context = (void *)context;

	debug(CCI_DB_CONN, "%s: accepting conn %p", __func__, conn);

	/* prepare conn_reply */

	tx->msg_type = TCP_MSG_CONN_REPLY;
	tx->rma_op = NULL;

	evt = &tx->evt;
	evt->conn = conn;
	evt->event.type = CCI_EVENT_ACCEPT;
	evt->event.accept.status = CCI_SUCCESS;	/* for now */
	evt->event.accept.context = (void *)context;
	evt->event.accept.connection = &conn->connection;

	/* pack the msg */

	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_conn_reply(hdr, CCI_SUCCESS, tx->id);
	hs = (tcp_handshake_t *) (tx->buffer + sizeof(*hdr));
	tcp_pack_handshake(hs, ep->rx_buf_cnt,
			   conn->connection.max_send_size, 0, tx->id);

	tx->len = sizeof(*hdr) + sizeof(*hs);

	/* insert at tail of tep's queued list */

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&tconn->slock);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->slock);

	/* try to progress txs */

	tcp_progress_conn_sends(conn);

	CCI_EXIT;

	return CCI_SUCCESS;
}

/* Send reject reply to client.
 *
 * We cannot use the event's buffer since the app will most likely return the
 * event before we get an ack from the client. We will get a tx for the reply.
 */
static int ctp_tcp_reject(cci_event_t *event)
{
	int ret = CCI_SUCCESS;
	uint32_t a;
	uint32_t unused;
	cci__evt_t *evt = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	tcp_header_t *hdr = NULL;
	tcp_msg_type_t type;
	char name[32];
	tcp_rx_t *rx = NULL;
	tcp_tx_t *tx = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	hdr = (void *)event->request.data_ptr;
	tcp_parse_header(hdr, &type, &a, &unused);

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	tep = ep->priv;
	conn = evt->conn;
	tconn = conn->priv;
	rx = container_of(evt, tcp_rx_t, evt);

	/* get a tx */
	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* prep the tx */

	tx->msg_type = TCP_MSG_CONN_REPLY;
	tx->evt.ep = ep;
	tx->evt.conn = NULL;
	tx->evt.event.type = CCI_EVENT_CONNECT;
	tx->evt.event.connect.status = ECONNREFUSED;
	tx->evt.event.connect.connection = NULL;
	tx->rma_op = NULL;
	tx->sin = rx->sin;

	/* prepare conn_reply */

	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_conn_reply(hdr, CCI_ECONNREFUSED, tx->id);

	tx->len = sizeof(*hdr);

	/* insert at tail of endpoint's queued list */

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	tcp_progress_sends(ep);

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(rx->sin, name, sizeof(name));
	debug((CCI_DB_MSG | CCI_DB_CONN), "ep %d sending reject to %s",
	      tep->sock, name);

out:
	CCI_EXIT;
	return ret;
}

static int tcp_getaddrinfo(const char *uri, in_addr_t * in, uint16_t * port)
{
	int ret;
	char *hostname, *svc, *colon;
	struct addrinfo *ai = NULL, hints;

	if (0 == strncmp("tcp://", uri, 6))
		hostname = strdup(&uri[6]);
	else {
		debug(CCI_DB_CONN, "%s: invalid URI %s", __func__, uri);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	colon = strchr(hostname, ':');
	if (colon) {
		*colon = '\0';
	} else {
		debug(CCI_DB_CONN, "%s: invalid URI %s", __func__, uri);
		free(hostname);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	colon++;
	svc = colon;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

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

static inline int
tcp_new_conn(cci__ep_t *ep, struct sockaddr_in sin, int fd, cci__conn_t **connp)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	tcp_conn_t *tconn = NULL;

	/* allocate a new connection */
	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return CCI_ENOMEM;

	conn->priv = calloc(1, sizeof(*tconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out_with_conn;
	}

	conn->plugin = ep->plugin;
	conn->connection.endpoint = &ep->endpoint;
	conn->connection.max_send_size = ep->dev->device.max_send_size;
	conn->tx_timeout = ep->tx_timeout;

	tconn = conn->priv;
	tconn->conn = conn;
	tconn->fd = fd;
	TAILQ_INIT(&tconn->rmas);
	TAILQ_INIT(&tconn->queued);
	TAILQ_INIT(&tconn->pending);

	memcpy(&tconn->sin, &sin, sizeof(sin));

	ret = pthread_mutex_init(&tconn->rlock, NULL);
	if (ret)
		goto out_with_tconn;

	ret = pthread_mutex_init(&tconn->slock, NULL);
	if (ret)
		goto out_with_rlock;

	*connp = conn;

	return ret;

out_with_rlock:
	pthread_mutex_destroy(&tconn->rlock);
out_with_tconn:
	free(tconn);
out_with_conn:
	free(conn);
	return ret;
}

static inline int
tcp_monitor_fd(cci__ep_t *ep, cci__conn_t *conn, int events)
{
	int ret = CCI_SUCCESS, one = 1;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	ret = tcp_set_nonblocking(tconn->fd);
	if (ret)
		goto out;

	ret = setsockopt(tconn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (ret)
		goto out;

	pthread_mutex_lock(&ep->lock);
	tconn->index = tep->nfds++;
	assert(tep->nfds < TCP_EP_MAX_CONNS);
	tep->fds[tconn->index].fd = tconn->fd;
	tep->fds[tconn->index].events = events;
	tep->c[tconn->index] = conn;
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "%s: tconn->index = %u", __func__, tconn->index);

out:
	return ret;
}

static int ctp_tcp_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout)
{
	int ret, fd = -1;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	tcp_tx_t *tx = NULL;
	tcp_header_t *hdr = NULL;
	cci__evt_t *evt = NULL;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	void *ptr = NULL;
	in_addr_t ip;
	tcp_handshake_t *hs = NULL;
	uint16_t port;
	uint32_t keepalive = 0ULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	/* get our endpoint and device */
	ep = container_of(endpoint, cci__ep_t, endpoint);
	tep = ep->priv;
	dev = ep->dev;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

	ret = tcp_getaddrinfo(server_uri, &ip, &port);
	if (ret)
		goto out;
	sin.sin_addr.s_addr = ip;	/* already in network order */
	sin.sin_port = port;	/* already in network order */

	ret = socket(PF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "%s: socket returned %s", __func__, strerror(ret));
		goto out;
	}
	fd = ret;

	ret = tcp_new_conn(ep, sin, fd, &conn);
	if (ret)
		goto out;

	conn->connection.attribute = attribute;
	conn->connection.context = (void *)context;
	conn->uri = strdup(server_uri);

	/* set up tcp specific info */

	tconn = conn->priv;
	tconn->status = TCP_CONN_ACTIVE1;

	/* Dealing with keepalive, if set, include the keepalive timeout value into
	   the connection request */
	if ((((attribute & CCI_CONN_ATTR_RO) == CCI_CONN_ATTR_RO)
	     || ((attribute & CCI_CONN_ATTR_RU) == CCI_CONN_ATTR_RU))
	    && ep->keepalive_timeout != 0UL) {
		keepalive = ep->keepalive_timeout;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->active, tconn, entry);
	pthread_mutex_unlock(&ep->lock);

	/* get a tx */
	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* prep the tx */
	tx->msg_type = TCP_MSG_CONN_REQUEST;

	evt = &tx->evt;
	evt->conn = conn;
	evt->event.type = CCI_EVENT_CONNECT;	/* for now */
	evt->event.connect.status = CCI_SUCCESS;
	evt->event.connect.context = (void *)context;
	evt->event.connect.connection = &conn->connection;

	/* pack the msg */

	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_conn_request(hdr, attribute, data_len, tx->id);
	tx->len = sizeof(*hdr);

	/* add handshake */
	hs = (tcp_handshake_t *) & hdr->data;
	if (keepalive != 0UL)
		conn->keepalive_timeout = keepalive;
	tcp_pack_handshake(hs, ep->rx_buf_cnt,
			    conn->connection.max_send_size, keepalive, 0);

	tx->len += sizeof(*hs);
	ptr = tx->buffer + tx->len;

	tx->rma_op = NULL;

	if (data_len)
		memcpy(ptr, data_ptr, data_len);

	tx->len += data_len;
	assert(tx->len <= ep->buffer_len);

	/* start connect now */
	ret = socket(PF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "%s: socket returned %s", __func__, strerror(ret));
		goto out;
	}
	tconn->fd = ret;

	/* we will have to check for POLLOUT to determine when
	 * the connect completed
	 */
	ret = tcp_monitor_fd(ep, conn, POLLOUT);
	if (ret)
		goto out;

	tx->state = TCP_TX_QUEUED;

	/* insert at tail of conn's queued list */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* ok, initiate connect()... */
	ret = connect(tconn->fd, (struct sockaddr *)&sin, slen);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			debug(CCI_DB_CONN, "%s: connect() returned %s",
				__func__, strerror(ret));
			goto out;
		}
	} else {
		/* TODO connect completed, send CONN_REQUEST */
		debug(CCI_DB_CONN, "%s: connect() completed", __func__);
		tep->fds[tconn->index].events = POLLIN | POLLOUT;
	}

	/* try to progress txs */

	tcp_progress_sends(ep);

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	if (conn) {
		if (ret == CCI_ENOBUFS) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&tep->active, tconn, entry);
			pthread_mutex_unlock(&ep->lock);
		}

		free((char *)conn->uri);
		free(conn->priv);
		free(conn);
	}
	CCI_EXIT;
	return ret;
}

static int ctp_tcp_disconnect(cci_connection_t * connection)
{
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);

	pthread_mutex_lock(&ep->lock);
	tcp_disconnect_locked(ep, conn);
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int ctp_tcp_set_opt(cci_opt_handle_t * handle,
			cci_opt_name_t name, const void *val)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		ep = container_of(handle, cci__ep_t, endpoint);
		ep->tx_timeout = *((uint32_t*) val);
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		ep = container_of(handle, cci__ep_t, endpoint);
		ep->keepalive_timeout = *((uint32_t*) val);
		break;
	case CCI_OPT_CONN_SEND_TIMEOUT:
		conn = container_of(handle, cci__conn_t, connection);
		conn->tx_timeout = *((uint32_t*) val);
		break;
	default:
		debug(CCI_DB_INFO, "unknown option %u", name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;

	return ret;
}

static int ctp_tcp_get_opt(cci_opt_handle_t * handle,
			cci_opt_name_t name, void *val)
{
	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;

	return CCI_EINVAL;
}

static int ctp_tcp_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_tcp_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep;
	cci__evt_t *ev = NULL, *e;
	tcp_ep_t *tep;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	tep = ep->priv;

	if (!tep->pipe[0])
		tcp_progress_ep(ep);

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

	if (ev) {
		TAILQ_REMOVE(&ep->evts, ev, entry);
	} else {
		ret = CCI_EAGAIN;
		if (TAILQ_EMPTY(&tep->idle_rxs))
			ret = CCI_ENOBUFS;
	}

	pthread_mutex_unlock(&ep->lock);

	/* TODO drain fd so that they can block again */

	*event = &ev->event;

	CCI_EXIT;
	return ret;
}

static int ctp_tcp_return_event(cci_event_t * event)
{
	cci__ep_t *ep;
	tcp_ep_t *tep;
	cci__evt_t *evt;
	tcp_tx_t *tx;
	tcp_rx_t *rx;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);

	ep = evt->ep;
	tep = ep->priv;

	/* enqueue the event */

	switch (event->type) {
	case CCI_EVENT_SEND:
		tx = container_of(evt, tcp_tx_t, evt);
		tcp_put_tx(tx);
		break;
	case CCI_EVENT_RECV:
		rx = container_of(evt, tcp_rx_t, evt);
		tcp_put_rx(rx);
		break;
	default:
		/* TODO */
		break;
	}

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int tcp_sendto(cci_os_handle_t sock, void *buf, int len,
			void *rma_ptr, uint32_t rma_len, uintptr_t *offset)
{
	int ret = CCI_SUCCESS;
	uintptr_t off = *offset;

	if (off < len) {
		ret = send(sock, buf + off, len - off, 0);
		if (ret != -1) {
			off += ret;
			*offset += ret;
			ret = CCI_SUCCESS;
		} else {
			ret = errno;
			goto out;
		}
	}
	if (rma_ptr && off >= len) {
		off -= len;
		ret = send(sock, rma_ptr + off, rma_len - off, 0);
		if (ret != -1) {
			*offset += ret;
			ret = CCI_SUCCESS;
		} else {
			ret = errno;
			goto out;
		}
	}
out:
	return ret;
}

static void tcp_progress_pending(cci__ep_t * ep)
{
	return;
}

static inline void
tcp_progress_conn_sends(cci__conn_t *conn)
{
	int ret, is_reliable = 0;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *read_reply = NULL;

	is_reliable = cci_conn_is_reliable(conn);
	tconn = conn->priv;

	pthread_mutex_lock(&tconn->slock);
	while (!TAILQ_EMPTY(&tconn->queued)) {
		cci__evt_t *evt = TAILQ_FIRST(&tconn->queued);
		tcp_tx_t *tx = container_of(evt, tcp_tx_t, evt);
		int off = tx->offset;

		if (tx->msg_type == TCP_MSG_CONN_REQUEST &&
			tconn->status == TCP_CONN_ACTIVE1)
			break;

		if (tx->msg_type == TCP_MSG_RMA_WRITE ||
			tx->msg_type == TCP_MSG_RMA_READ_REQUEST) {
			if (tx->rma_op->pending >= TCP_RMA_DEPTH)
				break;
		}

		debug(CCI_DB_MSG, "%s: sending %s to conn %p",
			__func__, tcp_msg_type(tx->msg_type), conn);

		ret = tcp_sendto(tconn->fd, tx->buffer, tx->len,
				tx->rma_ptr, tx->rma_len, &tx->offset);
		if (ret) {
			if (ret == EAGAIN || ret == EINTR) {
				debug(CCI_DB_MSG, "%s: sending %s returned %s",
					__func__, tcp_msg_type(tx->msg_type),
					strerror(ret));
				break;
			} else {
				/* close connection? */
				debug(CCI_DB_CONN, "%s: send() returned %s - "
					"do we need to close the connection?",
					__func__, strerror(ret));
			}
		} else {
			debug(CCI_DB_MSG, "%s: sent %u bytes to conn %p (offset %u off %u)",
				__func__, (int) tx->offset - off, conn, (int) tx->offset, off);
			if (tx->offset == (tx->len + tx->rma_len)) {
				debug(CCI_DB_MSG, "%s: completed %s send to conn %p",
					__func__, tcp_msg_type(tx->msg_type), conn);
				TAILQ_REMOVE(&tconn->queued, evt, entry);
				switch (tx->msg_type) {
				default:
					TAILQ_INSERT_TAIL(&tconn->pending, evt, entry);
					break;
				case TCP_MSG_RMA_READ_REPLY:
					read_reply = tx;
					break;
				case TCP_MSG_ACK:
					if (!tx->evt.ep) {
						debug(CCI_DB_MSG, "%s: freeing "
							"tx %p", __func__, tx);
						free(tx->buffer);
						free(tx);
					} else {
						/* FIXME locking violation
						 * queue the tx locally, then
						 * move it to the endpoint
						 * after dropping this lock
						 */
						tcp_put_tx(tx);
					}
					break;
				}
			} else {
				break;
			}
		}
	}
	if (TAILQ_EMPTY(&tconn->queued)) {
		cci_endpoint_t *endpoint = conn->connection.endpoint;
		cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
		tcp_ep_t *tep = ep->priv;
		tep->fds[tconn->index].events = POLLIN;
	}
	pthread_mutex_unlock(&tconn->slock);

	if (read_reply)
		tcp_put_tx(read_reply);

	return;
}

static void tcp_progress_queued(cci__ep_t * ep)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn, *tmp;

	CCI_ENTER;

	if (!tep)
		return;

	TAILQ_FOREACH_SAFE(tconn, &tep->conns, entry, tmp) {
		tcp_progress_conn_sends(tconn->conn);
	}

	CCI_EXIT;

	return;
}

static void
tcp_progress_sends(cci__ep_t * ep)
{
	tcp_progress_pending(ep);
	tcp_progress_queued(ep);

	return;
}

static int
tcp_progress_ep(cci__ep_t *ep)
{
	int ret = CCI_EAGAIN;

	tcp_poll_events(ep);
	tcp_progress_sends(ep);

	return ret;
}

static int ctp_tcp_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	if (msg_ptr && msg_len) {
		iovcnt = 1;
		iov.iov_base = (void *) msg_ptr;
		iov.iov_len = msg_len;
	}

	return ctp_tcp_sendv(connection, &iov, iovcnt, context, flags);
}

static int ctp_tcp_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags)
{
	int i, ret, is_reliable = 0, data_len = 0;
	char *func = iovcnt < 2 ? "send" : "sendv";
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep;
	cci__conn_t *conn;
	tcp_ep_t *tep;
	tcp_conn_t *tconn;
	tcp_tx_t *tx = NULL;
	tcp_header_t *hdr;
	void *ptr;
	cci__evt_t *evt;
	union cci_event *event;	/* generic CCI event */

	debug(CCI_DB_FUNC, "entering %s", func);

	if (!tglobals) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_ENODEV;
	}

	for (i = 0; i < iovcnt; i++)
		data_len += data[i].iov_len;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	tep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);
	tconn = conn->priv;

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_ENOBUFS;
	}

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* tx bookkeeping */
	tx->msg_type = TCP_MSG_SEND;
	tx->flags = flags;

	/* zero even if unreliable */
	if (!is_reliable) {
		/* If the connection is not reliable, it cannot be a RMA operation */
		tx->rma_op = NULL;
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
	tcp_pack_send(hdr, data_len, tx->id);
	tx->len = sizeof(*hdr);

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
		ret = tcp_sendto(tconn->fd, tx->buffer, tx->len, tx->rma_ptr,
				tx->rma_len, &tx->offset);
		if (ret == CCI_SUCCESS) {
			/* queue event on enpoint's completed queue */
			tx->state = TCP_TX_COMPLETED;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_MSG, "sent UU msg with %d bytes",
			      tx->len - (int)sizeof(tcp_header_t));

			debug(CCI_DB_FUNC, "exiting %s", func);

			return CCI_SUCCESS;
		}

		/* if error, fall through */
		/* FIXME if disconnected, need to return error */
	}

	/* insert at tail of sock device's queued list */

	debug(CCI_DB_MSG, "%s: queuing MSG %p to conn %p", __func__, tx, conn);

	tx->state = TCP_TX_QUEUED;
	pthread_mutex_lock(&tconn->slock);
	TAILQ_INSERT_TAIL(&tconn->queued, evt, entry);
	tep->fds[tconn->index].events = POLLIN | POLLOUT;
	pthread_mutex_unlock(&tconn->slock);

	/* try to progress txs */

	tcp_progress_conn_sends(conn);

	/* if unreliable, we are done since it is buffered internally */
	if (!is_reliable) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_SUCCESS;
	}

	ret = CCI_SUCCESS;

	/* if blocking, wait for completion */

	if (tx->flags & CCI_FLAG_BLOCKING) {
		while (tx->state != TCP_TX_COMPLETED)
			tcp_progress_ep(ep);

		/* get status and cleanup */
		ret = event->send.status;

		/* NOTE race with get_event()
		 *      get_event() must ignore sends with
		 *      flags & CCI_FLAG_BLOCKING */

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&ep->evts, evt, entry);
		tcp_put_tx_locked(tep, tx);
		pthread_mutex_unlock(&ep->lock);
	}

	debug(CCI_DB_FUNC, "exiting %s", func);
	return ret;
}

static int ctp_tcp_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle)
{
	cci__ep_t *ep = NULL;
	tcp_ep_t *tep = NULL;
	tcp_rma_handle_t *handle = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	tep = ep->priv;

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	handle->ep = ep;
	handle->length = length;
	handle->start = start;
	handle->flags = flags;
	handle->refcnt = 1;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = (uint64_t) ((uintptr_t) handle);

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int ctp_tcp_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle)
{
	int ret = CCI_EINVAL;
	tcp_rma_handle_t *handle =
	    (tcp_rma_handle_t *) ((uintptr_t) rma_handle);
	cci__ep_t *ep = NULL;
	tcp_ep_t *tep = NULL;
	tcp_rma_handle_t *h = NULL;
	tcp_rma_handle_t *tmp = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = handle->ep;
	tep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(h, &tep->handles, entry, tmp) {
		if (h == handle) {
			handle->refcnt--;
			if (handle->refcnt == 1)
				TAILQ_REMOVE(&tep->handles, handle, entry);
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

static int ctp_tcp_rma(cci_connection_t * connection,
		    const void *msg_ptr, uint32_t msg_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS, i, cnt, err = 0;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	tcp_rma_handle_t *local =
	    (tcp_rma_handle_t *) ((uintptr_t) local_handle);
	tcp_rma_handle_t *h = NULL;
	tcp_rma_op_t *rma_op = NULL;
	tcp_tx_t **txs = NULL;
	tcp_msg_type_t msg_type = flags & CCI_FLAG_WRITE ?
		TCP_MSG_RMA_WRITE : TCP_MSG_RMA_READ_REQUEST;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	tconn = conn->priv;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	tep = ep->priv;

	if (!local) {
		debug(CCI_DB_INFO, "%s: invalid local RMA handle", __func__);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &tep->handles, entry) {
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
	/* avoid modulo */
	rma_op->num_msgs = data_len / TCP_RMA_FRAG_SIZE;
	if ((rma_op->num_msgs * TCP_RMA_FRAG_SIZE) < data_len)
		rma_op->num_msgs++;
	rma_op->acked = -1;
	rma_op->status = CCI_SUCCESS;	/* for now */
	rma_op->context = (void *)context;
	rma_op->flags = flags;
	rma_op->msg_len = (uint16_t) msg_len;
	rma_op->tx = NULL;

	if (msg_len)
		rma_op->msg_ptr = (void *) msg_ptr;
	else
		rma_op->msg_ptr = NULL;

	debug(CCI_DB_MSG, "%s: starting RMA %s ***", __func__,
		flags & CCI_FLAG_WRITE ? "Write" : "Read");

	//if (flags & CCI_FLAG_WRITE) {
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
	for (i = 0; i < cnt; i++) {
		txs[i] = tcp_get_tx_locked(tep);
		if (!txs[i])
			err++;
	}
	if (err) {
		for (i = 0; i < cnt; i++) {
			if (txs[i])
				TAILQ_INSERT_HEAD(&tep->idle_txs,
						  &txs[i]->evt, entry);
		}
		local->refcnt--;
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
		    (uint64_t) i * (uint64_t) TCP_RMA_FRAG_SIZE;
		tcp_rma_header_t *rma_hdr =
		    (tcp_rma_header_t *) tx->buffer;

		rma_op->next = i + 1;
		tx->msg_type = msg_type;
		tx->flags = flags | CCI_FLAG_SILENT;
		tx->state = TCP_TX_QUEUED;
		tx->len = sizeof(*rma_hdr);
		tx->rma_len = TCP_RMA_FRAG_SIZE; /* for now */
		tx->rma_op = rma_op;
		tx->rma_id = i;

		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.event.send.status = CCI_SUCCESS; /* for now */
		tx->evt.event.send.context = (void *)context;
		tx->evt.event.send.connection = connection;
		tx->evt.conn = conn;

		if (i == (rma_op->num_msgs - 1)) {
			if (data_len % TCP_RMA_FRAG_SIZE)
				tx->rma_len = data_len % TCP_RMA_FRAG_SIZE;
		}

		tx->rma_ptr = local->start + local_offset + offset;

		debug(CCI_DB_MSG, "%s: %s local offset %"PRIu64" "
			"remote offset %"PRIu64" length %u", __func__,
			tcp_msg_type(msg_type),
			local_offset + offset, remote_offset + offset,
			tx->rma_len);

		if (msg_type == TCP_MSG_RMA_WRITE) {
			tcp_pack_rma_write(rma_hdr, tx->rma_len, tx->id,
						local_handle,
						local_offset + offset,
						remote_handle,
						remote_offset + offset);
		} else {
			tcp_pack_rma_read_request(rma_hdr, tx->rma_len, tx->id,
						local_handle,
						local_offset + offset,
						remote_handle,
						remote_offset + offset);
			tx->rma_ptr = NULL;
			tx->rma_len = 0;
		}
	}
	pthread_mutex_lock(&tconn->slock);
	for (i = 0; i < cnt; i++)
		TAILQ_INSERT_TAIL(&tconn->queued, &(txs[i])->evt, entry);
	TAILQ_INSERT_TAIL(&tconn->rmas, rma_op, rmas);
	tep->fds[tconn->index].events = POLLIN | POLLOUT;
	pthread_mutex_unlock(&tconn->slock);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	/* it is no longer needed */
	free(txs);

	ret = CCI_SUCCESS;

	tcp_progress_conn_sends(conn);

	CCI_EXIT;
	return ret;
}


static inline void tcp_drop_msg(cci_os_handle_t sock)
{
	char buf[4];
	struct sockaddr sa;
	socklen_t slen = sizeof(sa);

	recvfrom(sock, buf, 4, 0, &sa, &slen);
	return;
}

static void
tcp_handle_listen_socket(cci__ep_t *ep)
{
	int ret, fd = -1;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = NULL;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	char name[256 + 6];	/* POSIX HOST_NAME_MAX + tcp:// */

	CCI_ENTER;

	ret = accept(tep->sock, (struct sockaddr *)&sin, &slen);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "%s: accept() failed with %s (%d)",
			__func__, strerror(ret), ret);
		return;
	}
	fd = ret;

	ret = tcp_new_conn(ep, sin, fd, &conn);
	if (ret)
		goto out_with_fd;

	tconn = conn->priv;

	ret = tcp_monitor_fd(ep, conn, POLLIN);
	if (ret)
		goto out;

	tconn->status = TCP_CONN_PASSIVE1;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->passive, tconn, entry);
	pthread_mutex_unlock(&ep->lock);

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(tconn->sin, name, sizeof(name));
	debug(CCI_DB_CONN, "%s: new conn request from %s", __func__, name);

	CCI_EXIT;
	return;

out:
	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&tep->passive, tconn, entry);
	pthread_mutex_unlock(&ep->lock);

	/* TODO unmonitor fd */

	free(tconn);
	free(conn);
out_with_fd:
	close(fd);

	return;
}

static inline int
tcp_recv_msg(int fd, void *ptr, uint32_t len)
{
	int ret = CCI_SUCCESS;
	uint32_t offset = 0;
	static int count = 0;

	if (!len)
		goto out;

again:
	do {
		ret = recv(fd, ptr + offset, len - offset, 0);
		if (ret < 0) {
			ret = errno;
			if ((count++ & 0xFFFF) == 0xFFFF)
				debug(CCI_DB_MSG, "%s: recv() failed with %s (%u of %u bytes)",
					__func__, strerror(ret), offset, len);
			if (ret == EAGAIN)
				goto again;
			goto out;
		} else if (ret == 0) {
			debug(CCI_DB_MSG, "%s: recv() failed - peer closed "
				"connection", __func__);
			goto out;
		}
		offset += ret;
	} while (offset < len);

	ret = CCI_SUCCESS;
out:
	return ret;
}

static void
tcp_handle_conn_request(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx, uint32_t a)
{
	int ret;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_header_t *hdr = rx->buffer;
	tcp_handshake_t *hs = rx->buffer + sizeof(*hdr);
	cci_conn_attribute_t attr = a & 0xF;
	uint32_t len = (a >> 4) & 0xFFFF;
	uint32_t total = len + sizeof(*hs);
	uint32_t rx_cnt, mss, ka, ignore;

	ret = tcp_recv_msg(tconn->fd, hdr->data, total);
	if (ret) {
		/* TODO handle error */
		goto out;
	}

	tconn->status = TCP_CONN_PASSIVE2;

	tcp_parse_handshake(hs, &rx_cnt, &mss, &ka, &ignore);

	conn->keepalive_timeout = ka;
	if (mss < conn->connection.max_send_size)
		conn->connection.max_send_size = mss;

	conn->connection.attribute = attr;

	if (cci_conn_is_reliable(conn)) {
		tconn->max_tx_cnt = rx_cnt < ep->tx_buf_cnt ?
				    rx_cnt : ep->tx_buf_cnt;
	}

	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.event.request.attribute = attr;
	rx->evt.event.request.data_len = len;
	if (len)
		rx->evt.event.request.data_ptr = hdr->data + (uintptr_t) sizeof(*hs);
	else
		rx->evt.event.request.data_ptr = NULL;

	/* queue event on endpoint's completed event queue */

	debug(CCI_DB_CONN, "%s: recv'd conn request on conn %p", __func__, conn);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	return;
out:
	/* TODO send reject */

	/* we can cleanup now since the app never knew of this
	 * connection.
	 */
	close(tconn->fd);

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&tep->passive, tconn, entry);
	pthread_mutex_unlock(&ep->lock);

	//tcp_remove_conn(tep, tconn);

	free(tconn);
	free(conn);
	tcp_put_rx(rx);

	return;
}

static void
tcp_handle_conn_reply(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
			uint32_t a, uint32_t tx_id)
{
	int ret;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_header_t *hdr = rx->buffer;
	tcp_handshake_t *hs = rx->buffer + sizeof(*hdr);
	int reply = a & 0xFF;
	uint32_t total = sizeof(*hs);
	uint32_t rx_cnt, mss, ka, server_tx_id;
	tcp_tx_t *tx = &tep->txs[tx_id];

	ret = tcp_recv_msg(tconn->fd, hdr->data, total);
	if (ret) {
		/* TODO handle error */
		goto out;
	}

	debug(CCI_DB_CONN, "%s: conn %p is %s", __func__, conn,
		reply ? "rejected" : "ready");

	tconn->status = TCP_CONN_READY;

	tcp_parse_handshake(hs, &rx_cnt, &mss, &ka, &server_tx_id);

	if (mss < conn->connection.max_send_size)
		conn->connection.max_send_size = mss;

	if (cci_conn_is_reliable(conn)) {
		tconn->max_tx_cnt = rx_cnt < ep->tx_buf_cnt ?
				    rx_cnt : ep->tx_buf_cnt;
	}

	rx->evt.event.type = CCI_EVENT_CONNECT;
	rx->evt.event.connect.status = reply;
	rx->evt.event.connect.context = conn->connection.context;
	rx->evt.event.connect.connection = &conn->connection;

	tx->msg_type = TCP_MSG_CONN_ACK;
	tx->rma_op = NULL;
	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* pack the msg */

	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_conn_ack(hdr, server_tx_id);

	tx->len = sizeof(*hdr);
	tx->offset = 0;

	/* insert at tail of tep's queued list */

	tx->state = TCP_TX_QUEUED;

	pthread_mutex_lock(&tconn->slock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->slock);

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&tep->active, tconn, entry);
	TAILQ_INSERT_TAIL(&tep->conns, tconn, entry);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	tcp_progress_conn_sends(conn);

	return;
out:
	close(tconn->fd);

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&tep->active, tconn, entry);
	pthread_mutex_unlock(&ep->lock);

	//tcp_remove_conn(tep, tconn);

	free(tconn);
	free((void *)conn->uri);
	free(conn);
	tcp_put_rx(rx);

	return;
}

static void
tcp_handle_conn_ack(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx, uint32_t tx_id)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *tx = &tep->txs[tx_id];

	debug(CCI_DB_CONN, "%s: recv'd conn_ack from conn %p",
		__func__, conn);

	pthread_mutex_lock(&tconn->slock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->slock);

	pthread_mutex_lock(&ep->lock);
	tconn->status = TCP_CONN_READY;
	TAILQ_REMOVE(&tep->passive, tconn, entry);
	TAILQ_INSERT_TAIL(&tep->conns, tconn, entry);
	TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "%s: conn %p ready", __func__, conn);

	return;
}

static void
tcp_handle_send(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
		uint32_t a, uint32_t tx_id)
{
	int ret;
	tcp_conn_t *tconn = conn->priv;
	tcp_header_t *hdr = rx->buffer;
	uint32_t len = a & 0xFFFF;
	uint32_t total = len;

	ret = tcp_recv_msg(tconn->fd, hdr->data, total);
	if (ret) {
		/* TODO handle error */
		goto out;
	}

	rx->evt.event.type = CCI_EVENT_RECV;
	if (len)
		rx->evt.event.recv.ptr = hdr->data;
	else
		rx->evt.event.recv.ptr = NULL;
	rx->evt.event.recv.len = len;

	/* queue event on endpoint's completed event queue */

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = CCI_SUCCESS;
out:
	if (cci_conn_is_reliable(conn)) {
		tcp_ep_t *tep = ep->priv;
		tcp_tx_t *tx = NULL;
		tcp_header_t *ack;

		tx = tcp_get_tx(ep, 1);

		tx->msg_type = TCP_MSG_ACK;
		tx->len = sizeof(*ack);

		ack = tx->buffer;
		tcp_pack_ack(ack, tx_id, ret);

		pthread_mutex_lock(&tconn->slock);
		TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
		tep->fds[tconn->index].events = POLLIN | POLLOUT;
		pthread_mutex_unlock(&tconn->slock);
	}

	/* TODO close conn */

	return;
}

static void
tcp_handle_rma_write(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
			uint32_t len, uint32_t tx_id)
{
	int ret;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *tx = NULL;
	tcp_header_t *ack;
	tcp_rma_header_t *rma_header = rx->buffer; /* need to read more */
	uint32_t handle_len = 2 * sizeof(rma_header->local);
	uint64_t remote_handle, remote_offset;
	tcp_rma_handle_t *remote, *h = NULL;
	void *ptr = NULL;

	debug(CCI_DB_MSG, "%s: recv'ing RMA_WRITE on conn %p with len %u",
		__func__, conn, len);

	ret = tcp_recv_msg(tconn->fd, rma_header->header.data, handle_len);
	if (ret) {
		/* TODO handle error */
		goto out;
	}

	tcp_parse_rma_handle_offset(&rma_header->remote, &remote_handle,
				     &remote_offset);
	remote = (tcp_rma_handle_t *) (uintptr_t) remote_handle;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &tep->handles, entry) {
		if (h == remote) {
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != remote) {
		/* remote is no longer valid, send CCI_ERR_RMA_HANDLE */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote handle not valid", __func__);
		goto out;
	} else if (remote->start + (uintptr_t) remote_offset >
		   remote->start + (uintptr_t) remote->length) {
		/* offset exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote offset not valid", __func__);
		goto out;
	} else if (remote->start + (uintptr_t) remote_offset + (uintptr_t) len >
		   remote->start + (uintptr_t) remote->length) {
		/* length exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote length not valid", __func__);
		goto out;
	}

	/* valid remote handle, copy the data */
	debug(CCI_DB_INFO, "%s: recv'ing data into target buffer", __func__);
	ptr = remote->start + (uintptr_t) remote_offset;
	ret = tcp_recv_msg(tconn->fd, ptr, len);
	debug(CCI_DB_MSG, "%s: recv'd data into target buffer", __func__);
	if (ret)
		debug(CCI_DB_MSG, "%s: recv'ing RMA WRITE payload failed with %s",
			__func__, strerror(ret));
out:
	tx = tcp_get_tx(ep, 1);

	tx->msg_type = TCP_MSG_ACK;
	tx->len = sizeof(*ack);

	ack = tx->buffer;
	tcp_pack_ack(ack, tx_id, ret);

	pthread_mutex_lock(&tconn->slock);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	tep->fds[tconn->index].events = POLLIN | POLLOUT;
	pthread_mutex_unlock(&tconn->slock);

	tcp_put_rx(rx);

	return;
}

static void
tcp_handle_rma_read_request(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
			uint32_t len, uint32_t tx_id)
{
	int ret;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *tx = NULL;
	tcp_rma_header_t *read_request = rx->buffer; /* need to read more */
	tcp_rma_header_t *read_reply = NULL;
	uint32_t handle_len = 2 * sizeof(read_request->local);
	uint64_t local_handle, local_offset, remote_handle, remote_offset;
	tcp_rma_handle_t *remote, *h = NULL;

	debug(CCI_DB_MSG, "%s: recv'ing RMA_READ_REQUEST on conn %p with len %u",
		__func__, conn, len);

	ret = tcp_recv_msg(tconn->fd, read_request->header.data, handle_len);
	if (ret) {
		/* TODO handle error */
		goto out;
	}

	tcp_parse_rma_handle_offset(&read_request->local, &local_handle,
				     &local_offset);
	tcp_parse_rma_handle_offset(&read_request->remote, &remote_handle,
				     &remote_offset);
	remote = (tcp_rma_handle_t *) (uintptr_t) remote_handle;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &tep->handles, entry) {
		if (h == remote) {
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != remote) {
		/* remote is no longer valid, send CCI_ERR_RMA_HANDLE */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote handle not valid", __func__);
		goto out;
	} else if (remote->start + (uintptr_t) remote_offset >
		   remote->start + (uintptr_t) remote->length) {
		/* offset exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote offset not valid", __func__);
		goto out;
	} else if (remote->start + (uintptr_t) remote_offset + (uintptr_t) len >
		   remote->start + (uintptr_t) remote->length) {
		/* length exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: remote length not valid", __func__);
		goto out;
	}

	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		ret = CCI_ERR_RNR;
		goto out;
	}

	tx->msg_type = TCP_MSG_RMA_READ_REPLY;
	tx->flags = CCI_FLAG_SILENT;
	tx->state = TCP_TX_QUEUED;
	tx->len = sizeof(*read_reply);
	tx->rma_op = NULL;
	tx->rma_ptr = remote->start + (uintptr_t) remote_offset;
	tx->rma_len = len;

	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.status = CCI_SUCCESS; /* for now */
	tx->evt.event.send.context = NULL;
	tx->evt.event.send.connection = &conn->connection;
	tx->evt.conn = conn;

	read_reply = tx->buffer;
	tcp_pack_rma_read_reply(read_reply, len, tx_id,
			local_handle,
			local_offset,
			remote_handle,
			remote_offset);

	pthread_mutex_lock(&tconn->slock);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	tep->fds[tconn->index].events = POLLIN | POLLOUT;
	pthread_mutex_unlock(&tconn->slock);

out:
	if (ret) {
		tcp_header_t *ack;

		tx = tcp_get_tx(ep, 1);

		tx->msg_type = TCP_MSG_ACK;
		tx->len = sizeof(*ack);

		ack = tx->buffer;
		tcp_pack_ack(ack, tx_id, ret);

		pthread_mutex_lock(&tconn->slock);
		TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
		tep->fds[tconn->index].events = POLLIN | POLLOUT;
		pthread_mutex_unlock(&tconn->slock);
	}
	tcp_put_rx(rx);

	return;
}

static void
tcp_progress_rma(cci__ep_t *ep, cci__conn_t *conn,
			tcp_rx_t *rx, uint32_t status, tcp_tx_t *tx)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_rma_op_t *rma_op = tx->rma_op;
	tcp_msg_type_t msg_type = tx->msg_type;

	rma_op->acked = tx->rma_id;

	if (status && (rma_op->status == CCI_SUCCESS))
		rma_op->status = status;

	pthread_mutex_lock(&tconn->slock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->slock);

	if (tx->rma_id == (rma_op->num_msgs - 1)) {
		/* last segment - complete rma */
		tx->evt.event.send.status = rma_op->status;

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&tep->rma_ops, rma_op, entry);
		TAILQ_REMOVE(&tconn->rmas, rma_op, rmas);
		TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
		pthread_mutex_unlock(&ep->lock);
		free(rma_op);
		debug(CCI_DB_MSG, "%s: completed %s ***",
			__func__, tcp_msg_type(msg_type));
	} else if (rma_op->next == rma_op->num_msgs) {
		/* no more fragments, we don't need this tx anymore */
		debug(CCI_DB_MSG, "%s: releasing tx %p", __func__, tx);
		tcp_put_tx(tx);
	} else {
		/* send next fragment (or read fragment request) */
		int i = rma_op->next++;
		uint64_t offset =
		    (uint64_t) i * (uint64_t) TCP_RMA_FRAG_SIZE;
		tcp_rma_header_t *rma_hdr =
			(tcp_rma_header_t *) tx->buffer;
		tcp_rma_handle_t *local =
			(tcp_rma_handle_t *) ((uintptr_t) rma_op->local_handle);

		tx->state = TCP_TX_QUEUED;
		tx->rma_len = TCP_RMA_FRAG_SIZE; /* for now */
		tx->offset = 0;
		tx->rma_id = i;

		debug(CCI_DB_MSG, "%s: sending fragment %d at offset %"PRIu64,
			__func__, i, offset);

		if (i == (rma_op->num_msgs - 1)) {
			if (rma_op->data_len % TCP_RMA_FRAG_SIZE)
				tx->rma_len = rma_op->data_len % TCP_RMA_FRAG_SIZE;
		}

		tx->rma_ptr = (void*)(uintptr_t)(local->start + rma_op->local_offset + offset);

		debug(CCI_DB_MSG, "%s: %s local offset %"PRIu64" "
			"remote offset %"PRIu64" length %u", __func__,
			tcp_msg_type(msg_type),
			rma_op->local_offset + offset,
			rma_op->remote_offset + offset, tx->rma_len);

		if (msg_type == TCP_MSG_RMA_WRITE) {
			tcp_pack_rma_write(rma_hdr, tx->rma_len, tx->id,
					rma_op->local_handle,
					rma_op->local_offset + offset,
					rma_op->remote_handle,
					rma_op->remote_offset + offset);
		} else {
			tcp_pack_rma_read_request(rma_hdr, tx->rma_len, tx->id,
					rma_op->local_handle,
					rma_op->local_offset + offset,
					rma_op->remote_handle,
					rma_op->remote_offset + offset);
			tx->rma_ptr = NULL;
			tx->rma_len = 0;
		}

		pthread_mutex_lock(&tconn->slock);
		TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
		tep->fds[tconn->index].events = POLLIN | POLLOUT;
		pthread_mutex_unlock(&tconn->slock);
	}

	tcp_put_rx(rx);

	return;
}

static void
tcp_handle_rma_read_reply(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
				uint32_t len, uint32_t tx_id)
{
	int ret;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_rma_header_t *rma_header = rx->buffer; /* need to read more */
	uint32_t handle_len = 2 * sizeof(rma_header->local);
	uint64_t local_handle, local_offset;
	tcp_rma_handle_t *local, *h = NULL;
	void *ptr = NULL;
	tcp_tx_t *tx = &tep->txs[tx_id];

	debug(CCI_DB_MSG, "%s: recv'ing RMA_READ_REPLY on conn %p with len %u",
		__func__, conn, len);

	ret = tcp_recv_msg(tconn->fd, rma_header->header.data, handle_len);
	if (ret) {
		/* TODO handle error */
		debug(CCI_DB_MSG, "%s: recv_msg() returned %s",
			__func__, strerror(ret));
		goto out;
	}

	tcp_parse_rma_handle_offset(&rma_header->local, &local_handle,
				     &local_offset);
	local = (tcp_rma_handle_t *) (uintptr_t) local_handle;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &tep->handles, entry) {
		if (h == local) {
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != local) {
		/* local is no longer valid, send CCI_ERR_RMA_HANDLE */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: local handle not valid", __func__);
		goto out;
	} else if (local->start + (uintptr_t) local_offset >
		   local->start + (uintptr_t) local->length) {
		/* offset exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: local offset not valid", __func__);
		goto out;
	} else if (local->start + (uintptr_t) local_offset + (uintptr_t) len >
		   local->start + (uintptr_t) local->length) {
		/* length exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: local length not valid", __func__);
		goto out;
	}

	/* valid local handle, copy the data */
	debug(CCI_DB_INFO, "%s: recv'ing data into target buffer", __func__);
	ptr = local->start + (uintptr_t) local_offset;
	ret = tcp_recv_msg(tconn->fd, ptr, len);
	debug(CCI_DB_MSG, "%s: recv'd data into target buffer", __func__);
	if (ret)
		debug(CCI_DB_MSG, "%s: recv'ing RMA READ payload failed with %s",
			__func__, strerror(ret));
out:
	if (ret) {
		/* TODO we need to drain the message from the fd */
	}
	tcp_progress_rma(ep, conn, rx, ret, tx);

	return;
}

static void
tcp_handle_ack(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
		uint32_t a, uint32_t tx_id)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *tx = &tep->txs[tx_id];
	uint32_t status = a & 0xFF;

	debug(CCI_DB_MSG, "%s: conn %p acked tx %p (%s) with status %u",
		__func__, conn, tx, tcp_msg_type(tx->msg_type), status);

	switch (tx->msg_type) {
	case TCP_MSG_SEND:
		tx->evt.event.send.status = status ? CCI_ERR_DISCONNECTED : CCI_SUCCESS;
		if (status)
			debug((CCI_DB_MSG|CCI_DB_CONN), "%s: peer reported send completed "
				"with error %s", __func__,
				cci_strerror(&ep->endpoint, status));

		pthread_mutex_lock(&tconn->slock);
		TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
		pthread_mutex_unlock(&tconn->slock);

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
		tcp_put_rx_locked(tep, rx);
		pthread_mutex_unlock(&ep->lock);
		break;
	case TCP_MSG_RMA_WRITE:
		tcp_progress_rma(ep, conn, rx, status, tx);
		break;
	default:
		debug(CCI_DB_MSG, "%s: peer acked tx %p with type %s",
			__func__, tx, tcp_msg_type(tx->msg_type));
	}

	return;
}

static void
tcp_handle_recv(cci__ep_t *ep, cci__conn_t *conn)
{
	int ret;
	tcp_conn_t *tconn = conn->priv;
	tcp_rx_t *rx = NULL;
	tcp_header_t *hdr = NULL;
	uintptr_t len = sizeof(*hdr);
	tcp_msg_type_t type;
	uint32_t a, b;
	uint32_t q_rx = 0;

	debug(CCI_DB_MSG, "%s: conn %p recv'd message", __func__, conn);

	rx = tcp_get_rx(ep);
	if (!rx) {
		debug(CCI_DB_MSG, "%s: no rxs available", __func__);
		/* TODO peek at header, get msg id, send RNR */
		return;
	}

	rx->evt.conn = conn;
	hdr = rx->buffer;

	ret = tcp_recv_msg(tconn->fd, hdr, len);
	if (ret) {
		/* TODO handle error */
		debug(CCI_DB_MSG, "%s: tcp_recv_msg() returned %d", __func__, ret);
		q_rx = 1;
		tconn->status = TCP_CONN_CLOSING;
		goto out;
	}

	tcp_parse_header(hdr, &type, &a, &b);

	switch(type) {
	case TCP_MSG_CONN_REQUEST:
		tcp_handle_conn_request(ep, conn, rx, a);
		break;
	case TCP_MSG_CONN_REPLY:
		tcp_handle_conn_reply(ep, conn, rx, a, b);
		break;
	case TCP_MSG_CONN_ACK:
		tcp_handle_conn_ack(ep, conn, rx, b);
		break;
	case TCP_MSG_SEND:
		tcp_handle_send(ep, conn, rx, a, b);
		break;
	case TCP_MSG_ACK:
		tcp_handle_ack(ep, conn, rx, a, b);
		break;
	case TCP_MSG_RNR:
		break;
	case TCP_MSG_KEEPALIVE:
		break;
	case TCP_MSG_RMA_WRITE:
		tcp_handle_rma_write(ep, conn, rx, a, b);
		break;
	case TCP_MSG_RMA_READ_REQUEST:
		tcp_handle_rma_read_request(ep, conn, rx, a, b);
		break;
	case TCP_MSG_RMA_READ_REPLY:
		tcp_handle_rma_read_reply(ep, conn, rx, a, b);
		break;
	case TCP_MSG_RMA_INVALID:
		break;
	default:
		debug(CCI_DB_MSG, "%s: invalid msg type %d", __func__, type);
		break;
	}
out:
	if (q_rx)
		tcp_put_rx(rx);
	return;
}

static int
tcp_poll_events(cci__ep_t *ep)
{
	int ret = CCI_EAGAIN, i, count;
	tcp_ep_t *tep = ep->priv;

	if (!tep)
		return CCI_ENODEV;

	pthread_mutex_lock(&ep->lock);
	if (ep->closing || tep->is_polling) {
		pthread_mutex_unlock(&ep->lock);
		CCI_EXIT;
		return ret;
	}

	tep->is_polling++;
	assert(tep->is_polling == 1);
	pthread_mutex_unlock(&ep->lock);

	/* check for incoming messages (POLLIN) _and_
	 * connect completions (POLLOUT)
	 */
	ret = poll(tep->fds, tep->nfds, 0);
	if (ret < 1) {
		if (ret == -1) {
			ret = errno;
			debug(CCI_DB_EP, "%s: poll() returned %s",
				__func__, strerror(ret));
		} else {
			ret = CCI_EAGAIN;
		}
		goto out;
	}

	count = ret;
	debug(CCI_DB_EP, "%s: poll found %d events", __func__, count);

	i = 0;
	do {
		uint32_t found = 0;
		short revents = tep->fds[i].revents;
		cci__conn_t *conn = tep->c[i];
		tcp_conn_t *tconn = NULL;

		if (revents)
			debug(CCI_DB_CONN, "%s: revents 0x%x",
				__func__, revents);

		if (conn)
			tconn = conn->priv;

		if (revents & POLLIN) {
			found++;
			if (i == 0) {
				/* handle accept */
				tcp_handle_listen_socket(ep);
			} else {
				/* process recv */
				tcp_handle_recv(ep, conn);
			}
		}
		if (revents & POLLOUT) {
			if (tconn->status == TCP_CONN_ACTIVE1) {
				/*  send CONN_REQUEST on new connection */
				debug(CCI_DB_CONN, "%s: connect() completed", __func__);
				tconn->status = TCP_CONN_ACTIVE2;
				tep->fds[i].events = POLLIN | POLLOUT;
			}
			tcp_progress_conn_sends(conn);
			found++;
		}
		if (revents & POLLHUP) {
			/* handle disconnect */
			debug(CCI_DB_CONN, "%s: got POLLHUP on conn %p",
				__func__, conn);
			found++;
		}
		if (revents & POLLERR) {
			/* handle error */
			debug(CCI_DB_CONN, "%s: got POLLERR on conn %p",
				__func__, conn);
			found++;
		}
		if (!found && revents)
			debug(CCI_DB_WARN, "%s: unhandled revents %u",
				__func__, revents);
		if (found)
			count--;
		i++;

		if (count == tep->nfds)
			break; /* because OSX returns the wrong count from poll */
	} while (count);

out:
	pthread_mutex_lock(&ep->lock);
	/* TODO process queued changes to tep->fds, tep->c */
	tep->is_polling = 0;
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static void *tcp_progress_thread(void *arg)
{
	cci__ep_t *ep = (cci__ep_t *) arg;
	tcp_ep_t *tep;

	assert (ep);
	tep = ep->priv;

	while (!ep->closing)
		tcp_progress_ep(ep);

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}
