/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2014 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2014 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/private_config.h"

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
			     int flags, cci_rma_handle_t ** rma_handle);
static int ctp_tcp_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle);
static int ctp_tcp_rma(cci_connection_t * connection,
		    const void *header_ptr, uint32_t header_len,
		    cci_rma_handle_t * local_handle, uint64_t local_offset,
		    cci_rma_handle_t * remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags);

static void *tcp_progress_thread(void *arg);
static int tcp_progress_ep(cci__ep_t *ep);
static int tcp_poll_events(cci__ep_t *ep);
static int tcp_sendto(cci_os_handle_t sock, void *buf, int len,
			void *rma_ptr, uint32_t rma_len, uintptr_t *offset);
static inline void tcp_progress_conn_sends(cci__conn_t *conn);
static int handle_events (cci__ep_t *ep, uint32_t revents, cci__conn_t *conn);

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
			const char *interface = NULL;
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
				} else if (0 == strncmp("bufsize=", *arg, 8)) {
					const char *size_str = *arg + 8;
					tdev->bufsize = strtol(size_str, NULL, 0);
				} else if (0 == strncmp("interface=", *arg, 10)) {
					interface = *arg + 10;
				}
			}
			if (tdev->ip != 0 || interface) {
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
						if (interface &&
							!strcmp(interface, addr->ifa_name)) {
							memcpy(&tdev->ip, &sin->sin_addr, sizeof(tdev->ip));
							break;
						}
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
		cci_device_t *device;
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
	tglobals = NULL;

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

static inline int
tcp_new_conn(cci__ep_t *ep, struct sockaddr_in sin, int fd, cci__conn_t **connp);

static void
queue_conn(cci__ep_t *ep, cci__conn_t *conn);

static void
conn_decref(cci__ep_t *ep, cci__conn_t *conn);

static int ctp_tcp_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpointp,
				cci_os_handle_t * fd)
{
	int i, ret, one = 1;
	cci_os_handle_t sock;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
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

	TAILQ_INIT(&tep->conns);

	TAILQ_INIT(&tep->idle_txs);
	TAILQ_INIT(&tep->idle_rxs);
	TAILQ_INIT(&tep->handles);
	TAILQ_INIT(&tep->rma_ops);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		ret = errno;
		goto out;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
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

	ret = bind(sock, (const struct sockaddr *)&sin, sizeof(sin));
	if (ret) {
		ret = errno;
		goto out;
	}

	slen = sizeof(tep->sin);

	ret = getsockname(sock, (struct sockaddr *)&tep->sin, &slen);
	if (ret) {
		ret = errno;
		goto out;
	}

	memset(name, 0, sizeof(name));
	sprintf(name, "tcp://");
	tcp_sin_to_name(tep->sin, name + (uintptr_t) 6, sizeof(name) - 6);
	ep->uri = strdup(name);

	ret = tcp_new_conn(ep, sin, sock, &conn);
	if (ret)
		goto out;

	tconn = conn->priv;
	tconn->status = TCP_CONN_PASSIVE1;
	tconn->is_listener = 1;
	tconn->pfd.events = POLLIN;
	queue_conn(ep, conn);

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
	for (i = 0; i < (int) ep->tx_buf_cnt; i++) {
		tcp_tx_t *tx = &tep->txs[i];

		tx->id = i;
		tx->ctx = TCP_CTX_TX;

		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.ep = ep;
		tx->buffer = (void*)((uintptr_t)tep->tx_buf + (i * ep->buffer_len));
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
	for (i = 0; i < (int) ep->rx_buf_cnt; i++) {
		tcp_rx_t *rx = &tep->rxs[i];

		rx->ctx = TCP_CTX_RX;

		rx->evt.event.type = CCI_EVENT_RECV;
		rx->evt.ep = ep;
		rx->buffer = (void*)((uintptr_t)tep->rx_buf + (i * ep->buffer_len));
		rx->len = 0;
		TAILQ_INSERT_TAIL(&tep->idle_rxs, &rx->evt, entry);
	}

	ret = tcp_set_nonblocking(sock);
	if (ret)
		goto out;

	ret = listen(sock, SOMAXCONN);
	if (ret) {
		ret = errno;
		goto out;
	}

	tep->event_fd = 0;
	if (fd) {
#ifdef HAVE_SYS_EPOLL_H
		struct epoll_event ev;

		ret = epoll_create1 (0);
		if (ret == -1) {
			ret = errno;
			goto out;
		}
		tep->event_fd = ret;

		ev.data.ptr = conn;
		ev.events = EPOLLIN|EPOLLET;
		ret = epoll_ctl (tep->event_fd, EPOLL_CTL_ADD, sock, &ev);
		if (ret == -1) {
			ret = errno;
			goto out;
		}
#endif /* HAVE_SYS_EPOLL_H */
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

	conn_decref(ep, conn); /* drop our ref to the listening conn */

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	if (conn) {
		if (tconn) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&tep->conns, tconn, entry);
			pthread_mutex_unlock(&ep->lock);
			if (tconn->pfd.fd)
				close(tconn->pfd.fd);
		}
		free((char*)conn->uri);
		free(conn->priv);
	}
	free(conn);

	if (tep) {
		free(tep->txs);
		free(tep->tx_buf);

		free(tep->rxs);
		free(tep->rx_buf);

		if (sock)
			tcp_close_socket(sock);
		free(tep);
		ep->priv = NULL;
	}
	if (ep) {
		free(ep->uri);
	}
	*endpointp = NULL;
	CCI_EXIT;
	return ret;
}

static inline void
tcp_conn_set_closed(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	pthread_mutex_lock(&ep->lock);
	pthread_mutex_lock(&tconn->lock);
	if (tconn->status == TCP_CONN_READY) {
		if (tep->poll_conn == tconn)
			tep->poll_conn = NULL;
		close(tconn->pfd.fd);
		/* TODO complete queued and pending sends */
	}
	tconn->status = TCP_CONN_CLOSED;
	pthread_mutex_unlock(&tconn->lock);
	pthread_mutex_unlock(&ep->lock);

	return;
}

/* NOTE: the caller holds ep->lock and tconn->lock
 */
static void
tcp_conn_set_closing_locked(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	if (tconn->status > TCP_CONN_INIT) {
		close(tconn->pfd.fd);
		tconn->status = TCP_CONN_CLOSING;
		/* TODO complete queued and pending sends */

		if (tep->poll_conn == tconn)
			tep->poll_conn = NULL;
	}

	debug(CCI_DB_CONN, "%s: closing conn %p tconn %p status %s",
		__func__, (void*)conn, (void*)tconn, tcp_conn_status_str(tconn->status));

	return;
}

static void
tcp_conn_set_closing(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_conn_t *tconn = conn->priv;

	pthread_mutex_lock(&ep->lock);
	pthread_mutex_lock(&tconn->lock);
	tcp_conn_set_closing_locked(ep, conn);
	pthread_mutex_unlock(&tconn->lock);
	pthread_mutex_unlock(&ep->lock);
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

	debug(CCI_DB_EP, "%s: destroying %s (fd=%u)", __func__,
		ep->uri, tep->sock);

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);

	if (tep) {
		cci__conn_t *conn;
		tcp_conn_t *tconn;

		ep->closing = 1;

		pthread_mutex_unlock(&ep->lock);
		pthread_mutex_unlock(&dev->lock);
		tcp_terminate_threads (tep);
		pthread_mutex_lock(&dev->lock);
		pthread_mutex_lock(&ep->lock);

		while (!TAILQ_EMPTY(&tep->conns)) {
			tconn = TAILQ_FIRST(&tep->conns);
			conn = tconn->conn;
			TAILQ_REMOVE(&tep->conns, tconn, entry);
			free((char*)conn->uri);
			free(tconn);
			free(conn);
		}
		free(tep->txs);
		free(tep->tx_buf);

		free(tep->rxs);
		free(tep->rx_buf);

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
		tx->flags = 0;
		tx->evt.conn = NULL;
		debug(CCI_DB_MSG, "%s: getting tx %p buffer %p id %u",
			__func__, (void*)tx, (void*)tx->buffer, tx->id);
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
		debug(CCI_DB_MSG, "%s: allocating a tx ***", __func__);
		do {
			tx = calloc(1, sizeof(*tx));
		} while (!tx);
		do {
			tx->buffer = calloc(1, sizeof(tcp_header_t));
		} while (!tx->buffer);
	}

	return tx;
}

static inline void
tcp_put_tx_locked(tcp_ep_t *tep, tcp_tx_t *tx)
{
	assert(tx->ctx == TCP_CTX_TX);
	tx->state = TCP_TX_IDLE;
	debug(CCI_DB_MSG, "%s: putting tx %p buffer %p id %u",
		__func__, (void*)tx, (void*)tx->buffer, tx->id);
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
	assert(rx->ctx == TCP_CTX_RX);
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
	uintptr_t offset = 0;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	rx = container_of(evt, tcp_rx_t, evt);
	ep = evt->ep;
	tep = ep->priv;

	request_hdr = rx->buffer;
	client_tx_id = ntohl(request_hdr->b);

	conn = evt->conn;
	tconn = conn->priv;

	/* get a tx */
	tx = tcp_get_tx(ep, 0);
	if (!tx) {
		/* TODO send reject */
		/* TODO tep->nfds-- */

		close(tconn->pfd.fd);

		pthread_mutex_lock(&ep->lock);
		if (tep->poll_conn == tconn)
			tep->poll_conn = TAILQ_NEXT(tconn, entry);
		TAILQ_REMOVE(&tep->conns, tconn, entry);
		pthread_mutex_unlock(&ep->lock);

		free((char*)conn->uri);
		free(conn->priv);
		free(conn);
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	conn->connection.context = (void *)context;

	debug(CCI_DB_CONN, "%s: accepting conn %p", __func__, (void*)conn);

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
	tcp_pack_conn_reply(hdr, CCI_SUCCESS, client_tx_id);
	hs = (tcp_handshake_t *) ((uintptr_t)tx->buffer + sizeof(*hdr));
	tcp_pack_handshake(hs, ep->rx_buf_cnt,
			   conn->connection.max_send_size, 0, tx->id);

	tx->len = sizeof(*hdr) + sizeof(*hs);

	tx->state = TCP_TX_PENDING;
	tcp_sendto(tconn->pfd.fd, tx->buffer, tx->len, NULL, 0, &offset);

	assert((uint32_t)offset == tx->len);

	pthread_mutex_lock(&tconn->lock);
	TAILQ_INSERT_HEAD(&tconn->pending, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->lock);

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
	uint32_t a;
	uint32_t b;
	uintptr_t offset = 0;
	cci__evt_t *evt = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	tcp_header_t *hdr = NULL;
	tcp_header_t reject;
	tcp_msg_type_t type;
	char name[32];
	tcp_rx_t *rx = NULL;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	tep = ep->priv;
	conn = evt->conn;
	tconn = conn->priv;
	rx = container_of(evt, tcp_rx_t, evt);

	hdr = rx->buffer;
	tcp_parse_header(hdr, &type, &a, &b);

	/* prepare conn_reply */

	memset(&reject, 0, sizeof(reject));
	tcp_pack_conn_reply(&reject, CCI_ECONNREFUSED, b);

	tcp_sendto(tconn->pfd.fd, &reject, sizeof(reject),
			NULL, 0, &offset);

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(tconn->sin, name, sizeof(name));
	debug((CCI_DB_MSG | CCI_DB_CONN), "ep %d sending reject to %s",
	      tep->sock, name);

	tcp_conn_set_closing(ep, conn);
	conn_decref(ep, conn); /* drop list ref */

	CCI_EXIT;
	return CCI_SUCCESS;
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
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);

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
	tconn->refcnt = 1; /* one for the caller */
	tconn->pfd.fd = fd;
	if (fd != -1)
		tconn->status = TCP_CONN_ACTIVE1;
	else
		tconn->status = TCP_CONN_PASSIVE1;
	TAILQ_INIT(&tconn->rmas);
	TAILQ_INIT(&tconn->queued);
	TAILQ_INIT(&tconn->pending);

	memcpy(&tconn->sin, &sin, sizeof(sin));

	ret = pthread_mutex_init(&tconn->lock, &attr);
	if (ret)
		goto out_with_tconn;

	*connp = conn;

	return ret;

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
	cci__dev_t *dev = ep->dev;
	tcp_dev_t *tdev = dev->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_ep_t *tep = ep->priv;

	ret = tcp_set_nonblocking(tconn->pfd.fd);
	if (ret)
		goto out;

	ret = setsockopt(tconn->pfd.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (ret)
		goto out;

	if (tdev->bufsize) {
		uint32_t bufsize = tdev->bufsize;
		socklen_t opt_len = sizeof(bufsize);

		debug(CCI_DB_CONN, "%s: setting socket buffer sizes to %u",
			__func__, bufsize);

		ret = setsockopt(tconn->pfd.fd, SOL_SOCKET, SO_SNDBUF, &bufsize, opt_len);
		if (ret) debug(CCI_DB_EP, "%s: unable to set SO_SNDBUF (%s)",
				__func__, strerror(errno));

		ret = setsockopt(tconn->pfd.fd, SOL_SOCKET, SO_RCVBUF, &bufsize, opt_len);
		if (ret) debug(CCI_DB_EP, "%s: unable to set SO_RCVBUF (%s)",
				__func__, strerror(errno));

		ret = 0;
	}

	pthread_mutex_lock(&ep->lock);
	tconn->pfd.events = events;
	if (tep->event_fd) {
		/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
		struct epoll_event ev;

		ev.data.ptr = conn;
		ev.events = events;
		ret = epoll_ctl (tep->event_fd, EPOLL_CTL_MOD, tconn->pfd.fd, &ev);
                if (ret == -1) {
                        ret = errno;
		}
#else
		assert (0);
#endif
	}
	pthread_mutex_unlock(&ep->lock);

out:
	return ret;
}

static void
queue_conn(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->conns, tconn, entry);
	tconn->refcnt++; /* for the list */
	pthread_mutex_unlock(&ep->lock);
	return;
}

static int ctp_tcp_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout)
{
	int ret, fd = -1;
	cci__ep_t *ep = NULL;
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

	ret = tcp_new_conn(ep, sin, fd, &conn); /* gives us a ref on conn */
	if (ret)
		goto out;

	conn->connection.attribute = attribute;
	conn->connection.context = (void *)context;
	conn->uri = strdup(server_uri);

	/* set up tcp specific info */

	tconn = conn->priv;

	/* Dealing with keepalive, if set, include the keepalive timeout value into
	   the connection request */
	if ((((attribute & CCI_CONN_ATTR_RO) == CCI_CONN_ATTR_RO)
	     || ((attribute & CCI_CONN_ATTR_RU) == CCI_CONN_ATTR_RU))
	    && ep->keepalive_timeout != 0UL) {
		keepalive = ep->keepalive_timeout;
	}

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
	ptr = (void*)((uintptr_t)tx->buffer + tx->len);

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
	tconn->pfd.fd = ret;

        tx->state = TCP_TX_QUEUED;

        /* insert at tail of conn's queued list */
        pthread_mutex_lock(&tconn->lock);
        TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
        pthread_mutex_unlock(&tconn->lock);

        queue_conn(ep, conn);

	/* we will have to check for POLLOUT to determine when
	 * the connect completed
	 */
	if (!tep->event_fd) {
		/* Non-blocking mode */
		ret = tcp_monitor_fd(ep, conn, POLLOUT);
	} else {
		/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
		struct epoll_event ev;

		ev.data.ptr = conn;
		ev.events = EPOLLIN|EPOLLOUT;
		ret = epoll_ctl (tep->event_fd, EPOLL_CTL_ADD, tconn->pfd.fd, &ev);
		if (ret) {
			printf ("epoll_ctl() failed (%s)\n", strerror (errno));
		}

                ret = tcp_monitor_fd(ep, conn, EPOLLOUT);
                if (ret) 
                        goto out;
#else
		assert (0);
#endif /* HAVE_SYS_EPOLL_H */
	}

	if (ret)
		goto out;

again:
	/* ok, initiate connect()... */
	ret = connect(tconn->pfd.fd, (struct sockaddr *)&sin, slen);
	if (ret) {
		ret = errno;
		if (ret == EINTR) {
			debug(CCI_DB_CONN, "%s: connect() returned %s",
				__func__, strerror(ret));
			usleep(100000);
			goto again;
		}
		if (ret != EINPROGRESS) {
			debug(CCI_DB_CONN, "%s: connect() returned %s",
				__func__, strerror(ret));
			goto out;
		}
	} else {
		/* TODO connect completed, send CONN_REQUEST */
		debug(CCI_DB_CONN, "%s: connect() completed", __func__);
		tconn->pfd.events = POLLIN | POLLOUT;
	}

	conn_decref(ep, conn); /* drop our reference */

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	if (conn) {
		if (tconn) {
			pthread_mutex_lock(&ep->lock);
			if (tconn == tep->poll_conn)
				tep->poll_conn = TAILQ_NEXT(tconn, entry);
			TAILQ_REMOVE(&tep->conns, tconn, entry);
			pthread_mutex_unlock(&ep->lock);
		}

		free((char *)conn->uri);
#if CCI_DEBUG
		memset(tconn, 0xFF, sizeof(*tconn));
		memset(conn, 0xFF, sizeof(*conn));
#endif
		free(conn->priv);
		free(conn);
	}
	if (tx)
		tcp_put_tx(tx);
	CCI_EXIT;
	return ret;
}

static void
conn_decref_locked(cci__ep_t *ep, cci__conn_t *conn);

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

	tcp_conn_set_closed(ep, conn);
	conn_decref(ep, conn); /* drop application's ref */

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
		debug(CCI_DB_EP, "%s: found %s on conn %p", __func__,
			cci_event_type_str(ev->event.type), (void*)ev->conn);
		if (ev->event.type == CCI_EVENT_NONE) {
			tcp_tx_t *tx = container_of(ev, tcp_tx_t, evt);

			debug(CCI_DB_ALL, "%s: tx %s id %u state %u "
				"len %u flags %d rma_op %p rma_id %u", __func__,
				tcp_msg_type(tx->msg_type), tx->id, tx->state,
				tx->len, tx->flags, (void*)tx->rma_op, tx->rma_id);
		}
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
	cci__evt_t *evt;
	tcp_tx_t *tx;
	tcp_rx_t *rx;

	CCI_ENTER;

	if (!tglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);

	/* enqueue the event */

	switch (event->type) {
	case CCI_EVENT_SEND:
	case CCI_EVENT_ACCEPT:
		tx = container_of(evt, tcp_tx_t, evt);
		tcp_put_tx(tx);
		break;
	case CCI_EVENT_RECV:
	case CCI_EVENT_CONNECT_REQUEST:
		rx = container_of(evt, tcp_rx_t, evt);
		tcp_put_rx(rx);
		break;
	case CCI_EVENT_CONNECT:
		rx = container_of(evt, tcp_rx_t, evt);
		tx = (tcp_tx_t*)rx;
		if (rx->ctx == TCP_CTX_RX)
			tcp_put_rx(rx);
		else
			tcp_put_tx(tx);
		break;
	default:
		/* TODO */
		debug(CCI_DB_EP, "%s: unhandled %s event", __func__,
			cci_event_type_str(event->type));
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

	if (off < (uintptr_t) len) {
		ret = send(sock, (void*)((uintptr_t)buf + off), (int)((uintptr_t)len - off), 0);
		if (ret != -1) {
			off += ret;
			*offset += ret;
			ret = CCI_SUCCESS;
		} else {
			ret = errno;
			goto out;
		}
	}
	if (rma_ptr && (off >= (uintptr_t)len)) {
		off -= len;
		ret = send(sock, (void*)((uintptr_t)rma_ptr + off), rma_len - off, 0);
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

static inline void
tcp_progress_conn_sends(cci__conn_t *conn)
{
	int ret;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *put_tx = NULL;

	if (!conn || !conn->priv)
		return;

	tconn = conn->priv;

	pthread_mutex_lock(&tconn->lock);
	while (!TAILQ_EMPTY(&tconn->queued)) {
		cci__evt_t *evt = TAILQ_FIRST(&tconn->queued);
		tcp_tx_t *tx = container_of(evt, tcp_tx_t, evt);
		int off = tx->offset;

		if (tx->msg_type == TCP_MSG_CONN_REQUEST &&
			tconn->status == TCP_CONN_ACTIVE1)
			break;

		if (tx->msg_type == TCP_MSG_RMA_WRITE ||
			tx->msg_type == TCP_MSG_RMA_READ_REQUEST) {
			if (tx->rma_op->pending >= TCP_RMA_DEPTH &&
					tx->offset == 0)
				/* don't start this RMA fragment yet */
				break;
		}

		debug(CCI_DB_MSG, "%s: sending %s to conn %p",
			__func__, tcp_msg_type(tx->msg_type), (void*)conn);

		debug(CCI_DB_MSG, "%s: buffer %p len %u rma_ptr %p rma_len %u "
			"offset %"PRIuPTR" tx %u", __func__, (void*)tx->buffer,
			tx->len, (void*)tx->rma_ptr, tx->rma_len, tx->offset, tx->id);

		ret = tcp_sendto(tconn->pfd.fd, tx->buffer, tx->len,
				tx->rma_ptr, tx->rma_len, &tx->offset);
		if (ret) {
			if (ret == EAGAIN || ret == EINTR) {
				debug(CCI_DB_MSG, "%s: sending %s returned %s",
					__func__, tcp_msg_type(tx->msg_type),
					strerror(ret));
				break;
			} else {
				/* close connection? */
				debug(CCI_DB_CONN, "%s: send() returned %s (%d) - "
					"do we need to close the connection?",
					__func__, strerror(ret), ret);
			}
		} else {
			debug(CCI_DB_MSG, "%s: sent %u bytes to conn %p (offset %u off %u)",
				__func__, (int) tx->offset - off, (void*)conn, (int) tx->offset, off);
			if (tx->offset == (tx->len + tx->rma_len)) {
				debug(CCI_DB_MSG, "%s: completed %s send to conn %p",
					__func__, tcp_msg_type(tx->msg_type), (void*)conn);
				TAILQ_REMOVE(&tconn->queued, evt, entry);
				switch (tx->msg_type) {
				default:
					TAILQ_INSERT_TAIL(&tconn->pending, evt, entry);
					break;
				case TCP_MSG_RMA_READ_REPLY:
					put_tx = tx;
					break;
				case TCP_MSG_CONN_ACK:
					put_tx = tx;
					break;
				case TCP_MSG_ACK:
					if (!tx->evt.ep) {
						debug(CCI_DB_MSG, "%s: freeing "
							"tx %p", __func__, (void*)tx);
						free(tx->buffer);
						free(tx);
					} else {
						put_tx = tx;
					}
					break;
				}
			} else {
				break;
			}
		}
	}
	pthread_mutex_unlock(&tconn->lock);

	if (put_tx) {
		tcp_put_tx(put_tx);
	}

	return;
}

static int
tcp_progress_ep(cci__ep_t *ep)
{
	int ret = CCI_EAGAIN;

	tcp_poll_events(ep);

	return ret;
}

static inline void
tcp_queue_tx(tcp_ep_t *tep, tcp_conn_t *tconn, cci__evt_t *evt)
{
	pthread_mutex_lock(&tconn->lock);
	TAILQ_INSERT_TAIL(&tconn->queued, evt, entry);
	if (tep->event_fd) {
		/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
		int ret;
		struct epoll_event ev;
		ev.data.ptr = tconn->conn;
		ev.events = EPOLLIN|EPOLLOUT;
		ret = epoll_ctl (tep->event_fd, EPOLL_CTL_MOD, tconn->pfd.fd, &ev);
                if (ret == -1) {
			printf ("epoll_ctl() failed (%s)\n", strerror(errno));
                        return;
		}
#else
		assert (0);
#endif
	} else {
		/* Non-blocking mode */
		tconn->pfd.events = POLLIN | POLLOUT;
	}
	pthread_mutex_unlock(&tconn->lock);
}

static int tcp_send_common(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags,
		      tcp_rma_op_t *rma_op)
{
	int i, ret = CCI_SUCCESS, is_reliable = 0, data_len = 0;
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

	for (i = 0; i < (int) iovcnt; i++)
		data_len += data[i].iov_len;

	if (connection->max_send_size < (uint32_t) data_len) {
		debug(CCI_DB_MSG, "%s: total send length (%d) larger than "
			"max_send_size (%u)", func, data_len, connection->max_send_size);
		CCI_EXIT;
		return CCI_EMSGSIZE;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	tep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);
	tconn = conn->priv;

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	if (rma_op && rma_op->tx) {
		tx = rma_op->tx;
	} else {
		tx = tcp_get_tx(ep, 0);
		if (!tx) {
			tcp_progress_ep(ep);

			debug(CCI_DB_FUNC, "exiting %s", func);
			return CCI_ENOBUFS;
		}
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

	if (tconn->status < TCP_CONN_INIT) {
		debug(CCI_DB_CONN, "%s: trying to send on conn %p in state %s ***",
			__func__, (void*)conn, tcp_conn_status_str(tconn->status));
		tx->state = TCP_TX_COMPLETED;
		event->send.status = CCI_ERR_DISCONNECTED;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
		if (tep->event_fd) {
			WAKEUP_APP_THREAD(ep);
                }
		goto out;
	}

	/* pack buffer */
	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_send(hdr, data_len, tx->id);
	tx->len = sizeof(*hdr);

	ptr = (void*)((uintptr_t)tx->buffer + tx->len);

	/* copy user data to buffer
	 * NOTE: ignore CCI_FLAG_NO_COPY because we need to
	 send the entire packet in one shot. We could
	 use sendmsg() with an iovec. */

	for (i = 0; i < (int) iovcnt; i++) {
		if (!(rma_op && rma_op->tx)) {
			/* don't copy - the data is already in place
			 * from the rma() call */
			memcpy(ptr, data[i].iov_base, data[i].iov_len);
		}
		ptr = (void*)((uintptr_t)ptr + data[i].iov_len);
		tx->len += data[i].iov_len;
	}

	/* if unreliable, try to send */
	if (!is_reliable) {
    again:
		ret = tcp_sendto(tconn->pfd.fd, tx->buffer, tx->len, tx->rma_ptr,
				tx->rma_len, &tx->offset);
		if (ret == CCI_SUCCESS) {
			if (tx->offset < tx->len)
				goto again;
			/* queue event on enpoint's completed queue */
			tx->state = TCP_TX_COMPLETED;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_MSG, "sent UU msg with %d bytes",
			      tx->len - (int)sizeof(tcp_header_t));
			if (tep->event_fd) {
                                WAKEUP_APP_THREAD(ep);
                        }

			debug(CCI_DB_FUNC, "exiting %s", func);

			return CCI_SUCCESS;
		}

		/* if error, fall through */
		/* FIXME if disconnected, need to return error */
	}

	/* insert at tail of sock device's queued list */

	debug(CCI_DB_MSG, "%s: queuing MSG %p to conn %p", __func__, (void*)tx, (void*)conn);

	tx->state = TCP_TX_QUEUED;
	tcp_queue_tx(tep, tconn, evt);

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
		while (tx->state != TCP_TX_COMPLETED && tconn->status == TCP_CONN_READY)
			tcp_progress_ep(ep);

		/* get status and cleanup */
		ret = event->send.status;
		if (ret == CCI_SUCCESS && tconn->status != TCP_CONN_READY)
			ret = CCI_ERR_DISCONNECTED;

		/* NOTE race with get_event()
		 *      get_event() must ignore sends with
		 *      flags & CCI_FLAG_BLOCKING */

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&ep->evts, evt, entry);
		tcp_put_tx_locked(tep, tx);
		pthread_mutex_unlock(&ep->lock);
	}

out:
	debug(CCI_DB_FUNC, "exiting %s", func);
	return ret;
}

static int ctp_tcp_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS;
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	CCI_ENTER;

	if (msg_ptr && msg_len) {
		iovcnt = 1;
		iov.iov_base = (void *) msg_ptr;
		iov.iov_len = msg_len;
	}

	ret = tcp_send_common(connection, &iov, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int ctp_tcp_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	ret = tcp_send_common(connection, data, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int ctp_tcp_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, cci_rma_handle_t ** rma_handle)
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
	*((uint64_t*)&handle->rma_handle.stuff[0]) = (uintptr_t) handle;
	handle->flags = flags;
	handle->refcnt = 1;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&tep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = &handle->rma_handle;

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int ctp_tcp_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	int ret = CCI_EINVAL;
	const struct cci_rma_handle *lh = rma_handle;
	tcp_rma_handle_t *handle = (void*)((uintptr_t)lh->stuff[0]);
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
			if (handle->refcnt == 0)
				TAILQ_REMOVE(&tep->handles, handle, entry);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h == handle) {
		if (handle->refcnt == 0) {
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
		    cci_rma_handle_t * local_handle, uint64_t local_offset,
		    cci_rma_handle_t * remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS, i, cnt, err = 0;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *tconn = NULL;
	const struct cci_rma_handle *lh = local_handle;
	tcp_rma_handle_t *local = (tcp_rma_handle_t *)((uintptr_t)lh->stuff[0]);
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

	if ((data_len + local_offset) > local->length) {
		debug(CCI_DB_MSG,
		      "%s: RMA length + offset exceeds registered length "
		      "(%"PRIu64" + %"PRIu64" > %"PRIu64")",
		      __func__, data_len, local_offset, local->length);
		CCI_EXIT;
		return CCI_EINVAL;
	}

	conn = container_of(connection, cci__conn_t, connection);
	tconn = conn->priv;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	tep = ep->priv;

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

	if (msg_len) {
		rma_op->tx = tcp_get_tx(ep, 0);
		if (!rma_op->tx) {
			ret = CCI_ENOBUFS;
			goto out;
		}
		rma_op->msg_ptr = rma_op->tx->buffer;
		rma_op->msg_len = msg_len;
		memcpy(rma_op->msg_ptr, msg_ptr, msg_len);
	} else {
		rma_op->msg_ptr = NULL;
	}

	debug(CCI_DB_MSG, "%s: starting RMA %s ***", __func__,
		flags & CCI_FLAG_WRITE ? "Write" : "Read");

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
				tcp_put_tx_locked(tep, txs[i]);
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

		if (i == (int)(rma_op->num_msgs - 1)) {
			if (data_len % TCP_RMA_FRAG_SIZE)
				tx->rma_len = data_len % TCP_RMA_FRAG_SIZE;
		}

		tx->rma_ptr = (void*)((uintptr_t)local->start + local_offset + offset);

		debug(CCI_DB_MSG, "%s: %s local offset %"PRIu64" "
			"remote offset %"PRIu64" length %u", __func__,
			tcp_msg_type(msg_type),
			local_offset + offset, remote_offset + offset,
			tx->rma_len);

		if (msg_type == TCP_MSG_RMA_WRITE) {
			tcp_pack_rma_write(rma_hdr, tx->rma_len, tx->id,
						local_handle->stuff[0],
						local_offset + offset,
						remote_handle->stuff[0],
						remote_offset + offset);
		} else {
			tcp_pack_rma_read_request(rma_hdr, tx->rma_len, tx->id,
						local_handle->stuff[0],
						local_offset + offset,
						remote_handle->stuff[0],
						remote_offset + offset);
			tx->rma_ptr = NULL;
			tx->rma_len = 0;
		}
	}
	pthread_mutex_lock(&ep->lock);
	pthread_mutex_lock(&tconn->lock);
	for (i = 0; i < cnt; i++)
		TAILQ_INSERT_TAIL(&tconn->queued, &(txs[i])->evt, entry);
	TAILQ_INSERT_TAIL(&tconn->rmas, rma_op, rmas);
	if (tep->event_fd) {
		/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
		struct epoll_event ev;
                ev.data.ptr = tconn->conn;
                ev.events = EPOLLIN|EPOLLOUT;
                ret = epoll_ctl (tep->event_fd, EPOLL_CTL_MOD, tconn->pfd.fd, &ev);
                if (ret == -1) {
                        debug_ep (ep, CCI_DB_EP, "epoll_ctl() failed (%s)\n",
			          strerror(errno));
			ret = errno;
			goto out;
                }
#else
		assert (0);
#endif /* HAVE_SYS_EPOLL_H */
	} else {
		tconn->pfd.events = POLLIN | POLLOUT;
	}
	pthread_mutex_unlock(&tconn->lock);

	TAILQ_INSERT_TAIL(&tep->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	/* it is no longer needed */
	free(txs);

	ret = CCI_SUCCESS;

	tcp_progress_conn_sends(conn);

out:
	if (ret) {
		pthread_mutex_lock(&ep->lock);
		local->refcnt--;
		pthread_mutex_unlock(&ep->lock);
		free(rma_op);
	}
	CCI_EXIT;
	return ret;
}


/* Caller has a reference on listen_conn */
static void
tcp_handle_listen_socket(cci__ep_t *ep, cci__conn_t *listen_conn)
{
	int ret;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = NULL;
	tcp_conn_t *listen_tconn = listen_conn->priv, *tconn = NULL;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	char name[256 + 6];	/* POSIX HOST_NAME_MAX + tcp:// */

	CCI_ENTER;

	ret = tcp_new_conn(ep, sin, -1, &conn);
	if (ret)
		return;

	tconn = conn->priv;
	tep = ep->priv;

	ret = accept(listen_tconn->pfd.fd, (struct sockaddr *)&sin, &slen);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "%s: accept() failed with %s (%d)",
			__func__, strerror(ret), ret);
		goto out;
	}
	tconn->pfd.fd = ret;

	if (!tep->event_fd) {
		/* Non-blocking mode */
		ret = tcp_monitor_fd(ep, conn, POLLIN);
	} else {
		/* Blocking mode */
#if HAVE_SYS_EPOLL_H
		struct epoll_event ev;

		/* We setup first epoll for the new fd */
		ev.data.ptr = conn;
		ev.events = EPOLLIN|EPOLLET;
		ret = epoll_ctl (tep->event_fd, EPOLL_CTL_ADD, tconn->pfd.fd, &ev);
		if (ret) {
                        debug_ep (ep, CCI_DB_EP,
			          "epoll_ctl() failed (%s)\n",
			          strerror (errno));
                }

		/* Then we update the monitoring setup (which needs epoll to be setup) */
		ret = tcp_monitor_fd(ep, conn, EPOLLIN|EPOLLET);
                if (ret)
                        goto out;
#else
		assert (0);
#endif
	}

	if (ret)
		goto out;

	memset(name, 0, sizeof(name));
	tcp_sin_to_name(sin, name, sizeof(name));
	debug(CCI_DB_CONN, "%s: new conn request from %s", __func__, name);

	queue_conn(ep, conn);

	conn_decref(ep, conn); /* drop our ref */

	CCI_EXIT;
	return;

out:
	tcp_conn_set_closing(ep, conn);
	conn_decref(ep, conn); /* drop our ref */

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
		ret = recv(fd, (void*)((uintptr_t)ptr + offset), len - offset, 0);
		if (ret < 0) {
			ret = errno;
			if ((count++ & 0xFFFF) == 0xFFFF)
				debug(CCI_DB_MSG, "%s: recv() failed with %s (%u of %u bytes) "
					"ptr=%p", __func__, strerror(ret), offset, len,
					(void*)ptr);
			if (ret == EAGAIN)
				goto again;
			goto out;
		} else if (ret == 0) {
			debug(CCI_DB_MSG, "%s: recv() failed - peer closed "
				"connection", __func__);
			ret = CCI_ERROR;
			goto out;
		}
		offset += ret;
	} while (offset < len);

	ret = CCI_SUCCESS;
out:
	return ret;
}

/* Caller has ref on conn and will release it */
static void
tcp_handle_conn_request(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx, uint32_t a)
{
	int ret;
	tcp_conn_t *tconn = conn->priv;
	tcp_ep_t *tep = ep->priv;
	tcp_header_t *hdr = rx->buffer;
	tcp_handshake_t *hs = (void*)((uintptr_t)rx->buffer + sizeof(*hdr));
	cci_conn_attribute_t attr = a & 0xF;
	uint32_t len = (a >> 4) & 0xFFFF;
	uint32_t total = len + sizeof(*hs);
	uint32_t rx_cnt, mss, ka, ignore;

	ret = tcp_recv_msg(tconn->pfd.fd, hdr->data, total);
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

	debug(CCI_DB_CONN, "%s: recv'd conn request on conn %p", __func__, (void*)conn);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	if (tep->event_fd)
		WAKEUP_APP_THREAD (ep);

	return;
out:
	tcp_conn_set_closing(ep, conn);

	tcp_put_rx(rx);

	return;
}

/* The caller has a ref on conn and will release it */
static void
tcp_handle_conn_reply(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
			uint32_t a, uint32_t tx_id)
{
	int ret = CCI_SUCCESS;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_header_t *hdr = rx->buffer;
	tcp_handshake_t *hs = (void*)((uintptr_t)rx->buffer + sizeof(*hdr));
	int reply = a & 0xFF, accepted = 0;
	uint32_t total = sizeof(*hs);
	uint32_t rx_cnt, mss, ka, server_tx_id;
	tcp_tx_t *tx = &tep->txs[tx_id];

	accepted = reply == CCI_SUCCESS ? 1 : 0;

	debug(CCI_DB_CONN, "%s: conn %p is %s (a=%u)", __func__, (void*)conn,
		accepted ? "accepted" : "rejected", a);

	rx->evt.event.type = CCI_EVENT_CONNECT;
	rx->evt.event.connect.status = reply;
	rx->evt.event.connect.context = conn->connection.context;
	if (accepted)
		rx->evt.event.connect.connection = &conn->connection;
	else
		rx->evt.event.connect.connection = NULL;

	if (accepted) {
		ret = tcp_recv_msg(tconn->pfd.fd, hdr->data, total);
		if (ret) {
			/* TODO handle error */
			tcp_conn_set_closing(ep, conn);
			rx->evt.event.connect.status = CCI_ERROR;
			rx->evt.event.connect.connection = NULL;
			goto out;
		}

		tcp_parse_handshake(hs, &rx_cnt, &mss, &ka, &server_tx_id);

		if (mss < conn->connection.max_send_size)
			conn->connection.max_send_size = mss;

		if (cci_conn_is_reliable(conn)) {
			tconn->max_tx_cnt = rx_cnt < ep->tx_buf_cnt ?
						rx_cnt : ep->tx_buf_cnt;
		}
	} else {
		ret = CCI_ERROR;
		goto out;
	}

	tx->msg_type = TCP_MSG_CONN_ACK;
	tx->rma_op = NULL;
	tx->rma_ptr = NULL;
	tx->rma_len = 0;
	tx->evt.event.type = CCI_EVENT_NONE;

	/* pack the msg */

	hdr = (tcp_header_t *) tx->buffer;
	tcp_pack_conn_ack(hdr, server_tx_id);

	tx->len = sizeof(*hdr);
	tx->offset = 0;

	/* insert at tail of tep's queued list */

	tx->state = TCP_TX_QUEUED;

	pthread_mutex_lock(&tconn->lock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	TAILQ_INSERT_TAIL(&tconn->queued, &tx->evt, entry);
	tconn->status = TCP_CONN_READY;
	tconn->refcnt++; /* for the calling application */
	pthread_mutex_unlock(&tconn->lock);

	/* try to progress txs */
	tcp_progress_conn_sends(conn);

out:
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	if (ret) {
		pthread_mutex_lock(&tconn->lock);
		TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
		pthread_mutex_unlock(&tconn->lock);
		tcp_put_tx(tx);
		/* This will close our connection, the peer will get
		 * a POLLHUP and clean up accordingly */
		tcp_conn_set_closing(ep, conn);
		conn_decref(ep, conn); /* drop our ref and clean up */
	}

	if (tep->event_fd) {
		WAKEUP_APP_THREAD(ep);
	}

	return;
}

static void
tcp_handle_conn_ack(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx, uint32_t tx_id)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_tx_t *tx = &tep->txs[tx_id];

	debug(CCI_DB_CONN, "%s: recv'd conn_ack from conn %p",
		__func__, (void*)conn);

	pthread_mutex_lock(&tconn->lock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	pthread_mutex_unlock(&tconn->lock);

	pthread_mutex_lock(&ep->lock);
	tconn->status = TCP_CONN_READY;
	tconn->refcnt++; /* for calling the application */
	/* passive's refcnt goes to conns */
	TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	if (tep->event_fd) {
		WAKEUP_APP_THREAD(ep);
	}

	debug(CCI_DB_CONN, "%s: conn %p ready", __func__, (void*)conn);

	return;
}

static void
tcp_handle_send(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
		uint32_t a, uint32_t tx_id)
{
	int ret;
	tcp_conn_t *tconn = conn->priv;
	tcp_ep_t *tep = ep->priv;
	tcp_header_t *hdr = rx->buffer;
	uint32_t len = a & 0xFFFF;
	uint32_t total = len;

	debug(CCI_DB_MSG, "%s: recv'd MSG from conn %p with len %u",
		__func__, (void*)conn, len);

	ret = tcp_recv_msg(tconn->pfd.fd, hdr->data, total);
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
	rx->evt.event.recv.connection = &conn->connection;

	/* queue event on endpoint's completed event queue */

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);
	if (tep->event_fd) {
		WAKEUP_APP_THREAD(ep);
	}

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

		debug(CCI_DB_MSG, "%s: queuing ack for received tx %u", __func__, tx_id);

		tcp_queue_tx(tep, tconn, &tx->evt);
	}

	/* TODO close conn */

	return;
}

static void
tcp_handle_rma_write(cci__ep_t *ep, cci__conn_t *conn, tcp_rx_t *rx,
			uint32_t len, uint32_t tx_id)
{
	int ret = 0, valid = 1;
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
		__func__, (void*)conn, len);

	ret = tcp_recv_msg(tconn->pfd.fd, rma_header->header.data, handle_len);
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
		debug(CCI_DB_MSG, "%s: remote handle not valid", __func__);
		valid = 0;
	} else if (remote_offset > remote->length) {
		/* offset exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: remote offset not valid", __func__);
		valid = 0;
	} else if ((remote_offset + len) > remote->length) {
		/* length exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: remote length not valid", __func__);
		valid = 0;
	}

	if (valid) {
		/* valid remote handle, copy the data */
		debug(CCI_DB_INFO, "%s: recv'ing data into target buffer", __func__);
		ptr = (void*)((uintptr_t)remote->start + (uintptr_t) remote_offset);
		ret = tcp_recv_msg(tconn->pfd.fd, ptr, len);
		debug(CCI_DB_MSG, "%s: recv'd data into target buffer", __func__);
		if (ret)
			debug(CCI_DB_MSG, "%s: recv'ing RMA WRITE payload failed with %s",
				__func__, strerror(ret));
	} else {
		int l = 0;
		uint32_t offset = 0;
		char tmp[32];

		debug(CCI_DB_INFO, "%s: dumping %u bytes", __func__, len);
		do {
			l = sizeof(tmp);
			if (l > (int) (len - offset))
				l = len - offset;

			tcp_recv_msg(tconn->pfd.fd, tmp, l);
			offset += l;
		} while (offset < len);
	}
out:
	tx = tcp_get_tx(ep, 1);

	tx->msg_type = TCP_MSG_ACK;
	tx->len = sizeof(*ack);

	ack = tx->buffer;
	tcp_pack_ack(ack, tx_id, ret);

	tcp_queue_tx(tep, tconn, &tx->evt);

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
		__func__, (void*)conn, len);

	ret = tcp_recv_msg(tconn->pfd.fd, read_request->header.data, handle_len);
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
		debug(CCI_DB_MSG, "%s: remote handle not valid", __func__);
		goto out;
	} else if (remote_offset > remote->length) {
		/* offset exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: remote offset not valid", __func__);
		goto out;
	} else if ((remote_offset + len) > remote->length) {
		/* length exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: remote length not valid", __func__);
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
	tx->rma_ptr = (void*)((uintptr_t)remote->start + (uintptr_t) remote_offset);
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

	tcp_queue_tx(tep, tconn, &tx->evt);

out:
	if (ret) {
		tcp_header_t *ack;

		tx = tcp_get_tx(ep, 1);

		tx->msg_type = TCP_MSG_ACK;
		tx->len = sizeof(*ack);

		ack = tx->buffer;
		tcp_pack_ack(ack, tx_id, ret);

		tcp_queue_tx(tep, tconn, &tx->evt);
	}
	tcp_put_rx(rx);

	return;
}

static void
tcp_progress_rma(cci__ep_t *ep, cci__conn_t *conn,
			tcp_rx_t *rx, uint32_t status, tcp_tx_t *tx)
{
	int done = 0;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;
	tcp_rma_op_t *rma_op = tx->rma_op;
	tcp_msg_type_t msg_type = tx->msg_type;

	rma_op->acked = tx->rma_id;

	if (status && (rma_op->status == CCI_SUCCESS))
		rma_op->status = status;

	pthread_mutex_lock(&tconn->lock);
	TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
	if (rma_op->status && rma_op->pending == 0)
		done = 1;
	pthread_mutex_unlock(&tconn->lock);

	if ((tx->rma_id == (rma_op->num_msgs - 1)) || done) {
		int ret;

		/* last segment - complete rma */
		tx->evt.event.send.status = rma_op->status;
		if (rma_op->status || !rma_op->msg_ptr) {
			pthread_mutex_lock(&tconn->lock);
			TAILQ_REMOVE(&tconn->rmas, rma_op, rmas);
			pthread_mutex_unlock(&tconn->lock);
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&tep->rma_ops, rma_op, entry);
			TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
			pthread_mutex_unlock(&ep->lock);
			if (tep->event_fd) {
                                WAKEUP_APP_THREAD(ep);
                        }
			debug(CCI_DB_MSG, "%s: completed %s ***",
				__func__, tcp_msg_type(msg_type));
		} else {
			/* FIXME: This sends the completion MSG after the last
			 * RMA fragment is acked which adds a MSG latency
			 * on top of the RMA latency. Ideally, we would
			 * send the MSG just after sending the last
			 * RMA fragment which would knock off most of
			 * the MSG latency.
			 */
			struct iovec iov;

			iov.iov_base = rma_op->msg_ptr;
			iov.iov_len = rma_op->msg_len;

			pthread_mutex_lock(&tconn->lock);
			TAILQ_REMOVE(&tconn->rmas, rma_op, rmas);
			pthread_mutex_unlock(&tconn->lock);
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&tep->rma_ops, rma_op, entry);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_MSG, "%s: sending RMA completion MSG ***",
				__func__);
			ret = tcp_send_common(&conn->connection,
						&iov,
						1,
						rma_op->context,
						rma_op->flags,
						NULL);
			if (ret) {
				tx->evt.event.send.status = ret;
				pthread_mutex_lock(&ep->lock);
				TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
				pthread_mutex_unlock(&ep->lock);
				if (tep->event_fd) {
                         	       WAKEUP_APP_THREAD(ep);
                        	}
			} else {
				tcp_put_tx(tx);
			}
		}
		free(rma_op);
	} else if (rma_op->next == rma_op->num_msgs) {
		/* no more fragments, we don't need this tx anymore */
		debug(CCI_DB_MSG, "%s: releasing tx %p", __func__, (void*)tx);
		tcp_put_tx(tx);
	} else {
		/* send next fragment (or read fragment request) */
		int i = rma_op->next++;
		uint64_t offset =
		    (uint64_t) i * (uint64_t) TCP_RMA_FRAG_SIZE;
		tcp_rma_header_t *rma_hdr =
			(tcp_rma_header_t *) tx->buffer;
		const struct cci_rma_handle *ch = rma_op->local_handle;
		tcp_rma_handle_t *local = (void*)((uintptr_t)ch->stuff[0]);

		tx->state = TCP_TX_QUEUED;
		tx->rma_len = TCP_RMA_FRAG_SIZE; /* for now */
		tx->offset = 0;
		tx->rma_id = i;

		debug(CCI_DB_MSG, "%s: sending fragment %d at offset %"PRIu64,
			__func__, i, offset);

		if (i == (int)(rma_op->num_msgs - 1)) {
			if (rma_op->data_len % TCP_RMA_FRAG_SIZE)
				tx->rma_len = rma_op->data_len % TCP_RMA_FRAG_SIZE;
		}

		tx->rma_ptr = (void*)((uintptr_t)local->start + rma_op->local_offset + offset);

		debug(CCI_DB_MSG, "%s: %s local offset %"PRIu64" "
			"remote offset %"PRIu64" length %u", __func__,
			tcp_msg_type(msg_type),
			rma_op->local_offset + offset,
			rma_op->remote_offset + offset, tx->rma_len);

		if (msg_type == TCP_MSG_RMA_WRITE) {
			tcp_pack_rma_write(rma_hdr, tx->rma_len, tx->id,
					rma_op->local_handle->stuff[0],
					rma_op->local_offset + offset,
					rma_op->remote_handle->stuff[0],
					rma_op->remote_offset + offset);
		} else {
			tcp_pack_rma_read_request(rma_hdr, tx->rma_len, tx->id,
					rma_op->local_handle->stuff[0],
					rma_op->local_offset + offset,
					rma_op->remote_handle->stuff[0],
					rma_op->remote_offset + offset);
			tx->rma_ptr = NULL;
			tx->rma_len = 0;
		}

		tcp_queue_tx(tep, tconn, &tx->evt);
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
		__func__, (void*)conn, len);

	ret = tcp_recv_msg(tconn->pfd.fd, rma_header->header.data, handle_len);
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
		debug(CCI_DB_MSG, "%s: local handle not valid", __func__);
		goto out;
	} else if (local_offset > local->length) {
		/* offset exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: local offset not valid", __func__);
		goto out;
	} else if ((local_offset + len) > local->length) {
		/* length exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_MSG, "%s: local length not valid", __func__);
		goto out;
	}

	/* valid local handle, copy the data */
	debug(CCI_DB_INFO, "%s: recv'ing data into target buffer", __func__);
	ptr = (void*)((uintptr_t)local->start + (uintptr_t) local_offset);
	ret = tcp_recv_msg(tconn->pfd.fd, ptr, len);
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

	debug(CCI_DB_MSG, "%s: conn %p acked tx %p (%s) with status %u (conn "
		"status %s)", __func__, (void*)conn, (void*)tx,
		tcp_msg_type(tx->msg_type), status, tcp_conn_status_str(tconn->status));

	/* If disconnect() called, complete with disconnected */
	if (tconn->status < TCP_CONN_INIT)
		status = CCI_ERR_DISCONNECTED;

	switch (tx->msg_type) {
	case TCP_MSG_SEND:
		tx->evt.event.send.status = status ? CCI_ERR_DISCONNECTED : CCI_SUCCESS;
		if (status)
			debug((CCI_DB_MSG|CCI_DB_CONN), "%s: peer reported send completed "
				"with error %s", __func__,
				cci_strerror(&ep->endpoint, status));

		pthread_mutex_lock(&tconn->lock);
		TAILQ_REMOVE(&tconn->pending, &tx->evt, entry);
		pthread_mutex_unlock(&tconn->lock);

		pthread_mutex_lock(&ep->lock);
		if (!(tx->msg_type == TCP_MSG_CONN_REPLY &&
			tconn->status == TCP_CONN_CLOSING)) {
			if (tx->flags & CCI_FLAG_SILENT) {
				tcp_put_tx_locked(tep, tx);
			} else {
				tx->state = TCP_TX_COMPLETED;
				TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
				if (tep->event_fd) {
                         	       WAKEUP_APP_THREAD(ep);
                        	}
			}
		} else {
			/* We rejected this conn, clean it up */
			/* FIXME */
			/* FIXME do we need to put the tx? */
			pthread_mutex_lock(&tconn->lock);
			tcp_conn_set_closing_locked(ep, conn);
			pthread_mutex_unlock(&tconn->lock);
		}
		tcp_put_rx_locked(tep, rx);
		pthread_mutex_unlock(&ep->lock);
		break;
	case TCP_MSG_RMA_WRITE:
	case TCP_MSG_RMA_READ_REQUEST:
		tcp_progress_rma(ep, conn, rx, status, tx);
		break;
	default:
		debug(CCI_DB_MSG, "%s: peer acked tx %p with type %s",
			__func__, (void*)tx, tcp_msg_type(tx->msg_type));
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
	uint32_t len = sizeof(*hdr);
	tcp_msg_type_t type;
	uint32_t a, b;
	uint32_t q_rx = 0;
	int dbg = CCI_DB_MSG;

	debug(CCI_DB_MSG, "%s: conn %p recv'd message", __func__, (void*)conn);

	rx = tcp_get_rx(ep);
	if (!rx) {
		debug(CCI_DB_MSG, "%s: no rxs available", __func__);
		/* TODO peek at header, get msg id, send RNR */
		return;
	}

	rx->evt.conn = conn;
	hdr = rx->buffer;

	ret = tcp_recv_msg(tconn->pfd.fd, hdr, len);
	if (ret) {
		/* TODO handle error */
		debug(CCI_DB_MSG, "%s: tcp_recv_msg() returned %d (rx=%p hdr=%p)",
			__func__, ret, (void*)rx, (void*)hdr);
		q_rx = 1;
		tcp_conn_set_closing(ep, conn);
		goto out;
	}

	tcp_parse_header(hdr, &type, &a, &b);

	if (type == TCP_MSG_CONN_REQUEST ||
		type == TCP_MSG_CONN_REPLY ||
		type == TCP_MSG_CONN_ACK)
		dbg = CCI_DB_CONN;

	debug(dbg, "%s: msg type %s a=%u b=%u conn=%p",
		__func__, tcp_msg_type(type), a, b, (void*)conn);

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
		debug(CCI_DB_MSG, "%s: recv'd RMA_INVALID msg on conn %p",
			__func__, (void*)conn);
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

/* Get next conn from tep->conns
 *
 * Caller holds ep->lock
 *
 * Returns CCI_SUCCESS or CCI_EAGAIN
 * and sets connp accordingly
 */
static int
get_conn_locked(cci__ep_t *ep, cci__conn_t **connp)
{
	int ret = CCI_EAGAIN;
	cci__conn_t *conn = NULL;
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *last = tep->poll_conn, *end = NULL;

	if (TAILQ_EMPTY(&tep->conns)) {
		assert(last == NULL);
		goto out;
	}

	if (last == NULL)
		last = TAILQ_FIRST(&tep->conns);

	end = last;

	do {
		last = TAILQ_NEXT(last, entry);

		if (!last)
			last = TAILQ_FIRST(&tep->conns);

		pthread_mutex_lock(&last->lock);
		if (last->status > TCP_CONN_INIT) {
			if ((last->status == TCP_CONN_READY && last->refcnt == 2) ||
				(last->status < TCP_CONN_READY && last->refcnt == 1)) {
				conn = last->conn;
				last->refcnt++;
				pthread_mutex_unlock(&last->lock);
				ret = CCI_SUCCESS;
				break;
			}
		}
		pthread_mutex_unlock(&last->lock);
	} while (last != end);

	tep->poll_conn = last;
    out:
	*connp = conn;
	return ret;
}

/* Caller holds ep->lock */
static void
delete_conn_locked(cci__conn_t *conn)
{
	tcp_conn_t *tconn = conn->priv;

	assert(tconn->rx == NULL);
	assert(TAILQ_EMPTY(&tconn->queued));
	assert(TAILQ_EMPTY(&tconn->pending));
	assert(TAILQ_EMPTY(&tconn->rmas));

	free((char *)conn->uri);

#if CCI_DEBUG
	memset(tconn, 0xFF, sizeof(*tconn));
	memset(conn, 0xFF, sizeof(*conn));
#endif
	free(tconn);
	free(conn);
	return;
}

/* Caller holds ep->lock only */
static void
conn_decref_locked(cci__ep_t *ep, cci__conn_t *conn)
{
	tcp_ep_t *tep = ep->priv;
	tcp_conn_t *tconn = conn->priv;

	pthread_mutex_lock(&tconn->lock);
	tconn->refcnt--;

	if (tconn->refcnt == 0) {
		assert(tconn->status < TCP_CONN_INIT);
		TAILQ_REMOVE(&tep->conns, tconn, entry);
		pthread_mutex_unlock(&tconn->lock);
		delete_conn_locked(conn);
		goto out;
	}
	pthread_mutex_unlock(&tconn->lock);
    out:
	return;
}

static void
conn_decref(cci__ep_t *ep, cci__conn_t *conn)
{
	pthread_mutex_lock(&ep->lock);
	conn_decref_locked(ep, conn);
	pthread_mutex_unlock(&ep->lock);

	return;
}

/* Get the next conn to poll
 *
 * Maybe active, passive, or ready
 * Adds tconn->refcnt for the caller
 *
 * Return CCI_SUCCESS or CCI_EAGAIN
 */
static int
get_next_conn(cci__ep_t *ep, cci__conn_t **connp)
{
	int ret = CCI_EAGAIN;

	if (ep->closing)
		goto out;

	pthread_mutex_lock(&ep->lock);
	ret = get_conn_locked(ep, connp);
	pthread_mutex_unlock(&ep->lock);
    out:
	return ret;
}

static void
events_blocking_mode (uint32_t revents, char *str, int len)
{
        int bar = 0, offset = 0;

#ifdef HAVE_SYS_EPOLL_H
        memset(str, 0, len);

        if (revents & EPOLLIN) {
                sprintf(str, "EPOLLIN");
                bar = 1;
                offset = strlen(str);
                revents &= ~EPOLLIN;
        }
        if (revents & EPOLLOUT) {
                sprintf((void*)((uintptr_t)str + offset), "%sEPOLLOUT", bar ? "|" : "");
                bar = 1;
                offset = strlen(str);
                revents &= ~EPOLLOUT;
        }
        if (revents & EPOLLHUP) {
                sprintf((void*)((uintptr_t)str + offset), "%sEPOLLHUP", bar ? "|" : "");
                bar = 1;
                offset = strlen(str);
                revents &= ~EPOLLHUP;
        }
        if (revents & EPOLLERR) {
                sprintf((void*)((uintptr_t)str + offset), "%sEPOLLERR", bar ? "|" : "");
                bar = 1;
                offset = strlen(str);
                revents &= ~EPOLLERR;
        }
        if (revents) {
                sprintf((void*)((uintptr_t)str + offset), "%s0x%x", bar ? "|" : "", revents);
        }
        return;
#else
	/* We only support epoll for the blocking mode at the moment */
	assert (0);
#endif /* HAVE_SYS_EPOLL_H */
}

static void
events_non_blocking_mode (short revents, char *str, int len)
{
	int bar = 0, offset = 0;

	memset(str, 0, len);

	if (revents & POLLIN) {
		sprintf(str, "POLLIN");
		bar = 1;
		offset = strlen(str);
		revents &= ~POLLIN;
	}
	if (revents & POLLOUT) {
		sprintf((void*)((uintptr_t)str + offset), "%sPOLLOUT", bar ? "|" : "");
		bar = 1;
		offset = strlen(str);
		revents &= ~POLLOUT;
	}
	if (revents & POLLHUP) {
		sprintf((void*)((uintptr_t)str + offset), "%sPOLLHUP", bar ? "|" : "");
		bar = 1;
		offset = strlen(str);
		revents &= ~POLLHUP;
	}
	if (revents & POLLERR) {
		sprintf((void*)((uintptr_t)str + offset), "%sPOLLERR", bar ? "|" : "");
		bar = 1;
		offset = strlen(str);
		revents &= ~POLLERR;
	}
	if (revents & POLLNVAL) {
		sprintf((void*)((uintptr_t)str + offset), "%sPOLLNVAL", bar ? "|" : "");
		bar = 1;
		offset = strlen(str);
		revents &= ~POLLNVAL;
	}
	if (revents) {
		sprintf((void*)((uintptr_t)str + offset), "%s0x%x", bar ? "|" : "", revents);
	}
	return;
}

#define POLL_EVENTS_LEN	(64)

static int
handle_events (cci__ep_t *ep, uint32_t revents, cci__conn_t *conn)
{
	char 		str[POLL_EVENTS_LEN];
	tcp_conn_t 	*tconn	= NULL;
	tcp_ep_t	*tep	= NULL;
	char 		*prefix = "epoll()";

	tconn = conn->priv;
	tep = ep->priv;

	if (tep->event_fd) {
		events_blocking_mode (revents, str, POLL_EVENTS_LEN);
	} else {
		prefix = "poll()";
		events_non_blocking_mode ((short)revents, str, POLL_EVENTS_LEN);
	}
	debug(CCI_DB_EP, "%s: %s on conn %p found events %s", __func__,
	      prefix, (void*)conn, str);

	if (   (!tep->event_fd && (revents & POLLHUP))
#ifdef HAVE_SYS_EPOLL_H
	    || ( tep->event_fd && (revents & EPOLLHUP))
#endif /* HAVE_SYS_EPOLL_H */
	) {
		tcp_conn_status_t old_status = tconn->status;
		cci__evt_t *evt = NULL;
		tcp_tx_t *tx = NULL;

		/* handle disconnect */
		debug(CCI_DB_CONN, "%s: got POLLHUP on conn %p (%s) revents (0x%x)",
		        __func__, (void*)conn, tcp_conn_status_str(tconn->status), revents);

		tcp_conn_set_closing(ep, conn);

		switch (old_status) {
		case TCP_CONN_READY:
			/* TODO drain queues */
			break;
		case TCP_CONN_ACTIVE1:
		case TCP_CONN_ACTIVE2:
			pthread_mutex_lock(&tconn->lock);
			if (old_status == TCP_CONN_ACTIVE1 ||
			    !TAILQ_EMPTY(&tconn->queued)) {
				evt = TAILQ_FIRST(&tconn->queued);
				TAILQ_REMOVE(&tconn->queued, evt, entry);
			} else {
				evt = TAILQ_FIRST(&tconn->pending);
				TAILQ_REMOVE(&tconn->pending, evt, entry);
			}
			pthread_mutex_unlock(&tconn->lock);

			evt->event.connect.status = CCI_ETIMEDOUT;
			tx = container_of(evt, tcp_tx_t, evt);
			tx->state = TCP_TX_COMPLETED;

			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);
			if (tep->event_fd) {
				WAKEUP_APP_THREAD(ep);
			}
			break;
		case TCP_CONN_PASSIVE1:
		case TCP_CONN_PASSIVE2:
			/* handled in tcp_conn_set_closing_locked() */
			break;
		case TCP_CONN_CLOSING:
			fprintf(stderr, "%s: got POLLHUP on conn %p (%s) "
			        "with status TCP_CONN_CLOSING\n",
			        __func__, (void*)conn, conn->uri);
			break;
		default:
			debug(CCI_DB_CONN, "%s: connection status was %s",
			        __func__, tcp_conn_status_str(tconn->status));
		}

		goto out;
	}

	if (   (!tep->event_fd && (revents & POLLERR || revents & POLLNVAL))
#ifdef HAVE_SYS_EPOLL_H
	    || ( tep->event_fd && (revents & EPOLLERR))
#endif /* HAVE_SYS_EPOLL_H */
	) {
		/* handle error */
		/* TODO close connection */
		goto out;
	}
	if (   (!tep->event_fd && (revents & POLLIN))
#ifdef HAVE_SYS_EPOLL_H
	    || ( tep->event_fd && (revents & EPOLLIN))
	) {
#endif /* HAVE_SYS_EPOLL_H */
		if (tconn->is_listener == 1) {
			/* handle accept */
			tcp_handle_listen_socket(ep, conn);
		} else {
			/* process recv */
			tcp_handle_recv(ep, conn);
		}
		if (tep->event_fd) {
			/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
			revents &= ~EPOLLIN;
#else
			/* We only support epoll for the blocking mode at the moment */
			assert (0);
#endif /* HAVE_SYS_EPOLL_H */
		} else {
			/* Non-blocking mode */
			revents &= ~POLLIN;
		}
	}

	if (   (!tep->event_fd && (revents & POLLOUT))
#ifdef HAVE_SYS_EPOLL_H
	    || (tep->event_fd && (revents & EPOLLOUT))
#endif /* HAVE_SYS_EPOLL_H */
	) {
		int rc = 0;
		socklen_t err, *pe = &err, slen = sizeof(err);

		if (tconn->status == TCP_CONN_ACTIVE1) {
    again:
			rc = getsockopt(tconn->pfd.fd, SOL_SOCKET, SO_ERROR, (void*)pe, &slen);
			if (rc) {
				debug(CCI_DB_CONN, "%s: getsockopt() for conn %p (fd %d) "
				      "failed with %s", __func__, (void*)conn,
				      tconn->pfd.fd, strerror(errno));
				if (errno == EBADF) {
					/* TODO close connection */
					assert(0);
					goto out;
				} else if (errno == ENOMEM || errno == ENOBUFS) {
					goto again;
				}
			}

			if (err == 0) {
				/*  send CONN_REQUEST on new connection */
				debug(CCI_DB_CONN, "%s: conn %p connect() completed",
				      __func__, (void*)conn);
				pthread_mutex_lock(&ep->lock);
				tconn->status = TCP_CONN_ACTIVE2;
					if (tep->event_fd) {
						/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
						int ret;
						struct epoll_event ev;
	
						tconn->pfd.events = EPOLLIN | EPOLLOUT;
						ev.data.ptr = tconn->conn;
						ev.events = EPOLLIN|EPOLLOUT;
						ret = epoll_ctl (tep->event_fd, EPOLL_CTL_MOD, tconn->pfd.fd, &ev);
						if (ret == -1) {
							printf ("epoll_ctl() failed (%s)\n", strerror(errno));
							ret = errno;
							goto out;
						}
#else
						/* We only support epoll for the blocking mode at the moment */
						assert (0);
#endif /* HAVE_SYS_EPOLL_H */
					} else {
						/* Non-blocking mode */
						tconn->pfd.events = POLLIN | POLLOUT;
					}
					pthread_mutex_unlock(&ep->lock);
			} else {
				/* TODO close connection */
				assert(0);
				tcp_conn_set_closing(ep, conn);
				goto out;
			}
		}
		tcp_progress_conn_sends(conn);
		if (tep->event_fd) {
#ifdef HAVE_SYS_EPOLL_H
			revents &= ~EPOLLOUT;
#else
			/* We only support epoll for the blocking mode at the moment */
			assert (0);
#endif
		} else {
			revents &= ~POLLOUT;
		}
	}

#if CCI_DEBUG
	if (revents) {
		if (tep->event_fd) {
			/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
			events_blocking_mode (revents, str, POLL_EVENTS_LEN);
#else
			/* We only support epoll for the blocking mode at the moment */
			assert (0);
#endif
		} else {
			events_non_blocking_mode (revents, str, POLL_EVENTS_LEN);
		}
		debug(CCI_DB_WARN, "%s: conn %p has unhandled revents %s",
		      __func__, (void*)conn, str);
	}
#endif

out:
	conn_decref(ep, conn);

	return CCI_SUCCESS;
}

static int
tcp_poll_events(cci__ep_t *ep)
{
	int ret = CCI_EAGAIN;
	/*char str[POLL_EVENTS_LEN];*/
	tcp_ep_t *tep = ep->priv;
	cci__conn_t *conn = NULL;
	tcp_conn_t *tconn = NULL;
	uint32_t revents = 0;


	if (!tep) {
		return CCI_ENODEV;
	}

	if (tep->event_fd) {
		/* Blocking mode */
#ifdef HAVE_SYS_EPOLL_H
		struct epoll_event events[POLL_EVENTS_LEN];

		ret = epoll_wait (tep->event_fd, events, POLL_EVENTS_LEN, -1);

		if (ep->closing == 1)
			return CCI_SUCCESS;

                if (ret > 0) {
                        int i;

                        for (i = 0; i < ret; i++) {
				conn = events[i].data.ptr;
				revents = events[i].events;
				tconn = conn->priv;
				if (tconn != NULL && tconn->status > TCP_CONN_INIT) {
                                	if ((tconn->status == TCP_CONN_READY && tconn->refcnt == 2) ||
                                   	    (tconn->status < TCP_CONN_READY && tconn->refcnt == 1))
					{
						pthread_mutex_lock(&tconn->lock);
                                        	tconn->refcnt++;
                                       		pthread_mutex_unlock(&tconn->lock);
						handle_events (ep, revents, conn);
					}
				}
			}
		}
#else
		/* We only support epoll for the blocking mode at the moment */
		assert (0);
#endif /* HAVE_SYS_EPOLL_H */
	} else {
		/* Non-blocking mode */

		ret = get_next_conn(ep, &conn);
        	if (ret) {
                	goto out;
        	}

		tconn = conn->priv;
        	/* Note: we have a ref on this conn */

		if (!tconn->is_listener && tconn->status > TCP_CONN_INIT)
			tconn->pfd.events = POLLIN | POLLOUT;
	
		ret = poll(&tconn->pfd, 1, 0);
		if (ret < 1) {
			if (ret == -1) {
				ret = errno;
				debug(CCI_DB_EP, "%s: poll() on conn %p returned %s",
				      __func__, (void*)conn, strerror(ret));
			} else {
				ret = CCI_EAGAIN;
			}
			
			conn_decref(ep, conn);
			goto out;
		}

		revents = (uint32_t)tconn->pfd.revents;
		handle_events (ep, revents, conn);
	}

 out:
	return ret;
}

static void *tcp_progress_thread(void *arg)
{
	cci__ep_t *ep = (cci__ep_t *) arg;
	/*tcp_ep_t *tep;*/

	assert (ep);
	/*tep = ep->priv;*/

	while (!ep->closing) {
		tcp_progress_ep(ep);
	}

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}
