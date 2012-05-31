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
#endif //   __INTEL_COMPILER

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/ctp/ctp.h"
#include "ctp_sock.h"

#define DEBUG_RNR 0

#if DEBUG_RNR
#include <stdbool.h>
bool conn_established = false;
#endif

sock_globals_t *sglobals = NULL;
static int threads_running = 0;

/*
 * Local functions
 */
static int ctp_sock_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_sock_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_sock_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status);
static int ctp_sock_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpoint,
				cci_os_handle_t * fd);
static int ctp_sock_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_sock_accept(cci_event_t *event, const void *context);
static int ctp_sock_reject(cci_event_t *conn_req);
static int ctp_sock_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout);
static int ctp_sock_disconnect(cci_connection_t * connection);
static int ctp_sock_set_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, const void *val);
static int ctp_sock_get_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, void *val);
static int ctp_sock_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_sock_get_event(cci_endpoint_t * endpoint,
			  cci_event_t ** const event);
static int ctp_sock_return_event(cci_event_t * event);
static int ctp_sock_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags);
static int ctp_sock_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags);
static int ctp_sock_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle);
static int ctp_sock_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle);
static int ctp_sock_rma(cci_connection_t * connection,
		    const void *header_ptr, uint32_t header_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags);

static uint8_t sock_ip_hash(in_addr_t ip, uint16_t port);
static void sock_progress_sends(cci__ep_t * ep);
static void *sock_progress_thread(void *arg);
static void *sock_recv_thread(void *arg);
static int sock_sendto(cci_os_handle_t sock, void *buf, int len,
			void *rma_ptr, uint16_t rma_len,
		       const struct sockaddr_in sin);
static void sock_ack_conns(cci__ep_t * ep);
static inline int pack_piggyback_ack (cci__ep_t *ep,
            sock_conn_t *sconn, sock_tx_t *tx);

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
cci_plugin_ctp_t cci_ctp_sock_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "sock",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 30,

	 /* Bootstrap function pointers */
	 cci_ctp_sock_post_load,
	 cci_ctp_sock_pre_unload,
	 },

	/* API function pointers */
	ctp_sock_init,
	ctp_sock_finalize,
	ctp_sock_strerror,
	ctp_sock_create_endpoint,
	ctp_sock_destroy_endpoint,
	ctp_sock_accept,
	ctp_sock_reject,
	ctp_sock_connect,
	ctp_sock_disconnect,
	ctp_sock_set_opt,
	ctp_sock_get_opt,
	ctp_sock_arm_os_handle,
	ctp_sock_get_event,
	ctp_sock_return_event,
	ctp_sock_send,
	ctp_sock_sendv,
	ctp_sock_rma_register,
	ctp_sock_rma_deregister,
	ctp_sock_rma
};

static inline void
sock_sin_to_name(struct sockaddr_in sin, char *buffer, int len)
{
	snprintf(buffer, len, "%s:%d", inet_ntoa(sin.sin_addr),
		 ntohs(sin.sin_port));
	return;
}

static inline const char *sock_msg_type(sock_msg_type_t type)
{
	switch (type) {
	case SOCK_MSG_CONN_REQUEST:
		return "conn_request";
	case SOCK_MSG_CONN_REPLY:
		return "conn_reply";
	case SOCK_MSG_CONN_ACK:
		return "conn_ack";
	case SOCK_MSG_DISCONNECT:
		return "disconnect";
	case SOCK_MSG_SEND:
		return "send";
	case SOCK_MSG_RNR:
		return "receiver not ready";
	case SOCK_MSG_KEEPALIVE:
		return "keepalive";
	case SOCK_MSG_PING:
		return "ping for RTTM";
	case SOCK_MSG_ACK_ONLY:
		return "ack_only";
	case SOCK_MSG_ACK_UP_TO:
		return "ack_up_to";
	case SOCK_MSG_SACK:
		return "selective ack";
	case SOCK_MSG_RMA_WRITE:
		return "RMA write";
	case SOCK_MSG_RMA_WRITE_DONE:
		return "RMA write done";
	case SOCK_MSG_RMA_READ_REQUEST:
		return "RMA read request";
	case SOCK_MSG_RMA_READ_REPLY:
		return "RMA read reply";
	case SOCK_MSG_RMA_INVALID:
		return "invalid RMA handle";
	case SOCK_MSG_INVALID:
		assert(0);
		return "invalid";
	case SOCK_MSG_TYPE_MAX:
		assert(0);
		return "type_max";
	}
	return NULL;
}

static inline int sock_create_threads (cci__ep_t *ep)
{
	int ret;
	sock_ep_t *sep;

	assert (ep);

	sep = ep->priv;

	ret = pthread_create(&sep->recv_tid, NULL, sock_recv_thread, (void*)ep);
	if (ret)
		goto out;

	ret = pthread_create(&sep->progress_tid, NULL, sock_progress_thread, (void*)ep);
	if (ret)
		goto out;

out:
	return ret;
}

static inline int sock_terminate_threads (sock_ep_t *sep)
{
	assert (sep);

	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

	pthread_join(sep->progress_tid, NULL);
	pthread_join(sep->recv_tid, NULL);

	return CCI_SUCCESS;
}

static int ctp_sock_init(cci_plugin_ctp_t *plugin,
		     uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret;
	cci__dev_t *dev, *ndev;
	cci_device_t **devices;
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *addrs = NULL, *addr;
#endif

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

	srandom((unsigned int)sock_get_usecs());

#ifdef HAVE_GETIFADDRS
        getifaddrs(&addrs);
	/* ignore errors, we've use defaults */
#endif

	devices = calloc(CCI_MAX_DEVICES, sizeof(*sglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	if (!globals->configfile) {
#ifdef HAVE_GETIFADDRS
		if (addrs) {
			for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
				struct cci_device *device;
				sock_dev_t *sdev;
				uint32_t mtu = (uint32_t) -1;
				struct sockaddr_in *sai;

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
				dev->priv = calloc(1, sizeof(*sdev));
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
				device->transport = strdup("sock");
				device->name = strdup(addr->ifa_name);

				sdev = dev->priv;

				sai = (struct sockaddr_in *) addr->ifa_addr;
				memcpy(&sdev->ip, &sai->sin_addr, sizeof(sai->sin_addr));

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
					device->max_send_size = SOCK_DEFAULT_MSS;
				} else {
					/* compute mss from mtu */
					if (mtu > SOCK_UDP_MAX)
						mtu = SOCK_UDP_MAX;
					mtu -= SOCK_MAX_HDR_SIZE;
					assert(mtu >= SOCK_MIN_MSS); /* FIXME rather ignore the device? */
					device->max_send_size = mtu;
				}

				cci__add_dev(dev);
				devices[sglobals->count] = device;
				sglobals->count++;
				threads_running = 1;
			}
		}
#endif

	} else
	/* find devices that we own */
		TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("sock", dev->device.transport)) {
			const char * const *arg;
			struct cci_device *device;
			sock_dev_t *sdev;
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

			dev->priv = calloc(1, sizeof(*sdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}

			sdev = dev->priv;
            sdev->port = 0;

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

					sdev->ip = inet_addr(ip);	/* network order */
				} else if (0 == strncmp("mtu=", *arg, 4)) {
					const char *mtu_str = *arg + 4;
					mtu = strtol(mtu_str, NULL, 0);
				 }
			}
			if (sdev->ip != 0) {
				/* try to get the actual values now */
#ifdef HAVE_GETIFADDRS
				if (addrs) {
					for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
						struct sockaddr_in *sai;
						if (!addr->ifa_addr)
							continue;
						if (addr->ifa_addr->sa_family != AF_INET)
							continue;
						sai = (struct sockaddr_in *) addr->ifa_addr;
						if (!memcmp(&sdev->ip, &sai->sin_addr, sizeof(sdev->ip)))
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
					device->max_send_size = SOCK_DEFAULT_MSS;
				} else {
					/* compute mss from mtu */
					if (mtu > SOCK_UDP_MAX)
						mtu = SOCK_UDP_MAX;
					mtu -= SOCK_MAX_HDR_SIZE;
					assert(mtu >= SOCK_MIN_MSS); /* FIXME rather ignore the device? */
					device->max_send_size = mtu;
				}
				/* queue to the main device list now */
				TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
				cci__add_dev(dev);
				devices[sglobals->count] = device;
				sglobals->count++;
				threads_running = 1;
			}
		}
		}

	devices =
	    realloc(devices, (sglobals->count + 1) * sizeof(cci_device_t *));
	devices[sglobals->count] = NULL;

	*((cci_device_t ***) & sglobals->devices) = devices;

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
	if (sglobals) {
		free((void *)sglobals);
		sglobals = NULL;
	}
#ifdef HAVE_GETIFADDRS
	if (addrs) {
		freeifaddrs(addrs);
	}
#endif
	CCI_EXIT;
	return ret;
}

static const char *ctp_sock_strerror(cci_endpoint_t * endpoint,
				 enum cci_status status)
{
	CCI_ENTER;

	CCI_EXIT;
	return NULL;
}

/* NOTE the CCI layer has already unbound all devices
 *      and destroyed all endpoints.
 *      All we need to do if free dev->priv
 */
static int ctp_sock_finalize(cci_plugin_ctp_t * plugin)
{
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	TAILQ_FOREACH(dev, &globals->devs, entry)
		if (!strcmp(dev->device.transport, "sock"))
			free(dev->priv);

	free(sglobals->devices);
	free((void *)sglobals);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static inline int
sock_set_nonblocking(cci_os_handle_t sock, sock_fd_type_t type, void *p)
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

static inline void sock_close_socket(cci_os_handle_t sock)
{
	close(sock);
	return;
}

static int ctp_sock_create_endpoint(cci_device_t * device,
				int flags,
				cci_endpoint_t ** endpointp,
				cci_os_handle_t * fd)
{
	int i, ret;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	sock_dev_t *sdev;
	struct sockaddr_in sin;
	socklen_t slen;
	char name[40];

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	if (0 != strcmp("sock", device->transport)) {
		ret = CCI_EINVAL;
		goto out;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*sep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ep->rx_buf_cnt = SOCK_EP_RX_CNT;
	ep->tx_buf_cnt = SOCK_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size + SOCK_MAX_HDRS;
	ep->tx_timeout = SOCK_EP_TX_TIMEOUT_SEC * 1000000;

	sep = ep->priv;
	sep->ids = calloc(SOCK_NUM_BLOCKS, sizeof(*sep->ids));
	if (!sep->ids) {
		ret = CCI_ENOMEM;
		goto out;
	}
    sep->closing = 0;
    pthread_mutex_init (&sep->progress_mutex, NULL);
    pthread_cond_init (&sep->wait_condition, NULL);

	sep->sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sep->sock == -1) {
		ret = errno;
		goto out;
	}
	/* bind socket to device */
	sdev = dev->priv;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = sdev->ip;
    if (sdev->port != 0)
        sin.sin_port = sdev->port;

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
	sock_sin_to_name(sep->sin, name + (uintptr_t) 5, sizeof(name) - 5);
	ep->uri = strdup(name);

	for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
		TAILQ_INIT(&sep->conn_hash[i]);
		TAILQ_INIT(&sep->active_hash[i]);
	}

	TAILQ_INIT(&sep->txs);
	TAILQ_INIT(&sep->idle_txs);
	TAILQ_INIT(&sep->rxs);
	TAILQ_INIT(&sep->idle_rxs);
	TAILQ_INIT(&sep->handles);
	TAILQ_INIT(&sep->rma_ops);
    TAILQ_INIT(&sep->queued);
    TAILQ_INIT(&sep->pending);

	/* alloc txs */
	for (i = 0; i < ep->tx_buf_cnt; i++) {
		sock_tx_t *tx;

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
		sock_rx_t *rx;

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

	ret = sock_set_nonblocking(sep->sock, SOCK_FD_EP, ep);
	if (ret)
		goto out;

    ret = sock_create_threads (ep);
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
			sock_tx_t *tx;

			tx = TAILQ_FIRST(&sep->txs);
			TAILQ_REMOVE(&sep->txs, tx, tentry);
			if (tx->buffer)
				free(tx->buffer);
			free(tx);
		}
		while (!TAILQ_EMPTY(&sep->rxs)) {
			sock_rx_t *rx;

			rx = TAILQ_FIRST(&sep->rxs);
			TAILQ_REMOVE(&sep->rxs, rx, gentry);
			if (rx->buffer)
				free(rx->buffer);
			free(rx);
		}
		if (sep->ids)
			free(sep->ids);
		if (sep->sock)
			sock_close_socket(sep->sock);
		free(sep);
	}
	if (ep)
		free(ep);
	*endpointp = NULL;
	CCI_EXIT;
	return ret;
}

static int ctp_sock_destroy_endpoint(cci_endpoint_t * endpoint)
{
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	sock_ep_t *sep = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;
	sep = ep->priv;

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);

	ep->priv = NULL;

	if (sep) {
		int i;
		cci__conn_t *conn;
		sock_conn_t *sconn;

        sep->closing = 1;

        pthread_mutex_unlock(&dev->lock);
        pthread_mutex_unlock(&ep->lock);
        sock_terminate_threads (sep);
        pthread_mutex_lock(&dev->lock);
        pthread_mutex_lock(&ep->lock);

		if (sep->sock)
			sock_close_socket(sep->sock);

		for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
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
			sock_tx_t *tx;

			tx = TAILQ_FIRST(&sep->txs);
			TAILQ_REMOVE(&sep->txs, tx, tentry);
			if (tx->state == SOCK_TX_QUEUED)
				TAILQ_REMOVE(&sep->queued, &tx->evt, entry);
			else if (tx->state == SOCK_TX_PENDING)
				TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
			if (tx->buffer)
				free(tx->buffer);
			free(tx);
		}
		while (!TAILQ_EMPTY(&sep->rxs)) {
			sock_rx_t *rx;

			rx = TAILQ_FIRST(&sep->rxs);
			TAILQ_REMOVE(&sep->rxs, rx, gentry);
			if (rx->buffer)
				free(rx->buffer);
			free(rx);
		}
		while (!TAILQ_EMPTY(&sep->rma_ops)) {
			sock_rma_op_t *rma_op = TAILQ_FIRST(&sep->rma_ops);
			TAILQ_REMOVE(&sep->rma_ops, rma_op, entry);
			free(rma_op);
		}
		while (!TAILQ_EMPTY(&sep->handles)) {
			sock_rma_handle_t *handle = TAILQ_FIRST(&sep->handles);
			TAILQ_REMOVE(&sep->handles, handle, entry);
			free(handle);
		}
		if (sep->ids)
			free(sep->ids);
		free(sep);
		ep->priv = NULL;
	}
	if (ep->uri)
		free((char *)ep->uri);
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static void sock_get_id(sock_ep_t * ep, uint32_t * id)
{
	uint32_t n, block, offset;
	uint64_t *b;

	while (1) {
		n = random() % SOCK_NUM_BLOCKS;
		block = n / SOCK_BLOCK_SIZE;
		offset = n % SOCK_BLOCK_SIZE;
		b = &ep->ids[block];

		if ((*b & (1ULL << offset)) == 0) {
			*b |= (1ULL << offset);
			*id = (block * SOCK_BLOCK_SIZE) + offset;
			break;
		}
	}
	return;
}

static void sock_put_id(sock_ep_t * ep, uint32_t id)
{
	uint32_t block, offset;
	uint64_t *b;

	block = id / SOCK_BLOCK_SIZE;
	offset = id % SOCK_BLOCK_SIZE;
	b = &ep->ids[block];

	assert((*b & (1 << offset)) == 1);
	*b &= ~(1 << offset);

	return;
}

static inline uint32_t sock_get_new_seq(void)
{
	return ((uint32_t) random() & SOCK_SEQ_MASK);
}

/* The endpoint maintains 256 lists. Hash the ip and port and return the index
 * of the list. We use all six bytes and this is endian agnostic. It evenly
 * disperses large blocks of addresses as well as large ranges of ports on the
 * same address.
 */
static uint8_t sock_ip_hash(in_addr_t ip, uint16_t port)
{
	port ^= (ip & 0x0000FFFF);
	port ^= (ip & 0xFFFF0000) >> 16;
	return (port & 0x00FF) ^ ((port & 0xFF00) >> 8);
}

static int ctp_sock_accept(cci_event_t *event, const void *context)
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
	sock_ep_t *sep = NULL;
	sock_conn_t *sconn = NULL;
	sock_header_r_t *hdr_r = NULL;
	sock_msg_type_t type;
	sock_tx_t *tx = NULL;
	sock_rx_t *rx = NULL;
	sock_handshake_t *hs = NULL;
	uint32_t id, ack, max_recv_buffer_count, mss = 0, ka;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	rx = container_of(evt, sock_rx_t, evt);
	ep = evt->ep;
	endpoint = &ep->endpoint;
	sep = ep->priv;
	dev = ep->dev;

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

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	hdr_r = rx->buffer;
	sock_parse_header(&hdr_r->header, &type, &a, &b, &unused);
	sock_parse_seq_ts(&hdr_r->seq_ts, &peer_seq, &peer_ts);

	conn->connection.attribute = (enum cci_conn_attribute)a;
	conn->connection.endpoint = endpoint;
	conn->connection.context = (void *)context;
	conn->connection.max_send_size = dev->device.max_send_size;

	hs = (sock_handshake_t *) (rx->buffer +
				   (uintptr_t) sizeof(sock_header_r_t));
	sock_parse_handshake(hs, &id, &ack, &max_recv_buffer_count, &mss, &ka);
	if (ka != 0UL) {
		debug(CCI_DB_CONN, "keepalive timeout: %d", ka);
		conn->keepalive_timeout = ka;
	}
	if (mss < SOCK_MIN_MSS) {
		/* FIXME do what? */
	}
	if (mss < conn->connection.max_send_size)
		conn->connection.max_send_size = mss;

	sconn = conn->priv;
	TAILQ_INIT(&sconn->tx_seqs);
	TAILQ_INIT(&sconn->acks);
	TAILQ_INIT(&sconn->rmas);
	sconn->conn = conn;
	sconn->cwnd = SOCK_INITIAL_CWND;
	sconn->status = SOCK_CONN_READY;	/* set ready since the app thinks it is */
	*((struct sockaddr_in *)&sconn->sin) = rx->sin;
	sconn->peer_id = id;
	sock_get_id(sep, &sconn->id);
	sconn->seq = sock_get_new_seq();	/* even for UU since this reply is reliable */
	sconn->seq_pending = sconn->seq - 1; 
	if (cci_conn_is_reliable(conn)) {
		sconn->max_tx_cnt = max_recv_buffer_count < ep->tx_buf_cnt ?
		    max_recv_buffer_count : ep->tx_buf_cnt;
		sconn->last_ack_seq = sconn->seq;
		sconn->last_ack_ts = sock_get_usecs();
		sconn->ssthresh = sconn->max_tx_cnt;
        sconn->seq_pending = sconn->seq;
	}

	/* insert in sock ep's list of conns */

	i = sock_ip_hash(sconn->sin.sin_addr.s_addr, sconn->sin.sin_port);
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "accepting conn with hash %d", i);

	/* prepare conn_reply */

	tx->msg_type = SOCK_MSG_CONN_REPLY;
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

	hdr_r = (sock_header_r_t *) tx->buffer;
	sock_pack_conn_reply(&hdr_r->header, CCI_SUCCESS /* FIXME */ ,
			     sconn->peer_id);
	sock_pack_seq_ts(&hdr_r->seq_ts, sconn->seq,
			 (uint32_t) sconn->last_ack_ts);
	hs = (sock_handshake_t *) (tx->buffer + sizeof(*hdr_r));
	sock_pack_handshake(hs, sconn->id, peer_seq,
			    ep->rx_buf_cnt,
			    conn->connection.max_send_size, 0);

	tx->len = sizeof(*hdr_r) + sizeof(*hs);
	tx->seq = sconn->seq;

	debug(CCI_DB_CONN, "queuing conn_reply with seq %u ts %x", sconn->seq, sconn->ts);	// FIXME

	/* insert at tail of device's queued list */

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	sock_progress_sends (ep);

	CCI_EXIT;

	return CCI_SUCCESS;
}

/* Send reject reply to client.
 *
 * We cannot use the event's buffer since the app will most likely return the
 * event before we get an ack from the client. We will get a tx for the reply.
 */
static int ctp_sock_reject(cci_event_t *event)
{
	int ret = CCI_SUCCESS;
	uint8_t a;
	uint16_t b;
	uint32_t peer_id;
	uint32_t peer_seq;
	uint32_t peer_ts;
	cci__evt_t *evt = NULL;
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	sock_header_r_t *hdr_r = NULL;
	sock_msg_type_t type;
	char name[32];
	sock_rx_t *rx = NULL;
	sock_tx_t *tx = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	hdr_r = (void *)event->request.data_ptr;
	sock_parse_header(&hdr_r->header, &type, &a, &b, &peer_id);
	sock_parse_seq_ts(&hdr_r->seq_ts, &peer_seq, &peer_ts);

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	sep = ep->priv;
	rx = container_of(evt, sock_rx_t, evt);

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

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* prep the tx */

	tx->msg_type = SOCK_MSG_CONN_REPLY;
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

	hdr_r = (sock_header_r_t *) tx->buffer;
	sock_pack_conn_reply(&hdr_r->header, CCI_ECONNREFUSED /* FIXME */ ,
			     peer_id);
	sock_pack_seq_ts(&hdr_r->seq_ts, peer_seq, 0);

	tx->len = sizeof(*hdr_r);

	/* insert at tail of endpoint's queued list */

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	sock_progress_sends (ep);

	memset(name, 0, sizeof(name));
	sock_sin_to_name(rx->sin, name, sizeof(name));
	debug((CCI_DB_MSG | CCI_DB_CONN), "ep %d sending reject to %s",
	      sep->sock, name);

out:
	CCI_EXIT;
	return ret;
}

static int sock_getaddrinfo(const char *uri, in_addr_t * in, uint16_t * port)
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
	hints.ai_socktype = SOCK_DGRAM;
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

static sock_conn_t *sock_find_open_conn(sock_ep_t * sep, in_addr_t ip,
					uint16_t port, uint32_t id)
{
	uint8_t i;
	struct s_conns *conn_list;
	sock_conn_t *sconn = NULL, *sc;

	CCI_ENTER;

	i = sock_ip_hash(ip, port);
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

static sock_conn_t *sock_find_active_conn(sock_ep_t * sep, in_addr_t ip,
					  uint32_t id)
{
	uint8_t i;
	struct s_active *active_list;
	sock_conn_t *sconn = NULL, *sc;

	CCI_ENTER;
	i = sock_ip_hash(ip, 0);
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

static sock_conn_t *sock_find_conn(sock_ep_t * sep, in_addr_t ip, uint16_t port,
				   uint32_t id, sock_msg_type_t type)
{
	switch (type) {
	case SOCK_MSG_CONN_REPLY:
		return sock_find_active_conn(sep, ip, id);
	default:
		return sock_find_open_conn(sep, ip, port, id);
	}
}

static int ctp_sock_connect(cci_endpoint_t * endpoint, const char *server_uri,
			const void *data_ptr, uint32_t data_len,
			cci_conn_attribute_t attribute,
			const void *context, int flags, const struct timeval *timeout)
{
	int ret;
	int i;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	cci__conn_t *conn = NULL;
	sock_ep_t *sep = NULL;
	sock_conn_t *sconn = NULL;
	sock_tx_t *tx = NULL;
	sock_header_r_t *hdr_r = NULL;
	cci__evt_t *evt = NULL;
	struct cci_connection *connection = NULL;
	struct sockaddr_in *sin = NULL;
	void *ptr = NULL;
	in_addr_t ip;
	uint32_t ts = 0;
	struct s_active *active_list;
	sock_handshake_t *hs = NULL;
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

	sconn->status = SOCK_CONN_ACTIVE;
	sconn->cwnd = SOCK_INITIAL_CWND;
	sin = (struct sockaddr_in *)&sconn->sin;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;

	ret = sock_getaddrinfo(server_uri, &ip, &port);
	if (ret)
		goto out;
	sin->sin_addr.s_addr = ip;	/* already in network order */
	sin->sin_port = port;	/* already in network order */

	/* peer will assign id */

	/* get our endpoint and device */
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	dev = ep->dev;

	connection->max_send_size = dev->device.max_send_size;
	conn->plugin = ep->plugin;

	/* Dealing with keepalive, if set, include the keepalive timeout value into
	   the connection request */
	if ((((attribute & CCI_CONN_ATTR_RO) == CCI_CONN_ATTR_RO)
	     || ((attribute & CCI_CONN_ATTR_RU) == CCI_CONN_ATTR_RU))
	    && ep->keepalive_timeout != 0UL) {
		keepalive = ep->keepalive_timeout;
	}

	i = sock_ip_hash(ip, 0);
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

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* prep the tx */
	tx->msg_type = SOCK_MSG_CONN_REQUEST;

	evt = &tx->evt;
	evt->ep = ep;
	evt->conn = conn;
	evt->event.type = CCI_EVENT_CONNECT;	/* for now */
	evt->event.connect.status = CCI_SUCCESS;
	evt->event.connect.context = (void *)context;
	evt->event.connect.connection = connection;

	/* pack the msg */

	hdr_r = (sock_header_r_t *) tx->buffer;
	sock_get_id(sep, &sconn->id);
	/* FIXME silence -Wall -Werror until it is used */
	if (0)
		sock_put_id(sep, 0);
	sock_pack_conn_request(&hdr_r->header, attribute,
			       (uint16_t) data_len, 0);
	tx->len = sizeof(*hdr_r);

	/* add seq and ack */

	sconn->seq = sock_get_new_seq();
	sconn->seq_pending = sconn->seq - 1;
	sconn->last_ack_seq = sconn->seq;
	tx->seq = sconn->seq;
	sock_pack_seq_ts(&hdr_r->seq_ts, tx->seq, ts);

	/* add handshake */
	hs = (sock_handshake_t *) & hdr_r->data;
	if (keepalive != 0UL)
		conn->keepalive_timeout = keepalive;
	sock_pack_handshake(hs, sconn->id, 0,
			    ep->rx_buf_cnt,
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

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	sock_progress_sends (ep);

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

static int ctp_sock_disconnect(cci_connection_t * connection)
{
	int i = 0;
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;
	sock_conn_t *sconn = NULL;
	sock_ep_t *sep = NULL;

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

	if (conn->uri)
		free((char *)conn->uri);

	i = sock_ip_hash(sconn->sin.sin_addr.s_addr, sconn->sin.sin_port);
	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&sep->conn_hash[i], sconn, entry);
	pthread_mutex_unlock(&ep->lock);

	free(sconn);
	free(conn);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int ctp_sock_set_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, const void *val)
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
		ep->tx_timeout = *((uint32_t*) val);
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		ret = CCI_ERR_NOT_IMPLEMENTED;
		break;
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		ep->keepalive_timeout = *((uint32_t*) val);
		break;
	case CCI_OPT_CONN_SEND_TIMEOUT:
		conn->tx_timeout = *((uint32_t*) val);
		break;
	default:
		debug(CCI_DB_INFO, "unknown option %u", name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;

	return ret;
}

static int ctp_sock_get_opt(cci_opt_handle_t * handle,
			cci_opt_level_t level,
			cci_opt_name_t name, void *val)
{
	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;

	return CCI_EINVAL;
}

static int ctp_sock_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sock_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep;
	cci__evt_t *ev = NULL, *e;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sock_progress_sends (ep);

	pthread_mutex_lock(&ep->lock);

	/* give the user the first event */
	TAILQ_FOREACH(e, &ep->evts, entry) {
		if (e->event.type == CCI_EVENT_SEND) {
			/* NOTE: if it is blocking, skip it since sock_sendv()
			 * is waiting on it
			 */
			sock_tx_t *tx = container_of(e, sock_tx_t, evt);
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

static int ctp_sock_return_event(cci_event_t * event)
{
	cci__ep_t *ep;
	sock_ep_t *sep;
	cci__evt_t *evt;
	sock_tx_t *tx;
	sock_rx_t *rx;

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
		tx = container_of(evt, sock_tx_t, evt);
		pthread_mutex_lock(&ep->lock);
		/* insert at head to keep it in cache */
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
		break;
	case CCI_EVENT_RECV:
		rx = container_of(evt, sock_rx_t, evt);
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

static int sock_sendmsg(cci_os_handle_t sock, struct iovec iov[2],
			int count, const struct sockaddr_in sin)
{
	int ret, i;
	struct msghdr msg;
	ssize_t sent = 0;

	for (i = 0; i < count; i++)
		sent += iov[i].iov_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = count;

	ret = sendmsg(sock, &msg, 0);
	if (ret != -1) {
		//assert(ret == sent);
	} else if (ret == -1) {
		ret = errno;
		debug(CCI_DB_MSG, "%s: sendmsg() returned %d (%s) count %d iov[0] %p:%hu iov[1] %p:%hu",
				__func__, ret, strerror(ret), count,
				iov[0].iov_base, (int)iov[0].iov_len,
				iov[1].iov_base, (int)iov[1].iov_len);
	}

	return ret;
}

static int sock_sendto(cci_os_handle_t sock, void *buf, int len,
			void *rma_ptr, uint16_t rma_len,
		       const struct sockaddr_in sin)
{
	int ret;
	int count = 0;
	struct iovec iov[2];

	memset(&iov, 0, sizeof(iov));
	if (buf) {
		iov[0].iov_base = buf;
		iov[0].iov_len = len;
		count = 1;
		if (rma_ptr) {
			iov[1].iov_base = rma_ptr;
			iov[1].iov_len = rma_len;
			count = 2;
			len += rma_len;
		}
	}
	ret = sock_sendmsg(sock, iov, count, sin);
	if (ret != -1)
		assert(ret == len);

	return ret;
}

static void sock_progress_pending(cci__ep_t * ep)
{
	int ret;
	uint64_t now;
	sock_tx_t *tx;
	cci__evt_t *evt, *tmp, *my_temp_evt;
	union cci_event *event;	/* generic CCI event */
	cci__conn_t *conn;
	sock_conn_t *sconn;
	sock_ep_t *sep = ep->priv;

	CCI_ENTER;

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);

	now = sock_get_usecs();

	/* This is only for reliable messages.
	 * Do not dequeue txs, just walk the list.
	 */

    pthread_mutex_lock (&ep->lock);
	TAILQ_FOREACH_SAFE(evt, &sep->pending, entry, tmp) {
        sock_tx_t *tx = container_of (evt, sock_tx_t, evt);

		conn = evt->conn;
		sconn = conn->priv;
		event = &evt->event;

		assert(tx->last_attempt_us != 0ULL);

		/* has it timed out? */
		if (SOCK_U64_LT(tx->timeout_us, now)) {
			/* dequeue */

			debug(CCI_DB_WARN, "%s: timeout of %s msg",
			      __func__, sock_msg_type(tx->msg_type));

			TAILQ_REMOVE(&sep->pending, &tx->evt, entry);

			/* set status and add to completed events */

			if (tx->msg_type == SOCK_MSG_SEND)
				sconn->pending--;

			switch (tx->msg_type) {
			case SOCK_MSG_SEND:
				event->send.status = CCI_ETIMEDOUT;
				if (tx->rnr != 0) {
					event->send.status = CCI_ERR_RNR;
					/* If a message that is already marked RNR times out,
					   and if the connection is reliable and ordered, we
					   mark all following messages as RNR */
					if (conn->connection.attribute == CCI_CONN_ATTR_RO) {
						sock_tx_t *my_temp_tx;
						TAILQ_FOREACH_SAFE(my_temp_evt,
								           &sep->pending,
								           entry,
								           tmp)
                        {
                            my_temp_tx = container_of (my_temp_evt, sock_tx_t, evt);
							if (my_temp_tx->seq > tx->seq)
								my_temp_tx->rnr = 1;
						}
					}
				}
				break;
			case SOCK_MSG_RMA_WRITE:
				pthread_mutex_lock(&ep->lock);
				tx->rma_op->pending--;
				tx->rma_op->status = CCI_ETIMEDOUT;
				pthread_mutex_unlock(&ep->lock);
				break;
			case SOCK_MSG_CONN_REQUEST:
				{
					int i;
					struct s_active *active_list;

					event->connect.status = CCI_ETIMEDOUT;
					event->connect.connection = NULL;
					if (conn->uri)
						free((char *)conn->uri);
					sconn->status = SOCK_CONN_CLOSING;
					i = sock_ip_hash(sconn->sin.sin_addr.
							 s_addr, 0);
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
			case SOCK_MSG_CONN_REPLY:
			case SOCK_MSG_CONN_ACK:
			default:
				/* TODO */
				CCI_EXIT;
				return;
			}
			/* if SILENT, put idle tx */
			if (tx->flags & CCI_FLAG_SILENT &&
			    (tx->msg_type == SOCK_MSG_SEND ||
			     tx->msg_type == SOCK_MSG_RMA_WRITE)) {

				tx->state = SOCK_TX_IDLE;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
			} else {
				tx->state = SOCK_TX_COMPLETED;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_TAIL(&evts, evt, entry);
			}
			continue;
		}

		/* is it time to resend? */

		if ((tx->last_attempt_us +
		     ((1 << tx->send_count) * SOCK_RESEND_TIME_SEC * 1000000)) >
		    now)
			continue;

		/* need to resend it */

#if 0
		if (tx->send_count == 1 && tx->msg_type == SOCK_MSG_SEND && 0) {
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
		      sock_msg_type(tx->msg_type), tx->seq, tx->send_count);
        pack_piggyback_ack (ep, sconn, tx);
		ret = sock_sendto(sep->sock, tx->buffer, tx->len, tx->rma_ptr, tx->rma_len, sconn->sin);
		if (ret != tx->len) {
			debug((CCI_DB_MSG | CCI_DB_INFO),
			      "sendto() failed with %s",
			      cci_strerror(&ep->endpoint,
					   (enum cci_status)errno));
			continue;
		}
	}
    pthread_mutex_unlock (&ep->lock);

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

static inline int 
pack_piggyback_ack (cci__ep_t *ep, sock_conn_t *sconn, sock_tx_t *tx)
{
    sock_ack_t *ack = NULL;
    uint64_t now = 0ULL;

    if (!TAILQ_EMPTY(&sconn->acks)) {
        ack = TAILQ_FIRST(&sconn->acks);
        if (1 == sock_need_sack(sconn)) {
            /* Nothing to do */
        } else if (ack != NULL && ack->start == ack->end) {
            sock_header_r_t *hdr_r = tx->buffer;
            hdr_r->pb_ack = ack->start;
            TAILQ_REMOVE(&sconn->acks, ack, entry);
            ack = TAILQ_FIRST(&sconn->acks);
            /* We could get now from the caller if we wanted to */
            now = sock_get_usecs();
            sconn->last_ack_ts = now;
        } else {
            /* ACK_UP_TO, not handled at the moment */
        }
    } else {
        sock_header_r_t *hdr_r = tx->buffer;
        hdr_r->pb_ack = 0;
    }

    return CCI_SUCCESS;
}

static void sock_progress_queued(cci__ep_t * ep)
{
	int ret, is_reliable;
	uint32_t timeout;
	uint64_t now;
	sock_tx_t *tx;
	cci__evt_t *evt, *tmp;
	cci__conn_t *conn;
	sock_ep_t *sep = ep->priv;
	sock_conn_t *sconn;
	union cci_event *event;	/* generic CCI event */

	CCI_ENTER;

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);

	if (!sep)
		return;

	now = sock_get_usecs();

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(evt, &sep->queued, entry, tmp) {
        tx = container_of (evt, sock_tx_t, evt);
		event = &evt->event;
		conn = evt->conn;
		sconn = conn->priv;
		is_reliable = cci_conn_is_reliable(conn);

		/* try to send it */

		if (tx->last_attempt_us == 0ULL) {
			timeout =
			    conn->tx_timeout ? conn->tx_timeout : ep->tx_timeout;
			tx->timeout_us = now + (uint64_t) timeout;
		}

		if (SOCK_U64_LT(tx->timeout_us, now)) {

			/* set status and add to completed events */
			switch (tx->msg_type) {
			case SOCK_MSG_SEND:
				if (tx->rnr != 0) {
					event->send.status = CCI_ERR_RNR;
				} else {
					event->send.status = CCI_ETIMEDOUT;
				}
				break;
			case SOCK_MSG_CONN_REQUEST:
				/* FIXME only CONN_REQUEST gets an event
				 * the other two need to disconnect the conn */
				event->connect.status = CCI_ETIMEDOUT;
				event->connect.connection = NULL;
				break;
			case SOCK_MSG_RMA_WRITE:
				tx->rma_op->pending--;
				tx->rma_op->status = CCI_ETIMEDOUT;
				break;
			case SOCK_MSG_CONN_REPLY:
			case SOCK_MSG_CONN_ACK:
			default:
				/* TODO */
				debug(CCI_DB_WARN, "%s: timeout of %s msg",
				      __func__, sock_msg_type(tx->msg_type));
				CCI_EXIT;
				return;
			}
			TAILQ_REMOVE(&sep->queued, evt, entry);

			/* if SILENT, put idle tx */
			if (tx->flags & CCI_FLAG_SILENT &&
			    (tx->msg_type == SOCK_MSG_SEND ||
			     tx->msg_type == SOCK_MSG_RMA_WRITE)) {

				tx->state = SOCK_TX_IDLE;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
			} else {
				tx->state = SOCK_TX_COMPLETED;
				/* store locally until we can drop the dev->lock */
				TAILQ_INSERT_TAIL(&evts, evt, entry);
			}
			continue;
		}

		if ((tx->last_attempt_us + (SOCK_RESEND_TIME_SEC * 1000000)) >
		    now)
			continue;

#if 0
		if (sconn->pending > sconn->cwnd &&
		    tx->msg_type == SOCK_MSG_SEND && 0) {
			continue;
		}
#endif

		tx->last_attempt_us = now;
		tx->send_count = 1;

		if (is_reliable &&
		    !(tx->msg_type == SOCK_MSG_CONN_REQUEST ||
		      tx->msg_type == SOCK_MSG_CONN_REPLY)) {
			TAILQ_INSERT_TAIL(&sconn->tx_seqs, tx, tx_seq);
		}

		/* if reliable and ordered, we have to check whether the tx is marked
		   RNR */
		if (is_reliable
		    && conn->connection.attribute == CCI_CONN_ATTR_RO
		    && tx->rnr != 0) {
			event->send.status = CCI_ERR_RNR;
		}

        /* For RMA Writes, we only allow a given number of messages to be
           in fly */
        if (tx->msg_type == SOCK_MSG_RMA_WRITE) {
            if (tx->rma_op->pending >= SOCK_RMA_DEPTH)
                continue;
        }

		/* need to send it */

		debug(CCI_DB_MSG, "sending %s msg seq %u",
		      sock_msg_type(tx->msg_type), tx->seq);
        pack_piggyback_ack (ep, sconn, tx);
		ret = sock_sendto(sep->sock, tx->buffer, tx->len, tx->rma_ptr, tx->rma_len, sconn->sin);
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
				    !(tx->msg_type == SOCK_MSG_CONN_REQUEST ||
				      tx->msg_type == SOCK_MSG_CONN_REPLY)) {
					TAILQ_REMOVE(&sconn->tx_seqs, tx,
						     tx_seq);
				}
				continue;
			}
		}
		/* msg sent, dequeue */
		TAILQ_REMOVE(&sep->queued, &tx->evt, entry);
		if (tx->msg_type == SOCK_MSG_SEND)
			sconn->pending++;

		/* if reliable or connection, add to pending
		 * else add to idle txs */

		if (is_reliable ||
		    tx->msg_type == SOCK_MSG_CONN_REQUEST ||
		    tx->msg_type == SOCK_MSG_CONN_REPLY) {

			tx->state = SOCK_TX_PENDING;
			TAILQ_INSERT_TAIL(&sep->pending, evt, entry);
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "moving queued %s tx to pending",
			      sock_msg_type(tx->msg_type));
            if (tx->msg_type == SOCK_MSG_RMA_WRITE)
                tx->rma_op->pending++;
		} else {
			tx->state = SOCK_TX_COMPLETED;
			TAILQ_INSERT_TAIL(&idle_txs, tx, dentry);
		}
	}
	pthread_mutex_unlock(&ep->lock);

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

static void sock_progress_sends(cci__ep_t * ep)
{
	sock_progress_pending (ep);
    sock_ack_conns(ep);
	sock_progress_queued (ep);

	return;
}

static int ctp_sock_send(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	if (msg_ptr && msg_len) {
		iovcnt = 1;
		iov.iov_base = (void *) msg_ptr;
		iov.iov_len = msg_len;
	}

	return ctp_sock_sendv(connection, &iov, iovcnt, context, flags);
}

static int ctp_sock_sendv(cci_connection_t * connection,
		      const struct iovec *data, uint32_t iovcnt,
		      const void *context, int flags)
{
	int i, ret, is_reliable = 0, data_len = 0;
	char *func = iovcnt < 2 ? "send" : "sendv";
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep;
	cci__conn_t *conn;
	sock_ep_t *sep;
	sock_conn_t *sconn;
	sock_tx_t *tx = NULL;
	sock_header_t *hdr;
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

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	/* tx bookkeeping */
	tx->msg_type = SOCK_MSG_SEND;
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
		    sock_get_usecs() + SOCK_EP_TX_TIMEOUT_SEC * 1000000;
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
	hdr = (sock_header_t *) tx->buffer;
	sock_pack_send(hdr, data_len, sconn->peer_id);
	tx->len = sizeof(*hdr);

	/* if reliable, add seq and ack */

	if (is_reliable) {
		sock_header_r_t *hdr_r = tx->buffer;
		uint32_t ts = 0;

		pthread_mutex_lock(&ep->lock);
		tx->seq = ++(sconn->seq);
		pthread_mutex_unlock(&ep->lock);

		sock_pack_seq_ts(&hdr_r->seq_ts, tx->seq, ts);
        hdr_r->pb_ack = 0;
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
        pack_piggyback_ack (ep, sconn, tx);
		ret = sock_sendto(sep->sock, tx->buffer, tx->len, tx->rma_ptr, tx->rma_len, sconn->sin);
		if (ret == tx->len) {
			/* queue event on enpoint's completed queue */
			tx->state = SOCK_TX_COMPLETED;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_MSG, "sent UU msg with %d bytes",
			      tx->len - (int)sizeof(sock_header_t));

			sock_progress_sends (ep);

			debug(CCI_DB_FUNC, "exiting %s", func);

			return CCI_SUCCESS;
		}

		/* if error, fall through */
	}

	/* insert at tail of sock device's queued list */

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */

	sock_progress_sends (ep);

	/* if unreliable, we are done since it is buffered internally */
	if (!is_reliable) {
		debug(CCI_DB_FUNC, "exiting %s", func);
		return CCI_SUCCESS;
	}

	ret = CCI_SUCCESS;

	/* if blocking, wait for completion */

	if (tx->flags & CCI_FLAG_BLOCKING) {
		struct timeval tv = { 0, SOCK_PROG_TIME_US / 2 };

		while (tx->state != SOCK_TX_COMPLETED)
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

static int ctp_sock_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, uint64_t * rma_handle)
{
	/* FIXME use read/write flags? */
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	sock_rma_handle_t *handle = NULL;

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

static int ctp_sock_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle)
{
	int ret = CCI_EINVAL;
	sock_rma_handle_t *handle =
	    (sock_rma_handle_t *) ((uintptr_t) rma_handle);
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	sock_rma_handle_t *h = NULL;
	sock_rma_handle_t *tmp = NULL;

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
generate_context_id(sock_conn_t * sconn, const void *context, uint64_t * context_id)
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

static int ctp_sock_rma(cci_connection_t * connection,
		    const void *msg_ptr, uint32_t msg_len,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset,
		    uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	sock_ep_t *sep = NULL;
	sock_conn_t *sconn = NULL;
	sock_rma_handle_t *local =
	    (sock_rma_handle_t *) ((uintptr_t) local_handle);
	sock_rma_handle_t *h = NULL;
	sock_rma_op_t *rma_op = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	sconn = conn->priv;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

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
		sock_tx_t **txs = NULL;
		uint64_t old_seq = 0ULL;

		cnt = rma_op->num_msgs < SOCK_RMA_DEPTH ?
		    rma_op->num_msgs : SOCK_RMA_DEPTH;

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
			sock_tx_t *tx = txs[i];
			uint64_t offset =
			    (uint64_t) i * (uint64_t) connection->max_send_size;
			sock_rma_header_t *write =
			    (sock_rma_header_t *) tx->buffer;

			rma_op->next = i + 1;
			tx->msg_type = SOCK_MSG_RMA_WRITE;
			tx->flags = flags | CCI_FLAG_SILENT;
			tx->state = SOCK_TX_QUEUED;
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

			tx->rma_ptr = (void*)(uintptr_t)(local->start + offset);
			tx->rma_len = tx->len;

			sock_pack_rma_write(write, tx->len, sconn->peer_id,
					    tx->seq, 0, local_handle,
					    local_offset + offset,
					    remote_handle,
					    remote_offset + offset);
			tx->len = sizeof(sock_rma_header_t);
		}
		pthread_mutex_lock(&ep->lock);
		for (i = 0; i < cnt; i++)
			TAILQ_INSERT_TAIL(&sep->queued, &(txs[i])->evt, entry);
		TAILQ_INSERT_TAIL(&sconn->rmas, rma_op, rmas);
		TAILQ_INSERT_TAIL(&sep->rma_ops, rma_op, entry);
		pthread_mutex_unlock(&ep->lock);

		/* it is no longer needed */
		free(txs);

		ret = CCI_SUCCESS;
	} else if (flags & CCI_FLAG_READ) {
		sock_tx_t *tx = NULL;
		sock_rma_header_t *read = NULL;
		uint64_t context_id;

		/* RMA_READ is implemented using RMA_WRITE: we send a request to the
		   remote peer which will perform a RMA_WRITE */

		/* Get a TX */
		pthread_mutex_lock(&ep->lock);
		if (!TAILQ_EMPTY(&sep->idle_txs)) {
			tx = TAILQ_FIRST(&sep->idle_txs);
			TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
		}
		pthread_mutex_unlock(&ep->lock);

		tx->rma_ptr = NULL;
		tx->rma_len = 0;

		/* Prepare and send the msg */
		read = tx->buffer;
		sep = ep->priv;
		memset(tx->buffer, 0, sizeof(sock_rma_header_t));
		tx->seq = ++(sconn->seq);
		tx->timeout_us = 0ULL;
		tx->last_attempt_us = 0ULL;
		sock_pack_rma_read(read, data_len, sconn->peer_id, tx->seq, 0,
				   local_handle, local_offset,
				   remote_handle, remote_offset);
		tx->len = sizeof(sock_rma_header_t);
		generate_context_id(sconn, context, &context_id);
		memcpy(read->data, &data_len, sizeof(uint64_t));
		//msg_ptr = (void *)(read->data + sizeof(uint64_t));
		memcpy((void *)(((char *)read->data) + sizeof(uint64_t)),
		       &context_id, sizeof(uint64_t));
		tx->len += 2 * sizeof(uint64_t);
		tx->msg_type = SOCK_MSG_SEND;
		tx->rma_op = NULL;

		/* Queuing the RMA_READ_REQUEST message */
		tx->state = SOCK_TX_QUEUED;
		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.event.send.connection = connection;
		tx->evt.conn = conn;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
		pthread_mutex_unlock(&ep->lock);
		ret = CCI_SUCCESS;
	}

	sock_progress_sends (ep);

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
static inline void sock_handle_seq(sock_conn_t * sconn, uint32_t seq)
{
	int done = 0;
	sock_ack_t *ack = NULL;
	sock_ack_t *last = NULL;
	sock_ack_t *tmp = NULL;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);

	if (SOCK_SEQ_LTE(seq, sconn->acked)) {
		debug(CCI_DB_MSG, "%s ignoring seq %u (acked %u) ***", __func__,
		      seq, sconn->acked);
		return;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(ack, &sconn->acks, entry, tmp) {
		if (SOCK_SEQ_GTE(seq, ack->start) &&
		    SOCK_SEQ_LTE(seq, ack->end)) {
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
			sock_ack_t *next = TAILQ_NEXT(ack, entry);

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

            /* Forcing ACK */
            if (ack->end - ack->start >= PENDING_ACK_THRESHOLD) {
                debug(CCI_DB_MSG, "Forcing ACK");
                pthread_mutex_unlock(&ep->lock);
                sock_ack_conns (ep);
                pthread_mutex_lock(&ep->lock);
            }

			done = 1;
			break;
		} else if (last && SOCK_SEQ_GT(seq, last->end) &&
			   SOCK_SEQ_LT(seq, ack->start)) {
			sock_ack_t *new;

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
sock_handle_active_message(sock_conn_t * sconn,
			   sock_rx_t * rx, uint16_t len, uint32_t id)
{
	cci__evt_t *evt;
	cci__conn_t *conn = sconn->conn;
	sock_header_t *hdr;	/* wire header */
	union cci_event *event;	/* generic CCI event */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	cci__ep_t *ep;

	CCI_ENTER;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);

	/* get cci__evt_t to hang on ep->events */

	evt = &rx->evt;

	/* set wire header so we can find user header */

	hdr = (sock_header_t *) rx->buffer;

	/* setup the generic event for the application */

	event = & evt->event;
	event->type = CCI_EVENT_RECV;
	event->recv.len = len;
	event->recv.ptr = (void *)&hdr->data;
	event->recv.connection = &conn->connection;

	/* if a reliable connection, handle the ack */

	if (cci_conn_is_reliable(conn)) {
		sock_header_r_t *hdr_r = (sock_header_r_t *) rx->buffer;
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
static void sock_handle_rnr(sock_conn_t * sconn, uint32_t seq, uint32_t ts)
{
	sock_tx_t *tx = NULL;
	sock_tx_t *tmp = NULL;

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
sock_handle_ack(sock_conn_t * sconn,
		sock_msg_type_t type, sock_rx_t * rx, int count, uint32_t id)
{
	int i = 0;
	int found = 0;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__dev_t *dev = ep->dev;
	sock_ep_t *sep = ep->priv;
	sock_tx_t *tx = NULL;
	sock_tx_t *tmp = NULL;
	sock_header_r_t *hdr_r = rx->buffer;
	uint32_t acks[SOCK_MAX_SACK * 2];

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs =
	    TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);
	TAILQ_HEAD(s_queued, sock_tx) queued = TAILQ_HEAD_INITIALIZER(queued);
	TAILQ_INIT(&queued);

	assert(id == sconn->id);
	assert(count > 0);

	if (count == 1) {
		assert(type == SOCK_MSG_ACK_ONLY || type == SOCK_MSG_ACK_UP_TO
               || type == SOCK_MSG_SEND || type == SOCK_MSG_RMA_WRITE);
	} else {
		assert(type == SOCK_MSG_SACK);
	}
	sock_parse_ack(hdr_r, type, acks, count);

	if (type == SOCK_MSG_ACK_ONLY) {
		if (sconn->seq_pending == acks[0] - 1)
			sconn->seq_pending = acks[0];
	} else if (type == SOCK_MSG_ACK_UP_TO) {
		sconn->seq_pending = acks[0];
	} else if (type == SOCK_MSG_SEND || type == SOCK_MSG_RMA_WRITE) {
		/* Piggybacked ACK */
		acks[0] = hdr_r->pb_ack;
		if (sconn->seq_pending == acks[0] - 1)
			sconn->seq_pending = acks[0];
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(tx, &sconn->tx_seqs, tx_seq, tmp) {
		/* Note that SOCK_MSG_SEND and SOCK_MSG_RMA_WRITE msgs can include a 
		   piggybacked ACK */
		if (type == SOCK_MSG_ACK_ONLY || type == SOCK_MSG_SEND 
									  || type == SOCK_MSG_RMA_WRITE) {
			if (tx->seq == acks[0]) {
				if (tx->state == SOCK_TX_PENDING) {
					debug(CCI_DB_MSG,
					      "%s acking only seq %u", __func__,
					      acks[0]);
					TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
					TAILQ_REMOVE(&sconn->tx_seqs, tx,
						     tx_seq);
					if (tx->msg_type == SOCK_MSG_RMA_WRITE)
						tx->rma_op->pending--;
					if (tx->msg_type == SOCK_MSG_SEND) {
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
						tx->state = SOCK_TX_IDLE;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_HEAD(&idle_txs, tx,
								  dentry);
					} else {
						tx->state = SOCK_TX_COMPLETED;
						/* In the context of an ordered reliable connection,
						   if the receiver was always ready to receive, the 
						   complete the send with a success status. Otherwise,
						   we complete the send with a RNR status */
						if (conn->connection.
						    attribute ==
						    CCI_CONN_ATTR_RO
						    && tx->rnr != 0) {
							tx->evt.event.send.
							    status =
							    CCI_ERR_RNR;
						} else {
							tx->evt.event.send.
							    status =
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
		} else if (type == SOCK_MSG_ACK_UP_TO) {
			if (SOCK_SEQ_LTE(tx->seq, acks[0])) {
				if (tx->state == SOCK_TX_PENDING) {
					debug(CCI_DB_MSG,
					      "%s acking tx seq %u (up to seq %u)",
					      __func__, tx->seq, acks[0]);
					TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
					TAILQ_REMOVE(&sconn->tx_seqs, tx, tx_seq);
                    if (tx->msg_type == SOCK_MSG_RMA_WRITE)
                        tx->rma_op->pending--;
					if (tx->msg_type == SOCK_MSG_SEND) {
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
						tx->state = SOCK_TX_IDLE;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_HEAD(&idle_txs, tx,
								  dentry);
					} else {
						tx->state = SOCK_TX_COMPLETED;
						/* In the context of an ordered reliable connection,
						   if the receiver was always ready to receive, the 
						   complete the send with a success status. Otherwise,
						   we complete the send with a RNR status */
						if (conn->connection.attribute == CCI_CONN_ATTR_RO
						    && tx->rnr != 0) {
							tx->evt.event.send.status = CCI_ERR_RNR;
						} else {
							tx->evt.event.send.
							    status =
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
				if (SOCK_SEQ_GTE(tx->seq, acks[i]) &&
				    SOCK_SEQ_LTE(tx->seq, acks[i + 1])) {
					if (sconn->seq_pending == acks[i] - 1)
						sconn->seq_pending =
						    acks[i + 1];
					if (tx->state == SOCK_TX_PENDING) {
						debug(CCI_DB_MSG,
						      "%s sacking seq %u",
						      __func__, acks[0]);
						found++;
						TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
						TAILQ_REMOVE(&sconn->tx_seqs, tx, tx_seq);
                        if (tx->msg_type == SOCK_MSG_RMA_WRITE)
                            tx->rma_op->pending--;
						if (tx->msg_type ==
						    SOCK_MSG_SEND) {
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
								     sconn->cwnd);
							} else {
								sconn->cwnd++;
							}
#endif
						}
						/* if SILENT, put idle tx */
						if (tx->flags & CCI_FLAG_SILENT) {
							tx->state =
							    SOCK_TX_IDLE;
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_HEAD
							    (&idle_txs, tx,
							     dentry);
						} else {
							tx->state =
							    SOCK_TX_COMPLETED;
							/* In the context of an ordered reliable connection
							   if the receiver was always ready to receive, the
							   complete the send with a success status.
							   Otherwise, we complete the send with a RNR status
							 */
							if (conn->connection.
							    attribute ==
							    CCI_CONN_ATTR_RO
							    && tx->rnr != 0) {
								tx->evt.event.
								    send.status
								    =
								    CCI_ERR_RNR;
							} else {
								tx->evt.event.
								    send.status
								    =
								    CCI_SUCCESS;
							}
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_TAIL(&evts,
									  &tx->evt,
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
	      sock_msg_type(type), acks[0]);

	pthread_mutex_lock(&ep->lock);
	/* transfer txs to sock ep's list */
	while (!TAILQ_EMPTY(&idle_txs)) {
		sock_rma_op_t *rma_op = NULL;

		tx = TAILQ_FIRST(&idle_txs);
		TAILQ_REMOVE(&idle_txs, tx, dentry);

		rma_op = tx->rma_op;
		if (rma_op && rma_op->status == CCI_SUCCESS) {
			sock_rma_handle_t *local =
			    (sock_rma_handle_t *) ((uintptr_t)
						   rma_op->local_handle);
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
				sock_rma_header_t *write =
				    (sock_rma_header_t *) tx->buffer;
				uint64_t offset = 0ULL;

				/* send more data */
				i = rma_op->next++;
				tx->flags = rma_op->flags | CCI_FLAG_SILENT;
				tx->state = SOCK_TX_QUEUED;
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

				sock_pack_rma_write(write, tx->len,
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
				tx->len += sizeof(sock_rma_header_t);
				TAILQ_INSERT_TAIL(&queued, tx, dentry);
				continue;
			} else if (rma_op->completed == rma_op->num_msgs) {

				/* send remote completion? */
				if (rma_op->msg_len) {
					sock_header_r_t *hdr_r = tx->buffer;
					sock_rma_header_t *write = NULL;
					uint64_t context_id;
					void *msg_ptr = NULL;

					rma_op->tx = tx;
					tx->msg_type = SOCK_MSG_RMA_WRITE_DONE;
					tx->flags =
					    rma_op->flags | CCI_FLAG_SILENT;
					tx->state = SOCK_TX_QUEUED;
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
					       sizeof(sock_rma_header_t));
					write =
					    (sock_rma_header_t *) tx->buffer;
					context_id = (uint64_t) rma_op->context;
					sock_pack_rma_write_done(write,
                                 (uint16_t) rma_op->msg_len,
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
					    sizeof(sock_rma_header_t) +
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
		sock_tx_t *my_tx;
		my_tx = TAILQ_FIRST(&queued);
		TAILQ_REMOVE(&queued, my_tx, dentry);
		TAILQ_INSERT_TAIL(&sep->queued, &my_tx->evt, entry);
	}
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	/* We received a ACK so we wake up the send thread */
	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

	CCI_EXIT;
	return;
}

static void
sock_handle_conn_request(sock_rx_t * rx,
			 cci_conn_attribute_t attr,
			 uint16_t len, struct sockaddr_in sin, cci__ep_t * ep)
{
	char name[32];

	CCI_ENTER;

	memset(name, 0, sizeof(name));
	sock_sin_to_name(sin, name, sizeof(name));
	debug(CCI_DB_CONN, "recv'd conn_req from %s", name);

	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.event.request.attribute = attr;
	*((uint32_t *) & rx->evt.event.request.data_len) = len;
	if (len)
		*((void **)&rx->evt.event.request.data_ptr) =
		    (void *)((((sock_header_r_t *) rx->buffer)->data) +
			     (uintptr_t) sizeof(sock_handshake_t));
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
static void sock_handle_conn_reply(sock_conn_t * sconn,	/* NULL if rejected */
				   sock_rx_t * rx, uint8_t reply,	/* CCI_SUCCESS or CCI_ECONNREFUSED */
				   uint16_t unused,
				   uint32_t id,
				   struct sockaddr_in sin, cci__ep_t * ep)
{
	int i, ret;
	cci__evt_t *evt = NULL, *tmp = NULL, *e = NULL;
	cci__conn_t *conn = NULL;
	sock_ep_t *sep = NULL;
	sock_tx_t *tx = NULL, *t = NULL;
	sock_header_r_t *hdr_r;	/* wire header */
	union cci_event *event;	/* generic CCI event */
	uint32_t seq;		/* peer's seq */
	uint32_t ts;		/* FIXME our original seq */
	sock_handshake_t *hs = NULL;

	CCI_ENTER;

	sep = ep->priv;

	if (!sconn) {
		/* either this is a dup and the conn is now ready or
		 * the conn is closed and we simply ack the msg
		 */
		/* look for a conn that is ready */
		sconn =
		    sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
				   SOCK_MSG_SEND);
		if (!sconn) {
			sock_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char from[32];

			memset(from, 0, sizeof(from));
			sock_sin_to_name(sin, from, sizeof(from));
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "ep %d recv'd conn_reply (%s) from %s"
			      " with no matching conn", sep->sock,
			      reply ==
			      CCI_SUCCESS ? "success" : "rejected", from);
			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			sock_pack_conn_ack(&hdr.header, sconn->peer_id);
			ret = sock_sendto(sep->sock, &hdr, len, NULL, 0, sin);
			if (ret != len) {
				debug((CCI_DB_CONN | CCI_DB_MSG),
				      "ep %d failed to send conn_ack with %s",
				      sep->sock,
				      cci_strerror(&ep->endpoint,
						   (enum cci_status)ret));
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

	/* set wire header so we can find user header */

	hdr_r = (sock_header_r_t *) rx->buffer;

	/* TODO handle ack */

	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);	//FIXME do something with ts

	if (sconn->status == SOCK_CONN_ACTIVE) {
		uint32_t peer_id, ack, max_recv_buffer_count, mss, keepalive;
		struct s_active *active_list;

		debug(CCI_DB_CONN, "transition active connection to ready");

		hs = (sock_handshake_t *) (rx->buffer + sizeof(*hdr_r));
		/* With conn_reply, we do not care about the keepalive param */
		sock_parse_handshake(hs, &peer_id, &ack, &max_recv_buffer_count,
				     &mss, &keepalive);

		/* get pending conn_req tx, create event, move conn to conn_hash */
		pthread_mutex_lock(&ep->lock);
		TAILQ_FOREACH_SAFE(e, &sep->pending, entry, tmp) {
            t = container_of (e, sock_tx_t, evt);
			if (t->seq == ack) {
				TAILQ_REMOVE(&sep->pending, e, entry);
				tx = t;
				break;
			}
		}
		pthread_mutex_unlock(&ep->lock);
        /* Since we remove the pending tx, update the pending_seq for that
           given connection */
        if (sconn->seq_pending == ack - 1)
            sconn->seq_pending = ack;

		if (!tx) {
			char from[32];

			memset(from, 0, sizeof(from));
			sock_sin_to_name(sin, from, sizeof(from));

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
			    ep->tx_buf_cnt ? max_recv_buffer_count : ep->
			    tx_buf_cnt;
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

		i = sock_ip_hash(sin.sin_addr.s_addr, 0);
		active_list = &sep->active_hash[i];
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(active_list, sconn, entry);
		pthread_mutex_unlock(&ep->lock);

		if (CCI_SUCCESS == reply) {
			sconn->peer_id = peer_id;
			sconn->status = SOCK_CONN_READY;
			*((struct sockaddr_in *)&sconn->sin) = sin;
			sconn->acked = seq;

			i = sock_ip_hash(sin.sin_addr.s_addr, sin.sin_port);
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
			pthread_mutex_unlock(&ep->lock);

			debug(CCI_DB_CONN, "conn ready on hash %d", i);

		} else {
			sock_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char name[32];

			free(sconn);
			if (conn->uri)
				free((char *)conn->uri);
			free(conn);

			/* send unreliable conn_ack */
			memset(name, 0, sizeof(name));
			sock_sin_to_name(sin, name, sizeof(name));
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "ep %d recv'd conn_reply (rejected) from %s"
			      " - closing conn", sep->sock, name);

			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			sock_pack_conn_ack(&hdr.header, sconn->peer_id);
			ret = sock_sendto(sep->sock, &hdr, len, NULL, 0, sin);
			if (ret != len) {
				debug((CCI_DB_CONN | CCI_DB_MSG),
				      "ep %d failed to send conn_ack with %s",
				      sep->sock,
				      cci_strerror(&ep->endpoint,
						   (enum cci_status)ret));
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
	} else if (sconn->status == SOCK_CONN_READY) {
		pthread_mutex_lock(&ep->lock);
		if (!TAILQ_EMPTY(&sep->idle_txs)) {
			tx = TAILQ_FIRST(&sep->idle_txs);
			TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
		}
		pthread_mutex_unlock(&ep->lock);

		if (!tx) {
			char to[32];

			memset(to, 0, sizeof(to));
			sock_sin_to_name(sin, to, sizeof(to));

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

	tx->rma_ptr = NULL;
	tx->rma_len = 0;

	tx->seq = ++(sconn->seq);

	tx->flags = CCI_FLAG_SILENT;
	tx->msg_type = SOCK_MSG_CONN_ACK;
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.connect.connection = &conn->connection;
	tx->evt.ep = ep;
	tx->evt.conn = conn;

	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;

	hdr_r = tx->buffer;
	sock_pack_conn_ack(&hdr_r->header, sconn->peer_id);
	sconn->last_ack_ts = sock_get_usecs();
	/* the conn_ack acks the server's seq in the timestamp */
	sock_pack_seq_ts(&hdr_r->seq_ts, tx->seq, seq);

	debug(CCI_DB_CONN, "%s:%d queuing conn_ack with seq %u", __func__,
	      __LINE__, tx->seq);

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

#if DEBUG_RNR
	conn_established = true;
#endif

	/* try to progress txs */

	sock_progress_sends (ep);

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
sock_handle_conn_ack(sock_conn_t * sconn,
		     sock_rx_t * rx,
		     uint8_t unused1,
		     uint16_t unused2, uint32_t peer_id, struct sockaddr_in sin)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	sock_ep_t *sep;
    cci__evt_t *e = NULL, *tmp = NULL;
	sock_tx_t *tx = NULL, *t = NULL;
	sock_header_r_t *hdr_r;	/* wire header */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	uint32_t seq;
	uint32_t ts;

	CCI_ENTER;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	/* we check whether the connection ack match the id associated to the
	   connection */
	assert(peer_id == sconn->id);

	hdr_r = rx->buffer;
	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

	debug(CCI_DB_CONN, "%s: seq %u ack %u", __func__, seq, ts);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(e, &sep->pending, entry, tmp) {
		/* the conn_ack stores the ack for the conn_reply in ts */
        t = container_of (e, sock_tx_t, evt);
		if (t->seq == ts) {
			TAILQ_REMOVE(&sep->pending, e, entry);
			tx = t;
			debug(CCI_DB_CONN, "%s: found conn_reply", __func__);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

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
sock_handle_rma_read_request(sock_conn_t * sconn, sock_rx_t * rx,
			     uint16_t data_len)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	sock_rma_header_t *read = rx->buffer;
	cci_connection_t *connection = NULL;
	sock_ep_t *sep = NULL;
	void *context = NULL;
	int flags = 0;
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
	uint64_t context_id;
	uint64_t recved_data_len;
	sock_header_r_t *hdr_r;

	connection = &conn->connection;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	hdr_r = (sock_header_r_t *) rx->buffer;

	/* Parse the RMA read request message */
	sock_parse_rma_handle_offset(&read->local,
				     &msg_local_handle, &msg_local_offset);
	sock_parse_rma_handle_offset(&read->remote,
				     &msg_remote_handle, &msg_remote_offset);

	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
	sock_handle_seq(sconn, seq);
	memcpy(&recved_data_len, read->data, sizeof(uint64_t));
	memcpy(&context_id, (void *)((char *)read->data + sizeof(uint64_t)),
	       sizeof(uint64_t));

	local_handle = msg_remote_handle;
	local_offset = msg_remote_offset;
	remote_handle = msg_local_handle;
	remote_offset = msg_local_offset;

	flags |= CCI_FLAG_WRITE;
	flags |= CCI_FLAG_SILENT;

	rc = ctp_sock_rma(connection,
		      &context_id, sizeof(uint64_t),
		      local_handle, local_offset,
		      remote_handle, remote_offset, recved_data_len, context, flags);
	if (rc != CCI_SUCCESS)
		debug(CCI_DB_MSG, "%s: RMA Write failed", __func__);

	/* Put the RMA_READ_REQUEST into the pending queue until the msg is
	   acked */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);
}

static void
sock_handle_rma_write(sock_conn_t * sconn, sock_rx_t * rx, uint16_t len)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	sock_ep_t *sep = NULL;
	sock_rma_header_t *write = rx->buffer;
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;	/* our handle */
	uint64_t remote_offset;	/* our offset */
	sock_rma_handle_t *remote, *h;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	sock_parse_rma_handle_offset(&write->local, &local_handle,
				     &local_offset);
	sock_parse_rma_handle_offset(&write->remote, &remote_handle,
				     &remote_offset);
	remote = (sock_rma_handle_t *) (uintptr_t) remote_handle;

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
lookup_contextid(sock_conn_t * sconn, uint64_t context_id, void **context)
{
	/* Remember, the unique ID is actually the index in the array we use to
	   track the different contexts used in context of RMA read operations. */
	void *c;

	if (sconn->rma_contexts == NULL) {
		*context = NULL;
	} else {
		if (sconn->rma_contexts[context_id] != NULL) {
			c = (void*)sconn->rma_contexts[context_id];
			*context = c;
			sconn->rma_contexts[context_id] = NULL;
		} else {
			*context = NULL;
		}
	}
}

static void
sock_handle_rma_write_done(sock_conn_t * sconn, sock_rx_t * rx, uint16_t len)
{
	cci__evt_t *evt;
	cci__conn_t *conn = sconn->conn;
	union cci_event *event;	/* generic CCI event */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	cci__ep_t *ep;
	uint64_t context_id = 0;
	void *context;
	sock_header_r_t *hdr_r = rx->buffer;

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);

	memcpy(&context_id, hdr_r->data, sizeof(uint64_t));

	/* get cci__evt_t to hang on ep->events */
	evt = &rx->evt;

	/* setup the generic event for the application */
	event = & evt->event;
	event->type = CCI_EVENT_RECV;
	event->recv.len = len;
	lookup_contextid (sconn, context_id, &context);
	/* For RMA_READ, we lookup the context based on the received context id
	   For RMA_WRITE, the context_id is actually the context itself */
	if (context != NULL)
		*((void **)&event->recv.ptr) = context;
	else
		*((void **)&event->recv.ptr) = (void*)context_id;
	event->recv.connection = &conn->connection;

	/* queue event on endpoint's completed event queue */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);
}

static inline void sock_drop_msg(cci_os_handle_t sock)
{
	char buf[4];
	struct sockaddr sa;
	socklen_t slen = sizeof(sa);

	recvfrom(sock, buf, 4, 0, &sa, &slen);
	return;
}

static int sock_recvfrom_ep(cci__ep_t * ep)
{
	int ret = 0, drop_msg = 0, q_rx = 0, reply = 0, request = 0, again = 0;
	int ka = 0;
	uint8_t a;
	uint16_t b;
	uint32_t id;
	sock_rx_t *rx = NULL;
	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(sin);
	sock_conn_t *sconn = NULL;
	cci__conn_t *conn = NULL;
	sock_ep_t *sep;
	sock_msg_type_t type;
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
		char tmp_buff[SOCK_UDP_MAX];
		sock_header_t *hdr = NULL;

		debug(CCI_DB_INFO,
		      "no rx buffers available on endpoint %d", sep->sock);

		/* We do the receive using a temporary buffer so we can get enough
		   data to send a RNR NACK */
		ret = recvfrom(sep->sock, (void *)tmp_buff, SOCK_UDP_MAX,
			       0, (struct sockaddr *)&sin, &sin_len);
		if (ret < (int)sizeof(sock_header_t)) {
			debug(CCI_DB_INFO,
			      "Did not receive enough data to get the msg header");
			CCI_EXIT;
			return 0;
		}

		/* Now we get the header and parse it so we can know if we are in the
		   context of a reliable connection */
		hdr = (sock_header_t *) tmp_buff;
		sock_parse_header(hdr, &type, &a, &b, &id);
		sconn =
		    sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
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
			sock_header_r_t *header_r = NULL;

			/* We do the receive using a temporary buffer so we can get enough
			   data to send a RNR NACK */

			/* From the buffer, we get the TS and SEQ from the header (this is 
			   the only we need to deal with RNR) and will be used later on */
			header_r = (sock_header_r_t *) tmp_buff;
			sock_parse_seq_ts(&header_r->seq_ts, &seq, &ts);
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
	if (ret < (int)sizeof(sock_header_t)) {
		q_rx = 1;
		goto out;
	}

	again = 1;

	/* lookup connection from sin and id */

	sock_parse_header(rx->buffer, &type, &a, &b, &id);
	if (SOCK_MSG_CONN_REPLY == type) {
		reply = 1;
	} else if (SOCK_MSG_CONN_REQUEST == type) {
		request = 1;
		rx->sin = sin;
	}

	if (SOCK_MSG_KEEPALIVE == type)
		ka = 1;

	if (!request)
		sconn =
		    sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id,
				   type);

	{
		char name[32];

		if (CCI_DB_MSG & cci__debug) {
			memset(name, 0, sizeof(name));
			sock_sin_to_name(sin, name, sizeof(name));
			debug((CCI_DB_MSG),
			      "ep %d recv'd %s msg from %s with %d bytes",
			      sep->sock, sock_msg_type(type), name, a + b);
		}
	}

	/* if no conn, drop msg, requeue rx */
	if (!ka && !sconn && !reply && !request) {
		debug((CCI_DB_CONN | CCI_DB_MSG),
		      "no sconn for incoming %s msg " "from %s:%d",
		      sock_msg_type(type), inet_ntoa(sin.sin_addr),
		      ntohs(sin.sin_port));
		q_rx = 1;
		goto out;
	}

	if (sconn && cci_conn_is_reliable(sconn->conn) &&
	    !(type == SOCK_MSG_CONN_REPLY)) {
		sock_header_r_t *hdr_r = rx->buffer;
		sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
		sock_handle_seq(sconn, seq);
        if (hdr_r->pb_ack != 0)
            sock_handle_ack (sconn, type, rx, 1, id);
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
	case SOCK_MSG_CONN_REQUEST:
		sock_handle_conn_request(rx, a, b, sin, ep);
		break;
	case SOCK_MSG_CONN_REPLY:
		sock_handle_conn_reply(sconn, rx, a, b, id, sin, ep);
		break;
	case SOCK_MSG_CONN_ACK:
		sock_handle_conn_ack(sconn, rx, a, b, id, sin);
		break;
	case SOCK_MSG_DISCONNECT:
		break;
	case SOCK_MSG_SEND:
		sock_handle_active_message(sconn, rx, b, id);
		break;
	case SOCK_MSG_RNR:{
			sock_header_r_t *hdr_r = rx->buffer;

			sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
			sock_handle_rnr(sconn, seq, ts);
			break;
		}
	case SOCK_MSG_KEEPALIVE:
		/* Nothing to do? */
		break;
	case SOCK_MSG_ACK_ONLY:
	case SOCK_MSG_ACK_UP_TO:
	case SOCK_MSG_SACK:
		sock_handle_ack(sconn, type, rx, (int)a, id);
		break;
	case SOCK_MSG_RMA_WRITE:
		sock_handle_rma_write(sconn, rx, b);
		break;
	case SOCK_MSG_RMA_WRITE_DONE:
		sock_handle_rma_write_done(sconn, rx, b);
		break;
	case SOCK_MSG_RMA_READ_REQUEST:
		sock_handle_rma_read_request(sconn, rx, b);
		break;
	case SOCK_MSG_RMA_READ_REPLY:
		break;
	default:
		debug(CCI_DB_MSG, "unknown active message with type %u",
		      (enum sock_msg_type)type);
	}

out:
	if (q_rx) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	if (drop_msg) {
		if (cci_conn_is_reliable(sconn->conn) && sconn->rnr == seq) {
			char buffer[SOCK_MAX_HDR_SIZE];
			int len = 0;
			sock_header_r_t *hdr_r = NULL;

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
			hdr_r = (sock_header_r_t *) buffer;
			sock_pack_nack(hdr_r,
				       SOCK_MSG_RNR,
				       sconn->peer_id, seq, ts, 0);
			len = sizeof(*hdr_r);

			/* XXX: Should we queue the message or we send it? 
			   I seems to me that it should be queued to maintain order as much as
			   possible (but what about RU connections? */
			sock_sendto(sep->sock, buffer, len, NULL, 0, sconn->sin);
		}

		/* Drop the message */
		sock_drop_msg(sep->sock);
	}

	CCI_EXIT;

	return again;
}

/*
 * Check whether a keeplive timeout expired for a given endpoint.
 */
static void sock_keepalive(cci__ep_t *ep)
{
	cci__conn_t *conn;
	uint64_t now = 0ULL;
	uint32_t ka_timeout;
	uint8_t i;
	struct s_conns *conn_list;
	sock_conn_t *sconn = NULL;
	sock_dev_t *sdev;
	cci__dev_t *dev;
	sock_ep_t *sep = NULL;

	CCI_ENTER;

	now = sock_get_usecs();
	dev = ep->dev;
	sdev = dev->priv;
	sep = ep->priv;
	i = sock_ip_hash(sdev->ip, sdev->port);
	conn_list = &sep->conn_hash[i];
	TAILQ_FOREACH(sconn, conn_list, entry) {
		conn = sconn->conn;
		if (conn->keepalive_timeout == 0ULL)
			return;

		/* The keepalive is assumed to expire if we did not hear anything from the
		   peer since the last receive + keepalive timeout. */
		ka_timeout = sconn->ts + conn->keepalive_timeout;

		if (SOCK_U64_LT(now, ka_timeout)) {
			int len;
			char buffer[SOCK_MAX_HDR_SIZE];
			sock_header_t *hdr = NULL;
			cci_event_keepalive_timedout_t *event = NULL;
			cci__evt_t *evt = NULL;
			cci__ep_t *ep = NULL;
			sock_ep_t *sep = NULL;
			sock_tx_t *tx = NULL;

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
			hdr = (sock_header_t *) buffer;
			sock_pack_keepalive(hdr, sconn->peer_id);
			len = sizeof(*hdr);
			sock_sendto(sep->sock, buffer, len, NULL, 0, sconn->sin);
		}
	}

	CCI_EXIT;
	return;
}

static void sock_ack_conns(cci__ep_t * ep)
{
	int i;
	sock_ep_t *sep = ep->priv;
	sock_conn_t *sconn = NULL;
	sock_tx_t *tx = NULL;
	static uint64_t last = 0ULL;
	uint64_t now = 0ULL;
	cci__evt_t *evt;

	TAILQ_HEAD(s_txs, sock_tx) txs = TAILQ_HEAD_INITIALIZER(txs);
	TAILQ_INIT(&txs);

	CCI_ENTER;

	now = sock_get_usecs();

	if (last == 0ULL)
		last = now;
	else if (last + 10ULL > now)
		return;

	last = now;

	pthread_mutex_lock(&ep->lock);
	for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
		if (!TAILQ_EMPTY(&sep->conn_hash[i])) {
			TAILQ_FOREACH(sconn, &sep->conn_hash[i], entry) {
				if (!TAILQ_EMPTY(&sconn->acks)) {
					int count = 1;
					sock_header_r_t *hdr_r;
					uint32_t acks[SOCK_MAX_SACK * 2];
					sock_ack_t *ack = NULL;
					sock_msg_type_t type =
					    SOCK_MSG_ACK_UP_TO;
					char buffer[SOCK_MAX_HDR_SIZE];
					int len = 0;

					memset(buffer, 0, sizeof(buffer));

					if (1 == sock_need_sack(sconn)) {
						sock_ack_t *tmp;

						type = SOCK_MSG_SACK;
						count = 0;

						TAILQ_FOREACH_SAFE(ack, &sconn->acks, entry, tmp) {
							TAILQ_REMOVE (&sconn->acks, ack, entry);
							acks[count++] = ack->start;
							acks[count++] = ack->end;
							free(ack);
							if (count == SOCK_MAX_SACK * 2)
								break;
						}
						if (acks[0] == sconn->acked + 1) {
							sconn->acked = acks[1];
						}
					} else {
						ack = TAILQ_FIRST(&sconn->acks);
                        if (SOCK_U64_LT(now, sconn->last_ack_ts + ACK_TIMEOUT)
                           && (ack->end - ack->start < PENDING_ACK_THRESHOLD)) {
                            debug (CCI_DB_MSG, "Delaying ACK");
                            break;
                        }
						TAILQ_REMOVE(&sconn->acks, ack,
							     entry);
						if (ack->start == sconn->acked)
							sconn->acked = ack->end;
						acks[0] = ack->end;
                        /* If we have a single pending ACK, we send a 
                           SOCK_MSG_ACK_ONLY ACK, otherwise we send a
                           SOCK_MSG_ACK_UP_TO ACK */
						if (ack->start == ack->end)
							type = SOCK_MSG_ACK_ONLY;
						free(ack);
					}
					hdr_r = (sock_header_r_t *) buffer;
					sock_pack_ack(hdr_r, type,
						      sconn->peer_id, 0, 0,
						      acks, count);

					len =
					    sizeof(*hdr_r) +
					    (count * sizeof(acks[0]));
					sock_sendto(sep->sock, buffer, len, NULL, 0, sconn->sin);
                    sconn->last_ack_ts = now;
				}
			}
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&txs)) {
		tx = TAILQ_FIRST(&txs);
        evt = &tx->evt;
		TAILQ_REMOVE(&txs, tx, dentry);
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&sep->queued, evt, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	/* Since a ACK was issued, we try to receive more data */
	if (sconn != NULL && sconn->last_ack_ts == now)
		sock_recvfrom_ep (ep);

	CCI_EXIT;
	return;
}

static void *sock_progress_thread(void *arg)
{
	cci__ep_t *ep = (cci__ep_t *) arg;
	sock_ep_t *sep;

	assert (ep);
	sep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	while (!sep->closing) {

		pthread_mutex_unlock(&ep->lock);

		sock_keepalive (ep);
		sock_progress_sends (ep);

		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_wait(&sep->wait_condition, &sep->progress_mutex);
		pthread_mutex_unlock(&sep->progress_mutex);

		pthread_mutex_lock(&ep->lock);
	}
	pthread_mutex_unlock(&ep->lock);

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}

static void *sock_recv_thread(void *arg)
{
	int ret = 0;
	struct timeval tv = { 0, SOCK_PROG_TIME_US };
	fd_set fds;
	int again;
	cci__ep_t *ep = (cci__ep_t *)arg;
	sock_ep_t *sep;

	assert (ep);
	sep = ep->priv;
	while (!sep->closing) {
		FD_ZERO(&fds);
		FD_SET (sep->sock, &fds);
		ret = select (sep->sock + 1, &fds, NULL, NULL, &tv);
		if (ret == -1) {
			switch (errno) {
			case EBADF:
				debug(CCI_DB_INFO, "select() failed with %s",
				      strerror(errno));
				break;
			default:
				break;
			}
			goto wait4signal;
		}

		do {
			again = sock_recvfrom_ep (ep);
		} while (again == 1);
wait4signal:
		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_signal(&sep->wait_condition);
		pthread_mutex_unlock(&sep->progress_mutex);
	}

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}

