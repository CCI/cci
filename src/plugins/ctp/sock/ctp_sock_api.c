/* vim: set tabstop=8:softtabstop=8:shiftwidth=8:noexpandtab */

/*
* Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
* Copyright © 2010-2013 UT-Battelle, LLC. All rights reserved.
* Copyright © 2010-2013 Oak Ridge National Labs.  All rights reserved.
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
#endif /*   __INTEL_COMPILER	*/

#include "cci/private_config.h"

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


#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#else
#include <poll.h>
#endif /* HAVE_SYS_EPOLL_H */

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/ctp/ctp.h"
#include "ctp_sock_internals.h"

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
static int ctp_sock_init(cci_plugin_ctp_t *plugin,
                         uint32_t abi_ver,
                         uint32_t flags,
                         uint32_t * caps);
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
static int ctp_sock_connect(cci_endpoint_t * endpoint,
                            const char *server_uri,
                            const void *data_ptr,
                            uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            const void *context,
                            int flags,
                            const struct timeval *timeout);
static int ctp_sock_disconnect(cci_connection_t * connection);
static int ctp_sock_set_opt(cci_opt_handle_t * handle,
                            cci_opt_name_t name,
                            const void *val);
static int ctp_sock_get_opt(cci_opt_handle_t * handle,
                            cci_opt_name_t name,
                            void *val);
static int ctp_sock_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_sock_get_event(cci_endpoint_t * endpoint,
                              cci_event_t ** const event);
static int ctp_sock_return_event(cci_event_t * event);
static int ctp_sock_send(cci_connection_t * connection,
                         const void *msg_ptr,
                         uint32_t msg_len,
                         const void *context,
                         int flags);
static int ctp_sock_sendv(cci_connection_t * connection,
                          const struct iovec *data,
                          uint32_t iovcnt,
                          const void *context,
                          int flags);
static int ctp_sock_rma_register(cci_endpoint_t * endpoint,
                                 void *start,
                                 uint64_t length,
                                 int flags,
                                 cci_rma_handle_t ** rma_handle);
static int ctp_sock_rma_deregister(cci_endpoint_t * endpoint,
                                   cci_rma_handle_t * rma_handle);
static int ctp_sock_rma(cci_connection_t * connection,
                        const void *header_ptr,
                        uint32_t header_len,
                        cci_rma_handle_t * local_handle,
                        uint64_t local_offset,
                        cci_rma_handle_t * remote_handle,
                        uint64_t remote_offset,
                        uint64_t data_len,
                        const void *context,
                        int flags);
static uint8_t sock_ip_hash(in_addr_t ip, uint16_t port);
static void sock_progress_sends(cci__ep_t * ep);
static void *sock_progress_thread(void *arg);
static void *sock_recv_thread(void *arg);
static void sock_ack_conns(cci__ep_t * ep);
static inline int pack_piggyback_ack(cci__ep_t *ep,
                                     sock_conn_t *sconn, sock_tx_t *tx);
static inline int sock_ack_sconn(sock_ep_t *sep, sock_conn_t *sconn);
static int sock_recvfrom_ep(cci__ep_t * ep);
int progress_recv (cci__ep_t *ep);

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

static inline int
sock_recv_msg (int fd,
               void *ptr,
               uint32_t len,
               int flags,
               struct sockaddr_in *sin_out)
{
	int ret 		= 0;
	uint32_t recv_len	= 0;
	static int count	= 0;	
	uint32_t offset		= 0;
	struct sockaddr_in sin;
	socklen_t sin_len       = sizeof(sin);

	if (len == 0)
		return ret;

again:
	do {
		ret = recvfrom (fd, (void*) ((uintptr_t)ptr + offset), len - recv_len, flags, (struct sockaddr *)&sin, &sin_len);
		if (ret < 0) {
			if ((count++ & 0xFFFF) == 0xFFFF)
				debug (CCI_DB_EP, "%s: recvfrom() failed with %s (%u of %u bytes)", __func__,  strerror(ret), recv_len, len);
			if (ret == EAGAIN)
				goto again;
			goto out;
		} else if (ret == 0) {
			debug (CCI_DB_MSG, "%s: recvfrom() failed - socket closed", __func__);
			ret = -1;
			goto out;
		}
		recv_len += ret;
		offset += recv_len;
	} while (recv_len < len);

	ret = recv_len;
	if (sin_out != NULL)
		*sin_out = sin;
out:
	return ret;
}

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
    case SOCK_MSG_NACK:
        return "negative ack";
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

static inline void sock_drop_msg(cci_os_handle_t sock)
{
        char buf[4];
        struct sockaddr sa;
        socklen_t slen = sizeof(sa);

        recvfrom(sock, buf, 4, 0, &sa, &slen);
        return;
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
	CCI_ENTER;

	assert (sep);

	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

	pthread_join(sep->progress_tid, NULL);
	pthread_join(sep->recv_tid, NULL);

	CCI_EXIT;

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

	/* Some unused parameters, the following avoids warnings from 
	   compilers */
	UNUSED_PARAM (abi_ver);
	UNUSED_PARAM (flags);
	UNUSED_PARAM (caps);

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
			const char *interface = NULL;
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
			sdev->bufsize = 0;

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

					/* network order */
					sdev->ip = inet_addr(ip);
				} else if (0 == strncmp("mtu=", *arg, 4)) {
					const char *mtu_str = *arg + 4;
					mtu = strtol(mtu_str, NULL, 0);
				} else if (0 == strncmp("port=", *arg, 5)) {
					const char *s_port = *arg + 5;
					uint16_t    port;
					port = atoi (s_port);
					sdev->port = htons(port);
				} else if (0 == strncmp("bufsize=", *arg, 8)) {
					const char *size_str = *arg + 8;
					sdev->bufsize = strtol(size_str,
					                       NULL, 0);
				} else if (0 == strncmp("interface=",
				                        *arg, 10))
				{
					interface = *arg + 10;
				}
			}
			if (sdev->ip != 0 || interface) {
				/* try to get the actual values now */
#ifdef HAVE_GETIFADDRS
				if (addrs) {
					for (addr = addrs;
					     addr != NULL;
					     addr = addr->ifa_next)
					{
						struct sockaddr_in *sai;
						if (!addr->ifa_addr)
							continue;
						if (addr->ifa_addr->sa_family != AF_INET)
							continue;
						sai = (struct sockaddr_in *) addr->ifa_addr;
						if (!memcmp(&sdev->ip, &sai->sin_addr, sizeof(sdev->ip)))
							break;
						if (interface &&
							!strcmp(interface, addr->ifa_name)) {
							memcpy(&sdev->ip, &sai->sin_addr, sizeof(sdev->ip));
							break;
						}
					}
					if (!addr)
						/* no such device, don't initialize it */
						continue;

					cci__get_dev_ifaddrs_info(dev, addr);
				}
#endif
				if (mtu == (uint32_t) -1) {
					/* if mtu not specified, use the ifaddr one */
					mtu = device->max_send_size;
				}

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

/* TODO */
static const char *ctp_sock_strerror(cci_endpoint_t * endpoint,
				enum cci_status status)
{
	CCI_ENTER;

	UNUSED_PARAM (endpoint);
	UNUSED_PARAM (status);

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

	UNUSED_PARAM (plugin);

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

	UNUSED_PARAM (type);
	UNUSED_PARAM (p);

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
	int ret;
	uint32_t i;
	sock_dev_t *sdev;
	struct sockaddr_in sin;
	socklen_t slen;
	char name[40];
	unsigned int sndbuf_size 	= SOCK_SNDBUF_SIZE;
	unsigned int rcvbuf_size 	= SOCK_RCVBUF_SIZE;
	cci__dev_t *dev 		= NULL;
	cci__ep_t *ep 			= NULL;
	sock_ep_t *sep 			= NULL; 
	struct cci_endpoint *endpoint	= (struct cci_endpoint *) *endpointp;

	CCI_ENTER;

	UNUSED_PARAM (flags);

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

	sdev = dev->priv;

	if (sndbuf_size < sdev->bufsize)
		sndbuf_size = sdev->bufsize;
	if (rcvbuf_size < sdev->bufsize)
		rcvbuf_size = sdev->bufsize;

	if (sndbuf_size > 0) {
		ret = setsockopt (sep->sock, SOL_SOCKET, SO_SNDBUF,
		                  &sndbuf_size, sizeof (sndbuf_size));
		if (ret == -1)
			debug (CCI_DB_WARN,
			       "%s: Cannot set send buffer size", __func__);
	}

	if (rcvbuf_size > 0) {
		ret = setsockopt (sep->sock, SOL_SOCKET, SO_RCVBUF,
		                  &rcvbuf_size, sizeof (rcvbuf_size));
		if (ret == -1)
			debug (CCI_DB_WARN, "%s: Cannot set recv buffer size",
			       __func__);
	}

#if CCI_DEBUG
	{
		socklen_t optlen;

		optlen = sizeof (sndbuf_size);
		ret = getsockopt (sep->sock, SOL_SOCKET, SO_SNDBUF,
				  &sndbuf_size, &optlen);
		if (ret == -1)
			debug (CCI_DB_WARN, "%s: Cannot get send buffer size",
			       __func__);
		debug (CCI_DB_CTP, "Send buffer size: %d bytes (you may also "
		       "want to check the value of net.core.wmem_max using "
		       "sysctl)", sndbuf_size);

		optlen = sizeof (rcvbuf_size);
		ret = getsockopt (sep->sock, SOL_SOCKET, SO_RCVBUF,
		                  &rcvbuf_size, &optlen);
		if (ret == -1)
			debug (CCI_DB_WARN, "%s: Cannot get recv buffer size",
			       __func__);
		debug (CCI_DB_CTP, "Receive buffer size: %d bytes (you may also "
		                   "want to check the value of net.core.rmem_max using "
		                   "sysctl)", rcvbuf_size);
	}
#endif

	/* bind socket to device */
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
	sprintf(name, "sock://");
	sock_sin_to_name(sep->sin, name + (uintptr_t) 7, sizeof(name) - 7);
	ep->uri = strdup(name);

	for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
		TAILQ_INIT(&sep->conn_hash[i]);
		TAILQ_INIT(&sep->active_hash[i]);
	}

	TAILQ_INIT(&sep->idle_txs);
	TAILQ_INIT(&sep->idle_rxs);
	TAILQ_INIT(&sep->handles);
	TAILQ_INIT(&sep->rma_ops);
	TAILQ_INIT(&sep->queued);
	TAILQ_INIT(&sep->pending);

	sep->tx_buf = calloc (1, ep->tx_buf_cnt * ep->buffer_len);
	if (!sep->tx_buf) {
		ret = CCI_ENOMEM;
		goto out;
	}

	sep->txs = calloc (1, ep->tx_buf_cnt * sizeof (sock_tx_t));
	if (!sep->txs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* alloc txs */
	for (i = 0; i < ep->tx_buf_cnt; i++) {
		sock_tx_t *tx = &sep->txs[i];

		tx->ctx = SOCK_CTX_TX;
		tx->evt.event.type = CCI_EVENT_SEND;
		tx->evt.ep = ep;
		tx->buffer = (void*)((uintptr_t)sep->tx_buf
		                     + (i * ep->buffer_len));
		tx->len = 0;
		TAILQ_INSERT_TAIL(&sep->idle_txs, tx, dentry);
	}

	sep->rx_buf = calloc (1, ep->rx_buf_cnt * ep->buffer_len);
	if (!sep->rx_buf) {
		ret = CCI_ENOMEM;
		goto out;
	}

	sep->rxs = calloc (1, ep->rx_buf_cnt * sizeof (sock_rx_t));
	if (!sep->rx_buf) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* alloc rxs */
	for (i = 0; i < ep->rx_buf_cnt; i++) {
		sock_rx_t *rx = &sep->rxs[i];

		rx->ctx = SOCK_CTX_RX;
		rx->evt.event.type = CCI_EVENT_RECV;
		rx->evt.ep = ep;
		rx->buffer = (void*)((uintptr_t)sep->rx_buf
		                     + (i * ep->buffer_len));
		rx->len = 0;
		TAILQ_INSERT_TAIL(&sep->idle_rxs, rx, entry);
	}

	ret = sock_set_nonblocking(sep->sock, SOCK_FD_EP, ep);
	if (ret)
		goto out;

	sep->event_fd = 0;
#ifdef HAVE_SYS_EPOLL_H
	if (fd) {
		int fflags = 0;
		int rc;
		struct epoll_event ev;

		ret = epoll_create (2);
		if (ret == -1) {
			ret = errno;
			goto out;
		}
		sep->event_fd = ret;

		fflags = fcntl(sep->event_fd, F_GETFL, 0);
		if (fflags == -1) {
			ret = errno;
			goto out;
		}

		ret = fcntl(sep->event_fd, F_SETFL, fflags | O_NONBLOCK);
		if (ret == -1) {
			ret = errno;
			goto out;
		}

		ev.data.ptr = (void*)(uintptr_t)sock_recvfrom_ep;
		ev.events = EPOLLIN;
		ret = epoll_ctl (sep->event_fd, EPOLL_CTL_ADD, sep->sock, &ev);
		if (ret == -1) {
			ret = errno;
			goto out;
		}

		rc = pipe (sep->fd);
		if (rc == -1) {
			debug (CCI_DB_WARN, "%s: %s", __func__, strerror (errno));
			return CCI_ERROR;
		}
		*fd = sep->fd[0];
	}
#else
	if (fd) {
		/* We will have poll on the receive thread so we just need to create a
		   pipe so the receive and send thread can wake up the application
		   thread */
		pipe (sep->fd);
		*fd = sep->fd[0];
		/* We set event_fd to value different than zero to know that we are
		   in blocking mode at the application level */
		sep->event_fd = 1;
	}
#endif /* HAVE_SYS_EPOLL_H */

	ret = sock_create_threads (ep);
	if (ret)
		goto out;

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	/* Note that there is no need to remove the ep even in the context of
	   a failure because the ep is added to the list of active endpoints
	   by cci_create_endpoint(), AFTER the call to this function. */
	if (sep) {
		if (sep->txs)
			free (sep->txs);
		if (sep->tx_buf)
			free (sep->tx_buf);

		if (sep->rxs)
			free (sep->rxs);
		if (sep->rx_buf)
			free (sep->rx_buf);

		if (sep->ids)
			free(sep->ids);
		if (sep->sock)
			sock_close_socket(sep->sock);
		free(sep);
	}
	if (ep) {
		if (ep->uri)
			free (ep->uri);
		free (ep);
	}
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

		if (sep->fd[0] > 0)
			close (sep->fd[0]);
		if (sep->fd[1] > 0)
			close (sep->fd[1]);

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
				TAILQ_REMOVE(&sep->active_hash[i], sconn, entry);
				conn = sconn->conn;
				free(conn);
				free(sconn);
			}
		}

		free (sep->txs);
		free (sep->tx_buf);

		free (sep->rxs);
		free (sep->rx_buf);

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
	ep->priv = NULL;
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

#if 0
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
#endif

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
	tx = sock_get_tx (ep);
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

	hs = (sock_handshake_t *)((uintptr_t)rx->buffer +
	                          (uintptr_t) sizeof(sock_header_r_t));
	sock_parse_handshake(hs, &id, &ack, &max_recv_buffer_count, &mss, &ka);
	if (ka != 0UL) {
		debug(CCI_DB_CONN, "%s: keepalive timeout: %d", __func__, ka);
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
	sconn->last_recvd_seq = 0;
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

	debug_ep(ep, CCI_DB_CONN, "%s: accepting conn with hash %d",
	         __func__, i);

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
	hs = (sock_handshake_t *) ((uintptr_t)tx->buffer + sizeof(*hdr_r));
	sock_pack_handshake(hs, sconn->id, peer_seq,
				ep->rx_buf_cnt,
				conn->connection.max_send_size, 0);

	tx->len = sizeof(*hdr_r) + sizeof(*hs);
	tx->seq = sconn->seq;

	debug_ep(ep, CCI_DB_CONN, "%s: queuing conn_reply with seq %u ts %x", 
	         __func__, sconn->seq, sconn->ts);

	/* insert at tail of device's queued list */

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */
	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);
	
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
	sock_rx_t *rx = NULL;
	sock_tx_t *tx = NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	sep = ep->priv;
	rx = container_of(evt, sock_rx_t, evt);
	hdr_r = rx->buffer;
	sock_parse_header(&hdr_r->header, &type, &a, &b, &peer_id);
	sock_parse_seq_ts(&hdr_r->seq_ts, &peer_seq, &peer_ts);

	/* get a tx */
	tx = sock_get_tx (ep);
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
	tx->evt.event.connect.status = CCI_ECONNREFUSED;
	tx->evt.event.connect.connection = NULL;
	tx->last_attempt_us = 0ULL;
	tx->timeout_us = 0ULL;
	tx->rma_op = NULL;
	tx->sin = rx->sin;

	/* prepare conn_reply */
	hdr_r = (sock_header_r_t *) tx->buffer;
	sock_pack_conn_reply(&hdr_r->header, CCI_ECONNREFUSED, peer_id);
	sock_pack_seq_ts(&hdr_r->seq_ts, peer_seq, 0);

	tx->len = sizeof(*hdr_r);
	tx->state = SOCK_TX_QUEUED;
	/* We have no connection and the request is rejected so we generate
	   a new seq since the client may or not ack the conn_reply. In the
	   worst case, the conn_reply associated to the reject is thrown away
	   when it times out */
	tx->seq = sock_get_new_seq ();

	/* insert at tail of endpoint's queued list */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */
	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);
	
#if CCI_DEBUG
	{
		char name[32];
		memset(name, 0, sizeof(name));
		sock_sin_to_name(rx->sin, name, sizeof(name));
		debug_ep(ep, (CCI_DB_MSG | CCI_DB_CONN),
		         "%s: queued conn_reply (reject) to %s (seq %u)",
		         __func__, name, tx->seq);
	}
#endif

out:
	CCI_EXIT;
	return ret;
}

static int sock_getaddrinfo(const char *uri, in_addr_t * in, uint16_t * port)
{
	int ret;
	char *hostname, *svc, *colon;
	struct addrinfo *ai = NULL, hints;

	if (0 == strncmp("sock://", uri, 7))
		hostname = strdup(&uri[7]);
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

static int ctp_sock_connect(cci_endpoint_t * endpoint,
                            const char *server_uri,
                            const void *data_ptr,
                            uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            const void *context,
                            int flags,
                            const struct timeval *timeout)
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

	UNUSED_PARAM (flags);
	UNUSED_PARAM (timeout);

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
	sconn->last_recvd_seq = 0;
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
	tx = sock_get_tx (ep);
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
	sock_pack_conn_request(&hdr_r->header, attribute,
				(uint16_t) data_len, sconn->id);
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
	ptr = (void*)((uintptr_t)tx->buffer + tx->len);

	debug_ep(ep,CCI_DB_CONN, "%s: queuing conn_request with seq %u ts %x",
	         __func__, tx->seq, ts);

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
	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

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
		conn->tx_timeout = *((uint32_t*) val);
		break;
	default:
		debug(CCI_DB_INFO, "%s: unknown option %u", __func__, name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;

	return ret;
}

static int ctp_sock_get_opt(cci_opt_handle_t * handle,
			cci_opt_name_t name, void *val)
{
	int ret 			= CCI_SUCCESS;
	cci_endpoint_t *endpoint	= NULL;
	cci__ep_t *ep 			= NULL;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	endpoint = handle;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	assert (ep);
	

	switch (name) {
		case CCI_OPT_ENDPT_RECV_BUF_COUNT:
			{
				uint32_t *cnt = val;
				*cnt = ep->rx_buf_cnt;
				break;
			}
		case CCI_OPT_ENDPT_SEND_BUF_COUNT:
			{
				uint32_t *cnt = val;
				*cnt = ep->tx_buf_cnt;
				break;
			}
		case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
			{
				uint32_t *timeout = val;
				*timeout = ep->keepalive_timeout;
				break;
			}
		default:
			/* Invalid opt name */
			ret = CCI_EINVAL;
	}

	CCI_EXIT;

	return ret;
}

static int ctp_sock_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	UNUSED_PARAM (endpoint);
	UNUSED_PARAM (flags);

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int
ctp_sock_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep;
	sock_ep_t *sep;
	cci__evt_t *ev = NULL, *e;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	/* try to progress sends... */
	if (!sep->closing) {
		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_signal(&sep->wait_condition);
		pthread_mutex_unlock(&sep->progress_mutex);
	}

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

	if (ev) {
		TAILQ_REMOVE(&ep->evts, ev, entry);
		*event = &ev->event;
	} else {
		*event = NULL;
		/* No event is available and there are no available
		   receive buffers. The application must return events
		   before any more messages can be received. */
                if (TAILQ_EMPTY(&sep->idle_rxs)) {
                        ret = CCI_ENOBUFS;
                } else {
			ret = CCI_EAGAIN;
		}
	}

	pthread_mutex_unlock(&ep->lock);

	/* We read on the fd to block again */
	if (ev && sep->event_fd) {
		char a[1];
		int rc;

		/* We bock again only and only if there is no more
		   pending events */
		if (event_queue_is_empty (ep)) {
			/* Draining events so the app thread can block */
			rc = read (sep->fd[0], a, sizeof (a));
			if (rc != sizeof (a)) {
				ret = CCI_ERROR;
			}
		}
	}

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
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (!event) {
		CCI_EXIT;
		return CCI_SUCCESS;
	}

	evt = container_of(event, cci__evt_t, event);

	ep = evt->ep;
	sep = ep->priv;

	/* enqueue the event */

	switch (event->type) {
	case CCI_EVENT_SEND:
	case CCI_EVENT_ACCEPT:
		tx = container_of(evt, sock_tx_t, evt);
		pthread_mutex_lock(&ep->lock);
		/* insert at head to keep it in cache */
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
		break;
	case CCI_EVENT_RECV:
	case CCI_EVENT_CONNECT_REQUEST:
		rx = container_of(evt, sock_rx_t, evt);
		pthread_mutex_lock(&ep->lock);
		/* insert at head to keep it in cache */
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
		break;
	case CCI_EVENT_CONNECT:
		rx = container_of (evt, sock_rx_t, evt);
		if (rx->ctx == SOCK_CTX_RX) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD (&sep->idle_rxs, rx, entry);
			pthread_mutex_unlock(&ep->lock);
		} else {
			tx = (sock_tx_t*)rx;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD (&sep->idle_txs, tx, dentry);
			pthread_mutex_unlock(&ep->lock);
		}
		break;
	default:
		debug (CCI_DB_EP,
		       "%s: unhandled %s event", __func__,
		       cci_event_type_str(event->type));
		ret = CCI_ERROR;
		break;
	}

	CCI_EXIT;

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
	sock_conn_t *sconn 	= NULL;
	sock_ep_t *sep 		= ep->priv;

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs
		= TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_INIT(&idle_txs);                                                  
        TAILQ_INIT(&evts);

	CCI_ENTER; 

	now = sock_get_usecs();

	/* This is only for reliable messages.
	* Do not dequeue txs, just walk the list.
	*/

	pthread_mutex_lock (&ep->lock);
	TAILQ_FOREACH_SAFE(evt, &sep->pending, entry, tmp) {
		sock_tx_t *tx = container_of (evt, sock_tx_t, evt);

		conn = evt->conn;
		if (conn)
			sconn = conn->priv;
		event = &evt->event;

		assert(tx->last_attempt_us != 0ULL);

		/* has it timed out? */
		if (SOCK_U64_LT(tx->timeout_us, now)) {
			/* dequeue */

			debug_ep(ep, CCI_DB_WARN,
			         "%s: timeout of %s msg (seq %u)",
			         __func__, sock_msg_type(tx->msg_type),
			         tx->seq);

			TAILQ_REMOVE(&sep->pending, &tx->evt, entry);

			/* set status and add to completed events */

			if (tx->msg_type == SOCK_MSG_SEND)
				sconn->pending--;

			switch (tx->msg_type) {
			case SOCK_MSG_SEND:
				event->send.status = CCI_ETIMEDOUT;
				if (tx->rnr != 0) {
					event->send.status = CCI_ERR_RNR;
					/* If a message that is already marked
					   RNR times out, and if the connection
					   is reliable and ordered, we mark all
					   following messages as RNR */
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
			case SOCK_MSG_RMA_READ_REQUEST:
			case SOCK_MSG_RMA_WRITE:
				pthread_mutex_lock(&ep->lock);
				tx->rma_op->pending--;
				tx->rma_op->status = CCI_ETIMEDOUT;
				pthread_mutex_unlock(&ep->lock);
				break;
			case SOCK_MSG_CONN_REQUEST: {
				int i;
				struct s_active *active_list;

				event->connect.status = CCI_ETIMEDOUT;
				event->connect.connection = NULL;
				if (conn->uri)
					free((char *)conn->uri);
				sconn->status = SOCK_CONN_CLOSING;
				i = sock_ip_hash(sconn->sin.sin_addr.s_addr,
				                 0);
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
			case SOCK_MSG_CONN_REPLY: {
				/* The client is not requiered to ack a
				   conn_reply in the context of a reject, so
				   we just ignore the timeout in that
				   context */
				if (tx->evt.event.connect.status
				    == CCI_ECONNREFUSED)
				{
					/* store locally until we can drop the
					   dev->lock */
					debug_ep (ep, CCI_DB_CONN,
					          "%s: No ACK of the reject, "
					          "dropping pending msg",
					          __func__);
					TAILQ_INSERT_HEAD(&idle_txs,
					                  tx,
					                  dentry);
					break;
				}
			}
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
				/* store locally until we can drop the
				   dev->lock */
				TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
			} else {
				tx->state = SOCK_TX_COMPLETED;
				/* store locally until we can drop the
				   dev->lock */
				TAILQ_INSERT_TAIL(&evts, evt, entry);
			}
			continue;
		}

		/* is it time to resend? */

		if ((tx->last_attempt_us +
		    ((1 << tx->send_count) * SOCK_RESEND_TIME_SEC * 1000000)) >
		     now) {
			continue;
		}

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

		debug_ep(ep, CCI_DB_MSG,
		         "%s: re-sending %s msg seq %u count %u",
		         __func__, sock_msg_type(tx->msg_type), tx->seq,
		         tx->send_count);
		pack_piggyback_ack (ep, sconn, tx);
		ret = sock_sendto(sep->sock, tx->buffer, tx->len, tx->rma_ptr,
		                  tx->rma_len, sconn->sin);
		if (tx->rma_ptr == NULL && ret != tx->len) {
			debug((CCI_DB_MSG | CCI_DB_INFO),
			      "%s: sendto() failed with %s (%d/%d)", __func__,
			      cci_strerror(&ep->endpoint, (enum cci_status)errno),
			      ret, tx->len);
			continue;
		}

		if (tx->rma_ptr != NULL && ret != (tx->rma_len + tx->len)) {
			debug((CCI_DB_MSG | CCI_DB_INFO),
			      "%s: sendto() failed with %s (%d/%d)", __func__,
			      cci_strerror(&ep->endpoint, (enum cci_status)errno),
			      ret, tx->rma_len);
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
		sock_queue_event (ep, evt);
		if (sep->event_fd) {
			int rc;
			rc = write (sep->fd[1], "a", 1);
			if (rc != 1) {
				debug (CCI_DB_WARN, "%s: Write failed", __func__);
				return;
			}
		}
	}

	CCI_EXIT;

	return;
}

static inline int 
pack_piggyback_ack (cci__ep_t *ep, sock_conn_t *sconn, sock_tx_t *tx)
{
	sock_ack_t *ack = NULL;
	uint64_t now = 0ULL;

	UNUSED_PARAM (ep);

    if (!cci_conn_is_reliable(sconn->conn))
        return CCI_SUCCESS;

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
	int ret, is_reliable = 0;
	uint32_t timeout;
	uint64_t now;
	sock_tx_t *tx;
	cci__evt_t *evt, *tmp;
	cci__conn_t *conn;
	sock_ep_t *sep = ep->priv;
	sock_conn_t *sconn;
	union cci_event *event = NULL;	/* generic CCI event */

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs
		= TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);

	CCI_ENTER;

	TAILQ_INIT(&idle_txs);
	TAILQ_INIT(&evts);

	if (!sep)
		return;

	now = sock_get_usecs();

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(evt, &sep->queued, entry, tmp) {
		tx = container_of (evt, sock_tx_t, evt);
		event = &evt->event;
		/* If we deal with a CONN_REJECT, we do not have a
		   valid connection */
		if (tx->msg_type == SOCK_MSG_CONN_REPLY
		    && tx->evt.event.connect.status == CCI_ECONNREFUSED) {
			conn = NULL;
			sconn = NULL;
		} else {
			conn = evt->conn;
			sconn = conn->priv;
			is_reliable = cci_conn_is_reliable(conn);
		}

		/* try to send it */

		/*
		   RMA_READ_REPLY message are a special case: they act as an
		   ACK. For this reason, we do not handle any kind of timeout
		   for RMA_READ_REPLY messages 
		   SOCK_MSG_CONN_REPLY in the context of a reject are also a
		   special case because we do not have a valid connection yet
		*/
		if (!(tx->msg_type == SOCK_MSG_RMA_READ_REPLY ||
		      (tx->msg_type == SOCK_MSG_CONN_REPLY
                       && tx->evt.event.connect.status == CCI_ECONNREFUSED)))
		{
			if (tx->timeout_us == 0ULL) {
				timeout =
					conn->tx_timeout ? conn->tx_timeout
				                         : ep->tx_timeout;
				tx->timeout_us = now + (uint64_t) timeout; 
			}

			if (SOCK_U64_LT(tx->timeout_us, now)) {

				/* set status and add to completed events */
				switch (tx->msg_type) {
				case SOCK_MSG_SEND:
					if (tx->rnr != 0) {
						event->send.status
							= CCI_ERR_RNR;
					} else {
						event->send.status
							= CCI_ETIMEDOUT;
					}
					break;
				case SOCK_MSG_CONN_REQUEST:
					/* FIXME only CONN_REQUEST gets an
					 * event the other two need to
					 * disconnect the conn */
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
					debug(CCI_DB_WARN,
					      "%s: timeout of %s msg",
					      __func__,
					      sock_msg_type(tx->msg_type));
					pthread_mutex_lock(&ep->lock);
					CCI_EXIT;
					return;
				}
				TAILQ_REMOVE(&sep->queued, evt, entry);

				/* if SILENT, put idle tx */
				if (tx->flags & CCI_FLAG_SILENT &&
				    (tx->msg_type == SOCK_MSG_SEND ||
				     tx->msg_type == SOCK_MSG_RMA_WRITE))
				{
					tx->state = SOCK_TX_IDLE;
					/* store locally until we can drop the
					 * dev->lock */
					TAILQ_INSERT_HEAD(&idle_txs,
					                  tx, dentry);
				} else {
					tx->state = SOCK_TX_COMPLETED;
					/* store locally until we can drop the
					 * dev->lock */
					TAILQ_INSERT_TAIL(&evts, evt, entry);
				}
				continue;
			} /* end timeout case */
	
			if (tx->last_attempt_us
			    + (SOCK_RESEND_TIME_SEC * 1000000) > now)
			{
				continue;
			}
		}

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
		      tx->msg_type == SOCK_MSG_CONN_REPLY))
		{
			TAILQ_INSERT_TAIL(&sconn->tx_seqs, tx, tx_seq);
		}

#if 0
		/* if reliable and ordered, we have to check whether the tx is marked
		   RNR */
		if (is_reliable
		    && conn
		    && conn->connection.attribute == CCI_CONN_ATTR_RO 
		    && tx->rnr != 0)
		{
			event->send.status = CCI_ERR_RNR;
		}
#endif

		/* For RMA Writes and RMA read request, we only allow a given
		   number of messages to be in fly */
		if (tx->msg_type == SOCK_MSG_RMA_WRITE ||
		    tx->msg_type == SOCK_MSG_RMA_READ_REQUEST)
		{
			if (tx->rma_op->pending >= SOCK_RMA_DEPTH) {
				continue;
			}
		}

		/* need to send it */

		debug_ep(ep, CCI_DB_MSG, "%s: sending %s msg seq %u",
		         __func__, sock_msg_type(tx->msg_type), tx->seq);
		if (tx->msg_type != SOCK_MSG_RMA_READ_REPLY &&
		    tx->msg_type != SOCK_MSG_CONN_REPLY)
		{
			pack_piggyback_ack (ep, sconn, tx);
		}

		/* If we deal with a CONN_REJECT, we do not have a
		   valid connection */
		if (tx->msg_type == SOCK_MSG_CONN_REPLY
		    && tx->evt.event.connect.status == CCI_ECONNREFUSED) {
			ret = sock_sendto(sep->sock, tx->buffer, tx->len,
			                  tx->rma_ptr, tx->rma_len, tx->sin);
		} else if (tx->msg_type == SOCK_MSG_RMA_WRITE_DONE) {
			/* RMA_WRITE_DONE msg are normal messages even if
			   associated to a RMA operation so we make sure it
			   cannot be put on the wire as a RMA message. */
			ret = sock_sendto(sep->sock, tx->buffer, tx->len,
			                  NULL, 0, sconn->sin);
		} else {
			ret = sock_sendto(sep->sock, tx->buffer, tx->len,
			                  tx->rma_ptr, tx->rma_len,
			                  sconn->sin);
		}
		if (ret == -1) {
			switch (errno) {
			default:
				debug((CCI_DB_MSG | CCI_DB_INFO),
				      "%s: sendto() failed with %s\n",
				      __func__, strerror(errno));
				/* fall through */
			case EINTR:
			case EAGAIN:
			case ENOMEM:
			case ENOBUFS:
				if (is_reliable &&
				    !(tx->msg_type == SOCK_MSG_CONN_REQUEST ||
				      tx->msg_type == SOCK_MSG_CONN_REPLY))
				{
					TAILQ_REMOVE(&sconn->tx_seqs,
					             tx, tx_seq);
				}
				continue;
			}
		} else {
			/* msg sent, dequeue */
			TAILQ_REMOVE(&sep->queued, &tx->evt, entry);
			if (tx->msg_type == SOCK_MSG_SEND)
				sconn->pending++;

			/* If reliable or connection, add to pending
			   else add to idle txs. Note that is we have a
			   conn_reply with a conn_reject, we do not have a
			   valid connection and therefore we cannot deal with
			   a seq. As a result, we just send the conn_reply
			   message, but we do _NOT_ wait for a ACK (the message
			   does not go to the pending queue). */
			if (is_reliable ||
			    tx->msg_type == SOCK_MSG_CONN_REQUEST ||
			    (tx->msg_type == SOCK_MSG_CONN_REPLY &&
			     tx->evt.event.connect.status != CCI_ECONNREFUSED))
			{

				tx->state = SOCK_TX_PENDING;
				TAILQ_INSERT_TAIL(&sep->pending, evt, entry);
				debug((CCI_DB_CONN | CCI_DB_MSG),
				      "%s: moving queued %s tx to pending "
				      "(seq: %u)",
				      __func__, sock_msg_type(tx->msg_type),
				      tx->seq);
				if (tx->msg_type == SOCK_MSG_RMA_WRITE ||
				    tx->msg_type == SOCK_MSG_RMA_READ_REQUEST)
					tx->rma_op->pending++;
			} else {
				tx->state = SOCK_TX_COMPLETED;
				TAILQ_INSERT_TAIL(&idle_txs, tx, dentry);
			}
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
		sock_queue_event (evt->ep, evt);
		if (sep->event_fd) {
			int rc;
			rc = write (sep->fd[1], "a", 1);
			if (rc != 1) {
				debug (CCI_DB_WARN, "%s: Write failed", __func__);
				return;
			}
		}
	}

	CCI_EXIT;

	return;
}

static void sock_progress_sends(cci__ep_t * ep)
{
	CCI_ENTER;
	sock_progress_pending (ep);
	sock_ack_conns(ep);
	sock_progress_queued (ep);
	CCI_EXIT;

	return;
}

static int ctp_sock_send(cci_connection_t * connection,
			const void *msg_ptr,
			uint32_t msg_len,
			const void *context,
			int flags)
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
	int 		ret		= CCI_SUCCESS;
	int 		is_reliable 	= 0;
	int		data_len 	= 0;
	uint32_t 	i;
	size_t 		s 		= 0;
	cci_endpoint_t 	*endpoint 	= connection->endpoint;
	cci__ep_t 	*ep;
	cci__conn_t 	*conn;
	sock_ep_t 	*sep;
	sock_conn_t 	*sconn;
	sock_tx_t 	*tx 		= NULL;
	sock_header_t 	*hdr;
	void 		*ptr;
	cci__evt_t 	*evt;
	union cci_event	*event;	/* generic CCI event */

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
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
	tx = sock_get_tx (ep);
	if (!tx) {
		CCI_EXIT;
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
		tx->len = sizeof(*hdr_r);
	}
	ptr = (void*)((uintptr_t)tx->buffer + tx->len);

	/* copy user data to buffer
	* NOTE: ignore CCI_FLAG_NO_COPY because we need to
	send the entire packet in one shot. We could
	use sendmsg() with an iovec. */

	for (i = 0; i < iovcnt; i++) {
		if (s + data[i].iov_len > connection->max_send_size) {
			debug (CCI_DB_CTP,
			       "Msg too big: %lu/%u\n",
			       tx->len + data[i].iov_len,
			       connection->max_send_size);
			CCI_EXIT;
			return CCI_EINVAL;
		}
		memcpy(ptr, data[i].iov_base, data[i].iov_len);
		ptr = (void*)((uintptr_t)ptr + data[i].iov_len);
		tx->len += data[i].iov_len;
		s += data[i].iov_len;
	}

	/* if unreliable, try to send */
	if (!is_reliable) {
		ret = sock_sendto (sep->sock,
		                   tx->buffer,
		                   tx->len,
		                   tx->rma_ptr,
		                   tx->rma_len,
		                   sconn->sin);
		if (ret == tx->len) {
			/* queue event on enpoint's completed queue */
			tx->state = SOCK_TX_COMPLETED;
			sock_queue_event (ep, evt);
			debug(CCI_DB_MSG, "%s: sent UU msg with %d bytes",
			      __func__, tx->len - (int)sizeof(sock_header_t));
			/* waking up the app thread if it is blocking on a OS handle */
			if (sep->event_fd) {
				int rc;
				rc = write (sep->fd[1], "a", 1);
				if (rc != 1) {
					CCI_EXIT;
					return CCI_ERROR;
				}
			}

			if (!sep->closing) {
				pthread_mutex_lock(&sep->progress_mutex);
				pthread_cond_signal(&sep->wait_condition);
				pthread_mutex_unlock(&sep->progress_mutex);
			}

			CCI_EXIT;
			return CCI_SUCCESS;
		}

		/* if error, fall through and set the return code to CCI_ERROR
		   to make sure the application is notified that the send()
		   could not be locally completed */
		if (ret == -1) {
			/* If in debug mode, display a warning help tracing
			   things. */
			debug (CCI_DB_WARN, "%s: Send failed (%s)",
			       __func__, strerror (errno));
			CCI_EXIT;
			return (CCI_ERROR);
		}
	}

	/* insert at tail of sock device's queued list */
	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	/* try to progress txs */
	if (!sep->closing) {
		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_signal(&sep->wait_condition);
		pthread_mutex_unlock(&sep->progress_mutex);
	}

	ret = CCI_SUCCESS;

	/* if blocking, wait for completion */
	if (tx->flags & CCI_FLAG_BLOCKING) {
		struct timeval tv = { 0, SOCK_PROG_TIME_US / 2 };

		while (tx->state != SOCK_TX_COMPLETED)
			select(0, NULL, NULL, NULL, &tv);

		/* get status and cleanup */
		ret = event->send.status;

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
		/* waking up the app thread if it is blocking on a OS handle */
		if (sep->event_fd) {
			int rc;
			rc = write (sep->fd[1], "a", 1);
			if (rc != 1)
				ret = CCI_ERROR;
		}

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
		pthread_mutex_unlock(&ep->lock);
	}

	CCI_EXIT;
	return ret;
}

static int ctp_sock_rma_register(cci_endpoint_t * endpoint,
			     void *start, uint64_t length,
			     int flags, cci_rma_handle_t ** rma_handle)
{
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	sock_rma_handle_t *handle = NULL;

	CCI_ENTER;

	/* FIXME use read/write flags? */
	UNUSED_PARAM (flags);

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
	*((uint64_t *)&handle->rma_handle.stuff[0]) = (uintptr_t)handle;
	handle->refcnt = 1;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = &handle->rma_handle;

	CCI_EXIT;

	return CCI_SUCCESS;
}

static int
ctp_sock_rma_deregister(cci_endpoint_t * endpoint,
                        cci_rma_handle_t * rma_handle)
{
	int ret = CCI_EINVAL;
	const struct cci_rma_handle *lh = rma_handle;
	sock_rma_handle_t *handle = (void*)((uintptr_t)lh->stuff[0]);
	cci__ep_t *ep = NULL;
	sock_ep_t *sep = NULL;
	sock_rma_handle_t *h = NULL;
	sock_rma_handle_t *tmp = NULL;

	CCI_ENTER;
	debug (CCI_DB_INFO,
	       "%s: deregistering memory -- start: %p",
	       __func__, handle->start);

	UNUSED_PARAM (endpoint);

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
			if (handle->refcnt == 0)
				TAILQ_REMOVE(&sep->handles, handle, entry);
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

static int ctp_sock_rma(cci_connection_t * connection,
                        const void *msg_ptr,
                        uint32_t msg_len,
                        cci_rma_handle_t * local_handle,
                        uint64_t local_offset,
                        cci_rma_handle_t * remote_handle,
                        uint64_t remote_offset,
                        uint64_t data_len,
                        const void *context,
                        int flags)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	sock_ep_t *sep = NULL;
	sock_conn_t *sconn = NULL;
	sock_rma_handle_t *local = (void*)((uintptr_t)local_handle->stuff[0]);
	sock_rma_handle_t *h = NULL;
	sock_rma_op_t *rma_op = NULL;
	size_t max_send_size;

	CCI_ENTER;

	if (!sglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (local->length < local_offset + data_len) {
		debug(CCI_DB_MSG,
                      "%s: RMA length + offset exceeds registered length "
                      "(%"PRIu64" + %"PRIu64" > %"PRIu64")",
                      __func__, data_len, local_offset, local->length);
		CCI_EXIT;
		return CCI_EINVAL;
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
	RMA_PAYLOAD_SIZE (connection, max_send_size);
	rma_op->num_msgs = data_len / max_send_size;
	if (data_len % max_send_size)
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

	{
		uint32_t i, cnt;
		int err = 0;
		sock_tx_t **txs = NULL;
		uint64_t old_seq = 0ULL;

		debug(CCI_DB_MSG,
		      "%s: starting RMA %s (start: %p, len: %"PRIu64") ***",
		      __func__,
		      flags & CCI_FLAG_WRITE ? "Write" : "Read",
		      (void*)local->start, data_len);

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
				INIT_TX (txs[i]);
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
			uint64_t offset = (uint64_t)i * (uint64_t)max_send_size;
			sock_rma_header_t *rma_hdr = (sock_rma_header_t *) tx->buffer;

			rma_op->next = i + 1;
			tx->flags = flags | CCI_FLAG_SILENT;
			tx->state = SOCK_TX_QUEUED;
			/* For RMA, the TX length only includes the header */
			tx->len = sizeof(sock_rma_header_t);
			tx->send_count = 0;
			tx->last_attempt_us = 0ULL;
			tx->timeout_us = 0ULL;
			tx->rma_op = rma_op;

			tx->evt.event.type = CCI_EVENT_SEND;
			tx->evt.event.send.connection = connection;
			tx->evt.conn = conn;
			tx->evt.ep = ep;

			tx->rma_ptr = NULL;
			/* We calculate the amount of data we will actually need */
			if (i == (rma_op->num_msgs - 1)) {
				if (data_len % max_send_size)
					tx->rma_len = data_len % max_send_size;
			} else {
				tx->rma_len = (uint16_t)max_send_size;
			}

			if (flags & CCI_FLAG_WRITE) {
				uint64_t src_offset = local_offset + offset;
				uint64_t dst_offset = remote_offset + offset;
				tx->msg_type = SOCK_MSG_RMA_WRITE;
				tx->rma_ptr = (void*)((uintptr_t)local->start + src_offset);
				sock_pack_rma_write(rma_hdr,
				                    tx->rma_len,
				                    sconn->peer_id,
				                    tx->seq,
				                    0,
				                    local_handle->stuff[0],
				                    src_offset,
				                    remote_handle->stuff[0],
				                    dst_offset);
				debug_ep (ep, CCI_DB_INFO,
				          "%s: Preparing RMA write -- "
				          "local start: %p, "
				          "remote: %"PRIu64", "
				          "local offset: %"PRIu64", "
				          "remote offset: %"PRIu64", "
				          "len: %u, seq: %u",
				          __func__,
				          local->start,
				          remote_handle->stuff[0],
				          src_offset,
				          dst_offset,
				          tx->rma_len,
				          tx->seq);
			} else {
				tx->msg_type = SOCK_MSG_RMA_READ_REQUEST;
				debug (CCI_DB_MSG,
				       "%s: pack RMA_READ_REQUEST (seq %u)",
				       __func__, tx->seq);
				sock_pack_rma_read_request (rma_hdr,
				        tx->rma_len,
				        sconn->peer_id,
				        tx->seq, 0,
				        local_handle->stuff[0],
				        local_offset + offset,
				        remote_handle->stuff[0],
				        remote_offset + offset);
			}
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
	}

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
		debug(CCI_DB_MSG, "%s: ignoring seq %u (acked %u) ***",
		      __func__, seq, sconn->acked);
		return;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(ack, &sconn->acks, entry, tmp) {
		if (SOCK_SEQ_GTE(seq, ack->start) &&
			SOCK_SEQ_LTE(seq, ack->end)) {
			/* seq exists in this entry,
			   do nothing */
			debug(CCI_DB_MSG, "%s: seq %u exists between %u-%u",
			      __func__, seq, ack->start, ack->end);
			done = 1;
			break;
		} else if (seq == ack->start - 1) {
			/* add it to start of this entry */
			ack->start = seq;
			debug(CCI_DB_MSG, "%s: seq %u exists before %u-%u",
			      __func__, seq, ack->start, ack->end);
			done = 1;
			break;
		} else if (seq == ack->end + 1) {
			sock_ack_t *next = TAILQ_NEXT(ack, entry);

			/* add it to the end of this entry */
			debug(CCI_DB_MSG, "%s: seq %u exists after %u-%u",
			      __func__, seq, ack->start, ack->end);
			ack->end = seq;

			/* did we plug a hole between entries? */
			if (next) {
				/* add this range to next and delete this entry */
				debug(CCI_DB_MSG,
				      "%s: merging acks %u-%u with %u-%u",
				      __func__, ack->start, ack->end,
				      next->start, next->end);
				next->start = ack->start;
				TAILQ_REMOVE(&sconn->acks, ack, entry);
				free(ack);
			}

			/* Forcing ACK */
			if (ack->end - ack->start >= PENDING_ACK_THRESHOLD) {
				debug(CCI_DB_MSG, "%s: Forcing ACK", __func__);
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
				      "%s: seq %u insert after %u-%u before %u-%u ",
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
			debug(CCI_DB_MSG, "%s: seq %u add at tail", __func__,
			      seq);
		}
	}
	pthread_mutex_unlock(&ep->lock);

	return;
}

static void
sock_handle_active_message(sock_conn_t * sconn,
                           sock_rx_t * rx,
                           uint16_t len,
                           uint32_t id)
{
	cci__evt_t	*evt;
	cci__conn_t 	*conn 		= sconn->conn;
	cci_endpoint_t	*endpoint;	/* generic CCI endpoint */
	cci__ep_t 	*ep;
	sock_ep_t 	*sep;
	
	CCI_ENTER;

	UNUSED_PARAM (id);

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	/* get cci__evt_t to hang on ep->events */

	evt = &rx->evt;
	if (!evt->conn)
		evt->conn = conn;

	/* set wire header so we can find user header */
	if (cci_conn_is_reliable(conn)) {
                sock_header_r_t *hdr_r = (sock_header_r_t *) rx->buffer;
                evt->event.recv.ptr = (void *)&hdr_r->data;
        } else {
		sock_header_t *hdr = (sock_header_t *) rx->buffer;
		evt->event.recv.ptr = (void *)&hdr->data;
	}

	/* setup the generic event for the application */
	evt->event.type = CCI_EVENT_RECV;
	evt->event.recv.len = len;
	evt->event.recv.connection = &conn->connection;

	/* queue event on endpoint's completed event queue */
	sock_queue_event (ep, evt);

	/* waking up the app thread if it is blocking on a OS handle */
	if (sep->event_fd) {
		int rc;
		rc = write (sep->fd[1], "a", 1);
		if (rc != 1) {
			debug (CCI_DB_WARN, "%s: Write failed", __func__);
		}
	}

	CCI_EXIT;

	return;
}

/*!
Handle incoming RNR messages
*/
static void sock_handle_rnr(sock_conn_t * sconn, uint32_t seq, uint32_t ts)
{
	sock_tx_t *tx 	= NULL;
	sock_tx_t *tmp 	= NULL;
	int found	= 0;

	UNUSED_PARAM (ts);

	/* Find the corresponding SEQ/TS */
	TAILQ_FOREACH_SAFE(tx, &sconn->tx_seqs, tx_seq, tmp) {
		if (tx->seq == seq) {
			debug(CCI_DB_MSG,
			      "%s: Receiver not ready (seq: %u)", __func__,
			      seq);
			tx->rnr = 1;
			found = 1;
		}
	}

	/* We also mark the conn as RNR */
	if (sconn->rnr == 0)
		sconn->rnr = seq;

	if (found == 0)
		debug (CCI_DB_INFO,
		       "%s: Cannot find TX corresponding to RNR", __func__);
}

/*!
Handle incoming nack

*/
static void
sock_handle_nack (sock_conn_t * sconn,
                  cci__ep_t *ep,
                  sock_ep_t *sep,
                  uint32_t seq)
{
	sock_tx_t *tx	= NULL;
	sock_tx_t *tmp	= NULL;
	
	debug_ep (ep,
	          CCI_DB_MSG,
	          "%s: Received NACK (seq: %u)",
	          __func__,
	          seq);

	/* If the message is still in the pending queue, we resend it,
	   otherwise it means the message has been acked meanwhile and
	   therefore we can ignore the NACK */
	TAILQ_FOREACH_SAFE (tx, &sconn->tx_seqs, tx_seq, tmp) {
		if (tx->seq == seq) {
			/* Resend and return */
			debug_ep (ep,
			          CCI_DB_MSG,
			          "Resending NACKed msg (seq %u)",
			          seq); 
			sock_sendto (sep->sock,
			             tx->buffer,
			             tx->len,
			             tx->rma_ptr,
			             tx->rma_len,
			             sconn->sin);
			return;
		}
	}

	return;
}

/*!
Handle incoming ack

Check the device pending list for the matching tx
	if found, remove it and hang it on the completion list
	if not found, ignore (it is a duplicate)
*/
static void
sock_handle_ack(sock_conn_t * sconn,
                sock_msg_type_t type,
                sock_rx_t * rx,
                uint32_t count,
                uint32_t id)
{
	uint32_t i = 0;
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

	TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs
		= TAILQ_HEAD_INITIALIZER(idle_txs);
	TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
	TAILQ_HEAD(s_queued, sock_tx) queued = TAILQ_HEAD_INITIALIZER(queued);
	TAILQ_INIT(&idle_txs);                                                  
	TAILQ_INIT(&evts);
	TAILQ_INIT(&queued);

	assert(id == sconn->id);
	assert(count > 0);

	if (count == 1) {
		assert(type == SOCK_MSG_ACK_ONLY || type == SOCK_MSG_ACK_UP_TO
		       || type == SOCK_MSG_SEND || type == SOCK_MSG_RMA_WRITE
		       || type == SOCK_MSG_RMA_READ_REQUEST
		       || type == SOCK_MSG_RMA_WRITE_DONE
                       || type == SOCK_MSG_RMA_READ_REPLY);
	} else {
		assert(type == SOCK_MSG_SACK);
	}
	sock_parse_ack(hdr_r, type, acks, count);

	if (type == SOCK_MSG_ACK_ONLY) {
		if (sconn->seq_pending == acks[0] - 1)
			sconn->seq_pending = acks[0];
	} else if (type == SOCK_MSG_ACK_UP_TO) {
		sconn->seq_pending = acks[0];
	} else if (type == SOCK_MSG_SEND
	           || type == SOCK_MSG_RMA_WRITE
	           || type == SOCK_MSG_RMA_WRITE_DONE
	           || type == SOCK_MSG_RMA_READ_REQUEST
	           || type == SOCK_MSG_RMA_READ_REPLY)
	{
		/* Piggybacked ACK */
		acks[0] = hdr_r->pb_ack;
		/* Reset hdr_r->pb_ack so we cannot do this again later */
		hdr_r->pb_ack = 0;
		if (sconn->seq_pending == acks[0] - 1)
			sconn->seq_pending = acks[0];
	}

	/*
	   If this is an explicit ACK message, we "extracted" all the info we
	   need, we can return the RX buffer. If it is NOT an explicit ACK
	   (for instance in the context of a piggybacked ACK, the RX buffer
	   is returned by the function handling the specific type of messages
	*/
	if (type == SOCK_MSG_ACK_ONLY || type == SOCK_MSG_ACK_UP_TO
	                              || type == SOCK_MSG_SACK)
	{
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	pthread_mutex_lock(&dev->lock);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(tx, &sconn->tx_seqs, tx_seq, tmp) {
		/* Note that type of msgs can include a piggybacked ACK */
		if (type == SOCK_MSG_ACK_ONLY
		    || type == SOCK_MSG_SEND 
		    || type == SOCK_MSG_RMA_WRITE
		    || type == SOCK_MSG_RMA_READ_REQUEST
		    || type == SOCK_MSG_RMA_WRITE_DONE
		    || type == SOCK_MSG_RMA_READ_REPLY)
		{
			if (tx->seq == acks[0]) {
				if (tx->state == SOCK_TX_PENDING) {
					debug(CCI_DB_MSG,
						"%s: acking only seq %u", __func__,
						acks[0]);
					TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
					TAILQ_REMOVE(&sconn->tx_seqs, tx, tx_seq);
					if (tx->msg_type == SOCK_MSG_RMA_WRITE
					    || tx->msg_type == SOCK_MSG_RMA_READ_REQUEST)
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
						tx->evt.event.send.status = CCI_SUCCESS;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_TAIL(&evts, &tx->evt, entry);
					}
				}
				found = 1;
				break;
			}
		} else if (type == SOCK_MSG_ACK_UP_TO) {
			if (SOCK_SEQ_LTE(tx->seq, acks[0])) {
				if (tx->state == SOCK_TX_PENDING) {
					debug(CCI_DB_MSG,
						"%s: acking tx seq %u (up to seq %u)",
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
						tx->evt.event.send.status = CCI_SUCCESS;
						/* store locally until we can drop the locks */
						TAILQ_INSERT_TAIL(&evts, &tx->evt, entry);
					}
					found++;
				}
			} else {
				break;
			}
		} else {	/* SACK */
			for (i = 0; i < (uint32_t) count; i += 2) {
				if (SOCK_SEQ_GTE(tx->seq, acks[i]) &&
					SOCK_SEQ_LTE(tx->seq, acks[i + 1])) {
					if (sconn->seq_pending == acks[i] - 1)
						sconn->seq_pending =
							acks[i + 1];
					if (tx->state == SOCK_TX_PENDING) {
						debug(CCI_DB_MSG,
						      "%s: sacking seq %u",
						      __func__, tx->seq);
						found++;
						TAILQ_REMOVE(&sep->pending, &tx->evt, entry);
						TAILQ_REMOVE(&sconn->tx_seqs, tx, tx_seq);
						if (tx->msg_type == SOCK_MSG_RMA_WRITE ||
							tx->msg_type == SOCK_MSG_RMA_READ_REPLY)
						{
							tx->rma_op->pending--;
						}
						if (tx->msg_type == SOCK_MSG_SEND) {
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
							tx->state = SOCK_TX_IDLE;
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_HEAD (&idle_txs, tx, dentry);
						} else {
							tx->state = SOCK_TX_COMPLETED;
							tx->evt.event.send.status = CCI_SUCCESS;
							/* store locally until we can drop the dev->lock */
							TAILQ_INSERT_TAIL(&evts, &tx->evt, entry);
						}
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&ep->lock);
	pthread_mutex_unlock(&dev->lock);

	debug(CCI_DB_MSG, "%s: acked %d msgs (%s %u)", __func__, found,
	      sock_msg_type(type), acks[0]);

	pthread_mutex_lock(&ep->lock);
	/* transfer txs to sock ep's list */
	while (!TAILQ_EMPTY(&idle_txs)) {
		sock_rma_op_t *rma_op = NULL;

		tx = TAILQ_FIRST(&idle_txs);
		TAILQ_REMOVE(&idle_txs, tx, dentry);

		rma_op = tx->rma_op;
		if (rma_op && rma_op->status == CCI_SUCCESS) {
			sock_rma_handle_t *local = NULL;

			if (rma_op->local_handle != NULL) {
				local = (void*)((uintptr_t)rma_op->local_handle->stuff[0]);
			}
			rma_op->completed++;

			/* progress RMA */
			if (tx == rma_op->tx) {
				int flags = rma_op->flags;
				void *context = rma_op->context;

				/* they acked our remote completion */
				TAILQ_REMOVE(&sep->rma_ops, rma_op, entry);
				TAILQ_REMOVE(&sconn->rmas, rma_op, rmas);

				free(rma_op);
				if (!(flags & CCI_FLAG_SILENT)) {
					tx->evt.event.send.status = CCI_SUCCESS;
					tx->evt.event.send.context = context;
					TAILQ_INSERT_HEAD(&evts, &tx->evt,
							entry);
					continue;
				}
			}
			/* they acked a data segment, do we need to send more
			 * or send the remote completion? */
			if (rma_op->next < rma_op->num_msgs) {
				sock_rma_header_t *write = (sock_rma_header_t *) tx->buffer;
				uint64_t offset = 0ULL;
				size_t max_send_size;

				/* send more data */
				i = rma_op->next;
				rma_op->next++;
				tx->flags = rma_op->flags | CCI_FLAG_SILENT;
				tx->state = SOCK_TX_QUEUED;
				/* payload size for now */
				RMA_PAYLOAD_SIZE (connection, max_send_size);
				tx->send_count = 0;
				tx->last_attempt_us = 0ULL;
				tx->timeout_us = 0ULL;
				tx->rma_op = rma_op;

				tx->evt.event.type = CCI_EVENT_SEND;
				tx->evt.event.send.connection = connection;
				tx->evt.conn = conn;
				if (i == (rma_op->num_msgs - 1)) {
					if (rma_op->data_len % max_send_size)
						tx->rma_len = rma_op->data_len % max_send_size;
				} else {
					tx->rma_len = (uint16_t)max_send_size;
				}
				tx->seq = ++(sconn->seq);
				tx->len = sizeof(sock_rma_header_t);

				offset = (uint64_t) i * (uint64_t) max_send_size;

				if (tx->flags & CCI_FLAG_WRITE) {
					uint64_t src_offset = rma_op->local_offset + offset;
					uint64_t dst_offset = rma_op->remote_offset + offset;

					debug_ep (ep, CCI_DB_INFO,
					          "%s: Prepare RMA write -- "
					          "start: %p, offset: %"PRIu64", "
					          "len: %u, seq: %u",
					          __func__, local->start,
					          src_offset, tx->rma_len, tx->seq);
					tx->msg_type = SOCK_MSG_RMA_WRITE;
					tx->rma_ptr = (void*)((uintptr_t)local->start + src_offset);
					sock_pack_rma_write(write,
					                    tx->rma_len,
					                    sconn->peer_id,
					                    tx->seq,
					                    0,
					                    rma_op->local_handle->stuff[0],
					                    src_offset,
					                    rma_op->remote_handle->stuff[0],
					                    dst_offset);
				} else {
					tx->msg_type = SOCK_MSG_RMA_READ_REQUEST;
					/* FIXME: not nice to use a "write" variable here, esp since
					 * the code is correct, only the name is confusing */
					sock_pack_rma_read_request (write, tx->rma_len, 
								sconn->peer_id, tx->seq, 0, 
								rma_op->local_handle->stuff[0],
								rma_op->local_offset + offset,
								rma_op->remote_handle->stuff[0],
								rma_op->remote_offset + offset);
				}

				/* now include the header */
				TAILQ_INSERT_TAIL(&queued, tx, dentry);
				continue;
			} else if (rma_op->completed == rma_op->num_msgs) {
				/* send remote completion? */
				if (rma_op->msg_len) {
					sock_header_r_t *hdr_r = tx->buffer;
					sock_rma_header_t *write = NULL;
					void *msg_ptr = NULL;

					rma_op->tx = tx;
					tx->msg_type = SOCK_MSG_RMA_WRITE_DONE;
					tx->flags = rma_op->flags | CCI_FLAG_SILENT;
					tx->state = SOCK_TX_QUEUED;
					/* payload size for now */
					tx->len = (uint16_t) rma_op->msg_len;
					tx->send_count = 0;
					tx->last_attempt_us = 0ULL;
					tx->timeout_us = 0ULL;
					tx->rma_op = rma_op;
					tx->seq = ++(sconn->seq);

					tx->evt.event.type = CCI_EVENT_SEND;
					tx->evt.event.send.connection = connection;
					tx->evt.event.send.context = rma_op->context;
					tx->evt.conn = conn;
					tx->evt.ep = ep;

					/* From here we have a valid TX buffer 
					   that we can use to send the remote
					   completion. First we prepare the
					   header */
					write = (sock_rma_header_t *) tx->buffer;
					debug_ep (ep, CCI_DB_EP,
					          "%s: Sending msg completion; "
					          "msg cmpl len: %u, seq: %u",
					          __func__, rma_op->msg_len, tx->seq);
					sock_pack_rma_write_done(write,
					    sizeof(uint32_t) + rma_op->msg_len,
					    sconn->peer_id,
					    tx->seq, 0);
					/* Then we copy the completion data
					   (len + data) */
					msg_ptr = (void *)(hdr_r->data);
					memcpy(msg_ptr, &rma_op->msg_len,
					       sizeof(uint32_t));
					msg_ptr = (void *)(hdr_r->data + sizeof(uint32_t));
					memcpy(msg_ptr, rma_op->msg_ptr, rma_op->msg_len);
					/* The total size of the RMA_WRITE_DONE
					   msg is the RMA header + len and data
					   for the remote completion msg */
					tx->len = sizeof (sock_rma_header_t)
					          + sizeof(uint32_t)
					          + rma_op->msg_len;
					TAILQ_INSERT_TAIL(&queued, tx, dentry);
					continue;
				} else {
					int flags = rma_op->flags;
					void *context = rma_op->context;

					/* complete now */
					TAILQ_REMOVE(&sep->rma_ops, rma_op, entry);
					TAILQ_REMOVE(&sconn->rmas, rma_op, rmas);
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
		/* waking up the app thread if it is blocking on a OS handle */
		if (sep->event_fd) {
			int rc;
			rc = write (sep->fd[1], "a", 1);
			if (rc != 1) {
				debug (CCI_DB_WARN, "%s: Write failed", __func__);
				CCI_EXIT;
				return;
			}
		}
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
	if (!sep->closing) {
		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_signal(&sep->wait_condition);
		pthread_mutex_unlock(&sep->progress_mutex);
	}

	CCI_EXIT;
	return;
}

static void
sock_handle_conn_request(sock_rx_t * rx,
			cci_conn_attribute_t attr,
			uint16_t len, struct sockaddr_in sin, cci__ep_t * ep)
{
	char name[32];
	sock_ep_t *sep = NULL;

	CCI_ENTER;

	memset(name, 0, sizeof(name));
	sock_sin_to_name(sin, name, sizeof(name));
	debug_ep(ep, CCI_DB_CONN, "%s: recv'd conn_req from %s",
                 __func__, name);

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
	sock_queue_event (ep, &rx->evt);

	/* waking up the app thread if it is blocking on a OS handle */
	sep = ep->priv;
	if (sep->event_fd) {
		int rc;
		rc = write (sep->fd[1], "a", 1);
		if (rc != 1) {
			debug (CCI_DB_WARN, "%s: Write failed", __func__);
			return;
		}
	}

	CCI_EXIT;
	return;
}

/**
 * Possible states and what to do:
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
 * @param[in]	reply	CCI_SUCCESS or CCI_ECONNREFUSED
 */
static void sock_handle_conn_reply(sock_conn_t * sconn,	
                                   sock_rx_t * rx,
                                   uint8_t reply,
                                   uint16_t unused,
                                   uint32_t id,
                                   struct sockaddr_in sin,
                                   cci__ep_t * ep)
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
	struct s_active *active_list;

	CCI_ENTER;

	UNUSED_PARAM (unused);

	sep = ep->priv;

	if (!sconn) {
		/* 
		 * Either this is a dup and the conn is now ready or
		 * the conn is closed and we simply ack the msg
		 */

		/* look for a conn that is ready */
		sconn = sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port,
		                       id, SOCK_MSG_SEND);
		if (!sconn) {
			sock_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char from[32];

			memset(from, 0, sizeof(from));
			sock_sin_to_name(sin, from, sizeof(from));
			debug_ep(ep, (CCI_DB_CONN | CCI_DB_MSG),
			         "%s: recv'd conn_reply (%s) from %s"
			         " with no matching conn",
			         __func__,
			         reply == CCI_SUCCESS ? "success" : "rejected",
			         from);

			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			sock_pack_conn_ack(&hdr.header, id);
			ret = sock_sendto(sep->sock, &hdr, len, NULL, 0, sin);
			if (ret != len) {
				debug_ep(ep, (CCI_DB_CONN | CCI_DB_MSG),
				         "%s: failed to send conn_ack with %s",
				         __func__,
				         cci_strerror(&ep->endpoint,
				                      (enum cci_status)ret));
			}

			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
			pthread_mutex_unlock(&ep->lock);

			/* We only did a peek of the header so far and we got enough
			   data to move on so we drop the msg */
			sock_drop_msg (sep->sock);
			CCI_EXIT;
			return;
		}
		/* else we have a connection and we can ack normally */
	}

	conn = sconn->conn;

	/* set wire header so we can find user header */
	hdr_r = (sock_header_r_t *) rx->buffer;

	/* FIXME do something with ts */
	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

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

	if (sconn->status == SOCK_CONN_ACTIVE) {
		uint32_t peer_id, ack, max_recv_buffer_count, mss, keepalive;

		if (CCI_SUCCESS == reply)
		{
			/* Connection is accepted */

			/* We finally get the entire message */
			uint32_t total_size = sizeof (sock_header_r_t)
			                      + sizeof (sock_handshake_t);
			uint32_t recv_len = sock_recv_msg (sep->sock,
			                                   rx->buffer,
			                                   total_size, 0,
			                                   NULL);
			debug (CCI_DB_EP, "%s: We now have %d/%u bytes",
			       __func__, recv_len, total_size);
#if CCI_DEBUG
			assert (recv_len == total_size);
#endif

			debug(CCI_DB_CONN,
                              "%s: transition active connection to ready",
                              __func__);

			hs = (sock_handshake_t *) ((uintptr_t)rx->buffer
			                           + sizeof(*hdr_r));
			/* With conn_reply, we do not care about the keepalive
			   param */
			sock_parse_handshake(hs, &peer_id, &ack,
			                     &max_recv_buffer_count, &mss,
			                     &keepalive);

			/* get pending conn_req tx, create event, move conn to
			   conn_hash */
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
			/* Since we remove the pending tx, update the
			   pending_seq for that given connection */
			if (sconn->seq_pending == ack - 1)
				sconn->seq_pending = ack;

			if (!tx) {
				char from[32];

				memset(from, 0, sizeof(from));
				sock_sin_to_name(sin, from, sizeof(from));

				/* We cannot be active without a tx pending */
				debug_ep(ep, CCI_DB_WARN,
				         "%s: recv'd conn_reply (%s) from %s "
				         "with an active conn and no matching "
				         "tx",
				         __func__,
				         reply == CCI_SUCCESS ? "success"
				                              : "rejected",
				         from);
				/* we can't transition to ready since we do not
				   have the context from the conn_request tx */
				assert(0);
			}

			/* check mss and rx count */
			if (mss < conn->connection.max_send_size)
				conn->connection.max_send_size = mss;

			if (cci_conn_is_reliable(conn)) {
				sconn->max_tx_cnt = max_recv_buffer_count <
				                    ep->tx_buf_cnt ? 
				                    max_recv_buffer_count :
				                    ep->tx_buf_cnt;
				sconn->ssthresh = sconn->max_tx_cnt;
			}

			sconn->peer_id = peer_id;
			sconn->status = SOCK_CONN_READY;
			*((struct sockaddr_in *)&sconn->sin) = sin;
			sconn->acked = seq;

			i = sock_ip_hash(sin.sin_addr.s_addr, sin.sin_port);
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
			pthread_mutex_unlock(&ep->lock);

			debug(CCI_DB_CONN, "%s: conn ready on hash %d",
			      __func__, i);

		} else {
			/* Connection is rejected */
			sock_header_r_t hdr;
			int len = (int)sizeof(hdr);
			char name[32];

			/* We finally get the entire message */
			uint32_t total_size = sizeof (sock_header_r_t);
			uint32_t recv_len = sock_recv_msg (sep->sock,
			                                   rx->buffer,
			                                   total_size, 0,
			                                   NULL);
			debug (CCI_DB_EP, "%s: We now have %d/%u bytes",
			       __func__, recv_len, total_size);
#if CCI_DEBUG
			assert (recv_len == total_size);
#endif

			free(sconn);
			if (conn->uri)
				free((char *)conn->uri);
			free(conn);

			/* send unreliable conn_ack */
			memset(name, 0, sizeof(name));
			sock_sin_to_name(sin, name, sizeof(name));
			debug_ep(ep, (CCI_DB_CONN | CCI_DB_MSG),
			         "%s: recv'd conn_reply (rejected) from %s"
			         " - closing conn", __func__, name);

			/*
			 * Implicit ACK of the corresponding conn_req
			 */
			debug((CCI_DB_CONN | CCI_DB_MSG),
			      "%s: Implicitely ACKing conn_req %u",
			      __func__, seq);
			/* get pending conn_req tx, create event, move conn to
			   conn_hash */
			pthread_mutex_lock(&ep->lock);
			TAILQ_FOREACH_SAFE(e, &sep->pending, entry, tmp) {
				t = container_of (e, sock_tx_t, evt);
				if (t->seq == seq) {
					TAILQ_REMOVE(&sep->pending, e, entry);
					tx = t;
					break;
				}
			}
			pthread_mutex_unlock(&ep->lock);
			/* Since we remove the pending tx, update the
			   pending_seq for that given connection */
			if (sconn->seq_pending == seq - 1)
				sconn->seq_pending = seq;

			/* simply ack this msg and cleanup */
			memset(&hdr, 0, sizeof(hdr));
			sock_pack_conn_ack(&hdr.header, sconn->peer_id);
			ret = sock_sendto(sep->sock, &hdr, len, NULL, 0, sin);
			if (ret != len) {
				debug_ep(ep, (CCI_DB_CONN | CCI_DB_MSG),
				         "%s: failed to send conn_ack with %s",
				         __func__,
				         cci_strerror(&ep->endpoint,
				                      (enum cci_status)ret));
			}
		}
		/* add rx->evt to ep->evts */
		sock_queue_event (ep, &rx->evt);

		/* waking up the app thread if it is blocking on a OS handle */
		if (sep->event_fd) {
			int rc;
			rc = write (sep->fd[1], "a", 1);
			if (rc != 1) {
				debug (CCI_DB_WARN, "%s: Write failed", __func__);
				CCI_EXIT;
				return;
			}
		}

		if (reply != CCI_SUCCESS) {
			CCI_EXIT;
			return;
		}
	} else if (sconn->status == SOCK_CONN_READY) {
		tx = sock_get_tx (ep);
		if (!tx) {
			char to[32];

			memset(to, 0, sizeof(to));
			sock_sin_to_name(sin, to, sizeof(to));

			/* we can't ack, cleanup */
			debug_ep(ep, (CCI_DB_CONN | CCI_DB_MSG),
			         "%s: no tx buff to send a conn_ack to %s",
			         __func__, to);
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
	tx->len = sizeof (sock_header_r_t);

	debug(CCI_DB_CONN, "%s: queuing conn_ack with seq %u",
	      __func__, tx->seq);

	tx->state = SOCK_TX_QUEUED;
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&sep->queued, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

#if DEBUG_RNR
	conn_established = true;
#endif

	/* try to progress txs */
	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

	CCI_EXIT;

	return;
}

static void
sock_handle_rma_read_reply(sock_conn_t *sconn,
                           sock_rx_t *rx,
                           uint32_t len,
                           uint32_t tx_id)
{
	int ret = 0;
	cci__conn_t *conn = sconn->conn;
	cci_endpoint_t *endpoint;
	cci__ep_t *ep;
	sock_ep_t *sep;
	sock_rma_header_t *read = rx->buffer;
	uint64_t local_handle, local_offset;
	sock_rma_handle_t *local, *h = NULL;
	sock_header_r_t *hdr_r;
	uint32_t seq, ts;
	struct msghdr msg;
	struct iovec iov[2];
	struct sockaddr_in sin;

	CCI_ENTER;

	UNUSED_PARAM (tx_id);

	/* RX already contains the header */
	hdr_r = (sock_header_r_t *) rx->buffer;
	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

	debug(CCI_DB_MSG, 
	      "%s: recv'ing RMA_READ_REPLY on conn %p with len %u",
	      __func__, (void*)conn, len);

	sock_parse_rma_handle_offset(&read->local, &local_handle, &local_offset);
	local = (sock_rma_handle_t *) (uintptr_t) local_handle;
	assert (local);

	endpoint = (&conn->connection)->endpoint;
	ep = container_of (endpoint, cci__ep_t, endpoint);
	sep = ep->priv;
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &sep->handles, entry) {
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
	} else if (local_offset > local->length) {
		/* offset exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: local offset not valid", __func__);
		goto out;
	} else if ((local_offset + len) > local->length) {
		/* length exceeds local handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN, "%s: local length not valid (%"PRIu64"/%"PRIu64")",
		      __func__, local_offset + len, local->length);
		goto out;
	}

	/* valid local handle, copy the data */
	debug(CCI_DB_MSG, "%s: recv'ing data into target buffer (%u bytes)",
	      __func__, len);

	/* We receive the entire message using an IOVEC: the first elt of the
	   IOVEC is the header and the second one the actual data */
	memset (&msg, 0, sizeof (msg));
	msg.msg_name = (void*)&sin;
	msg.msg_namelen = sizeof(sin);
	iov[0].iov_len = sizeof (sock_rma_header_t);
	iov[0].iov_base = rx->buffer;
	iov[1].iov_len = len;
	iov[1].iov_base = (void*)((uintptr_t)h->start + (uintptr_t)local_offset);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
again:
	ret = recvmsg (sep->sock, &msg, 0);
	if (ret == -1) {
		/* TODO we need to drain the message from the fd */
		if (errno == EAGAIN)
			goto again;
		debug(CCI_DB_MSG,
                      "%s: recv'ing RMA READ payload failed with %s",
                      __func__, strerror(errno));
	}
#if CCI_DEBUG
	assert (ret == (int)(sizeof (sock_rma_header_t) + len));
#endif
	debug (CCI_DB_EP,
               "%s: We now have %d/%lu bytes",
               __func__, ret,
               sizeof (sock_rma_header_t) + len);
out:

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

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
* the conn_reply, we queue the conn_ack, we check the "context" (accept or
* reject) and generate an event to the server application.
* Therefore, when receiving a CONN_ACK, we have to:
* - if the connection is accepted, return an event to the server app with the 
*   ID of the remote peer; find the corresponding CONN_REPLY TX and "release"
*   it (the TX is also used to know the context of the conn_reply (i.e., accept
*   or reject),
* - if the connection is rejected, return an event to the app specifying that
*   no ID has assigned to the remote peer.
*/
static void
sock_handle_conn_ack(sock_conn_t * sconn,
                     sock_rx_t * rx,
                     uint8_t unused1,
                     uint16_t unused2,
                     uint32_t peer_id,
                     struct sockaddr_in sin)
{
	cci__ep_t *ep 		= NULL;
	cci__conn_t *conn 	= NULL;
	sock_ep_t *sep 		= NULL;
	cci__evt_t *e 		= NULL;
	cci__evt_t *tmp 	= NULL;
	sock_tx_t *tx 		= NULL;
	sock_tx_t *t 		= NULL;
	sock_header_r_t *hdr_r;	/* wire header */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	uint32_t seq;
	uint32_t ts;

	CCI_ENTER;

	UNUSED_PARAM (unused1);
	UNUSED_PARAM (unused2);
	UNUSED_PARAM (sin);

	if (sconn == NULL) {
		/* Connection was rejected */
	} else {
		/* Connection was accepted */
		conn = sconn->conn;
		endpoint = (&conn->connection)->endpoint;
		ep = container_of(endpoint, cci__ep_t, endpoint);
		sep = ep->priv;

		/* we check whether the connection ack match the id associated to the
		   connection */
		assert(peer_id == sconn->id);

		hdr_r = rx->buffer;
		sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

		debug(CCI_DB_CONN, "%s: seq %u acking conn_reply %u",
		      __func__, seq, ts);

		pthread_mutex_lock(&ep->lock);
		TAILQ_FOREACH_SAFE(e, &sep->pending, entry, tmp) {
			/* the conn_ack stores the ack for the conn_reply in ts */
			t = container_of (e, sock_tx_t, evt);
			if (t->seq == ts) {
				TAILQ_REMOVE(&sep->pending, e, entry);
				tx = t;
				debug(CCI_DB_CONN, "%s: found conn_reply",
				      __func__);
				break;
			}
		}
		pthread_mutex_unlock(&ep->lock);

		if (!tx) {
			/* FIXME do what here? */
			/* if no tx, then it timed out or this is a duplicate,
			 * but we have a sconn */
			debug((CCI_DB_MSG | CCI_DB_CONN), 
			      "%s: received conn_ack and no matching tx "
			      "(seq %u ack %u)", __func__, seq, ts);
		} else {
			pthread_mutex_lock(&ep->lock);
			if (tx->evt.event.accept.connection) {
				debug(CCI_DB_CONN,
                                      "%s: Generate the connect accept event",
				      __func__);
				TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
				/* waking up the app thread if it is blocking
				   on a OS handle */
				if (sep->event_fd) {
					int rc;
					rc = write (sep->fd[1], "a", 1);
					if (rc != 1) {
						debug (CCI_DB_WARN,
						       "%s: Write failed",
						       __func__);
						CCI_EXIT;
						return;
					}
				}
			} else {
				TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
			}
			pthread_mutex_unlock(&ep->lock);
		}

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
	
		pthread_mutex_lock(&sep->progress_mutex);
		pthread_cond_signal(&sep->wait_condition);
		pthread_mutex_unlock(&sep->progress_mutex);
	}

	CCI_EXIT;

	return;
}

static int
sock_handle_rma_read_request(sock_conn_t * sconn, sock_rx_t * rx,
                             uint16_t len, uint32_t id)
{
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = sconn->conn;
	sock_rma_header_t *read = rx->buffer;
	cci_connection_t *connection = NULL;
	sock_ep_t *sep = NULL;
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;
	uint64_t remote_offset;
	uint32_t seq, ts = 0;
	int ret = CCI_SUCCESS;
	sock_rma_header_t *rma_hdr;
	sock_rma_handle_t *remote, *h;
	sock_header_r_t *hdr_r;
	sock_tx_t *tx = NULL;

	hdr_r = (sock_header_r_t *) rx->buffer;
	sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

	connection = &conn->connection;
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

        /* Get a TX buffer */
        tx = sock_get_tx (ep);
        if (tx == NULL) {
                send_nack (sconn, sep, seq, ts);
                goto out;
        }

	if (hdr_r->pb_ack != 0) {
		sock_handle_ack (sconn, SOCK_MSG_RMA_READ_REQUEST, rx, 1, id);
	}

	/* Parse the RMA read request message */
	sock_parse_rma_handle_offset(&read->local, &local_handle, &local_offset);
	sock_parse_rma_handle_offset(&read->remote, &remote_handle, &remote_offset);
	remote = (sock_rma_handle_t *) (uintptr_t) remote_handle;
#if CCI_DEBUG
	assert (remote);
#endif

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &sep->handles, entry) {
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
	} else if (remote_offset > remote->length) {
		/* offset exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN,
		      "%s: remote offset not valid (start: %p, offset: %"PRIu64", "
		      "length: %"PRIu64")",
		      __func__, remote->start, remote_offset, remote->length);
		goto out;
	} else if ((remote_offset + len) > remote->length) {
		/* length exceeds remote handle's range, send nak */
		ret = CCI_ERR_RMA_HANDLE;
		debug(CCI_DB_WARN,
		      "%s: remote length not valid (remote offset: %"PRIu64", "
		      "len: %d, length: %"PRIu64")",
		      __func__, remote_offset, len, remote->length);
		goto out;
	}

	/* Prepare the TX buffer */
	tx->seq = 0;
	tx->msg_type = SOCK_MSG_RMA_READ_REPLY;
	tx->flags = CCI_FLAG_SILENT;
	tx->state = SOCK_TX_QUEUED;
	tx->len = sizeof(sock_rma_header_t);
	tx->rma_op = NULL;
	tx->rma_ptr
	    = (void*)((uintptr_t)remote->start + (uintptr_t) remote_offset);
	tx->rma_len = len;

	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.status = CCI_SUCCESS; /* for now */
	tx->evt.event.send.context = NULL;
	tx->evt.event.send.connection = &conn->connection;
	tx->evt.conn = conn;

	rma_hdr = (sock_rma_header_t*)tx->buffer;
	sock_pack_rma_read_reply(rma_hdr, (uint16_t)len, sconn->peer_id,
	                         tx->seq, 0,
	                         local_handle, local_offset,
	                         remote_handle, remote_offset);
	debug (CCI_DB_MSG,
	       "%s: Copying %d bytes in RMA_READ_REPLY msg",
	       __func__, len);
	memcpy(rma_hdr->data, tx->rma_ptr, len);
	/* We piggyback the seq of the initial READ REQUEST so it can act as an ACK */
	hdr_r = (sock_header_r_t*) tx->buffer;
	hdr_r->pb_ack = seq;

	/* Send the message: we try to send the RMA_READ_REPLY directly, like an
	   ACK */
	debug (CCI_DB_MSG,
	       "%s: Send RMA_READ_REPLY, response to RMA_READ_REQUEST seq %u"
	       " with %u bytes",
	       __func__, seq, tx->rma_len);
	sock_sendto(sep->sock, tx->buffer, tx->len, tx->rma_ptr,
	            tx->rma_len, sconn->sin);

	/* Since RMA_READ_REPLY are acting like an ACK, we return the buffer
	   right away. No need to generate a SEND event, this is only a
	   fragment of the RMA READ operation */
	pthread_mutex_lock (&ep->lock);
	TAILQ_INSERT_TAIL(&sep->idle_txs, tx, dentry);
	pthread_mutex_unlock (&ep->lock);

out:
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	pthread_mutex_lock(&sep->progress_mutex);
	pthread_cond_signal(&sep->wait_condition);
	pthread_mutex_unlock(&sep->progress_mutex);

	return (ret);
}

static void
sock_handle_rma_write(sock_conn_t * sconn, sock_rx_t * rx, uint16_t len)
{
	cci__ep_t *ep 			= NULL;
	cci__conn_t *conn 		= sconn->conn;
	sock_ep_t *sep 			= NULL;
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;	/* our handle */
	uint64_t remote_offset;	/* our offset */
	sock_rma_handle_t *remote, *h;
	struct sockaddr_in sin;
	struct msghdr msg;
	struct iovec iov[2];
	sock_rma_header_t *rma_header;
#if CCI_DEBUG
	int ret;
#endif

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	/* The header is already in the RX */
	rma_header = rx->buffer;

	sock_parse_rma_handle_offset(&(rma_header->local),
	                             &local_handle,
	                             &local_offset);
	sock_parse_rma_handle_offset(&(rma_header->remote),
	                             &remote_handle,
	                             &remote_offset);
	remote = (sock_rma_handle_t *) (uintptr_t) remote_handle;
#if CCI_DEBUG
	assert (remote);
        assert (len);
#endif

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &sep->handles, entry) {
		if (h == remote) {
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (h != remote) {
		/* remote is no longer valid, send nack */
		debug(CCI_DB_MSG, "%s: remote handle not valid", __func__);
		/* TODO
		   Note: we have already handled the seq for this rx
		         and we may have acked it. If it was the last
		         piece, then we lost the race. We should defer
		         the ack until we deliver the data. */

		goto out;
	}

#if CCI_DEBUG
	assert (h->start);
	assert (len);
#endif

	if (remote_offset > remote->length) {
		/* offset exceeds remote handle's range, send nak */
		debug(CCI_DB_MSG,
		      "%s: remote offset not valid (start: %p, offset: %"PRIu64", "
		      "length: %"PRIu64")", __func__, remote->start, remote_offset,
		      remote->length);
		/* TODO
		   Note: we have already handled the seq for this rx
		         and we may have acked it. If it was the last
		         piece, then we lost the race. We should defer
		         the ack until we deliver the data. */

		goto out;
	} else if (remote_offset + len > remote->length) {
		/* length exceeds remote handle's range, send nak */
		debug(CCI_DB_MSG, "%s: remote length not valid", __func__);
		/* TODO
		   Note: we have already handled the seq for this rx
		         and we may have acked it. If it was the last
		         piece, then we lost the race. We should defer
		         the ack until we deliver the data. */

		goto out;
	}

	/* valid remote handle, copy the data */
	debug_ep (ep, CCI_DB_INFO,
	          "%s: copying data into target buffer -- start: %p, "
	          "offset: %"PRIu64", len: %d",
	          __func__, h->start, remote_offset, len);

	/* We receive the entire message using an IOVEC: the first elt of the
	   IOVEC is the header and the second one the actual data */
	memset (&msg, 0, sizeof (msg));
	msg.msg_name = (void*)&sin;
	msg.msg_namelen = sizeof(sin);
	iov[0].iov_len = sizeof (sock_rma_header_t);
	iov[0].iov_base = rx->buffer;
	iov[1].iov_len = len;
	iov[1].iov_base = (void*)((uintptr_t)h->start + (uintptr_t)remote_offset);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
#if CCI_DEBUG
	ret = recvmsg (sep->sock, &msg, 0);
	debug (CCI_DB_EP, "%s: We now have %d/%lu bytes",
	       __func__, ret, sizeof (sock_rma_header_t) + len);
	assert ((unsigned int)ret == (sizeof (sock_rma_header_t) + len));
#else
	recvmsg (sep->sock, &msg, 0);
#endif

out:
	/* We force the ACK */
	pthread_mutex_lock(&ep->lock);
	sock_ack_sconn (sep, sconn);
	
	TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static void
sock_handle_rma_write_done(sock_conn_t * sconn,
                           sock_rx_t * rx,
                           uint16_t len,
                           uint32_t id)
{
	cci__evt_t *evt;
	cci__conn_t *conn = sconn->conn;
	union cci_event *event;	/* generic CCI event */
	cci_endpoint_t *endpoint;	/* generic CCI endpoint */
	cci__ep_t *ep;
	sock_ep_t *sep = NULL;
	/* Length of the completion msg */
	uint32_t *msg_len;
	/* Completion msg */
	void *ptr;
	sock_header_r_t *hdr_r = rx->buffer;
	uint32_t total_len;
#if CCI_DEBUG
	int ret;
#endif

#if 0
	if (hdr_r->pb_ack != 0) {
		sock_handle_ack (sconn, SOCK_MSG_RMA_WRITE_DONE, rx, 1, id);
	}
#endif

	endpoint = (&conn->connection)->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	sep = ep->priv;

	/* First we get the length of the completion message */
	msg_len = (uint32_t*)hdr_r->data;
	debug_ep (ep, CCI_DB_EP,
	          "%s: msg len is %u\n", __func__, *msg_len);

	total_len = sizeof (sock_rma_header_t) + sizeof(uint32_t) + *msg_len;
#if CCI_DEBUG
	ret = sock_recv_msg (sep->sock, rx->buffer, total_len, 0, NULL);
        debug (CCI_DB_EP, "We now have %d/%d bytes\n", ret, total_len);
	assert ((unsigned int)ret == total_len);
#else
	sock_recv_msg (sep->sock, rx->buffer, total_len, 0, NULL);
#endif

	/* get cci__evt_t to hang on ep->events */
	evt = &rx->evt;

	/* setup the generic event for the application */
	event = & evt->event;
	event->type = CCI_EVENT_RECV;
	event->recv.len = *msg_len;
	ptr = hdr_r->data + sizeof (uint32_t);
	*((void **)&event->recv.ptr) = ptr;
	event->recv.connection = &conn->connection;

	/* queue event on endpoint's completed event queue */
	sock_queue_event (ep, evt);

	/* waking up the app thread if it is blocking on a OS handle */
	if (sep->event_fd) {
		int rc;
		rc = write (sep->fd[1], "a", 1);
		if (rc != 1)
			debug (CCI_DB_WARN, "%s: Write failed", __func__);
	}
}

static int sock_recvfrom_ep(cci__ep_t * ep)
{
	int ret = 0, drop_msg = 0, q_rx = 0, reply = 0, request = 0, again = 0;
	int ka = 0;
	size_t recv_len = 0;
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
	uint32_t seq = 0;
	uint32_t ts = 0;

	CCI_ENTER;

	sep = ep->priv;
	if (!sep)
		return 0;

	pthread_mutex_lock(&ep->lock);
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
		/* We sumilate a case where we are not ready to receive 25% of
		   the time */
		int n = (int)(4.0 * rand() / (RAND_MAX + 1.0));
		if (n == 0) {
			fprintf(stderr, "Simulating lack of RX buffer...\n");
			rx = NULL;
		}
	}
#endif

	/*
	 * Two cases here:
	 * 1) Normal execution, we can get a RX buffer: then we read the msg
	 *    and just handle the message.
	 * 2) We are out of RX buffers; two cases again:
	 *    a. The connection is reliable and in this case we fall into a RNR
	 *       mode, which may lead to dropping the message and/or creating
	 *       an extra RX buffer. See the semantic of RNR for more details.
	 *    b. The connection is unreliable, we just drop the message.
	 */
	if (!rx) {
		char tmp_buff[SOCK_UDP_MAX];
		sock_header_t *hdr = NULL;

		debug(CCI_DB_INFO,
		      "%s: no rx buffers available on endpoint %d",
		      __func__, sep->sock);

		/* We do the receive using a temporary buffer so we can get
		   enough data to send a RNR NACK */
		ret = recvfrom(sep->sock, (void *)tmp_buff, SOCK_UDP_MAX,
				0, (struct sockaddr *)&sin, &sin_len);
		if (ret == -1) {
			debug (CCI_DB_INFO,
			       "%s: No RX buffer + cannot recv data: %s",
			       __func__, strerror (errno));
			CCI_EXIT;
			return 0;
		}
		if (ret < (int)sizeof(sock_header_t)) {
			debug(CCI_DB_INFO,
			      "%s: Not enough data (%d/%d) to get the header",
			      __func__, ret, (int)sizeof(sock_header_t));
			CCI_EXIT;
			return 0;
		}

		/* Now we get the header and parse it so we can know if we are
		   in the context of a reliable connection */
		hdr = (sock_header_t *) tmp_buff;
		sock_parse_header(hdr, &type, &a, &b, &id);
		sconn = sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port,
		                       id, type);
		conn = sconn->conn;
		if (sconn == NULL) {
			/* If the connection is not already established, we
			   just drop the message */
			debug(CCI_DB_INFO,
			      "%s: Connection not established, dropping msg",
			      __func__);
			CCI_EXIT;
			return 0;
		}

		/* If this is a reliable connection, we typically fall into a
		   RNR mode */
		if (cci_conn_is_reliable(conn)) {
			sock_header_r_t *header_r = NULL;

			/* We do the receive using a temporary buffer so we can
			   get enough data to send a RNR NACK */

			/* From the buffer, we get the TS and SEQ from the
			   header (this is the only we need to deal with RNR)
			   and will be used later on */
			header_r = (sock_header_r_t *) tmp_buff;
			sock_parse_seq_ts(&header_r->seq_ts, &seq, &ts);

			ret = update_rnr_mode (sconn, seq);
			if (ret == CCI_SOCK_RESUME_RNR) {
				/* In case we receive the message we were
				   waiting for to resume normal execution,
				   we make sure we have a proper RX buffer and
				   move on. This new buffer will be added to
				   the list of available RX buffers later on */
				rx = alloc_rx_buffer (ep);
				if (rx == NULL) {
					drop_msg = 1;
					goto out;
				}
				memcpy (rx->buffer, tmp_buff, ep->buffer_len);
			} else {
				/* Otherwise we drop the msg */
				drop_msg = 1;
				goto out;
			}
		} else {
			/* If the connection is unreliable, we simply exit */
			CCI_EXIT;
			return 0;
		}
	} else {
		ret = sock_recv_msg (sep->sock,
		                     rx->buffer,
		                     sizeof(sock_header_t),
				     MSG_PEEK,
		                     &sin);
		if (ret < 0 || ret < (int)sizeof(sock_header_t)) {
			q_rx = 1;
			goto out;
		}
		recv_len = ret;
#if CCI_DEBUG
		assert (recv_len == sizeof (sock_header_t));
#endif
		/* Getting here means we are in a normal execution code path
		   so we assume that if we received successfully a message,
		   another one may be already available right away, so it is
		   possible to try to receive it. */
		again = 1;
	}

	/* From here, we know we have the message in a valid RX buffer so we
	   can parse it and handle the data */

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

	if (!request) {
		sconn = sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port,
		                       id, type);
	}

#if CCI_DEBUG
	{
		char name[32];

		if (CCI_DB_MSG & cci__debug) {
			memset(name, 0, sizeof(name));
			sock_sin_to_name(sin, name, sizeof(name));
			
			/* Note that in the context of RMA_READ_REQUEST
			   messages the length of the message is actually the
			   size of the data to send back; for CONN_REPLY, a 
			   specifies whether the connection is accepted or
			   rejected and b should be equal to 0 (so the size in
			   the debug msg is not relevant */
			debug_ep(ep, (CCI_DB_MSG),
			         "%s: recv'd %s msg from %s with %d bytes",
			         __func__, sock_msg_type(type), name, a + b);
		}
	}
#endif /* CCI_DEBUG */

	/* if no conn, drop msg, requeue rx */
	if (!ka && !sconn && !reply && !request) {
		debug((CCI_DB_CONN | CCI_DB_MSG),
		      "%s: no sconn for incoming %s msg from %s:%d",
		      __func__,
		      sock_msg_type(type), inet_ntoa(sin.sin_addr),
		      ntohs(sin.sin_port));
		/* If we do not have a connection and if the message type is a
		   CONN_ACK, this is most certainly the ack in the context of
		   a conn_reject */
		if (SOCK_MSG_CONN_ACK == type) {
			uint32_t total_size = sizeof (sock_header_r_t);
			recv_len = sock_recv_msg (sep->sock, rx->buffer,
			                          total_size, 0, NULL);
			debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
			       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
			assert (recv_len == total_size);
#endif
			/* If we get a conn_ack but the sconn is NULL, this is
			   a ack in the context of a conn_reject. We can safely
			   call the sock_handle_conn_ack() but we need to
			   explicitely return the rx */
			sock_handle_conn_ack(NULL, rx, a, b, id, sin);
			/* Return the RX */
			TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		}
		q_rx = 1;
		goto out;
	}

	/* Some actions specific to reliable connections */
	if (sconn && cci_conn_is_reliable(sconn->conn))
	{
		sock_header_r_t *hdr_r;

		/* Make sure we receive the entire reliable header */
		if (recv_len < sizeof (sock_header_r_t)) {
			recv_len = sock_recv_msg (sep->sock,
			                          rx->buffer,
			                          sizeof (sock_header_r_t),
			                          MSG_PEEK,
			                          NULL);
#if CCI_DEBUG
			assert (recv_len == sizeof (sock_header_r_t));
#endif
		}
		hdr_r = rx->buffer;

		assert (recv_len >= sizeof (sock_header_t));
		sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);

		/* For reliable/ordered connection, we make sure we receive the expected
		   next seq */
		if (sconn->conn->connection.attribute == CCI_CONN_ATTR_RO) {
			if (sconn->last_recvd_seq == 0)
				sconn->last_recvd_seq = seq;

			if (seq > sconn->last_recvd_seq + 1) {
				ret = send_nack (sconn,
				                 sep,
				                 seq,
				                 ts);				
				goto out;
			}
		}

		if (!(type == SOCK_MSG_CONN_REPLY)) {
			/* We do not want to implicitely ack RMA_READ_REQUEST and
			   RMA_READ_REPLY message:
			   - RMA_READ_REQUEST are acked with the corresponding
			     RMA_READ_REPLY message
			   - RMA_READ_REPLY message are not acked since they act as an
			     ACK (not ack of acks). 
			   - SOCK_MSG_RNR are not acked since they act as a NACK */
			if (!(type == SOCK_MSG_RMA_READ_REQUEST)
			    && !(type == SOCK_MSG_RMA_READ_REPLY)
			    && !(type == SOCK_MSG_NACK)
			    && !(type == SOCK_MSG_RNR))
			{
				sock_handle_seq(sconn, seq);
			}

			if (hdr_r->pb_ack != 0) {
				sock_handle_ack (sconn, type, rx, 1, id);
				/* Reset the value of pb_ack to make sure we won't try
				   to do it again */
				hdr_r->pb_ack = 0;
			}
		}
	}

	switch (type) {
	case SOCK_MSG_CONN_REQUEST: {
		uint32_t total_size = sizeof (sock_header_r_t)
		                      + sizeof (sock_handshake_t) + b;
		recv_len = sock_recv_msg (sep->sock, rx->buffer,
		                          total_size, 0, NULL);
		debug (CCI_DB_EP,
		       "%s: We now have %u/%u bytes",
		       __func__,
		       (unsigned int)recv_len, total_size);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_conn_request(rx, a, b, sin, ep);
		break;
	}
	case SOCK_MSG_CONN_REPLY: {
		/* We first get the header and only the header to know if we
		   are in the context of a connect accept or reject */
		uint32_t total_size = sizeof (sock_header_r_t);
		recv_len = sock_recv_msg (sep->sock, rx->buffer,
		                          total_size, MSG_PEEK, NULL);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_conn_reply(sconn, rx, a, b, id, sin, ep);
		break;
	}
	case SOCK_MSG_CONN_ACK: {
		uint32_t total_size = sizeof (sock_header_r_t);
		recv_len = sock_recv_msg (sep->sock, rx->buffer,
		                          total_size, 0, NULL);
		debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
		       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_conn_ack(sconn, rx, a, b, id, sin);
		break;
	}
	case SOCK_MSG_DISCONNECT:
		break;
	case SOCK_MSG_SEND: {
		uint16_t total_size = b;
		if (cci_conn_is_reliable(sconn->conn)) {
			total_size += sizeof (sock_header_r_t);
		} else {
			total_size += sizeof (sock_header_t);
		}
		/* Make sure we have the entire msg */
		recv_len = sock_recv_msg (sep->sock,
		                          rx->buffer,
		                          total_size,
		                          0,
		                          NULL);
		debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
		       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_active_message(sconn, rx, b, id);
		break;
	}
	case SOCK_MSG_RNR:{
		sock_header_r_t *hdr_r = rx->buffer;

		debug (CCI_DB_INFO,
		       "%s: Receiver not ready", __func__);

		sock_parse_seq_ts(&hdr_r->seq_ts, &seq, &ts);
		sock_handle_rnr(sconn, seq, ts);
		/* No event is directly generated from the msg
		   so we can reuse the RX buffer */
		q_rx = 1;
		break;
	}
	case SOCK_MSG_KEEPALIVE:
		/* Nothing to do? */
		break;
	case SOCK_MSG_ACK_ONLY:
	case SOCK_MSG_ACK_UP_TO:
	case SOCK_MSG_SACK: {
		uint32_t total_size = sizeof (sock_header_r_t)
		                      + a * sizeof (uint32_t);
		recv_len = sock_recv_msg (sep->sock, rx->buffer,
		                       total_size, 0, NULL);
		debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
		       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_ack(sconn, type, rx, (uint32_t)a, id);
		/* sock_handle_ack already requeue the RXs in the idle list */
		break;
	}
	case SOCK_MSG_NACK: {
		uint32_t total_size 	= sizeof (sock_header_r_t);

		/* We just need to the data from the header */
		recv_len = sock_recv_msg (sep->sock, rx->buffer,
                                          total_size, 0, NULL);
                debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
                       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
                assert (recv_len == total_size);
#endif
		sock_handle_nack (sconn, ep, sep, seq);
		q_rx = 1;
		break;
	}
	case SOCK_MSG_RMA_WRITE: {
		/* At first we just need to make sure we have the header */
		recv_len = sock_recv_msg (sep->sock,
		                       rx->buffer,
		                       sizeof (sock_rma_header_t),
		                       MSG_PEEK,
		                       NULL);
#if CCI_DEBUG
		assert (recv_len == sizeof (sock_rma_header_t));
#endif
		sock_handle_rma_write(sconn, rx, b);
		break;
	}
	case SOCK_MSG_RMA_WRITE_DONE: {
		/* At first we just need to make sure we have the header
		   and the length of the completion message */
		uint32_t total_size = sizeof (sock_rma_header_t)
		                      + sizeof (uint32_t);
		recv_len = sock_recv_msg (sep->sock,
		                          rx->buffer,
		                          total_size,
		                          MSG_PEEK,
		                          NULL);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_rma_write_done(sconn, rx, b, id);
		break;
	}
	case SOCK_MSG_RMA_READ_REQUEST: {
		uint32_t total_size = sizeof (sock_rma_header_t);
		recv_len = sock_recv_msg (sep->sock,
		                          rx->buffer,
		                          total_size,
		                          0,
		                          NULL);
		debug (CCI_DB_EP, "%s: We now have %u/%u bytes",
		       __func__, (unsigned int)recv_len, total_size);
#if CCI_DEBUG
		assert (recv_len == total_size);
#endif
		sock_handle_rma_read_request(sconn, rx, b, id);
		break;
	}
	case SOCK_MSG_RMA_READ_REPLY: {
		/* At first we just need to make sure we have the header */
		recv_len = sock_recv_msg (sep->sock,
		                          rx->buffer,
		                          sizeof (sock_rma_header_t),
		                          MSG_PEEK,
		                          NULL);
#if CCI_DEBUG
		assert (recv_len == sizeof (sock_rma_header_t));
#endif
		sock_handle_rma_read_reply(sconn, rx, b, id);
		break;
	}
	default:
		debug(CCI_DB_MSG, "%s: unknown active message with type %u",
		      __func__, (enum sock_msg_type)type);
	}

out:
	if (q_rx) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	if (drop_msg) {
		/* If we have no connection, we can be in the context of
		   a connection reject */
		if (sconn && cci_conn_is_reliable(sconn->conn)
		    && sconn->rnr == seq)
		{
			char buffer[SOCK_MAX_HDR_SIZE];
			int len = 0;
			sock_header_r_t *hdr_r = NULL;

			/* 
			  Getting here, we are in the new RNR context on the
			  receiver side. Note that we already got the TS and
			  SEQ from the message header 
			*/

			debug (CCI_DB_INFO, "%s: Sending RNR msg (%u)",
			       __func__, sconn->rnr);

			/* Send a RNR NACK back to the sender */
			memset(buffer, 0, sizeof(buffer));
			hdr_r = (sock_header_r_t *) buffer;
			sock_pack_nack(hdr_r, SOCK_MSG_RNR, sconn->peer_id, seq, ts, 0);
			hdr_r->pb_ack = 0;
			len = sizeof(*hdr_r);

			ret = sock_sendto(sep->sock, buffer, len, NULL, 0, sconn->sin);
			if (ret == -1)
				debug (CCI_DB_INFO, "%s: Cannot send RNR", __func__);
		}

		/* Drop the message */
		sock_drop_msg(sep->sock);
	} else {
		if (sconn && sconn->conn &&
		    sconn->conn->connection.attribute == CCI_CONN_ATTR_RO)
			sconn->last_recvd_seq = seq;
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

		/* The keepalive is assumed to expire if we did not hear
		   anything from the peer since the last receive + keepalive
		   timeout. */
		ka_timeout = sconn->ts + conn->keepalive_timeout;

		if (SOCK_U64_LT(now, ka_timeout)) {
			int len;
			char buffer[SOCK_MAX_HDR_SIZE];
			sock_header_t *hdr = NULL;
			cci_event_keepalive_timedout_t *event = NULL;
			cci__evt_t *evt = NULL;
			cci__ep_t *ep = NULL;
			sock_ep_t *sep = NULL;

			/*
			* We generate a keepalive event
			*/

			TAILQ_HEAD(s_evts, cci__evt) evts
				= TAILQ_HEAD_INITIALIZER(evts);
			TAILQ_INIT(&evts);
			evt = TAILQ_FIRST(&evts);
			event = (cci_event_keepalive_timedout_t *) evt;
			event->type = CCI_EVENT_KEEPALIVE_TIMEDOUT;
			event->connection = &conn->connection;
			TAILQ_REMOVE(&evts, evt, entry);
			sock_queue_event (evt->ep, evt);

			/* waking up the app thread if it is blocking on a OS
			   handle */
			if (sep->event_fd) {
				int rc;
				rc = write (sep->fd[1], "a", 1);
				if (rc != 1) {
					debug (CCI_DB_WARN,
					       "%s: Write failed", __func__);
					return;
				}
			}

			/*
			* Finally we send an heartbeat
			*/

			/* Prepare and send the msg */
			ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
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

static inline int sock_ack_sconn (sock_ep_t *sep, sock_conn_t *sconn)
{
	uint64_t now = 0ULL;
	int count = 0;

	now = sock_get_usecs();

	if (!TAILQ_EMPTY(&sconn->acks)) {
		sock_header_r_t *hdr_r;
		uint32_t acks[SOCK_MAX_SACK * 2];
		sock_ack_t *ack = NULL;
		sock_msg_type_t type = SOCK_MSG_ACK_UP_TO;
		char buffer[SOCK_MAX_HDR_SIZE];
		int len = 0;
		int ret;

		count = 1;
		memset(buffer, 0, sizeof(buffer));
		
		if (1 == sock_need_sack(sconn)) {
			/* There are more than one element in the list of pending acks */
			sock_ack_t *tmp;
			
			type = SOCK_MSG_SACK;
			count = 0;
			
			/* We first count the number of pending ACKs */
			TAILQ_FOREACH_SAFE(ack, &sconn->acks, entry, tmp) {
				count++;
			}
			
			/* We check whether we want to ack now or delay acks */
			if (SOCK_U64_LT(now, sconn->last_ack_ts + ACK_TIMEOUT) &&
				count <= PENDING_ACK_THRESHOLD)
			{
				debug (CCI_DB_MSG,
				       "%s: Delaying ACK", __func__);
				return 0;
			}
			
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
			/* There is only one element in the list of pending acks */
			ack = TAILQ_FIRST(&sconn->acks);
			if (SOCK_U64_LT(now, sconn->last_ack_ts + ACK_TIMEOUT)
				&& (ack->end - ack->start < PENDING_ACK_THRESHOLD))
			{
				debug (CCI_DB_MSG,
				       "%s: Delaying ACK", __func__);
				return 0;
			}
			TAILQ_REMOVE(&sconn->acks, ack, entry);
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
		sock_pack_ack(hdr_r, type, sconn->peer_id, 0, 0, acks, count);
		
		len = sizeof(*hdr_r) + (count * sizeof(acks[0]));
		ret = sock_sendto(sep->sock, buffer, len, NULL, 0, sconn->sin);
		if (ret == -1)
			debug (CCI_DB_WARN, "%s: ACK send failed", __func__);
		sconn->last_ack_ts = now;
	}
	
	return count;
}

static void sock_ack_conns(cci__ep_t * ep)
{
	int i;
	sock_ep_t *sep = ep->priv;
	sock_conn_t *sconn = NULL;
	uint64_t now = 0ULL;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
		if (!TAILQ_EMPTY(&sep->conn_hash[i])) {
			TAILQ_FOREACH(sconn, &sep->conn_hash[i], entry) {
				sock_ack_sconn (sep, sconn);
			}
		}
	}
	pthread_mutex_unlock(&ep->lock);

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
	int i;
	sock_conn_t *sconn = NULL;

	assert (ep);
	sep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	while (!sep->closing) {

		pthread_mutex_unlock(&ep->lock);

		sock_keepalive (ep);
		sock_progress_sends (ep);

		/* If the endpoint is in the process of closing, we just move
		   on, otherwise, we wait for a signal to wake up and do progress */
		if (!sep->closing) {
			pthread_mutex_lock(&sep->progress_mutex);
			pthread_cond_wait(&sep->wait_condition,
			                  &sep->progress_mutex);
			pthread_mutex_unlock(&sep->progress_mutex);
		}

		pthread_mutex_lock(&ep->lock);
	}
	pthread_mutex_unlock(&ep->lock);

	/* Because we may have delayed some ACKs for optimization,
	   we drain all pending ACKs before ending the progress thread */
	for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
		if (!TAILQ_EMPTY(&sep->conn_hash[i])) {
			TAILQ_FOREACH(sconn, &sep->conn_hash[i], entry) {
				/* We trick the timeout value to ensure the ACK
				   will be sent */
				sconn->last_ack_ts 
					= sconn->last_ack_ts - 2 * ACK_TIMEOUT;
			}
		}
	}
	sock_ack_conns (ep);

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}

int progress_recv (cci__ep_t *ep)
{
	sock_ep_t *sep;
	int ret = 0;
	struct timeval tv = { 0, SOCK_PROG_TIME_US };
	fd_set fds;
	int again;

	sep = ep->priv;

	/* Not that on system without epoll support, sep->event_fd is equal to 0 */
	if (!sep->event_fd) {
		FD_ZERO(&fds);
		FD_SET (sep->sock, &fds);
		ret = select (sep->sock + 1, &fds, NULL, NULL, &tv);
		if (ret == -1) {
			switch (errno) {
			case EBADF:
				debug(CCI_DB_INFO,
				      "%s: select() failed with %s",
				      __func__, strerror(errno));
				break;
			default:
				break;
			}
			goto wait4signal;
		}

		do {
			again = sock_recvfrom_ep (ep);
		} while (again == 1);
	}

#ifdef HAVE_SYS_EPOLL_H
	else {
		struct epoll_event events[SOCK_EP_NUM_EVTS];

		ret = epoll_wait (sep->event_fd, events, SOCK_EP_NUM_EVTS, 0);
		if (ret > 0) {
			int count = ret;
			int i;

			debug(CCI_DB_EP,
			      "%s: epoll_wait() found %d event(s)", __func__, 
			      count);
			for (i = 0; i < count; i++) {
				int (*func)(cci__ep_t*) = events[i].data.ptr;
				if ((events[i].events & EPOLLIN)) {
					if (func != NULL && ep != NULL) {
						do {
							again = (*func)(ep);
						} while (again == 1);
					}
				}
			}
		} else if (ret == -1) {
			debug(CCI_DB_EP, "%s: epoll_wait() returned %s",
			      __func__, strerror(errno));
		}

		/* We need to avoid the case where a message is lost and we do
		   not handle a message timeout because we block */
		pthread_mutex_lock(&ep->lock);
		if (!TAILQ_EMPTY (&sep->queued) || !TAILQ_EMPTY (&sep->pending)) {
			/* If the send queue is not empty, wake up the send
			   thread */
			pthread_mutex_lock(&sep->progress_mutex);
			pthread_cond_signal(&sep->wait_condition);
			pthread_mutex_unlock(&sep->progress_mutex);
		}
		pthread_mutex_unlock(&ep->lock);

	}
#else
	else {
		struct pollfd fds[1];
		
		fds[0].fd = sep->sock;
		fds[0].events = POLLIN;
		ret = poll (fds, 1, -1);
		if (ret > 0) {
			int i;
			
			for (i = 0; i < 1; i++) {
				if (fds[i].revents & POLLIN) {
					sock_recvfrom_ep (ep);
				}
			}
		}
	}
#endif /* HAVE_SYS_EPOLL_H */

 wait4signal:
/*
 	pthread_mutex_lock(&sep->progress_mutex);
 	pthread_cond_signal(&sep->wait_condition);
 	pthread_mutex_unlock(&sep->progress_mutex);
*/
	return CCI_SUCCESS;
}

static void *sock_recv_thread(void *arg)
{
	cci__ep_t *ep = (cci__ep_t *)arg;
	sock_ep_t *sep;

	assert (ep);
	sep = ep->priv;
	while (!sep->closing) {
		progress_recv (ep);
	}

	pthread_exit(NULL);
	return (NULL);		/* make pgcc happy */
}

