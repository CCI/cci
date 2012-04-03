/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <search.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"

volatile int gni_shut_down = 0;
gni_globals_t *gglobals = NULL;
pthread_t progress_tid;

/*
 * Local functions
 */
static int gni_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int gni_finalize(void);
static const char *gni_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int gni_get_devices(cci_device_t const ***devices);
static int gni_create_endpoint(cci_device_t * device,
				 int flags,
				 cci_endpoint_t ** endpoint,
				 cci_os_handle_t * fd);
static int gni_destroy_endpoint(cci_endpoint_t * endpoint);
static int gni_accept(union cci_event *event, void *context);
static int gni_reject(union cci_event *event);
static int gni_connect(cci_endpoint_t * endpoint, char *server_uri,
			 void *data_ptr, uint32_t data_len,
			 cci_conn_attribute_t attribute,
			 void *context, int flags, struct timeval *timeout);
static int gni_disconnect(cci_connection_t * connection);
static int gni_set_opt(cci_opt_handle_t * handle,
			 cci_opt_level_t level,
			 cci_opt_name_t name, const void *val, int len);
static int gni_get_opt(cci_opt_handle_t * handle,
			 cci_opt_level_t level,
			 cci_opt_name_t name, void **val, int *len);
static int gni_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int gni_get_event(cci_endpoint_t * endpoint,
			   cci_event_t ** const event);
static int gni_return_event(cci_event_t * event);
static int gni_send(cci_connection_t * connection,
		      void *msg_ptr, uint32_t msg_len,
		      void *context, int flags);
static int gni_sendv(cci_connection_t * connection,
		       struct iovec *data, uint32_t iovcnt,
		       void *context, int flags);
static int gni_rma_register(cci_endpoint_t * endpoint,
			      cci_connection_t * connection,
			      void *start, uint64_t length,
			      uint64_t * rma_handle);
static int gni_rma_deregister(uint64_t rma_handle);
static int gni_rma(cci_connection_t * connection,
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
cci_plugin_core_t cci_core_gni_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CORE_API_VERSION,
	 "gni",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 10,

	 /* Bootstrap function pointers */
	 cci_core_gni_post_load,
	 cci_core_gni_pre_unload,
	 },

	/* API function pointers */
	gni_init,
	gni_finalize,
	gni_strerror,
	gni_get_devices,
	gni_create_endpoint,
	gni_destroy_endpoint,
	gni_accept,
	gni_reject,
	gni_connect,
	gni_disconnect,
	gni_set_opt,
	gni_get_opt,
	gni_arm_os_handle,
	gni_get_event,
	gni_return_event,
	gni_send,
	gni_sendv,
	gni_rma_register,
	gni_rma_deregister,
	gni_rma
};

static uint64_t gni_device_rate(void)
{
	uint64_t rate = 20000000000ULL;	/* 2.5 Gbps */

	return rate;
}

#if 0
static char *
gni_rc_str(gni_return_t rc)
{
	char *str = NULL;

	switch (rc) {
	case GNI_RC_SUCCESS:
		str = "GNI_RC_SUCCESS";
		break;
	case GNI_RC_NOT_DONE:
		str = "GNI_RC_NOT_DONE";
		break;
	case GNI_RC_INVALID_PARAM:
		str = "GNI_RC_INVALID_PARAM";
		break;
	case GNI_RC_ERROR_RESOURCE:
		str = "GNI_RC_ERROR_RESOURCE";
		break;
	case GNI_RC_TIMEOUT:
		str = "GNI_RC_TIMEOUT";
		break;
	case GNI_RC_PERMISSION_ERROR:
		str = "GNI_RC_PERMISSION_ERROR";
		break;
	case GNI_RC_DESCRIPTOR_ERROR:
		str = "GNI_RC_DESCRIPTOR_ERROR";
		break;
	case GNI_RC_ALIGNMENT_ERROR:
		str = "GNI_RC_ALIGNMENT_ERROR";
		break;
	case GNI_RC_INVALID_STATE:
		str = "GNI_RC_INVALID_STATE";
		break;
	case GNI_RC_NO_MATCH:
		str = "GNI_RC_NO_MATCH";
		break;
	case GNI_RC_SIZE_ERROR:
		str = "GNI_RC_SIZE_ERROR";
		break;
	case GNI_RC_TRANSACTION_ERROR:
		str = "GNI_RC_TRANSACTION_ERROR";
		break;
	case GNI_RC_ILLEGAL_OP:
		str = "GNI_RC_ILLEGAL_OP";
		break;
	case GNI_RC_ERROR_NOMEM:
		str = "GNI_RC_ERROR_NOMEM";
		break;
	default:
		str = "OTHER";
	}

	return str;
}
#endif

static cci_status_t gni_to_cci_status(gni_return_t rc)
{
	int ret = CCI_SUCCESS;

	switch (rc) {
	case GNI_RC_SUCCESS:
		ret = CCI_SUCCESS;
		break;
	case GNI_RC_NOT_DONE:
		ret = CCI_EAGAIN;
		break;
	case GNI_RC_INVALID_PARAM:
		ret = CCI_EINVAL;
		break;
	case GNI_RC_ERROR_RESOURCE:
		ret = CCI_ENOMEM;
		break;
	case GNI_RC_TIMEOUT:
		ret = CCI_ETIMEDOUT;
		break;
	case GNI_RC_PERMISSION_ERROR:
		ret = CCI_ERR_RMA_HANDLE;
		break;
	case GNI_RC_DESCRIPTOR_ERROR:
		ret = CCI_ERROR;
		break;
	case GNI_RC_ALIGNMENT_ERROR:
		ret = CCI_EINVAL;
		break;
	case GNI_RC_INVALID_STATE:
		ret = CCI_ERROR;
		break;
	case GNI_RC_NO_MATCH:
		ret = CCI_EAGAIN;
		break;
	case GNI_RC_SIZE_ERROR:
		ret = CCI_ERROR;
		break;
	case GNI_RC_TRANSACTION_ERROR:
		ret = CCI_ERROR;
		break;
	case GNI_RC_ILLEGAL_OP:
		ret = CCI_ERR_RMA_OP;
		break;
	case GNI_RC_ERROR_NOMEM:
		ret = CCI_ENOMEM;
		break;
	default:
		ret = CCI_ERROR;
	}

	return ret;
}

static int
gni_find_gni_device_sin(int id, struct sockaddr_in *sin)
{
	int ret = CCI_SUCCESS;
	char interface[16];
	socklen_t slen = sizeof(*sin);
	struct ifaddrs *ifa = NULL;
	struct ifaddrs *tmp = NULL;

	CCI_ENTER;

	memset(interface, 0, sizeof(interface));
	sprintf(interface, "ipogif%d", id);

	ret = getifaddrs(&ifa);
	if (ret) {
		ret = errno;
		goto out;
	}

	for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
		if (tmp->ifa_addr->sa_family == AF_INET &&
		    !(tmp->ifa_flags & IFF_LOOPBACK)) {
			if (0 == strcmp(interface, tmp->ifa_name)) {
				memcpy(sin, tmp->ifa_addr, slen);
				debug(CCI_DB_DRVR, "%s: device[%d] is %s",
					__func__, id, inet_ntoa(sin->sin_addr));
				break;
			}
		}
	}

	freeifaddrs(ifa);
      out:
	CCI_EXIT;
	return ret;
}

static gni_tx_t *gni_get_tx_locked(gni_ep_t * gep)
{
	gni_tx_t *tx = NULL;

	if (!TAILQ_EMPTY(&gep->idle_txs)) {
		tx = TAILQ_FIRST(&gep->idle_txs);
		TAILQ_REMOVE(&gep->idle_txs, tx, entry);
	}
	return tx;
}

static gni_tx_t *gni_get_tx(cci__ep_t * ep)
{
	gni_ep_t *gep = ep->priv;
	gni_tx_t *tx = NULL;

	pthread_mutex_lock(&ep->lock);
	tx = gni_get_tx_locked(gep);
	pthread_mutex_unlock(&ep->lock);

	return tx;
}

void
gni_cci__init_dev(cci__dev_t *dev)
{
	struct cci_device *device = &dev->device;

	dev->priority = 50; /* default */
	dev->is_default = 0;
	TAILQ_INIT(&dev->eps);
	pthread_mutex_init(&dev->lock, NULL);
	device->up = 1;
}

static int gni_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int count = 0;
	int index = 0;
	int used[CCI_MAX_DEVICES];
	int ret = 0;
	gni_return_t grc = GNI_RC_SUCCESS;
	cci__dev_t *dev = NULL;
	cci_device_t **devices = NULL;
	//struct ifaddrs *ifaddrs = NULL;
	uint32_t cpu_id = 0;

	CCI_ENTER;

	memset(used, 0, CCI_MAX_DEVICES);

	/* init driver globals */
	gglobals = calloc(1, sizeof(*gglobals));
	if (!gglobals) {
		ret = CCI_ENOMEM;
		goto out;
	}

	devices = calloc(CCI_MAX_DEVICES, sizeof(*gglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	grc = GNI_GetNumLocalDevices(&count);
	if (grc != GNI_RC_SUCCESS) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	gglobals->count = count;

	gglobals->device_ids = calloc(gglobals->count, sizeof(int));
	if (!gglobals->device_ids) {
		ret = CCI_ENOMEM;
		goto out;
	}

	grc = GNI_GetLocalDeviceIds(gglobals->count, gglobals->device_ids);
	if (grc != GNI_RC_SUCCESS) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

#if 0
	/* for each ifaddr, check if it is a GNI device */
	ret = gni_find_gni_device_ids(&gglobals->device_ids, count, &ifaddrs);
	if (ret) {
		/* TODO */
		ret = CCI_ENODEV;
		goto out;
	}
	gglobals->ifaddrs = ifaddrs;
#endif

	if (!configfile) {
		struct cci_device *device;
		gni_dev_t *gdev = NULL;

		dev = calloc(1, sizeof(*dev));
		if (!dev) {
			ret = CCI_ENOMEM;
			goto out;
		}
		dev->priv = calloc(1, sizeof(*gdev));
		if (!dev->priv) {
			free(dev);
			ret = CCI_ENOMEM;
			goto out;
		}

		gni_cci__init_dev(dev);

		device = &dev->device;
		device->max_send_size = GNI_EP_MSS;
		device->name = strdup("gni0");

		device->rate = gni_device_rate();
		device->pci.domain = -1;	/* per CCI spec */
		device->pci.bus = -1;		/* per CCI spec */
		device->pci.dev = -1;		/* per CCI spec */
		device->pci.func = -1;		/* per CCI spec */

		gdev = dev->priv;
		gdev->device_id = 0;
		gdev->ptag = GNI_DEFAULT_PTAG;
		gdev->cookie = GNI_DEFAULT_COOKIE;
		ret = gni_find_gni_device_sin(gdev->device_id, &gdev->sin);
		if (ret) {
			goto out;
		}

		grc = GNI_CdmGetNicAddress(0, &gdev->phys_addr, &cpu_id);
		if (grc != GNI_RC_SUCCESS) {
			ret = gni_to_cci_status(grc);
			goto out;
		}

		dev->driver = strdup("gni");
		dev->is_up = 1;
		dev->is_default = 1;
		TAILQ_INSERT_TAIL(&globals->devs, dev, entry);
		devices[gglobals->count] = device;
		gglobals->count++;

	} else
	/* find devices we own */
	TAILQ_FOREACH(dev, &globals->devs, entry) {
		if (0 == strcmp("gni", dev->driver)) {
			int i = 0;
			const char **arg;
			uint32_t port = 0;
			cci_device_t *device = NULL;
			gni_dev_t *gdev = NULL;

			device = &dev->device;
			device->pci.domain = -1;	/* per CCI spec */
			device->pci.bus = -1;	/* per CCI spec */
			device->pci.dev = -1;	/* per CCI spec */
			device->pci.func = -1;	/* per CCI spec */

			dev->priv = calloc(1, sizeof(*gdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}

			gdev = dev->priv;
			gdev->device_id = -1;
			gdev->ptag = GNI_DEFAULT_PTAG;
			gdev->cookie = GNI_DEFAULT_COOKIE;

			/* parse conf_argv */
			for (arg = device->conf_argv; *arg != NULL; arg++) {
				if (0 == strncmp("port=", *arg, 5)) {
					const char *port_str = *arg + 5;

					port =
					    (uint16_t) strtoul(port_str, NULL,
							       0);
				} else if (0 == strncmp("driver=", *arg, 7)) {
					/* do nothing */
				} else {
					debug(CCI_DB_INFO, "unknown keyword %s",
					      *arg);
				}
			}

			for (i = 0; i < count; i++) {
				int id = gglobals->device_ids[i];

				if (used[i]) {
					debug(CCI_DB_WARN,
					      "device already assigned %d", id);
					goto out;
				}
				gdev->device_id = id;
				ret = gni_find_gni_device_sin(gdev->device_id, &gdev->sin);
				if (ret) {
					goto out;
				}
				grc = GNI_CdmGetNicAddress(0, &gdev->phys_addr, &cpu_id);
				if (grc != GNI_RC_SUCCESS) {
					ret = gni_to_cci_status(grc);
					goto out;
				}

				gdev->base_port = port;
				used[i]++;
				break;
			}

			if (gdev->device_id == -1) {
				debug(CCI_DB_INFO, "%s: no device id for %d", __func__, i);
				goto out;
			}

			device->max_send_size = GNI_EP_MSS;
			device->rate = gni_device_rate();

			devices[index] = device;
			index++;
			dev->is_up = 1;
			debug(CCI_DB_INFO, "%s: device[%d] is up", __func__, i);
		}
	}

	devices =
	    realloc(devices, (gglobals->count + 1) * sizeof(cci_device_t *));
	devices[gglobals->count] = NULL;

	*((cci_device_t ***) & gglobals->devices) = devices;

	{
		struct timeval tv;
		int seed = 0;

		seed = getpid();
		seed = (seed & 0xFFFF) << 16;

		gettimeofday(&tv, NULL);
		seed |= (int) tv.tv_usec;
		srandom(seed);
	}

	/* TODO  start progress thread */

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
	if (gglobals) {
		free(gglobals->device_ids);
		free((void *)gglobals);
		gglobals = NULL;
	}

	CCI_EXIT;
	return ret;
}

static const char *gni_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	char *str = NULL;

	switch (status) {
		default:
			str = strerror(status);
	}
	return str;
}

static int gni_get_devices(cci_device_t const ***devices)
{
	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

/* FIXME: update the devices list (up field, ...).
   add new devices if !configfile */

	*devices = gglobals->devices;

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int gni_finalize(void)
{
	int ret = CCI_SUCCESS;
	//int i = 0;
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	pthread_mutex_lock(&globals->lock);
	gni_shut_down = 1;
	pthread_mutex_unlock(&globals->lock);
	/* TODO join progress thread */

	free(gglobals->device_ids);

	pthread_mutex_lock(&globals->lock);
	TAILQ_FOREACH(dev, &globals->devs, entry)
	    if (dev->priv)
		free(dev->priv);
	pthread_mutex_unlock(&globals->lock);

	free(gglobals->devices);
	free((void *)gglobals);
	gglobals = NULL;

	CCI_EXIT;
	return ret;
}

static int gni_destroy_rx_pool(cci__ep_t * ep, gni_rx_pool_t * rx_pool);

static int gni_post_rx(cci__ep_t * ep, gni_rx_t * rx)
{
	int ret = CCI_SUCCESS;
	//gni_ep_t *gep = ep->priv;
	//gni_rx_pool_t *rx_pool = rx->rx_pool;

	CCI_ENTER;

#if 0
	if (rx_pool->repost == 0) {
		/* do not repost - see if we need to tear-down rx_pool */
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
		free(rx);
		if (TAILQ_EMPTY(&rx_pool->rxs)) {
			int rc = 0;

			TAILQ_REMOVE(&gep->rx_pools, rx_pool, entry);
			rc = gni_destroy_rx_pool(ep, rx_pool);
			if (rc)
				debug(CCI_DB_EP, "%s: gni_destroy_rx_pool() "
				      "returned %s", __func__,
				      cci_strerror(&ep->endpoint, rc));
		}
		pthread_mutex_unlock(&ep->lock);
		/* return SUCCESS so that the caller does not continue
		 * using the rx */
		return CCI_SUCCESS;
	}

	rx_pool->posted++;
#endif
	/* FIXME place on idle_rxs
	 * indicate buffer is available to get a new GNI event */
	CCI_EXIT;
	return ret;
}

static int gni_create_rx_pool(cci__ep_t * ep, int rx_buf_cnt)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;
	gni_ep_t *gep = NULL;
	gni_rx_pool_t *rx_pool = NULL;
	size_t len = 0;

	CCI_ENTER;

	dev = ep->dev;
	gep = ep->priv;

	rx_pool = calloc(1, sizeof(*rx_pool));
	if (!rx_pool) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	TAILQ_INIT(&rx_pool->rxs);
	TAILQ_INIT(&rx_pool->idle_rxs);
	//rx_pool->repost = 1;
	rx_pool->size = rx_buf_cnt;
	len = rx_buf_cnt * dev->device.max_send_size;
	ret = posix_memalign((void **)&rx_pool->buf, getpagesize(), len);
	if (ret)
		goto out;
	memset(rx_pool->buf, 0, len);	/* silence valgrind */

	for (i = 0; i < rx_buf_cnt; i++) {
		uintptr_t offset = i * ep->buffer_len;
		gni_rx_t *rx = NULL;

		rx = calloc(1, sizeof(*rx));
		if (!rx) {
			ret = CCI_ENOMEM;
			goto out;
		}

		rx->evt.ep = ep;
		rx->offset = offset;
		rx->ptr = rx_pool->buf + (uintptr_t) rx->offset;
		rx->rx_pool = rx_pool;
		TAILQ_INSERT_TAIL(&rx_pool->rxs, rx, entry);
		TAILQ_INSERT_TAIL(&rx_pool->idle_rxs, rx, idle);

		ret = gni_post_rx(ep, rx);
		if (ret)
			goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&gep->rx_pools, rx_pool, entry);
	ep->rx_buf_cnt = rx_buf_cnt;
	pthread_mutex_unlock(&ep->lock);
      out:
	if (ret && rx_pool) {
		//rx_pool->repost = 0;
		if (0 /* rx_pool->posted */) {
			/* we can't free anything since we posted some rxs.
			 * add this to the tail of the ep->rx_pools and tear
			 * down after the last rx completes
			 */
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&gep->rx_pools, rx_pool, entry);
			pthread_mutex_unlock(&ep->lock);
		} else {
			/* FIXME There is a race here - rx_pool->posted might be 0 if
			 * we posted 1 or more rxs and they all completed before
			 * reaching here.
			 */
			while (!TAILQ_EMPTY(&rx_pool->rxs)) {
				gni_rx_t *rx = NULL;

				rx = TAILQ_FIRST(&rx_pool->rxs);
				TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
				free(rx);
			}
			if (rx_pool->buf)
				free(rx_pool->buf);
			free(rx_pool);
		}
	}
	CCI_EXIT;
	return ret;
}

static int
gni_create_endpoint(cci_device_t * device,
		      int flags,
		      cci_endpoint_t ** endpoint, cci_os_handle_t * fd)
{
	int i = 0;
	int ret = CCI_SUCCESS;
	int pg_sz = 0;
	char name[MAXHOSTNAMELEN + 16];	/* gni:// + phys_addr + port */
	size_t len = 0;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	gni_ep_t *gep = NULL;
	gni_dev_t *gdev = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	uint32_t port = 0;
	uint32_t unused = 0;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);

	CCI_ENTER;

	if (!gglobals) {
		debug(CCI_DB_INFO, "%s: no globals?", __func__);
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	gdev = dev->priv;
	port = gdev->base_port;

	ep = container_of(*endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*gep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gep = ep->priv;

	TAILQ_INIT(&gep->crs);
	TAILQ_INIT(&gep->idle_crs);
	TAILQ_INIT(&gep->txs);
	TAILQ_INIT(&gep->idle_txs);
	TAILQ_INIT(&gep->rx_pools);
	TAILQ_INIT(&gep->conns);
	TAILQ_INIT(&gep->active);
	TAILQ_INIT(&gep->active2);
	TAILQ_INIT(&gep->passive);
	TAILQ_INIT(&gep->passive2);
	TAILQ_INIT(&gep->handles);
	TAILQ_INIT(&gep->rma_ops);

	ret = pthread_rwlock_init(&gep->conn_tree_lock, NULL);
	if (ret) {
		/* TODO */
		goto out;
	}

	(*endpoint)->max_recv_buffer_count = GNI_EP_RX_CNT;
	ep->rx_buf_cnt = GNI_EP_RX_CNT;
	ep->tx_buf_cnt = GNI_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0;	/* FIXME */

	/* open socket to get port, don't use for communication */
	ret = socket(PF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	gep->sock = ret;

	memcpy(&gep->sin, &gdev->sin, slen);
	gep->sin.sin_port = htons(port);

	ret = bind(gep->sock, (struct sockaddr*)&gep->sin, slen);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_DRVR, "%s: bind() returned %s", __func__,
			strerror(ret));
		goto out;
	}
	ret = getsockname(gep->sock, (struct sockaddr*)&sin, &slen);
	port = (uint32_t) ntohs(sin.sin_port);

	memcpy(&gep->sin, &sin, slen);

	memset(name, 0, sizeof(name));
	sprintf(name, "%s%u:%u", GNI_URI, gdev->phys_addr, port);
	*((char **)&ep->endpoint.name) = strdup(name);

#if 0
	ret = listen(gep->sock, SOMAXCONN);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = fcntl(gep->sock, F_GETFD, 0);
	if (ret == -1)
		fflags = 0;
	else
		fflags = ret;
	ret = fcntl(gep->sock, F_SETFL, fflags | O_NONBLOCK);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
#endif

	debug(CCI_DB_DRVR, "%s: creating CDM port=%u ptag=%u cookie=0x%x",
		__func__, port, gdev->ptag, gdev->cookie);

	grc = GNI_CdmCreate(port, gdev->ptag, gdev->cookie,
			0, &gep->cdm);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	grc = GNI_CdmAttach(gep->cdm, gdev->device_id, &unused, &gep->nic);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	grc = GNI_CqCreate(gep->nic, GNI_EP_TX_CNT, 0, GNI_CQ_NOBLOCK,
			NULL, NULL, &gep->tx_cq);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	grc = GNI_CqCreate(gep->nic, GNI_EP_RX_CNT, 0, GNI_CQ_NOBLOCK,
			NULL, NULL, &gep->rx_cq);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	pg_sz = getpagesize();

	len = GNI_EP_TX_CNT * dev->device.max_send_size;
	ret = posix_memalign((void **)&gep->tx_buf, pg_sz, len);
	if (ret)
		goto out;
	memset(gep->tx_buf, 0, len);	/* silence valgrind */

	for (i = 0; i < GNI_EP_TX_CNT; i++) {
		uintptr_t offset = i * ep->buffer_len;
		gni_tx_t *tx = NULL;

		tx = calloc(1, sizeof(*tx));
		if (!tx) {
			ret = CCI_ENOMEM;
			goto out;
		}
		tx->evt.ep = ep;
		tx->buffer = gep->tx_buf + offset;
		tx->id = i;
		TAILQ_INSERT_TAIL(&gep->txs, tx, gentry);
		TAILQ_INSERT_TAIL(&gep->idle_txs, tx, entry);
	}

	ret = gni_create_rx_pool(ep, ep->rx_buf_cnt);
	if (ret)
		goto out;

	debug(CCI_DB_INFO, "%s: creating listening endpoint", __func__);

	grc = GNI_EpCreate(gep->nic, gep->tx_cq, &gep->lep);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	debug(CCI_DB_INFO, "%s: allocating connection request buffers", __func__);

	gep->infos = calloc(GNI_EP_CONN_REQ_CNT, sizeof(*gep->infos));
	if (!gep->infos) {
		ret = CCI_ENOMEM;
		goto out;
	}
	memset(gep->infos, 0, GNI_EP_CONN_REQ_CNT * sizeof(gep->infos));
	for (i = 0; i < GNI_EP_CONN_REQ_CNT; i++) {
		gni_smsg_info_t *info = &gep->infos[i];
		int len = sizeof(*info);

		grc = GNI_EpPostDataWId(gep->lep, NULL, 0, info, len, (uintptr_t)info);
		if (grc) {
			ret = gni_to_cci_status(grc);
			debug(CCI_DB_INFO, "%s: unable to post conn req %d (%d %d)",
					__func__, i, grc, ret);
			goto out;
		}
	}

	CCI_EXIT;
	return CCI_SUCCESS;

      out:
	/* TODO lots of clean up */
	if (ep->priv) {
		gni_ep_t *gep = ep->priv;

		while (!TAILQ_EMPTY(&gep->rx_pools)) {
			gni_rx_pool_t *rx_pool = TAILQ_FIRST(&gep->rx_pools);

			TAILQ_REMOVE(&gep->rx_pools, rx_pool, entry);
			while (!TAILQ_EMPTY(&rx_pool->rxs)) {
				gni_rx_t *rx = TAILQ_FIRST(&rx_pool->rxs);
				TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
				free(rx);
			}
			free(rx_pool->buf);
		}

		while (!TAILQ_EMPTY(&gep->txs)) {
			gni_tx_t *tx = TAILQ_FIRST(&gep->txs);
			TAILQ_REMOVE(&gep->txs, tx, gentry);
			free(tx);
		}

		free(gep->tx_buf);

		if (gep->tx_cq) {
			grc = GNI_CqDestroy(gep->tx_cq);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint tx_cq "
				      "failed with %s\n",
				      cci_strerror(NULL, gni_to_cci_status(grc)));
		}

		if (gep->rx_cq) {
			grc = GNI_CqDestroy(gep->rx_cq);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint rx_cq "
				      "failed with %s\n",
				      cci_strerror(NULL, gni_to_cci_status(grc)));
		}

		if (gep->cdm) {
			grc = GNI_CdmDestroy(gep->cdm);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint cdm "
				      "failed with %s\n",
				      cci_strerror(NULL, gni_to_cci_status(grc)));
		}

		if (gep->sock)
			close(gep->sock);

		free(gep);
		ep->priv = NULL;
	}
	return ret;
}

static int gni_destroy_rx_pool(cci__ep_t * ep, gni_rx_pool_t * rx_pool)
{
	int ret = CCI_SUCCESS;

	while (!TAILQ_EMPTY(&rx_pool->rxs)) {
		gni_rx_t *rx = TAILQ_FIRST(&rx_pool->rxs);
		TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
		free(rx);
	}

	if (rx_pool->buf)
		free(rx_pool->buf);

	free(rx_pool);

	CCI_EXIT;
	return ret;
}

static int gni_destroy_endpoint(cci_endpoint_t * endpoint)
{
	//int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	while (!TAILQ_EMPTY(&gep->conns)) {
		cci__conn_t *conn = NULL;
		gni_conn_t *gconn = NULL;

		gconn = TAILQ_FIRST(&gep->conns);
		conn = gconn->conn;
		gni_disconnect(&conn->connection);
	}

	if (gep->tx_cq) {
		grc = GNI_CqDestroy(gep->tx_cq);
		if (grc)
			debug(CCI_DB_WARN, "destroying endpoint tx_cq "
			      "failed with %s\n", strerror(gni_to_cci_status(grc)));
	}

	if (gep->rx_cq) {
		grc = GNI_CqDestroy(gep->rx_cq);
		if (grc)
			debug(CCI_DB_WARN, "destroying endpoint rx_cq "
			      "failed with %s\n", strerror(gni_to_cci_status(grc)));
	}

	if (gep->cdm) {
		grc = GNI_CdmDestroy(gep->cdm);
		if (grc)
			debug(CCI_DB_WARN, "destroying endpoint cdm "
			      "failed with %s\n", strerror(gni_to_cci_status(grc)));
	}

	if (gep->sock)
		close(gep->sock);

	ep->priv = NULL;

	while (!TAILQ_EMPTY(&gep->rx_pools)) {
		gni_rx_pool_t *rx_pool = TAILQ_FIRST(&gep->rx_pools);

		TAILQ_REMOVE(&gep->rx_pools, rx_pool, entry);
		gni_destroy_rx_pool(ep, rx_pool);
	}

	while (!TAILQ_EMPTY(&gep->txs)) {
		gni_tx_t *tx = TAILQ_FIRST(&gep->txs);
		TAILQ_REMOVE(&gep->txs, tx, gentry);
		free(tx);
	}

	free(gep->tx_buf);
	free(gep);
	free((char *)ep->endpoint.name);

	CCI_EXIT;
	return CCI_SUCCESS;
}

static const char *gni_msg_type_str(gni_msg_type_t msg_type)
{
	char *str;

	switch (msg_type) {
	case GNI_MSG_CONN_REQUEST:
		str = "conn_request";
		break;
	case GNI_MSG_CONN_PAYLOAD:
		str = "conn_payload";
		break;
	case GNI_MSG_CONN_REPLY:
		str = "conn_reply";
		break;
	case GNI_MSG_DISCONNECT:
		str = "disconnect";
		break;
	case GNI_MSG_SEND:
		str = "send";
		break;
	case GNI_MSG_RMA_REMOTE_REQUEST:
		str = "rma_remote_request";
		break;
	case GNI_MSG_RMA_REMOTE_REPLY:
		str = "rma_remote_reply";
		break;
	case GNI_MSG_KEEPALIVE:
		str = "keepalive";
		break;
	case GNI_MSG_RMA:
		str = "rma";
		break;
	default:
		str = "invalid";
		break;
	}
	return str;
}

typedef union gni_u64 {
	uint64_t ull;
	uint32_t ul[2];
} gni_u64_t;

#if 0
static uint64_t gni_ntohll(uint64_t val)
{
	gni_u64_t net = {.ull = val };
	gni_u64_t host;

	host.ul[0] = ntohl(net.ul[1]);
	host.ul[1] = ntohl(net.ul[0]);

	return host.ull;
}
#endif

static uint64_t gni_htonll(uint64_t val)
{
	gni_u64_t host = {.ull = val };
	gni_u64_t net;

	net.ul[0] = htonl(host.ul[1]);
	net.ul[1] = htonl(host.ul[0]);

	return net.ull;
}

static int
gni_post_send(cci__conn_t * conn, uint32_t id, void *buffer, uint32_t len,
		uint32_t header)
{
	int ret = CCI_SUCCESS;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_conn_t *gconn = conn->priv;

	CCI_ENTER;

	header |= (len << 4);
	debug(CCI_DB_MSG, "sending msg 0x%x", header);

	grc = GNI_SmsgSend(gconn->peer, &header, sizeof(header), buffer, len, id);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_MSG, "%s: grc %u ret %u", __func__,
			grc, ret);
	}

	CCI_EXIT;
	return ret;
}

static int gni_accept(union cci_event *event, void *context)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = NULL;
	gni_conn_t *gconn = NULL;
	gni_conn_request_t *cr = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	uint32_t header = GNI_MSG_CONN_REPLY;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	gep = ep->priv;

	conn = evt->conn;
	gconn = conn->priv;
	cr = gconn->conn_req;

	header |= (1 << 4);

	gconn->state = GNI_CONN_PASSIVE2;
	conn->connection.context = context;

	debug(CCI_DB_CONN, "%s: sending conn reply to %u:%u", __func__,
		cr->addr, cr->port);

	/* wait for client ack */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->passive2, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

	grc = GNI_SmsgSend(gconn->peer, &header, sizeof(header), NULL, 0, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

      out:
	/* TODO cleanup if ret != CCI_SUCCESS */
	if (ret) {
		debug(CCI_DB_CONN, "%s: failed with %s", __func__,
			cci_strerror(&ep->endpoint, ret));
	}
	CCI_EXIT;
	return ret;
}

static int gni_reject(union cci_event *event)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	gni_conn_t *gconn = NULL;
	gni_conn_request_t *cr = NULL;
	uint32_t header = GNI_MSG_CONN_REPLY;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);

	conn = evt->conn;
	gconn = conn->priv;
	cr = gconn->conn_req;

	gconn->state = GNI_CONN_CLOSING;

	debug(CCI_DB_CONN, "%s: sending conn reject to %u:%u", __func__,
		cr->addr, cr->port);

	grc = GNI_SmsgSend(gconn->peer, &header, sizeof(header), NULL, 0, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
	}

	/* TODO handle error
	 *      queue to wait for ack?
	 */

	/* wait for CONN_ACK to arrive before destorying the conn */

	CCI_EXIT;
	return ret;
}

static int gni_parse_uri(const char *uri, uint32_t *addr, uint32_t *port)
{
	int ret = CCI_SUCCESS;
	int len = strlen(GNI_URI);
	char *a = NULL;
	char *p = NULL;
	char *colon = NULL;

	CCI_ENTER;

	if (0 == strncmp(GNI_URI, uri, len)) {
		a = strdup(&uri[len]);
	} else {
		ret = CCI_EINVAL;
		goto out;
	}

	colon = strchr(a, ':');
	if (colon) {
		*colon = '\0';
	} else {
		ret = CCI_EINVAL;
		goto out;
	}

	colon++;
	p = colon;

	*addr = strtol(a, NULL, 0);
	*port = strtol(p, NULL, 0);

      out:
	free(a);
	CCI_EXIT;
	return ret;
}

static int
gni_compare_u32(const void *pa, const void *pb)
{
	if (*(uint32_t*) pa < *(uint32_t*) pb)
		return -1;
	if (*(uint32_t*) pa > *(uint32_t*) pb)
		return 1;
	return 0;
}

static int
gni_find_conn(cci__ep_t *ep, uint32_t id, cci__conn_t ** conn)
{
	int ret = CCI_ERROR;
	gni_ep_t *gep = ep->priv;
	void *node = NULL;
	uint32_t *i = NULL;

	CCI_ENTER;

	pthread_rwlock_rdlock(&gep->conn_tree_lock);
	node = tfind(&id, &gep->conn_tree, gni_compare_u32);
	pthread_rwlock_unlock(&gep->conn_tree_lock);
	if (node) {
		gni_conn_t *gconn = NULL;

		i = *((uint32_t **)node);
		gconn = container_of(i, gni_conn_t, id);
		assert(gconn->id == id);
		*conn = gconn->conn;
		ret = CCI_SUCCESS;
	}

	CCI_EXIT;
	return ret;
}

static void
gni_insert_conn(cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	uint32_t id = 0;
	cci__ep_t *ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	cci__conn_t *c = NULL;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	void *node = NULL;

	CCI_ENTER;

	pthread_rwlock_wrlock(&gep->conn_tree_lock);
	do {
		id = random();
		ret = gni_find_conn(ep, id, &c);
	} while (ret == CCI_SUCCESS);
	gconn->id = id;
	do {
		node = tsearch(&gconn->id, &gep->conn_tree, gni_compare_u32);
	} while (!node);
	pthread_rwlock_unlock(&gep->conn_tree_lock);

	debug(CCI_DB_CONN, "%s: inserted conn %u", __func__, gconn->id);

	CCI_EXIT;
	return;
}

static int
gni_connect(cci_endpoint_t * endpoint, char *server_uri,
	      void *data_ptr, uint32_t data_len,
	      cci_conn_attribute_t attribute,
	      void *context, int flags, struct timeval *timeout)
{
	int ret = CCI_SUCCESS;
	uint32_t peer_addr = 0;
	uint32_t peer_port = 0;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = NULL;
	gni_conn_t *gconn = NULL;
	gni_conn_request_t *cr = NULL;
	gni_smsg_attr_t attr;
	gni_smsg_info_t info;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_post_state_t post_state = GNI_POST_PENDING;
	uint32_t a, p;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	gep = ep->priv;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->connection.max_send_size = ep->buffer_len;
	conn->connection.endpoint = endpoint;
	conn->connection.attribute = attribute;
	conn->connection.context = context;

	conn->priv = calloc(1, sizeof(*gconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gconn = conn->priv;
	gconn->conn = conn;
	TAILQ_INIT(&gconn->remotes);
	TAILQ_INIT(&gconn->rma_ops);
	*((char **)&conn->uri) = strdup(server_uri);
	gni_insert_conn(conn);

	cr = calloc(1, sizeof(*cr));
	if (!cr) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gconn->conn_req = cr;

	memset(&attr, 0, sizeof(attr));
	attr.mbox_maxcredit = GNI_CONN_CREDIT;
	attr.msg_maxsize = GNI_EP_MSS;
	if (attribute == CCI_CONN_ATTR_RO || attribute == CCI_CONN_ATTR_RU)
			attr.msg_type = GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	else
			attr.msg_type = GNI_SMSG_TYPE_MBOX;

	grc = GNI_SmsgBufferSizeNeeded(&attr, &gconn->buff_size);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	gconn->msg_buffer = calloc(1, gconn->buff_size);
	if (!gconn->msg_buffer) {
		ret = CCI_ENOMEM;
		goto out;
	}

	grc = GNI_MemRegister(gep->nic, (uintptr_t) gconn->msg_buffer,
			gconn->buff_size, gep->rx_cq, GNI_MEM_READWRITE,
			-1, &gconn->mem_hndl);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.mem_hndl = gconn->mem_hndl;
	info.msg_buffer = (uintptr_t) gconn->msg_buffer;
	info.msg_type = attr.msg_type;
	info.buff_size = gconn->buff_size;
	info.mbox_offset = 0;
	info.mbox_maxcredit = attr.mbox_maxcredit;
	info.msg_maxsize = attr.msg_maxsize;
	info.id = gconn->id;
	info.len_attr = (data_len << 4) | attribute;

	/* store the payload for later */
	cr->ptr = calloc(1, data_len);
	if (!cr->ptr) {
		ret = CCI_ENOMEM;
		goto out;
	}
	cr->len = data_len;
	if (cr->len)
		memcpy(cr->ptr, data_ptr, data_len);

	/* conn->tx_timeout = 0;  by default */

	ret = gni_parse_uri(server_uri, &peer_addr, &peer_port);
	if (ret)
		goto out;

	cr->addr = peer_addr;
	cr->port = peer_port;
	gconn->state = GNI_CONN_ACTIVE;

	grc = GNI_EpCreate(gep->nic, gep->tx_cq, &gconn->peer);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	/* bind to peer's listening ep to send request */
	grc = GNI_EpBind(gconn->peer, peer_addr, peer_port);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	/* set our local event id for now */
	grc = GNI_EpSetEventData(gconn->peer, gconn->id, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	debug(CCI_DB_CONN, "%s: posting initial connect datagram", __func__);

	/* send the initial conn request */
	grc = GNI_EpPostData(gconn->peer, &info, sizeof(info), NULL, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_CONN, "%s: GNI_EpPostData() failed with %s (%d)",
			__func__, cci_strerror(&ep->endpoint, ret), grc);
		goto out;
	}

	/* need to check completion */
	do {
		grc = GNI_EpPostDataTest(gconn->peer, &post_state, &a, &p);
		if (grc) {
			ret = gni_to_cci_status(grc);
			debug(CCI_DB_CONN, "%s: GNI_EpPostDataTest() returned %s (%d)",
				__func__, cci_strerror(&ep->endpoint, ret), grc);
			goto out;
		}
	} while (post_state != GNI_POST_COMPLETED);

	debug(CCI_DB_CONN, "%s: posting rx datagram", __func__);

	/* post a reply datagram */
	grc = GNI_EpPostDataWId(gconn->peer, NULL, 0, &cr->reply, sizeof(cr->reply),
			cr->info.id);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_CONN, "%s: posting rx datagram failed with %s (%d)",
				__func__, cci_strerror(&ep->endpoint, ret), grc);
		goto out;
	}

	debug(CCI_DB_CONN, "connecting to %s\n", server_uri);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->active, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

      out:
	if (ret) {
		if (cr) {
			free(cr->ptr);
		}
		free(cr);
		free(gconn);
		free(conn);
	}

	CCI_EXIT;
	return ret;
}

static int gni_disconnect(cci_connection_t * connection)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	gni_conn_t *gconn = conn->priv;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->conns, gconn, entry);
	pthread_mutex_unlock(&ep->lock);

	free(gconn->conn_req->ptr);

	/* TODO free mbox */

	free(gconn);
	free(conn);

	CCI_EXIT;
	return ret;
}

static int
gni_set_opt(cci_opt_handle_t * handle,
	      cci_opt_level_t level,
	      cci_opt_name_t name, const void *val, int len)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	//cci_endpoint_t *endpoint = NULL;
	//cci__ep_t *ep = NULL;
	//cci__dev_t *dev = NULL;
	//gni_ep_t *gep = NULL;
	//gni_dev_t *gdev = NULL;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	//endpoint = handle->endpoint;
	//ep = container_of(endpoint, cci__ep_t, endpoint);
	//gep = ep->priv;
	//dev = ep->dev;
	//gdev = dev->priv;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
	case CCI_OPT_CONN_SEND_TIMEOUT:
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		/* not implemented */
		break;
	default:
		debug(CCI_DB_INFO, "unknown option %u",
		      (enum cci_opt_name)name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;
	return ret;
}

static int
gni_get_opt(cci_opt_handle_t * handle,
	      cci_opt_level_t level, cci_opt_name_t name, void **val, int *len)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int gni_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

#if 0
static const char *gni_conn_state_str(gni_conn_state_t state)
{
	char *str;
	switch (state) {
	case GNI_CONN_CLOSED:
		str = "closed";
		break;
	case GNI_CONN_CLOSING:
		str = "closing";
		break;
	case GNI_CONN_INIT:
		str = "init";
		break;
	case GNI_CONN_ACTIVE:
		str = "active";
		break;
	case GNI_CONN_PASSIVE:
		str = "passive";
		break;
	case GNI_CONN_PASSIVE2:
		str = "passive2";
		break;
	case GNI_CONN_ESTABLISHED:
		str = "established";
		break;
	}
	return str;
}
#endif

/* Our initial conn request completed. Check for the server's reply */
static int gni_conn_est_active(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	uint32_t addr, port;
	uint32_t header = GNI_MSG_CONN_PAYLOAD;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_conn_request_t *cr = gconn->conn_req;
	gni_post_state_t post_state = GNI_POST_PENDING;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_smsg_attr_t local, remote;
	gni_smsg_info_t reply;

	CCI_ENTER;

	debug(CCI_DB_CONN, "%s: check for conn reply from %u:%u", __func__,
		cr->addr, cr->port);

#if 0
	grc = GNI_EpPostData(gconn->peer, NULL, 0, &reply, sizeof(reply));
	if (grc) {
		ret = gni_to_cci_status(grc);
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&gep->active, gconn, temp);
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}
#endif

	do {
		grc = GNI_EpPostDataTest(gconn->peer, &post_state, &addr, &port);
		if (grc) {
			ret = gni_to_cci_status(grc);
			goto out;
		}
	} while (post_state != GNI_POST_COMPLETED);
	assert(addr == cr->addr && port == cr->port);

	/* set both local and remote event ids */
	grc = GNI_EpSetEventData(gconn->peer, gconn->id, reply.id);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	memset(&local, 0, sizeof(local));
	local.msg_type = conn->connection.attribute == CCI_CONN_ATTR_UU ?
		GNI_SMSG_TYPE_MBOX : GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	local.msg_buffer = gconn->msg_buffer;
	local.buff_size = gconn->buff_size;
	local.mem_hndl = gconn->mem_hndl;
	local.mbox_offset = cr->info.mbox_offset;
	local.mbox_maxcredit = cr->info.mbox_maxcredit;
	local.msg_maxsize = cr->info.msg_maxsize;

	memset(&remote, 0, sizeof(remote));
	remote.msg_type = reply.msg_type;
	remote.msg_buffer = (void *)(uintptr_t)reply.msg_buffer;
	remote.buff_size = reply.buff_size;
	remote.mem_hndl = reply.mem_hndl;
	remote.mbox_offset = reply.mbox_offset;
	remote.mbox_maxcredit = reply.mbox_maxcredit;
	remote.msg_maxsize = reply.msg_maxsize;

	grc = GNI_SmsgInit(gconn->peer, &local, &remote);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	header |= (cr->len << 4);

	/* send payload */
	grc = GNI_SmsgSend(gconn->peer, &header, sizeof(header), cr->ptr, cr->len, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->active2, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

      out:
	CCI_EXIT;
	return ret;
}

#if 0
/* Recv a new connection request */
static int gni_conn_est_passive(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	//gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_conn_request_t *cr = gconn->conn_req;
	cci__evt_t *evt = NULL;
	uint32_t header;

	CCI_ENTER;

	debug(CCI_DB_CONN, "%s: conn payload from %s:%u", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	ret = recv(cr->sock, &header, sizeof(header), 0);
	if (ret != sizeof(header)) {
		/* TODO tear-down connection */
		goto out;
	}

	assert(GNI_MSG_TYPE(header) == GNI_MSG_CONN_REQUEST);

	conn->connection.attribute = (header >> 4) & 0xF;
	cr->len = (header >> 8) & 0xFFF;

	ret = recv(cr->sock, &cr->info, sizeof(cr->info), 0);
	if (ret != sizeof(cr->info)) {
		/* TODO tear-down connection */
		goto out;
	}
	ret = CCI_SUCCESS;

	if (cr->len) {
		cr->ptr = calloc(1, cr->len);
		if (!cr->ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		ret = recv(cr->sock, cr->ptr, cr->len, 0);
		if (ret != cr->len) {
			/* TODO tear-down connection */
			goto out;
		} else {
			ret = CCI_SUCCESS;
		}
	}

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		/* TODO tear-down connection */
		goto out;
	}

	evt->event.type = CCI_EVENT_CONNECT_REQUEST;
	evt->event.request.data_len = cr->len;
	*((char **)&evt->event.request.data_ptr) = cr->ptr;
	evt->event.request.attribute = conn->connection.attribute;
	evt->ep = ep;
	evt->conn = conn;

	conn->connection.max_send_size = gconn->mss;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);
out:
	if (ret) {
		debug(CCI_DB_CONN, "%s: conn payload from %s:%u failed with %s", __func__,
			inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port),
			cci_strerror(&ep->endpoint, ret));
	}
	CCI_EXIT;
	return ret;
}
#endif

static int
gni_check_active_connections(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS;
	uint32_t addr, port;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_post_state_t post_state = GNI_POST_PENDING;
	TAILQ_HEAD(active_conns, gni_conn) active;

	CCI_ENTER;

	TAILQ_INIT(&active);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->active, temp, gc) {
		grc = GNI_EpPostDataTestById(gconn->peer, gconn->conn_req->info.id, &post_state, &addr, &port);
		if (grc) {
			ret = gni_to_cci_status(grc);
			if (ret != CCI_EAGAIN) {
				debug(CCI_DB_CONN, "%s: GNI_EpPostDataTest() returned %d (%s) "
					"sending initial conn request to gni://%u:%u",
					__func__, grc, cci_strerror(&ep->endpoint, ret),
					gconn->conn_req->addr, gconn->conn_req->port);
			}
		}
		if (post_state == GNI_POST_COMPLETED) {
			/* initial connect is done */
			TAILQ_REMOVE(&gep->active, gconn, temp);
			TAILQ_INSERT_TAIL(&active, gconn, temp);
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&active)) {
		gconn = TAILQ_FIRST(&active);
		TAILQ_REMOVE(&active, gconn, temp);
		gni_conn_est_active(ep, gconn->conn);
	}

	CCI_EXIT;
	return ret;
}

static int
gni_handle_conn_request(cci__ep_t *ep, uint32_t addr, uint32_t port,
			gni_smsg_info_t *info)
{
	int ret = 0;
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL;
	gni_conn_request_t *cr = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_smsg_attr_t local, remote;
	gni_smsg_info_t reply;
	gni_post_state_t post_state = GNI_POST_PENDING;
	uint32_t a, p;

	CCI_ENTER;

	cr = calloc(1, sizeof(*cr));
	if (!cr) {
		ret = CCI_ENOMEM;
		goto out;
	}
	cr->addr = addr;
	cr->port = port;
	memcpy(&cr->info, info, sizeof(*info));

	memset(info, 0, sizeof(*info));
	grc = GNI_EpPostDataWId(gep->lep, NULL, 0, info, sizeof(*info), (uintptr_t)info);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}

	conn->priv = calloc(1, sizeof(*gconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}

	conn->connection.endpoint = &ep->endpoint;
	conn->connection.max_send_size = ep->buffer_len;

	gconn = conn->priv;
	gconn->conn = conn;
	gconn->conn_req = cr;
	TAILQ_INIT(&gconn->remotes);
	TAILQ_INIT(&gconn->rma_ops);
	gconn->state = GNI_CONN_PASSIVE;
	gconn->mss = GNI_EP_MSS;
	gni_insert_conn(conn);

	grc = GNI_EpCreate(gep->nic, gep->tx_cq, &gconn->peer);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	debug(CCI_DB_CONN, "%s: binding to %u:%u", __func__, cr->addr, cr->port);

	grc = GNI_EpBind(gconn->peer, cr->addr, cr->port);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	grc = GNI_EpSetEventData(gconn->peer, gconn->id, cr->info.id);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	memset(&remote, 0, sizeof(remote));
	remote.msg_type = cr->info.msg_type;
	remote.msg_buffer = (void *)(uintptr_t) cr->info.msg_buffer;
	remote.buff_size = cr->info.buff_size;
	remote.mem_hndl = cr->info.mem_hndl;
	remote.mbox_offset = cr->info.mbox_offset;
	remote.mbox_maxcredit = cr->info.mbox_maxcredit;
	remote.msg_maxsize = cr->info.msg_maxsize;

	memset(&local, 0, sizeof(local));
	local.mbox_maxcredit = GNI_CONN_CREDIT;
	local.msg_maxsize = GNI_EP_MSS;
	local.msg_type = remote.msg_type;

	grc = GNI_SmsgBufferSizeNeeded(&local, &gconn->buff_size);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	local.buff_size = gconn->buff_size;

	gconn->msg_buffer = calloc(1, gconn->buff_size);
	if (!gconn->msg_buffer) {
		ret = CCI_EINVAL;
		goto out;
	}
	local.msg_buffer = (void *)(uintptr_t) gconn->msg_buffer;

	grc = GNI_MemRegister(gep->nic, (uintptr_t) gconn->msg_buffer,
			gconn->buff_size, gep->rx_cq, GNI_MEM_READWRITE,
			-1, &gconn->mem_hndl);
	if (grc == -1) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	local.mem_hndl = gconn->mem_hndl;

	debug(CCI_DB_CONN, "%s: initing SMSG for %u:%u", __func__, cr->addr, cr->port);

	grc = GNI_SmsgInit(gconn->peer, &local, &remote);
	if (grc == -1) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	memset(&reply, 0, sizeof(reply));
	reply.mem_hndl = gconn->mem_hndl;
	reply.msg_buffer = (uintptr_t) gconn->msg_buffer;
	reply.msg_type = local.msg_type;
	reply.buff_size = gconn->buff_size;
	reply.mbox_offset = 0;
	reply.mbox_maxcredit = local.mbox_maxcredit;
	reply.msg_maxsize = local.msg_maxsize;
	reply.id = gconn->id;

	debug(CCI_DB_CONN, "%s: sending reply to %u:%u", __func__,
			cr->addr, cr->port);

	grc = GNI_EpPostDataWId(gconn->peer, &reply, sizeof(reply), NULL, 0, reply.id);
	if (grc == -1) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	/* poll for completion now */
	do {
		grc = GNI_EpPostDataTestById(gconn->peer, reply.id, &post_state, &a, &p);
		if (grc == -1) {
			ret = gni_to_cci_status(grc);
			goto out;
		}
	} while (post_state != GNI_POST_COMPLETED);
	assert(a == addr && p == port);

	/* queue conn until payload arrives */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->passive, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

out:
	CCI_EXIT;
	return ret;
}

static int
gni_check_for_conn_requests(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS;
	int i = 0, first = 0;
	static int last = 0;
	uint32_t addr, port;
	gni_ep_t *gep = ep->priv;

	CCI_ENTER;

	first = last + 1;
	if (first == GNI_EP_CONN_REQ_CNT)
		first = 0;

	for (i = 0; i < GNI_EP_CONN_REQ_CNT; i++) {
		gni_smsg_info_t *info = &gep->infos[i];
		gni_post_state_t post_state  = GNI_POST_PENDING;
		gni_return_t grc = GNI_RC_SUCCESS;

		last = i;
		grc = GNI_EpPostDataTestById(gep->lep, (uintptr_t)info,
				&post_state, &addr, &port);
		if (grc) {
			ret = gni_to_cci_status(grc);
			goto out;
		}
		if (post_state == GNI_POST_COMPLETED) {
			debug(CCI_DB_CONN, "%s: conn_request from %u:%u",
				__func__, addr, port);
			ret = gni_handle_conn_request(ep, addr, port, info);
		}
	}
out:
	CCI_EXIT;
	return ret;
}

#if 0
static int
gni_check_passive_connections(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	TAILQ_HEAD(passive_conns, gni_conn) passive;

	CCI_ENTER;

	TAILQ_INIT(&passive);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->passive, temp, gc) {
		{
			/* connect is done */
			TAILQ_REMOVE(&gep->passive, gconn, temp);
			TAILQ_INSERT_TAIL(&passive, gconn, temp);
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&passive)) {
		gconn = TAILQ_FIRST(&passive);
		TAILQ_REMOVE(&passive, gconn, temp);
		gni_conn_est_passive(ep, gconn->conn);
	}
out:
	CCI_EXIT;
	return ret;
}
#endif

/* Server connection done */
static int gni_handle_conn_ack(cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(&(conn->connection.endpoint), cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_conn_request_t *cr = gconn->conn_req;
	cci__evt_t *evt = NULL;

	CCI_ENTER;

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		/* TODO */
		ret = CCI_ENOMEM;
		goto out;
	}

	evt->event.type = CCI_EVENT_ACCEPT;

	evt->event.accept.status = CCI_SUCCESS;
	evt->event.accept.context = conn->connection.context;
	evt->event.accept.connection = &conn->connection;

	gconn->state = GNI_CONN_ESTABLISHED;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->passive2, gconn, temp);
	TAILQ_INSERT_TAIL(&gep->conns, gconn, entry);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "%s: conn established from %u:%u", __func__,
		cr->addr, cr->port);

	free(cr->ptr);
	free(cr);
	gconn->conn_req = NULL;

      out:
	CCI_EXIT;
	return ret;
}

static int gni_progress_connections(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	gni_ep_t *gep = ep->priv;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	if (ep->closing || !gep) {
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}
	pthread_mutex_unlock(&ep->lock);

	/* TODO needs more */
	ret = gni_check_for_conn_requests(ep);
	/* TODO error check? debug()? */
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_for_conn_requests() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	ret = gni_check_active_connections(ep);
	/* TODO error check? debug()? */
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_active_connections() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

      out:
	CCI_EXIT;
	return ret;
}

#if 0
static int gni_handle_msg(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_conn_t *gconn = NULL;
	gni_rx_t *rx = NULL;
	void *ptr = NULL;

	CCI_ENTER;

	/* find the conn for this message */
	gconn = gni_qp_num_to_conn(ep, wc.qp_num);
	if (!gconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	rx = (gni_rx_t *) (uintptr_t) wc.wr_id;
	ptr = rx->rx_pool->buf + rx->offset;

	rx->evt.conn = gconn->conn;
	rx->evt.event.type = CCI_EVENT_RECV;
	rx->evt.event.recv.connection = &gconn->conn->connection;
	*((uint32_t *) & rx->evt.event.recv.len) = wc.byte_len;
	if (rx->evt.event.recv.len)
		*((void **)&rx->evt.event.request.data_ptr) = ptr;
	else
		*((void **)&rx->evt.event.request.data_ptr) = NULL;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);
      out:
	CCI_EXIT;
	return ret;
}

static int gni_handle_rdma_msg_ack(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	int index = 0;
	uint32_t header = ntohl(wc.imm_data);
	gni_conn_t *gconn = NULL;
	gni_rx_t *rx = (gni_rx_t *) (uintptr_t) wc.wr_id;

	/* find the conn for this message */
	gconn = gni_qp_num_to_conn(ep, wc.qp_num);
	if (!gconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	index = (header >> 21) & 0xFF;
	i = (1 << index);

	pthread_mutex_lock(&ep->lock);
	gconn->avail |= i;
	pthread_mutex_unlock(&ep->lock);

      out:
	gni_post_rx(ep, rx);
	return ret;
}

static int gni_handle_rma_remote_request(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	gni_conn_t *gconn = NULL;
	gni_ep_t *gep = ep->priv;
	gni_rma_handle_t *handle = NULL;
	gni_rma_handle_t *h = NULL;
	gni_rx_t *rx = NULL;
	gni_tx_t *tx = NULL;
	void *ptr = NULL;
	uint32_t header = GNI_MSG_RMA_REMOTE_REPLY;
	uint64_t request = 0ULL;
	gni_rma_addr_rkey_t info;

	CCI_ENTER;

	rx = (gni_rx_t *) (uintptr_t) wc.wr_id;

	/* check for a valid uint64_t payload */
	if (wc.byte_len != 8) {
		ret = CCI_EMSGSIZE;
		goto out;
	}

	/* find the conn for this message */
	gconn = gni_qp_num_to_conn(ep, wc.qp_num);
	if (!gconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		ret = CCI_ERR_NOT_FOUND;
		goto out;
	}
	conn = gconn->conn;

	/* find the RMA handle */
	memcpy(&request, rx->rx_pool->buf + rx->offset, sizeof(request));
	request = gni_ntohll(request);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &gep->handles, entry) {
		if ((uintptr_t) h == request) {
			handle = h;
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	tx = gni_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->msg_type = GNI_MSG_RMA_REMOTE_REPLY;
	memset(&tx->evt, 0, sizeof(tx->evt));
	tx->evt.conn = conn;
	tx->evt.event.type = CCI_EVENT_NONE;
	if (handle) {
		info.remote_handle = gni_htonll(request);
		info.remote_addr = gni_htonll((uintptr_t) handle->mr->addr);
		info.rkey = htonl(handle->mr->rkey);
		memcpy(tx->buffer, &info, sizeof(info));
		ptr = tx->buffer;
		tx->len = sizeof(info);
		header |= (1 << 4);
	} else {
		tx->len = 0;
	}

	ret = gni_post_send(conn, tx->id, ptr, tx->len, header);
      out:
	/* repost rx */
	gni_post_rx(ep, rx);

	CCI_EXIT;
	return ret;
}

static int gni_post_rma(gni_rma_op_t * rma_op);

static int gni_handle_rma_remote_reply(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_conn_t *gconn = NULL;
	gni_ep_t *gep = ep->priv;
	gni_rx_t *rx = NULL;
	gni_rma_remote_t *remote = NULL;
	gni_rma_op_t *rma_op = NULL;
	gni_rma_op_t *r = NULL;

	CCI_ENTER;

	rx = (gni_rx_t *) (uintptr_t) wc.wr_id;

	gconn = gni_qp_num_to_conn(ep, wc.qp_num);

	if (wc.byte_len == sizeof(gni_rma_addr_rkey_t)) {
		remote = calloc(1, sizeof(*remote));
		if (!remote) {
			ret = CCI_ENOMEM;
			goto out;
		}

		memcpy(&remote->info, rx->rx_pool->buf + rx->offset,
		       sizeof(remote->info));
		remote->info.remote_handle =
		    gni_ntohll(remote->info.remote_handle);
		remote->info.remote_addr =
		    gni_ntohll(remote->info.remote_addr);
		remote->info.rkey = ntohl(remote->info.rkey);
		if (GNI_RMA_REMOTE_SIZE) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&gconn->remotes, remote, entry);
			gconn->num_remotes++;
			if (gconn->num_remotes > GNI_RMA_REMOTE_SIZE) {
				gni_rma_remote_t *last =
				    TAILQ_LAST(&gconn->remotes, s_rems);
				TAILQ_REMOVE(&gconn->remotes, last, entry);
				free(last);
			}
			pthread_mutex_unlock(&ep->lock);
		}
		/* find RMA op waiting for this remote_handle
		 * and post the RMA */
		pthread_mutex_lock(&ep->lock);
		TAILQ_FOREACH(r, &gconn->rma_ops, entry) {
			if (r->remote_handle == remote->info.remote_handle) {
				rma_op = r;
				TAILQ_REMOVE(&gconn->rma_ops, rma_op, entry);
				TAILQ_INSERT_TAIL(&gep->rma_ops, rma_op, entry);
				rma_op->remote_addr = remote->info.remote_addr;
				rma_op->rkey = remote->info.rkey;
			}
		}
		pthread_mutex_unlock(&ep->lock);
		ret = gni_post_rma(rma_op);
	}
      out:
	gni_post_rx(ep, rx);

	CCI_EXIT;
	return ret;
}

static int gni_handle_recv(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	uint32_t header = 0;
	gni_msg_type_t type = 0;

	CCI_ENTER;

	header = ntohl(wc.imm_data);
	debug(CCI_DB_INFO, "recv'd header 0x%x", header);
	type = GNI_MSG_TYPE(header);

	switch (type) {
	case GNI_MSG_CONN_PAYLOAD:
		ret = gni_handle_conn_payload(ep, wc);
		break;
	case GNI_MSG_CONN_REPLY:
		ret = gni_handle_conn_reply(ep, wc);
		break;
	case GNI_MSG_SEND:
		ret = gni_handle_msg(ep, wc);
		break;
	case GNI_MSG_RMA_REMOTE_REQUEST:
		ret = gni_handle_rma_remote_request(ep, wc);
		break;
	case GNI_MSG_RMA_REMOTE_REPLY:
		ret = gni_handle_rma_remote_reply(ep, wc);
		break;
	case GNI_MSG_RDMA_MSG_ACK:
		ret = gni_handle_rdma_msg_ack(ep, wc);
		break;
	default:
		debug(CCI_DB_INFO, "%s: ignoring %s msg",
		      __func__, gni_msg_type_str(type));
		break;
	}

	CCI_EXIT;
	return ret;
}

static int gni_complete_send_msg(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_tx_t *tx = (gni_tx_t *) (uintptr_t) wc.wr_id;

	CCI_ENTER;

	tx->evt.event.send.status = gni_to_cci_status(wc.status);
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return ret;
}

static int gni_complete_send(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_msg_type_t type = GNI_MSG_INVALID;
	gni_tx_t *tx = (gni_tx_t *) (uintptr_t) wc.wr_id;
	gni_ep_t *gep = ep->priv;

	CCI_ENTER;

	if (tx)
		type = tx->msg_type;

	switch (type) {
	case GNI_MSG_SEND:
		ret = gni_complete_send_msg(ep, wc);
		break;
	case GNI_MSG_CONN_REQUEST:
	case GNI_MSG_CONN_PAYLOAD:
	case GNI_MSG_CONN_REPLY:
		break;
	default:
		debug(CCI_DB_MSG,
		      "%s: ignoring send completion for msg type %d", __func__,
		      type);
		break;
	}
	if (type != GNI_MSG_INVALID && type != GNI_MSG_SEND) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
		pthread_mutex_unlock(&ep->lock);
	}

	CCI_EXIT;
	return ret;
}
#endif

static int
gni_send_common(cci_connection_t * connection, struct iovec *iov,
		  uint32_t iovcnt, void *context, int flags,
		  gni_rma_op_t * rma_op);

#if 0
static int gni_handle_rma_completion(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_rma_op_t *rma_op = (gni_rma_op_t *) (uintptr_t) wc.wr_id;
	gni_ep_t *gep = ep->priv;

	CCI_ENTER;

	rma_op->status = gni_to_cci_status(wc.status);
	if (rma_op->msg_len == 0 || rma_op->status != CCI_SUCCESS) {
	      queue:
		/* we are done, queue it for the app */
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, &rma_op->evt, entry);
		pthread_mutex_unlock(&ep->lock);
	} else {
		uint32_t iovcnt = 1;
		struct iovec iov;
		cci__conn_t *conn = rma_op->evt.conn;

		iov.iov_base = rma_op->msg_ptr;
		iov.iov_len = rma_op->msg_len;
		ret = gni_send_common(&conn->connection, &iov, iovcnt,
					rma_op->context, rma_op->flags, rma_op);
		if (ret != CCI_SUCCESS) {
			rma_op->status = ret;
			goto queue;
		}
		/* we will pass the tx completion to the app,
		 * free the rma_op now */
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&gep->rma_ops, rma_op, entry);
		pthread_mutex_unlock(&ep->lock);
		free(rma_op);
	}

	CCI_EXIT;
	return ret;
}

static int gni_handle_send_completion(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	gni_tx_t *tx = (gni_tx_t *) (uintptr_t) wc.wr_id;

	CCI_ENTER;

	if (!tx)
		goto out;

	switch (tx->msg_type) {
	case GNI_MSG_CONN_PAYLOAD:
		debug(CCI_DB_CONN, "%s: send completed of conn_payload",
		      __func__);
		break;
	case GNI_MSG_CONN_REPLY:
		{
			cci__conn_t *conn = tx->evt.conn;
			gni_conn_t *gconn = conn->priv;

			if (gconn->state == GNI_CONN_CLOSED) {
				rdma_disconnect(gconn->id);
				rdma_destroy_ep(gconn->id);
				free(gconn);
				free(conn);
			} else {
				pthread_mutex_lock(&ep->lock);
				TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
				pthread_mutex_unlock(&ep->lock);
			}
		}
		break;
	case GNI_MSG_SEND:
		debug(CCI_DB_CONN, "%s: send completed", __func__);
		ret = gni_complete_send(ep, wc);
		break;
	case GNI_MSG_RMA_REMOTE_REQUEST:
	case GNI_MSG_RMA_REMOTE_REPLY:
		{
			gni_ep_t *gep = ep->priv;

			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
			pthread_mutex_unlock(&ep->lock);
		}
		break;
	default:
		debug(CCI_DB_INFO, "%s: ignoring %s msg",
		      __func__, gni_msg_type_str(tx->msg_type));
		break;
	}

      out:
	CCI_EXIT;
	return ret;
}
#endif

static int
gni_handle_recv(gni_rx_t *rx, void *msg)
{
	int ret = CCI_SUCCESS;
	uint32_t *header = (uint32_t*)msg;
	cci__ep_t *ep = rx->evt.ep;

	CCI_ENTER;

	rx->evt.event.type = CCI_EVENT_RECV;
	*((uint32_t *) & rx->evt.event.recv.len) = (*header >> 4) & 0xFFF;
	if (rx->evt.event.recv.len) {
		void *p = rx->ptr;
		void *m = msg + (uintptr_t) sizeof(*header);

		memcpy(p, m, rx->evt.event.recv.len);
		*((void **)&rx->evt.event.recv.ptr) = p;
	} else {
		*((void **)&rx->evt.event.recv.ptr) = NULL;
	}
	rx->evt.event.recv.connection = &((cci__conn_t*)(rx->evt.conn))->connection;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_MSG, "%s: recv'd 0x%x", __func__, *header);

	CCI_EXIT;
	return ret;
}

static int
gni_handle_conn_payload(gni_rx_t *rx, void *msg)
{
	int ret = CCI_SUCCESS;
	uint32_t *header = (uint32_t*)msg;
	cci__ep_t *ep = rx->evt.ep;

	CCI_ENTER;

	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	*((uint32_t *) & rx->evt.event.request.data_len) = (*header >> 4) & 0xFFF;
	if (rx->evt.event.request.data_len) {
		void *p = rx->ptr;
		void *m = msg + (uintptr_t) sizeof(*header);

		memcpy(p, m, rx->evt.event.request.data_len);
		*((void **)&rx->evt.event.request.data_ptr) = p;
	} else {
		*((void **)&rx->evt.event.request.data_ptr) = NULL;
	}
	rx->evt.event.request.attribute = (*header) & 0xF;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_MSG, "%s: recv'd conn request 0x%x", __func__, *header);

	CCI_EXIT;
	return ret;
}

static int
gni_handle_conn_reply(cci__conn_t *conn, uint32_t reply)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(&(conn->connection.endpoint), cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_conn_request_t *cr = gconn->conn_req;
	uint32_t header = GNI_MSG_CONN_ACK;
	gni_return_t grc = GNI_RC_SUCCESS;
	cci__evt_t *evt = NULL;

	CCI_ENTER;

	evt = calloc(1, sizeof(*evt));
	evt->event.type = CCI_EVENT_CONNECT;
	evt->event.connect.context = conn->connection.context;

	debug(CCI_DB_CONN, "%s: conn reply from %u:%u (%s)", __func__,
		cr->addr, cr->port, reply & 0x10 ? "success" : "reject");

	if (reply & 0x10) {
		evt->event.connect.status = CCI_SUCCESS;
		evt->event.connect.connection = &conn->connection;

		evt->conn = conn;
		evt->ep = ep;

		gconn->state = GNI_CONN_ESTABLISHED;

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&gep->conns, gconn, entry);
		pthread_mutex_unlock(&ep->lock);
	} else {
		evt->event.connect.status = CCI_ECONNREFUSED;
		gconn->state = GNI_CONN_CLOSING;
	}

	grc = GNI_SmsgSend(gconn->peer, &header, sizeof(header), NULL, 0, 0);
	if (grc) {
		ret = gni_to_cci_status(grc);
	}

	free(cr->ptr);
	free(cr);
	gconn->conn_req = NULL;

	if (gconn->state == GNI_CONN_CLOSING) {
		/* TODO more cleanup */
		grc = GNI_MemDeregister(gep->nic, &gconn->mem_hndl);
		/* TODO check */
		free(gconn->msg_buffer);
		free(gconn);
		free(conn);
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	if (ret) {
		debug(CCI_DB_CONN, "%s: failed with %s", __func__,
			cci_strerror(&ep->endpoint, ret));
	}
	CCI_EXIT;
	return ret;
}

static gni_rx_t *gni_get_rx_locked(gni_ep_t * gep)
{
	gni_rx_t *rx = NULL;
	gni_rx_pool_t *pool = TAILQ_FIRST(&gep->rx_pools);

	if (!TAILQ_EMPTY(&pool->idle_rxs)) {
		rx = TAILQ_FIRST(&pool->idle_rxs);
		TAILQ_REMOVE(&pool->idle_rxs, rx, entry);
	}
	return rx;
}

static gni_rx_t *
gni_get_rx(cci__ep_t *ep)
{
	gni_ep_t *gep = ep->priv;
	gni_rx_t *rx = NULL;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	rx = gni_get_rx_locked(gep);
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return rx;
}

static void
gni_put_rx(gni_rx_t *rx)
{
	cci__ep_t *ep = rx->evt.ep;
	gni_ep_t *gep = ep->priv;
	gni_rx_pool_t *pool = NULL;

	pthread_mutex_lock(&ep->lock);
	pool = TAILQ_FIRST(&gep->rx_pools);
	TAILQ_INSERT_HEAD(&pool->idle_rxs, rx, idle);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static int gni_get_recv_event(cci__ep_t * ep)
{
	int ret = CCI_SUCCESS;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_cq_entry_t gevt;
	gni_rx_t *rx = NULL;

	CCI_ENTER;

	/* Get an rx first. If none available, do _not_
	 * call GNI_CqGetEvent() since we will not
	 * be able to process it.
	 */
	/* TODO get rx */
	rx = gni_get_rx(ep);
	if (!rx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	grc = GNI_CqGetEvent(gep->rx_cq, &gevt);
	if (grc == GNI_RC_SUCCESS) {
		uint32_t id = GNI_CQ_GET_INST_ID(gevt);
		cci__conn_t *conn = NULL;
		gni_conn_t *gconn = NULL;
		void *msg = NULL;
		uint32_t header = 0;
		gni_msg_type_t msg_type;

		debug(CCI_DB_MSG, "%s: recv'd rx completion on conn %u",
			__func__, id);

		/* lookup conn from id */
		ret = gni_find_conn(ep, id, &conn);
		if (ret != CCI_SUCCESS) {
			/* TODO */
			goto out;
		}
		gconn = conn->priv;

		debug(CCI_DB_MSG, "%s: recv'd rx completion from %s:%u",
			__func__, inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

		grc = GNI_SmsgGetNext(gconn->peer, &msg);
		if (grc != GNI_RC_SUCCESS) {
			ret = gni_to_cci_status(grc);
			goto out;
		}
		memcpy(&header, msg, sizeof(header));

		msg_type = GNI_MSG_TYPE(header);
		switch (msg_type) {
		case GNI_MSG_SEND:
			rx->evt.conn = conn;
			ret = gni_handle_recv(rx, msg);
		case GNI_MSG_CONN_PAYLOAD:
			rx->evt.conn = conn;
			ret = gni_handle_conn_payload(rx, msg);
		case GNI_MSG_CONN_REPLY:
			gni_put_rx(rx);
			ret = gni_handle_conn_reply(conn, *((uint32_t*)msg));
		case GNI_MSG_CONN_ACK:
			gni_put_rx(rx);
			ret = gni_handle_conn_ack(conn);
		default:
			debug(CCI_DB_MSG, "%s: ignoring incoming %s",
				__func__, gni_msg_type_str(msg_type));
			break;
		}
#if 0
		rx->evt.ep = ep;
		rx->evt.conn = conn;
		rx->evt.event.type = CCI_EVENT_RECV;
		rx->evt.event.recv.ptr = NULL; /* FIXME */
		rx->evt.event.recv.len = 0; /* FIXME */
#endif
	} else if (grc == GNI_RC_NOT_DONE) {
		ret = CCI_EAGAIN;
	} else {
		ret = gni_to_cci_status(grc);
	}

out:
	if (ret != CCI_SUCCESS) {
		if (rx) {
			/* TODO queue rx */
			gni_put_rx(rx);
		}
	}
	CCI_EXIT;
	return ret;
}

static int gni_get_send_event(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_cq_entry_t gevt;

	CCI_ENTER;

	grc = GNI_CqGetEvent(gep->tx_cq, &gevt);
	if (grc == GNI_RC_SUCCESS) {
		uint32_t msg_id = GNI_CQ_GET_MSG_ID(gevt);
		//gni_tx_t *tx = NULL;
		//cci__conn_t *conn = NULL;
		//gni_conn_t *gconn = NULL;
		debug(CCI_DB_MSG, "%s: found msg_id %u", __func__, msg_id);
	} else {
		ret = gni_to_cci_status(grc);
	}

      //out:
	CCI_EXIT;
	return ret;
}

#define GNI_CONN_EVT 0
#define GNI_RECV_EVT 1
#define GNI_SEND_EVT 2
typedef enum gni_progress_event {
	GNI_PRG_EVT_CONN,
	GNI_PRG_EVT_RECV,
	GNI_PRG_EVT_SEND,
	GNI_PRG_EVT_MAX
} gni_progress_event_t;

static void gni_progress_ep(cci__ep_t * ep)
{
	int ret = CCI_SUCCESS;
	static gni_progress_event_t which = GNI_PRG_EVT_CONN;
	int try = 0;

	CCI_ENTER;

      again:
	try++;
	switch (which) {
		case GNI_PRG_EVT_CONN:
			ret = gni_progress_connections(ep);
			break;
		case GNI_PRG_EVT_RECV:
			ret = gni_get_recv_event(ep);
			break;
		case GNI_PRG_EVT_SEND:
			ret = gni_get_send_event(ep);
			break;
		default:
			debug(CCI_DB_WARN, "%s: unknown progress event type %d",
				__func__, which);
	}
	which++;
	if (which == GNI_PRG_EVT_MAX)
		which = GNI_PRG_EVT_CONN;

	if (ret == CCI_EAGAIN && try < GNI_PRG_EVT_MAX)
		goto again;

	CCI_EXIT;
	return;
}

static const char *
gni_eventstr(cci_event_t *event)
{
	char *str = NULL;

	switch (event->type) {
		case CCI_EVENT_SEND:
			str = "SEND";
			break;
		case CCI_EVENT_RECV:
			str = "RECV";
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			str = "CONNECT_REQUEST";
			break;
		case CCI_EVENT_ACCEPT:
			str = "ACCEPT";
			break;
		case CCI_EVENT_CONNECT:
			str = "CONNECT";
			break;
		default:
			str = "OTHER";
	}

	return str;
}

static int
gni_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__evt_t *e = NULL;
	cci__evt_t *ev = NULL;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_progress_ep(ep);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(e, &ep->evts, entry) {
		if (e->event.type == CCI_EVENT_SEND) {
			/* NOTE: if it is blocking, skip it since sendv()
			 *       is waiting on it
			 */
			gni_tx_t *tx = container_of(e, gni_tx_t, evt);
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

	if (ret == CCI_SUCCESS)
		debug(CCI_DB_INFO, "%s: got %s event", __func__,
			gni_eventstr(*event));

	CCI_EXIT;
	return ret;
}

static int gni_return_event(cci_event_t * event)
{
	int ret = CCI_SUCCESS;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);

	CCI_ENTER;

	switch (event->type) {
	case CCI_EVENT_CONNECT:
	case CCI_EVENT_ACCEPT:
	case CCI_EVENT_CONNECT_REQUEST:
		debug(CCI_DB_CONN,"%s: freed %s event", __func__,
			event->type == CCI_EVENT_CONNECT ? "connect" :
			event->type == CCI_EVENT_ACCEPT ? "accept" :
			"connect_request");
		free(evt);
		break;
	case CCI_EVENT_RECV:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			cci__ep_t *ep = evt->ep;
			gni_rx_t *rx = container_of(evt, gni_rx_t, evt);

			if (rx->rx_pool) {
				ret = gni_post_rx(ep, rx);
				if (ret) {
					ret = errno;
					debug(CCI_DB_MSG,
					      "%s: post_rx() returned %s",
					      __func__, strerror(ret));
				}
			}
		}
		break;
	case CCI_EVENT_SEND:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			cci__ep_t *ep = evt->ep;
			gni_ep_t *gep = ep->priv;
			gni_tx_t *tx = NULL;

			if (evt->priv) {
				gni_rma_op_t *rma_op = evt->priv;

				pthread_mutex_lock(&ep->lock);
				TAILQ_REMOVE(&gep->rma_ops, rma_op, entry);
				pthread_mutex_unlock(&ep->lock);
				free(rma_op);
			} else {
				tx = container_of(evt, gni_tx_t, evt);
				pthread_mutex_lock(&ep->lock);
				TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
				pthread_mutex_unlock(&ep->lock);
			}
		}
		break;
	default:
		debug(CCI_DB_WARN, "%s: ignoring %d event",
		      __func__, event->type);
		break;
	}

	CCI_EXIT;
	return ret;
}

static int
gni_send_common(cci_connection_t * connection, struct iovec *iov,
		  uint32_t iovcnt, void *context, int flags,
		  gni_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	int is_reliable = 0;
	uint32_t len = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;
	gni_ep_t *gep = NULL;
	//gni_conn_t *gconn = NULL;
	gni_tx_t *tx = NULL;
	uint32_t header = GNI_MSG_SEND;
	void *ptr = NULL;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	for (i = 0; i < iovcnt; i++)
		len += (uint32_t) iov[i].iov_len;

	if (len > connection->max_send_size) {
		debug(CCI_DB_MSG, "length %u > connection->max_send_size %u",
		      len, connection->max_send_size);
		CCI_EXIT;
		return CCI_EMSGSIZE;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	gep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);
	//gconn = conn->priv;

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	tx = gni_get_tx(ep);
	if (!tx) {
		debug(CCI_DB_MSG, "%s: no txs", __func__);
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	/* tx bookkeeping */
	tx->msg_type = GNI_MSG_SEND;
	tx->flags = flags;
	tx->rma_op = rma_op;	/* only set if RMA completion msg */

	/* setup generic CCI event */
	tx->evt.conn = conn;
	tx->evt.ep = ep;
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = context;
	tx->evt.event.send.status = CCI_SUCCESS;	/* for now */

	/* always copy into tx's buffer */
	if (len) {
		if (iovcnt > 1) {
			uint32_t offset = 0;

			ptr = tx->buffer;
			for (i = 0; i < iovcnt; i++) {
				memcpy(ptr + offset, iov[i].iov_base,
				       iov[i].iov_len);
				offset += iov[i].iov_len;
			}
		} else if (iovcnt == 1) {
			ptr = iov[0].iov_base;
		}
	}
	tx->len = len;

	ret = gni_post_send(conn, tx->id, ptr, tx->len, header);
	if (ret) {
		debug(CCI_DB_CONN, "%s: unable to send", __func__);
		goto out;
	}

	if (flags & CCI_FLAG_BLOCKING && is_reliable) {
		cci__evt_t *e, *evt = NULL;
		do {
			pthread_mutex_lock(&ep->lock);
			TAILQ_FOREACH(e, &ep->evts, entry) {
				if (&tx->evt == e) {
					evt = e;
					TAILQ_REMOVE(&ep->evts, evt, entry);
					ret = evt->event.send.status;
				}
			}
			pthread_mutex_unlock(&ep->lock);
		} while (evt == NULL);
		/* if successful, queue the tx now,
		 * if not, queue it below */
		if (ret == CCI_SUCCESS) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
			pthread_mutex_unlock(&ep->lock);
		}
	}

      out:
	if (ret) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
		pthread_mutex_unlock(&ep->lock);
	}
	CCI_EXIT;
	return ret;
}

static int gni_send(cci_connection_t * connection,	/* magic number */
		      void *msg_ptr, uint32_t msg_len, void *context, int flags)
{
	int ret = CCI_SUCCESS;
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	CCI_ENTER;

	if (msg_ptr && msg_len > 0) {
		iovcnt = 1;
		iov.iov_base = msg_ptr;
		iov.iov_len = msg_len;
	}

	ret = gni_send_common(connection, &iov, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
gni_sendv(cci_connection_t * connection,
	    struct iovec *data, uint32_t iovcnt, void *context, int flags)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	ret = gni_send_common(connection, data, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
gni_rma_register(cci_endpoint_t * endpoint,
		   cci_connection_t * connection,
		   void *start, uint64_t length, uint64_t * rma_handle)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_rma_handle_t *handle = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		debug(CCI_DB_INFO, "no memory for rma handle");
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	handle->ep = ep;

	grc = GNI_MemRegister(gep->nic, (uint64_t)(uintptr_t)start,
		length, NULL, GNI_MEM_READWRITE, -1, &handle->mh);
	if (grc != GNI_RC_SUCCESS) {
		free(handle);
		ret = gni_to_cci_status(grc);
		goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = (uint64_t) (uintptr_t) handle;

out:
	CCI_EXIT;
	return ret;
}

static int gni_rma_deregister(uint64_t rma_handle)
{
	int ret = CCI_SUCCESS;
	gni_rma_handle_t *handle =
	    (gni_rma_handle_t *) (uintptr_t) rma_handle;
	cci__ep_t *ep = handle->ep;
	gni_ep_t *gep = ep->priv;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	grc = GNI_MemDeregister(gep->nic, &handle->mh);
	if (grc != GNI_RC_SUCCESS) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_WARN, "%s: GNI_MemDeregister() returned %s (%d)",
		      __func__, cci_strerror(&ep->endpoint, ret), grc);
	}

	free(handle);

	CCI_EXIT;
	return ret;
}

static int
gni_conn_get_remote(gni_rma_op_t * rma_op, uint64_t remote_handle)
{
	int ret = CCI_ERR_NOT_FOUND;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = rma_op->evt.conn;
	gni_conn_t *gconn = conn->priv;
	gni_rma_remote_t *rem = NULL;

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(rem, &gconn->remotes, entry) {
		if (rem->info.remote_handle == remote_handle) {
			rma_op->remote_addr = rem->info.remote_addr;
			rma_op->remote_mem_hndl = rem->info.remote_mem_hndl;
			ret = CCI_SUCCESS;
			/* keep list in LRU order */
			if (TAILQ_FIRST(&gconn->remotes) != rem) {
				TAILQ_REMOVE(&gconn->remotes, rem, entry);
				TAILQ_INSERT_HEAD(&gconn->remotes, rem, entry);
			}
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return ret;
}

static int
gni_conn_request_rma_remote(gni_rma_op_t * rma_op, uint64_t remote_handle)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = rma_op->evt.conn;
	gni_tx_t *tx = NULL;
	gni_ep_t *gep = NULL;
	gni_conn_t *gconn = conn->priv;
	uint64_t header = GNI_MSG_RMA_REMOTE_REQUEST;
	uint64_t handle = gni_htonll(remote_handle);

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	gep = ep->priv;

	tx = gni_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	/* tx bookkeeping */
	tx->msg_type = GNI_MSG_RMA_REMOTE_REQUEST;
	tx->flags = 0;
	tx->rma_op = rma_op;
	tx->len = sizeof(remote_handle);

	memset(&tx->evt, 0, sizeof(cci__evt_t));
	tx->evt.conn = conn;

	/* in network byte order */
	memcpy(tx->buffer, &handle, tx->len);

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->rma_ops, rma_op, entry);
	TAILQ_INSERT_TAIL(&gconn->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	ret =
	    gni_post_send(conn, tx->id, tx->buffer, tx->len, header);

	CCI_EXIT;
	return ret;
}

static int gni_post_rma(gni_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
#if 0
	cci__conn_t *conn = rma_op->evt.conn;
	gni_conn_t *gconn = conn->priv;
	gni_rma_handle_t *local =
	    (gni_rma_handle_t *) (uintptr_t) rma_op->local_handle;
	struct ibv_sge list;
	struct ibv_send_wr wr, *bad_wr;
#endif

	CCI_ENTER;

#if 0
	memset(&list, 0, sizeof(list));
	list.addr =
	    (uintptr_t) local->mr->addr + (uintptr_t) rma_op->local_offset;
	list.length = rma_op->len;
	list.lkey = local->mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (uintptr_t) rma_op;
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode =
	    rma_op->
	    flags & CCI_FLAG_WRITE ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
	wr.send_flags = IBV_SEND_SIGNALED;
	if ((rma_op->flags & CCI_FLAG_WRITE)
	    && (rma_op->len && (rma_op->len <= gconn->inline_size)))
		wr.send_flags |= IBV_SEND_INLINE;
	if (rma_op->flags & CCI_FLAG_FENCE)
		wr.send_flags |= IBV_SEND_FENCE;
	wr.wr.rdma.remote_addr = rma_op->remote_addr;
	wr.wr.rdma.rkey = rma_op->rkey;

	ret = ibv_post_send(gconn->id->qp, &wr, &bad_wr);
	if (ret == -1)
		ret = errno;
#endif

	CCI_EXIT;
	return ret;
}

static int
gni_rma(cci_connection_t * connection,
	  void *msg_ptr, uint32_t msg_len,
	  uint64_t local_handle, uint64_t local_offset,
	  uint64_t remote_handle, uint64_t remote_offset,
	  uint64_t data_len, void *context, int flags)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = NULL;
	gni_rma_handle_t *local =
	    (gni_rma_handle_t *) (uintptr_t) local_handle;
	gni_rma_op_t *rma_op = NULL;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	gep = ep->priv;

	if (!local || local->ep != ep) {
		CCI_EXIT;
		return CCI_EINVAL;
	}

	rma_op = calloc(1, sizeof(*rma_op));
	if (!rma_op) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	rma_op->msg_type = GNI_MSG_RMA;
	rma_op->local_handle = local_handle;
	rma_op->local_offset = local_offset;
	rma_op->remote_handle = remote_handle;
	rma_op->remote_offset = remote_offset;
	rma_op->len = data_len;
	rma_op->context = context;
	rma_op->flags = flags;
	rma_op->msg_len = msg_len;
	rma_op->msg_ptr = msg_ptr;

	rma_op->evt.event.type = CCI_EVENT_SEND;
	rma_op->evt.event.send.connection = connection;
	rma_op->evt.event.send.context = context;
	rma_op->evt.event.send.status = CCI_SUCCESS;	/* for now */
	rma_op->evt.ep = ep;
	rma_op->evt.conn = conn;
	rma_op->evt.priv = rma_op;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	/* Do we have this remote handle info?
	 * If not, request it from the peer */
	ret = gni_conn_get_remote(rma_op, remote_handle);
	if (ret == CCI_SUCCESS)
		ret = gni_post_rma(rma_op);
	else
		ret = gni_conn_request_rma_remote(rma_op, remote_handle);
	if (ret) {
		/* FIXME clean up? */
	}

	CCI_EXIT;
	return ret;
}
