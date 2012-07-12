/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2011-2012 UT-Battelle, LLC.
 * Copyright © 2012 Inria.  All rights reserved.
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
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/ctp/ctp.h"
#include "ctp_gni.h"

volatile int gni_shut_down = 0;
gni_globals_t *gglobals = NULL;
pthread_t progress_tid;

#ifdef __GNUC__
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/*
 * Local functions
 */
static int ctp_gni_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver,
		    uint32_t flags, uint32_t * caps);
static int ctp_gni_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_gni_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_gni_create_endpoint(cci_device_t * device,
				 int flags,
				 cci_endpoint_t ** endpoint,
				 cci_os_handle_t * fd);
static int ctp_gni_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_gni_accept(cci_event_t *event, const void *context);
static int ctp_gni_reject(cci_event_t *event);
static int ctp_gni_connect(cci_endpoint_t * endpoint, const char *server_uri,
			 const void *data_ptr, uint32_t data_len,
			 cci_conn_attribute_t attribute,
			 const void *context, int flags, const struct timeval *timeout);
static int ctp_gni_disconnect(cci_connection_t * connection);
static int ctp_gni_set_opt(cci_opt_handle_t * handle,
			 cci_opt_name_t name, const void *val);
static int ctp_gni_get_opt(cci_opt_handle_t * handle,
			 cci_opt_name_t name, void *val);
static int ctp_gni_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_gni_get_event(cci_endpoint_t * endpoint,
			   cci_event_t ** const event);
static int ctp_gni_return_event(cci_event_t * event);
static int ctp_gni_send(cci_connection_t * connection,
		      const void *msg_ptr, uint32_t msg_len,
		      const void *context, int flags);
static int ctp_gni_sendv(cci_connection_t * connection,
		       const struct iovec *data, uint32_t iovcnt,
		       const void *context, int flags);
static int ctp_gni_rma_register(cci_endpoint_t * endpoint,
			    void *start, uint64_t length,
			    int flags, uint64_t * rma_handle);
static int ctp_gni_rma_deregister(cci_endpoint_t * endpoint,
			      uint64_t rma_handle);
static int ctp_gni_rma(cci_connection_t * connection,
		   const void *msg_ptr, uint32_t msg_len,
		   uint64_t local_handle, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset,
		   uint64_t data_len, const void *context, int flags);

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
cci_plugin_ctp_t cci_ctp_gni_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "gni",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 50,

	 /* Bootstrap function pointers */
	 cci_ctp_gni_post_load,
	 cci_ctp_gni_pre_unload,
	 },

	/* API function pointers */
	ctp_gni_init,
	ctp_gni_finalize,
	ctp_gni_strerror,
	ctp_gni_create_endpoint,
	ctp_gni_destroy_endpoint,
	ctp_gni_accept,
	ctp_gni_reject,
	ctp_gni_connect,
	ctp_gni_disconnect,
	ctp_gni_set_opt,
	ctp_gni_get_opt,
	ctp_gni_arm_os_handle,
	ctp_gni_get_event,
	ctp_gni_return_event,
	ctp_gni_send,
	ctp_gni_sendv,
	ctp_gni_rma_register,
	ctp_gni_rma_deregister,
	ctp_gni_rma
};

static uint64_t gni_device_rate(void)
{
	uint64_t rate = 20000000000ULL;	/* 2.5 Gbps */

	return rate;
}

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
		ret = CCI_ENODEV;
		break;
	case GNI_RC_SIZE_ERROR:
		ret = CCI_ERROR;
		break;
	case GNI_RC_TRANSACTION_ERROR:
		ret = CCI_ETIMEDOUT;
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
gni_find_gni_device_ids(int **device_ids, int count,
			struct ifaddrs **ifaddrs)
{
	int ret = CCI_SUCCESS;
	int i;
	struct ifaddrs *addrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct ifaddrs *tmp = NULL;

	CCI_ENTER;

	debug(CCI_DB_DRVR, "%s: count %d", __func__, count);

	addrs = calloc(count + 1, sizeof(*addrs));
	if (!addrs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ret = getifaddrs(&ifa);
	if (ret) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < count; i++) {
		for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
			if (tmp->ifa_addr->sa_family == AF_INET &&
			    !(tmp->ifa_flags & IFF_LOOPBACK)) {
				if (0 == strcmp("ipogif0", tmp->ifa_name)) {
					int len = sizeof(struct sockaddr);
					addrs[i].ifa_name =
					    strdup(tmp->ifa_name);
					addrs[i].ifa_flags = tmp->ifa_flags;
					addrs[i].ifa_addr = calloc(1, len);
					memcpy(addrs[i].ifa_addr, tmp->ifa_addr,
					       len);
					addrs[i].ifa_netmask = calloc(1, len);
					memcpy(addrs[i].ifa_netmask,
					       tmp->ifa_netmask, len);
					addrs[i].ifa_broadaddr = calloc(1, len);
					memcpy(addrs[i].ifa_broadaddr,
					       tmp->ifa_broadaddr, len);
					debug(CCI_DB_DRVR, "%s: device[%d] is %s",
						__func__, i, tmp->ifa_name);
					break;
				}
			}
		}
	}

	freeifaddrs(ifa);
	*ifaddrs = addrs;
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

static int ctp_gni_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver,
		    uint32_t flags, uint32_t * caps)
{
	int count = 0;
	int index = 0;
	int used[CCI_MAX_DEVICES];
	int ret = 0;
	gni_return_t grc = GNI_RC_SUCCESS;
	cci__dev_t *dev = NULL, *ndev = NULL;
	cci_device_t **devices = NULL;
	struct ifaddrs *ifaddrs = NULL;
	uint32_t cpu_id = 0;

	CCI_ENTER;

	memset(used, 0, CCI_MAX_DEVICES);

	/* init transport globals */
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

	grc = GNI_CdmGetNicAddress(0, &gglobals->phys_addr, &cpu_id);
	if (grc != GNI_RC_SUCCESS) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

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

	/* for each ifaddr, check if it is a GNI device */
	ret = gni_find_gni_device_ids(&gglobals->device_ids, count, &ifaddrs);
	if (ret) {
		/* TODO */
		ret = CCI_ENODEV;
		goto out;
	}
	gglobals->ifaddrs = ifaddrs;

	if (!globals->configfile) {
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

		cci__init_dev(dev);
		dev->plugin = plugin;
		dev->priority = plugin->base.priority;

		device = &dev->device;
		device->max_send_size = GNI_EP_MSS;
		device->transport = strdup("gni");
		device->name = strdup("ipogif0");

		device->up = 1;
		device->rate = gni_device_rate();
		device->pci.domain = -1;	/* per CCI spec */
		device->pci.bus = -1;		/* per CCI spec */
		device->pci.dev = -1;		/* per CCI spec */
		device->pci.func = -1;		/* per CCI spec */

		gdev = dev->priv;
		gdev->device_id = 0;
		gdev->ptag = GNI_DEFAULT_PTAG;
		gdev->cookie = GNI_DEFAULT_COOKIE;
		gdev->ifa = &gglobals->ifaddrs[0];

		dev->is_default = 1;
		dev->align.rma_read_local_addr = 4;
		dev->align.rma_read_remote_addr = 4;
		dev->align.rma_read_length = 4;
		cci__add_dev(dev);
		devices[gglobals->count] = device;
		gglobals->count++;

	} else
	/* find devices we own */
	TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("gni", dev->device.transport)) {
			int i = 0;
			const char * const *arg;
			const char *interface = NULL;
			char *ptag = NULL;
			char *cookie = NULL;
			struct in_addr in;
			uint16_t port = 0;
			struct cci_device *device = NULL;
			gni_dev_t *gdev = NULL;

			dev->plugin = plugin;

			in.s_addr = INADDR_ANY;

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
				if (0 == strncmp("ip=", *arg, 3)) {
					const char *ip = *arg + 3;

					ret = inet_aton(ip, &in);
					if (!ret)
						debug(CCI_DB_INFO,
						      "unable to parse %s", ip);
				} else if (0 == strncmp("port=", *arg, 5)) {
					const char *port_str = *arg + 5;

					port =
					    (uint16_t) strtoul(port_str, NULL,
							       0);
				} else if (0 == strncmp("interface=", *arg, 10)) {
					interface = (void *) *arg + 10;
				} else if (0 == strncmp("ptag=", *arg, 10)) {
					ptag = (void *) *arg + 5;
					gdev->ptag = strtoul(ptag, NULL, 0);
				} else if (0 == strncmp("cookie=", *arg, 10)) {
					cookie = (void *) *arg + 7;
					gdev->cookie = strtoul(cookie, NULL, 0);
				} else if (0 == strncmp("transport=", *arg, 7)) {
					/* do nothing */
				} else {
					debug(CCI_DB_INFO, "unknown keyword %s",
					      *arg);
				}
			}

			for (i = 0; i < count; i++) {
				struct ifaddrs *ifa = &ifaddrs[i];
				struct sockaddr_in *sin =
				    (struct sockaddr_in *)ifa->ifa_addr;
				int id = gglobals->device_ids[i];

				if (in.s_addr != INADDR_ANY) {
					if (sin->sin_addr.s_addr == in.s_addr) {
						if (used[i]) {
							debug(CCI_DB_WARN,
							      "device already assigned "
							      "%d %s %s",
							      id,
							      ifa->ifa_name,
							      inet_ntoa(sin->
									sin_addr));
							goto out;
						}
						gdev->device_id = id;
						gdev->ifa = ifa;
						used[i]++;
						break;
					}
				} else if (interface) {
					if (0 ==
					    strcmp(interface, ifa->ifa_name)) {
						debug(CCI_DB_INFO, "%s: found %s",
							__func__, interface);
						if (used[i]) {
							debug(CCI_DB_WARN,
							      "device already assigned "
							      "%d %s %s",
							      id,
							      ifa->ifa_name,
							      inet_ntoa(sin->
									sin_addr));
							goto out;
						}
						gdev->device_id = id;
						gdev->ifa = ifa;
						used[i]++;
						break;
					}
				} else {
					if (used[i]) {
						debug(CCI_DB_WARN,
						      "device already assigned "
						      "%d %s %s",
						      id,
						      ifa->ifa_name,
						      inet_ntoa(sin->sin_addr));
						goto out;
					}
					gdev->device_id = id;
					gdev->ifa = ifa;
					used[i]++;
					break;
				}
			}

			if (gdev->device_id == -1) {
				debug(CCI_DB_INFO, "%s: no device id for %d", __func__, i);
				goto out;
			}

			if (port) {
				struct sockaddr_in *sin =
				    (struct sockaddr_in *)gdev->ifa->ifa_addr;
				sin->sin_port = htons(port);
			}

			device->max_send_size = GNI_EP_MSS;
			device->rate = gni_device_rate();

			TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
			cci__add_dev(dev);
			devices[index] = device;
			index++;
			device->up = gdev->ifa->ifa_flags & IFF_UP;
			debug(CCI_DB_INFO, "%s: device[%d] is up (%s %s)", __func__,
				i, gdev->ifa->ifa_name,
				inet_ntoa(((struct sockaddr_in*)gdev->ifa->ifa_addr)->sin_addr));
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

static const char *ctp_gni_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	debug(CCI_DB_INFO, "%s: status %d", __func__, status);
	return strerror(status);
}

static int ctp_gni_finalize(cci_plugin_ctp_t * plugin)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!gglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	gni_shut_down = 1;
	/* TODO join progress thread */

	free(gglobals->device_ids);
	for (i = 0; i < gglobals->count; i++) {
		struct ifaddrs *ifa = &gglobals->ifaddrs[i];

		if (ifa) {
			free(ifa->ifa_name);
			free(ifa->ifa_addr);
			free(ifa->ifa_netmask);
			free(ifa->ifa_broadaddr);
		}
	}
	free(gglobals->ifaddrs);

	TAILQ_FOREACH(dev, &globals->devs, entry) {
		if (strcmp(dev->device.transport, "gni"))
			continue;

		if (dev->priv) {
			free(dev->priv);
			dev->priv = NULL;
		}
	}

	free(gglobals->devices);
	free((void *)gglobals);
	gglobals = NULL;

	CCI_EXIT;
	return ret;
}

static int gni_destroy_rx_pool(cci__ep_t * ep, gni_rx_pool_t * rx_pool);

static void gni_put_rx(gni_rx_t *rx);

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
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&gep->rx_pools, rx_pool, entry);
	ep->rx_buf_cnt = rx_buf_cnt;
	pthread_mutex_unlock(&ep->lock);
      out:
	if (ret && rx_pool) {
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
ctp_gni_create_endpoint(cci_device_t * device,
		      int flags,
		      cci_endpoint_t ** endpointp, cci_os_handle_t * fd)
{
	int i = 0;
	int ret = CCI_SUCCESS;
	int fflags = 0;
	int pg_sz = 0;
	char name[MAXHOSTNAMELEN + 16];	/* gni:// + host + port */
	size_t len = 0;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
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
		debug(CCI_DB_DRVR, "%s: no globals?", __func__);
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	gdev = dev->priv;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*gep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gep = ep->priv;

	TAILQ_INIT(&gep->crs);
	TAILQ_INIT(&gep->idle_crs);
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

	ep->rx_buf_cnt = GNI_EP_RX_CNT;
	ep->tx_buf_cnt = GNI_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0;	/* FIXME */

	ret = socket(PF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	gep->sock = ret;

	memcpy(&gep->sin, gdev->ifa->ifa_addr, sizeof(gep->sin));

	ret = bind(gep->sock, (struct sockaddr*)&gep->sin, sizeof(gep->sin));
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
	sprintf(name, "%s%s:%u", GNI_URI,
		inet_ntoa(gep->sin.sin_addr), port);
	ep->uri = strdup(name);

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

	/* dimension the tx CQ for MSGs and RMAs */
	grc = GNI_CqCreate(gep->nic, GNI_EP_TX_CNT * 2, 0, GNI_CQ_NOBLOCK,
			NULL, NULL, &gep->tx_cq);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	debug(CCI_DB_INFO, "%s: created tx cq %p", __func__, gep->tx_cq);

	grc = GNI_CqCreate(gep->nic, GNI_EP_RX_CNT, 0, GNI_CQ_NOBLOCK,
			NULL, NULL, &gep->rx_cq);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	debug(CCI_DB_INFO, "%s: created rx cq %p", __func__, gep->rx_cq);

	pg_sz = getpagesize();

	len = GNI_EP_TX_CNT * (dev->device.max_send_size + sizeof(uint64_t));
	ret = posix_memalign((void **)&gep->tx_buf, pg_sz, len);
	if (ret)
		goto out;
	memset(gep->tx_buf, 0, len);	/* silence valgrind */

	gep->txs = calloc(GNI_EP_TX_CNT, sizeof(*gep->txs));
	if (!gep->txs) {
		ret = CCI_SUCCESS;
		goto out;
	}

	for (i = 0; i < GNI_EP_TX_CNT; i++) {
		uintptr_t offset = i * (ep->buffer_len + sizeof(uint64_t));
		gni_tx_t *tx = &gep->txs[i];

		tx->evt.ep = ep;
		tx->buffer = gep->tx_buf + offset;
		tx->id = i;
		TAILQ_INSERT_TAIL(&gep->idle_txs, tx, entry);
	}

	ret = gni_create_rx_pool(ep, ep->rx_buf_cnt);
	if (ret)
		goto out;

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

		free(gep->txs);

		free(gep->tx_buf);

		if (gep->tx_cq) {
			grc = GNI_CqDestroy(gep->tx_cq);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint tx_cq "
				      "failed with %s\n", strerror(gni_to_cci_status(grc)));
		}

		if (gep->rx_cq) {
			grc = GNI_CqDestroy(gep->rx_cq);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint rx_cq "
				      "failed with %s\n", strerror(gni_to_cci_status(grc)));
		}

		if (gep->cdm) {
			grc = GNI_CdmDestroy(gep->cdm);
			if (grc)
				debug(CCI_DB_WARN, "destroying new endpoint cdm "
				      "failed with %s\n", strerror(gni_to_cci_status(grc)));
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

	CCI_ENTER;

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

static int ctp_gni_destroy_endpoint(cci_endpoint_t * endpoint)
{
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	while (!TAILQ_EMPTY(&gep->conns)) {
		cci__conn_t *conn = NULL;
		gni_conn_t *gconn = NULL;

		gconn = TAILQ_FIRST(&gep->conns);
		conn = gconn->conn;
		ctp_gni_disconnect(&conn->connection);
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

	free(gep->txs);

	free(gep->tx_buf);
	free(gep);
	free((char *)ep->uri);

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

static inline void
gni_flush_conn_pending(cci__conn_t *conn, gni_tx_t *tx)
{
	gni_return_t grc;
	cci_endpoint_t *endpoint = conn->connection.endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_conn_t *gconn = conn->priv;
	gni_tx_t *next = NULL;

	pthread_mutex_lock(&ep->lock);
	if (tx)
		TAILQ_INSERT_TAIL(&gconn->pending, tx, entry);
	do {
		next = TAILQ_FIRST(&gconn->pending);
		if (next) {
			grc = GNI_SmsgSend(gconn->peer, &next->header,
					sizeof(next->header), next->buffer,
					next->len, next->id);
			if (likely(grc == GNI_RC_SUCCESS)) {
				TAILQ_REMOVE(&gconn->pending, next, entry);
			}
		} else {
			grc = GNI_RC_NOT_DONE;
		}
	} while (grc == GNI_RC_SUCCESS);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static int
gni_post_send(gni_tx_t *tx)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = tx->evt.conn;

	CCI_ENTER;

	assert((tx->len >> 12) == 0);
	tx->header |= (tx->len << 4);

	gni_flush_conn_pending(conn, tx);

	CCI_EXIT;
	return ret;
}

static int ctp_gni_accept(cci_event_t *event, const void *context)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	gni_ep_t *gep = NULL;
	gni_conn_t *gconn = NULL;
	gni_new_conn_t *new = NULL;
	gni_smsg_attr_t local, remote;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_conn_request_t reply;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	gep = ep->priv;

	conn = evt->conn;
	gconn = conn->priv;
	new = gconn->new;

	memcpy(&remote, &new->cr.attr, sizeof(new->cr.attr));

	memset(&reply, 0, sizeof(reply));
	reply.type = (1 << 4) | GNI_MSG_CONN_REPLY;
	reply.addr = gglobals->phys_addr;
	reply.port = ntohs(gep->sin.sin_port);
	reply.id = gconn->id;

	gconn->state = GNI_CONN_PASSIVE2;
	conn->connection.context = (void *) context;

	debug(CCI_DB_INFO, "%s: creating GNI ep with tx cq %p", __func__, gep->tx_cq);
	grc = GNI_EpCreate(gep->nic, gep->tx_cq, &gconn->peer);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	grc = GNI_EpBind(gconn->peer, new->cr.addr, new->cr.port);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	debug(CCI_DB_CONN, "%s: set event %u %u", __func__, gconn->id, new->cr.id);
	grc = GNI_EpSetEventData(gconn->peer, gconn->id, new->cr.id);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	memset(&local, 0, sizeof(local));
	local.mbox_offset = 0;
	local.mbox_maxcredit = GNI_CONN_CREDIT;
	local.msg_maxsize = GNI_EP_MSS + sizeof(uint64_t);
	local.msg_type = new->cr.attr.msg_type;

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
	local.msg_buffer = gconn->msg_buffer;

	grc = GNI_MemRegister(gep->nic, (uintptr_t) gconn->msg_buffer,
			gconn->buff_size, gep->rx_cq,
			GNI_MEM_RELAXED_PI_ORDERING | GNI_MEM_READWRITE,
			-1, &gconn->mem_hndl);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}
	local.mem_hndl = gconn->mem_hndl;

	memcpy(&reply.attr, &local, sizeof(local));

	grc = GNI_SmsgInit(gconn->peer, &local, &remote);
	if (grc == -1) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	debug(CCI_DB_CONN, "%s: sending conn reply to %s:%u", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	/* wait for client ack */
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->passive2, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

	ret = send(new->sock, &reply, sizeof(reply), 0);
	if (ret != sizeof(reply)) {
		goto out;
	} else {
		ret = CCI_SUCCESS;
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

static int ctp_gni_reject(cci_event_t *event)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	gni_conn_t *gconn = NULL;
	gni_new_conn_t *new = NULL;
	uint32_t header = GNI_MSG_CONN_REPLY;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);

	conn = evt->conn;
	gconn = conn->priv;
	new = gconn->new;

	gconn->state = GNI_CONN_CLOSING;

	ret = send(new->sock, &header, sizeof(header), 0);
	if (ret != sizeof(header)) {
		ret = CCI_ENOBUFS;
		/* TODO try again */
	} else {
		ret = CCI_SUCCESS;
	}

	/* TODO handle error
	 *      queue to wait for ack?
	 */

	/* wait for CONN_ACK to arrive before destorying the conn */

	CCI_EXIT;
	return ret;
}

static int gni_parse_uri(const char *uri, char **node, char **service)
{
	int ret = CCI_SUCCESS;
	int len = strlen(GNI_URI);
	char *ip = NULL;
	char *port = NULL;
	char *colon = NULL;

	CCI_ENTER;

	if (0 == strncmp(GNI_URI, uri, len)) {
		ip = strdup(&uri[len]);
	} else {
		ret = CCI_EINVAL;
		goto out;
	}

	colon = strchr(ip, ':');
	if (colon) {
		*colon = '\0';
	} else {
		ret = CCI_EINVAL;
		goto out;
	}

	colon++;
	port = colon;

	*node = ip;
	*service = port;

      out:
	if (ret != CCI_SUCCESS) {
		if (ip)
			free(ip);
	}
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
gni_find_conn_locked(cci__ep_t *ep, uint32_t id, cci__conn_t ** conn)
{
	int ret = CCI_ERROR;
	gni_ep_t *gep = ep->priv;
	void *node = NULL;
	uint32_t *i = NULL;

	CCI_ENTER;

	node = tfind(&id, &gep->conn_tree, gni_compare_u32);
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
	cci_endpoint_t *endpoint = conn->connection.endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__conn_t *c = NULL;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	void *node = NULL;

	CCI_ENTER;

	ret = pthread_rwlock_wrlock(&gep->conn_tree_lock);
	if (ret)
		debug(CCI_DB_WARN, "%s: wrlock() failed with %s", __func__, strerror(errno));
	do {
		id = random();
		ret = gni_find_conn_locked(ep, id, &c);
	} while (ret == CCI_SUCCESS);
	gconn->id = id;
	do {
		node = tsearch(&gconn->id, &gep->conn_tree, gni_compare_u32);
	} while (!node);
	ret = pthread_rwlock_unlock(&gep->conn_tree_lock);
	if (ret)
		debug(CCI_DB_WARN, "%s: unlock() failed with %s", __func__, strerror(errno));

	debug(CCI_DB_CONN, "%s: inserted conn %u", __func__, gconn->id);

	CCI_EXIT;
	return;
}

static int
ctp_gni_connect(cci_endpoint_t * endpoint, const char *server_uri,
	      const void *data_ptr, uint32_t data_len,
	      cci_conn_attribute_t attribute,
	      const void *context, int flags, const struct timeval *timeout)
{
	int ret = CCI_SUCCESS;
	int fflags = 0;
	char *node = NULL;
	char *service = NULL;
	struct addrinfo hints, *ai = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = NULL;
	gni_conn_t *gconn = NULL;
	gni_new_conn_t *new = NULL;
	uint16_t len = sizeof(gni_conn_request_t);
	void *ptr = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	gep = ep->priv;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->plugin = ep->plugin;
	conn->connection.max_send_size = ep->buffer_len;
	conn->connection.endpoint = endpoint;
	conn->connection.attribute = attribute;
	conn->connection.context = (void *) context;

	conn->priv = calloc(1, sizeof(*gconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gconn = conn->priv;
	gconn->conn = conn;
	gconn->max_tx_cnt = GNI_CONN_CREDIT;
	TAILQ_INIT(&gconn->remotes);
	TAILQ_INIT(&gconn->rma_ops);
	TAILQ_INIT(&gconn->pending);
	*((char **)&conn->uri) = strdup(server_uri);
	gni_insert_conn(conn);

	new = calloc(1, sizeof(*new));
	if (!new) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gconn->new = new;

	new->cr.type = (data_len << 8) | (attribute << 4) | GNI_MSG_CONN_REQUEST;
	new->cr.addr = gglobals->phys_addr;
	new->cr.port = ntohs(gep->sin.sin_port);
	new->cr.id = gconn->id;

	ret = socket(PF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	new->sock = ret;
	ret = fcntl(new->sock, F_GETFD, 0);
	if (ret == -1)
		fflags = 0;
	else
		fflags = ret;
	ret = fcntl(new->sock, F_SETFL, fflags | O_NONBLOCK);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	new->cr.attr.mbox_maxcredit = GNI_CONN_CREDIT;
	new->cr.attr.msg_maxsize = GNI_EP_MSS + sizeof(uint64_t);
	if (attribute == CCI_CONN_ATTR_RO || attribute == CCI_CONN_ATTR_RU)
			new->cr.attr.msg_type = GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
	else
			new->cr.attr.msg_type = GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
			//new->cr.attr.msg_type = GNI_SMSG_TYPE_MBOX;

	grc = GNI_SmsgBufferSizeNeeded(&new->cr.attr, &gconn->buff_size);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_CONN, "%s: GNI_SmsgBufferSizeNeeded() returned %s (%d)",
			__func__, cci_strerror(&ep->endpoint, ret), grc);
		goto out;
	}
	new->cr.attr.buff_size = gconn->buff_size;

	gconn->msg_buffer = calloc(1, gconn->buff_size);
	if (!gconn->msg_buffer) {
		ret = CCI_ENOMEM;
		goto out;
	}
	new->cr.attr.msg_buffer = gconn->msg_buffer;

	grc = GNI_MemRegister(gep->nic, (uintptr_t) gconn->msg_buffer,
			gconn->buff_size, gep->rx_cq,
			GNI_MEM_RELAXED_PI_ORDERING | GNI_MEM_READWRITE,
			-1, &gconn->mem_hndl);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_CONN, "%s: GNI_MemRegister() returned %s (%d)",
			__func__, cci_strerror(&ep->endpoint, ret), grc);
		goto out;
	}
	new->cr.attr.mem_hndl = gconn->mem_hndl;

	new->ptr = calloc(1, data_len + len);
	if (!new->ptr) {
		ret = CCI_ENOMEM;
		goto out;
	}
	new->len = len + data_len; /* conn request and payload */
	ptr = new->ptr;
	memcpy(ptr, &new->cr, sizeof(new->cr));
	ptr += (uintptr_t) sizeof(new->cr);
	if (data_len)
		memcpy(ptr, data_ptr, data_len);

	/* conn->tx_timeout = 0;  by default */

	ret = gni_parse_uri(server_uri, &node, &service);
	if (ret) {
		debug(CCI_DB_CONN, "%s: gni_parse_uri() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));
		goto out;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(node, service, &hints, &ai);
	if (ret) {
		if (ret == EAI_SYSTEM) {
			ret = errno;
			debug(CCI_DB_CONN, "getaddrinfo() returned %s",
				strerror(ret));
		} else {
			debug(CCI_DB_CONN, "getaddrinfo() returned %s",
				gai_strerror(ret));
		}
		goto out;
	}

	gconn->state = GNI_CONN_ACTIVE;
	memcpy(&gconn->sin, ai->ai_addr, sizeof(gconn->sin));

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->active, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

	ret = connect(new->sock, ai->ai_addr, ai->ai_addrlen);
	if (ret == -1) {
		ret = errno;
		if (ret != EINPROGRESS) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&gep->active, gconn, temp);
			pthread_mutex_unlock(&ep->lock);
			debug(CCI_DB_CONN, "connect() returned %s", strerror(ret));
			goto out;
		}
	}
	ret = 0;	/* when connect is done, the socket will be ready
			   for writing. When ready, send payload */

	debug(CCI_DB_CONN, "connecting to %s %s\n", node, service);

      out:
	if (ret) {
		if (new) {
			if (new->sock)
				close(new->sock);
			free(new->ptr);
		}
		free(new);
		free(gconn);
		free(conn);
	}

	if (ai)
		freeaddrinfo(ai);
	free(node);
	CCI_EXIT;
	return ret;
}

static int ctp_gni_disconnect(cci_connection_t * connection)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	gni_conn_t *gconn = conn->priv;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_return_t grc = GNI_RC_SUCCESS;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->conns, gconn, entry);
	pthread_mutex_unlock(&ep->lock);

	if (gconn->new) {
		free(gconn->new->ptr);
		if (gconn->new->sock)
			close(gconn->new->sock);
	}

	free((char *)conn->uri);

	grc = GNI_EpDestroy(gconn->peer);
	if (grc) {
		/* TODO */
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_INFO, "%s: GNI_EpDestroy() failed with %s (%d)",
				__func__, cci_strerror(&ep->endpoint, ret), grc);
	}

	grc = GNI_MemDeregister(gep->nic, &gconn->mem_hndl);
	if (grc) {
		/* TODO */
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_INFO, "%s: GNI_MemDeregister() failed with %s (%d)",
				__func__, cci_strerror(&ep->endpoint, ret), grc);
	}

	pthread_rwlock_wrlock(&gep->conn_tree_lock);
	tdelete(&gconn->id, &gep->conn_tree, gni_compare_u32);
	pthread_rwlock_unlock(&gep->conn_tree_lock);

	free(gconn->msg_buffer);

	free(gconn);
	free(conn);

	CCI_EXIT;
	return ret;
}

static int
ctp_gni_set_opt(cci_opt_handle_t * handle,
		cci_opt_name_t name, const void *val)
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

	//endpoint = handle;
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
ctp_gni_get_opt(cci_opt_handle_t * handle,
		cci_opt_name_t name, void *val)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_gni_arm_os_handle(cci_endpoint_t * endpoint, int flags)
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

/* The connect() completed. We can now send our conn_request */
static int gni_conn_est_active(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_new_conn_t *new = gconn->new;

	CCI_ENTER;

	debug(CCI_DB_CONN, "%s: sending conn payload to %s:%u", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->active2, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

	ret = send(new->sock, new->ptr, new->len, 0);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret != new->len) {
		/* truncated send? */
		/* TODO */
	} else {
		ret = CCI_SUCCESS;
	}

      out:
	CCI_EXIT;
	return ret;
}

/* Recv a new connection request */
static int gni_conn_est_passive(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	gni_conn_t *gconn = conn->priv;
	gni_new_conn_t *new = gconn->new;
	cci__evt_t *evt = NULL;

	CCI_ENTER;

	debug(CCI_DB_CONN, "%s: conn payload from %s:%u", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	ret = recv(new->sock, &new->cr, sizeof(new->cr), 0);
	if (ret != sizeof(new->cr)) {
		/* TODO tear-down connection */
		goto out;
	}
	ret = CCI_SUCCESS;

	assert(GNI_MSG_TYPE(new->cr.type) == GNI_MSG_CONN_REQUEST);

	conn->connection.attribute = (new->cr.type >> 4) & 0xF;
	new->len = (new->cr.type >> 8) & 0xFFF;

	if (new->len) {
		new->ptr = calloc(1, new->len);
		if (!new->ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		ret = recv(new->sock, new->ptr, new->len, 0);
		if (ret != new->len) {
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
	evt->event.request.data_len = new->len;
	*((char **)&evt->event.request.data_ptr) = new->ptr;
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

/* Connection done */
static int gni_handle_conn_reply(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_new_conn_t *new = gconn->new;
	uint32_t header = GNI_MSG_CONN_ACK;
	gni_smsg_attr_t local, remote;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_conn_request_t reply;
	cci__evt_t *evt = NULL;

	CCI_ENTER;

	evt = calloc(1, sizeof(*evt));
	evt->event.type = CCI_EVENT_CONNECT;
	evt->event.connect.context = (void *) conn->connection.context;

	ret = recv(new->sock, &reply, sizeof(reply), 0);
	if (ret != sizeof(reply)) {
		/* TODO */
		ret = CCI_ERROR;
		goto out;
	}
	ret = CCI_SUCCESS;
	assert(GNI_MSG_TYPE(reply.type) == GNI_MSG_CONN_REPLY);

	debug(CCI_DB_CONN, "%s: conn reply from %s:%u (%s)", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port),
		reply.type & 0x10 ? "success" : "reject");

	if (reply.type & 0x10) {
		evt->event.connect.status = CCI_SUCCESS;
		evt->event.connect.connection = &conn->connection;

		evt->conn = conn;
		evt->ep = ep;

		memset(&local, 0, sizeof(local));
		local.msg_type = new->cr.attr.msg_type;
		local.msg_buffer = gconn->msg_buffer;
		local.buff_size = gconn->buff_size;
		local.mem_hndl = gconn->mem_hndl;
		local.mbox_offset = 0;
		local.mbox_maxcredit = GNI_CONN_CREDIT;
		local.msg_maxsize = GNI_EP_MSS + sizeof(uint64_t);

		memset(&remote, 0, sizeof(remote));
		memcpy(&remote, &reply.attr, sizeof(remote));

		debug(CCI_DB_INFO, "%s: creating GNI ep with tx cq %p",
			__func__, gep->tx_cq);
		grc = GNI_EpCreate(gep->nic, gep->tx_cq, &gconn->peer);
		if (grc) {
			ret = gni_to_cci_status(grc);
			goto out;
		}

		grc = GNI_EpBind(gconn->peer, reply.addr, reply.port);
		if (grc) {
			ret = gni_to_cci_status(grc);
			debug(CCI_DB_CONN, "%s: GNI_EpBind() failed with %s",
				__func__, gni_rc_str(grc));
			goto out;
		}

		debug(CCI_DB_CONN, "%s: set event %u %u", __func__, gconn->id, reply.id);
		grc = GNI_EpSetEventData(gconn->peer, gconn->id, reply.id);
		if (grc) {
			ret = gni_to_cci_status(grc);
			goto out;
		}

		grc = GNI_SmsgInit(gconn->peer, &local, &remote);
		if (grc) {
			ret = gni_to_cci_status(grc);
			goto out;
		}

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&gep->conns, gconn, entry);
		pthread_mutex_unlock(&ep->lock);

		gconn->state = GNI_CONN_ESTABLISHED;
	} else {
		evt->event.connect.status = CCI_ECONNREFUSED;
		gconn->state = GNI_CONN_CLOSING;
	}

	ret = send(new->sock, &header, sizeof(header), 0);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret != sizeof(header)) {
		/* truncated send? */
		/* TODO */
	} else {
		ret = CCI_SUCCESS;
	}

	close(new->sock);
	free(new->ptr);
	free(new);
	gconn->new = NULL;

	if (gconn->state == GNI_CONN_CLOSING) {
		grc = GNI_MemDeregister(gep->nic, &gconn->mem_hndl);
		/* TODO check */
		free(gconn->msg_buffer);
		free(gconn);
		free(conn);
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

      out:
	if (ret) {
		debug(CCI_DB_CONN, "%s: failed with %s", __func__,
			cci_strerror(&ep->endpoint, ret));
	}
	CCI_EXIT;
	return ret;
}


static int
gni_check_active_connections(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS, nfds = 0, count = 0;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	fd_set fds;
	struct timeval tv = { 0, 0 };	/* we want to poll */
	TAILQ_HEAD(active_conns, gni_conn) active;

	CCI_ENTER;

	FD_ZERO(&fds);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(gconn, &gep->active, temp) {
		FD_SET(gconn->new->sock, &fds);
		if (gconn->new->sock >= nfds)
			nfds = gconn->new->sock + 1;
	}
	pthread_mutex_unlock(&ep->lock);

	ret = select(nfds, NULL, &fds, NULL, &tv);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret == 0) {
		goto out;
	}
	TAILQ_INIT(&active);
	count = ret;
	ret = CCI_SUCCESS;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->active, temp, gc) {
		if (FD_ISSET(gconn->new->sock, &fds)) {
			/* connect is done */
			TAILQ_REMOVE(&gep->active, gconn, temp);
			TAILQ_INSERT_TAIL(&active, gconn, temp);
			count--;
			if (count == 0)
				break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&active)) {
		gconn = TAILQ_FIRST(&active);
		TAILQ_REMOVE(&active, gconn, temp);
		gni_conn_est_active(ep, gconn->conn);
	}
out:
	CCI_EXIT;
	return ret;
}

static int
gni_check_for_conn_replies(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS, nfds = 0, count = 0;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	fd_set fds;
	struct timeval tv = { 0, 0 };	/* we want to poll */
	TAILQ_HEAD(ready_conns, gni_conn) ready;

	CCI_ENTER;

	FD_ZERO(&fds);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(gconn, &gep->active2, temp) {
		FD_SET(gconn->new->sock, &fds);
		if (gconn->new->sock >= nfds)
			nfds = gconn->new->sock + 1;
	}
	pthread_mutex_unlock(&ep->lock);

	ret = select(nfds, &fds, NULL, NULL, &tv);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret == 0) {
		goto out;
	}
	TAILQ_INIT(&ready);
	count = ret;
	ret = CCI_SUCCESS;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->active2, temp, gc) {
		if (FD_ISSET(gconn->new->sock, &fds)) {
			/* connect is done */
			TAILQ_REMOVE(&gep->active2, gconn, temp);
			TAILQ_INSERT_TAIL(&ready, gconn, temp);
			count--;
			if (count == 0)
				break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&ready)) {
		gconn = TAILQ_FIRST(&ready);
		TAILQ_REMOVE(&ready, gconn, temp);
		gni_handle_conn_reply(ep, gconn->conn);
	}
out:
	CCI_EXIT;
	return ret;
}

static int
gni_check_for_conn_requests(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS;
	int sock = 0, fflags = 0;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL;
	gni_new_conn_t *new = NULL;

	CCI_ENTER;

	ret = accept(gep->sock, (struct sockaddr*) &sin, &slen);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	sock = ret;

	debug(CCI_DB_CONN, "%s: conn_request from %s:%u", __func__,
		inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->plugin = ep->plugin;

	conn->priv = calloc(1, sizeof(*gconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}

	conn->connection.endpoint = &ep->endpoint;
	conn->connection.max_send_size = ep->buffer_len;

	gconn = conn->priv;
	gconn->conn = conn;
	gconn->max_tx_cnt = GNI_CONN_CREDIT;
	TAILQ_INIT(&gconn->remotes);
	TAILQ_INIT(&gconn->rma_ops);
	TAILQ_INIT(&gconn->pending);
	gconn->state = GNI_CONN_PASSIVE;
	memcpy(&gconn->sin, &sin, sizeof(sin));
	gconn->mss = GNI_EP_MSS;
	gni_insert_conn(conn);

	new = calloc(1, sizeof(*new));
	if (!new) {
		ret = CCI_ENOMEM;
		goto out;
	}
	gconn->new = new;
	new->sock = sock;
	ret = fcntl(new->sock, F_GETFD, 0);
	if (ret == -1)
		fflags = 0;
	else
		fflags = ret;
	ret = fcntl(new->sock, F_SETFL, fflags | O_NONBLOCK);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->passive, gconn, temp);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "incoming connection request from %s:%hu",
		inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
out:
	CCI_EXIT;
	return ret;
}

static int
gni_check_passive_connections(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS, nfds = 0, count = 0;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	fd_set fds;
	struct timeval tv = { 0, 0 };	/* we want to poll */
	TAILQ_HEAD(passive_conns, gni_conn) passive;

	CCI_ENTER;

	FD_ZERO(&fds);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(gconn, &gep->passive, temp) {
		FD_SET(gconn->new->sock, &fds);
		if (gconn->new->sock >= nfds)
			nfds = gconn->new->sock + 1;
	}
	pthread_mutex_unlock(&ep->lock);

	ret = select(nfds, &fds, NULL, NULL, &tv);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret == 0) {
		goto out;
	}
	TAILQ_INIT(&passive);
	count = ret;
	ret = CCI_SUCCESS;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->passive, temp, gc) {
		if (FD_ISSET(gconn->new->sock, &fds)) {
			/* connect is done */
			TAILQ_REMOVE(&gep->passive, gconn, temp);
			TAILQ_INSERT_TAIL(&passive, gconn, temp);
			count--;
			if (count == 0)
				break;
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

/* Server connection done */
static int gni_conn_finish(cci__ep_t * ep, cci__conn_t *conn)
{
	int ret = CCI_SUCCESS;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;
	gni_new_conn_t *new = gconn->new;
	uint32_t header;
	cci__evt_t *evt = NULL;

	CCI_ENTER;

	debug(CCI_DB_CONN, "preparing ACCEPT event from %s:%hu",
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		/* TODO */
		ret = CCI_ENOMEM;
		goto out;
	}

	evt->event.type = CCI_EVENT_ACCEPT;
	evt->ep = ep;
	evt->conn = conn;

	ret = recv(new->sock, &header, sizeof(header), 0);
	if (ret != sizeof(header)) {
		/* TODO */
		ret = CCI_ERROR;
		goto out;
	} else {
		ret = CCI_SUCCESS;
	}
	assert(GNI_MSG_TYPE(header) == GNI_MSG_CONN_ACK);
	evt->event.accept.status = CCI_SUCCESS;
	evt->event.accept.context = (void *) conn->connection.context;
	evt->event.accept.connection = &conn->connection;

	gconn->state = GNI_CONN_ESTABLISHED;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&gep->conns, gconn, entry);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_CONN, "%s: conn established from %s:%u", __func__,
		inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port));

	close(new->sock);
	free(new->ptr);
	free(new);
	gconn->new = NULL;

      out:
	CCI_EXIT;
	return ret;
}

static int
gni_check_passive2_connections(cci__ep_t *ep)
{
	int ret = CCI_SUCCESS, nfds = 0, count = 0;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL, *gc = NULL;
	fd_set fds;
	struct timeval tv = { 0, 0 };	/* we want to poll */
	TAILQ_HEAD(new_conns, gni_conn) new;

	CCI_ENTER;

	FD_ZERO(&fds);
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(gconn, &gep->passive2, temp) {
		FD_SET(gconn->new->sock, &fds);
		if (gconn->new->sock >= nfds)
			nfds = gconn->new->sock + 1;
	}
	pthread_mutex_unlock(&ep->lock);

	ret = select(nfds, &fds, NULL, NULL, &tv);
	if (ret == -1) {
		ret = errno;
		goto out;
	} else if (ret == 0) {
		goto out;
	}
	TAILQ_INIT(&new);
	count = ret;
	ret = CCI_SUCCESS;

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH_SAFE(gconn, &gep->passive2, temp, gc) {
		if (FD_ISSET(gconn->new->sock, &fds)) {
			/* connect is done */
			TAILQ_REMOVE(&gep->passive2, gconn, temp);
			TAILQ_INSERT_TAIL(&new, gconn, temp);
			count--;
			if (count == 0)
				break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	while (!TAILQ_EMPTY(&new)) {
		gconn = TAILQ_FIRST(&new);
		TAILQ_REMOVE(&new, gconn, temp);
		gni_conn_finish(ep, gconn->conn);
	}
out:
	CCI_EXIT;
	return ret;
}

static int gni_progress_connections(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	static int count = 0;

	CCI_ENTER;

	if (likely(++count != 1000000))
		return CCI_EAGAIN;
	else
		count = 0;

	ret = gni_check_for_conn_requests(ep);
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_for_conn_requests() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	ret = gni_check_passive_connections(ep);
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_passive_connections() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	ret = gni_check_passive2_connections(ep);
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_passive2_connections() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	ret = gni_check_active_connections(ep);
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_active_connections() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	ret = gni_check_for_conn_replies(ep);
	if (ret && ret != CCI_EAGAIN)
		debug(CCI_DB_CONN, "%s: gni_check_for_conn_replies() returned %s",
			__func__, cci_strerror(&ep->endpoint, ret));

	CCI_EXIT;
	return ret;
}

static int
gni_send_common(cci_connection_t * connection, const struct iovec *iov,
		  uint32_t iovcnt, const void *context, int flags,
		  gni_rma_op_t * rma_op);

static int
gni_handle_recv(gni_rx_t *rx, void *msg)
{
	int ret = CCI_SUCCESS;
	uint32_t *header = (uint32_t*)msg;
	cci__ep_t *ep = rx->evt.ep;

	CCI_ENTER;

	rx->evt.event.type = CCI_EVENT_RECV; //FIXME redundant
	rx->evt.event.recv.len = (*header >> 4) & 0xFFF;
	if (rx->evt.event.recv.len) {
		void *p = rx->ptr;
		void *m = msg + (uintptr_t) sizeof(*header);

		memcpy(p, m, rx->evt.event.recv.len);
		rx->evt.event.recv.ptr = p;
	} else {
		rx->evt.event.recv.ptr = NULL;
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
gni_handle_rma_remote_request(cci__conn_t *conn, void *msg)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_tx_t *tx = NULL;
	gni_rma_handle_t *handle = NULL;
	gni_rma_handle_t *h = NULL;
	uint32_t *header = (uint32_t *)msg;
	uint64_t *request = (uint64_t *)(msg + (uintptr_t) sizeof(*header));
	gni_rma_addr_mhndl_t info;

	CCI_ENTER;

	assert(GNI_MSG_TYPE(*header) == GNI_MSG_RMA_REMOTE_REQUEST);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &gep->handles, entry) {
		if ((uintptr_t) h == *request) {
			handle = h;
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_MSG, "%s: peer requested RMA handle 0x%"PRIx64" (%s) 0x%x",
		__func__, *request, handle ? "found" : "not found", *header);

	tx = gni_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->header = GNI_MSG_RMA_REMOTE_REPLY;
	tx->msg_type = GNI_MSG_RMA_REMOTE_REPLY;
	tx->evt.conn = conn;
	tx->evt.event.type = CCI_EVENT_NONE;
	memset(&info, 0, sizeof(info));
	info.remote_handle = *request;
	if (handle) {
		info.remote_addr = handle->addr;
		info.remote_mem_hndl = handle->mh;
		tx->header |= (1 << 16);
	}
	memcpy(tx->buffer, &info, sizeof(info));
	tx->len = sizeof(info);

	ret = gni_post_send(tx);

      out:
	CCI_EXIT;
	return ret;
}

static int gni_post_rma(gni_rma_op_t * rma_op);

static int
gni_handle_rma_remote_reply(cci__conn_t *conn, void *msg)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	gni_conn_t *gconn = conn->priv;
	gni_ep_t *gep = ep->priv;
	gni_rma_remote_t *remote = NULL;
	gni_rma_op_t *rma_op = NULL;
	gni_rma_op_t *r = NULL;
	uint32_t *header = (uint32_t *)msg;
	void *ptr = msg + sizeof(uint32_t);
	uint32_t found = (*header >> 16) & 0x1;

	CCI_ENTER;

	assert(GNI_MSG_TYPE(*header) == GNI_MSG_RMA_REMOTE_REPLY);

	if (found) {
		remote = calloc(1, sizeof(*remote));
		if (!remote) {
			ret = CCI_ENOMEM;
			goto out;
		}
		memcpy(&remote->info, ptr, sizeof(remote->info));
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
			rma_op->remote_mem_hndl = remote->info.remote_mem_hndl;
		}
	}
	pthread_mutex_unlock(&ep->lock);
	ret = gni_post_rma(rma_op);
out:
	CCI_EXIT;
	return ret;
}

static gni_rx_t *gni_get_rx_locked(gni_ep_t * gep)
{
	gni_rx_t *rx = NULL;
	gni_rx_pool_t *pool = TAILQ_FIRST(&gep->rx_pools);

	if (!TAILQ_EMPTY(&pool->idle_rxs)) {
		rx = TAILQ_FIRST(&pool->idle_rxs);
		TAILQ_REMOVE(&pool->idle_rxs, rx, idle);
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
	gni_rx_pool_t *pool = rx->rx_pool;

	pthread_mutex_lock(&ep->lock);
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

		debug(CCI_DB_MSG, "%s: recv'd rx completion on conn %u",
			__func__, id);

		/* lookup conn from id */
		ret = gni_find_conn(ep, id, &conn);
		if (ret != CCI_SUCCESS) {
			/* TODO */
			goto out;
		}
		gconn = conn->priv;

		/* this may be a credit from the peer, try to send pending msgs */
		gni_flush_conn_pending(conn, NULL);

		/* we may get 0, 1, or many SMSGs */
		do {
			void *msg = NULL;
			uint32_t *header = NULL;
			uint32_t len = 0;
			gni_msg_type_t msg_type;

			grc = GNI_SmsgGetNext(gconn->peer, &msg);
			if (grc != GNI_RC_SUCCESS) {
				ret = gni_to_cci_status(grc);
				goto out;
			}

			header = (uint32_t *)msg;
			msg_type = GNI_MSG_TYPE(*header);
			len = (*header >> 4) & 0xFFF;
			memcpy(rx->ptr, msg, sizeof(*header) + len);

			grc = GNI_SmsgRelease(gconn->peer);
			if (grc != GNI_RC_SUCCESS) {
				ret = gni_to_cci_status(grc);
				goto out;
			}

			debug(CCI_DB_MSG, "%s: recv'd rx %d completion from %s:%u (0x%x)",
				__func__, msg_type,
				inet_ntoa(gconn->sin.sin_addr), ntohs(gconn->sin.sin_port),
				*((uint32_t *)rx->ptr));

			switch (msg_type) {
			case GNI_MSG_SEND:
				rx->evt.conn = conn;
				ret = gni_handle_recv(rx, rx->ptr);
				break;
			case GNI_MSG_RMA_REMOTE_REQUEST:
				ret = gni_handle_rma_remote_request(conn, rx->ptr);
				gni_put_rx(rx);
				rx = NULL;
				break;
			case GNI_MSG_RMA_REMOTE_REPLY:
				ret = gni_handle_rma_remote_reply(conn, rx->ptr);
				gni_put_rx(rx);
				rx = NULL;
				break;
			default:
				debug(CCI_DB_MSG, "%s: ignoring incoming %s",
					__func__, gni_msg_type_str(msg_type));
				break;
			}

			rx = gni_get_rx(ep);
			if (!rx) {
				ret = CCI_ENOBUFS;
				goto out;
			}
		} while (1);
	} else if (grc == GNI_RC_NOT_DONE) {
		ret = CCI_EAGAIN;
	} else {
		ret = gni_to_cci_status(grc);
	}

out:
	if (ret != CCI_SUCCESS) {
		if (rx) {
			gni_put_rx(rx);
		}
	}

	CCI_EXIT;
	return ret;
}

static int
gni_smsg_send_completion(cci__ep_t *ep, gni_cq_entry_t gevt)
{
	int ret = CCI_SUCCESS;
	uint32_t msg_id = GNI_CQ_GET_MSG_ID(gevt);
	gni_ep_t *gep = ep->priv;
	gni_tx_t *tx = &gep->txs[msg_id];
	cci__conn_t *conn = tx->evt.conn;

	CCI_ENTER;

	debug(CCI_DB_MSG, "%s: found msg_id %u", __func__, msg_id);

	gni_flush_conn_pending(conn, NULL);

	switch (tx->msg_type) {
	case GNI_MSG_SEND:
		if (likely(!(tx->flags & CCI_FLAG_SILENT))) {
			if (!GNI_CQ_STATUS_OK(gevt)) {
				int db = CCI_DB_MSG;
				int overrun = GNI_CQ_OVERRUN(gevt);

				if (overrun)
					db |= CCI_DB_WARN;
				tx->evt.event.send.status = CCI_ERROR;
				debug(db, "%s: send completed "
					"with %"PRIu64" (overrun %s", __func__,
					GNI_CQ_GET_STATUS(gevt),
					overrun ? "yes" : "no");
			}
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
			pthread_mutex_unlock(&ep->lock);
		} else {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
			pthread_mutex_unlock(&ep->lock);
		}
		break;
	case GNI_MSG_RMA_REMOTE_REQUEST:
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
		pthread_mutex_unlock(&ep->lock);
		break;
	default:
		debug(CCI_DB_MSG, "%s: ignoring send completion for type %d",
			__func__, tx->msg_type);
	}

	CCI_EXIT;
	return ret;
}

static int
gni_rma_send_completion(cci__ep_t *ep, gni_cq_entry_t gevt)
{
	int ret = CCI_SUCCESS;
	uint32_t id = GNI_CQ_GET_INST_ID(gevt);
	cci__conn_t *conn = NULL;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = NULL;
	gni_rma_op_t *rma_op = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	gni_post_descriptor_t *pd = NULL;

	CCI_ENTER;

	grc = GNI_GetCompleted(gep->tx_cq, gevt, &pd);
	if (grc) {
		ret = gni_to_cci_status(grc);
		goto out;
	}

	rma_op = container_of(pd, gni_rma_op_t, pd);
	conn = rma_op->evt.conn;
	gconn = conn->priv;
	assert(gconn->id == id);

	rma_op->status = GNI_CQ_GET_STATUS(gevt);
	rma_op->status = gni_to_cci_status(rma_op->status);

	if (rma_op->buf) {
		if (rma_op->status == CCI_SUCCESS) {
			void *src = NULL, *dest = NULL;
			gni_rma_handle_t *local =
				(gni_rma_handle_t *) (uintptr_t) rma_op->local_handle;

			dest = (void *) (local->addr + rma_op->local_offset);
			src = rma_op->buf + (((uintptr_t) rma_op->remote_addr) & 0xC);
			memcpy(dest, src, rma_op->data_len);
		}
		grc = GNI_MemDeregister(gep->nic, &rma_op->pd.local_mem_hndl);
		if (grc) {
			debug(CCI_DB_MSG, "%s: unable to deregister bounce "
				"buffer (%s - %u)", __func__,
				cci_strerror(&ep->endpoint,
				gni_to_cci_status(grc)), grc);
		}
		free(rma_op->buf);
		rma_op->buf = NULL;
	}

	if (!rma_op->msg_ptr || rma_op->status != CCI_SUCCESS) {
	      queue:
		/* we are done, queue it for the app */
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, &rma_op->evt, entry);
		pthread_mutex_unlock(&ep->lock);
	} else {
		struct iovec iov;

		iov.iov_base = rma_op->msg_ptr;
		iov.iov_len = rma_op->msg_len;
		ret = gni_send_common(&conn->connection, &iov, 1,
				rma_op->context, rma_op->flags, rma_op);
		if (ret != CCI_SUCCESS) {
			rma_op->status = ret;
			goto queue;
		}
		/* we will pass the tx completion to the app,
		 * free the rma_op now */
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&gep->rma_ops, rma_op, entry);
		gep->rma_op_cnt--;
		pthread_mutex_unlock(&ep->lock);
		free(rma_op);
	}

out:
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
		int cq_type = (int) GNI_CQ_GET_TYPE(gevt);

		debug(CCI_DB_MSG, "%s: completing %s send", __func__,
			cq_type == (int) GNI_CQ_EVENT_TYPE_SMSG ?
			"smsg" : "post");

		switch (cq_type) {
		case GNI_CQ_EVENT_TYPE_SMSG:
			ret = gni_smsg_send_completion(ep, gevt);
			break;
		case GNI_CQ_EVENT_TYPE_POST:
			ret = gni_rma_send_completion(ep, gevt);
			break;
		default:
			debug(CCI_DB_MSG, "%s: ignoring unknown cq_type %d",
				__func__, cq_type);
		}
	} else {
		ret = gni_to_cci_status(grc);
	}

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
	gni_ep_t *gep = ep->priv;
	static gni_progress_event_t which = GNI_PRG_EVT_CONN;
	int try = 0;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	if (ep->closing || !gep) {
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}
	pthread_mutex_unlock(&ep->lock);

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

out:
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
ctp_gni_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
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

	if (ev)
		*event = &ev->event;

	if (ret == CCI_SUCCESS)
		debug(CCI_DB_MSG, "%s: got %s event", __func__,
			gni_eventstr(*event));

	CCI_EXIT;
	return ret;
}

static int ctp_gni_return_event(cci_event_t * event)
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
			gni_rx_t *rx = container_of(evt, gni_rx_t, evt);

			if (rx->rx_pool) {
				gni_put_rx(rx);
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
				gep->rma_op_cnt--;
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
gni_send_common(cci_connection_t * connection, const struct iovec *iov,
		  uint32_t iovcnt, const void *context, int flags,
		  gni_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	uint32_t len = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;
	gni_ep_t *gep = NULL;
	gni_tx_t *tx = NULL;
	void *ptr = NULL;

	CCI_ENTER;

	if (unlikely(!gglobals)) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (likely(iovcnt == 1)) {
		len = iov[0].iov_len;
	} else {
		for (i = 0; i < iovcnt; i++)
			len += (uint32_t) iov[i].iov_len;
	}

	if (unlikely(len > connection->max_send_size)) {
		debug(CCI_DB_MSG, "length %u > connection->max_send_size %u",
		      len, connection->max_send_size);
		CCI_EXIT;
		return CCI_EMSGSIZE;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	gep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);

	/* get a tx */
	tx = gni_get_tx(ep);
	if (unlikely(!tx)) {
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
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = (void *) context;
	tx->evt.event.send.status = CCI_SUCCESS;	/* for now */

	tx->header = GNI_MSG_SEND;
	if (likely(len)) {
		ptr = tx->buffer;

		if (likely(iovcnt == 1)) {
			memcpy(ptr, iov[0].iov_base, len);
		} else {
			uint32_t offset = 0;

			for (i = 0; i < iovcnt; i++) {
				memcpy(ptr + offset, iov[i].iov_base, iov[i].iov_len);
				offset += iov[i].iov_len;
			}
		}
	}
	tx->len = len;

	ret = gni_post_send(tx);
	if (ret) {
		debug(CCI_DB_CONN, "%s: unable to send", __func__);
		goto out;
	}

	if (unlikely(flags & CCI_FLAG_BLOCKING)) {
		cci__evt_t *e, *evt = NULL;

		/* FIXME invoke get_send_completion() */
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
	if (unlikely(ret)) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_HEAD(&gep->idle_txs, tx, entry);
		pthread_mutex_unlock(&ep->lock);
	}
	CCI_EXIT;
	return ret;
}

static int ctp_gni_send(cci_connection_t * connection,	/* magic number */
		      const void *msg_ptr, uint32_t msg_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS;
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	CCI_ENTER;

	if (likely(msg_ptr && msg_len > 0)) {
		iovcnt = 1;
		iov.iov_base = (void *) msg_ptr;
		iov.iov_len = msg_len;
	}

	ret = gni_send_common(connection, &iov, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
ctp_gni_sendv(cci_connection_t * connection,
	    const struct iovec *data, uint32_t iovcnt, const void *context, int flags)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	ret = gni_send_common(connection, data, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
ctp_gni_rma_register(cci_endpoint_t * endpoint,
		 void *start, uint64_t length, int flags, uint64_t * rma_handle)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	gni_ep_t *gep = ep->priv;
	gni_rma_handle_t *handle = NULL;
	gni_return_t grc = GNI_RC_SUCCESS;
	uint32_t gflags = GNI_MEM_RELAXED_PI_ORDERING;

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

	handle->addr = (uintptr_t) start;
	handle->ep = ep;

	if (!(flags & CCI_FLAG_WRITE))
		gflags |= GNI_MEM_READ_ONLY;
	else
		gflags |= GNI_MEM_READWRITE;

	grc = GNI_MemRegister(gep->nic, (uint64_t)(uintptr_t)start,
		length, NULL, gflags, -1, &handle->mh);
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

static int ctp_gni_rma_deregister(cci_endpoint_t * endpoint,
			      uint64_t rma_handle)
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

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	gep = ep->priv;

	tx = gni_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	debug(CCI_DB_MSG, "%s: requesting remote_handle 0x%"PRIx64, __func__, remote_handle);

	/* tx bookkeeping */
	tx->msg_type = GNI_MSG_RMA_REMOTE_REQUEST;
	tx->flags = 0;
	tx->rma_op = rma_op;
	tx->header = GNI_MSG_RMA_REMOTE_REQUEST;
	tx->len = sizeof(remote_handle);
	memcpy(tx->buffer, &remote_handle, tx->len);

	tx->evt.conn = conn;
	tx->evt.ep = ep;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&gep->rma_ops, rma_op, entry);
	TAILQ_INSERT_TAIL(&gconn->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = gni_post_send(tx);

	CCI_EXIT;
	return ret;
}

gni_mem_handle_t NULL_HNDL;

static int gni_post_rma(gni_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	gni_return_t grc = GNI_RC_SUCCESS;
	cci__ep_t *ep = rma_op->evt.ep;
	cci__conn_t *conn = rma_op->evt.conn;
	gni_ep_t *gep = ep->priv;
	gni_conn_t *gconn = conn->priv;

	CCI_ENTER;

	if (unlikely(rma_op->remote_addr == 0 &&
		0 == memcmp(&rma_op->remote_mem_hndl, &NULL_HNDL, sizeof(NULL_HNDL)))) {
		/* invalid remote handle, complete now */
		rma_op->status = CCI_ERR_RMA_HANDLE;
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, &rma_op->evt, entry);
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}
	rma_op->pd.remote_addr = rma_op->remote_addr + rma_op->remote_offset;
	rma_op->pd.remote_mem_hndl = rma_op->remote_mem_hndl;

	if (unlikely(rma_op->pd.type == GNI_POST_RDMA_GET &&
			((rma_op->pd.local_addr & 0x3) ||
			(rma_op->pd.remote_addr & 0x3) ||
			(rma_op->pd.length & 0x3)))) {
		/* GNI requires 4-byte aligned addresses and length
		 * for GETs. We need to alloc and register a bounce
		 * buffer and then align the addresses and/or length
		 * and RMA into the bounce buffer. When complete,
		 * copy to the user buffer and ignore the extra bytes */

		int local_addr_pad = rma_op->pd.local_addr & 0x3;
		int remote_addr_pad = rma_op->pd.remote_addr & 0x3;
		int length_pad = rma_op->pd.length & 0x3;
		uint32_t new_len = rma_op->pd.length;

		if (remote_addr_pad)
			new_len += remote_addr_pad;
		else if (local_addr_pad)
			new_len += local_addr_pad;
		else if (length_pad)
			new_len += 4 - length_pad;

		if (new_len & 0x3)
			new_len += 4 - (new_len & 0x3);

		rma_op->buf = calloc(1, new_len);
		if (!rma_op->buf) {
			rma_op->status = CCI_ENOMEM;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, &rma_op->evt, entry);
			pthread_mutex_unlock(&ep->lock);
			goto out;
		}
		rma_op->pd.length = new_len;
		grc = GNI_MemRegister(gep->nic, (uintptr_t) rma_op->buf,
			new_len, NULL, GNI_MEM_RELAXED_PI_ORDERING| GNI_MEM_READWRITE,
			-1, &rma_op->pd.local_mem_hndl);
		if (grc) {
			debug(CCI_DB_MSG, "%s: unable to register bounce buffer (%s - %u)",
				__func__,
				cci_strerror(&ep->endpoint, gni_to_cci_status(grc)),
				grc);
			rma_op->status = CCI_ENOMEM;
			free(rma_op->buf);
			rma_op->buf = NULL;
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, &rma_op->evt, entry);
			pthread_mutex_unlock(&ep->lock);
			goto out;
		}
		rma_op->pd.local_addr = (uintptr_t) rma_op->buf;
		if (remote_addr_pad)
			rma_op->pd.remote_addr -= remote_addr_pad;
		assert((rma_op->pd.local_addr & 0x3) == 0);
		assert((rma_op->pd.remote_addr & 0x3) == 0);
		assert((rma_op->pd.length & 0x3) == 0);
	}

	grc = GNI_PostRdma(gconn->peer, &rma_op->pd);
	if (grc) {
		ret = gni_to_cci_status(grc);
		debug(CCI_DB_MSG, "%s: PostRdma() failed with %s (%d) len %"PRIu64,
			__func__, cci_strerror(&ep->endpoint, grc), grc, rma_op->pd.length);
	}

out:
	CCI_EXIT;
	return ret;
}

static int
ctp_gni_rma(cci_connection_t * connection,
	  const void *msg_ptr, uint32_t msg_len,
	  uint64_t local_handle, uint64_t local_offset,
	  uint64_t remote_handle, uint64_t remote_offset,
	  uint64_t data_len, const void *context, int flags)
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

	pthread_mutex_lock(&ep->lock);
	if (gep->rma_op_cnt < GNI_EP_TX_CNT) {
		gep->rma_op_cnt++;
	} else {
		pthread_mutex_unlock(&ep->lock);
		return CCI_ENOBUFS;
	}
	pthread_mutex_unlock(&ep->lock);

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
	rma_op->data_len = data_len;
	rma_op->context = (void *) context;
	rma_op->flags = flags;
	rma_op->msg_len = msg_len;
	rma_op->msg_ptr = (void *) msg_ptr;

	rma_op->evt.event.type = CCI_EVENT_SEND;
	rma_op->evt.event.send.connection = connection;
	rma_op->evt.event.send.context = (void *) context;
	rma_op->evt.event.send.status = CCI_SUCCESS;	/* for now */
	rma_op->evt.ep = ep;
	rma_op->evt.conn = conn;
	rma_op->evt.priv = rma_op;

	rma_op->pd.type = flags & CCI_FLAG_WRITE ? GNI_POST_RDMA_PUT :
				GNI_POST_RDMA_GET;
	rma_op->pd.cq_mode = GNI_CQMODE_GLOBAL_EVENT;
	/* NOTE: always use GNI_DLVMODE_PERFORMANCE. This round-robins over
	 *       the three available DMA channels. GNI_DLVMODE_IN_ORDER
	 *       restricts the RDMA to one channel and is meant to try to
	 *       emulate IB's last byte delivered last. It has no effect on
	 *       separate RDMAs so it does not help with RO connections. */
	rma_op->pd.dlvr_mode = GNI_DLVMODE_PERFORMANCE;
	rma_op->pd.local_addr = (uintptr_t) local->addr + local_offset;
	rma_op->pd.local_mem_hndl = local->mh;
	rma_op->pd.length = data_len;
	if (flags & CCI_FLAG_FENCE)
		rma_op->pd.rdma_mode = GNI_RDMAMODE_FENCE;

	/* still need remote_addr and remote_mem_hndl */

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

		free(rma_op);

		pthread_mutex_lock(&ep->lock);
		gep->rma_op_cnt--;
		pthread_mutex_unlock(&ep->lock);
	}

	CCI_EXIT;
	return ret;
}
