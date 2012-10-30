/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011-2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2012 Oak Ridge National Labs.  All rights reserved.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <search.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "cci-api.h"
#include "ctp_verbs.h"

volatile int verbs_shut_down = 0;
volatile verbs_globals_t *vglobals = NULL;

/*
 * Local functions
 */
static int ctp_verbs_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_verbs_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_verbs_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_verbs_create_endpoint(cci_device_t * device,
				 int flags,
				 cci_endpoint_t ** endpoint,
				 cci_os_handle_t * fd);
static int ctp_verbs_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_verbs_accept(cci_event_t * event, const void *context);
static int ctp_verbs_reject(cci_event_t * event);
static int ctp_verbs_connect(cci_endpoint_t * endpoint, const char *server_uri,
			 const void *data_ptr, uint32_t data_len,
			 cci_conn_attribute_t attribute,
			 const void *context, int flags,
			 const struct timeval *timeout);
static int ctp_verbs_disconnect(cci_connection_t * connection);
static int ctp_verbs_set_opt(cci_opt_handle_t * handle,
			 cci_opt_name_t name, const void *val);
static int ctp_verbs_get_opt(cci_opt_handle_t * handle,
			 cci_opt_name_t name, void *val);
static int ctp_verbs_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_verbs_get_event(cci_endpoint_t * endpoint,
			   cci_event_t ** const event);
static int ctp_verbs_return_event(cci_event_t * event);
static int ctp_verbs_send(cci_connection_t * connection,
		      const void *msg_ptr, uint32_t msg_len,
		      const void *context, int flags);
static int ctp_verbs_sendv(cci_connection_t * connection,
		       const struct iovec *data, uint32_t iovcnt,
		       const void *context, int flags);
static int ctp_verbs_rma_register(cci_endpoint_t * endpoint,
			      void *start, uint64_t length,
			      int flags, cci_rma_handle_t ** rma_handle);
static int ctp_verbs_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle);
static int ctp_verbs_rma(cci_connection_t * connection,
		     const void *msg_ptr, uint32_t msg_len,
		     cci_rma_handle_t * local_handle, uint64_t local_offset,
		     cci_rma_handle_t * remote_handle, uint64_t remote_offset,
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
cci_plugin_ctp_t cci_ctp_verbs_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "verbs",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 50,

	 /* Bootstrap function pointers */
	 cci_ctp_verbs_post_load,
	 cci_ctp_verbs_pre_unload,
	 },

	/* API function pointers */
	ctp_verbs_init,
	ctp_verbs_finalize,
	ctp_verbs_strerror,
	ctp_verbs_create_endpoint,
	ctp_verbs_destroy_endpoint,
	ctp_verbs_accept,
	ctp_verbs_reject,
	ctp_verbs_connect,
	ctp_verbs_disconnect,
	ctp_verbs_set_opt,
	ctp_verbs_get_opt,
	ctp_verbs_arm_os_handle,
	ctp_verbs_get_event,
	ctp_verbs_return_event,
	ctp_verbs_send,
	ctp_verbs_sendv,
	ctp_verbs_rma_register,
	ctp_verbs_rma_deregister,
	ctp_verbs_rma
};

static uint32_t verbs_mtu_val(enum ibv_mtu mtu)
{
	switch (mtu) {
		/* most common first */
	case IBV_MTU_2048:
		return 2048;
	case IBV_MTU_256:
		return 256;
	case IBV_MTU_512:
		return 512;
	case IBV_MTU_1024:
		return 1024;
	case IBV_MTU_4096:
		return 4096;
	default:
		/* invalid speed */
		return 0;
	}
}

static uint64_t verbs_device_rate(struct ibv_port_attr attr)
{
	uint64_t rate;

	switch (attr.active_speed) {
	case 1:
	case 2:
	case 4:
		rate = 2000000000ULL * attr.active_speed;	/* SDR/DDR/QDR: 2.5 Gbps signal, 2 Gbps data rate, per lane */
		break;
	case 8:
		rate = 10000000000ULL;	/* FDR-10 */
		break;
	case 16:
		rate = 13636363636ULL;	/* FDR: 14.0625 Gbps signal, 64/66 encoding */
		break;
	case 32:
		rate = 25000000000ULL;	/* EDR: 25.78125 Gbps signal, 64/66 encoding */
		break;
	default:
		rate = 0;
	}

	switch (attr.active_width) {
	case 1:
		break;
	case 2:
		rate *= 4;
		break;
	case 4:
		rate *= 8;
		break;
	case 8:
		rate *= 12;
		break;
	default:
		rate = 0;
	}
	return rate;
}

static cci_status_t verbs_wc_to_cci_status(enum ibv_wc_status wc_status)
{
	int ret = CCI_SUCCESS;

	switch (wc_status) {
	case IBV_WC_SUCCESS:
		ret = CCI_SUCCESS;
		break;
	case IBV_WC_LOC_LEN_ERR:
		ret = CCI_EMSGSIZE;
		break;
	case IBV_WC_LOC_PROT_ERR:
	case IBV_WC_REM_ACCESS_ERR:
		ret = CCI_ERR_RMA_HANDLE;
		break;
	case IBV_WC_REM_INV_REQ_ERR:
	case IBV_WC_REM_OP_ERR:
		ret = CCI_ERR_RMA_OP;
		break;
	case IBV_WC_RETRY_EXC_ERR:
	case IBV_WC_RESP_TIMEOUT_ERR:
		ret = CCI_ETIMEDOUT;
		break;
	case IBV_WC_RNR_RETRY_EXC_ERR:
		ret = CCI_ERR_RNR;
		break;
	case IBV_WC_WR_FLUSH_ERR:
		ret = CCI_ERR_DISCONNECTED;
		break;
	default:
		ret = EIO;
	}

	if (wc_status)
		debug(CCI_DB_INFO, "%s: wc_status %d cci status %d (%s)",
			__func__, wc_status, ret, cci_strerror(NULL, ret));

	return ret;
}

static int
verbs_ifa_to_context(struct ibv_context *context, struct sockaddr *sa)
{
	int ret = CCI_SUCCESS;
	struct rdma_cm_id *id;
	struct rdma_event_channel *ch = NULL;

	CCI_ENTER;

	/*
	 * Old OFED version requires an event channel to be passed on
	 * to the rdma_create_id function.
	 */
	ch = rdma_create_event_channel();
	if (NULL == ch) {
		ret = errno;
		goto out;
	}

	ret = rdma_create_id(ch, &id, NULL, RDMA_PS_UDP);
	if (ret) {
		ret = errno;
		goto out;
	}

	ret = rdma_bind_addr(id, sa);
	if (ret == 0) {
		if (id->verbs != context)
			ret = -1;
	}
	rdma_destroy_id(id);

	rdma_destroy_event_channel(ch);

out:
	CCI_EXIT;
	return ret;
}

static int
verbs_find_rdma_devices(struct ibv_context **contexts, int count,
			struct ifaddrs **ifaddrs)
{
	int ret = CCI_SUCCESS;
	int i, found = 0;
	struct ifaddrs *addrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct ifaddrs *tmp = NULL;

	CCI_ENTER;

	addrs = calloc(count + 1, sizeof(*addrs));
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

	for (i = 0; i < count; i++) {
		struct ibv_context *c = contexts[i];

		for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET &&
			    !(tmp->ifa_flags & IFF_LOOPBACK)) {
				int rc = 0;

				rc = verbs_ifa_to_context(c, tmp->ifa_addr);
				if (!rc) {
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
					found++;
					break;
				}
			}
		}
	}

	freeifaddrs(ifa);
	*ifaddrs = addrs;
out:
	if (!ret && found == 0)
		ret = CCI_ENODEV;

	CCI_EXIT;
	return ret;
}

static verbs_tx_t *verbs_get_tx_locked(verbs_ep_t * vep)
{
	verbs_tx_t *tx = NULL;

	if (!TAILQ_EMPTY(&vep->tx_pool->idle_txs)) {
		tx = TAILQ_FIRST(&vep->tx_pool->idle_txs);
		TAILQ_REMOVE(&vep->tx_pool->idle_txs, tx, entry);
		vep->tx_pool->posted++;
		debug(CCI_DB_MSG, "%s: allocating a tx, posted now %d",
		      __func__, vep->tx_pool->posted);
	} else {
		debug(CCI_DB_MSG, "%s: tx queue empty, failed to allocate",
		      __func__);
	}

	return tx;
}

static verbs_tx_t *verbs_get_tx(cci__ep_t * ep)
{
	verbs_ep_t *vep = ep->priv;
	verbs_tx_t *tx = NULL;

	pthread_mutex_lock(&vep->tx_pool->lock);
	tx = verbs_get_tx_locked(vep);
	pthread_mutex_unlock(&vep->tx_pool->lock);

	return tx;
}

static int verbs_destroy_tx_pool(verbs_tx_pool_t * tx_pool);

static int verbs_return_tx(struct verbs_tx *tx)
{

	int ret = CCI_SUCCESS;

	debug(CCI_DB_MSG, "%s: returning a tx, posted now %d (to be reduced)",
	      __func__, tx->tx_pool->posted);

	pthread_mutex_lock(&tx->tx_pool->lock);
	tx->tx_pool->posted--;
	if (tx->tx_pool->repost == 1) {
		TAILQ_INSERT_HEAD(&tx->tx_pool->idle_txs, tx, entry);
		pthread_mutex_unlock(&tx->tx_pool->lock);
	} else {
		if (tx->tx_pool->posted == 0) {
			pthread_mutex_unlock(&tx->tx_pool->lock);
			ret = verbs_destroy_tx_pool(tx->tx_pool);
		} else {
			pthread_mutex_unlock(&tx->tx_pool->lock);
		}
	}

	return ret;
}

static int verbs_get_pci_info(struct cci_device * device, struct ibv_context *context)
{
#ifdef __linux__
	const char * name = ibv_get_device_name(context->device);
	char path[128];
	char buf[128], *tmp = buf;
	int err;
	unsigned domain = 0 /* not always in the bus id */, bus, dev, func;
	snprintf(path, sizeof(path), "/sys/class/infiniband/%s/device", name);
	err = readlink(path, buf, sizeof(buf));
	if (!err)
		return -1;
	/* buf contains some '../' followed by the busid followed by '/' */
	while (1) {
		if (strncmp(tmp, "../", 3))
			break;
		tmp += 3;
	}
	/* buf doesn't start with ../ anymore */
	if (sscanf(tmp, "%x:%x:%x.%x", &domain, &bus, &dev, &func) != 4
	    && sscanf(tmp, "%x:%x.%x", &bus, &dev, &func) != 3)
		return -1;
	/* got it! */
	device->pci.domain = domain;
	device->pci.bus = bus;
	device->pci.dev = dev;
	device->pci.func = func;
	return 0;
#else
	return -1;
#endif
}

static int ctp_verbs_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	char *rmsg_conns = NULL;
	int count = 0;
	int index = 0;
	int used[CCI_MAX_DEVICES];
	int ret = 0;
	cci__dev_t *dev = NULL, *ndev;
	struct cci_device **devices = NULL;
	struct ifaddrs *ifaddrs = NULL;

	CCI_ENTER;

	memset(used, 0, sizeof(int) * CCI_MAX_DEVICES);

	/* init transport globals */
	vglobals = calloc(1, sizeof(*vglobals));
	if (!vglobals) {
		ret = CCI_ENOMEM;
		goto out;
	}

	vglobals->ep_rmsg_conns = VERBS_EP_RMSG_CONNS;
	rmsg_conns = getenv("CCI_CTP_VERBS_RMSG_CONNS");
	if (rmsg_conns && rmsg_conns[0] != '\0')
		vglobals->ep_rmsg_conns = strtol(rmsg_conns, NULL, 0);

	devices = calloc(CCI_MAX_DEVICES, sizeof(*vglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	vglobals->contexts = rdma_get_devices(&count);
	if (!vglobals->contexts) {
		ret = errno;
		debug(CCI_DB_DRVR, "%s: no RDMA devices found (%s)",
				__func__, strerror(ret));
		goto out;
	}
	vglobals->count = count;

	/* for each ifaddr, check if it is a RDMA device */
	ret = verbs_find_rdma_devices(vglobals->contexts, count, &ifaddrs);
	if (ret) {
		ret = errno;
		debug(CCI_DB_DRVR, "%s: no RDMA devices with ifaddrs (%s)",
				__func__, strerror(ret));
		ret = CCI_ENODEV;
		goto out;
	}
	vglobals->ifaddrs = ifaddrs;

	if (!globals->configfile) {
		int i;
		for (i = 0; i < count; i++) {
			if (ifaddrs[i].ifa_name) {
				struct cci_device *device = NULL;
				verbs_dev_t *vdev = NULL;
				struct ibv_port_attr port_attr;

				dev = calloc(1, sizeof(*dev));
				if (!dev) {
					/* FIXME this is a bit harsh */
					ret = CCI_ENOMEM;
					goto out;
				}

				cci__init_dev(dev);
				dev->plugin = plugin;
				dev->priority = plugin->base.priority;

				device = &dev->device;

				dev->priv = calloc(1, sizeof(*vdev));
				if (!dev->priv) {
					/* FIXME this is a bit harsh */
					ret = CCI_ENOMEM;
					goto out;
				}
				vdev = dev->priv;

				vdev->context = vglobals->contexts[i];
				vdev->ifa = &ifaddrs[i];

				ret = ibv_query_port(vdev->context, 1, &port_attr);
				if (ret) {
					/* FIXME this is a bit harsh */
					ret = errno;
					goto out;
				}

				device->transport = strdup("verbs");
				device->max_send_size =
					verbs_mtu_val(port_attr.max_mtu);
				device->rate = verbs_device_rate(port_attr);
				device->name = strdup(vdev->ifa->ifa_name);
				device->up = vdev->ifa->ifa_flags & IFF_UP;
				verbs_get_pci_info(device, vdev->context);

				cci__add_dev(dev);
				devices[index] = device;
				index++;
			}
		}
	} else
	/* find devices we own */
	TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("verbs", dev->device.transport)) {
			int i = 0;
			const char * const *arg;
			const char *interface = NULL;
			struct in_addr in;
			uint16_t port = 0;
			struct cci_device *device = NULL;
			verbs_dev_t *vdev = NULL;
			struct ibv_port_attr port_attr;

			in.s_addr = INADDR_ANY;

			device = &dev->device;
			device->pci.domain = -1;	/* per CCI spec */
			device->pci.bus = -1;	/* per CCI spec */
			device->pci.dev = -1;	/* per CCI spec */
			device->pci.func = -1;	/* per CCI spec */

			dev->priv = calloc(1, sizeof(*vdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}
			dev->plugin = plugin;
			if (dev->priority == -1)
				dev->priority = plugin->base.priority;

			vdev = dev->priv;

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
					interface = *arg + 10;
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
				struct ibv_context *ctx = vglobals->contexts[i];

				if (in.s_addr != INADDR_ANY) {
					if (sin->sin_addr.s_addr == in.s_addr) {
						if (used[i]) {
							debug(CCI_DB_WARN,
							      "device already assigned "
							      "%s %s %s",
							      ctx->device->name,
							      ifa->ifa_name,
							      inet_ntoa
							      (sin->sin_addr));
							goto out;
						}
						vdev->context = ctx;
						vdev->ifa = ifa;
						used[i]++;
						break;
					}
				} else if (interface) {
					if (0 ==
					    strcmp(interface, ifa->ifa_name)) {
						if (used[i]) {
							debug(CCI_DB_WARN,
							      "device already assigned "
							      "%s %s %s",
							      ctx->device->name,
							      ifa->ifa_name,
							      inet_ntoa
							      (sin->sin_addr));
							goto out;
						}
						vdev->context = ctx;
						vdev->ifa = ifa;
						used[i]++;
						break;
					}
				} else {
					if (used[i]) {
						debug(CCI_DB_WARN,
						      "device already assigned "
						      "%s %s %s",
						      ctx->device->name,
						      ifa->ifa_name,
						      inet_ntoa(sin->sin_addr));
						goto out;
					}
					vdev->context = ctx;
					vdev->ifa = ifa;
					used[i]++;
					break;
				}
			}

			if (!vdev->context)
				goto out;

			if (port) {
				struct sockaddr_in *sin =
				    (struct sockaddr_in *)vdev->ifa->ifa_addr;
				sin->sin_port = htons(port);
			}

			ret = ibv_query_port(vdev->context, 1, &port_attr);
			if (ret) {
				ret = errno;
				goto out;
			}

			device->max_send_size =
			    verbs_mtu_val(port_attr.max_mtu);
			device->rate = verbs_device_rate(port_attr);
			device->up = vdev->ifa->ifa_flags & IFF_UP;
			verbs_get_pci_info(device, vdev->context);

			TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
			cci__add_dev(dev);
			devices[index] = device;
			index++;
		}
	}

	devices =
	    realloc(devices, (vglobals->count + 1) * sizeof(cci_device_t *));
	devices[vglobals->count] = NULL;

	vglobals->devices = devices;

	{
		struct timeval tv;
		int seed = 0;

		seed = getpid();
		seed = (seed << 16);

		gettimeofday(&tv, NULL);
		seed |= (int) tv.tv_usec; /* mix the pid into the upper bits */
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
	if (vglobals) {
		if (vglobals->contexts)
			rdma_free_devices(vglobals->contexts);
		if (vglobals->ifaddrs)
			freeifaddrs(vglobals->ifaddrs);
		free((void *)vglobals);
		vglobals = NULL;
	}

	CCI_EXIT;
	return ret;
}

static const char *ctp_verbs_strerror(cci_endpoint_t * endpoint,
				  enum cci_status status)
{
	return strerror(status);
}

static int ctp_verbs_finalize(cci_plugin_ctp_t * plugin)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	verbs_shut_down = 1;
	/* TODO join progress thread */

	for (i = 0; i < vglobals->count; i++) {
		if (vglobals->ifaddrs[i].ifa_name)
			free(vglobals->ifaddrs[i].ifa_name);
		if (vglobals->ifaddrs[i].ifa_addr)
			free(vglobals->ifaddrs[i].ifa_addr);
		if (vglobals->ifaddrs[i].ifa_netmask)
			free(vglobals->ifaddrs[i].ifa_netmask);
		if (vglobals->ifaddrs[i].ifa_broadaddr)
			free(vglobals->ifaddrs[i].ifa_broadaddr);
	}
	if (vglobals->ifaddrs)
		free(vglobals->ifaddrs);

	if (vglobals->contexts)
		rdma_free_devices(vglobals->contexts);

	TAILQ_FOREACH(dev, &globals->devs, entry)
		if (!strcmp(dev->device.transport, "verbs"))
			if (dev->priv)
				free(dev->priv);

	free(vglobals->devices);
	free((void *)vglobals);
	vglobals = NULL;

	CCI_EXIT;
	return ret;
}

static int verbs_destroy_rx_pool(cci__ep_t * ep, verbs_rx_pool_t * rx_pool);

static int verbs_post_rx(cci__ep_t * ep, verbs_rx_t * rx)
{
	int ret = CCI_SUCCESS;
	verbs_ep_t *vep = ep->priv;
	struct ibv_sge list;
	struct ibv_recv_wr wr, *bad_wr;
	verbs_rx_pool_t *rx_pool = rx->rx_pool;

	CCI_ENTER;

	if (rx_pool->repost == 0) {
		/* do not repost - see if we need to tear-down rx_pool */
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
		free(rx);
		if (TAILQ_EMPTY(&rx_pool->rxs)) {
			int rc = 0;

			TAILQ_REMOVE(&vep->rx_pools, rx_pool, entry);
			rc = verbs_destroy_rx_pool(ep, rx_pool);
			if (rc)
				debug(CCI_DB_EP, "%s: verbs_destroy_rx_pool() "
				      "returned %s", __func__,
				      cci_strerror(&ep->endpoint, rc));
		}
		pthread_mutex_unlock(&ep->lock);
		/* return SUCCESS so that the caller does not continue
		 * using the rx */
		return CCI_SUCCESS;
	}

	memset(&list, 0, sizeof(list));
	list.addr = (uintptr_t) rx_pool->buf + rx->offset;
	list.length = ep->buffer_len;
	list.lkey = rx_pool->mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (uintptr_t) rx;
	wr.sg_list = &list;
	wr.num_sge = 1;

	rx_pool->posted++;
	ret = ibv_post_srq_recv(vep->srq, &wr, &bad_wr);
	if (ret == -1) {
		ret = errno;
		rx_pool->posted--;
	}
	CCI_EXIT;
	return ret;
}

static int verbs_destroy_tx_pool(verbs_tx_pool_t * tx_pool)
{

	int ret = CCI_SUCCESS;
	uint32_t posted;
	CCI_ENTER;

	if (tx_pool == NULL) {
		goto out;
	}

	pthread_mutex_lock(&tx_pool->lock);

	tx_pool->repost = 0;

	while (!TAILQ_EMPTY(&tx_pool->idle_txs)) {
		verbs_tx_t *tx = TAILQ_FIRST(&tx_pool->idle_txs);
		TAILQ_REMOVE(&tx_pool->idle_txs, tx, entry);
		free(tx);
	}

	posted = tx_pool->posted;
	pthread_mutex_unlock(&tx_pool->lock);

	if (tx_pool->mr) {
		int rc = CCI_SUCCESS;
		rc = ibv_dereg_mr(tx_pool->mr);
		if (rc) {
			debug(CCI_DB_WARN,
			      "deregistering endpoint tx_mr "
			      "failed with %s\n", strerror(ret));
		}
	}
	if (tx_pool->buf)
		free(tx_pool->buf);

	pthread_mutex_destroy(&tx_pool->lock);

	free(tx_pool);

out:
	CCI_EXIT;
	return ret;
}

static int verbs_create_tx_pool(cci__ep_t * ep, int tx_buf_cnt)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;
	verbs_ep_t *vep = NULL;
	verbs_tx_pool_t *tx_pool = NULL;
	size_t len = 0;

	CCI_ENTER;

	dev = ep->dev;
	vep = ep->priv;

	tx_pool = calloc(1, sizeof(*tx_pool));
	if (!tx_pool) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	TAILQ_INIT(&tx_pool->idle_txs);
	tx_pool->size = tx_buf_cnt;
	tx_pool->repost = 1;
	tx_pool->posted = 0;

	len = tx_buf_cnt * dev->device.max_send_size;
	ret = posix_memalign((void **)&tx_pool->buf, getpagesize(), len);
	if (ret)
		goto out;
	memset(tx_pool->buf, 0, len);	/* silence valgrind */

	tx_pool->mr =
	    ibv_reg_mr(vep->pd, tx_pool->buf, len, IBV_ACCESS_LOCAL_WRITE);
	if (!tx_pool->mr) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < tx_buf_cnt; i++) {
		uintptr_t offset = i * ep->buffer_len;
		verbs_tx_t *tx = NULL;

		tx = calloc(1, sizeof(*tx));
		if (!tx) {
			ret = CCI_ENOMEM;
			goto out;
		}
		tx->evt.ep = ep;
		tx->buffer = tx_pool->buf + offset;
		tx->tx_pool = tx_pool;
		TAILQ_INSERT_TAIL(&tx_pool->idle_txs, tx, entry);
	}

	pthread_mutex_init(&tx_pool->lock, NULL);

	pthread_mutex_lock(&ep->lock);
	vep->tx_pool_old = vep->tx_pool;
	vep->tx_pool = tx_pool;
	ep->tx_buf_cnt = tx_buf_cnt;
	pthread_mutex_unlock(&ep->lock);

out:
	if (ret && tx_pool) {
		debug(CCI_DB_INFO,
		      "tx_pool being removed after failed return code "
		      "during create, %s\n", strerror(ret));
		int rc;
		rc = verbs_destroy_tx_pool(tx_pool);
		if (rc != CCI_SUCCESS) {
			pthread_mutex_lock(&ep->lock);
			vep->tx_pool_old = tx_pool;
			pthread_mutex_unlock(&ep->lock);
		} else {
			debug(CCI_DB_INFO,
			      "tx_pool could not be destroyed during "
			      "recovery from failed create, %s\n",
			      strerror(rc));
		}
	}
	CCI_EXIT;
	return ret;

}

static int verbs_create_rx_pool(cci__ep_t * ep, int rx_buf_cnt)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;
	verbs_ep_t *vep = NULL;
	verbs_rx_pool_t *rx_pool = NULL;
	size_t len = 0;

	CCI_ENTER;

	dev = ep->dev;
	vep = ep->priv;

	rx_pool = calloc(1, sizeof(*rx_pool));
	if (!rx_pool) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	TAILQ_INIT(&rx_pool->rxs);
	rx_pool->repost = 1;
	rx_pool->size = rx_buf_cnt;
	len = rx_buf_cnt * dev->device.max_send_size;
	ret = posix_memalign((void **)&rx_pool->buf, getpagesize(), len);
	if (ret)
		goto out;
	memset(rx_pool->buf, 0, len);	/* silence valgrind */

	rx_pool->mr =
	    ibv_reg_mr(vep->pd, rx_pool->buf, len, IBV_ACCESS_LOCAL_WRITE);
	if (!rx_pool->mr) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < rx_buf_cnt; i++) {
		uintptr_t offset = i * ep->buffer_len;
		verbs_rx_t *rx = NULL;

		rx = calloc(1, sizeof(*rx));
		if (!rx) {
			ret = CCI_ENOMEM;
			goto out;
		}

		rx->evt.ep = ep;
		rx->offset = offset;
		rx->rx_pool = rx_pool;
		TAILQ_INSERT_TAIL(&rx_pool->rxs, rx, entry);

		ret = verbs_post_rx(ep, rx);
		if (ret)
			goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&vep->rx_pools, rx_pool, entry);
	ep->rx_buf_cnt = rx_buf_cnt;
	pthread_mutex_unlock(&ep->lock);
out:
	if (ret && rx_pool) {
		rx_pool->repost = 0;
		if (rx_pool->posted) {
			/* we can't free anything since we posted some rxs.
			 * add this to the tail of the ep->rx_pools and tear
			 * down after the last rx completes
			 */
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&vep->rx_pools, rx_pool, entry);
			pthread_mutex_unlock(&ep->lock);
		} else {
			/* FIXME There is a race here - rx_pool->posted might be 0 if
			 * we posted 1 or more rxs and they all completed before
			 * reaching here.
			 */
			while (!TAILQ_EMPTY(&rx_pool->rxs)) {
				verbs_rx_t *rx = NULL;

				rx = TAILQ_FIRST(&rx_pool->rxs);
				TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
				free(rx);
			}
			if (rx_pool->mr) {
				int rc = 0;
				rc = ibv_dereg_mr(rx_pool->mr);
				if (rc) {
					/* TODO */
				}
			}
			if (rx_pool->buf)
				free(rx_pool->buf);
			free(rx_pool);
		}
	}
	CCI_EXIT;
	return ret;
}

#if HAVE_RDMA_ADDRINFO
void rdma_destroy_ep(struct rdma_cm_id *id)
{
	if (id->qp)
		rdma_destroy_qp(id);

	rdma_destroy_id(id);
}
#endif /* HAVE_RDMA_ADDRINFO */

static int verbs_progress_ep(cci__ep_t * ep);
static int verbs_get_cq_event(cci__ep_t * ep);
static int verbs_get_cm_event(cci__ep_t * ep);
static int verbs_get_rdma_msg_event(cci__ep_t* ep);

#if 0
void *
verbs_progress_thread(void *arg)
{
	cci__ep_t *ep = (cci__ep_t *) arg;
	verbs_ep_t *vep = ep->priv;

	ibv_req_notify_cq(vep->cq, 0);

	while (!ep->closing)
		verbs_progress_ep(ep);

	pthread_exit(NULL);
}
#endif

static inline int
verbs_make_nonblocking(cci_os_handle_t fd)
{
	int ret, flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		ret = errno;
		goto out;
	}

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
out:
	return ret;
}

static int
ctp_verbs_create_endpoint(cci_device_t * device,
		      int flags,
		      cci_endpoint_t ** endpointp, cci_os_handle_t * fd)
{
	int ret = CCI_SUCCESS;
	char name[MAXHOSTNAMELEN + 16];	/* verbs:// + host + port */
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	verbs_ep_t *vep = NULL;
	verbs_dev_t *vdev = NULL;
	struct ibv_srq_init_attr srq_attr;
	struct cci_endpoint *endpoint = *(struct cci_endpoint **)endpointp;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	vdev = dev->priv;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*vep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	vep = ep->priv;

	vep->tx_pool = NULL;
	vep->tx_pool_old = NULL;
	TAILQ_INIT(&vep->rx_pools);
	TAILQ_INIT(&vep->conns);
	TAILQ_INIT(&vep->active);
	TAILQ_INIT(&vep->passive);
	TAILQ_INIT(&vep->handles);
	TAILQ_INIT(&vep->rma_ops);
	pthread_rwlock_init(&vep->conn_tree_lock, NULL);

	ep->rx_buf_cnt = VERBS_EP_RX_CNT;
	ep->tx_buf_cnt = VERBS_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0;	/* FIXME */

	vep->rdma_channel = rdma_create_event_channel();
	if (!vep->rdma_channel) {
		ret = errno;
		goto out;
	}

	ret = verbs_make_nonblocking(vep->rdma_channel->fd);
	if (ret)
		goto out;

	ret = rdma_create_id(vep->rdma_channel, &vep->id_rc, ep, RDMA_PS_TCP);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = rdma_create_id(vep->rdma_channel, &vep->id_ud, ep, RDMA_PS_UDP);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	vep->sin = *((struct sockaddr_in *)vdev->ifa->ifa_addr);

	ret = rdma_bind_addr(vep->id_rc, (struct sockaddr *)&vep->sin);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	vep->sin.sin_port = rdma_get_src_port(vep->id_rc);

	ret = rdma_listen(vep->id_rc, 1024);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = rdma_bind_addr(vep->id_ud, (struct sockaddr *)&vep->sin);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	memset(name, 0, sizeof(name));
	sprintf(name, "%s%s:%hu", VERBS_URI,
		inet_ntoa(vep->sin.sin_addr), ntohs(vep->sin.sin_port));
	ep->uri = strdup(name);

	vep->pd = ibv_alloc_pd(vdev->context);
	if (!vep->pd) {
		ret = errno;
		goto out;
	}

	if (fd) {
		vep->ib_channel = ibv_create_comp_channel(vep->id_rc->verbs);

		ret = verbs_make_nonblocking(vep->ib_channel->fd);
		if (ret)
			goto out;
	}

	vep->cq_size = VERBS_EP_CQ_CNT;
	vep->cq = ibv_create_cq(vdev->context, vep->cq_size, ep, vep->ib_channel, 0);
	if (!vep->cq) {
		ret = errno;
		goto out;
	}

	if (fd)
		ibv_req_notify_cq(vep->cq, 0);

	ret = verbs_create_tx_pool(ep, ep->tx_buf_cnt);

	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.attr.max_wr = ep->rx_buf_cnt;
	srq_attr.attr.max_sge = 1;
	vep->srq = ibv_create_srq(vep->pd, &srq_attr);
	if (!vep->srq) {
		ret = errno;
		goto out;
	}

	/* only enable the RMDA MSGs for SDR/DDR */
	if (dev->device.rate <= 16000000000)
		vep->rdma_msg_total = vglobals->ep_rmsg_conns;

	ret = verbs_create_rx_pool(ep, ep->rx_buf_cnt);
	if (ret)
		goto out;

	if (fd) {
		int i;
		struct epoll_event ev;

		ret = pipe(vep->pipe);
		if (ret) {
			ret = errno;
			goto out;
		}

		for (i = 0; i < 2; i++) {
			ret = verbs_make_nonblocking(vep->pipe[i]);
			if (ret)
				goto out;
		}

		ret = epoll_create(3);
		if (ret == -1) {
			ret = errno;
			debug(CCI_DB_EP, "%s: epoll() returned %s", __func__,
					strerror(ret));
			goto out;
		}
		vep->fd = ret;

		ret = verbs_make_nonblocking(vep->fd);
		if (ret)
			goto out;

		memset(&ev, 0, sizeof(ev));
		ev.data.ptr = (void *) verbs_get_cm_event;
		ev.events = EPOLLIN;

		ret = epoll_ctl(vep->fd, EPOLL_CTL_ADD, vep->rdma_channel->fd, &ev);
		if (ret == -1) {
			ret = errno;
			debug(CCI_DB_EP, "%s: epoll_ctl() returned %s", __func__,
					strerror(ret));
			goto out;
		}

		ev.data.ptr = (void *) verbs_get_cq_event;
		ev.events = EPOLLIN;

		ret = epoll_ctl(vep->fd, EPOLL_CTL_ADD, vep->ib_channel->fd, &ev);
		if (ret == -1) {
			ret = errno;
			debug(CCI_DB_EP, "%s: epoll_ctl() returned %s", __func__,
					strerror(ret));
			goto out;
		}

		/* The IB channel only provides edge-triggered behavior. To provide
		 * level-triggered behavior, we will need to add the pipe to the
		 * epoll set. We will keep a byte in the pipe as long as there is
		 * one event on ep->evts. This has the side benefit of not requiring
		 * verbs_get_cq_event() reap all the completions to we can return
		 * after a bounded amount of work.
		 */
		ev.data.ptr = NULL;
		ev.events = EPOLLIN;

		ret = epoll_ctl(vep->fd, EPOLL_CTL_ADD, vep->pipe[0], &ev);
		if (ret == -1) {
			ret = errno;
			debug(CCI_DB_EP, "%s: epoll_ctl() returned %s", __func__,
					strerror(ret));
			goto out;
		}

		*fd = vep->fd;
	}

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	/* TODO lots of clean up */
	if (ep->priv) {
		int rc;
		verbs_ep_t *vep = ep->priv;

		if (vep->srq)
			ibv_destroy_srq(vep->srq);

		while (!TAILQ_EMPTY(&vep->rx_pools)) {
			verbs_rx_pool_t *rx_pool = TAILQ_FIRST(&vep->rx_pools);

			TAILQ_REMOVE(&vep->rx_pools, rx_pool, entry);
			while (!TAILQ_EMPTY(&rx_pool->rxs)) {
				verbs_rx_t *rx = TAILQ_FIRST(&rx_pool->rxs);
				TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
				free(rx);
			}
			if (rx_pool->mr) {
				rc = ibv_dereg_mr(rx_pool->mr);
				if (rc)
					debug(CCI_DB_WARN,
					      "deregistering endpoint rx_mr "
					      "failed with %s\n",
					      strerror(rc));
			}
			if (rx_pool->buf)
				free(rx_pool->buf);
		}

		if (vep->tx_pool != NULL) {
			verbs_destroy_tx_pool(vep->tx_pool);
			vep->tx_pool = NULL;
		}

		if (vep->cq) {
			rc = ibv_destroy_cq(vep->cq);
			if (rc)
				debug(CCI_DB_WARN, "destroying new endpoint cq "
				      "failed with %s\n", strerror(rc));
		}

		if (vep->pd) {
			rc = ibv_dealloc_pd(vep->pd);
			if (rc)
				debug(CCI_DB_WARN, "deallocing new endpoint pd "
				      "failed with %s\n", strerror(rc));
		}

		if (vep->ib_channel)
			ibv_destroy_comp_channel(vep->ib_channel);

		if (vep->id_rc)
			rdma_destroy_ep(vep->id_rc);

		if (vep->id_ud)
			rdma_destroy_ep(vep->id_ud);

		if (vep->rdma_channel)
			rdma_destroy_event_channel(vep->rdma_channel);

		free(vep);
		ep->priv = NULL;
	}
	return ret;
}

static int verbs_destroy_rx_pool(cci__ep_t * ep, verbs_rx_pool_t * rx_pool)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	while (!TAILQ_EMPTY(&rx_pool->rxs)) {
		verbs_rx_t *rx = TAILQ_FIRST(&rx_pool->rxs);
		TAILQ_REMOVE(&rx_pool->rxs, rx, entry);
		free(rx);
	}

	if (rx_pool->mr) {
		ret = ibv_dereg_mr(rx_pool->mr);
		if (ret)
			debug(CCI_DB_WARN, "deregistering endpoint rx_mr "
			      "failed with %s\n", strerror(ret));
	}
	if (rx_pool->buf)
		free(rx_pool->buf);

	free(rx_pool);

	CCI_EXIT;
	return ret;
}

static int ctp_verbs_destroy_endpoint(cci_endpoint_t * endpoint)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	if (vep->tid) {
		debug(CCI_DB_EP, "%s: waiting on progress thread", __func__);
		pthread_join(vep->tid, NULL);
	}

	if (vep->acks)
		ibv_ack_cq_events(vep->cq, vep->acks);

	while (!TAILQ_EMPTY(&vep->handles)) {
		verbs_rma_handle_t *handle = TAILQ_FIRST(&vep->handles);

		ret = ctp_verbs_rma_deregister(endpoint, &handle->rma_handle);
		if (ret)
			debug(CCI_DB_EP, "%s: rma_deregister failed with %s",
				__func__, cci_strerror(endpoint, ret));
	}

	while (!TAILQ_EMPTY(&vep->conns)) {
		cci__conn_t *conn = NULL;
		verbs_conn_t *vconn = NULL;

		vconn = TAILQ_FIRST(&vep->conns);
		conn = vconn->conn;
		ctp_verbs_disconnect(&conn->connection);
	}

	while (!TAILQ_EMPTY(&vep->active)) {
		cci__conn_t *conn = NULL;
		verbs_conn_t *vconn = NULL;

		vconn = TAILQ_FIRST(&vep->active);
		conn = vconn->conn;
		ctp_verbs_disconnect(&conn->connection);
	}

	while (!TAILQ_EMPTY(&vep->passive)) {
		cci__conn_t *conn = NULL;
		verbs_conn_t *vconn = NULL;

		vconn = TAILQ_FIRST(&vep->passive);
		conn = vconn->conn;
		ctp_verbs_disconnect(&conn->connection);
	}

	if (vep->srq) {
		do {
			ret = ibv_destroy_srq(vep->srq);
			if (ret == EBUSY)
				verbs_get_cq_event(ep);
		} while (ret == EBUSY);
	}

	if (vep->cq) {
		do {
			ret = ibv_destroy_cq(vep->cq);
			if (ret == EBUSY)
				verbs_get_cq_event(ep);
		} while (ret == EBUSY);
	}

	ep->priv = NULL;

	while (!TAILQ_EMPTY(&vep->rx_pools)) {
		verbs_rx_pool_t *rx_pool = TAILQ_FIRST(&vep->rx_pools);

		TAILQ_REMOVE(&vep->rx_pools, rx_pool, entry);
		verbs_destroy_rx_pool(ep, rx_pool);
	}

	verbs_destroy_tx_pool(vep->tx_pool);
	vep->tx_pool = NULL;
	verbs_destroy_tx_pool(vep->tx_pool_old);
	vep->tx_pool_old = NULL;

	if (vep->ib_channel)
		ibv_destroy_comp_channel(vep->ib_channel);

	if (vep->id_rc)
		rdma_destroy_id(vep->id_rc);

	if (vep->id_ud)
		rdma_destroy_id(vep->id_ud);

	if (vep->rdma_channel)
		rdma_destroy_event_channel(vep->rdma_channel);

	if (vep->pd) {
		do {
			ret = ibv_dealloc_pd(vep->pd);
		} while (ret == EBUSY);
	}

	free(vep);

	if (ep->uri) {
		free((char *)ep->uri);
	}

	CCI_EXIT;
	return CCI_SUCCESS;
}

static const char *verbs_msg_type_str(verbs_msg_type_t msg_type)
{
	char *str;

	switch (msg_type) {
	case VERBS_MSG_CONN_REQUEST:
		str = "conn_request";
		break;
	case VERBS_MSG_CONN_PAYLOAD:
		str = "conn_payload";
		break;
	case VERBS_MSG_CONN_REPLY:
		str = "conn_reply";
		break;
	case VERBS_MSG_DISCONNECT:
		str = "disconnect";
		break;
	case VERBS_MSG_SEND:
		str = "send";
		break;
	case VERBS_MSG_KEEPALIVE:
		str = "keepalive";
		break;
	case VERBS_MSG_RDMA_MSG_ACK:
		str = "rdma_msg_ack";
		break;
	case VERBS_MSG_RMA:
		str = "rma";
		break;
	default:
		str = "invalid";
		break;
	}
	return str;
}

static int verbs_vconn_set_mss(verbs_conn_t * vconn)
{
	int ret = CCI_SUCCESS;
	struct ibv_qp_attr attr;
	struct ibv_qp_init_attr init;

	CCI_ENTER;

	ret = ibv_query_qp(vconn->id->qp, &attr, IBV_QP_PATH_MTU, &init);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	vconn->mss = verbs_mtu_val(attr.path_mtu);

out:
	CCI_EXIT;
	return ret;
}

typedef union verbs_u64 {
	uint64_t ull;
	uint32_t ul[2];
} verbs_u64_t;

static uint64_t verbs_ntohll(uint64_t val)
{
	verbs_u64_t net = {.ull = val };
	verbs_u64_t host;

	host.ul[0] = ntohl(net.ul[1]);
	host.ul[1] = ntohl(net.ul[0]);

	return host.ull;
}

static uint64_t verbs_htonll(uint64_t val)
{
	verbs_u64_t host = {.ull = val };
	verbs_u64_t net;

	net.ul[0] = htonl(host.ul[1]);
	net.ul[1] = htonl(host.ul[0]);

	return net.ull;
}

static int
verbs_post_send(cci__conn_t * conn, uint64_t id, void *buffer, uint32_t len,
		uint32_t header)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	verbs_conn_t *vconn = conn->priv;
	verbs_ep_t *vep = NULL;
	struct ibv_sge list[2];
	struct ibv_send_wr wr, *bad_wr;
	verbs_tx_t *tx = NULL;
	int use_rdma = 0;
	uint32_t orig_len = len;
	int pad = len & 0x7 ? 8 - (len & 0x7) : 0;

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	vep = ep->priv;

	debug(CCI_DB_MSG, "sending msg 0x%x conn %p qp_num %u",
		header, conn, ((verbs_conn_t*)conn->priv)->id->qp->qp_num);

	if (VERBS_TYPE(header) == VERBS_MSG_SEND) {
		tx = (verbs_tx_t *)(uintptr_t) id;
		use_rdma = (tx->rdma_slot != -1);
	}

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = id;
	if (buffer && len) {
		memset(list, 0, sizeof(list));
		list[0].addr = (uintptr_t) buffer;
		list[0].length = len;
		list[0].lkey = vep->tx_pool->mr->lkey;

		wr.sg_list = list;
		wr.num_sge = 1;
	} else {
		wr.sg_list = NULL;
		wr.num_sge = 0;
	}
	if (header) {
		if (use_rdma) {
			/* write at the end of the peer's slot.
			 * we allocated an extra 4 bytes for the header
			 * which we will poll on.
			 * we need to ensure the user data is 8 byte aligned. */

			uint32_t slot = tx->rdma_slot;
			uint32_t seqno = VERBS_SEQNO(header);
			/* add 1 to length so the header will always have a bit set */
			uint32_t h2 = (orig_len + 1) | (seqno << VERBS_RSEND_SEQNO_SHIFT);
			uint64_t addr = vconn->raddr;

			h2 = htonl(h2);

			/* move to the end of the slot, then back up 4 bytes */
			addr += ((vconn->mss + 4) * (slot + 1)) - 4;

			if (len == 0) {
				/* SEND_INLINE must be used */
				memset(list, 0, sizeof(list));
				list[0].addr = (uintptr_t) & h2;
				list[0].length = 4;

				wr.sg_list = list;
				wr.num_sge = 1;
			} else if (len < vconn->inline_size - 4 - pad) {
				/* SEND_INLINE must be used */
				debug(CCI_DB_MSG, "adding second list[1]");
				list[0].length += pad;
				CCI_VALGRIND_MEMORY_MAKE_READABLE(list[0].addr,
								list[0].length);
				list[1].addr = (uintptr_t) & h2;
				list[1].length = 4;	/* we will fix below */
				wr.num_sge = 2;
			} else {
				/* need to copy to registered buffer */
				debug(CCI_DB_MSG, "copying header to buffer");
				memcpy(buffer + len + pad, &h2, 4);
				list[0].length = len + pad + 4;	/* header after message */
			}

			len += pad;
			addr -= len;

			debug(CCI_DB_MSG,
			      "using RDMA MSG send 0x%x 0x%x len %u "
			      "orig_len %u pad %u", header, h2, len, orig_len,
			      pad);
			wr.opcode = IBV_WR_RDMA_WRITE;
			wr.wr.rdma.remote_addr = addr;
			wr.wr.rdma.rkey = vconn->rkey;
		} else {
			debug(CCI_DB_MSG,
			      "%s:  not using RDMA MSG send 0x%x", __func__,
			      header);
			wr.opcode = IBV_WR_SEND_WITH_IMM;
			wr.imm_data = htonl(header);
		}
	} else {
		debug(CCI_DB_MSG, "%s:  no header", __func__);
		wr.opcode = IBV_WR_SEND;
	}
	wr.send_flags = IBV_SEND_SIGNALED;
	if (vconn->inline_size && (len <= vconn->inline_size - 4)) {
		debug(CCI_DB_MSG, "%s: setting inline flag", __func__);
		wr.send_flags |= IBV_SEND_INLINE;
	}

	ret = ibv_post_send(vconn->id->qp, &wr, &bad_wr);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_MSG,
		      "unable to send id 0x%" PRIx64
		      " buffer %p len %u header %u", id, buffer, len, header);
	}
	CCI_EXIT;
	return ret;
}

static int ctp_verbs_accept(cci_event_t * event, const void *context)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	verbs_ep_t *vep = NULL;
	verbs_conn_t *vconn = NULL;
	uint32_t header = 0;
	void *ptr = NULL;
	int len = 0;
	verbs_tx_t *tx = NULL;
	verbs_rdma_attrs_t *attrs;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	vep = ep->priv;

	conn = evt->conn;
	vconn = conn->priv;

	tx = verbs_get_tx(ep);
	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}
	tx->msg_type = VERBS_MSG_CONN_REPLY;
	tx->flags = 0;
	tx->rma_op = NULL;
	tx->evt.event.type = CCI_EVENT_ACCEPT;
	tx->evt.event.accept.status = CCI_SUCCESS;	/* for now */
	tx->evt.event.accept.context = (void *)context;
	tx->evt.event.accept.connection = &conn->connection;
	tx->evt.conn = conn;
	tx->evt.ep = ep;
	conn->connection.context = (void *)context;

	ret = verbs_vconn_set_mss(vconn);
	if (ret) {
		/* TODO */
		goto out;
	}
	conn->connection.max_send_size = vconn->mss;

	if (vconn->num_slots) {
		pthread_mutex_lock(&ep->lock);
		if (vep->rdma_msg_used >= vep->rdma_msg_total)
			vconn->num_slots = 0;
		pthread_mutex_unlock(&ep->lock);
	}

	{
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init;

		ret = ibv_query_qp(vconn->id->qp, &attr, IBV_QP_CAP, &init);
		if (!ret)
			vconn->inline_size = init.cap.max_inline_data;
	}

	if (vconn->num_slots) {
		int i;
		verbs_rx_t *rx;

		attrs = tx->buffer;

		len = vconn->num_slots * (vconn->mss + sizeof(uint32_t));
		ret = posix_memalign((void **)&vconn->rbuf, getpagesize(), len);
		if (ret)
			goto out;

		memset(vconn->rbuf, 0, len);	/* silence valgrind */
		vconn->rxs = calloc(vconn->num_slots, sizeof(*rx));
		if (!vconn->rxs)
			goto out;
		vconn->slots = calloc(vconn->num_slots, sizeof(*vconn->slots));
		if (!vconn->slots)
			goto out;
		if (conn->connection.attribute == CCI_CONN_ATTR_RO) {
			vconn->seqno = (uint16_t) random();
		}
		for (i = 0; i < vconn->num_slots; i++) {
			rx = &vconn->rxs[i];
			rx->evt.ep = ep;
			rx->evt.conn = conn;
			rx->evt.event.type = CCI_EVENT_RECV;
			rx->evt.event.recv.connection = &conn->connection;
			rx->offset = i;
			vconn->slots[i] = (uint32_t *) ((vconn->rbuf) +
							(uintptr_t) (((vconn->mss + 4) * (i + 1))
								     - 4));
		}
		vconn->rmr = ibv_reg_mr(vep->pd, vconn->rbuf, len,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_WRITE);
		if (!vconn->rmr)
			goto out;

		vconn->avail = (1 << vconn->num_slots) - 1;

		len = sizeof(*attrs);
		attrs->addr = verbs_htonll((uintptr_t) vconn->rmr->addr);
		attrs->rkey = htonl(vconn->rmr->rkey);
		attrs->seqno = htons(vconn->seqno);
		ptr = tx->buffer;
	}

	header = VERBS_MSG_CONN_REPLY;
	header |= (CCI_SUCCESS << 4);
	if (vconn->num_slots)
		header |= (1 << 8);	/* magic number */

	vconn->state = VERBS_CONN_ESTABLISHED;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->conns, vconn, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = verbs_post_send(conn, (uintptr_t) tx, ptr, len, header);
	if (ret) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&vep->conns, vconn, entry);
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}

out:
	/* do not repost rx here - it will be posted in return event */
	CCI_EXIT;
	return ret;
}

static int ctp_verbs_reject(cci_event_t * event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_tx_t *tx = NULL;
	uint32_t header = 0;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;

	conn = evt->conn;
	vconn = conn->priv;

	tx = verbs_get_tx(ep);
	if (tx) {
		tx->msg_type = VERBS_MSG_CONN_REPLY;
		tx->evt.conn = conn;
		tx->evt.ep = ep;
	}

	vconn->state = VERBS_CONN_CLOSED;

	/* send a reject rather than just disconnect so the client knows */
	header = VERBS_MSG_CONN_REPLY;
	header |= (CCI_ECONNREFUSED << 4);

	ret = verbs_post_send(conn, (uintptr_t) tx, NULL, 0, header);
	/* FIXME handle error */

	/* do not repost rx here - it will be posted in return event */

	/* wait for send to complete before destorying the ep and conn */

	CCI_EXIT;
	return ret;
}

static int verbs_parse_uri(const char *uri, char **node, char **service)
{
	int ret = CCI_SUCCESS;
	int len = strlen(VERBS_URI);
	char *ip = NULL;
	char *port = NULL;
	char *colon = NULL;

	CCI_ENTER;

	if (0 == strncmp(VERBS_URI, uri, len)) {
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
verbs_compare_u32(const void *pa, const void *pb)
{
	if (*(uint32_t*) pa < *(uint32_t*) pb)
		return -1;
	if (*(uint32_t*) pa > *(uint32_t*) pb)
		return 1;
	return 0;
}

static int
verbs_find_conn(cci__ep_t *ep, uint32_t qp_num, cci__conn_t **conn)
{
	int ret = CCI_ERROR;
	verbs_ep_t *vep = ep->priv;
	void *node = NULL;
	uint32_t *q = NULL;

	CCI_ENTER;

	pthread_rwlock_rdlock(&vep->conn_tree_lock);
	node = tfind(&qp_num, &vep->conn_tree, verbs_compare_u32);
	pthread_rwlock_unlock(&vep->conn_tree_lock);
	if (node) {
		verbs_conn_t *vconn = NULL;

		q = *((uint32_t**)node);
		vconn = container_of(q, verbs_conn_t, qp_num);
		assert(vconn->qp_num == qp_num);
		*conn = vconn->conn;
		ret = CCI_SUCCESS;
	} else {
		debug(CCI_DB_CONN, "%s: unable to find qp_num %u", __func__, qp_num);
	}

	CCI_EXIT;
	return ret;
}

static void
verbs_insert_conn(cci__conn_t *conn)
{
	cci__ep_t *ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;
	verbs_conn_t *vconn = conn->priv;
	void *node = NULL;

	CCI_ENTER;

	pthread_rwlock_wrlock(&vep->conn_tree_lock);
	do {
		node = tsearch(&vconn->qp_num, &vep->conn_tree, verbs_compare_u32);
	} while (!node);
	pthread_rwlock_unlock(&vep->conn_tree_lock);
	debug(CCI_DB_CONN, "%s: added conn %p qp_num %u", __func__, conn, vconn->qp_num);

	CCI_EXIT;
	return;
}

static int
ctp_verbs_connect(cci_endpoint_t * endpoint, const char *server_uri,
	      const void *data_ptr, uint32_t data_len,
	      cci_conn_attribute_t attribute,
	      const void *context, int flags, const struct timeval *timeout)
{
	int ret = CCI_SUCCESS;
	char *node = NULL;
	char *service = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	verbs_ep_t *vep = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_conn_request_t *cr = NULL;
#if HAVE_RDMA_ADDRINFO
	struct rdma_addrinfo hints, *res = NULL;
#endif /* HAVE_RDMA_ADDRINFO */
	struct ibv_qp_init_attr attr;
	struct rdma_conn_param param;
	uint32_t header = 0;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	vep = ep->priv;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->plugin = ep->plugin;
	conn->uri = strdup(server_uri);

	debug(CCI_DB_CONN, "%s: alloced conn %p", __func__, conn);

	conn->priv = calloc(1, sizeof(*vconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	vconn = conn->priv;
	vconn->conn = conn;
	TAILQ_INIT(&vconn->rma_ops);
	TAILQ_INIT(&vconn->early);

	if (context || data_len) {
		cr = calloc(1, sizeof(*cr));
		if (!cr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		vconn->conn_req = cr;

		cr->context = (void *) context;
		cr->attr = attribute;
		if (data_len) {
			cr->len = data_len;
			cr->ptr = calloc(1, data_len);
			if (!cr->ptr) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(cr->ptr, data_ptr, data_len);
		}
	}

	/* conn->tx_timeout = 0;  by default */

	conn->connection.attribute = attribute;
	conn->connection.endpoint = endpoint;
	conn->connection.context = (void *) context;

	ret = verbs_parse_uri(server_uri, &node, &service);
	if (ret)
		goto out;

	memset(&attr, 0, sizeof(attr));
	attr.qp_type = IBV_QPT_RC;
	attr.send_cq = vep->cq;
	attr.recv_cq = vep->cq;
	attr.srq = vep->srq;
	attr.cap.max_send_wr = VERBS_EP_TX_CNT;
	attr.cap.max_send_sge = 2;
	attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = VERBS_INLINE_BYTES;

#if HAVE_RDMA_ADDRINFO
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_qp_type = IBV_QPT_RC;
	ret = rdma_getaddrinfo(node, service, &hints, &res);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "rdma_getaddrinfo() returned %s",
		      strerror(ret));
		goto out;
	}

	ret = rdma_create_ep(&vconn->id, res, vep->pd, &attr);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "rdma_create_ep() returned %s",
		      strerror(ret));
		goto out;
	}
#else
	{
		struct sockaddr_in dst;

		{
			struct addrinfo *res, hints;

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = PF_INET;
			ret = getaddrinfo(node, service, &hints, &res);
			if (ret) {
				ret = errno;
				debug(CCI_DB_PEER, "getaddrinfo failed - %s\n",
				      strerror(ret));
				goto out;
			}
			assert(res->ai_family == PF_INET);

			dst = *(struct sockaddr_in *)res->ai_addr;
			freeaddrinfo(res);
		}

		ret =
		    rdma_create_id(vep->rdma_channel, &vconn->id, NULL, RDMA_PS_TCP);
		if (ret != 0) {
			ret = errno;
			debug(CCI_DB_CONN, "rdma_create_id() returned %s",
			      strerror(ret));
			goto out;
		}

		ret =
		    rdma_resolve_addr(vconn->id, NULL, (struct sockaddr *)&dst,
				      2000);
		if (ret != 0) {
			ret = errno;
			debug(CCI_DB_CONN, "rdma_resolve_addr() returned %s",
			      strerror(ret));
			goto out;
		}

		{
			struct rdma_cm_event *event;
			int done = 0;

			while (!done) {
				ret = rdma_get_cm_event(vep->rdma_channel, &event);
				if (ret) {
					ret = errno;
					if (EAGAIN == ret)
						continue;
					debug(CCI_DB_CONN,
					      "rdma_get_cm_event() returned %s",
					      strerror(ret));
					goto out;
				}
				if (RDMA_CM_EVENT_ADDR_RESOLVED == event->event) {
					ret =
					    rdma_resolve_route(vconn->id, 2000);
					if (ret != 0) {
						ret = errno;
						debug(CCI_DB_CONN,
						      "rdma_resolve_route() returned %s",
						      strerror(ret));
						rdma_ack_cm_event(event);
						goto out;
					}
				} else if (RDMA_CM_EVENT_ROUTE_RESOLVED ==
					   event->event) {
					done = 1;
				} else {
					printf
					    ("Got %s while solving %s! Give up!!!\n",
					     rdma_event_str(event->event),
					     node);
					ret = CCI_EADDRNOTAVAIL;
					rdma_ack_cm_event(event);
					goto out;
				}
				rdma_ack_cm_event(event);
			}
		}

		ret = rdma_create_qp(vconn->id, vep->pd, &attr);
		if (ret != 0) {
			ret = errno;
			debug(CCI_DB_CONN, "rdma_create_qp() returned %s\n",
			      strerror(ret));
			goto out;
		}
	}
#endif /* HAVE_RDMA_ADDRINFO */

	vconn->qp_num = vconn->id->qp->qp_num;
	verbs_insert_conn(conn);

	ret = rdma_migrate_id(vconn->id, vep->rdma_channel);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN, "rdma_migrate_id() returned %s",
		      strerror(ret));
		goto out;
	}

	vconn->id->context = conn;
	vconn->state = VERBS_CONN_ACTIVE;

	header = VERBS_MSG_CONN_REQUEST;
	header = htonl(header);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->active, vconn, temp);
	pthread_mutex_unlock(&ep->lock);

	memset(&param, 0, sizeof(param));
	param.srq = 1;
	param.initiator_depth = param.responder_resources = 16;
	param.retry_count = 7;	/* infinite retry */
	param.rnr_retry_count = 7;	/* infinite retry */
	param.private_data = &header;
	param.private_data_len = sizeof(header);
	ret = rdma_connect(vconn->id, &param);
	if (ret == -1) {
		ret = errno;
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&vep->active, vconn, temp);
		pthread_mutex_unlock(&ep->lock);
		debug(CCI_DB_CONN, "rdma_connect() returned %s", strerror(ret));
		goto out;
	}
	ret = 0;		/* we're good to go at this point */

	debug(CCI_DB_CONN, "connecting to %s %s\n", node, service);

out:
	/* TODO
	 * if (ret)
	 *      free memory
	 */
#if HAVE_RDMA_ADDRINFO
	if (res)
		rdma_freeaddrinfo(res);
#endif /* HAVE_RDMA_ADDRINFO */
	if (node)
		free(node);
	CCI_EXIT;
	return ret;
}

static const char *verbs_conn_state_str(verbs_conn_state_t state);

static int ctp_verbs_disconnect(cci_connection_t * connection)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	verbs_conn_t *vconn = conn->priv;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	pthread_rwlock_wrlock(&vep->conn_tree_lock);
	tdelete(&vconn->qp_num, &vep->conn_tree, verbs_compare_u32);
	pthread_rwlock_unlock(&vep->conn_tree_lock);

	pthread_mutex_lock(&ep->lock);
	if (vconn->state == VERBS_CONN_ESTABLISHED ||
		vconn->state == VERBS_CONN_CLOSED)
		TAILQ_REMOVE(&vep->conns, vconn, entry);
	else if (vconn->state == VERBS_CONN_ACTIVE)
		TAILQ_REMOVE(&vep->active, vconn, temp);
	else if (vconn->state == VERBS_CONN_PASSIVE)
		TAILQ_REMOVE(&vep->passive, vconn, temp);
	else
		debug(CCI_DB_CONN, "%s: disconnecting conn in %s",
			__func__, verbs_conn_state_str(vconn->state));
	pthread_mutex_unlock(&ep->lock);

	if (vconn->conn_req) {
		if (vconn->conn_req->ptr)
			free(vconn->conn_req->ptr);
	}

	ret = rdma_disconnect(vconn->id);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_WARN, "%s: rdma_disconnect() returned %s",
		      __func__, strerror(ret));
	}

	if (vconn->rbuf) {
		if (vconn->rmr) {
			ret = ibv_dereg_mr(vconn->rmr);
			if (ret) {
				ret = errno;
				debug(CCI_DB_WARN,
				      "%s: ibv_dereg_mr() returned %s",
				      __func__, strerror(ret));
			}
		}
		free(vconn->slots);
		free(vconn->rxs);
		free(vconn->rbuf);
	}

	rdma_destroy_ep(vconn->id);

	free((void *)conn->uri);
	free(vconn);
	free(conn);

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_set_opt(cci_opt_handle_t * handle,
		  cci_opt_name_t name, const void *val)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	cci_endpoint_t *endpoint = NULL;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	verbs_ep_t *vep = NULL;
	verbs_dev_t *vdev = NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	endpoint = handle;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	vep = ep->priv;
	dev = ep->dev;
	vdev = dev->priv;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
	case CCI_OPT_CONN_SEND_TIMEOUT:
		/* not implemented */
		break;
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			uint32_t new_count = *((uint32_t*) val);
			struct ibv_device_attr dev_attr;
			verbs_rx_pool_t *rx_pool = TAILQ_FIRST(&vep->rx_pools);

			/* Does device allow resizing of srq and cq? */
			ret = ibv_query_device(vdev->context, &dev_attr);
			if (ret) {
				ret = errno;
				debug(CCI_DB_EP, "%s: could not query device",
				      __func__);
				break;
			}
			if (!
			    (dev_attr.device_cap_flags & IBV_DEVICE_SRQ_RESIZE))
			{
				debug(CCI_DB_EP,
				      "%s: this device does not support "
				      "resizing the srq", __func__);
				ret = EOPNOTSUPP;
				break;	/* ret = CCI_ERR_NOT_IMPLEMENTED */
			}

			/* Is new count supportable (i.e. < max_srq_wr)? */
			if (dev_attr.max_srq_wr < new_count) {
				debug(CCI_DB_EP,
				      "%s: requested recv buffer size %u "
				      "is larger than the max_cq_wr %u",
				      __func__, new_count, dev_attr.max_srq_wr);
				ret = CCI_ERANGE;
				break;
			}

			/* Modify cq first */
			ret = ibv_resize_cq(vep->cq, new_count);
			if (ret) {
				ret = errno;
				debug(CCI_DB_EP,
				      "%s: unable to resize completion queue",
				      __func__);
				if (new_count > ep->rx_buf_cnt) {
					/* we couldn't enlarge the cq, return error */
					break;
				} else {
					/* we couldn't shrink the cq, but we might be able
					 * to shrink the rx_pool. Let's continue. */
					ret = CCI_SUCCESS;
				}
			}

			/* Create new rx_pool based on new_count */
			ret = verbs_create_rx_pool(ep, new_count);
			if (ret == CCI_SUCCESS) {
				/* set the old rx_pool to not repost.
				 * the old rxs will clean up as we reap them from
				 * ibv_poll_cq() and eventually cleanup the old rx_pool. */
				pthread_mutex_lock(&ep->lock);
				rx_pool->repost = 0;
				pthread_mutex_unlock(&ep->lock);
			}
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			uint32_t new_count = *((uint32_t*) val);

			/* Check if the new buffer count is different from
			 * the old buffer count, if it is, continue, otherwise
			 * break and declare success */
			if (new_count == ep->tx_buf_cnt) {
				ret = CCI_SUCCESS;
				break;
			}

			/*
			 * Lock the endpoint to avoid a race condition, there could
			 * be two race conditions:
			 * - one if a resize is already in progress
			 * - a separate one if a buffer is still aging out of scope
			 */
			pthread_mutex_lock(&ep->lock);
			if (vep->tx_resize_in_progress != 0
			    || vep->tx_pool_old != NULL) {
				ret = CCI_EAGAIN;
				pthread_mutex_unlock(&ep->lock);
				break;
			}
			vep->tx_resize_in_progress = 1;
			pthread_mutex_unlock(&ep->lock);

			/*
			 * Create a new tx_pool, note that a side-effect of
			 * this is to recopy the existing tx_pool into the
			 * old location
			 */
			ret = verbs_create_tx_pool(ep, new_count);

			pthread_mutex_lock(&ep->lock);
			vep->tx_resize_in_progress = 0;
			pthread_mutex_unlock(&ep->lock);

			if (ret != CCI_SUCCESS) {
				debug(CCI_DB_EP,
				      "%s: unable to create new tx_pool",
				      __func__);

				break;
			}

			/*
			 * Now destroy the previous TX Pool
			 */
			ret = verbs_destroy_tx_pool(vep->tx_pool_old);
			vep->tx_pool_old = NULL;

			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			uint32_t new_time = *((uint32_t*) val);

			/* we don't do anything for keepalives.
			 * If the connection breaks, we will generate a
			 * keepalive timeout. When the app tries to send,
			 * it will fail. */
			ep->keepalive_timeout = new_time;
			ret = CCI_SUCCESS;
			break;
		}
	default:
		debug(CCI_DB_INFO, "unknown option %u",
		      (enum cci_opt_name)name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_get_opt(cci_opt_handle_t * handle,
		  cci_opt_name_t name, void *val)
{
	int ret = CCI_ERR_NOT_IMPLEMENTED;
	cci_endpoint_t *endpoint = NULL;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;
	verbs_ep_t *vep = NULL;
	verbs_dev_t *vdev = NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	endpoint = handle;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	vep = ep->priv;
	dev = ep->dev;
	vdev = dev->priv;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
	case CCI_OPT_CONN_SEND_TIMEOUT:
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			uint32_t *count = val;
			*count = ep->rx_buf_cnt;
			ret = CCI_SUCCESS;
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			uint32_t *count = val;
			*count = ep->tx_buf_cnt;
			ret = CCI_SUCCESS;
			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			uint32_t *timeout = val;
			*timeout = ep->keepalive_timeout;
			ret = CCI_SUCCESS;
			break;
		}
	default:
		debug(CCI_DB_INFO, "unknown option %u",
		      (enum cci_opt_name)name);
		ret = CCI_EINVAL;
	}

	CCI_EXIT;
	return ret;
}

static int ctp_verbs_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

/* A peer is trying to connect. Always accept and let them send the full
 * connect request as a regular message.
 */
static int
verbs_handle_conn_request(cci__ep_t * ep, struct rdma_cm_event *cm_evt)
{
	int ret = CCI_SUCCESS;
	verbs_ep_t *vep = ep->priv;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	struct rdma_cm_id *peer = NULL;
	struct ibv_qp_init_attr attr;
	struct rdma_conn_param *param = NULL;
	uint32_t header;

	peer = cm_evt->id;
	assert(cm_evt->status == 0);

	memset(&attr, 0, sizeof(attr));
	attr.qp_type = IBV_QPT_RC;
	attr.send_cq = vep->cq;
	attr.recv_cq = vep->cq;
	attr.srq = vep->srq;
	attr.cap.max_send_wr = VERBS_EP_TX_CNT;
	attr.cap.max_send_sge = 2;
	attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = VERBS_INLINE_BYTES;

	ret = rdma_create_qp(peer, vep->pd, &attr);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	param = &cm_evt->param.conn;
	param->srq = 1;
	param->qp_num = peer->qp->qp_num;

	header = ntohl(*((uint32_t *) param->private_data));
	assert((header & 0xF) == VERBS_MSG_CONN_REQUEST);

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->plugin = ep->plugin;

	conn->priv = calloc(1, sizeof(*vconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	vconn = conn->priv;
	vconn->conn = conn;
	vconn->id = peer;
	vconn->id->context = conn;
	vconn->state = VERBS_CONN_PASSIVE;
	TAILQ_INIT(&vconn->rma_ops);
	TAILQ_INIT(&vconn->early);
	vconn->qp_num = vconn->id->qp->qp_num;

	conn->connection.endpoint = &ep->endpoint;
	verbs_insert_conn(conn);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->passive, vconn, temp);
	pthread_mutex_unlock(&ep->lock);

	ret = rdma_accept(peer, param);
	if (ret == -1) {
		ret = errno;
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&vep->passive, vconn, temp);
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}

out:
	CCI_EXIT;
	return ret;
}

static const char *verbs_conn_state_str(verbs_conn_state_t state)
{
	char *str;
	switch (state) {
	case VERBS_CONN_CLOSED:
		str = "closed";
	case VERBS_CONN_CLOSING:
		str = "closing";
	case VERBS_CONN_INIT:
		str = "init";
	case VERBS_CONN_ACTIVE:
		str = "active";
	case VERBS_CONN_PASSIVE:
		str = "passive";
	case VERBS_CONN_ESTABLISHED:
		str = "established";
	}
	return str;
}

static int verbs_conn_est_active(cci__ep_t * ep, struct rdma_cm_event *cm_evt)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_conn_t *vconn = NULL;
	verbs_conn_request_t *cr = NULL;
	verbs_tx_t *tx = NULL;
	uint32_t header = 0;
	uint32_t len = 0;
	int need_rdma = 0;

	CCI_ENTER;

	conn = cm_evt->id->context;
	vconn = conn->priv;
	cr = vconn->conn_req;

	verbs_vconn_set_mss(vconn);
	conn->connection.max_send_size = vconn->mss;

	pthread_mutex_lock(&ep->lock);
	if (vep->rdma_msg_used < vep->rdma_msg_total && !vep->fd) {
		vep->rdma_msg_used++;
		need_rdma = 1;
	}
	pthread_mutex_unlock(&ep->lock);

	tx = verbs_get_tx(ep);

	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->msg_type = VERBS_MSG_INVALID;
	tx->evt.event.type = CCI_EVENT_NONE;	/* never hand to application */
	tx->evt.conn = conn;

	if (need_rdma) {
		int i;
		verbs_rx_t *rx;
		verbs_rdma_attrs_t *attrs = (verbs_rdma_attrs_t *)tx->buffer;

		vconn->num_slots = VERBS_CONN_RMSG_DEPTH;
		len = vconn->num_slots * (vconn->mss + sizeof(uint32_t));
		ret = posix_memalign((void **)&vconn->rbuf, getpagesize(), len);
		if (ret)
			goto out;
		memset(vconn->rbuf, 0, len);	/* silence valgrind */
		vconn->rxs = calloc(vconn->num_slots, sizeof(*rx));
		if (!vconn->rxs)
			goto out;
		vconn->slots = calloc(vconn->num_slots, sizeof(*vconn->slots));
		if (!vconn->slots)
			goto out;
		if (conn->connection.attribute == CCI_CONN_ATTR_RO) {
			vconn->seqno = (uint16_t) random();
		}
		for (i = 0; i < vconn->num_slots; i++) {
			rx = &vconn->rxs[i];
			rx->evt.ep = ep;
			rx->evt.conn = conn;
			rx->evt.event.type = CCI_EVENT_RECV;
			rx->evt.event.recv.connection = &conn->connection;
			rx->offset = i;
			vconn->slots[i] = (uint32_t *) ((vconn->rbuf) +
							(uintptr_t) (((vconn->mss + 4)
								      * (i +
									 1)) -
								     4));
		}
		vconn->rmr = ibv_reg_mr(vep->pd, vconn->rbuf, len,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_WRITE);
		if (!vconn->rmr)
			goto out;

		vconn->avail = (1 << vconn->num_slots) - 1;

		len = sizeof(*attrs);
		attrs->addr = verbs_htonll((uintptr_t) vconn->rmr->addr);
		attrs->rkey = htonl(vconn->rmr->rkey);
		attrs->seqno = htons(vconn->seqno);
	}

	/* if application has a conn request payload, send it */
	if (cr && cr->len) {
		memcpy(tx->buffer + (uintptr_t) len, cr->ptr, cr->len);
		len += cr->len;
	}

	header = VERBS_MSG_CONN_PAYLOAD;
	header |= (conn->connection.attribute & 0xF) << 4;	/* magic number */
	if (need_rdma)
		header |= (1 << 8);	/* magic number */
	if (cr && cr->len)
		header |= (cr->len & 0xFFF) << 9;	/* magic number */

	ret = verbs_post_send(conn, (uintptr_t) tx, tx->buffer, len, header);

	if (cr) {
		if (cr->ptr)
			free(cr->ptr);
		free(cr);
	}
	vconn->conn_req = NULL;
out:
	CCI_EXIT;
	return ret;
}

static int verbs_conn_est_passive(cci__ep_t * ep, struct rdma_cm_event *cm_evt)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	CCI_EXIT;
	return ret;
}

static int
verbs_handle_conn_established(cci__ep_t * ep, struct rdma_cm_event *cm_evt)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;

	CCI_ENTER;

	conn = cm_evt->id->context;
	assert(conn);
	vconn = conn->priv;
	assert(vconn);

	switch (vconn->state) {
	case VERBS_CONN_ACTIVE:
		ret = verbs_conn_est_active(ep, cm_evt);
		break;
	case VERBS_CONN_PASSIVE:
		ret = verbs_conn_est_passive(ep, cm_evt);
		break;
	case VERBS_CONN_ESTABLISHED:
		break;
	default:
		debug(CCI_DB_INFO, "%s: incorrect conn state %s", __func__,
		      verbs_conn_state_str(vconn->state));
		break;
	}

	CCI_EXIT;
	return ret;
}

static int
verbs_handle_disconnected(cci__ep_t * ep, struct rdma_cm_event *cm_evt)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;

	CCI_ENTER;

	conn = cm_evt->id->context;
	assert(conn);
	vconn = conn->priv;
	assert(vconn);

	switch (vconn->state) {
	case VERBS_CONN_ESTABLISHED:
		vconn->state = VERBS_CONN_CLOSED;
		debug(CCI_DB_CONN, "%s: marking vconn %p closed (%s)",
			__func__, vconn, conn->uri);
		break;
	default:
		debug(CCI_DB_INFO, "%s: incorrect conn state %s", __func__,
		      verbs_conn_state_str(vconn->state));
		break;
	}

	CCI_EXIT;
	return ret;
}

static int verbs_get_cm_event(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	verbs_ep_t *vep = ep->priv;
	struct rdma_cm_event *cm_evt = NULL;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	if (ep->closing || !vep) {
		pthread_mutex_unlock(&ep->lock);
		goto out;
	}
	pthread_mutex_unlock(&ep->lock);

	ret = rdma_get_cm_event(vep->rdma_channel, &cm_evt);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	switch (cm_evt->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = verbs_handle_conn_request(ep, cm_evt);
		if (ret)
			debug(CCI_DB_CONN, "%s: verbs_handle_conn_request()"
			      "returned %s", __func__, strerror(ret));
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		ret = verbs_handle_conn_established(ep, cm_evt);
		if (ret)
			debug(CCI_DB_CONN, "%s: verbs_handle_conn_established()"
			      "returned %s", __func__, strerror(ret));
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		ret = verbs_handle_disconnected(ep, cm_evt);
		if (ret)
			debug(CCI_DB_CONN, "%s: verbs_handle_disconnected()"
			      "returned %s", __func__, strerror(ret));
		break;
	default:
		debug(CCI_DB_CONN, "ignoring %s event",
		      rdma_event_str(cm_evt->event));
	}

	ret = rdma_ack_cm_event(cm_evt);
	if (ret == -1)
		ret = errno;
out:
	CCI_EXIT;
	return ret;
}

static inline void
verbs_queue_evt_locked(cci__ep_t *ep, cci__evt_t *evt)
{
	char need_write = 0;
	verbs_ep_t *vep = ep->priv;

	if (vep->fd && TAILQ_EMPTY(&ep->evts))
		need_write = 1;
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	if (need_write) {
		debug(CCI_DB_EP, "%s: writing to pipe", __func__);
		write(vep->pipe[1], &need_write, 1);
	}
}

static inline void
verbs_queue_evt(cci__ep_t *ep, cci__evt_t *evt)
{
	pthread_mutex_lock(&ep->lock);
	verbs_queue_evt_locked(ep, evt);
	pthread_mutex_unlock(&ep->lock);
}

static int verbs_handle_conn_payload(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	uint32_t header = 0;
	uint32_t len = 0;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_conn_t *vc = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_rx_t *rx = NULL;
	int need_rdma = 0;
	void *ptr = NULL;
	verbs_rdma_attrs_t *attrs = NULL;

	CCI_ENTER;

	/* find the passive conn waiting for this message */
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(vc, &vep->passive, temp) {
		if (vc->id->qp->qp_num == wc.qp_num) {
			vconn = vc;
			conn = vconn->conn;
			assert(conn == vc->id->context);
			TAILQ_REMOVE(&vep->passive, vconn, temp);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (!vconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	header = ntohl(wc.imm_data);
	conn->connection.attribute = (header >> 4) & 0xF;
	need_rdma = (header >> 8) & 0x1;
	len = (header >> 9) & 0xFFF;
	if (((len != wc.byte_len) && !need_rdma) ||
	    (need_rdma && (len != (wc.byte_len - sizeof(*attrs)))))
		debug(CCI_DB_WARN, "%s: len %u != wc.byte_len %u",
		      __func__, len, wc.byte_len);

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	rx->evt.conn = conn;
	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.event.request.attribute = conn->connection.attribute;
	ptr = rx->rx_pool->buf + rx->offset;
	if (need_rdma) {
		attrs = ptr;

		if (!vep->fd && vglobals->ep_rmsg_conns) {
			vconn->raddr = verbs_ntohll(attrs->addr);
			vconn->rkey = ntohl(attrs->rkey);
			vconn->expected = ntohs(attrs->seqno) + 1;
			/* indicate peer wants RDMA */
			vconn->num_slots = VERBS_CONN_RMSG_DEPTH;
		}

		ptr = ptr + (uintptr_t) sizeof(*attrs);
	}
	rx->evt.event.request.data_len = len;
	if (len)
		rx->evt.event.request.data_ptr = ptr;
	else
		rx->evt.event.request.data_ptr = NULL;

	verbs_queue_evt(ep, &rx->evt);
out:
	CCI_EXIT;
	return ret;
}

static int verbs_handle_conn_reply(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	uint32_t header = 0;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_conn_t *vc = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_rx_t *rx = NULL;
	verbs_rdma_attrs_t *attrs;

	CCI_ENTER;

	/* find the active conn waiting for this message */
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(vc, &vep->active, temp) {
		if (vc->id->qp->qp_num == wc.qp_num) {
			vconn = vc;
			conn = vconn->conn;
			assert(conn == vc->id->context);
			TAILQ_REMOVE(&vep->active, vconn, temp);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (!vconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	header = ntohl(wc.imm_data);

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	rx->evt.event.type = CCI_EVENT_CONNECT;
	rx->evt.event.connect.status = (header >> 4) & 0xF;	/* magic number */
	rx->evt.event.connect.context = conn->connection.context;
	rx->evt.conn = conn;
	if (rx->evt.event.connect.status == CCI_SUCCESS) {
		int use_rdma = (header >> 8) & 0x1;
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init;

		vconn->state = VERBS_CONN_ESTABLISHED;
		rx->evt.event.connect.connection = &conn->connection;
		if (vconn->num_slots) {
			if (use_rdma) {
				attrs = rx->rx_pool->buf + rx->offset;
				vconn->raddr = verbs_ntohll(attrs->addr);
				vconn->rkey = ntohl(attrs->rkey);
				vconn->expected = ntohs(attrs->seqno) + 1;
			} else {
				/* TODO clean up and use Send/Recv path for sends */
			}
		}

		ret = ibv_query_qp(vconn->id->qp, &attr, IBV_QP_CAP, &init);
		if (!ret)
			vconn->inline_size = init.cap.max_inline_data;

		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&vep->conns, vconn, entry);
		pthread_mutex_unlock(&ep->lock);
	} else {
		rx->evt.event.connect.connection = NULL;
	}

	verbs_queue_evt(ep, &rx->evt);
out:
	CCI_EXIT;
	return ret;
}

static int verbs_poll_rdma_msgs(verbs_conn_t * vconn)
{
	int ret = CCI_EAGAIN, i, end, found = -1, have_token = 0;
	static int last = 0;
	cci__conn_t *conn = vconn->conn;
	cci_endpoint_t *endpoint = conn->connection.endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	void *ptr = NULL;

	pthread_mutex_lock(&ep->lock);
	if (!vconn->is_polling) {
		vconn->is_polling = 1;
		have_token = 1;
	}
	pthread_mutex_unlock(&ep->lock);

	if (!have_token) {
		CCI_EXIT;
		return EBUSY;
	}

	i = last + 1;
	if (i == vconn->num_slots)
		i = 0;
	end = i;

	do {
		if (*(vconn->slots[i])) {
			uint32_t header = ntohl(*vconn->slots[i]);
			verbs_rx_t *rx = &vconn->rxs[i];
			uint32_t len = VERBS_RSEND_LEN(header);
			uint32_t pad = len % 8 == 0 ? 0 : 8 - (len % 8);
			uint16_t seqno = 0;
			int ignore_seqno = 1;

			if (conn->connection.attribute == CCI_CONN_ATTR_RO) {
				 seqno = VERBS_RSEND_SEQNO(header);
				 ignore_seqno = 0;
			}

			debug(CCI_DB_MSG, "%s: recv'd 0x%x len %u slot %d conn %p qp %u "
				"seqno %hu expected %hu",
				__func__, header, len, i, vconn->conn,
				vconn->id->qp->qp_num, seqno, vconn->expected);

			if (ignore_seqno || seqno == vconn->expected) {
				ptr = (void *)vconn->slots[i];
				ptr -= (len + pad);
				*vconn->slots[i] = 0;
				vconn->expected++;

				found = i;

				rx->evt.event.recv.len = len;
				if (rx->evt.event.recv.len)
					rx->evt.event.request.data_ptr = ptr;
				else
					rx->evt.event.request.data_ptr = NULL;

				pthread_mutex_lock(&ep->lock);
				verbs_queue_evt_locked(ep, &rx->evt);
				while (!TAILQ_EMPTY(&vconn->early)) {
					cci__evt_t *evt = TAILQ_FIRST(&vconn->early);
					verbs_rx_t *rx = container_of(evt, verbs_rx_t, evt);
					if (rx->seqno == vconn->expected) {
						TAILQ_REMOVE(&vconn->early, evt, entry);
						TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
						vconn->expected++;
					}
				}
				pthread_mutex_unlock(&ep->lock);
			}
		}
		i++;
		if (i == vconn->num_slots)
			i = 0;
	} while (i != end);

	if (found != -1)
		last = found;

	pthread_mutex_lock(&ep->lock);
	vconn->is_polling = 0;
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static int verbs_handle_msg(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_rx_t *rx = NULL;
	void *ptr = NULL;
	int queue = 0;
	uint32_t seqno = 0;

	CCI_ENTER;

	/* find the conn for this message */
	ret = verbs_find_conn(ep, wc.qp_num, &conn);
	if (ret) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}
	vconn = conn->priv;

	if (conn->connection.attribute == CCI_CONN_ATTR_RO) {
		seqno = VERBS_SEQNO(ntohl(wc.imm_data));

		/* record incoming seqno */
		if (seqno != vconn->expected && vconn->rbuf)
			queue = 1;
		else
			vconn->expected++;
	}

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	ptr = rx->rx_pool->buf + rx->offset;

	rx->evt.conn = vconn->conn;
	rx->evt.event.type = CCI_EVENT_RECV;
	rx->evt.event.recv.connection = &vconn->conn->connection;
	rx->evt.event.recv.len = wc.byte_len;
	if (rx->evt.event.recv.len)
		rx->evt.event.request.data_ptr = ptr;
	else
		rx->evt.event.request.data_ptr = NULL;

	pthread_mutex_lock(&ep->lock);
	if (!queue) {
		verbs_queue_evt_locked(ep, &rx->evt);
	} else {
		rx->seqno = seqno;
		TAILQ_INSERT_TAIL(&vconn->early, &rx->evt, entry);
	}
	pthread_mutex_unlock(&ep->lock);
out:
	CCI_EXIT;
	return ret;
}

static int verbs_handle_rdma_msg_ack(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	int index = 0;
	uint32_t header = ntohl(wc.imm_data);
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_rx_t *rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;

	/* find the conn for this message */
	ret = verbs_find_conn(ep, wc.qp_num, &conn);
	if (ret) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}
	vconn = conn->priv;

	index = (header >> VERBS_SEQNO_SHIFT) & 0xFF;
	debug(CCI_DB_MSG, "%s: %s acked slot %d", __func__, conn->uri, index);
	i = (1 << index);

	pthread_mutex_lock(&ep->lock);
	vconn->avail |= i;
	pthread_mutex_unlock(&ep->lock);

out:
	verbs_post_rx(ep, rx);
	return ret;
}

static int verbs_handle_recv(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	uint32_t header = 0;
	verbs_msg_type_t type = 0;

	CCI_ENTER;

	header = ntohl(wc.imm_data);
	debug(CCI_DB_INFO, "recv'd header 0x%x", header);
	type = header & 0xF;	/* magic number */

	switch (type) {
	case VERBS_MSG_CONN_PAYLOAD:
		ret = verbs_handle_conn_payload(ep, wc);
		break;
	case VERBS_MSG_CONN_REPLY:
		ret = verbs_handle_conn_reply(ep, wc);
		break;
	case VERBS_MSG_SEND:
		ret = verbs_handle_msg(ep, wc);
		break;
	case VERBS_MSG_RDMA_MSG_ACK:
		ret = verbs_handle_rdma_msg_ack(ep, wc);
		break;
	default:
		debug(CCI_DB_INFO, "%s: ignoring %s msg",
		      __func__, verbs_msg_type_str(type));
		break;
	}

	CCI_EXIT;
	return ret;
}

static int verbs_complete_send_msg(cci__ep_t * ep, struct ibv_wc wc)
{
	verbs_tx_t *tx = (verbs_tx_t *) (uintptr_t) wc.wr_id;

	CCI_ENTER;

	if (!(tx->flags & CCI_FLAG_SILENT)) {
		tx->evt.event.send.status = verbs_wc_to_cci_status(wc.status);
		verbs_queue_evt(ep, &tx->evt);
	} else {
		verbs_return_tx(tx);
	}

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int verbs_complete_send(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	verbs_msg_type_t type = VERBS_MSG_INVALID;
	verbs_tx_t *tx = (verbs_tx_t *) (uintptr_t) wc.wr_id;

	CCI_ENTER;

	if (tx)
		type = tx->msg_type;
	debug(CCI_DB_MSG,
	      "%s: send completion processing for msg type %d", __func__, type);

	switch (type) {
	case VERBS_MSG_SEND:
		ret = verbs_complete_send_msg(ep, wc);
		break;
	case VERBS_MSG_CONN_REQUEST:
	case VERBS_MSG_CONN_PAYLOAD:
	case VERBS_MSG_CONN_REPLY:
		break;
	default:
		debug(CCI_DB_MSG,
		      "%s: ignoring send completion for msg type %d", __func__,
		      type);
		break;
	}

	CCI_EXIT;
	return ret;
}

static int
verbs_send_common(cci_connection_t * connection, const struct iovec *iov,
		  uint32_t iovcnt, const void *context, int flags,
		  verbs_rma_op_t * rma_op);

static int verbs_handle_rma_completion(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	verbs_rma_op_t *rma_op = (verbs_rma_op_t *) (uintptr_t) wc.wr_id;
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	rma_op->status = verbs_wc_to_cci_status(wc.status);

	if (rma_op->msg_len == 0 || rma_op->status != CCI_SUCCESS) {
queue:
		rma_op->evt.event.send.status = rma_op->status;
		if (!(rma_op->flags & CCI_FLAG_SILENT)) {
			/* we are done, queue it for the app */
			verbs_queue_evt(ep, &rma_op->evt);
		} else {
			if (rma_op->tx)
				verbs_return_tx(rma_op->tx);
			free(rma_op);
		}
	} else {
		uint32_t iovcnt = 1;
		struct iovec iov;
		cci__conn_t *conn = rma_op->evt.conn;

		iov.iov_base = rma_op->msg_ptr;
		iov.iov_len = rma_op->msg_len;
		ret = verbs_send_common(&conn->connection, &iov, iovcnt,
					rma_op->context, rma_op->flags, rma_op);
		if (ret != CCI_SUCCESS) {
			rma_op->status = ret;
			goto queue;
		}
		/* we will pass the tx completion to the app,
		 * free the rma_op now */
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&vep->rma_ops, rma_op, entry);
		pthread_mutex_unlock(&ep->lock);
		free(rma_op);
	}

	CCI_EXIT;
	return ret;
}

static int verbs_handle_send_completion(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	int queue_tx = 1;
	verbs_tx_t *tx = (verbs_tx_t *) (uintptr_t) wc.wr_id;

	CCI_ENTER;

	if (!tx)
		goto out;

	switch (tx->msg_type) {
	case VERBS_MSG_CONN_PAYLOAD:
		debug(CCI_DB_CONN, "%s: send completed of conn_payload",
		      __func__);
		break;
	case VERBS_MSG_CONN_REPLY:
		{
			cci__conn_t *conn = tx->evt.conn;
			verbs_conn_t *vconn = conn->priv;

			if (vconn->state == VERBS_CONN_CLOSED) {
				rdma_disconnect(vconn->id);
				rdma_destroy_ep(vconn->id);
				free(vconn);
				free(conn);
			} else {
				queue_tx = 0;
				verbs_queue_evt(ep, &tx->evt);
			}
		}
		break;
	case VERBS_MSG_SEND:
		debug(CCI_DB_MSG, "%s: send completed", __func__);
		ret = verbs_complete_send(ep, wc);
		if (!ret)
			queue_tx = 0;
		break;
	default:
		debug(CCI_DB_MSG, "%s: ignoring %s msg",
		      __func__, verbs_msg_type_str(tx->msg_type));
		break;
	}

	if (queue_tx) {
		verbs_return_tx(tx);
	}
out:
	CCI_EXIT;
	return ret;
}

static int verbs_get_rdma_msg_event(cci__ep_t* ep)
{
	int ret = CCI_EAGAIN;
	verbs_ep_t *vep = ep->priv;
	verbs_conn_t *vconn = NULL;

	CCI_ENTER;

	TAILQ_FOREACH(vconn, &vep->conns, entry) {
		if (vconn->raddr) {
			ret = verbs_poll_rdma_msgs(vconn);
			if (ret == CCI_SUCCESS)
				goto out;
		}
	}
out:
	return ret;

}

#define VERBS_WC_CNT	32

static int verbs_get_cq_event(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	int i = 0;
	int found = 0, success = 0;
	struct ibv_wc wc[VERBS_WC_CNT];
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	if (vep->rdma_msg_used) {
		verbs_conn_t *vconn = NULL;

		TAILQ_FOREACH(vconn, &vep->conns, entry) {
			if (vconn->raddr)
				verbs_poll_rdma_msgs(vconn);
		}
	}

	if (vep->fd && !vep->check_cq) {
		struct ibv_cq *cq;
		void *cq_ctx;

		debug(CCI_DB_MSG, "%s: checking for CQ event", __func__);
		ret = ibv_get_cq_event(vep->ib_channel, &cq, &cq_ctx);
		if (!ret) {
			vep->acks++;
			if (vep->acks == VERBS_ACK_CNT) {
				ibv_ack_cq_events(vep->cq, VERBS_ACK_CNT);
				vep->acks = 0;
			}
			debug(CCI_DB_EP, "%s: rearming cq", __func__);
			ibv_req_notify_cq(vep->cq, 0);
		} else {
			ret = errno;
			if (ret != EAGAIN)
				debug(CCI_DB_ALL, "%s: ibv_get_cq_event() returned %s (%d)",
					__func__, strerror(ret), ret);
			return ret;
		}
	}

	memset(wc, 0, sizeof(wc));	/* silence valgrind */
	ret = ibv_poll_cq(vep->cq, VERBS_WC_CNT, wc);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	found = ret;
	if (found == 0)
		ret = CCI_EAGAIN;

	debug(CCI_DB_EP, "%s: poll_cq() found %d events", __func__, found);
	success++;

	if (vep->fd)
		vep->check_cq = 1;

	for (i = 0; i < found; i++) {
		if (wc[i].status != IBV_WC_SUCCESS) {
			debug(CCI_DB_INFO, "%s wc returned with status %s",
			      wc[i].opcode & IBV_WC_RECV ? "recv" : "send",
			      ibv_wc_status_str(wc[i].status));
			/* TODO do what? */
		}
		if (wc[i].opcode & IBV_WC_RECV) {
			ret = verbs_handle_recv(ep, wc[i]);
		} else {
			switch (wc[i].opcode) {
			case IBV_WC_SEND:
				if (wc[i].status != IBV_WC_SUCCESS) {
					verbs_rma_op_t *rma_op =
					    (verbs_rma_op_t *) (uintptr_t)
					    wc[i].wr_id;
					if (rma_op->msg_type == VERBS_MSG_RMA)
						goto complete_rma;
				}
				ret = verbs_handle_send_completion(ep, wc[i]);
				break;
			case IBV_WC_RDMA_WRITE:
				{
					verbs_rma_op_t *rma_op =
					    (verbs_rma_op_t *) (uintptr_t)
					    wc[i].wr_id;
					if (rma_op->msg_type != VERBS_MSG_RMA) {
						ret =
						    verbs_handle_send_completion
						    (ep, wc[i]);
						break;
					}
				}
			case IBV_WC_RDMA_READ:
complete_rma:
				ret = verbs_handle_rma_completion(ep, wc[i]);
				break;
			default:
				debug(CCI_DB_WARN,
				      "%s: missed opcode %u status %s wr_id 0x%"
				      PRIx64, __func__, wc[i].opcode,
				      ibv_wc_status_str(wc[i].status),
				      wc[i].wr_id);
				break;
			}
		}
	}

	if (success)
		ret = CCI_SUCCESS;
out:
	CCI_EXIT;
	return ret;
}

#define VERBS_CM_EVT	0
#define VERBS_CQ_EVT	1
#define VERBS_RMSG_EVT	2

#define VERBS_EP_NUM_EVTS	(8)

static int verbs_progress_ep(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	static int which = 0;
	int try = 0;
	int token = 0;
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	if (vep->is_progressing == 0) {
		vep->is_progressing = 1;
		token = 1;
	}
	pthread_mutex_unlock(&ep->lock);

	if (!token) {
		CCI_EXIT;
		return CCI_EAGAIN;
	}

	if (vep->fd && !vep->check_cq) {
		struct epoll_event events[VERBS_EP_NUM_EVTS];

		ret = epoll_wait(vep->fd, events, VERBS_EP_NUM_EVTS, 0);
		if (ret > 0) {
			int count = ret, i, ret2;

			debug(CCI_DB_EP, "%s: epoll_wait() found %d events",
				__func__, count);
			for (i = 0; i < count; i++) {
				int (*func)(cci__ep_t*) = events[i].data.ptr;
				if (!(events[i].events & EPOLLIN)) {
					debug(CCI_DB_EP, "%s: epoll error on %s"
						" fd", __func__,
						func == (void *) verbs_get_cm_event ?
						"rdma" : func ? "ib" : "queued_ib");
				} else {
					if (!func)
						continue;
					ret2 = (*func)(ep);
					if (ret2 == CCI_SUCCESS) {
						ret = CCI_SUCCESS;
					} else {
						debug(CCI_DB_EP, "%s: %s returned %s",
							__func__,
						func == (void *) verbs_get_cm_event ?
						"rdma" : "ib",
						cci_strerror(&ep->endpoint, ret2));
					}
				}
			}
		} else if (ret == -1) {
			debug(CCI_DB_EP, "%s: epoll_wait() returned %s",
				__func__, strerror(errno));
		} else {
			if (!vep->check_cq)
				debug(CCI_DB_EP, "%s: epoll_wait() returned 0?", __func__);
		}
	} else {
again:
		try++;
		switch (which) {
		case VERBS_CM_EVT:
			ret = verbs_get_cm_event(ep);
			break;
		case VERBS_CQ_EVT:
			ret = verbs_get_cq_event(ep);
			break;
		case VERBS_RMSG_EVT:
			ret = verbs_get_rdma_msg_event(ep);
			break;
		}
		which++;
		if (which > VERBS_RMSG_EVT)
			which = VERBS_CM_EVT;
		if (ret == CCI_EAGAIN && try < 3)
			goto again;
	}

	pthread_mutex_lock(&ep->lock);
	vep->is_progressing = 0;
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__evt_t *e = NULL;
	cci__evt_t *ev = NULL;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_progress_ep(ep);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(e, &ep->evts, entry) {
		if (e->event.type == CCI_EVENT_SEND) {
			/* NOTE: if it is blocking, skip it since sendv()
			 *       is waiting on it
			 */
			verbs_tx_t *tx = container_of(e, verbs_tx_t, evt);
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
		char one = 0;
		verbs_ep_t *vep = ep->priv;

		TAILQ_REMOVE(&ep->evts, ev, entry);
		if (vep->fd && TAILQ_EMPTY(&ep->evts)) {
			debug(CCI_DB_EP, "%s: reading from pipe", __func__);
			read(vep->pipe[0], &one, 1);
			assert(one == 1);
		}
	} else {
		ret = CCI_EAGAIN;
	}

	pthread_mutex_unlock(&ep->lock);

	*event = &ev->event;

	CCI_EXIT;
	return ret;
}

static int verbs_return_conn_request(cci_event_t * event)
{
	int ret = CCI_SUCCESS;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);
	verbs_rx_t *rx = container_of(evt, verbs_rx_t, evt);
	cci__conn_t *conn = evt->conn;
	verbs_conn_t *vconn = conn->priv;
	cci__ep_t *ep = evt->ep;

	CCI_ENTER;

	if (vconn->conn_req) {
		if (vconn->conn_req->len) {
			assert(vconn->conn_req->ptr);
			free(vconn->conn_req->ptr);
		}
		free(vconn->conn_req);
		vconn->conn_req = NULL;
	}

	ret = verbs_post_rx(ep, rx);

	CCI_EXIT;
	return ret;
}

static int ctp_verbs_return_event(cci_event_t * event)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	switch (event->type) {
	case CCI_EVENT_CONNECT_REQUEST:
		ret = verbs_return_conn_request(event);
		break;
	case CCI_EVENT_CONNECT:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			cci__conn_t *conn = evt->conn;
			verbs_conn_t *vconn = conn->priv;
			cci__ep_t *ep = evt->ep;
			verbs_rx_t *rx = container_of(evt, verbs_rx_t, evt);

			if (event->connect.status != CCI_SUCCESS) {
				/* TODO if RDMA MSGs requested, clean up as well */
				rdma_disconnect(vconn->id);
				rdma_destroy_ep(vconn->id);
				free(vconn);
				free(conn);
			}

			ret = verbs_post_rx(ep, rx);
			if (ret) {
				ret = errno;
				debug(CCI_DB_MSG, "%s: post_rx() returned %s",
				      __func__, strerror(ret));
			}
		}
		break;
	case CCI_EVENT_ACCEPT:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			verbs_tx_t *tx = NULL;

			tx = container_of(evt, verbs_tx_t, evt);
			verbs_return_tx(tx);
		}
		break;
	case CCI_EVENT_RECV:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			cci__ep_t *ep = evt->ep;
			verbs_rx_t *rx = container_of(evt, verbs_rx_t, evt);

			if (rx->rx_pool) {
				ret = verbs_post_rx(ep, rx);
				if (ret) {
					ret = errno;
					debug(CCI_DB_MSG,
					      "%s: post_rx() returned %s",
					      __func__, strerror(ret));
				}
			} else if (rx->evt.conn) {
				uint32_t header = VERBS_MSG_RDMA_MSG_ACK;
				header |= ((rx->offset) << VERBS_SEQNO_SHIFT);
				verbs_post_send(rx->evt.conn, 0, NULL, 0,
						header);
			}
		}
		break;
	case CCI_EVENT_SEND:
		{
			cci__evt_t *evt =
			    container_of(event, cci__evt_t, event);
			cci__ep_t *ep = evt->ep;
			verbs_ep_t *vep = ep->priv;
			verbs_tx_t *tx = NULL;

			if (evt->priv) {
				verbs_rma_op_t *rma_op = evt->priv;

				pthread_mutex_lock(&ep->lock);
				TAILQ_REMOVE(&vep->rma_ops, rma_op, entry);
				pthread_mutex_unlock(&ep->lock);
				free(rma_op);
			} else {
				tx = container_of(evt, verbs_tx_t, evt);
				verbs_return_tx(tx);
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
verbs_send_common(cci_connection_t * connection, const struct iovec *iov,
		  uint32_t iovcnt, const void *context, int flags,
		  verbs_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	int is_reliable = 0;
	int pad = 0;
	uint32_t len = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__conn_t *conn = NULL;
	cci__ep_t *ep = NULL;
	verbs_ep_t *vep = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_tx_t *tx = NULL;
	uint32_t header = VERBS_MSG_SEND;
	void *ptr = NULL;

	CCI_ENTER;

	if (!vglobals) {
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
	vep = ep->priv;
	conn = container_of(connection, cci__conn_t, connection);
	vconn = conn->priv;

	if (vconn->state == VERBS_CONN_CLOSED)
		return CCI_ERR_DISCONNECTED;

	//verbs_progress_ep(ep);

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	if (!(rma_op && rma_op->tx)) {
		tx = verbs_get_tx(ep);
		if (!tx) {
			debug(CCI_DB_MSG, "%s: no txs", __func__);
			CCI_EXIT;
			return CCI_ENOBUFS;
		}
	} else {
		tx = rma_op->tx;
	}

	/* tx bookkeeping */
	tx->msg_type = VERBS_MSG_SEND;
	tx->flags = flags;
	tx->rma_op = rma_op;	/* only set if RMA completion msg */

	/* setup generic CCI event */
	tx->evt.conn = conn;
	tx->evt.ep = ep;
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = (void *)context;
	tx->evt.event.send.status = CCI_SUCCESS;	/* for now */
	tx->rdma_slot = -1;

	pthread_mutex_lock(&ep->lock);
	if (connection->attribute == CCI_CONN_ATTR_RO) {
		vconn->seqno++;
		header |= vconn->seqno << VERBS_SEQNO_SHIFT;
	}

	if (vconn->raddr) {
		if (vconn->avail) {
			int old;

			i = vconn->last + 1;
			if (i == vconn->num_slots)
				i = 0;
			old = i;
			do {
				if ((1 << i) & vconn->avail) {
					vconn->last = i;
					break;
				}
				i++;
				if (i == vconn->num_slots)
					i = 0;
			} while (i != old);
			vconn->avail &= ~(1 << i);
			tx->rdma_slot = i;
			debug(CCI_DB_MSG, "%s: using RDMA slot %d", __func__, i);
			pad = len & 0x7 ? 8 - (len & 0x7) : 0;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	/* always copy into tx's buffer */
	if (len) {
		if (((len > (vconn->inline_size - 4 - pad)) || iovcnt != 1)
			&& !(rma_op && rma_op->tx)) {
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

	ret = verbs_post_send(conn, (uintptr_t) tx, ptr, tx->len, header);
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
			verbs_return_tx(tx);
		}
	}

out:
	if (ret) {
		verbs_return_tx(tx);
	}
	CCI_EXIT;
	return ret;
}

static int ctp_verbs_send(cci_connection_t * connection,	/* magic number */
		      const void *msg_ptr, uint32_t msg_len,
		      const void *context, int flags)
{
	int ret = CCI_SUCCESS;
	uint32_t iovcnt = 0;
	struct iovec iov = { NULL, 0 };

	CCI_ENTER;

	if (msg_ptr && msg_len > 0) {
		iovcnt = 1;
		iov.iov_base = (void *)msg_ptr;
		iov.iov_len = msg_len;
	}

	ret = verbs_send_common(connection, &iov, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_sendv(cci_connection_t * connection,
	    const struct iovec *data, uint32_t iovcnt, const void *context,
	    int flags)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	ret = verbs_send_common(connection, data, iovcnt, context, flags, NULL);

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_rma_register(cci_endpoint_t * endpoint,
		   void *start, uint64_t length,
		   int flags, cci_rma_handle_t ** rma_handle)
{
	/* FIXME use read/write flags? */
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;
	verbs_rma_handle_t *handle = NULL;

	CCI_ENTER;

	if (!vglobals) {
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

	handle->mr = ibv_reg_mr(vep->pd, start, (size_t) length,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_WRITE |
				IBV_ACCESS_REMOTE_READ);
	if (!handle->mr) {
		free(handle);
		CCI_EXIT;
		return CCI_ERROR;
	}

	*((uint64_t*)&handle->rma_handle.stuff[0]) =
		verbs_htonll((uintptr_t)handle->mr->addr);
	*((uint64_t*)&handle->rma_handle.stuff[1]) =
		verbs_htonll((uint64_t)handle->mr->rkey);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = &handle->rma_handle;

	CCI_EXIT;
	return ret;
}

static int ctp_verbs_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	int ret = CCI_SUCCESS;
	verbs_rma_handle_t *handle = container_of(rma_handle, verbs_rma_handle_t, rma_handle);
	cci__ep_t *ep = handle->ep;
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&vep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = ibv_dereg_mr(handle->mr);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_WARN, "%s: ibv_dereg_mr() returned %s",
		      __func__, strerror(ret));
	}

	free(handle);

	CCI_EXIT;
	return ret;
}

static int verbs_post_rma(verbs_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = rma_op->evt.conn;
	verbs_conn_t *vconn = conn->priv;
	verbs_rma_handle_t *local =
		container_of(rma_op->local_handle, verbs_rma_handle_t, rma_handle);
	struct ibv_sge list;
	struct ibv_send_wr wr, *bad_wr;

	CCI_ENTER;

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
	    rma_op->flags & CCI_FLAG_WRITE ? IBV_WR_RDMA_WRITE :
	    IBV_WR_RDMA_READ;
	wr.send_flags = IBV_SEND_SIGNALED;
	if ((rma_op->flags & CCI_FLAG_WRITE)
	    && (rma_op->len && (rma_op->len <= vconn->inline_size)))
		wr.send_flags |= IBV_SEND_INLINE;
	if (rma_op->flags & CCI_FLAG_FENCE)
		wr.send_flags |= IBV_SEND_FENCE;
	wr.wr.rdma.remote_addr =
		verbs_ntohll(rma_op->remote_handle->stuff[0]) + rma_op->remote_offset;
	wr.wr.rdma.rkey = (uint32_t) verbs_ntohll(rma_op->remote_handle->stuff[1]);

	ret = ibv_post_send(vconn->id->qp, &wr, &bad_wr);
	if (ret == -1)
		ret = errno;

	CCI_EXIT;
	return ret;
}

static int
ctp_verbs_rma(cci_connection_t * connection,
	  const void *msg_ptr, uint32_t msg_len,
	  cci_rma_handle_t * local_handle, uint64_t local_offset,
	  cci_rma_handle_t * remote_handle, uint64_t remote_offset,
	  uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	verbs_ep_t *vep = NULL;
	verbs_rma_handle_t *local = container_of(local_handle, verbs_rma_handle_t, rma_handle);
	verbs_rma_op_t *rma_op = NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	conn = container_of(connection, cci__conn_t, connection);
	ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	vep = ep->priv;

	if (!local || local->ep != ep) {
		CCI_EXIT;
		return CCI_EINVAL;
	}

	rma_op = calloc(1, sizeof(*rma_op));
	if (!rma_op) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	rma_op->msg_type = VERBS_MSG_RMA;
	rma_op->local_handle = local_handle;
	rma_op->local_offset = local_offset;
	rma_op->remote_handle = remote_handle;
	rma_op->remote_offset = remote_offset;
	rma_op->len = data_len;
	rma_op->context = (void *)context;
	rma_op->flags = flags;
	rma_op->msg_len = 0;
	rma_op->msg_ptr = NULL;

	rma_op->evt.event.type = CCI_EVENT_SEND;
	rma_op->evt.event.send.connection = connection;
	rma_op->evt.event.send.context = (void *)context;
	rma_op->evt.event.send.status = CCI_SUCCESS;	/* for now */
	rma_op->evt.ep = ep;
	rma_op->evt.conn = conn;
	rma_op->evt.priv = rma_op;

	if (msg_ptr && msg_len) {
		rma_op->tx = verbs_get_tx(ep);
		if (!rma_op->tx) {
			ret = CCI_ENOBUFS;
			goto out;
		}
		memcpy(rma_op->tx->buffer, msg_ptr, msg_len);
		rma_op->msg_ptr = rma_op->tx->buffer;
		rma_op->msg_len = msg_len;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = verbs_post_rma(rma_op);
	if (ret) {
		/* FIXME clean up? */
	}

out:
	if (ret)
		free(rma_op);

	CCI_EXIT;
	return ret;
}
