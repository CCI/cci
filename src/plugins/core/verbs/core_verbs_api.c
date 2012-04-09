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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_verbs.h"

volatile int verbs_shut_down = 0;
volatile verbs_globals_t *vglobals = NULL;
pthread_t progress_tid;

/*
 * Local functions
 */
static int verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int verbs_finalize(void);
static const char *verbs_strerror(cci_endpoint_t * endpoint,
				  enum cci_status status);
static int verbs_get_devices(cci_device_t * const **devices);
static int verbs_create_endpoint(cci_device_t * device,
				 int flags,
				 cci_endpoint_t ** endpoint,
				 cci_os_handle_t * fd);
static int verbs_destroy_endpoint(cci_endpoint_t * endpoint);
static int verbs_accept(cci_event_t * event, const void *context);
static int verbs_reject(cci_event_t * event);
static int verbs_connect(cci_endpoint_t * endpoint, const char *server_uri,
			 const void *data_ptr, uint32_t data_len,
			 cci_conn_attribute_t attribute,
			 const void *context, int flags,
			 const struct timeval *timeout);
static int verbs_disconnect(cci_connection_t * connection);
static int verbs_set_opt(cci_opt_handle_t * handle,
			 cci_opt_level_t level,
			 cci_opt_name_t name, const void *val, int len);
static int verbs_get_opt(cci_opt_handle_t * handle,
			 cci_opt_level_t level,
			 cci_opt_name_t name, void **val, int *len);
static int verbs_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int verbs_get_event(cci_endpoint_t * endpoint,
			   cci_event_t ** const event);
static int verbs_return_event(cci_event_t * event);
static int verbs_send(cci_connection_t * connection,
		      const void *msg_ptr, uint32_t msg_len,
		      const void *context, int flags);
static int verbs_sendv(cci_connection_t * connection,
		       const struct iovec *data, uint32_t iovcnt,
		       const void *context, int flags);
static int verbs_rma_register(cci_endpoint_t * endpoint,
			      cci_connection_t * connection,
			      void *start, uint64_t length,
			      uint64_t * rma_handle);
static int verbs_rma_deregister(uint64_t rma_handle);
static int verbs_rma(cci_connection_t * connection,
		     void *msg_ptr, uint32_t msg_len,
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
cci_plugin_core_t cci_core_verbs_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CORE_API_VERSION,
	 "verbs",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 10,

	 /* Bootstrap function pointers */
	 cci_core_verbs_post_load,
	 cci_core_verbs_pre_unload,
	 },

	/* API function pointers */
	verbs_init,
	verbs_finalize,
	verbs_strerror,
	verbs_get_devices,
	verbs_create_endpoint,
	verbs_destroy_endpoint,
	verbs_accept,
	verbs_reject,
	verbs_connect,
	verbs_disconnect,
	verbs_set_opt,
	verbs_get_opt,
	verbs_arm_os_handle,
	verbs_get_event,
	verbs_return_event,
	verbs_send,
	verbs_sendv,
	verbs_rma_register,
	verbs_rma_deregister,
	verbs_rma
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
	uint64_t rate = 2500000000ULL;	/* 2.5 Gbps */

	rate *= attr.active_speed;

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
	default:
		ret = EIO;
	}

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
	int i, j;
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
		goto out;
	}

	for (i = j = 0; i < count; i++) {
		struct ibv_context *c = contexts[i];
		//char ip[256];

		for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
			if (tmp->ifa_addr->sa_family == AF_INET &&
			    !(tmp->ifa_flags & IFF_LOOPBACK)) {
				ret = verbs_ifa_to_context(c, tmp->ifa_addr);
				if (!ret) {
					int len = sizeof(struct sockaddr);
					addrs[j].ifa_name =
					    strdup(tmp->ifa_name);
					addrs[j].ifa_flags = tmp->ifa_flags;
					addrs[j].ifa_addr = calloc(1, len);
					memcpy(addrs[j].ifa_addr, tmp->ifa_addr,
					       len);
					addrs[j].ifa_netmask = calloc(1, len);
					memcpy(addrs[j].ifa_netmask,
					       tmp->ifa_netmask, len);
					addrs[j].ifa_broadaddr = calloc(1, len);
					memcpy(addrs[j].ifa_broadaddr,
					       tmp->ifa_broadaddr, len);
					j++;
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

static int verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int count = 0;
	int index = 0;
	int used[CCI_MAX_DEVICES];
	int ret = 0;
	cci__dev_t *dev = NULL;
	struct cci_device **devices = NULL;
	struct ifaddrs *ifaddrs = NULL;

	CCI_ENTER;

	memset(used, 0, CCI_MAX_DEVICES);

	/* init driver globals */
	vglobals = calloc(1, sizeof(*vglobals));
	if (!vglobals) {
		ret = CCI_ENOMEM;
		goto out;
	}

	devices = calloc(CCI_MAX_DEVICES, sizeof(*vglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	vglobals->contexts = rdma_get_devices(&count);
	if (!vglobals->contexts) {
		ret = -errno;
		goto out;
	}
	vglobals->count = count;

	/* for each ifaddr, check if it is a RDMA device */
	ret = verbs_find_rdma_devices(vglobals->contexts, count, &ifaddrs);
	if (ret) {
		/* TODO */
		ret = CCI_ENODEV;
		goto out;
	}
	vglobals->ifaddrs = ifaddrs;

/* FIXME: if configfile == 0, create default devices */

	/* find devices we own */
	TAILQ_FOREACH(dev, &globals->devs, entry) {
		if (0 == strcmp("verbs", dev->driver)) {
			int i = 0;
			const char *const *arg;
			const char *hca_id = NULL;
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
				} else if (0 == strncmp("hca_id=", *arg, 7)) {
					hca_id = *arg + 7;
				} else if (0 == strncmp("interface=", *arg, 10)) {
					interface = *arg + 10;
				} else if (0 == strncmp("driver=", *arg, 7)) {
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
				} else if (hca_id) {
					if (0 ==
					    strcmp(hca_id, ctx->device->name)) {
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

			devices[index] = device;
			index++;
			dev->is_up = vdev->ifa->ifa_flags & IFF_UP;
		}
	}

	devices =
	    realloc(devices, (vglobals->count + 1) * sizeof(cci_device_t *));
	devices[vglobals->count] = NULL;

	vglobals->devices = devices;

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

static const char *verbs_strerror(cci_endpoint_t * endpoint,
				  enum cci_status status)
{
	return strerror(status);
}

static int verbs_get_devices(cci_device_t * const **devices)
{
	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

/* FIXME: update the devices list (up field, ...).
   add new devices if !configfile */

	*devices = (cci_device_t * const *)vglobals->devices;

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int verbs_finalize(void)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	pthread_mutex_lock(&globals->lock);
	verbs_shut_down = 1;
	pthread_mutex_unlock(&globals->lock);
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

	pthread_mutex_lock(&globals->lock);
	TAILQ_FOREACH(dev, &globals->devs, entry)
	    if (dev->priv)
		free(dev->priv);
	pthread_mutex_unlock(&globals->lock);

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

	if (posted == 0) {
		if (tx_pool->mr) {
			int rc = CCI_SUCCESS;
			rc = ibv_dereg_mr(tx_pool->mr);
			if (rc) {
				debug(CCI_DB_WARN,
				      "deregistering new endpoint tx_mr "
				      "failed with %s\n", strerror(ret));
			}
		}
		if (tx_pool->buf)
			free(tx_pool->buf);

		pthread_mutex_destroy(&tx_pool->lock);

		free(tx_pool);
	} else {
		debug(CCI_DB_INFO,
		      "tx_pool could not be destroyed to do "
		      "%d outstanding messages\n", tx_pool->posted);
		ret = CCI_EAGAIN;
	}

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
	//struct cma_id_private *id_priv;

	if (id->qp)
		rdma_destroy_qp(id);

	rdma_destroy_id(id);
}
#endif /* HAVE_RDMA_ADDRINFO */

static int
verbs_create_endpoint(cci_device_t * device,
		      int flags,
		      cci_endpoint_t ** endpointp, cci_os_handle_t * fd)
{
	int ret = CCI_SUCCESS;
	int fflags = 0;
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

	endpoint->max_recv_buffer_count = VERBS_EP_RX_CNT;
	ep->rx_buf_cnt = VERBS_EP_RX_CNT;
	ep->tx_buf_cnt = VERBS_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0;	/* FIXME */

	vep->channel = rdma_create_event_channel();
	if (!vep->channel) {
		ret = errno;
		goto out;
	}

	fflags = fcntl(vep->channel->fd, F_GETFL, 0);
	if (fflags == -1) {
		ret = errno;
		goto out;
	}

	ret = fcntl(vep->channel->fd, F_SETFL, fflags | O_NONBLOCK);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = rdma_create_id(vep->channel, &vep->id_rc, ep, RDMA_PS_TCP);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = rdma_create_id(vep->channel, &vep->id_ud, ep, RDMA_PS_UDP);
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
	endpoint->name = strdup(name);

	vep->pd = ibv_alloc_pd(vdev->context);
	if (!vep->pd) {
		ret = errno;
		goto out;
	}

	vep->cq_size = VERBS_EP_CQ_CNT;
	vep->cq = ibv_create_cq(vdev->context, vep->cq_size, ep, NULL, 0);
	if (!vep->cq) {
		ret = errno;
		goto out;
	}

	ret = verbs_create_tx_pool(ep, ep->tx_buf_cnt);

	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.attr.max_wr = ep->rx_buf_cnt;
	srq_attr.attr.max_sge = 1;
	vep->srq = ibv_create_srq(vep->pd, &srq_attr);
	if (!vep->srq) {
		ret = errno;
		goto out;
	}

	vep->rdma_msg_total = VERBS_EP_RMSG_CONNS;
	ret = verbs_create_rx_pool(ep, ep->rx_buf_cnt);
	if (ret)
		goto out;

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	/* TODO lots of clean up */
	if (ep->priv) {
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
				ret = ibv_dereg_mr(rx_pool->mr);
				if (ret)
					debug(CCI_DB_WARN,
					      "deregistering endpoint rx_mr "
					      "failed with %s\n",
					      strerror(ret));
			}
			if (rx_pool->buf)
				free(rx_pool->buf);
		}

		if (vep->tx_pool != NULL) {
			verbs_destroy_tx_pool(vep->tx_pool);
			vep->tx_pool = NULL;
		}

		if (vep->cq) {
			ret = ibv_destroy_cq(vep->cq);
			if (ret)
				debug(CCI_DB_WARN, "destroying new endpoint cq "
				      "failed with %s\n", strerror(ret));
		}

		if (vep->pd) {
			ret = ibv_dealloc_pd(vep->pd);
			if (ret)
				debug(CCI_DB_WARN, "deallocing new endpoint pd "
				      "failed with %s\n", strerror(ret));
		}

		if (vep->id_rc)
			rdma_destroy_ep(vep->id_rc);

		if (vep->id_ud)
			rdma_destroy_ep(vep->id_ud);

		if (vep->channel)
			rdma_destroy_event_channel(vep->channel);

		free(vep);
		ep->priv = NULL;
	}
	return ret;
}

static int verbs_get_cq_event(cci__ep_t * ep);

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

static int verbs_destroy_endpoint(cci_endpoint_t * endpoint)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	while (!TAILQ_EMPTY(&vep->conns)) {
		cci__conn_t *conn = NULL;
		verbs_conn_t *vconn = NULL;

		vconn = TAILQ_FIRST(&vep->conns);
		conn = vconn->conn;
		verbs_disconnect(&conn->connection);
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

	if (vep->id_rc)
		rdma_destroy_id(vep->id_rc);

	if (vep->id_ud)
		rdma_destroy_id(vep->id_ud);

	if (vep->channel)
		rdma_destroy_event_channel(vep->channel);

	if (vep->pd) {
		do {
			ret = ibv_dealloc_pd(vep->pd);
		} while (ret == EBUSY);
	}

	free(vep);

	if (ep->endpoint.name) {
		free((char *)ep->endpoint.name);
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
	case VERBS_MSG_RMA_REMOTE_REQUEST:
		str = "rma_remote_request";
		break;
	case VERBS_MSG_RMA_REMOTE_REPLY:
		str = "rma_remote_reply";
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
	int rdma_send = VERBS_MSG_SEND | (1 << 4);
	int use_rdma = header == rdma_send ? 1 : 0;
	uint32_t orig_len = len;

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	vep = ep->priv;

	debug(CCI_DB_MSG, "sending msg 0x%x", header);

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

			uint32_t slot = (header >> 21) & 0xFF;
			uint32_t h2 = header;
			uint32_t pad = len % 8 == 0 ? 0 : 8 - (len % 8);
			uint64_t addr = vconn->raddr;

			h2 |= (orig_len << 5);
			h2 |= (1 << 31);	/* set highest bit to make sure
						   we can poll on last byte
						   when swapped to net order */

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
			} else if (len < vconn->inline_size - 4) {
				/* SEND_INLINE must be used */
				debug(CCI_DB_MSG, "adding second list[1]");
				list[0].length += pad;
				list[1].addr = (uintptr_t) & h2;
				list[1].length = 4;	/* we will fix below */
				wr.num_sge = 2;
			} else {
				/* need to copy to registered buffer */
				debug(CCI_DB_MSG, "copying header to buffer");
				memcpy(buffer + len, &h2, 4);
				list[0].length = len + 4;	/* header after message */
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
	if (vconn->inline_size && (len <= vconn->inline_size - 4))
		wr.send_flags |= IBV_SEND_INLINE;

	ret = ibv_post_send(vconn->id->qp, &wr, &bad_wr);
	if (ret == -1) {
		ret = errno;
		debug(CCI_DB_CONN,
		      "unable to send id 0x%" PRIx64
		      " buffer %p len %u header %u", id, buffer, len, header);
	}
	CCI_EXIT;
	return ret;
}

static int verbs_accept(cci_event_t * event, const void *context)
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
		uint64_t addr;
		uint32_t rkey;

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

		len = 12;	/* magic number => uint64_t + uint32_t */
		addr = verbs_htonll((uintptr_t) vconn->rmr->addr);
		memcpy(tx->buffer, &addr, sizeof(addr));
		rkey = htonl(vconn->rmr->rkey);
		memcpy(tx->buffer + (uintptr_t) sizeof(addr), &rkey,
		       sizeof(rkey));
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

static int verbs_reject(cci_event_t * event)
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
verbs_connect(cci_endpoint_t * endpoint, const char *server_uri,
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

	conn->priv = calloc(1, sizeof(*vconn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	vconn = conn->priv;
	vconn->conn = conn;
	TAILQ_INIT(&vconn->remotes);
	TAILQ_INIT(&vconn->rma_ops);

	if (context || data_len) {
		cr = calloc(1, sizeof(*cr));
		if (!cr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		vconn->conn_req = cr;

		cr->context = (void *)context;
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
	conn->connection.context = (void *)context;

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
		debug(CCI_DB_ALL,
		      "not using rdma_create_ep() or rdma_getaddrinfo()");

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
		    rdma_create_id(vep->channel, &vconn->id, NULL, RDMA_PS_TCP);
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
				ret = rdma_get_cm_event(vep->channel, &event);
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

	ret = rdma_migrate_id(vconn->id, vep->channel);
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

static int verbs_disconnect(cci_connection_t * connection)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	verbs_conn_t *vconn = conn->priv;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&vep->conns, vconn, entry);
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

	free(vconn);
	free(conn);

	CCI_EXIT;
	return ret;
}

static int
verbs_set_opt(cci_opt_handle_t * handle,
	      cci_opt_level_t level,
	      cci_opt_name_t name, const void *val, int len)
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

	endpoint = handle->endpoint;
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
			uint32_t new_count;
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

			if (len != sizeof(new_count)) {
				ret = CCI_EINVAL;
				break;
			}
			memcpy(&new_count, val, len);

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
			uint32_t new_count;
			/* get the requested value from the parameters and create a local copy */
			if (len != sizeof(new_count)) {
				ret = CCI_EINVAL;
				break;
			}
			memcpy(&new_count, val, len);

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

			// TODO: this could yank memory out from under someone, need 
			//  to fix this, probably by doing the 
			ret = verbs_destroy_tx_pool(vep->tx_pool_old);
			vep->tx_pool_old = NULL;

			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			uint32_t new_time;

			if (len != sizeof(new_time)) {
				ret = CCI_EINVAL;
				break;
			}
			memcpy(&new_time, val, len);

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
verbs_get_opt(cci_opt_handle_t * handle,
	      cci_opt_level_t level, cci_opt_name_t name, void **val, int *len)
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

	endpoint = handle->endpoint;
	ep = container_of(endpoint, cci__ep_t, endpoint);
	vep = ep->priv;
	dev = ep->dev;
	vdev = dev->priv;

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
	case CCI_OPT_CONN_SEND_TIMEOUT:
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			*len = sizeof(ep->rx_buf_cnt);
			*val = malloc(*len);
			if (!val) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(*val, &ep->rx_buf_cnt, *len);
			ret = CCI_SUCCESS;
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			*len = sizeof(ep->tx_buf_cnt);
			*val = malloc(*len);
			if (!val) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(*val, &ep->tx_buf_cnt, *len);
			ret = CCI_SUCCESS;
			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			*len = sizeof(ep->keepalive_timeout);
			*val = malloc(*len);
			if (!val) {
				ret = CCI_ENOMEM;
				goto out;
			}
			memcpy(*val, &ep->keepalive_timeout, *len);

			ret = CCI_SUCCESS;
			break;
		}
	default:
		debug(CCI_DB_INFO, "unknown option %u",
		      (enum cci_opt_name)name);
		ret = CCI_EINVAL;
	}
out:
	CCI_EXIT;
	return ret;
}

static int verbs_arm_os_handle(cci_endpoint_t * endpoint, int flags)
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
	TAILQ_INIT(&vconn->remotes);
	TAILQ_INIT(&vconn->rma_ops);

	conn->connection.endpoint = &ep->endpoint;

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
	if (vep->rdma_msg_used < vep->rdma_msg_total) {
		vep->rdma_msg_used++;
		need_rdma = 1;
	}
	pthread_mutex_unlock(&ep->lock);

	tx = verbs_get_tx(ep);

	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->evt.event.type = CCI_EVENT_NONE;	/* never hand to application */
	tx->evt.conn = conn;

	if (need_rdma) {
		int i;
		verbs_rx_t *rx;
		uint64_t addr;
		uint32_t rkey;

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

		len = 12;	/* magic number => uint64_t + uint32_t */
		addr = verbs_htonll((uintptr_t) vconn->rmr->addr);
		memcpy(tx->buffer, &addr, sizeof(addr));
		rkey = htonl(vconn->rmr->rkey);
		memcpy(tx->buffer + (uintptr_t) sizeof(addr), &rkey,
		       sizeof(rkey));
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
	assert(vconn->state == VERBS_CONN_ACTIVE
	       || vconn->state == VERBS_CONN_PASSIVE);

	switch (vconn->state) {
	case VERBS_CONN_ACTIVE:
		ret = verbs_conn_est_active(ep, cm_evt);
		break;
	case VERBS_CONN_PASSIVE:
		ret = verbs_conn_est_passive(ep, cm_evt);
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

	ret = rdma_get_cm_event(vep->channel, &cm_evt);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	switch (cm_evt->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = verbs_handle_conn_request(ep, cm_evt);
		if (ret)
			debug(CCI_DB_INFO, "%s: verbs_handle_conn_request()"
			      "returned %s", __func__, strerror(ret));
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		ret = verbs_handle_conn_established(ep, cm_evt);
		if (ret)
			debug(CCI_DB_INFO, "%s: verbs_handle_conn_established()"
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
	    (need_rdma && (len != (wc.byte_len - 12))))
		debug(CCI_DB_WARN, "%s: len %u != wc.byte_len %u",
		      __func__, len, wc.byte_len);

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	rx->evt.conn = conn;
	rx->evt.event.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.event.request.attribute = conn->connection.attribute;
	ptr = rx->rx_pool->buf + rx->offset;
	if (need_rdma) {
		len -= 12;	/* magic number => uint64_t + uint32_t */
		ptr = ptr + (uintptr_t) 12;
		vconn->num_slots = VERBS_CONN_RMSG_DEPTH;	/* indicate peer wants RDMA */

		vconn->raddr = *((uint64_t *) (rx->rx_pool->buf + rx->offset));
		vconn->raddr = verbs_ntohll(vconn->raddr);
		vconn->rkey =
		    *((uint32_t *) (rx->rx_pool->buf + rx->offset + 8));
		vconn->rkey = ntohl(vconn->rkey);
	}
	*((uint32_t *) & rx->evt.event.request.data_len) = len;
	if (len)
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

static int verbs_handle_conn_reply(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	uint32_t header = 0;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_conn_t *vc = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_rx_t *rx = NULL;

	CCI_ENTER;

	/* find the active conn waiting for this message */
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(vc, &vep->active, temp) {
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

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	rx->evt.event.type = CCI_EVENT_CONNECT;
	rx->evt.event.connect.status = (header >> 4) & 0xF;	/* magic number */
	rx->evt.event.connect.context =
	    vconn->conn_req ? vconn->conn_req->context : NULL;
	rx->evt.conn = conn;
	if (rx->evt.event.connect.status == CCI_SUCCESS) {
		int use_rdma = (header >> 8) & 0x1;
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init;

		vconn->state = VERBS_CONN_ESTABLISHED;
		rx->evt.event.connect.connection = &conn->connection;
		if (vconn->num_slots) {
			if (use_rdma) {
				vconn->raddr =
				    *((uint64_t *) (rx->rx_pool->buf +
						    rx->offset));
				vconn->raddr = verbs_ntohll(vconn->raddr);
				vconn->rkey =
				    *((uint32_t *) (rx->rx_pool->buf +
						    rx->offset + 8));
				vconn->rkey = ntohl(vconn->rkey);
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

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

out:
	CCI_EXIT;
	return ret;
}

static verbs_conn_t *verbs_qp_num_to_conn(cci__ep_t * ep, uint32_t qp_num)
{
	verbs_ep_t *vep = ep->priv;
	verbs_conn_t *vconn = NULL;
	verbs_conn_t *vc = NULL;

	CCI_ENTER;

	/* find the conn for this QP */
	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(vc, &vep->conns, temp) {
		if (vc->id->qp->qp_num == qp_num) {
			vconn = vc;
			assert(vconn->conn == vc->id->context);
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return vconn;
}

static int verbs_poll_rdma_msgs(verbs_conn_t * vconn)
{
	int ret = CCI_EAGAIN;
	int i = 0;
	cci__conn_t *conn = vconn->conn;
	cci_endpoint_t *endpoint = conn->connection.endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	void *ptr = NULL;

	for (i = 0; i < vconn->num_slots; i++) {
		if (*(vconn->slots[i])) {
			uint32_t header = ntohl(*vconn->slots[i]);
			verbs_rx_t *rx = &vconn->rxs[i];
			uint32_t len = (header >> 5) & 0xFFFF;
			uint32_t pad = len % 8 == 0 ? 0 : 8 - (len % 8);

			debug(CCI_DB_MSG, "%s: recv'd 0x%x len %u slot %d",
			      __func__, header, len, i);

			//ptr = vconn->rbuf + (uintptr_t)(((i + 1) * (vconn->mss + 4)) - 4);
			ptr = (void *)vconn->slots[i];
			ptr -= (len + pad);
			*vconn->slots[i] = 0;

			*((uint32_t *) & rx->evt.event.recv.len) = len;
			if (rx->evt.event.recv.len)
				*((void **)&rx->evt.event.request.data_ptr) =
				    ptr;
			else
				*((void **)&rx->evt.event.request.data_ptr) =
				    NULL;

			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
			pthread_mutex_unlock(&ep->lock);
			return CCI_SUCCESS;
		}
	}

	return ret;
}

static int verbs_handle_msg(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	verbs_conn_t *vconn = NULL;
	verbs_rx_t *rx = NULL;
	void *ptr = NULL;

	CCI_ENTER;

	/* find the conn for this message */
	vconn = verbs_qp_num_to_conn(ep, wc.qp_num);
	if (!vconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;
	ptr = rx->rx_pool->buf + rx->offset;

	rx->evt.conn = vconn->conn;
	rx->evt.event.type = CCI_EVENT_RECV;
	rx->evt.event.recv.connection = &vconn->conn->connection;
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

static int verbs_handle_rdma_msg_ack(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	int i = 0;
	int index = 0;
	uint32_t header = ntohl(wc.imm_data);
	verbs_conn_t *vconn = NULL;
	verbs_rx_t *rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;

	/* find the conn for this message */
	vconn = verbs_qp_num_to_conn(ep, wc.qp_num);
	if (!vconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		goto out;
	}

	index = (header >> 21) & 0xFF;
	i = (1 << index);

	pthread_mutex_lock(&ep->lock);
	vconn->avail |= i;
	pthread_mutex_unlock(&ep->lock);

out:
	verbs_post_rx(ep, rx);
	return ret;
}

static int verbs_handle_rma_remote_request(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = NULL;
	verbs_conn_t *vconn = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_rma_handle_t *handle = NULL;
	verbs_rma_handle_t *h = NULL;
	verbs_rx_t *rx = NULL;
	verbs_tx_t *tx = NULL;
	void *ptr = NULL;
	uint32_t header = VERBS_MSG_RMA_REMOTE_REPLY;
	uint64_t request = 0ULL;
	verbs_rma_addr_rkey_t info;

	CCI_ENTER;

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;

	/* check for a valid uint64_t payload */
	if (wc.byte_len != 8) {
		ret = CCI_EMSGSIZE;
		goto out;
	}

	/* find the conn for this message */
	vconn = verbs_qp_num_to_conn(ep, wc.qp_num);
	if (!vconn) {
		debug(CCI_DB_WARN,
		      "%s: no conn found for message from qp_num %u", __func__,
		      wc.qp_num);
		ret = CCI_ERR_NOT_FOUND;
		goto out;
	}
	conn = vconn->conn;

	/* find the RMA handle */
	memcpy(&request, rx->rx_pool->buf + rx->offset, sizeof(request));
	request = verbs_ntohll(request);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(h, &vep->handles, entry) {
		if ((uintptr_t) h == request) {
			handle = h;
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	tx = verbs_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->msg_type = VERBS_MSG_RMA_REMOTE_REPLY;
	memset(&tx->evt, 0, sizeof(tx->evt));
	tx->evt.conn = conn;
	tx->evt.event.type = CCI_EVENT_NONE;
	if (handle) {
		info.remote_handle = verbs_htonll(request);
		info.remote_addr = verbs_htonll((uintptr_t) handle->mr->addr);
		info.rkey = htonl(handle->mr->rkey);
		memcpy(tx->buffer, &info, sizeof(info));
		ptr = tx->buffer;
		tx->len = sizeof(info);
		header |= (1 << 4);
	} else {
		tx->len = 0;
	}

	ret = verbs_post_send(conn, (uintptr_t) tx, ptr, tx->len, header);
out:
	/* repost rx */
	verbs_post_rx(ep, rx);

	CCI_EXIT;
	return ret;
}

static int verbs_post_rma(verbs_rma_op_t * rma_op);

static int verbs_handle_rma_remote_reply(cci__ep_t * ep, struct ibv_wc wc)
{
	int ret = CCI_SUCCESS;
	verbs_conn_t *vconn = NULL;
	verbs_ep_t *vep = ep->priv;
	verbs_rx_t *rx = NULL;
	verbs_rma_remote_t *remote = NULL;
	verbs_rma_op_t *rma_op = NULL;
	verbs_rma_op_t *r = NULL;

	CCI_ENTER;

	rx = (verbs_rx_t *) (uintptr_t) wc.wr_id;

	vconn = verbs_qp_num_to_conn(ep, wc.qp_num);

	if (wc.byte_len == sizeof(verbs_rma_addr_rkey_t)) {
		remote = calloc(1, sizeof(*remote));
		if (!remote) {
			ret = CCI_ENOMEM;
			goto out;
		}

		memcpy(&remote->info, rx->rx_pool->buf + rx->offset,
		       sizeof(remote->info));
		remote->info.remote_handle =
		    verbs_ntohll(remote->info.remote_handle);
		remote->info.remote_addr =
		    verbs_ntohll(remote->info.remote_addr);
		remote->info.rkey = ntohl(remote->info.rkey);
		if (VERBS_RMA_REMOTE_SIZE) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_INSERT_HEAD(&vconn->remotes, remote, entry);
			vconn->num_remotes++;
			if (vconn->num_remotes > VERBS_RMA_REMOTE_SIZE) {
				verbs_rma_remote_t *last =
				    TAILQ_LAST(&vconn->remotes, s_rems);
				TAILQ_REMOVE(&vconn->remotes, last, entry);
				free(last);
			}
			pthread_mutex_unlock(&ep->lock);
		}
		/* find RMA op waiting for this remote_handle
		 * and post the RMA */
		pthread_mutex_lock(&ep->lock);
		TAILQ_FOREACH(r, &vconn->rma_ops, entry) {
			if (r->remote_handle == remote->info.remote_handle) {
				rma_op = r;
				TAILQ_REMOVE(&vconn->rma_ops, rma_op, entry);
				TAILQ_INSERT_TAIL(&vep->rma_ops, rma_op, entry);
				rma_op->remote_addr = remote->info.remote_addr;
				rma_op->rkey = remote->info.rkey;
			}
		}
		pthread_mutex_unlock(&ep->lock);
		ret = verbs_post_rma(rma_op);
	}
out:
	verbs_post_rx(ep, rx);

	CCI_EXIT;
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
	case VERBS_MSG_RMA_REMOTE_REQUEST:
		ret = verbs_handle_rma_remote_request(ep, wc);
		break;
	case VERBS_MSG_RMA_REMOTE_REPLY:
		ret = verbs_handle_rma_remote_reply(ep, wc);
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

	tx->evt.event.send.status = verbs_wc_to_cci_status(wc.status);
	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

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
				pthread_mutex_lock(&ep->lock);
				TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
				pthread_mutex_unlock(&ep->lock);
			}
		}
		break;
	case VERBS_MSG_SEND:
		debug(CCI_DB_CONN, "%s: send completed", __func__);
		ret = verbs_complete_send(ep, wc);
		if (!ret)
			queue_tx = 0;
		break;
	case VERBS_MSG_RMA_REMOTE_REQUEST:
	case VERBS_MSG_RMA_REMOTE_REPLY:
		break;
	default:
		debug(CCI_DB_INFO, "%s: ignoring %s msg",
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

#define VERBS_WC_CNT	8

static int verbs_get_cq_event(cci__ep_t * ep)
{
	int ret = CCI_EAGAIN;
	int i = 0;
	int found = 0;
	struct ibv_wc wc[VERBS_WC_CNT];
	verbs_ep_t *vep = ep->priv;

	CCI_ENTER;

	{
		verbs_conn_t *vconn = NULL;

		TAILQ_FOREACH(vconn, &vep->conns, entry) {
			if (vconn->raddr) {
				ret = verbs_poll_rdma_msgs(vconn);
				if (ret == CCI_SUCCESS)
					return ret;
			}
		}
	}

	memset(wc, 0, sizeof(wc));	/* silence valgrind */

	ret = ibv_poll_cq(vep->cq, VERBS_WC_CNT, wc);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	found = ret;

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
				ret = verbs_handle_rma_completion(ep, wc[i]);
				break;
			default:
				debug(CCI_DB_ALL,
				      "%s: missed opcode %u status %s wr_id 0x%"
				      PRIx64, __func__, wc[i].opcode,
				      ibv_wc_status_str(wc[i].status),
				      wc[i].wr_id);
				break;
			}
		}
	}

out:
	CCI_EXIT;
	return ret;
}

#define VERBS_CM_EVT 0
#define VERBS_CQ_EVT 1

static void verbs_progress_ep(cci__ep_t * ep)
{
	int ret = CCI_SUCCESS;
	static int which = 0;
	int try = 0;

	CCI_ENTER;

again:
	try++;
	switch (which) {
	case VERBS_CM_EVT:
		ret = verbs_get_cm_event(ep);
		break;
	case VERBS_CQ_EVT:
		ret = verbs_get_cq_event(ep);
		break;
	}
	which = !which;
	if (ret == CCI_EAGAIN && try == 1)
		goto again;

	CCI_EXIT;
	return;
}

static int
verbs_get_event(cci_endpoint_t * endpoint, cci_event_t ** const event)
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

static int verbs_return_event(cci_event_t * event)
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
				header |= ((rx->offset) << 21);
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

	is_reliable = cci_conn_is_reliable(conn);

	/* get a tx */
	tx = verbs_get_tx(ep);
	if (!tx) {
		debug(CCI_DB_MSG, "%s: no txs", __func__);
		CCI_EXIT;
		return CCI_ENOBUFS;
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

	if (vconn->raddr && iovcnt < 2) {
		pthread_mutex_lock(&ep->lock);
		if (vconn->avail) {
			i = ffs(vconn->avail);
			i--;	/* convert to index */
			vconn->avail &= ~(1 << i);
			header |= (1 << 4);	/* set RDMA bit */
			header |= (i << 21);	/* add index */
		}
		pthread_mutex_unlock(&ep->lock);
	}

	/* always copy into tx's buffer */
	if (len) {
		if (len > vconn->inline_size || iovcnt != 1) {
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

static int verbs_send(cci_connection_t * connection,	/* magic number */
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
verbs_sendv(cci_connection_t * connection,
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
verbs_rma_register(cci_endpoint_t * endpoint,
		   cci_connection_t * connection,
		   void *start, uint64_t length, uint64_t * rma_handle)
{
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

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->handles, handle, entry);
	pthread_mutex_unlock(&ep->lock);

	*rma_handle = (uint64_t) (uintptr_t) handle;

	CCI_EXIT;
	return ret;
}

static int verbs_rma_deregister(uint64_t rma_handle)
{
	int ret = CCI_SUCCESS;
	verbs_rma_handle_t *handle =
	    (verbs_rma_handle_t *) (uintptr_t) rma_handle;
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

static int
verbs_conn_get_remote(verbs_rma_op_t * rma_op, uint64_t remote_handle)
{
	int ret = CCI_ERR_NOT_FOUND;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = rma_op->evt.conn;
	verbs_conn_t *vconn = conn->priv;
	verbs_rma_remote_t *rem = NULL;

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(rem, &vconn->remotes, entry) {
		if (rem->info.remote_handle == remote_handle) {
			rma_op->remote_addr = rem->info.remote_addr;
			rma_op->rkey = rem->info.rkey;
			ret = CCI_SUCCESS;
			/* keep list in LRU order */
			if (TAILQ_FIRST(&vconn->remotes) != rem) {
				TAILQ_REMOVE(&vconn->remotes, rem, entry);
				TAILQ_INSERT_HEAD(&vconn->remotes, rem, entry);
			}
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	CCI_EXIT;
	return ret;
}

static int
verbs_conn_request_rma_remote(verbs_rma_op_t * rma_op, uint64_t remote_handle)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = rma_op->evt.conn;
	verbs_tx_t *tx = NULL;
	verbs_ep_t *vep = NULL;
	verbs_conn_t *vconn = conn->priv;
	uint64_t header = VERBS_MSG_RMA_REMOTE_REQUEST;
	uint64_t handle = verbs_htonll(remote_handle);

	CCI_ENTER;

	ep = container_of(conn->connection.endpoint, cci__ep_t, endpoint);
	vep = ep->priv;

	tx = verbs_get_tx(ep);
	if (!tx) {
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	/* tx bookkeeping */
	tx->msg_type = VERBS_MSG_RMA_REMOTE_REQUEST;
	tx->flags = 0;
	tx->rma_op = rma_op;
	tx->len = sizeof(remote_handle);

	memset(&tx->evt, 0, sizeof(cci__evt_t));
	tx->evt.conn = conn;

	/* in network byte order */
	memcpy(tx->buffer, &handle, tx->len);

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&vep->rma_ops, rma_op, entry);
	TAILQ_INSERT_TAIL(&vconn->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	ret =
	    verbs_post_send(conn, (uintptr_t) tx, tx->buffer, tx->len, header);

	CCI_EXIT;
	return ret;
}

static int verbs_post_rma(verbs_rma_op_t * rma_op)
{
	int ret = CCI_SUCCESS;
	cci__conn_t *conn = rma_op->evt.conn;
	verbs_conn_t *vconn = conn->priv;
	verbs_rma_handle_t *local =
	    (verbs_rma_handle_t *) (uintptr_t) rma_op->local_handle;
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
	wr.wr.rdma.remote_addr = rma_op->remote_addr;
	wr.wr.rdma.rkey = rma_op->rkey;

	ret = ibv_post_send(vconn->id->qp, &wr, &bad_wr);
	if (ret == -1)
		ret = errno;

	CCI_EXIT;
	return ret;
}

static int
verbs_rma(cci_connection_t * connection,
	  void *msg_ptr, uint32_t msg_len,
	  uint64_t local_handle, uint64_t local_offset,
	  uint64_t remote_handle, uint64_t remote_offset,
	  uint64_t data_len, const void *context, int flags)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	verbs_ep_t *vep = NULL;
	verbs_rma_handle_t *local =
	    (verbs_rma_handle_t *) (uintptr_t) local_handle;
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
	rma_op->msg_len = msg_len;
	rma_op->msg_ptr = msg_ptr;

	rma_op->evt.event.type = CCI_EVENT_SEND;
	rma_op->evt.event.send.connection = connection;
	rma_op->evt.event.send.context = (void *)context;
	rma_op->evt.event.send.status = CCI_SUCCESS;	/* for now */
	rma_op->evt.ep = ep;
	rma_op->evt.conn = conn;
	rma_op->evt.priv = rma_op;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&vep->rma_ops, rma_op, entry);
	pthread_mutex_unlock(&ep->lock);

	/* Do we have this remote handle info?
	 * If not, request it from the peer */
	ret = verbs_conn_get_remote(rma_op, remote_handle);
	if (ret == CCI_SUCCESS)
		ret = verbs_post_rma(rma_op);
	else
		ret = verbs_conn_request_rma_remote(rma_op, remote_handle);
	if (ret) {
		/* FIXME clean up? */
	}

	CCI_EXIT;
	return ret;
}
