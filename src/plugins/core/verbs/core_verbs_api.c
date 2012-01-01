/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_verbs.h"

volatile int verbs_shut_down = 0;
volatile verbs_globals_t *vglobals = NULL;
pthread_t progress_tid;

/*
 * Local functions
 */
static int verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *verbs_strerror(enum cci_status status);
static int verbs_get_devices(cci_device_t const ***devices);
static int verbs_free_devices(cci_device_t const **devices);
static int verbs_create_endpoint(cci_device_t *device,
                                    int flags,
                                    cci_endpoint_t **endpoint,
                                    cci_os_handle_t *fd);
static int verbs_destroy_endpoint(cci_endpoint_t *endpoint);
static int verbs_accept(union cci_event *event,
                        void *context,
                           cci_connection_t **connection);
static int verbs_reject(union cci_event *event);
static int verbs_connect(cci_endpoint_t *endpoint, char *server_uri,
                            void *data_ptr, uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            void *context, int flags,
                            struct timeval *timeout);
static int verbs_disconnect(cci_connection_t *connection);
static int verbs_set_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, const void* val, int len);
static int verbs_get_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, void** val, int *len);
static int verbs_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int verbs_get_event(cci_endpoint_t *endpoint,
                              cci_event_t ** const event);
static int verbs_return_event(cci_event_t *event);
static int verbs_send(cci_connection_t *connection,
                         void *msg_ptr, uint32_t msg_len,
                         void *context, int flags);
static int verbs_sendv(cci_connection_t *connection,
                          struct iovec *data, uint32_t iovcnt,
                          void *context, int flags);
static int verbs_rma_register(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 void *start, uint64_t length,
                                 uint64_t *rma_handle);
static int verbs_rma_deregister(uint64_t rma_handle);
static int verbs_rma(cci_connection_t *connection,
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
    verbs_strerror,
    verbs_get_devices,
    verbs_free_devices,
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

static uint32_t
verbs_mtu_val(enum ibv_mtu mtu)
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

static uint64_t
verbs_device_rate(struct ibv_port_attr attr)
{
	uint64_t rate = 2500000000ULL; /* 2.5 Gbps */

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

#if 0
static int
verbs_ifa_by_interface(struct ifaddrs *ifaddrs, const char *interface, struct ifaddrs **ifaddr, int *up)
{
	int		ret	= CCI_ENODEV;
	struct ifaddrs	*ifa	= NULL;

	CCI_ENTER;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (0 == strcmp(interface, ifa->ifa_name)) {
			if (ifa->ifa_addr->sa_family != AF_INET) {
				debug(CCI_DB_INFO, "%s's sa_family = %d",
					interface, ifa->ifa_addr->sa_family);
				goto out;
			}
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				debug(CCI_DB_INFO, "%s is loopback", interface);
				goto out;
			}
			*up = ifa->ifa_flags & IFF_UP;
			*ifaddr =  ifa;
			ret = CCI_SUCCESS;
			goto out;
		}
	}
out:
	CCI_EXIT;
	return ret;
}

static int
verbs_ifa_by_inaddr(struct ifaddrs *ifaddrs, struct in_addr in,
			struct ifaddrs **ifaddr, int *up)
{
	int		ret	= CCI_ENODEV;
	struct ifaddrs	*ifa	= NULL;

	CCI_ENTER;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
		if (in.s_addr == s->sin_addr.s_addr) {
			if (ifa->ifa_addr->sa_family != AF_INET) {
				debug(CCI_DB_INFO, "%s's sa_family = %d",
					ifa->ifa_name, ifa->ifa_addr->sa_family);
				goto out;
			}
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				debug(CCI_DB_INFO, "%s is loopback", ifa->ifa_name);
				goto out;
			}
			*up = ifa->ifa_flags & IFF_UP;
			*ifaddr =  ifa;
			ret = CCI_SUCCESS;
			goto out;
		}
	}
out:
	CCI_EXIT;
	return ret;
}

static int
verbs_context_by_hca_id(struct ibv_context **contexts, const char *hca_id,
		struct ibv_context **context)
{
	int			ret	= CCI_ENODEV;
	struct ibv_context	*ctx	= NULL;

	CCI_ENTER;
	for (ctx = *contexts; ctx != NULL; ctx++) {
		if (0 == strcmp(hca_id, ctx->device->name)) {
			*context = ctx;
			ret = CCI_SUCCESS;
			goto out;
		}
	}
out:
	CCI_EXIT;
	return ret;
}
#endif

static int
verbs_ifa_to_context(struct ibv_context *context, struct sockaddr *sa)
{
	int			ret	= CCI_SUCCESS;
	struct rdma_cm_id	*id;

	CCI_ENTER;

	ret = rdma_create_id(NULL, &id, NULL, RDMA_PS_UDP);
	if (ret) {
		ret = errno;
		CCI_EXIT;
		goto out;
	}

	ret = rdma_bind_addr(id, sa);
	if (ret == 0) {
		if (id->verbs != context)
			ret = -1;
		rdma_destroy_id(id);
	}

out:
	CCI_EXIT;
	return ret;
}

static int
verbs_find_rdma_devices(struct ibv_context **contexts, int count, struct ifaddrs **ifaddrs)
{
	int		ret		= CCI_SUCCESS;
	int		i		= 0;
	struct ifaddrs	*addrs		= NULL;
	struct ifaddrs	*ifa		= NULL;
	struct ifaddrs	*tmp		= NULL;

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

	for (i = 0; i < count; i++) {
		struct ibv_context	*c	= contexts[i];

		for (tmp = ifa; tmp != NULL; tmp = tmp->ifa_next) {
			if (tmp->ifa_addr->sa_family == AF_INET &&
				!(tmp->ifa_flags & IFF_LOOPBACK)) {
				ret = verbs_ifa_to_context(c, tmp->ifa_addr);
				if (!ret) {
					addrs[i].ifa_name = strdup(tmp->ifa_name);
					addrs[i].ifa_flags = tmp->ifa_flags;
					addrs[i].ifa_addr = tmp->ifa_addr;
					addrs[i].ifa_netmask = tmp->ifa_netmask;
					addrs[i].ifa_broadaddr = tmp->ifa_broadaddr;
					i++;
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

static int
verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
	int		count		= 0;
	int		index		= 0;
	int		used[CCI_MAX_DEVICES];
	int		ret		= 0;
	cci__dev_t	*dev		= NULL;
	cci_device_t	**devices	= NULL;
	struct ifaddrs	*ifaddrs	= NULL;

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
	}
	vglobals->ifaddrs = ifaddrs;

	/* find devices we own */
	TAILQ_FOREACH(dev, &globals->devs, entry) {
	if (0 == strcmp("verbs", dev->driver)) {
		int			i		= 0;
		const char **arg;
		const char		*hca_id		= NULL;
		const char		*interface	= NULL;
		struct in_addr		in;
		uint16_t		port		= 0;
		uint32_t		mss		= 0;
		cci_device_t		*device		= NULL;
		verbs_dev_t		*vdev		= NULL;
		//struct ibv_device_attr	dev_attr;
		struct ibv_port_attr	port_attr;

		in.s_addr = INADDR_ANY;

		device = &dev->device;
		device->pci.domain = -1;	/* per CCI spec */
		device->pci.bus = -1;		/* per CCI spec */
		device->pci.dev = -1;		/* per CCI spec */
		device->pci.func = -1;		/* per CCI spec */

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
					debug(CCI_DB_INFO, "unable to parse %s", ip);
			} else if (0 == strncmp("port=", *arg, 5)) {
				const char *port_str = *arg + 5;

				port = (uint16_t) strtoul(port_str, NULL, 0);
			} else if (0 == strncmp("mss=", *arg, 4)) {
				const char *mss_str = *arg + 4;

				mss = strtoul(mss_str, NULL, 0);
				if (mss > IBV_MTU_4096) {
					debug(CCI_DB_INFO, "mss %s is larger than "
							"IBV_MTU_4096", mss_str);
					mss = IBV_MTU_4096;
				}
			} else if (0 == strncmp("hca_id=", *arg, 7)) {
				hca_id = *arg + 7;
			} else if (0 == strncmp("interface=", *arg, 10)) {
				interface = *arg + 10;
			} else if (0 == strncmp("driver=", *arg, 7)) {
				/* do nothing */
			} else {
				debug(CCI_DB_INFO, "unknown keyword %s", *arg);
			}
		}

		for (i = 0; i < count; i++) {
			struct ifaddrs		*ifa = &ifaddrs[i];
			struct sockaddr_in	*sin =
				(struct sockaddr_in *) ifa->ifa_addr;
			struct ibv_context	*ctx = vglobals->contexts[i];

			if (in.s_addr != INADDR_ANY) {
				if (sin->sin_addr.s_addr == in.s_addr) {
					if (used[i]) {
						debug(CCI_DB_WARN, "device already assigned "
							"%s %s %s", ctx->device->name,
							ifa->ifa_name,
							inet_ntoa(sin->sin_addr));
							goto out;
					}
					vdev->context = ctx;
					vdev->ifa = ifa;
					used[i]++;
					break;
				}
			} else if (interface) {
				if (0 == strcmp(interface, ifa->ifa_name)) {
					if (used[i]) {
						debug(CCI_DB_WARN, "device already assigned "
							"%s %s %s", ctx->device->name,
							ifa->ifa_name,
							inet_ntoa(sin->sin_addr));
							goto out;
					}
					vdev->context = ctx;
					vdev->ifa = ifa;
					used[i]++;
					break;
				}
			} else if (hca_id) {
				if (0 == strcmp(hca_id, ctx->device->name)) {
					if (used[i]) {
						debug(CCI_DB_WARN, "device already assigned "
							"%s %s %s", ctx->device->name,
							ifa->ifa_name,
							inet_ntoa(sin->sin_addr));
							goto out;
					}
					vdev->context = ctx;
					vdev->ifa = ifa;
					used[i]++;
					break;
				}
			} else {
				if (used[i]) {
					debug(CCI_DB_WARN, "device already assigned "
						"%s %s %s", ctx->device->name,
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
			struct sockaddr_in *sin = (struct sockaddr_in *)vdev->ifa->ifa_addr;
			sin->sin_port = htons(port);
		}

		ret = ibv_query_port(vdev->context, 1, &port_attr);
		if (ret) {
			ret = errno;
			goto out;
		}

		device->max_send_size = verbs_mtu_val(port_attr.max_mtu);
		device->rate = verbs_device_rate(port_attr);

		devices[index] = device;
		index++;
		dev->is_up = vdev->ifa->ifa_flags & IFF_UP;
	}
	}

	devices = realloc(devices, (vglobals->count + 1) * sizeof(cci_device_t *));
	devices[vglobals->count] = NULL;

	*((cci_device_t ***) &vglobals->devices) = devices;

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


static const char *
verbs_strerror(enum cci_status status)
{
	CCI_ENTER;
	CCI_EXIT;
	return NULL;
}


static int
verbs_get_devices(cci_device_t const ***devices)
{
	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	*devices = vglobals->devices;

	CCI_EXIT;
	return CCI_SUCCESS;
}


static int
verbs_free_devices(cci_device_t const **devices)
{
	cci__dev_t	*dev	= NULL;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	pthread_mutex_lock(&globals->lock);
	verbs_shut_down = 1;
	pthread_mutex_unlock(&globals->lock);
	/* TODO join progress thread */

	pthread_mutex_lock(&globals->lock);
	TAILQ_FOREACH(dev, &globals->devs, entry)
		if (dev->priv)
			free(dev->priv);
	pthread_mutex_unlock(&globals->lock);

	free(vglobals->devices);
	free((void *)vglobals);

	CCI_EXIT;
	return CCI_SUCCESS;
}


static int
verbs_create_endpoint(cci_device_t *device,
                                    int flags,
                                    cci_endpoint_t **endpoint,
                                    cci_os_handle_t *fd)
{
	int		i	= 0;
	int		ret	= CCI_SUCCESS;
	int		fflags	= 0;
	int		pg_sz	= 0;
	char		name[64];
	size_t		len	= 0;
	cci__dev_t	*dev	= NULL;
	cci__ep_t	*ep	= NULL;
	verbs_ep_t	*vep	= NULL;
	verbs_dev_t	*vdev	= NULL;
	struct ibv_srq_init_attr srq_attr;

	CCI_ENTER;

	if (!vglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	dev = container_of(device, cci__dev_t, device);
	vdev = dev->priv;

	ep = container_of(*endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*vep));
	if (!ep->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	vep = ep->priv;

	(*endpoint)->max_recv_buffer_count = VERBS_EP_RX_CNT;
	ep->rx_buf_cnt = VERBS_EP_RX_CNT;
	ep->tx_buf_cnt = VERBS_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0; /* FIXME */

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

	vep->sin = *((struct sockaddr_in *) vdev->ifa->ifa_addr);

	ret = rdma_bind_addr(vep->id_rc, (struct sockaddr *) &vep->sin);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
	vep->sin.sin_port = rdma_get_src_port(vep->id_rc);

	ret = rdma_bind_addr(vep->id_ud, (struct sockaddr *) &vep->sin);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	memset(name, 0, sizeof(name));
	sprintf(name, "%s%s:%hu", VERBS_URI,
			inet_ntoa(vep->sin.sin_addr), ntohs(vep->sin.sin_port));
	*((char **)&ep->endpoint.name) = strdup(name);

	vep->pd = ibv_alloc_pd(vdev->context);
	if (!vep->pd) {
		ret = errno;
		goto out;
	}

	vep->cq = ibv_create_cq(vdev->context, VERBS_EP_CQ_CNT, ep, NULL, 0);
	if (!vep->cq) {
		ret = errno;
		goto out;
	}

	TAILQ_INIT(&vep->txs);
	TAILQ_INIT(&vep->idle_txs);
	TAILQ_INIT(&vep->rxs);
	TAILQ_INIT(&vep->idle_rxs);
	TAILQ_INIT(&vep->conns);
	TAILQ_INIT(&vep->handles);
	TAILQ_INIT(&vep->rma_ops);

	pg_sz = getpagesize();

	len = VERBS_EP_TX_CNT * dev->device.max_send_size;
	ret = posix_memalign((void **) &vep->tx_buf, pg_sz, len);
	if (ret)
		goto out;

	vep->tx_mr = ibv_reg_mr(vep->pd, vep->tx_buf, len, IBV_ACCESS_LOCAL_WRITE);
	if (!vep->tx_mr) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < VERBS_EP_TX_CNT; i++) {
		uintptr_t	offset	= i * ep->buffer_len;
		verbs_tx_t	*tx	= NULL;

		tx = calloc(1, sizeof(*tx));
		if (!tx) {
			ret = CCI_ENOMEM;
			goto out;
		}
		tx->evt.ep = ep;
		tx->buffer = vep->tx_buf + offset;
		TAILQ_INSERT_TAIL(&vep->txs, tx, gentry);
		TAILQ_INSERT_TAIL(&vep->idle_txs, tx, entry);
	}

	len = VERBS_EP_RX_CNT * dev->device.max_send_size;
	ret = posix_memalign((void **) &vep->rx_buf, pg_sz, len);
	if (ret)
		goto out;

	vep->rx_mr = ibv_reg_mr(vep->pd, vep->rx_buf, len, IBV_ACCESS_LOCAL_WRITE);
	if (!vep->rx_mr) {
		ret = errno;
		goto out;
	}

	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.attr.max_wr = VERBS_EP_CQ_CNT * 2;
	srq_attr.attr.max_sge = 1;
	vep->srq = ibv_create_srq(vep->pd, &srq_attr);
	if (!vep->srq) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < VERBS_EP_RX_CNT; i++) {
		uintptr_t		offset = i * ep->buffer_len;
		struct ibv_sge		list;
		struct ibv_recv_wr	wr, *bad_wr;
		verbs_rx_t		*rx	= NULL;

		rx = calloc(1, sizeof(*rx));
		if (!rx) {
			ret = CCI_ENOMEM;
			goto out;
		}

		rx->evt.ep = ep;
		rx->offset = offset;
		TAILQ_INSERT_TAIL(&vep->rxs, rx, gentry);
		TAILQ_INSERT_TAIL(&vep->idle_rxs, rx, entry);

		memset(&list, 0, sizeof(list));
		list.addr = (uintptr_t) vep->rx_buf + offset;
		list.length = ep->buffer_len;
		list.lkey = vep->rx_mr->lkey;

		memset(&wr, 0, sizeof(wr));
		wr.wr_id = (uintptr_t) rx;
		wr.sg_list = &list;
		wr.num_sge = 1;

		ret = ibv_post_srq_recv(vep->srq, &wr, &bad_wr);
		if (ret == -1) {
			ret = errno;
			goto out;
		}
	}

	CCI_EXIT;
	return CCI_SUCCESS;

out:
	/* TODO lots of clean up */
	return ret;
}


static int
verbs_destroy_endpoint(cci_endpoint_t *endpoint)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_accept(union cci_event *event,
             void *context,
                           cci_connection_t **connection)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_reject(union cci_event *event)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_connect(cci_endpoint_t *endpoint, char *server_uri,
                            void *data_ptr, uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            void *context, int flags,
                            struct timeval *timeout)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_disconnect(cci_connection_t *connection)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_set_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, const void* val, int len)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_get_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, void** val, int *len)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_get_event(cci_endpoint_t *endpoint,
                              cci_event_t ** const event)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_return_event(cci_event_t *event)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_send(cci_connection_t *connection,
                         void *msg_ptr, uint32_t msg_len,
                         void *context, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_sendv(cci_connection_t *connection,
                          struct iovec *data, uint32_t iovcnt,
                          void *context, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_rma_register(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 void *start, uint64_t length,
                                 uint64_t *rma_handle)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_rma_deregister(uint64_t rma_handle)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}


static int
verbs_rma(cci_connection_t *connection,
                        void *msg_ptr, uint32_t msg_len,
                        uint64_t local_handle, uint64_t local_offset,
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
	CCI_ENTER;
	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}
